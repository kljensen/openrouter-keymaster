//! The file receiver: one key's plaintext, in one file, atomically.
//!
//! This is the receiver for local development and tests. It exists because a
//! developer needs *some* destination that is not stdout, and because the
//! interface deserves a second implementation before it is called an
//! interface. It is not a secret store: anything that can read the file can
//! spend the key.
//!
//! # What one delivery does
//!
//! The plaintext is written to an unguessable sibling temporary file created
//! with `O_EXCL` and mode `0600`, flushed, fsynced, and renamed over the
//! configured path; then the containing directory is synced. The file holds
//! the key's bytes and nothing else — no trailing newline, no metadata, no
//! JSON — so a consumer reads the whole file and has the key.
//!
//! **The target is replaced.** If the configured path already holds a file,
//! that file's contents are gone after a successful delivery, and no backup is
//! kept anywhere. Keeping one would mean a second copy of a live credential in
//! a file nobody is managing; a rotation that needs the previous key still
//! working is what the retained-predecessor rule in ADR-0002 is for, not a
//! `.bak` file.
//!
//! # What each failure guarantees
//!
//! - Anything before the rename — an unsafe path, a directory that cannot be
//!   created, a temporary file that cannot be written — is a definite
//!   rejection: the rename never happened, so any previous file is untouched
//!   and the temporary file is removed.
//! - Unless the removal *also* fails. Then the target is still untouched, but a
//!   file holding the key is left on disk, and calling that a rejection would
//!   tell the operator no cleanup is owed when in fact one is. That case is
//!   ambiguous, and the message names the file to delete.
//! - A failure syncing the directory happens *after* the rename. The new key
//!   is already visible to every reader, so this is ambiguous, not rejected:
//!   what is in doubt is whether the change survives a power loss.
//!
//! # Fails closed on an unsafe path
//!
//! The configured path must be absolute, and its directory must be a real
//! directory rather than a symbolic link: it is opened with `O_DIRECTORY` and
//! `O_NOFOLLOW`, and everything afterwards — the `stat` of the target, the
//! `O_EXCL` create, the rename, the unlink, the fsync — happens *relative to
//! that descriptor*. Nothing resolves the path a second time, so a directory
//! replaced by a symbolic link after the check cannot receive the key: the
//! descriptor still refers to the directory that was checked.
//!
//! The target itself must be absent or a regular file; a symbolic link there is
//! refused rather than followed, so Keymaster cannot be talked into writing a
//! credential through a link into somewhere world-readable.
//!
//! Two honest limits remain. The check covers the directory the file lives in,
//! not every ancestor above it — an attacker who can rewrite a grandparent
//! directory can point the whole subtree elsewhere before the descriptor is
//! opened. And if the directory is created because it was missing, that
//! creation is path-based; the `O_NOFOLLOW` open immediately after is what
//! ensures the thing then written into is a real directory. A directory a
//! stranger can modify is not a safe destination for a credential no matter
//! what this module does.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType};

use super::{DeliveryMetadata, Outcome, SecretReceiver};
use crate::client::KeyPlaintext;
use crate::files::{
    containing_directory, create_private_directory, create_temporary_at, open_directory_nofollow,
};

/// A point in the delivery at which a test can force a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    /// Before the temporary file is created.
    BeforeTemp,
    /// After the bytes are written, before they are flushed and synced.
    DuringWrite,
    /// After the temporary file is durable, before the rename.
    BeforeRename,
    /// After the rename, during the directory sync.
    AfterRename,
}

/// Which failures this receiver injects. Production callers inject none; the
/// field exists so the tests exercise the real delivery path rather than a
/// copy of it.
#[derive(Debug, Clone, Copy, Default)]
struct Faults {
    stage: Option<Fault>,
    cleanup_fails: bool,
}

impl Faults {
    fn check(self, stage: Fault) -> io::Result<()> {
        if self.stage == Some(stage) {
            return Err(io::Error::other(format!("injected fault at {stage:?}")));
        }
        Ok(())
    }
}

/// A destination that has been resolved to something concrete: an open
/// directory, and a name inside it.
///
/// Holding the descriptor is the point. Once it exists, "the directory the key
/// goes into" is a specific directory rather than a path that has to be looked
/// up again — and looked up again is where a swapped symbolic link would get
/// its chance.
struct Destination {
    directory: OwnedFd,
    name: OsString,
}

/// Refuses a target that is not somewhere Keymaster will write a credential.
///
/// Looked up inside the already-open directory, and without following a link:
/// what is inspected here is exactly what the rename will replace.
fn check_target(directory: &OwnedFd, name: &OsStr) -> Result<(), String> {
    match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(found) => match FileType::from_raw_mode(found.st_mode) {
            FileType::RegularFile => Ok(()),
            FileType::Symlink => {
                Err("the target is a symbolic link, which is never followed".to_owned())
            }
            _ => Err("the target exists and is not a regular file".to_owned()),
        },
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(format!("the target cannot be inspected: {error}")),
    }
}

/// What went wrong, and what that proves.
enum Failure {
    /// The target was not replaced, and cannot have been.
    NotCommitted(String),
    /// The target was replaced, but something after it failed.
    Ambiguous(String),
}

/// A receiver that writes one key's plaintext to one file.
#[derive(Debug, Clone)]
pub struct FileReceiver {
    path: PathBuf,
    faults: Faults,
}

impl FileReceiver {
    /// A receiver for the file at `path`.
    ///
    /// The path comes from a `[receivers.…]` block that names this file
    /// explicitly; configuration validation has already required it to be
    /// absolute, and [`FileReceiver::receive`] requires it again rather than
    /// trusting its caller with a credential.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            faults: Faults::default(),
        }
    }

    /// The file this receiver writes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Prefixes a message with the receiver and its path, so a diagnostic
    /// always says which destination it is about.
    fn say(&self, message: &str) -> String {
        format!("file receiver {}: {message}", self.path.display())
    }

    /// Resolves the destination once: an open descriptor for the directory the
    /// file lives in, and the name it has inside it.
    ///
    /// Everything after this works relative to that descriptor, which is what
    /// makes the checks below hold rather than merely having held.
    fn resolve(&self) -> Result<Destination, String> {
        if !self.path.is_absolute() {
            return Err("the configured path is not absolute".to_owned());
        }
        let name = self
            .path
            .file_name()
            .ok_or_else(|| "the configured path does not name a file".to_owned())?
            .to_owned();

        let parent = containing_directory(&self.path);
        // An existing directory keeps its permissions: the operator chose this
        // path, and quietly tightening a directory that is theirs would be a
        // surprising side effect of writing one file.
        if !parent.exists() {
            create_private_directory(&parent).map_err(|error| {
                format!(
                    "its directory {} cannot be created: {error}",
                    parent.display()
                )
            })?;
        }
        let directory = open_directory_nofollow(&parent).map_err(|error| {
            format!(
                "its directory {} cannot be opened as a real directory — a symbolic link in its \
                 place is never followed: {error}",
                parent.display()
            )
        })?;

        check_target(&directory, &name)?;
        Ok(Destination { directory, name })
    }

    /// Writes `bytes` to a temporary file and renames it over the target.
    fn replace_contents(&self, at: &Destination, bytes: &[u8]) -> Result<(), Failure> {
        self.faults
            .check(Fault::BeforeTemp)
            .map_err(|error| Failure::NotCommitted(format!("the write did not start: {error}")))?;

        let (file, temporary) = create_temporary_at(&at.directory, &at.name).map_err(|error| {
            Failure::NotCommitted(format!("no temporary file could be created: {error}"))
        })?;

        if let Err(error) = self.write_and_rename(at, &file, bytes, &temporary) {
            drop(file);
            let reason = format!("the key was not written: {error}");
            return Err(match self.remove_temporary(at, &temporary) {
                None => Failure::NotCommitted(reason),
                // The target is untouched, so nothing was delivered — but a
                // file holding the key is still on disk, and reporting that as
                // a plain rejection would say no cleanup is owed when one is.
                Some(leftover) => Failure::Ambiguous(format!(
                    "{reason}. Nothing was written to the target, but a temporary file holding \
                     the key remains at {} and could not be removed; delete it",
                    leftover.display()
                )),
            });
        }
        drop(file);

        // Past the rename every reader already sees the new key, so a failure
        // here cannot be reported as "nothing happened".
        self.faults
            .check(Fault::AfterRename)
            .and_then(|()| rustix::fs::fsync(&at.directory).map_err(io::Error::from))
            .map_err(|error| {
                Failure::Ambiguous(format!(
                    "the key is in place but its directory could not be synced, so the change \
                     may not survive a power loss: {error}"
                ))
            })
    }

    /// The durable part: write, flush, fsync, rename.
    fn write_and_rename(
        &self,
        at: &Destination,
        file: &File,
        bytes: &[u8],
        temporary: &OsStr,
    ) -> io::Result<()> {
        let mut handle = file;
        io::Write::write_all(&mut handle, bytes)?;
        self.faults.check(Fault::DuringWrite)?;
        io::Write::flush(&mut handle)?;
        file.sync_all()?;
        self.faults.check(Fault::BeforeRename)?;
        rustix::fs::renameat(&at.directory, temporary, &at.directory, &at.name)
            .map_err(io::Error::from)
    }

    /// Removes the temporary file, returning its path if it is still there.
    ///
    /// It holds the plaintext, so a failure to remove it changes what the
    /// delivery proved: see [`FileReceiver::replace_contents`].
    fn remove_temporary(&self, at: &Destination, temporary: &OsStr) -> Option<PathBuf> {
        let leftover = || containing_directory(&self.path).join(temporary);
        if self.faults.cleanup_fails {
            return Some(leftover());
        }
        match rustix::fs::unlinkat(&at.directory, temporary, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => None,
            Err(_) => Some(leftover()),
        }
    }

    /// A receiver that fails at one point of the delivery.
    #[cfg(test)]
    pub(super) fn with_fault(path: impl Into<PathBuf>, stage: Fault) -> Self {
        Self {
            path: path.into(),
            faults: Faults {
                stage: Some(stage),
                cleanup_fails: false,
            },
        }
    }

    /// A receiver that fails at one point of the delivery and cannot clean up
    /// after itself.
    #[cfg(test)]
    pub(super) fn with_failing_cleanup(path: impl Into<PathBuf>, stage: Fault) -> Self {
        Self {
            path: path.into(),
            faults: Faults {
                stage: Some(stage),
                cleanup_fails: true,
            },
        }
    }
}

impl SecretReceiver for FileReceiver {
    fn describe(&self) -> String {
        format!("file receiver {}", self.path.display())
    }

    fn receive(&self, metadata: &DeliveryMetadata, plaintext: &KeyPlaintext) -> Outcome {
        let destination = match self.resolve() {
            Ok(destination) => destination,
            Err(reason) => {
                return Outcome::rejected(self.say(&format!("refusing to deliver: {reason}")));
            }
        };

        match self.replace_contents(&destination, plaintext.expose().as_bytes()) {
            Ok(()) => Outcome::delivered(self.say(&format!(
                "wrote generation {generation} of {address} (operation {operation})",
                generation = metadata.generation(),
                address = metadata.address(),
                operation = metadata.operation()
            ))),
            Err(Failure::NotCommitted(reason)) => Outcome::rejected(self.say(&reason)),
            Err(Failure::Ambiguous(reason)) => Outcome::ambiguous(self.say(&reason)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::TempDir;

    use super::*;
    use crate::ids::{Address, KeyHash, OperationId};
    use crate::receiver::Acknowledgement;

    /// The plaintext every case here delivers. Unit tests cannot reach the
    /// shared sentinel in `test_support`, so it is repeated.
    const SENTINEL_KEY: &str = "sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE";

    fn metadata() -> DeliveryMetadata {
        DeliveryMetadata::new(
            Address::parse("jobfeed").expect("a valid address"),
            KeyHash::parse("keyhash-0001").expect("a valid hash"),
            3,
            OperationId::parse("op-0001").expect("a valid operation id"),
        )
    }

    fn plaintext() -> KeyPlaintext {
        KeyPlaintext::for_tests(SENTINEL_KEY)
    }

    /// Every entry in a directory, by name.
    fn entries(directory: &Path) -> BTreeSet<String> {
        fs::read_dir(directory)
            .expect("listing the directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777
    }

    /// Fails when the sentinel appears where it must not.
    fn assert_no_secret(label: &str, text: &str) {
        assert!(
            !text.contains(SENTINEL_KEY) && !text.contains("sk-or-"),
            "the key leaked into {label}: {text}"
        );
    }

    #[test]
    fn a_delivered_key_is_the_whole_file_and_only_its_owner_can_read_it() {
        let scratch = TempDir::new().expect("a temporary directory");
        let target = scratch.path().join("keys").join("jobfeed.key");
        let receiver = FileReceiver::new(&target);

        let outcome = receiver.receive(&metadata(), &plaintext());

        assert_eq!(outcome.acknowledgement(), Acknowledgement::Delivered);
        assert_eq!(fs::read_to_string(&target).expect("reading"), SENTINEL_KEY);
        // Nothing else is left behind: no temporary file, no backup.
        assert_eq!(
            entries(target.parent().expect("a parent")),
            BTreeSet::from(["jobfeed.key".to_owned()])
        );

        #[cfg(unix)]
        {
            assert_eq!(mode(&target), 0o600);
            assert_eq!(
                mode(target.parent().expect("a parent")),
                0o700,
                "a directory Keymaster creates is private"
            );
        }

        // The message says what happened and names nothing secret.
        assert_no_secret("the outcome", &outcome.to_string());
        assert!(outcome.to_string().contains("jobfeed"), "{outcome}");
    }

    #[test]
    fn an_existing_file_is_replaced_and_no_copy_of_the_old_key_is_kept() {
        let scratch = TempDir::new().expect("a temporary directory");
        let target = scratch.path().join("jobfeed.key");
        fs::write(&target, "sk-or-v1-THE-PREVIOUS-KEY").expect("planting a previous key");
        #[cfg(unix)]
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("loosening");

        let outcome = FileReceiver::new(&target).receive(&metadata(), &plaintext());

        assert!(outcome.is_delivered(), "{outcome}");
        assert_eq!(fs::read_to_string(&target).expect("reading"), SENTINEL_KEY);
        assert_eq!(
            entries(scratch.path()),
            BTreeSet::from(["jobfeed.key".to_owned()]),
            "replacement keeps no backup of either key"
        );
        // The replacement is the file Keymaster created, with its permissions,
        // not the loose ones the previous file carried.
        #[cfg(unix)]
        assert_eq!(mode(&target), 0o600);
    }

    #[test]
    fn a_relative_path_is_refused_before_anything_is_written() {
        let outcome = FileReceiver::new("jobfeed.key").receive(&metadata(), &plaintext());

        assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
        assert!(outcome.detail().contains("not absolute"), "{outcome}");
        assert!(!Path::new("jobfeed.key").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_at_the_target_is_refused_rather_than_followed() {
        use std::os::unix::fs::symlink;

        let scratch = TempDir::new().expect("a temporary directory");
        let victim = scratch.path().join("victim");
        fs::write(&victim, "do not overwrite me").expect("planting the victim");
        let target = scratch.path().join("jobfeed.key");
        symlink(&victim, &target).expect("planting the link");

        let outcome = FileReceiver::new(&target).receive(&metadata(), &plaintext());

        assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
        assert!(outcome.detail().contains("symbolic link"), "{outcome}");
        assert_eq!(
            fs::read_to_string(&victim).expect("reading the victim"),
            "do not overwrite me"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_in_place_of_the_directory_is_refused() {
        use std::os::unix::fs::symlink;

        let scratch = TempDir::new().expect("a temporary directory");
        let real = scratch.path().join("real");
        fs::create_dir(&real).expect("creating the real directory");
        let linked = scratch.path().join("linked");
        symlink(&real, &linked).expect("planting the link");

        let outcome =
            FileReceiver::new(linked.join("jobfeed.key")).receive(&metadata(), &plaintext());

        assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
        assert!(outcome.detail().contains("symbolic link"), "{outcome}");
        assert!(entries(&real).is_empty(), "nothing was written through it");
    }

    #[test]
    fn a_directory_where_the_file_belongs_is_refused() {
        let scratch = TempDir::new().expect("a temporary directory");
        let target = scratch.path().join("jobfeed.key");
        fs::create_dir(&target).expect("planting a directory");

        let outcome = FileReceiver::new(&target).receive(&metadata(), &plaintext());

        assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
        assert!(outcome.detail().contains("not a regular file"), "{outcome}");
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_written_is_a_definite_rejection() {
        let scratch = TempDir::new().expect("a temporary directory");
        let directory = scratch.path().join("locked");
        fs::create_dir(&directory).expect("creating the directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).expect("sealing it");

        // Running as root defeats the permission bits entirely, and a test
        // that silently passes for the wrong reason is worse than no test.
        let probe = directory.join("probe");
        if fs::write(&probe, b"x").is_ok() {
            fs::remove_file(&probe).expect("removing the probe");
            return;
        }

        let target = directory.join("jobfeed.key");
        let outcome = FileReceiver::new(&target).receive(&metadata(), &plaintext());

        assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
        assert_no_secret("a permissions failure", &outcome.to_string());
        assert!(entries(&directory).is_empty(), "no temporary file remains");

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("unsealing");
    }

    #[test]
    fn a_failure_before_the_rename_preserves_the_old_file_and_leaves_no_temporary() {
        for stage in [Fault::BeforeTemp, Fault::DuringWrite, Fault::BeforeRename] {
            let scratch = TempDir::new().expect("a temporary directory");
            let target = scratch.path().join("jobfeed.key");
            fs::write(&target, "the previous key").expect("planting a previous key");

            let outcome =
                FileReceiver::with_fault(&target, stage).receive(&metadata(), &plaintext());

            assert_eq!(
                outcome.acknowledgement(),
                Acknowledgement::Rejected,
                "{stage:?}: {outcome}"
            );
            assert_eq!(
                fs::read_to_string(&target).expect("reading"),
                "the previous key",
                "{stage:?} must not disturb the file that is there"
            );
            assert_eq!(
                entries(scratch.path()),
                BTreeSet::from(["jobfeed.key".to_owned()]),
                "{stage:?} must remove its temporary file"
            );
            assert_no_secret(&format!("the {stage:?} outcome"), &outcome.to_string());
        }
    }

    #[test]
    fn a_failure_after_the_rename_is_ambiguous_rather_than_a_rejection() {
        let scratch = TempDir::new().expect("a temporary directory");
        let target = scratch.path().join("jobfeed.key");

        let outcome = FileReceiver::with_fault(&target, Fault::AfterRename)
            .receive(&metadata(), &plaintext());

        assert_eq!(outcome.acknowledgement(), Acknowledgement::Ambiguous);
        assert_eq!(
            fs::read_to_string(&target).expect("reading"),
            SENTINEL_KEY,
            "the key is in place; only its durability is in doubt"
        );
        assert_no_secret("an ambiguous outcome", &outcome.to_string());
    }

    #[test]
    fn a_temporary_file_that_cannot_be_cleaned_up_is_ambiguous_and_named() {
        let scratch = TempDir::new().expect("a temporary directory");
        let target = scratch.path().join("jobfeed.key");

        let outcome = FileReceiver::with_failing_cleanup(&target, Fault::BeforeRename)
            .receive(&metadata(), &plaintext());

        // Nothing reached the target, but the key is on disk in a file nobody
        // is managing. "Rejected" would tell the operator no cleanup is owed.
        assert_eq!(outcome.acknowledgement(), Acknowledgement::Ambiguous);
        assert!(outcome.detail().contains("remains at"), "{outcome}");
        assert!(
            outcome
                .detail()
                .contains("Nothing was written to the target"),
            "{outcome}"
        );
        assert!(outcome.detail().contains(".tmp"), "{outcome}");
        assert_no_secret("a cleanup failure", &outcome.to_string());
        assert!(!target.exists(), "the target was never created");

        // The leftover is the temporary file, and its *name* carries nothing.
        let leftovers = entries(scratch.path());
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
        for name in &leftovers {
            assert_no_secret("a temporary filename", name);
        }
    }
}
