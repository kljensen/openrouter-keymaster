//! Reading, locking, and durably writing the state file.
//!
//! # Durability guarantee
//!
//! A write serializes the whole state, writes it to a sibling temporary file,
//! flushes and fsyncs that file, renames it over the state file, and syncs the
//! parent directory. Every file Keymaster creates here — the temporary file
//! and the lock — is opened with `O_EXCL` under a name that must not already
//! exist, so nothing Keymaster writes can be redirected through a symbolic
//! link someone else put in the way. So after [`StateLock::write`] returns:
//!
//! - on success, the state file holds the new state and no temporary file
//!   remains;
//! - on failure, the state file holds the previous state — never a partial
//!   document — and no temporary file remains. The one exception is a failure
//!   in the parent-directory sync, which happens after the rename: the new
//!   state is in place and merely may not survive a power loss.
//!
//! That exception is why ADR-0002 journals intent *before* the action it
//! announces. A write that reports failure may have landed, so the next run
//! must be able to read the phase and decide, rather than assume.
//!
//! # Locking
//!
//! Writers take an exclusive lock by creating `<state>.lock` with `O_EXCL`.
//! This needs no dependency and no `unsafe`, and it fails immediately and
//! visibly rather than blocking. Its cost is that a killed process leaves the
//! file behind; the contention error says so and names the file to remove.
//! v0.1 is a single-writer model on one machine (ADR-0001), so that trade is
//! acceptable — a lease or a remote lock would be solving a problem this
//! version does not have.
//!
//! Reads take no lock and never write. Observing remote drift is not a reason
//! to rewrite state.

use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, Hasher, RandomState};
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{SCHEMA_VERSION, State, StateError};

/// Mode for the directory holding state, when Keymaster creates it.
#[cfg(unix)]
const DIRECTORY_MODE: u32 = 0o700;

/// Mode for every file Keymaster writes here.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// How many temporary names to try before giving up. A collision needs a
/// 64-bit guess or a deliberate squatter, so one retry is already generous.
const TEMPORARY_ATTEMPTS: usize = 8;

/// Reads just enough to decide whether this build understands the file.
#[derive(Debug, Deserialize)]
struct VersionProbe {
    version: u32,
}

/// A point in the write path at which a test can force a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    /// Before the temporary file is created.
    BeforeTemp,
    /// After the bytes are written, before they are flushed and synced.
    DuringWrite,
    /// After the temporary file is durable, before the rename.
    BeforeRename,
    /// After the rename, during the parent-directory sync.
    AfterRename,
}

/// Which fault, if any, this state file injects. Production callers inject
/// none; the field exists so the durability tests exercise the real path
/// rather than a copy of it.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Faults(Option<Fault>);

impl Faults {
    fn check(self, stage: Fault) -> io::Result<()> {
        if self.0 == Some(stage) {
            return Err(io::Error::other(format!("injected fault at {stage:?}")));
        }
        Ok(())
    }
}

/// The state file on disk.
#[derive(Debug, Clone)]
pub struct StateFile {
    path: PathBuf,
    faults: Faults,
}

impl StateFile {
    /// Names the file state lives in.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            faults: Faults::default(),
        }
    }

    /// The documented default location, relative to the working directory.
    #[must_use]
    pub fn default_path() -> PathBuf {
        PathBuf::from(crate::cli::DEFAULT_STATE_PATH)
    }

    /// The file this reads and writes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads state without locking and without writing anything.
    ///
    /// A file that does not exist yet is empty state, not an error: the first
    /// run of a new project has nothing bound.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the file cannot be read, is not the JSON
    /// this schema describes, claims a version this build does not
    /// understand, or describes a combination of lifecycle facts that cannot
    /// happen.
    pub fn read(&self) -> Result<State, StateError> {
        let source = match fs::read_to_string(&self.path) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(State::new()),
            Err(error) => return Err(self.read_error(&error)),
        };
        self.parse(&source)
    }

    /// Takes the exclusive writer lock.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::Locked`] when another Keymaster holds the lock,
    /// or [`StateError::Write`] when the lock file cannot be created.
    pub fn lock(&self) -> Result<StateLock<'_>, StateError> {
        let lock_path = self.lock_path();
        self.create_private_directory(&containing_directory(&lock_path))?;

        match create_private_new(&lock_path) {
            Ok(file) => {
                // Not load-bearing: a hint for whoever finds a stale lock.
                let _ = io::Write::write_all(
                    &mut &file,
                    format!("keymaster pid {}\n", std::process::id()).as_bytes(),
                );
                Ok(StateLock {
                    file: self,
                    lock_path,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(StateError::Locked {
                path: lock_path.clone(),
                message: format!(
                    "another Keymaster is writing {state}. If no other Keymaster is running, \
                     a previous one was killed before it could release the lock; remove \
                     {lock} to continue.",
                    state = self.path.display(),
                    lock = lock_path.display()
                ),
            }),
            Err(error) => Err(StateError::Write {
                path: lock_path,
                message: error.to_string(),
            }),
        }
    }

    /// Parses and checks a state document.
    fn parse(&self, source: &str) -> Result<State, StateError> {
        let probe: VersionProbe =
            serde_json::from_str(source).map_err(|error| StateError::Parse {
                path: self.path.clone(),
                message: crate::redaction::redact(&error.to_string()),
            })?;
        if probe.version != SCHEMA_VERSION {
            return Err(StateError::UnsupportedVersion {
                path: self.path.clone(),
                found: probe.version,
                expected: SCHEMA_VERSION,
            });
        }

        let state: State = serde_json::from_str(source).map_err(|error| StateError::Parse {
            path: self.path.clone(),
            message: crate::redaction::redact(&error.to_string()),
        })?;
        state
            .check_invariants()
            .map_err(|message| StateError::Corrupt {
                path: self.path.clone(),
                message,
            })?;
        Ok(state)
    }

    /// Where the lock file lives: beside the state file, so both need the
    /// same directory and the same permissions.
    fn lock_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".lock");
        PathBuf::from(name)
    }

    /// Creates the temporary file to write the next state into, returning it
    /// and its path.
    ///
    /// The file is created with `O_EXCL`, so a name that is already taken —
    /// by a leftover file, a racing writer, or a symbolic link someone planted
    /// — makes the open fail rather than truncate whatever is there. The name
    /// is randomized as well, so it cannot be guessed and pre-created to keep
    /// Keymaster from writing at all.
    pub(super) fn create_temporary(&self) -> io::Result<(File, PathBuf)> {
        for _ in 0..TEMPORARY_ATTEMPTS {
            let path = self.temporary_path();
            match create_private_new(&path) {
                Ok(file) => return Ok((file, path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "could not claim a temporary file beside {} in {TEMPORARY_ATTEMPTS} attempts",
                self.path.display()
            ),
        ))
    }

    /// An unpredictable name for the temporary file, beside the state file so
    /// the rename stays within one filesystem and is therefore atomic.
    pub(super) fn temporary_path(&self) -> PathBuf {
        // `RandomState` is seeded by the operating system, which is enough
        // randomness for a name; `O_EXCL` is what makes the write correct.
        let token = RandomState::new().build_hasher().finish();
        let mut name = self.path.as_os_str().to_owned();
        name.push(format!(".{token:016x}.tmp"));
        PathBuf::from(name)
    }

    /// Creates a directory Keymaster owns, restricted on Unix.
    ///
    /// An existing directory is left as it is: `--state` may point into a
    /// directory that belongs to the operator, and tightening its permissions
    /// would be a surprising side effect of writing a file.
    fn create_private_directory(&self, directory: &Path) -> Result<(), StateError> {
        if directory.is_dir() {
            return Ok(());
        }
        fs::create_dir_all(directory).map_err(|error| StateError::Write {
            path: directory.to_path_buf(),
            message: error.to_string(),
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE)).map_err(
                |error| StateError::Write {
                    path: directory.to_path_buf(),
                    message: error.to_string(),
                },
            )?;
        }
        Ok(())
    }

    fn read_error(&self, error: &io::Error) -> StateError {
        StateError::Read {
            path: self.path.clone(),
            message: error.to_string(),
        }
    }

    /// Builds a state file that fails at one point of the write path.
    #[cfg(test)]
    pub(super) fn with_fault(path: impl Into<PathBuf>, fault: Fault) -> Self {
        Self {
            path: path.into(),
            faults: Faults(Some(fault)),
        }
    }
}

/// The exclusive writer lock. Released when it is dropped.
#[derive(Debug)]
pub struct StateLock<'a> {
    file: &'a StateFile,
    lock_path: PathBuf,
}

impl StateLock<'_> {
    /// Reads state under the lock.
    ///
    /// # Errors
    ///
    /// The errors of [`StateFile::read`].
    pub fn read(&self) -> Result<State, StateError> {
        self.file.read()
    }

    /// Writes state durably, advancing its serial.
    ///
    /// The serial on disk must match the one this state was read with. Under
    /// the lock that always holds; the check catches the case the lock cannot,
    /// which is another machine or a hand edit writing the same file.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::Conflict`] when the file changed since this state
    /// was read, [`StateError::SerialExhausted`] when the serial cannot
    /// advance, or [`StateError::Write`] when the state could not be made
    /// durable. See the module's durability guarantee for what the file holds
    /// afterwards.
    pub fn write(&self, state: &mut State) -> Result<(), StateError> {
        let on_disk = self.file.read()?.serial();
        if on_disk != state.serial {
            return Err(StateError::Conflict {
                path: self.file.path.clone(),
                expected: state.serial,
                found: on_disk,
            });
        }

        // Saturating here would write a second state at the same serial, which
        // is exactly the signal `StateError::Conflict` depends on.
        let Some(next) = state.serial.checked_add(1) else {
            return Err(StateError::SerialExhausted {
                path: self.file.path.clone(),
                serial: state.serial,
            });
        };
        let mut candidate = state.clone();
        candidate.serial = next;
        let mut bytes =
            serde_json::to_vec_pretty(&candidate).map_err(|error| StateError::Write {
                path: self.file.path.clone(),
                message: error.to_string(),
            })?;
        bytes.push(b'\n');

        self.persist(&bytes)?;
        state.serial = next;
        Ok(())
    }

    /// The temporary-file, fsync, rename, sync-parent sequence.
    fn persist(&self, bytes: &[u8]) -> Result<(), StateError> {
        let path = &self.file.path;
        let faults = self.file.faults;

        let write = || -> io::Result<()> {
            faults.check(Fault::BeforeTemp)?;
            let (file, temporary) = self.file.create_temporary()?;
            let written = write_durably(&file, bytes, faults)
                .and_then(|()| faults.check(Fault::BeforeRename))
                .and_then(|()| fs::rename(&temporary, path));
            if written.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            written
        };
        if let Err(error) = write() {
            return Err(StateError::Write {
                path: path.clone(),
                message: error.to_string(),
            });
        }

        sync_directory(&containing_directory(path), faults).map_err(|error| StateError::Write {
            path: path.clone(),
            message: error.to_string(),
        })
    }
}

impl Drop for StateLock<'_> {
    fn drop(&mut self) {
        // Nothing useful can be done about a failure here, and the contention
        // error explains how to clear a lock file left behind.
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// Creates a file that must not already exist and that only its owner can read.
///
/// `create_new` is `O_EXCL`, which fails rather than following a symbolic
/// link. That is the whole defence against a hostile file appearing at a path
/// Keymaster is about to write: it cannot be talked into truncating whatever
/// the link points at.
pub(super) fn create_private_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }
    let file = options.open(path)?;

    // `mode` is masked by the process umask, so the permissions are set again
    // to be sure of them rather than of the environment.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
    }
    Ok(file)
}

/// Writes the bytes and makes them durable.
fn write_durably(file: &File, bytes: &[u8], faults: Faults) -> io::Result<()> {
    let mut file = file;
    io::Write::write_all(&mut file, bytes)?;
    faults.check(Fault::DuringWrite)?;
    io::Write::flush(&mut file)?;
    file.sync_all()
}

/// The directory a file lives in, as a path that can actually be opened.
///
/// `Path::parent` of a bare filename is the empty path, which no system call
/// accepts. A bare filename names a file in the working directory, so that is
/// the directory to create and to sync — skipping the sync there would quietly
/// drop the durability that ADR-0002's journal-before-acting depends on.
pub(super) fn containing_directory(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Syncs a directory so a rename inside it is durable. A no-op off Unix,
/// where a directory cannot be opened as a file.
fn sync_directory(directory: &Path, faults: Faults) -> io::Result<()> {
    faults.check(Fault::AfterRename)?;

    #[cfg(unix)]
    {
        File::open(directory)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}
