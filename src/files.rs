//! Creating files only their owner can read, and replacing one atomically.
//!
//! Two places in Keymaster write a file that must not be readable by anyone
//! else and must never be observed half-written: the state file, which names
//! every live spending credential this project owns, and the file receiver,
//! which writes a key's plaintext. They share these primitives rather than
//! each carrying their own copy, because the paranoid parts — `O_EXCL` on
//! every create, an unguessable temporary name, `0600` set again after the
//! umask has had its say — are exactly the parts that must not drift apart.
//!
//! What is deliberately *not* here is the sequencing: which failure preserves
//! what, and which failure is ambiguous, differs between a state write and a
//! secret delivery, so each caller composes these steps itself and says in its
//! own documentation what the result guarantees.
//!
//! # Two ways to name a file
//!
//! The path-based helpers ([`create_private_new`], [`create_temporary`]) resolve
//! a whole path on every call, which means every directory along it is looked
//! up again each time. That is fine for state, which lives in a directory the
//! operator owns.
//!
//! The descriptor-relative helpers ([`open_directory_nofollow`],
//! [`create_private_new_at`], [`create_temporary_at`]) resolve the directory
//! once and work inside it afterwards, so nothing that happens to the path in
//! between can redirect the write. The file receiver uses those, because it
//! writes a live credential and the directory it writes into may not be one
//! only the operator can modify.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher as _, Hasher as _, RandomState};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

/// Mode for a directory Keymaster creates.
#[cfg(unix)]
pub(crate) const DIRECTORY_MODE: u32 = 0o700;

/// Mode for every file Keymaster writes.
#[cfg(unix)]
pub(crate) const FILE_MODE: u32 = 0o600;

/// How many temporary names to try before giving up. A collision needs a
/// 64-bit guess or a deliberate squatter, so one retry is already generous.
const TEMPORARY_ATTEMPTS: usize = 8;

/// Creates a file that must not already exist and that only its owner can read.
///
/// `create_new` is `O_EXCL`, which fails rather than following a symbolic
/// link. That is the whole defence against a hostile file appearing at a path
/// Keymaster is about to write: it cannot be talked into truncating whatever
/// the link points at.
pub(crate) fn create_private_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(FILE_MODE);
    }
    let file = options.open(path)?;

    // `mode` is masked by the process umask, so the permissions are set again
    // to be sure of them rather than of the environment.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
    }
    Ok(file)
}

/// Creates a directory Keymaster owns, restricted on Unix.
///
/// An existing directory is left exactly as it is: the path may have been
/// chosen by the operator inside a directory that is theirs, and tightening
/// its permissions would be a surprising side effect of writing one file.
pub(crate) fn create_private_directory(directory: &Path) -> io::Result<()> {
    if directory.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(directory)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE))?;
    }
    Ok(())
}

/// An unpredictable name beside `target`, so a rename onto it stays within one
/// filesystem and is therefore atomic.
pub(crate) fn temporary_path(target: &Path) -> PathBuf {
    PathBuf::from(temporary_name(target.as_os_str()))
}

/// An unpredictable name derived from `base`.
pub(crate) fn temporary_name(base: &OsStr) -> OsString {
    // `RandomState` is seeded by the operating system, which is enough
    // randomness for a name; `O_EXCL` is what makes the write correct.
    let token = RandomState::new().build_hasher().finish();
    let mut name = base.to_owned();
    name.push(format!(".{token:016x}.tmp"));
    name
}

/// Opens a directory, refusing to follow a symbolic link standing in for it.
///
/// The returned descriptor is the anchor for everything else the caller does:
/// once this succeeds, the directory being written into is *that* directory,
/// whatever later happens to the name it was reached by. `O_DIRECTORY` refuses
/// a path that is not a directory, and `O_NOFOLLOW` refuses one whose final
/// component is a symbolic link.
pub(crate) fn open_directory_nofollow(path: &Path) -> io::Result<OwnedFd> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// Creates `name` inside an already-opened directory: `O_EXCL`, `O_NOFOLLOW`,
/// and mode `0600`.
///
/// Nothing here resolves a path, so a directory swapped out after
/// [`open_directory_nofollow`] returned cannot receive this file.
pub(crate) fn create_private_new_at(directory: &OwnedFd, name: &OsStr) -> io::Result<File> {
    let owner_only = Mode::RUSR | Mode::WUSR;
    let file = rustix::fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        owner_only,
    )
    .map_err(io::Error::from)?;

    // The create mode is masked by the process umask, so the permissions are
    // set again to be sure of them rather than of the environment.
    rustix::fs::fchmod(&file, owner_only).map_err(io::Error::from)?;
    Ok(File::from(file))
}

/// Claims an unpredictable temporary name inside an already-opened directory,
/// returning the open file and the name it was created under.
pub(crate) fn create_temporary_at(
    directory: &OwnedFd,
    base: &OsStr,
) -> io::Result<(File, OsString)> {
    for _ in 0..TEMPORARY_ATTEMPTS {
        let name = temporary_name(base);
        match create_private_new_at(directory, &name) {
            Ok(file) => return Ok((file, name)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "could not claim a temporary file beside {} in {TEMPORARY_ATTEMPTS} attempts",
            base.display()
        ),
    ))
}

/// Creates the temporary file to write `target`'s next contents into,
/// returning it and its path.
///
/// The file is created with `O_EXCL`, so a name that is already taken — by a
/// leftover file, a racing writer, or a symbolic link someone planted — makes
/// the open fail rather than truncate whatever is there. The name is
/// randomized as well, so it cannot be guessed and pre-created to keep
/// Keymaster from writing at all.
pub(crate) fn create_temporary(target: &Path) -> io::Result<(File, PathBuf)> {
    for _ in 0..TEMPORARY_ATTEMPTS {
        let path = temporary_path(target);
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
            target.display()
        ),
    ))
}

/// The directory a file lives in, as a path that can actually be opened.
///
/// `Path::parent` of a bare filename is the empty path, which no system call
/// accepts. A bare filename names a file in the working directory, so that is
/// the directory to create and to sync — skipping the sync there would quietly
/// drop the durability that ADR-0002's journal-before-acting depends on.
pub(crate) fn containing_directory(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Syncs a directory so a rename inside it is durable. A no-op off Unix,
/// where a directory cannot be opened as a file.
pub(crate) fn sync_directory(directory: &Path) -> io::Result<()> {
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
