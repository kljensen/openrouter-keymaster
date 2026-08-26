//! A unique secret sentinel and the scanners that prove where it did and did
//! not travel.
//!
//! Tests use [`SECRET_SENTINEL`] wherever real code would handle credential
//! plaintext, then assert it is present exactly where it belongs — on the
//! wire, in the receiver — and absent everywhere else: output, diagnostics,
//! state, and any file Keymaster wrote.

use std::fs;
use std::path::Path;

/// The value that must never escape. Deliberately unmistakable and unique to
/// this repository, so a scan cannot match something else by accident.
pub const SECRET_SENTINEL: &str = "KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE";

/// A sentinel shaped like an OpenRouter inference key, for cases where the
/// value under test has to look like the real thing.
pub const SECRET_SENTINEL_KEY: &str = "sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE";

/// Fails when `haystack` contains either sentinel.
///
/// `label` names what was scanned, for example `"stderr"` or the file's path.
pub fn assert_absent(label: &str, haystack: &str) {
    for sentinel in [SECRET_SENTINEL, SECRET_SENTINEL_KEY] {
        assert!(
            !haystack.contains(sentinel),
            "the secret sentinel leaked into {label} at byte {offset:?}",
            offset = haystack.find(sentinel)
        );
    }
}

/// Fails unless `haystack` contains [`SECRET_SENTINEL`].
///
/// Used where disclosure is the expected behavior — the wire, the receiver —
/// so that an absent-everywhere assertion cannot pass vacuously.
pub fn assert_present(label: &str, haystack: &str) {
    assert!(
        haystack.contains(SECRET_SENTINEL) || haystack.contains(SECRET_SENTINEL_KEY),
        "the secret sentinel should have reached {label}, but did not"
    );
}

/// Fails when the file's name or contents contain a sentinel.
pub fn assert_absent_in_file(path: &Path) {
    let label = path.display().to_string();
    assert_absent(&label, &label);
    let contents = fs::read(path).unwrap_or_else(|error| panic!("reading {label}: {error}"));
    assert_absent(&label, &String::from_utf8_lossy(&contents));
}

/// Fails when any file at or under `path` — including its name — contains a
/// sentinel. Symbolic links are not followed.
pub fn assert_absent_under(path: &Path) {
    let label = path.display().to_string();
    let metadata =
        fs::symlink_metadata(path).unwrap_or_else(|error| panic!("reading {label}: {error}"));

    if metadata.is_dir() {
        assert_absent(&label, &label);
        let entries = fs::read_dir(path).unwrap_or_else(|error| panic!("listing {label}: {error}"));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| panic!("listing {label}: {error}"));
            assert_absent_under(&entry.path());
        }
    } else if metadata.is_file() {
        assert_absent_in_file(path);
    } else {
        assert_absent(&label, &label);
    }
}
