//! The receiver interface and the file receiver, delivering a real plaintext.
//!
//! Every case here hands a receiver the secret sentinel the way production
//! hands it one: a [`CreatedKey`](keymaster::client::CreatedKey) parsed out of
//! a create response served by the local HTTP harness. So an assertion that
//! the sentinel reached the file, and no assertion that it reached anything
//! else, is about the value the receiver actually held.
//!
//! The fault-injected failures — a write that fails partway, a temporary file
//! that cannot be removed — are unit tests in `src/receiver/file.rs`, because
//! the injection points are crate-internal by design. They scan for the same
//! sentinel value.

mod support;

use std::fs;
use std::path::Path;

use keymaster::ids::{Address, OperationId};
use keymaster::receiver::{Acknowledgement, DeliveryMetadata, FileReceiver, SecretReceiver as _};
use support::receiver::created_sentinel_key;
use support::sentinel::{SECRET_SENTINEL_KEY, assert_absent, assert_absent_under, assert_present};
use tempfile::TempDir;

/// The metadata of one delivery, all of it non-secret.
fn metadata(hash: &keymaster::ids::KeyHash) -> DeliveryMetadata {
    DeliveryMetadata::new(
        Address::parse("jobfeed").expect("a valid address"),
        hash.clone(),
        3,
        OperationId::parse("op-0001").expect("a valid operation id"),
    )
}

#[test]
fn a_file_receiver_delivers_the_key_and_nothing_else_learns_it() {
    let scratch = TempDir::new().expect("a temporary directory");
    let target = scratch.path().join("secrets").join("jobfeed.key");
    let created = created_sentinel_key();
    let receiver = FileReceiver::new(&target);

    let outcome = receiver.receive(&metadata(created.hash()), created.plaintext());

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Delivered);
    // The one place the secret belongs, so nothing below passes vacuously.
    assert_present(
        "the delivered file",
        &fs::read_to_string(&target).expect("reading the delivered key"),
    );
    assert_eq!(
        fs::read_to_string(&target).expect("reading"),
        SECRET_SENTINEL_KEY,
        "the file is the key and nothing else"
    );

    assert_absent("the delivery outcome", &outcome.to_string());
    assert_absent("the receiver's description", &receiver.describe());

    // Remove the one file that is supposed to hold it, and the whole tree —
    // every filename, every leftover temporary file — must be clean.
    fs::remove_file(&target).expect("removing the delivered key");
    assert_absent_under(scratch.path());
}

#[test]
fn a_refused_delivery_leaves_the_secret_nowhere_on_disk() {
    let scratch = TempDir::new().expect("a temporary directory");
    let victim = scratch.path().join("victim");
    fs::write(&victim, "not a key").expect("planting the victim");
    let target = scratch.path().join("jobfeed.key");
    std::os::unix::fs::symlink(&victim, &target).expect("planting the link");

    let created = created_sentinel_key();
    let outcome =
        FileReceiver::new(&target).receive(&metadata(created.hash()), created.plaintext());

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
    assert_absent("a refused delivery's outcome", &outcome.to_string());
    assert_absent_under(scratch.path());
}

#[test]
fn a_delivery_that_cannot_write_reports_a_safe_path_and_no_content() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = TempDir::new().expect("a temporary directory");
    let directory = scratch.path().join("locked");
    fs::create_dir(&directory).expect("creating the directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).expect("sealing it");

    // Root ignores the permission bits, and a test that passes for the wrong
    // reason is worse than no test.
    let probe = directory.join("probe");
    if fs::write(&probe, b"x").is_ok() {
        fs::remove_file(&probe).expect("removing the probe");
        return;
    }

    let target = directory.join("jobfeed.key");
    let created = created_sentinel_key();
    let outcome =
        FileReceiver::new(&target).receive(&metadata(created.hash()), created.plaintext());

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
    // The error names the receiver and the path it could not write, and
    // nothing about what it was asked to write there.
    assert!(outcome.detail().contains("file receiver"), "{outcome}");
    assert!(
        outcome.detail().contains(&target.display().to_string()),
        "{outcome}"
    );
    assert_absent("a permissions failure", &outcome.to_string());

    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("unsealing");
    assert_absent_under(scratch.path());
}

#[test]
fn a_receiver_is_chosen_by_the_configuration_and_never_by_default() {
    // The interface has no default implementation and no fallback: the only
    // way to get a receiver is to name a destination. This is the compile-time
    // half of "no receiver is selected implicitly"; the configuration half is
    // that a key with no `receiver` is never created.
    let scratch = TempDir::new().expect("a temporary directory");
    let configured = keymaster::config::Receiver::File {
        path: scratch.path().join("jobfeed.key"),
    };
    let keymaster::config::Receiver::File { path } = &configured else {
        unreachable!("the block above is a file receiver")
    };

    let created = created_sentinel_key();
    let outcome = FileReceiver::new(path).receive(&metadata(created.hash()), created.plaintext());

    assert!(outcome.is_delivered(), "{outcome}");
    assert!(Path::new(path).exists());
}
