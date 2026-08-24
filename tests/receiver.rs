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
use std::path::{Path, PathBuf};
use std::time::Duration;

use keymaster::ids::{Address, OperationId};
use keymaster::receiver::{
    Acknowledgement, CommandReceiver, DeliveryMetadata, FileReceiver, SecretReceiver as _,
};
use serde_json::Value;
use support::receiver::{created_oversized_key, created_sentinel_key};
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

// ===== the command receiver =====

/// The purpose-built adapter in `src/bin/keymaster-test-receiver.rs`. A real
/// compiled program, not a shell string: what is under test is process
/// spawning, argument passing, and an empty environment, none of which a
/// script interpreted by `/bin/sh` would exercise honestly.
const HELPER: &str = env!("CARGO_BIN_EXE_keymaster-test-receiver");

/// A receiver that runs the helper in one mode, recording into `directory`.
fn helper(directory: &Path, mode: &str, extra: &[&str]) -> CommandReceiver {
    let mut args = vec![mode.to_owned(), directory.display().to_string()];
    args.extend(extra.iter().map(|value| (*value).to_owned()));
    CommandReceiver::new(HELPER, args).with_timeout(Duration::from_secs(20))
}

/// What the helper recorded in one file.
fn recorded(directory: &Path, name: &str) -> String {
    fs::read_to_string(directory.join(name))
        .unwrap_or_else(|error| panic!("reading {name}: {error}"))
}

#[test]
fn a_command_receiver_delivers_one_envelope_and_nothing_else() {
    let scratch = TempDir::new().expect("a temporary directory");
    let created = created_sentinel_key();
    let receiver = helper(scratch.path(), "record", &[]);

    let outcome = receiver.receive(&metadata(created.hash()), created.plaintext());

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Delivered);

    // The envelope: versioned, non-secret metadata, and the key.
    let envelope = recorded(scratch.path(), "envelope.json");
    let parsed: Value = serde_json::from_str(&envelope).expect("the envelope is JSON");
    assert_eq!(parsed["envelope_version"], Value::from(1));
    assert_eq!(parsed["operation_id"], Value::from("op-0001"));
    assert_eq!(parsed["address"], Value::from("jobfeed"));
    assert_eq!(parsed["hash"], Value::from("keyhash-0001"));
    assert_eq!(parsed["generation"], Value::from(3));
    assert_present("the envelope on the adapter's stdin", &envelope);

    // `argv` is exactly what was configured — the program, the mode, and the
    // directory to record into. There is nowhere in it for a secret to hide,
    // and every user on the machine can read it out of the process list.
    let argv = recorded(scratch.path(), "argv.txt");
    assert_eq!(
        argv.lines().collect::<Vec<_>>(),
        [HELPER, "record", &scratch.path().display().to_string()]
    );
    assert_absent("the adapter's argument vector", &argv);

    // Keymaster passes no environment at all. Not a filtered copy — none. So
    // the management credential and everything else this process holds are
    // absent by construction rather than by an allowlist someone maintains.
    //
    // "None" is what Keymaster passes, not always what the child ends up with:
    // macOS's own runtime adds `__CF_USER_TEXT_ENCODING` to a process it
    // starts, below anything this program controls. Nothing else may appear.
    assert!(
        std::env::var_os("PATH").is_some(),
        "this test process must have an environment for its absence to mean anything"
    );
    let inherited = recorded(scratch.path(), "env.txt");
    for name in inherited.lines() {
        assert!(
            name == "__CF_USER_TEXT_ENCODING",
            "the adapter inherited {name} from somewhere"
        );
    }
    assert!(!inherited.contains("OPENROUTER_MANAGEMENT_KEY"));
    assert!(!inherited.contains(SENTINEL_VARIABLE));
    assert!(!inherited.contains("PATH"), "{inherited}");
    assert!(!inherited.contains("HOME"), "{inherited}");

    assert_absent("the delivery outcome", &outcome.to_string());
    assert_eq!(recorded(scratch.path(), "runs.txt"), "ran\n");
    fs::remove_file(scratch.path().join("envelope.json")).expect("removing the envelope");
    assert_absent_under(scratch.path());
}

/// A variable name the adapter must never see. Set on a control child below,
/// which is what proves the emptiness assertion above is not vacuous.
const SENTINEL_VARIABLE: &str = "KEYMASTER_TEST_AMBIENT_SECRET";

#[test]
fn the_environment_dump_would_have_caught_an_inherited_variable() {
    // The receiver clears the environment, so the case above can only prove
    // absence if the recording would have shown presence. Rust 2024 makes
    // `set_var` unsafe and this crate forbids unsafe code, so the contrast is
    // drawn by spawning the same helper directly, with variables set on the
    // child, which is safe.
    let scratch = TempDir::new().expect("a temporary directory");
    let status = std::process::Command::new(HELPER)
        .args(["record", &scratch.path().display().to_string()])
        .env("OPENROUTER_MANAGEMENT_KEY", SECRET_SENTINEL_KEY)
        .env(SENTINEL_VARIABLE, "ambient")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("the helper runs");

    assert!(status.success());
    let inherited = recorded(scratch.path(), "env.txt");
    assert!(
        inherited.contains("OPENROUTER_MANAGEMENT_KEY"),
        "{inherited}"
    );
    assert!(inherited.contains(SENTINEL_VARIABLE), "{inherited}");
    // Names only: the recording itself is not a place a value can land.
    assert_absent("the adapter's environment record", &inherited);
}

#[test]
fn the_documented_refusal_code_is_the_only_definite_rejection() {
    let scratch = TempDir::new().expect("a temporary directory");
    let created = created_sentinel_key();

    let refused = helper(scratch.path(), "reject", &[])
        .receive(&metadata(created.hash()), created.plaintext());
    assert_eq!(refused.acknowledgement(), Acknowledgement::Rejected);
    assert!(refused.detail().contains("10"), "{refused}");
    assert_eq!(
        recorded(scratch.path(), "runs.txt"),
        "ran\n",
        "a refusal is not retried either"
    );

    // Any other nonzero exit is ambiguous, however ordinary it looks: ADR-0002
    // will not read a generic failure as proof that nothing was committed.
    for code in ["1", "2", "127"] {
        let outcome = helper(scratch.path(), "fail", &[code])
            .receive(&metadata(created.hash()), created.plaintext());
        assert_eq!(
            outcome.acknowledgement(),
            Acknowledgement::Ambiguous,
            "exit {code}: {outcome}"
        );
    }
    assert_absent("a refused delivery", &refused.to_string());
}

#[test]
fn an_adapter_that_never_reads_the_envelope_is_never_a_rejection() {
    let scratch = TempDir::new().expect("a temporary directory");
    let created = created_sentinel_key();

    let outcome = helper(scratch.path(), "deaf", &["3"])
        .receive(&metadata(created.hash()), created.plaintext());

    // Its stdin goes away as the process exits, so Keymaster's write may or
    // may not land — the exit code settles it either way, and neither reading
    // says anything definite about what was committed.
    assert_eq!(outcome.acknowledgement(), Acknowledgement::Ambiguous);
    assert!(
        !scratch.path().join("envelope.json").exists(),
        "the adapter never read the envelope"
    );
    assert_absent_under(scratch.path());
}

#[test]
fn an_adapter_that_never_finishes_is_killed_and_left_ambiguous() {
    let scratch = TempDir::new().expect("a temporary directory");
    let created = created_sentinel_key();
    let receiver = CommandReceiver::new(
        HELPER,
        vec![
            "hang".to_owned(),
            scratch.path().display().to_string(),
            "60000".to_owned(),
        ],
    )
    // Long enough that the adapter certainly started and recorded the run
    // before it was killed, and far short of the minute it means to sleep.
    .with_timeout(Duration::from_millis(1_500));

    let started = std::time::Instant::now();
    let outcome = receiver.receive(&metadata(created.hash()), created.plaintext());
    let elapsed = started.elapsed();

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Ambiguous);
    assert!(outcome.detail().contains("did not finish"), "{outcome}");
    assert!(
        elapsed < Duration::from_secs(10),
        "the bound is enforced, not merely documented: {elapsed:?}"
    );
    // Ambiguity is never resolved by trying again: the adapter ran once, and
    // an operator decides what happens next (ADR-0002).
    assert_eq!(recorded(scratch.path(), "runs.txt"), "ran\n");
    // It read the envelope before hanging, so the key is on disk where the
    // adapter put it — and nowhere Keymaster reports.
    assert_absent("a timed-out delivery", &outcome.to_string());
}

#[test]
fn a_descendant_holding_the_pipes_cannot_outlast_the_bound() {
    let scratch = TempDir::new().expect("a temporary directory");
    let created = created_sentinel_key();

    // The adapter exits at once but leaves a child of its own holding the
    // stdout and stderr pipes for eight seconds. Waiting for end-of-file there
    // would be waiting on a process Keymaster never started and cannot kill.
    let started = std::time::Instant::now();
    let outcome = helper(scratch.path(), "orphan", &["8000"])
        .receive(&metadata(created.hash()), created.plaintext());
    let elapsed = started.elapsed();

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Delivered);
    assert!(
        elapsed < Duration::from_secs(6),
        "the capture must be bounded too, not just the child: {elapsed:?}"
    );
}

#[test]
fn an_adapter_that_stays_alive_without_reading_cannot_block_past_the_bound() {
    let scratch = TempDir::new().expect("a temporary directory");
    // Far larger than any pipe buffer, so the write cannot complete until
    // something reads it — and this adapter never will.
    let created = created_oversized_key(1_000_000);
    let receiver = CommandReceiver::new(
        HELPER,
        vec![
            "mute".to_owned(),
            scratch.path().display().to_string(),
            "20000".to_owned(),
        ],
    )
    .with_timeout(Duration::from_secs(1));

    let started = std::time::Instant::now();
    let outcome = receiver.receive(&metadata(created.hash()), created.plaintext());
    let elapsed = started.elapsed();

    // The bound has to cover the write as well as the wait: an inline write
    // would still be blocked here, with the timeout never reached.
    assert!(
        elapsed < Duration::from_secs(10),
        "the write is inside the bound: {elapsed:?}"
    );
    assert_eq!(outcome.acknowledgement(), Acknowledgement::Ambiguous);
    assert_absent("a delivery that could not be written", &outcome.to_string());

    // The child was killed rather than left running: it would have marked
    // itself done twenty seconds in, and it never gets there.
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !scratch.path().join("done.txt").exists(),
        "the adapter outlived its delivery"
    );
    assert_eq!(recorded(scratch.path(), "runs.txt"), "ran\n");
}

#[test]
fn an_adapter_killed_by_a_signal_is_ambiguous() {
    let scratch = TempDir::new().expect("a temporary directory");
    let created = created_sentinel_key();

    let outcome = helper(scratch.path(), "abort", &[])
        .receive(&metadata(created.hash()), created.plaintext());

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Ambiguous);
    assert!(outcome.detail().contains("signal"), "{outcome}");
    assert_absent("a delivery that died by signal", &outcome.to_string());
}

#[test]
fn a_loud_adapter_cannot_flood_a_diagnostic_or_wedge_the_delivery() {
    let scratch = TempDir::new().expect("a temporary directory");
    let created = created_sentinel_key();

    // Far more than any pipe buffer: an implementation that captured without a
    // bound, or stopped reading at its cap, would hang here rather than fail.
    let outcome = helper(scratch.path(), "spew", &["2000000"])
        .receive(&metadata(created.hash()), created.plaintext());

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Delivered);
    assert!(
        outcome.detail().len() < 1_000,
        "the diagnostic is bounded, not the output: {} bytes",
        outcome.detail().len()
    );
}

#[test]
fn an_adapter_that_echoes_the_key_cannot_leak_it_through_keymaster() {
    let scratch = TempDir::new().expect("a temporary directory");
    let created = created_sentinel_key();

    // The adapter prints the whole envelope — key included — to both streams.
    let outcome =
        helper(scratch.path(), "echo", &[]).receive(&metadata(created.hash()), created.plaintext());

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Delivered);
    assert_absent("an echoed envelope", &outcome.to_string());
    assert!(outcome.detail().contains("[redacted]"), "{outcome}");
    // The non-secret half survives, which is why capturing anything is worth
    // doing: an adapter's acknowledgement of the operation still reaches the
    // operator.
    assert!(outcome.detail().contains("op-0001"), "{outcome}");
}

#[test]
fn a_program_that_is_not_there_committed_nothing() {
    let scratch = TempDir::new().expect("a temporary directory");
    let created = created_sentinel_key();
    let missing = scratch.path().join("no-such-adapter");

    let outcome = CommandReceiver::new(&missing, Vec::new())
        .receive(&metadata(created.hash()), created.plaintext());

    assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
    assert!(
        outcome.detail().contains(&missing.display().to_string()),
        "{outcome}"
    );
    assert_absent_under(scratch.path());
}

#[test]
fn a_configured_command_block_builds_the_command_receiver() {
    let scratch = TempDir::new().expect("a temporary directory");
    let configured = keymaster::config::Receiver::Command {
        program: PathBuf::from(HELPER),
        args: vec!["record".to_owned(), scratch.path().display().to_string()],
    };
    let created = created_sentinel_key();

    let outcome = keymaster::receiver::from_config(&configured)
        .receive(&metadata(created.hash()), created.plaintext());

    assert!(outcome.is_delivered(), "{outcome}");
    assert_present(
        "the envelope the configured adapter received",
        &recorded(scratch.path(), "envelope.json"),
    );
}
