//! State's contract with the rest of the world: concurrent writers cannot
//! lose an update, and the secret sentinel never reaches a state file, a
//! temporary file, a filename, or an error.

use openrouter_keymaster_core::test_support as support;

use std::thread;

use openrouter_keymaster_core::config::Receiver;
use openrouter_keymaster_core::ids::{
    Address, KeyHash, OperationId, ReceiverFingerprint, RemoteName,
};
use openrouter_keymaster_core::state::{BeginCreate, Phase, State, StateFile, Transition};
use support::sentinel::{SECRET_SENTINEL_KEY, assert_absent, assert_absent_under};
use tempfile::TempDir;
use time::OffsetDateTime;

/// How many threads race to write the same state file.
const WRITERS: usize = 8;

fn address(value: &str) -> Address {
    Address::parse(value).expect("a valid test address")
}

fn hash(value: &str) -> KeyHash {
    KeyHash::parse(value).expect("a valid test hash")
}

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_767_225_600 + seconds).expect("a valid instant")
}

fn name(value: &str) -> RemoteName {
    RemoteName::parse(value).expect("a valid remote name")
}

/// The fingerprint of a configured receiver, the way a real run derives it.
fn receiver_fingerprint() -> ReceiverFingerprint {
    Receiver::File {
        path: "/var/lib/keymaster/jobfeed.key".into(),
    }
    .fingerprint()
}

/// A state file inside a fresh temporary directory.
fn scratch() -> (TempDir, StateFile) {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let file = StateFile::new(directory.path().join("state").join("state.json"));
    (directory, file)
}

/// State with one binding of every shape a real run produces.
fn populated() -> State {
    let jobfeed = address("jobfeed");
    let mut state = State::new();

    state
        .begin_create(
            &jobfeed,
            BeginCreate {
                operation: OperationId::parse("op-0001").expect("a valid operation id"),
                generation: 1,
                name: name("golf-jobfeed"),
                workspace: None,
                receiver: receiver_fingerprint(),
            },
            at(0),
        )
        .expect("starting a create");
    for (step, transition) in [
        Transition::Created {
            hash: hash("keyhash-0001"),
        },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::Delivered,
    ]
    .into_iter()
    .enumerate()
    {
        state
            .advance_key(&jobfeed, transition, at(step as i64 + 1))
            .expect("advancing the operation");
    }
    state.promote_key(&jobfeed, at(5)).expect("promoting");
    state
}

#[test]
fn concurrent_writers_cannot_lose_a_serial_update() {
    let (_directory, file) = scratch();
    let mut initial = State::new();
    file.lock()
        .expect("taking the lock")
        .write(&mut initial)
        .expect("writing the first state");

    thread::scope(|scope| {
        for writer in 0..WRITERS {
            let file = file.clone();
            scope.spawn(move || {
                let address = address(&format!("writer{writer}"));
                let hash = hash(&format!("keyhash-{writer}"));
                // Contention is an error, not a wait, so a racing writer
                // retries rather than blocking (ADR-0001's single-writer
                // model; this test is what proves nothing is lost).
                loop {
                    let Ok(lock) = file.lock() else {
                        thread::yield_now();
                        continue;
                    };
                    let mut state = lock.read().expect("reading state");
                    state
                        .bind_key(&address, hash.clone(), 1, at(0))
                        .expect("binding");
                    if lock.write(&mut state).is_ok() {
                        return;
                    }
                }
            });
        }
    });

    let final_state = file.read().expect("reading state back");
    assert_eq!(final_state.serial(), WRITERS as u64 + 1);
    assert_eq!(final_state.keys().len(), WRITERS);
    for writer in 0..WRITERS {
        assert!(
            final_state
                .key(&address(&format!("writer{writer}")))
                .is_some(),
            "writer {writer} lost its binding"
        );
    }
}

#[test]
fn nothing_a_state_file_holds_can_carry_the_sentinel() {
    let (directory, file) = scratch();
    let mut state = populated();
    file.lock()
        .expect("taking the lock")
        .write(&mut state)
        .expect("writing state");

    assert_absent_under(directory.path());
    assert_absent(
        "the serialized state",
        &serde_json::to_string(&state).expect("serializing state"),
    );
}

#[test]
fn key_plaintext_cannot_become_an_identifier_and_is_not_echoed_when_refused() {
    let error = KeyHash::parse(SECRET_SENTINEL_KEY).expect_err("plaintext is not a hash");
    assert_absent("the key hash refusal", &error.to_string());

    // An address and an operation id are made of the characters a credential
    // uses, so neither can be left to a shape check.
    let error = Address::parse(SECRET_SENTINEL_KEY).expect_err("plaintext is not an address");
    assert_absent("the address refusal", &error.to_string());
    let error =
        OperationId::parse(SECRET_SENTINEL_KEY).expect_err("plaintext is not an operation id");
    assert_absent("the operation id refusal", &error.to_string());
    let error = RemoteName::parse(SECRET_SENTINEL_KEY).expect_err("plaintext is not a name");
    assert_absent("the remote name refusal", &error.to_string());

    // A fingerprint is a digest, so a description of the destination — with or
    // without a secret in it — is not a fingerprint at all.
    let error = ReceiverFingerprint::parse(&format!("command:/bin/echo {SECRET_SENTINEL_KEY}"))
        .expect_err("only a digest is a fingerprint");
    assert_absent("the fingerprint refusal", &error.to_string());
    assert_eq!(
        receiver_fingerprint().as_str().len(),
        64,
        "a real receiver fingerprints to a digest"
    );
}

#[test]
fn a_sentinel_in_a_state_file_is_refused_without_being_echoed() {
    let (_directory, file) = scratch();
    std::fs::create_dir_all(file.path().parent().expect("the state directory"))
        .expect("creating the state directory");
    std::fs::write(
        file.path(),
        format!(
            r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{{
            "origin":"created","current":{{"hash":"{SECRET_SENTINEL_KEY}","generation":1,
            "bound_at":"2026-01-01T00:00:00Z"}}}}}}}}"#
        ),
    )
    .expect("writing a hostile document");

    let error = file.read().expect_err("plaintext is not a hash");
    assert_eq!(error.kind(), "state_parse");
    assert_absent("the state read error", &error.to_string());
    assert_absent("the state read error", &format!("{error:?}"));
}

#[test]
fn an_interrupted_operation_survives_a_reopen_with_its_phase_intact() {
    let (_directory, file) = scratch();
    let jobfeed = address("jobfeed");

    let mut state = State::new();
    state
        .begin_create(
            &jobfeed,
            BeginCreate {
                operation: OperationId::parse("op-0002").expect("a valid operation id"),
                generation: 1,
                name: name("golf-jobfeed"),
                workspace: None,
                receiver: Receiver::Command {
                    program: "/usr/local/bin/receiver".into(),
                    args: vec![
                        "add-file".to_owned(),
                        "jobfeed_openrouter_api_key".to_owned(),
                    ],
                }
                .fingerprint(),
            },
            at(0),
        )
        .expect("starting a create");
    file.lock()
        .expect("taking the lock")
        .write(&mut state)
        .expect("writing state");

    let reopened = file.read().expect("reading state back");
    let pending = reopened
        .key(&jobfeed)
        .and_then(|binding| binding.pending())
        .expect("the interrupted operation");
    assert_eq!(pending.phase, Phase::CreateStarted);
    assert_eq!(pending.hash, None);
    assert_eq!(pending.id.as_str(), "op-0002");
    assert_eq!(pending.name.as_str(), "golf-jobfeed");
}
