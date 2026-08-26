//! State model, transition, and persistence tests.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::persist::Fault;
use super::*;
use crate::files::{containing_directory, create_private_new, temporary_path};

/// The sentinel from the shared test harness. Repeated here because unit
/// tests cannot reach `tests/support`.
const SECRET_SENTINEL_KEY: &str = "sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE";

/// A receiver fingerprint as it appears in a state file: a hex digest.
const FINGERPRINT: &str = "0707070707070707070707070707070707070707070707070707070707070707";

/// A state document that parses and passes every invariant.
const EMPTY_DOCUMENT: &str = r#"{"version":1,"serial":1,"keys":{},"guardrails":{}}"#;

fn address(value: &str) -> Address {
    Address::parse(value).expect("a valid test address")
}

fn hash(value: &str) -> KeyHash {
    KeyHash::parse(value).expect("a valid test hash")
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse(value).expect("a valid test UUID")
}

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_767_225_600 + seconds).expect("a valid instant")
}

fn begin(generation: u32) -> BeginCreate {
    BeginCreate {
        operation: OperationId::parse("op-0001").expect("a valid operation id"),
        generation,
        name: RemoteName::parse("golf-jobfeed").expect("a valid remote name"),
        workspace: Some(uuid("6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b")),
        receiver: ReceiverFingerprint::from_digest([7; 32]),
    }
}

/// State whose one address has a pending operation in `phase`.
fn in_phase(phase: Phase) -> (State, Address) {
    let jobfeed = address("jobfeed");
    let mut state = State::new();
    state
        .begin_create(&jobfeed, begin(1), at(0))
        .expect("starting a create");

    let path: &[Transition] = match phase {
        Phase::CreateStarted => &[],
        Phase::CreateAmbiguous => &[Transition::CreateAmbiguous],
        Phase::Created => &[Transition::Created { hash: hash("h1") }],
        Phase::Secured => &[
            Transition::Created { hash: hash("h1") },
            Transition::Secured,
        ],
        Phase::DeliveryStarted => &[
            Transition::Created { hash: hash("h1") },
            Transition::Secured,
            Transition::DeliveryStarted,
        ],
        Phase::DeliveryAmbiguous => &[
            Transition::Created { hash: hash("h1") },
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::DeliveryAmbiguous,
        ],
        Phase::Delivered => &[
            Transition::Created { hash: hash("h1") },
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::Delivered,
        ],
    };
    for (step, transition) in path.iter().enumerate() {
        state
            .advance_key(&jobfeed, transition.clone(), at(step as i64 + 1))
            .unwrap_or_else(|error| panic!("reaching {phase}: {error}"));
    }
    assert_eq!(
        state
            .key(&jobfeed)
            .and_then(KeyBinding::pending)
            .map(|pending| pending.phase),
        Some(phase)
    );
    (state, jobfeed)
}

/// A state file in a fresh temporary directory.
struct Scratch {
    _directory: TempDir,
    path: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("state").join("state.json");
        Self {
            _directory: directory,
            path,
        }
    }

    fn file(&self) -> StateFile {
        StateFile::new(&self.path)
    }

    fn directory(&self) -> &Path {
        self.path.parent().expect("the state directory")
    }

    /// Writes state through the production path and returns it.
    fn store(&self, state: &mut State) {
        let file = self.file();
        let lock = file.lock().expect("taking the lock");
        lock.write(state).expect("writing state");
    }

    /// Every file beside the state file, by name.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.directory())
            .expect("listing the state directory")
            .map(|entry| {
                entry
                    .expect("a directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }
}

/// Reads a hand-written document through the production reader.
fn read_document(json: &str) -> Result<State, StateError> {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("state.json");
    fs::write(&path, json).expect("writing the document");
    StateFile::new(&path).read()
}

// --- the journal -----------------------------------------------------------

#[test]
fn a_new_state_owns_nothing_and_has_never_been_written() {
    let state = State::new();
    assert_eq!(state.version(), SCHEMA_VERSION);
    assert_eq!(state.serial(), 0);
    assert!(state.keys().is_empty());
    assert!(state.guardrails().is_empty());
}

#[test]
fn the_create_and_delivery_sequence_ends_in_a_promoted_current_key() {
    let (mut state, jobfeed) = in_phase(Phase::Delivered);
    state.promote_key(&jobfeed, at(9)).expect("promoting");

    let binding = state.key(&jobfeed).expect("the binding");
    assert_eq!(binding.origin(), Origin::Created);
    assert!(binding.pending().is_none());
    assert!(binding.retained().is_empty());

    let current = binding.current().expect("a current key");
    assert_eq!(current.hash, hash("h1"));
    assert_eq!(current.generation, 1);
    assert_eq!(current.bound_at, at(9));
    // Where the plaintext went, so a later change of destination is a reason
    // to replace the key rather than an invisible difference.
    assert_eq!(
        current.receiver,
        Some(ReceiverFingerprint::from_digest([7; 32]))
    );
}

#[test]
fn an_imported_key_records_no_delivery_destination() {
    let mut state = State::new();
    let jobfeed = address("jobfeed");
    state
        .bind_key(&jobfeed, hash("h1"), 1, at(0))
        .expect("binding");

    let current = state
        .key(&jobfeed)
        .and_then(KeyBinding::current)
        .expect("a current key");
    assert_eq!(current.receiver, None);
}

#[test]
fn binding_a_key_always_records_an_import_that_reads_back() {
    // `bind_key` is the import path and records `imported` whatever the caller
    // thinks. A key Keymaster created is bound by promotion, which is the only
    // place that knows where the plaintext went; binding one here would write
    // a created key with no destination — the shape the reader refuses — so
    // the type no longer offers the choice.
    let scratch = Scratch::new();
    let jobfeed = address("jobfeed");
    let mut state = State::new();
    state
        .begin_create(&jobfeed, begin(1), at(0))
        .expect("starting a create");
    state
        .abandon_create(&jobfeed)
        .expect("a create the server refused");
    assert_eq!(
        state.key(&jobfeed).expect("the binding").origin(),
        Origin::Created
    );

    state
        .bind_key(&jobfeed, hash("h1"), 1, at(1))
        .expect("importing a key instead");

    let binding = state.key(&jobfeed).expect("the binding");
    assert_eq!(binding.origin(), Origin::Imported);
    assert_eq!(binding.current().expect("a current key").receiver, None);

    scratch.store(&mut state);
    assert_eq!(scratch.file().read().expect("reading back"), state);
}

#[test]
fn a_write_refuses_a_state_the_reader_would_reject() {
    // Every public path keeps a binding consistent, so this has to reach past
    // them to build the shape at all — which is the point. The check makes the
    // run that produced an inconsistency fail, rather than the next run to
    // open a file that can never be read again.
    let scratch = Scratch::new();
    let (mut state, jobfeed) = in_phase(Phase::Delivered);
    state.promote_key(&jobfeed, at(9)).expect("promoting");
    scratch.store(&mut state);
    let stored = scratch.file().read().expect("reading back");

    state
        .keys
        .get_mut(&jobfeed)
        .and_then(|binding| binding.current.as_mut())
        .expect("a current key")
        .receiver = None;

    let file = scratch.file();
    let lock = file.lock().expect("taking the lock");
    let error = lock
        .write(&mut state)
        .expect_err("a state the reader would refuse");
    assert_eq!(error.kind(), "state_inconsistent", "{error}");
    assert!(error.to_string().contains("records no receiver"), "{error}");
    drop(lock);

    // The file still holds what was there before, at the serial it had.
    assert_eq!(scratch.file().read().expect("reading back"), stored);
}

#[test]
fn rotating_an_imported_key_leaves_a_binding_that_reads_back() {
    // Keymaster created and delivered the key this address now holds, so the
    // binding is `created` and records where the plaintext went. Writing
    // anything else here would produce a file the reader refuses.
    let mut state = State::new();
    let jobfeed = address("jobfeed");
    state
        .bind_key(&jobfeed, hash("h0"), 1, at(0))
        .expect("importing");
    state
        .begin_create(&jobfeed, begin(2), at(1))
        .expect("starting a rotation");
    for transition in [
        Transition::Created { hash: hash("h1") },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::Delivered,
    ] {
        state
            .advance_key(&jobfeed, transition, at(2))
            .expect("advancing");
    }
    state.promote_key(&jobfeed, at(3)).expect("promoting");

    let binding = state.key(&jobfeed).expect("the binding");
    assert_eq!(binding.origin(), Origin::Created);
    assert_eq!(binding.retained()[0].hash, hash("h0"));

    let scratch = Scratch::new();
    scratch.store(&mut state);
    assert_eq!(scratch.file().read().expect("reading back"), state);
}

/// State whose address holds `h1` at generation 2 and retains `h0`.
fn after_a_rotation() -> (State, Address) {
    let (mut state, jobfeed) = (State::new(), address("jobfeed"));
    state
        .bind_key(&jobfeed, hash("h0"), 1, at(0))
        .expect("importing the predecessor");
    state
        .begin_create(&jobfeed, begin(2), at(1))
        .expect("starting a rotation");
    for transition in [
        Transition::Created { hash: hash("h1") },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::Delivered,
    ] {
        state
            .advance_key(&jobfeed, transition, at(2))
            .expect("advancing");
    }
    state.promote_key(&jobfeed, at(3)).expect("promoting");
    (state, jobfeed)
}

#[test]
fn a_retained_hash_can_be_dropped_and_only_a_retained_one_can() {
    let (mut state, jobfeed) = after_a_rotation();

    let dropped = state
        .drop_retained(&jobfeed, &hash("h0"))
        .expect("dropping a retained hash");
    assert_eq!(dropped.hash, hash("h0"));
    assert_eq!(dropped.generation, 1);
    assert!(
        state
            .key(&jobfeed)
            .expect("the binding")
            .retained()
            .is_empty()
    );

    // The current key is deliberately out of reach: dropping it would leave a
    // live spending credential nothing names.
    assert_eq!(
        state.drop_retained(&jobfeed, &hash("h1")),
        Err(TransitionError::HashNotRetained {
            address: jobfeed.clone(),
            hash: hash("h1"),
        })
    );
    assert_eq!(
        state.drop_retained(&address("nowhere"), &hash("h0")),
        Err(TransitionError::HashNotRetained {
            address: address("nowhere"),
            hash: hash("h0"),
        })
    );
    assert!(
        state
            .key(&jobfeed)
            .expect("the binding")
            .current()
            .is_some()
    );
}

#[test]
fn a_deleted_generation_stays_spent_at_the_address() {
    // The retained candidate outranks the current key, which is what an
    // abandoned rotation leaves. Deleting it removes the only entry recording
    // that generation 2 was ever used here — so without a high-water mark the
    // next create would hand a different remote key the same number.
    let (mut state, jobfeed) = (State::new(), address("jobfeed"));
    state
        .bind_key(&jobfeed, hash("h1"), 1, at(0))
        .expect("binding the working key");
    state
        .begin_create(&jobfeed, begin(2), at(1))
        .expect("starting a rotation");
    state
        .advance_key(&jobfeed, Transition::Created { hash: hash("h2") }, at(2))
        .expect("the create returned a hash");
    state
        .retire_candidate(&jobfeed, at(3))
        .expect("the rotation is abandoned, and its key retained");
    assert_eq!(
        state
            .key(&jobfeed)
            .expect("the binding")
            .highest_generation(),
        2
    );

    state
        .drop_retained(&jobfeed, &hash("h2"))
        .expect("OpenRouter confirmed the key is gone");

    let binding = state.key(&jobfeed).expect("the binding");
    assert_eq!(binding.settled_generation(), 1, "only h1 is still held");
    assert_eq!(binding.generation_floor(), 2);
    assert_eq!(
        binding.highest_generation(),
        2,
        "the number is spent even though nothing holds it any more"
    );
    assert_eq!(
        state.begin_create(&jobfeed, begin(2), at(4)),
        Err(TransitionError::GenerationNotMonotonic {
            address: jobfeed.clone(),
            recorded: 2,
            requested: 2,
        }),
        "reusing a deleted key's generation is refused"
    );
    state
        .begin_create(&jobfeed, begin(3), at(5))
        .expect("the next free generation is 3");
}

/// Decommissioning is the one transition that empties a current slot without
/// filling it, and what it leaves has to be a state a file can hold.
#[test]
fn a_decommissioned_address_keeps_its_hash_its_number_and_its_binding() {
    let (mut state, jobfeed) = (State::new(), address("jobfeed"));
    state
        .bind_key(&jobfeed, hash("h1"), 1, at(0))
        .expect("binding the working key");

    let retained = state
        .decommission_current(&jobfeed, &hash("h1"), RetainedStatus::Retired, at(1))
        .expect("a read proved the key is out of service");

    assert_eq!(retained.generation, 1);
    let binding = state.key(&jobfeed).expect("the address is still bound");
    assert_eq!(binding.current(), None);
    assert_eq!(binding.retained().len(), 1);
    assert_eq!(
        binding.highest_generation(),
        1,
        "the number is still recorded, so a successor takes a higher one"
    );

    // And the shape survives a round trip, which is what proves no invariant
    // refuses a binding that holds a retained hash and no current one.
    let scratch = Scratch::new();
    let file = scratch.file();
    file.lock()
        .expect("the lock")
        .write(&mut state)
        .expect("writing a decommissioned binding");
    let reread = file.read().expect("reading it back");
    assert_eq!(reread.key(&jobfeed).expect("the binding").current(), None);
}

/// The two things `decommission_current` refuses, both of which the command
/// above it checks first: this is the floor under that check, not a duplicate
/// of it.
#[test]
fn decommissioning_needs_the_current_hash_and_no_operation_in_progress() {
    let (mut state, jobfeed) = (State::new(), address("jobfeed"));
    state
        .bind_key(&jobfeed, hash("h1"), 1, at(0))
        .expect("binding the working key");

    assert_eq!(
        state.decommission_current(&jobfeed, &hash("h2"), RetainedStatus::Retired, at(1)),
        Err(TransitionError::HashNotCurrent {
            address: jobfeed.clone(),
            hash: hash("h2"),
        }),
        "a hash the address does not use is not something to switch off"
    );

    state
        .begin_create(&jobfeed, begin(2), at(2))
        .expect("starting a rotation");
    assert_eq!(
        state.decommission_current(&jobfeed, &hash("h1"), RetainedStatus::Retired, at(3)),
        Err(TransitionError::AlreadyPending {
            address: jobfeed.clone(),
            phase: Phase::CreateStarted,
        }),
        "the successor being created would be promoted into the emptied slot"
    );
    assert_eq!(
        state
            .key(&jobfeed)
            .expect("the binding")
            .current()
            .map(|current| current.hash.clone()),
        Some(hash("h1")),
        "a refusal changes nothing"
    );
}

#[test]
fn a_generation_floor_survives_a_write_and_an_import_over_it() {
    let scratch = Scratch::new();
    let (mut state, jobfeed) = (State::new(), address("jobfeed"));
    state
        .begin_create(&jobfeed, begin(2), at(0))
        .expect("starting a create");
    state
        .advance_key(&jobfeed, Transition::Created { hash: hash("h2") }, at(1))
        .expect("the create returned a hash");
    state
        .retire_candidate(&jobfeed, at(2))
        .expect("the attempt is dead");
    state
        .drop_retained(&jobfeed, &hash("h2"))
        .expect("deleting it");

    scratch.store(&mut state);
    let reloaded = scratch.file().read().expect("reading back");
    assert_eq!(reloaded, state, "the high-water mark round-trips");
    assert_eq!(
        reloaded
            .key(&jobfeed)
            .expect("the binding")
            .generation_floor(),
        2
    );

    // Rebuilding lost state by importing must not release the number either:
    // `bind_key` replaces the binding wholesale, and the floor comes with it.
    let mut state = reloaded;
    assert!(
        state.bind_key(&jobfeed, hash("h9"), 2, at(3)).is_err(),
        "generation 2 is spent"
    );
    state
        .bind_key(&jobfeed, hash("h9"), 3, at(3))
        .expect("importing above the floor");
    assert_eq!(
        state.key(&jobfeed).expect("the binding").generation_floor(),
        2
    );
}

#[test]
fn a_state_file_written_before_the_floor_existed_defaults_to_none() {
    // The field is absent from every file an earlier build wrote, and zero is
    // the right answer: such a file's floor is whatever its own entries say.
    let document = r#"{
        "version": 1,
        "serial": 3,
        "keys": {
            "jobfeed": {
                "origin": "imported",
                "current": { "hash": "h1", "generation": 4,
                             "bound_at": "2026-01-01T00:00:00Z" }
            }
        },
        "guardrails": {}
    }"#;

    let state = read_document(document).expect("an older state file still reads");
    let binding = state.key(&address("jobfeed")).expect("the binding");
    assert_eq!(binding.generation_floor(), 0);
    assert_eq!(binding.highest_generation(), 4);

    // And a binding with no floor serializes without the field, so a file this
    // build writes is no larger than the one it read.
    let json = serde_json::to_string(&state).expect("serializing");
    assert!(!json.contains("generation_floor"), "{json}");
}

#[test]
fn forgetting_a_key_hands_back_every_hash_it_released() {
    let (mut state, jobfeed) = after_a_rotation();

    let forgotten = state
        .forget_key(&jobfeed)
        .expect("nothing is pending")
        .expect("a binding was there");

    assert_eq!(
        forgotten.current().expect("a current key").hash,
        hash("h1"),
        "the caller can report what it let go of"
    );
    assert_eq!(forgotten.retained()[0].hash, hash("h0"));
    assert!(state.key(&jobfeed).is_none());
    assert_eq!(
        state.forget_key(&jobfeed),
        Ok(None),
        "forgetting an address that owns nothing is a no-op, not an error"
    );
}

#[test]
fn forgetting_a_key_is_refused_while_an_operation_is_in_progress() {
    let (mut state, jobfeed) = in_phase(Phase::CreateAmbiguous);

    assert_eq!(
        state.forget_key(&jobfeed),
        Err(TransitionError::AlreadyPending {
            address: jobfeed.clone(),
            phase: Phase::CreateAmbiguous,
        }),
        "the journal is the only record that the attempt happened"
    );
    assert!(
        state
            .key(&jobfeed)
            .expect("the binding")
            .pending()
            .is_some()
    );
}

#[test]
fn forgetting_a_guardrail_removes_only_that_binding() {
    let mut state = State::new();
    let cheap = address("cheap");
    state
        .bind_guardrail(
            &cheap,
            uuid("6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b"),
            Origin::Imported,
            at(0),
        )
        .expect("binding a guardrail");
    state
        .bind_key(&cheap, hash("h1"), 1, at(0))
        .expect("binding a key at the same local name");

    let forgotten = state
        .forget_guardrail(&cheap)
        .expect("a guardrail was there");

    assert_eq!(forgotten.id, uuid("6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b"));
    assert!(state.guardrail(&cheap).is_none());
    assert!(
        state.key(&cheap).is_some(),
        "a key and a guardrail can share a local name, and forgetting one keeps the other"
    );
    assert!(state.forget_guardrail(&cheap).is_none());
}

#[test]
fn a_current_key_whose_origin_and_delivery_record_disagree_is_refused() {
    // The planner reads the delivery record to decide whether a changed
    // destination is a reason to replace a live credential, so a created key
    // with no record would read as an imported one and silently turn "the
    // receiver moved" into "nothing to do". Both halves of the shape are
    // refused rather than interpreted.
    let created_without = r#"{"version":1,"serial":1,"guardrails":{},"keys":{"jobfeed":{
        "origin":"created","current":{"hash":"h1","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}}}}"#;
    let error = read_document(created_without).expect_err("a created key with no receiver");
    assert_eq!(error.kind(), "state_corrupt", "{error}");
    assert!(error.to_string().contains("records no receiver"), "{error}");

    let imported_with = format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{{
        "origin":"imported","current":{{"hash":"h1","generation":1,
        "bound_at":"2026-01-01T00:00:00Z","receiver":"{FINGERPRINT}"}}}}}}}}"#
    );
    let error = read_document(&imported_with).expect_err("an imported key with a receiver");
    assert_eq!(error.kind(), "state_corrupt", "{error}");
    assert!(error.to_string().contains("was imported"), "{error}");
}

#[test]
fn both_delivery_records_a_current_key_may_have_read_back() {
    let created = format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{{
        "origin":"created","current":{{"hash":"h1","generation":1,
        "bound_at":"2026-01-01T00:00:00Z","receiver":"{FINGERPRINT}"}}}}}}}}"#
    );
    let state = read_document(&created).expect("a created key that records its receiver");
    assert_eq!(
        state
            .key(&address("jobfeed"))
            .and_then(KeyBinding::current)
            .and_then(|current| current.receiver.clone()),
        Some(ReceiverFingerprint::from_digest([7; 32]))
    );

    let imported = r#"{"version":1,"serial":1,"guardrails":{},"keys":{"jobfeed":{
        "origin":"imported","current":{"hash":"h1","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}}}}"#;
    let state = read_document(imported).expect("an imported key that records none");
    assert_eq!(
        state
            .key(&address("jobfeed"))
            .and_then(KeyBinding::current)
            .and_then(|current| current.receiver.clone()),
        None
    );
}

#[test]
fn a_transition_is_legal_from_exactly_one_phase() {
    let phases = [
        Phase::CreateStarted,
        Phase::CreateAmbiguous,
        Phase::Created,
        Phase::Secured,
        Phase::DeliveryStarted,
        Phase::DeliveryAmbiguous,
        Phase::Delivered,
    ];
    let transitions = [
        Transition::CreateAmbiguous,
        Transition::Created { hash: hash("h2") },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::DeliveryAmbiguous,
        Transition::DeliveryRejected,
        Transition::Delivered,
    ];

    for phase in phases {
        for transition in &transitions {
            let (mut state, jobfeed) = in_phase(phase);
            let legal = state
                .advance_key(&jobfeed, transition.clone(), at(50))
                .is_ok();
            assert_eq!(
                legal,
                transition.requires() == phase,
                "{transition:?} from {phase}"
            );
        }
    }
}

/// Every phase, so a table can be exhaustive rather than representative.
const ALL_PHASES: [Phase; 7] = [
    Phase::CreateStarted,
    Phase::CreateAmbiguous,
    Phase::Created,
    Phase::Secured,
    Phase::DeliveryStarted,
    Phase::DeliveryAmbiguous,
    Phase::Delivered,
];

/// The two phases in which nobody knows whether a key exists.
const UNKNOWN_EXISTENCE: [Phase; 2] = [Phase::CreateStarted, Phase::CreateAmbiguous];

#[test]
fn an_attestation_of_absence_is_legal_only_where_existence_is_unknown() {
    for phase in ALL_PHASES {
        let (mut state, jobfeed) = in_phase(phase);
        let cleared = state.clear_ambiguous_create(&jobfeed);
        assert_eq!(
            cleared.is_ok(),
            UNKNOWN_EXISTENCE.contains(&phase),
            "attesting absence from {phase}"
        );
        if cleared.is_ok() {
            assert!(
                state.key(&jobfeed).and_then(KeyBinding::pending).is_none(),
                "the operation is gone from {phase}"
            );
        } else {
            assert_eq!(
                state
                    .key(&jobfeed)
                    .and_then(KeyBinding::pending)
                    .map(|pending| pending.phase),
                Some(phase),
                "a refused attestation changes nothing"
            );
        }
    }
}

#[test]
fn a_leaked_candidate_is_bound_only_where_the_hash_is_still_unknown() {
    for phase in ALL_PHASES {
        let (mut state, jobfeed) = in_phase(phase);
        let bound = state.retain_leaked_candidate(&jobfeed, hash("leaked"), at(20));
        assert_eq!(
            bound.is_ok(),
            UNKNOWN_EXISTENCE.contains(&phase),
            "binding a leaked hash from {phase}"
        );
        let Ok(retained) = bound else { continue };

        assert_eq!(retained.status, RetainedStatus::FailedCandidate);
        assert_eq!(retained.generation, 1);
        let binding = state.key(&jobfeed).expect("the binding");
        assert!(
            binding.pending().is_none(),
            "binding the leak closes the operation"
        );
        assert_eq!(
            binding.retained().len(),
            1,
            "and the hash is tracked, never promoted"
        );
        assert!(
            binding.current().is_none(),
            "a found hash is never a working key: its plaintext is gone"
        );
    }
}

#[test]
fn a_leaked_hash_another_address_owns_is_refused() {
    let (mut state, jobfeed) = in_phase(Phase::CreateAmbiguous);
    let payroll = address("payroll");
    state
        .bind_key(&payroll, hash("leaked"), 1, at(0))
        .expect("binding the hash somewhere else first");

    let refused = state
        .retain_leaked_candidate(&jobfeed, hash("leaked"), at(20))
        .expect_err("one remote key belongs to one local address");
    assert!(
        matches!(refused, TransitionError::HashOwnedElsewhere { .. }),
        "{refused:?}"
    );
    assert_eq!(
        state
            .key(&jobfeed)
            .and_then(KeyBinding::pending)
            .map(|pending| pending.phase),
        Some(Phase::CreateAmbiguous),
        "a refused binding leaves the operation exactly as it was"
    );
}

#[test]
fn a_candidate_is_retired_only_from_a_phase_whose_key_is_dead() {
    // Every phase that carries a hash except `delivered`, which is not dead:
    // `promote_key` finishes that one.
    let dead = [
        Phase::Created,
        Phase::Secured,
        Phase::DeliveryStarted,
        Phase::DeliveryAmbiguous,
    ];

    for phase in ALL_PHASES {
        let (mut state, jobfeed) = in_phase(phase);
        let retired = state.retire_candidate(&jobfeed, at(20));
        assert_eq!(
            retired.is_ok(),
            dead.contains(&phase),
            "retiring a candidate from {phase}"
        );
        let Ok(retained) = retired else {
            assert_eq!(
                state
                    .key(&jobfeed)
                    .and_then(KeyBinding::pending)
                    .map(|pending| pending.phase),
                Some(phase),
                "a refused retirement changes nothing"
            );
            continue;
        };

        assert_eq!(retained.hash, hash("h1"), "the journaled hash is kept");
        assert_eq!(retained.status, RetainedStatus::FailedCandidate);
        let binding = state.key(&jobfeed).expect("the binding");
        assert!(binding.pending().is_none(), "the dead operation is cleared");
        assert!(
            binding.current().is_none(),
            "a dead key is never promoted to current"
        );
    }
}

#[test]
fn a_successor_can_be_created_once_the_dead_candidate_is_retired() {
    // The point of retiring: `begin_create` refuses while an operation stands,
    // and the successor's generation has to clear the one the dead key holds.
    let (mut state, jobfeed) = in_phase(Phase::Secured);
    state
        .retire_candidate(&jobfeed, at(20))
        .expect("retiring the dead candidate");

    assert!(
        state.begin_create(&jobfeed, begin(1), at(21)).is_err(),
        "the retained candidate still holds generation 1"
    );
    state
        .begin_create(&jobfeed, begin(2), at(22))
        .expect("the successor takes the next generation");
    assert_eq!(
        state
            .key(&jobfeed)
            .and_then(KeyBinding::pending)
            .map(|pending| pending.generation),
        Some(2)
    );
}

#[test]
fn a_retired_candidate_survives_a_round_trip_through_the_file() {
    let scratch = Scratch::new();
    let (mut state, jobfeed) = in_phase(Phase::DeliveryAmbiguous);
    state
        .retire_candidate(&jobfeed, at(20))
        .expect("retiring the dead candidate");

    let file = StateFile::new(&scratch.path);
    let lock = file.lock().expect("the lock");
    lock.write(&mut state).expect("writing the state");
    drop(lock);

    let reopened = file
        .read()
        .expect("the reader accepts what the writer wrote");
    let binding = reopened.key(&jobfeed).expect("the binding");
    assert_eq!(binding.retained().len(), 1);
    assert_eq!(binding.retained()[0].hash, hash("h1"));
    assert_eq!(
        binding.retained()[0].status,
        RetainedStatus::FailedCandidate
    );
    assert!(binding.pending().is_none());
}

#[test]
fn a_definite_receiver_rejection_returns_the_operation_to_secured() {
    let (mut state, jobfeed) = in_phase(Phase::DeliveryStarted);
    state
        .advance_key(&jobfeed, Transition::DeliveryRejected, at(9))
        .expect("recording the rejection");

    let pending = state
        .key(&jobfeed)
        .and_then(KeyBinding::pending)
        .expect("the operation stays pending");
    assert_eq!(pending.phase, Phase::Secured);
    assert_eq!(pending.hash, Some(hash("h1")));
}

#[test]
fn a_refused_delivery_can_never_be_attempted_again() {
    let (mut state, jobfeed) = in_phase(Phase::DeliveryStarted);
    state
        .advance_key(&jobfeed, Transition::DeliveryRejected, at(9))
        .expect("recording the rejection");

    // The rejection puts the operation back at `secured`, which is the phase
    // delivery starts from — the marker is what keeps it from starting again.
    let pending = state
        .key(&jobfeed)
        .and_then(KeyBinding::pending)
        .expect("the operation stays pending");
    assert_eq!(pending.phase, Phase::Secured);
    assert_eq!(pending.delivery_rejected_at, Some(at(9)));

    assert_eq!(
        state.advance_key(&jobfeed, Transition::DeliveryStarted, at(10)),
        Err(TransitionError::DeliveryRefused {
            address: jobfeed.clone()
        })
    );
    assert_eq!(
        state
            .key(&jobfeed)
            .and_then(KeyBinding::pending)
            .expect("the operation is unchanged")
            .phase,
        Phase::Secured
    );

    // An operation that was never refused still delivers normally.
    let (mut fresh, address) = in_phase(Phase::Secured);
    assert!(
        fresh
            .key(&address)
            .and_then(KeyBinding::pending)
            .expect("the operation")
            .delivery_rejected_at
            .is_none()
    );
    assert!(
        fresh
            .advance_key(&address, Transition::DeliveryStarted, at(10))
            .is_ok()
    );
}

#[test]
fn a_refused_delivery_survives_a_reopen_and_is_still_refused() {
    let scratch = Scratch::new();
    let (mut state, jobfeed) = in_phase(Phase::DeliveryStarted);
    state
        .advance_key(&jobfeed, Transition::DeliveryRejected, at(9))
        .expect("recording the rejection");
    scratch.store(&mut state);

    let mut reopened = scratch.file().read().expect("reading state back");
    assert_eq!(reopened, state);
    assert_eq!(
        reopened
            .key(&jobfeed)
            .and_then(KeyBinding::pending)
            .expect("the operation survived")
            .delivery_rejected_at,
        Some(at(9))
    );
    assert_eq!(
        reopened.advance_key(&jobfeed, Transition::DeliveryStarted, at(10)),
        Err(TransitionError::DeliveryRefused { address: jobfeed })
    );
}

#[test]
fn an_ambiguous_create_records_no_hash_because_none_came_back() {
    let (state, jobfeed) = in_phase(Phase::CreateAmbiguous);
    let pending = state
        .key(&jobfeed)
        .and_then(KeyBinding::pending)
        .expect("the operation");
    assert_eq!(pending.hash, None);
    assert_eq!(pending.id.as_str(), "op-0001");
    assert_eq!(pending.name.as_str(), "golf-jobfeed");
    assert_eq!(
        pending.workspace,
        Some(uuid("6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b"))
    );
    assert_eq!(pending.receiver, ReceiverFingerprint::from_digest([7; 32]));
}

#[test]
fn a_transition_needs_an_operation_to_move() {
    let mut state = State::new();
    let jobfeed = address("jobfeed");
    assert_eq!(
        state.advance_key(&jobfeed, Transition::Secured, at(1)),
        Err(TransitionError::NotPending {
            address: jobfeed.clone()
        })
    );
    assert_eq!(
        state.promote_key(&jobfeed, at(1)),
        Err(TransitionError::NotPending {
            address: jobfeed.clone()
        })
    );
    assert_eq!(
        state.abandon_create(&jobfeed),
        Err(TransitionError::NotPending { address: jobfeed })
    );
}

#[test]
fn a_second_operation_cannot_start_while_one_is_pending() {
    let (mut state, jobfeed) = in_phase(Phase::Created);
    assert_eq!(
        state.begin_create(&jobfeed, begin(2), at(9)),
        Err(TransitionError::AlreadyPending {
            address: jobfeed,
            phase: Phase::Created,
        })
    );
}

#[test]
fn only_one_key_may_have_an_operation_in_progress() {
    let (mut state, jobfeed) = in_phase(Phase::CreateStarted);
    let laptop = address("laptop");

    // The rule is global, not per-address: an unacknowledged create may have
    // made a key nobody can name, and a second one buries that evidence.
    assert_eq!(
        state.begin_create(&laptop, begin(1), at(9)),
        Err(TransitionError::AnotherOperationPending {
            address: laptop.clone(),
            blocking: jobfeed.clone(),
            operation: OperationId::parse("op-0001").expect("a valid operation id"),
            phase: Phase::CreateStarted,
        })
    );
    assert!(
        state.key(&laptop).is_none(),
        "a refused create left a binding"
    );
    assert_eq!(state.pending_operation().map(|(a, _)| a), Some(&jobfeed));

    // The blocking address gets the error that names its own phase.
    assert_eq!(
        state.begin_create(&jobfeed, begin(2), at(9)),
        Err(TransitionError::AlreadyPending {
            address: jobfeed.clone(),
            phase: Phase::CreateStarted,
        })
    );

    // Resolving the first operation frees the second.
    state
        .abandon_create(&jobfeed)
        .expect("a definite rejection");
    assert_eq!(state.pending_operation(), None);
    state
        .begin_create(&laptop, begin(1), at(9))
        .expect("the next key can start now");
    assert_eq!(state.pending_operation().map(|(a, _)| a), Some(&laptop));
}

#[test]
fn a_refused_create_leaves_no_trace_of_the_address() {
    let mut state = State::new();
    let jobfeed = address("jobfeed");

    // Generation 0 is refused, and refusing it must not create the binding on
    // the way out.
    assert!(state.begin_create(&jobfeed, begin(0), at(0)).is_err());
    assert_eq!(state, State::new());
}

#[test]
fn a_generation_only_moves_upward() {
    let (mut state, jobfeed) = in_phase(Phase::Delivered);
    state.promote_key(&jobfeed, at(9)).expect("promoting");

    for requested in [0, 1] {
        assert_eq!(
            state.begin_create(&jobfeed, begin(requested), at(10)),
            Err(TransitionError::GenerationNotMonotonic {
                address: jobfeed.clone(),
                recorded: 1,
                requested,
            })
        );
    }
    assert!(state.begin_create(&jobfeed, begin(2), at(10)).is_ok());
}

#[test]
fn a_create_can_only_be_abandoned_before_a_key_could_exist() {
    let (mut state, jobfeed) = in_phase(Phase::CreateStarted);
    state
        .abandon_create(&jobfeed)
        .expect("a definite rejection");
    assert!(
        state
            .key(&jobfeed)
            .expect("the binding stays")
            .pending()
            .is_none()
    );

    let (mut state, jobfeed) = in_phase(Phase::CreateAmbiguous);
    assert_eq!(
        state.abandon_create(&jobfeed),
        Err(TransitionError::CannotAbandon {
            address: jobfeed,
            phase: Phase::CreateAmbiguous,
        })
    );
}

#[test]
fn promotion_retains_the_predecessor_and_leaves_it_enabled() {
    let (mut state, jobfeed) = in_phase(Phase::Delivered);
    state.promote_key(&jobfeed, at(9)).expect("promoting");

    state
        .begin_create(&jobfeed, begin(2), at(10))
        .expect("a rotation");
    for (step, transition) in [
        Transition::Created { hash: hash("h2") },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::Delivered,
    ]
    .into_iter()
    .enumerate()
    {
        state
            .advance_key(&jobfeed, transition, at(11 + step as i64))
            .expect("rotating");
    }
    state.promote_key(&jobfeed, at(20)).expect("promoting");

    let binding = state.key(&jobfeed).expect("the binding");
    assert_eq!(binding.current().expect("a current key").hash, hash("h2"));
    assert_eq!(binding.generation(), 2);
    assert_eq!(
        binding.retained(),
        [RetainedKey {
            hash: hash("h1"),
            generation: 1,
            status: RetainedStatus::AwaitingRetirement,
            recorded_at: at(20),
        }]
    );
}

#[test]
fn a_key_cannot_be_promoted_before_it_is_delivered() {
    for phase in [Phase::Created, Phase::Secured, Phase::DeliveryAmbiguous] {
        let (mut state, jobfeed) = in_phase(phase);
        assert_eq!(
            state.promote_key(&jobfeed, at(9)),
            Err(TransitionError::CannotPromote {
                address: jobfeed,
                phase,
            })
        );
    }
}

#[test]
fn a_retained_hash_records_why_it_is_still_tracked() {
    let (mut state, jobfeed) = in_phase(Phase::Delivered);
    state.promote_key(&jobfeed, at(9)).expect("promoting");
    state
        .begin_create(&jobfeed, begin(2), at(10))
        .expect("a rotation");
    for transition in [
        Transition::Created { hash: hash("h2") },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::Delivered,
    ] {
        state
            .advance_key(&jobfeed, transition, at(11))
            .expect("rotating");
    }
    state.promote_key(&jobfeed, at(15)).expect("promoting");

    assert_eq!(
        state.set_retained_status(&jobfeed, &hash("h9"), RetainedStatus::Retired, at(16)),
        Err(TransitionError::HashNotRetained {
            address: jobfeed.clone(),
            hash: hash("h9"),
        })
    );
    state
        .set_retained_status(&jobfeed, &hash("h1"), RetainedStatus::Retired, at(16))
        .expect("retiring the predecessor");
    assert_eq!(
        state.key(&jobfeed).expect("the binding").retained()[0].status,
        RetainedStatus::Retired
    );
}

// --- bindings --------------------------------------------------------------

#[test]
fn binding_a_key_is_one_to_one_and_repeating_it_is_a_no_op() {
    let mut state = State::new();
    let jobfeed = address("jobfeed");
    let laptop = address("laptop");

    state
        .bind_key(&jobfeed, hash("h1"), 1, at(0))
        .expect("binding");
    state
        .bind_key(&jobfeed, hash("h1"), 1, at(1))
        .expect("repeating the same binding");
    assert_eq!(state.address_owning(&hash("h1")), Some(&jobfeed));
    assert_eq!(
        state.key(&jobfeed).expect("the binding").origin(),
        Origin::Imported
    );

    assert_eq!(
        state.bind_key(&laptop, hash("h1"), 1, at(2)),
        Err(BindError::HashOwnedElsewhere {
            hash: hash("h1"),
            owner: jobfeed.clone(),
        })
    );
    assert_eq!(
        state.bind_key(&jobfeed, hash("h2"), 1, at(2)),
        Err(BindError::AddressBound {
            address: jobfeed,
            hash: hash("h1"),
        })
    );
}

#[test]
fn binding_records_the_generation_the_configuration_asks_for() {
    let mut state = State::new();
    let jobfeed = address("jobfeed");

    // Rebuilding lost state: the configuration is already at generation 3, so
    // recording 1 would make the next plan propose replacing a live key.
    state
        .bind_key(&jobfeed, hash("h1"), 3, at(0))
        .expect("binding");
    assert_eq!(state.key(&jobfeed).expect("the binding").generation(), 3);

    // Repeating the import is a no-op, and a later rise is recorded.
    state
        .bind_key(&jobfeed, hash("h1"), 3, at(1))
        .expect("repeating the same binding");
    assert_eq!(
        state.key(&jobfeed).expect("the binding").current(),
        Some(&CurrentKey {
            hash: hash("h1"),
            generation: 3,
            bound_at: at(0),
            receiver: None,
        })
    );
    state
        .bind_key(&jobfeed, hash("h1"), 4, at(2))
        .expect("a raised generation");
    assert_eq!(state.key(&jobfeed).expect("the binding").generation(), 4);

    // A create after an import continues from the imported generation.
    assert!(state.begin_create(&jobfeed, begin(4), at(3)).is_err());
    assert!(state.begin_create(&jobfeed, begin(5), at(3)).is_ok());
}

/// A rotation to generation 2 whose delivery failed: h2 is retained above the
/// current h1, which is still the live key.
fn with_a_failed_candidate_above_the_current_key() -> (State, Address) {
    let state = read_document(
        r#"{"version":1,"serial":1,"guardrails":{},"keys":{"jobfeed":{"origin":"imported",
        "current":{"hash":"h1","generation":1,"bound_at":"2026-01-01T00:00:00Z"},
        "retained":[{"hash":"h2","generation":2,"status":"failed_candidate",
        "recorded_at":"2026-01-01T00:00:00Z"}]}}}"#,
    )
    .expect("a binding that retains a higher generation");
    (state, address("jobfeed"))
}

#[test]
fn a_binding_may_not_take_a_generation_another_key_at_the_address_holds() {
    let (mut state, jobfeed) = with_a_failed_candidate_above_the_current_key();
    assert_eq!(state.key(&jobfeed).expect("the binding").generation(), 1);
    assert_eq!(
        state
            .key(&jobfeed)
            .expect("the binding")
            .settled_generation(),
        2
    );

    // Raising the current key to 2 would give h1 and h2 the same generation
    // at one address, so equality with what the address records is not enough.
    assert_eq!(
        state.bind_key(&jobfeed, hash("h1"), 2, at(9)),
        Err(BindError::GenerationUnavailable {
            address: jobfeed.clone(),
            recorded: 2,
            requested: 2,
        })
    );
    assert_eq!(state.key(&jobfeed).expect("the binding").generation(), 1);

    // Re-importing the current key at the generation it already holds is the
    // one equality that is allowed, and it changes nothing.
    let before = state.clone();
    state
        .bind_key(&jobfeed, hash("h1"), 1, at(9))
        .expect("re-importing the key already bound");
    assert_eq!(state, before);

    // Clearing everything the address records is what a new number means.
    state
        .bind_key(&jobfeed, hash("h1"), 3, at(9))
        .expect("a generation above every one recorded");
    assert_eq!(state.key(&jobfeed).expect("the binding").generation(), 3);
}

#[test]
fn a_create_may_not_take_a_generation_another_key_at_the_address_holds() {
    let (mut state, jobfeed) = with_a_failed_candidate_above_the_current_key();
    assert_eq!(
        state.begin_create(&jobfeed, begin(2), at(9)),
        Err(TransitionError::GenerationNotMonotonic {
            address: jobfeed.clone(),
            recorded: 2,
            requested: 2,
        })
    );
    assert!(state.begin_create(&jobfeed, begin(3), at(9)).is_ok());
}

#[test]
fn a_retained_key_is_not_bindable_as_the_current_one() {
    let (mut state, jobfeed) = with_a_failed_candidate_above_the_current_key();

    // h2 is disabled or awaiting retirement. Binding it as current would also
    // leave one hash recorded twice at one address.
    assert_eq!(
        state.bind_key(&jobfeed, hash("h2"), 3, at(9)),
        Err(BindError::HashRetained {
            address: jobfeed.clone(),
            hash: hash("h2"),
        })
    );
    assert_eq!(state.key(&jobfeed).expect("the binding").generation(), 1);
}

#[test]
fn a_bound_generation_must_be_at_least_one_and_may_not_fall() {
    let mut state = State::new();
    let jobfeed = address("jobfeed");

    assert_eq!(
        state.bind_key(&jobfeed, hash("h1"), 0, at(0)),
        Err(BindError::GenerationInvalid {
            address: jobfeed.clone()
        })
    );
    assert!(state.key(&jobfeed).is_none());

    state
        .bind_key(&jobfeed, hash("h1"), 3, at(0))
        .expect("binding");
    assert_eq!(
        state.bind_key(&jobfeed, hash("h1"), 2, at(1)),
        Err(BindError::GenerationUnavailable {
            address: jobfeed.clone(),
            recorded: 3,
            requested: 2,
        })
    );
    assert_eq!(state.key(&jobfeed).expect("the binding").generation(), 3);
}

#[test]
fn binding_an_address_does_not_drop_the_hashes_it_still_owns() {
    // An address can own retained hashes with nothing current — a key whose
    // delivery failed, disabled and awaiting deletion. Importing a working key
    // into that address must not lose them.
    let mut state = read_document(
        r#"{"version":1,"serial":1,"guardrails":{},"keys":{"jobfeed":{"origin":"created",
        "retained":[{"hash":"h0","generation":1,"status":"failed_candidate",
        "recorded_at":"2026-01-01T00:00:00Z"}]}}}"#,
    )
    .expect("a binding that owns only retained hashes");

    let jobfeed = address("jobfeed");
    state
        .bind_key(&jobfeed, hash("h1"), 2, at(0))
        .expect("binding");

    let binding = state.key(&jobfeed).expect("the binding");
    assert_eq!(binding.current().expect("a current key").hash, hash("h1"));
    assert_eq!(binding.retained().len(), 1);
    assert_eq!(binding.retained()[0].hash, hash("h0"));
    assert_eq!(state.address_owning(&hash("h0")), Some(&jobfeed));
}

#[test]
fn an_address_with_an_operation_in_progress_cannot_be_rebound() {
    let (mut state, jobfeed) = in_phase(Phase::CreateStarted);
    assert_eq!(
        state.bind_key(&jobfeed, hash("h1"), 1, at(9)),
        Err(BindError::OperationInProgress {
            address: jobfeed.clone()
        })
    );
}

#[test]
fn a_created_hash_may_not_already_belong_to_another_address() {
    let mut state = State::new();
    let laptop = address("laptop");
    state
        .bind_key(&laptop, hash("h1"), 1, at(0))
        .expect("binding");

    let jobfeed = address("jobfeed");
    state
        .begin_create(&jobfeed, begin(1), at(1))
        .expect("starting a create");
    assert_eq!(
        state.advance_key(&jobfeed, Transition::Created { hash: hash("h1") }, at(2)),
        Err(TransitionError::HashOwnedElsewhere {
            hash: hash("h1"),
            owner: laptop,
        })
    );
}

#[test]
fn binding_a_guardrail_is_one_to_one_and_repeating_it_is_a_no_op() {
    let one = uuid("6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b");
    let two = uuid("11111111-2222-3333-4444-555555555555");
    let cheap = address("cheap");
    let rich = address("rich");

    let mut state = State::new();
    state
        .bind_guardrail(&cheap, one.clone(), Origin::Created, at(0))
        .expect("binding");
    state
        .bind_guardrail(&cheap, one.clone(), Origin::Created, at(1))
        .expect("repeating the same binding");
    assert_eq!(
        state.guardrail(&cheap).expect("the binding").bound_at,
        at(0)
    );

    assert_eq!(
        state.bind_guardrail(&rich, one.clone(), Origin::Created, at(2)),
        Err(BindError::GuardrailOwnedElsewhere {
            id: one.clone(),
            owner: cheap.clone(),
        })
    );
    assert_eq!(
        state.bind_guardrail(&cheap, two, Origin::Created, at(2)),
        Err(BindError::GuardrailBound {
            address: cheap,
            id: one,
        })
    );
}

#[test]
fn a_recreated_guardrail_replaces_the_binding_to_the_one_that_is_gone() {
    let gone = uuid("6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b");
    let fresh = uuid("11111111-2222-3333-4444-555555555555");
    let cheap = address("cheap");
    let rich = address("rich");

    let mut state = State::new();
    state
        .bind_guardrail(&cheap, gone, Origin::Imported, at(0))
        .expect("binding the guardrail that later disappears");

    state
        .replace_guardrail(&cheap, fresh.clone(), at(1))
        .expect("recreating it");
    let binding = state.guardrail(&cheap).expect("the new binding");
    assert_eq!(binding.id, fresh);
    assert_eq!(
        binding.origin,
        Origin::Created,
        "the guardrail it now names is one Keymaster created"
    );
    assert_eq!(binding.bound_at, at(1));

    // The one-to-one rule still holds: a UUID another address owns is refused.
    assert_eq!(
        state.replace_guardrail(&rich, fresh.clone(), at(2)),
        Err(BindError::GuardrailOwnedElsewhere {
            id: fresh,
            owner: cheap,
        })
    );
}

// --- persistence -----------------------------------------------------------

#[test]
fn state_round_trips_through_the_production_path() {
    let scratch = Scratch::new();
    let jobfeed = address("jobfeed");
    let cheap = address("cheap");

    let (mut state, _) = in_phase(Phase::DeliveryAmbiguous);
    state
        .bind_guardrail(
            &cheap,
            uuid("6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b"),
            Origin::Imported,
            at(3),
        )
        .expect("binding a guardrail");
    scratch.store(&mut state);

    let reopened = scratch.file().read().expect("reading state back");
    assert_eq!(reopened, state);

    let pending = reopened
        .key(&jobfeed)
        .and_then(KeyBinding::pending)
        .expect("the operation survived");
    assert_eq!(pending.phase, Phase::DeliveryAmbiguous);
    assert_eq!(pending.hash, Some(hash("h1")));
    assert_eq!(
        reopened.guardrail(&cheap).expect("the guardrail").origin,
        Origin::Imported
    );
}

#[test]
fn a_missing_state_file_reads_as_empty_and_creates_nothing() {
    let scratch = Scratch::new();
    assert_eq!(scratch.file().read().expect("an absent file"), State::new());
    assert!(!scratch.directory().exists());
}

#[test]
fn reading_never_rewrites_the_file() {
    let scratch = Scratch::new();
    let mut state = State::new();
    scratch.store(&mut state);

    let before = fs::read(&scratch.path).expect("reading the raw file");
    for _ in 0..3 {
        scratch.file().read().expect("reading state");
    }
    assert_eq!(fs::read(&scratch.path).expect("reading again"), before);
    assert_eq!(scratch.entries(), ["state.json"]);
}

#[test]
fn the_serial_advances_on_every_write() {
    let scratch = Scratch::new();
    let mut state = State::new();
    assert_eq!(state.serial(), 0);

    scratch.store(&mut state);
    assert_eq!(state.serial(), 1);
    scratch.store(&mut state);
    assert_eq!(state.serial(), 2);
    assert_eq!(scratch.file().read().expect("reading").serial(), 2);
}

#[test]
fn a_writer_holding_a_stale_serial_cannot_silently_overwrite() {
    let scratch = Scratch::new();
    let mut first = State::new();
    scratch.store(&mut first);

    let mut second = scratch.file().read().expect("reading state");
    scratch.store(&mut second);

    let file = scratch.file();
    let lock = file.lock().expect("taking the lock");
    let error = lock.write(&mut first).expect_err("a stale write");
    assert_eq!(error.kind(), "state_conflict");
    assert!(error.to_string().contains("serial 1"), "{error}");
    assert_eq!(scratch.file().read().expect("reading").serial(), 2);
}

#[test]
fn lock_contention_is_a_clear_error_and_the_lock_is_released_on_drop() {
    let scratch = Scratch::new();
    let file = scratch.file();

    let held = file.lock().expect("taking the lock");
    let error = file.lock().expect_err("a second lock");
    assert_eq!(error.kind(), "state_locked");
    let message = error.to_string();
    assert!(
        message.contains("another Keymaster is writing"),
        "{message}"
    );
    assert!(message.contains("state.json.lock"), "{message}");

    drop(held);
    file.lock().expect("the lock is released on drop");
}

#[test]
fn a_serial_that_cannot_advance_stops_the_write_rather_than_repeating_itself() {
    // Unreachable through ordinary use, but a hand-edited file can arrive this
    // way, and saturating would write a second state at the same serial —
    // exactly the signal conflict detection reads.
    let scratch = Scratch::new();
    fs::create_dir_all(scratch.directory()).expect("creating the state directory");
    fs::write(
        &scratch.path,
        format!(
            r#"{{"version":1,"serial":{},"keys":{{}},"guardrails":{{}}}}"#,
            u64::MAX
        ),
    )
    .expect("writing an exhausted state");

    let file = scratch.file();
    let mut state = file.read().expect("reading state");
    assert_eq!(state.serial(), u64::MAX);

    let lock = file.lock().expect("taking the lock");
    let error = lock
        .write(&mut state)
        .expect_err("the serial cannot advance");
    assert_eq!(error.kind(), "state_serial_exhausted");
    assert!(
        error.to_string().contains("cannot record another write"),
        "{error}"
    );

    // The state on disk is untouched, and no temporary file was left behind.
    assert_eq!(state.serial(), u64::MAX);
    drop(lock);
    assert_eq!(file.read().expect("reading state").serial(), u64::MAX);
    assert_eq!(scratch.entries(), ["state.json"]);
}

#[cfg(unix)]
#[test]
fn state_and_the_directory_keymaster_creates_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new();
    let mut state = State::new();
    scratch.store(&mut state);

    let mode = |path: &Path| {
        fs::metadata(path)
            .expect("reading metadata")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(scratch.directory()), 0o700);
    assert_eq!(mode(&scratch.path), 0o600);
}

// --- refusals --------------------------------------------------------------

#[test]
fn an_unknown_future_version_is_refused() {
    let error = read_document(r#"{"version":2,"serial":1,"keys":{},"guardrails":{}}"#)
        .expect_err("a future version");
    assert_eq!(error.kind(), "state_unsupported_version");
    assert!(error.to_string().contains("version 2"), "{error}");
}

#[test]
fn an_unknown_field_is_refused_rather_than_dropped() {
    let error = read_document(
        r#"{"version":1,"serial":1,"keys":{},"guardrails":{},"plaintext":"anything"}"#,
    )
    .expect_err("an unknown field");
    assert_eq!(error.kind(), "state_parse");
}

#[test]
fn a_valid_document_reads_back() {
    assert_eq!(
        read_document(EMPTY_DOCUMENT)
            .expect("a valid document")
            .serial(),
        1
    );
}

#[test]
fn a_phase_that_cannot_carry_a_hash_is_refused() {
    let error = read_document(&format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{{"origin":"created",
        "pending":{{"id":"op-1","generation":1,"phase":"create_started",
        "phase_at":"2026-01-01T00:00:00Z","name":"golf-jobfeed","hash":"h1",
        "receiver":"{FINGERPRINT}"}}}}}}}}"#
    ))
    .expect_err("a hash in create_started");
    assert_eq!(error.kind(), "state_corrupt", "{error}");
    assert!(error.to_string().contains("cannot happen"), "{error}");
    assert_eq!(
        FINGERPRINT,
        ReceiverFingerprint::from_digest([7; 32]).as_str(),
        "the fixtures must carry a fingerprint the reader accepts"
    );
}

#[test]
fn a_phase_that_requires_a_hash_is_refused_without_one() {
    let error = read_document(&format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{{"origin":"created",
        "pending":{{"id":"op-1","generation":1,"phase":"delivered",
        "phase_at":"2026-01-01T00:00:00Z","name":"golf-jobfeed",
        "receiver":"{FINGERPRINT}"}}}}}}}}"#
    ))
    .expect_err("delivered with no hash");
    assert_eq!(error.kind(), "state_corrupt");
}

#[test]
fn a_refused_delivery_recorded_anywhere_but_secured_is_refused() {
    let document = |phase: &str| {
        format!(
            r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{{"origin":"created",
            "pending":{{"id":"op-1","generation":1,"phase":"{phase}",
            "phase_at":"2026-01-01T00:00:00Z","name":"golf-jobfeed","hash":"h1",
            "delivery_rejected_at":"2026-01-01T00:00:00Z",
            "receiver":"{FINGERPRINT}"}}}}}}}}"#
        )
    };

    // The shape the bug would have produced: refused, then delivering again.
    let error = read_document(&document("delivery_started")).expect_err("a refused delivery");
    assert_eq!(error.kind(), "state_corrupt", "{error}");
    assert!(error.to_string().contains("holds at `secured`"), "{error}");

    for phase in ["delivered", "delivery_ambiguous", "created"] {
        assert_eq!(
            read_document(&document(phase))
                .expect_err("a refused delivery")
                .kind(),
            "state_corrupt",
            "{phase}"
        );
    }

    // Refused and holding at `secured` is the one shape that is real.
    let state = read_document(&document("secured")).expect("a refused delivery at rest");
    assert!(
        state
            .key(&address("jobfeed"))
            .and_then(KeyBinding::pending)
            .expect("the operation")
            .delivery_rejected_at
            .is_some()
    );
}

#[test]
fn a_pending_generation_at_or_below_the_current_one_is_refused() {
    let error = read_document(&format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{{"origin":"created",
        "current":{{"hash":"h1","generation":2,"bound_at":"2026-01-01T00:00:00Z",
        "receiver":"{FINGERPRINT}"}},
        "pending":{{"id":"op-1","generation":2,"phase":"create_started",
        "phase_at":"2026-01-01T00:00:00Z","name":"golf-jobfeed",
        "receiver":"{FINGERPRINT}"}}}}}}}}"#
    ))
    .expect_err("a generation that does not advance");
    assert_eq!(error.kind(), "state_corrupt");
    assert!(error.to_string().contains("only moves upward"), "{error}");
}

#[test]
fn a_generation_of_zero_is_refused_wherever_it_is_recorded() {
    let document = |binding: &str| {
        format!(r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{binding}}}}}"#)
    };
    let bindings = [
        r#"{"origin":"created","current":{"hash":"h1","generation":0,
        "bound_at":"2026-01-01T00:00:00Z"}}"#,
        r#"{"origin":"created","retained":[{"hash":"h0","generation":0,
        "status":"retired","recorded_at":"2026-01-01T00:00:00Z"}]}"#,
        &format!(
            r#"{{"origin":"created","pending":{{"id":"op-1","generation":0,
            "phase":"create_started","phase_at":"2026-01-01T00:00:00Z",
            "name":"golf-jobfeed","receiver":"{FINGERPRINT}"}}}}"#
        ),
    ];

    for binding in bindings {
        let error = read_document(&document(binding)).expect_err("a generation of zero");
        assert_eq!(error.kind(), "state_corrupt", "{binding}");
        assert!(
            error.to_string().contains("counted from 1"),
            "{error}: {binding}"
        );
    }
}

#[test]
fn two_keys_at_one_address_sharing_a_generation_are_refused() {
    // The rule `bind_key` and `begin_create` enforce as state is built, applied
    // to a file that could have been hand-edited into this shape.
    let error = read_document(
        r#"{"version":1,"serial":1,"guardrails":{},"keys":{"jobfeed":{"origin":"imported",
        "current":{"hash":"h1","generation":2,"bound_at":"2026-01-01T00:00:00Z"},
        "retained":[{"hash":"h2","generation":2,"status":"awaiting_retirement",
        "recorded_at":"2026-01-01T00:00:00Z"}]}}}"#,
    )
    .expect_err("two keys at one generation");
    assert_eq!(error.kind(), "state_corrupt");
    assert!(error.to_string().contains("more than one key"), "{error}");

    // Two retained keys can collide with each other just as easily.
    let error = read_document(
        r#"{"version":1,"serial":1,"guardrails":{},"keys":{"jobfeed":{"origin":"imported",
        "current":{"hash":"h1","generation":3,"bound_at":"2026-01-01T00:00:00Z"},
        "retained":[{"hash":"h2","generation":2,"status":"retired",
        "recorded_at":"2026-01-01T00:00:00Z"},
        {"hash":"h3","generation":2,"status":"failed_candidate",
        "recorded_at":"2026-01-01T00:00:00Z"}]}}}"#,
    )
    .expect_err("two retained keys at one generation");
    assert_eq!(error.kind(), "state_corrupt");

    // Distinct generations are what a real rotation leaves behind.
    read_document(
        r#"{"version":1,"serial":1,"guardrails":{},"keys":{"jobfeed":{"origin":"imported",
        "current":{"hash":"h3","generation":3,"bound_at":"2026-01-01T00:00:00Z"},
        "retained":[{"hash":"h2","generation":2,"status":"awaiting_retirement",
        "recorded_at":"2026-01-01T00:00:00Z"},
        {"hash":"h1","generation":1,"status":"retired",
        "recorded_at":"2026-01-01T00:00:00Z"}]}}}"#,
    )
    .expect("a rotation history with one key per generation");
}

#[test]
fn two_operations_in_progress_at_once_are_refused() {
    let operation = |address: &str| {
        format!(
            r#""{address}":{{"origin":"created","pending":{{"id":"op-{address}","generation":1,
            "phase":"create_started","phase_at":"2026-01-01T00:00:00Z",
            "name":"{address}","receiver":"{FINGERPRINT}"}}}}"#
        )
    };

    let error = read_document(&format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{{},{}}}}}"#,
        operation("jobfeed"),
        operation("laptop")
    ))
    .expect_err("two operations in progress");
    assert_eq!(error.kind(), "state_corrupt", "{error}");
    assert!(error.to_string().contains("one key at a time"), "{error}");

    // One is what a real interrupted run leaves behind.
    let state = read_document(&format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{{}}}}}"#,
        operation("jobfeed")
    ))
    .expect("one interrupted operation");
    assert_eq!(
        state.pending_operation().map(|(address, _)| address),
        Some(&address("jobfeed"))
    );
}

#[test]
fn an_address_named_twice_in_one_file_is_refused() {
    // JSON lets an object repeat a key and the derived reader would keep the
    // last one, so a merged or hand-edited file could drop a binding to a live
    // key without saying anything. Both entries here are well formed on their
    // own; only naming the address twice is the problem.
    let error = read_document(
        r#"{"version":1,"serial":1,"guardrails":{},"keys":{
        "jobfeed":{"origin":"created","current":{"hash":"h1","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}},
        "jobfeed":{"origin":"imported","current":{"hash":"h2","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}}}}"#,
    )
    .expect_err("one address named twice");
    assert_eq!(error.kind(), "state_parse", "{error}");
    assert!(
        error.to_string().contains("appears more than once"),
        "{error}"
    );

    let error = read_document(
        r#"{"version":1,"serial":1,"keys":{},"guardrails":{
        "cheap":{"id":"6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b","origin":"created",
        "bound_at":"2026-01-01T00:00:00Z"},
        "cheap":{"id":"11111111-2222-3333-4444-555555555555","origin":"imported",
        "bound_at":"2026-01-01T00:00:00Z"}}}"#,
    )
    .expect_err("one guardrail address named twice");
    assert_eq!(error.kind(), "state_parse", "{error}");

    // Two distinct addresses are of course fine.
    let state = read_document(
        r#"{"version":1,"serial":1,"guardrails":{},"keys":{
        "jobfeed":{"origin":"imported","current":{"hash":"h1","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}},
        "laptop":{"origin":"imported","current":{"hash":"h2","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}}}}"#,
    )
    .expect("two distinct addresses");
    assert_eq!(state.keys().len(), 2);
}

#[test]
fn one_remote_key_bound_to_two_addresses_is_refused() {
    let error = read_document(
        r#"{"version":1,"serial":1,"guardrails":{},"keys":{
        "jobfeed":{"origin":"imported","current":{"hash":"h1","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}},
        "laptop":{"origin":"imported","current":{"hash":"h1","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}}}}"#,
    )
    .expect_err("one hash, two addresses");
    assert_eq!(error.kind(), "state_corrupt");
}

#[test]
fn one_remote_guardrail_bound_to_two_addresses_is_refused() {
    let error = read_document(
        r#"{"version":1,"serial":1,"keys":{},"guardrails":{
        "cheap":{"id":"6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b","origin":"created",
        "bound_at":"2026-01-01T00:00:00Z"},
        "rich":{"id":"6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b","origin":"created",
        "bound_at":"2026-01-01T00:00:00Z"}}}"#,
    )
    .expect_err("one guardrail, two addresses");
    assert_eq!(error.kind(), "state_corrupt");
}

#[test]
fn a_credential_shaped_address_or_operation_id_cannot_be_read_back() {
    // Every character of a credential is one an address and an operation id
    // allow, so a file could carry one in either position. Both are printed
    // in diagnostics and the operation id travels to the receiver, so both
    // are refused where they are parsed rather than where they are used.
    let by_address = format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"{SECRET_SENTINEL_KEY}":{{
        "origin":"imported","current":{{"hash":"h1","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}}}}}}}}"#
    );
    let by_operation = format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{{"origin":"created",
        "pending":{{"id":"{SECRET_SENTINEL_KEY}","generation":1,"phase":"create_started",
        "phase_at":"2026-01-01T00:00:00Z","name":"golf-jobfeed",
        "receiver":"{FINGERPRINT}"}}}}}}}}"#
    );

    for (label, document) in [("address", &by_address), ("operation id", &by_operation)] {
        let error = read_document(document).expect_err("a credential is not an identifier");
        assert_eq!(error.kind(), "state_parse", "{label}: {error}");
        assert!(
            !error.to_string().contains("sk-or"),
            "the {label} refusal echoed a credential: {error}"
        );
        assert!(
            !format!("{error:?}").contains("SENTINEL"),
            "the {label} refusal echoed the sentinel: {error:?}"
        );
    }
}

#[test]
fn key_plaintext_cannot_be_read_back_as_a_hash() {
    let document = format!(
        r#"{{"version":1,"serial":1,"guardrails":{{}},"keys":{{"jobfeed":{{"origin":"created",
        "current":{{"hash":"{SECRET_SENTINEL_KEY}","generation":1,
        "bound_at":"2026-01-01T00:00:00Z"}}}}}}}}"#
    );
    let error = read_document(&document).expect_err("plaintext is not a hash");
    assert_eq!(error.kind(), "state_parse");
    assert!(
        !error.to_string().contains("sk-or-"),
        "the refusal echoed plaintext: {error}"
    );
}

// --- durability ------------------------------------------------------------

/// Runs a write that fails at `fault` and reports what the state file holds
/// afterwards, having first stored one key binding as the previous state.
fn write_under_fault(scratch: &Scratch, fault: Fault) -> (StateError, State) {
    let mut previous = State::new();
    previous
        .bind_key(&address("jobfeed"), hash("h1"), 1, at(0))
        .expect("binding");
    scratch.store(&mut previous);

    let faulty = StateFile::with_fault(&scratch.path, fault);
    let mut next = faulty.read().expect("reading state");
    next.bind_key(&address("laptop"), hash("h2"), 1, at(1))
        .expect("binding");

    let lock = faulty.lock().expect("taking the lock");
    let error = lock.write(&mut next).expect_err("an injected failure");
    drop(lock);
    (error, scratch.file().read().expect("reading state back"))
}

#[test]
fn a_failure_before_the_rename_leaves_the_previous_state_untouched() {
    for fault in [Fault::BeforeTemp, Fault::DuringWrite, Fault::BeforeRename] {
        let scratch = Scratch::new();
        let (error, state) = write_under_fault(&scratch, fault);

        assert_eq!(error.kind(), "state_write", "{fault:?}");
        assert_eq!(state.serial(), 1, "{fault:?}");
        assert_eq!(state.keys().len(), 1, "{fault:?}");
        assert!(state.key(&address("jobfeed")).is_some(), "{fault:?}");
        assert_eq!(scratch.entries(), ["state.json"], "{fault:?}");
    }
}

#[test]
fn a_failure_after_the_rename_leaves_the_new_state_in_place() {
    let scratch = Scratch::new();
    let (error, state) = write_under_fault(&scratch, Fault::AfterRename);

    assert_eq!(error.kind(), "state_write");
    assert_eq!(state.serial(), 2);
    assert_eq!(state.keys().len(), 2);
    assert_eq!(scratch.entries(), ["state.json"]);
}

#[test]
fn a_successful_write_leaves_no_temporary_file() {
    let scratch = Scratch::new();
    let mut state = State::new();
    scratch.store(&mut state);
    assert_eq!(scratch.entries(), ["state.json"]);
}

#[cfg(unix)]
#[test]
fn a_temporary_file_is_never_opened_through_a_symbolic_link() {
    use std::os::unix::fs::symlink;

    // A predictable temporary name in a directory someone else can write to
    // is an invitation to plant a link and have Keymaster truncate its target.
    let scratch = Scratch::new();
    let mut state = State::new();
    scratch.store(&mut state);

    let victim = scratch.directory().join("victim");
    fs::write(&victim, b"do not truncate me").expect("writing the victim");
    let planted = temporary_path(scratch.file().path());
    symlink(&victim, &planted).expect("planting a symbolic link");

    let error = create_private_new(&planted).expect_err("a link is not a new file");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        fs::read(&victim).expect("reading the victim"),
        b"do not truncate me"
    );

    // The real write picks a name of its own and finishes normally.
    scratch.store(&mut state);
    assert_eq!(
        fs::read(&victim).expect("reading the victim"),
        b"do not truncate me"
    );
    assert_eq!(scratch.file().read().expect("reading").serial(), 2);
    fs::remove_file(&planted).expect("removing the planted link");
    fs::remove_file(&victim).expect("removing the victim");
    assert_eq!(scratch.entries(), ["state.json"]);
}

#[test]
fn temporary_names_are_unpredictable_and_claimed_exclusively() {
    let scratch = Scratch::new();
    let mut state = State::new();
    scratch.store(&mut state);
    let file = scratch.file();

    let names: BTreeSet<PathBuf> = (0..8).map(|_| temporary_path(file.path())).collect();
    assert_eq!(names.len(), 8, "temporary names must not repeat");
    for name in &names {
        assert!(!name.exists());
        assert!(
            name.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("state.json.") && name.ends_with(".tmp")),
            "{name:?}"
        );
    }

    let (_handle, claimed) = file.create_temporary().expect("claiming a temporary name");
    assert!(claimed.exists());
    assert_eq!(
        create_private_new(&claimed)
            .expect_err("a claimed name cannot be claimed twice")
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    fs::remove_file(&claimed).expect("removing the temporary file");
}

#[test]
fn a_bare_state_filename_still_names_a_directory_to_sync() {
    assert_eq!(
        containing_directory(Path::new("state.json")),
        Path::new(".")
    );
    assert_eq!(
        containing_directory(Path::new(".openrouter-keymaster/state.json")),
        Path::new(".openrouter-keymaster")
    );
    assert_eq!(
        containing_directory(Path::new("/var/lib/keymaster/state.json")),
        Path::new("/var/lib/keymaster")
    );
    assert_eq!(containing_directory(Path::new("/")), Path::new("."));
}
