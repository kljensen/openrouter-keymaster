//! Binary-level tests for `keymaster recover`.
//!
//! Recovery exists because Keymaster refuses to guess. So most of what these
//! cases assert is what *did not* happen: no candidate was selected, no second
//! `POST /keys` was sent, no receiver ran twice, no found hash was promoted, and
//! nothing was written when the answer was "there is nothing there".
//!
//! The receiver is the purpose-built helper binary, which appends a line every
//! time it runs. That is how "no path automatically re-delivers" is asserted
//! rather than assumed. It writes into a directory of its own, because what it
//! writes is a live credential and the project directory is scanned for exactly
//! that.

mod support;

use std::fs;
use std::path::Path;

use keymaster::ids::{OperationId, ReceiverFingerprint, RemoteName};
use keymaster::state::{BeginCreate, Phase, RetainedStatus, State, Transition};
use serde_json::{Value, json};
use support::fixtures::{FAKE_WORKSPACE_ID, api_key, created_key};
use support::http::{Scripted, json_response};
use support::project::{Project, address, at, hash};
use support::sentinel::{SECRET_SENTINEL_KEY, assert_absent};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// The hash the operator finds in the dashboard, or `POST /keys` returns.
const LEAKED_HASH: &str = "hash-jobfeed-leaked";
const OTHER_HASH: &str = "hash-somebody-elses";
const SUCCESSOR_HASH: &str = "hash-jobfeed-successor";

/// An operation's journaled name, so a report can be checked for it.
const OPERATION: &str = "op-0042";

/// When the attempt was journaled, as the fixtures record it.
///
/// `at(0)` is 2026-01-01T00:00:00Z, and the fixtures' remote keys say they were
/// created on the same day, so a candidate window measured in hours separates
/// them from a key created a year earlier.
const ATTEMPT_AT: &str = "2026-01-01T00:10:00Z";

/// When the attempt was classified `create_ambiguous`, one second later. The
/// journal records the phase's own time, not the operation's start.
const CLASSIFIED_AT: &str = "2026-01-01T00:10:01Z";

/// A project whose one key delivers through the helper binary.
struct Recovery {
    project: Project,
    vault: TempDir,
}

impl Recovery {
    fn new() -> Self {
        let vault = tempfile::tempdir().expect("a temporary vault directory");
        let project = Project::new(&configuration(vault.path()));
        Self { project, vault }
    }

    /// A project whose key names no receiver, so no successor can be created.
    ///
    /// The configuration still parses and the address is still described; what
    /// is missing is the one thing a create cannot do without, which is exactly
    /// the kind of failure that must be found before anything is retired.
    fn without_a_receiver() -> Self {
        let vault = tempfile::tempdir().expect("a temporary vault directory");
        let project = Project::new(
            "version = 1\n\n[keys.jobfeed]\nname = \"golf-jobfeed\"\nlimit_usd = 5\n\
             limit_reset = \"monthly\"\ndisabled = true\n",
        );
        Self { project, vault }
    }

    /// How many times the receiver program ran. Absent means never.
    fn deliveries(&self) -> usize {
        fs::read_to_string(self.vault.path().join("runs.txt"))
            .map(|runs| runs.lines().count())
            .unwrap_or_default()
    }

    /// The phase of the operation the state file holds, if it holds one.
    fn journaled(&self) -> Option<Phase> {
        self.project
            .read_state()
            .pending_operation()
            .map(|(_, operation)| operation.phase)
    }

    /// Writes a journal fixture whose operation stops at `phase`.
    ///
    /// The transitions are replayed through the production state API, so a
    /// fixture is exactly a shape a real run could have left.
    fn journal(&self, phase: Phase, workspace: bool) {
        self.project.write_state(|state| {
            let jobfeed = address("jobfeed");
            state
                .begin_create(
                    &jobfeed,
                    BeginCreate {
                        operation: OperationId::parse(OPERATION).expect("an operation id"),
                        generation: 1,
                        name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                        workspace: workspace.then(|| {
                            keymaster::ids::Uuid::parse(FAKE_WORKSPACE_ID).expect("a UUID")
                        }),
                        receiver: ReceiverFingerprint::from_digest([42; 32]),
                    },
                    at(600),
                )
                .expect("journaling the attempt");
            for (step, transition) in replay(phase).iter().enumerate() {
                state
                    .advance_key(&jobfeed, transition.clone(), at(601 + step as i64))
                    .expect("replaying the transaction");
            }
        });
        assert_eq!(self.journaled(), Some(phase), "the fixture is in {phase}");
    }
}

/// The transitions that reach `phase` from `create_started`.
fn replay(phase: Phase) -> Vec<Transition> {
    let created = Transition::Created {
        hash: hash(LEAKED_HASH),
    };
    match phase {
        Phase::CreateStarted => Vec::new(),
        Phase::CreateAmbiguous => vec![Transition::CreateAmbiguous],
        Phase::Created => vec![created],
        Phase::Secured => vec![created, Transition::Secured],
        Phase::DeliveryStarted => vec![created, Transition::Secured, Transition::DeliveryStarted],
        Phase::DeliveryAmbiguous => vec![
            created,
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::DeliveryAmbiguous,
        ],
        Phase::Delivered => vec![
            created,
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::Delivered,
        ],
    }
}

fn configuration(vault: &Path) -> String {
    format!(
        r#"
version = 1

[receivers.vault]
type = "command"
program = "{program}"
args = ["record", "{vault}"]

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
disabled = true
receiver = "vault"
"#,
        program = env!("CARGO_BIN_EXE_keymaster-test-receiver"),
        vault = vault.display(),
    )
}

/// A remote key with a chosen name and creation time.
fn remote_key(hash: &str, name: &str, created_at: &str) -> Value {
    let mut key = api_key(hash, name);
    key["created_at"] = json!(created_at);
    key
}

/// The new key as OpenRouter has it once its restrictions are applied.
fn secured_key(hash: &str) -> Value {
    let mut key = api_key(hash, "golf-jobfeed");
    key["disabled"] = json!(true);
    key
}

/// Answers `GET /keys/{hash}` with a key in the state the caller chose.
fn serve_get(project: &Project, hash: &str, body: Value) {
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(json_response(200, &json!({ "data": body }))),
    );
}

/// Answers `PATCH /keys/{hash}` with an empty success.
fn serve_patch(project: &Project, hash: &str) {
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(json_response(200, &json!({}))),
    );
}

/// The candidate hashes an inspect document lists, in order.
fn candidates(document: &Value) -> Vec<String> {
    document["candidates"]
        .as_array()
        .expect("a candidate array")
        .iter()
        .map(|candidate| candidate["hash"].as_str().unwrap_or_default().to_owned())
        .collect()
}

// --- inspect -----------------------------------------------------------------

#[test]
fn inspect_reports_the_journal_and_never_writes_anything() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    world.project.observe(Vec::new(), Vec::new(), Vec::new());
    let before = fs::read(world.project.state_path()).expect("the state fixture");

    let streams = world
        .project
        .succeed(&["--json", "recover", "inspect", "jobfeed"]);
    let document = streams.document();

    let operation = &document["operation"];
    assert_eq!(operation["id"], OPERATION);
    assert_eq!(operation["phase"], "create_ambiguous");
    assert_eq!(operation["phase_at"], CLASSIFIED_AT);
    assert_eq!(operation["intended_name"], "golf-jobfeed");
    assert_eq!(operation["generation"], 1);
    assert_eq!(
        operation["receiver_fingerprint"],
        ReceiverFingerprint::from_digest([42; 32]).as_str(),
        "the non-secret digest of where the plaintext was bound for"
    );
    assert!(
        operation["known_hash"].is_null(),
        "the response never arrived, so no hash is known: {operation}"
    );
    assert!(
        document["remediation"]
            .as_str()
            .is_some_and(|text| text.contains("recover resolve jobfeed")),
        "{document}"
    );

    world.project.assert_read_only();
    assert_eq!(
        before,
        fs::read(world.project.state_path()).expect("the state file"),
        "inspect leaves the journal byte for byte as it found it"
    );
}

#[test]
fn inspect_lists_no_candidate_and_says_that_is_not_proof() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    // One remote key, with the wrong name and created a year before the
    // attempt: neither signal fires.
    world.project.observe(
        vec![remote_key(
            OTHER_HASH,
            "someone-elses",
            "2025-01-01T00:00:00Z",
        )],
        Vec::new(),
        Vec::new(),
    );

    let streams = world
        .project
        .succeed(&["--json", "recover", "inspect", "jobfeed"]);
    let document = streams.document();

    assert!(candidates(&document).is_empty(), "{document}");
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("not proof it created none"))),
        "an empty listing must not read as an all-clear: {document}"
    );
}

#[test]
fn inspect_lists_one_candidate_and_calls_it_a_candidate() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    world.project.observe(
        vec![remote_key(
            LEAKED_HASH,
            "golf-jobfeed",
            "2026-01-01T00:11:00Z",
        )],
        Vec::new(),
        Vec::new(),
    );

    let streams = world
        .project
        .succeed(&["--json", "recover", "inspect", "jobfeed"]);
    let document = streams.document();

    assert_eq!(candidates(&document), vec![LEAKED_HASH.to_owned()]);
    let candidate = &document["candidates"][0];
    assert_eq!(
        candidate["matched_on"],
        json!(["carries the intended name", "was created near the attempt"]),
        "both signals are reported separately: {candidate}"
    );
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("not as a match"))),
        "{document}"
    );

    let human = world
        .project
        .succeed(&["recover", "inspect", "jobfeed"])
        .out;
    assert!(
        human.contains("these are possibilities, not matches"),
        "{human}"
    );
}

#[test]
fn a_name_collision_lists_every_candidate_and_resolves_nothing() {
    // Two remote keys carry the intended name. A display name is mutable and
    // not unique, so this is exactly the case that must never resolve itself.
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    world.project.observe(
        vec![
            remote_key(LEAKED_HASH, "golf-jobfeed", "2026-01-01T00:11:00Z"),
            remote_key(OTHER_HASH, "golf-jobfeed", "2025-01-01T00:00:00Z"),
        ],
        Vec::new(),
        Vec::new(),
    );

    let document = world
        .project
        .succeed(&["--json", "recover", "inspect", "jobfeed"])
        .document();

    let listed = candidates(&document);
    assert_eq!(listed.len(), 2, "both are shown: {document}");
    assert!(listed.contains(&LEAKED_HASH.to_owned()));
    assert!(listed.contains(&OTHER_HASH.to_owned()));
    assert_eq!(
        world.journaled(),
        Some(Phase::CreateAmbiguous),
        "listing candidates resolves nothing"
    );
    world.project.assert_read_only();
}

#[test]
fn a_candidate_in_another_workspace_is_not_listed() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, true);
    let mut elsewhere = remote_key(OTHER_HASH, "golf-jobfeed", "2026-01-01T00:11:00Z");
    elsewhere["workspace_id"] = json!("00000000-0000-4000-8000-00000000dead");
    world.project.observe(
        vec![
            remote_key(LEAKED_HASH, "golf-jobfeed", "2026-01-01T00:11:00Z"),
            elsewhere,
        ],
        Vec::new(),
        Vec::new(),
    );

    let document = world
        .project
        .succeed(&["--json", "recover", "inspect", "jobfeed"])
        .document();

    assert_eq!(
        candidates(&document),
        vec![LEAKED_HASH.to_owned()],
        "a key the attempt could not have created is not a candidate: {document}"
    );
}

#[test]
fn a_key_another_address_already_owns_is_never_offered_as_a_candidate() {
    let world = Recovery::new();
    world.project.write_state(|state| {
        state
            .bind_key(&address("payroll"), hash(OTHER_HASH), 1, at(0))
            .expect("binding a key somewhere else");
        state
            .begin_create(
                &address("jobfeed"),
                BeginCreate {
                    operation: OperationId::parse(OPERATION).expect("an operation id"),
                    generation: 1,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([42; 32]),
                },
                at(600),
            )
            .expect("journaling the attempt");
    });
    world.project.observe(
        vec![remote_key(
            OTHER_HASH,
            "golf-jobfeed",
            "2026-01-01T00:11:00Z",
        )],
        Vec::new(),
        Vec::new(),
    );

    let document = world
        .project
        .succeed(&["--json", "recover", "inspect", "jobfeed"])
        .document();
    assert!(
        candidates(&document).is_empty(),
        "offering it would invite binding one remote key to two addresses: {document}"
    );
}

#[test]
fn inspect_says_plainly_when_there_is_nothing_to_recover() {
    let world = Recovery::new();
    world.project.observe(Vec::new(), Vec::new(), Vec::new());

    let document = world
        .project
        .succeed(&["--json", "recover", "inspect", "jobfeed"])
        .document();

    assert!(document["operation"].is_null());
    assert!(
        document["remediation"]
            .as_str()
            .is_some_and(|text| text.contains("nothing to recover")),
        "{document}"
    );
    world.project.server.assert_request_count(0);
}

#[test]
fn inspecting_an_operation_whose_hash_is_known_needs_no_credential_and_no_api() {
    // Every fact about a `secured` operation is on disk, and a candidate
    // listing would be meaningless: the journal already records the hash. So
    // this must work for an operator who has no management credential to hand
    // and no route to OpenRouter — which is exactly when a broken operation
    // most needs explaining.
    let world = Recovery::new();
    world.journal(Phase::Secured, false);

    let output = world
        .project
        .run_without_credential(&["--json", "recover", "inspect", "jobfeed"]);
    let streams = support::project::Streams::of(&output);
    world.project.assert_no_secret_escaped(&streams);

    assert_eq!(
        output.status.code(),
        Some(0),
        "inspect must not need a credential here:\n{}",
        streams.err
    );
    let document = streams.document();
    assert_eq!(document["operation"]["phase"], "secured");
    assert_eq!(document["operation"]["known_hash"], LEAKED_HASH);
    assert!(
        candidates(&document).is_empty(),
        "there is nothing to search for once the hash is journaled: {document}"
    );
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning array")
            .is_empty(),
        "and no listing means no warning about one: {document}"
    );
    assert!(
        document["remediation"]
            .as_str()
            .is_some_and(|text| text.contains("recover replace jobfeed")),
        "{document}"
    );
    world.project.server.assert_request_count(0);
}

#[test]
fn a_candidate_whose_remote_name_is_a_credential_is_reported_redacted() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    world.project.observe(
        vec![remote_key(
            LEAKED_HASH,
            SECRET_SENTINEL_KEY,
            "2026-01-01T00:11:00Z",
        )],
        Vec::new(),
        Vec::new(),
    );

    // `succeed` scans both streams and every file under the project.
    let streams = world.project.succeed(&["recover", "inspect", "jobfeed"]);
    assert!(streams.out.contains("[redacted]"), "{}", streams.out);
    assert!(streams.out.contains(LEAKED_HASH), "{}", streams.out);
}

/// The command `inspect` names for a phase is the command that phase accepts.
///
/// Two rules split the seven phases, and they are opposites: `recover resolve`
/// is refused once the journal records a hash, and `recover replace` is refused
/// while it does not. A remediation that named the wrong one would send an
/// operator holding a broken key to a command that rejects them, which is the
/// worst possible moment for that. So each phase is inspected, the command the
/// remediation names is then actually run, and it has to be accepted.
#[test]
fn every_phase_is_told_to_run_a_command_that_accepts_it() {
    for phase in [
        Phase::CreateStarted,
        Phase::CreateAmbiguous,
        Phase::Created,
        Phase::Secured,
        Phase::DeliveryStarted,
        Phase::DeliveryAmbiguous,
        Phase::Delivered,
    ] {
        let world = Recovery::new();
        world.journal(phase, false);
        world
            .project
            .observe(vec![secured_key(LEAKED_HASH)], Vec::new(), Vec::new());
        // Everything a replacement would need, so a phase that names one is
        // tested against a world where it can actually finish.
        serve_patch(&world.project, LEAKED_HASH);
        serve_get(&world.project, LEAKED_HASH, secured_key(LEAKED_HASH));
        serve_patch(&world.project, SUCCESSOR_HASH);
        serve_get(&world.project, SUCCESSOR_HASH, secured_key(SUCCESSOR_HASH));
        world.project.server.mount(
            Mock::given(method("POST"))
                .and(path("/api/v1/keys"))
                .respond_with(json_response(
                    200,
                    &created_key(SUCCESSOR_HASH, "golf-jobfeed", SECRET_SENTINEL_KEY),
                )),
        );

        let document = world
            .project
            .succeed(&["--json", "recover", "inspect", "jobfeed"])
            .document();
        let remediation = document["remediation"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let names_resolve = remediation.contains("keymaster recover resolve jobfeed");
        let names_replace = remediation.contains("keymaster recover replace jobfeed");
        assert!(
            !(names_resolve && names_replace),
            "{phase}: one command, not a menu: {remediation}"
        );

        if names_resolve {
            let resolved = world.project.succeed(&[
                "--json",
                "recover",
                "resolve",
                "jobfeed",
                "--no-resource-created",
            ]);
            assert_eq!(
                resolved.document()["resolved_from"],
                phase.as_str(),
                "{phase}: the command the remediation named accepted it"
            );
        } else if names_replace {
            let replaced = world
                .project
                .succeed(&["--json", "recover", "replace", "jobfeed"]);
            assert_eq!(
                replaced.document()["hash"],
                SUCCESSOR_HASH,
                "{phase}: the command the remediation named accepted it"
            );
        } else {
            assert_eq!(
                phase,
                Phase::Delivered,
                "{phase}: every unfinished phase names a `recover` command: {remediation}"
            );
            assert!(
                remediation.contains("keymaster apply"),
                "{phase}: {remediation}"
            );
            // Apply completes the promotion locally, which is the whole of
            // what `delivered` is waiting for.
            world.project.succeed(&["--json", "apply"]);
            assert_eq!(world.journaled(), None, "{phase}");
        }
    }
}

// --- resolve --no-resource-created --------------------------------------------

#[test]
fn attesting_absence_clears_the_operation_and_the_next_run_creates_afresh() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    world.project.observe(Vec::new(), Vec::new(), Vec::new());

    let document = world
        .project
        .succeed(&[
            "--json",
            "recover",
            "resolve",
            "jobfeed",
            "--no-resource-created",
        ])
        .document();

    assert_eq!(document["resolution"], "no_resource_created");
    assert_eq!(document["operation"], OPERATION);
    assert_eq!(document["resolved_from"], "create_ambiguous");
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("Keymaster has no way to check it"))),
        "an attestation Keymaster cannot verify says so: {document}"
    );
    assert_eq!(world.journaled(), None);
    assert_eq!(
        world.project.server.requests().len(),
        0,
        "an attestation of absence needs no remote call at all"
    );

    // The address is free again: the next plan proposes an ordinary create.
    let planned = world.project.succeed(&["--json", "plan"]).document();
    assert_eq!(planned["blocked"], Value::Bool(false));
    let create = planned["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == "keys.jobfeed")
        .expect("an action for the key");
    assert_eq!(create["kind"], "create");
}

#[test]
fn repeating_a_completed_resolution_is_a_clear_no_op() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    world.project.observe(Vec::new(), Vec::new(), Vec::new());

    world
        .project
        .succeed(&["recover", "resolve", "jobfeed", "--no-resource-created"]);
    let serial = world.project.read_state().serial();

    let document = world
        .project
        .succeed(&[
            "--json",
            "recover",
            "resolve",
            "jobfeed",
            "--no-resource-created",
        ])
        .document();

    assert!(document["operation"].is_null());
    assert!(
        document["summary"]
            .as_str()
            .is_some_and(|text| text.contains("nothing to resolve")),
        "{document}"
    );
    assert_eq!(
        world.project.read_state().serial(),
        serial,
        "a repeated resolution writes nothing"
    );
}

#[test]
fn another_writer_holding_the_lock_stops_a_resolution_before_it_reads_anything() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    fs::write(
        world.project.directory.path().join("state.json.lock"),
        "keymaster pid 1\n",
    )
    .expect("taking the lock");
    let before = fs::read(world.project.state_path()).expect("the state fixture");

    let streams = world.project.fail_silently(&[
        "--json",
        "recover",
        "resolve",
        "jobfeed",
        "--no-resource-created",
    ]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "state_locked");
    world.project.server.assert_request_count(0);
    assert_eq!(
        before,
        fs::read(world.project.state_path()).expect("the state file"),
        "a resolution that never took the lock resolved nothing"
    );
}

// --- resolve --leaked-hash -----------------------------------------------------

#[test]
fn a_leaked_hash_is_bound_disabled_verified_and_never_promoted() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    serve_patch(&world.project, LEAKED_HASH);
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{LEAKED_HASH}")))
            .respond_with(Scripted::new([
                // The fetch that proves the key exists, then the read that
                // confirms the disable took.
                json_response(
                    200,
                    &json!({ "data": remote_key(LEAKED_HASH, "golf-jobfeed", ATTEMPT_AT) }),
                ),
                json_response(200, &json!({ "data": secured_key(LEAKED_HASH) })),
            ])),
    );
    world.project.observe(Vec::new(), Vec::new(), Vec::new());

    let document = world
        .project
        .succeed(&[
            "--json",
            "recover",
            "resolve",
            "jobfeed",
            "--leaked-hash",
            LEAKED_HASH,
        ])
        .document();

    assert_eq!(document["resolution"], "leaked_hash");
    assert_eq!(document["retained"]["hash"], LEAKED_HASH);
    assert_eq!(document["retained"]["status"], "retired");
    assert!(
        document["cleanup"]
            .as_str()
            .is_some_and(|text| text.contains("confirmed that by reading it back")),
        "{document}"
    );

    let state = world.project.read_state();
    let binding = state.key(&address("jobfeed")).expect("the binding");
    assert!(binding.pending().is_none(), "the operation is closed");
    assert!(
        binding.current().is_none(),
        "a found hash is never promoted: its plaintext is unrecoverable"
    );
    assert_eq!(binding.retained().len(), 1);
    assert_eq!(binding.retained()[0].hash.as_str(), LEAKED_HASH);
    assert_eq!(binding.retained()[0].status, RetainedStatus::Retired);
    assert_eq!(
        world.deliveries(),
        0,
        "nothing re-delivers a lost plaintext"
    );
}

#[test]
fn a_leaked_hash_openrouter_does_not_have_leaves_state_unchanged() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{LEAKED_HASH}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": 404, "message": "no such key" }
            }))),
    );
    let before = fs::read(world.project.state_path()).expect("the state fixture");

    let streams = world.project.fail(&[
        "--json",
        "recover",
        "resolve",
        "jobfeed",
        "--leaked-hash",
        LEAKED_HASH,
    ]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "recover_absent");
    assert_eq!(
        before,
        fs::read(world.project.state_path()).expect("the state file"),
        "a hash that is not there binds nothing"
    );
    assert!(
        world.project.write_trace().is_empty(),
        "and nothing is disabled"
    );
}

#[test]
fn a_leaked_hash_whose_disable_fails_stays_tracked() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    serve_get(
        &world.project,
        LEAKED_HASH,
        remote_key(LEAKED_HASH, "golf-jobfeed", ATTEMPT_AT),
    );
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{LEAKED_HASH}")))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "error": { "code": 500, "message": "server exploded" }
            }))),
    );

    let document = world
        .project
        .succeed(&[
            "--json",
            "recover",
            "resolve",
            "jobfeed",
            "--leaked-hash",
            LEAKED_HASH,
        ])
        .document();

    assert_eq!(
        document["retained"]["status"], "failed_candidate",
        "a disable that failed leaves the hash tracked for a later retry: {document}"
    );
    assert!(
        document["cleanup"]
            .as_str()
            .is_some_and(|text| text.contains("disable it yourself")),
        "{document}"
    );

    let state = world.project.read_state();
    let binding = state.key(&address("jobfeed")).expect("the binding");
    assert_eq!(
        binding.retained()[0].status,
        RetainedStatus::FailedCandidate
    );
    assert!(binding.pending().is_none());
}

#[test]
fn a_state_write_that_fails_leaves_the_operation_exactly_as_it_was() {
    let world = Recovery::new();
    world.journal(Phase::CreateAmbiguous, false);
    exhaust_the_serial(&world.project);
    world.project.observe(Vec::new(), Vec::new(), Vec::new());
    let before = fs::read(world.project.state_path()).expect("the state fixture");

    let streams = world.project.fail(&[
        "--json",
        "recover",
        "resolve",
        "jobfeed",
        "--no-resource-created",
    ]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "state_serial_exhausted"
    );
    assert_eq!(
        before,
        fs::read(world.project.state_path()).expect("the state file"),
        "a resolution that could not be recorded resolved nothing"
    );
    assert_eq!(world.journaled(), Some(Phase::CreateAmbiguous));
}

/// Puts the state file's serial at its ceiling, so every further write fails.
///
/// The narrowest way to make a state write fail from outside the process: the
/// document stays valid and every invariant still holds, so the run reaches the
/// write and only the write fails.
fn exhaust_the_serial(project: &Project) {
    let source = fs::read_to_string(project.state_path()).expect("the state fixture");
    let mut document: Value = serde_json::from_str(&source).expect("a JSON state file");
    document["serial"] = json!(u64::MAX);
    fs::write(
        project.state_path(),
        serde_json::to_string(&document).expect("a serializable state file"),
    )
    .expect("writing the state file");
}

#[test]
fn a_leaked_hash_is_refused_once_the_journal_records_one() {
    let world = Recovery::new();
    world.journal(Phase::Secured, false);

    let streams = world.project.fail(&[
        "--json",
        "recover",
        "resolve",
        "jobfeed",
        "--leaked-hash",
        OTHER_HASH,
    ]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "recover_hash_already_known"
    );
    world.project.server.assert_request_count(0);
    assert_eq!(world.journaled(), Some(Phase::Secured));
}

// --- replace -------------------------------------------------------------------

#[test]
fn replace_is_refused_while_it_is_unknown_whether_a_key_exists() {
    for phase in [Phase::CreateStarted, Phase::CreateAmbiguous] {
        let world = Recovery::new();
        world.journal(phase, false);

        let streams = world
            .project
            .fail(&["--json", "recover", "replace", "jobfeed"]);

        assert_eq!(
            streams.diagnostic()["error"]["kind"],
            "recover_ambiguity_unresolved",
            "{phase}"
        );
        world.project.server.assert_request_count(0);
        assert_eq!(world.journaled(), Some(phase), "{phase}");
        assert_eq!(world.deliveries(), 0, "{phase}");
    }
}

#[test]
fn replace_retires_the_dead_key_and_stages_a_successor_under_one_lock() {
    let world = Recovery::new();
    world.journal(Phase::Secured, false);
    // The dead key is disabled and confirmed; the successor is created,
    // restricted, verified, and delivered.
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{LEAKED_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    serve_get(&world.project, LEAKED_HASH, secured_key(LEAKED_HASH));
    world.project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                200,
                &created_key(SUCCESSOR_HASH, "golf-jobfeed", SECRET_SENTINEL_KEY),
            )),
    );
    serve_patch(&world.project, SUCCESSOR_HASH);
    serve_get(&world.project, SUCCESSOR_HASH, secured_key(SUCCESSOR_HASH));

    let document = world
        .project
        .succeed(&["--json", "recover", "replace", "jobfeed"])
        .document();

    assert_eq!(document["retired_operation"], OPERATION);
    assert_eq!(document["retired"]["hash"], LEAKED_HASH);
    assert_eq!(document["retired"]["status"], "retired");
    assert_eq!(document["hash"], SUCCESSOR_HASH);
    assert_eq!(
        document["generation"], 2,
        "the dead candidate holds generation 1, so the successor takes the next one"
    );
    assert_eq!(document["promoted"], Value::Bool(true));

    assert_eq!(
        world
            .project
            .request_trace()
            .iter()
            .filter(|request| *request == "POST /api/v1/keys")
            .count(),
        1,
        "one create, for the successor, and none for the key that is beyond saving"
    );
    assert_eq!(world.deliveries(), 1, "the successor is delivered once");

    let state = world.project.read_state();
    let binding = state.key(&address("jobfeed")).expect("the binding");
    assert_eq!(
        binding.current().expect("a promoted key").hash.as_str(),
        SUCCESSOR_HASH
    );
    assert!(binding.pending().is_none());
    assert_eq!(
        binding.retained()[0].hash.as_str(),
        LEAKED_HASH,
        "the dead key stays tracked so it can be deleted explicitly"
    );
}

#[test]
fn replace_is_how_a_delivery_ambiguity_is_resolved() {
    // v0.1 has no receiver query contract, so a lost acknowledgement can never
    // be attested as delivered. Replacement is the resolution, and it must not
    // re-invoke the receiver for the key whose delivery is in doubt.
    let world = Recovery::new();
    world.journal(Phase::DeliveryAmbiguous, false);
    serve_patch(&world.project, LEAKED_HASH);
    serve_get(&world.project, LEAKED_HASH, secured_key(LEAKED_HASH));
    world.project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                200,
                &created_key(SUCCESSOR_HASH, "golf-jobfeed", SECRET_SENTINEL_KEY),
            )),
    );
    serve_patch(&world.project, SUCCESSOR_HASH);
    serve_get(&world.project, SUCCESSOR_HASH, secured_key(SUCCESSOR_HASH));

    let document = world
        .project
        .succeed(&["--json", "recover", "replace", "jobfeed"])
        .document();

    assert_eq!(document["hash"], SUCCESSOR_HASH);
    assert_eq!(
        world.deliveries(),
        1,
        "exactly one delivery, and it is the successor's: the ambiguous one is never retried"
    );
    assert_eq!(
        world.journaled(),
        None,
        "the ambiguity is resolved by replacement, not by an attestation"
    );
}

#[test]
fn replace_refuses_rather_than_creating_a_second_key_when_nothing_is_pending() {
    let world = Recovery::new();
    world.project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(LEAKED_HASH), 1, at(0))
            .expect("binding a working key");
    });
    world.project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                200,
                &created_key(SUCCESSOR_HASH, "golf-jobfeed", SECRET_SENTINEL_KEY),
            )),
    );

    let streams = world
        .project
        .fail(&["--json", "recover", "replace", "jobfeed"]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "recover_nothing_to_replace"
    );
    assert!(
        streams.err.contains("keymaster rotate"),
        "the error names the command for a working key: {}",
        streams.err
    );
    world.project.server.assert_request_count(0);
    assert_eq!(world.deliveries(), 0);
}

#[test]
fn replace_refuses_a_delivered_operation_apply_would_finish_locally() {
    let world = Recovery::new();
    world.journal(Phase::Delivered, false);

    let streams = world
        .project
        .fail(&["--json", "recover", "replace", "jobfeed"]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "recover_already_delivered"
    );
    assert_eq!(world.journaled(), Some(Phase::Delivered));
    world.project.server.assert_request_count(0);
}

#[test]
fn a_successor_that_cannot_be_created_leaves_the_dead_key_alone() {
    // The ordering this asserts is the difference between a replacement and an
    // outage. The key about to be retired may be live, and disabling it before
    // discovering that no successor can be created would leave the address with
    // a disabled key and nothing to replace it.
    let world = Recovery::without_a_receiver();
    world.journal(Phase::Secured, false);
    // Mounted so that a run which got as far as touching the key would succeed
    // at it, and the assertion below would therefore fail loudly.
    serve_patch(&world.project, LEAKED_HASH);
    serve_get(&world.project, LEAKED_HASH, secured_key(LEAKED_HASH));
    world.project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                200,
                &created_key(SUCCESSOR_HASH, "golf-jobfeed", SECRET_SENTINEL_KEY),
            )),
    );
    let before = fs::read(world.project.state_path()).expect("the state fixture");

    let streams = world
        .project
        .fail(&["--json", "recover", "replace", "jobfeed"]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "recover_unstageable");
    assert!(
        streams.err.contains("names no receiver"),
        "the error says what is missing: {}",
        streams.err
    );
    assert!(
        streams.err.contains("Nothing was changed"),
        "and that nothing was touched: {}",
        streams.err
    );

    assert!(
        world.project.write_trace().is_empty(),
        "no write of any kind: not the disable, and certainly not a create: {:?}",
        world.project.write_trace()
    );
    assert_eq!(world.deliveries(), 0);
    assert_eq!(
        world.journaled(),
        Some(Phase::Secured),
        "the operation still stands, so a fixed configuration can retry"
    );
    assert_eq!(
        before,
        fs::read(world.project.state_path()).expect("the state file"),
        "and the journal is byte for byte as it was"
    );
    assert!(
        world
            .project
            .read_state()
            .key(&address("jobfeed"))
            .expect("the binding")
            .retained()
            .is_empty(),
        "nothing was retired"
    );
}

#[test]
fn a_failed_replacement_leaves_the_dead_key_retired_and_nothing_created() {
    // The successor's create is ambiguous. The dead key has already been
    // retired, which is the point of retiring it first: it stays tracked
    // whatever becomes of the replacement.
    let world = Recovery::new();
    world.journal(Phase::Secured, false);
    serve_patch(&world.project, LEAKED_HASH);
    serve_get(&world.project, LEAKED_HASH, secured_key(LEAKED_HASH));
    world.project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "error": { "code": 500, "message": "server exploded" }
            }))),
    );

    let streams = world
        .project
        .fail(&["--json", "recover", "replace", "jobfeed"]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "recover_issuance");
    assert_absent("stderr", &streams.err);
    assert_eq!(world.deliveries(), 0);
    assert_eq!(
        world.journaled(),
        Some(Phase::CreateAmbiguous),
        "the successor's own attempt is now the unresolved one"
    );

    let state: State = world.project.read_state();
    let binding = state.key(&address("jobfeed")).expect("the binding");
    assert_eq!(binding.retained().len(), 1);
    assert_eq!(binding.retained()[0].hash.as_str(), LEAKED_HASH);
    assert_eq!(binding.retained()[0].status, RetainedStatus::Retired);
}
