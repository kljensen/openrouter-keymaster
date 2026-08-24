//! Binary-level tests for staged rotation and the three explicit endings.
//!
//! One rule runs through all of them, and it is the reason `rotate`, `retire`,
//! and `delete key` are three commands rather than one: **the predecessor is
//! never touched by the thing that replaces it.** Keymaster cannot know when a
//! downstream deployment has adopted a new credential, so it stages the
//! successor, promotes it, and stops. Every case below asserts that in the two
//! ways that can actually catch a regression — the order and content of the
//! requests the server saw, and the shape of the state file afterwards.
//!
//! The receiver is the purpose-built helper binary, which records every run, so
//! "delivered exactly once" is measured rather than assumed. It writes into a
//! directory outside the project, because what it writes is a live credential
//! and the project directory is scanned for exactly that.

mod support;

use std::fs;
use std::path::Path;

use openrouter_keymaster::ids::{OperationId, ReceiverFingerprint, RemoteName};
use openrouter_keymaster::state::{BeginCreate, Origin, RetainedStatus, State, Transition};
use serde_json::{Value, json};
use support::fixtures::{FAKE_GUARDRAIL_ID, api_key, assignment, created_key, guardrail};
use support::http::{Scripted, json_response};
use support::project::{Project, Streams, address, at, hash, uuid};
use support::sentinel::SECRET_SENTINEL_KEY;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// The key the address already owns when a rotation starts.
const OLD_HASH: &str = "hash-jobfeed-1";
/// The key `POST /keys` hands back.
const NEW_HASH: &str = "hash-jobfeed-2";
/// A hash no local address owns.
const STRAY_HASH: &str = "hash-nobodys";

const ASSIGNMENT_ID: &str = "44444444-4444-4444-8444-444444444444";

/// A project whose one key delivers through the helper binary.
struct World {
    project: Project,
    vault: TempDir,
}

impl World {
    /// A project whose key is delivered by the helper in `mode`.
    fn new(mode: &str) -> Self {
        let vault = tempfile::tempdir().expect("a temporary vault directory");
        let project = Project::new(&configuration(vault.path(), mode, ""));
        Self { project, vault }
    }

    /// The same, with extra key configuration appended.
    fn with(mode: &str, extra: &str) -> Self {
        let vault = tempfile::tempdir().expect("a temporary vault directory");
        let project = Project::new(&configuration(vault.path(), mode, extra));
        Self { project, vault }
    }

    /// How many times the receiver program ran. Absent means never.
    fn deliveries(&self) -> usize {
        fs::read_to_string(self.vault.path().join("runs.txt"))
            .map(|runs| runs.lines().count())
            .unwrap_or_default()
    }

    /// The fingerprint of the receiver this project configures.
    ///
    /// A journal fixture has to record the destination the configuration names,
    /// or a plan computed after the operation is promoted reads the difference
    /// as "the receiver moved" and asks to replace a key that is perfectly good.
    fn receiver_fingerprint(&self) -> ReceiverFingerprint {
        let source = fs::read_to_string(self.project.config_path()).expect("the configuration");
        openrouter_keymaster::config::Config::parse(&source)
            .expect("a valid test configuration")
            .receivers
            .values()
            .next()
            .expect("one receiver")
            .fingerprint()
    }

    /// Binds `OLD_HASH` as the address's current key, at generation 1.
    ///
    /// Bound rather than journaled: this is the ordinary starting point for a
    /// rotation — an address with a key that works.
    fn owning_a_working_key(&self) {
        self.project.write_state(|state| {
            state
                .bind_key(&address("jobfeed"), hash(OLD_HASH), 1, at(0))
                .expect("binding the working key");
        });
    }

    /// The key binding as the state file now holds it.
    fn binding(&self) -> openrouter_keymaster::state::KeyBinding {
        self.project
            .read_state()
            .key(&address("jobfeed"))
            .cloned()
            .expect("a binding at `jobfeed`")
    }

    /// The hash the address currently uses, if it uses one.
    fn current(&self) -> Option<String> {
        self.binding()
            .current()
            .map(|current| current.hash.as_str().to_owned())
    }

    /// Every retained hash and its status, in state order.
    fn retained(&self) -> Vec<(String, RetainedStatus)> {
        self.binding()
            .retained()
            .iter()
            .map(|retained| (retained.hash.as_str().to_owned(), retained.status))
            .collect()
    }
}

/// One key at generation 1, delivered to the helper.
fn configuration(vault: &Path, mode: &str, extra: &str) -> String {
    format!(
        r#"
version = 1

[receivers.vault]
type = "command"
program = "{program}"
args = ["{mode}", "{vault}"]

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
disabled = true
receiver = "vault"
{extra}
"#,
        program = env!("CARGO_BIN_EXE_openrouter-keymaster-test-receiver"),
        vault = vault.display(),
    )
}

/// A key as OpenRouter has it once its restrictions are applied.
fn secured_key(hash: &str) -> Value {
    let mut key = api_key(hash, "golf-jobfeed");
    key["disabled"] = json!(true);
    key
}

/// Answers `POST /keys` with a created key carrying the secret sentinel.
fn serve_create(project: &Project, hash: &str) {
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                200,
                &created_key(hash, "golf-jobfeed", SECRET_SENTINEL_KEY),
            )),
    );
}

/// Answers the `PATCH` and the verifying `GET` the transaction makes.
fn serve_secure(project: &Project, hash: &str) {
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(json_response(200, &json!({}))),
    );
    serve_get(project, hash, secured_key(hash));
}

/// Answers `GET /keys/{hash}` with a key in the state the caller chose.
fn serve_get(project: &Project, hash: &str, body: Value) {
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(json_response(200, &json!({ "data": body }))),
    );
}

/// Answers `GET /keys/{hash}` with a confirmed 404.
fn serve_missing(project: &Project, hash: &str) {
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": 404, "message": "no such key" }
            }))),
    );
}

/// Everything a successful rotation needs from the server.
fn serve_rotation(project: &Project) {
    serve_create(project, NEW_HASH);
    serve_secure(project, NEW_HASH);
    project.observe_sequence(
        vec![
            vec![api_key(OLD_HASH, "golf-jobfeed")],
            vec![api_key(OLD_HASH, "golf-jobfeed"), secured_key(NEW_HASH)],
        ],
        vec![Vec::new()],
        vec![Vec::new()],
    );
}

/// The requests the server saw, as `METHOD /path`.
fn trace(project: &Project) -> Vec<String> {
    project.request_trace()
}

/// Where a request first appears in the trace, or the trace's length.
fn first(trace: &[String], request: &str) -> usize {
    trace
        .iter()
        .position(|seen| seen == request)
        .unwrap_or(trace.len())
}

// --- rotate ------------------------------------------------------------------

#[test]
fn rotate_stages_a_successor_and_leaves_the_predecessor_enabled_and_tracked() {
    let world = World::new("record");
    world.owning_a_working_key();
    serve_rotation(&world.project);

    let document = world
        .project
        .succeed(&["--json", "rotate", "jobfeed"])
        .document();

    assert_eq!(document["hash"], NEW_HASH);
    assert_eq!(
        document["generation"], 2,
        "the successor takes the next free generation: {document}"
    );
    assert_eq!(document["promoted"], Value::Bool(true));
    assert_eq!(document["predecessor"]["hash"], OLD_HASH);
    assert_eq!(document["predecessor"]["generation"], 1);
    assert_eq!(document["predecessor"]["status"], "awaiting_retirement");
    assert!(
        document["summary"]
            .as_str()
            .is_some_and(|text| text.contains("still enabled")),
        "{document}"
    );

    assert_eq!(world.deliveries(), 1, "the successor is delivered once");
    assert_eq!(world.current(), Some(NEW_HASH.to_owned()));
    assert_eq!(
        world.retained(),
        vec![(OLD_HASH.to_owned(), RetainedStatus::AwaitingRetirement)]
    );

    // The only writes are the successor's. Nothing addressed the predecessor.
    assert_eq!(
        world.project.write_trace(),
        vec![
            "POST /api/v1/keys".to_owned(),
            format!("PATCH /api/v1/keys/{NEW_HASH}"),
        ],
    );
    assert!(
        !trace(&world.project)
            .iter()
            .any(|request| request.ends_with(OLD_HASH)),
        "the predecessor was not even read: {:?}",
        trace(&world.project)
    );
}

/// The acceptance criterion in its own test, asserted the only two ways it can
/// be: request order, and the state the run left.
///
/// A retirement is a `PATCH` that disables the predecessor. This asserts that no
/// such request exists at all while the successor is being created, secured,
/// verified, delivered, and promoted — and then that running `retire`
/// explicitly is what finally produces one, strictly afterwards.
#[test]
fn create_secure_verify_deliver_and_promote_all_precede_any_retirement() {
    let world = World::new("record");
    world.owning_a_working_key();
    serve_rotation(&world.project);
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{OLD_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );

    world.project.succeed(&["--json", "rotate", "jobfeed"]);
    let after_rotation = trace(&world.project);

    assert!(
        !after_rotation.contains(&format!("PATCH /api/v1/keys/{OLD_HASH}")),
        "rotation must send nothing at the predecessor, and the route is mounted \
         so that a run which did would succeed and be caught here: {after_rotation:?}"
    );
    let created = first(&after_rotation, "POST /api/v1/keys");
    let secured = first(&after_rotation, &format!("PATCH /api/v1/keys/{NEW_HASH}"));
    let verified = first(&after_rotation, &format!("GET /api/v1/keys/{NEW_HASH}"));
    assert!(
        created < secured && secured < verified,
        "create, then restrict, then verify: {after_rotation:?}"
    );
    assert_eq!(
        world.retained(),
        vec![(OLD_HASH.to_owned(), RetainedStatus::AwaitingRetirement)],
        "the promotion happened, and it retired nothing"
    );

    // Only now, and only because an operator asked.
    serve_get(&world.project, OLD_HASH, secured_key(OLD_HASH));
    world
        .project
        .succeed(&["--json", "retire", "jobfeed", "--hash", OLD_HASH]);

    let retirement = first(
        &trace(&world.project),
        &format!("PATCH /api/v1/keys/{OLD_HASH}"),
    );
    assert!(
        retirement > after_rotation.len(),
        "the predecessor's first write belongs to the retirement run, not the rotation"
    );
    assert_eq!(
        world.retained(),
        vec![(OLD_HASH.to_owned(), RetainedStatus::Retired)]
    );
}

#[test]
fn a_rotation_whose_receiver_refuses_leaves_the_old_current_key_untouched() {
    // The successor is created and secured, and the receiver definitely refuses
    // it. The address must come out of this still using the key it had.
    let world = World::new("reject");
    world.owning_a_working_key();
    serve_rotation(&world.project);
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{OLD_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let streams = world.project.fail(&["--json", "rotate", "jobfeed"]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "rotate_issuance");
    assert_eq!(
        world.current(),
        Some(OLD_HASH.to_owned()),
        "the working key is still the working key"
    );
    assert_eq!(
        world.binding().current().expect("a current key").generation,
        1
    );
    assert!(
        world.retained().is_empty(),
        "and nothing was retired: {:?}",
        world.retained()
    );
    assert!(
        !trace(&world.project).contains(&format!("PATCH /api/v1/keys/{OLD_HASH}")),
        "the predecessor was never written to: {:?}",
        trace(&world.project)
    );
    // The successor, whose plaintext is gone, is the one Keymaster disables.
    assert!(
        trace(&world.project).contains(&format!("PATCH /api/v1/keys/{NEW_HASH}")),
        "{:?}",
        trace(&world.project)
    );
}

#[test]
fn a_rotation_that_cannot_be_staged_sends_nothing_and_changes_nothing() {
    // No receiver, so no successor is possible. The preflight has to catch that
    // before anything is journaled or sent.
    let project = Project::new(
        "version = 1\n\n[keys.jobfeed]\nname = \"golf-jobfeed\"\nlimit_usd = 5\n\
         limit_reset = \"monthly\"\n",
    );
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(OLD_HASH), 1, at(0))
            .expect("binding the working key");
    });
    project.observe(
        vec![api_key(OLD_HASH, "golf-jobfeed")],
        Vec::new(),
        Vec::new(),
    );
    let before = fs::read(project.state_path()).expect("the state fixture");

    let streams = project.fail(&["--json", "rotate", "jobfeed"]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "rotate_unstageable");
    assert!(
        streams.err.contains("names no receiver"),
        "the error says what is missing: {}",
        streams.err
    );
    assert!(project.write_trace().is_empty(), "no write of any kind");
    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "and the state file is byte for byte as it was"
    );
}

#[test]
fn rotate_is_refused_while_an_operation_is_pending() {
    let world = World::new("record");
    world.project.write_state(|state| {
        state
            .begin_create(
                &address("payroll"),
                BeginCreate {
                    operation: OperationId::parse("op-0007").expect("an operation id"),
                    generation: 1,
                    name: RemoteName::parse("golf-payroll").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([7; 32]),
                },
                at(0),
            )
            .expect("journaling an attempt somewhere else");
        state
            .bind_key(&address("jobfeed"), hash(OLD_HASH), 1, at(0))
            .expect("binding the working key");
    });
    serve_rotation(&world.project);

    let streams = world.project.fail(&["--json", "rotate", "jobfeed"]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "rotate_operation_pending"
    );
    assert!(streams.err.contains("op-0007"), "{}", streams.err);
    assert!(
        streams.err.contains("openrouter-keymaster recover"),
        "an unresolved attempt is an operator's to close: {}",
        streams.err
    );
    world.project.server.assert_request_count(0);
    assert_eq!(world.deliveries(), 0);
    assert_eq!(world.current(), Some(OLD_HASH.to_owned()));
}

/// The command a delivered refusal names actually clears it.
///
/// The sweep above checks that every refusal for `delivered` says `apply`. This
/// checks the claim: advice an operator follows and finds does not work is
/// worse than no advice, so the command is run and the operation has to be
/// gone afterwards.
#[test]
fn the_command_a_delivered_refusal_names_does_clear_it() {
    let world = after_a_delivery();
    // Both keys are already there: once the promotion lands there is nothing
    // left for the `apply` below to converge, so what it does is exactly the
    // one thing the refusal promises.
    world.project.observe(
        vec![api_key(OLD_HASH, "golf-jobfeed"), secured_key(NEW_HASH)],
        Vec::new(),
        Vec::new(),
    );

    let streams = world.project.fail(&["--json", "rotate", "jobfeed"]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "rotate_promotion_pending"
    );
    assert!(
        streams.err.contains("openrouter-keymaster apply"),
        "the refusal names the command that clears this phase: {}",
        streams.err
    );
    world.project.server.assert_request_count(0);
    assert_eq!(world.deliveries(), 0);

    world.project.succeed(&["--json", "apply"]);
    assert!(world.project.read_state().pending_operation().is_none());
    assert_eq!(world.current(), Some(NEW_HASH.to_owned()));
}

#[test]
fn rotate_refuses_an_address_that_owns_no_key() {
    let world = World::new("record");
    serve_rotation(&world.project);

    let streams = world.project.fail(&["--json", "rotate", "jobfeed"]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "rotate_no_current_key"
    );
    world.project.server.assert_request_count(0);
    assert_eq!(world.deliveries(), 0);
}

/// A generation only ever moves upward, whatever the configuration says.
///
/// The configuration here still asks for generation 1 while the address already
/// records 4, and the successor must take 5 rather than reusing a number that
/// names a key the address still owns. Reuse is what the state API rejects, and
/// this is the path that could have offered it one.
#[test]
fn a_successor_never_reuses_a_generation_the_address_records() {
    let world = World::new("record");
    world.project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(OLD_HASH), 4, at(0))
            .expect("binding a key at generation 4");
    });
    serve_rotation(&world.project);

    let document = world
        .project
        .succeed(&["--json", "rotate", "jobfeed"])
        .document();

    assert_eq!(document["generation"], 5, "{document}");
    assert_eq!(world.binding().settled_generation(), 5);
}

/// A rotation interrupted between `delivered` and the promotion.
///
/// The successor exists, is verified, and its plaintext has been committed;
/// only the local promotion is outstanding. The next `apply` completes it under
/// its lock, and that is when — and the only reason — the predecessor becomes
/// retained.
#[cfg(feature = "fault-injection")]
#[test]
fn current_and_retained_identities_survive_a_crash_before_the_promotion() {
    use openrouter_keymaster::state::{Phase, STATE_FAULT_VAR};

    let world = World::new("record");
    world.owning_a_working_key();
    serve_rotation(&world.project);

    // Six writes: create_started, created, secured, delivery_started,
    // delivered, promotion. Failing the sixth before its rename leaves
    // `delivered` on disk.
    let output = world.project.run_with(
        &["--json", "rotate", "jobfeed"],
        &[(STATE_FAULT_VAR, "before_rename@6")],
    );
    let streams = Streams::of(&output);
    world.project.assert_no_secret_escaped(&streams);

    // The run still succeeds: the transaction is over and nothing remote is
    // outstanding. What it must not do is claim the successor is in use.
    assert_eq!(output.status.code(), Some(0), "{}", streams.err);
    let document = streams.document();
    assert_eq!(document["promoted"], Value::Bool(false));
    assert_eq!(
        document["predecessor"]["status"], "still_current",
        "the promotion did not land, so the old key is still the one in use: {document}"
    );
    let summary = document["summary"].as_str().unwrap_or_default();
    assert!(
        !summary.contains("now uses") && summary.contains("still using key"),
        "the summary must not claim the successor is in service: {summary}"
    );

    let state = world.project.read_state();
    let (_, pending) = state.pending_operation().expect("a delivered operation");
    assert_eq!(pending.phase, Phase::Delivered);
    assert_eq!(
        world.current(),
        Some(OLD_HASH.to_owned()),
        "until the promotion lands, the predecessor is still the current key"
    );
    assert_eq!(world.deliveries(), 1);

    let restarted = world.project.succeed(&["--json", "apply"]).document();

    assert!(
        restarted["warnings"]
            .as_array()
            .expect("a warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("completed that promotion"))),
        "{restarted}"
    );
    assert_eq!(world.current(), Some(NEW_HASH.to_owned()));
    assert_eq!(
        world.retained(),
        vec![(OLD_HASH.to_owned(), RetainedStatus::AwaitingRetirement)]
    );
    assert_eq!(world.deliveries(), 1, "nothing was re-delivered");
}

// --- apply's own rotation ------------------------------------------------------

/// A guardrailed project whose predecessor is bound at generation 1, and a
/// server that answers everything a replacement needs.
fn a_guardrailed_rotation() -> World {
    let world = World::with(
        "record",
        "generation = 2\nguardrail = \"cheap\"\n\n[guardrails.cheap]\n\
         name = \"cheap-rail\"\nlimit_usd = 10\nreset_interval = \"monthly\"\n",
    );
    world.project.write_state(|state| {
        state
            .bind_guardrail(
                &address("cheap"),
                uuid(FAKE_GUARDRAIL_ID),
                Origin::Imported,
                at(0),
            )
            .expect("binding the guardrail");
        state
            .bind_key(&address("jobfeed"), hash(OLD_HASH), 1, at(0))
            .expect("binding the predecessor");
    });
    serve_create(&world.project, NEW_HASH);
    serve_secure(&world.project, NEW_HASH);
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}")))
            .respond_with(json_response(
                200,
                &json!({ "data": guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[]) }),
            )),
    );
    world.project.server.mount(
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/guardrails/{FAKE_GUARDRAIL_ID}/assignments/keys"
            )))
            .respond_with(json_response(200, &json!({}))),
    );
    // The assignment listing gains the successor's row after the assignment,
    // which is what the transaction's verification reads.
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/guardrails/{FAKE_GUARDRAIL_ID}/assignments/keys"
            )))
            .respond_with(Scripted::json([
                json!({ "data": [assignment(ASSIGNMENT_ID, NEW_HASH, FAKE_GUARDRAIL_ID)] }),
                json!({ "data": [] }),
            ])),
    );
    world.project.observe_sequence(
        vec![
            vec![api_key(OLD_HASH, "golf-jobfeed")],
            vec![api_key(OLD_HASH, "golf-jobfeed"), secured_key(NEW_HASH)],
        ],
        vec![vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])]],
        vec![
            Vec::new(),
            vec![assignment(ASSIGNMENT_ID, NEW_HASH, FAKE_GUARDRAIL_ID)],
        ],
    );
    world
}

/// The configuration asks for generation 2, so the planner proposes a
/// replacement and apply runs the same transaction.
#[test]
fn a_planned_replacement_runs_the_transaction_and_assigns_only_the_successor() {
    let world = a_guardrailed_rotation();

    let document = world.project.succeed(&["--json", "apply"]).document();

    let key = action(&document, "keys.jobfeed");
    assert_eq!(key["kind"], "replace");
    assert_eq!(key["status"], "applied");
    assert!(
        key["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains(OLD_HASH) && detail.contains("untouched")),
        "the outcome names the predecessor it left alone: {key}"
    );

    let assigned = action(&document, "keys.jobfeed.guardrail");
    assert_eq!(assigned["status"], "applied");
    assert!(
        assigned["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("journaled creation")),
        "the assignment was made inside the transaction: {assigned}"
    );

    assert_eq!(world.current(), Some(NEW_HASH.to_owned()));
    assert_eq!(
        world.retained(),
        vec![(OLD_HASH.to_owned(), RetainedStatus::AwaitingRetirement)]
    );
    assert!(
        !trace(&world.project)
            .iter()
            .any(|request| request.starts_with("PATCH") && request.ends_with(OLD_HASH)),
        "the predecessor keeps its own guardrail and its own settings: {:?}",
        trace(&world.project)
    );
}

/// A changed `creator_user_id` is a rotation trigger, and the create body is
/// the only place the new value can go.
///
/// OpenRouter accepts `creator_user_id` on `POST /keys` and has no field for it
/// on `PATCH /keys/{hash}`, so an existing key can never be moved to a new
/// creator. That makes it the third immutable key field, beside `expires_at`
/// and `workspace_id` — and makes this the test that the value actually reaches
/// the wire, rather than being diffed and then dropped.
#[test]
fn a_changed_creator_replaces_the_key_and_the_create_body_carries_the_new_one() {
    const CREATOR: &str = "user_2dHFtVWx2n56w6HkM0000000000";

    let world = World::with("record", &format!("creator_user_id = \"{CREATOR}\"\n"));
    world.owning_a_working_key();

    // The successor reads back with the configured creator; the predecessor
    // carries the fixture's, which is what makes them differ.
    let mut successor = secured_key(NEW_HASH);
    successor["creator_user_id"] = json!(CREATOR);
    serve_create(&world.project, NEW_HASH);
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{NEW_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    serve_get(&world.project, NEW_HASH, successor.clone());
    world.project.observe_sequence(
        vec![
            vec![api_key(OLD_HASH, "golf-jobfeed")],
            vec![api_key(OLD_HASH, "golf-jobfeed"), successor],
        ],
        vec![Vec::new()],
        vec![Vec::new()],
    );

    let planned = world.project.succeed(&["--json", "plan"]).document();
    let key = action(&planned, "keys.jobfeed");
    assert_eq!(key["kind"], "replace");
    assert!(
        serde_json::to_string(&key["changes"])
            .expect("the changes serialize")
            .contains("creator_user_id"),
        "the plan names the field that forces the replacement: {key}"
    );

    let document = world.project.succeed(&["--json", "apply"]).document();
    assert_eq!(action(&document, "keys.jobfeed")["status"], "applied");

    let created = world
        .project
        .server
        .requests()
        .into_iter()
        .find(|request| request.method.as_str() == "POST" && request.url.path().ends_with("/keys"))
        .expect("one POST /keys");
    assert_eq!(
        support::http::body_json(&created)["creator_user_id"],
        CREATOR,
        "the create body is the only place a creator can be set"
    );

    assert_eq!(world.current(), Some(NEW_HASH.to_owned()));
    assert_eq!(
        world.retained(),
        vec![(OLD_HASH.to_owned(), RetainedStatus::AwaitingRetirement)]
    );
}

/// A replacement whose promotion did not persist must not report the
/// predecessor as retired.
///
/// Promotion is a durable write of its own. Until it lands the predecessor is
/// still the address's current key, so an outcome saying it is
/// `awaiting_retirement` — and naming the `retire` command for it — would be
/// pointing an operator at the key everything is still using.
#[cfg(feature = "fault-injection")]
#[test]
fn a_replacement_whose_promotion_failed_does_not_call_the_predecessor_retired() {
    use openrouter_keymaster::state::{Phase, STATE_FAULT_VAR};

    let world = a_guardrailed_rotation();

    // Six writes reach the promotion; failing the sixth before its rename
    // leaves `delivered` on disk and the predecessor still current.
    let output = world.project.run_with(
        &["--json", "apply"],
        &[(STATE_FAULT_VAR, "before_rename@6")],
    );
    let streams = Streams::of(&output);
    world.project.assert_no_secret_escaped(&streams);

    let document = streams.document();
    let key = action(&document, "keys.jobfeed");
    let detail = key["detail"].as_str().unwrap_or_default();
    assert_eq!(key["status"], "applied", "the successor was delivered");
    assert!(
        detail.contains(OLD_HASH) && detail.contains("still `jobfeed`'s current key"),
        "the outcome must say the predecessor is still in use: {detail}"
    );
    assert!(
        !detail.contains("now tracked as") && !detail.contains("openrouter-keymaster retire "),
        "and must not call it retired or name the command that would disable it: {detail}"
    );

    let state = world.project.read_state();
    let (_, pending) = state.pending_operation().expect("a delivered operation");
    assert_eq!(pending.phase, Phase::Delivered);
    assert_eq!(world.current(), Some(OLD_HASH.to_owned()));
    assert!(world.retained().is_empty());
}

/// Removing a key from the configuration is not a lifecycle action.
///
/// Regression cover beside rotation, because the two are the temptation: once
/// apply can replace a key, "the block is gone" starts to look like "replace it
/// with nothing". It is an orphaned binding, and it stays one.
#[test]
fn a_key_removed_from_the_configuration_stays_an_orphaned_binding() {
    let project = Project::new("version = 1\n");
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(OLD_HASH), 1, at(0))
            .expect("binding a key the configuration no longer describes");
    });
    project.observe(
        vec![api_key(OLD_HASH, "golf-jobfeed")],
        Vec::new(),
        Vec::new(),
    );
    let before = fs::read(project.state_path()).expect("the state fixture");

    let planned = project.succeed(&["--json", "plan"]).document();
    assert_eq!(action(&planned, "keys.jobfeed")["kind"], "orphaned_binding");

    let applied = project.succeed(&["--json", "apply"]).document();
    assert_eq!(action(&applied, "keys.jobfeed")["kind"], "orphaned_binding");
    assert!(
        project.write_trace().is_empty(),
        "an orphaned binding is reported and nothing else: {:?}",
        project.write_trace()
    );
    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "the binding is kept exactly as it was"
    );
}

/// The action at one address, from a JSON plan or apply document.
fn action<'a>(document: &'a Value, address: &str) -> &'a Value {
    document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == address)
        .unwrap_or_else(|| panic!("no action at {address} in {document}"))
}

// --- retire ---------------------------------------------------------------------

/// A project holding one working key and one predecessor awaiting retirement.
fn after_a_rotation() -> World {
    staged(&through(&Transition::Delivered), true)
}

/// A project whose successor is delivered but not yet promoted.
///
/// The one unfinished phase no operator has to resolve: `apply` completes the
/// promotion under its own lock, which is why it is the phase whose refusals
/// have to name a different command.
fn after_a_delivery() -> World {
    staged(&through(&Transition::Delivered), false)
}

/// A project whose rotation stopped at `last`.
fn staged_at(last: Transition) -> World {
    staged(&through(&last), false)
}

/// The transitions from `create_started` up to and including `last`.
fn through(last: &Transition) -> Vec<Transition> {
    let mut replayed = Vec::new();
    for transition in [
        Transition::Created {
            hash: hash(NEW_HASH),
        },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::Delivered,
    ] {
        let reached = transition == *last;
        replayed.push(transition);
        if reached {
            break;
        }
    }
    replayed
}

/// Replays a rotation into the journal, stopping where the caller says.
///
/// The transitions go through the production state API, so the fixture is
/// exactly a shape a real run could have left. The receiver is the
/// configuration's own fingerprint rather than a stand-in: a plan computed
/// after the promotion would otherwise read the difference as "the receiver
/// moved" and propose replacing a perfectly good key.
fn staged(replay: &[Transition], promote: bool) -> World {
    let world = World::new("record");
    let fingerprint = world.receiver_fingerprint();
    world.project.write_state(|state| {
        let jobfeed = address("jobfeed");
        state
            .bind_key(&jobfeed, hash(OLD_HASH), 1, at(0))
            .expect("binding the predecessor");
        state
            .begin_create(
                &jobfeed,
                BeginCreate {
                    operation: OperationId::parse("op-0002").expect("an operation id"),
                    generation: 2,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: fingerprint,
                },
                at(10),
            )
            .expect("journaling the successor's creation");
        for (step, transition) in replay.iter().enumerate() {
            state
                .advance_key(&jobfeed, transition.clone(), at(11 + step as i64))
                .expect("replaying the transaction");
        }
        if promote {
            state
                .promote_key(&jobfeed, at(20))
                .expect("promoting the successor");
        }
    });
    world
}

#[test]
fn retire_disables_a_retained_hash_and_confirms_it_by_reading_it_back() {
    let world = after_a_rotation();
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{OLD_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{OLD_HASH}")))
            .respond_with(Scripted::new([
                // Enabled when the run looks, disabled when it checks.
                json_response(200, &json!({ "data": api_key(OLD_HASH, "golf-jobfeed") })),
                json_response(200, &json!({ "data": secured_key(OLD_HASH) })),
            ])),
    );

    let document = world
        .project
        .succeed(&["--json", "retire", "jobfeed", "--hash", OLD_HASH])
        .document();

    assert_eq!(document["hash"], OLD_HASH);
    assert_eq!(document["generation"], 1);
    assert_eq!(document["status"], "retired");
    assert_eq!(document["confirmed"], Value::Bool(true));
    assert!(
        document["detail"]
            .as_str()
            .is_some_and(|text| text.contains("reading it back")),
        "{document}"
    );

    assert_eq!(
        world.retained(),
        vec![(OLD_HASH.to_owned(), RetainedStatus::Retired)],
        "a retired key stays tracked so an audit can still see it"
    );
    assert_eq!(
        world.current(),
        Some(NEW_HASH.to_owned()),
        "the working key is untouched"
    );
}

#[test]
fn retiring_a_key_openrouter_already_has_disabled_is_a_success_that_sends_nothing() {
    let world = after_a_rotation();
    serve_get(&world.project, OLD_HASH, secured_key(OLD_HASH));

    let document = world
        .project
        .succeed(&["--json", "retire", "jobfeed", "--hash", OLD_HASH])
        .document();

    assert_eq!(document["status"], "retired");
    assert_eq!(document["confirmed"], Value::Bool(true));
    assert!(
        world.project.write_trace().is_empty(),
        "a key that is already disabled needs no write: {:?}",
        world.project.write_trace()
    );

    // And running it a second time changes nothing at all.
    let serial = world.project.read_state().serial();
    world
        .project
        .succeed(&["--json", "retire", "jobfeed", "--hash", OLD_HASH]);
    assert_eq!(
        world.project.read_state().serial(),
        serial,
        "a repeated retirement writes no state"
    );
}

#[test]
fn retiring_the_current_hash_is_refused() {
    let world = after_a_rotation();
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{NEW_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let streams = world
        .project
        .fail(&["--json", "retire", "jobfeed", "--hash", NEW_HASH]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "lifecycle_key_in_use"
    );
    assert!(
        streams.err.contains("openrouter-keymaster rotate jobfeed"),
        "the refusal names the command that makes retirement possible: {}",
        streams.err
    );
    world.project.server.assert_request_count(0);
    assert_eq!(world.current(), Some(NEW_HASH.to_owned()));
}

#[test]
fn a_retirement_whose_disable_fails_keeps_the_hash_tracked_for_a_retry() {
    let world = after_a_rotation();
    serve_get(&world.project, OLD_HASH, api_key(OLD_HASH, "golf-jobfeed"));
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{OLD_HASH}")))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "error": { "code": 500, "message": "server exploded" }
            }))),
    );

    let streams = world
        .project
        .fail(&["--json", "retire", "jobfeed", "--hash", OLD_HASH]);

    // The result document is written even though the run failed: what happened
    // is what an operator needs.
    let document = streams.document();
    assert_eq!(document["status"], "retirement_failed");
    assert_eq!(document["confirmed"], Value::Bool(false));
    assert_eq!(streams.diagnostic()["error"]["kind"], "retire_unconfirmed");
    assert_eq!(
        world.retained(),
        vec![(OLD_HASH.to_owned(), RetainedStatus::RetirementFailed)]
    );
}

/// Every refusal that stands aside for a pending operation names the same
/// command, and `delivered` is the phase where that command is not `recover`.
///
/// Three sites read the phase — `rotate` refuses to stage beside an operation,
/// `retire` and `delete key` refuse to touch the key one is producing, and
/// `state forget` refuses to throw the journal away — and all three used to
/// send an operator to `openrouter-keymaster recover`, which refuses `delivered` outright.
/// They share one reading of the phase now, so this checks all of them at once.
#[test]
fn every_refusal_for_a_delivered_operation_names_apply_and_not_recover() {
    // Each command needs its own project: two of them would otherwise resolve
    // the operation the third is being tested against.
    let cases: [(&[&str], &str); 3] = [
        (&["rotate", "jobfeed"], "rotate_promotion_pending"),
        (
            &["retire", "jobfeed", "--hash", NEW_HASH],
            "lifecycle_key_under_operation",
        ),
        (&["state", "forget", "keys.jobfeed"], "forget_pending"),
    ];

    for (command, kind) in cases {
        let world = after_a_delivery();
        let mut arguments = vec!["--json"];
        arguments.extend_from_slice(command);

        let streams = world.project.fail(&arguments);

        assert_eq!(
            streams.diagnostic()["error"]["kind"],
            kind,
            "{command:?}: {}",
            streams.err
        );
        assert!(
            streams.err.contains("openrouter-keymaster apply"),
            "{command:?} must name the command that clears `delivered`: {}",
            streams.err
        );
        assert!(
            !streams.err.contains("openrouter-keymaster recover"),
            "{command:?} must not name a command that refuses this phase: {}",
            streams.err
        );
        world.project.server.assert_request_count(0);
        assert!(
            world.project.read_state().pending_operation().is_some(),
            "{command:?} changed nothing"
        );
    }
}

/// And the same three name `recover` for every phase that does need one.
#[test]
fn the_same_refusals_name_recover_while_an_outcome_is_still_unknown() {
    let cases: [(&[&str], &str); 3] = [
        (&["rotate", "jobfeed"], "rotate_operation_pending"),
        (
            &["retire", "jobfeed", "--hash", NEW_HASH],
            "lifecycle_key_under_operation",
        ),
        (&["state", "forget", "keys.jobfeed"], "forget_pending"),
    ];

    for (command, kind) in cases {
        // `secured`: the key exists and its plaintext is gone, which only an
        // operator can act on.
        let world = staged_at(Transition::Secured);
        let mut arguments = vec!["--json"];
        arguments.extend_from_slice(command);

        let streams = world.project.fail(&arguments);

        assert_eq!(
            streams.diagnostic()["error"]["kind"],
            kind,
            "{command:?}: {}",
            streams.err
        );
        assert!(
            streams
                .err
                .contains("openrouter-keymaster recover inspect jobfeed"),
            "{command:?} must name the command that reads the journal: {}",
            streams.err
        );
        assert!(
            !streams.err.contains("openrouter-keymaster apply"),
            "{command:?} must not promise apply can clear an unresolved attempt: {}",
            streams.err
        );
    }
}

#[test]
fn retire_refuses_a_hash_the_address_does_not_retain() {
    let world = after_a_rotation();

    let streams = world
        .project
        .fail(&["--json", "retire", "jobfeed", "--hash", STRAY_HASH]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "retire_not_retained");
    world.project.server.assert_request_count(0);
}

#[test]
fn retiring_a_hash_openrouter_does_not_have_changes_no_state() {
    let world = after_a_rotation();
    serve_missing(&world.project, OLD_HASH);
    let before = fs::read(world.project.state_path()).expect("the state fixture");

    let streams = world
        .project
        .fail(&["--json", "retire", "jobfeed", "--hash", OLD_HASH]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "retire_absent");
    assert!(
        streams.err.contains("delete key"),
        "the error names the command that settles an absent key: {}",
        streams.err
    );
    assert!(world.project.write_trace().is_empty());
    assert_eq!(
        before,
        fs::read(world.project.state_path()).expect("the state file")
    );
}

// --- delete key ------------------------------------------------------------------

#[test]
fn delete_removes_the_remote_key_and_only_then_stops_tracking_it() {
    let world = after_a_rotation();
    world.project.server.mount(
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/keys/{OLD_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    serve_missing(&world.project, OLD_HASH);

    let document = world
        .project
        .succeed(&["--json", "delete", "key", "--hash", OLD_HASH])
        .document();

    assert_eq!(document["outcome"], "deleted");
    assert_eq!(document["tracked"], Value::Bool(false));
    assert_eq!(document["address"], "keys.jobfeed");
    assert_eq!(
        trace(&world.project),
        vec![
            format!("DELETE /api/v1/keys/{OLD_HASH}"),
            format!("GET /api/v1/keys/{OLD_HASH}"),
        ],
        "one delete, sent once, then the read that proves it"
    );
    assert!(
        world.retained().is_empty(),
        "the hash is gone from state: {:?}",
        world.retained()
    );
    assert_eq!(world.current(), Some(NEW_HASH.to_owned()));
}

/// Deleting the highest-generation key an address records must not release its
/// number.
///
/// The retained candidate here outranks the current key, which is what an
/// abandoned rotation leaves behind. Deleting it removes the only entry saying
/// generation 2 was ever used at this address, so the next create is exactly
/// the moment the number could be handed to a second, different remote key.
#[test]
fn a_deleted_generation_is_never_handed_to_the_next_key() {
    let world = World::new("record");
    world.project.write_state(|state| {
        let jobfeed = address("jobfeed");
        state
            .bind_key(&jobfeed, hash(OLD_HASH), 1, at(0))
            .expect("binding the working key");
        state
            .begin_create(
                &jobfeed,
                BeginCreate {
                    operation: OperationId::parse("op-0009").expect("an operation id"),
                    generation: 2,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([9; 32]),
                },
                at(1),
            )
            .expect("starting a rotation");
        state
            .advance_key(
                &jobfeed,
                Transition::Created {
                    hash: hash(STRAY_HASH),
                },
                at(2),
            )
            .expect("the create returned a hash");
        state
            .retire_candidate(&jobfeed, at(3))
            .expect("the rotation is abandoned and its key retained");
    });
    world.project.server.mount(
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/keys/{STRAY_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    serve_missing(&world.project, STRAY_HASH);

    let deleted = world
        .project
        .succeed(&["--json", "delete", "key", "--hash", STRAY_HASH])
        .document();
    assert_eq!(deleted["outcome"], "deleted");
    assert_eq!(deleted["generation"], 2);
    assert!(
        deleted["summary"]
            .as_str()
            .is_some_and(|text| text.contains("stays spent")),
        "{deleted}"
    );
    assert!(world.retained().is_empty(), "nothing tracked holds it now");

    // Generation 2 named a remote key at this address. The successor takes 3.
    serve_rotation(&world.project);
    let rotated = world
        .project
        .succeed(&["--json", "rotate", "jobfeed"])
        .document();

    assert_eq!(
        rotated["generation"], 3,
        "reusing the deleted key's generation would give two remote keys one number: {rotated}"
    );
}

#[test]
fn a_confirmed_404_is_already_absent_and_settles_the_hash() {
    let world = after_a_rotation();
    world.project.server.mount(
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/keys/{OLD_HASH}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": 404, "message": "no such key" }
            }))),
    );

    let document = world
        .project
        .succeed(&["--json", "delete", "key", "--hash", OLD_HASH])
        .document();

    assert_eq!(document["outcome"], "already_absent");
    assert_eq!(document["tracked"], Value::Bool(false));
    assert!(world.retained().is_empty());
    assert_eq!(
        world.project.request_trace().len(),
        1,
        "a 404 has already answered the question: {:?}",
        trace(&world.project)
    );
}

#[test]
fn a_delete_the_read_does_not_confirm_keeps_the_hash_tracked() {
    let world = after_a_rotation();
    world.project.server.mount(
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/keys/{OLD_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    // OpenRouter accepted the delete and still returns the key.
    serve_get(&world.project, OLD_HASH, api_key(OLD_HASH, "golf-jobfeed"));

    let streams = world
        .project
        .fail(&["--json", "delete", "key", "--hash", OLD_HASH]);

    let document = streams.document();
    assert_eq!(document["outcome"], "unconfirmed");
    assert_eq!(document["tracked"], Value::Bool(true));
    assert_eq!(streams.diagnostic()["error"]["kind"], "delete_unconfirmed");
    assert_eq!(
        world.retained(),
        vec![(OLD_HASH.to_owned(), RetainedStatus::RetirementFailed)],
        "state is never dropped ahead of the confirmation"
    );
}

#[test]
fn delete_refuses_a_hash_no_local_address_tracks() {
    let world = after_a_rotation();
    world.project.server.mount(
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/keys/{STRAY_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let streams = world
        .project
        .fail(&["--json", "delete", "key", "--hash", STRAY_HASH]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "delete_untracked");
    world.project.server.assert_request_count(0);
}

#[test]
fn delete_refuses_the_key_an_address_is_using() {
    let world = after_a_rotation();

    let streams = world
        .project
        .fail(&["--json", "delete", "key", "--hash", NEW_HASH]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "lifecycle_key_in_use"
    );
    world.project.server.assert_request_count(0);
    assert_eq!(world.current(), Some(NEW_HASH.to_owned()));
}

// --- state forget -------------------------------------------------------------------

#[test]
fn forget_releases_every_hash_and_makes_no_remote_call() {
    let world = after_a_rotation();

    // No credential and no base URL in the environment: a run that reached for
    // the API would aim at production and fail, rather than quietly succeeding
    // against the harness.
    let output =
        world
            .project
            .run_without_credential(&["--json", "state", "forget", "keys.jobfeed"]);
    let streams = Streams::of(&output);
    world.project.assert_no_secret_escaped(&streams);

    assert_eq!(output.status.code(), Some(0), "{}", streams.err);
    let document = streams.document();
    assert_eq!(document["resource"], "key");
    assert_eq!(document["forgotten"], Value::Bool(true));

    let released: Vec<(String, String)> = document["released"]
        .as_array()
        .expect("a released array")
        .iter()
        .map(|entry| {
            (
                entry["identity"].as_str().unwrap_or_default().to_owned(),
                entry["role"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        released,
        vec![
            (NEW_HASH.to_owned(), "current".to_owned()),
            (OLD_HASH.to_owned(), "awaiting_retirement".to_owned()),
        ],
        "every hash being released is listed, so an operator sees what they let go"
    );

    world.project.server.assert_request_count(0);
    assert_eq!(world.deliveries(), 0);
    assert!(
        world
            .project
            .read_state()
            .key(&address("jobfeed"))
            .is_none(),
        "the binding is gone"
    );
}

#[test]
fn forgetting_an_address_twice_is_a_clear_no_op() {
    let world = after_a_rotation();
    world
        .project
        .succeed(&["--json", "state", "forget", "keys.jobfeed"]);
    let serial = world.project.read_state().serial();

    let document = world
        .project
        .succeed(&["--json", "state", "forget", "keys.jobfeed"])
        .document();

    assert_eq!(document["forgotten"], Value::Bool(false));
    assert!(
        document["summary"]
            .as_str()
            .is_some_and(|text| text.contains("nothing to forget")),
        "{document}"
    );
    assert_eq!(
        world.project.read_state().serial(),
        serial,
        "a repeated forget writes nothing"
    );
}

#[test]
fn forget_refuses_an_address_with_an_operation_in_progress() {
    let world = World::new("record");
    world.project.write_state(|state| {
        state
            .begin_create(
                &address("jobfeed"),
                BeginCreate {
                    operation: OperationId::parse("op-0003").expect("an operation id"),
                    generation: 1,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([3; 32]),
                },
                at(0),
            )
            .expect("journaling an attempt");
    });
    let before = fs::read(world.project.state_path()).expect("the state fixture");

    let streams = world
        .project
        .fail(&["--json", "state", "forget", "keys.jobfeed"]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "forget_pending");
    assert!(
        streams.err.contains("openrouter-keymaster recover"),
        "{}",
        streams.err
    );
    assert_eq!(
        before,
        fs::read(world.project.state_path()).expect("the state file")
    );
}

#[test]
fn a_bare_address_bound_as_both_a_key_and_a_guardrail_must_be_qualified() {
    let world = World::new("record");
    world.project.write_state(|state| {
        state
            .bind_key(&address("shared"), hash(OLD_HASH), 1, at(0))
            .expect("binding a key");
        state
            .bind_guardrail(
                &address("shared"),
                uuid(FAKE_GUARDRAIL_ID),
                Origin::Imported,
                at(0),
            )
            .expect("binding a guardrail at the same name");
    });

    let streams = world.project.fail(&["--json", "state", "forget", "shared"]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "forget_ambiguous");
    assert!(
        streams.err.contains("keys.shared") && streams.err.contains("guardrails.shared"),
        "the refusal spells both answers: {}",
        streams.err
    );

    // Qualified, it works, and touches only the one named.
    world
        .project
        .succeed(&["--json", "state", "forget", "guardrails.shared"]);
    let state: State = world.project.read_state();
    assert!(state.guardrail(&address("shared")).is_none());
    assert!(state.key(&address("shared")).is_some());
}
