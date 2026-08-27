//! Binary-level tests for the journaled key creation transaction (ADR-0002).
//!
//! Three questions run through every case here, because they are the three the
//! ADR exists to answer:
//!
//! 1. **How many `POST /keys` requests were sent?** The answer is always zero or
//!    one. Never two, whatever happened.
//! 2. **What phase is on disk afterwards?** That is what the next run reads, and
//!    the interruption table in ADR-0002 says what each phase means.
//! 3. **Did the plaintext go anywhere it should not?** Every run is scanned, and
//!    the receiver's own record is checked so the absent-everywhere assertion
//!    cannot pass because nothing was delivered at all.
//!
//! The receiver is the purpose-built helper binary, not a fake: it records how
//! many times it ran, which is how "delivery is at-most-once" is asserted rather
//! than assumed. It writes into a directory outside the project, because what it
//! writes is a live credential and the project directory is scanned for exactly
//! that.

mod support;

use std::fs;
use std::path::Path;

use openrouter_keymaster_core::ids::{OperationId, ReceiverFingerprint, RemoteName};
use openrouter_keymaster_core::state::{BeginCreate, Origin, Phase, Transition};
use serde_json::{Value, json};
use support::fixtures::{FAKE_GUARDRAIL_ID, api_key, assignment, created_key, guardrail};
use support::http::{
    RawServer, Scripted, connection_lost, json_response, malformed_json,
    truncated_body_with_status, whole_body,
};
use support::project::{Project, address, at, hash, uuid};
use support::sentinel::{SECRET_SENTINEL, SECRET_SENTINEL_KEY, assert_absent, assert_present};
use tempfile::TempDir;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

/// The hash `POST /keys` hands back in these tests.
const NEW_HASH: &str = "hash-jobfeed-new";

const ASSIGNMENT_ID: &str = "44444444-4444-4444-8444-444444444444";

/// A project whose one key is created by Keymaster and delivered to a program.
///
/// The vault is a directory of its own. The receiver writes the key's envelope
/// into it, and the project directory — which every run scans for the sentinel —
/// must not be where a live credential lands.
struct Creation {
    project: Project,
    vault: TempDir,
}

impl Creation {
    /// A project with one creatable key, delivering through the helper in
    /// `mode`.
    fn new(mode: &str) -> Self {
        let vault = tempfile::tempdir().expect("a temporary vault directory");
        let project = Project::new(&configuration(vault.path(), mode, ""));
        Self { project, vault }
    }

    /// The same, with extra configuration appended.
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

    /// The envelope the receiver was handed, if it was handed one.
    fn envelope(&self) -> Option<String> {
        fs::read_to_string(self.vault.path().join("envelope.json")).ok()
    }

    /// The fingerprint of the receiver this project configures.
    ///
    /// A journal fixture has to record the destination the configuration names,
    /// or the next plan reads the difference as "the receiver moved" and asks to
    /// replace a key that is perfectly good.
    fn receiver_fingerprint(&self) -> ReceiverFingerprint {
        let source = fs::read_to_string(self.project.config_path()).expect("the configuration");
        openrouter_keymaster_core::config::Config::parse(&source)
            .expect("a valid test configuration")
            .receivers
            .iter()
            .next()
            .map(|(address, spec)| spec.fingerprint(address))
            .expect("one receiver")
    }

    /// The phase of the operation the state file holds, if it holds one.
    fn journaled(&self) -> Option<Phase> {
        self.project
            .read_state()
            .pending_operation()
            .map(|(_, operation)| operation.phase)
    }

    /// The hash the journal records for the pending operation, if any.
    fn journaled_hash(&self) -> Option<String> {
        self.project
            .read_state()
            .pending_operation()
            .and_then(|(_, operation)| operation.hash.as_ref().map(|hash| hash.to_string()))
    }
}

/// The configuration under test: one key, disabled, delivered to the helper.
///
/// `disabled = true` is load-bearing. `POST /keys` has no field for it, so a
/// disabled key is born enabled and can only be restricted by the update that
/// follows — which is the step ADR-0002 requires before any plaintext leaves the
/// process, and the one a test would otherwise never notice was skipped.
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

/// The new key as OpenRouter has it once its restrictions are applied.
fn secured_key(hash: &str) -> Value {
    let mut key = api_key(hash, "golf-jobfeed");
    key["disabled"] = json!(true);
    key
}

/// Answers the writes and reads the transaction makes after its create.
fn serve_secure(project: &Project, hash: &str) {
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(json_response(200, &json!({}))),
    );
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(json_response(200, &json!({ "data": secured_key(hash) }))),
    );
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

/// How many `POST /keys` requests the server saw.
fn create_requests(project: &Project) -> usize {
    project
        .request_trace()
        .iter()
        .filter(|request| *request == "POST /api/v1/keys")
        .count()
}

/// The action at one address, from a JSON apply document.
fn action<'a>(document: &'a Value, address: &str) -> &'a Value {
    document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == address)
        .unwrap_or_else(|| panic!("no action at {address} in {document}"))
}

// --- the happy path ---------------------------------------------------------

#[test]
fn a_planned_key_is_created_restricted_verified_delivered_and_promoted() {
    let world = Creation::new("record");
    serve_create(&world.project, NEW_HASH);
    serve_secure(&world.project, NEW_HASH);
    world.project.observe_sequence(
        vec![Vec::new(), vec![secured_key(NEW_HASH)]],
        vec![Vec::new()],
        vec![Vec::new()],
    );

    let document = world.project.succeed(&["--json", "apply"]).document();

    assert_eq!(
        world.project.write_trace(),
        vec![
            "POST /api/v1/keys".to_owned(),
            format!("PATCH /api/v1/keys/{NEW_HASH}"),
        ],
        "one create, then the restrictions the create body could not carry"
    );
    assert_eq!(create_requests(&world.project), 1);

    let created = action(&document, "keys.jobfeed");
    assert_eq!(created["kind"], "create");
    assert_eq!(created["status"], "applied");
    assert_eq!(created["verified"], Value::Bool(true));
    assert_eq!(created["safety"], "issuing");
    assert_eq!(document["outcome"], "applied");

    // The plaintext reached the receiver and nowhere else. `succeed` has
    // already scanned stdout, stderr, and every file under the project.
    assert_eq!(world.deliveries(), 1, "delivery is at most once");
    assert_present(
        "the receiver's envelope",
        &world
            .envelope()
            .expect("the receiver was handed an envelope"),
    );

    let state = world.project.read_state();
    let binding = state.key(&address("jobfeed")).expect("the created binding");
    let current = binding.current().expect("a promoted current key");
    assert_eq!(current.hash.as_str(), NEW_HASH);
    assert_eq!(current.generation, 1);
    assert_eq!(binding.origin(), Origin::Created);
    assert!(
        current.receiver.is_some(),
        "promotion records where the plaintext went"
    );
    assert!(
        binding.pending().is_none(),
        "a completed transaction leaves no operation behind"
    );
}

#[test]
fn the_envelope_carries_the_operation_id_the_journal_minted() {
    let world = Creation::new("record");
    serve_create(&world.project, NEW_HASH);
    serve_secure(&world.project, NEW_HASH);
    world.project.observe_sequence(
        vec![Vec::new(), vec![secured_key(NEW_HASH)]],
        vec![Vec::new()],
        vec![Vec::new()],
    );

    let human = world.project.succeed(&["apply"]).out;
    let envelope: Value = serde_json::from_str(&world.envelope().expect("an envelope"))
        .expect("the envelope is one JSON document");

    let operation = envelope["operation_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the envelope names its operation: {envelope}"));
    assert!(
        OperationId::parse(operation).is_ok(),
        "the minted id is one the journal can read back: {operation}"
    );
    assert!(
        human.contains(NEW_HASH),
        "the run reports the hash it created: {human}"
    );
}

#[test]
fn a_key_with_a_guardrail_is_attached_and_verified_before_it_is_delivered() {
    let world = Creation::with(
        "record",
        "guardrail = \"cheap\"\n\n[guardrails.cheap]\nname = \"cheap-rail\"\nlimit_usd = 10\n\
         reset_interval = \"monthly\"\n",
    );
    serve_create(&world.project, NEW_HASH);
    serve_secure(&world.project, NEW_HASH);
    for route in [
        format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}/assignments/keys"),
        format!("/api/v1/keys/{NEW_HASH}"),
    ] {
        world.project.server.mount(
            Mock::given(method("POST"))
                .and(path(route))
                .respond_with(json_response(200, &json!({}))),
        );
    }
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}")))
            .respond_with(json_response(
                200,
                &json!({ "data": guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[]) }),
            )),
    );
    // Offset-aware, like every other listing the harness serves: a responder
    // that answered the same page at every offset would look to the client like
    // a server ignoring its offset, which pagination refuses.
    let attached = format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}/assignments/keys");
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(attached.clone()))
            .and(query_param("offset", "0"))
            .respond_with(json_response(
                200,
                &json!({ "data": [assignment(ASSIGNMENT_ID, NEW_HASH, FAKE_GUARDRAIL_ID)] }),
            ))
            .with_priority(1),
    );
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(attached))
            .respond_with(json_response(200, &json!({ "data": [] })))
            .with_priority(2),
    );
    world.project.observe_sequence(
        vec![Vec::new(), vec![secured_key(NEW_HASH)]],
        vec![vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])]],
        vec![
            Vec::new(),
            vec![assignment(ASSIGNMENT_ID, NEW_HASH, FAKE_GUARDRAIL_ID)],
        ],
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
    });

    let document = world.project.succeed(&["--json", "apply"]).document();

    assert_eq!(
        world.project.write_trace(),
        vec![
            "POST /api/v1/keys".to_owned(),
            format!("PATCH /api/v1/keys/{NEW_HASH}"),
            format!("POST /api/v1/guardrails/{FAKE_GUARDRAIL_ID}/assignments/keys"),
        ],
        "create, restrict, attach — and the delivery happens after all three"
    );
    assert_eq!(world.deliveries(), 1);
    assert_eq!(
        action(&document, "keys.jobfeed.guardrail")["status"],
        "applied",
        "the assignment was made inside the transaction, not a second time after it"
    );
    assert_eq!(document["outcome"], "applied");
}

// --- nothing was created ----------------------------------------------------

#[test]
fn a_failed_pre_create_state_write_sends_no_post_at_all() {
    // The serial is at its ceiling, so every state write is refused. ADR-0002
    // sends no `POST /keys` until `create_started` is durable, so this run has
    // to stop before the request rather than after it.
    let world = Creation::new("record");
    serve_create(&world.project, NEW_HASH);
    fs::write(
        world.project.state_path(),
        r#"{"version":1,"serial":18446744073709551615,"keys":{},"guardrails":{}}"#,
    )
    .expect("writing a state file that cannot advance");
    world
        .project
        .observe_sequence(vec![Vec::new()], vec![Vec::new()], vec![Vec::new()]);

    let streams = world.project.fail(&["--json", "apply"]);

    assert_eq!(
        create_requests(&world.project),
        0,
        "no journal entry, no request"
    );
    assert_eq!(world.deliveries(), 0);
    let document = streams.document();
    let created = action(&document, "keys.jobfeed");
    assert_eq!(created["status"], "failed");
    assert!(
        created["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("no key was created")),
        "the failure says plainly that nothing exists: {created}"
    );
}

#[test]
fn a_definite_rejection_clears_the_attempt_and_leaves_no_operation() {
    let world = Creation::new("record");
    world.project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": { "code": 400, "message": "limit_reset is not valid" }
            }))),
    );
    world
        .project
        .observe_sequence(vec![Vec::new()], vec![Vec::new()], vec![Vec::new()]);

    let streams = world.project.fail(&["--json", "apply"]);

    assert_eq!(create_requests(&world.project), 1);
    assert_eq!(world.deliveries(), 0);
    assert_eq!(
        world.journaled(),
        None,
        "a well-formed 4xx says the request was declined, so nothing is pending"
    );
    let document = streams.document();
    let created = action(&document, "keys.jobfeed");
    assert!(
        created["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("no key was created")),
        "{created}"
    );

    // The next run plans an ordinary create again, because nothing is unresolved.
    let planned = world.project.succeed(&["--json", "plan"]).document();
    assert_eq!(action(&planned, "keys.jobfeed")["kind"], "create");
    assert_eq!(planned["blocked"], Value::Bool(false));
}

// --- the four ambiguous shapes ----------------------------------------------

/// Every way a create can end without saying whether a key exists.
///
/// ADR-0002 treats all four identically and so does this table: exactly one
/// request, `create_ambiguous` on disk, and a next run that reports
/// `recovery_required` rather than proposing another create.
#[test]
fn every_ambiguous_create_sends_one_post_and_requires_recovery() {
    /// One way a create can end with nobody knowing what happened.
    type Shape = (&'static str, fn() -> Mock);

    let shapes: [Shape; 4] = [
        ("a lost connection", || {
            Mock::given(method("POST"))
                .and(path("/api/v1/keys"))
                .respond_with_err(connection_lost)
        }),
        ("a server error", || {
            Mock::given(method("POST"))
                .and(path("/api/v1/keys"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                    "error": { "code": 500, "message": "server exploded" }
                })))
        }),
        ("a success with a truncated body", || {
            Mock::given(method("POST"))
                .and(path("/api/v1/keys"))
                .respond_with(malformed_json())
        }),
        ("a success with no hash", || {
            Mock::given(method("POST"))
                .and(path("/api/v1/keys"))
                .respond_with(json_response(
                    200,
                    &json!({ "data": { "name": "golf-jobfeed" }, "key": SECRET_SENTINEL_KEY }),
                ))
        }),
    ];

    for (description, mock) in shapes {
        let world = Creation::new("record");
        world.project.server.mount(mock());
        world
            .project
            .observe_sequence(vec![Vec::new()], vec![Vec::new()], vec![Vec::new()]);

        let streams = world.project.fail(&["--json", "apply"]);

        assert_eq!(
            create_requests(&world.project),
            1,
            "{description}: exactly one request, never a retry"
        );
        assert_eq!(world.deliveries(), 0, "{description}");
        assert_eq!(
            world.journaled(),
            Some(Phase::CreateAmbiguous),
            "{description}: the journal records that nobody knows"
        );
        assert!(
            world.journaled_hash().is_none(),
            "{description}: no response, no hash"
        );

        let document = streams.document();
        let created = action(&document, "keys.jobfeed");
        assert!(
            created["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("recover inspect")),
            "{description}: the failure names the command that resolves it: {created}"
        );

        // The next run reports recovery, not another create.
        let planned = world.project.succeed(&["--json", "plan"]).document();
        assert_eq!(
            action(&planned, "keys.jobfeed")["kind"],
            "recovery_required",
            "{description}"
        );
        assert_eq!(planned["blocked"], Value::Bool(true), "{description}");

        // And a second apply writes nothing rather than trying again.
        let before = create_requests(&world.project);
        world.project.fail(&["--json", "apply"]);
        assert_eq!(
            create_requests(&world.project),
            before,
            "{description}: a blocked run sends no second create"
        );
    }
}

#[test]
fn a_rejection_whose_body_stopped_short_is_ambiguous_rather_than_definite() {
    // ADR-0002 clears a journal entry only for a *well-formed* 4xx. Here the
    // status line arrived and the response then stopped, so the server may have
    // created a key and said so in the part that never came. `wiremock` cannot
    // express that, so this run talks to a socket-level server instead.
    let world = Creation::new("record");
    let empty = || whole_body(r#"{"data":[]}"#);
    let server = RawServer::scripted(vec![
        // The snapshot apply plans from: keys, guardrails, assignments.
        empty(),
        empty(),
        empty(),
        // The create, refused with a body that stops mid-sentence.
        truncated_body_with_status(400, r#"{"error": {"code": 400, "mess"#),
        // Everything after: the snapshot the run reads to verify itself.
        empty(),
    ]);

    let output = world
        .project
        .run_against(&server.api_base_url(), &["--json", "apply"]);
    let streams = support::project::Streams::of(&output);
    world.project.assert_no_secret_escaped(&streams);
    assert_eq!(output.status.code(), Some(1), "{}", streams.err);

    assert_eq!(
        world.journaled(),
        Some(Phase::CreateAmbiguous),
        "an incomplete answer settles nothing, so the attempt stays unresolved"
    );
    assert_eq!(world.deliveries(), 0);
    // Three listings, one create, three listings to verify. A second create
    // would make it eight; the scripted server has no way to report methods, so
    // the count is what proves the request was sent exactly once.
    server.assert_request_count(7);

    let document: Value = serde_json::from_str(&streams.out).expect("one JSON document");
    let created = action(&document, "keys.jobfeed");
    let detail = created["detail"].as_str().unwrap_or_default().to_owned();
    assert!(detail.contains("outcome is unknown"), "{detail}");
    assert!(detail.contains("recover inspect"), "{detail}");

    // And the next run reports recovery rather than proposing another create.
    world.project.observe(Vec::new(), Vec::new(), Vec::new());
    let planned = world.project.succeed(&["--json", "plan"]).document();
    assert_eq!(
        action(&planned, "keys.jobfeed")["kind"],
        "recovery_required"
    );
    assert_eq!(planned["blocked"], Value::Bool(true));
}

// --- after the hash is durable ----------------------------------------------

#[test]
fn a_failed_restriction_leaves_the_hash_durable_and_the_key_disabled() {
    // The first PATCH — the restrictions — fails; the second is the safe
    // disable that follows. The hash must already be on disk before either.
    let world = Creation::new("record");
    serve_create(&world.project, NEW_HASH);
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{NEW_HASH}")))
            .respond_with(Scripted::new([
                ResponseTemplate::new(500).set_body_json(json!({
                    "error": { "code": 500, "message": "server exploded" }
                })),
                json_response(200, &json!({})),
            ])),
    );
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{NEW_HASH}")))
            .respond_with(json_response(
                200,
                &json!({ "data": secured_key(NEW_HASH) }),
            )),
    );
    world
        .project
        .observe_sequence(vec![Vec::new()], vec![Vec::new()], vec![Vec::new()]);

    let streams = world.project.fail(&["--json", "apply"]);

    assert_eq!(create_requests(&world.project), 1);
    assert_eq!(
        world.deliveries(),
        0,
        "the receiver cannot run before the restrictions are verified"
    );
    assert_eq!(world.journaled(), Some(Phase::Created));
    assert_eq!(
        world.journaled_hash().as_deref(),
        Some(NEW_HASH),
        "the hash is durable before any follow-up call"
    );

    let document = streams.document();
    let created = action(&document, "keys.jobfeed");
    let detail = created["detail"].as_str().unwrap_or_default();
    assert!(detail.contains(NEW_HASH), "{created}");
    assert!(detail.contains("disabled it"), "{created}");
    assert!(detail.contains("recover replace"), "{created}");
}

#[test]
fn a_key_that_does_not_match_after_the_update_is_never_delivered() {
    // The PATCH is accepted and the read that follows still shows an enabled
    // key. Nothing establishes that the restrictions took, so the plaintext
    // stays in the process and dies there.
    let world = Creation::new("record");
    serve_create(&world.project, NEW_HASH);
    world.project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{NEW_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    world.project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{NEW_HASH}")))
            .respond_with(json_response(
                200,
                &json!({ "data": api_key(NEW_HASH, "golf-jobfeed") }),
            )),
    );
    world
        .project
        .observe_sequence(vec![Vec::new()], vec![Vec::new()], vec![Vec::new()]);

    let streams = world.project.fail(&["--json", "apply"]);

    assert_eq!(world.deliveries(), 0, "verification gates the receiver");
    assert_eq!(world.journaled(), Some(Phase::Created));
    let document = streams.document();
    let detail = action(&document, "keys.jobfeed")["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        detail.contains("does not match the configuration"),
        "{detail}"
    );
    assert!(detail.contains("disabled"), "{detail}");
}

// --- what the receiver's answer means ---------------------------------------

#[test]
fn a_refused_delivery_holds_at_secured_and_asks_for_a_replacement() {
    let world = Creation::new("reject");
    serve_create(&world.project, NEW_HASH);
    serve_secure(&world.project, NEW_HASH);
    world
        .project
        .observe_sequence(vec![Vec::new()], vec![Vec::new()], vec![Vec::new()]);

    let streams = world.project.fail(&["--json", "apply"]);

    assert_eq!(world.deliveries(), 1, "the receiver ran exactly once");
    assert_eq!(world.journaled(), Some(Phase::Secured));

    let state = world.project.read_state();
    let (_, operation) = state.pending_operation().expect("the held operation");
    assert!(
        operation.delivery_rejected_at.is_some(),
        "a refusal is marked, so nothing can invoke the receiver again"
    );

    let document = streams.document();
    let detail = action(&document, "keys.jobfeed")["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(detail.contains("refused the plaintext"), "{detail}");
    assert!(detail.contains("recover replace"), "{detail}");

    // The next run reports a replacement rather than a recovery: what happened
    // is known, and the key can never be delivered.
    let planned = world.project.succeed(&["--json", "plan"]).document();
    assert_eq!(action(&planned, "keys.jobfeed")["kind"], "replace");
    assert_eq!(planned["blocked"], Value::Bool(false));
    assert_eq!(
        world.deliveries(),
        1,
        "planning never invokes a receiver, and nothing re-delivers"
    );
}

#[test]
fn a_lost_acknowledgement_is_ambiguous_and_the_receiver_never_runs_again() {
    // The helper dies by signal after reading the envelope: it may have
    // committed the secret and may not.
    let world = Creation::new("abort");
    serve_create(&world.project, NEW_HASH);
    serve_secure(&world.project, NEW_HASH);
    world
        .project
        .observe_sequence(vec![Vec::new()], vec![Vec::new()], vec![Vec::new()]);

    let streams = world.project.fail(&["--json", "apply"]);

    assert_eq!(world.deliveries(), 1);
    assert_eq!(world.journaled(), Some(Phase::DeliveryAmbiguous));
    let document = streams.document();
    let detail = action(&document, "keys.jobfeed")["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(detail.contains("acknowledgement was lost"), "{detail}");
    assert!(detail.contains("never invoked again"), "{detail}");

    // A second apply is blocked, and above all does not deliver again.
    world.project.fail(&["--json", "apply"]);
    assert_eq!(
        world.deliveries(),
        1,
        "delivery is at-most-once; an ambiguous acknowledgement is not a retry"
    );
    assert_eq!(create_requests(&world.project), 1);
}

// --- sequencing --------------------------------------------------------------

#[test]
fn a_second_creation_never_starts_beside_an_unresolved_one() {
    let vault = tempfile::tempdir().expect("a vault");
    let project = Project::new(&format!(
        "{base}\n[keys.payroll]\nname = \"golf-payroll\"\nlimit_usd = 5\n\
         limit_reset = \"monthly\"\ndisabled = true\nreceiver = \"vault\"\n",
        base = configuration(vault.path(), "record", "")
    ));
    // The one create this run is allowed to attempt ends ambiguously.
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with_err(connection_lost),
    );
    project.observe_sequence(vec![Vec::new()], vec![Vec::new()], vec![Vec::new()]);

    let streams = project.fail(&["--json", "apply"]);
    let document = streams.document();

    assert_eq!(
        project
            .request_trace()
            .iter()
            .filter(|request| *request == "POST /api/v1/keys")
            .count(),
        1,
        "creations run one at a time, and the run stops at the first unresolved one"
    );
    // Whichever address went first, the other was never attempted.
    let statuses: Vec<&str> = ["keys.jobfeed", "keys.payroll"]
        .iter()
        .map(|address| action(&document, address)["status"].as_str().unwrap_or(""))
        .collect();
    assert!(
        statuses.contains(&"failed") && statuses.contains(&"not_attempted"),
        "one failed and the other never ran: {statuses:?}"
    );
}

// --- promotion ---------------------------------------------------------------

#[test]
fn apply_completes_a_delivered_operation_before_it_plans_anything() {
    // The journal holds `delivered`: the transaction finished and the run died
    // before promoting. Promotion touches nothing remote, so apply completes it
    // under its lock and the plan it then computes describes the world as it is.
    let world = Creation::new("record");
    world
        .project
        .observe(vec![secured_key(NEW_HASH)], Vec::new(), Vec::new());
    let fingerprint = world.receiver_fingerprint();
    world.project.write_state(|state| {
        let jobfeed = address("jobfeed");
        state
            .begin_create(
                &jobfeed,
                BeginCreate {
                    operation: OperationId::parse("op-0031").expect("an operation id"),
                    generation: 1,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: fingerprint.clone(),
                },
                at(1),
            )
            .expect("starting the create");
        for transition in [
            Transition::Created {
                hash: hash(NEW_HASH),
            },
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::Delivered,
        ] {
            state
                .advance_key(&jobfeed, transition, at(2))
                .expect("replaying the transaction");
        }
    });

    let streams = world.project.succeed(&["--json", "apply"]);
    let document = streams.document();

    assert!(
        world.project.write_trace().is_empty(),
        "promotion is local; it writes nothing to OpenRouter"
    );
    assert_eq!(create_requests(&world.project), 0);
    assert_eq!(world.deliveries(), 0);
    assert_eq!(document["outcome"], "converged");

    let state = world.project.read_state();
    let binding = state.key(&address("jobfeed")).expect("the binding");
    assert_eq!(
        binding.current().expect("a promoted key").hash.as_str(),
        NEW_HASH
    );
    assert!(binding.pending().is_none());
    assert!(
        streams.err.is_empty(),
        "under --json every diagnostic travels in the document"
    );
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("completed that promotion locally"))),
        "the run says what it finished: {document}"
    );
}

// --- crash injection ---------------------------------------------------------

/// A crash immediately before and immediately after every durable phase.
///
/// The `fault-injection` feature makes `KEYMASTER_STATE_FAULT` stop a real run
/// inside the real write path. `before_temp@N` fails the Nth state write before
/// anything reaches the disk — an interruption immediately *before* that phase
/// lands — and `after_rename@N` fails the parent-directory sync, which happens
/// after the rename, so the phase *has* landed and the run still stops: an
/// interruption immediately *after* it.
///
/// The six writes of one creation, in order: `create_started`, `created`,
/// `secured`, `delivery_started`, `delivered`, and the promotion. Each row below
/// is one of the twelve edges, and asserts the two things ADR-0002's
/// interruption table promises: what the next run reads, and what was sent.
#[cfg(feature = "fault-injection")]
#[test]
fn a_crash_at_every_durable_phase_leaves_the_phase_adr_0002_promises() {
    use openrouter_keymaster_core::state::STATE_FAULT_VAR;

    // Each row: the fault, the phase the state file must then hold, how many
    // `POST /keys` requests were sent, and how many times the receiver ran.
    let edges: [(&str, Option<Phase>, usize, usize); 12] = [
        // create_started: nothing journaled means nothing sent.
        ("before_temp@1", None, 0, 0),
        ("after_rename@1", Some(Phase::CreateStarted), 0, 0),
        // created: the request went out; whether the hash survived is the
        // difference between "a key may exist" and "this key exists". A hash
        // that could not be recorded is classified ambiguous on the spot, so
        // the third write lands where the second did not.
        ("before_temp@2", Some(Phase::CreateAmbiguous), 1, 0),
        ("after_rename@2", Some(Phase::Created), 1, 0),
        // secured: restrictions are verified, delivery has not begun.
        ("before_temp@3", Some(Phase::Created), 1, 0),
        ("after_rename@3", Some(Phase::Secured), 1, 0),
        // delivery_started: the intent marker gates the receiver, so a crash on
        // either side of it leaves the receiver un-run.
        ("before_temp@4", Some(Phase::Secured), 1, 0),
        ("after_rename@4", Some(Phase::DeliveryStarted), 1, 0),
        // delivered: the receiver has run exactly once by now, and a crash
        // before the acknowledgement lands is indistinguishable from a lost one.
        ("before_temp@5", Some(Phase::DeliveryStarted), 1, 1),
        ("after_rename@5", Some(Phase::Delivered), 1, 1),
        // promotion: local only, and the next apply finishes it.
        ("before_temp@6", Some(Phase::Delivered), 1, 1),
        ("after_rename@6", None, 1, 1),
    ];

    for (fault, phase, creates, deliveries) in edges {
        let world = Creation::new("record");
        serve_create(&world.project, NEW_HASH);
        serve_secure(&world.project, NEW_HASH);
        world.project.observe_sequence(
            vec![Vec::new(), vec![secured_key(NEW_HASH)]],
            vec![Vec::new()],
            vec![Vec::new()],
        );

        let output = world
            .project
            .run_with(&["--json", "apply"], &[(STATE_FAULT_VAR, fault)]);
        let streams = support::project::Streams::of(&output);
        world.project.assert_no_secret_escaped(&streams);

        assert_eq!(world.journaled(), phase, "{fault}: the phase on disk");
        assert_eq!(
            create_requests(&world.project),
            creates,
            "{fault}: `POST /keys` requests"
        );
        assert_eq!(world.deliveries(), deliveries, "{fault}: receiver runs");
        assert_absent(&format!("{fault} stdout"), &streams.out);
        assert_absent(&format!("{fault} stderr"), &streams.err);
    }
}

/// A hash that could not be journaled is never touched again.
///
/// ADR-0002 puts the returned hash on disk before *any* follow-up call, and
/// here it never got there. A disable would be exactly the call that rule
/// forbids — aimed at a key whose identity the process is about to lose, and
/// with an outcome nobody would record. The report names the hash and hands the
/// cleanup to `recover resolve --leaked-hash`, which binds it before disabling
/// it.
#[cfg(feature = "fault-injection")]
#[test]
fn a_hash_that_could_not_be_journaled_is_never_touched_again() {
    use openrouter_keymaster_core::state::STATE_FAULT_VAR;

    let world = Creation::new("record");
    serve_create(&world.project, NEW_HASH);
    serve_secure(&world.project, NEW_HASH);
    world.project.observe_sequence(
        vec![Vec::new(), vec![secured_key(NEW_HASH)]],
        vec![Vec::new()],
        vec![Vec::new()],
    );

    let output = world
        .project
        .run_with(&["--json", "apply"], &[(STATE_FAULT_VAR, "before_temp@2")]);
    let streams = support::project::Streams::of(&output);
    world.project.assert_no_secret_escaped(&streams);

    assert_eq!(
        world.project.write_trace(),
        vec!["POST /api/v1/keys".to_owned()],
        "the create, and nothing else: no PATCH may follow a hash that is not durable"
    );
    assert_eq!(world.journaled(), Some(Phase::CreateAmbiguous));
    assert!(
        world.journaled_hash().is_none(),
        "the ambiguous phases carry no hash, which is why the report has to"
    );

    let document: Value = serde_json::from_str(&streams.out).expect("one JSON document");
    let detail = action(&document, "keys.jobfeed")["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(detail.contains(NEW_HASH), "{detail}");
    assert!(detail.contains("sent nothing further about it"), "{detail}");
    assert!(
        detail.contains(&format!("--leaked-hash {NEW_HASH}")),
        "{detail}"
    );
}

/// Every fault above leaves the state file readable and internally consistent.
///
/// The durability guarantee is not only "the phase is right": a torn write that
/// produced a file the reader refuses would strand an operator with no way to
/// run any command at all.
#[cfg(feature = "fault-injection")]
#[test]
fn a_crash_never_leaves_a_state_file_keymaster_cannot_read() {
    use openrouter_keymaster_core::state::STATE_FAULT_VAR;

    for stage in [
        "before_temp",
        "during_write",
        "before_rename",
        "after_rename",
    ] {
        for nth in 1..=6 {
            let world = Creation::new("record");
            serve_create(&world.project, NEW_HASH);
            serve_secure(&world.project, NEW_HASH);
            world.project.observe_sequence(
                vec![Vec::new(), vec![secured_key(NEW_HASH)]],
                vec![Vec::new()],
                vec![Vec::new()],
            );
            let fault = format!("{stage}@{nth}");

            let output = world
                .project
                .run_with(&["--json", "apply"], &[(STATE_FAULT_VAR, &fault)]);
            let streams = support::project::Streams::of(&output);
            world.project.assert_no_secret_escaped(&streams);

            // Reading through the production reader is the assertion: it
            // enforces every invariant, and a torn or half-written document
            // fails here.
            let state = world.project.read_state();
            assert!(
                state.serial() <= 6,
                "{fault}: a run makes at most one write per phase"
            );
            assert!(
                world
                    .project
                    .entries()
                    .iter()
                    .all(|name| !name.ends_with(".tmp")),
                "{fault}: no temporary file is left behind: {:?}",
                world.project.entries()
            );
            assert_absent(&format!("{fault} stdout"), &streams.out);
        }
    }
}

/// The sentinel never reaches anything Keymaster writes, on any path.
#[test]
fn the_secret_never_reaches_state_output_or_a_temporary_file() {
    let world = Creation::new("echo");
    serve_create(&world.project, NEW_HASH);
    serve_secure(&world.project, NEW_HASH);
    world.project.observe_sequence(
        vec![Vec::new(), vec![secured_key(NEW_HASH)]],
        vec![Vec::new()],
        vec![Vec::new()],
    );

    // The `echo` helper prints the whole envelope — the key included — to both
    // of its streams. Keymaster captures that output for diagnostics, so this
    // is the adversarial case: a receiver deliberately handing the secret back.
    let streams = world.project.succeed(&["--json", "apply"]);
    assert_absent("stdout", &streams.out);
    assert_absent("stderr", &streams.err);
    assert_absent(
        "the state file",
        &fs::read_to_string(world.project.state_path()).expect("a state file"),
    );
    assert!(
        !streams.out.contains(SECRET_SENTINEL),
        "not even the bare sentinel: {}",
        streams.out
    );
    assert_present(
        "the receiver's envelope",
        &world.envelope().expect("an envelope"),
    );
}
