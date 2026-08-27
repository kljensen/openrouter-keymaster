//! The caller receiver (ADR-0005): a key's plaintext, handed to host code.
//!
//! These cases call `ops` directly, because the callback is the one input the
//! command line cannot supply — which is itself something to prove, and the
//! last case here does.
//!
//! Three questions run through them, the same three ADR-0002 asks of every
//! delivery, plus the one ADR-0005 adds:
//!
//! 1. **How many `POST /keys`?** Zero or one per key, never two.
//! 2. **What did the callback answer, and what did the journal make of it?**
//! 3. **Did the plaintext go anywhere else?** Every case scans the project
//!    directory and the report it produced; the recorded calls hold a flag
//!    saying the callback saw the sentinel, never the sentinel itself.
//! 4. **Was the callback needed before it was missing?** A run with none fails
//!    its preflight with nothing created.

mod support;

use std::fs;
use std::sync::{Arc, Mutex};

use openrouter_keymaster_core::ids::{OperationId, RemoteName};
use openrouter_keymaster_core::ops::{
    self, Context, DeliveryMetadata, DeliveryOutcome, KeyPlaintext, ManagementKey, Options, Paths,
    PlanFingerprint,
};
/// The host callback type, spelled out here because core does not export an alias for it.
type Deliver = Box<dyn FnMut(&DeliveryMetadata, &KeyPlaintext) -> DeliveryOutcome + Send>;

use openrouter_keymaster_core::state::{BeginCreate, Phase, State, Transition};
use serde_json::{Value, json};
use support::fixtures::{api_key, created_key};
use support::http::{Scripted, json_response};
use support::project::{Project, address, at, hash};
use support::sentinel::{SECRET_SENTINEL_KEY, assert_absent, assert_absent_under};
use wiremock::Mock;
use wiremock::matchers::{method, path};
use zeroize::Zeroizing;

const JOBFEED_HASH: &str = "hash-jobfeed-1";
const REPORTS_HASH: &str = "hash-reports-1";
const SUCCESSOR_HASH: &str = "hash-jobfeed-2";
const DESTINATION: &str = "vault/jobfeed";

/// One key, delivered to the host rather than to a file or a program.
const CONFIG: &str = r#"
version = 1

[receivers.host]
type = "caller"
destination = "vault/jobfeed"

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
receiver = "host"
"#;

/// The same, plus a second key delivered through the same receiver.
const TWO_KEYS: &str = r#"
version = 1

[receivers.host]
type = "caller"
destination = "vault/jobfeed"

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
receiver = "host"

[keys.reports]
name = "golf-reports"
limit_usd = 5
limit_reset = "monthly"
receiver = "host"
"#;

/// What the callback was handed, with the plaintext reduced to the one fact a
/// test needs about it.
///
/// The secret itself is never recorded. A record that held it would make the
/// scan below pass for the wrong reason.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Call {
    address: String,
    hash: String,
    generation: u32,
    operation: String,
    destination: Option<String>,
    saw_the_sentinel: bool,
}

impl Call {
    fn of(metadata: &DeliveryMetadata, plaintext: &KeyPlaintext) -> Self {
        Self {
            address: metadata.address().to_string(),
            hash: metadata.hash().to_string(),
            generation: metadata.generation(),
            operation: metadata.operation().to_string(),
            destination: metadata.destination().map(str::to_owned),
            saw_the_sentinel: plaintext.expose() == SECRET_SENTINEL_KEY,
        }
    }
}

/// How the host's code answers.
#[derive(Clone, Copy)]
enum Answer {
    Stored,
    Refused,
    Panics,
}

/// Every call the host's code was made, in order.
type Calls = Arc<Mutex<Vec<Call>>>;

/// A callback that records what it is handed and then answers `answer`.
fn recording(answer: Answer) -> (Calls, Deliver) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&calls);
    let deliver: Deliver = Box::new(move |metadata, plaintext| {
        recorded
            .lock()
            .expect("the recorder is not poisoned")
            .push(Call::of(metadata, plaintext));
        match answer {
            Answer::Stored => DeliveryOutcome::delivered("the host stored it"),
            Answer::Refused => DeliveryOutcome::rejected("the host refused it and stored nothing"),
            // Deliberately says nothing about the key: a panic message is host
            // text, and the receiver must not repeat it.
            Answer::Panics => panic!("the host's own code failed"),
        }
    });
    (calls, deliver)
}

fn calls(recorded: &Calls) -> Vec<Call> {
    recorded
        .lock()
        .expect("the recorder is not poisoned")
        .clone()
}

/// The context a host hands to `ops`, with or without its delivery callback.
fn context(project: &Project, deliver: Option<Deliver>) -> Context {
    Context {
        paths: Paths {
            config: project.config_path(),
            state: project.state_path(),
        },
        options: Options::new(project.server.api_base_url()),
        key: Some(
            ManagementKey::from_secret(Zeroizing::new(SECRET_SENTINEL_KEY.to_owned()))
                .expect("a usable test credential"),
        ),
        workspace: None,
        deliver,
    }
}

/// Answers `POST /keys` with `hashes` in turn, each carrying the sentinel.
fn serve_creates(project: &Project, names: &[(&str, &str)]) {
    let responses: Vec<Value> = names
        .iter()
        .map(|(hash, name)| created_key(hash, name, SECRET_SENTINEL_KEY))
        .collect();
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(Scripted::json(responses)),
    );
}

/// Answers the restriction write and the read that verifies it.
fn serve_secure(project: &Project, hash: &str, name: &str) {
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(json_response(200, &json!({}))),
    );
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(json_response(200, &json!({ "data": api_key(hash, name) }))),
    );
}

/// A project whose one key is creatable and whose creation is answered.
fn creatable() -> Project {
    let project = Project::new(CONFIG);
    serve_creates(&project, &[(JOBFEED_HASH, "golf-jobfeed")]);
    serve_secure(&project, JOBFEED_HASH, "golf-jobfeed");
    project.observe_sequence(
        vec![Vec::new(), vec![api_key(JOBFEED_HASH, "golf-jobfeed")]],
        vec![Vec::new()],
        vec![Vec::new()],
    );
    project
}

/// How many `POST /keys` requests the server saw.
fn create_requests(project: &Project) -> usize {
    project
        .request_trace()
        .iter()
        .filter(|request| *request == "POST /api/v1/keys")
        .count()
}

/// The action at one address, from a serialized report.
fn action<'a>(document: &'a Value, at_address: &str) -> &'a Value {
    document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == at_address)
        .unwrap_or_else(|| panic!("no action at {at_address} in {document}"))
}

/// Serializes a report and fails unless the plaintext is nowhere in it or in
/// the project directory.
fn assert_nothing_leaked(project: &Project, report: &impl serde::Serialize) -> Value {
    let document = serde_json::to_value(report).expect("the report serializes");
    assert_absent("the report", &document.to_string());
    assert_absent_under(project.directory.path());
    document
}

// --- the happy path ---------------------------------------------------------

#[test]
fn a_created_key_is_handed_to_the_callback_exactly_once() {
    let project = creatable();
    let (recorded, deliver) = recording(Answer::Stored);

    let outcome = ops::apply(context(&project, Some(deliver)), None).expect("the apply runs");

    assert!(
        outcome.error.is_none(),
        "the host stored the key: {:?}",
        outcome.error.map(|error| error.to_string())
    );
    assert_eq!(create_requests(&project), 1);

    let made = calls(&recorded);
    assert_eq!(made.len(), 1, "one key, one call: {made:?}");
    let call = &made[0];
    assert_eq!(call.address, "jobfeed");
    assert_eq!(call.hash, JOBFEED_HASH);
    assert_eq!(call.generation, 1);
    assert_eq!(call.destination.as_deref(), Some(DESTINATION));
    assert!(
        OperationId::parse(&call.operation).is_ok(),
        "the metadata names the journaled operation: {}",
        call.operation
    );
    assert!(
        call.saw_the_sentinel,
        "the callback is handed the real plaintext, so the scan below means something"
    );

    let document = assert_nothing_leaked(&project, &outcome.report);
    assert_eq!(document["outcome"], "applied", "{document}");
    assert!(
        action(&document, "keys.jobfeed")["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("the host stored it"),
        "the callback's own sentence is what the report gives an operator: {document}"
    );

    let state = project.read_state();
    let binding = state.key(&address("jobfeed")).expect("the created binding");
    let current = binding.current().expect("a promoted current key");
    assert_eq!(current.hash.as_str(), JOBFEED_HASH);
    assert!(binding.pending().is_none(), "the transaction is finished");
}

#[test]
fn two_keys_in_one_apply_are_two_calls_with_distinct_metadata() {
    let project = Project::new(TWO_KEYS);
    serve_creates(
        &project,
        &[
            (JOBFEED_HASH, "golf-jobfeed"),
            (REPORTS_HASH, "golf-reports"),
        ],
    );
    serve_secure(&project, JOBFEED_HASH, "golf-jobfeed");
    serve_secure(&project, REPORTS_HASH, "golf-reports");
    project.observe_sequence(
        vec![
            Vec::new(),
            vec![
                api_key(JOBFEED_HASH, "golf-jobfeed"),
                api_key(REPORTS_HASH, "golf-reports"),
            ],
        ],
        vec![Vec::new()],
        vec![Vec::new()],
    );
    let (recorded, deliver) = recording(Answer::Stored);

    let outcome = ops::apply(context(&project, Some(deliver)), None).expect("the apply runs");

    assert!(
        outcome.error.is_none(),
        "both keys were stored: {:?}",
        outcome.error.map(|error| error.to_string())
    );
    assert_eq!(create_requests(&project), 2);

    let made = calls(&recorded);
    assert_eq!(made.len(), 2, "one call per delivered key: {made:?}");
    assert_eq!(made[0].address, "jobfeed");
    assert_eq!(made[0].hash, JOBFEED_HASH);
    assert_eq!(made[1].address, "reports");
    assert_eq!(made[1].hash, REPORTS_HASH);
    assert_ne!(
        made[0].operation, made[1].operation,
        "each delivery belongs to its own journaled operation, which is what a \
         host routes on rather than call order"
    );
    assert!(made.iter().all(|call| call.saw_the_sentinel));

    assert_nothing_leaked(&project, &outcome.report);
}

#[test]
fn a_rotation_delivers_the_successor_to_the_callback() {
    let project = Project::new(CONFIG);
    serve_creates(&project, &[(SUCCESSOR_HASH, "golf-jobfeed")]);
    serve_secure(&project, SUCCESSOR_HASH, "golf-jobfeed");
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key the rotation succeeds");
    });
    let (recorded, deliver) = recording(Answer::Stored);

    let outcome =
        ops::rotate(context(&project, Some(deliver)), "jobfeed").expect("the rotation runs");

    assert!(outcome.error.is_none(), "the host stored the successor");
    assert_eq!(create_requests(&project), 1);

    let made = calls(&recorded);
    assert_eq!(made.len(), 1, "one successor, one call: {made:?}");
    assert_eq!(made[0].hash, SUCCESSOR_HASH);
    assert_eq!(
        made[0].generation, 2,
        "a successor takes the next generation"
    );
    assert_eq!(made[0].destination.as_deref(), Some(DESTINATION));
    assert!(made[0].saw_the_sentinel);

    let document = assert_nothing_leaked(&project, &outcome.report);
    assert_eq!(
        document["receiver"], "caller receiver for vault/jobfeed",
        "the receiver describes itself by its destination, which is not secret: {document}"
    );
}

// --- what the callback's answer means ---------------------------------------

#[test]
fn a_refused_delivery_holds_at_secured_and_disables_the_key() {
    let project = creatable();
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{JOBFEED_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    let (recorded, deliver) = recording(Answer::Refused);

    let outcome = ops::apply(context(&project, Some(deliver)), None).expect("a failure reports");

    assert_eq!(calls(&recorded).len(), 1, "delivery is at most once");
    assert!(outcome.error.is_some(), "a refused delivery fails the run");

    let state = project.read_state();
    let (_, operation) = state.pending_operation().expect("the held operation");
    assert_eq!(operation.phase, Phase::Secured);
    assert!(
        operation.delivery_rejected_at.is_some(),
        "a refusal is marked, so nothing can invoke the callback again"
    );

    let document = assert_nothing_leaked(&project, &outcome.report);
    let detail = action(&document, "keys.jobfeed")["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(detail.contains("refused the plaintext"), "{detail}");
    assert!(detail.contains("recover replace"), "{detail}");
    assert!(
        project
            .write_trace()
            .contains(&format!("PATCH /api/v1/keys/{JOBFEED_HASH}")),
        "the key that can never be delivered is disabled: {:?}",
        project.write_trace()
    );
}

#[test]
fn a_panicking_callback_is_ambiguous_and_is_never_called_again() {
    let project = creatable();
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{JOBFEED_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    let (recorded, deliver) = recording(Answer::Panics);

    let outcome = ops::apply(context(&project, Some(deliver)), None).expect("a failure reports");

    assert_eq!(
        calls(&recorded).len(),
        1,
        "a panic proves nothing, and nothing is retried"
    );
    assert_eq!(create_requests(&project), 1);
    assert!(outcome.error.is_some());

    let state = project.read_state();
    let (_, operation) = state.pending_operation().expect("the held operation");
    assert_eq!(operation.phase, Phase::DeliveryAmbiguous);

    let document = assert_nothing_leaked(&project, &outcome.report);
    let detail = action(&document, "keys.jobfeed")["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(detail.contains("panicked"), "{detail}");
    assert!(
        !detail.contains("the host's own code failed"),
        "the panic message is host text and is not repeated: {detail}"
    );
}

// --- no callback ------------------------------------------------------------

#[test]
fn planning_needs_no_callback() {
    let project = Project::new(CONFIG);
    project.observe(Vec::new(), Vec::new(), Vec::new());

    let outcome = ops::plan(context(&project, None)).expect("a plan is readable");

    assert!(outcome.error.is_none());
    let document = assert_nothing_leaked(&project, &outcome.report);
    assert_eq!(
        action(&document, "keys.jobfeed")["kind"],
        "create",
        "the destination is configuration, so a plan is complete without the \
         host's code: {document}"
    );
}

#[test]
fn an_apply_with_no_callback_creates_nothing() {
    let project = creatable();

    let outcome = ops::apply(context(&project, None), None).expect("a failure reports");

    let error = outcome.error.expect("the run cannot issue the key");
    assert_eq!(error.kind(), "apply_undeliverable", "{error}");
    assert!(error.to_string().contains("jobfeed"), "{error}");
    assert!(error.to_string().contains("Context.deliver"), "{error}");
    assert_eq!(
        create_requests(&project),
        0,
        "the refusal is ahead of the create"
    );
    assert!(
        project.write_trace().is_empty(),
        "nothing was written anywhere: {:?}",
        project.write_trace()
    );
    assert!(
        project.read_state().pending_operation().is_none(),
        "the refusal is before `create_started`, so there is nothing to recover"
    );

    let document = assert_nothing_leaked(&project, &outcome.report);
    assert_eq!(action(&document, "keys.jobfeed")["status"], "held_back");
}

/// A plan whose first phase writes, and whose key phase cannot: one guardrail
/// to create, one bound key to update, and one key that only a host callback
/// could take delivery of.
const MIXED: &str = r#"
version = 1

[receivers.host]
type = "caller"
destination = "vault/jobfeed"

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"
limit_usd = 25
reset_interval = "monthly"

[keys.reports]
name = "golf-reports"
limit_usd = 7
limit_reset = "monthly"
receiver = "vault"

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
receiver = "host"
"#;

#[test]
fn a_write_in_an_earlier_phase_never_lands_when_a_later_key_cannot_be_delivered() {
    // ADR-0005 item 3 refuses before *any* write. An apply is a sequence, so a
    // refusal that waited for the key's own transaction would arrive after the
    // guardrail had been created and the other key patched.
    let project = Project::new(MIXED);
    project.observe(
        vec![api_key(REPORTS_HASH, "golf-reports")],
        Vec::new(),
        Vec::new(),
    );
    project.write_state(|state| {
        state
            .bind_key(&address("reports"), hash(REPORTS_HASH), 1, at(0))
            .expect("binding the key this plan would update");
    });
    let before = fs::read(project.state_path()).expect("the state file");

    let outcome = ops::apply(context(&project, None), None).expect("a failure reports");

    let error = outcome.error.expect("the run cannot issue `jobfeed`");
    assert_eq!(error.kind(), "apply_undeliverable", "{error}");
    assert!(
        project.write_trace().is_empty(),
        "not the guardrail create, not the key update, nothing: {:?}",
        project.write_trace()
    );
    assert_eq!(
        fs::read(project.state_path()).expect("the state file"),
        before,
        "and no guardrail binding was recorded either"
    );

    let document = assert_nothing_leaked(&project, &outcome.report);
    for held in ["guardrails.cheap", "keys.reports", "keys.jobfeed"] {
        assert_eq!(
            action(&document, held)["status"],
            "held_back",
            "every write in the plan is held back, not just the issuance: {document}"
        );
    }
}

#[test]
fn a_rotation_with_no_callback_stages_nothing() {
    let project = creatable();
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key a rotation replaces");
    });

    let error = ops::rotate(context(&project, None), "jobfeed")
        .expect_err("a successor that cannot be delivered is never staged");

    assert!(error.to_string().contains("Context.deliver"), "{error}");
    assert_eq!(create_requests(&project), 0);
    assert!(
        project.write_trace().is_empty(),
        "the working key is untouched: {:?}",
        project.write_trace()
    );
}

#[test]
fn a_recover_replace_with_no_callback_closes_nothing() {
    let project = creatable();
    project.write_state(ambiguous_delivery);
    let before = fs::read(project.state_path()).expect("the state file");

    let error = ops::recover_replace(context(&project, None), "jobfeed")
        .expect_err("a successor that cannot be delivered is never staged");

    assert!(error.to_string().contains("Context.deliver"), "{error}");
    assert!(
        project.write_trace().is_empty(),
        "the dead operation is not closed and its key is not disabled: {:?}",
        project.write_trace()
    );
    assert_eq!(
        fs::read(project.state_path()).expect("the state file"),
        before,
        "the journal is byte for byte as it was"
    );
}

// --- the destination is part of the plan ------------------------------------

#[test]
fn a_changed_destination_plans_a_replacement() {
    let project = creatable();
    let (_, deliver) = recording(Answer::Stored);
    let applied = ops::apply(context(&project, Some(deliver)), None).expect("the apply runs");
    assert!(applied.error.is_none(), "the key was created and delivered");

    fs::write(
        project.config_path(),
        CONFIG.replace(DESTINATION, "vault/elsewhere"),
    )
    .expect("moving the destination");

    let outcome = ops::plan(context(&project, None)).expect("a plan is readable");
    let document = assert_nothing_leaked(&project, &outcome.report);
    assert_eq!(
        action(&document, "keys.jobfeed")["kind"],
        "replace",
        "where the plaintext goes is part of what a key is: {document}"
    );
}

#[test]
fn a_plan_fingerprint_refuses_an_apply_after_the_destination_changes() {
    let project = creatable();
    let expected: PlanFingerprint = ops::plan(context(&project, None))
        .expect("a plan")
        .report
        .fingerprint()
        .expect("a plan with no operation pending is bindable")
        .clone();

    fs::write(
        project.config_path(),
        CONFIG.replace(DESTINATION, "vault/elsewhere"),
    )
    .expect("moving the destination");

    let (recorded, deliver) = recording(Answer::Stored);
    let outcome = ops::apply(context(&project, Some(deliver)), Some(expected))
        .expect("a refusal still reports");

    let error = outcome.error.expect("a refused apply says why");
    assert_eq!(error.kind(), "plan_changed", "{error}");
    assert_eq!(create_requests(&project), 0);
    assert!(
        calls(&recorded).is_empty(),
        "the callback is never reached by a refused apply"
    );
}

/// A configuration whose `reports` key is bound and whose `jobfeed` key only a
/// host callback could take delivery of.
const PROMOTION: &str = r#"
version = 1

[receivers.host]
type = "caller"
destination = "vault/jobfeed"

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
receiver = "host"

[keys.reports]
name = "golf-reports"
limit_usd = 5
limit_reset = "monthly"
receiver = "vault"
generation = 2
"#;

/// The successor `reports` already owns, delivered but not yet promoted.
const REPORTS_SUCCESSOR: &str = "hash-reports-2";

#[test]
fn a_refusal_reports_the_promotion_it_completed_first() {
    // An apply finishes a delivered operation's promotion under its lock before
    // it plans anything (ADR-0002). That is local, it is older than the plan,
    // and it is the one write a refusal cannot claim did not happen — so the
    // report carries it and the error says so.
    let project = Project::new(PROMOTION);
    project.observe(
        vec![
            api_key(REPORTS_HASH, "golf-reports"),
            api_key(REPORTS_SUCCESSOR, "golf-reports"),
        ],
        Vec::new(),
        Vec::new(),
    );
    project.write_state(delivered_successor_for_reports);

    let outcome = ops::apply(context(&project, None), None).expect("a failure reports");

    let error = outcome.error.expect("the run cannot issue `jobfeed`");
    assert_eq!(error.kind(), "apply_undeliverable", "{error}");
    assert!(
        error.to_string().contains(
            "no remote write was made and no key was issued; a previously delivered key was \
             promoted"
        ),
        "the message says what the run did do: {error}"
    );

    let state = project.read_state();
    let current = state
        .key(&address("reports"))
        .and_then(|binding| binding.current())
        .expect("a promoted current key");
    assert_eq!(
        current.hash.as_str(),
        REPORTS_SUCCESSOR,
        "the promotion stands; it was complete before the plan existed"
    );
    assert!(state.pending_operation().is_none());
    assert!(
        project.write_trace().is_empty(),
        "and nothing remote was written: {:?}",
        project.write_trace()
    );

    let document = assert_nothing_leaked(&project, &outcome.report);
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap_or_default()
                .contains("completed that promotion locally")),
        "the report names the promotion rather than swallowing it: {document}"
    );
    assert_eq!(action(&document, "keys.jobfeed")["status"], "held_back");
}

/// Journals a `reports` successor that reached `delivered` and stopped there,
/// beside the key the address already owns.
fn delivered_successor_for_reports(state: &mut State) {
    let reports = address("reports");
    state
        .bind_key(&reports, hash(REPORTS_HASH), 1, at(0))
        .expect("binding the key the successor replaces");
    state
        .begin_create(
            &reports,
            BeginCreate {
                operation: OperationId::parse("op-0002").expect("an operation id"),
                generation: 2,
                name: RemoteName::parse("golf-reports").expect("a remote name"),
                workspace: None,
                receiver: openrouter_keymaster_core::config::Config::parse(PROMOTION)
                    .expect("a valid test configuration")
                    .receivers[&address("vault")]
                    .fingerprint(&address("vault")),
            },
            at(1),
        )
        .expect("journaling the successor's creation");
    for (step, transition) in [
        Transition::Created {
            hash: hash(REPORTS_SUCCESSOR),
        },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::Delivered,
    ]
    .into_iter()
    .enumerate()
    {
        state
            .advance_key(&reports, transition, at(2 + step as i64))
            .expect("replaying the transaction");
    }
}

/// Journals a create that reached `delivery_ambiguous` and stopped there: a
/// key exists, its plaintext is gone, and only a replacement can fix it.
fn ambiguous_delivery(state: &mut State) {
    let jobfeed = address("jobfeed");
    state
        .begin_create(
            &jobfeed,
            BeginCreate {
                operation: OperationId::parse("op-0001").expect("an operation id"),
                generation: 1,
                name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                workspace: None,
                receiver: openrouter_keymaster_core::config::Config::parse(CONFIG)
                    .expect("a valid test configuration")
                    .receivers[&address("host")]
                    .fingerprint(&address("host")),
            },
            at(0),
        )
        .expect("journaling the creation");
    for (step, transition) in [
        Transition::Created {
            hash: hash(JOBFEED_HASH),
        },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::DeliveryAmbiguous,
    ]
    .into_iter()
    .enumerate()
    {
        state
            .advance_key(&jobfeed, transition, at(1 + step as i64))
            .expect("replaying the transaction");
    }
}
