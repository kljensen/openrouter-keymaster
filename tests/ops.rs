//! Core API tests: the `ops` functions called directly, with no binary and no
//! terminal.
//!
//! Most of these are about one promise. A plan carries a fingerprint of every
//! input that decides what an apply would write, and an apply given that
//! fingerprint executes only if every one of them is still what it was — so a
//! host that shows a plan and an "apply" button never writes something the
//! operator did not see. Each case below changes exactly one input and proves
//! the refusal costs nothing: no remote write, no receiver invocation, no state
//! write, not even a promotion.

mod support;

use std::fs;
use std::path::PathBuf;

use openrouter_keymaster::client::{ManagementKey, Options};
use openrouter_keymaster::ids::{OperationId, RemoteName};
use openrouter_keymaster::ops::{self, Context, Paths, PlanFingerprint};
use openrouter_keymaster::state::{BeginCreate, Origin, State, StateFile, Transition};
use serde_json::{Value, json};
use support::fixtures::{
    FAKE_GUARDRAIL_ID, OTHER_FAKE_GUARDRAIL_ID, api_key, assignment, guardrail,
};
use support::http::json_response;
use support::project::{Project, address, at, hash, uuid};
use support::sentinel::SECRET_SENTINEL_KEY;
use wiremock::Mock;
use wiremock::matchers::{method, path};
use zeroize::Zeroizing;

const JOBFEED_HASH: &str = "hash-jobfeed-1";
const ASSIGNMENT_ID: &str = "44444444-4444-4444-8444-444444444444";

/// A configuration whose guardrail has drifted: the budget is the one managed
/// field that differs, so the plan holds exactly one executable action and an
/// apply is a single `PATCH`.
const CONFIG: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"
limit_usd = 25
reset_interval = "monthly"

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
guardrail = "cheap"
receiver = "vault"
generation = 1
"#;

/// Binds the guardrail and the key the configuration describes.
fn bind(state: &mut State) {
    state
        .bind_guardrail(
            &address("cheap"),
            uuid(FAKE_GUARDRAIL_ID),
            Origin::Imported,
            at(0),
        )
        .expect("binding the guardrail");
    state
        .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
        .expect("binding the key");
}

/// The guardrail as OpenRouter has it, with `limit_usd` dollars of budget.
fn rail(limit: f64) -> Value {
    let mut rail = guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[]);
    rail["limit_usd"] = json!(limit);
    rail
}

/// What a snapshot of this project sees: one key, one drifted guardrail, and
/// the assignment between them.
fn observe_drift(project: &Project) {
    project.observe(
        vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
        vec![rail(10.0)],
        vec![assignment(ASSIGNMENT_ID, JOBFEED_HASH, FAKE_GUARDRAIL_ID)],
    );
}

/// A bound project whose guardrail has drifted.
fn drifted() -> Project {
    let project = Project::new(CONFIG);
    observe_drift(&project);
    project.write_state(bind);
    project
}

/// Changes the state file the way a later run would: under the lock, from what
/// is already there.
fn rewrite_state(project: &Project, change: impl FnOnce(&mut State)) {
    let file = StateFile::new(project.state_path());
    let lock = file.lock().expect("the state lock");
    let mut state = lock.read().expect("reading state");
    change(&mut state);
    lock.write(&mut state).expect("writing state");
}

/// The context a host would hand to a worker thread.
fn context(project: &Project) -> Context {
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
    }
}

/// The fingerprint of the plan as it stands, which must be bindable.
fn fingerprint(project: &Project) -> PlanFingerprint {
    ops::plan(context(project))
        .expect("a plan")
        .report
        .fingerprint()
        .expect("a plan with no operation pending is bindable")
        .clone()
}

/// Applies with a fingerprint and fails unless the run refused before writing
/// anything at all, anywhere.
fn assert_refused(project: &Project, context: Context, expected: &PlanFingerprint) {
    let state = fs::read(project.state_path()).expect("the state file");
    let entries = project.entries();

    let outcome = ops::apply(context, Some(expected.clone())).expect("a refusal still reports");
    let error = outcome.error.expect("a refused apply says why");
    assert_eq!(error.kind(), "plan_changed", "{error}");

    let document = serde_json::to_value(&outcome.report).expect("the report serializes");
    assert_eq!(
        document["outcome"], "held_back",
        "the refusal returns the fresh plan with its writes held back: {document}"
    );

    assert!(
        project.write_trace().is_empty(),
        "a refused apply sends no write: {:?}",
        project.write_trace()
    );
    assert_eq!(
        fs::read(project.state_path()).expect("the state file"),
        state,
        "a refused apply leaves the state file byte for byte as it was"
    );
    assert_eq!(
        project.entries(),
        entries,
        "a refused apply invokes no receiver, so nothing new appears"
    );
}

#[test]
fn a_matching_fingerprint_applies_the_plan_it_was_taken_from() {
    let project = Project::new(CONFIG);
    project.observe_sequence(
        vec![vec![api_key(JOBFEED_HASH, "golf-jobfeed")]],
        // Drifted when the plan is computed and when apply recomputes it,
        // converged for the read that verifies the write.
        vec![vec![rail(10.0)], vec![rail(10.0)], vec![rail(25.0)]],
        vec![vec![assignment(
            ASSIGNMENT_ID,
            JOBFEED_HASH,
            FAKE_GUARDRAIL_ID,
        )]],
    );
    project.write_state(bind);
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let expected = fingerprint(&project);
    let outcome = ops::apply(context(&project), Some(expected)).expect("the apply runs");

    assert!(
        outcome.error.is_none(),
        "nothing changed between the plan and the apply: {:?}",
        outcome.error.map(|error| error.to_string())
    );
    let document = serde_json::to_value(&outcome.report).expect("the report serializes");
    assert_eq!(document["outcome"], "applied", "{document}");
    assert_eq!(
        project.write_trace(),
        vec![format!("PATCH /api/v1/guardrails/{FAKE_GUARDRAIL_ID}")]
    );
}

#[test]
fn a_configuration_edit_that_changes_an_action_refuses_the_bound_apply() {
    let project = drifted();
    let expected = fingerprint(&project);

    fs::write(
        project.config_path(),
        CONFIG.replace("limit_usd = 25", "limit_usd = 30"),
    )
    .expect("editing the configuration");

    assert_refused(&project, context(&project), &expected);
}

#[test]
fn a_moved_receiver_destination_refuses_the_bound_apply() {
    // The plan's actions are identical either way — nothing here is created —
    // but where a key's plaintext would go is an input to what an apply does,
    // and the fingerprint binds the whole configuration rather than a list of
    // fields precisely so that this is covered without enumerating it.
    let project = drifted();
    let expected = fingerprint(&project);

    fs::write(
        project.config_path(),
        CONFIG.replace("vault.key", "elsewhere.key"),
    )
    .expect("moving the receiver");

    assert_refused(&project, context(&project), &expected);
}

#[test]
fn a_raised_generation_refuses_the_bound_apply() {
    let project = drifted();
    let expected = fingerprint(&project);

    fs::write(
        project.config_path(),
        CONFIG.replace("generation = 1", "generation = 2"),
    )
    .expect("raising the generation");

    assert_refused(&project, context(&project), &expected);
}

#[test]
fn a_rebound_guardrail_uuid_refuses_the_bound_apply() {
    // The guardrail a key is secured by is resolved from state while the key is
    // being issued. Rebinding it also advances the serial, which is the point:
    // binding the whole state rather than a list of fields is what makes every
    // state-resolved input covered without enumerating one of them.
    let project = drifted();
    let expected = fingerprint(&project);

    rewrite_state(&project, |state| {
        state
            .replace_guardrail(&address("cheap"), uuid(OTHER_FAKE_GUARDRAIL_ID), at(1))
            .expect("rebinding the guardrail");
    });

    assert_refused(&project, context(&project), &expected);
}

#[test]
fn a_different_endpoint_refuses_the_bound_apply() {
    // The same organization, described identically, at another API root: a plan
    // is a plan against one endpoint and no other.
    let project = drifted();
    let expected = fingerprint(&project);

    let elsewhere = Project::new(CONFIG);
    observe_drift(&elsewhere);
    let mut context = context(&project);
    context.options = Options::new(elsewhere.server.api_base_url());

    assert_refused(&project, context, &expected);
    assert!(
        elsewhere.write_trace().is_empty(),
        "and nothing was written at the other endpoint either"
    );
}

#[test]
fn a_different_credential_refuses_the_bound_apply() {
    let project = drifted();
    let expected = fingerprint(&project);

    let mut context = context(&project);
    context.key = Some(
        ManagementKey::from_secret(Zeroizing::new(
            "sk-or-v1-A-DIFFERENT-FAKE-CREDENTIAL".to_owned(),
        ))
        .expect("a usable test credential"),
    );

    assert_refused(&project, context, &expected);
}

#[test]
fn a_different_state_path_refuses_the_bound_apply() {
    // Byte for byte the same state, in another file. Which file an apply writes
    // is part of what a plan describes.
    let project = drifted();
    let expected = fingerprint(&project);

    let copy: PathBuf = project.directory.path().join("copy.json");
    fs::copy(project.state_path(), &copy).expect("copying the state file");
    let mut context = context(&project);
    context.paths.state = copy.clone();

    assert_refused(&project, context, &expected);
    assert_eq!(
        fs::read(&copy).expect("the copied state file"),
        fs::read(project.state_path()).expect("the state file"),
        "and the file the run was pointed at is unchanged too"
    );
}

#[test]
fn any_state_write_refuses_the_bound_apply() {
    // Nothing about what state *says* changes here: it is rewritten as it was,
    // which advances the serial. That is the point — the serial is what makes
    // "state has been written since" answerable at all.
    let project = drifted();
    let expected = fingerprint(&project);

    {
        let file = StateFile::new(project.state_path());
        let lock = file.lock().expect("the state lock");
        let mut state = lock.read().expect("reading state");
        lock.write(&mut state).expect("rewriting state");
    }

    assert_refused(&project, context(&project), &expected);
}

#[test]
fn a_pending_operation_makes_a_plan_unbindable_and_refuses_without_promoting() {
    let project = drifted();
    let expected = fingerprint(&project);

    // A delivered operation is the one a plain apply promotes before it plans
    // anything. A bound apply must not: the comparison comes first, and this
    // plan is not the one the caller was shown.
    rewrite_state(&project, deliver);

    assert!(
        ops::plan(context(&project))
            .expect("a plan")
            .report
            .fingerprint()
            .is_none(),
        "a plan computed beside an unfinished operation cannot be bound"
    );

    assert_refused(&project, context(&project), &expected);
    let state = project.read_state();
    assert!(
        state.pending_operation().is_some(),
        "the delivered operation was not promoted"
    );
}

#[test]
fn an_apply_with_no_credential_promotes_nothing() {
    // The credential is checked where a client would first be built, which is
    // before the promotion a plain apply performs (ADR-0003).
    let project = drifted();
    rewrite_state(&project, deliver);
    let before = fs::read(project.state_path()).expect("the state file");

    let mut context = context(&project);
    context.key = None;
    let error = ops::apply(context, None).expect_err("there is no report to give");

    assert_eq!(error.kind(), "missing_credential");
    assert_eq!(
        fs::read(project.state_path()).expect("the state file"),
        before,
        "an apply with no credential writes nothing at all"
    );
    project.server.assert_request_count(0);
}

#[test]
fn state_forget_needs_no_credential() {
    let project = drifted();
    let mut context = context(&project);
    context.key = None;

    let outcome = ops::forget(context, "keys.jobfeed").expect("forgetting a bound address");

    assert!(outcome.error.is_none());
    assert!(
        project.read_state().key(&address("jobfeed")).is_none(),
        "the binding was released"
    );
    project.server.assert_request_count(0);
}

/// Journals a create that reached `delivered` and stopped there.
fn deliver(state: &mut State) {
    let jobfeed = address("jobfeed");
    state
        .begin_create(
            &jobfeed,
            BeginCreate {
                operation: OperationId::parse("op-0002").expect("an operation id"),
                generation: 2,
                name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                workspace: None,
                receiver: receiver_fingerprint(),
            },
            at(10),
        )
        .expect("journaling the successor's creation");
    for (step, transition) in [
        Transition::Created {
            hash: hash("hash-jobfeed-2"),
        },
        Transition::Secured,
        Transition::DeliveryStarted,
        Transition::Delivered,
    ]
    .into_iter()
    .enumerate()
    {
        state
            .advance_key(&jobfeed, transition, at(11 + step as i64))
            .expect("replaying the transaction");
    }
}

/// The fingerprint of the receiver the configuration names.
fn receiver_fingerprint() -> openrouter_keymaster::ids::ReceiverFingerprint {
    openrouter_keymaster::config::Config::parse(CONFIG)
        .expect("a valid configuration")
        .receivers[&address("vault")]
        .fingerprint()
}
