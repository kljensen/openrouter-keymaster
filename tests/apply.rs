//! Binary-level tests for `keymaster apply`.
//!
//! Apply is the only command that writes to OpenRouter, so most of what these
//! cases assert is *which requests were sent, in what order, carrying what* —
//! and, just as often, that none were. The listings are scripted with
//! [`Project::observe_sequence`], so a case decides what the world looks like
//! before the writes and what it looks like to the read that verifies them.

mod support;

use std::fs;

use keymaster::ids::{OperationId, ReceiverFingerprint, RemoteName};
use keymaster::state::{BeginCreate, Origin, Transition};
use serde_json::{Value, json};
use support::fixtures::{
    FAKE_GUARDRAIL_ID, OTHER_FAKE_GUARDRAIL_ID, api_key, assignment, guardrail,
};
use support::http::{Scripted, body_json, json_response};
use support::project::{Project, address, at, hash, uuid};
use support::sentinel::SECRET_SENTINEL_KEY;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const JOBFEED_HASH: &str = "hash-jobfeed-1";
const STRAY_HASH: &str = "hash-stray-1";
const NEW_RAIL_ID: &str = "33333333-3333-4333-8333-333333333333";
const ASSIGNMENT_ID: &str = "44444444-4444-4444-8444-444444444444";

/// A guardrail to create, and a key that drifts and wants that guardrail.
const CONFIG: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"
limit_usd = 25

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 10
limit_reset = "monthly"
guardrail = "cheap"
receiver = "vault"
"#;

/// The same project with nothing to converge.
const CONVERGED_CONFIG: &str = r#"
version = 1

[guardrails.cheap]
name = "cheap-rail"
limit_usd = 10
reset_interval = "monthly"

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
guardrail = "cheap"
"#;

/// Answers `POST /guardrails` with a guardrail carrying `id`.
fn serve_guardrail_create(project: &Project, id: &str, name: &str) {
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/guardrails"))
            .respond_with(json_response(
                200,
                &json!({ "data": guardrail(id, name, &[]) }),
            )),
    );
}

/// Answers every `PATCH` and assignment write with an empty success.
fn serve_writes(project: &Project) {
    for (verb, route) in [
        ("PATCH", format!("/api/v1/keys/{JOBFEED_HASH}")),
        ("PATCH", format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}")),
        (
            "POST",
            format!("/api/v1/guardrails/{NEW_RAIL_ID}/assignments/keys"),
        ),
        (
            "POST",
            format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}/assignments/keys"),
        ),
        (
            "POST",
            format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}/assignments/keys/remove"),
        ),
    ] {
        project.server.mount(
            Mock::given(method(verb))
                .and(path(route))
                .respond_with(json_response(200, &json!({}))),
        );
    }
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

/// The warnings a JSON document carries.
fn warnings(document: &Value) -> Vec<String> {
    document["warnings"]
        .as_array()
        .expect("a warning array")
        .iter()
        .map(|warning| warning.as_str().unwrap_or_default().to_owned())
        .collect()
}

/// A key as the fixture returns it, with one field overridden.
fn key_with(name: &str, field: &str, value: Value) -> Value {
    let mut key = api_key(JOBFEED_HASH, name);
    key[field] = value;
    key
}

// --- nothing to do ---------------------------------------------------------

#[test]
fn a_converged_project_writes_nothing_at_all() {
    let project = Project::new(CONVERGED_CONFIG);
    project.observe(
        vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
        vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])],
        vec![assignment(ASSIGNMENT_ID, JOBFEED_HASH, FAKE_GUARDRAIL_ID)],
    );
    project.write_state(|state| {
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
    });
    let before = fs::read(project.state_path()).expect("the state fixture");

    let streams = project.succeed(&["--json", "apply"]);
    let document = streams.document();

    assert_eq!(document["outcome"], "converged");
    assert_eq!(document["applied"], 0);
    assert_eq!(document["planned"], 0);
    assert!(
        project.write_trace().is_empty(),
        "a no-op apply writes nothing"
    );
    project.assert_read_only();
    assert_eq!(
        project.server.requests().len(),
        6,
        "one snapshot and no verification read: there is nothing to verify"
    );
    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "a no-op apply leaves the state file byte for byte as it was"
    );

    let human = project.succeed(&["apply"]);
    assert!(
        human.out.contains("converged: OpenRouter already matches"),
        "{}",
        human.out
    );
}

#[test]
fn a_remote_resource_no_address_owns_is_never_written_to() {
    let project = Project::new(CONVERGED_CONFIG);
    project.observe(
        vec![
            api_key(JOBFEED_HASH, "golf-jobfeed"),
            api_key(STRAY_HASH, "someone-elses-key"),
        ],
        vec![
            guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[]),
            guardrail(OTHER_FAKE_GUARDRAIL_ID, "someone-elses-rail", &[]),
        ],
        vec![assignment(ASSIGNMENT_ID, JOBFEED_HASH, FAKE_GUARDRAIL_ID)],
    );
    project.write_state(|state| {
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
    });

    let document = project.succeed(&["--json", "apply"]).document();
    assert_eq!(
        action(&document, &format!("remote key {STRAY_HASH}"))["status"],
        "reported"
    );
    assert!(project.write_trace().is_empty());
}

// --- the ordinary convergence ----------------------------------------------

#[test]
fn guardrails_then_keys_then_assignments_are_written_once_each_and_verified() {
    let project = Project::new(CONFIG);
    serve_guardrail_create(&project, NEW_RAIL_ID, "cheap-rail");
    serve_writes(&project);
    project.observe_sequence(
        // The key drifts on its limit; afterwards it matches.
        vec![
            vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
            vec![key_with("golf-jobfeed", "limit", json!(10.0))],
        ],
        // The guardrail does not exist yet; afterwards it does.
        vec![Vec::new(), vec![converged_rail()]],
        vec![
            Vec::new(),
            vec![assignment(ASSIGNMENT_ID, JOBFEED_HASH, NEW_RAIL_ID)],
        ],
    );
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key");
    });

    let document = project.succeed(&["--json", "apply"]).document();

    assert_eq!(
        project.write_trace(),
        vec![
            "POST /api/v1/guardrails".to_owned(),
            format!("PATCH /api/v1/keys/{JOBFEED_HASH}"),
            format!("POST /api/v1/guardrails/{NEW_RAIL_ID}/assignments/keys"),
        ],
        "guardrails, then existing keys, then assignments — one request each"
    );

    let requests = project.server.requests();
    let writes: Vec<_> = requests
        .iter()
        .filter(|request| request.method != "GET")
        .collect();
    assert_eq!(
        body_json(writes[0]),
        json!({
            "name": "cheap-rail",
            "limit_usd": 25.0,
            "include_byok_in_budgets": false,
        }),
        "a create sends only the managed fields"
    );
    assert_eq!(
        body_json(writes[1]),
        json!({
            "name": "golf-jobfeed",
            "limit": 10.0,
            "limit_reset": "monthly",
            "include_byok_in_limit": false,
            "disabled": false,
        }),
        "a key patch carries no immutable field"
    );
    assert_eq!(
        body_json(writes[2]),
        json!({ "key_hashes": [JOBFEED_HASH] }),
        "an assignment names one key, never the guardrail's whole list"
    );

    assert_eq!(document["outcome"], "applied");
    assert_eq!(document["applied"], 3);
    assert_eq!(document["verified"], 3);
    assert_eq!(document["unverified"], 0);
    for address in ["guardrails.cheap", "keys.jobfeed", "keys.jobfeed.guardrail"] {
        let action = action(&document, address);
        assert_eq!(action["status"], "applied", "{address}");
        assert_eq!(action["verified"], Value::Bool(true), "{address}");
    }

    let state = project.read_state();
    let binding = state
        .guardrail(&address("cheap"))
        .expect("the created guardrail's identity");
    assert_eq!(binding.id.as_str(), NEW_RAIL_ID);
    assert_eq!(binding.origin, Origin::Created);
}

/// The guardrail `CONFIG` asks for, as it looks once apply has created it.
fn converged_rail() -> Value {
    let mut rail = guardrail(NEW_RAIL_ID, "cheap-rail", &[]);
    rail["limit_usd"] = json!(25.0);
    rail["reset_interval"] = Value::Null;
    rail
}

#[test]
fn a_second_apply_after_a_successful_one_is_a_no_op() {
    let project = Project::new(CONFIG);
    serve_guardrail_create(&project, NEW_RAIL_ID, "cheap-rail");
    serve_writes(&project);
    project.observe_sequence(
        vec![
            vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
            vec![key_with("golf-jobfeed", "limit", json!(10.0))],
        ],
        vec![Vec::new(), vec![converged_rail()]],
        vec![
            Vec::new(),
            vec![assignment(ASSIGNMENT_ID, JOBFEED_HASH, NEW_RAIL_ID)],
        ],
    );
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key");
    });

    project.succeed(&["apply"]);
    let writes_after_first = project.write_trace().len();
    let state_after_first = fs::read(project.state_path()).expect("the state file");

    let document = project.succeed(&["--json", "apply"]).document();
    assert_eq!(document["outcome"], "converged");
    assert_eq!(
        project.write_trace().len(),
        writes_after_first,
        "the second apply sends no write at all"
    );
    assert_eq!(
        state_after_first,
        fs::read(project.state_path()).expect("the state file"),
        "and writes no state"
    );
}

#[test]
fn a_guardrail_that_is_gone_is_recreated_and_its_key_reassigned() {
    let project = Project::new(CONFIG);
    serve_guardrail_create(&project, NEW_RAIL_ID, "cheap-rail");
    serve_writes(&project);
    project.observe_sequence(
        vec![vec![key_with("golf-jobfeed", "limit", json!(10.0))]],
        // The bound guardrail is not there, and nothing else carries its name.
        vec![Vec::new(), vec![converged_rail()]],
        vec![
            Vec::new(),
            vec![assignment(ASSIGNMENT_ID, JOBFEED_HASH, NEW_RAIL_ID)],
        ],
    );
    project.write_state(|state| {
        state
            .bind_guardrail(
                &address("cheap"),
                uuid(FAKE_GUARDRAIL_ID),
                Origin::Imported,
                at(0),
            )
            .expect("binding the guardrail that later disappears");
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key");
    });

    let document = project.succeed(&["--json", "apply"]).document();

    assert_eq!(
        project.write_trace(),
        vec![
            "POST /api/v1/guardrails".to_owned(),
            format!("POST /api/v1/guardrails/{NEW_RAIL_ID}/assignments/keys"),
        ],
        "the guardrail is recreated and the key's assignment is restored"
    );
    assert_eq!(document["outcome"], "applied");
    assert_eq!(
        project
            .read_state()
            .guardrail(&address("cheap"))
            .expect("the rebound guardrail")
            .id
            .as_str(),
        NEW_RAIL_ID,
        "the dead UUID gives way to the one that exists"
    );
}

#[test]
fn an_assignment_the_configuration_no_longer_wants_is_removed() {
    let project = Project::new(
        "version = 1\n\n[keys.jobfeed]\nname = \"golf-jobfeed\"\nlimit_usd = 5\n\
         limit_reset = \"monthly\"\nclear = [\"guardrail\"]\n",
    );
    serve_writes(&project);
    project.observe_sequence(
        vec![vec![api_key(JOBFEED_HASH, "golf-jobfeed")]],
        vec![vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])]],
        vec![
            vec![assignment(ASSIGNMENT_ID, JOBFEED_HASH, FAKE_GUARDRAIL_ID)],
            Vec::new(),
        ],
    );
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key");
    });

    let document = project.succeed(&["--json", "apply"]).document();

    assert_eq!(
        project.write_trace(),
        vec![format!(
            "POST /api/v1/guardrails/{FAKE_GUARDRAIL_ID}/assignments/keys/remove"
        )]
    );
    let removal = project
        .server
        .requests()
        .into_iter()
        .find(|request| request.url.path().ends_with("/remove"))
        .expect("the removal request");
    assert_eq!(body_json(&removal), json!({ "key_hashes": [JOBFEED_HASH] }));
    assert_eq!(document["outcome"], "applied");
    assert_eq!(
        action(&document, "keys.jobfeed.guardrail")["verified"],
        Value::Bool(true)
    );
}

#[test]
fn a_guardrail_whose_name_is_taken_is_not_recreated() {
    // The bound guardrail is gone, but something else already answers to the
    // configured name. Recreating would produce a second guardrail under a
    // name that is already ambiguous, so the planner reports it instead — and
    // apply writes nothing.
    let project = Project::new(CONFIG);
    serve_guardrail_create(&project, NEW_RAIL_ID, "cheap-rail");
    serve_writes(&project);
    project.observe(
        vec![key_with("golf-jobfeed", "limit", json!(10.0))],
        vec![guardrail(OTHER_FAKE_GUARDRAIL_ID, "cheap-rail", &[])],
        Vec::new(),
    );
    project.write_state(|state| {
        state
            .bind_guardrail(
                &address("cheap"),
                uuid(FAKE_GUARDRAIL_ID),
                Origin::Imported,
                at(0),
            )
            .expect("binding the guardrail that later disappears");
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key");
    });

    let document = project.succeed(&["--json", "apply"]).document();

    assert!(
        project.write_trace().is_empty(),
        "a collision blocks the recreation"
    );
    let missing = action(&document, "guardrails.cheap");
    assert_eq!(missing["kind"], "missing");
    assert_eq!(missing["status"], "reported");
    assert_eq!(
        project
            .read_state()
            .guardrail(&address("cheap"))
            .expect("the binding")
            .id
            .as_str(),
        FAKE_GUARDRAIL_ID,
        "the binding is left exactly as it was"
    );
}

// --- the boundaries --------------------------------------------------------

#[test]
fn a_plan_an_operator_read_is_never_the_plan_that_runs() {
    // The world converges between the plan and the apply. A run that executed
    // the plan it was shown would send a PATCH; this one recomputes under the
    // lock and finds nothing to do.
    let project = Project::new(CONVERGED_CONFIG);
    serve_writes(&project);
    project.observe_sequence(
        vec![
            vec![key_with("golf-jobfeed", "limit", json!(99.0))],
            vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
        ],
        vec![vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])]],
        vec![vec![assignment(
            ASSIGNMENT_ID,
            JOBFEED_HASH,
            FAKE_GUARDRAIL_ID,
        )]],
    );
    project.write_state(|state| {
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
    });

    let planned = project.succeed(&["--json", "plan"]).document();
    assert_eq!(planned["has_changes"], Value::Bool(true));
    assert_eq!(action(&planned, "keys.jobfeed")["kind"], "update");

    let applied = project.succeed(&["--json", "apply"]).document();
    assert_eq!(applied["outcome"], "converged");
    assert!(
        project.write_trace().is_empty(),
        "the stale observation was never executed"
    );
}

#[test]
fn a_failed_write_stops_the_apply_and_says_what_was_and_was_not_verified() {
    let project = Project::new(&format!(
        "{CONFIG}\n[guardrails.spare]\nname = \"spare-rail\"\nlimit_usd = 5\n"
    ));
    serve_writes(&project);
    // The first guardrail is created; the second fails with a 500, which
    // leaves it unknown whether it exists.
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/guardrails"))
            .respond_with(Scripted::new([
                json_response(
                    200,
                    &json!({ "data": guardrail(NEW_RAIL_ID, "cheap-rail", &[]) }),
                ),
                ResponseTemplate::new(500).set_body_json(json!({
                    "error": { "code": 500, "message": "server exploded" }
                })),
            ])),
    );
    project.observe_sequence(
        vec![vec![api_key(JOBFEED_HASH, "golf-jobfeed")]],
        vec![Vec::new(), vec![converged_rail()]],
        vec![Vec::new()],
    );
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key");
    });

    let streams = project.fail(&["--json", "apply"]);
    let document = streams.document();

    assert_eq!(
        project.write_trace(),
        vec![
            "POST /api/v1/guardrails".to_owned(),
            "POST /api/v1/guardrails".to_owned()
        ],
        "the failure stops the run before the key patch and the assignment"
    );
    assert_eq!(streams.diagnostic()["error"]["kind"], "apply_unresolved");

    assert_eq!(document["outcome"], "failed");
    let created = action(&document, "guardrails.cheap");
    assert_eq!(created["status"], "applied");
    assert_eq!(created["verified"], Value::Bool(true));

    let failed = action(&document, "guardrails.spare");
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["verified"], Value::Bool(false));
    assert!(
        failed["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("It may exist all the same")),
        "an ambiguous create says so: {failed}"
    );

    assert_eq!(action(&document, "keys.jobfeed")["status"], "not_attempted");
    assert_eq!(
        action(&document, "keys.jobfeed.guardrail")["status"],
        "not_attempted"
    );

    assert_eq!(
        project
            .read_state()
            .guardrail(&address("cheap"))
            .expect("the identity of the guardrail that was created")
            .id
            .as_str(),
        NEW_RAIL_ID,
        "a partial failure still leaves what was created tracked"
    );
    assert!(
        project.read_state().guardrail(&address("spare")).is_none(),
        "and binds nothing for the one whose outcome is unknown"
    );
}

#[test]
fn an_unfinished_operation_stops_apply_before_any_write() {
    let project = Project::new(CONFIG);
    serve_writes(&project);
    project.observe(
        vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
        Vec::new(),
        Vec::new(),
    );
    project.write_state(|state| {
        state
            .begin_create(
                &address("jobfeed"),
                BeginCreate {
                    operation: OperationId::parse("op-0011").expect("an operation id"),
                    generation: 1,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([11; 32]),
                },
                at(3),
            )
            .expect("starting a create");
    });

    let streams = project.fail(&["--json", "apply"]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "apply_blocked");
    assert_eq!(streams.document()["outcome"], "blocked");
    assert!(project.write_trace().is_empty());
    project.assert_read_only();
}

#[test]
fn a_write_the_plan_holds_back_is_never_reported_as_convergence() {
    // The guardrail is unbound and a remote one carries its name, so binding it
    // is an operator's decision. The key create that depends on it is held back
    // with it, and so is the assignment that depends on both. Nothing runs —
    // and an apply that ran nothing because everything is waiting on an
    // operator has converged nothing.
    let project = Project::new(CONFIG);
    serve_guardrail_create(&project, NEW_RAIL_ID, "cheap-rail");
    serve_writes(&project);
    project.observe(
        Vec::new(),
        vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])],
        Vec::new(),
    );

    let streams = project.succeed(&["--json", "apply"]);
    let document = streams.document();

    assert!(project.write_trace().is_empty());
    assert_eq!(
        document["outcome"], "held_back",
        "nothing was written and nothing is converged: {document}"
    );
    assert_eq!(document["applied"], 0);
    assert_eq!(document["skipped"], 0);
    assert_eq!(document["held_back"], 2);

    let create = action(&document, "keys.jobfeed");
    assert_eq!(create["kind"], "create");
    assert_eq!(create["status"], "held_back");
    assert!(
        create["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("guardrails.cheap")),
        "the held-back write names what blocks it: {create}"
    );
    assert_eq!(
        action(&document, "guardrails.cheap")["kind"],
        "adoption_required",
        "and the thing blocking it is reported, never adopted"
    );
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning array")
            .iter()
            .any(|warning| warning.as_str().is_some_and(|warning| {
                warning.contains("held back") && warning.contains("keys.jobfeed")
            })),
        "the blockers are named in a warning: {document}"
    );

    let human = project.succeed(&["apply"]).out;
    assert!(human.contains("held_back"), "{human}");
    assert!(human.contains("held back:"), "{human}");
    assert!(
        !human.contains("converged:"),
        "an apply with unapplied work must not claim convergence: {human}"
    );
}

#[test]
fn a_replacement_an_unfinished_operation_holds_back_is_not_convergence_either() {
    // A `secured` operation: the key exists and is restricted, and its
    // plaintext is gone, so the planner proposes a replacement — which only
    // `keymaster recover replace` can perform. Apply must report that, not
    // report a converged project.
    let project = Project::new(
        "version = 1\n\n[receivers.vault]\ntype = \"file\"\n\
         path = \"/var/lib/keymaster/vault.key\"\n\n[keys.jobfeed]\n\
         name = \"golf-jobfeed\"\nreceiver = \"vault\"\n",
    );
    serve_writes(&project);
    project.observe(
        vec![
            api_key(JOBFEED_HASH, "golf-jobfeed"),
            api_key(STRAY_HASH, "golf-jobfeed"),
        ],
        Vec::new(),
        Vec::new(),
    );
    project.write_state(|state| {
        let jobfeed = address("jobfeed");
        state
            .bind_key(&jobfeed, hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key that is being replaced");
        state
            .begin_create(
                &jobfeed,
                BeginCreate {
                    operation: OperationId::parse("op-0021").expect("an operation id"),
                    generation: 2,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([21; 32]),
                },
                at(1),
            )
            .expect("starting the replacement");
        state
            .advance_key(
                &jobfeed,
                Transition::Created {
                    hash: hash(STRAY_HASH),
                },
                at(2),
            )
            .expect("recording the create response");
        state
            .advance_key(&jobfeed, Transition::Secured, at(3))
            .expect("recording the verified restrictions");
    });

    let document = project.succeed(&["--json", "apply"]).document();

    assert!(project.write_trace().is_empty());
    assert_eq!(document["outcome"], "held_back");
    assert_eq!(
        document["blocked"],
        Value::Bool(false),
        "`secured` is not an operation of unknown outcome"
    );
    let replace = action(&document, "keys.jobfeed");
    assert_eq!(replace["kind"], "replace");
    assert_eq!(replace["status"], "held_back");
    assert!(
        replace["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("op-0021") && detail.contains("secured")),
        "the held-back replacement names the operation that holds it: {replace}"
    );
}

#[test]
fn a_planned_key_creation_is_skipped_and_says_which_issue_owns_it() {
    let project = Project::new(CONFIG);
    serve_guardrail_create(&project, NEW_RAIL_ID, "cheap-rail");
    serve_writes(&project);
    // Nothing is bound and nothing remote carries the key's name, so the plan
    // proposes creating it — the one thing apply must not do.
    project.observe_sequence(
        vec![Vec::new()],
        vec![Vec::new(), vec![converged_rail()]],
        vec![Vec::new()],
    );

    let streams = project.succeed(&["--json", "apply"]);
    let document = streams.document();

    assert_eq!(
        project.write_trace(),
        vec!["POST /api/v1/guardrails".to_owned()],
        "the guardrail is created; the key is not"
    );
    assert_eq!(document["outcome"], "incomplete");
    let key = action(&document, "keys.jobfeed");
    assert_eq!(key["kind"], "create");
    assert_eq!(key["status"], "skipped");
    assert!(
        key["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("#16")),
        "the skip names the issue that will implement it: {key}"
    );
    assert_eq!(
        action(&document, "keys.jobfeed.guardrail")["status"],
        "not_attempted",
        "and so is the assignment of a key that does not exist"
    );
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("not fully converged"))),
        "an incomplete apply says so: {document}"
    );
    assert!(
        streams.err.is_empty(),
        "under --json a stream carries exactly one document: {}",
        streams.err
    );
}

/// A key whose generation rose: the planner proposes a replacement, which apply
/// cannot make yet.
const REPLACEMENT_CONFIG: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"
limit_usd = 10
reset_interval = "monthly"

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
guardrail = "cheap"
receiver = "vault"
generation = 2
"#;

#[test]
fn a_skipped_replacement_never_reassigns_the_key_it_would_have_replaced() {
    // The assignment planned beside a replacement belongs to the successor
    // key. The predecessor is a live credential assigned to another guardrail;
    // pointing it at the successor's guardrail would change what it may do, on
    // the strength of a key that was never created.
    let project = Project::new(REPLACEMENT_CONFIG);
    serve_writes(&project);
    project.observe(
        vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
        vec![
            guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[]),
            guardrail(OTHER_FAKE_GUARDRAIL_ID, "other-rail", &[]),
        ],
        vec![assignment(
            ASSIGNMENT_ID,
            JOBFEED_HASH,
            OTHER_FAKE_GUARDRAIL_ID,
        )],
    );
    project.write_state(|state| {
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
            .expect("binding the predecessor key");
    });
    let before = fs::read(project.state_path()).expect("the state fixture");

    let document = project.succeed(&["--json", "apply"]).document();

    assert!(
        project.write_trace().is_empty(),
        "a skipped replacement writes nothing at all, its assignment included: {:?}",
        project.write_trace()
    );
    assert_eq!(document["outcome"], "incomplete");

    let key = action(&document, "keys.jobfeed");
    assert_eq!(key["kind"], "replace");
    assert_eq!(key["status"], "skipped");

    let assignment = action(&document, "keys.jobfeed.guardrail");
    assert_eq!(assignment["kind"], "assign");
    assert_eq!(assignment["status"], "not_attempted");
    assert!(
        assignment["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("#16")),
        "the assignment says it is waiting on the same issuance: {assignment}"
    );
    assert!(
        assignment["verified"].is_null(),
        "nothing was attempted, so there is nothing to verify"
    );

    // The second run reports exactly the same thing, and still writes nothing.
    let again = project.succeed(&["--json", "apply"]).document();
    assert_eq!(again["actions"], document["actions"]);
    assert!(project.write_trace().is_empty());
    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "and leaves the predecessor's binding exactly as it was"
    );
}

#[test]
fn another_writer_holding_the_lock_stops_apply_before_it_reads_anything() {
    let project = Project::new(CONFIG);
    serve_writes(&project);
    fs::write(
        project.directory.path().join("state.json.lock"),
        "keymaster pid 1\n",
    )
    .expect("taking the lock");

    let streams = project.fail_silently(&["--json", "apply"]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "state_locked");
    project.server.assert_request_count(0);
}

#[test]
fn the_lock_is_taken_before_the_configuration_is_read() {
    // Ordering, asserted without a race: the configuration here is invalid and
    // the lock is already held. Whichever failure is reported is the check that
    // ran first, and it has to be the lock — a configuration read before the
    // lock leaves a window in which an edit lands between the two, and apply
    // would converge OpenRouter to a file that has already been superseded.
    let project = Project::new("version = 1\n\n[keys.jobfeed]\nname = \"\"\n");
    serve_writes(&project);
    fs::write(
        project.directory.path().join("state.json.lock"),
        "keymaster pid 1\n",
    )
    .expect("taking the lock");

    let streams = project.fail_silently(&["--json", "apply"]);
    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "state_locked",
        "the lock is what apply reaches first"
    );
    project.server.assert_request_count(0);

    // With the lock released, the same run reaches the configuration — which
    // proves the case above failed for the reason it claims, and not because
    // the configuration happened to be readable.
    fs::remove_file(project.directory.path().join("state.json.lock")).expect("releasing the lock");
    let streams = project.fail_silently(&["--json", "apply"]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "config_invalid");
    project.server.assert_request_count(0);
    assert!(
        !project.state_path().exists(),
        "neither run wrote any state"
    );
}

/// A key whose configured budget is above the fixture's, so converging it
/// widens what the credential may spend.
const EXPANDING_CONFIG: &str = r#"
version = 1

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 10
limit_reset = "monthly"
"#;

/// Binds the one key `EXPANDING_CONFIG` describes.
fn bind_expanding_key(project: &Project) {
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key");
    });
}

#[test]
fn an_expanding_write_that_failed_and_took_effect_anyway_is_reported_as_occurred() {
    // The PATCH is refused with a 500 and the budget is raised all the same.
    // A report keyed to the response would say nothing widened; the credential
    // can now spend twice as much, and the read that follows is what knows it.
    let project = Project::new(EXPANDING_CONFIG);
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{JOBFEED_HASH}")))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "error": { "code": 500, "message": "server exploded" }
            }))),
    );
    // Two runs, each reading a snapshot and then a verification snapshot: the
    // budget is low before each apply and high after it.
    project.observe_sequence(
        vec![
            vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
            vec![key_with("golf-jobfeed", "limit", json!(10.0))],
            vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
            vec![key_with("golf-jobfeed", "limit", json!(10.0))],
        ],
        vec![Vec::new()],
        vec![Vec::new()],
    );
    bind_expanding_key(&project);

    let streams = project.fail(&["--json", "apply"]);
    let document = streams.document();

    let update = action(&document, "keys.jobfeed");
    assert_eq!(update["status"], "failed");
    assert_eq!(update["verified"], Value::Bool(true));
    assert_eq!(
        update["privilege_expansion"], "occurred",
        "the read that followed says the budget rose: {update}"
    );
    assert_eq!(document["expansions_occurred"], 1);
    assert_eq!(document["expansions_unconfirmed"], 0);

    let warnings = warnings(&document);
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("widened what a credential may do")),
        "an expansion that happened is named: {warnings:?}"
    );
    assert!(
        !warnings
            .iter()
            .any(|warning| warning.contains("NOT confirmed")),
        "and is not also reported as unconfirmed: {warnings:?}"
    );

    let human = project.fail(&["apply"]).out;
    assert!(human.contains("! privilege expansions (1):"), "{human}");
    assert!(human.contains("(failed, occurred)"), "{human}");
}

#[test]
fn an_expanding_write_the_read_does_not_confirm_is_reported_louder_than_one_that_did() {
    // The PATCH is accepted and the budget is unchanged afterwards. Nothing
    // establishes that the credential was widened, and nothing establishes
    // that it was not — which is the case that deserves the loudest warning,
    // not silence and not a claim.
    let project = Project::new(EXPANDING_CONFIG);
    serve_writes(&project);
    project.observe_sequence(
        vec![
            vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
            vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
        ],
        vec![Vec::new()],
        vec![Vec::new()],
    );
    bind_expanding_key(&project);

    let streams = project.fail(&["--json", "apply"]);
    let document = streams.document();

    let update = action(&document, "keys.jobfeed");
    assert_eq!(update["status"], "applied");
    assert_eq!(update["verified"], Value::Bool(false));
    assert_eq!(
        update["privilege_expansion"], "unconfirmed",
        "an accepted write the read does not confirm is not a fact: {update}"
    );
    assert_eq!(document["expansions_occurred"], 0);
    assert_eq!(document["expansions_unconfirmed"], 1);

    let warnings = warnings(&document);
    assert!(
        warnings.iter().any(|warning| {
            warning.contains("NOT confirmed")
                && warning.contains("may have taken effect")
                && warning.contains("keys.jobfeed")
        }),
        "the unconfirmed expansion is named, loudly: {warnings:?}"
    );
    assert!(
        !warnings
            .iter()
            .any(|warning| warning.contains("widened what a credential may do")),
        "and is never reported as one that occurred: {warnings:?}"
    );

    let human = project.fail(&["apply"]).out;
    assert!(human.contains("(applied, unconfirmed)"), "{human}");
    assert!(human.contains("UNVERIFIED"), "{human}");
}

#[test]
fn an_attempted_write_whose_resource_vanished_is_never_verified() {
    // The PATCH is accepted and the key is gone from the read that follows.
    // "Nothing executable at this address" would call that verified — the
    // planner reports a bound key that is absent as `missing` precisely
    // because it will not act on it — but a resource that is not there
    // confirms nothing, least of all that a budget was raised on it.
    let project = Project::new(EXPANDING_CONFIG);
    serve_writes(&project);
    project.observe_sequence(
        vec![vec![api_key(JOBFEED_HASH, "golf-jobfeed")], Vec::new()],
        vec![Vec::new()],
        vec![Vec::new()],
    );
    bind_expanding_key(&project);

    let streams = project.fail(&["--json", "apply"]);
    let document = streams.document();

    let update = action(&document, "keys.jobfeed");
    assert_eq!(update["status"], "applied");
    assert_eq!(
        update["verified"],
        Value::Bool(false),
        "a key that is not in the snapshot verifies nothing: {update}"
    );
    assert_eq!(
        update["privilege_expansion"], "unconfirmed",
        "and it certainly does not establish that the budget rose: {update}"
    );
    assert_eq!(document["outcome"], "failed");
    assert_eq!(document["unverified"], 1);
    assert_eq!(document["expansions_occurred"], 0);
    assert!(
        warnings(&document)
            .iter()
            .any(|warning| warning.contains("NOT confirmed")),
        "{document}"
    );
}

#[test]
fn a_privilege_expansion_apply_made_is_conspicuous_and_secret_free() {
    let project = Project::new(CONVERGED_CONFIG);
    serve_writes(&project);
    // The remote key is disabled, its budget is lower than the configuration
    // asks for, and someone put a credential in its display name.
    let mut drifted = key_with(SECRET_SENTINEL_KEY, "disabled", json!(true));
    drifted["limit"] = json!(1.0);
    project.observe_sequence(
        vec![vec![drifted], vec![api_key(JOBFEED_HASH, "golf-jobfeed")]],
        vec![vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])]],
        vec![vec![assignment(
            ASSIGNMENT_ID,
            JOBFEED_HASH,
            FAKE_GUARDRAIL_ID,
        )]],
    );
    project.write_state(|state| {
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
    });

    // `succeed` scans both streams and the whole project directory for the
    // sentinel; this proves the name was rewritten rather than simply unread.
    let streams = project.succeed(&["apply"]);
    assert!(streams.out.contains("[redacted]"), "{}", streams.out);
    assert!(
        streams.out.contains("! privilege expansions"),
        "{}",
        streams.out
    );
    assert!(
        streams.err.contains("widened what a credential may do"),
        "{}",
        streams.err
    );

    let document = project.succeed(&["--json", "plan"]).document();
    assert_eq!(document["outcome"], "converged", "the apply converged it");
}
