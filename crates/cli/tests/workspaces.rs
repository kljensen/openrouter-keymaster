//! Workspaces as a managed resource (ADR-0004).
//!
//! The cases below are about the four things a workspace adds that no other
//! resource has: an identity everything inside it is fixed to at creation, a
//! pooled budget written one interval at a time in an order the server accepts,
//! a default guardrail that exists as an identity before it exists as a
//! resource, and a deletion that refuses to take its contents with it.

mod support;

use std::fs;

use openrouter_keymaster_core::state::Origin;
use serde_json::{Value, json};
use support::fixtures::{
    FAKE_DEFAULT_GUARDRAIL_ID, FAKE_GUARDRAIL_ID, FAKE_WORKSPACE_ID, api_key, guardrail, workspace,
    workspace_budgets,
};
use support::http::json_response;
use support::project::{Project, address, at, uuid};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const CLUB: &str = FAKE_WORKSPACE_ID;
const DEFAULT_RAIL: &str = FAKE_DEFAULT_GUARDRAIL_ID;
const JOBFEED_HASH: &str = "hash-jobfeed-1";

/// A club: one workspace with a pooled budget, its default guardrail, and one
/// key placed in it by address.
const PROJECT: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[workspaces.club]
name = "Golf Club"
slug = "golf-club"
budgets = { monthly = 50, lifetime = 500 }
default_guardrail = "house"

[guardrails.house]
name = "house-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
workspace = "club"
"#;

/// Just the workspace, for the cases that are only about one.
const ONLY_WORKSPACE: &str = r#"
version = 1

[workspaces.club]
name = "Golf Club"
slug = "golf-club"
budgets = { monthly = 50, lifetime = 500 }
"#;

/// The one action at `address`, whatever kind it is.
fn action<'a>(document: &'a Value, address: &str) -> &'a Value {
    document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == address)
        .unwrap_or_else(|| panic!("no action at {address} in {document}"))
}

/// The budgets a workspace has, as the API reports them.
fn budgets(intervals: &[(&str, f64)]) -> Value {
    workspace_budgets(intervals, false)
}

/// A project whose workspace is already bound and present. The caller mounts
/// whatever budget listing the case is about.
fn bound(config: &str) -> Project {
    let project = Project::new(config);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_workspaces(vec![workspace(CLUB, "Golf Club", "golf-club")]);
    project.write_state(bind_club);
    project
}

/// Binds the club workspace, and nothing else.
fn bind_club(state: &mut openrouter_keymaster_core::state::State) {
    state
        .bind_workspace(
            &address("club"),
            uuid(CLUB),
            Some(uuid(DEFAULT_RAIL)),
            Origin::Imported,
            at(0),
        )
        .expect("binding the workspace");
}

/// Binds the club workspace and the guardrail block that is its default, as
/// `import workspace` and a created workspace both do.
fn bind_club_and_default(state: &mut openrouter_keymaster_core::state::State) {
    bind_club(state);
    state
        .bind_guardrail(
            &address("house"),
            uuid(DEFAULT_RAIL),
            Origin::Imported,
            at(0),
        )
        .expect("binding the default guardrail");
}

// --- create, update, orphan -------------------------------------------------

#[test]
fn a_created_workspace_records_its_identity_and_its_default_guardrail_before_anything_else() {
    let project = Project::new(ONLY_WORKSPACE);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_workspace_sequence(vec![
        Vec::new(),
        vec![workspace(CLUB, "Golf Club", "golf-club")],
    ]);
    project.observe_budgets(CLUB, &budgets(&[("monthly", 50.0), ("lifetime", 500.0)]));
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/workspaces"))
            .respond_with(json_response(
                200,
                &json!({ "data": workspace(CLUB, "Golf Club", "golf-club") }),
            )),
    );
    for interval in ["monthly", "lifetime"] {
        project.server.mount(
            Mock::given(method("PUT"))
                .and(path(format!(
                    "/api/v1/workspaces/{CLUB}/budgets/{interval}"
                )))
                .respond_with(json_response(200, &json!({}))),
        );
    }

    let document = project.succeed(&["--json", "apply"]).document();
    assert_eq!(document["outcome"], "applied", "{document}");

    assert_eq!(
        project.write_trace(),
        vec![
            "POST /api/v1/workspaces".to_owned(),
            format!("PUT /api/v1/workspaces/{CLUB}/budgets/lifetime"),
            format!("PUT /api/v1/workspaces/{CLUB}/budgets/monthly"),
        ],
        "the create comes first, then the budgets, widest interval first"
    );

    let state = project.read_state();
    let binding = state
        .workspace(&address("club"))
        .expect("the workspace binding");
    assert_eq!(binding.id, uuid(CLUB));
    assert_eq!(binding.origin, Origin::Created);
    assert_eq!(
        binding.default_guardrail_id,
        Some(uuid(DEFAULT_RAIL)),
        "the identity the workspace names is the only handle on its default guardrail"
    );
}

#[test]
fn a_drifted_workspace_is_patched_and_only_the_intervals_that_differ_are_written() {
    let project = bound(ONLY_WORKSPACE);
    // The second read shows the world after the write, so the run converges.
    project.observe_budget_sequence(
        CLUB,
        vec![
            budgets(&[("monthly", 50.0), ("lifetime", 100.0)]),
            budgets(&[("monthly", 50.0), ("lifetime", 500.0)]),
        ],
    );
    project.server.mount(
        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/workspaces/{CLUB}/budgets/lifetime")))
            .respond_with(json_response(200, &json!({}))),
    );

    let document = project.succeed(&["--json", "apply"]).document();
    assert_eq!(document["outcome"], "applied", "{document}");
    assert_eq!(
        project.write_trace(),
        vec![format!("PUT /api/v1/workspaces/{CLUB}/budgets/lifetime")],
        "the monthly budget already matches, and nothing else about the workspace differs, so \
         there is no `PATCH` either"
    );
}

#[test]
fn removing_the_block_orphans_the_binding_and_deletes_nothing() {
    let project = bound("version = 1\n");
    project.observe_budgets(CLUB, &budgets(&[]));
    let before = fs::read(project.state_path()).expect("the state fixture");

    let document = project.succeed(&["--json", "plan"]).document();
    let workspace = action(&document, "workspaces.club");
    assert_eq!(workspace["kind"], "orphaned_binding", "{document}");
    assert_eq!(
        workspace["reasons"][0]["reason"], "removed_from_configuration",
        "{document}"
    );

    project.assert_read_only();
    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "a plan writes no state"
    );
}

// --- budget ordering --------------------------------------------------------

#[test]
fn budget_increases_are_written_widest_first_and_decreases_narrowest_first() {
    // OpenRouter checks lifetime > monthly > weekly > daily on every write, so
    // the order is what keeps every intermediate state legal.
    for (from, to, expected) in [
        (
            vec![("monthly", 20.0), ("lifetime", 100.0)],
            vec![("monthly", 50.0), ("lifetime", 500.0)],
            vec!["lifetime", "monthly"],
        ),
        (
            vec![("monthly", 80.0), ("lifetime", 900.0)],
            vec![("monthly", 50.0), ("lifetime", 500.0)],
            vec!["monthly", "lifetime"],
        ),
    ] {
        let project = bound(ONLY_WORKSPACE);
        project.observe_budget_sequence(CLUB, vec![budgets(&from), budgets(&to)]);
        for interval in ["monthly", "lifetime"] {
            project.server.mount(
                Mock::given(method("PUT"))
                    .and(path(format!(
                        "/api/v1/workspaces/{CLUB}/budgets/{interval}"
                    )))
                    .respond_with(json_response(200, &json!({}))),
            );
        }

        project.succeed(&["--json", "apply"]);
        assert_eq!(
            project.write_trace(),
            expected
                .iter()
                .map(|interval| format!("PUT /api/v1/workspaces/{CLUB}/budgets/{interval}"))
                .collect::<Vec<_>>(),
            "moving from {from:?} to {to:?}"
        );
    }
}

#[test]
fn an_interval_the_table_drops_is_deleted_before_anything_is_raised() {
    let project = bound(ONLY_WORKSPACE);
    project.observe_budget_sequence(
        CLUB,
        vec![
            budgets(&[("daily", 5.0), ("monthly", 20.0)]),
            budgets(&[("monthly", 50.0), ("lifetime", 500.0)]),
        ],
    );
    project.server.mount(
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/workspaces/{CLUB}/budgets/daily")))
            .respond_with(json_response(200, &json!({ "deleted": true }))),
    );
    for interval in ["monthly", "lifetime"] {
        project.server.mount(
            Mock::given(method("PUT"))
                .and(path(format!(
                    "/api/v1/workspaces/{CLUB}/budgets/{interval}"
                )))
                .respond_with(json_response(200, &json!({}))),
        );
    }

    project.succeed(&["--json", "apply"]);
    assert_eq!(
        project.write_trace(),
        vec![
            format!("DELETE /api/v1/workspaces/{CLUB}/budgets/daily"),
            format!("PUT /api/v1/workspaces/{CLUB}/budgets/lifetime"),
            format!("PUT /api/v1/workspaces/{CLUB}/budgets/monthly"),
        ],
        "deletes first, then increases from the widest interval to the narrowest"
    );
}

// --- a budget the account's plan refuses ------------------------------------

#[test]
fn a_refused_budget_interval_fails_alone_and_holds_back_everything_it_would_have_capped() {
    let project = Project::new(PROJECT);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_workspaces(vec![workspace(CLUB, "Golf Club", "golf-club")]);
    project.observe_budgets(CLUB, &budgets(&[]));
    project.write_state(bind_club_and_default);
    project.server.mount(
        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/workspaces/{CLUB}/budgets/lifetime")))
            .respond_with(json_response(200, &json!({}))),
    );
    project.server.mount(
        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/workspaces/{CLUB}/budgets/monthly")))
            .respond_with(json_response(
                403,
                &json!({ "error": { "code": 403, "message": "workspace budgets require an \
                                                             Enterprise plan" } }),
            )),
    );
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/guardrails/{DEFAULT_RAIL}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let document = project.fail(&["--json", "apply"]).document();

    let workspace = action(&document, "workspaces.club");
    assert_eq!(workspace["status"], "failed", "{document}");
    let detail = workspace["detail"].as_str().expect("a detail");
    assert!(
        detail.contains("monthly") && detail.contains("lifetime"),
        "the refusal names the interval, and so does what did land: {detail}"
    );

    // Independent work continued: both budget writes were attempted, and the
    // guardrail — a routine write — was made.
    let writes = project.write_trace();
    assert!(
        writes.contains(&format!("PUT /api/v1/workspaces/{CLUB}/budgets/monthly")),
        "{writes:?}"
    );
    assert!(
        writes.contains(&format!("PUT /api/v1/workspaces/{CLUB}/budgets/lifetime")),
        "{writes:?}"
    );
    assert!(
        writes.contains(&format!("PATCH /api/v1/guardrails/{DEFAULT_RAIL}")),
        "routine writes proceed: {writes:?}"
    );

    // And nothing was issued under a cap that is not in force.
    let key = action(&document, "keys.jobfeed");
    assert_eq!(key["status"], "held_back", "{document}");
    assert!(
        key["reasons"]
            .as_array()
            .expect("a reason list")
            .iter()
            .any(|reason| reason["reason"] == "budget_not_converged"),
        "{document}"
    );
    assert!(
        !writes
            .iter()
            .any(|write| write.contains("POST /api/v1/keys")),
        "no key is created in a workspace whose budget was refused: {writes:?}"
    );
}

// --- the default guardrail --------------------------------------------------

#[test]
fn a_default_guardrail_is_materialized_by_patching_the_identity_its_workspace_names() {
    let project = Project::new(
        "version = 1\n\n[workspaces.club]\nname = \"Golf Club\"\nslug = \"golf-club\"\n\
         default_guardrail = \"house\"\n\n[guardrails.house]\nname = \"house-rail\"\n",
    );
    project.observe_sequence(
        vec![Vec::new()],
        // Absent from the listing until its configuration is first written.
        vec![
            Vec::new(),
            Vec::new(),
            vec![guardrail(DEFAULT_RAIL, "house-rail", &[])],
        ],
        vec![Vec::new()],
    );
    project.observe_workspaces(vec![workspace(CLUB, "Golf Club", "golf-club")]);
    project.write_state(bind_club_and_default);
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/guardrails/{DEFAULT_RAIL}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let planned = project.succeed(&["--json", "plan"]).document();
    let create = action(&planned, "guardrails.house");
    assert_eq!(
        create["kind"], "create",
        "bound but absent is `missing` everywhere except here: {planned}"
    );
    assert_eq!(
        create["identity"],
        format!("guardrail {DEFAULT_RAIL}"),
        "the create already knows the identity it will write to: {planned}"
    );
    assert!(
        create["reasons"]
            .as_array()
            .expect("a reason list")
            .iter()
            .any(|reason| reason["reason"] == "default_guardrail_unmaterialized"),
        "{planned}"
    );

    let applied = project.succeed(&["--json", "apply"]).document();
    assert_eq!(applied["outcome"], "applied", "{applied}");
    assert_eq!(
        project.write_trace(),
        vec![format!("PATCH /api/v1/guardrails/{DEFAULT_RAIL}")],
        "a default guardrail is never `POST`ed"
    );
}

// --- import -----------------------------------------------------------------

#[test]
fn importing_a_workspace_records_its_default_guardrail_and_binds_the_block() {
    let project = Project::new(PROJECT);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/workspaces/{CLUB}")))
            .respond_with(json_response(
                200,
                &json!({ "data": workspace(CLUB, "Golf Club", "golf-club") }),
            )),
    );
    project.observe_budgets(CLUB, &budgets(&[("monthly", 20.0)]));
    project.write_state(|_| {});

    let document = project
        .succeed(&["--json", "import", "workspace", "club", "--id", CLUB])
        .document();
    assert_eq!(document["resource"], "workspace", "{document}");
    assert_eq!(document["bound"], true, "{document}");
    assert_eq!(document["origin"], "imported", "{document}");
    let changed: Vec<&str> = document["changes"]
        .as_array()
        .expect("a change list")
        .iter()
        .map(|change| change["field"].as_str().expect("a field name"))
        .collect();
    assert_eq!(
        changed,
        vec!["budgets.monthly", "budgets.lifetime"],
        "a later apply reconciles the budgets: {document}"
    );

    let state = project.read_state();
    let binding = state
        .workspace(&address("club"))
        .expect("the workspace binding");
    assert_eq!(binding.default_guardrail_id, Some(uuid(DEFAULT_RAIL)));
    assert_eq!(
        state
            .guardrail(&address("house"))
            .expect("the default guardrail binding")
            .id,
        uuid(DEFAULT_RAIL),
        "the default guardrail can never be imported by name, so importing the workspace is what \
         binds it"
    );

    project.assert_read_only();
}

// --- placement --------------------------------------------------------------

#[test]
fn a_key_naming_an_unbound_workspace_is_held_back_until_the_binding_exists() {
    let project = Project::new(PROJECT);
    project.observe(Vec::new(), Vec::new(), Vec::new());

    let document = project.succeed(&["--json", "plan"]).document();
    assert_eq!(action(&document, "workspaces.club")["kind"], "create");

    let key = action(&document, "keys.jobfeed");
    assert_eq!(key["kind"], "create", "{document}");
    assert_eq!(key["executable"], false, "{document}");
    assert!(
        key["reasons"]
            .as_array()
            .expect("a reason list")
            .iter()
            .any(|reason| reason["dependency"] == "workspaces.club"),
        "the key says which workspace it waits on: {document}"
    );
}

#[test]
fn a_scoped_run_refuses_a_workspace_block_it_does_not_already_own() {
    let project = Project::new(ONLY_WORKSPACE);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.write_state(|_| {});

    // Unbound: a scoped run cannot create its own workspace, because the UUID a
    // create returns could never be the one it was scoped to.
    let diagnostic = project
        .fail(&["--json", "--workspace", CLUB, "plan"])
        .diagnostic();
    assert_eq!(
        diagnostic["error"]["kind"], "config_invalid",
        "{diagnostic}"
    );
    let message = diagnostic["error"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(message.contains("workspaces.club"), "{message}");
    assert!(
        message.contains("import workspace club"),
        "the refusal names the way out: {message}"
    );

    // Bound to the scope, it is this run's own workspace and nothing objects.
    let owned = bound(ONLY_WORKSPACE);
    owned.observe_budgets(CLUB, &budgets(&[("monthly", 50.0), ("lifetime", 500.0)]));
    owned.succeed(&["--json", "--workspace", CLUB, "plan"]);
}

// --- delete -----------------------------------------------------------------

#[test]
fn deleting_a_workspace_is_refused_while_it_still_holds_anything() {
    let project = Project::new(PROJECT);
    project.observe(
        vec![api_key(JOBFEED_HASH, "someone-elses-key")],
        vec![guardrail(FAKE_GUARDRAIL_ID, "someone-elses-rail", &[])],
        Vec::new(),
    );
    project.write_state(bind_club);
    let before = fs::read(project.state_path()).expect("the state fixture");

    let diagnostic = project
        .fail_silently(&["--json", "delete", "workspace", "--id", CLUB])
        .diagnostic();

    assert_eq!(
        diagnostic["error"]["kind"], "delete_workspace_inhabited",
        "{diagnostic}"
    );
    let message = diagnostic["error"]["message"].as_str().expect("a message");
    assert!(message.contains(JOBFEED_HASH), "{message}");
    assert!(message.contains(FAKE_GUARDRAIL_ID), "{message}");

    assert!(
        project.write_trace().is_empty(),
        "nothing is deleted while the workspace holds anything: {:?}",
        project.write_trace()
    );
    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "a refused deletion leaves the state file byte for byte as it was"
    );
}

#[test]
fn deleting_a_workspace_releases_it_and_the_default_guardrail_that_cannot_outlive_it() {
    let project = Project::new(PROJECT);
    // The only thing in the workspace is its own default guardrail, which is
    // part of the workspace rather than an occupant of it.
    project.observe(
        Vec::new(),
        vec![guardrail(DEFAULT_RAIL, "house-rail", &[])],
        Vec::new(),
    );
    project.server.mount(
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/workspaces/{CLUB}")))
            .respond_with(json_response(200, &json!({ "deleted": true }))),
    );
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/workspaces/{CLUB}")))
            .respond_with(json_response(
                404,
                &json!({ "error": { "code": 404, "message": "not found" } }),
            )),
    );
    project.write_state(bind_club_and_default);

    let document = project
        .succeed(&["--json", "delete", "workspace", "--id", CLUB])
        .document();
    assert_eq!(document["outcome"], "deleted", "{document}");
    assert_eq!(document["tracked"], false, "{document}");
    assert_eq!(
        document["released"],
        json!([
            format!("workspaces.club ({CLUB})"),
            format!("guardrails.house ({DEFAULT_RAIL})"),
        ]),
        "{document}"
    );

    let state = project.read_state();
    assert!(state.workspace(&address("club")).is_none());
    assert!(
        state.guardrail(&address("house")).is_none(),
        "the default guardrail cannot outlive its workspace, so its binding goes with it"
    );
}

#[test]
fn deleting_a_workspace_no_local_address_tracks_is_refused() {
    let project = Project::new(PROJECT);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.write_state(|_| {});

    let diagnostic = project
        .fail_silently(&["--json", "delete", "workspace", "--id", CLUB])
        .diagnostic();
    assert_eq!(
        diagnostic["error"]["kind"], "delete_workspace_untracked",
        "{diagnostic}"
    );
    assert!(
        project.server.requests().is_empty(),
        "a workspace Keymaster does not own is not even read: {:?}",
        project.request_trace()
    );
}

// --- status -----------------------------------------------------------------

#[test]
fn status_lists_workspaces_with_the_budgets_openrouter_has_in_force() {
    let project = bound(ONLY_WORKSPACE);
    project.observe_budgets(CLUB, &budgets(&[("monthly", 50.0), ("lifetime", 500.0)]));

    let document = project.succeed(&["--json", "status"]).document();
    let listed = document["workspaces"].as_array().expect("a list");
    assert_eq!(listed.len(), 1, "{document}");
    assert_eq!(listed[0]["address"], "workspaces.club");
    assert_eq!(listed[0]["id"], CLUB);
    assert_eq!(listed[0]["present_remotely"], true);
    assert_eq!(listed[0]["default_guardrail_id"], DEFAULT_RAIL);
    assert_eq!(
        listed[0]["budgets"],
        json!({ "monthly": 50.0, "lifetime": 500.0 }),
        "{document}"
    );

    let human = project.succeed(&["status"]);
    assert!(
        human
            .out
            .contains("budgets: lifetime 500.000000, monthly 50.000000"),
        "{}",
        human.out
    );
}

#[test]
fn a_workspace_no_local_address_owns_is_reported_and_never_changed() {
    let project = Project::new("version = 1\n");
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_workspaces(vec![workspace(CLUB, "Default", "default")]);

    let document = project.succeed(&["--json", "plan"]).document();
    let unmanaged = action(&document, &format!("remote workspace {CLUB}"));
    assert_eq!(unmanaged["kind"], "unmanaged", "{document}");
    assert_eq!(unmanaged["reasons"][0]["reason"], "not_configured");
    project.assert_read_only();
}

#[test]
fn a_workspace_that_is_bound_but_gone_is_never_recreated_over_a_name_that_is_taken() {
    let project = Project::new(ONLY_WORKSPACE);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    // A different workspace answers to the configured name.
    project.observe_workspaces(vec![workspace(
        "00000000-0000-4000-8000-00000000000f",
        "Golf Club",
        "golf-club",
    )]);
    project.write_state(bind_club);

    let document = project.succeed(&["--json", "plan"]).document();
    let workspace = action(&document, "workspaces.club");
    assert_eq!(workspace["kind"], "missing", "{document}");
    assert!(
        workspace["reasons"]
            .as_array()
            .expect("a reason list")
            .iter()
            .any(|reason| reason["reason"] == "name_collision"),
        "{document}"
    );
    project.assert_read_only();
}

#[test]
fn a_changed_byok_setting_is_carried_by_rewriting_a_budget_that_already_matches() {
    // `include_byok_in_budgets` is workspace-wide and only a budget `PUT` can
    // write it, so a configuration that changed nothing else would otherwise
    // drift forever with no request able to fix it.
    let project = Project::new(
        "version = 1\n\n[workspaces.club]\nname = \"Golf Club\"\nslug = \"golf-club\"\n\
         budgets = { monthly = 50 }\ninclude_byok_in_budgets = true\n",
    );
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_workspaces(vec![workspace(CLUB, "Golf Club", "golf-club")]);
    project.observe_budget_sequence(
        CLUB,
        vec![
            workspace_budgets(&[("monthly", 50.0)], false),
            workspace_budgets(&[("monthly", 50.0)], true),
        ],
    );
    project.write_state(bind_club);
    project.server.mount(
        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/workspaces/{CLUB}/budgets/monthly")))
            .respond_with(json_response(200, &json!({}))),
    );

    project.succeed(&["--json", "apply"]);
    assert_eq!(
        project.write_trace(),
        vec![format!("PUT /api/v1/workspaces/{CLUB}/budgets/monthly")],
        "the limit it carries is the one already in force"
    );
}

#[test]
fn a_bound_workspace_that_vanished_is_reported_and_never_recreated() {
    let project = Project::new(ONLY_WORKSPACE);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.write_state(bind_club);

    let planned = project.succeed(&["--json", "plan"]).document();
    let workspace = action(&planned, "workspaces.club");
    assert_eq!(
        workspace["kind"], "missing",
        "a new workspace would have a new UUID, so everything the old one held would be beyond \
         reach: {planned}"
    );
    assert_eq!(
        workspace["identity"],
        format!("workspace {CLUB}"),
        "{planned}"
    );

    // `held_back`, not a failure: nothing went wrong, and what is left needs an
    // operator rather than another run.
    let applied = project.succeed(&["--json", "apply"]).document();
    assert_eq!(applied["outcome"], "held_back", "{applied}");
    assert_eq!(applied["applied"], 0, "{applied}");
    assert!(
        project.write_trace().is_empty(),
        "a workspace that is bound and absent is reported, never recreated: {:?}",
        project.write_trace()
    );
}

#[test]
fn a_default_guardrail_added_after_the_workspace_was_imported_takes_the_identity_it_names() {
    // The workspace binding already carries `default_guardrail_id`; the
    // guardrail address does not exist in state at all.
    let project = Project::new(
        "version = 1\n\n[workspaces.club]\nname = \"Golf Club\"\nslug = \"golf-club\"\n\
         default_guardrail = \"house\"\n\n[guardrails.house]\nname = \"house-rail\"\n",
    );
    project.observe_sequence(
        vec![Vec::new()],
        vec![
            vec![guardrail(DEFAULT_RAIL, "named-by-hand", &[])],
            vec![guardrail(DEFAULT_RAIL, "named-by-hand", &[])],
            vec![guardrail(DEFAULT_RAIL, "house-rail", &[])],
        ],
        vec![Vec::new()],
    );
    project.observe_workspaces(vec![workspace(CLUB, "Golf Club", "golf-club")]);
    project.write_state(bind_club);
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/guardrails/{DEFAULT_RAIL}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let planned = project.succeed(&["--json", "plan"]).document();
    let update = action(&planned, "guardrails.house");
    assert_eq!(update["kind"], "update", "{planned}");
    assert_eq!(
        update["identity"],
        format!("guardrail {DEFAULT_RAIL}"),
        "an unbound address a workspace names as its default is bound in effect: {planned}"
    );

    let applied = project.succeed(&["--json", "apply"]).document();
    assert_eq!(applied["outcome"], "applied", "{applied}");
    assert_eq!(
        project.write_trace(),
        vec![format!("PATCH /api/v1/guardrails/{DEFAULT_RAIL}")],
        "no second guardrail is created under the same name"
    );
    assert_eq!(
        project
            .read_state()
            .guardrail(&address("house"))
            .expect("the binding this run recorded")
            .id,
        uuid(DEFAULT_RAIL),
        "and the run writes the binding down"
    );
}

#[test]
fn a_default_guardrail_address_that_owns_another_guardrail_is_held_back_naming_both() {
    let project = Project::new(
        "version = 1\n\n[workspaces.club]\nname = \"Golf Club\"\nslug = \"golf-club\"\n\
         default_guardrail = \"house\"\n\n[guardrails.house]\nname = \"house-rail\"\n",
    );
    project.observe(
        Vec::new(),
        vec![guardrail(FAKE_GUARDRAIL_ID, "some-other-rail", &[])],
        Vec::new(),
    );
    project.observe_workspaces(vec![workspace(CLUB, "Golf Club", "golf-club")]);
    project.write_state(|state| {
        bind_club(state);
        state
            .bind_guardrail(
                &address("house"),
                uuid(FAKE_GUARDRAIL_ID),
                Origin::Imported,
                at(0),
            )
            .expect("binding an ordinary guardrail at the address");
    });

    let planned = project.succeed(&["--json", "plan"]).document();
    let conflict = action(&planned, "guardrails.house");
    assert_eq!(conflict["executable"], false, "{planned}");
    let reason = conflict["reasons"]
        .as_array()
        .expect("a reason list")
        .iter()
        .find(|reason| reason["reason"] == "default_guardrail_conflict")
        .unwrap_or_else(|| panic!("no conflict reason in {planned}"));
    assert_eq!(reason["bound"], FAKE_GUARDRAIL_ID);
    assert_eq!(reason["expected"], DEFAULT_RAIL);

    let applied = project.succeed(&["--json", "apply"]).document();
    assert_eq!(applied["outcome"], "held_back", "{applied}");
    assert!(
        project.write_trace().is_empty(),
        "neither identity is safe to write: {:?}",
        project.write_trace()
    );
}

#[test]
fn a_budget_write_that_never_got_an_answer_is_unverified_rather_than_refused() {
    // Only a well-formed 4xx says the server saw the write and declined it. A
    // 503 leaves it unknown whether the cap is in force.
    let project = Project::new(ONLY_WORKSPACE);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_workspaces(vec![workspace(CLUB, "Golf Club", "golf-club")]);
    project.observe_budgets(CLUB, &budgets(&[]));
    project.write_state(bind_club);
    project.server.mount(
        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/workspaces/{CLUB}/budgets/lifetime")))
            .respond_with(json_response(200, &json!({}))),
    );
    project.server.mount(
        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/workspaces/{CLUB}/budgets/monthly")))
            .respond_with(json_response(
                503,
                &json!({ "error": { "code": 503, "message": "service unavailable" } }),
            )),
    );

    let document = project.fail(&["--json", "apply"]).document();
    let action = action(&document, "workspaces.club");
    assert_eq!(action["status"], "failed", "{document}");
    assert_eq!(
        action["verified"], false,
        "the read that follows is what settles it: {document}"
    );
    let detail = action["detail"].as_str().expect("a detail");
    assert!(
        detail.contains("no answer that settles anything") && detail.contains("monthly"),
        "an ambiguous write is never reported as a refusal: {detail}"
    );
    assert!(
        !detail.contains("OpenRouter refused"),
        "nothing here says the server declined anything: {detail}"
    );
    assert_eq!(document["unverified"], 1, "{document}");
}

#[test]
fn importing_a_guardrail_from_another_workspace_binds_nothing() {
    // A guardrail's workspace is fixed when it is created and a guardrail is
    // never replaced, so binding one that sits elsewhere would record a
    // difference no apply could converge.
    let project = Project::new(PROJECT);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_workspaces(vec![workspace(CLUB, "Golf Club", "golf-club")]);
    project.observe_budgets(CLUB, &budgets(&[("monthly", 50.0), ("lifetime", 500.0)]));
    let mut elsewhere = guardrail(FAKE_GUARDRAIL_ID, "house-rail", &[]);
    elsewhere["workspace_id"] = json!("00000000-0000-4000-8000-00000000000e");
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}")))
            .respond_with(json_response(200, &json!({ "data": elsewhere }))),
    );
    project.write_state(bind_club);
    let before = fs::read(project.state_path()).expect("the state fixture");

    let diagnostic = project
        .fail_silently(&[
            "--json",
            "import",
            "guardrail",
            "house",
            "--id",
            FAKE_GUARDRAIL_ID,
        ])
        .diagnostic();

    assert_eq!(
        diagnostic["error"]["kind"], "import_workspace_mismatch",
        "{diagnostic}"
    );
    let message = diagnostic["error"]["message"].as_str().expect("a message");
    assert!(message.contains(CLUB), "{message}");
    assert!(
        message.contains("00000000-0000-4000-8000-00000000000e"),
        "{message}"
    );
    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "a refused import leaves the state file byte for byte as it was"
    );
}

#[test]
fn forgetting_a_workspace_releases_it_and_its_default_guardrail_and_calls_nothing() {
    let project = Project::new(PROJECT);
    project.write_state(bind_club_and_default);

    let document = project
        .succeed(&["--json", "state", "forget", "workspaces.club"])
        .document();
    assert_eq!(document["resource"], "workspace", "{document}");
    assert_eq!(document["forgotten"], true, "{document}");
    let released: Vec<&str> = document["released"]
        .as_array()
        .expect("a released list")
        .iter()
        .map(|entry| entry["identity"].as_str().expect("an identity"))
        .collect();
    assert_eq!(
        released,
        vec![CLUB, DEFAULT_RAIL],
        "the default guardrail cannot outlive its workspace: {document}"
    );
    assert!(
        document["summary"]
            .as_str()
            .expect("a summary")
            .contains("no API call"),
        "{document}"
    );

    let state = project.read_state();
    assert!(state.workspace(&address("club")).is_none());
    assert!(state.guardrail(&address("house")).is_none());
    assert!(
        project.server.requests().is_empty(),
        "forget makes no request at all: {:?}",
        project.request_trace()
    );

    // Repeating it is a clean no-op.
    let again = project
        .succeed(&["--json", "state", "forget", "workspaces.club"])
        .document();
    assert_eq!(again["forgotten"], false, "{again}");
}

#[test]
fn a_bare_address_bound_as_a_workspace_and_a_guardrail_is_refused() {
    let project = Project::new(PROJECT);
    project.write_state(|state| {
        bind_club(state);
        state
            .bind_guardrail(
                &address("club"),
                uuid(FAKE_GUARDRAIL_ID),
                Origin::Imported,
                at(0),
            )
            .expect("binding a guardrail at the same name");
    });

    let diagnostic = project
        .fail_silently(&["--json", "state", "forget", "club"])
        .diagnostic();
    assert_eq!(
        diagnostic["error"]["kind"], "forget_ambiguous",
        "{diagnostic}"
    );
    let message = diagnostic["error"]["message"].as_str().expect("a message");
    assert!(message.contains("workspaces.club"), "{message}");
    assert!(message.contains("guardrails.club"), "{message}");

    // Qualified, it is unambiguous.
    project.succeed(&["--json", "state", "forget", "workspaces.club"]);
}

#[test]
fn a_scoped_run_never_patches_a_guardrail_that_lives_in_another_workspace() {
    // The block names no workspace, so the scope is what places it — and a
    // scoped run must not reach into a workspace it was told to stay out of,
    // however much the guardrail has drifted.
    let project = Project::new("version = 1\n\n[guardrails.house]\nname = \"renamed-rail\"\n");
    let mut elsewhere = guardrail(FAKE_GUARDRAIL_ID, "house-rail", &[]);
    elsewhere["workspace_id"] = json!("00000000-0000-4000-8000-00000000000e");
    project.observe(Vec::new(), vec![elsewhere], Vec::new());
    project.write_state(|state| {
        state
            .bind_guardrail(
                &address("house"),
                uuid(FAKE_GUARDRAIL_ID),
                Origin::Imported,
                at(0),
            )
            .expect("binding the guardrail");
    });

    // Unscoped, the block names no workspace at all, so nothing places it and
    // the rename is an ordinary update.
    let unscoped = project.succeed(&["--json", "plan"]).document();
    assert_eq!(action(&unscoped, "guardrails.house")["kind"], "update");

    let scoped = project
        .succeed(&["--json", "--workspace", CLUB, "plan"])
        .document();
    let held = action(&scoped, "guardrails.house");
    assert_eq!(held["executable"], false, "{scoped}");
    let reason = held["reasons"]
        .as_array()
        .expect("a reason list")
        .iter()
        .find(|reason| reason["reason"] == "workspace_fixed_at_creation")
        .unwrap_or_else(|| panic!("no placement reason in {scoped}"));
    assert_eq!(reason["observed"], "00000000-0000-4000-8000-00000000000e");
    assert_eq!(reason["desired"], CLUB);

    let applied = project
        .succeed(&["--json", "--workspace", CLUB, "apply"])
        .document();
    assert_eq!(applied["outcome"], "held_back", "{applied}");
    assert!(
        project.write_trace().is_empty(),
        "a guardrail's workspace is fixed at creation, and this run may not touch that one: {:?}",
        project.write_trace()
    );
}

#[test]
fn a_workspace_binding_that_never_learned_its_default_guardrail_learns_it_from_the_listing() {
    // `POST /workspaces` is documented to return `default_guardrail_id`. A
    // response that omitted it would leave the only handle on that guardrail
    // unrecorded, and the guardrail held back for good.
    let project = Project::new(
        "version = 1\n\n[workspaces.club]\nname = \"Golf Club\"\nslug = \"golf-club\"\n\
         default_guardrail = \"house\"\n\n[guardrails.house]\nname = \"house-rail\"\n",
    );
    let mut without = workspace(CLUB, "Golf Club", "golf-club");
    without["default_guardrail_id"] = Value::Null;
    // Four reads of each listing: each run plans from one and verifies with the
    // next. The workspace does not exist until this run creates it, and the
    // guardrail not until the second run materializes it.
    project.observe_sequence(
        vec![Vec::new()],
        vec![
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![guardrail(DEFAULT_RAIL, "house-rail", &[])],
        ],
        vec![Vec::new()],
    );
    project.observe_workspace_sequence(vec![
        Vec::new(),
        vec![workspace(CLUB, "Golf Club", "golf-club")],
    ]);
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/workspaces"))
            .respond_with(json_response(200, &json!({ "data": without }))),
    );
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/guardrails/{DEFAULT_RAIL}")))
            .respond_with(json_response(200, &json!({}))),
    );

    // The create records what the response carried, which is no identity, so
    // this run holds the guardrail back.
    let created = project.succeed(&["--json", "apply"]).document();
    assert_eq!(created["outcome"], "held_back", "{created}");
    assert!(
        project
            .read_state()
            .workspace(&address("club"))
            .expect("the workspace binding")
            .default_guardrail_id
            .is_none(),
        "the create response is the only thing that run had to go on"
    );

    // The next run reads the identity off the workspace listing, records it,
    // and materializes the guardrail.
    let streams = project.succeed(&["--json", "apply"]);
    let document = streams.document();
    assert_eq!(document["outcome"], "applied", "{document}");
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning list")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("default guardrail identity"))),
        "the run says what it recorded: {document}"
    );

    let state = project.read_state();
    assert_eq!(
        state
            .workspace(&address("club"))
            .expect("the workspace binding")
            .default_guardrail_id,
        Some(uuid(DEFAULT_RAIL)),
    );
    assert_eq!(
        state
            .guardrail(&address("house"))
            .expect("the default guardrail binding")
            .id,
        uuid(DEFAULT_RAIL),
    );
    assert!(
        project
            .write_trace()
            .contains(&format!("PATCH /api/v1/guardrails/{DEFAULT_RAIL}")),
        "and the guardrail is materialized rather than held back for good: {:?}",
        project.write_trace()
    );
}
