//! The workspace scope: what `--workspace` guards, filters, and leaves alone.
//!
//! One question runs through every case (ADR-0004, item 5): the scope is a
//! guard on *placement* and a filter on *noise*, and nothing else. So the cases
//! below assert both halves — what a scoped run stops reporting and stops
//! matching by name, and what it must go on judging exactly as an unscoped run
//! does, because the snapshot is still the whole organization.

mod support;

use std::fs;

use openrouter_keymaster_core::state::Origin;
use serde_json::{Value, json};
use support::fixtures::{FAKE_GUARDRAIL_ID, FAKE_WORKSPACE_ID, api_key, created_key, guardrail};
use support::http::{body_json, json_response};
use support::project::{Project, address, at, hash, uuid};
use support::sentinel::SECRET_SENTINEL_KEY;
use tempfile::TempDir;
use wiremock::Mock;
use wiremock::matchers::{method, path};

/// The workspace a scoped run in these cases is scoped to. The shared fixtures
/// put their resources here, so anything from `elsewhere` is deliberate.
const CLUB: &str = FAKE_WORKSPACE_ID;

/// Another club's workspace: in the organization, outside the scope.
const OTHER: &str = "00000000-0000-4000-8000-000000000002";

const OTHER_RAIL_ID: &str = "22222222-2222-4222-8222-222222222222";
const JOBFEED_HASH: &str = "hash-jobfeed-1";
const STRANGER_HASH: &str = "hash-stranger-1";
const NEW_HASH: &str = "hash-jobfeed-new";

/// The same record, in another workspace.
fn elsewhere(mut resource: Value) -> Value {
    resource["workspace_id"] = json!(OTHER);
    resource
}

/// Every `unmanaged` identity a plan document reports, in the plan's order.
fn unmanaged(document: &Value) -> Vec<String> {
    document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .filter(|action| action["kind"] == "unmanaged")
        .map(|action| {
            action["identity"]
                .as_str()
                .expect("an unmanaged action names what it saw")
                .to_owned()
        })
        .collect()
}

/// The one action at `address`, whatever kind it is.
fn action<'a>(document: &'a Value, address: &str) -> &'a Value {
    document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == address)
        .unwrap_or_else(|| panic!("no action at {address} in {document}"))
}

// --- the filter on noise ----------------------------------------------------

#[test]
fn a_scoped_plan_reports_only_its_own_workspaces_unmanaged_resources() {
    let project = Project::new("version = 1\n");
    project.observe(
        vec![
            api_key(JOBFEED_HASH, "golf-jobfeed"),
            elsewhere(api_key(STRANGER_HASH, "another-clubs-key")),
        ],
        vec![
            guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[]),
            elsewhere(guardrail(OTHER_RAIL_ID, "another-clubs-rail", &[])),
        ],
        Vec::new(),
    );

    let unscoped = project.succeed(&["--json", "plan"]).document();
    assert_eq!(
        unmanaged(&unscoped),
        vec![
            format!("key {JOBFEED_HASH}"),
            format!("key {STRANGER_HASH}"),
            format!("guardrail {FAKE_GUARDRAIL_ID}"),
            format!("guardrail {OTHER_RAIL_ID}"),
        ],
        "without a scope the whole organization is unowned and reported"
    );

    let scoped = project
        .succeed(&["--json", "--workspace", CLUB, "plan"])
        .document();
    assert_eq!(
        unmanaged(&scoped),
        vec![
            format!("key {JOBFEED_HASH}"),
            format!("guardrail {FAKE_GUARDRAIL_ID}"),
        ],
        "another club's resources are not this operator's to see"
    );
}

#[test]
fn a_scoped_status_reports_only_its_own_workspaces_unmanaged_resources() {
    let project = Project::new("version = 1\n");
    project.observe(
        vec![
            api_key(JOBFEED_HASH, "golf-jobfeed"),
            elsewhere(api_key(STRANGER_HASH, "another-clubs-key")),
        ],
        Vec::new(),
        Vec::new(),
    );

    let unscoped = project.succeed(&["--json", "status"]).document();
    assert_eq!(unscoped["unmanaged"].as_array().expect("a list").len(), 2);

    let scoped = project
        .succeed(&["--json", "--workspace", CLUB, "status"])
        .document();
    let listed = scoped["unmanaged"].as_array().expect("a list");
    assert_eq!(listed.len(), 1, "{scoped}");
    assert_eq!(listed[0]["identity"], JOBFEED_HASH);
}

// --- the filter on name matching --------------------------------------------

/// One creatable key and one guardrail, both named after resources another
/// workspace also has.
const NAMED: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
"#;

#[test]
fn an_identically_named_resource_in_another_workspace_is_no_candidate_and_no_collision() {
    let project = Project::new(NAMED);
    project.observe(
        vec![elsewhere(api_key(STRANGER_HASH, "golf-jobfeed"))],
        vec![elsewhere(guardrail(OTHER_RAIL_ID, "cheap-rail", &[]))],
        Vec::new(),
    );

    let unscoped = project.succeed(&["--json", "plan"]).document();
    assert_eq!(
        action(&unscoped, "keys.jobfeed")["kind"],
        "adoption_required",
        "a remote name match with no scope is an operator's to resolve: {unscoped}"
    );
    assert_eq!(
        action(&unscoped, "guardrails.cheap")["kind"],
        "adoption_required",
        "{unscoped}"
    );

    let scoped = project
        .succeed(&["--json", "--workspace", CLUB, "plan"])
        .document();
    assert_eq!(
        action(&scoped, "keys.jobfeed")["kind"],
        "create",
        "another club's identically named key must not block this one: {scoped}"
    );
    assert_eq!(
        action(&scoped, "guardrails.cheap")["kind"],
        "create",
        "nor its identically named guardrail: {scoped}"
    );
    assert!(
        unmanaged(&scoped).is_empty(),
        "and neither is reported as noise: {scoped}"
    );
}

// --- what the scope does not change -----------------------------------------

/// Two bound keys: one the snapshot has, one it does not.
const BOUND: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"

[keys.gone]
name = "gone-key"
receiver = "vault"
"#;

#[test]
fn a_bound_key_is_judged_present_or_missing_the_same_way_scoped_or_not() {
    let project = Project::new(BOUND);
    // The bound key lives in *another* workspace, which is the case the scope
    // must not touch: state records no workspace, so filtering the snapshot
    // would make this binding look orphaned (ADR-0004, rejected alternative).
    project.observe(
        vec![elsewhere(api_key(JOBFEED_HASH, "golf-jobfeed"))],
        Vec::new(),
        Vec::new(),
    );
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the present key");
        state
            .bind_key(&address("gone"), hash("hash-gone-1"), 1, at(0))
            .expect("binding the absent key");
    });

    let unscoped = project.succeed(&["--json", "plan"]).document();
    let scoped = project
        .succeed(&["--json", "--workspace", CLUB, "plan"])
        .document();

    for document in [&unscoped, &scoped] {
        assert_eq!(
            action(document, "keys.jobfeed")["kind"],
            "no_op",
            "identity decides presence, and the snapshot is still organization-wide: {document}"
        );
        assert_eq!(
            action(document, "keys.gone")["kind"],
            "missing",
            "a bound key absent from the snapshot is missing either way: {document}"
        );
    }
}

#[test]
fn the_fingerprint_separates_a_scoped_plan_from_an_unscoped_one() {
    let project = Project::new(BOUND);
    project.observe(
        vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
        Vec::new(),
        Vec::new(),
    );
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key");
    });

    let unscoped = project.succeed(&["--json", "plan"]).document();
    let scoped = project
        .succeed(&["--json", "--workspace", CLUB, "plan"])
        .document();

    assert!(unscoped["fingerprint"].is_string(), "{unscoped}");
    assert_ne!(
        unscoped["fingerprint"], scoped["fingerprint"],
        "the same world placed somewhere else is a different plan"
    );
}

// --- the guard on placement -------------------------------------------------

/// A project whose one key is configured into a workspace the scope excludes.
fn misplaced() -> Project {
    let project = Project::new(&format!(
        "version = 1\n\n[receivers.vault]\ntype = \"file\"\n\
         path = \"/var/lib/keymaster/vault.key\"\n\n[keys.jobfeed]\n\
         name = \"golf-jobfeed\"\nreceiver = \"vault\"\nworkspace_id = \"{OTHER}\"\n"
    ));
    project.observe(
        vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
        Vec::new(),
        Vec::new(),
    );
    // What an import would read, so the unscoped control run below is refused
    // by nothing at all.
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{JOBFEED_HASH}")))
            .respond_with(json_response(
                200,
                &json!({ "data": api_key(JOBFEED_HASH, "golf-jobfeed") }),
            )),
    );
    project
}

/// Fails unless `diagnostic` is the refusal that names the offending block.
fn assert_names_the_block(diagnostic: &Value) {
    assert_eq!(
        diagnostic["error"]["kind"], "config_invalid",
        "{diagnostic}"
    );
    assert!(
        diagnostic["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("keys.jobfeed.workspace_id"),
        "the refusal names the block that has to change: {diagnostic}"
    );
}

#[test]
fn a_configuration_naming_another_workspace_is_refused_before_any_request() {
    let project = misplaced();

    let diagnostic = project
        .fail(&["--json", "--workspace", CLUB, "plan"])
        .diagnostic();

    assert_names_the_block(&diagnostic);
    assert!(
        project.server.requests().is_empty(),
        "a configuration that cannot converge is refused before a client exists: {:?}",
        project.request_trace()
    );

    project.succeed(&["--json", "plan"]);
}

/// Import reads the configuration under the lock, before it builds a client or
/// binds anything, so a scoped import is refused by the same check every other
/// command makes rather than by a second one written into this path.
#[test]
fn a_scoped_import_of_a_misplaced_key_is_refused_before_it_binds_anything() {
    let project = misplaced();
    project.write_state(|_| {});
    let before = fs::read(project.state_path()).expect("the state file");

    let diagnostic = project
        .fail(&[
            "--json",
            "--workspace",
            CLUB,
            "import",
            "key",
            "jobfeed",
            "--hash",
            JOBFEED_HASH,
        ])
        .diagnostic();

    assert_names_the_block(&diagnostic);
    assert!(
        project.server.requests().is_empty(),
        "nothing is read about a key this run could never place: {:?}",
        project.request_trace()
    );
    assert_eq!(
        fs::read(project.state_path()).expect("the state file"),
        before,
        "a refused import leaves the state file byte for byte as it was"
    );

    project.succeed(&["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
}

#[test]
fn a_scoped_run_creates_its_guardrail_in_the_scope() {
    let project = Project::new("version = 1\n\n[guardrails.cheap]\nname = \"cheap-rail\"\n");
    project.observe_sequence(
        vec![Vec::new()],
        vec![
            Vec::new(),
            vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])],
        ],
        vec![Vec::new()],
    );
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/guardrails"))
            .respond_with(json_response(
                200,
                &json!({ "data": guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[]) }),
            )),
    );

    let document = project
        .succeed(&["--json", "--workspace", CLUB, "apply"])
        .document();
    assert_eq!(document["outcome"], "applied", "{document}");

    let requests = project.server.requests();
    let create = requests
        .iter()
        .find(|request| request.method == "POST")
        .expect("the guardrail create");
    assert_eq!(
        body_json(create),
        json!({
            "name": "cheap-rail",
            "include_byok_in_budgets": false,
            "workspace_id": CLUB,
        }),
        "a scoped create places the guardrail in the scope"
    );
}

#[test]
fn a_scoped_run_creates_its_key_in_the_scope() {
    let vault = TempDir::new().expect("a temporary vault directory");
    let project = Project::new(&format!(
        "version = 1\n\n[receivers.vault]\ntype = \"file\"\npath = \"{vault}/jobfeed.key\"\n\n\
         [keys.jobfeed]\nname = \"golf-jobfeed\"\nreceiver = \"vault\"\n",
        vault = vault.path().display()
    ));
    project.observe_sequence(
        vec![Vec::new(), vec![api_key(NEW_HASH, "golf-jobfeed")]],
        vec![Vec::new()],
        vec![Vec::new()],
    );
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                200,
                &created_key(NEW_HASH, "golf-jobfeed", SECRET_SENTINEL_KEY),
            )),
    );
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{NEW_HASH}")))
            .respond_with(json_response(200, &json!({}))),
    );
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{NEW_HASH}")))
            .respond_with(json_response(
                200,
                &json!({ "data": api_key(NEW_HASH, "golf-jobfeed") }),
            )),
    );

    let document = project
        .succeed(&["--json", "--workspace", CLUB, "apply"])
        .document();
    assert_eq!(document["outcome"], "applied", "{document}");

    let requests = project.server.requests();
    let create = requests
        .iter()
        .find(|request| request.method == "POST")
        .expect("the key create");
    assert_eq!(
        body_json(create)["workspace_id"],
        json!(CLUB),
        "a scoped create places the key in the scope"
    );

    let state = project.read_state();
    let binding = state.key(&address("jobfeed")).expect("the created binding");
    assert_eq!(binding.origin(), Origin::Created);
    assert!(
        fs::read_to_string(vault.path().join("jobfeed.key"))
            .expect("the receiver wrote the plaintext")
            .contains(SECRET_SENTINEL_KEY),
        "the key was actually delivered, so the assertions above are not vacuous"
    );
}

#[test]
fn a_scoped_run_leaves_the_guardrail_a_block_names_alone() {
    let project = Project::new("version = 1\n\n[guardrails.cheap]\nname = \"renamed-rail\"\n");
    project.observe(
        Vec::new(),
        vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])],
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
            .expect("binding the guardrail");
    });

    let scoped = project
        .succeed(&["--json", "--workspace", CLUB, "plan"])
        .document();
    let update = action(&scoped, "guardrails.cheap");
    assert_eq!(update["kind"], "update", "{scoped}");
    assert!(
        update["changes"]
            .as_array()
            .expect("a change list")
            .iter()
            .all(|change| change["field"] != "workspace_id"),
        "a workspace is fixed at creation and is never patched: {scoped}"
    );
}
