//! Log destinations as a managed resource (ADR-0006).
//!
//! Four things here are unlike any other resource, and the cases below are
//! about those four. A destination's `config` may hold a third-party
//! credential, so it is write-only and never leaves this process except in a
//! request body. Its `type` and its workspace are fixed at creation on a
//! resource nothing replaces automatically. Its key allowlist is managed as
//! always empty. And its failures may not quote a response body.
//!
//! The sentinel used throughout is a fake provider token written into `config`.
//! Every run the harness starts already scans stdout, stderr, and every file
//! under the project for the *key* sentinel; the cases here scan for the
//! provider one as well, which is what proves the redactor's exact-match
//! registry does its job.

mod support;

use std::fs;

use openrouter_keymaster_core::state::Origin;
use serde_json::{Value, json};
use support::fixtures::{
    FAKE_DESTINATION_ID, FAKE_WORKSPACE_ID, OTHER_FAKE_DESTINATION_ID, log_destination,
};
use support::http::json_response;
use support::project::{Project, address, at, uuid};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const CLUB: &str = FAKE_WORKSPACE_ID;
const AUDIT: &str = FAKE_DESTINATION_ID;
const DESTINATIONS: &str = "/api/v1/observability/destinations";

/// A fake provider token, long enough for the redactor to register. It stands
/// where a real Datadog API key would, and must never appear in any output.
const PROVIDER_TOKEN: &str = "dd-PROVIDER-TOKEN-NEVER-DISCLOSE-8f31c2";

/// One destination, in a workspace this configuration also manages.
fn project_toml(config_fields: &str) -> String {
    format!(
        "version = 1\n\n[workspaces.club]\nname = \"Golf Club\"\nslug = \"golf-club\"\n\n\
         [log_destinations.audit]\ntype = \"datadog\"\nname = \"Club audit\"\nworkspace = \"club\"\n\
         config = {{ site = \"datadoghq.com\", apiKey = \"{PROVIDER_TOKEN}\"{config_fields} }}\n"
    )
}

/// The same destination, placed by raw UUID so no workspace block is needed.
fn standalone_toml(name: &str) -> String {
    format!(
        "version = 1\n\n[log_destinations.audit]\ntype = \"datadog\"\nname = \"{name}\"\n\
         workspace_id = \"{CLUB}\"\n\
         config = {{ site = \"datadoghq.com\", apiKey = \"{PROVIDER_TOKEN}\" }}\n"
    )
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

/// The reasons of one action, as stable spellings.
fn reasons(action: &Value) -> Vec<String> {
    action["reasons"]
        .as_array()
        .expect("a reason list")
        .iter()
        .map(|reason| {
            reason["reason"]
                .as_str()
                .expect("a reason spelling")
                .to_owned()
        })
        .collect()
}

/// The fields one action changes.
fn changed(action: &Value) -> Vec<String> {
    action["changes"]
        .as_array()
        .map(|changes| {
            changes
                .iter()
                .map(|change| change["field"].as_str().expect("a field").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Binds the club workspace, and nothing else.
fn bind_club(state: &mut openrouter_keymaster_core::state::State) {
    state
        .bind_workspace(&address("club"), uuid(CLUB), None, Origin::Imported, at(0))
        .expect("binding the workspace");
}

/// Binds the audit destination with `digest`, which is `None` for an import.
fn bind_audit(state: &mut openrouter_keymaster_core::state::State, digest: Option<&str>) {
    state
        .bind_log_destination(
            &address("audit"),
            uuid(AUDIT),
            digest.map(str::to_owned),
            Origin::Imported,
            at(0),
        )
        .expect("binding the destination");
}

/// The digest of the `config` one configuration file describes.
///
/// Read out of Keymaster's own parser rather than recomputed by hand: it is the
/// value state records, and a test that hardcoded a hash would be asserting
/// against itself.
fn digest_of(source: &str) -> String {
    openrouter_keymaster_core::config::Config::parse(source)
        .expect("a valid configuration")
        .log_destinations
        .values()
        .next()
        .expect("one destination")
        .config
        .digest()
}

/// Fails unless the provider token appears nowhere in a run's two streams or in
/// any file under the project.
fn assert_token_absent(streams: &support::project::Streams, project: &Project) {
    assert!(
        !streams.out.contains(PROVIDER_TOKEN),
        "the provider token reached stdout:\n{}",
        streams.out
    );
    assert!(
        !streams.err.contains(PROVIDER_TOKEN),
        "the provider token reached stderr:\n{}",
        streams.err
    );
    let state = fs::read_to_string(project.state_path()).unwrap_or_default();
    assert!(
        !state.contains(PROVIDER_TOKEN),
        "the provider token reached the state file:\n{state}"
    );
}

/// The body of the one request matching `method` and `path`.
fn sent_body(project: &Project, verb: &str, route: &str) -> Value {
    let requests = project.server.requests();
    let request = requests
        .iter()
        .find(|request| request.method == verb && request.url.path() == route)
        .unwrap_or_else(|| panic!("no {verb} {route} in {:?}", project.request_trace()));
    serde_json::from_slice(&request.body).expect("a JSON request body")
}

// --- create -----------------------------------------------------------------

#[test]
fn a_created_destination_records_its_identity_and_the_digest_of_what_it_wrote() {
    let source = standalone_toml("Club audit");
    let project = Project::new(&source);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_destination_sequence(vec![
        Vec::new(),
        vec![log_destination(AUDIT, "datadog", "Club audit")],
    ]);
    project.server.mount(
        Mock::given(method("POST"))
            .and(path(DESTINATIONS))
            .respond_with(json_response(
                201,
                &json!({ "data": log_destination(AUDIT, "datadog", "Club audit") }),
            )),
    );

    let streams = project.succeed(&["--json", "apply"]);
    let document = streams.document();
    assert_eq!(document["outcome"], "applied", "{document}");
    assert_eq!(
        project.write_trace(),
        vec![format!("POST {DESTINATIONS}")],
        "one create and nothing else"
    );

    // The body carries the configuration verbatim — that is the one place it is
    // allowed to go — and places the destination in the workspace the block
    // names.
    let body = sent_body(&project, "POST", DESTINATIONS);
    assert_eq!(body["type"], "datadog", "{body}");
    assert_eq!(body["config"]["apiKey"], PROVIDER_TOKEN, "{body}");
    assert_eq!(body["workspace_id"], CLUB, "{body}");
    assert_eq!(
        body.get("api_key_hashes"),
        None,
        "a create omits a filter that has never existed: {body}"
    );

    let binding = project
        .read_state()
        .log_destination(&address("audit"))
        .cloned()
        .expect("the destination binding");
    assert_eq!(binding.id, uuid(AUDIT));
    assert_eq!(binding.origin, Origin::Created);
    assert_eq!(
        binding.config_digest.as_deref(),
        Some(digest_of(&source).as_str()),
        "the digest recorded is the digest of what was written"
    );
    assert_token_absent(&streams, &project);
}

#[test]
fn a_destination_naming_an_unbound_workspace_is_held_back_until_the_binding_exists() {
    let project = Project::new(&project_toml(""));
    project.observe(Vec::new(), Vec::new(), Vec::new());

    let document = project.succeed(&["--json", "plan"]).document();
    assert_eq!(action(&document, "workspaces.club")["kind"], "create");

    let destination = action(&document, "log_destinations.audit");
    assert_eq!(destination["kind"], "create", "{document}");
    assert_eq!(destination["executable"], false, "{document}");
    assert!(
        destination["reasons"]
            .as_array()
            .expect("a reason list")
            .iter()
            .any(|reason| reason["dependency"] == "workspaces.club"),
        "the destination says which workspace it waits on: {document}"
    );
    project.assert_read_only();
}

// --- update, and the digest that drives `config` ----------------------------

#[test]
fn an_ordinary_field_change_is_patched_without_resending_the_configuration() {
    let source = standalone_toml("Renamed audit");
    let project = Project::new(&source);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    // Three reads: the plan below, the apply's own planning snapshot, and the
    // read that verifies what the apply wrote.
    project.observe_destination_sequence(vec![
        vec![log_destination(AUDIT, "datadog", "Club audit")],
        vec![log_destination(AUDIT, "datadog", "Club audit")],
        vec![log_destination(AUDIT, "datadog", "Renamed audit")],
    ]);
    project.write_state(|state| bind_audit(state, Some(&digest_of(&source))));
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("{DESTINATIONS}/{AUDIT}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let planned = project.succeed(&["--json", "plan"]).document();
    assert_eq!(
        changed(action(&planned, "log_destinations.audit")),
        vec!["name"],
        "the stored digest matches, so `config` is not in the diff: {planned}"
    );

    let streams = project.succeed(&["--json", "apply"]);
    assert_eq!(streams.document()["outcome"], "applied");

    let body = sent_body(&project, "PATCH", &format!("{DESTINATIONS}/{AUDIT}"));
    assert_eq!(body.get("config"), None, "a converged config is not resent");
    assert_eq!(body["api_key_hashes"], Value::Null, "{body}");
    assert_eq!(body.get("type"), None, "{body}");
    assert_eq!(body.get("workspace_id"), None, "{body}");
    assert_token_absent(&streams, &project);
}

#[test]
fn a_changed_configuration_is_an_update_whose_diff_says_config_and_nothing_else() {
    // The stored digest is the one a different configuration produced, which is
    // exactly what an edited `config` looks like on the next run.
    let stale = digest_of(&standalone_toml("Club audit"));
    let source = format!(
        "version = 1\n\n[log_destinations.audit]\ntype = \"datadog\"\nname = \"Club audit\"\n\
         workspace_id = \"{CLUB}\"\n\
         config = {{ site = \"datadoghq.eu\", apiKey = \"{PROVIDER_TOKEN}\" }}\n"
    );
    let project = Project::new(&source);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(vec![log_destination(AUDIT, "datadog", "Club audit")]);
    project.write_state(|state| bind_audit(state, Some(&stale)));
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("{DESTINATIONS}/{AUDIT}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let planned = project.succeed(&["--json", "plan"]).document();
    let update = action(&planned, "log_destinations.audit");
    assert_eq!(update["kind"], "update", "{planned}");
    assert_eq!(
        changed(update),
        vec!["config"],
        "a changed digest is the whole of the diff: {planned}"
    );
    let rendered = format!("{update}");
    assert!(
        !rendered.contains("datadoghq.eu") && !rendered.contains(PROVIDER_TOKEN),
        "the diff shows that it changed, never to what: {rendered}"
    );

    let streams = project.succeed(&["--json", "apply"]);
    let body = sent_body(&project, "PATCH", &format!("{DESTINATIONS}/{AUDIT}"));
    assert_eq!(body["config"]["site"], "datadoghq.eu", "{body}");
    assert_eq!(
        project
            .read_state()
            .log_destination(&address("audit"))
            .expect("the binding")
            .config_digest
            .as_deref(),
        Some(digest_of(&source).as_str()),
        "the run records the digest it just wrote"
    );
    assert_token_absent(&streams, &project);
}

#[test]
fn an_imported_destination_has_no_digest_so_its_first_apply_writes_the_configuration_once() {
    let source = standalone_toml("Club audit");
    let project = Project::new(&source);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(vec![log_destination(AUDIT, "datadog", "Club audit")]);
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("{DESTINATIONS}/{AUDIT}")))
            .respond_with(json_response(
                200,
                &json!({ "data": log_destination(AUDIT, "datadog", "Club audit") }),
            )),
    );
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("{DESTINATIONS}/{AUDIT}")))
            .respond_with(json_response(200, &json!({}))),
    );
    project.write_state(|_| {});

    // Import binds and records no digest: OpenRouter masks what it holds.
    let imported = project
        .succeed(&[
            "--json",
            "import",
            "log-destination",
            "audit",
            "--id",
            AUDIT,
        ])
        .document();
    assert_eq!(imported["resource"], "log destination", "{imported}");
    assert_eq!(imported["bound"], true, "{imported}");
    assert_eq!(
        changed(&imported),
        vec!["config"],
        "with no digest recorded, a later apply writes the configuration once: {imported}"
    );
    assert!(
        project
            .read_state()
            .log_destination(&address("audit"))
            .expect("the binding")
            .config_digest
            .is_none(),
        "an import records no digest"
    );

    // The first apply writes it, and records the digest.
    let streams = project.succeed(&["--json", "apply"]);
    assert_eq!(streams.document()["outcome"], "applied");
    let body = sent_body(&project, "PATCH", &format!("{DESTINATIONS}/{AUDIT}"));
    assert_eq!(body["config"]["apiKey"], PROVIDER_TOKEN, "{body}");
    assert_eq!(
        project
            .read_state()
            .log_destination(&address("audit"))
            .expect("the binding")
            .config_digest
            .as_deref(),
        Some(digest_of(&source).as_str())
    );
    assert_token_absent(&streams, &project);

    // And a second plan has nothing left to say, because the digest now matches
    // — no read of `config` was needed at any point.
    let settled = project.succeed(&["--json", "plan"]).document();
    assert_eq!(action(&settled, "log_destinations.audit")["kind"], "no_op");
}

#[test]
fn a_repeated_import_compares_against_the_digest_the_binding_records() {
    // The address is already bound and its digest is the one this very
    // configuration produces, which is what an import repeated after an apply
    // looks like. Comparing against nothing would claim a `config` write that
    // would never happen.
    let source = standalone_toml("Club audit");
    let project = Project::new(&source);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(vec![log_destination(AUDIT, "datadog", "Club audit")]);
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("{DESTINATIONS}/{AUDIT}")))
            .respond_with(json_response(
                200,
                &json!({ "data": log_destination(AUDIT, "datadog", "Club audit") }),
            )),
    );
    project.write_state(|state| bind_audit(state, Some(&digest_of(&source))));

    let document = project
        .succeed(&[
            "--json",
            "import",
            "log-destination",
            "audit",
            "--id",
            AUDIT,
        ])
        .document();

    assert_eq!(document["bound"], false, "nothing changed: {document}");
    assert_eq!(
        changed(&document),
        Vec::<String>::new(),
        "the recorded digest matches, so there is nothing to reconcile: {document}"
    );
    assert_eq!(
        document["warnings"],
        json!([]),
        "and nothing to warn about either: {document}"
    );
    project.assert_read_only();
}

// --- the allowlist Keymaster manages as always empty ------------------------

#[test]
fn an_allowlist_openrouter_holds_is_drift_the_apply_clears_with_null() {
    let source = standalone_toml("Club audit");
    let mut filtered = log_destination(AUDIT, "datadog", "Club audit");
    filtered["api_key_hashes"] = json!(["hash-one", "hash-two"]);
    let project = Project::new(&source);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    // The plan below, the apply's planning snapshot, then the verifying read.
    project.observe_destination_sequence(vec![
        vec![filtered.clone()],
        vec![filtered],
        vec![log_destination(AUDIT, "datadog", "Club audit")],
    ]);
    project.write_state(|state| bind_audit(state, Some(&digest_of(&source))));
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("{DESTINATIONS}/{AUDIT}")))
            .respond_with(json_response(200, &json!({}))),
    );

    let planned = project.succeed(&["--json", "plan"]).document();
    assert_eq!(
        changed(action(&planned, "log_destinations.audit")),
        vec!["api_key_hashes"],
        "an allowlist Keymaster did not ask for is the only difference: {planned}"
    );

    project.succeed(&["--json", "apply"]);
    let body = sent_body(&project, "PATCH", &format!("{DESTINATIONS}/{AUDIT}"));
    assert_eq!(
        body["api_key_hashes"],
        Value::Null,
        "`null` is what clears the filter, so every key in the workspace is forwarded: {body}"
    );
}

// --- the two fields fixed at creation ---------------------------------------

#[test]
fn a_changed_type_or_workspace_is_held_back_naming_the_field_and_the_way_out() {
    for (source, field, observed) in [
        (
            format!(
                "version = 1\n\n[log_destinations.audit]\ntype = \"langfuse\"\nname = \"Club \
                 audit\"\nworkspace_id = \"{CLUB}\"\nconfig = {{ apiKey = \"{PROVIDER_TOKEN}\" }}\n"
            ),
            "type",
            log_destination(AUDIT, "datadog", "Club audit"),
        ),
        (standalone_toml("Club audit"), "workspace_id", {
            let mut elsewhere = log_destination(AUDIT, "datadog", "Club audit");
            elsewhere["workspace_id"] = json!("00000000-0000-4000-8000-00000000000e");
            elsewhere
        }),
    ] {
        let project = Project::new(&source);
        project.observe(Vec::new(), Vec::new(), Vec::new());
        project.observe_log_destinations(vec![observed]);
        project.write_state(|state| bind_audit(state, Some(&digest_of(&source))));

        let planned = project.succeed(&["--json", "plan"]).document();
        let held = action(&planned, "log_destinations.audit");
        assert_eq!(held["kind"], "no_op", "{field}: {planned}");
        assert_eq!(held["executable"], false, "{field}: {planned}");
        assert!(
            held["blocked"].as_bool().unwrap_or(false),
            "{field}: held-back drift, not convergence: {planned}"
        );
        let reason = held["reasons"]
            .as_array()
            .expect("a reason list")
            .iter()
            .find(|reason| reason["reason"] == "destination_fixed_at_creation")
            .unwrap_or_else(|| panic!("no fixed-at-creation reason in {planned}"));
        assert_eq!(reason["field"], field, "{planned}");
        assert_eq!(reason["id"], AUDIT, "{planned}");

        let human = project.succeed(&["plan"]);
        assert!(
            human.out.contains("delete log-destination --id"),
            "{field}: the plan names the explicit command that clears it:\n{}",
            human.out
        );

        // Nothing converges, and the apply is held back rather than failing.
        let applied = project.succeed(&["--json", "apply"]).document();
        assert_eq!(applied["outcome"], "held_back", "{field}: {applied}");
        assert!(
            project.write_trace().is_empty(),
            "{field}: no write can converge this: {:?}",
            project.write_trace()
        );
    }
}

// --- orphan, delete, forget --------------------------------------------------

#[test]
fn removing_the_block_orphans_the_binding_and_deletes_nothing() {
    let project = Project::new("version = 1\n");
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(vec![log_destination(AUDIT, "datadog", "Club audit")]);
    project.write_state(|state| bind_audit(state, Some("abc")));
    let before = fs::read(project.state_path()).expect("the state fixture");

    let document = project.succeed(&["--json", "plan"]).document();
    let orphan = action(&document, "log_destinations.audit");
    assert_eq!(orphan["kind"], "orphaned_binding", "{document}");
    assert_eq!(reasons(orphan), vec!["removed_from_configuration"]);

    project.assert_read_only();
    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "a plan writes no state"
    );
}

#[test]
fn deleting_a_tracked_destination_releases_the_binding_once_a_404_proves_it_is_gone() {
    let project = Project::new(&standalone_toml("Club audit"));
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.server.mount(
        Mock::given(method("DELETE"))
            .and(path(format!("{DESTINATIONS}/{AUDIT}")))
            .respond_with(json_response(200, &json!({ "deleted": true }))),
    );
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("{DESTINATIONS}/{AUDIT}")))
            .respond_with(json_response(
                404,
                &json!({ "error": { "code": 404, "message": "not found" } }),
            )),
    );
    project.write_state(|state| bind_audit(state, Some("abc")));

    let document = project
        .succeed(&["--json", "delete", "log-destination", "--id", AUDIT])
        .document();
    assert_eq!(document["outcome"], "deleted", "{document}");
    assert_eq!(document["tracked"], false, "{document}");
    assert_eq!(
        document["released"],
        json!([format!("log_destinations.audit ({AUDIT})")]),
        "{document}"
    );
    assert!(
        project
            .read_state()
            .log_destination(&address("audit"))
            .is_none()
    );
}

#[test]
fn deleting_a_destination_no_local_address_tracks_is_refused_without_a_request() {
    let project = Project::new(&standalone_toml("Club audit"));
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.write_state(|_| {});

    let diagnostic = project
        .fail_silently(&["--json", "delete", "log-destination", "--id", AUDIT])
        .diagnostic();
    assert_eq!(
        diagnostic["error"]["kind"], "delete_log_destination_untracked",
        "{diagnostic}"
    );
    assert!(
        project.server.requests().is_empty(),
        "a destination Keymaster does not own is not even read: {:?}",
        project.request_trace()
    );
}

#[test]
fn forgetting_a_destination_releases_it_and_calls_nothing() {
    let project = Project::new(&standalone_toml("Club audit"));
    project.write_state(|state| bind_audit(state, Some("abc")));

    let document = project
        .succeed(&["--json", "state", "forget", "log_destinations.audit"])
        .document();
    assert_eq!(document["resource"], "log destination", "{document}");
    assert_eq!(document["forgotten"], true, "{document}");
    assert_eq!(document["released"][0]["identity"], AUDIT, "{document}");
    assert!(
        project
            .read_state()
            .log_destination(&address("audit"))
            .is_none()
    );
    assert!(
        project.server.requests().is_empty(),
        "forget makes no request at all: {:?}",
        project.request_trace()
    );

    // Repeating it is a clean no-op.
    let again = project
        .succeed(&["--json", "state", "forget", "log_destinations.audit"])
        .document();
    assert_eq!(again["forgotten"], false, "{again}");
}

#[test]
fn deleting_a_workspace_is_refused_while_it_still_holds_a_log_destination() {
    let project = Project::new(&project_toml(""));
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(vec![log_destination(AUDIT, "datadog", "someone else's")]);
    project.write_state(bind_club);

    let diagnostic = project
        .fail_silently(&["--json", "delete", "workspace", "--id", CLUB])
        .diagnostic();
    assert_eq!(
        diagnostic["error"]["kind"], "delete_workspace_inhabited",
        "{diagnostic}"
    );
    let message = diagnostic["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains(&format!("log destination {AUDIT}")),
        "deleting the workspace would take the destination with it: {message}"
    );
    assert!(project.write_trace().is_empty());
}

// --- adoption, unmanaged, and the scope --------------------------------------

#[test]
fn an_unbound_destination_whose_name_is_taken_is_an_adoption_rather_than_a_create() {
    let project = Project::new(&standalone_toml("Club audit"));
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(vec![log_destination(AUDIT, "datadog", "Club audit")]);
    project.write_state(|_| {});

    let document = project.succeed(&["--json", "plan"]).document();
    let adoption = action(&document, "log_destinations.audit");
    assert_eq!(adoption["kind"], "adoption_required", "{document}");
    assert!(
        reasons(adoption).contains(&"name_matches".to_owned()),
        "{document}"
    );
    project.assert_read_only();
}

#[test]
fn a_destination_no_local_address_owns_is_reported_and_never_changed() {
    let project = Project::new("version = 1\n");
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(vec![log_destination(
        OTHER_FAKE_DESTINATION_ID,
        "webhook",
        "someone else's",
    )]);

    let document = project.succeed(&["--json", "plan"]).document();
    let unmanaged = action(
        &document,
        &format!("remote log destination {OTHER_FAKE_DESTINATION_ID}"),
    );
    assert_eq!(unmanaged["kind"], "unmanaged", "{document}");
    assert_eq!(reasons(unmanaged), vec!["not_configured"]);
    project.assert_read_only();
}

#[test]
fn a_scoped_run_refuses_a_destination_placed_in_another_workspace() {
    let elsewhere = "00000000-0000-4000-8000-00000000000e";
    let project = Project::new(&standalone_toml("Club audit"));
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.write_state(|_| {});

    let diagnostic = project
        .fail(&["--json", "--workspace", elsewhere, "plan"])
        .diagnostic();
    assert_eq!(
        diagnostic["error"]["kind"], "config_invalid",
        "{diagnostic}"
    );
    let message = diagnostic["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("log_destinations.audit.workspace_id"),
        "{message}"
    );

    // Scoped to the workspace the block names, nothing objects.
    project.succeed(&["--json", "--workspace", CLUB, "plan"]);
}

// --- the secret, everywhere it must not be -----------------------------------

#[test]
fn a_failed_write_reports_a_status_and_a_code_and_never_the_body() {
    // The body quotes the value it refused, which is exactly the shape of
    // response ADR-0006 item 4 forbids repeating.
    let source = standalone_toml("Club audit");
    let project = Project::new(&source);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(Vec::new());
    project.server.mount(
        Mock::given(method("POST"))
            .and(path(DESTINATIONS))
            .respond_with(json_response(
                400,
                &json!({
                    "error": {
                        "code": 400,
                        "message": format!(
                            "invalid config: apiKey \"{PROVIDER_TOKEN}\" is not a Datadog key"
                        ),
                    }
                }),
            )),
    );

    let streams = project.fail(&["--json", "apply"]);
    let document = streams.document();
    let failed = action(&document, "log_destinations.audit");
    assert_eq!(failed["status"], "failed", "{document}");
    let detail = failed["detail"].as_str().expect("a detail");
    assert!(
        detail.contains("HTTP 400") && detail.contains("error code 400"),
        "the status and the code are what a destination failure carries: {detail}"
    );
    assert!(
        !detail.contains("invalid config"),
        "no part of the response body is repeated: {detail}"
    );
    assert_token_absent(&streams, &project);
}

#[test]
fn the_configuration_never_appears_in_plan_or_status_output() {
    let source = standalone_toml("Club audit");
    let project = Project::new(&source);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(vec![log_destination(AUDIT, "datadog", "Club audit")]);
    project.write_state(|state| bind_audit(state, Some(&digest_of(&source))));

    for arguments in [
        vec!["--json", "plan"],
        vec!["plan"],
        vec!["--json", "status"],
        vec!["status"],
    ] {
        let streams = project.succeed(&arguments);
        assert_token_absent(&streams, &project);
        assert!(
            !streams.out.contains("datadoghq.com"),
            "{arguments:?}: not even the masked value OpenRouter returned:\n{}",
            streams.out
        );
    }

    // Status says what it can say about a write-only field: whether Keymaster
    // has ever written it, and that the allowlist is the empty one it manages.
    let document = project.succeed(&["--json", "status"]).document();
    let listed = document["log_destinations"]
        .as_array()
        .expect("a destination list");
    assert_eq!(listed.len(), 1, "{document}");
    assert_eq!(listed[0]["address"], "log_destinations.audit");
    assert_eq!(listed[0]["id"], AUDIT);
    assert_eq!(listed[0]["present_remotely"], true);
    assert_eq!(listed[0]["config_digest_recorded"], true);
    assert_eq!(listed[0]["api_key_hashes"], 0);
    assert_eq!(
        listed[0].get("config"),
        None,
        "there is nowhere in this document to put one: {document}"
    );
}

#[test]
fn a_configuration_value_is_scrubbed_from_a_message_that_would_have_quoted_it() {
    // The redactor learns the value when the configuration is loaded, and
    // scrubs it by exact match from everything it touches afterwards. Here it
    // is a display name someone put it in on the OpenRouter side, which
    // `status` would otherwise read back verbatim — the one class of text
    // Keymaster did not write and no parser has checked.
    let source = standalone_toml("Club audit");
    let project = Project::new(&source);
    project.observe(Vec::new(), Vec::new(), Vec::new());
    project.observe_log_destinations(vec![log_destination(
        OTHER_FAKE_DESTINATION_ID,
        "webhook",
        &format!("named after {PROVIDER_TOKEN}"),
    )]);
    project.write_state(|_| {});

    let streams = project.succeed(&["--json", "status"]);
    assert!(
        streams.out.contains("named after [redacted]"),
        "the registered value is replaced where it appears:\n{}",
        streams.out
    );
    assert_token_absent(&streams, &project);
}

#[test]
fn a_configuration_value_never_reaches_a_deserializer_error() {
    let project = Project::new(&format!(
        "version = 1\n\n[log_destinations.audit]\ntype = \"datadog\"\nname = \"Club audit\"\n\
         config = {{ apiKey = {{ nested = 1.5 }}, marker = \"{PROVIDER_TOKEN}\" }}\n"
    ));
    project.observe(Vec::new(), Vec::new(), Vec::new());

    let streams = project.fail_silently(&["--json", "plan"]);
    let diagnostic = streams.diagnostic();
    assert_eq!(diagnostic["error"]["kind"], "config_syntax", "{diagnostic}");
    let message = diagnostic["error"]["message"].as_str().expect("a message");
    assert!(
        !message.contains("1.5"),
        "the refused value is never quoted: {message}"
    );
    assert_token_absent(&streams, &project);
}

#[test]
fn an_unknown_type_is_refused_by_name_before_anything_is_sent() {
    let project = Project::new(&format!(
        "version = 1\n\n[log_destinations.audit]\ntype = \"splunk\"\nname = \"Club audit\"\n\
         config = {{ apiKey = \"{PROVIDER_TOKEN}\" }}\n"
    ));
    project.observe(Vec::new(), Vec::new(), Vec::new());

    let diagnostic = project.fail_silently(&["--json", "plan"]).diagnostic();
    assert_eq!(
        diagnostic["error"]["kind"], "config_invalid",
        "{diagnostic}"
    );
    let message = diagnostic["error"]["message"].as_str().expect("a message");
    assert!(message.contains("log_destinations.audit.type"), "{message}");
    assert!(
        message.contains("`datadog`") && !message.contains("splunk"),
        "the refusal names the field and lists the types, never the value: {message}"
    );
    assert!(
        project.server.requests().is_empty(),
        "a configuration mistake is caught before a client exists"
    );
}
