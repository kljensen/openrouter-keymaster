//! Binary-level tests for `keymaster import`.
//!
//! Import is the one command whose whole job is to write a binding, and the
//! cases below are the ways that can go wrong. Every one of them asserts what
//! the state file holds afterwards, because "state is unchanged" is the
//! guarantee each failure path makes.

mod support;

use std::fs;

use keymaster::state::{KeyBinding, Origin, State};
use serde_json::Value;
use support::fixtures::{FAKE_GUARDRAIL_ID, OTHER_FAKE_GUARDRAIL_ID, api_key, guardrail};
use support::http::json_response;
use support::project::{Project, address, at, hash, uuid};
use support::sentinel::{SECRET_SENTINEL_KEY, assert_absent_under};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const JOBFEED_HASH: &str = "hash-jobfeed-1";
const OTHER_HASH: &str = "hash-other-1";

/// One guardrail and one key, each with a managed field beyond its name, so
/// every import below has something for a later apply to reconcile.
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
receiver = "vault"

[keys.other]
name = "other-key"
receiver = "vault"
"#;

/// Answers `GET /keys/{hash}` with one key under the name the fixture chooses.
fn serve_key(project: &Project, key_hash: &str, name: &str) {
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{key_hash}")))
            .respond_with(json_response(200, &one(api_key(key_hash, name)))),
    );
}

/// Answers `GET /guardrails/{id}`.
fn serve_guardrail(project: &Project, id: &str, name: &str) {
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/guardrails/{id}")))
            .respond_with(json_response(200, &one(guardrail(id, name, &[])))),
    );
}

/// A single-resource response, as `GET /keys/{hash}` returns one.
fn one(resource: Value) -> Value {
    serde_json::json!({ "data": resource })
}

/// The binding one address holds, if it holds one.
fn bound_hash(state: &State, name: &str) -> Option<String> {
    state
        .key(&address(name))
        .and_then(KeyBinding::current)
        .map(|current| current.hash.as_str().to_owned())
}

// --- the ordinary path -----------------------------------------------------

#[test]
fn an_import_looks_up_the_exact_hash_and_reports_what_apply_would_reconcile() {
    let project = Project::new(CONFIG);
    // The remote name differs from the configured one, which is exactly the
    // difference an import has to surface: it is the usual sign that the
    // operator pasted the wrong hash.
    serve_key(&project, JOBFEED_HASH, "an-older-name");

    let streams = project.succeed(&["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    let document = streams.document();

    assert_eq!(document["command"], "import");
    assert_eq!(document["resource"], "key");
    assert_eq!(document["address"], "keys.jobfeed");
    assert_eq!(document["identity"], format!("key {JOBFEED_HASH}"));
    assert_eq!(document["origin"], "imported");
    assert_eq!(document["bound"], Value::Bool(true));
    assert_eq!(document["remote_name"], "an-older-name");

    let changes: Vec<(String, String, String)> = document["changes"]
        .as_array()
        .expect("a change array")
        .iter()
        .map(|change| {
            (
                change["field"].as_str().unwrap_or_default().to_owned(),
                change["from"].as_str().unwrap_or_default().to_owned(),
                change["to"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        changes,
        vec![
            (
                "name".to_owned(),
                "an-older-name".to_owned(),
                "golf-jobfeed".to_owned()
            ),
            (
                "limit_usd".to_owned(),
                "5.000000".to_owned(),
                "10.000000".to_owned()
            ),
        ]
    );

    assert_eq!(
        project.request_trace(),
        vec![format!("GET /api/v1/keys/{JOBFEED_HASH}")],
        "an import addresses the exact identity; it never lists and matches by name"
    );

    let state = project.read_state();
    let binding = state.key(&address("jobfeed")).expect("the new binding");
    assert_eq!(binding.origin(), Origin::Imported);
    let current = binding.current().expect("a current key");
    assert_eq!(current.hash.as_str(), JOBFEED_HASH);
    assert_eq!(current.generation, 1);
    assert!(
        current.receiver.is_none(),
        "an imported key records no delivery: its plaintext was never Keymaster's"
    );
}

#[test]
fn a_human_import_names_the_binding_and_the_difference() {
    let project = Project::new(CONFIG);
    serve_key(&project, JOBFEED_HASH, "an-older-name");

    let streams = project.succeed(&["import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    assert!(
        streams.out.contains(&format!(
            "imported: keys.jobfeed is bound to key {JOBFEED_HASH}"
        )),
        "{}",
        streams.out
    );
    assert!(streams.out.contains("origin: imported"), "{}", streams.out);
    assert!(
        streams.out.contains("name: an-older-name -> golf-jobfeed"),
        "{}",
        streams.out
    );
    assert!(
        streams.err.contains("2 managed fields differ"),
        "a difference is a warning on stderr: {}",
        streams.err
    );
    assert!(
        streams.err.contains("cannot be delivered to a receiver"),
        "an imported key's plaintext is permanently unavailable: {}",
        streams.err
    );
}

#[test]
fn importing_a_guardrail_binds_its_uuid() {
    let project = Project::new(CONFIG);
    serve_guardrail(&project, FAKE_GUARDRAIL_ID, "cheap-rail");

    let document = project
        .succeed(&[
            "--json",
            "import",
            "guardrail",
            "cheap",
            "--id",
            FAKE_GUARDRAIL_ID,
        ])
        .document();

    assert_eq!(document["resource"], "guardrail");
    assert_eq!(document["address"], "guardrails.cheap");
    assert_eq!(document["origin"], "imported");
    // The fixture guardrail's limit is $10 and the configuration asks for $25.
    assert_eq!(document["changes"][0]["field"], "limit_usd");
    assert_eq!(document["changes"][0]["to"], "25.000000");

    let state = project.read_state();
    let binding = state.guardrail(&address("cheap")).expect("the binding");
    assert_eq!(binding.id.as_str(), FAKE_GUARDRAIL_ID);
    assert_eq!(binding.origin, Origin::Imported);
}

#[test]
fn repeating_an_import_writes_nothing_and_says_so() {
    let project = Project::new(CONFIG);
    serve_key(&project, JOBFEED_HASH, "golf-jobfeed");

    project.succeed(&["import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    let after_first = fs::read(project.state_path()).expect("the state file");
    let serial = project.read_state().serial();

    let streams = project.succeed(&["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    assert_eq!(streams.document()["bound"], Value::Bool(false));
    assert_eq!(
        project.read_state().serial(),
        serial,
        "a repeated import must not advance the serial"
    );
    assert_eq!(
        after_first,
        fs::read(project.state_path()).expect("the state file"),
        "a repeated import must leave the file byte for byte as it was"
    );

    let human = project.succeed(&["import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    assert!(
        human
            .out
            .contains("unchanged: keys.jobfeed was already bound"),
        "{}",
        human.out
    );
}

#[test]
fn an_imported_key_is_planned_as_ordinary_convergence_rather_than_a_replacement() {
    let project = Project::new(CONFIG);
    serve_key(&project, JOBFEED_HASH, "an-older-name");
    project.observe(
        vec![api_key(JOBFEED_HASH, "an-older-name")],
        Vec::new(),
        Vec::new(),
    );

    project.succeed(&["import", "key", "jobfeed", "--hash", JOBFEED_HASH]);

    let document = project.succeed(&["--json", "plan"]).document();
    let jobfeed = document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == "keys.jobfeed")
        .expect("the imported key")
        .clone();

    assert_eq!(
        jobfeed["kind"], "update",
        "a missing delivery record is not a reason to replace an imported key"
    );
    assert_eq!(jobfeed["executable"], Value::Bool(true));
}

// --- everything that must leave state unchanged ----------------------------

#[test]
fn an_identity_openrouter_does_not_have_imports_nothing() {
    let project = Project::new(CONFIG);
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{JOBFEED_HASH}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(
                serde_json::json!({ "error": { "code": 404, "message": "not found" } }),
            )),
    );

    let streams =
        project.fail_silently(&["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "import_absent");
    assert!(
        !project.state_path().exists(),
        "a failed import writes no state file at all"
    );
}

#[test]
fn a_hash_another_address_owns_is_refused_and_names_both_addresses() {
    let project = Project::new(CONFIG);
    serve_key(&project, JOBFEED_HASH, "golf-jobfeed");
    project.write_state(|state| {
        state
            .bind_key(&address("other"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the hash elsewhere");
    });
    let before = fs::read(project.state_path()).expect("the state file");

    let streams =
        project.fail_silently(&["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    let diagnostic = streams.diagnostic();
    assert_eq!(diagnostic["error"]["kind"], "import_owned_elsewhere");
    let message = diagnostic["error"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(message.contains("jobfeed"), "{message}");
    assert!(message.contains("other"), "{message}");

    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "a refused import leaves state byte for byte as it was"
    );
}

#[test]
fn an_address_bound_to_a_different_object_is_refused() {
    let project = Project::new(CONFIG);
    serve_key(&project, OTHER_HASH, "golf-jobfeed");
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the address");
    });

    let streams =
        project.fail_silently(&["--json", "import", "key", "jobfeed", "--hash", OTHER_HASH]);
    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "import_address_bound"
    );
    assert_eq!(
        bound_hash(&project.read_state(), "jobfeed"),
        Some(JOBFEED_HASH.to_owned()),
        "the original binding stands"
    );
}

#[test]
fn a_guardrail_another_address_owns_is_refused() {
    let project = Project::new(&format!(
        "{CONFIG}\n[guardrails.spare]\nname = \"spare-rail\"\n"
    ));
    serve_guardrail(&project, FAKE_GUARDRAIL_ID, "cheap-rail");
    project.write_state(|state| {
        state
            .bind_guardrail(
                &address("spare"),
                uuid(FAKE_GUARDRAIL_ID),
                Origin::Imported,
                at(0),
            )
            .expect("binding the guardrail elsewhere");
    });

    let streams = project.fail_silently(&[
        "--json",
        "import",
        "guardrail",
        "cheap",
        "--id",
        FAKE_GUARDRAIL_ID,
    ]);
    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "import_owned_elsewhere"
    );
    assert!(
        project.read_state().guardrail(&address("cheap")).is_none(),
        "the refused address stays unbound"
    );
}

#[test]
fn another_writer_holding_the_lock_stops_the_import_before_it_reads_anything() {
    let project = Project::new(CONFIG);
    serve_key(&project, JOBFEED_HASH, "golf-jobfeed");
    let lock = project.directory.path().join("state.json.lock");
    fs::write(&lock, "keymaster pid 1\n").expect("taking the lock");

    let streams =
        project.fail_silently(&["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "state_locked");
    project.server.assert_request_count(0);
    assert!(!project.state_path().exists(), "state was never written");
}

#[test]
fn a_state_write_that_cannot_happen_stops_the_import_before_it_reads_anything() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let project = Project::new(CONFIG);
        serve_key(&project, JOBFEED_HASH, "golf-jobfeed");
        let closed = project.directory.path().join("closed");
        fs::create_dir(&closed).expect("a directory to close");
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o500))
            .expect("closing the directory");

        let state = closed.join("state.json");
        let output = project.run_at(
            &state,
            &["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH],
        );
        let streams = support::project::Streams::of(&output);

        assert_eq!(output.status.code(), Some(1), "{}", streams.err);
        assert!(streams.out.is_empty(), "a failed import writes no result");
        assert_eq!(streams.diagnostic()["error"]["kind"], "state_write");
        project.server.assert_request_count(0);
        assert!(!state.exists(), "nothing was written");

        // Restored so the temporary directory can be removed.
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o700))
            .expect("reopening the directory");
    }
}

#[test]
fn the_lock_is_taken_before_the_configuration_is_read() {
    // Ordering, asserted without a race: the configuration here is invalid and
    // the lock is already held. Whichever failure is reported is the check that
    // ran first, and it has to be the lock — the generation an import records
    // comes from the configuration, so the file it reads must be one nothing
    // can edit out from under it between the read and the write.
    let project = Project::new("version = 1\n\n[keys.jobfeed]\nname = \"\"\n");
    serve_key(&project, JOBFEED_HASH, "golf-jobfeed");
    let lock = project.directory.path().join("state.json.lock");
    fs::write(&lock, "keymaster pid 1\n").expect("taking the lock");

    let streams =
        project.fail_silently(&["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "state_locked",
        "the lock is what import reaches first"
    );
    project.server.assert_request_count(0);

    // With the lock released, the same run reaches the configuration — which
    // proves the case above failed for the reason it claims, and not because
    // the configuration happened to be readable.
    fs::remove_file(&lock).expect("releasing the lock");
    let streams =
        project.fail_silently(&["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "config_invalid");
    project.server.assert_request_count(0);
    assert!(
        !project.state_path().exists(),
        "neither run wrote any state"
    );
}

#[test]
fn an_address_the_configuration_does_not_describe_cannot_be_imported() {
    let project = Project::new(CONFIG);
    serve_key(&project, JOBFEED_HASH, "golf-jobfeed");

    let streams =
        project.fail_silently(&["--json", "import", "key", "nowhere", "--hash", JOBFEED_HASH]);
    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "import_not_configured"
    );
    project.server.assert_request_count(0);
}

#[test]
fn a_malformed_identifier_is_rejected_before_anything_is_read() {
    let project = Project::new(CONFIG);

    for (arguments, kind) in [
        (
            vec!["import", "key", "jobfeed", "--hash", "has a space"],
            "import_argument",
        ),
        (
            vec!["import", "guardrail", "cheap", "--id", "not-a-uuid"],
            "import_argument",
        ),
        (
            vec![
                "import",
                "key",
                "not a local address",
                "--hash",
                JOBFEED_HASH,
            ],
            "import_argument",
        ),
    ] {
        let mut with_json = vec!["--json"];
        with_json.extend(arguments);
        let streams = project.fail_silently(&with_json);
        assert_eq!(streams.diagnostic()["error"]["kind"], kind);
    }
    project.server.assert_request_count(0);
}

#[test]
fn a_key_that_offers_its_plaintext_as_a_hash_is_refused() {
    // `KeyHash::parse` refuses credential-shaped input, so a confused paste
    // cannot put a live credential into the state file.
    let project = Project::new(CONFIG);

    let streams = project.fail_silently(&[
        "--json",
        "import",
        "key",
        "jobfeed",
        "--hash",
        SECRET_SENTINEL_KEY,
    ]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "import_argument");
    project.server.assert_request_count(0);
    assert_absent_under(project.directory.path());
}

// --- disclosure ------------------------------------------------------------

#[test]
fn a_remote_name_cannot_smuggle_a_credential_into_the_import_report() {
    let project = Project::new(CONFIG);
    serve_key(&project, JOBFEED_HASH, SECRET_SENTINEL_KEY);

    for arguments in [
        &["import", "key", "jobfeed", "--hash", JOBFEED_HASH][..],
        &["--json", "import", "key", "jobfeed", "--hash", JOBFEED_HASH],
    ] {
        // `succeed` scans both streams and the whole project directory.
        let streams = project.succeed(arguments);
        assert!(streams.out.contains("[redacted]"), "{}", streams.out);
    }
}

#[test]
fn importing_a_guardrail_no_one_owns_leaves_the_other_binding_alone() {
    let project = Project::new(CONFIG);
    serve_guardrail(&project, OTHER_FAKE_GUARDRAIL_ID, "cheap-rail");
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding a key");
    });

    project.succeed(&[
        "import",
        "guardrail",
        "cheap",
        "--id",
        OTHER_FAKE_GUARDRAIL_ID,
    ]);

    let state = project.read_state();
    assert_eq!(bound_hash(&state, "jobfeed"), Some(JOBFEED_HASH.to_owned()));
    assert_eq!(
        state
            .guardrail(&address("cheap"))
            .map(|binding| binding.id.as_str().to_owned()),
        Some(OTHER_FAKE_GUARDRAIL_ID.to_owned())
    );
}
