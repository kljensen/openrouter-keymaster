//! Binary-level tests for the two read-only commands.
//!
//! Every case runs the compiled `keymaster` against the local API harness, so
//! what is asserted is the contract an operator and a script actually see: the
//! exit code, the stdout/stderr split, the JSON document, and — for the whole
//! run — that nothing was written anywhere.

mod support;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use keymaster::ids::{Address, KeyHash, OperationId, ReceiverFingerprint, RemoteName, Uuid};
use keymaster::state::{BeginCreate, Origin, State, StateFile, Transition};
use serde_json::{Value, json};
use support::fixtures::{
    FAKE_GUARDRAIL_ID, OTHER_FAKE_GUARDRAIL_ID, api_error, api_key, empty_page, guardrail, page,
};
use support::http::{TestServer, json_response};
use support::sentinel::{SECRET_SENTINEL_KEY, assert_absent, assert_absent_under};
use tempfile::TempDir;
use time::OffsetDateTime;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

/// The environment variables the binary reads.
const CREDENTIAL_VAR: &str = "OPENROUTER_MANAGEMENT_KEY";
const BASE_URL_VAR: &str = "OPENROUTER_BASE_URL";

const JOBFEED_HASH: &str = "hash-jobfeed-1";
const GONE_HASH: &str = "hash-gone-1";
const STRAY_HASH: &str = "hash-stray-1";

/// A configuration binding one guardrail and one key, with no managed field
/// beyond their names: any difference the cases below show is one they made.
const BASE_CONFIG: &str = r#"
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

/// A project directory, a server, and the binary that talks to both.
struct Project {
    directory: TempDir,
    server: TestServer,
}

impl Project {
    fn new(config: &str) -> Self {
        let project = Self {
            directory: tempfile::tempdir().expect("a temporary directory"),
            server: TestServer::start(),
        };
        fs::write(project.config_path(), config).expect("writing the configuration");
        project
    }

    fn config_path(&self) -> PathBuf {
        self.directory.path().join("keymaster.toml")
    }

    fn state_path(&self) -> PathBuf {
        self.directory.path().join("state.json")
    }

    /// Answers the three listings the snapshot needs.
    ///
    /// The answer depends on the offset rather than on call order, because
    /// several cases run the binary more than once against one server and each
    /// run reads every listing from the beginning.
    fn observe(&self, keys: Vec<Value>, guardrails: Vec<Value>, assignments: Vec<Value>) {
        for (route, items) in [
            ("/api/v1/keys", keys),
            ("/api/v1/guardrails", guardrails),
            ("/api/v1/guardrails/assignments/keys", assignments),
        ] {
            self.server.mount(
                Mock::given(method("GET"))
                    .and(path(route))
                    .and(query_param("offset", "0"))
                    .respond_with(json_response(200, &page(items)))
                    .with_priority(1),
            );
            self.server.mount(
                Mock::given(method("GET"))
                    .and(path(route))
                    .respond_with(json_response(200, &empty_page()))
                    .with_priority(2),
            );
        }
    }

    /// Writes a state file through Keymaster's own writer, so the fixture is
    /// exactly what a previous run would have left.
    fn write_state(&self, build: impl FnOnce(&mut State)) {
        let mut state = State::new();
        build(&mut state);
        let file = StateFile::new(self.state_path());
        let lock = file.lock().expect("the state lock");
        lock.write(&mut state).expect("writing the state fixture");
    }

    /// Runs the binary with the harness's base URL and a sentinel credential.
    fn run(&self, arguments: &[&str]) -> Output {
        let mut command = Command::cargo_bin("keymaster").expect("the binary builds");
        command
            .env_remove(CREDENTIAL_VAR)
            .env_remove(BASE_URL_VAR)
            .env(CREDENTIAL_VAR, SECRET_SENTINEL_KEY)
            .env(BASE_URL_VAR, self.server.api_base_url())
            .arg("--config")
            .arg(self.config_path())
            .arg("--state")
            .arg(self.state_path())
            .args(arguments);
        command.output().expect("the binary runs")
    }

    /// Runs the binary and fails unless it exited 0.
    fn succeed(&self, arguments: &[&str]) -> Streams {
        let output = self.run(arguments);
        let streams = Streams::of(&output);
        assert_eq!(
            output.status.code(),
            Some(0),
            "expected success from {arguments:?}:\n{}",
            streams.err
        );
        self.assert_no_secret_escaped(&streams);
        streams
    }

    /// Runs the binary and fails unless it exited 1.
    fn fail(&self, arguments: &[&str]) -> Streams {
        let output = self.run(arguments);
        let streams = Streams::of(&output);
        assert_eq!(
            output.status.code(),
            Some(1),
            "expected an application error from {arguments:?}:\n{}",
            streams.out
        );
        assert!(streams.out.is_empty(), "a failed run writes no result");
        self.assert_no_secret_escaped(&streams);
        streams
    }

    /// The scan every case runs, on the success path and the failure path
    /// alike: the credential must reach the wire and nothing else.
    fn assert_no_secret_escaped(&self, streams: &Streams) {
        assert_absent("stdout", &streams.out);
        assert_absent("stderr", &streams.err);
        assert_absent_under(self.directory.path());
    }

    /// Fails unless every request the server saw was a read.
    fn assert_read_only(&self) {
        let requests = self.server.requests();
        assert!(!requests.is_empty(), "the run must have read something");
        for request in &requests {
            assert_eq!(
                request.method.to_string(),
                "GET",
                "plan and status may only read:\n{}",
                support::http::describe_request(request)
            );
        }
    }
}

/// One run's two streams, as text.
struct Streams {
    out: String,
    err: String,
}

impl Streams {
    fn of(output: &Output) -> Self {
        Self {
            out: String::from_utf8(output.stdout.clone()).expect("utf-8 stdout"),
            err: String::from_utf8(output.stderr.clone()).expect("utf-8 stderr"),
        }
    }

    /// The single JSON document on stdout.
    fn document(&self) -> Value {
        serde_json::from_str(&self.out).unwrap_or_else(|error| {
            panic!(
                "stdout is not exactly one JSON document ({error}):\n{}",
                self.out
            )
        })
    }

    /// The single JSON diagnostic on stderr.
    fn diagnostic(&self) -> Value {
        serde_json::from_str(&self.err).unwrap_or_else(|error| {
            panic!(
                "stderr is not exactly one JSON document ({error}):\n{}",
                self.err
            )
        })
    }
}

fn address(value: &str) -> Address {
    Address::parse(value).expect("a valid test address")
}

fn hash(value: &str) -> KeyHash {
    KeyHash::parse(value).expect("a valid test hash")
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse(value).expect("a valid test UUID")
}

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_767_225_600 + seconds).expect("a valid instant")
}

/// Binds the guardrail and the key `BASE_CONFIG` describes.
fn bind_base(state: &mut State) {
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

/// The remote side of a converged project.
fn converged_remote() -> (Vec<Value>, Vec<Value>) {
    (
        vec![api_key(JOBFEED_HASH, "golf-jobfeed")],
        vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail", &[])],
    )
}

/// Every action kind in a document, in order.
fn kinds(document: &Value) -> Vec<String> {
    document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .map(|action| action["kind"].as_str().unwrap_or_default().to_owned())
        .collect()
}

// --- the representative planning cases -------------------------------------

#[test]
fn a_converged_project_plans_no_changes_and_exits_zero() {
    let project = Project::new(BASE_CONFIG);
    let (keys, guardrails) = converged_remote();
    project.observe(keys, guardrails, Vec::new());
    project.write_state(bind_base);

    let human = project.succeed(&["plan"]);
    assert!(
        human
            .out
            .contains("converged: OpenRouter matches the configuration"),
        "{}",
        human.out
    );
    assert!(human.err.is_empty(), "a clean plan warns about nothing");

    let json = project.succeed(&["--json", "plan"]);
    let document = json.document();
    assert_eq!(document["command"], "plan");
    assert_eq!(document["has_changes"], Value::Bool(false));
    assert_eq!(document["blocked"], Value::Bool(false));
    assert_eq!(document["outcome"], "converged");
    assert_eq!(kinds(&document), vec!["no_op", "no_op"]);
    assert!(json.err.is_empty(), "a JSON stream carries one document");
}

#[test]
fn drift_is_planned_as_an_update_and_its_expansion_is_conspicuous() {
    // The fixture key's limit is $5; the configuration asks for $10.
    let project = Project::new(&format!("{BASE_CONFIG}limit_usd = 10\n"));
    let (keys, guardrails) = converged_remote();
    project.observe(keys, guardrails, Vec::new());
    project.write_state(bind_base);

    let human = project.succeed(&["plan"]);
    assert!(human.out.contains("update"), "{}", human.out);
    assert!(human.out.contains("limit_usd: 5.000000 -> 10.000000"));
    assert!(human.out.contains("! privilege expansions (1):"));
    assert!(
        human.err.contains("warning:") && human.err.contains("widen"),
        "a widening plan warns on stderr: {}",
        human.err
    );

    let document = project.succeed(&["--json", "plan"]).document();
    let update = document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["kind"] == "update")
        .expect("the update")
        .clone();
    assert_eq!(update["address"], "keys.jobfeed");
    assert_eq!(update["safety"], "expanding");
    assert_eq!(update["expands_privilege"], Value::Bool(true));
    assert_eq!(update["expansions"][0]["expansion"], "budget_raised");
    assert_eq!(update["expansions"][0]["field"], "limit_usd");
    assert_eq!(update["executable"], Value::Bool(true));
    assert_eq!(document["has_changes"], Value::Bool(true));
}

#[test]
fn a_name_collision_asks_for_an_import_rather_than_adopting_it() {
    let project = Project::new(&format!(
        "{BASE_CONFIG}\n[keys.stray]\nname = \"stray-key\"\nreceiver = \"vault\"\n"
    ));
    let (mut keys, guardrails) = converged_remote();
    keys.push(api_key(STRAY_HASH, "stray-key"));
    project.observe(keys, guardrails, Vec::new());
    project.write_state(bind_base);

    let document = project.succeed(&["--json", "plan"]).document();
    let stray = document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == "keys.stray")
        .expect("the unbound key")
        .clone();

    assert_eq!(stray["kind"], "adoption_required");
    assert_eq!(stray["safety"], "report");
    assert_eq!(stray["reasons"][0]["reason"], "name_matches");
    assert_eq!(stray["reasons"][0]["candidates"][0], "key hash-stray-1");
    assert_eq!(document["has_changes"], Value::Bool(false));

    let human = project.succeed(&["plan"]).out;
    assert!(human.contains("adoption_required"), "{human}");
    assert!(human.contains("keymaster import"), "{human}");
}

#[test]
fn a_bound_key_that_is_not_there_is_reported_and_never_recreated() {
    let project = Project::new(BASE_CONFIG);
    let (_, guardrails) = converged_remote();
    // The bound key is absent from the snapshot entirely.
    project.observe(Vec::new(), guardrails, Vec::new());
    project.write_state(|state| {
        bind_base(state);
    });

    let streams = project.succeed(&["--json", "plan"]);
    let document = streams.document();
    let key = document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == "keys.jobfeed")
        .expect("the bound key")
        .clone();

    assert_eq!(key["kind"], "missing");
    assert_eq!(key["reasons"][0]["reason"], "absent_remotely");
    assert!(!kinds(&document).contains(&"create".to_owned()));

    let human = project.succeed(&["plan"]);
    assert!(
        human.err.contains("absent from OpenRouter"),
        "a missing resource warns on stderr: {}",
        human.err
    );
}

#[test]
fn a_remote_resource_no_address_owns_is_reported_as_unmanaged() {
    let project = Project::new(BASE_CONFIG);
    let (mut keys, mut guardrails) = converged_remote();
    keys.push(api_key(STRAY_HASH, "someone-elses-key"));
    guardrails.push(guardrail(
        OTHER_FAKE_GUARDRAIL_ID,
        "someone-elses-rail",
        &[],
    ));
    project.observe(keys, guardrails, Vec::new());
    project.write_state(bind_base);

    let document = project.succeed(&["--json", "plan"]).document();
    let unmanaged: Vec<&str> = document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .filter(|action| action["kind"] == "unmanaged")
        .filter_map(|action| action["address"].as_str())
        .collect();

    assert_eq!(
        unmanaged,
        vec![
            format!("remote key {STRAY_HASH}"),
            format!("remote guardrail {OTHER_FAKE_GUARDRAIL_ID}"),
        ]
    );
    assert_eq!(document["has_changes"], Value::Bool(false));
}

#[test]
fn an_unfinished_operation_blocks_the_plan_and_reports_how_to_resolve_it() {
    let project = Project::new(BASE_CONFIG);
    let (keys, guardrails) = converged_remote();
    project.observe(keys, guardrails, Vec::new());
    project.write_state(|state| {
        state
            .begin_create(
                &address("jobfeed"),
                BeginCreate {
                    operation: OperationId::parse("op-0007").expect("an operation id"),
                    generation: 1,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([7; 32]),
                },
                at(3),
            )
            .expect("starting a create");
        state
            .advance_key(
                &address("jobfeed"),
                Transition::Created {
                    hash: hash(JOBFEED_HASH),
                },
                at(4),
            )
            .expect("recording the create response");
    });

    let streams = project.succeed(&["--json", "plan"]);
    let document = streams.document();
    let recovery = document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["kind"] == "recovery_required")
        .expect("the unfinished operation")
        .clone();

    assert_eq!(document["blocked"], Value::Bool(true));
    assert_eq!(document["has_changes"], Value::Bool(false));
    assert_eq!(recovery["recovery"]["operation"], "op-0007");
    assert_eq!(recovery["recovery"]["phase"], "created");
    assert_eq!(recovery["recovery"]["phase_at"], "2026-01-01T00:00:04Z");
    assert_eq!(recovery["recovery"]["known_hash"], JOBFEED_HASH);
    assert!(
        recovery["recovery"]["remediation"]
            .as_str()
            .is_some_and(|text| text.contains("keymaster recover inspect jobfeed"))
    );

    let human = project.succeed(&["plan"]);
    assert!(
        human.out.contains("unfinished operations (1):"),
        "{}",
        human.out
    );
    assert!(human.out.contains("op-0007"));
    assert!(human.out.contains("known key hash: hash-jobfeed-1"));
    assert!(human.out.contains("remediation:"));
    assert!(human.out.contains("blocked:"));
    assert!(human.err.contains("warning:"), "{}", human.err);
}

// --- the properties that hold for every plan -------------------------------

#[test]
fn plan_writes_nothing_anywhere() {
    let project = Project::new(&format!("{BASE_CONFIG}limit_usd = 10\n"));
    let (keys, guardrails) = converged_remote();
    project.observe(keys, guardrails, Vec::new());
    project.write_state(bind_base);

    let before = fs::read(project.state_path()).expect("the state fixture");
    let directory_before = entries(project.directory.path());

    project.succeed(&["plan"]);
    project.succeed(&["--json", "plan"]);
    project.succeed(&["status"]);

    project.assert_read_only();
    assert_eq!(
        before,
        fs::read(project.state_path()).expect("the state file"),
        "plan and status must leave the state file byte for byte as they found it"
    );
    assert_eq!(
        directory_before,
        entries(project.directory.path()),
        "no lock file and no temporary file may be left behind"
    );
}

#[test]
fn repeated_plans_render_identically() {
    let project = Project::new(&format!("{BASE_CONFIG}limit_usd = 10\n"));
    let (keys, guardrails) = converged_remote();
    project.observe(keys, guardrails, Vec::new());
    project.write_state(bind_base);

    let first = project.succeed(&["plan"]);
    let second = project.succeed(&["plan"]);
    assert_eq!(first.out, second.out);
    assert_eq!(first.err, second.err);

    let first = project.succeed(&["--json", "plan"]);
    let second = project.succeed(&["--json", "plan"]);
    assert_eq!(first.out, second.out);
}

// --- the failure categories ------------------------------------------------

#[test]
fn a_rejected_credential_is_an_authentication_error() {
    let project = Project::new(BASE_CONFIG);
    project
        .server
        .mount(Mock::given(method("GET")).respond_with(json_response(
            401,
            &api_error(401, "invalid management key"),
        )));
    project.write_state(bind_base);

    let streams = project.fail(&["--json", "plan"]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "authentication");
    let human = project.fail(&["plan"]);
    assert!(human.err.starts_with("error: "), "{}", human.err);
}

#[test]
fn a_missing_credential_is_its_own_category() {
    let project = Project::new(BASE_CONFIG);
    project.observe(Vec::new(), Vec::new(), Vec::new());

    let output = Command::cargo_bin("keymaster")
        .expect("the binary builds")
        .env_remove(CREDENTIAL_VAR)
        .env(BASE_URL_VAR, project.server.api_base_url())
        .arg("--config")
        .arg(project.config_path())
        .arg("--state")
        .arg(project.state_path())
        .args(["--json", "plan"])
        .output()
        .expect("the binary runs");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    let diagnostic: Value = serde_json::from_str(&stderr).expect("one JSON document");
    assert_eq!(diagnostic["error"]["kind"], "missing_credential");
    project.server.assert_request_count(0);
}

#[test]
fn an_invalid_configuration_is_reported_before_anything_is_read() {
    let project = Project::new("version = 1\n[keys.jobfeed]\nname = \"\"\n");

    let streams = project.fail(&["--json", "plan"]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "config_invalid");
    project.server.assert_request_count(0);
}

#[test]
fn an_unreadable_state_file_is_a_state_error() {
    let project = Project::new(BASE_CONFIG);
    fs::write(project.state_path(), "{\"version\": 99}").expect("writing a future state file");

    let streams = project.fail(&["--json", "plan"]);
    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "state_unsupported_version"
    );
    project.server.assert_request_count(0);
}

#[test]
fn a_base_url_that_is_not_unicode_stops_the_run_rather_than_falling_back() {
    // Falling back to production here would send the management credential
    // somewhere the operator did not name, which is the one thing an override
    // like this must never be able to do.
    let project = Project::new(BASE_CONFIG);
    project.observe(Vec::new(), Vec::new(), Vec::new());

    let output = Command::cargo_bin("keymaster")
        .expect("the binary builds")
        .env(CREDENTIAL_VAR, SECRET_SENTINEL_KEY)
        .env(BASE_URL_VAR, OsStr::from_bytes(b"http://\xff\xfe/api/v1"))
        .arg("--config")
        .arg(project.config_path())
        .arg("--state")
        .arg(project.state_path())
        .args(["--json", "plan"])
        .output()
        .expect("the binary runs");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    let diagnostic: Value = serde_json::from_str(&stderr).expect("one JSON document");
    assert_eq!(diagnostic["error"]["kind"], "invariant");
    assert!(
        diagnostic["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(BASE_URL_VAR)),
        "the diagnostic must name the variable: {diagnostic}"
    );
    assert_absent("stderr", &stderr);
    project.server.assert_request_count(0);
}

#[test]
fn a_remote_display_name_cannot_smuggle_a_credential_or_an_escape_into_output() {
    // A display name is free text an operator or an attacker with dashboard
    // access chooses. Here one is a credential and the other rewrites the
    // terminal; neither may reach the operator as it was written.
    let project = Project::new(BASE_CONFIG);
    project.observe(
        vec![api_key(JOBFEED_HASH, SECRET_SENTINEL_KEY)],
        vec![guardrail(FAKE_GUARDRAIL_ID, "cheap-rail\u{1b}[2K", &[])],
        Vec::new(),
    );
    project.write_state(bind_base);

    for arguments in [
        &["plan"][..],
        &["--json", "plan"],
        &["status"],
        &["--json", "status"],
    ] {
        // `succeed` already scans both streams and the project directory for
        // the sentinel; these assert the value was rewritten rather than
        // merely absent because nothing printed it.
        let streams = project.succeed(arguments);
        assert!(streams.out.contains("[redacted]"), "{}", streams.out);
        assert!(
            !streams.out.contains('\u{1b}'),
            "a control character reached stdout: {}",
            streams.out.escape_debug()
        );
        assert!(streams.out.contains("\\u{1b}"), "{}", streams.out);
    }
}

#[test]
fn an_api_failure_is_a_status_error() {
    let project = Project::new(BASE_CONFIG);
    project.server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "error": { "code": 500, "message": "server exploded" }
            }))),
    );
    project.write_state(bind_base);

    let streams = project.fail(&["--json", "plan"]);
    assert_eq!(streams.diagnostic()["error"]["kind"], "http_status");
}

// --- status ----------------------------------------------------------------

#[test]
fn status_reports_bindings_presence_usage_and_unmanaged_resources() {
    let project = Project::new(BASE_CONFIG);
    let (mut keys, guardrails) = converged_remote();
    keys.push(api_key(STRAY_HASH, "someone-elses-key"));
    project.observe(keys, guardrails, Vec::new());
    project.write_state(|state| {
        bind_base(state);
        state
            .bind_key(&address("gone"), hash(GONE_HASH), 1, at(0))
            .expect("binding a key that is not there");
    });

    let human = project.succeed(&["status"]);
    for expected in [
        "keys.jobfeed",
        "remote: present, enabled, named \"golf-jobfeed\"",
        "usage: total 1.250000",
        "limit 5.000000, remaining 3.750000",
        "remote: absent from the snapshot",
        "(orphaned",
        "unmanaged (1):",
    ] {
        assert!(
            human.out.contains(expected),
            "status omits {expected}:\n{}",
            human.out
        );
    }
    assert!(human.err.contains("warning:"), "{}", human.err);

    let document = project.succeed(&["--json", "status"]).document();
    assert_eq!(document["command"], "status");
    let jobfeed = document["keys"]
        .as_array()
        .expect("a key array")
        .iter()
        .find(|key| key["address"] == "keys.jobfeed")
        .expect("the bound key")
        .clone();
    assert_eq!(jobfeed["present_remotely"], Value::Bool(true));
    assert_eq!(jobfeed["usage"]["limit_remaining"], 3.75);
    assert_eq!(jobfeed["usage"]["limit"], 5.0);
    assert_eq!(document["unmanaged"][0]["identity"], STRAY_HASH);
}

#[test]
fn status_reports_an_incomplete_operation_with_non_secret_remediation() {
    let project = Project::new(BASE_CONFIG);
    let (keys, guardrails) = converged_remote();
    project.observe(keys, guardrails, Vec::new());
    project.write_state(|state| {
        state
            .begin_create(
                &address("jobfeed"),
                BeginCreate {
                    operation: OperationId::parse("op-0009").expect("an operation id"),
                    generation: 1,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([9; 32]),
                },
                at(5),
            )
            .expect("starting a create");
    });

    let document = project.succeed(&["--json", "status"]).document();
    let operation = &document["operation"];
    assert_eq!(operation["address"], "keys.jobfeed");
    assert_eq!(operation["operation"], "op-0009");
    assert_eq!(operation["phase"], "create_started");
    assert_eq!(operation["phase_at"], "2026-01-01T00:00:05Z");
    assert!(operation["known_hash"].is_null());
    assert!(
        operation["remediation"]
            .as_str()
            .is_some_and(|text| text.contains("keymaster recover"))
    );

    let human = project.succeed(&["status"]);
    assert!(human.out.contains("incomplete operation:"), "{}", human.out);
    assert!(human.err.contains("unfinished"), "{}", human.err);
}

/// The names of everything directly under a directory, sorted.
fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("listing the project directory")
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}
