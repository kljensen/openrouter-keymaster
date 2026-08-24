//! A project directory, a local API server, and the binary that talks to both.
//!
//! Every binary-level test needs the same four things: a configuration file, a
//! state file, a server answering the three listings a snapshot reads, and a
//! way to run `keymaster` against them with a sentinel credential instead of a
//! real one. This is that, so `tests/plan.rs`, `tests/import.rs`, and
//! `tests/apply.rs` differ only in what they assert.
//!
//! Two properties hold for every run started here. The binary sees no ambient
//! credential or base URL — both variables are removed before they are set —
//! and every successful or failed run is scanned for the secret sentinel in
//! stdout, stderr, and every file under the project directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use keymaster::ids::{Address, KeyHash, Uuid};
use keymaster::state::{State, StateFile};
use serde_json::Value;
use tempfile::TempDir;
use time::OffsetDateTime;
use wiremock::Mock;
use wiremock::matchers::{method, path, query_param};

use super::fixtures::{empty_page, page};
use super::http::{Scripted, TestServer, json_response};
use super::sentinel::{SECRET_SENTINEL_KEY, assert_absent, assert_absent_under};

/// The environment variables the binary reads.
pub const CREDENTIAL_VAR: &str = "OPENROUTER_MANAGEMENT_KEY";
pub const BASE_URL_VAR: &str = "OPENROUTER_BASE_URL";

/// A temporary project and the server it reads OpenRouter from.
pub struct Project {
    pub directory: TempDir,
    pub server: TestServer,
}

impl Project {
    /// Writes `config` into a fresh project directory and starts a server.
    #[must_use]
    pub fn new(config: &str) -> Self {
        let project = Self {
            directory: tempfile::tempdir().expect("a temporary directory"),
            server: TestServer::start(),
        };
        fs::write(project.config_path(), config).expect("writing the configuration");
        project
    }

    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.directory.path().join("keymaster.toml")
    }

    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.directory.path().join("state.json")
    }

    /// Answers the three listings the snapshot needs.
    ///
    /// The answer depends on the offset rather than on call order, because
    /// several cases run the binary more than once against one server and each
    /// run reads every listing from the beginning.
    pub fn observe(&self, keys: Vec<Value>, guardrails: Vec<Value>, assignments: Vec<Value>) {
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

    /// Answers the three listings differently each time they are read.
    ///
    /// The first complete read of a listing gets the first set of records, the
    /// second read the second, and so on, with the last repeating. That is how
    /// a case scripts a world that changes between two runs — or between an
    /// apply's writes and the read that verifies them — without a stateful
    /// fake server standing in for OpenRouter.
    ///
    /// Only the first page of each read is scripted; the page after it is
    /// empty, which is what ends a listing.
    pub fn observe_sequence(
        &self,
        keys: Vec<Vec<Value>>,
        guardrails: Vec<Vec<Value>>,
        assignments: Vec<Vec<Value>>,
    ) {
        for (route, reads) in [
            ("/api/v1/keys", keys),
            ("/api/v1/guardrails", guardrails),
            ("/api/v1/guardrails/assignments/keys", assignments),
        ] {
            self.server.mount(
                Mock::given(method("GET"))
                    .and(path(route))
                    .and(query_param("offset", "0"))
                    .respond_with(Scripted::json(reads.into_iter().map(page)))
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
    pub fn write_state(&self, build: impl FnOnce(&mut State)) {
        let mut state = State::new();
        build(&mut state);
        let file = StateFile::new(self.state_path());
        let lock = file.lock().expect("the state lock");
        lock.write(&mut state).expect("writing the state fixture");
    }

    /// The state file as Keymaster reads it back.
    #[must_use]
    pub fn read_state(&self) -> State {
        StateFile::new(self.state_path())
            .read()
            .expect("reading the state file")
    }

    /// Runs the binary with the harness's base URL and a sentinel credential.
    #[must_use]
    pub fn run(&self, arguments: &[&str]) -> Output {
        self.run_at(&self.state_path(), arguments)
    }

    /// Runs the binary against a state file other than the project's own.
    ///
    /// `--state` is a global option that may appear once, so a case that needs
    /// a different one — an unwritable directory, say — cannot simply add it
    /// to `arguments`.
    #[must_use]
    pub fn run_at(&self, state: &Path, arguments: &[&str]) -> Output {
        self.run_at_with(state, arguments, &[])
    }

    /// Runs the binary against a base URL other than this project's own
    /// server.
    ///
    /// For the handful of answers `wiremock` cannot express — a body that stops
    /// before its declared length — which `RawServer` writes onto the socket
    /// directly. The configuration, the state file, and the credential are this
    /// project's; only where the requests go differs.
    #[must_use]
    pub fn run_against(&self, base_url: &str, arguments: &[&str]) -> Output {
        let mut command = Command::cargo_bin("keymaster").expect("the binary builds");
        command
            .env_remove(CREDENTIAL_VAR)
            .env_remove(BASE_URL_VAR)
            .env(CREDENTIAL_VAR, SECRET_SENTINEL_KEY)
            .env(BASE_URL_VAR, base_url)
            .arg("--config")
            .arg(self.config_path())
            .arg("--state")
            .arg(self.state_path())
            .args(arguments);
        command.output().expect("the binary runs")
    }

    /// Runs the binary with extra environment variables set.
    ///
    /// The only current use is `KEYMASTER_STATE_FAULT`, which the
    /// `fault-injection` feature reads to stop a real run at a named durable
    /// phase. Nothing here relaxes the isolation the other runners have: the
    /// credential and base URL are still removed before they are set.
    #[must_use]
    pub fn run_with(&self, arguments: &[&str], environment: &[(&str, &str)]) -> Output {
        self.run_at_with(&self.state_path(), arguments, environment)
    }

    fn run_at_with(
        &self,
        state: &Path,
        arguments: &[&str],
        environment: &[(&str, &str)],
    ) -> Output {
        let mut command = Command::cargo_bin("keymaster").expect("the binary builds");
        command
            .env_remove(CREDENTIAL_VAR)
            .env_remove(BASE_URL_VAR)
            .env(CREDENTIAL_VAR, SECRET_SENTINEL_KEY)
            .env(BASE_URL_VAR, self.server.api_base_url())
            .arg("--config")
            .arg(self.config_path())
            .arg("--state")
            .arg(state)
            .args(arguments);
        for (name, value) in environment {
            command.env(name, value);
        }
        command.output().expect("the binary runs")
    }

    /// Runs the binary and fails unless it exited 0.
    pub fn succeed(&self, arguments: &[&str]) -> Streams {
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
    pub fn fail(&self, arguments: &[&str]) -> Streams {
        let output = self.run(arguments);
        let streams = Streams::of(&output);
        assert_eq!(
            output.status.code(),
            Some(1),
            "expected an application error from {arguments:?}:\n{}",
            streams.out
        );
        self.assert_no_secret_escaped(&streams);
        streams
    }

    /// Runs the binary, fails unless it exited 1, and fails unless it wrote no
    /// result at all.
    pub fn fail_silently(&self, arguments: &[&str]) -> Streams {
        let streams = self.fail(arguments);
        assert!(
            streams.out.is_empty(),
            "this run must write no result:\n{}",
            streams.out
        );
        streams
    }

    /// The scan every case runs, on the success path and the failure path
    /// alike: the credential must reach the wire and nothing else.
    pub fn assert_no_secret_escaped(&self, streams: &Streams) {
        assert_absent("stdout", &streams.out);
        assert_absent("stderr", &streams.err);
        assert_absent_under(self.directory.path());
    }

    /// Fails unless every request the server saw was a read.
    pub fn assert_read_only(&self) {
        let requests = self.server.requests();
        assert!(!requests.is_empty(), "the run must have read something");
        for request in &requests {
            assert_eq!(
                request.method.to_string(),
                "GET",
                "this command may only read:\n{}",
                super::http::describe_request(request)
            );
        }
    }

    /// Every request the server saw, as `METHOD /path`.
    #[must_use]
    pub fn request_trace(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .map(|request| format!("{} {}", request.method, request.url.path()))
            .collect()
    }

    /// Every write request the server saw, as `METHOD /path`.
    #[must_use]
    pub fn write_trace(&self) -> Vec<String> {
        self.request_trace()
            .into_iter()
            .filter(|request| !request.starts_with("GET "))
            .collect()
    }

    /// The names of everything directly under the project directory, sorted.
    #[must_use]
    pub fn entries(&self) -> Vec<String> {
        entries(self.directory.path())
    }
}

/// One run's two streams, as text.
pub struct Streams {
    pub out: String,
    pub err: String,
}

impl Streams {
    #[must_use]
    pub fn of(output: &Output) -> Self {
        Self {
            out: String::from_utf8(output.stdout.clone()).expect("utf-8 stdout"),
            err: String::from_utf8(output.stderr.clone()).expect("utf-8 stderr"),
        }
    }

    /// The single JSON document on stdout.
    #[must_use]
    pub fn document(&self) -> Value {
        serde_json::from_str(&self.out).unwrap_or_else(|error| {
            panic!(
                "stdout is not exactly one JSON document ({error}):\n{}",
                self.out
            )
        })
    }

    /// The single JSON diagnostic on stderr.
    #[must_use]
    pub fn diagnostic(&self) -> Value {
        serde_json::from_str(&self.err).unwrap_or_else(|error| {
            panic!(
                "stderr is not exactly one JSON document ({error}):\n{}",
                self.err
            )
        })
    }
}

/// The names of everything directly under a directory, sorted.
#[must_use]
pub fn entries(directory: &Path) -> Vec<String> {
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

#[must_use]
pub fn address(value: &str) -> Address {
    Address::parse(value).expect("a valid test address")
}

#[must_use]
pub fn hash(value: &str) -> KeyHash {
    KeyHash::parse(value).expect("a valid test hash")
}

#[must_use]
pub fn uuid(value: &str) -> Uuid {
    Uuid::parse(value).expect("a valid test UUID")
}

/// A fixed instant plus `seconds`, so timestamps in fixtures are deterministic.
#[must_use]
pub fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_767_225_600 + seconds).expect("a valid instant")
}
