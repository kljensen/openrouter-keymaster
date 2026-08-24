//! Binary-level contract tests for the command-line surface.
//!
//! These run the compiled `keymaster` binary and assert its stable contract:
//! the command tree, exit codes, and the stdout/stderr split. Every case
//! removes `OPENROUTER_MANAGEMENT_KEY` from the environment unless it is
//! testing what happens when the credential is present.

use assert_cmd::Command;
use predicates::prelude::*;

/// The environment variable Keymaster reads its management credential from.
const CREDENTIAL_VAR: &str = "OPENROUTER_MANAGEMENT_KEY";

/// Exit code clap uses for a usage error.
const USAGE_ERROR: i32 = 2;

/// Exit code for an application error.
const APPLICATION_ERROR: i32 = 1;

/// A `keymaster` invocation isolated from the ambient credential.
fn keymaster() -> Command {
    let mut command = Command::cargo_bin("keymaster").expect("the binary builds");
    command.env_remove(CREDENTIAL_VAR);
    command
}

#[test]
fn help_lists_the_whole_command_tree_and_exits_zero() {
    keymaster()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("plan"))
        .stdout(predicate::str::contains("apply"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("import"))
        .stdout(predicate::str::contains("rotate"))
        .stdout(predicate::str::contains("recover"))
        .stdout(predicate::str::contains("retire"))
        .stdout(predicate::str::contains("delete"))
        .stdout(predicate::str::contains("state"))
        .stdout(predicate::str::contains("--config"))
        .stdout(predicate::str::contains("--state"))
        .stdout(predicate::str::contains("--json"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn version_exits_zero_on_stdout() {
    keymaster()
        .arg("--version")
        .assert()
        .code(0)
        .stdout(predicate::str::starts_with("keymaster "))
        .stderr(predicate::str::is_empty());
}

#[test]
fn subcommand_help_exits_zero() {
    keymaster()
        .args(["recover", "resolve", "--help"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("--no-resource-created"))
        .stdout(predicate::str::contains("--leaked-hash"));
}

#[test]
fn help_offers_no_management_credential_option() {
    let output = keymaster().arg("--help").output().expect("the binary runs");
    let help = String::from_utf8(output.stdout).expect("utf-8 help");
    assert!(
        !help.contains(CREDENTIAL_VAR),
        "help must not name the credential variable"
    );
    assert!(
        !help.contains("--management"),
        "there must be no credential option"
    );
    assert!(
        !help.contains("--token"),
        "there must be no credential option"
    );
}

#[test]
fn missing_subcommand_is_a_usage_error() {
    keymaster()
        .assert()
        .code(USAGE_ERROR)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty().not());
}

#[test]
fn unknown_subcommand_is_a_usage_error() {
    keymaster()
        .arg("destroy")
        .assert()
        .code(USAGE_ERROR)
        .stdout(predicate::str::is_empty());
}

#[test]
fn import_key_requires_a_hash() {
    keymaster()
        .args(["import", "key", "jobfeed"])
        .assert()
        .code(USAGE_ERROR)
        .stderr(predicate::str::contains("--hash"));
}

#[test]
fn delete_key_requires_a_hash_and_takes_no_name() {
    keymaster()
        .args(["delete", "key"])
        .assert()
        .code(USAGE_ERROR)
        .stderr(predicate::str::contains("--hash"));

    keymaster()
        .args(["delete", "key", "jobfeed", "--hash", "sha256:aaaa"])
        .assert()
        .code(USAGE_ERROR);
}

#[test]
fn recover_resolve_requires_exactly_one_finding() {
    keymaster()
        .args(["recover", "resolve", "jobfeed"])
        .assert()
        .code(USAGE_ERROR);

    keymaster()
        .args([
            "recover",
            "resolve",
            "jobfeed",
            "--no-resource-created",
            "--leaked-hash",
            "sha256:aaaa",
        ])
        .assert()
        .code(USAGE_ERROR)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn a_parsed_command_fails_with_an_application_error_on_stderr() {
    keymaster()
        .arg("apply")
        .assert()
        .code(APPLICATION_ERROR)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("not implemented"));
}

#[test]
fn every_unimplemented_command_parses_and_reaches_its_handler() {
    let commands: [&[&str]; 8] = [
        &["apply"],
        &["rotate", "jobfeed"],
        &["recover", "inspect", "jobfeed"],
        &["recover", "resolve", "jobfeed", "--no-resource-created"],
        &["recover", "replace", "jobfeed"],
        &["retire", "jobfeed", "--hash", "sha256:aaaa"],
        &["delete", "key", "--hash", "sha256:aaaa"],
        &["state", "forget", "keys.jobfeed"],
    ];

    for command in commands {
        keymaster()
            .args(command)
            .assert()
            .code(APPLICATION_ERROR)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("not implemented"));
    }
}

/// `plan`, `status`, and `import` are implemented, so "reaching the handler"
/// means reading the configuration. Each is given a path that does not exist,
/// which stops it before a client is built and therefore before any network
/// call. `import` validates its identifier first, so the identifiers here are
/// well formed.
#[test]
fn the_implemented_commands_reach_their_handler_and_stop_at_the_configuration() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let missing = directory.path().join("nowhere.toml");
    // A writing command takes the state lock before it reads the
    // configuration, so it needs a state path of its own rather than the
    // default one, relative to wherever the test runner happens to be.
    let state = directory.path().join("state.json");

    let commands: [&[&str]; 4] = [
        &["plan"],
        &["status"],
        &["import", "key", "jobfeed", "--hash", "sha256:aaaa"],
        &[
            "import",
            "guardrail",
            "cheap",
            "--id",
            "00000000-0000-4000-8000-000000000000",
        ],
    ];

    for command in commands {
        keymaster()
            .arg("--config")
            .arg(&missing)
            .arg("--state")
            .arg(&state)
            .args(command)
            .assert()
            .code(APPLICATION_ERROR)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("cannot read"));
    }

    assert!(
        !state.exists(),
        "a run that stopped at the configuration writes no state"
    );
}

#[test]
fn plan_help_documents_that_exit_zero_covers_a_plan_with_changes() {
    keymaster()
        .args(["plan", "--help"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Exit code 0"))
        .stdout(predicate::str::contains("whether or not there are changes"));
}

#[test]
fn json_diagnostics_are_one_uncolored_json_document() {
    let output = keymaster()
        .args(["--json", "apply"])
        .output()
        .expect("the binary runs");

    assert_eq!(output.status.code(), Some(APPLICATION_ERROR));
    assert!(output.stdout.is_empty(), "stdout carries results only");

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    let document: serde_json::Value =
        serde_json::from_str(&stderr).expect("stderr is exactly one JSON document");
    assert_eq!(document["error"]["kind"], "not_implemented");
    assert!(
        !stderr.contains('\u{1b}'),
        "JSON output must never be colored"
    );
}

#[test]
fn json_usage_errors_are_one_uncolored_json_document() {
    let output = keymaster()
        .args(["--json", "destroy"])
        .output()
        .expect("the binary runs");

    assert_eq!(output.status.code(), Some(USAGE_ERROR));
    assert!(output.stdout.is_empty(), "stdout carries results only");

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    let document: serde_json::Value =
        serde_json::from_str(&stderr).expect("stderr is exactly one JSON document");
    assert_eq!(document["error"]["kind"], "usage");
    assert!(
        document["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("destroy")),
        "the message must name the problem: {document}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "JSON output must never be colored"
    );
}

#[test]
fn help_and_version_stay_on_the_success_path_under_json() {
    for argument in ["--help", "--version"] {
        keymaster()
            .args(["--json", argument])
            .assert()
            .code(0)
            .stderr(predicate::str::is_empty());
    }
}

#[test]
fn global_paths_are_accepted_from_any_position() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let config = directory.path().join("keymaster.toml");
    let state = directory.path().join("state.json");

    keymaster()
        .arg("--config")
        .arg(&config)
        .arg("plan")
        .arg("--state")
        .arg(&state)
        .assert()
        .code(APPLICATION_ERROR)
        .stderr(predicate::str::contains(config.display().to_string()));
}

#[test]
fn an_ambient_credential_does_not_change_behavior_or_appear_in_output() {
    // The only test that sets the credential: it must stay out of the output.
    const AMBIENT: &str = "sk-or-mgmt-FAKEAMBIENTCREDENTIAL";

    let directory = tempfile::tempdir().expect("a temporary directory");
    let output = Command::cargo_bin("keymaster")
        .expect("the binary builds")
        .env(CREDENTIAL_VAR, AMBIENT)
        .arg("--config")
        .arg(directory.path().join("nowhere.toml"))
        .args(["--json", "status"])
        .output()
        .expect("the binary runs");

    assert_eq!(output.status.code(), Some(APPLICATION_ERROR));
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stdout.is_empty());
    assert!(
        !stderr.contains(AMBIENT),
        "the credential must not be echoed"
    );
    assert!(stderr.contains("config_read"));
}
