//! Binary-level contract tests for the command-line surface.
//!
//! These run the compiled `openrouter-keymaster` binary and assert its stable contract:
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

/// A `openrouter-keymaster` invocation isolated from the ambient credential.
fn keymaster() -> Command {
    let mut command = Command::cargo_bin("openrouter-keymaster").expect("the binary builds");
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
        .stdout(predicate::str::contains("spend"))
        .stdout(predicate::str::contains("import"))
        .stdout(predicate::str::contains("rotate"))
        .stdout(predicate::str::contains("recover"))
        .stdout(predicate::str::contains("retire"))
        .stdout(predicate::str::contains("decommission"))
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
        .stdout(predicate::str::starts_with("openrouter-keymaster "))
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
    let directory = tempfile::tempdir().expect("a temporary directory");
    keymaster()
        .arg("--config")
        .arg(directory.path().join("nowhere.toml"))
        .arg("--state")
        .arg(directory.path().join("state.json"))
        .args(["rotate", "jobfeed"])
        .assert()
        .code(APPLICATION_ERROR)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("cannot read"));
}

/// Every v0.1 command is implemented, so "reaching the handler" means failing
/// in that handler's own vocabulary. A `usage` kind would mean clap stopped the
/// run before it started, and a shared kind would mean it stopped somewhere
/// generic; each case below names the refusal that belongs to exactly one
/// command.
///
/// The configuration path does not exist, which stops the commands that read
/// one before any client is built and therefore before any network call. The
/// four that do not read a configuration — retire, decommission, delete, and
/// forget act on the state file's own record — get as far as looking for the
/// hash.
#[test]
fn every_command_reaches_its_own_handler_before_any_network_call() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let missing = directory.path().join("nowhere.toml");
    // A writing command takes the state lock before it reads the
    // configuration, so it needs a state path of its own rather than the
    // default one, relative to wherever the test runner happens to be.
    let state = directory.path().join("state.json");

    let cases: [(&[&str], &str); 10] = [
        (&["plan"], "config_read"),
        (&["status"], "config_read"),
        (&["apply"], "config_read"),
        (&["rotate", "jobfeed"], "config_read"),
        (&["recover", "replace", "jobfeed"], "config_read"),
        (
            &["import", "key", "jobfeed", "--hash", "sha256:aaaa"],
            "config_read",
        ),
        (
            &[
                "import",
                "guardrail",
                "cheap",
                "--id",
                "00000000-0000-4000-8000-000000000000",
            ],
            "config_read",
        ),
        (
            &["retire", "jobfeed", "--hash", "sha256:aaaa"],
            "retire_not_bound",
        ),
        (
            &["delete", "key", "--hash", "sha256:aaaa"],
            "delete_untracked",
        ),
        (
            &["decommission", "jobfeed", "--hash", "sha256:aaaa"],
            "decommission_no_current_key",
        ),
    ];

    for (command, kind) in cases {
        let output = keymaster()
            .arg("--json")
            .arg("--config")
            .arg(&missing)
            .arg("--state")
            .arg(&state)
            .args(command)
            .output()
            .expect("the binary runs");

        assert_eq!(output.status.code(), Some(APPLICATION_ERROR), "{command:?}");
        assert!(output.stdout.is_empty(), "{command:?} wrote a result");
        let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
        let document: serde_json::Value =
            serde_json::from_str(&stderr).expect("one JSON diagnostic");
        assert_eq!(document["error"]["kind"], kind, "{command:?}: {stderr}");
    }

    assert!(
        !state.exists(),
        "none of these got far enough to write state"
    );
}

/// `state forget` is the exception: an address bound to nothing is a clean
/// no-op rather than an error, so it succeeds and still writes no state.
#[test]
fn forgetting_an_unbound_address_succeeds_and_writes_nothing() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let state = directory.path().join("state.json");

    keymaster()
        .arg("--config")
        .arg(directory.path().join("nowhere.toml"))
        .arg("--state")
        .arg(&state)
        .args(["state", "forget", "keys.jobfeed"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("nothing to forget"))
        .stderr(predicate::str::is_empty());

    assert!(!state.exists(), "a no-op forget writes no state");
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
    let directory = tempfile::tempdir().expect("a temporary directory");
    let output = keymaster()
        .arg("--config")
        .arg(directory.path().join("nowhere.toml"))
        .args(["--json", "status"])
        .output()
        .expect("the binary runs");

    assert_eq!(output.status.code(), Some(APPLICATION_ERROR));
    assert!(output.stdout.is_empty(), "stdout carries results only");

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    let document: serde_json::Value =
        serde_json::from_str(&stderr).expect("stderr is exactly one JSON document");
    assert_eq!(document["error"]["kind"], "config_read");
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
    let config = directory.path().join("openrouter-keymaster.toml");
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
    const AMBIENT: &str = "sk-or-v1-FAKEAMBIENTCREDENTIAL";

    let directory = tempfile::tempdir().expect("a temporary directory");
    let output = Command::cargo_bin("openrouter-keymaster")
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
