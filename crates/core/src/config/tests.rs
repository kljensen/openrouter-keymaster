//! Configuration parsing and validation tests.

use super::*;
use crate::ids::Address;

/// The sentinel from the shared test harness. Repeated here because unit
/// tests cannot reach `tests/support`.
const SECRET_SENTINEL_KEY: &str = "sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE";

/// A minimal valid configuration, so a test can add exactly the one thing it
/// is about.
const MINIMAL: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap"

[keys.jobfeed]
name = "jobfeed"
receiver = "vault"
"#;

fn parse(source: &str) -> Config {
    Config::parse(source).unwrap_or_else(|error| panic!("expected a valid configuration: {error}"))
}

fn problems(source: &str) -> Vec<Problem> {
    let error = Config::parse(source).expect_err("expected a rejection");
    assert_eq!(error.kind(), "config_invalid", "{error}");
    error.problems().to_vec()
}

/// The configuration paths a rejected document complains about.
fn paths(source: &str) -> Vec<String> {
    problems(source)
        .into_iter()
        .map(|problem| problem.path)
        .collect()
}

fn address(value: &str) -> Address {
    Address::parse(value).expect("a valid test address")
}

fn key<'a>(config: &'a Config, name: &str) -> &'a Key {
    config.keys.get(&address(name)).expect("the configured key")
}

fn guardrail<'a>(config: &'a Config, name: &str) -> &'a Guardrail {
    config
        .guardrails
        .get(&address(name))
        .expect("the configured guardrail")
}

// --- the checked-in example ------------------------------------------------

#[test]
fn the_example_configuration_is_valid() {
    let config = parse(include_str!(
        "../../../../examples/openrouter-keymaster.toml"
    ));
    assert_eq!(config.workspaces.len(), 1);
    assert_eq!(config.guardrails.len(), 1);
    assert_eq!(config.keys.len(), 1);
    assert_eq!(config.receivers.len(), 2);
    assert_eq!(config.log_destinations.len(), 1);

    let receivers: Vec<&Receiver> = config.receivers.values().collect();
    assert!(matches!(receivers[0], Receiver::Command { .. }));
    assert!(matches!(receivers[1], Receiver::File { .. }));
}

#[test]
fn parsing_touches_no_other_file() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let before = std::fs::read_dir(directory.path())
        .expect("listing the directory")
        .count();

    parse(include_str!(
        "../../../../examples/openrouter-keymaster.toml"
    ));

    let after = std::fs::read_dir(directory.path())
        .expect("listing the directory")
        .count();
    assert_eq!(before, 0);
    assert_eq!(after, 0);
}

#[test]
fn loading_reports_a_missing_file_without_panicking() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let error = Config::load(&directory.path().join("absent.toml"))
        .expect_err("a missing file is an error");
    assert_eq!(error.kind(), "config_read");
}

#[test]
fn loading_a_file_matches_parsing_its_text() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("openrouter-keymaster.toml");
    std::fs::write(&path, MINIMAL).expect("writing the configuration");
    assert_eq!(Config::load(&path).expect("a valid file"), parse(MINIMAL));
}

// --- defaults --------------------------------------------------------------

#[test]
fn byok_inclusion_defaults_to_false_and_is_inherited() {
    let config = parse(MINIMAL);
    assert!(!config.defaults.include_byok_in_limit);
    assert!(!key(&config, "jobfeed").include_byok_in_limit);
    assert!(!guardrail(&config, "cheap").include_byok_in_limit);
}

#[test]
fn a_resource_may_override_the_inherited_default() {
    let config = parse(
        r#"
version = 1
[defaults]
include_byok_in_limit = true
[guardrails.cheap]
name = "cheap"
include_byok_in_limit = false
[keys.jobfeed]
name = "jobfeed"
"#,
    );
    assert!(config.defaults.include_byok_in_limit);
    assert!(key(&config, "jobfeed").include_byok_in_limit);
    assert!(!guardrail(&config, "cheap").include_byok_in_limit);
}

#[test]
fn omitted_optional_fields_are_unmanaged() {
    let config = parse(MINIMAL);
    let key = key(&config, "jobfeed");
    assert_eq!(key.limit, Managed::Unmanaged);
    assert_eq!(key.expires_at, Managed::Unmanaged);
    assert_eq!(key.guardrail, Managed::Unmanaged);
    assert_eq!(key.generation, 1);
    assert!(!key.disabled);
    assert_eq!(guardrail(&config, "cheap").description, Managed::Unmanaged);
    assert_eq!(guardrail(&config, "cheap").allowed_models, None);
    assert_eq!(guardrail(&config, "cheap").require_zdr, None);
}

// --- explicit clearing -----------------------------------------------------

#[test]
fn naming_a_field_in_clear_is_the_explicit_null() {
    let config = parse(
        r#"
version = 1
[guardrails.cheap]
name = "cheap"
clear = ["description", "limit_usd", "reset_interval"]
[keys.jobfeed]
name = "jobfeed"
clear = ["limit_usd", "limit_reset", "expires_at", "guardrail"]
"#,
    );
    let guardrail = guardrail(&config, "cheap");
    assert_eq!(guardrail.description, Managed::Cleared);
    assert_eq!(guardrail.limit, Managed::Cleared);
    assert_eq!(guardrail.reset_interval, Managed::Cleared);

    let key = key(&config, "jobfeed");
    assert_eq!(key.limit, Managed::Cleared);
    assert_eq!(key.limit_reset, Managed::Cleared);
    assert_eq!(key.expires_at, Managed::Cleared);
    assert_eq!(key.guardrail, Managed::Cleared);
    assert!(key.expires_at.is_managed());
    assert_eq!(key.expires_at.value(), None);
}

#[test]
fn a_field_cannot_be_both_set_and_cleared() {
    assert_eq!(
        paths(
            r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
expires_at = "2027-01-01T00:00:00Z"
clear = ["expires_at"]
"#,
        ),
        ["keys.jobfeed.expires_at"]
    );
}

#[test]
fn only_clearable_fields_may_be_cleared() {
    let problems = problems(
        r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
clear = ["name"]
"#,
    );
    assert_eq!(problems[0].path, "keys.jobfeed.clear[0]");
    assert!(problems[0].message.contains("cannot be cleared"));
}

// --- references ------------------------------------------------------------

#[test]
fn references_resolve_to_configured_addresses() {
    let config = parse(
        r#"
version = 1
[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"
[guardrails.cheap]
name = "cheap"
[keys.jobfeed]
name = "jobfeed"
guardrail = "cheap"
receiver = "vault"
"#,
    );
    let key = key(&config, "jobfeed");
    assert_eq!(key.guardrail, Managed::Set(address("cheap")));
    assert_eq!(key.receiver, Some(address("vault")));
}

#[test]
fn dangling_references_are_rejected() {
    assert_eq!(
        paths(
            r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
guardrail = "absent"
receiver = "absent"
"#,
        ),
        ["keys.jobfeed.guardrail", "keys.jobfeed.receiver"]
    );
}

// --- receivers -------------------------------------------------------------

#[test]
fn both_receiver_shapes_parse() {
    let config = parse(
        r#"
version = 1
[receivers.to_file]
type = "file"
path = "/var/lib/keymaster/one.key"
[receivers.to_command]
type = "command"
program = "/usr/local/bin/receiver"
args = ["add-file", "var_name"]
"#,
    );
    assert_eq!(
        config.receivers[&address("to_file")],
        Receiver::File {
            path: "/var/lib/keymaster/one.key".into()
        }
    );
    assert_eq!(
        config.receivers[&address("to_command")],
        Receiver::Command {
            program: "/usr/local/bin/receiver".into(),
            args: vec!["add-file".to_owned(), "var_name".to_owned()],
        }
    );
}

#[test]
fn a_caller_receiver_carries_only_its_destination() {
    let config = parse(
        r#"
version = 1
[receivers.host]
type = "caller"
destination = "  vault/jobfeed  "
"#,
    );
    assert_eq!(
        config.receivers[&address("host")],
        Receiver::Caller {
            destination: "vault/jobfeed".to_owned()
        },
        "a destination is trimmed like every other single-line human string"
    );
}

#[test]
fn a_caller_destination_must_be_present_bounded_and_not_a_credential() {
    let caller = |field: &str| {
        format!(
            r#"
version = 1
[receivers.host]
type = "caller"
{field}
"#
        )
    };

    assert_eq!(paths(&caller("")), ["receivers.host.destination"]);
    assert_eq!(
        paths(&caller(r#"destination = "   ""#)),
        ["receivers.host.destination"]
    );
    assert_eq!(
        paths(&caller(&format!(r#"destination = "{}""#, "d".repeat(201)))),
        ["receivers.host.destination"]
    );

    let refused = problems(&caller(&format!(
        r#"destination = "{SECRET_SENTINEL_KEY}""#
    )));
    assert_eq!(refused.len(), 1);
    assert!(refused[0].message.contains("looks like a credential"));
    assert!(
        !refused[0].message.contains("sk-or-"),
        "and the value is not echoed back: {}",
        refused[0].message
    );
}

/// The fingerprint of the one receiver in a configuration.
fn fingerprint_of(source: &str) -> String {
    let config = parse(source);
    let (address, receiver) = config
        .receivers
        .iter()
        .next()
        .expect("one configured receiver");
    receiver.fingerprint(address).as_str().to_owned()
}

#[test]
fn a_receiver_fingerprint_is_a_hex_digest_that_does_not_change_between_runs() {
    const SOURCE: &str = r#"
version = 1
[receivers.to_file]
type = "file"
path = "/var/lib/keymaster/one.key"
"#;
    let fingerprint = fingerprint_of(SOURCE);
    assert_eq!(fingerprint.len(), 64);
    assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(fingerprint, fingerprint_of(SOURCE));
}

#[test]
fn different_receivers_have_different_fingerprints() {
    let command = |args: &str| {
        fingerprint_of(&format!(
            r#"
version = 1
[receivers.to_command]
type = "command"
program = "/usr/local/bin/receiver"
args = {args}
"#
        ))
    };

    // The preimage length-prefixes each argument, so an argument containing a
    // separator cannot look like two arguments.
    assert_ne!(command(r#"["a b"]"#), command(r#"["a", "b"]"#));
    assert_ne!(command("[]"), command(r#"[""]"#));
    assert_ne!(command(r#"["a"]"#), command(r#"["a", ""]"#));

    let file = fingerprint_of(
        r#"
version = 1
[receivers.to_file]
type = "file"
path = "/usr/local/bin/receiver"
"#,
    );
    assert_ne!(file, command("[]"), "the kind is part of the preimage");

    // A `caller` is identified by the block a host wires code up to and the
    // destination that block names, so both are in its preimage (ADR-0005).
    let caller = |block: &str, destination: &str| {
        fingerprint_of(&format!(
            r#"
version = 1
[receivers.{block}]
type = "caller"
destination = "{destination}"
"#
        ))
    };
    assert_eq!(
        caller("host", "vault/jobfeed"),
        caller("host", "vault/jobfeed")
    );
    assert_ne!(
        caller("host", "vault/jobfeed"),
        caller("host", "vault/other")
    );
    assert_ne!(
        caller("host", "vault/jobfeed"),
        caller("elsewhere", "vault/jobfeed")
    );
}

#[test]
fn receiver_paths_and_arguments_must_not_carry_control_characters() {
    // A NUL cannot survive the conversion the operating system requires, so a
    // receiver configured with one fails at delivery — after a key exists and
    // its plaintext is in hand. Refusing it here costs nothing; refusing it
    // there costs a key. Written as TOML escapes so this file stays printable.
    let problems = problems(
        r#"
version = 1
[receivers.nul_path]
type = "file"
path = "/var/lib/keymaster/on\u0000e.key"
[receivers.nul_program]
type = "command"
program = "/usr/local/bin/rec\u0000eiver"
args = []
[receivers.control_arg]
type = "command"
program = "/usr/local/bin/receiver"
args = ["add-file", "va\u0000r", "line\u000Abreak"]
"#,
    );
    let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "receivers.control_arg.args[1]",
            "receivers.control_arg.args[2]",
            "receivers.nul_path.path",
            "receivers.nul_program.program",
        ]
    );
    for problem in &problems {
        assert!(
            problem.message.contains("control characters"),
            "{}",
            problem.message
        );
        assert!(!problem.message.contains('\u{0}'));
    }
}

#[test]
fn receiver_paths_and_arguments_keep_spaces_and_other_ordinary_text() {
    // Unlike a slug, a path is not an identifier: a space or non-ASCII text in
    // one is ordinary, and refusing it would be wrong.
    let config = parse(
        r#"
version = 1
[receivers.spaced]
type = "command"
program = "/usr/local/bin/my receiver"
args = ["--label", "Ansible Vault (caf\u00E9)"]
"#,
    );
    assert_eq!(
        config.receivers[&address("spaced")],
        Receiver::Command {
            program: "/usr/local/bin/my receiver".into(),
            args: vec!["--label".to_owned(), "Ansible Vault (caf\u{e9})".to_owned()],
        }
    );
}

#[test]
fn receiver_paths_must_be_absolute_and_free_of_parent_components() {
    assert_eq!(
        paths(
            r#"
version = 1
[receivers.relative]
type = "file"
path = "secrets/key"
[receivers.climbing]
type = "command"
program = "/usr/local/bin/../../bin/sh"
"#,
        ),
        ["receivers.climbing.program", "receivers.relative.path"]
    );
}

// --- validation classes ----------------------------------------------------

#[test]
fn the_schema_version_must_be_present_and_known() {
    assert_eq!(paths("[keys]\n"), ["version"]);
    let problems = problems("version = 2\n");
    assert_eq!(problems[0].path, "version");
    assert!(problems[0].message.contains("unsupported schema version 2"));
}

#[test]
fn local_addresses_may_not_differ_by_letter_case_alone() {
    let problems = problems(
        r#"
version = 1
[keys.jobfeed]
name = "one"
[keys.JobFeed]
name = "two"
"#,
    );
    assert_eq!(problems[0].path, "keys.jobfeed");
    assert!(problems[0].message.contains("duplicates the local address"));
}

#[test]
fn malformed_local_addresses_are_rejected() {
    let problems = problems(
        r#"
version = 1
[keys."has space"]
name = "one"
"#,
    );
    assert_eq!(problems[0].path, "keys.has space");
    assert!(problems[0].message.contains("local address"));
}

#[test]
fn remote_names_must_be_present_and_non_empty() {
    assert_eq!(
        paths(
            r#"
version = 1
[guardrails.cheap]
description = "no name"
[keys.jobfeed]
name = "   "
"#,
        ),
        ["guardrails.cheap.name", "keys.jobfeed.name"]
    );
}

#[test]
fn two_resources_of_a_kind_may_not_share_a_remote_name() {
    let problems = problems(
        r#"
version = 1
[keys.one]
name = "shared"
[keys.two]
name = "shared"
"#,
    );
    assert_eq!(problems[0].path, "keys.two.name");
    assert!(problems[0].message.contains("duplicates the remote name"));
}

#[test]
fn timestamps_must_be_rfc_3339() {
    assert_eq!(
        paths(
            r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
expires_at = "2027-01-01"
"#,
        ),
        ["keys.jobfeed.expires_at"]
    );
}

#[test]
fn workspace_ids_must_be_uuids() {
    assert_eq!(
        paths(
            r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
workspace_id = "not-a-uuid"
"#,
        ),
        ["keys.jobfeed.workspace_id"]
    );
}

#[test]
fn a_creator_is_an_opaque_member_identifier() {
    let config = parse(
        r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
creator_user_id = "user_2dHFtVWx2n56w6HkM0000000000"
"#,
    );
    assert_eq!(
        config.keys[&address("jobfeed")]
            .creator_user_id
            .as_ref()
            .map(|user| user.as_str()),
        Some("user_2dHFtVWx2n56w6HkM0000000000")
    );

    // Not one token, so it is a pasted mistake rather than an identifier.
    assert_eq!(
        paths(
            r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
creator_user_id = "user one"
"#,
        ),
        ["keys.jobfeed.creator_user_id"]
    );
}

#[test]
fn budgets_must_be_non_negative_and_representable() {
    let problems = problems(
        r#"
version = 1
[keys.negative]
name = "negative"
limit_usd = -1
[keys.precise]
name = "precise"
limit_usd = 0.00000001
[keys.huge]
name = "huge"
limit_usd = 1000000001
[guardrails.infinite]
name = "infinite"
limit_usd = inf
"#,
    );
    let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "guardrails.infinite.limit_usd",
            "keys.huge.limit_usd",
            "keys.negative.limit_usd",
            "keys.precise.limit_usd",
        ]
    );
    assert!(problems[2].message.contains("must not be negative"));
}

#[test]
fn a_guardrail_budget_must_be_greater_than_zero() {
    // Live: `POST /guardrails` with `limit_usd = 0` is a 400, "Too small:
    // expected number to be >0". The OpenAPI document does not say so.
    let problems = problems(
        r#"
version = 1
[guardrails.free]
name = "free"
limit_usd = 0
reset_interval = "daily"
"#,
    );
    let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(paths, ["guardrails.free.limit_usd"]);
    assert!(problems[0].message.contains("greater than zero"));
}

#[test]
fn a_key_budget_of_zero_is_a_cap_the_api_accepts() {
    // Live: `POST /keys` with `limit: 0` is a 201, and the key comes back with
    // `limit_remaining: 0`. Only guardrails carry the positive minimum.
    let config = parse(
        r#"
version = 1
[keys.spent]
name = "spent"
limit_usd = 0
limit_reset = "daily"
"#,
    );
    let Managed::Set(limit) = key(&config, "spent").limit else {
        panic!("a limit was configured");
    };
    assert_eq!(limit.micros(), 0);
}

#[test]
fn reset_intervals_must_be_one_of_the_supported_three() {
    assert_eq!(
        paths(
            r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
limit_usd = 5
limit_reset = "quarterly"
"#,
        ),
        ["keys.jobfeed.limit_reset"]
    );
}

#[test]
fn a_reset_interval_without_a_budget_is_incompatible() {
    let problems = problems(
        r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
limit_reset = "monthly"
[guardrails.cheap]
name = "cheap"
reset_interval = "daily"
clear = ["limit_usd"]
"#,
    );
    let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "guardrails.cheap.reset_interval",
            "keys.jobfeed.limit_reset"
        ]
    );
    assert!(problems[1].message.contains("no budget to reset"));
}

#[test]
fn a_guardrail_budget_without_a_reset_interval_is_incompatible() {
    let problems = problems(
        r#"
version = 1
[guardrails.cheap]
name = "cheap"
limit_usd = 10
"#,
    );
    let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(paths, ["guardrails.cheap.reset_interval"]);
    assert!(
        problems[0]
            .message
            .contains("a budget needs `reset_interval`")
    );
}

#[test]
fn clearing_a_guardrails_reset_interval_still_leaves_its_budget_unpaired() {
    assert_eq!(
        paths(
            r#"
version = 1
[guardrails.cheap]
name = "cheap"
limit_usd = 10
clear = ["reset_interval"]
"#,
        ),
        ["guardrails.cheap.reset_interval"]
    );
}

#[test]
fn a_budget_is_accepted_with_its_interval_and_so_is_no_budget_at_all() {
    // A key budget needs no interval: OpenRouter documents a null
    // `limit_reset` as a limit that never resets.
    let config = parse(
        r#"
version = 1
[guardrails.paired]
name = "paired"
limit_usd = 10
reset_interval = "monthly"
[guardrails.unbudgeted]
name = "unbudgeted"
[keys.capped]
name = "capped"
limit_usd = 5
"#,
    );
    assert_eq!(
        config.guardrails[&address("paired")].reset_interval,
        Managed::Set(ResetInterval::Monthly)
    );
    assert_eq!(
        config.guardrails[&address("unbudgeted")].limit,
        Managed::Unmanaged
    );
    assert_eq!(
        config.keys[&address("capped")].limit_reset,
        Managed::Unmanaged
    );
}

#[test]
fn generations_must_be_whole_numbers_of_at_least_one() {
    assert_eq!(
        paths(
            r#"
version = 1
[keys.zero]
name = "zero"
generation = 0
[keys.negative]
name = "negative"
generation = -3
"#,
        ),
        ["keys.negative.generation", "keys.zero.generation"]
    );
}

#[test]
fn model_and_provider_entries_must_be_usable_slugs() {
    // A slug reaches a plan, a log, and the wire, so a control sequence or a
    // bidirectional override in one is refused the same as a space is. The
    // fixture writes them as TOML escapes so the test file itself stays
    // printable.
    let problems = problems(
        r#"
version = 1
[guardrails.cheap]
name = "cheap"
allowed_models = ["", "has space", "\u001B[31mred", "goo\u202Egle/x"]
denied_providers = ["ok-provider"]
"#,
    );
    let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "guardrails.cheap.allowed_models[0]",
            "guardrails.cheap.allowed_models[1]",
            "guardrails.cheap.allowed_models[2]",
            "guardrails.cheap.allowed_models[3]",
        ]
    );
    for problem in &problems[1..] {
        assert!(
            problem.message.contains("printable ASCII"),
            "{}",
            problem.message
        );
    }
    for problem in &problems {
        assert!(!problem.message.contains('\u{1b}'));
        assert!(!problem.message.contains('\u{202e}'));
    }
}

#[test]
fn an_unknown_field_is_a_syntax_error_rather_than_a_silent_ignore() {
    let error = Config::parse(
        r#"
version = 1
[keys.jobfeed]
name = "jobfeed"
api_key = "whatever"
"#,
    )
    .expect_err("an unknown field is rejected");
    assert_eq!(error.kind(), "config_syntax");
}

#[test]
fn every_problem_is_reported_in_one_pass() {
    let problems = problems(
        r#"
version = 9
[keys.jobfeed]
name = ""
limit_usd = -1
expires_at = "yesterday"
workspace_id = "nope"
generation = 0
guardrail = "absent"
"#,
    );
    let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "keys.jobfeed.expires_at",
            "keys.jobfeed.generation",
            "keys.jobfeed.guardrail",
            "keys.jobfeed.limit_usd",
            "keys.jobfeed.name",
            "keys.jobfeed.workspace_id",
            "version",
        ]
    );
}

#[test]
fn a_rejection_renders_every_problem() {
    let error = Config::parse("version = 9\n").expect_err("a rejection");
    let rendered = error.to_string();
    assert!(rendered.contains("1 problem:"), "{rendered}");
    assert!(rendered.contains("version:"), "{rendered}");
}

// --- credential refusal ----------------------------------------------------

#[test]
fn credential_shaped_values_are_refused_and_never_echoed() {
    let source = format!(
        r#"
version = 1
[receivers.vault]
type = "command"
program = "/usr/local/bin/receiver"
args = ["{SECRET_SENTINEL_KEY}"]
[keys.jobfeed]
name = "{SECRET_SENTINEL_KEY}"
[guardrails."{SECRET_SENTINEL_KEY}"]
name = "cheap"
"#
    );
    let problems = problems(&source);
    let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "guardrails.[redacted]",
            "keys.jobfeed.name",
            "receivers.vault.args[0]",
        ]
    );

    let rendered = Config::parse(&source).expect_err("a rejection").to_string();
    assert!(
        !rendered.contains("sk-or-"),
        "the rejection echoed a credential: {rendered}"
    );
}

#[test]
fn a_syntax_error_does_not_echo_a_credential() {
    let source = format!("version = \"{SECRET_SENTINEL_KEY}\"\n");
    let error = Config::parse(&source).expect_err("a rejection");
    assert_eq!(error.kind(), "config_syntax");
    assert!(
        !error.to_string().contains("sk-or-"),
        "the rejection echoed a credential: {error}"
    );
}

// --- normalization ---------------------------------------------------------

#[test]
fn slug_sets_are_sorted_lowercased_and_deduplicated() {
    let config = parse(
        r#"
version = 1
[guardrails.cheap]
name = "cheap"
allowed_models = ["OpenAI/GPT-4o-mini", " google/gemini-2.5-flash ", "openai/gpt-4o-mini"]
"#,
    );
    let models: Vec<&String> = guardrail(&config, "cheap")
        .allowed_models
        .as_ref()
        .expect("the configured models")
        .iter()
        .collect();
    assert_eq!(models, ["google/gemini-2.5-flash", "openai/gpt-4o-mini"]);
}

#[test]
fn timestamps_normalize_to_utc() {
    let config = parse(
        r#"
version = 1
[keys.a]
name = "a"
expires_at = "2026-12-31T19:00:00-05:00"
[keys.b]
name = "b"
expires_at = "2027-01-01T00:00:00Z"
"#,
    );
    assert_eq!(key(&config, "a").expires_at, key(&config, "b").expires_at);
    let Managed::Set(when) = key(&config, "a").expires_at else {
        panic!("an expiry was configured");
    };
    assert_eq!(when.offset(), time::UtcOffset::UTC);
}

#[test]
fn budgets_normalize_to_whole_millionths_of_a_dollar() {
    let config = parse(
        r#"
version = 1
[keys.a]
name = "a"
limit_usd = 10
[keys.b]
name = "b"
limit_usd = 10.0
[keys.c]
name = "c"
limit_usd = 1e1
[keys.d]
name = "d"
limit_usd = 0.1
"#,
    );
    assert_eq!(key(&config, "a").limit, key(&config, "b").limit);
    assert_eq!(key(&config, "a").limit, key(&config, "c").limit);
    assert_eq!(
        key(&config, "a").limit,
        Managed::Set(Usd::from_dollars(10.0).expect("ten dollars"))
    );

    let Managed::Set(dime) = key(&config, "d").limit else {
        panic!("a limit was configured");
    };
    assert_eq!(dime.micros(), 100_000);
    assert!((dime.dollars() - 0.1).abs() < f64::EPSILON);
    assert_eq!(dime.to_string(), "0.100000");
}

#[test]
fn parsing_the_same_text_twice_produces_the_same_configuration() {
    let source = include_str!("../../../../examples/openrouter-keymaster.toml");
    assert_eq!(parse(source), parse(source));
}

#[test]
fn reset_intervals_render_the_way_they_are_written() {
    assert_eq!(ResetInterval::Daily.to_string(), "daily");
    assert_eq!(ResetInterval::Weekly.as_str(), "weekly");
    assert_eq!(ResetInterval::Monthly.as_str(), "monthly");
}

// --- workspaces (ADR-0004) --------------------------------------------------

/// A workspace with everything a block can carry.
const WORKSPACE: &str = r#"
version = 1

[workspaces.club]
name = "Golf Club"
slug = "golf-club"
description = "the golf club's inference workspace"
budgets = { daily = 5, weekly = 20, monthly = 50, lifetime = 500 }
include_byok_in_budgets = true
default_guardrail = "house"

[guardrails.house]
name = "house-rail"
"#;

fn workspace<'a>(config: &'a Config, name: &str) -> &'a Workspace {
    config
        .workspaces
        .get(&address(name))
        .expect("the configured workspace")
}

#[test]
fn a_workspace_block_normalizes_into_the_desired_state() {
    let config = parse(WORKSPACE);
    let club = workspace(&config, "club");

    assert_eq!(club.name.as_str(), "Golf Club");
    assert_eq!(club.slug, "golf-club");
    assert_eq!(club.include_byok_in_budgets, Some(true));
    assert_eq!(club.default_guardrail.as_ref(), Some(&address("house")));
    assert_eq!(
        club.budgets.as_ref().expect("a managed budget table"),
        &BTreeMap::from([
            (BudgetInterval::Daily, Usd::from_dollars(5.0).expect("5")),
            (BudgetInterval::Weekly, Usd::from_dollars(20.0).expect("20")),
            (
                BudgetInterval::Monthly,
                Usd::from_dollars(50.0).expect("50")
            ),
            (
                BudgetInterval::Lifetime,
                Usd::from_dollars(500.0).expect("500")
            ),
        ])
    );
}

#[test]
fn a_slug_must_be_lowercase_segments_separated_by_single_hyphens() {
    for accepted in ["golf", "golf-club", "club2", "a-b-c", "0"] {
        let source =
            format!("version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"{accepted}\"\n");
        assert_eq!(
            parse(&source).workspaces[&address("club")].slug,
            accepted,
            "{accepted} is a slug OpenRouter accepts"
        );
    }
    for rejected in [
        "",
        "Golf-Club",
        "golf_club",
        "-golf",
        "golf-",
        "golf--club",
        "golf club",
        "golf.club",
        "gölf",
    ] {
        let source =
            format!("version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"{rejected}\"\n");
        assert_eq!(
            paths(&source),
            vec!["workspaces.club.slug"],
            "{rejected:?} is not a slug"
        );
    }
}

#[test]
fn a_slug_that_looks_like_a_credential_is_refused_without_echoing_it() {
    // A credential is already shaped like a slug — `sk-or-v1-…` is lowercase
    // alphanumeric segments separated by single hyphens — so the pattern check
    // cannot be what catches one.
    let source = "version = 1\n\n[workspaces.club]\nname = \"Club\"\n\
                  slug = \"sk-or-v1-deadbeef\"\n";
    let problems = problems(source);
    let [problem] = problems.as_slice() else {
        panic!("expected exactly one problem, not {problems:?}");
    };
    assert_eq!(problem.path, "workspaces.club.slug");
    assert!(
        problem.message.contains("credential"),
        "the answer is about the secret, not the pattern: {problem}"
    );

    let rendered = Config::parse(source).expect_err("a rejection").to_string();
    assert!(
        !rendered.contains("sk-or-"),
        "the rejection echoed a credential: {rendered}"
    );
}

#[test]
fn a_workspace_needs_a_name_and_a_slug() {
    assert_eq!(
        paths("version = 1\n\n[workspaces.club]\n"),
        vec!["workspaces.club.name", "workspaces.club.slug"]
    );
}

#[test]
fn budgets_must_grow_as_the_interval_widens() {
    // The server checks lifetime > monthly > weekly > daily on every write, so
    // a table that violates it can never be applied in any order.
    let source = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
                  budgets = { daily = 50, monthly = 20 }\n";
    assert_eq!(paths(source), vec!["workspaces.club.budgets.monthly"]);

    // Equal is not greater.
    let equal = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
                 budgets = { weekly = 20, monthly = 20 }\n";
    assert_eq!(paths(equal), vec!["workspaces.club.budgets.monthly"]);

    // Only the intervals actually written are compared: a daily budget with no
    // weekly one is checked against the monthly one.
    let sparse = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
                  budgets = { daily = 5, lifetime = 500 }\n";
    assert!(Config::parse(sparse).is_ok());
}

#[test]
fn a_workspace_budget_must_be_greater_than_zero() {
    // `PUT /workspaces/{id}/budgets/{interval}` documents `limit_usd` as "Must
    // be greater than 0", so every interval carries the same minimum.
    for interval in ["daily", "weekly", "monthly", "lifetime"] {
        let source = format!(
            "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
             budgets = {{ {interval} = 0 }}\n"
        );
        let problems = problems(&source);
        let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, [format!("workspaces.club.budgets.{interval}")]);
        assert!(problems[0].message.contains("greater than zero"));
    }
}

#[test]
fn byok_in_budgets_needs_a_budget_to_travel_with() {
    // OpenRouter writes the setting only as part of a budget `PUT`, so there is
    // no request a configuration without one could carry it in.
    for source in [
        "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
         include_byok_in_budgets = true\n",
        "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
         budgets = {}\ninclude_byok_in_budgets = false\n",
    ] {
        assert_eq!(
            paths(source),
            vec!["workspaces.club.include_byok_in_budgets"],
            "{source}"
        );
    }
}

#[test]
fn a_budget_that_does_not_validate_is_the_only_thing_reported() {
    // The block has a budget; it is wrong. Saying it "needs at least one"
    // beside that would be false, and would bury the problem there is to fix.
    let source = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
                  budgets = { monthly = 0 }\ninclude_byok_in_budgets = true\n";
    assert_eq!(paths(source), vec!["workspaces.club.budgets.monthly"]);

    let ordering = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
                    budgets = { daily = 50, monthly = 20 }\ninclude_byok_in_budgets = true\n";
    assert_eq!(paths(ordering), vec!["workspaces.club.budgets.monthly"]);
}

#[test]
fn a_guardrail_is_the_default_of_at_most_one_workspace() {
    let source = "version = 1\n\n[workspaces.one]\nname = \"One\"\nslug = \"one\"\n\
                  default_guardrail = \"house\"\n\n\
                  [workspaces.two]\nname = \"Two\"\nslug = \"two\"\n\
                  default_guardrail = \"house\"\n\n\
                  [guardrails.house]\nname = \"house-rail\"\n";
    assert_eq!(paths(source), vec!["workspaces.two.default_guardrail"]);
}

#[test]
fn a_default_guardrail_belongs_to_its_own_workspace() {
    let elsewhere = "version = 1\n\n[workspaces.one]\nname = \"One\"\nslug = \"one\"\n\
                     default_guardrail = \"house\"\n\n\
                     [workspaces.two]\nname = \"Two\"\nslug = \"two\"\n\n\
                     [guardrails.house]\nname = \"house-rail\"\nworkspace = \"two\"\n";
    assert_eq!(paths(elsewhere), vec!["guardrails.house.workspace"]);

    // Omitted and equal are both fine.
    for placement in ["", "workspace = \"one\"\n"] {
        let source = format!(
            "version = 1\n\n[workspaces.one]\nname = \"One\"\nslug = \"one\"\n\
             default_guardrail = \"house\"\n\n[guardrails.house]\nname = \"house-rail\"\n{placement}"
        );
        assert!(Config::parse(&source).is_ok(), "{source}");
    }
}

#[test]
fn a_default_guardrail_must_be_a_configured_block() {
    let source = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
                  default_guardrail = \"missing\"\n";
    assert_eq!(paths(source), vec!["workspaces.club.default_guardrail"]);
}

#[test]
fn a_block_names_its_workspace_by_address_or_by_uuid_and_never_both() {
    let base = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\n\
                [receivers.vault]\ntype = \"file\"\npath = \"/tmp/vault.key\"\n\n";
    let both = format!(
        "{base}[keys.jobfeed]\nname = \"jobfeed\"\nreceiver = \"vault\"\n\
         workspace = \"club\"\nworkspace_id = \"00000000-0000-4000-8000-000000000001\"\n"
    );
    assert_eq!(paths(&both), vec!["keys.jobfeed.workspace"]);

    let rail = format!(
        "{base}[guardrails.house]\nname = \"house-rail\"\n\
         workspace = \"club\"\nworkspace_id = \"00000000-0000-4000-8000-000000000001\"\n"
    );
    assert_eq!(paths(&rail), vec!["guardrails.house.workspace"]);

    let one = format!("{base}[guardrails.house]\nname = \"house-rail\"\nworkspace = \"club\"\n");
    assert_eq!(
        parse(&one).guardrails[&address("house")].workspace.as_ref(),
        Some(&address("club"))
    );
}

#[test]
fn a_workspace_reference_must_name_a_configured_block() {
    let source = "version = 1\n\n[receivers.vault]\ntype = \"file\"\npath = \"/tmp/vault.key\"\n\n\
                  [keys.jobfeed]\nname = \"jobfeed\"\nreceiver = \"vault\"\n\
                  workspace = \"missing\"\n";
    assert_eq!(paths(source), vec!["keys.jobfeed.workspace"]);
}

#[test]
fn a_workspace_description_can_be_cleared() {
    let source = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
                  clear = [\"description\"]\n";
    assert_eq!(
        parse(source).workspaces[&address("club")].description,
        Managed::Cleared
    );

    let both = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
                description = \"a club\"\nclear = [\"description\"]\n";
    assert_eq!(paths(both), vec!["workspaces.club.description"]);
}

#[test]
fn a_misspelled_budget_interval_is_a_syntax_error_rather_than_a_silent_omission() {
    let source = "version = 1\n\n[workspaces.club]\nname = \"Club\"\nslug = \"club\"\n\
                  budgets = { montly = 50 }\n";
    let error = Config::parse(source).expect_err("an unknown budget interval is rejected");
    assert_eq!(error.kind(), "config_syntax", "{error}");
}

#[test]
fn a_default_guardrail_takes_its_placement_from_the_relationship_and_not_a_uuid() {
    // Being a workspace's default *is* the placement, so a second spelling of
    // it can only disagree — and nothing offline can check a raw UUID against a
    // workspace whose identity is whatever its binding says.
    let source = "version = 1\n\n[workspaces.one]\nname = \"One\"\nslug = \"one\"\n\
                  default_guardrail = \"house\"\n\n[guardrails.house]\nname = \"house-rail\"\n\
                  workspace_id = \"00000000-0000-4000-8000-000000000001\"\n";
    assert_eq!(paths(source), vec!["guardrails.house.workspace_id"]);

    // A guardrail that is nobody's default may name one freely.
    let ordinary = "version = 1\n\n[guardrails.house]\nname = \"house-rail\"\n\
                    workspace_id = \"00000000-0000-4000-8000-000000000001\"\n";
    assert!(Config::parse(ordinary).is_ok());
}

// --- log destinations (ADR-0006) --------------------------------------------

/// A block with the two required fields and whatever else a case adds.
fn destination_source(extra: &str) -> String {
    format!(
        "version = 1\n\n[log_destinations.audit]\ntype = \"datadog\"\nname = \"Club audit\"\n\
         config = {{ site = \"datadoghq.com\", apiKey = \"dd-XXXXXXXXXXXXXXXXXXXX\" }}\n{extra}"
    )
}

fn destination<'a>(config: &'a Config, name: &str) -> &'a LogDestination {
    config
        .log_destinations
        .get(&address(name))
        .expect("the configured log destination")
}

#[test]
fn a_destination_takes_openrouters_own_defaults_for_what_it_does_not_say() {
    let parsed = parse(&destination_source(""));
    let audit = destination(&parsed, "audit");
    assert_eq!(audit.kind, DestinationType::Datadog);
    assert_eq!(audit.name.as_str(), "Club audit");
    assert!(audit.enabled, "OpenRouter creates a destination enabled");
    assert!(!audit.privacy_mode);
    assert_eq!(audit.sampling_rate, None, "unmanaged unless it is written");
    assert_eq!(audit.workspace, None);
    assert_eq!(audit.workspace_id, None);
}

#[test]
fn a_type_or_a_configuration_the_schema_refuses_names_its_field() {
    let unknown = "version = 1\n\n[log_destinations.audit]\ntype = \"splunk\"\n\
                   name = \"Club audit\"\nconfig = { apiKey = \"x-XXXXXXXXXXXXXXXX\" }\n";
    assert_eq!(paths(unknown), vec!["log_destinations.audit.type"]);

    let missing = "version = 1\n\n[log_destinations.audit]\ntype = \"datadog\"\n\
                   name = \"Club audit\"\n";
    assert_eq!(paths(missing), vec!["log_destinations.audit.config"]);

    let empty = "version = 1\n\n[log_destinations.audit]\ntype = \"datadog\"\n\
                 name = \"Club audit\"\nconfig = {}\n";
    assert_eq!(paths(empty), vec!["log_destinations.audit.config"]);
}

#[test]
fn a_sampling_rate_outside_the_range_openrouter_accepts_is_refused() {
    for rate in ["0", "1.5", "0.00001"] {
        assert_eq!(
            paths(&destination_source(&format!("sampling_rate = {rate}\n"))),
            vec!["log_destinations.audit.sampling_rate"],
            "{rate}"
        );
    }
    let managed = parse(&destination_source("sampling_rate = 0.25\n"));
    assert_eq!(
        destination(&managed, "audit").sampling_rate,
        SamplingRate::from_rate(0.25).ok()
    );
}

#[test]
fn a_destination_names_its_workspace_by_address_or_by_uuid_and_never_both() {
    let both = destination_source(
        "workspace = \"club\"\nworkspace_id = \"00000000-0000-4000-8000-000000000001\"\n\n\
         [workspaces.club]\nname = \"Club\"\nslug = \"club\"\n",
    );
    assert_eq!(paths(&both), vec!["log_destinations.audit.workspace"]);

    let dangling = destination_source("workspace = \"club\"\n");
    assert_eq!(paths(&dangling), vec!["log_destinations.audit.workspace"]);
}

#[test]
fn two_destinations_may_not_share_a_remote_name() {
    let source = "version = 1\n\n[log_destinations.one]\ntype = \"datadog\"\nname = \"Audit\"\n\
                  config = { apiKey = \"a-XXXXXXXXXXXXXXXX\" }\n\n\
                  [log_destinations.two]\ntype = \"webhook\"\nname = \"Audit\"\n\
                  config = { url = \"https://example.invalid/hook\" }\n";
    assert_eq!(paths(source), vec!["log_destinations.two.name"]);
}

#[test]
fn loading_a_configuration_registers_its_destination_secrets_with_the_redactor() {
    // `Config::parse` is pure and registers nothing; `Config::load` is the one
    // that takes charge of the file, and the one an operation calls
    // (ADR-0006, item 4).
    const PROVIDER_TOKEN: &str = "dd-CONFIG-UNIT-TEST-TOKEN-NEVER-DISCLOSE";
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("keymaster.toml");
    std::fs::write(
        &path,
        format!(
            "version = 1\n\n[log_destinations.audit]\ntype = \"datadog\"\nname = \"Club audit\"\n\
             config = {{ region = \"eu\", apiKey = \"{PROVIDER_TOKEN}\" }}\n"
        ),
    )
    .expect("writing the configuration");

    Config::load(&path).expect("a valid configuration");

    assert_eq!(
        crate::redaction::redact(&format!("refused {PROVIDER_TOKEN} outright")),
        "refused [redacted] outright"
    );
    assert_eq!(
        crate::redaction::redact("the region is eu"),
        "the region is eu",
        "a short value is not registered, so it is not scrubbed out of every sentence"
    );
}
