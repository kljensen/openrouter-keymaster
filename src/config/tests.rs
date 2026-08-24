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
    let config = parse(include_str!("../../examples/openrouter-keymaster.toml"));
    assert_eq!(config.guardrails.len(), 1);
    assert_eq!(config.keys.len(), 1);
    assert_eq!(config.receivers.len(), 2);

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

    parse(include_str!("../../examples/openrouter-keymaster.toml"));

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

/// The fingerprint of the one receiver in a configuration.
fn fingerprint_of(source: &str) -> String {
    let config = parse(source);
    config
        .receivers
        .values()
        .next()
        .expect("one configured receiver")
        .fingerprint()
        .as_str()
        .to_owned()
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
    let source = include_str!("../../examples/openrouter-keymaster.toml");
    assert_eq!(parse(source), parse(source));
}

#[test]
fn reset_intervals_render_the_way_they_are_written() {
    assert_eq!(ResetInterval::Daily.to_string(), "daily");
    assert_eq!(ResetInterval::Weekly.as_str(), "weekly");
    assert_eq!(ResetInterval::Monthly.as_str(), "monthly");
}
