//! The TOML document, exactly as written on disk.
//!
//! These types mirror the file's syntax and nothing else. Every field that a
//! human can get wrong is deserialized as loosely as the syntax allows — names
//! are `String`, addresses are `String`, timestamps are `String` — so that
//! [`super::validate`] can report every mistake in one pass instead of
//! stopping at the first one serde rejects.
//!
//! Requiredness is deliberately not expressed here either: a missing `name` is
//! an `Option` that validation reports against its configuration path, not a
//! deserializer error naming a Rust type.
//!
//! `deny_unknown_fields` is on every table. It is what makes a stray
//! `api_key = "…"` a hard error rather than an ignored field, so credential
//! plaintext cannot sit unnoticed in a checked-in configuration file.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The whole configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Document {
    /// Schema version. Optional here so a missing version is reported as a
    /// validation problem rather than a deserializer error.
    pub(super) version: Option<u32>,

    #[serde(default)]
    pub(super) defaults: Defaults,

    #[serde(default)]
    pub(super) workspaces: BTreeMap<String, Workspace>,

    #[serde(default)]
    pub(super) guardrails: BTreeMap<String, Guardrail>,

    #[serde(default)]
    pub(super) keys: BTreeMap<String, Key>,

    #[serde(default)]
    pub(super) receivers: BTreeMap<String, Receiver>,
}

/// One `[workspaces.<address>]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Workspace {
    pub(super) name: Option<String>,
    pub(super) slug: Option<String>,
    pub(super) description: Option<String>,
    pub(super) budgets: Option<Budgets>,
    pub(super) include_byok_in_budgets: Option<bool>,
    pub(super) default_guardrail: Option<String>,

    /// See [`Guardrail::clear`].
    #[serde(default)]
    pub(super) clear: Vec<String>,
}

/// The `budgets` table of a workspace block.
///
/// Four named fields rather than a map, so `budgets = { montly = 10 }` is a
/// deserializer error naming the table rather than a budget silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Budgets {
    pub(super) daily: Option<Number>,
    pub(super) weekly: Option<Number>,
    pub(super) monthly: Option<Number>,
    pub(super) lifetime: Option<Number>,
}

/// The `[defaults]` table.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Defaults {
    pub(super) include_byok_in_limit: Option<bool>,
}

/// One `[guardrails.<address>]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Guardrail {
    pub(super) name: Option<String>,
    pub(super) description: Option<String>,
    pub(super) allowed_models: Option<Vec<String>>,
    pub(super) denied_models: Option<Vec<String>>,
    pub(super) allowed_providers: Option<Vec<String>>,
    pub(super) denied_providers: Option<Vec<String>>,
    pub(super) limit_usd: Option<Number>,
    pub(super) reset_interval: Option<String>,
    pub(super) include_byok_in_limit: Option<bool>,
    pub(super) require_zdr: Option<bool>,
    pub(super) workspace: Option<String>,
    pub(super) workspace_id: Option<String>,

    /// Fields to clear remotely. TOML has no null literal, so this list is how
    /// a configuration distinguishes "leave the remote value alone" (omit the
    /// field) from "set the remote value to nothing" (name it here).
    #[serde(default)]
    pub(super) clear: Vec<String>,
}

/// One `[keys.<address>]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Key {
    pub(super) name: Option<String>,
    pub(super) limit_usd: Option<Number>,
    pub(super) limit_reset: Option<String>,
    pub(super) expires_at: Option<String>,
    pub(super) disabled: Option<bool>,
    pub(super) workspace: Option<String>,
    pub(super) workspace_id: Option<String>,
    pub(super) creator_user_id: Option<String>,
    pub(super) guardrail: Option<String>,
    pub(super) receiver: Option<String>,
    pub(super) generation: Option<i64>,
    pub(super) include_byok_in_limit: Option<bool>,

    /// See [`Guardrail::clear`].
    #[serde(default)]
    pub(super) clear: Vec<String>,
}

/// One `[receivers.<address>]` table, chosen by its `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Receiver {
    /// Writes the plaintext to one file. For local development and tests.
    File { path: Option<String> },

    /// Runs a program and hands it the plaintext on stdin.
    Command {
        program: Option<String>,
        #[serde(default)]
        args: Vec<String>,
    },

    /// Hands the plaintext to the host's own code (ADR-0005).
    Caller { destination: Option<String> },
}

/// A TOML number, before it is interpreted as an amount of money.
///
/// Accepting both shapes keeps `limit_usd = 10` and `limit_usd = 10.50` equally
/// natural to write; [`super::Usd`] normalizes them to one representation.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(untagged)]
pub(super) enum Number {
    Integer(i64),
    Float(f64),
}
