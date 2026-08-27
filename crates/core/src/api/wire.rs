//! Wire types: the JSON OpenRouter actually sends.
//!
//! These are separate from the observed domain types on purpose. They are
//! shaped by the API — `f64` budgets, string timestamps, `ignored_models` for
//! what the configuration calls denied models — and they change when OpenRouter
//! changes. Nothing outside this module sees them.
//!
//! These are read-only responses, which is why nothing here clears itself the
//! way `client::create` does: OpenRouter discloses a key's plaintext only in
//! the create response, and the one credential-adjacent field a read returns —
//! `label`, a truncated prefix of the key — is deliberately not modelled.
//!
//! Two deserialization rules matter. Unknown fields are ignored, so a field
//! added to the API tomorrow does not stop a plan today. And only the immutable
//! identity of a resource is required: everything else defaults, because a
//! response that omits a budget is a key without one, while a response that
//! omits a hash is not a key at all.

use serde::Deserialize;

/// A list response. `total_count` is documented for guardrails and assignments
/// and absent for keys, so it is optional here and never trusted.
#[derive(Debug, Deserialize)]
pub(super) struct List<T> {
    pub data: Vec<T>,
    #[serde(default)]
    pub total_count: Option<u64>,
}

/// A single-resource response.
#[derive(Debug, Deserialize)]
pub(super) struct One<T> {
    pub data: T,
}

/// An API key as `GET /keys` and `GET /keys/{hash}` return it.
#[derive(Debug, Deserialize)]
pub(super) struct Key {
    pub hash: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub limit: Option<f64>,
    #[serde(default)]
    pub limit_reset: Option<String>,
    #[serde(default)]
    pub include_byok_in_limit: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub creator_user_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub limit_remaining: Option<f64>,
    #[serde(default)]
    pub usage: f64,
    #[serde(default)]
    pub usage_daily: f64,
    #[serde(default)]
    pub usage_weekly: f64,
    #[serde(default)]
    pub usage_monthly: f64,
    #[serde(default)]
    pub byok_usage: f64,
    #[serde(default)]
    pub byok_usage_daily: f64,
    #[serde(default)]
    pub byok_usage_weekly: f64,
    #[serde(default)]
    pub byok_usage_monthly: f64,
}

/// A guardrail as `GET /guardrails` and `GET /guardrails/{id}` return it.
#[derive(Debug, Deserialize)]
pub(super) struct Guardrail {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub allowed_models: Option<Vec<String>>,
    #[serde(default)]
    pub ignored_models: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_providers: Option<Vec<String>>,
    #[serde(default)]
    pub ignored_providers: Option<Vec<String>>,
    #[serde(default)]
    pub limit_usd: Option<f64>,
    #[serde(default)]
    pub reset_interval: Option<String>,
    #[serde(default)]
    pub include_byok_in_budgets: bool,
    /// Deprecated by OpenRouter in favour of the per-provider flags, and still
    /// returned.
    #[serde(default)]
    pub enforce_zdr: Option<bool>,
    #[serde(default)]
    pub enforce_zdr_anthropic: Option<bool>,
    #[serde(default)]
    pub enforce_zdr_google: Option<bool>,
    #[serde(default)]
    pub enforce_zdr_openai: Option<bool>,
    #[serde(default)]
    pub enforce_zdr_xai: Option<bool>,
    #[serde(default)]
    pub enforce_zdr_other: Option<bool>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// A guardrail as a write returns it.
///
/// The reads are documented to wrap a single resource in `data`, and a write
/// is expected to do the same. Accepting a bare object as well costs four
/// lines and avoids the worst outcome a create can have: a guardrail that
/// exists remotely and whose UUID Keymaster failed to read out of the
/// response, which is not recoverable by sending the request again.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum GuardrailEnvelope {
    Wrapped(One<Guardrail>),
    Bare(Guardrail),
}

impl GuardrailEnvelope {
    pub(super) fn into_guardrail(self) -> Guardrail {
        match self {
            Self::Wrapped(one) => one.data,
            Self::Bare(guardrail) => guardrail,
        }
    }
}

/// A workspace as `GET /workspaces` and `GET /workspaces/{id}` return it.
#[derive(Debug, Deserialize)]
pub(super) struct Workspace {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub description: Option<String>,
    /// A deterministic identity derived from the workspace's own, which the
    /// default guardrail is materialized under.
    #[serde(default)]
    pub default_guardrail_id: Option<String>,
    #[serde(default)]
    pub include_byok_in_budgets: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// A workspace as a write returns it. See [`GuardrailEnvelope`].
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum WorkspaceEnvelope {
    Wrapped(One<Workspace>),
    Bare(Workspace),
}

impl WorkspaceEnvelope {
    pub(super) fn into_workspace(self) -> Workspace {
        match self {
            Self::Wrapped(one) => one.data,
            Self::Bare(workspace) => workspace,
        }
    }
}

/// The budgets of one workspace, as `GET /workspaces/{id}/budgets` returns
/// them.
///
/// `include_byok_in_budgets` sits beside the list rather than inside each
/// budget, because it is one workspace-wide setting the budget endpoints are
/// the only way to write.
#[derive(Debug, Deserialize)]
pub(super) struct Budgets {
    pub data: Vec<Budget>,
    #[serde(default)]
    pub include_byok_in_budgets: bool,
}

/// One workspace budget. A `null` reset interval is a lifetime budget.
#[derive(Debug, Deserialize)]
pub(super) struct Budget {
    #[serde(default)]
    pub limit_usd: Option<f64>,
    #[serde(default)]
    pub reset_interval: Option<String>,
}

/// A log destination as `GET /observability/destinations` and
/// `GET /observability/destinations/{id}` return it.
///
/// `config` is deliberately absent. Reads mask its secret fields, so the value
/// that comes back compares equal to nothing in particular; the planner
/// compares digests instead (ADR-0006, item 3). Leaving the field out of this
/// type is what makes that structural rather than a rule to remember.
///
/// `filter_rules` and the three `broadcast_*` flags are absent for a different
/// reason: Keymaster does not model them, so it neither sends nor diffs them,
/// and an unmodelled field is preserved by being ignored.
#[derive(Debug, Deserialize)]
pub(super) struct LogDestination {
    pub id: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    /// OpenRouter's own default is `true`, so an omitted field must not read as
    /// a disabled destination — that would be drift this run then "fixed".
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default)]
    pub privacy_mode: bool,
    #[serde(default)]
    pub sampling_rate: Option<f64>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// The key allowlist Keymaster manages as always empty.
    #[serde(default)]
    pub api_key_hashes: Option<Vec<String>>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

const fn enabled_by_default() -> bool {
    true
}

/// A log destination as a write returns it. See [`GuardrailEnvelope`].
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum LogDestinationEnvelope {
    Wrapped(One<LogDestination>),
    Bare(LogDestination),
}

impl LogDestinationEnvelope {
    pub(super) fn into_destination(self) -> LogDestination {
        match self {
            Self::Wrapped(one) => one.data,
            Self::Bare(destination) => destination,
        }
    }
}

/// One key-to-guardrail assignment.
#[derive(Debug, Deserialize)]
pub(super) struct Assignment {
    pub id: String,
    pub key_hash: String,
    pub guardrail_id: String,
    #[serde(default)]
    pub created_at: Option<String>,
}
