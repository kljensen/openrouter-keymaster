//! OpenRouter's keys, guardrails, and the assignments between them.
//!
//! Planning needs a complete, fresh snapshot of everything Keymaster manages,
//! and completeness is the hard part — see [`pagination`]. [`Reader`] is that
//! snapshot; [`Writer`] is the small set of writes an ordinary convergence
//! needs, and it never trusts what a write echoes back — apply refetches
//! through [`Reader`] and checks.
//!
//! The observed types here are not the desired types. A desired value is
//! something an operator asked for and Keymaster will converge; an observed
//! value is a fact about the remote object at one instant. Some of those facts
//! — usage counters, remaining budget, creation timestamps — are OpenRouter's
//! alone and can never be desired, so they live in [`KeyUsage`] and
//! [`RemoteTimestamps`] rather than beside the managed fields, where a diff
//! could pick them up by accident.

pub mod pagination;
mod wire;
mod write;

use std::collections::BTreeSet;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::client::{ApiError, Client};
use crate::config::{ResetInterval, Usd};
use crate::ids::{KeyHash, Uuid};
use pagination::{Page, PageLimits};

pub use write::{AssignKeys, GuardrailBody, UpdateKey};

/// How a USD budget resets, as OpenRouter reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResetPolicy {
    /// No reset: the budget is a lifetime total.
    Never,
    /// Resets on this schedule.
    Every(ResetInterval),
    /// A schedule this Keymaster does not know.
    ///
    /// Tolerated rather than rejected: an interval added to the API is not a
    /// reason to fail a whole snapshot, and reporting the unmanaged key that
    /// carries it matters more than understanding its schedule.
    Unrecognized(String),
}

/// Counters OpenRouter keeps for a key. Read-only, and never a desired value.
///
/// Amounts here are plain `f64` rather than [`Usd`] deliberately: they are
/// reported, not compared. Giving them the type used for budgets would invite
/// exactly the diff that must never happen — a plan proposing to "fix" spend.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyUsage {
    pub total: f64,
    pub daily: f64,
    pub weekly: f64,
    pub monthly: f64,
    pub byok_total: f64,
    pub byok_daily: f64,
    pub byok_weekly: f64,
    pub byok_monthly: f64,
    /// What is left of the budget, when there is one.
    pub limit_remaining: Option<f64>,
}

/// When OpenRouter says a resource was created and last changed. Read-only.
///
/// Both are optional because the API documents them as free-form strings: a
/// value that is not RFC 3339 is reported as absent rather than failing a
/// snapshot, since nothing is decided from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RemoteTimestamps {
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

/// An API key as OpenRouter currently has it.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedKey {
    /// Immutable identity.
    pub hash: KeyHash,
    /// Display name. Mutable remotely and not unique, so never an identifier.
    pub name: String,
    pub disabled: bool,
    pub limit: Option<Usd>,
    pub limit_reset: ResetPolicy,
    pub include_byok_in_limit: bool,
    pub expires_at: Option<OffsetDateTime>,
    pub workspace_id: Option<Uuid>,
    pub usage: KeyUsage,
    pub timestamps: RemoteTimestamps,
}

/// Which providers a guardrail requires zero data retention from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZeroDataRetention {
    /// OpenRouter's deprecated single flag, still returned.
    pub any: Option<bool>,
    pub anthropic: Option<bool>,
    pub google: Option<bool>,
    pub openai: Option<bool>,
    pub xai: Option<bool>,
    pub other: Option<bool>,
}

/// A guardrail as OpenRouter currently has it.
///
/// Slug collections are lowercased and sorted, matching how the configuration
/// normalizes them, so comparing the two is an equality test.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedGuardrail {
    /// Immutable identity.
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub allowed_models: Option<BTreeSet<String>>,
    /// What the configuration calls denied models.
    pub ignored_models: Option<BTreeSet<String>>,
    pub allowed_providers: Option<BTreeSet<String>>,
    /// What the configuration calls denied providers.
    pub ignored_providers: Option<BTreeSet<String>>,
    pub limit: Option<Usd>,
    pub reset_interval: ResetPolicy,
    pub include_byok_in_budgets: bool,
    pub zero_data_retention: ZeroDataRetention,
    pub workspace_id: Option<Uuid>,
    pub timestamps: RemoteTimestamps,
}

/// One key bound to one guardrail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAssignment {
    /// The assignment's own immutable identity.
    pub id: Uuid,
    pub key_hash: KeyHash,
    pub guardrail_id: Uuid,
    pub created_at: Option<OffsetDateTime>,
}

/// Read-only access to the OpenRouter resources Keymaster manages.
#[derive(Debug)]
pub struct Reader<'client> {
    client: &'client Client,
    limits: PageLimits,
}

impl<'client> Reader<'client> {
    /// Reads through `client` with the default pagination bounds.
    #[must_use]
    pub fn new(client: &'client Client) -> Self {
        Self {
            client,
            limits: PageLimits::default(),
        }
    }

    /// Reads with explicit pagination bounds.
    #[must_use]
    pub fn with_limits(client: &'client Client, limits: PageLimits) -> Self {
        Self { client, limits }
    }

    /// Every API key, disabled ones included.
    ///
    /// Disabled keys are still Keymaster's to manage — a key it disabled during
    /// retirement is one it must keep seeing — so leaving them out would make a
    /// disabled key indistinguishable from a deleted one.
    ///
    /// `GET /keys` documents no page-size parameter, so the page size is the
    /// server's; only the offset is Keymaster's to advance.
    ///
    /// # Errors
    ///
    /// Returns the client's errors, or [`ApiError::InvalidResponse`] when a
    /// record has no usable identity or pagination does not terminate.
    pub fn list_keys(&self, workspace: Option<&Uuid>) -> Result<Vec<ObservedKey>, ApiError> {
        pagination::collect(
            self.limits,
            "API keys",
            |key: &ObservedKey| key.hash.clone(),
            |offset, _page_size| {
                let mut query = vec![
                    ("offset", offset.to_string()),
                    ("include_disabled", "true".to_owned()),
                ];
                if let Some(workspace) = workspace {
                    query.push(("workspace_id", workspace.to_string()));
                }
                let page: wire::List<wire::Key> = self.client.get_json(&["keys"], &query)?;
                Ok(Page {
                    items: convert(page.data, ObservedKey::from_wire)?,
                    total: page.total_count,
                })
            },
        )
    }

    /// One API key, by its immutable hash.
    ///
    /// # Errors
    ///
    /// Returns the client's errors, including a 404 as
    /// [`ApiError::Status`], or [`ApiError::InvalidResponse`] when the record
    /// has no usable identity.
    pub fn get_key(&self, hash: &KeyHash) -> Result<ObservedKey, ApiError> {
        let one: wire::One<wire::Key> = self.client.get_json(&["keys", hash.as_str()], &[])?;
        ObservedKey::from_wire(one.data)
    }

    /// Every guardrail.
    ///
    /// # Errors
    ///
    /// As [`Reader::list_keys`].
    pub fn list_guardrails(
        &self,
        workspace: Option<&Uuid>,
    ) -> Result<Vec<ObservedGuardrail>, ApiError> {
        pagination::collect(
            self.limits,
            "guardrails",
            |guardrail: &ObservedGuardrail| guardrail.id.clone(),
            |offset, page_size| {
                let mut query = vec![
                    ("offset", offset.to_string()),
                    ("limit", page_size.to_string()),
                ];
                if let Some(workspace) = workspace {
                    query.push(("workspace_id", workspace.to_string()));
                }
                let page: wire::List<wire::Guardrail> =
                    self.client.get_json(&["guardrails"], &query)?;
                Ok(Page {
                    items: convert(page.data, ObservedGuardrail::from_wire)?,
                    total: page.total_count,
                })
            },
        )
    }

    /// One guardrail, by its immutable UUID.
    ///
    /// # Errors
    ///
    /// As [`Reader::get_key`].
    pub fn get_guardrail(&self, id: &Uuid) -> Result<ObservedGuardrail, ApiError> {
        let one: wire::One<wire::Guardrail> =
            self.client.get_json(&["guardrails", id.as_str()], &[])?;
        ObservedGuardrail::from_wire(one.data)
    }

    /// Every key-to-guardrail assignment in the organization.
    ///
    /// # Errors
    ///
    /// As [`Reader::list_keys`].
    pub fn list_assignments(&self) -> Result<Vec<ObservedAssignment>, ApiError> {
        self.assignments("key assignments", &["guardrails", "assignments", "keys"])
    }

    /// The assignments of one guardrail, for verifying a write.
    ///
    /// # Errors
    ///
    /// As [`Reader::list_keys`].
    pub fn list_assignments_of(
        &self,
        guardrail: &Uuid,
    ) -> Result<Vec<ObservedAssignment>, ApiError> {
        self.assignments(
            "assignments of a guardrail",
            &["guardrails", guardrail.as_str(), "assignments", "keys"],
        )
    }

    /// The shared body of both assignment listings.
    fn assignments(
        &self,
        resource: &str,
        segments: &[&str],
    ) -> Result<Vec<ObservedAssignment>, ApiError> {
        pagination::collect(
            self.limits,
            resource,
            |assignment: &ObservedAssignment| assignment.id.clone(),
            |offset, page_size| {
                let query = [
                    ("offset", offset.to_string()),
                    ("limit", page_size.to_string()),
                ];
                let page: wire::List<wire::Assignment> = self.client.get_json(segments, &query)?;
                Ok(Page {
                    items: convert(page.data, ObservedAssignment::from_wire)?,
                    total: page.total_count,
                })
            },
        )
    }
}

/// The writes an ordinary convergence makes.
///
/// Deliberately small: a guardrail can be created and patched, an existing
/// key can be patched, and a key can be attached to or detached from a
/// guardrail. Creating an inference key is not here — it is
/// [`crate::client::Client::create_key_once`], because a one-time secret is a
/// different kind of operation with its own journal (ADR-0002).
///
/// No method here reports success from what the server echoed back. An update
/// returns `()`, and a create returns only the identity apply must persist
/// before it does anything else; everything else is established by refetching
/// through [`Reader`]. That is what makes an ambiguous write recoverable: the
/// answer to "did it land?" comes from a fresh read, never from a replay.
#[derive(Debug)]
pub struct Writer<'client> {
    client: &'client Client,
}

impl<'client> Writer<'client> {
    /// Writes through `client`.
    #[must_use]
    pub fn new(client: &'client Client) -> Self {
        Self { client }
    }

    /// Creates one guardrail and returns it, as OpenRouter recorded it.
    ///
    /// The returned identity is the only part of this that matters, and it
    /// matters immediately: a guardrail whose UUID is not persisted is one
    /// nothing can find again except by its mutable name.
    ///
    /// # Errors
    ///
    /// Returns the client's errors. Any failure other than a definite 4xx
    /// leaves it unknown whether the guardrail exists; resolve that by
    /// refreshing remote state, never by sending the request again.
    pub fn create_guardrail(&self, body: &GuardrailBody) -> Result<ObservedGuardrail, ApiError> {
        let created: wire::GuardrailEnvelope = self.client.post_json_once(&["guardrails"], body)?;
        ObservedGuardrail::from_wire(created.into_guardrail())
    }

    /// Brings one guardrail's managed fields to the configured values.
    ///
    /// # Errors
    ///
    /// As [`Writer::create_guardrail`].
    pub fn update_guardrail(&self, id: &Uuid, body: &GuardrailBody) -> Result<(), ApiError> {
        self.client
            .patch_once_discarding_body(&["guardrails", id.as_str()], body)
    }

    /// Brings one existing key's managed fields to the configured values.
    ///
    /// # Errors
    ///
    /// As [`Writer::create_guardrail`].
    pub fn update_key(&self, hash: &KeyHash, body: &UpdateKey) -> Result<(), ApiError> {
        self.client
            .patch_once_discarding_body(&["keys", hash.as_str()], body)
    }

    /// Attaches one key to one guardrail.
    ///
    /// # Errors
    ///
    /// As [`Writer::create_guardrail`].
    pub fn assign_key(&self, guardrail: &Uuid, key: &KeyHash) -> Result<(), ApiError> {
        self.client.post_once_discarding_body(
            &["guardrails", guardrail.as_str(), "assignments", "keys"],
            &AssignKeys::one(key),
        )
    }

    /// Detaches one key from one guardrail.
    ///
    /// # Errors
    ///
    /// As [`Writer::create_guardrail`].
    pub fn unassign_key(&self, guardrail: &Uuid, key: &KeyHash) -> Result<(), ApiError> {
        self.client.post_once_discarding_body(
            &[
                "guardrails",
                guardrail.as_str(),
                "assignments",
                "keys",
                "remove",
            ],
            &AssignKeys::one(key),
        )
    }
}

/// Converts a page of wire records, failing on the first unusable one.
fn convert<W, T>(
    records: Vec<W>,
    from_wire: impl Fn(W) -> Result<T, ApiError>,
) -> Result<Vec<T>, ApiError> {
    records.into_iter().map(from_wire).collect()
}

impl ObservedKey {
    fn from_wire(key: wire::Key) -> Result<Self, ApiError> {
        let hash = KeyHash::parse(&key.hash)
            .map_err(|error| unusable("an API key", "hash", &error.to_string()))?;
        let identity = format!("the API key {hash}");

        Ok(Self {
            name: key.name,
            disabled: key.disabled,
            limit: budget(key.limit, "limit", &identity)?,
            limit_reset: reset(key.limit_reset),
            include_byok_in_limit: key.include_byok_in_limit,
            expires_at: managed_timestamp(key.expires_at.as_deref(), "expires_at", &identity)?,
            workspace_id: workspace(key.workspace_id.as_deref(), &identity)?,
            usage: KeyUsage {
                total: key.usage,
                daily: key.usage_daily,
                weekly: key.usage_weekly,
                monthly: key.usage_monthly,
                byok_total: key.byok_usage,
                byok_daily: key.byok_usage_daily,
                byok_weekly: key.byok_usage_weekly,
                byok_monthly: key.byok_usage_monthly,
                limit_remaining: key.limit_remaining,
            },
            timestamps: timestamps(key.created_at.as_deref(), key.updated_at.as_deref()),
            hash,
        })
    }
}

impl ObservedGuardrail {
    fn from_wire(guardrail: wire::Guardrail) -> Result<Self, ApiError> {
        let id = Uuid::parse(&guardrail.id)
            .map_err(|error| unusable("a guardrail", "id", &error.to_string()))?;
        let identity = format!("the guardrail {id}");

        Ok(Self {
            name: guardrail.name,
            description: guardrail.description,
            allowed_models: slugs(guardrail.allowed_models),
            ignored_models: slugs(guardrail.ignored_models),
            allowed_providers: slugs(guardrail.allowed_providers),
            ignored_providers: slugs(guardrail.ignored_providers),
            limit: budget(guardrail.limit_usd, "limit_usd", &identity)?,
            reset_interval: reset(guardrail.reset_interval),
            include_byok_in_budgets: guardrail.include_byok_in_budgets,
            zero_data_retention: ZeroDataRetention {
                any: guardrail.enforce_zdr,
                anthropic: guardrail.enforce_zdr_anthropic,
                google: guardrail.enforce_zdr_google,
                openai: guardrail.enforce_zdr_openai,
                xai: guardrail.enforce_zdr_xai,
                other: guardrail.enforce_zdr_other,
            },
            workspace_id: workspace(guardrail.workspace_id.as_deref(), &identity)?,
            timestamps: timestamps(
                guardrail.created_at.as_deref(),
                guardrail.updated_at.as_deref(),
            ),
            id,
        })
    }
}

impl ObservedAssignment {
    fn from_wire(assignment: wire::Assignment) -> Result<Self, ApiError> {
        let id = Uuid::parse(&assignment.id)
            .map_err(|error| unusable("an assignment", "id", &error.to_string()))?;
        let key_hash = KeyHash::parse(&assignment.key_hash)
            .map_err(|error| unusable("an assignment", "key_hash", &error.to_string()))?;
        let guardrail_id = Uuid::parse(&assignment.guardrail_id)
            .map_err(|error| unusable("an assignment", "guardrail_id", &error.to_string()))?;

        Ok(Self {
            id,
            key_hash,
            guardrail_id,
            created_at: lenient_timestamp(assignment.created_at.as_deref()),
        })
    }
}

/// A record whose identity or managed field cannot be read.
fn unusable(resource: &str, field: &str, why: &str) -> ApiError {
    ApiError::InvalidResponse {
        message: format!("{resource} has an unusable `{field}`: {why}"),
    }
}

/// Reads a budget the way the configuration reads one, so the two compare.
fn budget(dollars: Option<f64>, field: &str, identity: &str) -> Result<Option<Usd>, ApiError> {
    dollars
        .map(|dollars| {
            Usd::from_dollars(dollars)
                .map_err(|problem| unusable(identity, field, problem.message()))
        })
        .transpose()
}

/// Reads a reset schedule, tolerating one this build does not know.
fn reset(value: Option<String>) -> ResetPolicy {
    let Some(value) = value else {
        return ResetPolicy::Never;
    };
    ResetInterval::parse(&value.to_ascii_lowercase())
        .map_or(ResetPolicy::Unrecognized(value), ResetPolicy::Every)
}

/// Reads a timestamp Keymaster compares against a desired one.
///
/// Strict, unlike [`lenient_timestamp`]: an expiry that cannot be read would
/// otherwise look like an expiry that is not set, and a plan would propose
/// setting it — replacing the key, because expiry is immutable.
fn managed_timestamp(
    value: Option<&str>,
    field: &str,
    identity: &str,
) -> Result<Option<OffsetDateTime>, ApiError> {
    value
        .map(|value| {
            OffsetDateTime::parse(value, &Rfc3339)
                .map(|when| when.to_offset(time::UtcOffset::UTC))
                .map_err(|_| unusable(identity, field, "it is not an RFC 3339 timestamp"))
        })
        .transpose()
}

/// Reads a timestamp nothing is decided from.
fn lenient_timestamp(value: Option<&str>) -> Option<OffsetDateTime> {
    let parsed = OffsetDateTime::parse(value?, &Rfc3339).ok()?;
    Some(parsed.to_offset(time::UtcOffset::UTC))
}

fn timestamps(created_at: Option<&str>, updated_at: Option<&str>) -> RemoteTimestamps {
    RemoteTimestamps {
        created_at: lenient_timestamp(created_at),
        updated_at: lenient_timestamp(updated_at),
    }
}

/// Reads a workspace identifier, which must be a UUID if it is anything.
fn workspace(value: Option<&str>, identity: &str) -> Result<Option<Uuid>, ApiError> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| {
            Uuid::parse(value)
                .map_err(|error| unusable(identity, "workspace_id", &error.to_string()))
        })
        .transpose()
}

/// Normalizes a slug collection the way the configuration does.
fn slugs(values: Option<Vec<String>>) -> Option<BTreeSet<String>> {
    values.map(|values| {
        values
            .into_iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .collect()
    })
}
