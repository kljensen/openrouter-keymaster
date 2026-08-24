//! Request bodies for the writes Keymaster makes.
//!
//! Three rules shape every type here, and they are the reason these are
//! hand-written rather than derived from the desired types.
//!
//! **Only managed fields travel.** A field the configuration does not describe
//! is left out of the body entirely, so a budget, an expiry, or a
//! provider-managed field Keymaster cannot express is preserved rather than
//! overwritten. That is what [`Patch`] is for: omitted, set, or explicitly
//! `null`.
//!
//! **A collection is sent whole.** OpenRouter replaces a model or provider list
//! rather than merging into it, so a managed list is serialized complete and
//! normalized — the same sorted, lowercased set the planner compared. An empty
//! managed list is sent as `null`, because "no restriction" is how an absent
//! list reads back and sending `[]` would ask for the opposite.
//!
//! **No immutable field appears in an update.** `expires_at`, `workspace_id`,
//! and `creator_user_id` are fixed when a key is created — `POST /keys` accepts
//! all three and `PATCH /keys/{hash}` accepts none of them — so a difference in
//! one is a replacement, not a patch, and [`UpdateKey`] has nowhere to put
//! them.

use serde::Serialize;

use crate::client::Patch;
use crate::config::{Guardrail, Key, Managed, ResetInterval, Usd};
use crate::ids::{KeyHash, RemoteName};

/// The body of `POST /guardrails` and `PATCH /guardrails/{id}`.
///
/// One type for both, because the managed fields are the same ones. They
/// differ in exactly one way, which [`GuardrailBody::create`] applies: a create
/// omits what an update would clear, since a field that has never existed
/// cannot be unset.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GuardrailBody {
    /// Display name. Always managed, so always sent.
    name: String,
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    description: Patch<String>,
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    allowed_models: Patch<Vec<String>>,
    /// What the configuration calls denied models.
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    ignored_models: Patch<Vec<String>>,
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    allowed_providers: Patch<Vec<String>>,
    /// What the configuration calls denied providers.
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    ignored_providers: Patch<Vec<String>>,
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    limit_usd: Patch<f64>,
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    reset_interval: Patch<&'static str>,
    /// Always managed: the configuration inherits a default for it.
    include_byok_in_budgets: bool,
    /// The single zero-data-retention flag the configuration models. The
    /// per-provider flags are OpenRouter's and are never sent.
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    enforce_zdr: Patch<bool>,
}

impl GuardrailBody {
    /// The body that creates `desired`.
    #[must_use]
    pub fn create(desired: &Guardrail) -> Self {
        let update = Self::update(desired);
        Self {
            description: update.description.omit_clears(),
            allowed_models: update.allowed_models.omit_clears(),
            ignored_models: update.ignored_models.omit_clears(),
            allowed_providers: update.allowed_providers.omit_clears(),
            ignored_providers: update.ignored_providers.omit_clears(),
            limit_usd: update.limit_usd.omit_clears(),
            reset_interval: update.reset_interval.omit_clears(),
            enforce_zdr: update.enforce_zdr.omit_clears(),
            ..update
        }
    }

    /// The body that brings an existing guardrail to `desired`.
    #[must_use]
    pub fn update(desired: &Guardrail) -> Self {
        Self {
            name: name(&desired.name),
            description: Patch::from_managed(&desired.description, Clone::clone),
            allowed_models: slugs(desired.allowed_models.as_ref()),
            ignored_models: slugs(desired.denied_models.as_ref()),
            allowed_providers: slugs(desired.allowed_providers.as_ref()),
            ignored_providers: slugs(desired.denied_providers.as_ref()),
            limit_usd: budget(&desired.limit),
            reset_interval: interval(&desired.reset_interval),
            include_byok_in_budgets: desired.include_byok_in_limit,
            enforce_zdr: desired.require_zdr.map_or(Patch::Omit, Patch::Set),
        }
    }
}

/// The body of `PATCH /keys/{hash}`.
///
/// Deliberately without `expires_at`, `workspace_id`, and `creator_user_id`:
/// OpenRouter fixes all three when the key is created, and a difference in one
/// is planned as a replacement.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UpdateKey {
    /// Display name. Always managed, so always sent.
    name: String,
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    limit: Patch<f64>,
    #[serde(skip_serializing_if = "Patch::is_omitted")]
    limit_reset: Patch<&'static str>,
    /// Always managed: the configuration inherits a default for it.
    include_byok_in_limit: bool,
    /// Always managed: a key the configuration does not disable is enabled.
    disabled: bool,
}

impl UpdateKey {
    /// The body that brings an existing key to `desired`.
    #[must_use]
    pub fn new(desired: &Key) -> Self {
        Self {
            name: name(&desired.name),
            limit: budget(&desired.limit),
            limit_reset: interval(&desired.limit_reset),
            include_byok_in_limit: desired.include_byok_in_limit,
            disabled: desired.disabled,
        }
    }
}

/// The body that disables one key and asks for nothing else.
///
/// Deliberately not [`UpdateKey`] with `disabled` forced true. This is the body
/// of a cleanup: a key whose plaintext is lost, or one an operator found as the
/// leaked result of an ambiguous create. Keymaster may know nothing about that
/// key beyond its hash — the configuration block may be gone, or may never have
/// described it — and sending a name and a budget alongside the one field that
/// matters would rewrite a resource while trying to make it harmless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DisableKey {
    disabled: bool,
}

impl DisableKey {
    /// The body that disables a key.
    #[must_use]
    pub const fn new() -> Self {
        Self { disabled: true }
    }
}

impl Default for DisableKey {
    fn default() -> Self {
        Self::new()
    }
}

/// The body of both assignment endpoints: the keys to attach to a guardrail,
/// or to detach from it.
///
/// Never the guardrail's complete key list. Keymaster manages one key at a
/// time and a guardrail can carry keys no local address owns; sending the
/// complete list would unassign a stranger's key.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AssignKeys {
    key_hashes: Vec<String>,
}

impl AssignKeys {
    /// A body naming exactly one key.
    #[must_use]
    pub fn one(key: &KeyHash) -> Self {
        Self {
            key_hashes: vec![key.as_str().to_owned()],
        }
    }
}

fn name(value: &RemoteName) -> String {
    value.as_str().to_owned()
}

fn budget(value: &Managed<Usd>) -> Patch<f64> {
    Patch::from_managed(value, |amount| amount.dollars())
}

fn interval(value: &Managed<ResetInterval>) -> Patch<&'static str> {
    Patch::from_managed(value, |interval| interval.as_str())
}

/// A managed slug collection, sent whole.
///
/// An empty managed collection is sent as `null` rather than `[]`: a list that
/// restricts nothing reads back absent, so `null` is the spelling that makes
/// the next plan see what this write intended.
fn slugs(value: Option<&std::collections::BTreeSet<String>>) -> Patch<Vec<String>> {
    match value {
        None => Patch::Omit,
        Some(slugs) if slugs.is_empty() => Patch::Clear,
        Some(slugs) => Patch::Set(slugs.iter().cloned().collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use serde_json::{Value, json};

    /// Parses one configuration and returns it.
    fn config(source: &str) -> Config {
        Config::parse(source).expect("a valid test configuration")
    }

    fn body(value: &impl Serialize) -> Value {
        serde_json::to_value(value).expect("a serializable body")
    }

    fn guardrail(source: &str) -> Guardrail {
        config(source)
            .guardrails
            .values()
            .next()
            .cloned()
            .expect("one guardrail")
    }

    fn key(source: &str) -> Key {
        config(source)
            .keys
            .values()
            .next()
            .cloned()
            .expect("one key")
    }

    #[test]
    fn an_update_sends_only_the_fields_the_configuration_manages() {
        let desired =
            guardrail("version = 1\n[guardrails.cheap]\nname = \"cheap-rail\"\nlimit_usd = 10\n");
        assert_eq!(
            body(&GuardrailBody::update(&desired)),
            json!({
                "name": "cheap-rail",
                "limit_usd": 10.0,
                "include_byok_in_budgets": false,
            }),
            "a field the configuration does not describe must not be sent"
        );
    }

    #[test]
    fn a_managed_collection_is_sent_whole_and_normalized() {
        let desired = guardrail(
            "version = 1\n[guardrails.cheap]\nname = \"cheap-rail\"\n\
             allowed_models = [\"Z/one\", \"a/two\"]\ndenied_providers = []\n",
        );
        let sent = body(&GuardrailBody::update(&desired));
        assert_eq!(sent["allowed_models"], json!(["a/two", "z/one"]));
        assert_eq!(
            sent["ignored_providers"],
            Value::Null,
            "a managed but empty collection restricts nothing, which is `null`"
        );
    }

    #[test]
    fn an_update_clears_what_a_create_omits() {
        let desired = guardrail(
            "version = 1\n[guardrails.cheap]\nname = \"cheap-rail\"\nclear = [\"limit_usd\"]\n",
        );
        assert_eq!(
            body(&GuardrailBody::update(&desired))["limit_usd"],
            Value::Null
        );
        assert_eq!(
            body(&GuardrailBody::create(&desired)),
            json!({ "name": "cheap-rail", "include_byok_in_budgets": false }),
            "a field that has never existed cannot be unset"
        );
    }

    #[test]
    fn a_key_update_carries_no_immutable_field() {
        let desired = key(
            "version = 1\n[keys.jobfeed]\nname = \"golf-jobfeed\"\nlimit_usd = 5\n\
             limit_reset = \"monthly\"\nexpires_at = \"2027-01-01T00:00:00Z\"\n\
             workspace_id = \"00000000-0000-4000-8000-000000000001\"\n\
             creator_user_id = \"user_2dHFtVWx2n56w6HkM0000000000\"\n",
        );
        assert_eq!(
            body(&UpdateKey::new(&desired)),
            json!({
                "name": "golf-jobfeed",
                "limit": 5.0,
                "limit_reset": "monthly",
                "include_byok_in_limit": false,
                "disabled": false,
            }),
            "expires_at, workspace_id, and creator_user_id are fixed at creation and are never \
             patched"
        );
    }

    #[test]
    fn a_disable_body_carries_one_field_and_no_other() {
        assert_eq!(
            body(&DisableKey::new()),
            json!({ "disabled": true }),
            "a cleanup must not rewrite fields it was never asked about"
        );
    }

    #[test]
    fn an_assignment_body_names_one_key_and_no_other() {
        let hash = KeyHash::parse("hash-jobfeed-1").expect("a valid hash");
        assert_eq!(
            body(&AssignKeys::one(&hash)),
            json!({ "key_hashes": ["hash-jobfeed-1"] })
        );
    }
}
