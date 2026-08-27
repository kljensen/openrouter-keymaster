//! Small hand-written JSON fixtures.
//!
//! These follow the shapes in OpenRouter's published OpenAPI document, written
//! by hand and kept short enough to read in one screen. They are deliberately
//! not exhaustive: a response carries more fields than these, and a test that
//! cares about one adds it.
//!
//! Every secret-looking value here is obviously fake. Nothing in this file
//! hides an authentication or request-shape assertion: a test that cares about
//! headers or bodies asserts them itself.

use serde_json::{Value, json};

/// An obviously fake management credential.
///
/// It carries the `sk-or-v1-` prefix a real one does: OpenRouter's Management
/// API Keys page is what makes a key a management key, and nothing in its text
/// distinguishes it from an inference key.
pub const FAKE_MANAGEMENT_KEY: &str = "sk-or-v1-FAKEMANAGEMENTCREDENTIAL";

/// An obviously fake inference key, as `POST /keys` would return once.
pub const FAKE_INFERENCE_KEY: &str = "sk-or-v1-FAKEFAKEFAKE";

/// An obviously fake workspace, in the UUID form the API uses.
pub const FAKE_WORKSPACE_ID: &str = "00000000-0000-4000-8000-000000000001";

/// Obviously fake guardrail UUIDs.
pub const FAKE_GUARDRAIL_ID: &str = "11111111-1111-4111-8111-111111111111";
pub const OTHER_FAKE_GUARDRAIL_ID: &str = "22222222-2222-4222-8222-222222222222";

/// One API key as a list or get response returns it.
///
/// The usage counters are non-zero on purpose: they are remote read-only data,
/// and a test that mistook one for a managed field should fail loudly.
#[must_use]
pub fn api_key(hash: &str, name: &str) -> Value {
    json!({
        "hash": hash,
        "name": name,
        "label": name,
        "disabled": false,
        "limit": 5.0,
        "limit_remaining": 3.75,
        "limit_reset": "monthly",
        "include_byok_in_limit": false,
        "expires_at": null,
        "workspace_id": FAKE_WORKSPACE_ID,
        "usage": 1.25,
        "usage_daily": 0.25,
        "usage_weekly": 0.5,
        "usage_monthly": 1.25,
        "byok_usage": 0.0,
        "byok_usage_daily": 0.0,
        "byok_usage_weekly": 0.0,
        "byok_usage_monthly": 0.0,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "creator_user_id": "user_FAKE",
    })
}

/// The one-time `POST /keys` response: the key object plus its plaintext.
///
/// `plaintext` is a parameter so a test can pass the secret sentinel and prove
/// where it does and does not travel.
#[must_use]
pub fn created_key(hash: &str, name: &str, plaintext: &str) -> Value {
    json!({ "data": api_key(hash, name), "key": plaintext })
}

/// One guardrail as a list or get response returns it.
#[must_use]
pub fn guardrail(id: &str, name: &str, allowed_models: &[&str]) -> Value {
    json!({
        "id": id,
        "name": name,
        "description": null,
        "allowed_models": allowed_models,
        "allowed_providers": null,
        "ignored_models": null,
        "ignored_providers": null,
        "limit_usd": 10.0,
        "reset_interval": "monthly",
        "include_byok_in_budgets": false,
        "enforce_zdr": null,
        "enforce_zdr_anthropic": true,
        "workspace_id": FAKE_WORKSPACE_ID,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
    })
}

/// The deterministic default-guardrail identity of [`FAKE_WORKSPACE_ID`].
///
/// OpenRouter derives it from the workspace's own UUID; here it is simply a
/// distinct constant, because nothing in Keymaster derives it — the workspace
/// object is the only thing that ever names it (ADR-0004, item 3).
pub const FAKE_DEFAULT_GUARDRAIL_ID: &str = "33333333-3333-4333-8333-333333333333";

/// One workspace as a list or get response returns it.
#[must_use]
pub fn workspace(id: &str, name: &str, slug: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "slug": slug,
        "description": null,
        "default_guardrail_id": FAKE_DEFAULT_GUARDRAIL_ID,
        "include_byok_in_budgets": false,
        "io_logging_sampling_rate": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
    })
}

/// The budgets of one workspace, as `GET /workspaces/{id}/budgets` returns
/// them.
///
/// Each entry is an interval spelling and a limit in dollars; `lifetime` is the
/// one the API reports as a `null` reset interval.
#[must_use]
pub fn workspace_budgets(budgets: &[(&str, f64)], include_byok_in_budgets: bool) -> Value {
    let data: Vec<Value> = budgets
        .iter()
        .enumerate()
        .map(|(index, (interval, limit))| {
            json!({
                "id": format!("44444444-4444-4444-8444-00000000000{index}"),
                "workspace_id": FAKE_WORKSPACE_ID,
                "limit_usd": limit,
                "reset_interval": if *interval == "lifetime" {
                    Value::Null
                } else {
                    json!(interval)
                },
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-02T00:00:00Z",
            })
        })
        .collect();
    json!({ "data": data, "include_byok_in_budgets": include_byok_in_budgets })
}

/// One key-to-guardrail assignment.
#[must_use]
pub fn assignment(id: &str, key_hash: &str, guardrail_id: &str) -> Value {
    json!({
        "id": id,
        "key_hash": key_hash,
        "guardrail_id": guardrail_id,
        "key_name": "a key",
        "key_label": "a key",
        "assigned_by": "user_FAKE",
        "created_at": "2026-01-01T00:00:00Z",
    })
}

/// A collection page, as `GET /keys` returns one: records and nothing else.
#[must_use]
pub fn page(items: Vec<Value>) -> Value {
    json!({ "data": items })
}

/// A collection page that also reports a total, as the guardrail and
/// assignment endpoints do. The total is a parameter so a test can make it
/// disagree with the records.
#[must_use]
pub fn counted_page(items: Vec<Value>, total_count: u64) -> Value {
    json!({ "data": items, "total_count": total_count })
}

/// A page with no items, which ends pagination.
#[must_use]
pub fn empty_page() -> Value {
    page(Vec::new())
}

/// One page per slice of key hashes.
///
/// The shape of the sequence is the test's to choose: disjoint slices are
/// ordinary pagination, a repeated slice is a server making no progress,
/// slices that share a hash are overlapping pages, and an empty slice ends
/// the sequence.
#[must_use]
pub fn key_pages(pages: &[&[&str]]) -> Vec<Value> {
    pages
        .iter()
        .map(|hashes| {
            page(
                hashes
                    .iter()
                    .map(|hash| api_key(hash, &format!("key-{hash}")))
                    .collect(),
            )
        })
        .collect()
}

/// A structured API error body.
#[must_use]
pub fn api_error(status: u16, message: &str) -> Value {
    json!({ "error": { "code": status, "message": message } })
}

/// Puts a value into the canonical form a server would return it in.
///
/// Today that means sorting string arrays. Drift tests use this to tell an
/// ordering difference — which is not drift — from a real one.
#[must_use]
pub fn normalize(value: Value) -> Value {
    match value {
        Value::Array(items) => {
            let mut items: Vec<Value> = items.into_iter().map(normalize).collect();
            if items.iter().all(Value::is_string) {
                items.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            }
            Value::Array(items)
        }
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(name, field)| (name, normalize(field)))
                .collect(),
        ),
        scalar => scalar,
    }
}
