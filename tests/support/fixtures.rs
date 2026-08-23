//! Small hand-written JSON fixtures.
//!
//! These are approximations of the OpenRouter management API, written by hand
//! and kept short enough to read in one screen. The authoritative wire types
//! land with the client (issues #8 and #9); until then these exist so tests
//! have a realistic shape to assert against.
//!
//! Every secret-looking value here is obviously fake. Nothing in this file
//! hides an authentication or request-shape assertion: a test that cares about
//! headers or bodies asserts them itself.

use serde_json::{Value, json};

/// An obviously fake management credential.
pub const FAKE_MANAGEMENT_KEY: &str = "sk-or-mgmt-FAKEFAKEFAKE";

/// An obviously fake inference key, as `POST /keys` would return once.
pub const FAKE_INFERENCE_KEY: &str = "sk-or-v1-FAKEFAKEFAKE";

/// One API key as a list or get response returns it.
#[must_use]
pub fn api_key(hash: &str, name: &str) -> Value {
    json!({
        "hash": hash,
        "name": name,
        "label": name,
        "disabled": false,
        "limit": 5.0,
        "usage": 0.0,
        "created_at": "2026-01-01T00:00:00Z",
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
        "limit": 10.0,
        "created_at": "2026-01-01T00:00:00Z",
    })
}

/// A collection page.
#[must_use]
pub fn page(items: Vec<Value>) -> Value {
    json!({ "data": items })
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
