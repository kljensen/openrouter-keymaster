//! Creating a key, and holding the one thing OpenRouter says only once.
//!
//! `POST /keys` returns the new key's plaintext in its response and never
//! again. Everything here exists to keep that value from being written
//! anywhere it was not deliberately sent: [`KeyPlaintext`] has no `Serialize`,
//! prints redacted, and clears its buffer when dropped, and the only way to
//! read it is [`KeyPlaintext::expose`], which is deliberately awkward to type
//! and easy to grep for.
//!
//! Note what is *absent*: neither [`KeyPlaintext`] nor [`CreatedKey`] derives
//! or implements `Serialize`, so no output DTO, JSON document, or state file
//! can contain one, and the compiler says so rather than a review. The wire
//! type that briefly holds the plaintext during deserialization is private to
//! this module and is `Deserialize` only.
//!
//! # What is and is not cleared
//!
//! Worth stating plainly, because the difference is not obvious and the gap is
//! not closeable from here.
//!
//! Cleared: the plaintext itself, from the moment serde reads it, through
//! [`KeyPlaintext`]'s `Drop`; every wire field of the create response, whole or
//! half-built, through `ZeroizingString`; the response byte buffer, in
//! `Client::create_key_once`; and the text of any error this module returns.
//! Deserialization here is written by hand rather than derived so that a
//! rejected value is never formatted into an error message, because
//! `serde_json` keeps that message inside the error object it hands back, out
//! of reach of anything this module could clear afterwards.
//!
//! Not cleared, and not reachable: copies made below this module. `serde_json`
//! allocates a scratch buffer to unescape a JSON string before handing it over,
//! and `hyper` and `rustls` buffer the response on its way in. Those live and
//! die inside their own crates. Chasing zeroization into them would mean
//! forking them, and the honest position is that Keymaster clears what it owns
//! and does not pretend the plaintext never existed anywhere else. The
//! guarantee this module makes is about what Keymaster writes down, returns,
//! and prints — not about the whole address space.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use time::OffsetDateTime;
use zeroize::Zeroize as _;

use super::error::ApiError;
use crate::config::ResetInterval;
use crate::ids::{KeyHash, RemoteName, Uuid};

/// The body of `POST /keys`.
///
/// Wire-shaped on purpose — dollars as a number, the reset interval as the
/// word OpenRouter uses — because this is the request, not the desired state
/// it was derived from. Absent fields are left out of the body rather than
/// sent as `null`.
#[derive(Debug, Serialize)]
pub struct CreateKeyRequest {
    /// The key's display name. Mutable remotely, never an identifier.
    pub name: RemoteName,
    /// USD spending limit. `None` creates a key with no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<f64>,
    /// How often the limit resets. `None` means it does not.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_reset"
    )]
    pub limit_reset: Option<ResetInterval>,
    /// Whether spend on the operator's own provider keys counts against the
    /// limit.
    pub include_byok_in_limit: bool,
    /// When the key stops working. `None` creates a key that does not expire.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub expires_at: Option<OffsetDateTime>,
    /// The workspace to create the key in. Immutable once it exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Uuid>,
}

impl CreateKeyRequest {
    /// A request for a named key with no limit, no expiry, and no workspace.
    #[must_use]
    pub fn new(name: RemoteName) -> Self {
        Self {
            name,
            limit: None,
            limit_reset: None,
            include_byok_in_limit: false,
            expires_at: None,
            workspace_id: None,
        }
    }
}

/// Writes a reset interval as the word OpenRouter uses for it.
fn serialize_reset<S: Serializer>(
    value: &Option<ResetInterval>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(interval) => serializer.serialize_str(interval.as_str()),
        None => serializer.serialize_none(),
    }
}

/// A newly created key's plaintext.
///
/// OpenRouter discloses this once, in the create response. It is write-only
/// material: Keymaster holds it in memory between parsing that response and
/// handing it to a receiver, and never writes it to state, a log, or output.
pub struct KeyPlaintext(String);

impl KeyPlaintext {
    /// The plaintext itself.
    ///
    /// Named to be conspicuous in a diff. There is exactly one legitimate
    /// caller — the receiver that delivers the key to its destination — and
    /// anything else that calls this is disclosing a credential.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for KeyPlaintext {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for KeyPlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyPlaintext([redacted])")
    }
}

/// What `POST /keys` returned: an identity to persist and a secret to deliver.
///
/// The identity is durable and the plaintext is not, which is the whole shape
/// of ADR-0002: the hash must be written down before anything else happens,
/// because it is the only handle that survives a crash.
#[derive(Debug)]
pub struct CreatedKey {
    hash: KeyHash,
    plaintext: KeyPlaintext,
}

impl CreatedKey {
    /// The new key's immutable identity. Safe to persist, log, and display.
    #[must_use]
    pub fn hash(&self) -> &KeyHash {
        &self.hash
    }

    /// The new key's plaintext, for handing to a receiver.
    #[must_use]
    pub fn plaintext(&self) -> &KeyPlaintext {
        &self.plaintext
    }
}

/// A string that clears itself when dropped, for a field holding a secret
/// before it has been moved anywhere safer.
///
/// Deserialization is not all-or-nothing: serde fills a struct field by field,
/// and a response like `{"key": "sk-or-v1-…", "data": {}}` populates `key`
/// before failing on `data`. The half-built value is then dropped, and a bare
/// `String` there would leave the plaintext in freed memory — somewhere
/// clearing the response buffer cannot reach, because the allocation is not
/// part of it.
struct ZeroizingString(String);

impl ZeroizingString {
    /// Moves the string out, leaving nothing behind to clear.
    ///
    /// The allocation is moved rather than copied, so the caller's wrapper
    /// becomes the one thing responsible for clearing those bytes.
    fn take(&mut self) -> String {
        std::mem::take(&mut self.0)
    }

    /// Borrows the string, for a parser that only needs to look at it.
    ///
    /// Borrowing rather than cloning is the point: a value that turns out to
    /// be unusable is never copied anywhere this type cannot clear.
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for ZeroizingString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The create response as it arrives.
///
/// `Deserialize` and nothing else: it is private, it never leaves this module,
/// and it is converted — and its plaintext moved into a [`KeyPlaintext`] —
/// immediately.
pub(super) struct CreateKeyResponse {
    data: CreatedIdentity,
    key: ZeroizingString,
}

/// The identity half of the create response.
///
/// `hash` is cleared on drop like the plaintext beside it. It is not a secret
/// when the server is behaving — a hash is persisted, logged, and displayed —
/// but this is the one response where the plaintext is in the same object, and
/// [`KeyHash::parse`] exists precisely because a hash field could arrive
/// carrying a key. A value rejected for that reason must not then be left in
/// freed memory.
struct CreatedIdentity {
    hash: ZeroizingString,
}

// ===== deserialization, written out rather than derived =====
//
// A derived `Deserialize` rejects a value of the wrong shape with
// `Error::invalid_type(Unexpected::Str(value), …)`, which formats the value
// into the message. `serde_json` keeps that message in the error it returns, so
// a response body of `"sk-or-v1-…"` — or a key under a field whose value is not
// a string — would put the plaintext inside an error object, where clearing the
// response buffer cannot reach it and no amount of redacting the rendered text
// afterwards can unmake the copy.
//
// So the visitors below are written by hand. Every rejection is a fixed string.
// Values that could carry a credential — strings and byte strings — are
// intercepted at each visitor; numbers, booleans, lists, and objects are left
// to serde, because a key cannot take those shapes and their `Unexpected`
// carries no text from the response. Unknown fields are ignored without being
// named, so a field *name* cannot smuggle one out either.
//
// Each entry point asks for `deserialize_any` rather than the shape it wants.
// That is load-bearing: `deserialize_map` on a JSON string never reaches the
// visitor at all, because `serde_json` recognizes the mismatch itself and
// raises `invalid_type` with the string already formatted in. Asking what is
// actually there routes every value through the methods below, which is the
// only place the interception can happen. These types are deserialized from
// JSON and nothing else, so being self-describing costs nothing.

/// The rejection every visitor here returns: a fixed description of what was
/// expected, and nothing about what arrived.
fn wrong_shape<E: de::Error>(expected: &'static str) -> E {
    E::custom(expected)
}

impl<'de> Deserialize<'de> for ZeroizingString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SecretStringVisitor)
    }
}

struct SecretStringVisitor;

impl<'de> Visitor<'de> for SecretStringVisitor {
    type Value = ZeroizingString;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(ZeroizingString(value.to_owned()))
    }

    /// Takes ownership rather than copying: `serde_json` calls this with the
    /// string it had to build itself, and that allocation is better owned by
    /// something that clears it than left to drop.
    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(ZeroizingString(value))
    }

    fn visit_bytes<E: de::Error>(self, _value: &[u8]) -> Result<Self::Value, E> {
        Err(wrong_shape("a string, not binary data"))
    }

    fn visit_byte_buf<E: de::Error>(self, _value: Vec<u8>) -> Result<Self::Value, E> {
        Err(wrong_shape("a string, not binary data"))
    }
}

/// Which field of the create response a key names, or none of them.
enum ResponseField {
    Data,
    Key,
    Other,
}

impl<'de> Deserialize<'de> for ResponseField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_identifier(ResponseFieldVisitor)
    }
}

struct ResponseFieldVisitor;

impl<'de> Visitor<'de> for ResponseFieldVisitor {
    type Value = ResponseField;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a field name")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        // Anything unrecognized is ignored rather than reported, both to
        // tolerate a field OpenRouter adds later and so that an unexpected
        // field name is never repeated in an error.
        Ok(match value {
            "data" => ResponseField::Data,
            "key" => ResponseField::Key,
            _ => ResponseField::Other,
        })
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(match value {
            b"data" => ResponseField::Data,
            b"key" => ResponseField::Key,
            _ => ResponseField::Other,
        })
    }
}

impl<'de> Deserialize<'de> for CreateKeyResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CreateKeyResponseVisitor)
    }
}

struct CreateKeyResponseVisitor;

impl<'de> Visitor<'de> for CreateKeyResponseVisitor {
    type Value = CreateKeyResponse;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a create-key response object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut data: Option<CreatedIdentity> = None;
        let mut key: Option<ZeroizingString> = None;

        while let Some(field) = map.next_key::<ResponseField>()? {
            match field {
                ResponseField::Data if data.is_some() => {
                    return Err(de::Error::duplicate_field("data"));
                }
                ResponseField::Key if key.is_some() => {
                    return Err(de::Error::duplicate_field("key"));
                }
                ResponseField::Data => data = Some(map.next_value()?),
                ResponseField::Key => key = Some(map.next_value()?),
                ResponseField::Other => {
                    map.next_value::<de::IgnoredAny>()?;
                }
            }
        }

        // `key` is bound to a clearing wrapper the moment it is read, so
        // failing here on a missing `data` still drops the plaintext cleanly.
        Ok(CreateKeyResponse {
            data: data.ok_or_else(|| de::Error::missing_field("data"))?,
            key: key.ok_or_else(|| de::Error::missing_field("key"))?,
        })
    }

    fn visit_str<E: de::Error>(self, _value: &str) -> Result<Self::Value, E> {
        Err(wrong_shape("a create-key response object, not a string"))
    }

    fn visit_string<E: de::Error>(self, _value: String) -> Result<Self::Value, E> {
        Err(wrong_shape("a create-key response object, not a string"))
    }

    fn visit_bytes<E: de::Error>(self, _value: &[u8]) -> Result<Self::Value, E> {
        Err(wrong_shape("a create-key response object, not binary data"))
    }

    fn visit_byte_buf<E: de::Error>(self, _value: Vec<u8>) -> Result<Self::Value, E> {
        Err(wrong_shape("a create-key response object, not binary data"))
    }
}

/// Which field of the identity object a key names, or none of them.
enum IdentityField {
    Hash,
    Other,
}

impl<'de> Deserialize<'de> for IdentityField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_identifier(IdentityFieldVisitor)
    }
}

struct IdentityFieldVisitor;

impl<'de> Visitor<'de> for IdentityFieldVisitor {
    type Value = IdentityField;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a field name")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(match value {
            "hash" => IdentityField::Hash,
            _ => IdentityField::Other,
        })
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(match value {
            b"hash" => IdentityField::Hash,
            _ => IdentityField::Other,
        })
    }
}

impl<'de> Deserialize<'de> for CreatedIdentity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CreatedIdentityVisitor)
    }
}

struct CreatedIdentityVisitor;

impl<'de> Visitor<'de> for CreatedIdentityVisitor {
    type Value = CreatedIdentity;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a created-key identity object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut hash: Option<ZeroizingString> = None;
        while let Some(field) = map.next_key::<IdentityField>()? {
            match field {
                IdentityField::Hash if hash.is_some() => {
                    return Err(de::Error::duplicate_field("hash"));
                }
                IdentityField::Hash => hash = Some(map.next_value()?),
                IdentityField::Other => {
                    map.next_value::<de::IgnoredAny>()?;
                }
            }
        }
        Ok(CreatedIdentity {
            hash: hash.ok_or_else(|| de::Error::missing_field("hash"))?,
        })
    }

    fn visit_str<E: de::Error>(self, _value: &str) -> Result<Self::Value, E> {
        Err(wrong_shape("a created-key identity object, not a string"))
    }

    fn visit_string<E: de::Error>(self, _value: String) -> Result<Self::Value, E> {
        Err(wrong_shape("a created-key identity object, not a string"))
    }

    fn visit_bytes<E: de::Error>(self, _value: &[u8]) -> Result<Self::Value, E> {
        Err(wrong_shape(
            "a created-key identity object, not binary data",
        ))
    }

    fn visit_byte_buf<E: de::Error>(self, _value: Vec<u8>) -> Result<Self::Value, E> {
        Err(wrong_shape(
            "a created-key identity object, not binary data",
        ))
    }
}

/// Parses a create response without leaving any of it in freed memory.
///
/// `serde_json` quotes the offending input in several of its messages, and for
/// this one response that input is a key. Redaction keeps the credential out of
/// the error that is shown; clearing the message afterwards keeps the copy
/// redaction was given out of memory, which the caller's clearing of the
/// response buffer cannot reach.
pub(super) fn parse_response(body: &[u8]) -> Result<CreateKeyResponse, ApiError> {
    serde_json::from_slice(body).map_err(|error| {
        let mut reported = error.to_string();
        let redacted = ApiError::invalid_response(&reported);
        reported.zeroize();
        redacted
    })
}

impl CreateKeyResponse {
    /// Converts the response, moving the plaintext into its wrapper.
    ///
    /// A hash that does not parse fails the create: without a usable identity
    /// the key cannot be persisted, and ADR-0002 calls that ambiguous rather
    /// than successful.
    pub(super) fn into_created_key(mut self) -> Result<CreatedKey, ApiError> {
        // Bound before the hash is parsed, so a failure drops the plaintext
        // through `KeyPlaintext`'s own `Drop` rather than leaving it anywhere.
        let plaintext = KeyPlaintext(self.key.take());
        let hash =
            KeyHash::parse(self.data.hash.as_str()).map_err(|error| ApiError::InvalidResponse {
                message: format!("the created key has an unusable `hash`: {error}"),
            })?;
        Ok(CreatedKey { hash, plaintext })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_fields_are_left_out_of_the_body() {
        let request = CreateKeyRequest::new(RemoteName::parse("jobfeed").expect("a valid name"));
        assert_eq!(
            serde_json::to_value(&request).expect("a serializable request"),
            json!({ "name": "jobfeed", "include_byok_in_limit": false })
        );
    }

    #[test]
    fn a_full_body_is_wire_shaped() {
        let request = CreateKeyRequest {
            limit: Some(5.0),
            limit_reset: Some(ResetInterval::Monthly),
            include_byok_in_limit: true,
            expires_at: Some(
                OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("a valid instant"),
            ),
            workspace_id: Some(
                Uuid::parse("00000000-0000-4000-8000-000000000001").expect("a valid UUID"),
            ),
            ..CreateKeyRequest::new(RemoteName::parse("jobfeed").expect("a valid name"))
        };
        assert_eq!(
            serde_json::to_value(&request).expect("a serializable request"),
            json!({
                "name": "jobfeed",
                "limit": 5.0,
                "limit_reset": "monthly",
                "include_byok_in_limit": true,
                "expires_at": "2027-01-15T08:00:00Z",
                "workspace_id": "00000000-0000-4000-8000-000000000001",
            })
        );
    }

    #[test]
    fn a_created_key_prints_its_identity_and_redacts_its_secret() {
        let created = CreatedKey {
            hash: KeyHash::parse("hash-one").expect("a valid hash"),
            plaintext: KeyPlaintext("sk-or-v1-NOT-A-REAL-KEY".to_owned()),
        };

        let printed = format!("{created:?}");
        assert!(printed.contains("hash-one"), "{printed}");
        assert!(!printed.contains("sk-or-v1"), "{printed}");
        assert_eq!(created.plaintext().expose(), "sk-or-v1-NOT-A-REAL-KEY");
    }

    #[test]
    fn a_response_whose_hash_is_plaintext_is_refused() {
        let response = CreateKeyResponse {
            data: CreatedIdentity {
                hash: ZeroizingString("sk-or-v1-NOT-A-REAL-KEY".to_owned()),
            },
            key: ZeroizingString("sk-or-v1-NOT-A-REAL-KEY".to_owned()),
        };
        let failure = response
            .into_created_key()
            .expect_err("plaintext is not an identity");
        assert_eq!(failure.kind(), "invalid_response");
        assert!(!failure.to_string().contains("sk-or-v1"), "{failure}");
    }

    /// A value no error is allowed to repeat. Not the shared test sentinel:
    /// these assertions read `serde_json`'s own message before any redaction,
    /// so the string must be one nothing else would strip.
    const NEVER_ECHOED: &str = "PLAINTEXT-THAT-MUST-NOT-APPEAR";

    #[test]
    fn serde_never_puts_a_rejected_value_into_its_own_error() {
        // This reads the raw `serde_json` message, not a redacted `ApiError`.
        // Redaction would hide a leak here rather than prove there is none, and
        // the message lives inside the error object, where clearing the
        // response buffer cannot reach it.
        let bodies = [
            // The whole response is the key: rejected at the top level.
            format!(r#""{NEVER_ECHOED}""#),
            // The identity is a string where an object belongs.
            format!(r#"{{"key": "k", "data": "{NEVER_ECHOED}"}}"#),
            // The hash is a string where the identity expects one, but the
            // identity itself is a list.
            format!(r#"{{"key": "k", "data": ["{NEVER_ECHOED}"]}}"#),
            // The key is an object where a string belongs.
            format!(r#"{{"data": {{"hash": "h"}}, "key": {{"a": "{NEVER_ECHOED}"}}}}"#),
            // The secret is a *field name* rather than a value.
            format!(r#"{{"data": {{"hash": "h"}}, "{NEVER_ECHOED}": 1}}"#),
            // Both halves are the wrong shape at once.
            format!(r#"{{"data": "{NEVER_ECHOED}", "key": "{NEVER_ECHOED}"}}"#),
        ];

        for body in bodies {
            let outcome = serde_json::from_str::<CreateKeyResponse>(&body);
            let Err(error) = outcome else {
                // The field-name case parses: an unknown field is ignored, and
                // ignoring it is exactly how the name avoids being reported.
                continue;
            };
            let message = error.to_string();
            assert!(
                !message.contains(NEVER_ECHOED),
                "serde repeated the rejected value: {message}"
            );
        }
    }

    #[test]
    fn an_unknown_field_is_ignored_rather_than_named() {
        let body = format!(r#"{{"data": {{"hash": "h"}}, "key": "k", "{NEVER_ECHOED}": 1}}"#);
        let parsed = serde_json::from_str::<CreateKeyResponse>(&body)
            .expect("an unknown field is tolerated, as it is on every other read");
        assert_eq!(parsed.data.hash.as_str(), "h");
    }

    #[test]
    fn taking_a_secret_moves_it_rather_than_copying_it() {
        // The allocation must end up owned by exactly one wrapper: two owners
        // would mean one of them is not the one that clears these bytes.
        let mut held = ZeroizingString("sk-or-v1-NOT-A-REAL-KEY".to_owned());
        let taken = held.take();
        assert_eq!(taken, "sk-or-v1-NOT-A-REAL-KEY");
        assert!(held.0.is_empty(), "the source must keep no copy");
    }
}
