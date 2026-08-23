//! Identity newtypes shared by configuration and state.
//!
//! Each type parses once, at the boundary, and is infallible thereafter.
//! Their `Deserialize` implementations go through the same parser, so a value
//! read back from a file is held to the rule that produced it.
//!
//! Errors here never quote the rejected value: an operator who pastes a
//! credential where an identifier belongs must not see it echoed back.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Longest accepted local address. Long enough for a descriptive name, short
/// enough that an address is readable in a plan or an error.
const ADDRESS_MAX: usize = 64;

/// Longest accepted remote display name.
const REMOTE_NAME_MAX: usize = 200;

/// Longest accepted key hash. Generous: the hash is OpenRouter's to choose.
const KEY_HASH_MAX: usize = 256;

/// Longest accepted operation identifier.
const OPERATION_ID_MAX: usize = 64;

/// Characters in a receiver fingerprint: a SHA-256 digest in lowercase hex.
const FINGERPRINT_LENGTH: usize = 64;

/// Why an identifier was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// A local address did not match the allowed shape.
    #[error(
        "a local address must be 1 to {ADDRESS_MAX} characters of ASCII letters, digits, `_`, \
         or `-`, and must start with a letter or digit"
    )]
    Address,

    /// A local address carried something credential-shaped.
    #[error(
        "a local address is Keymaster's own name for a resource and must carry no secret \
         material; the management credential is read from the environment, and a key's \
         plaintext is delivered through a receiver"
    )]
    AddressIsSecret,

    /// A UUID did not match the canonical hyphenated form.
    #[error("expected a UUID in 8-4-4-4-12 hexadecimal form")]
    Uuid,

    /// A remote display name was empty, oversized, or not one line of text.
    #[error(
        "a remote name must be 1 to {REMOTE_NAME_MAX} characters and must not contain control \
         characters"
    )]
    RemoteName,

    /// A remote display name carried something credential-shaped.
    #[error(
        "a remote name is sent to OpenRouter as a label and must carry no secret material; a \
         key's plaintext is delivered through a receiver instead"
    )]
    RemoteNameIsSecret,

    /// A key hash was empty, oversized, or not printable ASCII.
    #[error("a key hash must be 1 to {KEY_HASH_MAX} printable ASCII characters with no spaces")]
    KeyHash,

    /// A value offered as a key hash was credential plaintext.
    #[error(
        "that is a key's plaintext, not its hash; Keymaster never stores or accepts key \
         plaintext, and OpenRouter returns it only once, in the create response"
    )]
    KeyHashIsPlaintext,

    /// An operation identifier did not match the allowed shape.
    #[error(
        "an operation id must be 1 to {OPERATION_ID_MAX} characters of ASCII letters, digits, \
         `_`, or `-`"
    )]
    OperationId,

    /// An operation identifier carried something credential-shaped.
    #[error(
        "an operation id names an attempt and must carry no secret material; it travels to the \
         receiver alongside the key, so a secret in one would be written wherever the receiver \
         records the operation"
    )]
    OperationIdIsSecret,

    /// A receiver fingerprint was not a SHA-256 digest in lowercase hex.
    #[error(
        "a receiver fingerprint must be exactly {FINGERPRINT_LENGTH} lowercase hexadecimal \
         characters; it is a digest of the receiver's specification, never a description of it"
    )]
    ReceiverFingerprint,
}

/// A stable local resource address, as written in the configuration.
///
/// The address is Keymaster's name for a resource. It is never sent to
/// OpenRouter and it never changes when the remote display name does.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Address(String);

impl Address {
    /// Parses a local address.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::AddressIsSecret`] for credential-shaped input, or
    /// [`IdError::Address`] unless the value is 1 to 64 characters of ASCII
    /// letters, digits, `_`, or `-`, starting with a letter or digit.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        // A credential is made of the characters an address allows, so the
        // shape check below would pass one. State reads addresses back from a
        // file it did not necessarily write, and an address is printed in
        // every diagnostic that mentions the resource.
        if crate::redaction::looks_like_credential(value) {
            return Err(IdError::AddressIsSecret);
        }
        let mut characters = value.chars();
        let starts_well = characters.next().is_some_and(|c| c.is_ascii_alphanumeric());
        let rest_is_well = characters.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

        if !starts_well || !rest_is_well || value.len() > ADDRESS_MAX {
            return Err(IdError::Address);
        }
        Ok(Self(value.to_owned()))
    }

    /// The address as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An OpenRouter guardrail's immutable identity.
///
/// Stored lowercase so two spellings of the same UUID compare equal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Uuid(String);

impl Uuid {
    /// Parses a canonical hyphenated UUID, normalizing it to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::Uuid`] unless the value is 8-4-4-4-12 hexadecimal
    /// characters separated by hyphens.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        let groups: Vec<&str> = value.split('-').collect();
        let shaped = groups.len() == 5
            && [8, 4, 4, 4, 12].iter().zip(&groups).all(|(width, group)| {
                group.len() == *width && group.bytes().all(|b| b.is_ascii_hexdigit())
            });

        if !shaped {
            return Err(IdError::Uuid);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// The normalized UUID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A display name OpenRouter shows for a key or a guardrail.
///
/// A name is a managed field, never an identifier: it is mutable remotely and
/// not unique, so nothing is ever looked up by it (ADR-0001). It is stored
/// trimmed, so two spellings that differ only in surrounding space compare
/// equal and cannot look like drift.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RemoteName(String);

impl RemoteName {
    /// Parses a remote display name, trimming surrounding whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::RemoteNameIsSecret`] for credential-shaped input, or
    /// [`IdError::RemoteName`] unless the trimmed value is 1 to 200 characters
    /// with no control characters.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        if crate::redaction::looks_like_credential(value) {
            return Err(IdError::RemoteNameIsSecret);
        }
        let value = value.trim();
        let shaped = !value.is_empty()
            && value.chars().count() <= REMOTE_NAME_MAX
            && !value.chars().any(char::is_control);
        if !shaped {
            return Err(IdError::RemoteName);
        }
        Ok(Self(value.to_owned()))
    }

    /// The name as it is sent to OpenRouter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An OpenRouter API key's immutable identity.
///
/// The hash is what `GET`, `PATCH`, and `DELETE` address a key by, and it is
/// the only durable handle Keymaster has on one. It is not the key: a key's
/// plaintext is returned once, in the create response, and is never written
/// anywhere. [`KeyHash::parse`] refuses credential-shaped input so a plaintext
/// key cannot be mistaken for a hash and persisted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyHash(String);

impl KeyHash {
    /// Parses a key hash.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::KeyHashIsPlaintext`] for credential-shaped input, or
    /// [`IdError::KeyHash`] unless the value is 1 to 256 printable ASCII
    /// characters with no spaces.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        if crate::redaction::looks_like_credential(value) {
            return Err(IdError::KeyHashIsPlaintext);
        }
        let shaped = !value.is_empty()
            && value.len() <= KEY_HASH_MAX
            && value.bytes().all(|byte| byte.is_ascii_graphic());
        if !shaped {
            return Err(IdError::KeyHash);
        }
        Ok(Self(value.to_owned()))
    }

    /// The hash as OpenRouter returned it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identifies one attempt to create and deliver a key.
///
/// The identifier is written to the journal before the create request is sent
/// and travels to the receiver, so an operator — or a receiver with its own
/// idempotency contract — can match an unacknowledged attempt to what it did.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

impl OperationId {
    /// Parses an operation identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::OperationIdIsSecret`] for credential-shaped input,
    /// or [`IdError::OperationId`] unless the value is 1 to 64 characters of
    /// ASCII letters, digits, `_`, or `-`.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        // Same trap as an address: a credential is made of the characters an
        // operation id allows, so the shape check below would pass one.
        if crate::redaction::looks_like_credential(value) {
            return Err(IdError::OperationIdIsSecret);
        }
        let shaped = !value.is_empty()
            && value.len() <= OPERATION_ID_MAX
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
        if !shaped {
            return Err(IdError::OperationId);
        }
        Ok(Self(value.to_owned()))
    }

    /// The identifier as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A non-secret identifier of where a key's plaintext was sent.
///
/// State records this so a changed destination is recognizable as a reason to
/// replace a key, and so recovery can tell an operator whether an interrupted
/// delivery was talking to the receiver they have configured now.
///
/// It is a SHA-256 digest of the receiver's specification and nothing else —
/// see [`ReceiverFingerprint::from_digest`] and `config::Receiver::fingerprint`.
/// Accepting only that shape is what makes the type a guarantee rather than a
/// convention: no path, argument, or pasted secret can be stored in one, and a
/// hand-edited state file offering a description instead of a digest is
/// refused when it is read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReceiverFingerprint(String);

impl ReceiverFingerprint {
    /// Parses a receiver fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::ReceiverFingerprint`] unless the value is exactly 64
    /// lowercase hexadecimal characters.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        let shaped = value.len() == FINGERPRINT_LENGTH
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !shaped {
            return Err(IdError::ReceiverFingerprint);
        }
        Ok(Self(value.to_owned()))
    }

    /// Builds a fingerprint from a digest of the receiver's specification.
    ///
    /// Infallible by construction: hexadecimal is printable, bounded, and
    /// cannot be credential-shaped, so the caller has nothing to handle.
    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Self(hex)
    }

    /// The fingerprint as recorded.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! string_newtype_conversions {
    ($type:ty) => {
        impl TryFrom<String> for $type {
            type Error = IdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(&value)
            }
        }

        impl From<$type> for String {
            fn from(value: $type) -> Self {
                value.0
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_newtype_conversions!(Address);
string_newtype_conversions!(Uuid);
string_newtype_conversions!(RemoteName);
string_newtype_conversions!(KeyHash);
string_newtype_conversions!(OperationId);
string_newtype_conversions!(ReceiverFingerprint);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_accept_the_documented_shape() {
        for accepted in [
            "a",
            "golf_jobfeed",
            "laptop-pi",
            "k9",
            &"a".repeat(ADDRESS_MAX),
        ] {
            assert!(Address::parse(accepted).is_ok(), "{accepted} should parse");
        }
    }

    #[test]
    fn addresses_reject_everything_else() {
        for rejected in [
            "",
            "_leading",
            "-leading",
            "has space",
            "has.dot",
            "hasüü",
            &"a".repeat(ADDRESS_MAX + 1),
        ] {
            assert_eq!(
                Address::parse(rejected),
                Err(IdError::Address),
                "{rejected}"
            );
        }
    }

    #[test]
    fn addresses_refuse_credential_shaped_values() {
        // Every character of a credential is one an address allows, so this
        // has to be refused by name rather than by shape.
        for rejected in [
            "sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE",
            "sk-or-mgmt-abc123",
            "prefixed-SK-OR-v1-abc",
        ] {
            let error = Address::parse(rejected).expect_err("a credential is not an address");
            assert_eq!(error, IdError::AddressIsSecret, "{rejected}");
            assert!(!error.to_string().contains("sk-or"), "{error}");
            assert!(!error.to_string().contains("SENTINEL"), "{error}");
        }
    }

    #[test]
    fn uuids_normalize_to_lowercase() {
        let parsed = Uuid::parse("6C7F5F5A-4F1B-4E2D-9A3C-1B2D3E4F5A6B").expect("a valid UUID");
        assert_eq!(parsed.as_str(), "6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b");
    }

    #[test]
    fn uuids_reject_malformed_values() {
        for rejected in [
            "",
            "6c7f5f5a4f1b4e2d9a3c1b2d3e4f5a6b",
            "6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6",
            "6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6z",
            "6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b-extra",
        ] {
            assert_eq!(Uuid::parse(rejected), Err(IdError::Uuid), "{rejected}");
        }
    }

    #[test]
    fn deserialization_goes_through_the_parser() {
        let error = serde_json::from_str::<Address>(r#""has space""#)
            .expect_err("an invalid address must not deserialize");
        assert!(error.to_string().contains("local address"));
    }

    #[test]
    fn errors_do_not_echo_the_rejected_value() {
        let error = Uuid::parse("sk-or-v1-not-a-uuid").expect_err("not a UUID");
        assert!(!error.to_string().contains("sk-or"));
    }

    #[test]
    fn remote_names_are_trimmed_and_bounded() {
        assert_eq!(
            RemoteName::parse("  golf-jobfeed  ")
                .expect("a valid name")
                .as_str(),
            "golf-jobfeed"
        );
        for rejected in ["", "   ", "line\nbreak", &"a".repeat(REMOTE_NAME_MAX + 1)] {
            assert_eq!(
                RemoteName::parse(rejected),
                Err(IdError::RemoteName),
                "{rejected}"
            );
        }
        assert_eq!(
            RemoteName::parse("sk-or-v1-leaked"),
            Err(IdError::RemoteNameIsSecret)
        );
    }

    #[test]
    fn key_hashes_accept_an_opaque_printable_identifier() {
        assert_eq!(
            KeyHash::parse("a1b2c3d4e5f6")
                .expect("a valid hash")
                .as_str(),
            "a1b2c3d4e5f6"
        );
        assert!(KeyHash::parse(&"a".repeat(KEY_HASH_MAX)).is_ok());
    }

    #[test]
    fn key_hashes_reject_plaintext_and_unprintable_values() {
        assert_eq!(
            KeyHash::parse("sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE"),
            Err(IdError::KeyHashIsPlaintext)
        );
        for rejected in [
            "",
            "has space",
            "line\nbreak",
            &"a".repeat(KEY_HASH_MAX + 1),
        ] {
            assert_eq!(
                KeyHash::parse(rejected),
                Err(IdError::KeyHash),
                "{rejected}"
            );
        }
    }

    #[test]
    fn operation_ids_accept_only_a_readable_token() {
        assert!(OperationId::parse("op-2026-01-01-000001").is_ok());
        for rejected in [
            "",
            "has space",
            "has/slash",
            &"a".repeat(OPERATION_ID_MAX + 1),
        ] {
            assert_eq!(
                OperationId::parse(rejected),
                Err(IdError::OperationId),
                "{rejected}"
            );
        }
    }

    #[test]
    fn operation_ids_refuse_credential_shaped_values() {
        for rejected in [
            "sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE",
            "sk-or-mgmt-abc123",
            "op-sk-or-v1-abc",
        ] {
            let error =
                OperationId::parse(rejected).expect_err("a credential is not an operation id");
            assert_eq!(error, IdError::OperationIdIsSecret, "{rejected}");
            assert!(!error.to_string().contains("sk-or"), "{error}");
            assert!(!error.to_string().contains("SENTINEL"), "{error}");
        }
    }

    #[test]
    fn receiver_fingerprints_are_digests_and_nothing_else() {
        let digest = ReceiverFingerprint::from_digest([0xab; 32]);
        assert_eq!(digest.as_str(), "ab".repeat(32));
        assert_eq!(ReceiverFingerprint::parse(digest.as_str()), Ok(digest));

        // A description of the destination, a pasted secret, an uppercase
        // digest, and a truncated one are all refused, so nothing but a digest
        // can reach a state file even by hand.
        for rejected in [
            "",
            "file:/var/lib/keymaster/one.key",
            "command:/bin/echo sk-or-v1-leaked",
            &"AB".repeat(32),
            &"ab".repeat(31),
            &"ab".repeat(33),
            &format!("{}g", "ab".repeat(31) + "a"),
        ] {
            assert_eq!(
                ReceiverFingerprint::parse(rejected),
                Err(IdError::ReceiverFingerprint),
                "{rejected}"
            );
        }
    }
}
