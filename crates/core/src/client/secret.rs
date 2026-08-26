//! The management credential and the only type that holds one.

use std::fmt;

use reqwest::header::HeaderValue;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use super::error::ApiError;

/// The one environment variable the `openrouter-keymaster` binary reads a
/// credential from, and the one every diagnostic here names.
///
/// The read itself is the binary crate's (`openrouter_keymaster::app::env`);
/// this module holds the
/// name because the errors that name it are here. There is deliberately no
/// command-line option and no configuration key: a credential in either would
/// end up in a shell history, a process list, or a Git repository.
pub const MANAGEMENT_KEY_VAR: &str = "OPENROUTER_MANAGEMENT_KEY";

/// Longest accepted credential. Far above any real management key, and short
/// enough that a whole file handed in by mistake is rejected rather than
/// sent.
const MAX_LENGTH: usize = 512;

/// An OpenRouter management credential, held so it cannot be disclosed.
///
/// The type has no `Serialize`, no `Display`, and no accessor that returns the
/// plaintext. Its `Debug` prints a placeholder, and its buffer is cleared when
/// it is dropped. The value leaves this type exactly once, as the sensitive
/// `Authorization` header of the one approved HTTP client.
pub struct ManagementKey(String);

impl ManagementKey {
    /// Wraps a credential the caller already holds.
    ///
    /// This is the only constructor. The caller's copy is taken by value in a
    /// [`Zeroizing`] wrapper, so it is cleared when this returns whether or not
    /// the value turned out to be usable, and a host that keeps its secrets
    /// somewhere other than the environment — a vault, a request header, a
    /// database — has a way in that does not go through a process variable.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::MissingCredential`] when the value is empty or all
    /// whitespace, or [`ApiError::UnusableCredential`] when it cannot be sent
    /// as an HTTP header. Neither ever repeats the value.
    pub fn from_secret(secret: Zeroizing<String>) -> Result<Self, ApiError> {
        Self::checked(secret.trim())
    }

    /// Validates a credential's shape without ever quoting it.
    fn checked(value: &str) -> Result<Self, ApiError> {
        if value.is_empty() {
            return Err(ApiError::MissingCredential);
        }
        if value.len() > MAX_LENGTH {
            return Err(ApiError::UnusableCredential {
                reason: "it is longer than a management key can be",
            });
        }
        // An HTTP header value cannot carry a control character, and a newline
        // in one would let the value forge a second header.
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(ApiError::UnusableCredential {
                reason: "it contains a space or a character that cannot be sent in a header",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// A non-reversible digest of the credential: SHA-256 and nothing else.
    ///
    /// A plan fingerprint covers the account a plan was computed against, so
    /// that a plan shown for one organization cannot be applied to another.
    /// The credential itself must not travel into a report, and a digest is
    /// what makes "the same credential" checkable without it.
    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }

    /// The `Authorization` header this credential authenticates with, marked
    /// sensitive so `hyper` and `reqwest` print it as `Sensitive` rather than
    /// as its value.
    pub(super) fn authorization_header(&self) -> Result<HeaderValue, ApiError> {
        let mut rendered = format!("Bearer {}", self.0);
        let header = HeaderValue::from_str(&rendered);
        rendered.zeroize();

        let mut header = header.map_err(|_| ApiError::UnusableCredential {
            reason: "it cannot be sent as an HTTP header",
        })?;
        header.set_sensitive(true);
        Ok(header)
    }
}

impl Drop for ManagementKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for ManagementKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagementKey([redacted])")
    }
}
