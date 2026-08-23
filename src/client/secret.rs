//! The management credential and the only place it is read from.

use std::env::{self, VarError};
use std::fmt;

use reqwest::header::HeaderValue;
use zeroize::Zeroize as _;

use super::error::ApiError;

/// The one environment variable Keymaster reads a credential from.
///
/// There is deliberately no command-line option and no configuration key: a
/// credential in either would end up in a shell history, a process list, or a
/// Git repository.
pub const MANAGEMENT_KEY_VAR: &str = "OPENROUTER_MANAGEMENT_KEY";

/// Longest accepted credential. Far above any real management key, and short
/// enough that a whole file pasted into the variable is rejected rather than
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
    /// Reads the credential from [`MANAGEMENT_KEY_VAR`].
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::MissingCredential`] when the variable is unset or
    /// empty, or [`ApiError::UnusableCredential`] when its value cannot be sent
    /// as an HTTP header.
    pub fn from_env() -> Result<Self, ApiError> {
        match env::var(MANAGEMENT_KEY_VAR) {
            Ok(value) => Self::new(value),
            Err(VarError::NotPresent) => Err(ApiError::MissingCredential),
            Err(VarError::NotUnicode(_)) => Err(ApiError::UnusableCredential {
                reason: "it is not valid Unicode",
            }),
        }
    }

    /// Wraps a credential supplied by a test.
    ///
    /// This is not a second production path. Nothing in the binary calls it,
    /// and no command-line option or configuration key reaches it. It exists
    /// because `std::env::set_var` is `unsafe` in Rust 2024 and this crate
    /// forbids unsafe code, so a test cannot install a credential in the
    /// process environment to reach [`ManagementKey::from_env`].
    ///
    /// # Errors
    ///
    /// As [`ManagementKey::from_env`].
    pub fn for_tests(value: &str) -> Result<Self, ApiError> {
        Self::new(value.to_owned())
    }

    /// Takes ownership of the caller's copy so it can be cleared, whether or
    /// not the value turns out to be usable.
    fn new(mut value: String) -> Result<Self, ApiError> {
        let checked = Self::checked(value.trim());
        value.zeroize();
        checked
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
