//! The two environment variables the binary reads, and the only place it
//! reads them.
//!
//! The credential and the endpoint are the binary's contract with the operator
//! (ADR-0003): nothing under [`crate::client`], [`crate::ops`], or
//! [`crate::state`] reads a variable, so a host that keeps its secrets
//! elsewhere hands them in instead.

use std::env::{self, VarError};

use zeroize::Zeroizing;

use crate::client::{ApiError, MANAGEMENT_KEY_VAR, ManagementKey, Options};

/// The environment variable that overrides [`crate::client::PRODUCTION_BASE_URL`].
///
/// It exists so the compiled binary can be pointed at a local server — the
/// integration tests run it against the harness in `tests/support/http.rs` —
/// and so an operator behind a gateway can name it explicitly rather than
/// having ambient proxy settings redirect a credential. The value is validated
/// like any other base URL: absolute, HTTP or HTTPS, no trailing slash, no
/// query. It is not a credential and never appears in output.
pub const BASE_URL_VAR: &str = "OPENROUTER_BASE_URL";

/// Reads the credential from [`MANAGEMENT_KEY_VAR`].
///
/// # Errors
///
/// Returns [`ApiError::MissingCredential`] when the variable is unset or
/// empty, or [`ApiError::UnusableCredential`] when its value cannot be sent as
/// an HTTP header.
pub fn management_key() -> Result<ManagementKey, ApiError> {
    match env::var(MANAGEMENT_KEY_VAR) {
        Ok(value) => ManagementKey::from_secret(Zeroizing::new(value)),
        Err(VarError::NotPresent) => Err(ApiError::MissingCredential),
        Err(VarError::NotUnicode(_)) => Err(ApiError::UnusableCredential {
            reason: "it is not valid Unicode",
        }),
    }
}

/// The API root this process should talk to.
///
/// An override that is present but unusable is an error rather than a
/// fallback. Quietly ignoring it would send the management credential to
/// production while the operator believes it is going to the endpoint they
/// named — the one mistake an override like this must not be able to make.
/// A variable that is unset, or set to nothing at all, is not an override and
/// means production.
///
/// # Errors
///
/// Returns [`ApiError::Invariant`] when [`BASE_URL_VAR`] is set to something
/// that cannot be a base URL.
pub fn options() -> Result<Options, ApiError> {
    match env::var(BASE_URL_VAR) {
        Ok(base_url) if base_url.trim().is_empty() => Ok(Options::default()),
        Ok(base_url) => Ok(Options::new(base_url.trim())),
        Err(VarError::NotPresent) => Ok(Options::default()),
        Err(VarError::NotUnicode(_)) => Err(ApiError::invariant(&format!(
            "{BASE_URL_VAR} is set to a value that is not valid Unicode, so it cannot be a base \
             URL; unset it to use the production API root"
        ))),
    }
}
