//! Everything that can go wrong talking to OpenRouter, in Keymaster's own
//! vocabulary.
//!
//! Two rules hold for every variant. It carries no `reqwest` type, so the HTTP
//! library stays an implementation detail and the application model does not
//! change when it does. And every string in one has been through
//! [`crate::redaction::redact`], because the two places text arrives from — a
//! transport error and an API error body — are written by something other than
//! Keymaster and can quote a request that carried a credential.

use std::fmt;
use std::ops::Deref;
use std::time::Duration;

use serde::Deserialize;
use zeroize::{Zeroize as _, Zeroizing};

use super::secret::MANAGEMENT_KEY_VAR;
use crate::redaction;

/// Longest excerpt of a remote message any error repeats.
const MAX_DETAIL: usize = 200;

/// A piece of text an error kept from something Keymaster did not write.
///
/// It clears itself when it drops, and that is the whole reason it exists.
/// Every string in an [`ApiError`] comes from a transport failure or a response
/// body, both of which can quote the request that produced them — a log
/// destination's validation error can echo the `config` it refused, which may be
/// a third-party credential (ADR-0006, item 4). Redaction handles what such a
/// message *shows*; this handles what it leaves behind.
///
/// Redaction is not enough on its own here, which is the point. The exact-value
/// registry is populated when a configuration is loaded, and two commands never
/// load one: `delete log-destination` acts on a UUID alone, as `delete key`
/// does. So a body quoting the credential arrives with nothing registered to
/// match it, and the honest answer is to keep it in a buffer that clears rather
/// than to assume the redactor saw it.
///
/// `Display` and `Deref` give back exactly the text, so every error message
/// reads as it always did.
pub struct Detail(Zeroizing<String>);

impl Detail {
    /// The text itself.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Detail {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl Deref for Detail {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Detail {
    /// The text, quoted, exactly as the `String` this replaced printed. An
    /// error's `Debug` is a diagnostic an operator may need, and the value it
    /// holds has already been through [`excerpt`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

/// Why a request to the OpenRouter management API did not produce a usable
/// answer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApiError {
    /// No management credential is available.
    #[error(
        "no management credential: set {MANAGEMENT_KEY_VAR} to an OpenRouter management key, \
         created on OpenRouter's Management API Keys page"
    )]
    MissingCredential,

    /// A credential was present but cannot be sent.
    #[error("the credential in {MANAGEMENT_KEY_VAR} cannot be used: {reason}")]
    UnusableCredential {
        /// What is wrong with it. Never the value itself.
        reason: &'static str,
    },

    /// The request never reached OpenRouter, or the connection failed.
    #[error("cannot reach the OpenRouter API: {message}")]
    Transport {
        /// The transport's explanation, redacted and cleared when it drops.
        message: Detail,
    },

    /// No response arrived within the configured timeout.
    #[error("the OpenRouter API did not answer within {after:?}")]
    Timeout {
        /// The timeout that elapsed.
        after: Duration,
    },

    /// OpenRouter refused the credential.
    #[error(
        "OpenRouter rejected the management credential (HTTP {status}){}{}",
        detail(.message),
        incomplete(*.body_complete)
    )]
    Authentication {
        /// The HTTP status, 401 or 403.
        status: u16,
        /// OpenRouter's own message, redacted and cleared when it drops, when
        /// it sent one.
        message: Option<Detail>,
        /// Whether the response body was read to the end. See
        /// [`ApiError::is_definite_rejection`].
        body_complete: bool,
    },

    /// OpenRouter answered with an error status.
    #[error("OpenRouter returned HTTP {status}{}{}", detail(.message), incomplete(*.body_complete))]
    Status {
        /// The HTTP status.
        status: u16,
        /// The `error.code` field of the response body, when it had one.
        code: Option<i64>,
        /// The `error.message` field of the response body, redacted and cleared
        /// when it drops.
        message: Option<Detail>,
        /// Whether the response body was read to the end. See
        /// [`ApiError::is_definite_rejection`].
        body_complete: bool,
    },

    /// OpenRouter answered with a redirect.
    ///
    /// Keymaster does not follow one: the request carries a management
    /// credential, and the redirect target is chosen by whatever answered.
    #[error(
        "OpenRouter redirected the request (HTTP {status}); Keymaster does not follow redirects \
         from the management API, because the request carries the management credential"
    )]
    Redirected {
        /// The HTTP status.
        status: u16,
    },

    /// The response arrived but is not something Keymaster can act on.
    #[error("the OpenRouter API returned a response Keymaster cannot use: {message}")]
    InvalidResponse {
        /// What was wrong with it, redacted and cleared when it drops.
        message: Detail,
    },

    /// The response body was larger than Keymaster will read.
    #[error("the OpenRouter API returned more than {limit} bytes; Keymaster stopped reading")]
    OversizedResponse {
        /// The cap that was exceeded, in bytes.
        limit: usize,
    },

    /// Keymaster asked itself to do something impossible.
    #[error("openrouter-keymaster cannot make this request: {message}")]
    Invariant {
        /// What was wrong, redacted and cleared when it drops.
        message: Detail,
    },
}

impl ApiError {
    /// A stable machine-readable category, used as the `kind` field of JSON
    /// diagnostics. Treat these strings as a compatibility surface.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::MissingCredential => "missing_credential",
            Self::UnusableCredential { .. } => "unusable_credential",
            Self::Transport { .. } => "transport",
            Self::Timeout { .. } => "timeout",
            Self::Authentication { .. } => "authentication",
            Self::Status { .. } => "http_status",
            Self::Redirected { .. } => "redirected",
            Self::InvalidResponse { .. } => "invalid_response",
            Self::OversizedResponse { .. } => "oversized_response",
            Self::Invariant { .. } => "invariant",
        }
    }

    /// The HTTP status Keymaster saw, when it saw one.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Authentication { status, .. }
            | Self::Status { status, .. }
            | Self::Redirected { status } => Some(*status),
            _ => None,
        }
    }

    /// Whether this answer proves the server processed the request and declined
    /// it without applying it.
    ///
    /// The one question ADR-0002 asks of a failed `POST /keys`, and the reason
    /// the status alone will not answer it. A definite rejection needs a
    /// *well-formed* 4xx: the server saw the request, refused it, and said so
    /// in a response that arrived whole. A 4xx status line followed by a body
    /// that stops partway through is a different thing — the status is the last
    /// complete fact Keymaster has, the exchange failed after it, and treating
    /// that as proof that nothing was created would clear a journal entry for
    /// an attempt that may have made a live key.
    ///
    /// So both halves are required. A 3xx is never a rejection either: it is a
    /// redirect Keymaster refuses to follow, and what the server would have
    /// done with the request is unknown.
    #[must_use]
    pub const fn is_definite_rejection(&self) -> bool {
        match self {
            Self::Authentication { body_complete, .. } => *body_complete,
            Self::Status {
                status,
                body_complete,
                ..
            } => *body_complete && *status >= 400 && *status < 500,
            _ => false,
        }
    }

    /// The HTTP status and OpenRouter's error code, and nothing else.
    ///
    /// For the one class of write whose failure must not repeat a response
    /// body: a log destination's `config` may hold a third-party credential,
    /// and a validation error can quote the value it refused, so a destination
    /// write reports only what the status line and the error code say
    /// (ADR-0006, item 4). Every arm below is fixed text plus a number.
    #[must_use]
    pub fn status_and_code(&self) -> String {
        match self {
            Self::Status {
                status,
                code: Some(code),
                ..
            } => format!("HTTP {status}, OpenRouter error code {code}"),
            Self::Status { status, .. }
            | Self::Authentication { status, .. }
            | Self::Redirected { status } => format!("HTTP {status}"),
            Self::Timeout { .. } => "no answer within the request timeout".to_owned(),
            Self::Transport { .. } => "the request did not reach OpenRouter".to_owned(),
            Self::InvalidResponse { .. } => "the response could not be read".to_owned(),
            Self::OversizedResponse { .. } => {
                "the response was larger than Keymaster reads".to_owned()
            }
            Self::MissingCredential | Self::UnusableCredential { .. } | Self::Invariant { .. } => {
                self.kind().to_owned()
            }
        }
    }

    /// An invalid-response error carrying redacted text.
    pub(super) fn invalid_response(message: &str) -> Self {
        Self::InvalidResponse {
            message: excerpt(message),
        }
    }

    /// An invariant error carrying redacted text.
    ///
    /// Public because the binary crate's environment reader
    /// (`openrouter_keymaster::app::env`) refuses an endpoint that cannot be a
    /// base URL, and that refusal is this error like any other.
    pub fn invariant(message: &str) -> Self {
        Self::Invariant {
            message: excerpt(message),
        }
    }

    /// Classifies a failed HTTP exchange whose body arrived whole.
    ///
    /// `body` is the response body as read, which may be JSON, may be a plain
    /// string, and may be neither. What matters for
    /// [`ApiError::is_definite_rejection`] is not that it parsed but that it
    /// *finished*: a server that sent a complete response processed the request
    /// and answered it, whatever it chose to put in the body.
    pub(super) fn from_status(status: u16, body: &[u8]) -> Self {
        Self::classify(status, body, true)
    }

    /// Classifies a failed exchange whose body could not be read to the end.
    ///
    /// The status is worth keeping — it is more informative than the read
    /// failure that followed it — but it is not a complete answer, and
    /// [`ApiError::is_definite_rejection`] says so.
    pub(super) fn from_incomplete_status(status: u16) -> Self {
        Self::classify(status, &[], false)
    }

    fn classify(status: u16, body: &[u8], body_complete: bool) -> Self {
        if (300..400).contains(&status) {
            return Self::Redirected { status };
        }

        let reported = ReportedError::parse(body);
        let message = reported.as_ref().map(|error| excerpt(&error.message));
        if status == 401 || status == 403 {
            return Self::Authentication {
                status,
                message,
                body_complete,
            };
        }
        Self::Status {
            status,
            code: reported.and_then(|error| error.code),
            message,
            body_complete,
        }
    }
}

/// Converts a transport failure, keeping `reqwest` out of the public model.
pub(super) fn from_reqwest(error: &reqwest::Error, timeout: Duration) -> ApiError {
    if error.is_timeout() {
        return ApiError::Timeout { after: timeout };
    }
    ApiError::Transport {
        message: excerpt(&error.to_string()),
    }
}

/// Redacts and truncates untrusted text so it is safe to show and bounded.
fn excerpt(message: &str) -> Detail {
    let redacted = redaction::redact(message);
    if redacted.chars().count() <= MAX_DETAIL {
        return redacted.into();
    }
    let mut truncated: String = redacted.chars().take(MAX_DETAIL).collect();
    truncated.push('…');
    truncated.into()
}

/// Says so when the answer stopped before its body finished.
///
/// Worth a phrase in the message rather than only a field, because the two
/// failures read identically otherwise and they mean opposite things for a
/// create: one says the key was not made, the other says nobody knows.
fn incomplete(body_complete: bool) -> &'static str {
    if body_complete {
        ""
    } else {
        " (the response stopped before its body finished, so what the server did with the \
         request is unknown)"
    }
}

/// Renders an optional remote message as a suffix.
fn detail(message: &Option<Detail>) -> String {
    message
        .as_ref()
        .map_or_else(String::new, |message| format!(": {message}"))
}

/// The error body OpenRouter documents for every failing status.
///
/// `message` is cleared when this drops. It is the one piece of a failing
/// response Keymaster parses out and keeps for a moment, and a validation error
/// from a log destination write can quote the `config` it refused — which may
/// be a third-party credential (ADR-0006, item 4). What is stored in the
/// [`ApiError`] afterwards is the redacted excerpt, never this.
#[derive(Debug, Deserialize)]
struct ReportedError {
    /// OpenRouter repeats the HTTP status here; it is not always an integer in
    /// practice, so a missing or unexpected value is simply dropped.
    #[serde(default)]
    code: Option<i64>,
    message: String,
}

impl Drop for ReportedError {
    fn drop(&mut self) {
        self.message.zeroize();
    }
}

impl ReportedError {
    /// Reads `{"error": {"code": …, "message": …}}`, if that is what arrived.
    fn parse(body: &[u8]) -> Option<Self> {
        #[derive(Deserialize)]
        struct Envelope {
            error: ReportedError,
        }

        serde_json::from_slice::<Envelope>(body)
            .ok()
            .map(|envelope| envelope.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every string an error keeps is a [`Detail`], so it clears when the error
    /// drops.
    ///
    /// A type assertion, for the reason the one over response buffers is: freed
    /// memory is not observable from a test, and what would regress this is a
    /// field going back to a bare `String`. Two commands make it matter —
    /// `delete log-destination` and `delete key` act on an identity alone and
    /// never load a configuration, so the exact-value redactor has nothing
    /// registered and a body quoting a credential reaches the error unscrubbed.
    #[test]
    fn every_message_an_error_keeps_is_held_in_a_buffer_that_clears_itself() {
        let _transport: fn(String) -> Detail = Detail::from;
        let error = ApiError::Status {
            status: 400,
            code: Some(400),
            message: Some("invalid config".to_owned().into()),
            body_complete: true,
        };
        let ApiError::Status { message, .. } = &error else {
            panic!("this is a status error");
        };
        let _: &Option<Detail> = message;
    }

    /// The one thing that must not change: an error reads exactly as it did.
    #[test]
    fn a_detail_renders_as_the_text_it_holds() {
        let detail: Detail = "Not found".to_owned().into();
        assert_eq!(detail.to_string(), "Not found");
        assert_eq!(&*detail, "Not found");
        assert_eq!(
            format!("{detail:?}"),
            "\"Not found\"",
            "quoted, exactly as the `String` this replaced printed, so an \
             `Option<Detail>` still reads `Some(\"…\")`"
        );

        let error = ApiError::Status {
            status: 404,
            code: Some(404),
            message: Some(detail),
            body_complete: true,
        };
        assert_eq!(error.to_string(), "OpenRouter returned HTTP 404: Not found");
        assert_eq!(error.kind(), "http_status");
        assert_eq!(error.status(), Some(404));
        assert_eq!(
            error.status_and_code(),
            "HTTP 404, OpenRouter error code 404"
        );
    }

    /// And an error with no message still renders the way it always did.
    #[test]
    fn an_error_with_no_message_renders_as_it_always_did() {
        let error = ApiError::Status {
            status: 500,
            code: None,
            message: None,
            body_complete: false,
        };
        assert!(
            error
                .to_string()
                .starts_with("OpenRouter returned HTTP 500 ("),
            "{error}"
        );
        assert!(!error.is_definite_rejection());
    }
}
