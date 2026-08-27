//! The blocking OpenRouter management client.
//!
//! Keymaster is a sequential administration tool: it reads a snapshot, plans,
//! and then makes a handful of ordered writes. A blocking client is the honest
//! shape for that, and it keeps an async runtime out of a program that would
//! never overlap two requests anyway.
//!
//! Three properties are worth knowing before using this module.
//!
//! **One client, built one way.** [`build_http`] is the only place an HTTP
//! client is constructed. It sets a connect timeout, a whole-request timeout, a
//! user agent, `Accept: application/json`, and a redirect policy that refuses
//! to follow anything. `reqwest::blocking::Client::new` is in `clippy.toml`'s
//! disallowed list so a client without those cannot appear elsewhere by
//! accident.
//!
//! **Retries are a property of the operation, not of the transport.**
//! [`Client::get_json`] retries a bounded number of times on a connection
//! failure, a body that stops partway through, a 429, or one of a few 5xx
//! statuses — but not on a timeout, which has already been waited for, and not
//! on an oversized body, which would be oversized again.
//! [`Client::create_key_once`] has no retry loop in it at all — not a disabled
//! one, none — and the transport's own retry policy is turned off underneath
//! it, because a replayed `POST /keys` can create a live credential nobody
//! knows about and OpenRouter documents no idempotency token (ADR-0002).
//!
//! **A secret that arrives once is typed as such.** The create response is a
//! [`CreatedKey`], whose plaintext cannot be serialized, prints redacted, and
//! is cleared when dropped. No public method returns unrestricted JSON from a
//! write, so no caller can route that plaintext into `Debug` or `Serialize` by
//! choosing its own response type.
//!
//! **Nothing that leaves here carries a credential or a `reqwest` type.** The
//! management key is handed in by the caller, is held as a [`ManagementKey`]
//! that cannot be serialized or printed, and reaches the wire as a header
//! marked sensitive. Errors are [`ApiError`], whose text has been redacted.
//!
//! Nothing here reads the environment. Where the credential and the endpoint
//! come from is the caller's to decide; the binary reads them in its own
//! `openrouter_keymaster::app::env`.

mod create;
mod error;
mod patch;
pub mod retry;
mod secret;
mod url;

use std::io::{self, Read as _};
use std::time::Duration;

use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, RETRY_AFTER};
use serde::Serialize;
use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use zeroize::Zeroize as _;

pub use create::{CreateKeyRequest, CreatedKey, KeyPlaintext};
pub use error::ApiError;
pub use patch::Patch;
pub use retry::RetryPolicy;
pub use secret::{MANAGEMENT_KEY_VAR, ManagementKey};

/// OpenRouter's production API root.
pub const PRODUCTION_BASE_URL: &str = "https://openrouter.ai/api/v1";

/// Identifies Keymaster and its version to OpenRouter, so a problem caused by
/// one release is attributable.
const USER_AGENT: &str = concat!(
    "openrouter-keymaster/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/kljensen/openrouter-keymaster)"
);

/// How the client is built and how far it will go.
///
/// Every field is a bound. The defaults are the production ones; a test
/// overrides the base URL, and usually shortens the timeouts and flattens the
/// backoff so a case that exercises the retry path does not also exercise the
/// operator's patience.
#[derive(Debug, Clone)]
pub struct Options {
    /// The API root, without a trailing slash, query, or fragment.
    pub base_url: String,
    /// Longest wait for a connection to be established.
    pub connect_timeout: Duration,
    /// Longest wait for a whole request, connection and body included.
    pub request_timeout: Duration,
    /// Longest response body Keymaster will read.
    pub max_response_bytes: usize,
    /// How a safe read is retried.
    pub retry: RetryPolicy,
}

impl Options {
    /// Options for one API root, with production defaults elsewhere.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            ..Self::default()
        }
    }

    /// Whether [`Options::base_url`] is an endpoint a client can be built for.
    ///
    /// The same parser `Client::new` resolves requests with, so a caller can
    /// tell an unusable endpoint from a usable one before it has a client — or
    /// a credential to send anywhere.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Invariant`] unless the value parses as an absolute
    /// HTTP or HTTPS URL that names a host and carries no credentials, query,
    /// or fragment.
    pub fn check_base_url(&self) -> Result<(), ApiError> {
        Client::check_base_url(&self.base_url)
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            base_url: PRODUCTION_BASE_URL.to_owned(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            // Two orders of magnitude above the largest page of keys an
            // organization could plausibly have, and small enough that a
            // misdirected request cannot exhaust memory.
            max_response_bytes: 8 * 1024 * 1024,
            retry: RetryPolicy::default(),
        }
    }
}

/// A configured connection to one OpenRouter API root.
#[derive(Debug)]
pub struct Client {
    http: reqwest::blocking::Client,
    /// Normalized: absolute, no trailing slash, no query.
    base_url: String,
    options: Options,
}

impl Client {
    /// Whether a value can be used as a base URL, without building anything.
    ///
    /// The same parser [`Client::new`] resolves requests with, exposed so a
    /// caller can tell an unusable endpoint from a usable one before it has a
    /// client — or a credential to send anywhere.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Invariant`] unless the value parses as an absolute
    /// HTTP or HTTPS URL that names a host and carries no credentials, query,
    /// or fragment.
    pub fn check_base_url(base_url: &str) -> Result<(), ApiError> {
        url::base(base_url).map(|_| ())
    }

    /// Builds a client against an explicit API root.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Invariant`] when the base URL is not an absolute
    /// HTTP or HTTPS URL, or when the HTTP client cannot be built, and
    /// [`ApiError::UnusableCredential`] when the credential cannot be sent as
    /// a header.
    pub fn new(options: Options, key: &ManagementKey) -> Result<Self, ApiError> {
        let base_url = url::base(&options.base_url)?;
        let http = build_http(&options, key)?;
        Ok(Self {
            http,
            base_url,
            options,
        })
    }

    /// The API root this client talks to.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The bounds this client was built with.
    #[must_use]
    pub const fn options(&self) -> &Options {
        &self.options
    }

    /// Performs a safe read, retrying within [`Options::retry`].
    ///
    /// `segments` are joined onto the base URL and percent-encoded, so a hash
    /// or a name cannot address a different endpoint.
    ///
    /// # Errors
    ///
    /// Returns the [`ApiError`] the exchange ended with, after the policy is
    /// spent.
    pub fn get_json<T: DeserializeOwned>(
        &self,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<T, ApiError> {
        let url = url::build(&self.base_url, segments, query);
        let body = self.read_with_retry(&url)?;
        parse_json(&body)
    }

    /// Creates one API key, sending `POST /keys` exactly once.
    ///
    /// The response is the only time OpenRouter discloses the key's plaintext,
    /// so it is returned as a [`CreatedKey`], which cannot be serialized and
    /// prints redacted. The response bytes are cleared as soon as they have
    /// been parsed.
    ///
    /// # Errors
    ///
    /// Returns the [`ApiError`] the single attempt ended with. Every failure
    /// except a definite 4xx is ambiguous: the key may exist. Resolve it by
    /// refreshing remote state, never by calling this again (ADR-0002).
    pub fn create_key_once(&self, request: &CreateKeyRequest) -> Result<CreatedKey, ApiError> {
        let mut body = self.post_once(&["keys"], request)?;
        let created = create::parse_response(&body);
        // The plaintext is in these bytes. It has either been moved into a
        // `CreatedKey` or lost to a parse failure; either way this copy goes.
        body.zeroize();
        created?.into_created_key()
    }

    /// Sends one `POST` and parses its response. Never repeated.
    ///
    /// `pub(crate)`, like [`Client::patch_json_once`] and
    /// [`Client::post_once_discarding_body`]: the generic response type is
    /// what makes these usable for the ordinary write endpoints, and it is
    /// also what would let a caller deserialize the create response into
    /// `serde_json::Value` and hand a key's plaintext to `Debug` or
    /// `Serialize`. Keeping them inside the crate keeps the public rule — no
    /// public method returns unrestricted JSON from a write — intact, and
    /// [`Client::create_key_once`] remains the only way to reach `POST /keys`.
    ///
    /// # Errors
    ///
    /// Returns the [`ApiError`] the single attempt ended with. Every failure
    /// except a definite 4xx leaves the outcome unknown: resolve it by
    /// refreshing remote state, never by calling this again (ADR-0002).
    pub(crate) fn post_json_once<B: Serialize, T: DeserializeOwned>(
        &self,
        segments: &[&str],
        body: &B,
    ) -> Result<T, ApiError> {
        parse_json(&self.post_once(segments, body)?)
    }

    /// Sends one `POST` and reads its response without interpreting it.
    ///
    /// For an endpoint whose success is established by refetching rather than
    /// by what it echoes back: a body that does not parse is then not a
    /// failure, and a body that parses is not evidence.
    ///
    /// # Errors
    ///
    /// As [`Client::post_json_once`].
    pub(crate) fn post_once_discarding_body<B: Serialize>(
        &self,
        segments: &[&str],
        body: &B,
    ) -> Result<(), ApiError> {
        self.post_once(segments, body).map(|_| ())
    }

    /// Sends one `PATCH` and reads its response without interpreting it.
    ///
    /// # Errors
    ///
    /// As [`Client::post_json_once`].
    pub(crate) fn patch_once_discarding_body<B: Serialize>(
        &self,
        segments: &[&str],
        body: &B,
    ) -> Result<(), ApiError> {
        self.write_once(reqwest::Method::PATCH, segments, body)
            .map(|_| ())
    }

    /// Sends one `PUT` and reads its response without interpreting it.
    ///
    /// # Errors
    ///
    /// As [`Client::post_json_once`].
    pub(crate) fn put_once_discarding_body<B: Serialize>(
        &self,
        segments: &[&str],
        body: &B,
    ) -> Result<(), ApiError> {
        self.write_once(reqwest::Method::PUT, segments, body)
            .map(|_| ())
    }

    /// Sends one `DELETE` and reads its response without interpreting it.
    ///
    /// No body: the resource is named in the path, and a permanent removal
    /// should say what it removes exactly once. Like every other write here it
    /// is sent once and never repeated — a 404 on a resend would be
    /// indistinguishable from a 404 that proves the resource was never there.
    ///
    /// # Errors
    ///
    /// As [`Client::post_json_once`]. A 404 arrives as [`ApiError::Status`]
    /// with that status, which a caller may read as "already absent"; no other
    /// failure proves anything about whether the resource is gone.
    pub(crate) fn delete_once_discarding_body(&self, segments: &[&str]) -> Result<(), ApiError> {
        self.send_once(reqwest::Method::DELETE, segments, |request| request)
            .map(|_| ())
    }

    /// Sends one write and never repeats it.
    ///
    /// There is no retry loop here and no parameter that would enable one. A
    /// failure — a timeout, a lost connection, a 5xx, a body that does not
    /// parse — is reported as it happened, and the caller resolves the
    /// ambiguity by refreshing remote state, never by sending the request
    /// again (ADR-0002).
    fn post_once<B: Serialize>(&self, segments: &[&str], body: &B) -> Result<Vec<u8>, ApiError> {
        self.write_once(reqwest::Method::POST, segments, body)
    }

    /// One write request carrying a JSON body, sent exactly once.
    fn write_once<B: Serialize>(
        &self,
        method: reqwest::Method,
        segments: &[&str],
        body: &B,
    ) -> Result<Vec<u8>, ApiError> {
        self.send_once(method, segments, |request| request.json(body))
    }

    /// One write request, sent exactly once, shaped by the caller.
    ///
    /// The shaping closure is what lets a bodiless `DELETE` and a JSON `PATCH`
    /// share the single place that sends a non-idempotent request.
    fn send_once(
        &self,
        method: reqwest::Method,
        segments: &[&str],
        shape: impl FnOnce(reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder,
    ) -> Result<Vec<u8>, ApiError> {
        let url = url::build(&self.base_url, segments, &[]);
        let sent = shape(self.http.request(method, &url))
            .send()
            .map_err(|error| error::from_reqwest(&error, self.options.request_timeout))?;
        self.consume(sent).result
    }

    /// Sends a read until it succeeds or the retry policy is spent.
    fn read_with_retry(&self, url: &str) -> Result<Vec<u8>, ApiError> {
        let mut attempt: u32 = 1;
        loop {
            let attempted = self.attempt_read(url);
            let error = match attempted.result {
                Ok(body) => return Ok(body),
                Err(error) => error,
            };

            if !attempted.retryable {
                return Err(error);
            }
            let delay = retry::next_delay(
                &self.options.retry,
                attempt,
                attempted.retry_after.as_deref(),
                OffsetDateTime::now_utc(),
            );
            let Some(delay) = delay else {
                return Err(error);
            };
            std::thread::sleep(delay);
            attempt += 1;
        }
    }

    /// One `GET`, classified but not retried.
    fn attempt_read(&self, url: &str) -> Attempt {
        match self.http.get(url).send() {
            Ok(response) => self.consume(response),
            Err(error) => Attempt {
                // A read is safe to repeat, so a connection that was refused or
                // dropped is worth another attempt. A timeout is not: waiting
                // longer for a server that is answering slowly only multiplies
                // the wait an operator sits through.
                retryable: !error.is_timeout(),
                retry_after: None,
                result: Err(error::from_reqwest(&error, self.options.request_timeout)),
            },
        }
    }

    /// Reads a response and turns a failing status into a typed error.
    fn consume(&self, response: reqwest::blocking::Response) -> Attempt {
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        // Whether a failure is worth repeating depends on which half of the
        // exchange failed, so the body is classified before the status is.
        let (retryable, result) = match self.read_body(response) {
            // The body arrived whole. Only now does a transient status mean
            // anything: repeating a request whose body could not be read to the
            // end would be repeating it for a different reason.
            Ok(body) => (
                retry::is_retryable_status(status),
                if (200..300).contains(&status) {
                    Ok(body)
                } else {
                    Err(ApiError::from_status(status, &body))
                },
            ),
            // The body failed, but some statuses have already said everything
            // that matters and are reported as themselves.
            Err(error) => match definitive_without_body(status) {
                Some(definite) => (retry::is_retryable_status(status), Err(definite)),
                // Nothing definitive to fall back on, so the body's failure is
                // the answer. A truncated read — a connection reset partway
                // through a page — is worth another attempt for a safe read,
                // and is how a complete snapshot is obtained rather than a
                // partial one. The other two are not: an oversized body would
                // be oversized again, and a request that has already spent its
                // whole timeout does not deserve two more of them.
                None => (matches!(error, ApiError::Transport { .. }), Err(error)),
            },
        };

        Attempt {
            retryable,
            retry_after,
            result,
        }
    }

    /// Reads at most [`Options::max_response_bytes`], then stops.
    ///
    /// One byte past the cap is read deliberately: it is how an oversized body
    /// is told from one that exactly fills the budget.
    fn read_body(&self, response: reqwest::blocking::Response) -> Result<Vec<u8>, ApiError> {
        let limit = self.options.max_response_bytes;
        let mut body = Vec::new();
        let read = response
            .take(limit as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| self.body_failure(&error));

        read?;
        if body.len() > limit {
            return Err(ApiError::OversizedResponse { limit });
        }
        Ok(body)
    }

    /// Classifies a failure that happened while reading a body.
    ///
    /// A stall partway through a body expires the same whole-request timeout as
    /// a response that never started, and it arrives here as an ordinary I/O
    /// error. Reporting it as a transport failure would both mislabel it and,
    /// because a safe read repeats a transport failure, spend the timeout once
    /// per attempt.
    fn body_failure(&self, error: &io::Error) -> ApiError {
        if timed_out(error) {
            return ApiError::Timeout {
                after: self.options.request_timeout,
            };
        }
        ApiError::Transport {
            message: crate::redaction::redact(&error.to_string()),
        }
    }
}

/// Whether an I/O error from reading a body is the request timeout expiring.
///
/// `reqwest`'s blocking reader reports it either as the I/O kind or as a
/// `reqwest` error wrapped somewhere in the chain, so both are checked.
fn timed_out(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::TimedOut {
        return true;
    }

    let mut cause: Option<&(dyn std::error::Error + 'static)> =
        error.get_ref().map(|inner| inner as _);
    while let Some(error) = cause {
        if error
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout)
        {
            return true;
        }
        cause = error.source();
    }
    false
}

/// The error a status justifies on its own, when the body cannot be read.
///
/// A redirect and a rejection say more than the read failure that followed
/// them: the body carries a human-readable message and nothing Keymaster
/// decides from, so reporting "the connection dropped" instead would throw away
/// the one fact that names what happened.
///
/// 2xx and 5xx are absent deliberately. A success is its body, so a success
/// without one is not a success; and a 5xx is ambiguous whether or not its body
/// arrives, so nothing is gained by preferring it to the read failure.
///
/// "Complete without their body" is about the *diagnostic*, not about what the
/// exchange proves. The error built here records that the body did not arrive,
/// so [`ApiError::is_definite_rejection`] refuses it: a 400 whose response
/// stopped partway through still leaves it unknown whether `POST /keys` created
/// a key, and ADR-0002 requires a well-formed 4xx before a journal entry is
/// cleared.
fn definitive_without_body(status: u16) -> Option<ApiError> {
    (300..500)
        .contains(&status)
        .then(|| ApiError::from_incomplete_status(status))
}

/// What one attempt produced, and whether repeating it is allowed.
struct Attempt {
    retryable: bool,
    retry_after: Option<String>,
    result: Result<Vec<u8>, ApiError>,
}

/// The one approved HTTP client constructor.
///
/// Everything a management request needs is set here, because a client built
/// anywhere else would have none of it: no timeout, so a hung server blocks an
/// operator indefinitely; no redirect policy, so a 302 could carry the
/// `Authorization` header to another host; no user agent, so a problem is not
/// attributable to a release.
fn build_http(
    options: &Options,
    key: &ManagementKey,
) -> Result<reqwest::blocking::Client, ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(reqwest::header::AUTHORIZATION, key.authorization_header()?);

    reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .default_headers(headers)
        .connect_timeout(options.connect_timeout)
        .timeout(options.request_timeout)
        // Management traffic goes direct. `reqwest` reads `HTTP_PROXY`,
        // `HTTPS_PROXY`, and `ALL_PROXY` from the environment by default, and a
        // proxy named there terminates TLS to inspect what passes through it —
        // which here means reading the `Authorization` header, the one value
        // this whole module exists to protect. Ambient environment must not be
        // able to redirect a credential; an operator who genuinely needs a
        // proxy can have an explicit option for it, deliberately chosen.
        .no_proxy()
        // `reqwest` retransmits a request up to twice by default when HTTP/2
        // NACKs the stream — a `REFUSED_STREAM` reset or a graceful `GOAWAY`.
        // The protocol says the server did not process that stream, so the
        // resend is safe by HTTP's standard; Keymaster's standard for
        // `POST /keys` is stricter, because the cost of being wrong is a live
        // credential nobody knows about and no idempotency token to detect it
        // (ADR-0002). At-most-once transmission has to hold below the layer
        // where Keymaster can count requests, so the transport does no
        // retrying at all and `Client::get_json` retries reads explicitly.
        // The `lints` test fails if this line is removed.
        .retry(reqwest::retry::never())
        // Refused rather than limited: the request carries the management
        // credential, and the redirect target is chosen by whatever answered.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| ApiError::invariant(&format!("cannot build an HTTP client: {error}")))
}

/// Parses a response body, reporting a failure in Keymaster's own terms.
fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|error| ApiError::invalid_response(&error.to_string()))
}
