//! Retry policy, as pure functions.
//!
//! Nothing here sends a request, reads a clock, or sleeps. Each function takes
//! what it needs — the attempt number, the server's `Retry-After`, the current
//! instant — and returns a delay, so the policy can be unit tested exactly and
//! driven by a fake clock. [`super::Client`] is the only thing that sleeps.
//!
//! The policy applies to safe reads only. A write has no retry plumbing at all:
//! `POST /keys` returns a key's plaintext once, and a replayed create can leave
//! a live credential nobody knows about (ADR-0002).

use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;

/// How long a bounded read may keep trying.
///
/// Every field is a bound, not a suggestion: a server that asks for an hour
/// through `Retry-After` gets [`RetryPolicy::max_backoff`] instead, so no
/// remote value can decide how long Keymaster blocks an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, including the first. One means never retry.
    pub max_attempts: u32,
    /// Delay before the second attempt; doubled for each one after that.
    pub initial_backoff: Duration,
    /// Longest delay between two attempts, whatever the doubling or the
    /// server's `Retry-After` works out to.
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(8),
        }
    }
}

impl RetryPolicy {
    /// A policy that never retries, for a request that must be sent at most
    /// once.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            max_attempts: 1,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        }
    }
}

/// The statuses a safe read may be repeated after.
///
/// 429 and 503 say so outright. 500, 502, and 504 are the shapes a failed
/// upstream hop takes. 501 and 505 are not here: repeating a request the server
/// says it will never handle only wastes an operator's time.
#[must_use]
pub const fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// The doubling delay before attempt number `attempt + 1`, bounded by the
/// policy.
///
/// `attempt` is 1-based: after the first attempt fails the delay is
/// [`RetryPolicy::initial_backoff`], after the second it is twice that, and so
/// on until [`RetryPolicy::max_backoff`].
#[must_use]
pub fn backoff(policy: &RetryPolicy, attempt: u32) -> Duration {
    let doublings = attempt.saturating_sub(1).min(u32::BITS - 1);
    policy
        .initial_backoff
        .saturating_mul(1_u32 << doublings)
        .min(policy.max_backoff)
}

/// Reads a `Retry-After` header value.
///
/// HTTP allows two spellings: a whole number of seconds, and an absolute
/// instant. Both are honoured; an instant already past is zero rather than an
/// error, and anything else is `None` so the caller falls back to its own
/// backoff. The result is not bounded here — [`next_delay`] applies the policy.
#[must_use]
pub fn retry_after(value: &str, now: OffsetDateTime) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let when = http_date(value)?;
    if when <= now {
        return Some(Duration::ZERO);
    }
    // The difference is positive and both instants are real timestamps, so the
    // conversion cannot fail; a clamp keeps the function total either way.
    (when - now).try_into().ok()
}

/// How long to wait before attempt number `attempt + 1`, or `None` when the
/// policy is spent.
///
/// The server's `Retry-After` is preferred when it parses, because it is the
/// only party that knows when a rate limit lifts, but it is clamped to
/// [`RetryPolicy::max_backoff`] like every other delay.
#[must_use]
pub fn next_delay(
    policy: &RetryPolicy,
    attempt: u32,
    retry_after_header: Option<&str>,
    now: OffsetDateTime,
) -> Option<Duration> {
    if attempt >= policy.max_attempts {
        return None;
    }
    let requested = retry_after_header.and_then(|value| retry_after(value, now));
    Some(
        requested
            .unwrap_or_else(|| backoff(policy, attempt))
            .min(policy.max_backoff),
    )
}

/// The HTTP-date formats that carry an unambiguous year.
///
/// RFC 9110's third form, RFC 850's `Sunday, 06-Nov-94 …`, is deliberately not
/// here: its two-digit year has no unambiguous reading, and no server has sent
/// one this century. A value that matches none of these is simply not a
/// `Retry-After` Keymaster can use, and [`next_delay`] falls back to its own
/// backoff — which is bounded, unlike a guess at what the server meant.
const HTTP_DATES: [&[BorrowedFormatItem<'_>]; 2] = [
    // IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT`.
    format_description!(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
    ),
    // asctime: `Sun Nov  6 08:49:37 1994`.
    format_description!(
        "[weekday repr:short] [month repr:short] [day padding:space] [hour]:[minute]:[second] \
         [year]"
    ),
];

/// Parses an HTTP-date. All three forms are UTC by definition.
fn http_date(value: &str) -> Option<OffsetDateTime> {
    HTTP_DATES.iter().find_map(|format| {
        time::PrimitiveDateTime::parse(value, format)
            .ok()
            .map(time::PrimitiveDateTime::assume_utc)
    })
}
