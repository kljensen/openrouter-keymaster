//! Building request URLs without letting a value change which resource is
//! addressed.
//!
//! Every path segment and query value here comes from somewhere else: a hash
//! OpenRouter returned, a UUID from a state file, a workspace an operator
//! typed. A `/` or a `?` in one of those would silently address a different
//! endpoint, so each is percent-encoded and joined onto a base URL that is
//! never allowed to carry a query of its own.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use super::error::ApiError;

/// Everything except the RFC 3986 unreserved characters is escaped.
///
/// Encoding is deliberately maximal: `-`, `.`, `_`, and `~` are the only
/// literals that survive, because those are the only ones a server is required
/// to treat as equivalent to their escaped form.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Checks and normalizes a base URL.
///
/// Parsed rather than pattern-matched. A prefix check reads as sufficient and
/// is not: `https:///api` starts with `https://` and names no host, and a URL
/// parser is then free to read `api` as the host — which would send the
/// management credential to whatever answers at that name. Deciding where a
/// request goes is the parser's job, so the parser is what validates it.
///
/// The value returned is the trimmed original rather than the parser's
/// normalization, so a base URL reaches the wire exactly as it was configured.
///
/// # Errors
///
/// Returns [`ApiError::Invariant`] unless the value parses as an absolute HTTP
/// or HTTPS URL that names a host and carries no credentials, query, or
/// fragment.
pub(super) fn base(value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim().trim_end_matches('/');
    // Whether the value may be quoted is decided once, before anything can be
    // reported, because the checks below run in an order the value does not
    // respect: `https://user:hunter2@host:99999/api` fails to *parse*, so the
    // first error out of this function would have quoted a password long before
    // the userinfo check had a chance to run. Anything that could introduce a
    // credential — userinfo, a query, a fragment — makes the value unquotable
    // whatever eventually rejects it.
    let shown = (!trimmed.contains(['@', '?', '#'])).then_some(value);

    // `reqwest::Url` is `url::Url`, and it is what `reqwest` itself will parse
    // this string with later. Validating with a different parser than the one
    // that resolves the request would be validating a different question. It
    // stays inside this function: no `reqwest` type reaches the public API.
    let parsed = reqwest::Url::parse(trimmed).map_err(|error| {
        // `url`'s messages name the kind of failure — `empty host`, `invalid
        // port number` — and never quote the input, so the reason is safe to
        // repeat even when the value itself is not.
        refused(&format!("could not be parsed: {error}"), shown)
    })?;

    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(refused("must use `https://` or `http://`", shown));
    }
    if parsed.host_str().unwrap_or_default().is_empty() {
        return Err(refused("must name a host", shown));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(refused(
            "must carry no username or password; Keymaster authenticates with the management \
             credential from the environment",
            None,
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(refused("must carry no query or fragment", shown));
    }

    // The check that catches `https:///api`. Parsing alone does not: the URL
    // grammar collapses the empty authority and reads `api` as the *host*, so
    // asking whether a host is present answers yes to the very input that has
    // none. What gives it away is that the parser had to rewrite the string to
    // reach that reading. So the rule is that a base URL must already be what
    // it will be requested as — case aside, since a host is case-insensitive —
    // and anything the parser reinterprets is refused rather than guessed at.
    let requested = parsed.as_str();
    if !requested
        .trim_end_matches('/')
        .eq_ignore_ascii_case(trimmed)
    {
        // Reached only after userinfo, query, and fragment have been refused,
        // so `requested` holds nothing the value did not already show — but it
        // goes through the same gate as every other message rather than relying
        // on that ordering staying true.
        return Err(refused(
            &format!(
                "must already be written the way it will be requested; as given it would be \
                 requested as `{requested}`"
            ),
            shown,
        ));
    }
    Ok(trimmed.to_owned())
}

/// Builds a rejection, quoting the offending value only when it is safe to.
fn refused(reason: &str, value: Option<&str>) -> ApiError {
    ApiError::invariant(&value.map_or_else(
        || format!("the base URL {reason}"),
        |value| format!("the base URL {reason}, but it is `{value}`"),
    ))
}

/// Joins percent-encoded path segments and query parameters onto a base URL.
pub(super) fn build(base: &str, segments: &[&str], query: &[(&str, String)]) -> String {
    let mut url = base.to_owned();
    for segment in segments {
        url.push('/');
        url.extend(utf8_percent_encode(segment, UNRESERVED));
    }

    for (index, (name, value)) in query.iter().enumerate() {
        url.push(if index == 0 { '?' } else { '&' });
        url.extend(utf8_percent_encode(name, UNRESERVED));
        url.push('=');
        url.extend(utf8_percent_encode(value, UNRESERVED));
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_cannot_escape_their_position() {
        let url = build(
            "https://openrouter.ai/api/v1",
            &["keys", "a/../b?c#d e"],
            &[],
        );
        assert_eq!(
            url,
            "https://openrouter.ai/api/v1/keys/a%2F..%2Fb%3Fc%23d%20e"
        );
    }

    #[test]
    fn query_parameters_are_encoded_and_ordered_as_given() {
        let url = build(
            "http://127.0.0.1:1/api/v1",
            &["keys"],
            &[
                ("offset", "0".to_owned()),
                ("workspace_id", "a b&c=d".to_owned()),
            ],
        );
        assert_eq!(
            url,
            "http://127.0.0.1:1/api/v1/keys?offset=0&workspace_id=a%20b%26c%3Dd"
        );
    }

    #[test]
    fn unreserved_characters_are_left_alone() {
        let url = build("https://h/api", &["keys", "a-b_c.d~e"], &[]);
        assert_eq!(url, "https://h/api/keys/a-b_c.d~e");
    }

    #[test]
    fn base_urls_are_accepted_as_written() {
        for (given, expected) in [
            (
                "https://openrouter.ai/api/v1",
                "https://openrouter.ai/api/v1",
            ),
            // A trailing slash is dropped so joining a segment cannot double it.
            (
                "https://openrouter.ai/api/v1/",
                "https://openrouter.ai/api/v1",
            ),
            (
                "  https://openrouter.ai/api/v1  ",
                "https://openrouter.ai/api/v1",
            ),
            (
                "http://127.0.0.1:53019/api/v1",
                "http://127.0.0.1:53019/api/v1",
            ),
            ("https://openrouter.ai", "https://openrouter.ai"),
        ] {
            assert_eq!(base(given).expect("a valid base URL"), expected, "{given}");
        }
    }

    #[test]
    fn a_base_url_that_names_no_host_is_refused() {
        // `https:///api` is the one a prefix check waves through, and parsing
        // alone does not catch it either: the URL grammar reads `api` as the
        // host, so a credential would go to whatever answers at that name.
        for rejected in [
            "https:///api",
            "http:///api",
            "https://",
            "https:///",
            r"https://\/api",
            r"https:/\/api",
        ] {
            let failure = base(rejected).expect_err("a URL naming no host is refused");
            assert_eq!(failure.kind(), "invariant", "{rejected}");
            assert!(
                !base_is_host(rejected, "api"),
                "{rejected} must never resolve to the host `api`"
            );
        }
    }

    /// Whether the URL parser reads `raw` as pointing at `host`.
    fn base_is_host(raw: &str, host: &str) -> bool {
        reqwest::Url::parse(raw.trim().trim_end_matches('/'))
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned))
            .is_some_and(|parsed| parsed == host)
            && base(raw).is_ok()
    }

    #[test]
    fn base_urls_of_the_wrong_shape_are_refused() {
        for rejected in [
            "",
            "   ",
            "openrouter.ai/api/v1",
            "//openrouter.ai/api/v1",
            "ftp://openrouter.ai",
            "file:///etc/passwd",
            "openrouter.ai:443",
            "https://openrouter.ai/api/v1?token=x",
            "https://openrouter.ai/api/v1#fragment",
            "https://open router.ai/api/v1",
        ] {
            let failure = base(rejected).expect_err("an unusable base URL is refused");
            assert_eq!(failure.kind(), "invariant", "{rejected}");
        }
    }

    #[test]
    fn a_base_url_carrying_a_credential_is_refused_without_repeating_it() {
        // Every one of these is rejected by a different check — userinfo, a
        // parse failure, an unusable scheme, a query — and the value reaches
        // each of them with a secret still in it. Which check fires first is
        // not something the value gets to decide, so none of them may quote it.
        for rejected in [
            // Refused by the userinfo check.
            "https://user:hunter2@openrouter.ai/api/v1",
            "https://user@openrouter.ai/api/v1",
            // Refused by the parser, before the userinfo check runs at all.
            "https://user:hunter2@",
            "https://user:hunter2@openrouter.ai:99999/api/v1",
            "https://user:hunter2@[bad",
            // Refused by the scheme check, likewise before it.
            "ftp://user:hunter2@openrouter.ai/api/v1",
            // A secret can sit in a query as easily as in userinfo.
            "https://openrouter.ai/api/v1?token=hunter2",
            "https://openrouter.ai/api/v1#hunter2",
        ] {
            let failure = base(rejected).expect_err("a base URL with a secret in it is refused");
            assert_eq!(failure.kind(), "invariant", "{rejected}");

            let message = failure.to_string();
            assert!(
                !message.contains("hunter2"),
                "{rejected} leaked its secret: {message}"
            );
            // Nor the value in any other form: the whole string stays out.
            assert!(!message.contains('@'), "{rejected}: {message}");
            assert!(!message.contains("openrouter.ai"), "{rejected}: {message}");

            // The reason still has to be worth reading.
            assert!(message.contains("base URL"), "{rejected}: {message}");
        }
    }

    #[test]
    fn a_value_with_nothing_to_hide_is_quoted_so_a_typo_is_obvious() {
        for rejected in [
            "openrouter.ai/api/v1",
            "ftp://openrouter.ai",
            "https:///api",
        ] {
            let message = base(rejected)
                .expect_err("an unusable base URL is refused")
                .to_string();
            assert!(
                message.contains(rejected),
                "{rejected} should be quoted back: {message}"
            );
        }
    }
}
