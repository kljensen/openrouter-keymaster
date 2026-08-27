//! Making untrusted text safe to show an operator.
//!
//! Keymaster never accepts credential plaintext as input and never repeats it
//! in a diagnostic. Four defences live here: a predicate that rejects a value
//! at the boundary where it is parsed, an escaper for text that reaches a
//! terminal or a log, a redactor for the one class of message Keymaster does
//! not write itself — a deserializer's error, which may quote the offending
//! input — and a run-scoped registry of exact values to scrub.
//!
//! The registry exists for one thing: a log destination's `config`, which is
//! the only configuration value that may hold a third-party credential
//! (ADR-0006, item 4). Such a value carries no marker this module could
//! recognize, so the values themselves are registered when the configuration
//! is loaded and scrubbed by exact match from everything [`redact`] touches.

use std::collections::BTreeSet;
use std::sync::{PoisonError, RwLock};

/// The marker every OpenRouter credential carries.
///
/// What follows it does not say which kind of credential it is: a management
/// key from OpenRouter's Management API Keys page carries the same `sk-or-v1-`
/// shape an inference key does. So the marker is the whole test, and any
/// `sk-or-` string is treated as a secret.
const CREDENTIAL_MARKER: &str = "sk-or-";

/// What a redacted token is replaced with.
const REPLACEMENT: &str = "[redacted]";

/// The shortest value [`register`] will accept.
///
/// A heuristic, and stated as one (ADR-0006, item 4): credentials are long,
/// while a short value such as a region, a hostname fragment, or a flag would
/// otherwise be scrubbed out of every sentence that happens to contain it.
pub const MIN_REGISTERED_LENGTH: usize = 16;

/// Values registered for the rest of this run, longest first.
///
/// Process-lifetime by design: a value registered while the configuration is
/// read has to be scrubbed from a message written at any later point in the
/// run, and there is no scope narrower than the process that every one of
/// those messages sits inside. The copy this holds is of a value that is
/// already sitting in the configuration file on disk.
static REGISTERED: RwLock<BTreeSet<String>> = RwLock::new(BTreeSet::new());

/// Registers one value to be scrubbed by exact match for the rest of the run.
///
/// Values shorter than [`MIN_REGISTERED_LENGTH`] characters are ignored, which
/// is what keeps the registry from turning ordinary words into `[redacted]`.
pub fn register(value: &str) {
    if value.chars().count() < MIN_REGISTERED_LENGTH {
        return;
    }
    let mut registered = REGISTERED.write().unwrap_or_else(PoisonError::into_inner);
    registered.insert(value.to_owned());
}

/// Replaces every registered value in `message`.
///
/// Longest first, so a registered value that contains another is replaced
/// whole rather than leaving the tail of it behind.
fn scrub_registered(message: &str) -> String {
    let registered = REGISTERED.read().unwrap_or_else(PoisonError::into_inner);
    if registered.is_empty() {
        return message.to_owned();
    }
    let mut ordered: Vec<&String> = registered.iter().collect();
    ordered.sort_by_key(|value| std::cmp::Reverse(value.len()));

    let mut scrubbed = message.to_owned();
    for value in ordered {
        if scrubbed.contains(value.as_str()) {
            scrubbed = scrubbed.replace(value.as_str(), REPLACEMENT);
        }
    }
    scrubbed
}

/// Whether `value` contains something shaped like an OpenRouter credential.
///
/// Matching is case-insensitive and looks anywhere in the value, because a
/// secret pasted into a configuration field is as likely to be surrounded by
/// other text as to stand alone.
///
/// The search allocates nothing. That is a security property, not a
/// performance one: this runs on credential plaintext — `KeyHash::parse`
/// checks every hash the create response returns — and a lowercased copy would
/// be a second, untracked allocation of the secret, dropped without being
/// cleared and beyond the reach of every wrapper that exists to clear it.
///
/// Comparing raw bytes is safe here because the marker is ASCII, and a UTF-8
/// multi-byte sequence never contains an ASCII byte: no window can match part
/// of a character.
#[must_use]
pub fn looks_like_credential(value: &str) -> bool {
    let marker = CREDENTIAL_MARKER.as_bytes();
    value
        .as_bytes()
        .windows(marker.len())
        .any(|window| window.eq_ignore_ascii_case(marker))
}

/// Escapes everything that is not plain printable text.
///
/// An error message is written to a terminal and to a log, and part of it can
/// come from a configuration or state file that Keymaster did not write. A
/// control character there is not cosmetic: an ANSI escape sequence can
/// rewrite the line an operator is reading, and a bidirectional override can
/// make a name render as something other than what it is. Anything outside
/// printable ASCII is therefore shown as its escape — `\n`, `\u{1b}` — which
/// is also more informative than an invisible character would be.
#[must_use]
pub fn printable(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len());
    for character in value.chars() {
        if character == ' ' || character.is_ascii_graphic() {
            rendered.push(character);
        } else {
            rendered.extend(character.escape_default());
        }
    }
    rendered
}

/// Replaces every registered value and every whitespace-delimited token that
/// looks like a credential, and escapes what is left with [`printable`].
///
/// Registered values are scrubbed first, and by exact match rather than by
/// token, because such a value may contain whitespace.
///
/// Whitespace is normalized to single spaces, which is acceptable for the
/// error messages this is used on and keeps the implementation obvious.
#[must_use]
pub fn redact(message: &str) -> String {
    scrub_registered(message)
        .split_whitespace()
        .map(|token| {
            if looks_like_credential(token) {
                REPLACEMENT.to_owned()
            } else {
                printable(token)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_prefixes_are_recognized_anywhere_in_a_value() {
        assert!(looks_like_credential("sk-or-v1-abc"));
        // A management key looks like an inference key, so the marker match
        // must not depend on what follows it.
        assert!(looks_like_credential("sk-or-mgmt-abc"));
        assert!(looks_like_credential("Bearer SK-OR-V1-ABC"));
        assert!(!looks_like_credential("google/gemini-2.5-flash"));
        assert!(!looks_like_credential("skorv1"));
    }

    #[test]
    fn the_marker_is_matched_whatever_its_case_and_wherever_it_sits() {
        // The scan compares bytes rather than lowercasing a copy, so every
        // mixed spelling, every position, and every length near the marker's
        // own is worth stating outright.
        for matched in [
            "sk-or-",
            "SK-OR-",
            "Sk-Or-V1-abc",
            "sK-oR-MGMT-abc",
            "trailing sk-OR-v1",
            "sk-or-v1 leading",
            "…sk-or-v1…",
            "naïve sk-OR-mgmt-abc",
        ] {
            assert!(looks_like_credential(matched), "{matched}");
        }

        for unmatched in [
            "",
            "sk-or",
            "SK-OR",
            "sk_or_v1",
            "skor-v1",
            "google/gemini-2.5-flash",
            "a name with no marker in it at all",
            // Multi-byte characters cannot combine into an ASCII marker.
            "ѕk-оr-v1",
        ] {
            assert!(!looks_like_credential(unmatched), "{unmatched}");
        }
    }

    #[test]
    fn redaction_removes_the_token_and_keeps_the_rest() {
        let redacted = redact(r#"invalid type: string "sk-or-v1-leaked", expected u32"#);
        assert!(!redacted.contains("leaked"));
        assert!(redacted.contains("[redacted]"));
        assert!(redacted.starts_with("invalid type: string"));
    }

    #[test]
    fn redaction_leaves_a_clean_message_alone() {
        assert_eq!(redact("expected a table"), "expected a table");
    }

    #[test]
    fn control_characters_are_escaped_rather_than_emitted() {
        assert_eq!(printable("plain text"), "plain text");
        assert_eq!(printable("a\u{1b}[2Kb"), "a\\u{1b}[2Kb");
        assert_eq!(printable("one\ntwo"), "one\\ntwo");
        assert_eq!(printable("\u{202e}gnp.exe"), "\\u{202e}gnp.exe");
        assert!(!printable("\u{7}bell").contains('\u{7}'));
    }

    /// The registry is process-wide, so this value is unique to this test and
    /// appears nowhere else in the crate.
    const REGISTERED_SENTINEL: &str = "dd-api-key-REDACTION-UNIT-TEST-VALUE";

    #[test]
    fn a_registered_value_is_scrubbed_by_exact_match_wherever_it_appears() {
        register(REGISTERED_SENTINEL);
        let redacted = redact(&format!("cannot reach https://x/{REGISTERED_SENTINEL}?a=1"));
        assert!(!redacted.contains("REDACTION-UNIT-TEST"), "{redacted}");
        assert!(redacted.contains("[redacted]"), "{redacted}");
    }

    #[test]
    fn a_short_value_is_never_registered() {
        register("us-east-1");
        assert_eq!(
            redact("the bucket is in us-east-1"),
            "the bucket is in us-east-1",
            "a short value would otherwise be scrubbed out of every sentence containing it"
        );
    }

    #[test]
    fn redaction_escapes_what_it_does_not_replace() {
        let redacted = redact("invalid value: \u{1b}[31mred\u{1b}[0m");
        assert!(!redacted.contains('\u{1b}'), "{redacted}");
        assert!(redacted.contains("\\u{1b}"), "{redacted}");
    }
}
