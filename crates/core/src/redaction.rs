//! Making untrusted text safe to show an operator.
//!
//! Keymaster never accepts credential plaintext as input and never repeats it
//! in a diagnostic. Three defences live here: a predicate that rejects a value
//! at the boundary where it is parsed, an escaper for text that reaches a
//! terminal or a log, and a redactor for the one class of message Keymaster
//! does not write itself — a deserializer's error, which may quote the
//! offending input.

/// The marker every OpenRouter credential carries.
///
/// What follows it does not say which kind of credential it is: a management
/// key from OpenRouter's Management API Keys page carries the same `sk-or-v1-`
/// shape an inference key does. So the marker is the whole test, and any
/// `sk-or-` string is treated as a secret.
const CREDENTIAL_MARKER: &str = "sk-or-";

/// What a redacted token is replaced with.
const REPLACEMENT: &str = "[redacted]";

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

/// Replaces every whitespace-delimited token that looks like a credential, and
/// escapes what is left with [`printable`].
///
/// Whitespace is normalized to single spaces, which is acceptable for the
/// error messages this is used on and keeps the implementation obvious.
#[must_use]
pub fn redact(message: &str) -> String {
    message
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

    #[test]
    fn redaction_escapes_what_it_does_not_replace() {
        let redacted = redact("invalid value: \u{1b}[31mred\u{1b}[0m");
        assert!(!redacted.contains('\u{1b}'), "{redacted}");
        assert!(redacted.contains("\\u{1b}"), "{redacted}");
    }
}
