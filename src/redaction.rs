//! Making untrusted text safe to show an operator.
//!
//! Keymaster never accepts credential plaintext as input and never repeats it
//! in a diagnostic. Three defences live here: a predicate that rejects a value
//! at the boundary where it is parsed, an escaper for text that reaches a
//! terminal or a log, and a redactor for the one class of message Keymaster
//! does not write itself — a deserializer's error, which may quote the
//! offending input.

/// The marker every OpenRouter credential carries: management keys are
/// `sk-or-mgmt-…` and inference keys are `sk-or-v1-…`.
const CREDENTIAL_MARKER: &str = "sk-or-";

/// What a redacted token is replaced with.
const REPLACEMENT: &str = "[redacted]";

/// Whether `value` contains something shaped like an OpenRouter credential.
///
/// Matching is case-insensitive and looks anywhere in the value, because a
/// secret pasted into a configuration field is as likely to be surrounded by
/// other text as to stand alone.
#[must_use]
pub fn looks_like_credential(value: &str) -> bool {
    value.to_ascii_lowercase().contains(CREDENTIAL_MARKER)
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
        assert!(looks_like_credential("sk-or-mgmt-abc"));
        assert!(looks_like_credential("Bearer SK-OR-V1-ABC"));
        assert!(!looks_like_credential("google/gemini-2.5-flash"));
        assert!(!looks_like_credential("skorv1"));
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
