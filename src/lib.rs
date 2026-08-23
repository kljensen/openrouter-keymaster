//! Keymaster library entry point.

/// The placeholder greeting printed by the `keymaster` binary.
#[must_use]
pub fn greeting() -> &'static str {
    "Hello from Keymaster, a declarative OpenRouter management CLI."
}

#[cfg(test)]
mod tests {
    use super::greeting;

    #[test]
    fn greeting_identifies_keymaster() {
        assert!(greeting().contains("Keymaster"));
    }
}
