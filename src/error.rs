//! Keymaster's application error type.

/// An application error. Every variant is safe to display: no variant may
/// carry credential plaintext or a credential-shaped string.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The command parses and is part of the v0.1 surface, but its feature
    /// issue has not landed yet.
    #[error("`{command}` is not implemented yet")]
    NotImplemented {
        /// The canonical command path, for example `import key`.
        command: &'static str,
    },

    /// The command line could not be parsed. Carries clap's own rendered
    /// message so `--json` can report it without inventing a second wording.
    #[error("{message}")]
    Usage {
        /// Clap's rendered message, already stripped of ANSI styling.
        message: String,
    },
}

impl Error {
    /// A stable machine-readable category, used as the `kind` field of JSON
    /// diagnostics. Treat these strings as a compatibility surface.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotImplemented { .. } => "not_implemented",
            Self::Usage { .. } => "usage",
        }
    }
}
