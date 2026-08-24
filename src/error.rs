//! Keymaster's application error type.

use crate::app::apply::ApplyError;
use crate::app::import::ImportError;
use crate::app::lifecycle::LifecycleError;
use crate::app::recover::RecoverError;
use crate::app::rotate::RotateError;
use crate::client::ApiError;
use crate::config::ConfigError;
use crate::state::StateError;

/// An application error. Every variant is safe to display: no variant may
/// carry credential plaintext or a credential-shaped string.
///
/// The wrapping variants keep each layer's own vocabulary rather than
/// flattening it: [`Error::kind`] returns the inner category, so a caller
/// reading JSON diagnostics can tell a missing credential from a rejected one,
/// and either from a configuration that does not parse.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The command line could not be parsed. Carries clap's own rendered
    /// message so `--json` can report it without inventing a second wording.
    #[error("{message}")]
    Usage {
        /// Clap's rendered message, already stripped of ANSI styling.
        message: String,
    },

    /// The desired configuration could not be read, parsed, or validated.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Local state could not be read.
    #[error(transparent)]
    State(#[from] StateError),

    /// OpenRouter could not be reached, refused the credential, or answered
    /// with something Keymaster cannot use.
    #[error(transparent)]
    Api(#[from] ApiError),

    /// A binding could not be recorded. State is unchanged.
    #[error(transparent)]
    Import(#[from] ImportError),

    /// An apply did not converge the configuration. Whatever it did do has
    /// already been reported on stdout.
    #[error(transparent)]
    Apply(#[from] ApplyError),

    /// A rotation could not be staged. The key the address holds is untouched.
    #[error(transparent)]
    Rotate(#[from] RotateError),

    /// An unfinished operation could not be inspected or resolved. State is
    /// unchanged unless the message says otherwise.
    #[error(transparent)]
    Recover(#[from] RecoverError),

    /// A retirement, deletion, or forget could not be performed, or could not
    /// be confirmed. The result document on stdout says what was established.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),

    /// A result could not be written to stdout or stderr.
    #[error("cannot write output: {message}")]
    Output {
        /// The operating system's explanation.
        message: String,
    },
}

impl Error {
    /// A stable machine-readable category, used as the `kind` field of JSON
    /// diagnostics. Treat these strings as a compatibility surface.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Usage { .. } => "usage",
            Self::Config(error) => error.kind(),
            Self::State(error) => error.kind(),
            Self::Api(error) => error.kind(),
            Self::Import(error) => error.kind(),
            Self::Apply(error) => error.kind(),
            Self::Rotate(error) => error.kind(),
            Self::Recover(error) => error.kind(),
            Self::Lifecycle(error) => error.kind(),
            Self::Output { .. } => "output",
        }
    }

    /// Wraps a failure to write a result or a diagnostic.
    #[must_use]
    pub fn output(error: &std::io::Error) -> Self {
        Self::Output {
            message: error.to_string(),
        }
    }
}
