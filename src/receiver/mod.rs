//! Where a newly created key's plaintext goes, and what its delivery proved.
//!
//! OpenRouter discloses an inference key once. Keymaster's only job after that
//! is to put it somewhere the operator chose, or to say clearly that it could
//! not. There is no fallback: a key is never printed, never written to state,
//! and never delivered to a destination the configuration did not name. A key
//! with no configured receiver is a key Keymaster refuses to create.
//!
//! # The interface
//!
//! [`SecretReceiver::receive`] takes the plaintext by reference and non-secret
//! metadata beside it. Borrowing is the point: [`KeyPlaintext`] clears itself
//! when dropped and has exactly one owner, so a receiver that needed an owned
//! copy would be a second, untracked copy of a credential. Nothing here can be
//! serialized or debug-printed into a diagnostic — [`DeliveryMetadata`] is
//! non-secret by construction, and the plaintext beside it has no `Serialize`
//! and prints redacted.
//!
//! # Outcomes
//!
//! A delivery attempt answers one question: what does this result *prove*
//! about the receiver's side? ADR-0002 allows three answers and makes the
//! third the default.
//!
//! - [`Acknowledgement::Delivered`] — the receiver committed the secret and
//!   said so.
//! - [`Acknowledgement::Rejected`] — the receiver committed nothing, and the
//!   mechanism *guarantees* it. Nothing was written, so the plaintext is dead
//!   and the key needs replacing, but no cleanup is owed on the receiver's
//!   side and no operator investigation is required.
//! - [`Acknowledgement::Ambiguous`] — everything else. The receiver may or may
//!   not hold the secret.
//!
//! There is no retry. Re-invoking a receiver that may already have committed
//! could overwrite a live destination with a stale or duplicate secret, so
//! ADR-0002 makes delivery at-most-once: ambiguity is journaled and resolved
//! by an operator, not by a second attempt.

pub mod command;
pub mod file;

use crate::client::KeyPlaintext;
use crate::ids::{Address, KeyHash, OperationId};

pub use command::CommandReceiver;
pub use file::FileReceiver;

/// The non-secret facts about one delivery attempt.
///
/// Every field is safe to write to a log, a state file, or a receiver's own
/// records; the types enforce that, since none of them accepts
/// credential-shaped input. The operation ID is the stable name of the
/// journaled attempt, so a receiver that wants idempotency has something to
/// key on that survives a retry by the operator.
#[derive(Debug, Clone)]
pub struct DeliveryMetadata {
    address: Address,
    hash: KeyHash,
    generation: u32,
    operation: OperationId,
}

impl DeliveryMetadata {
    /// Describes one delivery.
    #[must_use]
    pub fn new(address: Address, hash: KeyHash, generation: u32, operation: OperationId) -> Self {
        Self {
            address,
            hash,
            generation,
            operation,
        }
    }

    /// The local address whose key is being delivered, for example `jobfeed`.
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The delivered key's immutable remote identity.
    #[must_use]
    pub fn hash(&self) -> &KeyHash {
        &self.hash
    }

    /// The generation being delivered. Raising it is what asks for a new key.
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The journaled operation this delivery belongs to.
    #[must_use]
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
}

/// What one delivery attempt proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acknowledgement {
    /// The receiver committed the secret and acknowledged it.
    Delivered,
    /// The receiver committed nothing, and the mechanism guarantees it.
    Rejected,
    /// Nothing is guaranteed either way. The default (ADR-0002).
    Ambiguous,
}

impl Acknowledgement {
    /// A stable machine-readable spelling, used in output and state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Rejected => "rejected",
            Self::Ambiguous => "ambiguous",
        }
    }

    /// Whether the secret is known to have reached its destination.
    #[must_use]
    pub const fn is_delivered(self) -> bool {
        matches!(self, Self::Delivered)
    }
}

impl std::fmt::Display for Acknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One delivery attempt's classification and the sentence explaining it.
///
/// The detail is passed through [`crate::redaction::redact`] on the way in, so
/// no receiver can put a credential-shaped token into a message Keymaster will
/// print — not even by quoting an error from a program it ran. It is not
/// `Serialize`: an output DTO decides what to publish, rather than this type
/// leaking into a JSON document by default.
#[derive(Debug, Clone)]
pub struct Outcome {
    acknowledgement: Acknowledgement,
    detail: String,
}

impl Outcome {
    /// The receiver committed the secret.
    #[must_use]
    pub fn delivered(detail: impl AsRef<str>) -> Self {
        Self::new(Acknowledgement::Delivered, detail)
    }

    /// The receiver committed nothing, and the mechanism guarantees it.
    ///
    /// Only for a failure that cannot have left a partial commit behind. When
    /// in doubt the answer is [`Outcome::ambiguous`]; ADR-0002 makes that the
    /// default precisely because a wrong `Rejected` is the expensive mistake.
    #[must_use]
    pub fn rejected(detail: impl AsRef<str>) -> Self {
        Self::new(Acknowledgement::Rejected, detail)
    }

    /// Nothing is guaranteed either way.
    #[must_use]
    pub fn ambiguous(detail: impl AsRef<str>) -> Self {
        Self::new(Acknowledgement::Ambiguous, detail)
    }

    fn new(acknowledgement: Acknowledgement, detail: impl AsRef<str>) -> Self {
        Self {
            acknowledgement,
            detail: crate::redaction::redact(detail.as_ref()),
        }
    }

    /// What this attempt proved.
    #[must_use]
    pub fn acknowledgement(&self) -> Acknowledgement {
        self.acknowledgement
    }

    /// A non-secret sentence naming the receiver and what happened.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Whether the secret is known to have reached its destination.
    #[must_use]
    pub fn is_delivered(&self) -> bool {
        self.acknowledgement.is_delivered()
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.acknowledgement, self.detail)
    }
}

/// Somewhere a key's plaintext can be delivered.
///
/// Implementations must never return [`Acknowledgement::Rejected`] for a
/// failure that could have committed, must never copy the plaintext anywhere
/// that outlives the call, and must never put it in a message, a filename, an
/// argument, or an environment variable.
pub trait SecretReceiver {
    /// A short non-secret description of this destination, for diagnostics.
    fn describe(&self) -> String;

    /// Delivers one key, once.
    ///
    /// This is the only method in Keymaster that is handed a live credential.
    /// It returns an [`Outcome`] rather than a `Result` because a failure here
    /// is not an error to propagate but a classification the journal has to
    /// record: what the caller must know is what the attempt proved.
    fn receive(&self, metadata: &DeliveryMetadata, plaintext: &KeyPlaintext) -> Outcome;
}

/// Builds the receiver a configuration block names.
///
/// Selection is always explicit. There is no default receiver and no fallback:
/// a key whose configuration names no receiver has nowhere for its plaintext
/// to go, and is never created.
#[must_use]
pub fn from_config(spec: &crate::config::Receiver) -> Box<dyn SecretReceiver> {
    match spec {
        crate::config::Receiver::File { path } => Box::new(FileReceiver::new(path)),
        crate::config::Receiver::Command { program, args } => {
            Box::new(CommandReceiver::new(program, args.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value no message here is allowed to repeat. Unit tests cannot reach
    /// the shared sentinel in `tests/support`.
    const SENTINEL_KEY: &str = "sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE";

    #[test]
    fn a_detail_cannot_carry_a_credential_shaped_token() {
        let outcome = Outcome::ambiguous(format!("the program printed {SENTINEL_KEY}"));
        assert!(!outcome.detail().contains("sk-or-"), "{outcome}");
        assert!(outcome.detail().contains("[redacted]"), "{outcome}");
        assert_eq!(outcome.acknowledgement(), Acknowledgement::Ambiguous);
    }

    #[test]
    fn a_detail_is_escaped_so_it_cannot_rewrite_a_terminal() {
        let outcome = Outcome::rejected("the program printed \u{1b}[2Kgone");
        assert!(!outcome.detail().contains('\u{1b}'), "{outcome}");
    }

    #[test]
    fn the_three_classifications_are_distinct_and_only_one_is_success() {
        assert!(Outcome::delivered("wrote it").is_delivered());
        assert!(!Outcome::rejected("refused").is_delivered());
        assert!(!Outcome::ambiguous("who knows").is_delivered());
        assert_eq!(Acknowledgement::Delivered.as_str(), "delivered");
        assert_eq!(Acknowledgement::Rejected.as_str(), "rejected");
        assert_eq!(Acknowledgement::Ambiguous.as_str(), "ambiguous");
    }
}
