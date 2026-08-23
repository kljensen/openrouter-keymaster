//! A fake secret receiver.
//!
//! The real receiver interface arrives with issue #15. This fake is
//! deliberately self-contained: it models the four outcomes a delivery can
//! have and records what it was told, so tests can assert delivery happened
//! exactly once without the fake itself becoming a place a secret is kept.

use std::collections::VecDeque;
use std::sync::Mutex;

/// How a receiver answered one delivery attempt.
///
/// The distinction that matters is what the outcome proves about the
/// receiver's side: `Rejected` guarantees nothing was stored, while
/// `TimedOut` and `AcknowledgementLost` guarantee nothing at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverOutcome {
    /// Acknowledged: the receiver stored the secret.
    Delivered,
    /// Definite rejection: the receiver refused and stored nothing.
    Rejected,
    /// The attempt timed out. The receiver may or may not have stored it.
    TimedOut,
    /// The receiver stored the secret, but the acknowledgement was lost.
    AcknowledgementLost,
}

/// The non-secret metadata of one delivery attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Local resource address, for example `keys.jobfeed`.
    pub address: String,
    /// Immutable hash of the delivered key.
    pub hash: String,
    /// Generation of the delivered key.
    pub generation: u32,
    /// Operation ID of the journaled create transaction.
    pub operation_id: String,
}

/// A receiver that answers from a script and records what it was called with.
///
/// It records the metadata and the plaintext's length, never the plaintext,
/// so a sentinel scan of the recorded calls proves the harness is not itself
/// a place secrets accumulate.
#[derive(Debug)]
pub struct FakeReceiver {
    scripted: Mutex<VecDeque<ReceiverOutcome>>,
    trailing: ReceiverOutcome,
    deliveries: Mutex<Vec<Delivery>>,
    plaintext_lengths: Mutex<Vec<usize>>,
}

impl FakeReceiver {
    /// Answers every attempt the same way.
    #[must_use]
    pub fn always(outcome: ReceiverOutcome) -> Self {
        Self::scripted([], outcome)
    }

    /// Answers each attempt from `outcomes` in turn, then `trailing`.
    #[must_use]
    pub fn scripted(
        outcomes: impl IntoIterator<Item = ReceiverOutcome>,
        trailing: ReceiverOutcome,
    ) -> Self {
        Self {
            scripted: Mutex::new(outcomes.into_iter().collect()),
            trailing,
            deliveries: Mutex::new(Vec::new()),
            plaintext_lengths: Mutex::new(Vec::new()),
        }
    }

    /// Records one delivery attempt and answers it.
    pub fn receive(&self, delivery: Delivery, plaintext: &str) -> ReceiverOutcome {
        self.deliveries
            .lock()
            .expect("the fake receiver is not poisoned")
            .push(delivery);
        self.plaintext_lengths
            .lock()
            .expect("the fake receiver is not poisoned")
            .push(plaintext.len());

        self.scripted
            .lock()
            .expect("the fake receiver is not poisoned")
            .pop_front()
            .unwrap_or(self.trailing)
    }

    /// Every delivery attempt, in order.
    #[must_use]
    pub fn deliveries(&self) -> Vec<Delivery> {
        self.deliveries
            .lock()
            .expect("the fake receiver is not poisoned")
            .clone()
    }

    /// The length of each plaintext the receiver was given, in order.
    #[must_use]
    pub fn plaintext_lengths(&self) -> Vec<usize> {
        self.plaintext_lengths
            .lock()
            .expect("the fake receiver is not poisoned")
            .clone()
    }
}
