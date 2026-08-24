//! A fake secret receiver, and a real one-time plaintext to hand a real one.
//!
//! The fake implements the production [`SecretReceiver`] trait, so a test that
//! scripts a delivery failure is scripting the same interface the file and
//! command receivers implement. It models the four *situations* a delivery can
//! be in and maps each to the classification ADR-0002 gives it, which is how a
//! test asserts that a lost acknowledgement is ambiguous rather than a
//! rejection.
//!
//! [`created_sentinel_key`] exists because there is deliberately no way to
//! construct a [`KeyPlaintext`] out of thin air: the only source of one is a
//! create response. So this makes a real one, out of a real response, served
//! by the local HTTP harness — the same path production takes.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use keymaster::client::{
    Client, CreateKeyRequest, CreatedKey, KeyPlaintext, ManagementKey, Options,
};
use keymaster::ids::RemoteName;
use keymaster::receiver::{Acknowledgement, DeliveryMetadata, Outcome, SecretReceiver};
use wiremock::Mock;
use wiremock::matchers::{method, path};

use super::fixtures::created_key;
use super::http::{TestServer, json_response};
use super::sentinel::SECRET_SENTINEL_KEY;

/// The situation a scripted delivery attempt ends in.
///
/// The distinction that matters is what each one proves about the receiver's
/// side: `Rejected` guarantees nothing was stored, while `TimedOut` and
/// `AcknowledgementLost` guarantee nothing at all and are therefore both
/// [`Acknowledgement::Ambiguous`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptedOutcome {
    /// Acknowledged: the receiver stored the secret.
    Delivered,
    /// Definite rejection: the receiver refused and stored nothing.
    Rejected,
    /// The attempt timed out. The receiver may or may not have stored it.
    TimedOut,
    /// The receiver stored the secret, but the acknowledgement was lost.
    AcknowledgementLost,
}

impl ScriptedOutcome {
    /// How Keymaster must classify this situation.
    #[must_use]
    pub fn acknowledgement(self) -> Acknowledgement {
        match self {
            Self::Delivered => Acknowledgement::Delivered,
            Self::Rejected => Acknowledgement::Rejected,
            Self::TimedOut | Self::AcknowledgementLost => Acknowledgement::Ambiguous,
        }
    }

    /// The outcome a receiver in this situation returns.
    #[must_use]
    pub fn outcome(self) -> Outcome {
        match self {
            Self::Delivered => Outcome::delivered("the fake receiver stored the key"),
            Self::Rejected => Outcome::rejected("the fake receiver refused and stored nothing"),
            Self::TimedOut => Outcome::ambiguous("the fake receiver did not answer in time"),
            Self::AcknowledgementLost => {
                Outcome::ambiguous("the fake receiver's acknowledgement was lost")
            }
        }
    }
}

/// The non-secret metadata of one delivery attempt, as the fake recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Local resource address, for example `jobfeed`.
    pub address: String,
    /// Immutable hash of the delivered key.
    pub hash: String,
    /// Generation of the delivered key.
    pub generation: u32,
    /// Operation ID of the journaled create transaction.
    pub operation_id: String,
}

impl Delivery {
    /// Records what a delivery was told.
    #[must_use]
    pub fn of(metadata: &DeliveryMetadata) -> Self {
        Self {
            address: metadata.address().as_str().to_owned(),
            hash: metadata.hash().as_str().to_owned(),
            generation: metadata.generation(),
            operation_id: metadata.operation().as_str().to_owned(),
        }
    }
}

/// A receiver that answers from a script and records what it was called with.
///
/// It records the metadata and the plaintext's length, never the plaintext,
/// so a sentinel scan of the recorded calls proves the harness is not itself
/// a place secrets accumulate.
#[derive(Debug)]
pub struct FakeReceiver {
    scripted: Mutex<VecDeque<ScriptedOutcome>>,
    trailing: ScriptedOutcome,
    deliveries: Mutex<Vec<Delivery>>,
    plaintext_lengths: Mutex<Vec<usize>>,
}

impl FakeReceiver {
    /// Answers every attempt the same way.
    #[must_use]
    pub fn always(outcome: ScriptedOutcome) -> Self {
        Self::scripted([], outcome)
    }

    /// Answers each attempt from `outcomes` in turn, then `trailing`.
    #[must_use]
    pub fn scripted(
        outcomes: impl IntoIterator<Item = ScriptedOutcome>,
        trailing: ScriptedOutcome,
    ) -> Self {
        Self {
            scripted: Mutex::new(outcomes.into_iter().collect()),
            trailing,
            deliveries: Mutex::new(Vec::new()),
            plaintext_lengths: Mutex::new(Vec::new()),
        }
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

impl SecretReceiver for FakeReceiver {
    fn describe(&self) -> String {
        "fake receiver".to_owned()
    }

    fn receive(&self, metadata: &DeliveryMetadata, plaintext: &KeyPlaintext) -> Outcome {
        self.deliveries
            .lock()
            .expect("the fake receiver is not poisoned")
            .push(Delivery::of(metadata));
        self.plaintext_lengths
            .lock()
            .expect("the fake receiver is not poisoned")
            .push(plaintext.expose().len());

        self.scripted
            .lock()
            .expect("the fake receiver is not poisoned")
            .pop_front()
            .unwrap_or(self.trailing)
            .outcome()
    }
}

/// A key whose plaintext is the secret sentinel, created the way production
/// creates one: by parsing a create response off a socket.
///
/// The server lives only for the duration of the call; what comes back owns
/// the plaintext and clears it when it is dropped.
#[must_use]
pub fn created_sentinel_key() -> CreatedKey {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                201,
                &created_key("keyhash-0001", "golf-jobfeed", SECRET_SENTINEL_KEY),
            )),
    );

    let options = Options {
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(10),
        ..Options::new(server.api_base_url())
    };
    let credential = ManagementKey::for_tests(SECRET_SENTINEL_KEY).expect("a usable fake key");
    Client::new(options, &credential)
        .expect("a client")
        .create_key_once(&CreateKeyRequest::new(
            RemoteName::parse("golf-jobfeed").expect("a valid name"),
        ))
        .expect("the harness creates a key")
}
