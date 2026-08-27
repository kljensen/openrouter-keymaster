//! The caller receiver: the plaintext, in memory, handed to the host once.
//!
//! A web host that issues keys needs the plaintext to show it to a user or to
//! forward it to a store it controls. A file and a program cannot do that, so
//! ADR-0005 adds a third destination whose code the host supplies: a callback
//! in [`crate::ops::Context`], wrapped here in the same [`SecretReceiver`] the
//! other two implement.
//!
//! # Where the guarantee ends
//!
//! At the callback. Everything Keymaster promises about a plaintext — one
//! delivery, no copy that outlives the call, nothing printed, nothing
//! serialized — holds right up to the moment the host's code is handed the
//! [`KeyPlaintext`], and not one step past it. What the host does with it is
//! the host's responsibility.
//!
//! # One callback, several keys
//!
//! The callback is `FnMut` and one operation may issue several keys, so it is
//! called once per delivery, on the thread running the operation, and routes
//! by [`DeliveryMetadata`] — the address and the configured `destination` —
//! rather than by call order. The [`RefCell`] is what lets a `&self` receiver
//! call it: an operation is single-threaded, and no delivery is nested inside
//! another.
//!
//! # A panic is ambiguous
//!
//! Host code that panics has proved nothing about what it stored, so the panic
//! is caught and classified [`Acknowledgement::Ambiguous`] like any other lost
//! acknowledgement. The panic payload is not repeated in the detail: it is
//! host text that may hold anything at all, and the process's own panic hook
//! has already written it to stderr for whoever is debugging.

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::{DeliveryMetadata, Outcome, SecretReceiver};
use crate::client::KeyPlaintext;

/// The host code one operation delivers through (ADR-0005, item 1).
///
/// `FnMut` because one operation may deliver several keys, `Send` because a
/// host hands its whole [`crate::ops::Context`] to a worker thread, and boxed
/// because the context owns it.
pub type Deliver = Box<dyn FnMut(&DeliveryMetadata, &KeyPlaintext) -> Outcome + Send>;

/// A destination that is the host's own code.
pub struct CallerReceiver<'a> {
    deliver: &'a RefCell<Deliver>,
    destination: String,
}

impl<'a> CallerReceiver<'a> {
    /// Wraps one operation's callback as the receiver `destination` names.
    #[must_use]
    pub fn new(deliver: &'a RefCell<Deliver>, destination: String) -> Self {
        Self {
            deliver,
            destination,
        }
    }
}

impl SecretReceiver for CallerReceiver<'_> {
    fn describe(&self) -> String {
        format!("caller receiver for {}", self.destination)
    }

    fn receive(&self, metadata: &DeliveryMetadata, plaintext: &KeyPlaintext) -> Outcome {
        let answered = catch_unwind(AssertUnwindSafe(|| {
            (self.deliver.borrow_mut())(metadata, plaintext)
        }));
        answered.unwrap_or_else(|_| {
            Outcome::ambiguous(format!(
                "the host callback panicked while it was being handed generation {generation} of \
                 {address} for {destination}, so what it stored is unknown",
                generation = metadata.generation(),
                address = metadata.address(),
                destination = self.destination
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{Address, KeyHash, OperationId};
    use crate::receiver::Acknowledgement;

    /// A value no message here is allowed to repeat. Unit tests cannot reach
    /// the shared sentinel in `test_support`.
    const SENTINEL_KEY: &str = "sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE";

    fn metadata() -> DeliveryMetadata {
        DeliveryMetadata::new(
            Address::parse("jobfeed").expect("a valid address"),
            KeyHash::parse("hash-jobfeed-1").expect("a valid hash"),
            3,
            OperationId::parse("op-0001").expect("a valid operation id"),
            Some("vault/jobfeed".to_owned()),
        )
    }

    fn deliver_through(callback: Deliver) -> Outcome {
        let cell = RefCell::new(callback);
        CallerReceiver::new(&cell, "vault/jobfeed".to_owned())
            .receive(&metadata(), &KeyPlaintext::for_tests(SENTINEL_KEY))
    }

    #[test]
    fn the_callbacks_own_answer_is_the_outcome() {
        let outcome = deliver_through(Box::new(|metadata, plaintext| {
            assert_eq!(metadata.destination(), Some("vault/jobfeed"));
            assert_eq!(plaintext.expose(), SENTINEL_KEY);
            Outcome::delivered("the host stored it")
        }));

        assert_eq!(outcome.acknowledgement(), Acknowledgement::Delivered);
        assert!(outcome.detail().contains("the host stored it"), "{outcome}");
    }

    #[test]
    fn a_panicking_callback_is_ambiguous_and_repeats_nothing_it_said() {
        // The hook is silenced for the length of the call because this panic
        // message deliberately carries the fake key: the point of the case is
        // that the outcome does not repeat it, and the default hook would
        // print it into the test log on its way past.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = deliver_through(Box::new(|_, plaintext| {
            panic!("the host blew up holding {}", plaintext.expose())
        }));
        std::panic::set_hook(previous);

        assert_eq!(outcome.acknowledgement(), Acknowledgement::Ambiguous);
        assert!(!outcome.detail().contains("sk-or-"), "{outcome}");
        assert!(!outcome.detail().contains("blew up"), "{outcome}");
        assert!(outcome.detail().contains("jobfeed"), "{outcome}");
    }

    #[test]
    fn one_callback_answers_every_key_it_is_handed() {
        let addresses = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&addresses);
        let cell: RefCell<Deliver> = RefCell::new(Box::new(move |metadata, _| {
            recorded
                .lock()
                .expect("the recorder is not poisoned")
                .push(metadata.address().as_str().to_owned());
            Outcome::delivered("stored")
        }));
        let receiver = CallerReceiver::new(&cell, "vault/jobfeed".to_owned());
        for _ in 0..2 {
            receiver.receive(&metadata(), &KeyPlaintext::for_tests(SENTINEL_KEY));
        }

        assert_eq!(
            *addresses.lock().expect("the recorder is not poisoned"),
            vec!["jobfeed".to_owned(), "jobfeed".to_owned()],
            "one `FnMut` callback answers every delivery in the operation"
        );
    }
}
