//! `openrouter-keymaster rotate`: staging a replacement for a key that works.
//!
//! Rotation is the one lifecycle operation an operator asks for directly rather
//! than describing in the configuration. `apply` rotates too — when a
//! generation rises, a receiver moves, or an immutable field changes — and this
//! command is the same transaction under a different trigger: an operator who
//! wants a fresh credential now, for a reason no file records.
//!
//! # Staging, not swapping
//!
//! The predecessor is never touched. It is not disabled, not deleted, not
//! unassigned, and not even read. The successor is created, restricted,
//! guardrailed, verified, and delivered first; only the promotion that follows
//! a *confirmed* delivery moves the old hash to
//! `retained.awaiting_retirement`, where it stays exactly as it was until an
//! operator runs `openrouter-keymaster retire`.
//!
//! That ordering is the whole value of the command. Keymaster cannot know when
//! a downstream deployment has read the new secret out of wherever the receiver
//! put it, so it must not be the thing that decides the old one has stopped
//! being needed. A rotation that fails at any phase — the create is ambiguous,
//! the restrictions do not verify, the receiver refuses — leaves the working
//! credential working and its consumers untouched.
//!
//! # What is checked before anything is sent
//!
//! Under one lock: the address owns a key at all, no operation is in progress
//! anywhere, and [`Issuer::preflight`] passes — the configuration still
//! describes the key, it names a receiver, and its guardrail is bound and has
//! converged. Nothing is written until all of that holds, and a failure here
//! costs a read.
//!
//! The successor's generation is the higher of the configured one and the next
//! free number at the address, so rotating a key at generation 3 whose
//! configuration still says 1 produces generation 4 rather than a collision. A
//! generation names one remote key at one address and only ever moves upward.

use time::OffsetDateTime;

use crate::api::{Reader, Writer};
use crate::config::Config;
use crate::error::Error;
use crate::ids::{Address, IdError, OperationId};
use crate::report::{Predecessor, RotateReport, Successor};
use crate::state::{CurrentKey, KeyBinding, Phase, State, StateFile};

use super::issuance::Issuer;
use super::{Context, Outcome, Resolution};

/// Stages a successor for the key an address currently owns.
///
/// # Errors
///
/// Returns [`RotateError`] when the address owns no key, an operation is in
/// progress, the successor cannot be staged, or the transaction did not finish,
/// and the configuration, state, and API errors of the steps it performs,
/// including `missing_credential`.
pub fn rotate(context: Context, name: &str) -> Result<Outcome<RotateReport>, Error> {
    let address = Address::parse(name).map_err(|error| argument("NAME", &error))?;

    // As everywhere that writes: the lock, then the two files the decision is
    // made from, so neither can change underneath it.
    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let config = Config::load(&context.paths.config)?;
    let mut state = lock.read()?;

    check_nothing_pending(&state)?;
    let predecessor = state
        .key(&address)
        .and_then(KeyBinding::current)
        .cloned()
        .ok_or_else(|| RotateError::NoCurrentKey {
            address: address.clone(),
        })?;

    let client = context.client()?;
    let (reader, writer) = (Reader::new(&client), Writer::new(&client));
    let issuer = Issuer {
        config: &config,
        client: &client,
        reader: &reader,
        writer: &writer,
        lock: &lock,
    };

    // Nothing has been sent or written yet, and nothing will be until this
    // passes. A configuration that cannot produce a successor leaves the
    // working key exactly as it was.
    let prepared =
        issuer
            .preflight(&address, &state)
            .map_err(|message| RotateError::Unstageable {
                address: address.clone(),
                message,
            })?;

    let issued = issuer
        .issue_prepared(&address, &mut state, prepared, now())
        .map_err(|message| RotateError::Issuance {
            address: address.clone(),
            message,
        })?;

    Ok(Outcome::ok(RotateReport::new(
        &address,
        retired(&state, &address, &predecessor),
        Successor {
            operation: issued.operation.as_str().to_owned(),
            hash: issued.hash.as_str().to_owned(),
            generation: issued.generation,
            receiver: issued.receiver,
            promoted: issued.promoted,
        },
    )))
}

/// What became of the key the address held, read back from state.
///
/// Read rather than assumed: promotion is a separate durable write from
/// `delivered`, and a run whose promotion did not land leaves the predecessor
/// still current. Reporting it as retained would tell an operator to retire a
/// key that is still the one in use.
fn retired(state: &State, address: &Address, predecessor: &CurrentKey) -> Predecessor {
    let status = state
        .key(address)
        .and_then(|binding| {
            binding
                .retained()
                .iter()
                .find(|retained| retained.hash == predecessor.hash)
        })
        .map(|retained| retained.status);

    Predecessor {
        hash: predecessor.hash.as_str().to_owned(),
        generation: predecessor.generation,
        status,
    }
}

/// Refuses a rotation while any address has an operation in progress.
///
/// The state API enforces this from below — `begin_create` will not start a
/// second operation — but reaching it through the transaction would report the
/// refusal as "the attempt could not be journaled", which describes the
/// mechanism rather than the situation. An unresolved attempt may have made a
/// live key nobody can name, and starting a rotation beside it buries that
/// under a second unknown.
fn check_nothing_pending(state: &State) -> Result<(), RotateError> {
    let Some((blocking, pending)) = state.pending_operation() else {
        return Ok(());
    };
    let (blocking, operation) = (blocking.clone(), pending.id.clone());
    // The address a refusal points at is the one holding the operation, not the
    // one whose rotation was refused: they are the same only sometimes.
    let resolution = Resolution::of(pending.phase).instruction(&blocking);

    // One branch, on the shared reading of the phase, so this refusal and the
    // ones `retire`, `delete key`, and `state forget` make cannot drift apart
    // on which command an operator should run.
    match Resolution::of(pending.phase) {
        Resolution::Promotion => Err(RotateError::PromotionPending {
            blocking,
            operation,
            resolution,
        }),
        Resolution::Recovery => Err(RotateError::OperationPending {
            blocking,
            operation,
            phase: pending.phase,
            resolution,
        }),
    }
}

/// Reports a command-line value this command cannot use.
fn argument(value: &'static str, error: &IdError) -> RotateError {
    RotateError::Argument {
        value,
        message: error.to_string(),
    }
}

/// When the rotation was recorded. The only clock this module reads.
fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Why a rotation could not be staged.
#[derive(Debug, thiserror::Error)]
pub enum RotateError {
    /// A command-line value is not the kind of identifier it names.
    #[error("`{value}` is not usable: {message}")]
    Argument {
        /// Which value: `NAME`.
        value: &'static str,
        /// Why it was rejected. Never repeats the value.
        message: String,
    },

    /// The address owns no key, so there is nothing to replace.
    #[error(
        "`{address}` owns no key, so there is nothing to rotate; `openrouter-keymaster apply` \
         creates the first one, and `openrouter-keymaster import key {address} --hash HASH` binds \
         one that already exists"
    )]
    NoCurrentKey {
        /// The local address.
        address: Address,
    },

    /// An unfinished operation stands, so no create may begin.
    #[error(
        "`{blocking}` has an operation in progress (operation {operation}, phase `{phase}`), and \
         Keymaster creates and delivers one key at a time. Close it first: {resolution}. Nothing \
         was rotated and no key was created."
    )]
    OperationPending {
        /// The address that holds the unfinished operation.
        blocking: Address,
        /// That operation's identifier.
        operation: OperationId,
        /// The phase it stopped in.
        phase: Phase,
        /// The command that clears it, from [`Resolution`].
        resolution: String,
    },

    /// A delivered operation stands, and only its local promotion is left.
    ///
    /// Separate from [`RotateError::OperationPending`] because the remedy is a
    /// different command, and a script reading the kind should be able to tell
    /// "this needs a person" from "this needs one more run". Which of the two a
    /// phase gets is [`Resolution`]'s to decide, not this module's.
    #[error(
        "`{blocking}` has a delivered key whose promotion to current was not recorded (operation \
         {operation}), and Keymaster creates and delivers one key at a time. Finish it first: \
         {resolution}. Nothing was rotated and no key was created."
    )]
    PromotionPending {
        /// The address that holds the delivered operation.
        blocking: Address,
        /// That operation's identifier.
        operation: OperationId,
        /// The command that clears it, from [`Resolution`].
        resolution: String,
    },

    /// The successor cannot be created, so nothing was staged.
    #[error(
        "`{address}` cannot be rotated: {message}. Nothing was changed and nothing was sent — the \
         key the address holds is untouched and still working."
    )]
    Unstageable {
        /// The local address.
        address: Address,
        /// The preflight's own explanation, already secret-free.
        message: String,
    },

    /// The successor's journaled creation did not finish.
    #[error(
        "`{address}` was not rotated: {message} The key the address held is untouched: rotation \
         promotes only after a confirmed delivery, and never disables a predecessor."
    )]
    Issuance {
        /// The local address.
        address: Address,
        /// The transaction's own explanation, already secret-free.
        message: String,
    },
}

impl RotateError {
    /// A stable machine-readable category.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Argument { .. } => "rotate_argument",
            Self::NoCurrentKey { .. } => "rotate_no_current_key",
            Self::OperationPending { .. } => "rotate_operation_pending",
            Self::PromotionPending { .. } => "rotate_promotion_pending",
            Self::Unstageable { .. } => "rotate_unstageable",
            Self::Issuance { .. } => "rotate_issuance",
        }
    }
}
