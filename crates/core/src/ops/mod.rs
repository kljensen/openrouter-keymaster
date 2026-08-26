//! The operations, as functions a caller can hold the result of.
//!
//! One function per command. Each takes an owned [`Context`] and the command's
//! arguments, and returns the command's report. Nothing here reads the
//! environment, prints, or exits: warnings are fields of the report, and the
//! caller decides what to do with them (ADR-0003).
//!
//! [`Context`] is `Send + 'static` and carries no client. Each operation builds
//! its own [`Client`] and its receivers on the thread that runs it, from the
//! context and the configuration, which is what lets a host hand a context to a
//! worker thread. The operations are synchronous and blocking, and so is
//! everything they build: an async host moves the whole call to a blocking
//! thread, and serializes calls on one state file itself.
//!
//! The credential is optional because two commands never need one. `state
//! forget` makes no request, and `recover inspect` is offline once the journal
//! records a hash. Every other operation checks for it at the point it would
//! first build a client — after the configuration and state have been read, and
//! before any API call or state write — and fails there with
//! `missing_credential`.
//!
//! [`Outcome`] keeps the report beside a failure: an operation that wrote
//! something and then could not verify it still returns its full report, with
//! the failure next to it. `Err` is reserved for the cases where there is no
//! report to give — an invalid configuration, a held lock, a missing
//! credential.

pub mod apply;
mod fingerprint;
pub mod import;
mod issuance;
pub mod lifecycle;
pub mod recover;
pub mod rotate;

use std::path::PathBuf;

use crate::api::Reader;
use crate::client::{ApiError, Client, ManagementKey, Options};
use crate::config::Config;
use crate::error::Error;
use crate::ids::Address;
use crate::plan::{self, Snapshot};
use crate::report::{PlanReport, StatusReport};
use crate::state::{Phase, State, StateFile};

pub use apply::apply;
pub use fingerprint::PlanFingerprint;
pub use import::{import_guardrail, import_key};
pub use lifecycle::{decommission, delete_key, forget, retire};
pub use recover::{Finding, recover_inspect, recover_replace, recover_resolve};
pub use rotate::rotate;

/// The two files an operation reads.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The desired-state configuration.
    pub config: PathBuf,
    /// The local state file.
    pub state: PathBuf,
}

/// Everything an operation needs that is not one of its arguments.
///
/// Owned rather than borrowed, and `Send + 'static`, so a host can move it to
/// the thread that runs the operation.
#[derive(Debug)]
pub struct Context {
    /// Where the configuration and state files are.
    pub paths: Paths,
    /// The API root and the bounds every request is made under.
    pub options: Options,
    /// The management credential, when the caller has one.
    pub key: Option<ManagementKey>,
}

impl Context {
    /// Builds the client for this operation, checking the credential.
    ///
    /// Every caller reaches this after the configuration and state have been
    /// read and before its first API call or state write, so a run with no
    /// credential fails having changed nothing.
    fn client(&self) -> Result<Client, ApiError> {
        let key = self.key.as_ref().ok_or(ApiError::MissingCredential)?;
        Client::new(self.options.clone(), key)
    }
}

/// A report, and the failure that stands beside it.
///
/// `error` is what the caller maps to a failed run. The CLI maps it to exit 1,
/// after rendering the report.
#[derive(Debug)]
pub struct Outcome<R> {
    /// What the operation did.
    pub report: R,
    /// Why it did not finish, when it did not.
    pub error: Option<Error>,
}

impl<R> Outcome<R> {
    /// An operation that finished.
    pub(crate) const fn ok(report: R) -> Self {
        Self {
            report,
            error: None,
        }
    }

    /// An operation that produced a report and then failed.
    pub(crate) fn failed(report: R, error: impl Into<Error>) -> Self {
        Self {
            report,
            error: Some(error.into()),
        }
    }
}

/// What clears an unfinished operation, which is not always `recover`.
///
/// Several commands stand aside for an operation in progress — `rotate` will
/// not stage a successor beside one, `retire` and `delete key` will not touch
/// the key one is about to produce, `decommission` will not switch off a
/// credential while another is being created, and `state forget` will not throw
/// away the journal that records it. Each of those refusals has to name the
/// command that resolves it, and they must all name the same one, so the phase
/// is read here and nowhere else.
///
/// The split is a single phase wide. `delivered` needs no operator at all: the
/// key exists, its restrictions were verified, the receiver acknowledged the
/// plaintext, and the only thing outstanding is a local promotion that `apply`
/// completes under its own lock (ADR-0002). `recover replace` refuses that
/// phase outright, so a refusal that sent an operator there would send them to
/// a command that turns them away — at the moment they most need one that
/// works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// `delivered`: `apply` finishes it, locally.
    Promotion,
    /// Every other phase: only an operator can establish what happened.
    Recovery,
}

impl Resolution {
    /// Which of the two an operation in `phase` needs.
    pub(crate) const fn of(phase: Phase) -> Self {
        match phase {
            Phase::Delivered => Self::Promotion,
            Phase::CreateStarted
            | Phase::CreateAmbiguous
            | Phase::Created
            | Phase::Secured
            | Phase::DeliveryStarted
            | Phase::DeliveryAmbiguous => Self::Recovery,
        }
    }

    /// The sentence naming the one command that clears it, for an error to
    /// interpolate.
    ///
    /// Written to follow a colon or a dash, so each caller keeps its own
    /// account of what it refused and shares only the instruction.
    pub(crate) fn instruction(self, address: &Address) -> String {
        match self {
            Self::Promotion => format!(
                "no operator has to establish anything and nothing remote is outstanding — \
                 `openrouter-keymaster apply` records that key as `{address}`'s current key, under \
                 its own lock"
            ),
            Self::Recovery => format!(
                "only an operator can establish what happened — `openrouter-keymaster recover \
                 inspect {address}` names the one command this phase takes"
            ),
        }
    }
}

/// Reports the changes an apply would make. Writes nothing anywhere.
///
/// The report carries a [`PlanFingerprint`] of everything that decides what an
/// apply would write, so the plan a caller has shown can be made binding by
/// handing it back to [`apply::apply`]. It is `None` while an operation is
/// pending, because a plan computed beside one cannot be executed as it stands.
///
/// # Errors
///
/// Returns the configuration, state, and API errors of the reads it makes, and
/// `missing_credential` when the context carries no credential.
pub fn plan(context: Context) -> Result<Outcome<PlanReport>, Error> {
    let observed = observe(&context)?;
    let plan = plan::plan(&observed.config, &observed.state, &observed.snapshot);

    let mut report = PlanReport::new(&plan);
    let fingerprint = fingerprint::of(&context, &observed.config, &observed.state, &report);
    report.bind(fingerprint);
    // Success whether or not there are changes: planning succeeded either way,
    // and a distinct outcome for "has changes" is deliberately not part of the
    // contract.
    Ok(Outcome::ok(report))
}

/// Reports bindings, remote presence, usage, and unfinished operations.
///
/// # Errors
///
/// As [`plan`].
pub fn status(context: Context) -> Result<Outcome<StatusReport>, Error> {
    let observed = observe(&context)?;
    Ok(Outcome::ok(StatusReport::new(
        &observed.config,
        &observed.state,
        &observed.snapshot,
    )))
}

/// The three read-only inputs a reporting command needs.
struct Observation {
    config: Config,
    state: State,
    snapshot: Snapshot,
}

/// Parses the configuration, loads state, and reads OpenRouter.
///
/// The order is deliberate. A configuration problem is reported before a
/// client exists, so a run that cannot succeed never sends a credential
/// anywhere; state is read next, because it is local and cheap; the snapshot
/// is last.
///
/// State is read with [`StateFile::read`], which takes no lock and writes
/// nothing: observing remote drift is not a reason to rewrite state, and the
/// exclusive lock belongs to the commands that write.
///
/// The listings are unfiltered even when the configuration names a workspace.
/// The planner needs a *complete* snapshot: a key left out of it reads as a key
/// that does not exist, and a remote resource left out of it is one nothing
/// would report as unmanaged.
fn observe(context: &Context) -> Result<Observation, Error> {
    let config = Config::load(&context.paths.config)?;
    let state = StateFile::new(&context.paths.state).read()?;

    let client = context.client()?;
    let snapshot = snapshot(&Reader::new(&client))?;

    Ok(Observation {
        config,
        state,
        snapshot,
    })
}

/// Reads one complete snapshot of everything Keymaster manages.
///
/// Shared with apply, which reads one under its lock before planning and a
/// second one afterwards to verify what it wrote.
fn snapshot(reader: &Reader<'_>) -> Result<Snapshot, ApiError> {
    Ok(Snapshot {
        keys: reader.list_keys(None)?,
        guardrails: reader.list_guardrails(None)?,
        assignments: reader.list_assignments()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host hands a context to a worker thread, so it has to be movable and
    /// to own everything it names (ADR-0003, item 8).
    const fn assert_send_and_static<T: Send + 'static>() {}

    #[test]
    fn a_context_can_be_moved_to_another_thread() {
        assert_send_and_static::<Context>();
    }
}
