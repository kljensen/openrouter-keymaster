//! The operations, as functions a caller can hold the result of.
//!
//! One function per command. Each takes an owned [`Context`] and the command's
//! arguments, and returns the command's report. Nothing here reads the
//! environment, prints, or exits: warnings are fields of the report, and the
//! caller decides what to do with them (ADR-0003).
//!
//! [`Context`] is `Send + 'static` and carries no client. Each operation builds
//! its own HTTP client and its receivers on the thread that runs it, from the
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
//! [`Context::deliver`] is optional for the same kind of reason: only an
//! operation that issues a key through a `caller` receiver needs the host's
//! code, and the shared issuance preflight checks for it before anything is
//! journaled or created (ADR-0005).
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
use crate::client::{ApiError, Client};
use crate::config::{Config, ConfigError, Problem};
use crate::error::Error;
use crate::ids::{Address, Uuid};
use crate::plan::{self, Snapshot};
use crate::report::{PlanReport, StatusReport};
use crate::state::{Phase, State, StateFile};

// The credential and endpoint types a caller needs to build a [`Context`], and
// the two environment variable names the CLI reads them from. They are defined
// beside the HTTP client, which is internal (ADR-0003, item 7); a host reaches
// them here, where the context that carries them is defined.
pub use crate::client::{MANAGEMENT_KEY_VAR, ManagementKey, Options, PRODUCTION_BASE_URL};

// What a host's own delivery callback is handed and what it answers with
// (ADR-0005). The receiver module behind them stays internal: a host supplies a
// closure, never an implementation of the trait, so this is the whole of the
// receiver surface it needs.
pub use crate::client::KeyPlaintext;
pub(crate) use crate::receiver::Deliver;
pub use crate::receiver::{Acknowledgement, DeliveryMetadata, Outcome as DeliveryOutcome};

pub use apply::apply;
pub use fingerprint::PlanFingerprint;
pub use import::{import_guardrail, import_key, import_workspace};
pub use lifecycle::{decommission, delete_key, delete_workspace, forget, retire};
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
/// the thread that runs the operation. It is not `Clone` and its `Debug` is
/// hand-written, because [`Context::deliver`] is a closure: a host builds one
/// context per operation.
pub struct Context {
    /// Where the configuration and state files are.
    pub paths: Paths,
    /// The API root and the bounds every request is made under.
    pub options: Options,
    /// The management credential, when the caller has one.
    pub key: Option<ManagementKey>,
    /// The one workspace this run places resources in and reports on.
    ///
    /// `None` is the whole organization, which is what every run did before
    /// the scope existed. `Some(id)` is a guard on placement and a filter on
    /// noise, and nothing more (ADR-0004, item 5): every key and guardrail
    /// this run creates is placed in that workspace, a configuration naming
    /// another one is refused, reports leave out `unmanaged` resources
    /// elsewhere, and matching by *name* — adoption candidates, the collision
    /// check before a recreation — considers only resources in it. Matching by
    /// *identity* does not change: the snapshot is still the whole
    /// organization, so a bound resource is judged present or missing exactly
    /// as it is without a scope. Two scopes pointed at one state file give
    /// correct but mixed plans; the scope does not isolate.
    pub workspace: Option<Uuid>,

    /// The host code a `caller` receiver hands a new key's plaintext to
    /// (ADR-0005).
    ///
    /// `None` — what the `openrouter-keymaster` command line always passes —
    /// is a host with no such code, and an operation that would have to issue a
    /// key through a `caller` receiver fails its preflight before anything is
    /// created. Planning never needs it.
    ///
    /// One operation may issue several keys, so the callback is called once per
    /// delivery, on the thread running the operation, and routes by the
    /// [`DeliveryMetadata`] it is handed — the address and the block's
    /// configured destination — rather than by call order. What it returns is
    /// the delivery's classification, and a panic inside it is caught and
    /// classified [`Acknowledgement::Ambiguous`].
    ///
    /// Keymaster's guarantees about the plaintext end at this call.
    pub deliver: Option<Deliver>,
}

impl std::fmt::Debug for Context {
    /// Written by hand because a closure has no `Debug`; it is reported as
    /// present or absent, which is all there is to say about it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("paths", &self.paths)
            .field("options", &self.options)
            .field("key", &self.key)
            .field("workspace", &self.workspace)
            .field("deliver", &self.deliver.is_some())
            .finish()
    }
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

    /// Reads the configuration and checks it against the workspace scope.
    ///
    /// Every operation that reads a configuration reads it here, so a scoped
    /// run refuses a configuration that describes another workspace before it
    /// has built a client, sent a request, or taken anything but the lock.
    fn config(&self) -> Result<Config, Error> {
        let config = Config::load(&self.paths.config)?;
        if let Some(scope) = &self.workspace {
            refuse_other_workspaces(&config, scope)?;
        }
        Ok(config)
    }

    /// The scope, as the planner and the write bodies take it.
    const fn scope(&self) -> Option<&Uuid> {
        self.workspace.as_ref()
    }

    /// Refuses a scoped run whose blocks resolve to another workspace, or whose
    /// workspace blocks this scope could never own.
    ///
    /// Separate from [`Context::config`] because it needs state: a `workspace`
    /// address means whatever the binding says it means, and a workspace block
    /// is in scope only when it is already bound to the scope itself. Every
    /// caller runs it as soon as it has both files, before it builds a client
    /// or writes anything.
    fn check_scope(&self, config: &Config, state: &State) -> Result<(), ConfigError> {
        let Some(scope) = &self.workspace else {
            return Ok(());
        };
        refuse_out_of_scope(config, state, scope)
    }
}

/// Refuses a configuration that names a workspace other than `scope`.
///
/// A block that names no workspace is not a problem — the scope is where it
/// gets placed. Naming a different one is, because a scoped run creates
/// nothing outside its scope and reports nothing from outside it either, so
/// such a block could never converge.
fn refuse_other_workspaces(config: &Config, scope: &Uuid) -> Result<(), ConfigError> {
    let problems: Vec<Problem> = config
        .keys
        .iter()
        .filter(|(_, key)| key.workspace_id.as_ref().is_some_and(|id| id != scope))
        .map(|(address, _)| Problem {
            path: format!("keys.{address}.workspace_id"),
            message: misplaced(scope),
        })
        .chain(
            config
                .guardrails
                .iter()
                .filter(|(_, rail)| rail.workspace_id.as_ref().is_some_and(|id| id != scope))
                .map(|(address, _)| Problem {
                    path: format!("guardrails.{address}.workspace_id"),
                    message: misplaced(scope),
                }),
        )
        .collect();
    if problems.is_empty() {
        return Ok(());
    }
    Err(ConfigError::Invalid { problems })
}

/// Refuses the blocks a scoped run could never place or own (ADR-0004, item 5).
///
/// Three rules, all the same rule seen from different sides. A key or guardrail
/// whose `workspace` address is bound elsewhere would be created outside the
/// scope. A workspace block bound elsewhere is another club's. And a workspace
/// block bound to nothing at all cannot be created here either: a scoped run
/// places what it creates in the scope, and the UUID `POST /workspaces` returns
/// could never be the one it was scoped to. The operator applies unscoped once,
/// or imports, and scopes from then on.
fn refuse_out_of_scope(config: &Config, state: &State, scope: &Uuid) -> Result<(), ConfigError> {
    refuse_other_workspaces(config, scope)?;

    let elsewhere = |address: &Address| {
        state
            .workspace(address)
            .is_none_or(|binding| binding.id != *scope)
    };
    let problems: Vec<Problem> = config
        .keys
        .iter()
        .filter(|(_, key)| key.workspace.as_ref().is_some_and(elsewhere))
        .map(|(address, _)| Problem {
            path: format!("keys.{address}.workspace"),
            message: misplaced(scope),
        })
        .chain(
            config
                .guardrails
                .iter()
                .filter(|(_, rail)| rail.workspace.as_ref().is_some_and(elsewhere))
                .map(|(address, _)| Problem {
                    path: format!("guardrails.{address}.workspace"),
                    message: misplaced(scope),
                }),
        )
        .chain(
            config
                .workspaces
                .keys()
                .filter(|address| elsewhere(address))
                .map(|address| Problem {
                    path: format!("workspaces.{address}"),
                    message: format!(
                        "this run is scoped to workspace {scope}, and a scoped run neither creates \
                         a workspace nor manages another one; import this block with \
                         `openrouter-keymaster import workspace {address} --id {scope}`, or apply \
                         it once without `--workspace`"
                    ),
                }),
        )
        .collect();
    if problems.is_empty() {
        return Ok(());
    }
    Err(ConfigError::Invalid { problems })
}

/// What every refusal of a block placed outside the scope says.
fn misplaced(scope: &Uuid) -> String {
    format!(
        "this run is scoped to workspace {scope} and places every resource it creates there, so a \
         block may name that workspace or none"
    )
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
    let plan = plan::plan(
        &observed.config,
        &observed.state,
        &observed.snapshot,
        context.scope(),
    );

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
        context.scope(),
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
/// The listings are unfiltered even when the configuration names a workspace or
/// the context is scoped to one. The planner needs a *complete* snapshot: a key
/// left out of it reads as a key that does not exist, and a bound resource in
/// another workspace would look orphaned. The scope filters what is reported
/// and matched by name, never what is observed (ADR-0004, item 5).
fn observe(context: &Context) -> Result<Observation, Error> {
    let config = context.config()?;
    let state = StateFile::new(&context.paths.state).read()?;
    context.check_scope(&config, &state)?;

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
        workspaces: reader.list_workspaces()?,
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
