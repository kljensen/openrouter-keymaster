//! Command dispatch.
//!
//! Every v0.1 command is implemented. Each match arm calls that feature's
//! handler, which builds an output DTO for [`Renderer`] to write.
//!
//! `plan` and `status` are strictly read-only: they parse the configuration,
//! read state without locking or rewriting it, read a complete snapshot of
//! OpenRouter, and print. No API write, no receiver invocation, and no state
//! write happens on either path. `recover inspect` is read-only in the same
//! sense, and `state forget` is the mirror image: it writes state and makes no
//! remote call at all.
//!
//! The writing commands take the exclusive state lock first and reload
//! everything under it. [`import`] makes no remote write — it reads one remote
//! object and records a binding; [`apply`] converges guardrails, keys, and
//! assignments, verifying what it wrote, and runs the journaled transaction for
//! a planned key create or replace; [`rotate`] runs that same transaction on an
//! operator's word; [`recover`] closes an operation whose outcome only an
//! operator can establish; and [`lifecycle`] holds the four explicit endings —
//! `retire`, `decommission`, `delete key`, and `state forget` — that nothing
//! else ever performs.

pub mod apply;
pub mod import;
mod issuance;
pub mod lifecycle;
pub mod recover;
pub mod rotate;

use std::fmt::Display;
use std::io::Write;

use serde::Serialize;

use crate::api::Reader;
use crate::cli::{Cli, Command, DeleteResource, StateAction};
use crate::client::{ApiError, Client};
use crate::config::Config;
use crate::error::Error;
use crate::ids::Address;
use crate::output::Renderer;
use crate::plan::{self, Snapshot};
use crate::report::{PlanReport, StatusReport};
use crate::state::{Phase, State, StateFile};

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
pub(super) enum Resolution {
    /// `delivered`: `apply` finishes it, locally.
    Promotion,
    /// Every other phase: only an operator can establish what happened.
    Recovery,
}

impl Resolution {
    /// Which of the two an operation in `phase` needs.
    pub(super) const fn of(phase: Phase) -> Self {
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
    pub(super) fn instruction(self, address: &Address) -> String {
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

/// Runs the parsed command, writing its result through `renderer`.
///
/// # Errors
///
/// Returns the command's application error. Callers map any error to exit
/// code 1; clap has already exited 2 for a usage error by this point.
pub fn run<O: Write, E: Write>(cli: &Cli, renderer: &mut Renderer<O, E>) -> Result<(), Error> {
    match &cli.command {
        Command::Plan => plan_command(cli, renderer),
        Command::Status => status_command(cli, renderer),
        Command::Import { resource } => import::run(cli, resource, renderer),
        Command::Apply => apply::run(cli, renderer),
        Command::Rotate { name } => rotate::run(cli, name, renderer),
        Command::Recover { action } => recover::run(cli, action, renderer),
        Command::Retire { name, hash } => lifecycle::retire(cli, name, hash, renderer),
        Command::Decommission { name, hash, delete } => {
            lifecycle::decommission(cli, name, hash, *delete, renderer)
        }
        Command::Delete {
            resource: DeleteResource::Key { hash },
        } => lifecycle::delete_key(cli, hash, renderer),
        Command::State {
            action: StateAction::Forget { address },
        } => lifecycle::forget(cli, address, renderer),
    }
}

/// Reports the changes an apply would make. Writes nothing anywhere.
fn plan_command<O: Write, E: Write>(cli: &Cli, renderer: &mut Renderer<O, E>) -> Result<(), Error> {
    let observed = observe(cli)?;
    let plan = plan::plan(&observed.config, &observed.state, &observed.snapshot);
    let report = PlanReport::new(&plan);
    // Exit 0 whether or not there are changes: planning succeeded either way,
    // and a distinct code for "has changes" is deliberately not part of v0.1.
    write(renderer, &report, report.warnings())
}

/// Reports bindings, remote presence, usage, and unfinished operations.
fn status_command<O: Write, E: Write>(
    cli: &Cli,
    renderer: &mut Renderer<O, E>,
) -> Result<(), Error> {
    let observed = observe(cli)?;
    let report = StatusReport::new(&observed.config, &observed.state, &observed.snapshot);
    write(renderer, &report, report.warnings())
}

/// Writes a command's warnings and then its result.
///
/// Warnings first, so a human run sees them before a long result scrolls past;
/// they are separate streams, so the order between them is the operator's
/// terminal's to decide either way.
fn write<O: Write, E: Write, T: Serialize + Display>(
    renderer: &mut Renderer<O, E>,
    report: &T,
    warnings: &[String],
) -> Result<(), Error> {
    for warning in warnings {
        renderer
            .warning(warning)
            .map_err(|error| Error::output(&error))?;
    }
    renderer
        .result(report)
        .map_err(|error| Error::output(&error))
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
fn observe(cli: &Cli) -> Result<Observation, Error> {
    let config = Config::load(&cli.config)?;
    let state = StateFile::new(&cli.state).read()?;

    let client = Client::from_env()?;
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
    use crate::output::Format;
    use clap::Parser;

    /// `state forget` is the one command that must work with no credential, no
    /// network, and no configuration: it exists to correct state that is wrong,
    /// which is exactly when the other three may be unavailable.
    #[test]
    fn forget_needs_no_configuration_and_makes_no_remote_call() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let cli = Cli::parse_from([
            "openrouter-keymaster",
            "--config",
            "/nonexistent/openrouter-keymaster.toml",
            "--state",
            &directory.path().join("state.json").display().to_string(),
            "state",
            "forget",
            "keys.jobfeed",
        ]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut renderer = Renderer::new(Format::Human, &mut out, &mut err);

        run(&cli, &mut renderer).expect("forgetting an unbound address is a no-op");

        let out = String::from_utf8(out).expect("utf-8 output");
        assert!(out.contains("nothing to forget"), "{out}");
    }

    #[test]
    fn a_missing_configuration_stops_plan_before_any_client_exists() {
        let cli = Cli::parse_from([
            "openrouter-keymaster",
            "--config",
            "/nonexistent/openrouter-keymaster.toml",
            "--state",
            "/nonexistent/state.json",
            "plan",
        ]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut renderer = Renderer::new(Format::Human, &mut out, &mut err);

        let error = run(&cli, &mut renderer).expect_err("there is no configuration to read");

        assert_eq!(error.kind(), "config_read");
        assert!(out.is_empty(), "a failed plan writes no result");
    }
}
