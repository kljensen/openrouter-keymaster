//! Command dispatch.
//!
//! `plan` and `status` are implemented; every other v0.1 command parses and
//! fails with a typed [`Error::NotImplemented`] until its feature issue lands.
//! Each match arm calls that feature's handler, which builds an output DTO for
//! [`Renderer`] to write.
//!
//! Both implemented commands are strictly read-only: they parse the
//! configuration, read state without locking or rewriting it, read a complete
//! snapshot of OpenRouter, and print. No API write, no receiver invocation, and
//! no state write happens on either path.

use std::fmt::Display;
use std::io::Write;

use serde::Serialize;

use crate::api::Reader;
use crate::cli::{Cli, Command, DeleteResource, ImportResource, RecoverAction, StateAction};
use crate::client::Client;
use crate::config::Config;
use crate::error::Error;
use crate::output::Renderer;
use crate::plan::{self, Snapshot};
use crate::report::{PlanReport, StatusReport};
use crate::state::{State, StateFile};

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
        command => Err(Error::NotImplemented {
            command: command_path(command),
        }),
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
    let reader = Reader::new(&client);
    let snapshot = Snapshot {
        keys: reader.list_keys(None)?,
        guardrails: reader.list_guardrails(None)?,
        assignments: reader.list_assignments()?,
    };

    Ok(Observation {
        config,
        state,
        snapshot,
    })
}

/// The canonical dotted-free command path, as an operator would type it.
fn command_path(command: &Command) -> &'static str {
    match command {
        Command::Plan => "plan",
        Command::Apply => "apply",
        Command::Status => "status",
        Command::Import {
            resource: ImportResource::Key { .. },
        } => "import key",
        Command::Import {
            resource: ImportResource::Guardrail { .. },
        } => "import guardrail",
        Command::Rotate { .. } => "rotate",
        Command::Recover {
            action: RecoverAction::Inspect { .. },
        } => "recover inspect",
        Command::Recover {
            action: RecoverAction::Resolve { .. },
        } => "recover resolve",
        Command::Recover {
            action: RecoverAction::Replace { .. },
        } => "recover replace",
        Command::Retire { .. } => "retire",
        Command::Delete {
            resource: DeleteResource::Key { .. },
        } => "delete key",
        Command::State {
            action: StateAction::Forget { .. },
        } => "state forget",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Format;
    use clap::Parser;

    fn path_of(argv: &[&str]) -> &'static str {
        command_path(&Cli::parse_from(argv).command)
    }

    #[test]
    fn every_command_reports_its_own_path() {
        assert_eq!(path_of(&["keymaster", "plan"]), "plan");
        assert_eq!(path_of(&["keymaster", "apply"]), "apply");
        assert_eq!(path_of(&["keymaster", "status"]), "status");
        assert_eq!(
            path_of(&["keymaster", "import", "key", "jobfeed", "--hash", "h"]),
            "import key"
        );
        assert_eq!(
            path_of(&["keymaster", "import", "guardrail", "cheap", "--id", "u"]),
            "import guardrail"
        );
        assert_eq!(path_of(&["keymaster", "rotate", "jobfeed"]), "rotate");
        assert_eq!(
            path_of(&["keymaster", "recover", "inspect", "jobfeed"]),
            "recover inspect"
        );
        assert_eq!(
            path_of(&[
                "keymaster",
                "recover",
                "resolve",
                "jobfeed",
                "--no-resource-created"
            ]),
            "recover resolve"
        );
        assert_eq!(
            path_of(&["keymaster", "recover", "replace", "jobfeed"]),
            "recover replace"
        );
        assert_eq!(
            path_of(&["keymaster", "retire", "jobfeed", "--hash", "h"]),
            "retire"
        );
        assert_eq!(
            path_of(&["keymaster", "delete", "key", "--hash", "h"]),
            "delete key"
        );
        assert_eq!(
            path_of(&["keymaster", "state", "forget", "keys.jobfeed"]),
            "state forget"
        );
    }

    #[test]
    fn an_unimplemented_command_reports_itself() {
        let cli = Cli::parse_from(["keymaster", "apply"]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut renderer = Renderer::new(Format::Human, &mut out, &mut err);

        let error = run(&cli, &mut renderer).expect_err("apply is not implemented yet");

        assert_eq!(error.kind(), "not_implemented");
        assert!(error.to_string().contains("apply"));
        assert!(out.is_empty(), "an unimplemented command writes nothing");
    }

    #[test]
    fn a_missing_configuration_stops_plan_before_any_client_exists() {
        let cli = Cli::parse_from([
            "keymaster",
            "--config",
            "/nonexistent/keymaster.toml",
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
