//! Command dispatch: the glue between the command line and the core crate's
//! [`ops`](openrouter_keymaster_core::ops).
//!
//! Every command is an [`ops`] function. This module builds the [`Context`]
//! those functions take from the parsed [`Cli`] and the environment, calls the
//! one the command names, renders the report it returns, and maps a failure
//! beside that report to exit code 1. It makes no decision of its own: what
//! each command does, what it refuses, and in what order it reads and writes
//! are all `ops`'.

pub mod env;

use std::fmt::Display;
use std::io::Write;

use serde::Serialize;

use crate::cli::StateAction;
use crate::cli::{Cli, Command, DeleteResource, ImportResource, RecoverAction, ResolveFinding};
use crate::output::Renderer;
use openrouter_keymaster_core::error::ApiError;
use openrouter_keymaster_core::error::Error;
use openrouter_keymaster_core::ops::recover::RecoverError;
use openrouter_keymaster_core::ops::{
    self, Context, Finding, ManagementKey, Options, Outcome, Paths,
};

/// Calls one operation and renders what it returned.
///
/// A macro rather than a function because each report type carries its own
/// `warnings()`, and Keymaster deliberately has no trait over the reports: the
/// documents are data, and a trait would exist only to satisfy this one call
/// site.
macro_rules! rendered {
    ($renderer:expr, $operation:expr) => {{
        let Outcome { report, error } = $operation?;
        render($renderer, &report, report.warnings(), error)
    }};
}

/// Runs the parsed command, writing its result through `renderer`.
///
/// # Errors
///
/// Returns the command's application error. Callers map any error to exit
/// code 1; clap has already exited 2 for a usage error by this point.
pub fn run<O: Write, E: Write>(cli: &Cli, renderer: &mut Renderer<O, E>) -> Result<(), Error> {
    let context = context(cli)?;
    match &cli.command {
        Command::Plan => rendered!(renderer, ops::plan(context)),
        Command::Status => rendered!(renderer, ops::status(context)),
        Command::Import {
            resource: ImportResource::Key { name, hash },
        } => rendered!(renderer, ops::import_key(context, name, hash)),
        Command::Import {
            resource: ImportResource::Guardrail { name, id },
        } => rendered!(renderer, ops::import_guardrail(context, name, id)),
        // The CLI applies whatever the recomputed plan says. Binding a plan to
        // the one an operator read is a caller's to ask for, and no terminal
        // run has a plan to bind.
        Command::Apply => rendered!(renderer, ops::apply(context, None)),
        Command::Rotate { name } => rendered!(renderer, ops::rotate(context, name)),
        Command::Recover {
            action: RecoverAction::Inspect { name },
        } => rendered!(renderer, ops::recover_inspect(context, name)),
        Command::Recover {
            action: RecoverAction::Resolve { name, finding },
        } => rendered!(
            renderer,
            ops::recover_resolve(context, name, &attested(finding)?)
        ),
        Command::Recover {
            action: RecoverAction::Replace { name },
        } => rendered!(renderer, ops::recover_replace(context, name)),
        Command::Retire { name, hash } => rendered!(renderer, ops::retire(context, name, hash)),
        Command::Decommission { name, hash, delete } => {
            rendered!(renderer, ops::decommission(context, name, hash, *delete))
        }
        Command::Delete {
            resource: DeleteResource::Key { hash },
        } => rendered!(renderer, ops::delete_key(context, hash)),
        Command::State {
            action: StateAction::Forget { address },
        } => rendered!(renderer, ops::forget(context, address)),
    }
}

/// Builds the context every operation takes.
///
/// The two environment variables are read here, where the binary's contract
/// puts them: the credential comes from `OPENROUTER_MANAGEMENT_KEY` and the
/// endpoint from `OPENROUTER_BASE_URL`, and neither has a command-line option.
/// An endpoint that is present and cannot be a base URL stops the run rather
/// than falling back, because falling back would send the credential somewhere
/// the operator did not name.
///
/// Two commands are exempt, and only because neither needs an endpoint to do
/// its work: they are the ones an operator runs when the environment is the
/// thing that is wrong, and a variable they never use must not be what stops
/// them.
fn context(cli: &Cli) -> Result<Context, Error> {
    let paths = Paths {
        config: cli.config.clone(),
        state: cli.state.clone(),
    };

    // `state forget` makes no request at all — no credential, no network, no
    // configuration — so it reads neither variable and neither can refuse it.
    if matches!(
        cli.command,
        Command::State {
            action: StateAction::Forget { .. }
        }
    ) {
        return Ok(offline(paths));
    }

    let endpoint = env::options();
    // `recover inspect` is offline once the journal records a hash, and it is
    // the command that explains a broken operation — precisely when the
    // environment may be broken too. An endpoint that cannot be read, or that
    // could never be requested, leaves it the production default and no
    // credential: nothing is sent anywhere, and an inspect that does turn out
    // to need a candidate listing then reports `missing_credential`, which is
    // the honest answer for an environment whose endpoint is unusable.
    if inspecting(&cli.command) && !usable(endpoint.as_ref()) {
        return Ok(offline(paths));
    }

    Ok(Context {
        paths,
        options: endpoint?,
        key: credential(&cli.command)?,
    })
}

/// A context that reaches nothing: the production defaults, and no credential
/// to send anywhere.
fn offline(paths: Paths) -> Context {
    Context {
        paths,
        options: Options::default(),
        key: None,
    }
}

/// Whether the endpoint was read *and* could be requested.
///
/// Both halves matter, and they fail at different moments: a variable that is
/// not Unicode is refused when it is read, and one that is Unicode but not a
/// URL is refused when a client is built from it. Either way there is no
/// endpoint, which is what the caller is asking about.
fn usable(endpoint: Result<&Options, &ApiError>) -> bool {
    endpoint.is_ok_and(|options| options.check_base_url().is_ok())
}

/// The credential, when the environment holds one that can be sent.
///
/// An unset credential is not an error here: a command that needs one reports
/// `missing_credential` where it would build its client, and two commands need
/// none at all. A credential that is set and *unusable* is a different fact —
/// a typo, not an absence — and every command that could send one reports it as
/// itself, so an operator is not sent looking for a variable they did set.
/// `recover inspect` is the exception, for the reason it tolerates an unusable
/// endpoint: it has to go on explaining a broken operation when the credential
/// is the broken thing.
fn credential(command: &Command) -> Result<Option<ManagementKey>, Error> {
    match env::management_key() {
        Ok(key) => Ok(Some(key)),
        Err(ApiError::MissingCredential) => Ok(None),
        Err(_) if inspecting(command) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Whether the command is `recover inspect`.
const fn inspecting(command: &Command) -> bool {
    matches!(
        command,
        Command::Recover {
            action: RecoverAction::Inspect { .. }
        }
    )
}

/// The finding an operator attested, as [`ops::recover_resolve`] takes it.
///
/// Clap's group requires exactly one of the two flags, so the third case cannot
/// be typed — but nothing about the parsed type says so, and guessing which the
/// operator meant is precisely what `recover` exists not to do.
fn attested(finding: &ResolveFinding) -> Result<Finding, Error> {
    match (&finding.leaked_hash, finding.no_resource_created) {
        (Some(hash), _) => Ok(Finding::LeakedHash(hash.clone())),
        (None, true) => Ok(Finding::NoResourceCreated),
        (None, false) => Err(RecoverError::NoFinding.into()),
    }
}

/// Writes a command's warnings, then its result, then reports its failure.
///
/// Warnings first, so a human run sees them before a long result scrolls past;
/// they are separate streams, so the order between them is the operator's
/// terminal's to decide either way. The result is written whether or not the
/// operation failed: what did happen is what an operator needs.
fn render<O: Write, E: Write, R: Serialize + Display>(
    renderer: &mut Renderer<O, E>,
    report: &R,
    warnings: &[String],
    error: Option<Error>,
) -> Result<(), Error> {
    for warning in warnings {
        renderer
            .warning(warning)
            .map_err(|error| Error::output(&error))?;
    }
    renderer
        .result(report)
        .map_err(|error| Error::output(&error))?;

    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
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
