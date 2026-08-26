//! Parse, construct dependencies, dispatch, render, and map the exit code.

use std::io;
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;
use openrouter_keymaster::app;
use openrouter_keymaster::cli::Cli;
use openrouter_keymaster::output::{Format, Renderer};
use openrouter_keymaster_core::error::Error;

/// Exit code for an application error.
const FAILURE: u8 = 1;

/// Exit code for a usage error, matching clap's own convention.
const USAGE: u8 = 2;

fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(cli) => dispatch(&cli),
        Err(error) => report_parse_failure(&error),
    }
}

/// Runs a parsed command and renders its outcome.
fn dispatch(cli: &Cli) -> ExitCode {
    let mut renderer = renderer(Format::from_json_flag(cli.json));
    match app::run(cli, &mut renderer) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // A diagnostic that cannot be written cannot itself be reported.
            let _ = renderer.error(&error);
            ExitCode::from(FAILURE)
        }
    }
}

/// Renders help, the version, or a usage error.
///
/// Clap reports all three as errors from `try_parse`. Help and version are
/// successful output; anything else is a usage error and exits 2.
fn report_parse_failure(error: &clap::Error) -> ExitCode {
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        // Clap already knows help and version belong on stdout.
        let _ = error.print();
        return ExitCode::SUCCESS;
    }

    if json_requested() {
        // `Error::render` returns the message without ANSI styling.
        let usage = Error::Usage {
            message: error.render().to_string(),
        };
        let _ = renderer(Format::Json).error(&usage);
    } else {
        let _ = error.print();
    }
    ExitCode::from(USAGE)
}

/// Whether `--json` appears on the command line.
///
/// A usage error means there is no parsed `Cli` to ask, so this scans the raw
/// arguments. It is best-effort by construction: it cannot tell `--json` used
/// as a flag from the same text used as an option's value, and it does not
/// understand `--` or abbreviations. Being wrong only changes the format of a
/// usage error, never the exit code or whether one is reported.
fn json_requested() -> bool {
    std::env::args_os().any(|argument| argument == "--json")
}

fn renderer(format: Format) -> Renderer<io::StdoutLock<'static>, io::StderrLock<'static>> {
    Renderer::new(format, io::stdout().lock(), io::stderr().lock())
}
