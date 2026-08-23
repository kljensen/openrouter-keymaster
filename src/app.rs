//! Command dispatch.
//!
//! Every v0.1 command parses today, and every one of them fails with a typed
//! [`Error::NotImplemented`] until its feature issue lands. Each match arm
//! becomes a call into that feature's handler, which will return an output
//! DTO for [`crate::output::Renderer`] to write.

use crate::cli::{Cli, Command, DeleteResource, ImportResource, RecoverAction, StateAction};
use crate::error::Error;

/// Runs the parsed command.
///
/// # Errors
///
/// Returns the command's application error. Callers map any error to exit
/// code 1; clap has already exited 2 for a usage error by this point.
pub fn run(cli: &Cli) -> Result<(), Error> {
    Err(Error::NotImplemented {
        command: command_path(&cli.command),
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
    fn running_a_command_reports_it_as_unimplemented() {
        let cli = Cli::parse_from(["keymaster", "plan"]);
        let error = run(&cli).expect_err("no command is implemented yet");
        assert_eq!(error.kind(), "not_implemented");
        assert!(error.to_string().contains("plan"));
    }
}
