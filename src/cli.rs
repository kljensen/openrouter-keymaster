//! The `keymaster` command tree.
//!
//! This module only describes the command-line surface. It performs no
//! validation beyond parsing, reads no environment variable, and prints
//! nothing. There is deliberately no option for the management credential:
//! it is read from `OPENROUTER_MANAGEMENT_KEY` only, so it can never appear
//! in a process argument list.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Where local state lives unless `--state` says otherwise. Defaulting here
/// rather than in each handler keeps one answer to "which file is it?".
/// Issue #10 owns the file's format, permissions, and locking.
pub const DEFAULT_STATE_PATH: &str = ".openrouter-keymaster/state.json";

/// Declarative OpenRouter key and guardrail management.
#[derive(Debug, Parser)]
#[command(name = "keymaster", version, about, long_about = None)]
pub struct Cli {
    /// Desired-state configuration file.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        default_value = "keymaster.toml"
    )]
    pub config: PathBuf,

    /// Local state file.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        default_value = DEFAULT_STATE_PATH
    )]
    pub state: PathBuf,

    /// Print one JSON document instead of human-readable output.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// A top-level `keymaster` command.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the changes an apply would make. Makes no remote or local write.
    #[command(long_about = "\
Show the changes an apply would make.

Plan validates the whole configuration, loads local state without rewriting \
it, reads a complete snapshot of OpenRouter, and prints the actions an apply \
would take and why. It makes no API write, invokes no receiver, and leaves the \
state file byte for byte as it found it.

Exit code 0 means planning succeeded, whether or not there are changes to \
make: there is no separate exit code for a plan that found work to do. Exit \
code 1 means planning failed — a configuration, credential, state, or API \
error, whose category is named in the diagnostic.")]
    Plan,

    /// Converge OpenRouter with the desired configuration.
    #[command(long_about = "\
Converge OpenRouter with the desired configuration.

Apply takes the exclusive state lock, reloads the configuration and state under \
it, reads a complete snapshot of OpenRouter, and computes the plan again — so \
what runs is never the plan an earlier `keymaster plan` printed. It then \
executes that plan in three fixed phases: guardrail creates and updates, \
updates to keys that already exist, and assignment changes. A created \
guardrail's UUID is recorded before anything else happens. Finally it reads \
OpenRouter again and reports, per action, whether the result was verified.

Every write is sent exactly once. A write whose outcome is unknown is never \
repeated; the read that follows says whether it took effect.

Apply does not yet create or replace inference keys: issuing a one-time secret \
needs the journaled transaction of #16. A planned creation is skipped, and the \
run reports that the configuration is not fully converged.

Exit code 0 means nothing went wrong, which is not the same as converged: a \
write apply cannot make yet, or one the plan holds back until an operator \
resolves what blocks it, leaves the run reporting `incomplete` or `held_back`. \
Exit code 1 means something did go wrong — a write failed, a write could not \
be confirmed, or an unfinished operation stopped the run — and the result \
document on stdout says exactly which.")]
    Apply,

    /// Report bindings, remote presence, and incomplete operations.
    #[command(long_about = "\
Report bindings, remote presence, and incomplete operations.

Status prints which local address owns which remote resource, whether that \
resource is still there, what each key has spent against its budget, which \
remote resources no local address owns, and any operation an earlier run left \
unfinished. Like plan, it makes no write of any kind.

Exit code 0 means the report was produced, whatever it says. Exit code 1 means \
it could not be — a configuration, credential, state, or API error.")]
    Status,

    /// Bind an existing remote resource to a local address.
    Import {
        #[command(subcommand)]
        resource: ImportResource,
    },

    /// Stage a replacement key for a local address.
    Rotate {
        /// Local key address, as written in the configuration.
        name: String,
    },

    /// Inspect or resolve an interrupted key operation.
    Recover {
        #[command(subcommand)]
        action: RecoverAction,
    },

    /// Disable a tracked retained key hash and verify the result.
    Retire {
        /// Local key address, as written in the configuration.
        name: String,

        /// Immutable hash of the retained key to disable.
        #[arg(long, value_name = "HASH")]
        hash: String,
    },

    /// Permanently delete a tracked remote resource.
    Delete {
        #[command(subcommand)]
        resource: DeleteResource,
    },

    /// Local state maintenance.
    State {
        #[command(subcommand)]
        action: StateAction,
    },
}

/// The resource kind an `import` binds.
#[derive(Debug, Subcommand)]
pub enum ImportResource {
    /// Bind an existing API key by its immutable hash.
    Key {
        /// Local key address, as written in the configuration.
        name: String,

        /// Immutable hash of the remote key.
        #[arg(long, value_name = "HASH")]
        hash: String,
    },

    /// Bind an existing guardrail by its UUID.
    Guardrail {
        /// Local guardrail address, as written in the configuration.
        name: String,

        /// UUID of the remote guardrail.
        #[arg(long, value_name = "UUID")]
        id: String,
    },
}

/// A `recover` action.
#[derive(Debug, Subcommand)]
pub enum RecoverAction {
    /// Report an interrupted operation and its remote candidates.
    Inspect {
        /// Local key address, as written in the configuration.
        name: String,
    },

    /// Record the operator's finding about an ambiguous operation.
    Resolve {
        /// Local key address, as written in the configuration.
        name: String,

        #[command(flatten)]
        finding: ResolveFinding,
    },

    /// Create a replacement for a key whose ambiguity has been resolved.
    Replace {
        /// Local key address, as written in the configuration.
        name: String,
    },
}

/// The operator's attested finding about an ambiguous operation.
///
/// Exactly one finding is required: Keymaster never guesses which happened.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct ResolveFinding {
    /// Attest that inspection found no remote resource was created.
    #[arg(long)]
    pub no_resource_created: bool,

    /// Bind this exact hash as the leaked candidate of the operation.
    #[arg(long, value_name = "HASH")]
    pub leaked_hash: Option<String>,
}

/// The resource kind a `delete` removes.
#[derive(Debug, Subcommand)]
pub enum DeleteResource {
    /// Permanently delete a tracked key, identified by its immutable hash.
    Key {
        /// Immutable hash of the tracked key to delete.
        #[arg(long, value_name = "HASH")]
        hash: String,
    },
}

/// A `state` action.
#[derive(Debug, Subcommand)]
pub enum StateAction {
    /// Relinquish local ownership of an address. Makes no remote call.
    Forget {
        /// Local resource address, as written in the configuration.
        address: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn paths_have_documented_defaults() {
        let cli = Cli::parse_from(["keymaster", "plan"]);
        assert_eq!(cli.config, PathBuf::from("keymaster.toml"));
        assert_eq!(cli.state, PathBuf::from(DEFAULT_STATE_PATH));
        assert!(!cli.json);
    }

    #[test]
    fn global_options_are_accepted_after_the_subcommand() {
        let cli = Cli::parse_from(["keymaster", "plan", "--json", "--state", "/tmp/s.json"]);
        assert!(cli.json);
        assert_eq!(cli.state, PathBuf::from("/tmp/s.json"));
    }

    #[test]
    fn no_argument_carries_the_management_credential() {
        let rendered = format!("{:?}", Cli::command().render_long_help());
        assert!(!rendered.contains("OPENROUTER_MANAGEMENT_KEY"));
        assert!(!rendered.contains("--management-key"));
    }
}
