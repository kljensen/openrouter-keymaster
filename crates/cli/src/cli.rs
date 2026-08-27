//! The `openrouter-keymaster` command tree.
//!
//! This module only describes the command-line surface. It performs no
//! validation beyond parsing, reads no environment variable, and prints
//! nothing. There is deliberately no option for the management credential:
//! it is read from `OPENROUTER_MANAGEMENT_KEY` only, so it can never appear
//! in a process argument list.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use openrouter_keymaster_core::ids::Uuid;

/// Where local state lives unless `--state` says otherwise. The command line
/// is the only place this default lives: core's
/// [`state`](openrouter_keymaster_core::state) is handed the path it works on,
/// so a host that keeps state somewhere else names it (ADR-0003).
/// Issue #10 owns the file's format, permissions, and locking.
pub const DEFAULT_STATE_PATH: &str = ".openrouter-keymaster/state.json";

/// Declarative OpenRouter key and guardrail management.
#[derive(Debug, Parser)]
#[command(name = "openrouter-keymaster", version, about, long_about = None)]
pub struct Cli {
    /// Desired-state configuration file.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        default_value = "openrouter-keymaster.toml"
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

    /// Place and report only in this OpenRouter workspace.
    #[arg(long, global = true, value_name = "UUID", value_parser = Uuid::parse)]
    pub workspace: Option<Uuid>,

    /// Print one JSON document instead of human-readable output.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// A top-level `openrouter-keymaster` command.
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
what runs is never the plan an earlier `openrouter-keymaster plan` printed. It then \
executes that plan in three fixed phases: guardrail creates and updates, \
updates to keys that already exist, and assignment changes. A created \
guardrail's UUID is recorded before anything else happens. Finally it reads \
OpenRouter again and reports, per action, whether the result was verified.

Every write is sent exactly once. A write whose outcome is unknown is never \
repeated; the read that follows says whether it took effect.

A planned key creation runs the journaled transaction of ADR-0002: one durable \
journal entry before and after every non-idempotent step, exactly one \
`POST /keys` with retries disabled, restrictions and the guardrail applied and \
verified before the plaintext goes anywhere, and the configured receiver \
invoked exactly once. Any outcome other than a delivered key stops the whole \
run and is resolved with `openrouter-keymaster recover`, never by trying again.

A planned replacement — a raised generation, a moved receiver, a changed \
immutable field — runs that same transaction. The key the address already holds \
is not disabled, deleted, or unassigned: promotion moves it to \
`retained.awaiting_retirement`, where it stays exactly as it was until an \
explicit `openrouter-keymaster retire`.

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
    #[command(long_about = "\
Stage a replacement key for a local address.

Rotate runs the journaled transaction of ADR-0002 on your word, exactly as a \
planned replacement does: one `POST /keys`, restrictions and the guardrail \
applied and verified, the receiver invoked once, and the new hash promoted to \
current only after a confirmed delivery.

The key the address already holds is never touched. It is not disabled, not \
deleted, not unassigned, and not read. Promotion moves it to \
`retained.awaiting_retirement`, where it stays exactly as it was until you run \
`openrouter-keymaster retire`, because Keymaster cannot know when the consumers of a \
credential have adopted its successor. A rotation that fails at any phase \
therefore leaves the working credential working.

Everything the successor needs is checked before anything is sent: the address \
owns a key, no operation is in progress anywhere, the configuration still \
describes the key and names a receiver, and its guardrail is bound and \
converged. A failure there costs a read and changes nothing, and each refusal \
names the one command that clears it: an unresolved attempt goes to `openrouter-keymaster \
recover`, and a delivered one goes to `openrouter-keymaster apply`, which completes the \
outstanding local promotion.

The successor takes the higher of the configured generation and the next free \
number at the address; a generation names one remote key and only ever moves \
upward.

Exit code 0 means the successor was created and delivered. Exit code 1 means it \
was not, and the diagnostic says what the address still holds.")]
    Rotate {
        /// Local key address, as written in the configuration.
        name: String,
    },

    /// Inspect or resolve an interrupted key operation.
    #[command(long_about = "\
Inspect or resolve an interrupted key operation.

A create request whose response was lost, a receiver that never acknowledged, \
or a run that died between two journal entries leaves an operation whose \
outcome only an operator can establish. Keymaster never guesses: it does not \
retry the create, adopt a remote key because its display name matches, or \
invoke a receiver a second time.

`recover inspect NAME` reports the journaled operation — its identifier, \
phase, timestamp, intended name and workspace, known hash, and the non-secret \
fingerprint of the receiver it was bound for — and lists the remote keys that \
could be the one a lost create made. Those are candidates, never matches, and \
none of them is ever selected automatically. It writes nothing, locally or \
remotely, and it reaches OpenRouter only when there is something to search \
for: once the journal records a hash, inspect needs no credential and makes no \
API call.

`recover resolve NAME --no-resource-created` records your attestation that \
OpenRouter holds no key from the attempt, and clears it. Keymaster cannot \
verify that.

`recover resolve NAME --leaked-hash HASH` fetches that exact hash, binds it as \
a failed candidate so it stays tracked, then disables it and confirms that by \
reading it back. A found hash is never promoted: OpenRouter disclosed its \
plaintext once, in a response nobody received, so the key can only be cleaned \
up. A disable that fails leaves the hash tracked for a later `retire` or \
`delete`.

`recover replace NAME` retires a dead operation — one whose key exists and \
whose plaintext is gone — and stages a successor through the same journaled \
transaction, under one lock. Everything the successor needs is checked before \
anything is retired or disabled, so a configuration that cannot produce one \
leaves the operation and its key exactly as they were. It is refused while it is still unknown whether \
the attempt created a key; resolve that first. A lost delivery acknowledgement \
has no attestation in v0.1, because no receiver exposes a query contract: \
replacement is the resolution.")]
    Recover {
        #[command(subcommand)]
        action: RecoverAction,
    },

    /// Disable a tracked retained key hash and verify the result.
    #[command(long_about = "\
Disable a tracked retained key hash and verify the result.

Retirement is always explicit. Nothing plans it, no rotation performs it, and \
a configuration block disappearing does not cause it: only this command \
disables a key Keymaster owns.

The hash is an immutable identity and must be one the address retains. \
Retiring the key an address is *using* is refused — Keymaster cannot know that \
nothing still holds it, and v0.1 defines no policy that permits the shortcut. \
Rotate first, then retire the predecessor.

The key is read before anything is sent; one OpenRouter already has disabled is \
reported as retired with no write at all, which is what makes repeating this \
free. Otherwise the disable is sent once and confirmed by reading the key back. \
A disable that cannot be confirmed leaves the hash tracked as \
`retirement_failed` so it can be retried.

The hash stays in state either way: a retired key is still visible to an audit \
and to a later `openrouter-keymaster delete key`.

Exit code 0 means a read proved the key is disabled. Exit code 1 means it did \
not; the result document on stdout says what the attempt established.")]
    Retire {
        /// Local key address, as written in the configuration.
        name: String,

        /// Immutable hash of the retained key to disable.
        #[arg(long, value_name = "HASH")]
        hash: String,
    },

    /// End the life of the key an address is currently using.
    #[command(long_about = "\
End the life of the key an address is currently using.

Decommission is the ending for a key that is not being replaced. `rotate` \
stages a successor and `retire` disables a predecessor; between them there is \
no way to stop using a credential and stop nothing else, which is what this \
command does.

HASH must be the address's *current* hash, and it is checked before anything is \
sent. There is no decommission-by-name: a display name is mutable and this \
disables a working credential, so the immutable identity is the only thing it \
will act on. Nothing plans it, and no rotation, apply, or configuration change \
performs it.

The key is read first; one OpenRouter already has disabled costs no write, and \
one OpenRouter no longer has is settled by the 404 that proves it. Otherwise \
the disable is sent once and confirmed by reading the key back. Only a \
confirmed disable moves the hash out of `current`, where it becomes \
`retained.retired` — so a disable that cannot be confirmed leaves the address \
using the key it already had, changes no state at all, and exits 1.

`--delete` continues into the same deletion `delete key` performs: one DELETE, \
confirmed by a 404, and only then does the hash stop being tracked. Without it \
the hash stays tracked as `retired`, and `openrouter-keymaster delete key \
--hash HASH` can finish the job whenever you choose. The generation is spent \
either way; a number never returns to the pool.

Afterwards the address is bound and owns no key. If the configuration still \
describes it, the next `openrouter-keymaster apply` creates a replacement at \
the next generation and delivers it — remove the `[keys.NAME]` block first if \
what you meant was to stop having this key at all.

An operation in progress anywhere refuses the run, naming the command that \
clears it.

Exit code 0 means every step this run took was confirmed by a read. Exit code 1 \
means one was not; the result document on stdout says which, and the diagnostic \
names the exact command that finishes it.")]
    Decommission {
        /// Local key address, as written in the configuration.
        name: String,

        /// Immutable hash of the key the address is currently using.
        #[arg(long, value_name = "HASH")]
        hash: String,

        /// Also delete the key from OpenRouter, confirmed by a 404.
        #[arg(long)]
        delete: bool,
    },

    /// Permanently delete a tracked remote resource.
    #[command(long_about = "\
Permanently delete a tracked remote resource.

`delete key --hash HASH` removes the key OpenRouter holds under that immutable \
identity, and then stops tracking it. Deletion is irreversible and is never \
planned, proposed, or performed as a side effect of anything.

The hash must be one a local address already tracks: a key Keymaster does not \
own belongs to whoever made it, and the tool that reports a stray key as \
unmanaged must not also be the tool that deletes it. There is no address \
argument, so the owner is looked up rather than asserted. The key an address is \
using is refused, as is one belonging to an unfinished operation.

The request is sent exactly once. A 2xx is not the answer on its own: the key \
is read back, and only a 404 proves it is gone. A 404 on the delete itself \
means it was already absent, which is the same end state. Anything else — a \
refusal, a timeout, or a read that still finds the key — leaves the hash \
tracked as `retirement_failed`, because the local record is the one thing that \
can still find a live credential. State is never dropped ahead of the \
confirmation.

Exit code 0 means OpenRouter is known not to have the key. Exit code 1 means \
that is not established; the result document says what happened.")]
    Delete {
        #[command(subcommand)]
        resource: DeleteResource,
    },

    /// Local state maintenance.
    #[command(long_about = "\
Local state maintenance.

`state forget ADDRESS` relinquishes local ownership of everything an address \
is bound to. It makes no API call and invokes no receiver: nothing is disabled \
and nothing is deleted, so a released resource is left however it already was — \
Keymaster made no request, and does not claim it is still there. It needs no \
management credential, no network, and no configuration, because it exists to \
correct state that is wrong — which is when those may all be unavailable.

The result lists every identity being released, so you can see what you are \
letting go of. Afterwards `openrouter-keymaster plan` reports whichever of them \
OpenRouter still has as unmanaged, and no Keymaster command will touch them \
again.

ADDRESS is `keys.NAME`, `guardrails.NAME`, `workspaces.NAME`, or \
`log_destinations.NAME`. A bare NAME is accepted when only one of the four is \
bound, and refused when more than one is. Forgetting a workspace releases the default guardrail bound to it as well: \
that guardrail cannot outlive its workspace, and nothing else can reach it.

Forgetting an address with an operation in progress is refused: the journal is \
the only record that the attempt happened, and in the create phases the only \
evidence that a live key may exist. Close it first — the refusal names the one \
command that does, which is `openrouter-keymaster recover` for the phases only an operator \
can settle and `openrouter-keymaster apply` for a delivered key whose promotion is still \
outstanding.

Forgetting an address that is bound to nothing is a clean no-op that writes no \
state, so repeating the command is safe.")]
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

    /// Bind an existing workspace by its UUID.
    #[command(long_about = "\
Bind an existing workspace by its UUID.

Like every import, this makes no remote write: it reads that one workspace and \
records a binding. It also records the workspace's `default_guardrail_id`, and \
binds the guardrail block the configuration names as `default_guardrail` to \
that identity — the default guardrail appears in no listing until its \
configuration is first written, so the identity the workspace carries is the \
only handle on it, and it can never be imported by name.")]
    Workspace {
        /// Local workspace address, as written in the configuration.
        name: String,

        /// UUID of the remote workspace.
        #[arg(long, value_name = "UUID")]
        id: String,
    },

    /// Bind an existing observability log destination by its UUID.
    #[command(long_about = "\
Bind an existing observability log destination by its UUID.

Like every import, this makes no remote write: it reads that one destination \
and records a binding.

It records no digest for the destination's `config`. OpenRouter masks a \
destination's configuration on read, so there is nothing Keymaster could \
honestly claim to have written; the next `openrouter-keymaster apply` writes \
the configured value once and records its digest from then on. Until it does, \
whatever configuration the destination already has is what is in force.")]
    LogDestination {
        /// Local log destination address, as written in the configuration.
        name: String,

        /// UUID of the remote log destination.
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

    /// Permanently delete a tracked workspace, identified by its UUID.
    #[command(long_about = "\
Permanently delete a tracked workspace, identified by its UUID.

Deleting a workspace permanently deletes its budgets and its guardrails, so \
this refuses while OpenRouter shows the workspace holding any key or guardrail \
— tracked or not, because Keymaster does not destroy what it does not manage. \
Remove them first; the refusal lists exactly what it found.

The one exception is the workspace's own default guardrail. It is part of the \
workspace, cannot outlive it, and cannot be deleted on its own, so it is not \
counted as an occupant and its binding is released along with the workspace's.

The UUID must be one a local address already tracks. The request is sent \
exactly once, and only a 404 on the read that follows proves the workspace is \
gone; anything else leaves the binding tracked.

Exit code 0 means OpenRouter is known not to have the workspace. Exit code 1 \
means that is not established, or that the workspace still holds something.")]
    Workspace {
        /// UUID of the tracked workspace to delete.
        #[arg(long, value_name = "UUID")]
        id: String,
    },

    /// Permanently delete a tracked log destination, identified by its UUID.
    #[command(long_about = "\
Permanently delete a tracked log destination, identified by its UUID.

This is the only thing that ever changes a destination's `type` or its \
workspace. OpenRouter fixes both when the destination is created and its \
`PATCH` accepts neither, and Keymaster never replaces a destination on its own \
— doing so would stop and restart log forwarding without being asked. So a plan \
that finds either field changed holds the drift back and names this command; \
run it, and the next apply creates the destination the configuration describes.

The UUID must be one a local address already tracks: a destination Keymaster \
does not own belongs to whoever made it. Unlike a workspace, a destination \
holds nothing, so there is nothing for this to refuse over.

The request is sent exactly once, and only a 404 on the read that follows \
proves the destination is gone; anything else leaves the binding tracked. \
Failures name an HTTP status and an OpenRouter error code and never a response \
body, because a destination endpoint can quote the configuration it was given.

Exit code 0 means OpenRouter is known not to have the destination. Exit code 1 \
means that is not established.")]
    LogDestination {
        /// UUID of the tracked log destination to delete.
        #[arg(long, value_name = "UUID")]
        id: String,
    },
}

/// A `state` action.
#[derive(Debug, Subcommand)]
pub enum StateAction {
    /// Relinquish local ownership of an address. Makes no remote call.
    Forget {
        /// Local address: `keys.NAME`, `guardrails.NAME`, `workspaces.NAME`,
        /// `log_destinations.NAME`, or an unambiguous bare NAME.
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
        let cli = Cli::parse_from(["openrouter-keymaster", "plan"]);
        assert_eq!(cli.config, PathBuf::from("openrouter-keymaster.toml"));
        assert_eq!(cli.state, PathBuf::from(DEFAULT_STATE_PATH));
        assert!(!cli.json);
    }

    #[test]
    fn global_options_are_accepted_after_the_subcommand() {
        let cli = Cli::parse_from([
            "openrouter-keymaster",
            "plan",
            "--json",
            "--state",
            "/tmp/s.json",
        ]);
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
