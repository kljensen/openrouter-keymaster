# Keymaster

Keymaster manages OpenRouter inference keys, guardrails, workspaces, and log
destinations declaratively. One TOML file says what should exist, `plan` shows
the difference, and `apply` converges it; `spend` reads what the organization
has cost. Keymaster never prints a key's plaintext and never records it in
configuration or state; a new key is handed at most once to the receiver that
file names.

`openrouter-keymaster` is the crate and the binary. Prose calls it Keymaster.

## Install

Built from source, on Unix only: the durability and permission guarantees are
Unix primitives, and a build elsewhere fails rather than weakening them. There
is no published crate. The toolchain is pinned in
[`rust-toolchain.toml`](rust-toolchain.toml), which `rustup` installs for you.

```sh
git clone https://github.com/kljensen/openrouter-keymaster
cd openrouter-keymaster
cargo install --path crates/cli   # or: cargo build --release
openrouter-keymaster --version
```

## Quick start

The credential is read from `OPENROUTER_MANAGEMENT_KEY` and nowhere else. Read
it from a file, so it reaches neither shell history nor a process argument list:

```sh
read -r OPENROUTER_MANAGEMENT_KEY < ~/.config/openrouter/management.key
export OPENROUTER_MANAGEMENT_KEY
mkdir -p -m 700 ~/keymaster-keys   # where the new key will be delivered
```

[`docs/threat-model.md`](docs/threat-model.md#supplying-the-credential) covers
secret managers and `systemd`. Then write `openrouter-keymaster.toml`:

```toml
version = 1

[guardrails.cheap]
name = "cheap"
allowed_models = ["google/gemini-2.5-flash"]
limit_usd = 10
reset_interval = "monthly"

[keys.jobfeed]
name = "jobfeed"
limit_usd = 5
guardrail = "cheap"
receiver = "local_key_file"

[receivers.local_key_file]
type = "file"
path = "/home/you/keymaster-keys/jobfeed.key"   # absolute; substitute yours
```

```sh
openrouter-keymaster plan     # read-only: what an apply would do
openrouter-keymaster apply    # converge, and deliver the new key to that file
openrouter-keymaster status   # what is bound, what is present, what it spent
```

[`examples/openrouter-keymaster.toml`](examples/openrouter-keymaster.toml) is a fuller
example, [`docs/configuration.md`](docs/configuration.md) the field reference,
and [`docs/operations.md`](docs/operations.md#first-run) the runbook.

## Safety and operating limits

- `plan` is read-only, and `apply` recomputes the plan under its own lock. What
  runs is never the plan you read, so plan output is not an approval artifact.
- State is the ownership record. **Back it up**: losing it means re-importing
  every resource by hash or UUID. Keep one authoritative state file per managed
  deployment and run it from one machine — the lock is a local file, so
  independent copies against the same resources are never detected.
- Removing a block from the configuration deletes, disables, and forgets
  nothing. The binding becomes an orphan, reported and otherwise left alone.
- A resource that already exists is adopted only by an explicit `import` naming
  its hash or UUID. Display names are mutable and are never identities.
- A delivered key that is missing remotely is reported, never recreated.
- `rotate` stages a successor and stops. It does not retire the predecessor;
  that is a separate command, run once every consumer has the new credential.
- Creating a key requires a receiver. The `file` receiver replaces its target
  with no backup, and anything that can read that file can spend the key.
- An ambiguous creation or delivery stops the run for an operator, so Keymaster
  is not suitable for unattended scheduled runs.
- `--workspace` guards where a run places what it creates and hides unmanaged
  resources elsewhere. It is not isolation: resources an address already owns
  are still judged wherever they live.

## Commands

`plan`, `status`, and `spend` write nothing anywhere. `apply` is the only
command that writes to OpenRouter as part of convergence; other remote writes
happen only through an explicit lifecycle command, and destructive ones require
an immutable identity rather than a name.

| Family | Commands | What it does |
| --- | --- | --- |
| Converge | `plan`, `apply` | Compare the configuration with OpenRouter, then apply the planned changes. |
| Report | `status`, `spend` | What each address owns and what it has spent; the organization's cost by key. |
| Adopt | `import key`, `import guardrail`, `import workspace`, `import log-destination` | Bind an existing remote resource to a local address by hash or UUID. |
| Replace | `rotate` | Issue a successor key and deliver it; the predecessor is untouched. |
| End | `retire`, `decommission`, `delete key`, `delete workspace`, `delete log-destination` | Disable or permanently delete one identity. |
| Repair | `recover inspect`, `recover resolve`, `recover replace`, `state forget` | Close an interrupted operation, or relinquish ownership. |

The ordinary path is `plan`, `apply`, `status`, then `rotate` and `retire` when
a credential has to be replaced. Four global options are accepted everywhere:
`--config PATH` (default `openrouter-keymaster.toml`), `--state PATH` (default
`.openrouter-keymaster/state.json`), `--workspace UUID`, and `--json`, which
puts one JSON document on stdout and one diagnostic document on stderr.

[`docs/commands.md`](docs/commands.md) is the full reference: every subcommand,
what it reads and writes, its outcomes, and its exit behavior.

## Using the library

`openrouter-keymaster-core` runs the same operations from Rust.

```toml
[dependencies]
openrouter-keymaster-core = { git = "https://github.com/kljensen/openrouter-keymaster" }
zeroize = "1"
```

```rust
use openrouter_keymaster_core::ops::{self, Context, ManagementKey, Options, Paths};
use openrouter_keymaster_core::report;
use zeroize::Zeroizing;

fn plan(secret: String) -> Result<report::PlanReport, Box<dyn std::error::Error>> {
    let context = Context {
        paths: Paths { config: "openrouter-keymaster.toml".into(), state: "state.json".into() },
        options: Options::default(),
        key: Some(ManagementKey::from_secret(Zeroizing::new(secret))?),
        workspace: None,
        deliver: None,
    };
    Ok(ops::plan(context)?.report)
}
```

The client is blocking and panics on a thread running a Tokio runtime, so an
async host moves the whole call to `tokio::task::spawn_blocking`; the state lock
refuses a concurrent writer, so a host serializes its own operations on one
state file. See [`docs/library.md`](docs/library.md).

## Documentation

| Page | What it is for |
| --- | --- |
| [docs/commands.md](docs/commands.md) | Every command: arguments, reads and writes, outcomes, exit behavior. |
| [docs/configuration.md](docs/configuration.md) | Every field of the desired-state file, with its type, default, and rules. |
| [docs/operations.md](docs/operations.md) | Runbooks: what to type, in what order, and what to check afterwards. |
| [docs/library.md](docs/library.md) | Calling `ops` from Rust: the context, the `caller` receiver, scoping a run. |
| [docs/receiver-protocol.md](docs/receiver-protocol.md) | The contract for writing a receiver a key's plaintext is delivered through. |
| [docs/threat-model.md](docs/threat-model.md) | Supplying the credential, and what the design does and does not protect. |
| [docs/compatibility.md](docs/compatibility.md) | Non-goals, which surfaces are contracts, and how state migrations work. |
| [docs/adr/](docs/adr/) | The decisions that are expensive to reverse. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Checks, the test harness, and the lint and dependency policies. |
| [CHANGELOG.md](CHANGELOG.md) | What each release changed. |

## Development

`just check` verifies the local `cargo-deny` version, then runs CI's battery:
format, check, clippy, tests, and `cargo deny`. See
[`CONTRIBUTING.md`](CONTRIBUTING.md). `just live` is the one thing it does not
run — it creates and deletes real resources with a real management credential,
so read [`docs/live-tests.md`](docs/live-tests.md) first.

## License

[The Unlicense](LICENSE): public domain, no conditions. The crates are `publish
= false`; publishing to crates.io is a separate decision.
