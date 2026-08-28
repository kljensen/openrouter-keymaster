# Documentation

The [top-level README](../README.md) is the entry point. These pages are the
reference and procedure material it links to.

| Page | What it is for |
| --- | --- |
| [commands.md](commands.md) | Every command and subcommand: arguments, what it reads and writes, its outcomes, and its exit behavior. |
| [configuration.md](configuration.md) | Every field of the desired-state TOML file, with its type, defaults, and validation rules. |
| [operations.md](operations.md) | Runbooks. First run, adoption, changes, workspaces, log destinations, scoped runs, key creation, rotation, retirement, decommissioning, forgetting, recovery, spend, and looking after state. |
| [library.md](library.md) | Calling `ops` from a Rust host: the context, the `caller` receiver, scoping a run, and one context per tenant. |
| [threat-model.md](threat-model.md) | How to supply the management credential, what Keymaster protects against, and what it does not. |
| [receiver-protocol.md](receiver-protocol.md) | The contract for writing a command receiver — the envelope, the empty environment, the exit codes — and the `caller` receiver a library host delivers through. |
| [compatibility.md](compatibility.md) | Non-goals, which surfaces are contracts, and how state schema migrations will work. |
| [live-tests.md](live-tests.md) | The opt-in acceptance suite that runs against a real organization. |
| [release-checklist.md](release-checklist.md) | The release gate, with the command that verifies each item. |
| [adr/](adr/) | Architecture decision records, and the convention for writing them. |

[`CONTRIBUTING.md`](../CONTRIBUTING.md) covers the checks, the test harness, and
the lint and dependency policies.

Start with the README, then [commands.md](commands.md) for what a command does,
[operations.md](operations.md) if you are about to run something, and
[configuration.md](configuration.md) if you are about to write something.
