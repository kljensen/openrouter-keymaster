# Documentation

The [top-level README](../README.md) is the entry point: what each command does
and why it behaves that way. These pages are the reference and procedure
material it links to.

| Page | What it is for |
| --- | --- |
| [configuration.md](configuration.md) | Every field of the desired-state TOML file, with its type, defaults, and validation rules. |
| [operations.md](operations.md) | Runbooks. First run, adoption, changes, key creation, rotation, retirement, decommissioning, forgetting, recovery, and looking after state. |
| [threat-model.md](threat-model.md) | How to supply the management credential, what Keymaster protects against, and what it does not. |
| [receiver-protocol.md](receiver-protocol.md) | The contract for writing a command receiver — the envelope, the empty environment, the exit codes — and the `caller` receiver a library host delivers through. |
| [compatibility.md](compatibility.md) | v0.1 non-goals, which surfaces are contracts, and how state schema migrations will work. |
| [live-tests.md](live-tests.md) | The opt-in acceptance suite that runs against a real organization. |
| [release-checklist.md](release-checklist.md) | The v0.1 release gate, with the command that verifies each item. |
| [adr/](adr/) | Architecture decision records, and the convention for writing them. |

Start with the README, then [operations.md](operations.md) if you are about to
run something and [configuration.md](configuration.md) if you are about to write
something.
