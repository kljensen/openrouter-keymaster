# Keymaster

A declarative OpenRouter management CLI, written in Rust.

Keymaster is an early work in progress. The command-line surface below is
final for v0.1, but no command does its work yet: the OpenRouter API client,
desired-state configuration, planning, and apply behavior are not implemented,
so every command fails with a "not implemented yet" error and exits 1.

## Build, run, and test

```sh
cargo build
cargo run -- --help
cargo test
```

## Commands

```text
keymaster plan                          show the changes an apply would make
keymaster apply                         converge OpenRouter with the configuration
keymaster status                        report bindings and incomplete operations
keymaster import key NAME --hash HASH   bind an existing key by its hash
keymaster import guardrail NAME --id ID bind an existing guardrail by its UUID
keymaster rotate NAME                   stage a replacement key
keymaster recover inspect NAME          report an interrupted key operation
keymaster recover resolve NAME ...      attest what an ambiguous operation did
keymaster recover replace NAME          replace a key after resolving ambiguity
keymaster retire NAME --hash HASH       disable a tracked retained key
keymaster delete key --hash HASH        permanently delete a tracked key
keymaster state forget ADDRESS          relinquish local ownership of an address
```

Global options: `--config PATH` (default `keymaster.toml`), `--state PATH`
(default `.openrouter-keymaster/state.json`), and `--json`.

`recover resolve` requires exactly one attested finding, either
`--no-resource-created` or `--leaked-hash HASH`. Keymaster never guesses which
one is true.

## Credentials

The management credential is read from the `OPENROUTER_MANAGEMENT_KEY`
environment variable only. There is deliberately no command-line option for
it, so it cannot appear in a process argument list, and no command echoes it.

## Output and exit codes

Stdout carries requested results only — human-readable text, or exactly one
JSON document when `--json` is given. Stderr carries diagnostics, also as one
JSON document under `--json`. Neither is ever colored, so `--json` output is
machine-readable on a terminal. Only `src/output.rs` writes to either stream;
the other modules return values.

| Exit code | Meaning |
| --------- | ------- |
| 0 | Success, including `--help` and `--version` |
| 1 | Application error |
| 2 | Usage error |

## Checks

`just check` runs exactly what CI runs:

```sh
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo deny check advisories licenses bans sources
```

`just fmt`, `just lint`, and `just test` run those steps individually.
[`just`](https://github.com/casey/just) and
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) must be installed
locally at the version pinned in the `justfile` (the same version CI installs);
`just check` fails with installation instructions if the versions differ.

The Rust toolchain is pinned in `rust-toolchain.toml` and must match
`package.rust-version` in `Cargo.toml`; `tests/toolchain_pin.rs` fails if they
drift apart.

## Lint policy

`Cargo.toml` `[lints]` forbids `unsafe_code` and denies `dbg!`, `todo!`,
`unimplemented!`, and `unwrap()`. Complexity tripwires live in `clippy.toml`:
cognitive complexity 20, function length 80, argument count 7, type complexity
200. Tests may add narrowly scoped `#[allow(...)]` with a reason; production
code may not disable the policy wholesale.

## Dependency policy

Keymaster handles management credentials and one-time secret material, so the
dependency graph stays small and auditable.

- Prefer the standard library, then a well-maintained crate with few
  transitive dependencies. Justify every new direct dependency in its PR.
- `Cargo.lock` is committed and every CI command runs with `--locked`, so an
  unreviewed dependency change fails the build.
- `cargo deny` enforces the policy in `deny.toml`: RustSec advisories, an
  allow-list of permissive licenses, no wildcard version requirements, and
  crates.io as the only source.
- Advisory or license failures are fixed by upgrading or removing the
  dependency; an exception must be a narrow, dated, explained entry in
  `deny.toml`.
