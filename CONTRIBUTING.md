# Contributing

Keymaster handles management credentials and one-time secret material, which is
why the checks and policies below exist. CI enforces the mechanical ones —
formatting, lints, tests, and `cargo deny`. The review policies further down
("prefer the standard library", "justify every new direct dependency") are
followed by contributors and checked in review; no tool can decide them.

## Checks

`just check` first fails unless the local `cargo-deny` matches the version the
`justfile` pins, then runs CI's battery:

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo check --locked --package openrouter-keymaster-core --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo deny check advisories licenses bans sources
```

The second `cargo check` builds the core crate alone, without the CLI's
dev-dependency turning on `test-support`, so the shape a library host compiles
against is checked on every run.

`just fmt`, `just lint`, and `just test` run those steps individually.
[`just`](https://github.com/casey/just) and
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) must be installed
locally, and the pinned `cargo-deny` version is the one CI installs; the version
check prints the exact `cargo install` line when they differ.

The Rust toolchain is pinned in `rust-toolchain.toml` and must match
`workspace.package.rust-version` in the root `Cargo.toml`.
`crates/cli/tests/toolchain_pin.rs` fails if the two ever drift apart.

`just live` is the one thing `just check` does not run and CI never will. It is
an opt-in acceptance suite against a **real** OpenRouter organization, gated by
`#[ignore]` and by `KEYMASTER_LIVE_TESTS=1`, and it creates and deletes real
resources with a real management credential. Read
[`docs/live-tests.md`](docs/live-tests.md) before running it.

## The test harness

The shared harness is `crates/core/src/test_support/`, compiled into the core
library only under its `test-support` feature — which core's own tests require
and the CLI crate's dev-dependency turns on, so there is one copy rather than
one per crate. It uses no external network and no real credential. Core's tests
reach it as `use openrouter_keymaster_core::test_support as support;`; the CLI
crate's tests pick it up with `mod support;`, through
`crates/cli/tests/support/mod.rs`, which re-exports it beside the one part that
cannot be shared.

- `http` — a local `wiremock` server with a synchronous interface, so tests of
  the blocking client never write `async`. It matches routes and methods,
  captures headers and bodies, counts requests, scripts ordered responses, holds
  mutable remote state for drift tests, and produces the failure modes the
  client has to survive: delay, lost connection, malformed JSON, an oversized
  body, 4xx, 429 with `Retry-After`, and 5xx. Failures print the requests that
  arrived, with credential headers redacted.
- `fixtures` — small hand-written JSON bodies with obviously fake secrets.
- `clock` — a clock that moves only when a test moves it.
- `receiver` — a fake secret receiver covering the four delivery outcomes:
  delivered, definitely rejected, timed out, and acknowledgement lost.
- `sentinel` — a unique secret sentinel with scanners that assert its absence
  from strings, files, and directory trees, and its presence where disclosure is
  the expected behavior.

`project` is the part that cannot be shared, because `Command::cargo_bin` only
finds a binary of the package under test. It lives in
`crates/cli/tests/support/project.rs` and gives a test a temporary project
directory, a server answering the listings a snapshot reads — unscoped and per
workspace — and the compiled binary pointed at both with a sentinel credential.
Every run it starts is scanned for the sentinel in stdout, stderr, and every
file under the project directory.

Each integration test file states what it covers in its own `//!` header; read
that before adding to one. `crates/core/tests/harness.rs` has one demonstration
test per capability, including one that proves the server received the expected
bearer credential while sentinel scanning proves it reached neither diagnostics
nor any written artifact.

Extending it: a new remote behavior belongs in `test_support::http` so both
crates get it; a new end-to-end shape belongs in a `crates/cli/tests/*.rs` file
driving `project`. A test that issues or delivers a key scans for the sentinel
on the failure path as well as the success path — a secret that escapes only
when something goes wrong is the case worth catching. There is deliberately no
way to construct a `KeyPlaintext` outside a parsed create response, so a
delivery test serves one through the local HTTP harness.

## Lint policy

`[workspace.lints]` in the root `Cargo.toml`, which both crates inherit, forbids
`unsafe_code` and denies `dbg!`, `todo!`, `unimplemented!`, and `unwrap()`.
Complexity tripwires live in `clippy.toml`: cognitive complexity 20, function
length 80, argument count 7, type complexity 200. Tests may add narrowly scoped
`#[allow(...)]` with a reason; production code may not disable the policy
wholesale.

`clippy.toml` also lists disallowed methods, currently the two `reqwest` client
constructors that would produce an HTTP client with no timeout, redirect policy,
or credential. `crates/core/tests/lints.rs` fails if that ban is removed.

## Dependency policy

The dependency graph stays small and auditable.

- Prefer the standard library, then a well-maintained crate with few transitive
  dependencies. Justify every new direct dependency in its PR.
- `Cargo.lock` is committed and every CI command runs with `--locked`, so an
  unreviewed dependency change fails the build.
- `cargo deny` enforces the policy in `deny.toml`: RustSec advisories, an
  allow-list of permissive licenses, no wildcard version requirements, and
  crates.io as the only source.
- Advisory or license failures are fixed by upgrading or removing the
  dependency; an exception must be a narrow, dated, explained entry in
  `deny.toml`.

## Decisions

A change that is expensive to reverse gets an ADR under
[`docs/adr/`](docs/adr/), following [the convention there](docs/adr/README.md).
A change to a compatibility surface — the command tree, the exit codes, the JSON
field names, the configuration schema, or the core crate's public API — gets a
`CHANGELOG.md` entry and follows the rules in
[`docs/compatibility.md`](docs/compatibility.md#compatibility-surfaces).
