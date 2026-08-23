# Keymaster

A declarative OpenRouter management CLI, written in Rust.

Keymaster is an early work in progress. Today it is a hello-world baseline; the
OpenRouter API client, desired-state configuration, planning, and apply
behavior are not implemented yet.

## Build, run, and test

```sh
cargo build
cargo run
cargo test
```

`cargo run` prints the placeholder Keymaster greeting and exits successfully.

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
