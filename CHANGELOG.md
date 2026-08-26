# Changelog

All notable changes to Keymaster are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Keymaster follows
[semantic versioning](https://semver.org/spec/v2.0.0.html) over the surfaces
named in [`docs/compatibility.md`](docs/compatibility.md).

## [Unreleased]

### Added

- A Rust API. `openrouter_keymaster::ops` holds one function per command —
  `plan`, `status`, `apply`, `import_key`, `import_guardrail`, `rotate`,
  `recover_inspect`, `recover_resolve`, `recover_replace`, `retire`,
  `decommission`, `delete_key`, and `forget`. Each takes an owned `Context`
  (the configuration and state paths, the client options, and an optional
  management credential) plus the command's arguments, and returns the
  command's report rather than printing it: `Outcome { report, error }` keeps
  the report on a partial failure, and `Err` is reserved for the runs with no
  report to give. A `Context` is `Send + 'static` and carries no client, so a
  host can hand one to a worker thread; each operation builds its own client
  and receivers on the thread that runs it. Nothing under `ops` reads the
  environment, prints, or exits. The command line is now the glue that builds a
  context, calls one of these, renders the report, and maps a failure beside it
  to exit code 1 — every user-visible behavior is unchanged except the two
  entries below. First step of
  [ADR-0003](docs/adr/0003-core-library-split.md).

- `plan --json` carries a new `fingerprint` field: the digest of every input
  that decides what an apply would write and where — the endpoint, a
  non-reversible digest of the management credential, the state file path, the
  whole normalized configuration, the whole state as read (its serial
  included), and the executable actions. Two plans computed from the same
  inputs share one; a change to any of them does not. It is absent while an
  operation is pending, because a plan computed beside one is not what an apply
  would do. A Rust caller can hand it back to `ops::apply`, which recomputes
  the plan under the lock, compares, and writes only on a match — so a page
  that shows a plan and an "apply" button never executes writes nobody saw. A
  new field in a JSON document is a minor change under the 0.x policy in
  [`docs/compatibility.md`](docs/compatibility.md); human output is unchanged,
  and the command line has no way to bind an apply to a fingerprint. A bound
  apply that refuses returns the fresh plan with its writes held back, under
  the new error kind `plan_changed`, having written nothing anywhere.

- `ManagementKey::from_secret` takes a credential the caller already holds, in
  a `Zeroizing<String>`, so a host that keeps its secrets somewhere other than
  the process environment has a constructor. With it, reading
  `OPENROUTER_MANAGEMENT_KEY` and `OPENROUTER_BASE_URL` moved to the binary
  (`app::env`) and `state` is handed the path it works on, so nothing under
  `client`, `ops`, or `state` reads the environment. A Rust API addition only:
  the variables, the defaults, and every message are unchanged. Second step of
  [ADR-0003](docs/adr/0003-core-library-split.md).

- The Unlicense: a `LICENSE` file and `license = "Unlicense"` in `Cargo.toml`.
  `deny.toml` no longer exempts the crate from the license policy.

- `decommission NAME --hash HASH [--delete]` ends the key an address is using,
  which `retire` and `delete key` refuse and rotation cannot express — it always
  issues a successor. The hash must be the address's current one. The key is
  disabled and the disable confirmed by a read before any state moves, so a
  disable that cannot be proved leaves the address using the key it had and
  writes nothing; `--delete` continues into the same confirmed-by-404 deletion
  `delete key` performs. Afterwards the address is bound and owns no key, and if
  the configuration still describes it the next `apply` creates a replacement at
  the next generation. New error kinds: `decommission_no_current_key`,
  `decommission_not_current`, `decommission_pending`, `decommission_unconfirmed`,
  and `decommission_delete_unconfirmed`.

### Changed

- `apply` checks the management credential before it promotes a `delivered`
  operation, so an apply with no credential now writes nothing at all. It used
  to complete that local promotion — a state write — and only then fail with
  `missing_credential`. An apply always needs the API to plan, so a run without
  a credential converged nothing either way; what changes is that it no longer
  moves state on the way to failing. Intentional, and part of
  [ADR-0003](docs/adr/0003-core-library-split.md).

### Fixed

- A 404 from either request of a disable — the `PATCH` or the read that
  confirms it — is now treated as proof the key is gone rather than as a failure
  to disable it. `retire`, `decommission`, and both `recover` paths share that
  step, and all of them used to report a key OpenRouter does not have as one to
  "disable yourself", leaving it tracked as `retirement_failed`.
- Documentation no longer claims management keys carry a distinct
  `sk-or-mgmt-` prefix. A management key is the one OpenRouter's Management API
  Keys page issues, carries the same `sk-or-v1-` shape an inference key does,
  and any `sk-or-` string is treated as a secret.
- `state forget` no longer says the resources it released are still live.
  It sends no request, so the warning and the summary now say each may still
  exist remotely and that nothing was disabled or deleted.
- `rotate` and a planned replacement no longer describe the predecessor as
  "still enabled". Rotation does not read it, so the summary says it is
  unchanged — neither disabled nor deleted — and `apply` reports the `disabled`
  value its own read observed, or says nothing about it.
- `plan` and `apply` report `converged` when there is nothing to write and
  nothing an operator has to clear. An `unmanaged` remote resource, an
  `orphaned_binding` with no operation pending, and a `no_op` no longer make a
  run `held_back`, which is now reserved for a write that cannot run and for a
  blocker only an operator can resolve.
- A guardrail with `limit_usd` and no `reset_interval` is now rejected by
  offline validation, naming `guardrails.NAME.reset_interval`, instead of
  failing at apply time with an HTTP 400 from OpenRouter. Keys are unchanged: a
  key limit with no `limit_reset` is a cap that never refills.

## [0.1.0] - 2026-08-24

First release. Keymaster manages OpenRouter inference keys, guardrails, and the
assignments between them from a checked-in description of what should exist.

### Commands

- `plan` and `status`: read-only. Validate the configuration, load state without
  taking the writer lock, read a complete snapshot of OpenRouter, and report —
  no API write, no receiver invocation, no change to the state file.
- `apply`: the only command that writes to OpenRouter. Takes the exclusive lock,
  recomputes the plan under it, executes guardrail writes, key updates, and
  assignment changes in fixed phases, and verifies the result with a second
  read.
- `import key --hash` and `import guardrail --id`: bind an existing remote
  object to a local address by its immutable identity. No name lookup, no remote
  write.
- `rotate`: stage a replacement key. The predecessor is left unchanged and
  tracked.
- `recover inspect | resolve | replace`: close an interrupted create or delivery.
- `retire --hash`, `delete key --hash`, `state forget ADDRESS`: the three
  explicit endings. Nothing else performs them.

### Behavior

- **Declarative reconciliation against stored remote identity.** A key hash and
  a guardrail UUID are identity; a display name never is
  ([ADR-0001](docs/adr/0001-native-reconciliation.md)).
- **Journaled key creation.** `POST /keys` is sent exactly once, after a durable
  intent record, and is never retried. An ambiguous outcome stops the run and
  requires an explicit operator resolution
  ([ADR-0002](docs/adr/0002-journaled-key-creation.md)).
- **Delivery at most once**, only after the new key's budget and guardrail are
  verified, and never with a plaintext fallback to stdout.
- **Config removal destroys nothing.** A removed block becomes a tracked
  orphaned binding.
- **Privilege expansions are conspicuous** in both human and JSON output, and
  are reported from the post-write verification rather than from the response.

### Configuration and state

- Versioned TOML desired state with one-pass validation, explicit clearing, and
  a hard error for any unknown field or credential-shaped value. See
  [`docs/configuration.md`](docs/configuration.md).
- Versioned, locked, atomically written local state holding identities and
  lifecycle phases only. Never a credential. `0700` directory, `0600` file, one
  writer.

### Receivers

- `file`: an atomic `0600` write, for local development.
- `command`: a program run with no shell, an exact argument vector, and an empty
  environment, handed one versioned JSON envelope on stdin. See
  [`docs/receiver-protocol.md`](docs/receiver-protocol.md).

### Client

- One blocking `rustls` client with bounded timeouts and response bodies, no
  proxy, and no redirects. Retries are bounded for safe reads and absent for
  writes.
- Typed, redacted errors that expose no `reqwest` type and distinguish a
  definite rejection from an ambiguous failure.
- Defensive pagination: stop on an empty page, advance by records returned,
  deduplicate by identity, and refuse a page that makes no identity progress.

### Testing and documentation

- A local HTTP harness, a fake clock, fake receivers, and a secret sentinel with
  scanners that assert its absence from output, diagnostics, state, and every
  written file.
- Fault injection at every durable state phase, so the crash cases interrupt the
  production write path rather than a copy of it.
- An opt-in live acceptance suite against a real organization, gated by
  `#[ignore]` and `KEYMASTER_LIVE_TESTS=1`, never run by `just check` or CI. It
  has not yet been run against a live organization; see
  [`docs/release-checklist.md`](docs/release-checklist.md).
- Operator documentation: runbooks, a configuration reference, a threat model,
  compatibility expectations, and the release checklist, indexed in
  [`docs/`](docs/README.md).

### Known limitations

- Unix only. The durability and permission guarantees are built on Unix
  primitives, and v0.1 fails to build elsewhere rather than weakening them.
- Single writer, single machine. The state lock is a local file and does not
  coordinate two machines.
- Cannot run unattended. Any ambiguous create or delivery stops the run until a
  person resolves it.
- A delivery whose acknowledgement is lost costs a replacement, because v0.1
  defines no receiver query contract.
- A predecessor cannot be re-adopted as a retained hash. Retained entries are
  created only by a rotation's promotion, so a state file restored from a backup
  taken before a rotation cannot bring the old key back under management for
  `retire` or `delete key`; clean it up in the OpenRouter dashboard.
- No license is chosen and the crate is `publish = false`.

[Unreleased]: https://github.com/kljensen/openrouter-keymaster/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kljensen/openrouter-keymaster/releases/tag/v0.1.0
