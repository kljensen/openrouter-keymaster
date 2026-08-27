# Changelog

All notable changes to Keymaster are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Keymaster follows
[semantic versioning](https://semver.org/spec/v2.0.0.html) over the surfaces
named in [`docs/compatibility.md`](docs/compatibility.md).

## [Unreleased]

### Added

- Observability log destinations as a managed resource. A
  `[log_destinations.NAME]` block carries `type` (one of the seventeen types
  OpenRouter documents), `name`, `config`, `enabled`, `privacy_mode`,
  `sampling_rate`, and a workspace by local address or raw `workspace_id`.
  Identity is the destination UUID: `openrouter-keymaster import log-destination
  NAME --id UUID` binds an existing one, removing the block orphans the binding,
  and `openrouter-keymaster delete log-destination --id UUID` is the only
  deletion. The planner orders destinations after workspaces and holds one back
  until its workspace is bound, and `delete workspace` now also refuses while
  OpenRouter shows the workspace holding a log destination. `state forget` takes
  `log_destinations.NAME`. `status` lists destinations, and `plan` reports a
  destination no local address owns as `unmanaged`.

  `config` may hold a third-party credential — the sink's own API key — which
  makes a configuration file carrying one a secret, and the documentation says
  so. It is write-only: OpenRouter masks it on read, so state records a SHA-256
  digest of the canonical JSON of what was written and the planner compares
  digests. A changed digest is an `update` whose diff says `config` and nothing
  else; an imported destination has no digest, so its first apply writes `config`
  once; and apply does not read it back, verifying every other field as usual.
  The value is a `DestinationConfig`, which deserializes through its own visitors
  so no rejected value reaches a deserializer message, prints `[redacted]`, has
  no public `Serialize`, and clears its strings on drop; `Config::load` reads the
  file into a buffer it clears and registers every `config` string of sixteen
  characters or more with the redactor for the rest of the run, which scrubs them
  by exact match from every error, warning, and report. A destination write's
  failure carries an HTTP status and OpenRouter's error code and never a response
  body.

  `type` and the workspace are fixed at creation — `PATCH` accepts neither — so a
  change to either is held-back drift carrying the new reason
  `destination_fixed_at_creation`, which names the field and the explicit delete
  that clears it. The `api_key_hashes` allowlist is managed as always empty, so a
  destination forwards every key in its workspace and a non-empty allowlist is
  drift an apply clears by sending `null`; `filter_rules` and the `broadcast_*`
  flags are not modelled, so they are never sent and never diffed. New error
  kinds: `delete_log_destination_untracked` and
  `delete_log_destination_unconfirmed`.
  [ADR-0006](docs/adr/0006-log-destinations.md).

- Workspaces as a managed resource. A `[workspaces.NAME]` block carries `name`,
  `slug`, `description`, a `budgets` table (any of `daily`, `weekly`, `monthly`,
  `lifetime`, in USD), `include_byok_in_budgets`, and `default_guardrail`.
  Identity is the workspace UUID: `openrouter-keymaster import workspace NAME
  --id UUID` binds an existing one, removing the block orphans the binding, and
  `openrouter-keymaster delete workspace --id UUID` is the only deletion — which
  refuses while OpenRouter shows the workspace holding any key or guardrail,
  tracked or not, since deleting a workspace deletes what is in it. Keys and
  guardrails name their workspace with `workspace = "<address>"`, resolved
  through the binding at plan time; the raw `workspace_id` form stays for a
  workspace Keymaster does not manage, and writing both on one block is a
  validation error. The planner orders workspaces before guardrails before keys
  and holds back anything whose workspace is not bound yet. Budgets are written
  one interval at a time, ordered deletes first, then increases from the widest
  interval to the narrowest, then decreases from the narrowest to the widest, so
  no intermediate state violates OpenRouter's lifetime > monthly > weekly >
  daily rule — which is also checked offline. A budget a plan refuses is a
  definite failure naming the interval, and while a configured budget has not
  converged every `issuing` or `expanding` write in that workspace is held back
  with the new reason `budget_not_converged`; routine writes proceed, and the
  workspace's own budget writes are exempt. A workspace's default guardrail is a
  guardrail block bound to its `default_guardrail_id`: the one exception to
  "bound but absent means missing", reported as a `create` carrying the reason
  `default_guardrail_unmaterialized` and performed as the first `PATCH` to that
  identity, never `POST`ed, never imported by name, and released with the
  workspace it belongs to; an address that already owns a different guardrail is
  held back with `default_guardrail_conflict`, naming both identities, and one
  whose identity another address owns with `default_guardrail_owned_elsewhere`.
  A guardrail's workspace is fixed when it is created and a guardrail is never
  replaced, so one OpenRouter has in another workspace is held back with
  `workspace_fixed_at_creation` rather than patched, and `import guardrail`
  refuses it with the new error kind `import_workspace_mismatch`; both read one
  resolution — the workspace the block names, then the workspace whose default
  guardrail it is, then the run's scope. A workspace binding that never learned
  its `default_guardrail_id` — a create response that omitted it — takes the
  identity from the workspace listing on the next apply, before the plan is
  computed, so the guardrail it is the only handle on is not held back for
  good. `state forget`
  now takes `workspaces.NAME`, releasing the workspace binding and the default
  guardrail that cannot outlive it, and a bare name bound as more than one of
  the three kinds is refused. A
  workspace that is bound and absent is reported as `missing` and never
  recreated, because a new one would have a new UUID and everything the old one
  held would be beyond reach. `status` lists workspaces with the budgets OpenRouter
  has in force. New error kinds: `delete_workspace_untracked`,
  `delete_workspace_inhabited`, and `delete_workspace_unconfirmed`.
  [ADR-0004](docs/adr/0004-workspaces.md).

- A `caller` receiver, for a program that embeds the core crate. A
  `[receivers.NAME] type = "caller"` block names one field, `destination` — a
  stable non-secret label for where the plaintext ends up — and the host
  supplies the code as `Context.deliver`, a callback handed the delivery
  metadata (address, hash, generation, operation ID, and that destination) and
  the plaintext. One operation may issue several keys, so the callback is
  called once per delivered key and routes on the metadata rather than on call
  order; what it returns is the delivery's classification, and a panic inside
  it is caught and recorded as ambiguous. `DeliveryMetadata`, `Acknowledgement`,
  the delivery outcome (as `ops::DeliveryOutcome`), and `KeyPlaintext` with its
  single `expose()` accessor are now public; the plaintext keeps its guarantees
  and Keymaster's end at the callback. Every operation that issues a key —
  `apply`, `rotate`, `recover replace` — refuses when a `caller`-backed key has
  no callback, before the journal entry and before `POST /keys`; `apply` scans
  the whole plan before its first phase and fails with the new error kind
  `apply_undeliverable` having made no remote write, so a guardrail it would
  have created earlier in the same run is not created either. The one local
  write that can precede that refusal is the promotion of an already-delivered
  key, which the report carries and the error names. `plan` and `status` never
  need a callback. The `openrouter-keymaster`
  command line supplies no callback, so a `caller` receiver is always that
  preflight failure under the CLI.
  [ADR-0005](docs/adr/0005-caller-receiver.md).

- A workspace scope. `Context.workspace` — set from the new `--workspace UUID`
  global option — names the one OpenRouter workspace a run places resources in
  and reports on. With a scope, a configuration that names a different workspace
  is refused before any request, every key and guardrail the run
  creates is placed in the scope, `plan` and `status` leave out `unmanaged`
  resources from other workspaces, and matching by name — adoption candidates,
  and the collision check before a guarded recreation — considers only
  resources in the scope, so another club's identically named key cannot block
  this one. The snapshot is still the whole organization, so a bound resource
  is judged present or missing exactly as before; the scope is a guard on
  placement and a filter on noise, not an isolation mechanism. Without it,
  behavior is unchanged. The plan fingerprint now covers the scope, so a
  fingerprint taken by an earlier build no longer matches. First step of
  [ADR-0004](docs/adr/0004-workspaces.md).

- A Rust API. `openrouter_keymaster_core::ops` holds one function per command —
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

- `Context` gained a `deliver` field, so a struct literal that built one now
  needs it; `None` is the previous behavior. `config::Receiver::fingerprint`
  now takes the receiver's own local address, which only a `caller` receiver's
  digest absorbs — a `file` or `command` fingerprint is unchanged, so no state
  file is invalidated.

- The repository is a Cargo workspace of two crates.
  `openrouter-keymaster-core` (`crates/core`) holds the client, the API reads
  and writes, configuration, state, the planner, the receivers, the reports,
  the identifiers, and `ops`; `openrouter-keymaster` (`crates/cli`) holds
  argument parsing, dispatch, rendering, and the two binaries. Core does not
  depend on `clap`. The shared test harness moved into core as `test_support`,
  behind a `test-support` feature the CLI crate's dev-dependency turns on, so
  there is still one copy of it. Nothing a user sees changed: the binary, its
  name, its help, its output, and its exit codes are the same; `cargo build`
  and `cargo run -- …` at the root are still the CLI's; and
  `cargo install --path crates/cli` produces the same program. Third step of
  [ADR-0003](docs/adr/0003-core-library-split.md).

- The core crate's public surface is curated, and it is a compatibility
  contract. `pub` is now what `ops` exposes — `Context`, `Paths`, `Options`,
  `ManagementKey`, `Outcome`, the reports, `PlanFingerprint`, the identifiers,
  and the errors — plus what a host needs to *read* configuration and state:
  `Config` and everything reachable from it, and `StateFile::read` with `State`
  and everything reachable from it. State mutation — the lock, the transitions,
  and the write path — is `pub(crate)`, so a key's lifecycle moves only through
  an operation that journals it. The HTTP client, the OpenRouter resource
  layer, the planner, the receivers, and redaction are `pub(crate)` too; the
  handful of items a host still needs from them (`ApiError`,
  `MANAGEMENT_KEY_VAR`, `PRODUCTION_BASE_URL`, `REJECTED_EXIT_CODE`, and the
  new `Options::check_base_url`) are re-exported where they are used.
  [`docs/compatibility.md`](docs/compatibility.md) now names the Rust API as a
  0.x contract beside the CLI, the JSON documents, and the configuration file,
  and says what an additive change is and what breaks. Every public error enum
  is `#[non_exhaustive]`, so a new error variant stays additive; every other
  public enum is exhaustive on purpose, so a host is told at compile time when
  there is a new case to handle. `tests/public_api.rs`
  compiles against that surface and nothing else. Last step of
  [ADR-0003](docs/adr/0003-core-library-split.md), which is now Accepted.

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
