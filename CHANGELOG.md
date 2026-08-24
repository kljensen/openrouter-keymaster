# Changelog

All notable changes to Keymaster are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Keymaster follows
[semantic versioning](https://semver.org/spec/v2.0.0.html) over the surfaces
named in [`docs/compatibility.md`](docs/compatibility.md).

## [Unreleased]

### Fixed

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
- `rotate`: stage a replacement key. The predecessor stays enabled and tracked.
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
