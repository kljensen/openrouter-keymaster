# ADR-0003: Core library and CLI split

- **Date:** 2026-08-25
- **Status:** Proposed

## Context

A Rust web application will drive the same operations Keymaster's CLI does —
plan, apply, import, rotate, recover, retire, delete, decommission — from HTTP
handlers instead of a terminal. Today the crate cannot be consumed that way:

- Every operation is a function of `&Cli` (the clap argument struct) and a
  `Renderer`, reads its config and state paths from the CLI struct, and prints
  its result. There is no way to call "apply" and get a value back.
- `clap` is an unconditional dependency, because `cli` and `app` are modules of
  the one library crate.
- The credential is read only from `OPENROUTER_MANAGEMENT_KEY` and the endpoint
  only from `OPENROUTER_BASE_URL`; a host that keeps secrets elsewhere has no
  constructor to hand them in.
- About two hundred items are `pub` with no curation; nothing distinguishes the
  Rust surface a consumer may rely on from what happens to be visible.
- The HTTP client is `reqwest::blocking`. Calling it from a thread that is
  running a Tokio runtime panics; a web host has to know that.
- State is one local file with an exclusive per-process lock (ADR-0001). A
  long-lived process that serves many requests must serialize them itself.

The layering underneath is already clean: `client`, `api`, `config`, `state`,
`plan`, `receiver`, `ids`, and `redaction` do not reference the CLI, except
for one constant (`cli::DEFAULT_STATE_PATH`) used by `state`. The report DTOs
are `Serialize`, so a JSON API can return them as they are.

## Decision

The repository becomes a Cargo workspace of two crates, and the operations
become a library API.

1. **`openrouter-keymaster-core`** (library) holds everything except argument
   parsing and terminal rendering: `client`, `api`, `config`, `state`, `plan`,
   `receiver`, `ids`, `redaction`, `files`, the `report` DTOs with their
   `Display` impls, a new `ops` module, and a core error type. It does not
   depend on `clap`.
2. **`openrouter-keymaster`** (binary) holds `cli`, `output`, `main`, exit-code
   mapping, and the `Usage`/`Output` error variants. It reads the environment,
   builds core inputs, calls `ops`, and renders the returned report. Its name
   and every user-visible behavior are unchanged. The test-receiver helper
   binary stays here too, with the integration tests that spawn it: Cargo
   defines `CARGO_BIN_EXE_*` only for the package under test, so a helper in
   core would be invisible to the binary crate's tests. Core keeps the
   receiver unit tests that need no child process.
3. **The test harness lives in core behind a `test-support` feature.** The
   local HTTP server, fake clock, secret sentinel, and fake receiver become a
   `test_support` module of core, compiled only with that feature, which the
   binary crate's dev-dependency turns on. One copy, no third crate, and the
   fake receiver keeps its access to the crate-private receiver types. The
   `Project` harness that spawns the binary stays in the binary crate's
   tests.
4. **`ops` is the API.** One function per command. Each takes an owned
   `Context` and the command's arguments, and returns the command's report:

   ```text
   ops::plan(Context)                                  -> Result<Outcome<PlanReport>>
   ops::apply(Context, Option<PlanFingerprint>)        -> Result<Outcome<ApplyReport>>
   ops::import_key(Context, Address, KeyHash)          -> Result<Outcome<ImportReport>>
   ...

   struct Context { paths: Paths, options: Options, key: Option<ManagementKey> }   // Send + 'static
   struct Outcome<R> { report: R, error: Option<Error> }
   ```

   `Paths` names the config and state files. `Context` is `Send + 'static`
   and carries no client: each `ops` function builds its `Client` and its
   receivers on the thread that runs it, from the context and the
   configuration. That is what lets a host hand a context to a worker thread.
   The credential is optional because some commands never need one —
   `state forget` makes no request, and `recover inspect` is offline once the
   journal records a hash — and they keep working without it. An operation
   checks for the credential at the point it would first build a client,
   which is after configuration and state are read and before any API call
   or write; with none present it fails with `missing_credential` there.
   One intentional change from the CLI's current order: `apply` today
   promotes a `delivered` operation before it reads the credential, so an
   apply with no credential could still write state. Under this decision the
   credential check comes first, because `apply` always needs the API to
   plan, and an apply without one writes nothing.

   `Outcome` keeps what the CLI already does today: an operation that wrote
   something and then could not verify it, or that failed partway, still
   returns its full report, with the failure beside it. `Err` is reserved for
   the cases where there is no report to give — an invalid configuration, a
   held lock, a missing credential. The CLI maps `error: Some(_)` to exit 1
   exactly as it does now.

   An `ops` function never reads the environment, never prints, and never
   exits. Warnings are fields of the report, as they already are under
   `--json`. Receivers are resolved from configuration by core's
   `receiver::from_config`, as today; host-defined receiver kinds are not
   part of this decision (see below).

   **A shown plan can be made binding.** `PlanReport` gains a `fingerprint`: a
   digest of every input that decides what an apply would write and where —
   the endpoint (`Options.base_url`), a non-reversible digest of the
   management credential (so the same plan against a different account is a
   different plan), the state file path, the normalized configuration, the
   state as read (its serial advances on every write, so any state change is
   a different plan), and the executable actions with their kinds, addresses,
   identities, field changes, and rationale. Binding the whole configuration
   and the whole state, rather than a list of fields, is deliberate: every
   value apply resolves while issuing a key — the bound guardrail's UUID, the
   effective generation, the receiver destination — comes from one of them,
   so nothing has to be enumerated and nothing can be forgotten. Two plans
   computed from the same inputs have the same fingerprint; a change to any
   of them between plan and apply does not.

   A plan is bindable only when no operation is pending. While one stands —
   in any phase, including `delivered`, which a plain apply promotes before
   planning — `fingerprint` is `None`, and an apply given an expected
   fingerprint refuses before its first state write and returns the fresh
   plan. The host settles the operation with a plain apply or `recover`, then
   plans again. This keeps every check ahead of every write: with a
   fingerprint, apply takes its lock, recomputes the plan, compares, and only
   then writes; there is no promotion or other state change before the
   comparison. Without a fingerprint apply behaves as the CLI does now, apart
   from the credential-order change above. This is how a web page that shows a plan and
   an "apply" button never executes writes the user did not see.

   **Operations run to completion.** An `ops` call blocks until the operation
   is done; there is no cancellation and no progress stream. A host that
   needs a responsive request runs the call as a background job with its own
   handle and shows the report when it returns. If the process dies mid-way,
   the journal of ADR-0002 makes the next run recover, which is the same
   guarantee the CLI has. If a host needs progress events later, they arrive
   as separate observer-taking functions beside the existing ones, so the
   signatures decided here do not change.
5. **Credentials come from the caller.** Core gains
   `ManagementKey::from_secret(Zeroizing<String>)`; reading
   `OPENROUTER_MANAGEMENT_KEY` and `OPENROUTER_BASE_URL` moves to the binary
   crate. The type keeps its guarantees: no `Serialize`, no accessor, redacted
   `Debug`, zeroized on drop.
6. **Core requires Unix**, as the whole crate does today. State persistence,
   the file receiver, and the command receiver are built on Unix primitives,
   and `ops` needs all three, so the crate-wide `compile_error!` moves to core
   unchanged. Portability of the client alone is not a goal of this decision.
7. **The public surface is curated.** `pub` in core is what the `ops`
   signatures expose — `Context`, `Paths`, `Options`, `ManagementKey`,
   `Outcome`, the reports and `PlanFingerprint`, the identifier types, and the
   errors — plus what a host needs to *read* configuration and state:
   `Config` and every type reachable from it (`Key`, `Guardrail`, `Receiver`,
   `Managed`, …), and `StateFile::read` with `State` and every type reachable
   from it (`KeyBinding`, `PendingOperation`, `Phase`, the retained-key
   types, …). State *mutation* — the lock, the transitions, the write path —
   is reachable only through `ops`, so a host cannot move a key's lifecycle
   except by the operations that journal it. Everything else becomes `pub(crate)`. The core crate is versioned
   0.x under semver and `docs/compatibility.md` lists its API as a contract
   alongside the CLI output and the state format.
8. **Concurrency is the host's job, and the rules are written down.** `ops`
   functions are synchronous and blocking, and so is everything they build:
   `reqwest::blocking` panics when constructed or used on a thread that is
   running a Tokio runtime. An async host therefore moves the whole call —
   context in, outcome out — to a blocking thread with `spawn_blocking` or an
   equivalent; the `Send + 'static` context is what makes that possible.
   Within one process, callers serialize `ops` calls on one state file
   themselves — the file lock refuses a concurrent writer, it does not queue
   one. Nothing about the single-writer model changes.

Not decided here: an async client, a remote or shared state backend,
host-defined receiver kinds (which need an extensible receiver specification
and a fingerprint contract for it, not just a resolver), a progress observer,
and publishing to crates.io. Each is a later decision with its own ADR if it
comes.

## Consequences

- The web application depends on `openrouter-keymaster-core` alone, gets no
  `clap`, and calls the same code path the CLI does — one implementation of
  every operation, one set of tests behind it.
- The report DTOs are the JSON API for free, and the `Display` impls remain for
  a host that wants text.
- The binary crate becomes thin, and its binary-driven integration tests keep
  covering the whole path, so the refactor is verified by tests that already
  exist rather than by new ones.

Costs:

- Two crates instead of one: a workspace `Cargo.toml`, two manifests, and
  dependency declarations to keep aligned. `just check` and CI run over the
  workspace.
- The `ops` signatures are new public API. Changing them is a breaking change
  for the web application from the day it exists; every field added to a report
  is a compatibility decision.
- The blocking client makes the async host pay a thread hop per operation, and
  a request that times out on the web side does not stop the operation on the
  worker. That is acceptable for an administration tool that does one thing at
  a time; it is the wrong shape for anything high-volume, and an async client
  would be a separate decision.
- Serializing operations is now a host obligation with no help from core. A
  web application that forgets it gets `state_locked` errors under concurrent
  requests, which is the safe failure but a surprising one.
- Moving files across crates rewrites `git blame` for most of the tree once.

## Alternatives considered

**Feature-gate `clap` in the single crate.** Cheapest change: put `cli`,
`output`, and `main` behind a `cli` feature and let a library consumer turn it
off. Rejected as the whole answer because it leaves every operation taking
`&Cli` and a `Renderer` — the consumer still cannot call apply and get a value —
and leaves the Unix gate and the uncurated surface as they are. Extracting
`ops` is most of the work either way; once it exists, the crate boundary is the
smaller step and the one that makes the contract visible.

**Rewrite the client and operations as async.** A web host is async, so this
would remove the `spawn_blocking` hop. Rejected for now: it is a large change
to code that is correct, tested, and reviewed, for a tool whose operations are
serialized anyway. The blocking design is contained behind `ops`, so an async
client later would change core's internals, not its callers' shape.

**Expose only the HTTP client and let the web application reimplement
planning.** Smallest surface. Rejected because the planner, the journaled
create transaction, and the recovery rules are the parts that are hard to get
right; two implementations of them is the outcome this project exists to avoid.

## Migration

Four steps, each one pull request, each reviewed on its own, each leaving
`just check` green and the CLI's behavior unchanged — with two stated
exceptions in step 1: `plan --json` gains the additive `fingerprint` field,
which the 0.x policy in `docs/compatibility.md` allows, and `apply` with no
credential no longer promotes a `delivered` operation before failing. Human
output is otherwise unchanged.

1. **Extract `ops` inside the existing crate.** Turn each `app` handler into an
   `ops` function that takes a `Context` and returns an `Outcome`; `app`
   becomes the glue that builds the context from `Cli`, renders the report,
   and maps `error: Some(_)` to exit 1. Add the plan fingerprint and the
   optional precondition on apply, with core API tests that call `ops::apply`
   with a fingerprint directly and prove that a change to any single input —
   an action, a receiver destination, a generation, the endpoint, the
   credential, the state path — is refused with no remote, receiver, or
   state write, and that a bound apply while an operation is pending is
   refused the same way, with no promotion. No crate split yet. The binary tests prove the CLI did not change, apart from
   the two stated exceptions.
2. **Move the environment boundary.** Add `ManagementKey::from_secret`; env
   reads move from `client` to the binary side; `state` stops reading
   `cli::DEFAULT_STATE_PATH`.
3. **Split the workspace.** Create the two crates, move the harness behind
   core's `test-support` feature, keep the Unix gate in core. Update
   `justfile`, CI, README, and the release checklist for a workspace.
4. **Curate and commit.** Reduce `pub` to the decided surface, add the core API
   to `docs/compatibility.md`, set this ADR to Accepted, record the change in
   `CHANGELOG.md`.

## References

- [ADR-0001](0001-native-reconciliation.md) — the single-writer state model
  this decision keeps.
- [ADR-0002](0002-journaled-key-creation.md) — the transaction `ops::apply`
  and `ops::rotate` expose unchanged.
- [`docs/compatibility.md`](../compatibility.md) — where the core API joins
  the list of contracts.
- reqwest's documentation on using the blocking client inside an async
  runtime: <https://docs.rs/reqwest/latest/reqwest/blocking/index.html>
