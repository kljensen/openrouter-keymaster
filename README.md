# Keymaster

A declarative OpenRouter management CLI, written in Rust.

Keymaster is an early work in progress. The command-line surface below is
final for v0.1. `plan`, `status`, `import`, and `apply` are implemented end to
end; every remaining command still fails with a "not implemented yet" error and
exits 1. `apply` converges guardrails, existing keys, and assignments, but does
not create or replace inference keys yet — that is #16.

## Build, run, and test

```sh
cargo build
cargo run -- --help
cargo test
```

## Commands

```text
keymaster plan                          show the changes an apply would make   [works]
keymaster status                        report bindings and incomplete operations [works]
keymaster apply                         converge OpenRouter with the configuration [partly]
keymaster import key NAME --hash HASH   bind an existing key by its hash      [works]
keymaster import guardrail NAME --id ID bind an existing guardrail by its UUID [works]
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

## Plan and status

Both commands do the same four read-only things — validate the whole
configuration, load state, read a complete snapshot of OpenRouter, and print —
and neither makes an API write, invokes a receiver, or touches the state file.
State is read without taking the writer lock, so a `plan` never blocks an
`apply` and never rewrites the file, even when it observes remote drift.

`plan` prints every action an apply would take, dependencies before dependents,
each with the resource it is about, its immutable remote identity, the managed
fields that differ, why the planner proposes it, and how much care it needs:

| Safety class | Meaning |
| ------------ | ------- |
| `report` | Writes nothing; something to look at |
| `routine` | A write that cannot widen what any credential may do |
| `expanding` | A write that widens what an existing credential may do |
| `issuing` | Issues new secret material |

**A privilege expansion is made hard to miss.** Enabling a key, raising or
removing a budget, shortening a budget's reset period, widening an allowlist,
narrowing a denylist, weakening zero-data-retention enforcement, excluding BYOK
spend from a limit, and removing a key's guardrail are each reported as a named
expansion. In human output the action carries a `!` marker and the run ends
with a `! privilege expansions` section; in JSON each action carries
`expands_privilege` and an `expansions` array naming the expansion and the
field it applies to.

**An unfinished operation is reported with everything needed to resolve it**:
the operation identifier, the phase it stopped in, the timestamp of that phase,
the created key's hash when the journal recorded one, and a remediation
sentence naming the exact `keymaster recover` command for that phase. None of
those is secret; a key's plaintext is exactly what is never recorded anywhere.
While an operation of unknown outcome stands, the plan is `blocked` and nothing
is executable.

**"Nothing to apply" has two causes and they are not the same**, so a plan ends
in one of three outcomes: `converged` (every action is a no-op — OpenRouter
matches the configuration), `changes_pending` (an apply would execute at least
one action), or `held_back` (there is work and none of it can run, behind an
adoption, a missing resource, an unfinished operation, or a dependency on one
of those). The outcome is a field in JSON and the last line of human output.

`status` reports the same underlying facts from the other direction: which
local address owns which remote resource and where the binding came from,
whether that resource is still in the snapshot, each key's observed usage and
remaining budget, which addresses are orphaned, which remote resources no local
address owns, and the one unfinished operation if there is one. A retained
hash — a predecessor waiting for retirement is a live credential until
something disables it — is joined against the snapshot like any other key the
address owns, so its remote presence, disabled flag, and spend are reported
too.

**Text OpenRouter wrote is scrubbed before it is printed.** A display name, a
description, a slug, and an unrecognized reset schedule are free text nothing
has validated. Each goes through `redaction::redact` as it enters a report
DTO, so a credential someone pasted into a key's name is replaced with
`[redacted]` rather than read back, and an ANSI escape or bidirectional
override in one is shown escaped rather than allowed to rewrite the line an
operator is reading.

Output is deterministic: the planner is a pure function of its three inputs and
rendering reads no clock, so two runs over unchanged inputs print identical
bytes. Stdout carries the result only and is safe to pipe; warnings go to
stderr in human runs, and travel in the result document's `warnings` field
under `--json`, where a stream carries exactly one JSON document.

**Exit code 0 means planning succeeded, whether or not there are changes.**
There is no Terraform-style detailed exit code. A failure exits 1 with an
actionable category — `config_invalid`, `config_read`, `config_syntax`,
`missing_credential`, `authentication`, `transport`, `timeout`, `http_status`,
`state_parse`, and the rest — in the diagnostic's `kind` field.

## Import

`keymaster import key NAME --hash HASH` and
`keymaster import guardrail NAME --id UUID` bind an existing remote object to a
local address. **Import is the operator's authority to make that binding**;
Keymaster never makes it on its own, because a display name is mutable and not
unique. A remote object whose name matches an unbound address is reported by
`plan` as `adoption_required` — a candidate, never an adoption.

The command reads one object and writes one binding, in this order:

1. Parse the address and the identifier. Neither reads a file, so a value that
   cannot be used is refused before a lock or a credential is taken.
2. Take the exclusive state lock.
3. Load and validate the configuration, and reload state, both under the lock.
   The address has to be described in the configuration: a binding whose
   desired state nobody wrote is one no plan can act on, and a key's generation
   comes from the configuration, so the file it is read from must be one
   nothing can edit out from under the write that follows.
4. `GET /keys/{hash}` or `GET /guardrails/{id}` — the exact identity, never a
   listing filtered by name. A confirmed 404 ends the run and state is
   untouched.
5. Refuse an address already bound to a different object, and refuse an object
   another address already owns. Either refusal names both addresses.
6. Report the managed fields a later `keymaster apply` would reconcile.
7. Record the binding with `origin = imported` and write state atomically.

**It makes no remote write.** Whatever the configuration asks for that the
remote object does not have is reported, not applied. Repeating an import that
changes nothing writes nothing at all — not even a new serial — and says
`unchanged`.

**An imported key records no delivery.** Its plaintext was never Keymaster's to
hold, so it can never be delivered to a receiver; the way to put a
Keymaster-delivered key at that address is to raise the key's `generation` and
let a replacement be created. That absence is not itself a reason to replace
anything: a subsequent `plan` proposes ordinary managed-field convergence.

Failures each have their own category and all of them leave state exactly as
they found it: `import_argument`, `import_not_configured`, `import_absent`,
`import_owned_elsewhere`, `import_address_bound`, `import_refused`, and the
`state_locked` and `state_write` categories from the lock and the write path.

## Apply

`keymaster apply` is the only command that writes to OpenRouter. It:

1. takes the exclusive state lock;
2. reloads the configuration and state under it;
3. reads a complete snapshot of OpenRouter and **computes the plan again**;
4. executes that plan in three fixed phases — guardrail creates and updates,
   updates to keys that already exist, then assignment changes;
5. records a created guardrail's UUID before anything else happens;
6. reads OpenRouter again and reports, per action, whether the result was
   verified.

**The plan an operator read is never the plan that runs.** Step 3 is not an
optimization: a plan printed a minute ago was computed against a snapshot that
has since been replaced, and nothing carries a plan across the lock boundary,
so there is nothing to go stale.

**Verification is a replan, not a spot check.** An attempted action counts as
verified when the recomputed plan's actions at that address are all no-ops —
the same question the next run will ask, so a verified apply is one whose
successor is a no-op. Nothing weaker counts. "No *executable* action there"
would pass a key that vanished between the write and the read, which the
planner reports as `missing` precisely because it will not act on it, and it
would pass an address the plan stopped describing at all. Those are questions,
not confirmation. Anything short of a no-op is reported as `UNVERIFIED` rather
than assumed, and the run exits 1.

**A privilege expansion is reported from the verification, not from the
response.** Each action carries `privilege_expansion`: `occurred` when the
write was attempted and a fresh read confirms the configured state,
`unconfirmed` when it was attempted and the read does not, and `none` when
nothing was attempted. Both failure shapes land on the wrong side of a boolean,
which is why it is not one: an expanding PATCH that returned 500 and took
effect anyway *did* widen the credential, and an expanding PATCH that returned
200 and does not show up afterwards may not have. The unconfirmed case gets the
louder warning of the two — a credential whose privileges nobody can currently
state is worse than one that changed on purpose — and the human run marks both
with `!` and names the state on each line of the `! privilege expansions`
section.

What apply will not do:

- **Create or replace an inference key.** Issuing a one-time secret needs the
  journaled transaction of ADR-0002, which is #16 (and rotation is #19). A
  planned creation or replacement is skipped with a reason naming the issue,
  and the outcome is `incomplete` rather than `applied`. The assignment planned
  beside it is held back too, because that assignment belongs to the key the
  issuance would have produced: for a replacement, the address still owns the
  live predecessor, and assigning *it* to the successor's guardrail would
  change what an existing credential may do on the strength of a key that was
  never created.
- **Touch anything unmanaged.** Only actions the planner produced are executed,
  and the planner never proposes a write to a remote object no local address
  owns.
- **Delete, disable, or forget anything because a configuration block
  disappeared.** That stays an orphaned binding, reported and tracked.
- **Repeat an ambiguous write.** Every write is sent exactly once. Whether it
  landed is answered by the read that follows, never by sending it again.
- **Continue after a failed write.** A later action may depend on the one that
  failed, so the rest are reported as `not_attempted`. Verification still runs,
  so the report says exactly what was and was not confirmed — including a
  failed PATCH that turns out to have taken effect anyway.

Request bodies carry only managed fields, so a budget, an expiry, or a
provider-managed field Keymaster cannot express is preserved rather than
overwritten; a managed model or provider list is sent whole, because OpenRouter
replaces those rather than merging into them; and a key PATCH never carries
`expires_at` or `workspace_id`, which are fixed at creation and are a reason to
replace a key rather than to patch one. An assignment write names one key,
never a guardrail's whole key list — a guardrail can carry keys no local
address owns.

An apply's outcome is one of six, and `converged` is the strict one — it means
the plan held nothing but no-ops, exactly what `keymaster plan` calls converged:

| Outcome | Meaning | Exit |
| ------- | ------- | ---- |
| `converged` | The plan was all no-ops; nothing was written | 0 |
| `applied` | Every planned write was made and verified | 0 |
| `incomplete` | Nothing failed, but a write apply cannot make yet was skipped | 0 |
| `held_back` | Nothing failed, and work remains that only an operator can unblock | 0 |
| `failed` | A write failed, or one that was made could not be confirmed | 1 |
| `blocked` | An unfinished operation of unknown outcome stopped the run | 1 |

**A write the planner held back is not convergence.** An action whose
dependency needs an operator — an adoption, a missing resource, an unfinished
operation — is reported as `held_back`, per action and in the counts, with a
warning naming the addresses and each action saying what it waits on. An apply
that wrote nothing because everything it wanted to write is waiting on someone
has converged nothing, and it says so.

The two failing outcomes exit 1 with `apply_unresolved` or `apply_blocked` —
after writing the result document, because what did happen is what an operator
needs.

## Credentials

The management credential is read from the `OPENROUTER_MANAGEMENT_KEY`
environment variable only. There is deliberately no command-line option for
it, so it cannot appear in a process argument list, and no command echoes it.
In memory it is a `client::ManagementKey`, which cannot be serialized, prints
as `[redacted]`, and clears its buffer when dropped.

`OPENROUTER_BASE_URL` overrides the API root, which is
`https://openrouter.ai/api/v1` otherwise. It is not a credential and is
validated like any other base URL: absolute, HTTP or HTTPS, no trailing slash
or query. It exists so the compiled binary can be run against the local test
harness, and so an operator behind a gateway can name it deliberately rather
than having ambient proxy settings redirect a credential. An override that is
present but unusable — a value that is not valid Unicode, or not a base URL —
stops the run rather than falling back, because quietly reverting to
production would send the management credential somewhere the operator did not
name. Unset, or set to nothing at all, means production.

## Configuration

Desired state is one TOML file. [`examples/keymaster.toml`](examples/keymaster.toml)
is a complete, commented example with fake values; copy it to `keymaster.toml`
and edit. It declares `guardrails` (model, provider, and budget policy), `keys`
(the inference keys Keymaster manages), and `receivers` (where a newly created
key's plaintext is delivered), each addressed by a stable local name that is
never sent to OpenRouter.

Three properties are worth knowing before editing one:

- **Omitted is not empty.** A field you leave out is not managed: Keymaster
  reads the remote value and leaves it alone. TOML has no null, so clearing a
  remote field is spelled by naming it in the block's `clear` list.
- **No credential ever goes in this file.** The management key comes from the
  environment, and a new key's plaintext goes to a receiver. Any unrecognized
  field is a hard error, and so is any value shaped like an OpenRouter
  credential.
- **Validation runs before anything else.** Parsing and validation read one
  file and nothing else — no credential, no network, no write — and report
  every problem in one pass, each named by its configuration path.

## Local state

State lives in `.openrouter-keymaster/state.json` (git-ignored) unless
`--state` says otherwise, in a directory Keymaster creates `0700` with the file
`0600`. It records which immutable remote identity — a key hash, a guardrail
UUID — each local address owns, where that binding came from, and which
lifecycle transitions an interrupted run left incomplete. It holds no observed
policy or usage: those are read fresh from OpenRouter every run.

**State never contains a credential.** No type in it has a field for one, and
the key-hash type refuses credential-shaped input, so even a confused caller
cannot write a key's plaintext to disk.

Operating notes:

- **Back it up.** Losing state means re-importing every managed resource by its
  hash or UUID; there is no way to recover a binding from a display name.
- **One writer.** `apply` and the other writing commands take an exclusive lock
  by creating `<state>.lock`. A second run fails immediately with a message
  naming the lock file rather than waiting. A killed run leaves the file
  behind; removing it is safe once no Keymaster is running. The lock is local,
  so it does not coordinate two machines — see ADR-0001.
- **Reads never write.** `plan` and `status` load state and leave the file
  exactly as they found it, even when they observe remote drift.
- **Writes are atomic.** State is written to a sibling temporary file, fsynced,
  and renamed into place, so an interrupted write leaves the previous file
  intact rather than a truncated one.
- **A newer file is refused, not reinterpreted.** State carries a schema
  version; a file written by a later Keymaster stops this one with an error.
- **One operation at a time.** At most one key creation or delivery may be
  incomplete across the whole file; an apply stops at the first unresolved one
  until an operator resolves it with `keymaster recover`.
- **Unix only.** These durability and permission guarantees are implemented
  with Unix primitives, so v0.1 fails to build on other platforms rather than
  offering a weaker version of them.

## OpenRouter client

`src/client/` is a small blocking client for the OpenRouter management API. It
is deliberately not a generated SDK: Keymaster touches a handful of endpoints,
sequentially, and a hand-written client is what makes the safety properties
below inspectable.

- **One client, built one way.** Every request goes through the client built by
  `client::build_http`, which sets a connect timeout, a whole-request timeout, a
  Keymaster user agent, `Accept: application/json`, and a redirect policy that
  refuses to follow anything — the request carries the management credential,
  and the redirect target is chosen by whatever answered. `clippy.toml` refuses
  `reqwest::blocking::Client::new` so a client without those cannot be created
  elsewhere; `tests/lints.rs` fails if that ban is removed.
- **Management traffic goes direct.** Proxies are disabled outright, because
  `reqwest` otherwise honours `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` and a proxy
  named there terminates TLS to inspect what passes through it — the
  `Authorization` header included. Ambient environment must not be able to
  redirect a credential.
- **Where a request goes is decided by a parser, not a prefix check.** A base
  URL is validated with the same URL parser that will resolve the request, and
  refused unless it is already written the way it will be requested: `https:///api`
  looks absolute and silently resolves to the host `api`.
- **The credential cannot be printed or serialized.** `ManagementKey` is read
  only from `OPENROUTER_MANAGEMENT_KEY`, has no `Serialize` and no accessor, is
  cleared when dropped, and reaches the wire once, as a header marked sensitive.
- **Responses are bounded.** Bodies are read up to a cap and refused past it;
  path segments and query values are percent-encoded.
- **Errors are Keymaster's own.** `ApiError` distinguishes transport, timeout,
  HTTP status, redirect, authentication, invalid-response, oversized-response,
  and invariant failures. It exposes no `reqwest` type, and every string in one
  is redacted and truncated. A status that is definitive on its own — a redirect
  or a rejection — keeps its status even when the body underneath it cannot be
  read, so a create refused with a 400 stays a refusal rather than becoming an
  ambiguous failure that sends an operator to `recover`.
- **Retries belong to the operation.** A safe read is retried a bounded number
  of times on a lost connection, a body that stops partway through an otherwise
  good response, a 429, or a transient 5xx; `Retry-After` is
  honoured as a signal but clamped to the policy. A write has no retry loop at
  all, and the transport's own HTTP/2 retry policy is turned off underneath it:
  a replayed `POST /keys` can create a live credential nobody knows about, so an
  ambiguous write is resolved by refreshing state (ADR-0002).
- **A secret that arrives once is typed as such.** `POST /keys` returns a
  `CreatedKey`, whose plaintext has no `Serialize`, prints redacted, and is
  cleared when dropped. No public method returns unrestricted JSON from a write,
  so no caller can route that plaintext into `Debug` or `Serialize` by choosing
  its own response type.

## Reading and writing OpenRouter

`src/api/` reads and writes the resources Keymaster manages: keys, guardrails,
and the assignments between them. `api::Reader` is read-only and its types are
observations, not desires; `api::Writer` is the small set of writes an ordinary
convergence needs. No method on the writer reports success from what the server
echoed back — an update returns `()`, a create returns only the identity apply
must persist immediately — because an ambiguous write is resolved by a fresh
read, never by a replay.

Usage counters, remaining budget, and creation timestamps are OpenRouter's
alone, so they live in `KeyUsage` and `RemoteTimestamps` rather than beside the
managed fields, where a diff could pick one up and propose "fixing" recorded
spend.

Pagination is centralized in `api::pagination` because a partial snapshot is
worse than none: a key that pagination missed reads as a key that is not there,
and the plan that follows would propose creating a second one. So a listing
stops on an empty page, advances by the records actually returned, deduplicates
by immutable identity, and refuses — with a diagnostic naming the offset and
the page — a non-empty page that repeats only identities already seen. A
documented `total_count` tightens the bound on how much will be read but never
ends the listing, so a wrong total cannot truncate a snapshot. Page and record
caps stop a listing that would otherwise never end.

Unknown response fields are ignored, so a field OpenRouter adds tomorrow does
not stop a plan today; a record with no usable identity is a typed
invalid-response error instead.

Write bodies live in `api::write`. `Patch` gives every managed field three
states — omitted, set, and explicitly `null` — so a field Keymaster does not
manage is left out of the body rather than cleared by accident, and a create
omits what an update would clear, because a field that has never existed cannot
be unset.

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

A successful `plan` exits 0 whether or not it found changes to make, and a
successful `status` exits 0 whatever it reports. Only a failure — a
configuration, credential, state, or API error — exits 1, and its `kind` names
the category.

Results are rendered from dedicated DTOs in `src/report/`, not from the domain
types: a field added to a planner or state type cannot silently change the
output contract, and no type that could hold secret material is reachable from
one.

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

## Test harness

`tests/support/` is shared test support that any integration test picks up
with `mod support;`. It uses no external network and no real credential.

- `http` — a local `wiremock` server with a synchronous interface, so tests of
  the blocking client never write `async`. It matches routes and methods,
  captures headers and bodies, counts requests, scripts ordered responses,
  holds mutable remote state for drift tests, and produces the failure modes
  the client has to survive: delay, lost connection, malformed JSON, an
  oversized body, 4xx, 429 with `Retry-After`, and 5xx. Failures print the
  requests that arrived, with credential headers redacted.
- `fixtures` — small hand-written JSON bodies with obviously fake secrets.
- `clock` — a clock that moves only when a test moves it.
- `receiver` — a fake secret receiver covering the four delivery outcomes:
  delivered, definitely rejected, timed out, and acknowledgement lost.
- `sentinel` — a unique secret sentinel with scanners that assert its absence
  from strings, files, and directory trees, and its presence where disclosure
  is the expected behavior.

`tests/harness.rs` has one demonstration test per capability, including one
that proves the server received the expected bearer credential while sentinel
scanning proves it reached neither diagnostics nor any written artifact.

- `project` — a temporary project directory, a server answering the three
  listings a snapshot reads, and the compiled binary pointed at both with a
  sentinel credential. Every run it starts is scanned for the sentinel in
  stdout, stderr, and every file under the project directory.

`tests/plan.rs` runs the compiled binary against that harness for the
representative planning cases — converged, drift, name collision, missing,
unmanaged, and an unfinished operation — and for the failure categories. Every
run in it scans stdout, stderr, and the whole project directory for the
sentinel on the success path and the failure path alike, and one case proves
that `plan` and `status` sent nothing but `GET` requests and left the state
file byte for byte as they found it.

`tests/import.rs` covers the binding rules the same way: the exact-identity
lookup and the requests it does *not* make, the reported difference, a repeated
import that writes nothing, a 404, both one-to-one violations, lock contention,
a state write that cannot happen, and a remote display name carrying the
sentinel.

`tests/apply.rs` asserts which requests apply sent, in what order, carrying
what — and, as often, that it sent none: a converged project, an unmanaged
resource, a blocked plan, and a plan whose only work is a key creation all
write nothing. It also covers the phase order and request bodies, verification,
a second apply that is a no-op, a guardrail recreated after it disappeared, an
assignment removed and one restored, and a guardrail create that fails midway —
which must leave the identity of the one that succeeded tracked and state
exactly which actions were verified.

## Lint policy

`Cargo.toml` `[lints]` forbids `unsafe_code` and denies `dbg!`, `todo!`,
`unimplemented!`, and `unwrap()`. Complexity tripwires live in `clippy.toml`:
cognitive complexity 20, function length 80, argument count 7, type complexity
200. Tests may add narrowly scoped `#[allow(...)]` with a reason; production
code may not disable the policy wholesale. `clippy.toml` also lists disallowed
methods, currently the two `reqwest` client constructors that would produce an
HTTP client with no timeout, redirect policy, or credential.

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
