# ADR-0001: Native declarative reconciliation

- **Date:** 2026-08-23
- **Status:** Accepted

Accepted through automated code review of the commit that introduces it. This
repository currently has a single maintainer committing directly to `main`, so
that review stands in for a second human reviewer; see
[the ADR convention](README.md#review).

## Context

Keymaster manages OpenRouter inference keys and guardrails for an organization
from a checked-in description of what should exist. Two properties of the
managed resources set the constraints:

- An inference key's plaintext is returned only in the create response. A key
  cannot be re-read, so creation is not a repeatable operation and a lost
  create result is not recoverable by asking OpenRouter again.
- Display names are mutable and not unique. The only stable remote identifiers
  are the key hash and the guardrail UUID.

A tool that manages these resources therefore needs to know which remote object
belongs to which local configuration block, and it needs to know that
independently of any name a human can change in the OpenRouter dashboard. It
also needs to survive being interrupted between "sent a request" and "recorded
the result".

The available shapes were: embed an existing reconciliation engine
(Terraform/OpenTofu) or implement its provider protocol; match remote resources
by name on every run and keep no local state; run imperative batches that do
what the operator asks and remember nothing; or build a small native
reconciler with its own state.

## Decision

Keymaster implements a native declarative reconciliation model:

```text
desired TOML + non-secret identity state + freshly observed OpenRouter state
    -> typed plan -> ordered apply -> verification
```

Every run reads all three inputs and computes a typed plan as a pure function
of them. `plan` stops there and renders the result; it never writes. `apply`
recomputes the plan under its lock, executes it in a fixed dependency order,
and re-reads OpenRouter to verify the result.

Keymaster does not embed Terraform or OpenTofu, does not implement a provider
protocol, and does not identify remote resources by mutable display name.

The following lifecycle semantics follow from that model and are fixed:

1. **Hashes and UUIDs are remote identity.** A key is identified by its hash
   and a guardrail by its UUID. Names are managed fields, never identifiers.
2. **State is an identity/inventory and lifecycle journal, not an API cache.**
   It records which remote object each local address is bound to, where each
   binding came from, and which lifecycle transitions are incomplete. Observed
   policy, usage, and timestamps are read fresh from OpenRouter on every run
   and are never planned against a stored copy.
3. **Removing a block from configuration does not delete, disable, or forget
   the remote resource.** It produces a reported orphaned binding that stays
   tracked until an explicit command acts on it.
4. **A previously delivered key that is missing remotely is not silently
   recreated.** It is reported as missing. Recreating it would issue a new
   secret to a consumer that still holds the old one, on the strength of a read
   that may simply have been incomplete.
5. **Import is explicit and one-to-one.** An operator binds an existing remote
   object by hash or UUID. One remote object maps to exactly one local address,
   and one local address to exactly one remote object.
6. **v0.1 uses a local single-writer state model.** State lives in a
   project-local file, and apply holds an exclusive local lock for its
   duration.

## Consequences

Planning is a pure function of three explicit inputs, so representative cases
and invariants can be tested without HTTP, a filesystem, or a clock, and
re-planning identical inputs produces identical output.

Because identity is stored rather than inferred, renaming a key in the
OpenRouter dashboard is drift that Keymaster corrects, not an identity change
that makes it lose track of the object or adopt a stranger's.

Because state is a journal as well as an inventory, an interrupted create or
delivery is visible on the next run and can be reported as requiring recovery
instead of being retried blindly. ADR-0002 specifies that protocol.

Because nothing is destroyed implicitly, the failure mode of a bad
configuration edit or an incomplete read is a stale resource and a warning, not
a deleted credential.

Negative consequences:

- **Keymaster owns a state format, and therefore a compatibility burden.** The
  state file is load-bearing: losing it means re-importing every managed
  resource by its immutable identifier — a key by its hash, a guardrail by its
  UUID — and corrupting it can mean losing track of a live
  credential. Every future change to the format needs a version bump and a
  migration path, and operators need to back it up. This cost is permanent and
  is the main thing the stateless alternative would have avoided.
- **No shared remote locking. Concurrent operators can conflict.** The v0.1
  lock is a local file lock, so it only serializes runs on one machine against
  one state file. Two people running apply from two checkouts can both observe
  the same pre-change state and both act on it, and the second one's state file
  will not know about the first one's key. There is no remote backend, no lease,
  and no way for Keymaster to detect this. The mitigation is procedural — one
  operator, one state file — and it must be documented as a real limitation
  rather than an implementation gap.
- **We reimplement reconciliation machinery that mature tools already have.**
  Plan/apply ordering, drift reporting, and import all have to be written and
  tested here, and bugs in them are ours.
- **Verification costs an extra read pass**, so every apply is slower than
  fire-and-forget writes would be.
- **Recovery is manual by design.** Ambiguous operations stop the run and wait
  for an operator. That is the correct trade for one-time secret material, but
  it means Keymaster is not safe to run unattended on a schedule.

## Alternatives considered

**Embed Terraform or OpenTofu, or implement a provider protocol.** This would
give a mature plan/apply engine, a state format with remote backends and
locking, and an existing ecosystem — the official OpenRouter Terraform provider
already covers much of the API surface. Rejected for three reasons. First, the
default and idiomatic thing for a provider to do with a computed sensitive
attribute is retain it in state — the official OpenRouter provider retains the
one-time plaintext, marked sensitive but present — and Keymaster's core
invariant is that plaintext never enters persistent state at all. A provider
could be written to discard it, but then Terraform's state no longer describes
the resource it manages, which is working against the tool. Second, the
provider protocol's create/read/update/delete contract assumes a resource can
be re-read after creation; a resource whose secret exists only in the create
response, with no idempotency token, does not fit it, and the journaling and
operator-driven ambiguity recovery in ADR-0002 have no place in the framework's
lifecycle. Third, it would make
Keymaster a plugin to a tool the operator must already run, rather than a
single binary, for a resource set this small.

**Stateless name matching.** Every run lists remote resources and matches them
to configuration by name, keeping nothing locally. This has real appeal: no
state file, no compatibility burden, no single-writer limitation, and no import
step. Rejected because OpenRouter names are mutable and not unique. A rename in
the dashboard makes an existing key invisible and the next apply creates a
duplicate; a name collision makes Keymaster adopt and reconfigure an object it
never created; and a partial or paginated read that misses a key looks exactly
like the key not existing. For resources that hold spending authority, silently
adopting or duplicating by name is unacceptable. Stateless matching also cannot
journal an interrupted create, which is the failure this project most needs to
handle.

**One-shot imperative batches.** Commands like "create these keys" and "set
this budget", with no desired-state file and no plan step. Simple, obvious, and
easy to write. Rejected because it puts convergence in the operator's head:
nothing detects drift, the operator must compare desired and remote state by
hand, and repeating a command is not safe. It also has no place to record an
in-flight create, so an interrupted run leaves no trace at all — the worst
possible outcome for an operation that may have produced an unknown live key.

## References

- Terraform state identity: https://developer.hashicorp.com/terraform/language/state/purpose
- OpenTofu state identity: https://opentofu.org/docs/language/state/
- Kubernetes controller model: https://kubernetes.io/docs/concepts/architecture/controller/
- Flux inventory and prune behavior: https://fluxcd.io/flux/components/kustomize/kustomizations/#prune

### Implementation checks

As of v0.1 these checks exist and run in `just check`. The decision above is
unchanged; this section records where each part of it is enforced.

- **Versioned, locked, atomic, non-secret state** — `crates/core/src/state/`,
  with `crates/core/src/state/tests.rs` and `crates/core/tests/state.rs`. State
  carries identity and lifecycle phases only, refuses credential-shaped input
  and unrecognized schema versions, and holds its exclusive lock and atomic
  write under fault injection.
- **The pure planner** — `crates/core/src/plan/`, with the table-driven cases
  in `crates/core/src/plan/tests.rs`. Planning takes no clock, environment,
  filesystem, network, or output; state-bound identity is resolved before any
  name; an unbound desired object with a matching remote name yields
  `adoption_required`; a config-removed binding yields `orphaned_binding`; a
  missing delivered key yields `missing` rather than `create`; unknown remote
  resources are `unmanaged` and never written to.
- **Explicit import** — `crates/core/src/ops/import.rs`, covered by
  `crates/cli/tests/import.rs`: identity lookup only, never a name search, and
  the one-to-one binding rule refused from both directions with state left
  untouched.
- **Sequential apply** — `crates/core/src/ops/apply.rs`, covered by
  `crates/cli/tests/apply.rs`: a no-op plan sends no writes, `unmanaged`
  objects are never touched, and the plan is recomputed after the lock is taken
  so nothing carries a stale observation across that boundary.

The local single-writer model and the absence of remote locking are consequences
this ADR accepts, not gaps these checks close;
[`docs/operations.md`](../operations.md#looking-after-state) is the operator's
side of that.
