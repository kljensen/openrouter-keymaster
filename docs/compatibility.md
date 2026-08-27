# v0.1 scope and compatibility

What Keymaster 0.1 deliberately does not do, and what an operator or a script
may rely on not changing under them.

## Non-goals

These are decisions, not gaps waiting on effort. Each one exists because doing
it would make Keymaster less safe or less honest, or because it belongs to a
problem Keymaster is not trying to solve.

**No unattended operation.** Any ambiguous create or delivery stops the whole
run until a person resolves it. Keymaster cannot be run on a cron schedule
without someone reading the result, and a flaky network turns into operational
toil. The alternative is silently accumulating orphaned credentials
([ADR-0002](adr/0002-journaled-key-creation.md)).

**No automatic adoption.** A remote object whose display name matches an unbound
address is a candidate, never a match. Binding is always an explicit `import` by
hash or UUID ([ADR-0001](adr/0001-native-reconciliation.md)).

**No destruction from a deletion.** Removing a block from the configuration
retires nothing, deletes nothing, and forgets nothing. It becomes an orphaned
binding. `retire`, `decommission`, `delete key`, and `state forget` are the only
ways to end something, and each names an immutable identity.

**No automatic retirement.** Rotation stages a successor and stops. Keymaster
cannot know when a downstream deployment has adopted a new credential.

**No plaintext recovery, and no plaintext output.** An inference key's plaintext
exists only in memory between the create response and the receiver. There is no
command that prints one and no fallback that would.

**No multi-machine coordination.** The state lock is a local file. Two machines
can apply against one organization simultaneously and nothing detects it.

**No saved plans.** `apply` recomputes the plan under its own lock, so there is
nothing to save and nothing to go stale. There is no plan file format, no
interactive approval, no `--only`, and no Terraform-style detailed exit code.
A plan's `fingerprint` is not a saved plan either: it is a digest of the inputs,
and an apply given one still recomputes the plan and then refuses unless every
input that decides the outcome is still what it was. The command line never
sends one.

**No scheduled rotation**, no downstream smoke tests, no pruning, no
delete-by-name, no bulk import, no generated configuration.

**Unix only.** The durability and permission guarantees are built on Unix
primitives. v0.1 fails to build elsewhere rather than offering a weaker version
of them.

**A narrow slice of OpenRouter.** Keys, guardrails, and the assignments between
them. Not workspaces as managed resources, BYOK credentials, content filters,
members, analytics, or any inference endpoint.

**No shell completions, TUI, progress spinners, or color.** Output is text or
one JSON document, and never colored.

## Compatibility surfaces

Four things are contracts. Everything else in the repository is
implementation, and will change without ceremony.

### The command-line surface

The command tree, the global options, and the exit codes are a compatibility
surface. Scripts call this binary, and a renamed subcommand or a repurposed exit
code breaks them silently.

Exit codes are `0` success (including `--help` and `--version`), `1` application
error, `2` usage error. A successful `plan` exits 0 whether or not it found
changes.

Within 0.x: a new command, a new option, or a new field in a JSON document is a
minor change. Renaming or removing a command or option, changing what an exit
code means, or changing the type of an existing JSON field is a breaking change
and gets a version bump and a changelog entry.

### The JSON documents

`--json` puts exactly one JSON document on stdout, or exactly one diagnostic
document on stderr. Field names, and the string values of enumerated fields —
a plan's `outcome`, an apply's `outcome`, an action's safety class, an error's
`kind` — are part of the contract. They are rendered from dedicated DTOs rather
than from internal types, precisely so that a field added to a planner or state
type cannot change the output by accident.

Human-readable output is **not** a contract. Parse `--json`.

### The desired-state file

`version = 1` names the schema. A field's meaning will not change under that
version. New optional fields may be added; a file that a newer Keymaster
understands may not parse in an older one, which is why unknown fields are a
hard error rather than a silent skip.

### The core crate's Rust API

`openrouter-keymaster-core` is a library, and what it exposes is a contract for
the same reason the command line is: a host compiles against it, and a signature
that changes shape breaks a build rather than a script. It is versioned 0.x
alongside the binary, and the surface is deliberately small — everything else is
`pub(crate)`, so there is nothing to accidentally depend on
([ADR-0003](adr/0003-core-library-split.md)).

Covered:

- **The `ops` functions**, their names and their signatures: the `Context` a
  caller builds (`Paths`, `Options`, `ManagementKey`), the arguments each takes,
  and the `Outcome<R>` or `Error` each returns. A `Context` stays movable to
  another thread, and the operations stay synchronous and blocking.
- **The report types** `ops` returns, their public accessors, and the field
  names and enumerated string values of their JSON. These are the same DTOs the
  `--json` contract above describes; a field is one promise, made once, in both
  places.
- **`PlanFingerprint`** as an opaque value: a plan's fingerprint can be handed
  back to `ops::apply` and nothing else. Its digest inputs and its encoding are
  not a contract — a build that computes a different digest simply refuses a
  plan computed by another build, which is the safe direction.
- **The read-only configuration and state types**: `Config` and everything
  reachable from it, and `StateFile::read` with `State` and everything reachable
  from it. Their fields, accessors, and the meanings of their values.
- **The delivery callback** a `caller` receiver runs: `Context.deliver`'s
  signature, the `DeliveryMetadata` it is handed and that type's accessors,
  `KeyPlaintext::expose`, and the `DeliveryOutcome` and `Acknowledgement` it
  answers with ([ADR-0005](adr/0005-caller-receiver.md)). What the plaintext
  type guarantees — no `Serialize`, redacted `Debug`, cleared on drop — is part
  of it.
- **The error types** — `Error`, its variants, the per-layer errors it wraps,
  and `Error::kind`, whose strings are already part of the JSON contract. Every
  one of them is `#[non_exhaustive]`; see the rule for variants below.

Not covered, and free to change in any release: everything behind `ops` — the
HTTP client, the OpenRouter resource layer, the planner, the receiver
implementations behind that callback, and redaction — the crate's internal module layout, and the `test-support` feature,
which exists for this repository's own tests and makes no promise to anyone.

Within 0.x: a new `ops` function, a new field on a report, and a new accessor
are minor changes — including a new function that takes extra arguments beside
an existing one, which is how an option is added without changing a signature.
Changing an existing `ops` signature, removing or renaming a public item,
changing the type or meaning of a report, configuration, or state field, and
moving an item out of the public surface are breaking changes, and each gets a
version bump and a changelog entry.

Enum variants follow one rule. Every public error enum — `Error`, `ApiError`,
and the per-layer errors `Error` wraps — is `#[non_exhaustive]`, so a caller has to
write a fallback arm and adding a variant to one is a minor change. Every other
public enum is exhaustive deliberately: a host matching on a `Phase`, a
`DeleteOutcome`, or a `Receiver` should be told at compile time that there is a
new case to handle, so adding a variant to one of those is a breaking change.

A host also inherits two obligations that are not API and will not change
without an ADR: an async caller moves the whole `ops` call to a blocking thread,
because the client panics on a thread running a Tokio runtime, and callers
serialize their own operations on one state file, because the lock refuses a
concurrent writer rather than queueing it.

## State format migrations

The state file carries its own schema version, independent of the crate
version. **v0.1 ships schema version 1, and is where the compatibility promise
starts.** There is nothing to migrate from yet; every state file in existence
claims version 1, and the reader accepts exactly that.

From here on:

- A version this build does not understand is **refused**, naming the version it
  found and exiting with `state_unsupported_version`. It is never reinterpreted,
  because a misread binding is a live credential attributed to the wrong
  address.
- A later schema version ships with a forward migration and a changelog entry
  saying so. Migration is one-way, and it happens on the next write.
- There is no downgrade. Restoring a backup taken before the upgrade is the
  supported way back, which is the practical reason to
  [back state up](operations.md#looking-after-state) before upgrading.

Run one version of Keymaster against one state file.

## The receiver protocol

The envelope a command receiver reads on stdin is versioned inside the envelope
itself, so an adapter can reject a shape it does not understand rather than
guess. See [the receiver protocol](receiver-protocol.md). Its version moves
independently of the crate version and of the state schema.

## Dependencies and the toolchain

`Cargo.lock` is committed and every check runs with `--locked`. The Rust
toolchain is pinned in `rust-toolchain.toml` and must match
`package.rust-version`; a test fails if they drift apart. Neither is a
compatibility promise to anyone outside the repository — they are how a build
is made reproducible.
