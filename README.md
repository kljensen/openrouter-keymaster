# Keymaster

A declarative OpenRouter management CLI, written in Rust.

Keymaster is at v0.1.0. The command-line surface below is final for that
version, and every command on it is implemented end to end: `apply`
converges guardrails, keys, and assignments, and creates *and replaces*
inference keys through the journaled transaction of ADR-0002; `rotate`,
`retire`, `delete key`, and `state forget` are the explicit lifecycle
operations nothing else ever performs.

## Naming

The tool's full name is `openrouter-keymaster`, and that is the name used
wherever a machine or a shell has to identify it: the Cargo package and library
crate (`openrouter_keymaster`), the binary and its test-receiver companion
(`openrouter-keymaster-test-receiver`), the command name in `--help`, the HTTP
user agent, the default configuration file (`openrouter-keymaster.toml`), and
the state directory (`.openrouter-keymaster/`).

"Keymaster" is the short name, and it is what running prose in this README, the
docs, and the ADRs calls the project.

Environment variables use the short name as their prefix —
`KEYMASTER_LIVE_TESTS`, `KEYMASTER_LIVE_SWEEP`, and `KEYMASTER_STATE_FAULT`.
The credential and endpoint variables are named for the service instead:
`OPENROUTER_MANAGEMENT_KEY` and `OPENROUTER_BASE_URL`.

## Install and build

Keymaster is built from source. It needs the Rust toolchain pinned in
[`rust-toolchain.toml`](rust-toolchain.toml), which `rustup` installs on its own
the first time you build, and a Unix system — the durability and permission
guarantees are built on Unix primitives, so v0.1 fails to build elsewhere rather
than offering a weaker version of them.

```sh
git clone https://github.com/kljensen/openrouter-keymaster
cd openrouter-keymaster
cargo build --release
./target/release/openrouter-keymaster --version
```

Put the binary somewhere on your `PATH`, or run it from `target/release`. There
is no installer, no package, and no published crate.

For development, `cargo build`, `cargo run -- --help`, and `cargo test` work as
usual; [`just check`](#checks) runs the same battery CI does.

Then read [Credentials](#credentials) and
[the first-run runbook](docs/operations.md#first-run).

## Documentation

This README is the reference for what each command does and why. The pages under
[`docs/`](docs/README.md) are the material it links to:

| Page | What it is for |
| --- | --- |
| [operations.md](docs/operations.md) | Runbooks: first run, adoption, changes, key creation, rotation, retirement, recovery, and looking after state. |
| [configuration.md](docs/configuration.md) | Every field of the desired-state file. |
| [threat-model.md](docs/threat-model.md) | Supplying the management credential, and what Keymaster does and does not protect. |
| [receiver-protocol.md](docs/receiver-protocol.md) | The contract for writing a command receiver. |
| [compatibility.md](docs/compatibility.md) | v0.1 non-goals, which surfaces are contracts, and how state migrations will work. |
| [live-tests.md](docs/live-tests.md) | The opt-in acceptance suite that runs against a real organization. |
| [release-checklist.md](docs/release-checklist.md) | The v0.1 release gate, with the command that verifies each item. |
| [adr/](docs/adr/) | The decisions that are expensive to reverse. |

[`CHANGELOG.md`](CHANGELOG.md) records what each release changed.

## Commands

```text
openrouter-keymaster plan                          show the changes an apply would make
openrouter-keymaster status                        report bindings and incomplete operations
openrouter-keymaster apply                         converge OpenRouter with the configuration
openrouter-keymaster import key NAME --hash HASH   bind an existing key by its hash
openrouter-keymaster import guardrail NAME --id ID bind an existing guardrail by its UUID
openrouter-keymaster rotate NAME                   stage a replacement key
openrouter-keymaster recover inspect NAME          report an interrupted key operation
openrouter-keymaster recover resolve NAME ...      attest what an ambiguous operation did
openrouter-keymaster recover replace NAME          replace a key after resolving ambiguity
openrouter-keymaster retire NAME --hash HASH       disable a tracked retained key
openrouter-keymaster delete key --hash HASH        permanently delete a tracked key
openrouter-keymaster state forget ADDRESS          relinquish local ownership of an address
```

Global options: `--config PATH` (default `openrouter-keymaster.toml`),
`--state PATH` (default `.openrouter-keymaster/state.json`), and `--json`.

`recover resolve` requires exactly one attested finding, either
`--no-resource-created` or `--leaked-hash HASH`. Keymaster never guesses which
one is true.

[`docs/operations.md`](docs/operations.md) is the same list as procedures: what
to type, in what order, and what to check afterwards.

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
sentence naming the exact `openrouter-keymaster recover` command for that
phase. None of those is secret; a key's plaintext is exactly what is never
recorded anywhere. While an operation of unknown outcome stands, the plan is
`blocked` and nothing is executable.

**"Nothing to apply" has two causes and they are not the same**, so a plan ends
in one of three outcomes: `converged` (nothing to write and nothing an operator
has to clear — everything the configuration describes matches OpenRouter),
`changes_pending` (an apply would execute at least one action), or `held_back`
(there is work and none of it can run, behind an adoption, a missing resource,
an unfinished operation, or a dependency on one of those). The outcome is a
field in JSON and the last line of human output.

**A report is not work.** An `unmanaged` remote resource, an `orphaned_binding`
with no operation pending, and a `no_op` ask nothing of Keymaster or of an
operator, so a run holding only those is `converged` and the actions still say
what is there. An orphaned binding that carries an unfinished operation is
different — that operation is unsettled — and it holds the run back.

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

`openrouter-keymaster import key NAME --hash HASH` and
`openrouter-keymaster import guardrail NAME --id UUID` bind an existing remote
object to a local address. **Import is the operator's authority to make that
binding**; Keymaster never makes it on its own, because a display name is
mutable and not unique. A remote object whose name matches an unbound address
is reported by `plan` as `adoption_required` — a candidate, never an adoption.

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
6. Report the managed fields a later `openrouter-keymaster apply` would
   reconcile.
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

`openrouter-keymaster apply` is the only command that writes to OpenRouter. It:

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

- **Retire, disable, or delete a predecessor.** A planned replacement runs the
  journaled transaction and stops at the promotion. The key the address held
  is left exactly as it was, tracked as `awaiting_retirement`, until an explicit
  `openrouter-keymaster retire`. See
  [Rotation and retirement](#rotation-and-retirement).
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

An apply's outcome is one of six, and `converged` means what
`openrouter-keymaster plan` means by it — nothing was written, and the plan held
no write and nothing an operator has to clear:

| Outcome | Meaning | Exit |
| ------- | ------- | ---- |
| `converged` | Nothing to write and nothing to clear; nothing was written | 0 |
| `applied` | Every planned write was made and verified | 0 |
| `incomplete` | Nothing failed, but a write apply deliberately did not make was skipped | 0 |
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

## Creating a key

Creating an inference key is the one operation Keymaster cannot make
repeatable. OpenRouter returns the plaintext in the create response and nowhere
else, and documents no idempotency token, so a request whose response is lost
can never be told apart from one that was never applied. ADR-0002 answers that
with a journal, and it is the one path that issues secret material: `apply` runs
it for every planned key `create` and `replace`, and so do
`openrouter-keymaster rotate` and `openrouter-keymaster recover replace`.

```text
validate ─▶ create_started ─▶ POST /keys ─▶ created ─▶ PATCH + assign
                                                           │
        delivered ◀─ receiver ◀─ delivery_started ◀─ secured ◀─ verify
            │
            └─▶ promote to current
```

Each arrow a crash could fall through is a durable state write. The intent
markers — `create_started` and `delivery_started` — land *before* the
non-idempotent action they announce; the outcome phases land after the result
is known. The rules that follow from that:

- **Exactly one `POST /keys`, ever.** Retries are off at the transport as well
  as in the client. A timeout, a reset, a 5xx, or a success whose body cannot be
  read is journaled as `create_ambiguous` and stops the whole apply. It is never
  resolved by sending the request again, and never by adopting a remote key
  because its display name matches.
- **A well-formed 4xx is the one definite negative.** The server saw the
  request, declined it, and said so in a response that arrived whole, so no key
  exists: the attempt is cleared and the next run plans an ordinary create.
  *Well-formed* is load-bearing. A 4xx status line followed by a body that stops
  partway through is ambiguous, not definite — the exchange failed after the
  status, and clearing the journal on it would forget an attempt that may have
  made a live key. The body has to finish; it does not have to parse.
- **The hash is durable before anything else.** Before the update that applies
  restrictions, before the guardrail assignment, before the receiver. Until that
  write lands the process holds the only record that the key exists.
- **Restrictions and the guardrail are verified before delivery.** `POST /keys`
  has no `disabled` field, so a disabled key is born enabled and restricted by
  the update that follows; that update and the assignment are then read back and
  compared. The receiver cannot run until both check out.
- **The receiver runs at most once.** A definite rejection holds the operation
  at `secured` with a refusal marker the state API reads to refuse a second
  invocation. A lost acknowledgement is `delivery_ambiguous` and is never
  retried: the receiver may already have committed the secret.
- **A failure after the hash is durable tries to disable the key**, confirms
  that by reading it back, keeps the hash tracked either way, and says so. A
  failure *at* the hash write sends nothing further at all — the rule is that
  the hash is on disk before any follow-up call, and a disable would be one.
  The report names the hash, and `recover resolve --leaked-hash` binds it
  before disabling it.
- **The plaintext exists only in memory**, between the response being parsed and
  the receiver returning. It is never written to state, a log, stdout, stderr,
  JSON, argv, an environment variable, or a temporary file, and it is never
  printed as a fallback. A key with no configured receiver is never created.

Creations run one at a time, and the whole apply stops at the first unresolved
operation — the state API enforces the same rule from below, refusing to start a
second operation while one stands. Everything an unresolved one leaves behind is
handled by `openrouter-keymaster recover`.

One phase needs no operator: `delivered`. The transaction is over and only the
local promotion is outstanding, so `apply` completes it under its lock before it
plans, and says so in a warning.

## Rotation and retirement

Replacing a credential is four commands, not one, and the split is the whole
design. Keymaster can create a new key and put it where the configuration says.
It cannot know when the deployment that reads from there has picked it up. So
it stages the successor and stops; ending the predecessor's life is always
something an operator asks for by name.

```text
rotate ──▶ successor current, predecessor `awaiting_retirement`  (never touched)
             │
retire ──────▶ predecessor disabled, confirmed by a read, still tracked
             │
delete ──────▶ predecessor gone from OpenRouter, then dropped from state
```

`state forget` is the fifth door and leads out of the building: it relinquishes
ownership without touching anything remote.

All four stand aside for an operation in progress — `rotate` will not stage a
successor beside one, `retire` and `delete key` will not touch the key one is
about to produce, and `state forget` will not throw away the journal recording
it — and every one of those refusals names the command that clears it. That is
`openrouter-keymaster recover` for the phases only an operator can settle, and
`openrouter-keymaster apply` for `delivered`, which needs no operator at all:
the transaction is over and the outstanding promotion is local.
`recover replace` refuses `delivered` outright, so being sent there would be
being sent to a command that turns you away.

### rotate

```sh
openrouter-keymaster rotate jobfeed
```

A rotation is the journaled transaction of ADR-0002 with a different trigger.
`apply` runs the same one when the configuration demands it, and `rotate` runs
it when you want a fresh credential now, for a reason no file records.
`recover replace` runs it too, for a key whose plaintext is already gone.

`apply` plans a replacement when:

- `generation` rises;
- the key's `receiver` changes, or that receiver's non-secret fingerprint does;
- an immutable key field changes — `expires_at`, `workspace_id`, or
  `creator_user_id`.

Those three are immutable because `POST /keys` accepts them and
`PATCH /keys/{hash}` does not, so there is no way to move an existing key to a
new expiry, workspace, or creator. A `PATCH` body never carries one.

Whichever triggered it, the predecessor is not touched: not disabled, not
deleted, not unassigned, not even read. Only the promotion that follows a
*confirmed* delivery moves it to `retained.awaiting_retirement`, and it stays
enabled there. A rotation that fails at any phase — an ambiguous create,
restrictions that do not verify, a receiver that refuses — leaves the working
credential working and its consumers untouched.

Everything the successor needs is checked before anything is sent: the address
owns a key, no operation is in progress anywhere, the configuration still
describes the key and names a receiver, and its guardrail is bound and
converged. A failure there costs a read and changes nothing at all.

The successor takes the higher of the configured `generation` and the next free
number at the address. A generation names one remote key at one address and only
ever moves upward, so rotating a key at generation 3 whose configuration still
says 1 produces generation 4 rather than a collision; a number the address has
already used is refused outright by the state API.

**Deleting a key does not release its generation.** State keeps a per-address
high-water mark, so a number stays spent after the key that held it is gone.
Otherwise deleting the highest-generation key an address records — an abandoned
rotation's dead candidate, say — would let the next create hand that number to a
different remote key, right after the evidence of the first one was destroyed.

### retire

```sh
openrouter-keymaster retire jobfeed --hash <PREDECESSOR-HASH>
```

Disables one hash the address retains, and proves it by reading the key back.
The hash is an immutable identity: there is no retire-by-name, and no search.

`openrouter-keymaster status` lists the hashes an address holds and why each is
still tracked. Run `retire` when every consumer has the new credential — that is
the judgement Keymaster cannot make.

- **The current hash is refused.** Keymaster cannot know that nothing is still
  using it. Rotate first; the predecessor is what you retire. v0.1 defines no
  policy that permits the shortcut, so there is no flag for it.
- **Already disabled is a success that sends nothing.** The key is read first,
  so a repeated `retire` costs one read, writes no state, and reports `retired`.
- **A failed disable stays tracked.** The hash becomes `retirement_failed` so it
  can be retried, and the run exits 1 after writing its result document.
- **A retired hash stays in state.** It is still visible to an audit and to a
  later `delete key`. Nothing prunes it.

### delete key

```sh
openrouter-keymaster delete key --hash <HASH>
```

Permanent, irreversible, and never planned. There is no address argument: the
hash identifies the key, and the owning address is looked up rather than
asserted, so you cannot delete one address's key by typing another's name.

- **Only a hash Keymaster tracks.** A stray key belongs to whoever made it;
  `plan` reports it as unmanaged and this command refuses it.
- **The key an address is using is refused**, as is one belonging to an
  unfinished operation.
- **A 2xx is not the answer.** The key is read back, and only a 404 proves it is
  gone. A 404 on the delete itself means it was already absent — the same end
  state — and settles the hash.
- **State is never dropped ahead of the confirmation.** A refusal, a timeout, or
  a read that still finds the key leaves the hash tracked as
  `retirement_failed` and exits 1. The local record is the one thing that can
  still find a live spending credential, so it is the last thing to go.

### state forget

```sh
openrouter-keymaster state forget keys.jobfeed
openrouter-keymaster state forget guardrails.cheap
```

Relinquishes local ownership. **Zero HTTP requests and zero receiver
invocations**: nothing is disabled and nothing is deleted, so a released
resource is left however it already was. Keymaster makes no request, so it does
not claim the resource is still there. It needs no management credential,
no network, and no configuration — it exists to correct state that is wrong,
which is precisely when those may be unavailable.

Forgetting a key address releases every hash it held: the current key *and*
every retained one, because relinquishing ownership means relinquishing all of
it. The result document lists each identity and its role, so you can see what
you are letting go of before it stops being yours. Afterwards
`openrouter-keymaster plan` reports them as unmanaged.

`ADDRESS` is `keys.NAME` or `guardrails.NAME`. A bare `NAME` is accepted when
only one of the two is bound and refused when both are — the same word can name
a key and a guardrail.

- **An address with an operation in progress is refused.** The journal is the
  only record that the attempt happened, and in the create phases the only
  evidence that a live key may exist. Resolve it with
  `openrouter-keymaster recover` first.
- **An address bound to nothing is a clean no-op.** It writes no state and exits
  0, so repeating the command is safe.

### What none of this does

Removing a `[keys.*]` block from the configuration performs no lifecycle action
whatsoever. The binding becomes an `orphaned_binding`: reported by every `plan`
and `apply`, tracked, and otherwise left alone. Nothing is retired, deleted, or
forgotten because a block disappeared — Keymaster does not read a deletion in
one file as authority to destroy a credential in another system. Use `retire`,
`delete key`, and `state forget` explicitly.

There is also no scheduled rotation, no automatic smoke test of a downstream
application, no automatic retirement of a predecessor, no pruning, and no
delete-by-name. [`docs/compatibility.md`](docs/compatibility.md) is the full
list of what v0.1 deliberately does not do, alongside the surfaces that *are*
contracts — the command tree, the exit codes, the JSON field names, and the
configuration schema.

## Recovering an interrupted operation

Any create or delivery that ends without an answer leaves a journal entry and
stops the whole apply. `openrouter-keymaster recover` is the only way to close
one, and it never guesses: it does not retry a create, adopt a remote key
because its display name matches, or invoke a receiver a second time.

What follows is why each step is shaped the way it is.
[`docs/operations.md`](docs/operations.md#recovering-an-interrupted-operation)
is the same thing as a procedure, with a table that maps each phase to the one
command it accepts.

Start by reading the journal:

```sh
openrouter-keymaster recover inspect jobfeed
```

It reports the operation's identifier, phase, timestamp, generation, the
intended name and workspace, the hash when the journal has one, and the
non-secret fingerprint of the receiver the plaintext was bound for. When the
phase is one where a key's existence is still unknown — `create_started` or
`create_ambiguous` — it also lists the remote keys that *could* be the one the
attempt made: keys no local address owns, in the workspace the attempt named,
that carry the intended name or were created within an hour of it. Each says
which of those two signals fired. They are candidates, never matches, and
Keymaster will not choose one. An empty listing is not an all-clear either, and
the run says so. Each report ends with a remediation naming the one command that phase accepts:
`recover resolve` while a key's existence is unknown, `recover replace` once the
journal records a hash, and neither for `delivered`, which the next `apply`
finishes by itself.

`inspect` takes no lock and writes nothing. It reaches the network only when
there is something to search for: once the journal records a hash, every fact in
the report is already on disk, so inspecting a `secured` or `delivery_ambiguous`
operation needs no management credential and makes no API call at all.

Then look at OpenRouter yourself, and tell Keymaster what you found:

```sh
# Nothing was created.
openrouter-keymaster recover resolve jobfeed --no-resource-created

# A key was created, and this is its hash.
openrouter-keymaster recover resolve jobfeed --leaked-hash <HASH>
```

Exactly one of the two is required, and giving both is a usage error.
`--no-resource-created` clears the operation on your word — Keymaster has no way
to check it, and says so; an attestation that is wrong leaves a live key nothing
tracks. `--leaked-hash` fetches that exact hash, refuses if OpenRouter does not
have it, binds it as a **failed candidate** so it stays tracked *before* any
cleanup, then disables it and confirms that by reading it back. A confirmed
disable records it as `retired`; anything else leaves it a failed candidate for
a later explicit `retire` or `delete`. A found hash is never promoted to
current: its plaintext was disclosed once, in a response nobody received.

Repeating a resolution that already succeeded is a clear no-op, not an error.

Finally, get the address a working key:

```sh
openrouter-keymaster recover replace jobfeed
```

`replace` handles the phases where the outcome is already known and the
plaintext is gone — `created`, `secured`, `delivery_started`, and
`delivery_ambiguous`. Under one lock it checks everything the successor needs
first — the key is configured, a receiver is named, the guardrail is bound and
converged — and only once that passes does it retire the dead key into
`retained`, try to disable it, and stage a successor through the same journaled
transaction, taking the next free generation. The order matters: the key about
to be disabled may be live, and finding out afterwards that no successor can be
created would leave the address with neither. A preflight failure writes
nothing and sends no write, so the operation still stands and can be retried
once the configuration is fixed. It is refused from
`create_started` and `create_ambiguous`, because creating a successor before
anyone knows whether the first attempt made a key is how a live credential ends
up untracked; resolve those first. It is refused from `delivered` too, where the
next `apply` finishes the local promotion, and when nothing is pending at all —
`rotate` is the command for a key that works.

**Delivery ambiguity has no attestation.** ADR-0002 allows a lost
acknowledgement to be resolved as delivered only through a receiver-specific
idempotency or query contract: one that accepts the operation ID and can be
asked authoritatively whether it committed. v0.1 defines no such contract, so
there is deliberately no `resolve --delivered` flag. The only resolution is
`recover replace`, which costs a rotation even when the original delivery in
fact succeeded.

## Credentials

The credential is a management key, created on OpenRouter's Management API Keys
page — where it comes from is what makes it one. Its text does not: a management
key carries the same `sk-or-v1-` prefix an inference key does, so nothing can
tell them apart by shape and every `sk-or-` string is treated as a secret.

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

[`docs/threat-model.md`](docs/threat-model.md) covers how to supply the
credential without putting it in a shell history or a process list, and what the
design does and does not defend against.

## Configuration

Desired state is one TOML file.
[`examples/openrouter-keymaster.toml`](examples/openrouter-keymaster.toml) is a
complete, commented example with fake values; copy it to
`openrouter-keymaster.toml` and edit. It declares `guardrails` (model,
provider, and budget policy), `keys` (the inference keys Keymaster manages),
and `receivers` (where a newly created key's plaintext is delivered), each
addressed by a stable local name that is never sent to OpenRouter.

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

[`docs/configuration.md`](docs/configuration.md) is the field-by-field
reference: every key, its type, its default, and the rules that reject it.

## Receivers

A receiver is where a newly created key's plaintext goes. Keymaster never
prints a key, never writes one to state, and never creates a key whose
configuration names no receiver — there is no fallback and no implicit default.

- **`file`** writes the key, and nothing else, to one absolute path: an
  `O_EXCL` sibling temporary file at `0600`, fsynced and renamed into place, in
  a directory created `0700` if it was missing. An existing target is replaced
  with no backup. A relative path, a symbolic link at the target or its parent,
  and a target that is not a regular file are all refused — and the directory
  is opened once, with `O_DIRECTORY` and `O_NOFOLLOW`, with every step after
  that relative to the descriptor, so a symbolic link swapped in after the
  check cannot redirect the key. It is for local development: anything that can
  read the file can spend the key.
- **`command`** runs a program you write, with no shell, an exact argument
  vector, and an empty environment, and writes one versioned JSON envelope to
  its stdin. The key travels only in that envelope — never in `argv`, the
  environment, or a temporary file — and the program's bounded stdout and
  stderr are scrubbed of the key before an operator ever sees them.

A delivery is classified as delivered, rejected, or ambiguous, and ambiguous is
the default: only a mechanism that *guarantees* nothing was committed produces
a rejection. Delivery is at-most-once and is never retried automatically
(ADR-0002).

[`docs/receiver-protocol.md`](docs/receiver-protocol.md) is the contract for
adapter authors: the envelope schema, the empty-environment rules, the exit-code
meanings, the idempotency story, and a worked example.

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
  until an operator resolves it with `openrouter-keymaster recover`.
- **Unix only.** These durability and permission guarantees are implemented
  with Unix primitives, so v0.1 fails to build on other platforms rather than
  offering a weaker version of them.

[`docs/operations.md`](docs/operations.md#looking-after-state) has the
procedures: backing state up, restoring it, and clearing a lock a killed run
left behind.

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

`just live` is the one thing `just check` does not run and CI never will. It is
an opt-in acceptance suite against a **real** OpenRouter organization, gated by
`#[ignore]` and by `KEYMASTER_LIVE_TESTS=1`, and it creates and deletes real
resources with a real management credential. Read
[`docs/live-tests.md`](docs/live-tests.md) before running it.

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

`tests/receiver.rs` delivers a real plaintext — one parsed out of a create
response served by the local HTTP harness, because there is deliberately no
other way to obtain a `KeyPlaintext` — to both receivers, and scans the
outcome, the messages, and every file and filename left behind for the
sentinel. The command cases run
`src/bin/openrouter-keymaster-test-receiver.rs`, a real compiled adapter rather
than a shell string, which records its argument vector, the names of every
environment variable it inherited, and the envelope it was given, and can end
in every way the protocol describes: cleanly, with the
refusal code, with an undefined code, by signal, by timeout, by shouting
megabytes at both streams, and by echoing the key back.

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

## License

None yet. The crate is `publish = false` and carries no license expression, so
`deny.toml` ignores the private crate while still holding every dependency to
the allow-list. Choosing one is an open item on
[the release checklist](docs/release-checklist.md#8-license-chosen).
