# Commands

The reference for every command: its arguments, what it reads, what it writes,
what it will refuse, and how it ends. [`operations.md`](operations.md) is the
same material as procedures, and the ADRs under [`adr/`](adr/) hold the
reasoning.

## The command tree

```text
openrouter-keymaster plan                          show the changes an apply would make
openrouter-keymaster status                        report bindings and incomplete operations
openrouter-keymaster spend                         report credit balance and per-key cost
openrouter-keymaster apply                         converge OpenRouter with the configuration
openrouter-keymaster import key NAME --hash HASH   bind an existing key by its hash
openrouter-keymaster import guardrail NAME --id ID bind an existing guardrail by its UUID
openrouter-keymaster import workspace NAME --id ID bind an existing workspace by its UUID
openrouter-keymaster import log-destination NAME --id ID
                                                   bind an existing log destination by its UUID
openrouter-keymaster rotate NAME                   stage a replacement key
openrouter-keymaster recover inspect NAME          report an interrupted key operation
openrouter-keymaster recover resolve NAME ...      attest what an ambiguous operation did
openrouter-keymaster recover replace NAME          replace a key after resolving ambiguity
openrouter-keymaster retire NAME --hash HASH       disable a tracked retained key
openrouter-keymaster decommission NAME --hash HASH end the key an address is using
openrouter-keymaster delete key --hash HASH        permanently delete a tracked key
openrouter-keymaster delete workspace --id UUID    permanently delete a tracked workspace
openrouter-keymaster delete log-destination --id UUID
                                                   permanently delete a tracked log destination
openrouter-keymaster state forget ADDRESS          relinquish local ownership of an address
```

The command tree, the global options, and the exit codes are a compatibility
surface ([`compatibility.md`](compatibility.md#the-command-line-surface)).

Every command reaches OpenRouter and needs `OPENROUTER_MANAGEMENT_KEY`, with two
exceptions: `state forget` never makes a request, and `recover inspect` makes
none once the journal records a hash — an inspect that does need a candidate
listing reports `missing_credential` instead.

## Global options

Every command accepts all four.

| Option | Default | Meaning |
| --- | --- | --- |
| `--config PATH` | `openrouter-keymaster.toml` | The desired-state file. |
| `--state PATH` | `.openrouter-keymaster/state.json` | The state file. Its lock is `<state>.lock`. |
| `--workspace UUID` | none | Scope the run to one OpenRouter workspace. |
| `--json` | off | One JSON document on stdout, one diagnostic document on stderr. |

`--workspace` is a guard on placement and a filter on reports, not isolation.
Every key, guardrail, and log destination the run creates is placed in the
scope; a configuration naming another workspace is refused before any request;
matching by name — adoption candidates, and the collision check before a guarded
recreation — considers only the scope; and reports omit `unmanaged` resources
from other workspaces. Resources a local address already owns are judged and
reported exactly as they are without a scope, wherever they live. The plan
fingerprint covers the scope, so a scoped plan can never be applied unscoped.
See [`operations.md`](operations.md#scoping-a-run-to-one-workspace) and
[ADR-0004](adr/0004-workspaces.md).

## Output and exit codes

Stdout carries the requested result only, and is safe to pipe; stderr carries
diagnostics. Neither is ever colored. Under `--json` each stream carries exactly
one document, and warnings travel in the result document's `warnings` field
rather than on stderr.

| Exit code | Meaning |
| --- | --- |
| 0 | Success, including `--help` and `--version` |
| 1 | Application error |
| 2 | Usage error |

There is no Terraform-style detailed exit code: a successful `plan` exits 0
whether or not it found changes. A failure exits 1 with an actionable category
in the diagnostic's `kind` field — `config_invalid`, `config_read`,
`config_syntax`, `missing_credential`, `authentication`, `transport`, `timeout`,
`http_status`, `invalid_response`, `state_parse`, `state_locked`, `state_write`,
`apply_unresolved`, `apply_blocked`, and the import categories below.

Field names and the string values of enumerated fields are part of the JSON
contract ([`compatibility.md`](compatibility.md#the-json-documents)). Output is
deterministic: two runs over unchanged inputs print identical bytes. Text
OpenRouter wrote is scrubbed before it is printed
([`threat-model.md`](threat-model.md#what-keymaster-protects-against)).

## Safety classes and outcomes

Every planned action carries a safety class.

| Safety class | Meaning |
| --- | --- |
| `report` | Writes nothing; something to look at |
| `routine` | A write that cannot widen what any credential may do |
| `expanding` | A write that widens what an existing credential may do |
| `issuing` | Issues new secret material |

**A privilege expansion is made hard to miss.** Enabling a key, raising or
removing a budget, shortening a budget's reset period, widening an allowlist,
narrowing a denylist, weakening zero-data-retention enforcement, excluding BYOK
spend from a limit, and removing a key's guardrail are each reported as a named
expansion: a `!` marker and a closing `! privilege expansions` section in human
output, and `expands_privilege` with an `expansions` array in JSON.

A plan ends in one of three outcomes, reported as a JSON field and as the last
line of human output:

| Plan outcome | Meaning |
| --- | --- |
| `converged` | Nothing to write and nothing an operator has to clear |
| `changes_pending` | An apply would execute at least one action |
| `held_back` | There is work, and none of it can run |

An apply ends in one of six:

| Apply outcome | Meaning | Exit |
| --- | --- | --- |
| `converged` | Nothing to write and nothing to clear; nothing was written | 0 |
| `applied` | Every planned write was made and verified | 0 |
| `incomplete` | Nothing failed, but a write apply deliberately did not make was skipped | 0 |
| `held_back` | Nothing failed, and work remains that only an operator can unblock | 0 |
| `failed` | A write failed, or one that was made could not be confirmed | 1 |
| `blocked` | An unfinished operation of unknown outcome stopped the run | 1 |

**"Nothing to apply" has two causes.** `converged` means OpenRouter already
matches the file; `held_back` means work is waiting on an adoption, a missing
resource, or an unfinished operation. An apply that wrote nothing because
everything it wanted to write is waiting on someone has converged nothing.

**A report is not work.** An `unmanaged` resource, an `orphaned_binding` with no
operation pending, and a `no_op` ask nothing of anyone, so a run holding only
those is `converged`. An orphaned binding carrying an unfinished operation is
different — that operation is unsettled — and it holds the run back.

## `plan`

```sh
openrouter-keymaster plan
```

Validates the whole configuration, loads state, reads a complete snapshot of
OpenRouter, and prints. It makes no API write, invokes no receiver, and writes
no file: state is read without the writer lock, so a `plan` never blocks an
`apply` and never rewrites the file, even when it observes remote drift.

It prints every action an apply would take, dependencies before dependents, each
with the resource, its immutable remote identity, the managed fields that
differ, why the planner proposes it, and its safety class.

**An unfinished operation is reported with everything needed to resolve it**,
none of it secret, ending in the exact `recover` command that phase accepts.
While one of unknown outcome stands, the plan is `blocked` and nothing is
executable.

Runbook: [First run](operations.md#first-run),
[Making a change](operations.md#making-a-change).

## `status`

```sh
openrouter-keymaster status
```

The same facts from the other direction, and the same guarantee of writing
nothing: which local address owns which remote resource and where the binding
came from, whether that resource is still in the snapshot, each key's observed
usage and remaining budget, each workspace's `budgets` and
`include_byok_in_budgets`, which addresses are orphaned, which remote resources
no local address owns, and the one unfinished operation if there is one.

A retained hash — a predecessor waiting for retirement is a live credential
until something disables it — is joined against the snapshot like any other key
the address owns. `status` is where the hashes `retire` and `delete key` take
come from.

## `spend`

```sh
openrouter-keymaster spend [--since RFC3339] [--until RFC3339] [--granularity day|week|month]
```

Reads `GET /credits`, `GET /analytics/meta`, and `POST /analytics/query`, and
writes nothing at all — no state, no lock, no remote change. `--since` and
`--until` default to the last thirty days ending now; `--granularity` defaults
to `day`.

**The metric and dimension names are discovered, not assumed.** OpenRouter's
specification names no metric or dimension, so every run reads the meta first
and asks in names that endpoint lists, trying each row below in order. The
report's `columns` field names the three it settled on; an organization whose
meta lists none of the names for one of them fails the run with
`invalid_response` rather than reporting a silent zero.

| Quantity | Names tried | What it means |
| --- | --- | --- |
| Cost | `total_usage`, then `credits_usage`, `openrouter_usage` | `total_usage` is the whole cost of the traffic — credit-paid inference plus the credit-equivalent of BYOK usage and its fees. The other two are narrower answers and fallbacks, not preferences. |
| Tokens | `tokens_total` | Prompt plus completion. The breakdown beside it is deliberately not asked for. |
| Key | `api_key_id` | The dimension every row is grouped by. It answers with the key's **display name**, not its hash. |

**`key` is a label, not an identity.** The api-key dimension is enriched: a
grouped query answers with the display name, while a *filter* on it takes the
numeric id or the hash. Keymaster prints the label as it arrived.

**A metric arrives as a number or as a quoted one** (`"tokens_total":
"18993032"`), so both are read as the number they hold. One that is neither
fails the run naming the field, rather than letting a token count silently
become zero beside a real dollar cost.

**A scope is a filter, or a warning.** `--workspace UUID` adds a `workspace`
filter when the meta lists that dimension; when it does not, the report covers
the whole organization and says so on stderr.

The JSON fields are listed in
[`compatibility.md`](compatibility.md#the-core-crates-rust-api). Runbook:
[Reading spend](operations.md#reading-spend).

## `apply`

```sh
openrouter-keymaster apply
```

The only command that writes to OpenRouter as part of convergence.

**Reads:** the configuration and state, both reloaded under the exclusive state
lock, and a complete snapshot of OpenRouter. **Writes:** the plan's actions in
five fixed phases — workspaces, log destinations, guardrails, keys, then
assignments — dependencies before dependents; and state, where a created
resource's identity is recorded before anything else happens.

**The plan an operator read is never the plan that runs.** Apply recomputes it
under its own lock, so nothing carries a plan across the lock boundary and there
is nothing to go stale. A `fingerprint` may be handed back through the library,
and an apply given one still recomputes and then refuses unless every input that
decides the outcome is still what it was; the command line never sends one.

**Verification is a replan, not a spot check.** Apply reads OpenRouter again
afterwards and recomputes. An action counts as verified when the recomputed
plan's actions at that address are all no-ops — the same question the next run
will ask. Anything less is reported as `UNVERIFIED` and the run exits 1.

**A privilege expansion is reported from the verification, not the response.**
Each action carries `privilege_expansion`: `occurred` when the write was
attempted and a fresh read confirms the configured state, `unconfirmed` when the
read does not, and `none` when nothing was attempted. `unconfirmed` gets the
louder warning of the two.

What apply will not do:

- **Retire, disable, or delete a predecessor.** A planned replacement stops at
  the promotion, leaving the key the address held exactly as it was and tracked
  as `awaiting_retirement` until an explicit `retire`.
- **Touch anything unmanaged**, or act on a configuration block that
  disappeared. That stays an orphaned binding, reported and tracked.
- **Repeat an ambiguous write.** Every write is sent once; the read that follows
  says whether it landed.
- **Continue after a failed write.** A later action may depend on it, so the
  rest are reported as `not_attempted`. Verification still runs.
- **Overwrite what it does not manage.** Request bodies carry only managed
  fields, so a budget, an expiry, or a provider-managed field Keymaster cannot
  express is preserved. A managed model or provider list is the exception, sent
  whole because OpenRouter replaces those rather than merging into them.

The failing outcomes exit 1 with `apply_unresolved` or `apply_blocked`, after
writing the result document — what did happen is what an operator needs.

Runbook: [Making a change](operations.md#making-a-change). Rationale:
[ADR-0001](adr/0001-native-reconciliation.md).

### Issuing a key

Every planned key `create` and `replace` runs the journaled transaction of
[ADR-0002](adr/0002-journaled-key-creation.md), which is what `rotate` and
`recover replace` run too. The ADR is the reference for its phases; the command
surface promises:

- **A key with no configured receiver is never created.** The plaintext exists
  only in memory, between the create response being parsed and the receiver
  returning. Keymaster never writes it to state, a log, stdout, stderr, JSON,
  argv, an environment variable, or a file of its own, and never prints it as a
  fallback. Where it goes after that is the receiver's business — the `file`
  receiver, for one, writes it through a `0600` temporary file it renames over
  the target.
- **At most one `POST /keys` per journaled attempt**, and the receiver runs at
  most once. An ambiguous outcome is never retried and never resolved by
  adopting a remote key whose display name matches; only a well-formed 4xx —
  which proves the server declined the request and made no key — clears the
  attempt, and a later run may then plan an ordinary create.
- **Creations run one at a time**, and the apply stops at the first operation
  whose outcome is unknown. What it leaves behind is closed with
  [`recover`](#recover).
- **`delivered` needs no operator.** The transaction is over and only the local
  promotion is outstanding, so `apply` completes it under its lock before it
  plans, and says so in a warning.

Runbook: [Creating a key](operations.md#creating-a-key).

## `import`

```sh
openrouter-keymaster import key NAME --hash HASH
openrouter-keymaster import guardrail NAME --id UUID
openrouter-keymaster import workspace NAME --id UUID
openrouter-keymaster import log-destination NAME --id UUID
```

**Import is the operator's authority to bind an existing remote object to a
local address.** Keymaster never makes that binding on its own, because a
display name is mutable and not unique; a remote object whose name matches an
unbound address is reported by `plan` as `adoption_required` — a candidate,
never an adoption.

**Reads:** the configuration and state under the exclusive state lock, and one
`GET` of the exact identity, never a listing filtered by name. **Writes:** one
binding, recorded with `origin = imported` and written atomically, and nothing
remote at all. Whatever the configuration asks for that the object does not have
is reported for a later `apply` to reconcile, not applied. Repeating an import
that changes nothing writes nothing — not even a new serial — and says
`unchanged`.

**Refusals** each have their own category and leave state exactly as they found
it, alongside `state_locked` and `state_write` from the lock and the write path:

| Category | Cause |
| --- | --- |
| `import_argument` | The address or identifier will not parse. Refused before a lock or a credential is taken. |
| `import_not_configured` | The configuration does not describe the address, so no plan could act on the binding. |
| `import_absent` | A confirmed 404. |
| `import_address_bound` | The address already owns a different object. Names both. |
| `import_owned_elsewhere` | Another address already owns the object. Names both. |
| `import_refused` | The resource cannot be imported by name at all — a workspace's default guardrail. |

Two records an import cannot make, neither of them a reason to replace
anything: **no `config` digest** for a log destination, because OpenRouter masks
that field on read, so the first apply writes the configured value and records
its digest from then on; and **no delivery** for a key, whose plaintext was
never Keymaster's to hold — raising `generation` is how that address gets a
Keymaster-delivered key.

Runbook: [Adopting resources that already exist](operations.md#adopting-resources-that-already-exist).

## `rotate`

```sh
openrouter-keymaster rotate NAME
```

Runs the journaled transaction above on your word. `apply` runs the same one
when the configuration demands a replacement: `generation` rises; the key's
`receiver` changes, or that receiver's non-secret fingerprint does; or an
immutable key field changes — `expires_at`, `workspace_id`, or
`creator_user_id`, which `POST /keys` accepts and `PATCH /keys/{hash}` does not.

**The predecessor is not touched**: not disabled, not deleted, not unassigned,
not even read. Only the promotion that follows a *confirmed* delivery moves it
to `retained.awaiting_retirement`, and whatever state it was in — enabled or
not — it keeps there. A rotation that fails at any phase leaves the working
credential working.

Everything the successor needs is checked before anything is sent: the address
owns a key, no operation is in progress anywhere, the configuration still
describes the key and names a receiver, and its guardrail is bound and
converged. A failure there costs a read and changes nothing.

The successor takes the higher of the configured `generation` and the next free
number at the address. A generation names one remote key at one address and only
moves upward, so rotating a key at generation 3 whose configuration still says 1
produces generation 4; a number the address has used is refused. **Deleting a
key does not release its generation** — state keeps a per-address high-water
mark, so a number stays spent after the key that held it is gone.

Runbook: [Rotating a key](operations.md#rotating-a-key).

## `retire`

```sh
openrouter-keymaster retire NAME --hash HASH
```

Disables one hash the address *retains*, and proves it by reading the key back.
The hash is an immutable identity: there is no retire-by-name and no search. Run
it when every consumer has the new credential — the judgement Keymaster cannot
make.

**The current hash is refused**, because Keymaster cannot know that nothing is
still using it; ending a working key is [`decommission`](#decommission). A key
OpenRouter already has disabled is read, reported `retired`, and written
nowhere, so repeating the command is free. A retired hash stays in state,
visible to an audit and to a later `delete key`; nothing prunes it.

Runbook: [Ending a key's life](operations.md#ending-a-keys-life), which covers
the failure paths.

## `decommission`

```sh
openrouter-keymaster decommission NAME --hash HASH [--delete]
```

Ends the key an address is *using*, which is the one thing `retire` and
`delete key` refuse. `HASH` must be the address's **current** hash and is
checked before anything is sent; there is no decommission-by-name.

**Only a confirmed disable moves state**, and the hash is then retained rather
than dropped: it becomes `retained.retired`, so an audit can still see it and
`delete key --hash HASH` can finish the job. A key OpenRouter no longer has is
settled by the 404 that proves it, and nothing further is sent — not even a
`--delete`, whose answer is already in hand.

**The address is left bound and owning no key**, which is the shape `apply`
treats as "not created yet". The runbook covers what to do about the
configuration before running it, and the failure paths:
[Ending a key that is not being replaced](operations.md#ending-a-key-that-is-not-being-replaced).

## `delete`

```sh
openrouter-keymaster delete key --hash HASH
openrouter-keymaster delete workspace --id UUID
openrouter-keymaster delete log-destination --id UUID
```

Permanent, irreversible, and never planned. Every subcommand takes an immutable
identity, and only one Keymaster already tracks: a stray resource belongs to
whoever made it, so `plan` reports it as unmanaged and this command refuses it.
`delete key` takes no address argument — the hash identifies the key and the
owning address is looked up rather than asserted, so one address's key cannot be
deleted by typing another's name.

**A 2xx is not the answer.** The request is sent once, the resource is read
back, and only a 404 proves it is gone. A 404 on the delete itself means it was
already absent, which is the same end state.

`delete key` additionally refuses the key an address is using and one belonging
to an unfinished operation, and never drops state ahead of the confirmation.

`delete workspace` refuses while OpenRouter shows the workspace holding any key,
guardrail, or log destination, tracked or not: deleting a workspace deletes what
is in it, and Keymaster does not destroy what it does not manage. The
workspace's own default guardrail is not an occupant — it cannot outlive the
workspace, so its binding is released with it.

`delete log-destination` is also the step that clears a destination whose `type`
or workspace has to change, since OpenRouter's `PATCH` accepts neither: the next
apply creates the destination the configuration now describes. See
[Changing a destination's type or workspace](operations.md#changing-a-destinations-type-or-workspace)
and [ADR-0006](adr/0006-log-destinations.md).

There is no `delete guardrail`, in `ops` or on the command line.

## `recover`

```sh
openrouter-keymaster recover inspect NAME
openrouter-keymaster recover resolve NAME --no-resource-created
openrouter-keymaster recover resolve NAME --leaked-hash HASH
openrouter-keymaster recover replace NAME
```

Any create or delivery that ends without an answer leaves a journal entry and
stops the whole apply. `recover` is the only way to close one, and it never
guesses: it does not retry a create, adopt a remote key because its display name
matches, or invoke a receiver a second time. Each phase accepts exactly one
command, and `inspect` ends its report by naming that command.

| Phase | What is true | What to run |
| --- | --- | --- |
| `create_started`, `create_ambiguous` | A key may or may not exist | `recover resolve`, then `plan`/`apply` |
| `created`, `secured` | The key exists; its plaintext is gone | `recover replace` |
| `delivery_started`, `delivery_ambiguous` | The receiver may or may not have committed; the plaintext is gone either way | `recover replace` |
| `delivered` | The transaction finished; only the local promotion is outstanding | `apply` |

**`inspect`** reports the operation's identifier, phase, timestamp, generation,
intended name and workspace, the hash when the journal has one, and the
receiver's non-secret fingerprint. In the two phases where a key's existence is
unknown it also lists candidate remote keys — never matches, and an empty
listing is not an all-clear. It takes no lock and writes nothing.

**`resolve`** requires exactly one attested finding; giving both is a usage
error. `--no-resource-created` clears the operation on your word, which
Keymaster cannot check. `--leaked-hash HASH` fetches that exact hash, refuses if
OpenRouter does not have it, binds it as a **failed candidate** so it stays
tracked *before* any cleanup, then disables it and confirms that by reading it
back. A found hash is never promoted to current: its plaintext was disclosed
once, in a response nobody received. Repeating a resolution that already
succeeded is a no-op.

**`replace`** checks everything the successor needs *before* it retires the dead
key, tries to disable it, and stages a successor at the next free generation,
all under one lock — the key about to be disabled may be live, and finding out
afterwards that no successor can be created would leave the address with
neither. A preflight failure writes nothing, so the operation still stands.

**Delivery ambiguity has no attestation**, so there is deliberately no
`resolve --delivered`: the only resolution is `recover replace`, which costs a
rotation even when the original delivery in fact succeeded (ADR-0002).

Runbook: [Recovering an interrupted operation](operations.md#recovering-an-interrupted-operation).

## `state forget`

```sh
openrouter-keymaster state forget keys.jobfeed
```

Relinquishes local ownership. **Zero HTTP requests and zero receiver
invocations**: nothing is disabled and nothing is deleted, so a released
resource is left however it already was, and Keymaster makes no claim that it is
still there. It needs no credential, no network, and no configuration — it
exists to correct state that is wrong, which is when those may be unavailable.

`ADDRESS` is `keys.NAME`, `guardrails.NAME`, `workspaces.NAME`, or
`log_destinations.NAME`. A bare `NAME` is accepted when only one of the four is
bound and refused when more than one is.

Forgetting a key address releases every hash it held, current and retained.
Forgetting a workspace releases the default guardrail bound to it as well: that
guardrail cannot outlive its workspace and nothing else can reach it.

**An address with an operation in progress is refused** — the journal is the
only record that the attempt happened, and in the create phases the only
evidence that a live key may exist, so close it with `recover` first. An address
bound to nothing is a clean no-op that writes no state and exits 0.

Runbook: [Giving up ownership](operations.md#giving-up-ownership).
