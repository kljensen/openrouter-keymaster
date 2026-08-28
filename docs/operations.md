# Runbooks

Ordered procedures for the things an operator does. The
[README](../README.md) explains why each command behaves the way it does; this
page is what to type, in what order, and what to check afterwards.

Every procedure assumes `OPENROUTER_MANAGEMENT_KEY` is exported for the
organization you mean to change. See
[the threat model](threat-model.md#supplying-the-credential).

- [First run](#first-run)
- [Adopting resources that already exist](#adopting-resources-that-already-exist)
- [Making a change](#making-a-change)
- [Running a workspace](#running-a-workspace)
- [Forwarding logs to a destination](#forwarding-logs-to-a-destination)
- [Scoping a run to one workspace](#scoping-a-run-to-one-workspace)
- [Creating a key](#creating-a-key)
- [Rotating a key](#rotating-a-key)
- [Ending a key's life](#ending-a-keys-life)
- [Ending a key that is not being replaced](#ending-a-key-that-is-not-being-replaced)
- [Giving up ownership](#giving-up-ownership)
- [Recovering an interrupted operation](#recovering-an-interrupted-operation)
- [Reading spend](#reading-spend)
- [Looking after state](#looking-after-state)

## First run

1. **Build it.**

   ```sh
   cargo build --release
   ./target/release/openrouter-keymaster --version
   ```

2. **Write a configuration.** Copy the example and edit it. Nothing here is
   sent anywhere yet.

   ```sh
   cp examples/openrouter-keymaster.toml openrouter-keymaster.toml
   ```

   [The configuration reference](configuration.md) is the field list. Start with
   one guardrail and no keys; keys can come after the first plan is clean.

3. **Check the file before the credential.** Validation reads this one file and
   makes no network call, so a broken configuration costs nothing:

   ```sh
   openrouter-keymaster plan
   ```

   Without a credential this fails with `missing_credential` *after* reporting
   any configuration problem, which is a fine way to check syntax.

4. **Export the credential and plan for real.**

   ```sh
   export OPENROUTER_MANAGEMENT_KEY="$(pass show openrouter/management)"
   openrouter-keymaster plan
   ```

   Read the outcome on the last line. `converged` means OpenRouter already
   matches the file — it can still list `unmanaged` resources and orphaned
   bindings, which are reports rather than work. `changes_pending` means an
   apply would write something — read every action before you run one.
   `held_back` means there is work that only you can unblock, usually an
   `adoption_required` (see below).

`plan` writes nothing: no API write, no receiver, no change to the state file,
not even when it observes drift. Run it as often as you like.

## Adopting resources that already exist

A guardrail or key that already exists in OpenRouter is invisible to Keymaster
until you bind it. Keymaster will not adopt one on its own, because a display
name is mutable and not unique — a plan reports a name match as
`adoption_required`, which is a candidate and not a decision.

1. **Find the immutable identity.** A guardrail's UUID and a key's hash, from
   the OpenRouter dashboard or API. The name is not enough and is not accepted.

2. **Describe it in the configuration.** Import refuses an address the file does
   not describe: a binding with no desired state is one no plan can act on.

3. **Bind it.**

   ```sh
   openrouter-keymaster import guardrail cheap --id 6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b
   openrouter-keymaster import key jobfeed --hash <HASH>
   openrouter-keymaster import workspace golf_club --id <UUID>
   openrouter-keymaster import log-destination club_audit --id <UUID>
   ```

4. **Read the difference it reports.** Import makes no remote write; it tells
   you what a later apply would reconcile. If that list is a surprise, the file
   is wrong or the identity is.

5. **Converge when you agree with it:** `openrouter-keymaster apply`.

Repeating an import that changes nothing writes nothing and says `unchanged`.

**An imported key can never be delivered.** Its plaintext was never Keymaster's
to hold. To put a Keymaster-delivered key at that address, raise the key's
`generation` and let a replacement be created.

## Making a change

1. Edit `openrouter-keymaster.toml`.
2. `openrouter-keymaster plan` — read every action, and read the
   `! privilege expansions` section if there is one.
3. `openrouter-keymaster apply`.
4. Check the outcome: `applied` means every write was made **and verified by a
   re-read**. `converged` means there was nothing to do. `incomplete` or
   `held_back` means work remains and the report says what is waiting on what.
   `failed` and `blocked` exit 1.
5. `openrouter-keymaster plan` again. A successful apply's successor is a no-op.

The plan you read in step 2 is never the plan that runs. Apply takes the lock,
reloads, refreshes OpenRouter, and computes the plan again — so nothing goes
stale between the two commands, and there is no plan file to save.

## Running a workspace

A workspace is the unit that carries a pooled spending cap and a default
guardrail. Keys, guardrails, and log destinations are placed in one when they
are created, and OpenRouter fixes that placement for good.

1. **Describe it, and apply once without a scope.**

   ```toml
   [workspaces.golf_club]
   name = "Golf Club"
   slug = "golf-club"
   default_guardrail = "club_house"

   # A workspace's default guardrail omits `name`: OpenRouter names that one.
   [guardrails.club_house]
   limit_usd = 10
   reset_interval = "monthly"
   ```

   ```sh
   openrouter-keymaster apply
   ```

   The workspace is created first and its UUID is recorded before anything else
   happens. Everything that names it — a key, a guardrail, a destination —
   depends on that create and runs after it in the same apply, resolving its
   placement from the binding. A workspace only an operator can bind holds its
   contents back instead.

2. **Or bind one that already exists.**

   ```sh
   openrouter-keymaster import workspace golf_club --id <UUID>
   ```

   That also records the workspace's `default_guardrail_id` and binds whichever
   guardrail block the configuration names as `default_guardrail` to it.

3. **Materialize the default guardrail** by describing that block and applying.
   Every workspace has one, derived from its UUID, and it governs all traffic in
   the workspace — but until its configuration is first written it is in no
   listing at all, and after that only in its own workspace's. So the plan
   reports it as a create carrying the reason
   `default_guardrail_unmaterialized`, and the apply performs that create as the
   first `PATCH` to the identity the workspace names. There is no `POST` for it,
   it can never be imported by name, and it is never deleted on its own.

   Its block omits `name`. OpenRouter names it `Workspace <workspace-uuid>
   Default` and refuses to change that, so the configuration has no say in it
   and the plan never reports it as drift; `openrouter-keymaster status` shows
   the name OpenRouter gave it.

4. **Set a pooled budget, if your plan has them.**

   ```toml
   budgets = { monthly = 50, lifetime = 500 }
   ```

   The table is the complete desired set: an interval OpenRouter has and the
   table does not is removed. Apply writes one request per interval, ordered so
   that no intermediate state violates OpenRouter's lifetime > monthly > weekly
   > daily rule.

   **Workspace budgets are documented as an Enterprise feature**, and were
   accepted on the account this repository has tested against. If your plan
   refuses them, the refusal is definite and names the interval, and every apply
   reports it again. While a configured budget has not converged, every write in
   that workspace the plan classifies `issuing` or `expanding` is held back — no
   new key, no enable, no raised limit — because spend under a cap that is not
   in force is exactly what the cap was for. Routine writes carry on. Removing
   the `budgets` table is the only way that configuration converges.

5. **Delete it when it is empty.**

   ```sh
   openrouter-keymaster delete workspace --id <UUID>
   ```

   Refused while OpenRouter shows the workspace holding any key, guardrail, or
   log destination — tracked or not, because Keymaster does not destroy what it
   does not manage — and the refusal lists what it found. Empty it first. The
   one exception is the workspace's own default guardrail, which is part of the
   workspace: it cannot outlive it, so its binding is released along with the
   workspace's.

   `openrouter-keymaster state forget workspaces.golf_club` gives up ownership
   without deleting anything, and releases that default guardrail's binding for
   the same reason.

**A workspace that is bound and absent is reported, never recreated.** A
guardrail may be recreated, because a guardrail is policy. A workspace is a
container: a new one would have a new UUID, and every key, guardrail, and budget
the old one held would be somewhere Keymaster can no longer reach. It is
reported as `missing`, like a missing key, and what to do about it is yours.

## Forwarding logs to a destination

A log destination is where OpenRouter forwards a workspace's request logs.

**A configuration file with one in it is a secret.** A destination's `config`
holds the sink's own credential — a Datadog API key, a webhook token — because
there is no other channel through which OpenRouter can be told what to send logs
to. Keep such a file out of version control, or encrypt it the way you would any
other secret. Keymaster protects the value inside its own process and nothing
beyond that.

1. **Describe it, naming the workspace it belongs to.**

   ```toml
   [log_destinations.club_audit]
   type = "datadog"
   name = "Golf Club audit log"
   workspace = "golf_club"
   config = { site = "datadoghq.com", apiKey = "…" }
   ```

2. **Apply.** The destination is created, its UUID is recorded, `config` is
   written once, and a digest of what was written is recorded with it. A
   destination is created after the `workspace` block it names — in the same
   apply when this run creates that workspace, and held back while only an
   operator can bind it — exactly as a key would be.

3. **Change it.** Everything except `type` and the workspace is an ordinary
   patch. `config` travels only when its digest changed, because OpenRouter
   masks it on read and there is nothing to compare against; the plan then says
   `config` and nothing else — never what changed, and never either value. Apply
   does not read `config` back. It verifies every other field as usual and takes
   the `2xx` as the configuration having landed, which is the only evidence the
   API offers, so an out-of-band edit in the dashboard stays invisible until the
   configured value changes.

4. **Bind one that already exists.**

   ```sh
   openrouter-keymaster import log-destination club_audit --id <UUID>
   ```

   No digest is recorded, because a read cannot see `config`. Whatever
   configuration the destination already has stays in force until the next apply
   writes the configured one and records its digest from then on.

5. **Delete it.**

   ```sh
   openrouter-keymaster delete log-destination --id <UUID>
   ```

   One `DELETE`, sent once, confirmed by a 404. Nothing is forwarded through
   that destination from then on. `state forget log_destinations.club_audit`
   gives up ownership instead, leaving the destination forwarding.

**The key allowlist is managed as always empty**, so a destination forwards
every key in its workspace and an allowlist OpenRouter holds is drift the next
apply clears. `filter_rules` and the `broadcast_*` flags are not modelled at
all, so whatever you set in the dashboard is preserved.

### Changing a destination's type or workspace

Both are fixed when the destination is created — OpenRouter's `PATCH` accepts
neither — and Keymaster never replaces a destination on its own, because that
would stop and restart log forwarding without being asked. So a plan that finds
either changed holds the drift back, names the field, and names this procedure.

1. **Read the plan.** The action is a `no_op` carrying the reason
   `destination_fixed_at_creation`, with the field and the destination's UUID.

2. **Delete the destination:**

   ```sh
   openrouter-keymaster delete log-destination --id <UUID>
   ```

   One `DELETE`, sent once, confirmed by a 404 on the read that follows. Only
   then does the binding stop being yours. Nothing is forwarded through that
   destination from this point on.

3. **Apply.** The next `openrouter-keymaster apply` creates the destination the
   configuration now describes, writes its `config`, and records the digest.

## Scoping a run to one workspace

`--workspace UUID` names the one workspace a run places resources in and reports
on. It is what a host running one club per operation sets, and it is a guard on
placement and a filter on noise — not an isolation mechanism.

**Apply unscoped once, or import; scope from then on.** A scoped run refuses a
`[workspaces.NAME]` block that is not already bound to the scope, because the
UUID `POST /workspaces` returns could never be the one the run was scoped to. So
the order is fixed:

```sh
openrouter-keymaster apply                        # creates the workspace
openrouter-keymaster --workspace <UUID> apply     # everything after that
```

or, for a workspace that already exists:

```sh
openrouter-keymaster import workspace golf_club --id <UUID>
openrouter-keymaster --workspace <UUID> apply
```

A scoped run also refuses a key, guardrail, or log destination whose workspace
resolves anywhere else, before it has built a client or sent a request. Reports
leave out `unmanaged` resources in other workspaces, and matching by *name* —
adoption candidates, the collision check before a recreation — considers only
resources in the scope, so another club's identically named key cannot block
this one.

**It does not isolate.** The snapshot is still the whole organization, so a
bound resource is judged present or missing exactly as it is without a scope,
and two scopes pointed at one state file produce correct but mixed plans. One
configuration and one state file per club is what keeps them apart.

## Creating a key

This is the one operation that cannot be repeated safely, so do it
deliberately. [ADR-0002](adr/0002-journaled-key-creation.md) is the protocol.

1. **Have a receiver, and test it first.** A key whose configuration names no
   receiver is never created — there is no fallback, and Keymaster will not
   print a key. For a command receiver, run your adapter by hand against a fake
   envelope before a real key is on the line; see
   [the receiver protocol](receiver-protocol.md#testing-an-adapter).

2. **Add the key block**, naming its guardrail and its receiver. Give it a
   `limit_usd`. Consider `disabled = true` for the first create: the key is born
   enabled and disabled by the update that follows, so a key you are not ready
   to use is off from the first moment anything could reach it.

3. **Plan.** The action is classified `issuing`, the loudest safety class.

   ```sh
   openrouter-keymaster plan
   ```

4. **Apply.** Do it interactively, on a machine you are watching, with the
   receiver's destination reachable.

   ```sh
   openrouter-keymaster apply
   ```

5. **Confirm the destination.** Keymaster verified the key's budget and
   guardrail before delivery and verified the receiver's acknowledgement, but
   whether the thing that reads from that destination picked it up is yours to
   check.

If the run does not finish cleanly, stop and go to
[Recovering an interrupted operation](#recovering-an-interrupted-operation). Do
not re-run `apply` hoping it sorts itself out — it will refuse, which is the
point.

## Rotating a key

```sh
openrouter-keymaster rotate jobfeed
```

Rotation stages a successor and stops. **The predecessor is not touched**: not
disabled, not deleted, not unassigned. Ending its life is a separate command you
run when you know the consumer has moved.

`apply` stages the same replacement by itself when `generation` rises, when the
receiver or its fingerprint changes, or when an immutable field changes
(`expires_at`, `workspace_id`, `creator_user_id`).

Afterwards:

```sh
openrouter-keymaster status          # the address now holds a current hash and a retained one
```

A rotation that fails at any phase leaves the working credential working. What
to do next depends on how far it got, and **"rotate again" is usually not it** —
a rotation that began the journaled transaction leaves an operation behind, and
`rotate` refuses to stage a successor beside one.

- **A preflight failure changes nothing.** The address owns no key, the
  configuration no longer names a receiver, the guardrail is not converged: all
  of these are checked before anything is sent, so nothing was journaled. Fix
  what it named and rotate again.
- **A failure after that leaves an operation.** `rotate` will refuse, naming the
  address that holds it and the phase. Ask what that phase accepts:

  ```sh
  openrouter-keymaster recover inspect jobfeed
  ```

  Its last line names the one command for that phase — that is the mechanism,
  and it is better than guessing from a table. In practice: an ambiguous create
  needs `recover resolve` and then `recover replace`; a create that succeeded
  but whose delivery did not needs `recover replace`; and `delivered` needs no
  operator at all, because only a local promotion is left and the next
  `openrouter-keymaster apply` records it.

Either way Keymaster neither disabled nor deleted the predecessor.
[Recovering an interrupted operation](#recovering-an-interrupted-operation) is
the full procedure.

## Ending a key's life

Only after every consumer has the new credential. That judgement is yours;
Keymaster has no way to make it.

```sh
openrouter-keymaster status                                   # find the retained hash
openrouter-keymaster retire jobfeed --hash <PREDECESSOR-HASH> # disable, confirmed by a read
```

Then, once you are sure nothing needs it back:

```sh
openrouter-keymaster delete key --hash <PREDECESSOR-HASH>     # permanent, confirmed by a 404
```

- `retire` refuses the **current** hash. Rotate first, or end it with
  [`decommission`](#ending-a-key-that-is-not-being-replaced) if there is to be
  no successor.
- `retire` on an already-disabled key reads it, writes nothing, and reports
  `retired`.
- `delete key` refuses a hash Keymaster does not track, the hash an address is
  using, and one belonging to an unfinished operation.
- A failed retire or delete leaves the hash tracked as `retirement_failed` and
  exits 1, so you can retry it. State is never dropped ahead of the
  confirmation: the local record is the one thing that can still find a live
  spending credential.

## Ending a key that is not being replaced

`retire` and `delete key` refuse the key an address is *using*, and rotation
always issues a successor, so a key you simply want to stop having needs its own
command:

```sh
openrouter-keymaster status                                  # find the current hash
openrouter-keymaster decommission jobfeed --hash <CURRENT-HASH>
```

That reads the key, disables it, reads it back to prove it, and moves the hash
from `current` to `retained.retired`. The address is then bound and owns no key.
Add `--delete` to continue into the deletion in the same run, or run
`openrouter-keymaster delete key --hash <HASH>` later — the hash is retained
now, so that command will take it.

**Decide what happens to the configuration before you run it.** The address
owning no key is exactly the shape `apply` treats as "not created yet":

```sh
openrouter-keymaster plan   # keys.jobfeed: create
```

- If you meant to stop having this key, remove the `[keys.jobfeed]` block. The
  binding becomes an `orphaned_binding` — reported, tracked, left alone — and
  `openrouter-keymaster state forget keys.jobfeed` relinquishes it once the hash
  is deleted or you no longer care to track it.
- If you meant to hand this address a fresh credential with no overlap, leave
  the block. The next `apply` creates a real key at the next generation and
  delivers it to the receiver. The old number is spent for good, deleted or not.

Each step exits 1 if a read did not prove it, and nothing is retried
automatically:

- **A disable that is not confirmed changes nothing at all.** The address goes
  on using the key, which is the truth while the key may still work. The
  diagnostic names the exact command to run again.
- **A delete that is not confirmed leaves the hash tracked** as
  `retirement_failed`, and `openrouter-keymaster delete key --hash <HASH>`
  retries it.
- **An operation in progress anywhere refuses the run**, naming the command that
  clears it. Nothing is disabled and nothing is deleted.

## Giving up ownership

```sh
openrouter-keymaster state forget keys.jobfeed
openrouter-keymaster state forget guardrails.cheap
openrouter-keymaster state forget workspaces.golf_club
openrouter-keymaster state forget log_destinations.club_audit
```

Zero HTTP requests, zero receiver invocations, no configuration and no
credential needed — it exists to correct state that is wrong, which is exactly
when those may be unavailable. Nothing it releases is disabled or deleted, and
nothing is read either: a later `plan` is what says which of them OpenRouter
still has, reported as `unmanaged`.

Forgetting a key address releases **every** hash it held, current and retained.
The result document lists each one before it stops being yours.

Removing a `[keys.*]` block from the configuration does none of this. That
becomes an `orphaned_binding`: reported, tracked, and otherwise left alone.

## Recovering an interrupted operation

Any create or delivery that ends without an answer leaves a journal entry, stops
the whole apply, and needs you. Keymaster will not retry a create, adopt a key
by name, or invoke a receiver twice.

### 1. Inspect

```sh
openrouter-keymaster recover inspect jobfeed
```

You get the operation ID, the phase it stopped in, its timestamp, the intended
name and workspace, the hash if the journal recorded one, and the receiver's
non-secret fingerprint. The last line names the one command that phase accepts.

Inspect takes no lock and writes nothing. Once the journal holds a hash it makes
no API call at all, so it works with no credential.

### 2. Choose a path by phase

| Phase | What is true | What to do |
| --- | --- | --- |
| `create_started`, `create_ambiguous` | A key may or may not exist. Nobody knows. | [Resolve the ambiguity](#3-resolve-a-create-ambiguity), then replace. |
| `created`, `secured` | The key exists and its plaintext is gone for good. | [Replace it](#4-replace). |
| `delivery_started`, `delivery_ambiguous` | The receiver may or may not have committed. The plaintext is gone either way. | [Replace it](#4-replace). |
| `delivered` | The transaction finished; only the local promotion is outstanding. | Run `openrouter-keymaster apply`. It completes the promotion under its own lock and says so. |

### 3. Resolve a create ambiguity

**Go and look at OpenRouter yourself.** The dashboard or the API, filtered to
the workspace the attempt named, around the timestamp `inspect` reported.
`inspect` lists candidates for you, but they are candidates: keys no local
address owns, in that workspace, carrying the intended name or created within an
hour of the attempt. Keymaster will not choose one, and an empty list is not an
all-clear.

Then tell it exactly one of two things:

```sh
# You looked, and nothing was created.
openrouter-keymaster recover resolve jobfeed --no-resource-created

# You looked, and this is the key it made.
openrouter-keymaster recover resolve jobfeed --leaked-hash <HASH>
```

`--no-resource-created` clears the operation **on your word**. Keymaster cannot
check it. An attestation that is wrong leaves a live key nothing tracks.

`--leaked-hash` fetches that exact hash, refuses if OpenRouter does not have it,
binds it as a failed candidate so it stays tracked *before* any cleanup, then
disables it and confirms that by reading it back. A confirmed disable records it
as `retired`; anything else leaves it a failed candidate for a later explicit
`retire` or `delete key`. It is never promoted to current — its plaintext was
disclosed once, in a response nobody received.

Repeating a resolution that already succeeded is a no-op, not an error.

### 4. Replace

```sh
openrouter-keymaster recover replace jobfeed
```

Under one lock it checks everything the successor needs first — the key is
configured, a receiver is named, the guardrail is bound and converged — and only
then retires the dead key into `retained`, tries to disable it, and stages a
successor through the same journaled transaction. A preflight failure writes
nothing and sends no write, so the operation still stands and you can retry once
the configuration is fixed.

It is refused from `create_started` and `create_ambiguous` — resolve those
first — and from `delivered`, which the next `apply` finishes by itself.

### Delivery ambiguity has no attestation

There is deliberately no `resolve --delivered`. ADR-0002 permits resolving a
lost acknowledgement as delivered only through a receiver contract that accepts
the operation ID and can be asked authoritatively whether it committed, and v0.1
defines no such contract. So a `delivery_ambiguous` costs a replacement even
when the original delivery in fact succeeded. Replace the key, then clean up
whatever the receiver's destination now holds.

## Reading spend

`openrouter-keymaster spend` is read-only in the strictest sense: three
requests, no lock, no state write, nothing changed remotely.

```sh
# The default: the last thirty days, one row per key, one bucket per day.
openrouter-keymaster spend

# A named range and coarser buckets, as JSON for a dashboard.
openrouter-keymaster spend \
  --since 2026-08-01T00:00:00Z --until 2026-09-01T00:00:00Z \
  --granularity week --json
```

What to check in the output:

1. **`credits`** is the organization's lifetime balance — purchased, used, and
   what is left. It comes from `GET /credits` and has nothing to do with the
   range.
2. **`columns`** names the metric and dimension the numbers came from. They are
   discovered per organization from `GET /analytics/meta` — OpenRouter's
   specification names none of them — so quoting them is how a report says what
   it measured. Ordinarily they are:

   - `total_usage` for cost: the whole cost of the traffic in dollars, which is
     credit-paid inference plus the credit-equivalent of BYOK usage and its
     fees. It is **not** the same as the credit balance moving: `credits_usage`
     is that narrower number, and is used only when an organization does not
     offer `total_usage`.
   - `tokens_total` for tokens: prompt plus completion. The per-direction
     metrics (`tokens_prompt`, `tokens_completion`, `reasoning_tokens`,
     `cached_tokens`) are not read.
   - `api_key_id` for the grouping.
3. **`rows`** is one entry per key, with a total and one period per bucket. The
   `key` field is **OpenRouter's own display name for the key, not its hash** —
   the api-key dimension is enriched, so a grouped query answers with the label.

   An entry therefore usually carries no `address`, and that is **not** evidence
   of an unmanaged key: an address is attached only in the rare case where the
   returned value happens to be a hash some local address tracks. Match a row to
   a local address by the display name you gave the key, and use
   `openrouter-keymaster status` for the question "what does Keymaster own".
4. **`warnings`** — on stderr in a human run — carry a truncated answer, a
   scope that could not be filtered on, and anything OpenRouter said about the
   query itself. A truncated answer means the rows are incomplete: narrow the
   range or use a coarser granularity and run it again.

Three failures are worth recognising:

- `invalid_response` naming a cost metric, a token metric, or an api-key
  dimension means this organization's analytics lists none of the spellings
  Keymaster knows. Nothing was queried. Read the vocabulary yourself and compare
  it with the names in the error, then open an issue; there is no flag that
  forces a name.

  ```sh
  curl -s https://openrouter.ai/api/v1/analytics/meta \
    -H "Authorization: Bearer $OPENROUTER_MANAGEMENT_KEY" | jq '.data.metrics[].name'
  ```
- `invalid_response` naming a metric field — `tokens_total`, say — means a row
  carried that metric as something Keymaster cannot read as a number. Integral
  metrics arrive quoted and fractional ones do not, and both are accepted; a
  value that is neither fails the run rather than reporting a zero beside a real
  cost. Capture the row and open an issue.
- A scoped run (`--workspace UUID`) whose warning says the report covers the
  whole organization means the analytics API offered no `workspace` dimension to
  filter on. The numbers are real, but they are the organization's.

Spend needs no configuration file and reads state only to attach addresses, so
it is safe to run against a directory whose configuration is mid-edit.

## Looking after state

State lives in `.openrouter-keymaster/state.json` unless `--state` says
otherwise, in a `0700` directory as a `0600` file.

**Back it up.** This is the one operational duty Keymaster puts on you. State
binds each local address to an immutable remote identity, and a display name
cannot recover that binding. Losing it means re-importing every managed resource
by its hash or UUID, and re-discovering every hash from the dashboard.

```sh
cp .openrouter-keymaster/state.json backups/state-$(date -u +%Y%m%dT%H%M%SZ).json
```

Back it up after every `apply`, `rotate`, `retire`, `decommission`,
`delete key`, `import`, and `recover`. It contains no secret, so it can go anywhere your configuration can.

### Restoring state

Copying the file back is the first step, not the whole procedure. A restored
state is *behind reality*: it can still call a rotated predecessor current, and
it knows nothing about a key created after the backup was taken. The job is to
re-establish the correct binding for each address by immutable identity.
Rotation is not that job — a rotation mints a *new* credential and leaves the
one the backup missed unowned, which is the opposite of what you want.

1. **Restore the file and see what it thinks it owns.**

   ```sh
   cp backups/state-20260824T120000Z.json .openrouter-keymaster/state.json
   openrouter-keymaster status --json > /tmp/claimed.json
   ```

2. **Inventory what actually exists.** `openrouter-keymaster plan` lists every
   remote key and guardrail no local address owns as `unmanaged`, with its hash
   or UUID — that listing is the inventory, and the OpenRouter dashboard is the
   cross-check for anything the credential cannot see.

   ```sh
   openrouter-keymaster plan --json > /tmp/observed.json
   ```

3. **Reconcile the two, address by address.** For each address, decide which
   remote identity it should own. Creation time, workspace, and display name are
   evidence for that decision; none of them is authority, which is why nothing
   automates this step.

4. **Rebind by immutable identity.**

   - An address whose binding survived and is still correct needs nothing.
   - An address bound to a *stale* identity — the backup's predecessor, where a
     rotation has happened since — must first release what it holds, then take
     the right one:

     ```sh
     openrouter-keymaster state forget keys.jobfeed
     openrouter-keymaster import key jobfeed --hash <CURRENT-HASH>
     ```

     `state forget` performs no remote write, so the key keeps working
     throughout.

     **The predecessor cannot be brought back at that address.** Once the
     address is bound to the current hash, a second `import key` at it is
     refused: one address, one key. Nor can it become a retained entry there —
     only a rotation's promotion ever creates one, by moving the hash it just
     replaced, and nothing reconstructs that from the outside.

     It can still be ended with Keymaster, at a spare address, where it lands
     as that address's own current key:

     ```sh
     # A temporary [keys.jobfeed-old] block with no receiver, so that even a
     # forgotten one can never cause a create.
     openrouter-keymaster import key jobfeed-old --hash <PREDECESSOR-HASH>
     openrouter-keymaster decommission jobfeed-old --hash <PREDECESSOR-HASH> --delete
     openrouter-keymaster state forget keys.jobfeed-old
     ```

     Then remove the temporary block. `openrouter-keymaster plan` reports the
     predecessor as `unmanaged` until something ends it, so it stays visible
     rather than forgotten.
   - An address the backup never knew about is a plain import:

     ```sh
     openrouter-keymaster import guardrail cheap --id <UUID>
     openrouter-keymaster import key newer --hash <HASH>
     ```

5. **Reconcile.** `openrouter-keymaster plan` until nothing is `unmanaged` that
   should be owned and nothing is `adoption_required`, then
   `openrouter-keymaster apply`.

**Rotate only when identity genuinely cannot be established** — when you cannot
tell which of several keys an address holds, or the key it held is gone. Then
the address has no working credential to protect and a fresh one is the answer.

An imported key cannot be delivered to a receiver; its plaintext was never
Keymaster's. If the consumer already has the credential, that is fine — the
binding is what was lost, not the secret.

**One writer.** Every writing command creates `<state>.lock` and fails
immediately if it is already there, naming the file, rather than waiting. A
killed run leaves it behind; deleting it is safe once no Keymaster is running:

```sh
pgrep -f 'openrouter-keymaster' || rm .openrouter-keymaster/state.json.lock
```

The lock is a local file. It does not coordinate two machines — nothing stops
two operators applying against the same organization at once, and v0.1 does not
try to ([ADR-0001](adr/0001-native-reconciliation.md)). If more than one person
runs Keymaster, run it from one place.

**Do not edit it by hand.** State carries a schema version and a serial, and
rejects impossible lifecycle combinations. `state forget` is the supported way
to change what it owns.
