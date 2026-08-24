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
- [Creating a key](#creating-a-key)
- [Rotating a key](#rotating-a-key)
- [Ending a key's life](#ending-a-keys-life)
- [Giving up ownership](#giving-up-ownership)
- [Recovering an interrupted operation](#recovering-an-interrupted-operation)
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

- `retire` refuses the **current** hash. Rotate first.
- `retire` on an already-disabled key reads it, writes nothing, and reports
  `retired`.
- `delete key` refuses a hash Keymaster does not track, the hash an address is
  using, and one belonging to an unfinished operation.
- A failed retire or delete leaves the hash tracked as `retirement_failed` and
  exits 1, so you can retry it. State is never dropped ahead of the
  confirmation: the local record is the one thing that can still find a live
  spending credential.

## Giving up ownership

```sh
openrouter-keymaster state forget keys.jobfeed
openrouter-keymaster state forget guardrails.cheap
```

Zero HTTP requests, zero receiver invocations, no configuration and no
credential needed — it exists to correct state that is wrong, which is exactly
when those may be unavailable. Everything it releases goes on existing; a later
`plan` reports it as `unmanaged`.

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

Back it up after every `apply`, `rotate`, `retire`, `delete key`, `import`, and
`recover`. It contains no secret, so it can go anywhere your configuration can.

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

     **The predecessor cannot be brought back under management.** Once the
     address is bound to the current hash, a second `import key` at it is
     refused: one address, one key. Importing the predecessor at a spare
     address does not help either — it would land there as *that* address's
     current key, and both `retire` and `delete key` refuse a current hash.
     This is a real v0.1 limitation, and it follows from where retained
     entries come from: only a rotation's promotion ever creates one, by
     moving the hash it just replaced. Nothing reconstructs that from the
     outside. Disable and delete the old key in the OpenRouter dashboard
     instead. `openrouter-keymaster plan` reports it as `unmanaged` until you
     do, so it stays visible rather than forgotten.
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
