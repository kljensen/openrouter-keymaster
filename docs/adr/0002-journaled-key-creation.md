# ADR-0002: Journaled key creation and delivery

- **Date:** 2026-08-23
- **Status:** Accepted

Accepted through automated code review of the commit that introduces it. This
repository currently has a single maintainer committing directly to `main`, so
that review stands in for a second human reviewer; see
[the ADR convention](README.md#review).

Accepted before any write-capable key creation is merged.

## Context

ADR-0001 established that Keymaster reconciles declaratively against stored
remote identity. Creating an inference key is the one operation that model
cannot make repeatable, because of two properties of the OpenRouter API:

- `POST /keys` returns the key's plaintext in the create response and nowhere
  else. There is no endpoint that reads it back.
- No client idempotency token is documented. Keymaster cannot ask the API
  whether a request it already sent was applied, and cannot make a resend
  collapse into the first attempt.

Two distinct failures follow. A request that succeeds on the server while its
response is lost creates a live key that no local record names — a spending
credential belonging to nobody, without its guardrail, and capped only if the
create request itself carried a limit. A process that dies after parsing the
response but before the secret reaches its destination destroys the plaintext
permanently, leaving a key that exists, is tracked, and can never be used.

These are different problems and they need different handling. The first must
never be resolved by guessing; the second must never be resolved by pretending
the secret can be recovered.

## Decision

Key creation is a journaled, one-at-a-time transaction. Every state transition
below is persisted durably and atomically. Intent markers — `create_started`
and `delivery_started` — are persisted before the non-idempotent action they
announce. Outcome phases — `created`, `secured`, `delivered`, and the two
ambiguous phases — are persisted after the result they record is known.

```text
create_started
create_started -> create_ambiguous | created
created        -> secured
secured        -> delivery_started
delivery_started -> delivery_ambiguous | delivered
delivery_started -> secured (definite rejection; see below)
delivered      -> promoted current
```

The old current hash remains enabled and tracked until an explicit retirement
operation. Rotation never disables or deletes a predecessor.

### Journal before the request

The durable `create_started` transition — carrying an operation ID, generation,
timestamp, intended name and workspace, and a non-secret receiver fingerprint —
must be persisted successfully before any `POST /keys` is sent. If that write
fails, the POST is not sent and the run stops. The journal entry is what makes
an unacknowledged attempt visible on the next run; writing it after the request
would leave exactly the window this ADR exists to close.

### Classify the create outcome

The response is classified into one of three categories, and only one of them
is a definite negative:

- **Definite rejection.** A well-formed 4xx that states the request was not
  applied — malformed body, authentication or authorization failure, validation
  error. The server processed the request and declined it, so no key exists.
  Keymaster clears the pending attempt and reports the error.
- **Definite success.** A well-formed success response containing a usable key
  hash and plaintext.
- **Ambiguous.** Everything else: a request timeout, a connection reset or
  close before the response completed, any 5xx, a success status with a body
  that is missing, malformed, or missing the hash, and — importantly — a valid
  success response that Keymaster failed to persist. In every one of these the
  server may or may not have created a key.

Ambiguity is never resolved by inference. Keymaster persists
`create_ambiguous`, stops the entire apply, and requires an explicit operator
recovery decision. It does not send a second `POST /keys`, and it does not
search for a key by display name and adopt it.

Note that 429 and 5xx are retryable for safe reads, but not here: `POST /keys`
is never retried under any circumstance.

### Persist the hash before anything else

On a definite success the returned hash is persisted as `created` before any
follow-up call — before the update-only PATCH that applies restrictions, before
the guardrail assignment, and before the receiver is invoked. Until that write
lands, the process holds the only record that the key exists. If persisting the
hash fails, the outcome is ambiguous and is journaled as such, because a key
now exists whose identity may be lost.

### Secure before delivering

After the hash is durable, Keymaster applies the desired restrictions and the
guardrail assignment, then refetches and verifies both. Only then does it
persist `secured`. The receiver cannot be invoked before `secured`, so a
plaintext key never leaves the process until its budget and guardrail are
confirmed active. If verification fails, Keymaster attempts to disable the key,
keeps it tracked either way, and stops.

### Deliver at most once

Keymaster persists `delivery_started`, invokes the configured receiver exactly
once, and classifies the acknowledgement as success, definite rejection, or
ambiguous. Ambiguous is the default: a timeout, a signal, a lost process
status, a broken pipe, and an ordinary nonzero exit after the envelope was
written are all `delivery_ambiguous`. A nonzero exit counts as a definite
rejection only when the receiver's documented contract guarantees that no
commit occurred; absent that guarantee, an exit code says nothing about what
the receiver already wrote.

Receiver invocation is **at-most-once**: an ambiguous acknowledgement is
journaled as `delivery_ambiguous` and never retried automatically. A receiver
may have committed the secret before the acknowledgement was lost, and
re-invoking it could write a stale or duplicate secret to a live destination.

The single exception: a receiver that exposes an explicit idempotency or query
contract — one that accepts the operation ID and can be asked authoritatively
whether that operation committed — may have its ambiguity resolved through that
contract. Absent such a contract, `delivery_ambiguous` is resolved only by
replacing the key.

A **definite rejection** needs no new phase. Nothing was committed, so the
plaintext is dead and the key is useless. Keymaster attempts to disable the key,
records whether that disable succeeded, keeps the hash tracked either way, and
returns the operation to `secured`. It reports the rejection and stops. On the
next run `secured` means what it always means — the key can never be delivered —
so the plan reports that this address requires replacement, and a key whose
disable failed stays tracked for retry. Keymaster does not re-invoke the
receiver, and it cannot, because the plaintext is gone.

After a definite delivery success Keymaster persists `delivered`, promotes the
new hash to current, moves any previous current hash to
`retained.awaiting_retirement`, and refetches final non-secret state.

Plaintext exists only in memory between response parsing and receiver
completion, and is zeroized and dropped as early as practical. It is never
written to state, logs, stdout, stderr, JSON output, argv, environment
variables, or temporary files, and it is never printed as a recovery mechanism.

### Process interruption

Because the intent phase is durable before each non-idempotent action, an
interruption at any point leaves a phase on disk that the next run can read.
That phase identifies which action was interrupted; it does not say whether the
action took effect. Every phase has one defined next-run behavior:

| Interrupted | On-disk phase | Next run |
| --- | --- | --- |
| Before the `create_started` write completes | none | Nothing happened. Ordinary planning; a create may be proposed. |
| After `create_started`, before or during the POST | `create_started` | Indistinguishable from a lost response. Treated as ambiguous: `recovery_required`, no retry. |
| After the POST, before the hash is persisted | `create_started` | Same. A key may exist; the operator must resolve it. |
| After the hash is persisted | `created` | Key identity is known, plaintext is gone. Restrictions can still be verified, but delivery is impossible: the key must be disabled/retired and replaced. |
| After restrictions are verified | `secured` | Same as `created` — plaintext is gone, replacement required. |
| After `delivery_started`, before acknowledgement | `delivery_started` | Delivery may or may not have committed. Ambiguous; resolved only by the receiver's query contract or by replacement. |
| After the receiver acknowledged success, before `delivered` persists | `delivery_started` | Indistinguishable from the row above, so delivery is treated as ambiguous even though it in fact succeeded. Without a receiver query contract this costs a replacement. |
| After `delivered`, before promotion | `delivered` | Safe to complete: promotion is a local state operation with no external effect. |

`create_started` and `create_ambiguous` are the same situation from the
recovery command's point of view; the distinction is only whether Keymaster got
to record a classification before it stopped. Any incomplete create or delivery
makes the whole apply stop, and the next plan reports `recovery_required`
rather than proposing a create.

### Recovery is explicit, and a found hash is not a recovered key

Recovery is operator-driven. The operator inspects OpenRouter externally, then
either attests that no resource was created — which clears the ambiguity — or
supplies the exact leaked hash they found. Keymaster lists candidates created
near the attempt time when it can, but labels them candidates and never selects
one automatically.

Supplying a leaked hash binds it as a failed, retained candidate so it can be
disabled, verified, and eventually deleted; because OpenRouter returns plaintext
only in the create response, the hash identifies the key for cleanup and can
never recover its secret. Remediation for any lost plaintext is always to create
a replacement.

## Consequences

An unacknowledged create is never silent. The journal holds intent metadata —
operation ID, timestamp, intended name and workspace — but not the hash, which
was lost with the response, so it cannot guarantee that an orphaned key can be
found or identified. What it guarantees is that the failed attempt is visible on
the next run and forces explicit recovery, instead of leaving no trace at all.

A key is never delivered before its budget and guardrail are verified, so a
failed delivery leaves a budgeted, guardrailed key that Keymaster then tries to
disable and keeps tracked — not an unrestricted credential in the wild.

A failed rotation does not revoke anything. The predecessor stays enabled until
an explicit `retire`, so a replacement that fails at any phase leaves the
already-delivered credential working and its consumers untouched. Keymaster
cannot promise more than that: whether the consumer stays up also depends on
the receiver and the deployment that reads from it.

Negative consequences:

- **Ambiguity halts the run and requires a human.** Any timeout or 5xx on
  create stops the entire apply, including unrelated pending work, until an
  operator inspects OpenRouter and resolves it. Keymaster cannot be run
  unattended on a schedule, and a flaky network turns into operational toil.
  This is deliberate — the alternative is silently accumulating orphaned
  credentials — but it is a real cost.
- **Recovery requires access Keymaster does not have.** Resolving a
  `create_ambiguous` means the operator looking at the OpenRouter dashboard or
  API themselves and attesting to what they see. Keymaster cannot verify that
  attestation. An operator who attests wrongly leaves a live orphaned key.
- **A crash between the create response and delivery destroys a working key.**
  The key exists and is tracked, but its plaintext is gone for good. There is
  no mitigation; the window can only be made small, not closed.
- **Delivery ambiguity usually costs a rotation.** Without a receiver
  idempotency contract, the only safe resolution is to create a replacement key
  and deliver it, even though the original delivery may well have succeeded.
- **Every phase costs a durable write.** Creating one key involves several
  fsync-and-rename cycles and a verification read pass, and creates are
  sequential rather than batched.

## Alternatives considered

**Crossplane-style creation annotations.** Crossplane writes a
`crossplane.io/external-create-pending` annotation with a timestamp before
calling a provider's Create, then records `external-create-succeeded` or
`external-create-failed` after. If a controller
observes a pending annotation with no matching resource, it refuses to create
again and surfaces the conflict. This is the closest existing model and
Keymaster's journal is essentially the same idea; what differs is what happens
next. Crossplane can eventually reconcile because its managed resources are
readable after creation — the controller can list, find the created object by
its external name, and adopt it. An OpenRouter key created by a lost request
cannot be recognized: the only stable identifier is the hash, which came back
in the response we lost, and matching on the display name is exactly what
ADR-0001 forbids. So Keymaster adopts the pre-write marker and rejects the
automatic reconciliation that follows it, requiring explicit operator
resolution instead. Keymaster also journals more phases, because delivery of a
one-time secret has no equivalent in Crossplane's model.

**AWS Secrets Manager pending/current/previous rotation.** Secrets Manager
stages a new secret version with an `AWSPENDING` label, tests it, then atomically
moves `AWSCURRENT` to it and demotes the old version to `AWSPREVIOUS`, keeping
it usable. Keymaster's `delivered -> promoted current` transition and its
retained-predecessor rule are taken directly from this: staged creation,
verification before promotion, and a predecessor that stays live until
explicitly retired. What Keymaster cannot take is the durability model.
Secrets Manager holds the secret material itself, so a failed rotation step can
be retried against a stored `AWSPENDING` version and the label move is atomic
inside one service. Keymaster's plaintext exists only in process memory for a
few seconds and its "promotion" spans two independent systems — OpenRouter and
whatever the receiver writes to — with no shared transaction. So the staging
shape carries over and the retry semantics do not.

**Blind retry on ambiguity.** Resend `POST /keys` after a timeout or 5xx, as
one would for an idempotent read. Rejected outright. Without an idempotency
token, every resend that follows a request the server actually applied creates
a second live key with a full budget that no local record names, and repeated
retries multiply it. The failure is silent, it costs real money, and it is
undetectable without an out-of-band audit of the organization. No amount of
retry-budget tuning makes this safe; the operation is simply not idempotent.

**Delete-before-create rotation.** Delete the old key first, then create the
replacement, so there is only ever one key per address and no retained
predecessor to track. Simpler state, no retirement command, no bookkeeping.
Rejected because it converts every rotation failure into an outage: if the
create fails, is ambiguous, or the delivery fails, the consumer has already
lost its working credential and Keymaster cannot give it back. It also removes
the evidence needed to diagnose a rotation — the old hash is gone — and makes
the destructive step happen first, which is the wrong order for an operation
that can be interrupted at any point.

## References

- OpenRouter one-time key response: https://openrouter.ai/docs/api/api-reference/api-keys/create-keys
- Crossplane creation annotations: https://docs.crossplane.io/v1.20/concepts/managed-resources/#creation-annotations
- AWS Secrets Manager rotation: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html
- [ADR-0001](0001-native-reconciliation.md) — the reconciliation model and
  identity rules this protocol depends on.

### Implementation checks

These checks do not exist yet. This decision will be enforced by:

- [#10](https://github.com/kljensen/openrouter-keymaster/issues/10) — state
  transition functions enforcing legal phase ordering, plus durability
  fault-injection tests.
- [#15](https://github.com/kljensen/openrouter-keymaster/issues/15) and
  [#18](https://github.com/kljensen/openrouter-keymaster/issues/18) — receiver
  outcome categories distinguishing definite success, definite rejection, and
  ambiguous acknowledgement, with no automatic retry.
- [#16](https://github.com/kljensen/openrouter-keymaster/issues/16) — the
  journaled create transaction. Tests will enforce zero POSTs after a failed
  pre-create state write, exactly one POST on connection loss, timeout, 500,
  and malformed success, hash durability before any follow-up call, delivery
  only after verified restrictions, and crash injection immediately before and
  after every durable phase.
- [#17](https://github.com/kljensen/openrouter-keymaster/issues/17) — explicit
  recovery, enforcing that no path sends a second create or receiver call and
  that a found hash is never promoted as delivered.
- [#19](https://github.com/kljensen/openrouter-keymaster/issues/19) — staged
  rotation, enforcing that promotion happens only after verified delivery and
  that the predecessor stays enabled until explicit retirement.
