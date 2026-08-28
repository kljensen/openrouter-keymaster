# ADR-0005: The caller receiver

- **Date:** 2026-08-27
- **Status:** Accepted

Accepted on 2026-08-27, through automated code review of the commit that
implements it. This repository currently has a single maintainer committing
directly to `main`, so that review stands in for a second human reviewer; see
[the ADR convention](README.md#review).

## Context

ADR-0002 delivers a new key's plaintext through a `SecretReceiver` exactly
once. The two receivers write a file or run a program. A web host that issues
keys needs the plaintext in memory, once, to show it to a user or forward it to
a store the host controls. ADR-0003 deferred host-defined receiver kinds; this
is the first and only one needed.

## Decision

1. **A `caller` receiver hands the plaintext to the host.**
   `[receivers.NAME] type = "caller"` carries one field, `destination`: a
   stable, non-secret name for where the plaintext will go — a vault path, a
   user ID, a page. It lives in configuration so that planning needs nothing
   from the host. The host supplies the code in `Context` as an owned,
   reusable callback:

   ```text
   Context.deliver: Option<Box<dyn FnMut(&DeliveryMetadata, &KeyPlaintext) -> receiver::Outcome + Send>>
   ```

   `DeliveryMetadata` (address, hash, generation, operation ID, and — for a
   `caller` receiver — the configured `destination`), `receiver::Outcome`,
   and `KeyPlaintext` with its single `expose()` accessor
   become public; `KeyPlaintext` keeps its guarantees (no `Serialize`,
   redacted `Debug`, zeroized on drop), so the only way to read it is the one
   conspicuous call. One apply may deliver several keys; the callback is
   called once per delivery and routes by the metadata.
2. **The receiver is built inside the op, like every receiver.** `ops` wraps
   the callback in a `SecretReceiver` on the calling thread. The receiver
   fingerprint is the digest of `("caller", address, destination)`, computed
   from configuration alone, so `plan` never needs a callback and changing
   the destination is a replacement, as any receiver change is. The plan
   fingerprint of ADR-0003 already covers the whole configuration, so a plan
   shown with one destination cannot be applied with another.
3. **The refusal comes before any remote write or issuance.** Every operation
   that issues a key — `apply`, `rotate`, `recover replace` — runs the shared
   issuance preflight (ADR-0002); when the key's receiver is a `caller` and
   `Context.deliver` is `None`, that preflight fails before `create_started`.
   For `rotate` and `recover replace` the preflight is the whole of it: each
   issues one key and writes nothing ahead of it. An apply is a sequence of
   phases, so it makes the same refusal one level up — it scans the recomputed
   plan before its first phase, and fails with every write held back — or a
   guardrail create earlier in the run would land before the issuance was ever
   reached. The one write that can precede the refusal is local and older than
   the plan: an apply completes a delivered operation's promotion under its
   lock before it plans anything, and the report shows that promotion rather
   than claiming nothing happened. Planning is unaffected: it needs the
   destination, which it has, not the callback. The CLI never supplies a callback, so under the CLI
   a `caller` receiver is always that refusal, with a message saying
   which host feature it needs.
4. **Classification is the callback's answer.** The callback returns
   `Delivered`, `Rejected` (only under a documented no-commit contract, as for
   command receivers), or `Ambiguous`. A panic inside the callback is caught
   and classified `Ambiguous`. At-most-once, the rejection path, and the
   ambiguity path are unchanged from ADR-0002.

## Consequences

- The library's guarantees end at the callback: what the host does with the
  plaintext is the host's responsibility, and the receiver documentation says
  so in those words.
- A `FnMut` callback can be called for several keys in one apply, so hosts
  must key their handling on `DeliveryMetadata`, not on call order.
- `Context` now carries a boxed closure, which is why it is `Send` and not
  `Clone`; a host builds one per operation.

## Alternatives considered

**Return the plaintext in the report.** Rejected: reports are `Serialize` and
printed; plaintext in a report is exactly what ADR-0002 forbids.

**A channel instead of a callback.** Equivalent power, more machinery: the
host would need a receiver thread and the outcome would still have to travel
back. A callback is the smallest thing that works.

## References

- [ADR-0002](0002-journaled-key-creation.md), [ADR-0003](0003-core-library-split.md)
- [`docs/receiver-protocol.md`](../receiver-protocol.md)

### Implementation checks

Merged. These checks exist and run in `just check`. The decision above is
unchanged; this section records where each part of it is enforced.

- **The receiver and its callback** (items 1 and 2) —
  `crates/core/src/receiver/caller.rs` wraps `Context.deliver` as an ordinary
  `SecretReceiver`. What a host actually touches is the public `deliver` field
  on `Context` and the types in its signature — `DeliveryMetadata`,
  `KeyPlaintext`, and `DeliveryOutcome`, all `pub` from
  `crates/core/src/ops/mod.rs` — so a callback is written as a boxed closure and
  the alias naming that boxed type, `receiver::Deliver`, stays `pub(crate)`.
  That is deliberate and is what the decision above describes: a host supplies a
  closure, never an implementation of the receiver trait, so the trait and the
  receivers behind it need no public name either. The fingerprint of
  `("caller", address, destination)` is
  `crates/core/src/config/mod.rs::Receiver::digest`, which is why
  `a_changed_destination_plans_a_replacement` and
  `a_plan_fingerprint_refuses_an_apply_after_the_destination_changes` hold in
  `crates/cli/tests/caller.rs`.
- **Delivery, once, routed by metadata** (items 1 and 4) — the same file:
  `a_created_key_is_handed_to_the_callback_exactly_once`,
  `two_keys_in_one_apply_are_two_calls_with_distinct_metadata`,
  `a_rotation_delivers_the_successor_to_the_callback`,
  `a_refused_delivery_holds_at_secured_and_disables_the_key`, and
  `a_panicking_callback_is_ambiguous_and_is_never_called_again` — which also
  proves the panic payload is not repeated.
- **The refusal before any issuance** (item 3) — the shared preflight in
  `crates/core/src/ops/issuance.rs`, and the whole-plan scan `apply` makes ahead
  of its first phase in `crates/core/src/ops/apply.rs`. Covered by
  `an_apply_with_no_callback_creates_nothing`,
  `a_write_in_an_earlier_phase_never_lands_when_a_later_key_cannot_be_delivered`,
  `a_rotation_with_no_callback_stages_nothing`,
  `a_recover_replace_with_no_callback_closes_nothing`,
  `a_refusal_reports_the_promotion_it_completed_first`, and
  `planning_needs_no_callback`.
- **Nothing escapes the callback** — every case in that file runs
  `assert_nothing_leaked`, which scans the serialized report and the whole
  project directory for the sentinel the callback was handed.

The live counterpart is the opt-in
`live_caller_receiver_hands_a_key_to_host_code` in
`crates/cli/tests/live.rs`, which calls `ops::apply` against the real API with
a real callback. It has not been run;
see [`docs/live-tests.md`](../live-tests.md).
