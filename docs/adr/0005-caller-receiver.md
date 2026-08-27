# ADR-0005: The caller receiver

- **Date:** 2026-08-27
- **Status:** Proposed

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
3. **Preflight refuses before any write.** Every operation that issues a key
   — `apply`, `rotate`, `recover replace` — runs the shared issuance preflight
   (ADR-0002); when the key's receiver is a `caller` and `Context.deliver` is
   `None`, that preflight fails before `create_started`. Planning is unaffected: it needs the
   destination, which it has, not the callback. The CLI never supplies a callback, so under the CLI
   a `caller` receiver is always a preflight failure with a message saying
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
