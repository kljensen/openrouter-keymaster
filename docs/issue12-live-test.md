# Token Fund issue #12 live probe

`crates/cli/tests/issue12_live.rs` is a narrow, opt-in probe for the OpenRouter
controls Token Fund issue #12 needs. It is separate from `tests/live.rs` on
purpose. The older suite is designed for an empty disposable organization and
recovers crashed runs by listing an account and sweeping a run-name prefix.
This probe is safe to use only in the more conservative sense described here:
it never lists resources and it only deletes immutable IDs it wrote into its
own journal.

## Before running

Use a management credential with authority to create a workspace. Do not use
BYOK and do not point `OPENROUTER_BASE_URL` at a proxy or a test endpoint by
accident. The probe sends `include_byok_in_limit = false` on every key and
`include_byok_in_budgets = false` on the workspace budget.

Choose two current, distinct, text-capable catalog model slugs:

- `KEYMASTER_ISSUE12_ALLOWED_MODEL` is permitted by the new guardrail.
- `KEYMASTER_ISSUE12_DENIED_MODEL` is valid but is not in that allowlist.

The test deliberately does not bake model names into source. A stale name
would turn a model-policy assertion into an unrelated catalog failure. The
operator must record the selected catalog revision alongside the test result.

The probe creates one new `tf-i12-<UUID>` workspace and one named guardrail.
It creates six named keys inside that workspace, initially at a zero limit,
with short expiries. It records only the workspace UUID, guardrail UUID, key
hashes, endpoint, and lifecycle events in
`target/issue12-live-runs/<run>.jsonl`; the directory is `0700` and the
journal is `0600`. It never writes a plaintext inference key, response body,
or a resource name to that journal.

The workspace starts with a $0.50 lifetime cap. Its ordinary keys cap at $0.10;
the two aggregate probes cap at $0.25 each. After exact created-key usage has
settled, the probe narrows the workspace lifetime budget to that amount plus
$0.000001 and creates the aggregate keys. It sends at most eight sequential
256-token aggregate probes and six sequential post-disable probes. This keeps
the configured exposure below a few dollars, but it is **not** an exact
spending guarantee: OpenRouter documents that an already-dispatched request
can slightly exceed a workspace budget and does not state a numerical maximum.
No live test can establish an exact no-overage promise with that API contract.

## Run

First compile it without touching the provider:

```sh
cargo test --locked --test issue12_live --no-run
```

Export the management credential through the operator's normal secret channel,
then set the two model variables and run:

```sh
just issue12-live
```

This checks, in this order:

1. an accepted and read-back-verified workspace lifetime budget (a 403 fails);
2. create/attach/read-back of zero-limit keys and direct guardrail assignment;
3. lifetime zero-limit and distinct monthly-reset zero-limit inference
   rejection;
4. a success from the same key before its explicit expiry, then its rejection
   after that timestamp;
5. runtime rejection of an allowlist-excluded model;
6. observed latency from a verified management-plane disable to inference
   rejection; and
7. exact created-key usage polling, a read-back-verified lifetime-budget
   narrowing to settled usage plus $0.000001, then sequential requests from two
   newly created, read-back-enabled keys until the narrowed workspace parent
   returns a 403. The earlier successful request proves the child path worked
   before narrowing; the test deliberately does not require OpenRouter to
   permit a post-narrowing overage before rejecting. The elapsed result is
   recorded as the observed workspace-budget narrowing latency.

The inference client has no proxy, redirects, or automatic retries. It records
only HTTP status and elapsed disable latency, and drains response bodies without
logging them.

## Cleanup and recovery

On success, failure, or panic, cleanup first disables then deletes each exact
journaled key and verifies a `404` by hash. It then deletes each exact
journaled guardrail and verifies it by UUID, and finally deletes the exact
journaled workspace and verifies it by UUID. It does not list resources and it
does not delete a workspace default guardrail separately; that guardrail goes
with the recorded workspace.

If the process dies before cleanup, recover only from its exact journal:

```sh
just issue12-live-recover target/issue12-live-runs/tf-i12-<UUID>.jsonl
```

Recovery requires both opt-in variables, refuses an endpoint different from
the one the journal recorded, and sends deletes only for still-owned IDs in
that journal. It cannot clean a create whose network response was lost before
the server returned an ID: this is intentional. Under this no-sweep policy the
safe outcome is to leave the zero-limit, short-expiry resource for manual
operator inspection by its unique name, rather than guess ownership from a
name or enumerate the account.
