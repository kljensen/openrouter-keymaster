# The live acceptance suite

`crates/cli/tests/live.rs` runs Keymaster against a real OpenRouter organization. It exists
for the one thing the local harness cannot check: whether the real management
API behaves the way its documentation says it does.

**It creates and deletes real resources with a real management credential.**
Read this page before running it.

## What you need

**A dedicated test organization**, with no inference credits and nothing else in
it. Not a shared organization, and not one that holds a key anything depends on.
The suite deletes every key, log destination, and workspace whose name carries
its run prefix, and a bug in that filter is only survivable if there is nothing
else there to hit.

**A management credential for that organization** — a key from OpenRouter's
Management API Keys page — exported as `OPENROUTER_MANAGEMENT_KEY`. The suite never reads it into a test variable; the
child `openrouter-keymaster` process inherits it from the environment.

## Running it

```sh
just live                                        # every live test
just live live_key_create_rotate_retire_delete   # one of them
```

The recipe is `KEYMASTER_LIVE_TESTS=1 cargo test --locked --test live --
--ignored --test-threads=1`. Run it by hand if you want other `libtest` flags.

`just live` is **not** part of `just check` and is not in CI. It never will be:
CI has no test organization and no credential, and a suite that spends money
does not belong on the path a pull request takes.

## How the gate works

Two gates, answering two different questions.

**`#[ignore]`** on every test answers "was this suite asked for at all". It is
what keeps live tests out of `cargo test`, `cargo test --all-features`, `just
check`, and CI. Nothing in the default path runs them, and they still compile on
every build, so they cannot rot.

**`KEYMASTER_LIVE_TESTS=1`**, checked at the top of each test, answers "did a
person mean it". `--ignored` is a blunt instrument, and a wrapper script or an
idle `cargo test -- --ignored` can reach for it. Without the variable each test
prints a skip notice and returns without touching the network.

Opting in with no usable credential is a **failure**, not a skip. That is a
misconfigured live run rather than a decision not to make one, and passing
silently would tell you the API had been checked when it had not.

## What each test does

| Test | Covers |
| --- | --- |
| `live_guardrail_create_read_import_update` | Guardrail create through `apply`; a one-record-per-page listing that must still return every guardrail exactly once; exact `GET` by UUID; `state forget` then `import guardrail --id`, which must report the description **OpenRouter** holds rather than the edited one on disk; the update that follows, verified by reading it back. |
| `live_key_create_rotate_retire_delete` | Key create with the hash captured immediately; the update-only `disabled` policy, which `POST /keys` cannot set; guardrail assignment verified through the assignment endpoint; file-receiver delivery at `0600`; non-disclosure of the delivered plaintext; `rotate`, after which the predecessor — enabled by the test beforehand, so the check means something — must still be **enabled** and tracked; `retire`, after which it must be disabled; `delete key`, after which reading it must give 404. Key listing across both generations. |
| `live_workspace_create_budget_default_guardrail_and_scoped_key` | Workspace create through `apply`; the default guardrail, which is created by the first `PATCH` to the identity the workspace names and must then be in its own workspace's guardrail listing, in no unscoped listing, and carry the configured budget and the name OpenRouter gave it; one budget `PUT`, whose answer must be **definite** either way (see below); the description update in the same action, which must land whatever became of the budget; a key created inside the workspace by a `--workspace` run, whose `workspace_id` must come back as the scope; `state forget workspaces.club` then `import workspace --id`, which must report the description OpenRouter holds. |
| `live_caller_receiver_hands_a_key_to_host_code` | A `caller` receiver end to end, through `ops::apply` called directly — the command line supplies no callback and can never reach this path. The callback must be handed the address, the created key's hash, and the configured destination, with a plaintext that carries OpenRouter's own `sk-or-` marker; the serialized report must carry no part of it. The test records the plaintext's *shape*, never the plaintext. |
| `live_log_destination_webhook_create_update_delete` | A `webhook` destination created through `apply`, read back as `type = webhook`, enabled, with an empty key allowlist; a `config` change, which must plan as a diff of `config` **and nothing else** and leave the next plan `converged`; `delete log-destination --id`, after which reading it must give 404. The configured URL must appear in no stream. |
| `live_spend_reports_credits_and_key_costs` | `GET /credits` and the analytics vocabulary this organization offers: the report's `columns` must be `api_key_id`, `tokens_total`, and one of the three cost metrics Keymaster knows. Every cost and token in every row and period must be a number by the time it is reported, which is what proves the quoted-integer handling. |
| `live_sweep_named_prefix` | Not a test. The cleanup tool described below. |

**The budget write is the one whose answer is not predicted.** Workspace
budgets are documented as an Enterprise feature, so a `403` is a perfectly good
outcome; **on the account this suite has been run against, the `PUT` was
accepted** and the workspace's `monthly` budget was written. What the test
requires is the *shape* of the answer ADR-0004 item 4 promises: written, or
refused `403` naming the interval — never a write that settles nothing, and
never some other definite `4xx`, which would be OpenRouter objecting to the
request rather than to the account's plan. Either way the rest of the same
action has to land. When the budget is
refused the test drops the `budgets` table before it goes on, because that is
the only way a refused budget converges and everything after it is placed in
that workspace — which the planner holds back while a configured budget has not
converged. The outcome is printed, so a run says which kind of account it met.

**The webhook URL is `https://example.invalid/<run>/…`.** `.invalid` is
reserved precisely so that a name in it can never resolve, which is what makes
the endpoint harmless: nothing is listening and nothing can be. Whether
OpenRouter accepts an unreachable URL at create time is **unverified** — it is
one of the things a first live run is there to find out. If it turns out to
validate reachability, the create fails, and that is a finding about the API
rather than a bug in the test: replace the URL with a documented harmless echo
endpoint you control and say so here.

The guardrail listing is the one that really pages: `GET /guardrails` accepts a
limit, so a page size of one turns three guardrails into three pages plus the
empty one that ends the listing. `GET /keys` takes only an offset, so the key
listing pages at whatever size the server chooses and the check there is that
the offset arithmetic collects every generation exactly once. Deep pagination —
overlapping pages, a page that makes no identity progress, a wrong
`total_count` — is covered by the local harness, which can produce those on
demand.

The non-disclosure check is the live counterpart of the sentinel scan. The
sentinel is useless here — the secret is whatever OpenRouter just issued — so
the test reads the delivered plaintext back out of the receiver file and uses
*that* as the needle, scanning every stream the run produced, every file in the
project directory including state, and the run journal.

## Safety rules the suite holds itself to

**A unique run prefix.** Every remote name starts with `km-live-<8 hex>`,
derived from the clock, the process, and a counter. The sweep touches nothing
whose name does not start with that exact prefix followed by a hyphen, so
`km-live-1a2b3c4d` cannot match `km-live-1a2b3c4de`.

**Zero-budget keys.** Every key the suite creates carries `limit_usd = 0`, so a
key that escapes cleanup cannot spend anything: `POST /keys` takes `limit: 0`
and returns a key with nothing left to spend. Keys are also created
`disabled = true` and only enabled where the scenario needs it, which is the
same step that proves the update-only disabled policy works.

**One-cent guardrails.** Guardrails cannot go to zero the way keys can.
`POST /guardrails` answers `limit_usd = 0` with a 400, "Too small: expected
number to be >0" — the first live run found this, and the OpenAPI document does
not mention the minimum. So every guardrail in the suite, including the
workspace default guardrail that governs all traffic in its workspace, carries
`limit_usd = 0.01` a day. Nothing under a guardrail can spend anyway, because
every key is capped at zero in its own right. The other non-zero amount is the
workspace budget the suite tries to write, one dollar a month, which is
documented as having to be greater than zero.

**A journal written before the resource exists.** `target/live-runs/<prefix>.jsonl`
gets the run prefix and the base URL as its first line, before anything is
created, and one line per identity as soon as the test learns it. The binary
creates the resources, so there is a window between the create and the record —
the prefix closes it, because a sweep by prefix finds what the journal missed.

**Cleanup from `Drop`.** The sweep runs on the panic path too. It lists by
prefix, unions that with what was journaled, deletes each resource by its
immutable identity, and reads that identity back until OpenRouter answers 404 —
a 2xx on the delete is not proof.

**Listings are per workspace.** `GET /keys` and `GET /guardrails` answer for the
credential's default workspace unless `workspace_id` names another, so the suite
adopts and sweeps by listing every workspace it created as well as the default
one. A key created in a workspace is in that workspace's listing and in no
other, and a sweep that read only the unscoped listing would leave it behind.

**Cleanup in dependency order.** Log destinations first, then keys, then each
workspace's own default guardrail, then workspaces. A destination is what watches the keys, so it goes before them: the
run stops forwarding before it starts churning what was being forwarded, rather
than aiming a burst of log traffic at an endpoint that deliberately cannot
answer. OpenRouter refuses to delete a workspace that still holds anything, so a
workspace goes last and only once its occupants are gone. A workspace's own
default guardrail is not an occupant: it goes with the workspace, so it is not
reported as something to remove by hand. Whether it can be deleted on its own is
a question the sweep asks once per run — one `DELETE` per default guardrail,
where a `400` or a `403` is the expected answer — and journals, because the
answer is the API's to give and nothing in Keymaster depends on it.

**No response bodies in cleanup output.** A failure is reported as an identity
and an error kind. A body from a failed cleanup call is exactly where a stray
credential echo would show up, so it is drained and discarded rather than
printed.

## Cleaning up after a crash

A run killed hard — `Ctrl-C`, a panic in the harness itself, a laptop closing —
leaves its journal behind.

```sh
ls target/live-runs                    # each file is named for a run prefix
just live-sweep km-live-1a2b3c4d
```

The sweep deletes every key, log destination, and workspace whose name carries
that prefix, and verifies each deletion by reading the identity back. It also
reads the named run's journal, so a resource the run recorded is cleaned up even
if the listing cannot reach it, and it writes its own records to a new journal
rather than overwriting the evidence.

**Give it a complete run identifier.** `km-live-` followed by exactly eight
lowercase hex digits — the journal file's name, without the extension. A partial
prefix is refused outright, because ownership is decided by matching
`<prefix>-` against a remote name: `km-live` would own every live run's
resources, and sweeping it while another run is in progress would delete that
run's keys out from under it.

**Point it at the endpoint the run used.** The first line of a journal records
the run's effective base URL, and the sweep refuses to proceed unless the
current one matches — telling you which to set. This is not pedantry: the sweep
proves a key is gone by reading its hash back and getting a 404, and against the
wrong endpoint *every* hash 404s. It would report a clean run while every
resource survived where it was actually created. The trap is easy to fall into,
because leaving `OPENROUTER_BASE_URL` unset means production, which looks like a
default rather than a choice.

```sh
OPENROUTER_BASE_URL=https://gateway.example/api/v1 just live-sweep km-live-1a2b3c4d
```

A journal with no endpoint line predates this check and is refused the same way;
set `OPENROUTER_BASE_URL` explicitly to the endpoint that run used. A missing
journal is refused too — without one the sweep cannot know the endpoint.

**Guardrails are reported, not deleted.** Nothing in Keymaster deletes a
guardrail: config removal is deliberately not authority to destroy one, so the
client has no delete for it. A guardrail spends nothing, so leaving one behind
is safe, but a test organization will accumulate them. The sweep prints each
one's UUID and name; remove them in the OpenRouter dashboard. The exception is a
workspace's default guardrail, which is deleted with its workspace and is
therefore not reported.

**A workspace or destination left behind is a failure, not a notice.**
Keymaster can delete both, and the run created them, so anything still there
after the sweep fails the run and is named by UUID with what to do about it. A
workspace that refuses deletion is usually one that still holds something the
sweep could not remove; empty it and delete it by ID.

**A listing that fails is a cleanup failure, for guardrails as much as for
keys.** The journal names only what a run got as far as recording, so a run that
died between a create and its record left something only the listing can name.
A sweep that could not list has not proved anything, and says so rather than
reporting success.

Every cleanup failure is printed the same way — the exact non-secret identity,
and what to do with it — and fails the test unless a panic is already in flight,
so it can never mask the failure that caused it.

## Status

The suite has been run against a live organization once, and **has not yet
passed**; see [the release checklist](release-checklist.md). That first run
stopped in four of seven scenarios on exactly the kind of thing it exists to
find: `POST /guardrails` rejects `limit_usd = 0`, which the OpenAPI document
does not say and this suite assumed. The guardrail fixtures now ask for one
cent. Every run should be treated the same way — what it finds about the
production API is a finding about OpenRouter first, and only then maybe a bug in
the test. The suite also compiles on every build, and
`cargo test --locked --test live --no-run` is the check that keeps it that way.

Some of what the newer scenarios assert is predicted rather than observed. The
read side of workspaces and analytics was checked by hand against a real
organization — `GET /workspaces`, `GET /workspaces/{id}/budgets`, and the
`/analytics/meta` vocabulary. A workspace create and one budget `PUT` have since
been sent against a real organization, and **both were accepted**: budgets are
documented as Enterprise, and they were accepted on the tested account. **No log
destination request of any kind has ever been sent** from this repository, so
those are the assertions most likely to move on a first run.
