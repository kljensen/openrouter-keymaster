# The Keymaster receiver protocol

A **receiver** is where a newly created inference key's plaintext goes.
OpenRouter discloses that plaintext once, in the create response, and never
again; Keymaster holds it in memory for a few seconds and hands it to the
receiver the configuration names. There is no fallback. Keymaster never prints
a key, never writes one to its state file, and never creates a key that has
nowhere to go.

Two receivers exist in v0.1: `file`, for local development, and `command`,
which runs a program you write — the **adapter**. This document is the contract
that program implements.

Read [ADR-0002](adr/0002-journaled-key-creation.md) first if you are writing an
adapter. It explains why delivery is at-most-once and why almost every failure
is classified as ambiguous.

## Configuring a command receiver

```toml
[receivers.vault]
program = "/usr/local/lib/keymaster/store-in-vault"
args = ["--mount", "keymaster", "--path", "inference/jobfeed"]

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
```

`program` is an absolute path. `args` is the argument vector, passed verbatim.
There is no shell: no `$(…)`, no globbing, no quoting rules, and no string for
an injection to hide in. If you need shell features, write a script and name
the script here.

## What the adapter receives

One JSON object on stdin, then end-of-file. Nothing else. In particular, the
key is **not** in `argv` (readable by every user on the machine through the
process list), **not** in the environment, and **not** in a file Keymaster
wrote for you.

```json
{
  "envelope_version": 1,
  "operation_id": "op-2026-08-23-000017",
  "address": "jobfeed",
  "hash": "keyhash-4f2c…",
  "generation": 3,
  "key": "sk-or-v1-…"
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `envelope_version` | integer | Schema version of this object. Currently `1`. |
| `operation_id` | string | Stable name of the journaled create-and-deliver attempt. Idempotency key. |
| `address` | string | Keymaster's local name for the key, from the configuration. Never sent to OpenRouter. |
| `hash` | string | The key's immutable remote identity. Safe to log and to store. |
| `generation` | integer | Which replacement of this address is being delivered. Increases monotonically. |
| `key` | string | The plaintext. The only secret in the envelope. |

Rules for reading it:

- **Check `envelope_version` first.** If it is not a version you implement,
  write a message to stderr, commit nothing, and exit `10` — the refusal code
  below, which is exactly what "refused, nothing committed" means. Do not
  guess at the fields.
- **Read to end-of-file before acting.** Keymaster closes stdin after writing
  the whole object; a partial read is a partial envelope.
- **Ignore fields you do not know.** Later versions may add non-secret fields.
  A new *required* field will come with a version bump.
- **Everything but `key` is non-secret** and may be logged, stored, and used to
  name what you wrote.

## The environment is empty

The adapter is started with no environment variables. Not a filtered copy — an
empty one.

Keymaster's own process holds `OPENROUTER_MANAGEMENT_KEY`, a credential that
can create and delete every key in the organization, and an adapter has no
business seeing it. Nor should an adapter's behaviour depend on ambient
configuration that happened to be exported in whatever shell ran Keymaster.
There is no allowlist and no passthrough setting; there is nothing to
misconfigure.

Consequences for you:

- `PATH` is empty, so the `program` path must be absolute — there is nothing to
  search — and anything your adapter runs must be named by absolute path too.
  That includes a script's `#!` line: `#!/usr/bin/env python3` fails, because
  `env` is what searches `PATH`. Name the interpreter outright.
- `HOME` is unset, so a tool that reads `~/.config/…` will not find it. Point
  at configuration explicitly, in `args`.
- Your adapter's own credentials must come from a file it can read, or from a
  wrapper script that sets them, and never from Keymaster.

The working directory is inherited and carries nothing: no key material is ever
placed in a path, a directory name, or a temporary file.

*(One caveat, for completeness: macOS adds `__CF_USER_TEXT_ENCODING` to any
process it starts, below the level of anything Keymaster controls. Nothing from
Keymaster's own environment survives, which is the property that matters.)*

## How the adapter answers

By exiting. Keymaster reads the exit status, and the protocol defines exactly
three answers:

| Exit | Keymaster records | Meaning you are asserting |
| --- | --- | --- |
| `0` | **delivered** | You committed the key. It is durably stored where it belongs. |
| `10` | **rejected** | You refused, **and committed nothing**. |
| anything else | **ambiguous** | Unknown. You may or may not have committed the key. |

Also ambiguous: dying by a signal, exceeding the execution timeout (30 seconds;
Keymaster then kills the process), and any failure to write the whole envelope
to your stdin.

Exit code `10` is a promise, and it is the only place in this protocol where
Keymaster believes a definite negative. Use it **only** when you can guarantee
nothing was written anywhere — a rejected envelope version, a validation
failure, a policy refusal, an authentication failure against your own backend
before any write. If you have already written something and then fail, exit
with any other nonzero code: the operator will be told the delivery is
ambiguous, which is the truth.

Why this asymmetry: an ambiguous delivery costs a key rotation, while a wrong
`rejected` tells the operator no cleanup is owed on a destination that may hold
a live credential. ADR-0002 chooses the expensive-but-safe answer by default.

## What happens after you answer

- **delivered** — Keymaster marks the operation delivered, promotes the new key
  to current, and moves the previous key to `awaiting_retirement`. The
  predecessor is left as it is until an explicit `openrouter-keymaster retire`.
- **rejected** — the plaintext is discarded, the new key is disabled if
  possible and kept tracked, and the operator is told the address needs
  replacement. Your adapter is not called again for that key.
- **ambiguous** — the operation is journaled as `delivery_ambiguous`, the whole
  apply stops, and an operator resolves it. Keymaster will not call your
  adapter again on its own.

**There is no automatic retry, ever.** A receiver that may already hold the key
must not be handed a second one: re-delivering could overwrite a live
destination with a stale or duplicate secret. This is why `operation_id`
exists — see below.

## Idempotency, and the operation ID

`operation_id` names one attempt. It is stable across everything Keymaster
does with that attempt, and it appears in `openrouter-keymaster status` and
`openrouter-keymaster recover inspect` output, so an operator can match a
Keymaster journal entry to whatever your adapter recorded.

Use it:

- **Record it beside whatever you write.** A version tag, a metadata field, an
  annotation — anything the operator can query later. When a delivery goes
  ambiguous, the question is always "did operation `op-…` commit?", and an
  adapter that wrote the ID down can answer it.
- **Make repeat deliveries of the same operation ID a no-op.** Keymaster will
  not retry on its own, but an operator resolving an ambiguity may run one
  deliberately.

Without such a record, an ambiguous delivery can only be resolved by rotating
the key — creating a replacement and delivering that. That is the default
assumption, and it is not a failure of your adapter; it is the honest cost of
not being able to ask.

## Diagnostics

Keymaster captures a bounded amount of your stdout and stderr — the first few
kilobytes of each, of which a short excerpt reaches the operator's screen and
logs — and removes the plaintext from it by exact match before it goes
anywhere. Beyond the cap the streams are drained and discarded, so writing
volumes of output cannot wedge a delivery.

Still: **do not print the key**. The scrub is a backstop against an adapter's
mistake, and it cannot recognize a key you transformed — base64-encoded, split
across lines, embedded in a hex dump. Print the operation ID and what you did
with it; that survives the scrub and is what the operator needs.

## Security expectations for adapter authors

- Never write the key to `argv`, to an environment variable, or to a log.
- Write it to its destination with restrictive permissions, and do not leave a
  temporary copy behind. If you must stage it in a file, create it with mode
  `0600` and `O_EXCL`, and remove it on every path.
- Do not keep a backup of the previous key. Keymaster's rotation model keeps
  the predecessor *live at OpenRouter* until an explicit retirement, which is
  the supported way to not break consumers; a `.bak` file is just a second copy
  of a credential nobody manages.
- Finish quickly. The bound is 30 seconds, and a killed adapter is an ambiguous
  delivery.
- Be boring about failure: fail before you write, or report ambiguity honestly.
- Assume Keymaster tells you nothing else. There is no second call, no
  handshake, no plugin API, and no discovery: your program is a program that
  reads JSON on stdin and exits.

## A minimal adapter

```python
#!/usr/bin/python3
# Absolute, not `/usr/bin/env python3`: the environment is empty, so `env` has
# no PATH to search. Adjust the path to the interpreter on your machine.
"""Store a Keymaster-delivered key. Reads one envelope on stdin."""
import json, os, sys, tempfile

REJECTED = 10

envelope = json.load(sys.stdin)              # reads to end-of-file
if envelope.get("envelope_version") != 1:
    print("unsupported envelope version", file=sys.stderr)
    sys.exit(REJECTED)                       # nothing written yet: a rejection

target = sys.argv[1]
directory = os.path.dirname(target)
handle, staged = tempfile.mkstemp(dir=directory)  # same filesystem
try:
    with os.fdopen(handle, "w") as out:
        out.write(envelope["key"])
    os.chmod(staged, 0o600)
    os.replace(staged, target)               # atomic; past here, committed
except Exception as error:
    os.unlink(staged)
    print(f"could not store the key: {error}", file=sys.stderr)
    sys.exit(REJECTED)                       # the replace never happened

print(f"stored operation {envelope['operation_id']}")
```

Note where `REJECTED` is and is not used: both exits are before the atomic
`os.replace`, so both can promise nothing was committed. A failure *after* the
replace would have to exit with a different code.

## The file receiver

For local development, `[receivers.…] path = "/absolute/path"` writes the key
to one file and nothing else — no newline, no JSON, no metadata — through an
`O_EXCL` sibling temporary file at mode `0600`, fsynced and renamed into place.
A missing parent directory is created `0700`; an existing one is left as you
set it. An existing target is **replaced**, with no backup.

It refuses a relative path, a symbolic link in place of the target or its
parent directory, and a target that is not a regular file. The directory is
opened once, with `O_DIRECTORY` and `O_NOFOLLOW`, and the create, rename, and
unlink all happen relative to that descriptor, so a directory swapped for a
symbolic link after the check cannot receive the key. It is not a secret store:
anything that can read the file can spend the key.

## Testing an adapter

`src/bin/openrouter-keymaster-test-receiver.rs` is the adapter Keymaster's own
tests run. It is small, it records exactly what it was given — its argument
vector, the names of every environment variable it inherited, and the envelope
— and it can end in every way this document describes, including badly. Read it
as a worked example of the receiving half.
