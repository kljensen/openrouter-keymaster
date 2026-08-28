# The management credential, and what Keymaster does about it

Keymaster holds two kinds of secret material and holds them very differently.
The **management credential** is long-lived, belongs to the operator, and can do
everything to an organization's keys that Keymaster can. An **inference key's
plaintext** is short-lived in Keymaster's hands: it arrives once, in a create
response, and leaves immediately for a receiver.

This page says how to supply the first, and what the design does and does not
protect.

## Supplying the credential

The management credential is the key OpenRouter's Management API Keys page
issues. Its prefix is not distinctive — it looks like an inference key — so
treat any `sk-or-` string as a secret.

It is read from the `OPENROUTER_MANAGEMENT_KEY` environment variable and from
nowhere else.

```sh
export OPENROUTER_MANAGEMENT_KEY="$(pass show openrouter/management)"
openrouter-keymaster plan
```

There is deliberately no `--management-key` option, no configuration field, and
no file Keymaster will read it from. A command-line option would put the
credential in the process list, where every other user on the machine can read
it, and it would end up in shell history. Providing it through a secret manager
that sets the environment for one command — `pass`, `op run`, `vault exec`, a CI
secret — keeps it out of both.

Under `systemd`, `LoadCredential=` hands the unit a *file path* in
`$CREDENTIALS_DIRECTORY`, not a value, so it cannot populate the variable on its
own. Read the file in a wrapper and never let the value reach `argv`:

```sh
#!/bin/sh
# ExecStart=/usr/local/bin/keymaster-apply, with
# LoadCredential=openrouter:/etc/keymaster/management.key
set -eu
OPENROUTER_MANAGEMENT_KEY="$(cat "$CREDENTIALS_DIRECTORY/openrouter")"
export OPENROUTER_MANAGEMENT_KEY
exec openrouter-keymaster apply
```

`systemd`'s `Environment=` and `EnvironmentFile=` also work, but both leave the
credential readable in the unit's or the file's contents and in
`systemctl show`; `LoadCredential=` keeps it in a tmpfs the unit alone can read.
Note that Keymaster cannot run unattended anyway — an ambiguous operation stops
and waits for a person — so a unit like this belongs on a `systemd` timer only
if someone reads its result.

Every command that reaches OpenRouter needs it, which is every command but two.
`state forget` makes no request at all. `recover inspect` makes none once the
journal records a hash — every fact in its report is already on disk — and an
inspect that does have to search for candidate keys reports
`missing_credential` rather than guessing.

`OPENROUTER_BASE_URL` names the API root, which is
`https://openrouter.ai/api/v1` otherwise; unset or empty means production. It is
not a credential, and it is validated like any other base URL: absolute, HTTP or
HTTPS, with no trailing slash and no query. It exists so a binary can be pointed
at the local test harness, or at a gateway the operator names deliberately
rather than having ambient proxy settings redirect a credential. A value that is
present but unusable — not valid Unicode, or not a base URL — stops the run,
because quietly falling back to production would send the credential somewhere
nobody chose.

Every other environment variable Keymaster reads uses the short name as its
prefix, and none of them is a credential: `KEYMASTER_LIVE_TESTS` and
`KEYMASTER_LIVE_SWEEP` gate the live acceptance suite
([`live-tests.md`](live-tests.md)), and `KEYMASTER_STATE_FAULT` exists only in a
build with the `fault-injection` feature, which is never a release build.

## What Keymaster protects against

**Disclosure through its own output.** No command prints an inference key's
plaintext, and there is no fallback that would. `openrouter-keymaster` writes
results to stdout and diagnostics to stderr through one module, from DTOs that
have no field a secret could occupy. The management credential lives in a type
with no `Serialize`, no accessor, a `Debug` that prints `[redacted]`, and a
buffer that is cleared when it is dropped; it reaches the wire once, as a header
marked sensitive. Text OpenRouter returns — a display name, a description, an
unrecognized reset schedule — is scrubbed before it is printed, so a credential
someone pasted into a key's name is not read back out, and an ANSI escape in one
cannot rewrite the line an operator is reading.

**Disclosure through what it writes.** State holds identities and lifecycle
phases; no type in it has a field for a secret, and its key-hash type refuses
credential-shaped input. Configuration is refused outright if any value contains
`sk-or-`. The delivered plaintext is written by a receiver, to a destination the
operator named, and by nothing else.

**Credential exfiltration by ambient configuration.** The HTTP client disables
proxies, so `HTTPS_PROXY` cannot route management traffic through something that
terminates TLS to inspect it. It refuses to follow redirects, so a response
cannot choose a new host for the next request that carries the credential. It
validates the base URL with the parser that will resolve the request rather than
with a prefix check.

**Leaking the credential into a receiver.** A command receiver is started with
an *empty* environment, so it cannot inherit `OPENROUTER_MANAGEMENT_KEY` or
anything else from the parent. It is spawned directly, with no shell, and its
argument vector never carries secret material. The plaintext travels only in a
JSON envelope on stdin, and the receiver's own stdout and stderr are bounded and
scrubbed before an operator sees them — a receiver that echoes the key back
cannot leak it through Keymaster's diagnostics.

**A lost create response becoming a silent orphan.** The one operation that
cannot be made repeatable is journaled before it is attempted, never retried,
and never resolved by guessing. See [ADR-0002](adr/0002-journaled-key-creation.md).

**Local file exposure.** State is written into a directory created `0700`, as a
`0600` file, atomically. The file receiver writes `0600` through an `O_EXCL`
temporary file into a directory it opened once with `O_DIRECTORY|O_NOFOLLOW`, so
a symbolic link swapped in after the check cannot redirect the key.

## What Keymaster does not protect against

**Anything that can read the operator's environment or memory.** A process
running as the same user can read `/proc/self/environ`, attach a debugger, or
read the state file. Keymaster's protections are against accident and against
the ordinary blast radius of a credential in a command line — not against a
local attacker with your privileges.

**A compromised management credential.** It can create, modify, and delete keys
in the organization directly. Keymaster has no second factor, no approval step,
and no audit trail of its own beyond local state. Scope the credential to what
it must manage, and rotate it out of band; Keymaster does not manage the
credential it authenticates with.

**Whatever the receiver's destination is.** The file receiver writes a live
credential to a path where anything that can read the file can spend the key; it
is for local development. A command receiver is a program the operator wrote,
running with the operator's privileges — Keymaster hands it the plaintext and
its judgement ends there.

**A key that has already been spent.** Keymaster reports usage, and a guardrail
can cap a budget, but it does not watch for anomalous spend and cannot claw back
what a leaked key already cost.

**A second machine.** The state lock is a local file. Two operators on two
machines can apply against the same organization at the same time, and nothing
stops them. See [ADR-0001](adr/0001-native-reconciliation.md).

**A wrong attestation.** `recover resolve --no-resource-created` is the
operator's word that no key was created. Keymaster cannot check it. Attesting
wrongly leaves a live key nothing tracks.

**Supply chain.** The dependency graph is small, pinned by a committed
`Cargo.lock`, and checked against the RustSec advisory database on every run of
`just check` — but Keymaster is built from crates.io like anything else.

## If the credential leaks

Keymaster is not part of the answer. Revoke the management credential in
OpenRouter, issue a new one, and export it. Then use Keymaster for what follows:
`openrouter-keymaster status` lists every key it tracks, and `rotate`,
`retire`, `decommission`, and `delete key` replace and end them one identity at
a time.
