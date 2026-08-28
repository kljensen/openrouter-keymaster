# The desired-state file

Keymaster reads one TOML file — `openrouter-keymaster.toml` unless `--config`
says otherwise — that describes what should exist in OpenRouter.
[`examples/openrouter-keymaster.toml`](../examples/openrouter-keymaster.toml)
is a working example with fake values. This page is the reference: every field,
its type, and the rules that reject it.

## Three rules that explain most of the surprises

**Omitted is not empty.** A field you leave out is a field Keymaster does not
manage: it reads the remote value and leaves it alone. A field you set is one
Keymaster owns and will converge. Those are different states, and the file
spells them differently.

**Clearing is spelled out.** TOML has no null, so setting a remote field back to
nothing means naming it in the block's `clear` array. Each block type has a
fixed list of what may be cleared; anything else is an error.

**Nothing here may be an OpenRouter secret.** The management credential comes
from the environment and a new key's plaintext goes to a receiver. Any value
containing `sk-or-` — an inference key or a management key, in any letter case —
is refused, as is any field this schema does not define. One value is different,
and it is the exception that proves the rule: a log destination's `config` may
hold a *third-party* credential, because there is no other channel through which
OpenRouter can be told what to send logs to. **A file with a
`[log_destinations.*]` block should be treated as a secret** — see that section.

## Errors

Parsing and validation read this one file and nothing else: no credential, no
network, no write. Validation reports every problem it finds in a single pass,
each named by its configuration path (`keys.jobfeed.limit_usd`), and no message
quotes the value that caused it.

Two error categories come out of this file. A `config_syntax` error means TOML
could not parse it, or a table carried a field the schema does not define — an
unknown field is a hard error everywhere, including the document root, so a
misspelled `limit_used` stops the run instead of being silently ignored. A
`config_invalid` error means the file parsed and a value is unusable.

## `version`

```toml
version = 1
```

Required, and must be exactly `1`. A file with a version this build does not
understand is refused rather than interpreted.

## `[defaults]`

Optional.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `include_byok_in_limit` | bool | `false` | Whether spend on your own provider keys counts against a USD limit. Guardrails and keys inherit this and may override it. |

## Local addresses

The table key in `[workspaces.NAME]`, `[guardrails.NAME]`, `[keys.NAME]`,
`[receivers.NAME]`, and `[log_destinations.NAME]` is a
**local address**. It is Keymaster's name for the resource, it is never sent to
OpenRouter, and it is what `state forget`, `rotate`, `retire`, and `import` take
as an argument. Changing one is not a rename — it is a new address bound to
nothing, and the old binding becomes an orphan.

An address is 1 to 64 characters of ASCII letters, digits, `_`, and `-`,
starting with a letter or a digit, and may not contain `sk-or-`. Two addresses
of the same kind may not differ only by letter case.

## `[workspaces.ADDRESS]`

A workspace is the unit that carries a pooled spending cap and a default
guardrail. Identity is the workspace UUID: removing the block orphans the
binding, `openrouter-keymaster import workspace NAME --id UUID` binds an
existing one, and `openrouter-keymaster delete workspace --id UUID` is the only
deletion.

```toml
[workspaces.golf_club]
name = "Golf Club"
slug = "golf-club"
description = "The golf club's inference workspace."
budgets = { daily = 5, weekly = 20, monthly = 50, lifetime = 500 }
include_byok_in_budgets = false
default_guardrail = "cheap_summarization"
```

| Field | Type | Required | Clearable | Notes |
| --- | --- | --- | --- | --- |
| `name` | string | yes | no | Remote display name. Mutable remotely and never an identifier. |
| `slug` | string | yes | no | 1 to 50 characters of lowercase letters and digits in segments separated by single hyphens, with no leading or trailing hyphen. |
| `description` | string | no | yes | At most 1000 characters. |
| `budgets` | table | no | no | Any of `daily`, `weekly`, `monthly`, `lifetime`, in USD and greater than zero. |
| `include_byok_in_budgets` | bool | no | no | Needs at least one budget. Omitted leaves the remote setting alone. |
| `default_guardrail` | local address | no | no | Names a `[guardrails.*]` block, which is bound to this workspace's `default_guardrail_id`. |
| `clear` | array of string | no | — | `"description"`. |

**`budgets` is managed as a whole or not at all.** Omitting the table leaves
OpenRouter's budgets alone; writing one makes it the complete desired set, so an
interval OpenRouter has and the table does not is removed. Every configured
interval must be strictly larger than the next narrower one — OpenRouter checks
lifetime > monthly > weekly > daily on every budget write — and that is checked
before anything is sent. Apply writes one request per interval, ordered deletes
first, then increases from the widest interval to the narrowest, then decreases
from the narrowest to the widest, so no intermediate state violates the rule.

**A refused budget holds back everything it would have capped.** Workspace
budgets are a plan feature, and a well-formed `4xx` — a `403` plan restriction
among them — is reported as a definite failure naming the interval. Anything
else (a timeout, a reset, a `5xx`) settles nothing, so it is reported as a write
whose effect is unknown and left to the read that follows the apply. While a configured budget has not converged, every write in that
workspace the plan classifies `issuing` or `expanding` is held back — a key
create or replacement, an enable, a raised limit, a widened guardrail — and
routine writes go on as usual. The workspace's own budget writes are exempt,
because they are what converges it.

**`include_byok_in_budgets` travels with a budget.** It is a workspace-wide
setting that only a budget `PUT` can write, which is why it needs at least one
budget to be written at all.

**A `default_guardrail` is that workspace's own guardrail.** Every workspace has
a `default_guardrail_id`, derived from the workspace's UUID, which governs all
traffic in the workspace; it appears in no listing until its configuration is
first written. Naming a guardrail block here binds the block to that identity —
including when the block is added after the workspace was already imported,
since the workspace binding records the identity and the address takes it. Such
a guardrail is never created by `POST`, never imported by name, and never
deleted on its own: it is created by the first `PATCH` to the identity its
workspace names, and `delete workspace` releases its binding along with the
workspace's.

A guardrail address may be the default of at most one workspace, that block must
omit `workspace` or name the same one, and it may not set `workspace_id` at all:
being a workspace's default *is* the placement, so a second spelling of it can
only disagree. If the address already owns a different guardrail, nothing is
written — writing the bound identity would edit a guardrail that is not the
default, and writing the workspace's would leave two at one address — and the
plan says so, naming both. Nothing is written either when the identity the
workspace names is owned by *another* address, since one remote guardrail
belongs to exactly one local address. Release the address with `state forget`,
or give the default guardrail a block of its own.

**A guardrail's workspace is fixed when it is created.** Unlike a key, a
guardrail is never replaced — it is policy other resources are attached to, not
a credential a successor can stand in for — so a guardrail OpenRouter has in one
workspace and the configuration places in another is a difference nothing can
converge. The plan reports it and writes nothing, and `import guardrail` refuses
a guardrail whose workspace is not the one the address would place it in. Both
read the same rule, in the same order: the workspace the block names, then the
workspace whose `default_guardrail` it is, then the run's `--workspace` scope —
so under a scope a bound guardrail living elsewhere is held back rather than
patched from a run that may not touch that workspace at all. The
never-materialized case obeys the same rule: a block still bound to one
workspace's default identity but placed in another is held back, not written,
because writing it would materialize the first workspace's default guardrail
while the configuration asks for one in the second.

**A workspace that is bound and absent is reported, never recreated.** A
guardrail may be recreated, because a guardrail is policy and a new one governs
the same keys. A workspace is a container: a new one has a new UUID, so every
key, guardrail, and budget the old one held would be somewhere Keymaster could
no longer reach. It is reported as `missing`, like a missing key.

## `[guardrails.ADDRESS]`

A guardrail holds model, provider, and budget policy. A key is assigned at most
one.

```toml
[guardrails.cheap_summarization]
name = "cheap-summarization"
description = "Small, cheap models for background summarization."
allowed_models = ["google/gemini-2.5-flash", "openai/gpt-4o-mini"]
denied_providers = ["example-untrusted-provider"]
limit_usd = 10
reset_interval = "monthly"
require_zdr = true
```

| Field | Type | Required | Clearable | Notes |
| --- | --- | --- | --- | --- |
| `name` | string | yes | no | Remote display name. Mutable remotely and never an identifier. |
| `description` | string | no | yes | At most 1000 characters. |
| `allowed_models` | array of string | no | no (use `[]`) | Model slugs permitted. |
| `denied_models` | array of string | no | no (use `[]`) | Model slugs refused. Sent as `ignored_models`. |
| `allowed_providers` | array of string | no | no (use `[]`) | Provider slugs permitted. |
| `denied_providers` | array of string | no | no (use `[]`) | Provider slugs refused. Sent as `ignored_providers`. |
| `limit_usd` | number | no | yes | USD budget. Needs `reset_interval`. |
| `reset_interval` | `"daily"`, `"weekly"`, `"monthly"` | no | yes | Needs `limit_usd`, and is required whenever `limit_usd` is set. |
| `include_byok_in_limit` | bool | no | no | Inherits `defaults`. Always managed. |
| `require_zdr` | bool | no | no | Restrict inference to zero-data-retention providers. Omitted means unmanaged. Sent as `enforce_zdr`. |
| `workspace` | local address | no | no | Names a `[workspaces.*]` block. Fixed at creation. |
| `workspace_id` | UUID string | no | no | A workspace Keymaster does not manage. Never alongside `workspace`, and never on a workspace's `default_guardrail`. |
| `clear` | array of string | no | — | `"description"`, `"limit_usd"`, `"reset_interval"`. |

## `[keys.ADDRESS]`

A key is one OpenRouter inference key at one address, across however many
generations that address goes through.

```toml
[keys.golf_jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
expires_at = "2027-01-01T00:00:00Z"
disabled = false
workspace_id = "6c7f5f5a-4f1b-4e2d-9a3c-1b2d3e4f5a6b"
guardrail = "cheap_summarization"
receiver = "jobfeed_vault"
generation = 1
```

| Field | Type | Required | Clearable | Notes |
| --- | --- | --- | --- | --- |
| `name` | string | yes | no | Remote display name. |
| `limit_usd` | number | no | yes | USD spending limit. |
| `limit_reset` | `"daily"`, `"weekly"`, `"monthly"` | no | yes | Needs `limit_usd`, but is optional with it: a key limit with no reset never refills. Note the key-level spelling differs from a guardrail's `reset_interval`. |
| `expires_at` | RFC 3339 string | no | yes | Quoted string, not a bare TOML datetime. Normalized to UTC. |
| `disabled` | bool | no (default `false`) | no | Always managed. |
| `workspace` | local address | no | no | Names a `[workspaces.*]` block, resolved through its binding at plan time. |
| `workspace_id` | UUID string | no | no | A workspace Keymaster does not manage. Never alongside `workspace`. |
| `creator_user_id` | string | no | no | The organization member the key is created for. Trimmed, 1 to 128 characters, no whitespace. |
| `guardrail` | local address | no | yes | Names a `[guardrails.*]` block. Clearing unassigns. |
| `receiver` | local address | no | no | Names a `[receivers.*]` block. |
| `generation` | integer ≥ 1 | no (default `1`) | no | Raise it to ask for a replacement. |
| `include_byok_in_limit` | bool | no | no | Inherits `defaults`. Always managed. |
| `clear` | array of string | no | — | `"limit_usd"`, `"limit_reset"`, `"expires_at"`, `"guardrail"`. |

**`expires_at`, `workspace_id`, and `creator_user_id` are fixed at creation.**
`POST /keys` accepts them and `PATCH /keys/{hash}` has no field for any of them,
so changing one here plans a replacement rather than an update. So does raising
`generation` or changing which receiver the key delivers to.

**A key or guardrail whose `workspace` block is not bound yet is held back.**
OpenRouter fixes a workspace at creation, so the identity has to exist before
anything is placed in it. The first run creates the workspace; the next one
creates what goes inside.

**A key with no `receiver` can be managed and imported but never created.**
There is no fallback destination for a plaintext key and Keymaster will not
print one.

## `[log_destinations.ADDRESS]`

A log destination is where OpenRouter forwards a workspace's request logs.
Identity is the destination UUID: removing the block orphans the binding,
`openrouter-keymaster import log-destination NAME --id UUID` binds an existing
one, and `openrouter-keymaster delete log-destination --id UUID` is the only
deletion.

```toml
[log_destinations.club_audit]
type = "datadog"
name = "Golf Club audit log"
workspace = "golf_club"
enabled = true
privacy_mode = false
sampling_rate = 1
config = { site = "datadoghq.com", apiKey = "REPLACE-ME" }
```

| Field | Type | Required | Clearable | Notes |
| --- | --- | --- | --- | --- |
| `type` | string | yes | no | One of the types below. Fixed when the destination is created. |
| `name` | string | yes | no | Remote display name. Mutable remotely and never an identifier. |
| `config` | table | yes | no | Provider-specific, validated server-side. **May hold a credential.** |
| `enabled` | bool | no (default `true`) | no | Whether the destination forwards anything. |
| `privacy_mode` | bool | no (default `false`) | no | When true, request and response bodies are withheld and only metadata is forwarded. |
| `sampling_rate` | number | no | no | The fraction of requests forwarded, between 0.0001 and 1 and no finer than a millionth. Omitted leaves the remote value alone. |
| `workspace` | local address | no | no | Names a `[workspaces.*]` block. Fixed at creation. |
| `workspace_id` | UUID | no | no | A workspace Keymaster does not manage. Never alongside `workspace`. |

A log destination block has no `clear` list: every field it has is either
required or has a default, so there is nothing to set back to nothing. Writing
`clear` here is an unknown field and a hard error.

The accepted `type` values are `arize`, `braintrust`, `clickhouse`, `datadog`,
`grafana`, `langfuse`, `langsmith`, `newrelic`, `opik`, `otel-collector`,
`posthog`, `ramp`, `s3`, `sentry`, `snowflake`, `weave`, and `webhook`. Anything
else is rejected here, naming the field, rather than sent and refused remotely.

**`config` is write-only, and this file is a secret because of it.** The shape
of `config` depends on `type` and OpenRouter validates it server-side, so
Keymaster passes the table through as JSON and checks nothing about it beyond
its being a non-empty table. Every type that ships logs to a hosted service —
`arize`, `braintrust`, `datadog`, `grafana`, `langfuse`, `langsmith`,
`newrelic`, `opik`, `posthog`, `ramp`, `sentry`, `snowflake`, `weave` — needs
that service's API key or token in `config`; `clickhouse` and `s3` need
connection credentials; `otel-collector` and `webhook` need one whenever the
endpoint you name requires an authorization header. **Assume `config` holds a
secret: keep a file with a `[log_destinations.*]` block out of version control,
or encrypt it the way you would any other secret.** Keymaster protects the value
inside its own process — it is never printed, never written to state, never put
in an error, and cleared from the buffers it passes through — but what the file
itself holds is outside its reach.

Because reads mask `config`, there is nothing to compare a desired value
against. State records a **SHA-256 digest of the canonical JSON** of what
Keymaster last wrote, and the planner compares digests: an equal digest is
converged, and a changed one is an `update` whose diff says `config` and nothing
else — never what changed, and never either value. A destination you imported
has no stored digest, so its first apply writes `config` once and records the
digest from then on. Apply does not read `config` back: it verifies every other
field as usual and treats the `2xx` on the write as the configuration having
landed, which is the only evidence the API offers. Two consequences follow, and
both are real: a write that returned `2xx` but did not take effect is not
detected, and an out-of-band edit to `config` in the dashboard is invisible
until the configured value changes.

`config` accepts strings, whole numbers, booleans, arrays, and nested tables,
and nothing else — a fractional number and a TOML datetime are both refused,
naming neither. Every accepted scalar has one exact JSON spelling, while a
digest of a rendered float would be a comparison that depends on formatting, and
a datetime has no JSON form at all. Write a timestamp as a string if a provider
wants one.

**`type` and the workspace are fixed when the destination is created.**
OpenRouter's `PATCH` accepts neither, and Keymaster never replaces a destination
on its own — doing so would stop and restart log forwarding without being asked.
A change to either is planned as held-back drift naming the field, and the plan
names the command that clears it: `openrouter-keymaster delete log-destination
--id UUID`, after which the next apply creates the destination the configuration
now describes.

**The key allowlist is managed as always empty.** OpenRouter lets a destination
carry a list of API key hashes whose traffic it forwards; Keymaster does not
model it, and manages it as the empty list, so a destination forwards every key
in its workspace. An allowlist OpenRouter holds — on a destination you imported,
or after an out-of-band edit — is drift the next apply clears by sending `null`.

`filter_rules` and the three `broadcast_*` flags are not modelled at all. They
are never sent and never diffed, so whatever you set in the dashboard is
preserved.

**A destination that is bound and absent is reported, never recreated**, for the
reason a workspace is: a new destination has a new UUID, and recreating one
silently would restart log forwarding under an identity nothing recorded.

Destinations are ordered after workspaces, and one naming a `workspace` block
nothing is bound to yet is held back until the binding exists — the same rule
keys and guardrails follow.

## `[receivers.ADDRESS]`

A receiver is where a newly created key's plaintext goes. It has no remote
counterpart: nothing about a receiver is sent to OpenRouter, and there is
nothing to clear.

```toml
[receivers.laptop_file]
type = "file"
path = "/var/lib/keymaster/laptop-pi.key"

[receivers.jobfeed_vault]
type = "command"
program = "/usr/local/bin/keymaster-vault-receiver"
args = ["add-file", "jobfeed_openrouter_api_key"]

[receivers.host]
type = "caller"
destination = "vault/jobfeed"
```

| Field | Type | Required | Applies to | Notes |
| --- | --- | --- | --- | --- |
| `type` | `"file"`, `"command"`, or `"caller"` | yes | all | Selects the variant. Fields from another variant are a syntax error. |
| `path` | string | yes | `file` | Absolute path of the file to write. |
| `program` | string | yes | `command` | Absolute path of the executable. Run with no shell. |
| `args` | array of string | no (default `[]`) | `command` | At most 64. Never carries secret material. |
| `destination` | string | yes | `caller` | A non-secret label for where the host puts the plaintext. At most 200 characters. |

`path` and `program` must be absolute, at most 4096 bytes, free of control
characters and `..` components, and not credential-shaped. Spaces and non-ASCII
characters are fine. Each `args` element is held to the same length, control
character, and credential rules, minus the ones about being a path. `destination` is trimmed, must not be empty, and carries no
control characters and nothing credential-shaped; Keymaster never interprets it.

**A `caller` receiver only works inside a library host.** It hands the plaintext
to code the host supplies on the operation context, so the
`openrouter-keymaster` command line — which has none — refuses to issue a key
through one, in the preflight before anything is created. `plan` and `status`
are unaffected.

Keymaster derives a **receiver fingerprint** — a SHA-256 over the type and the
path, over the program and each argument, or over the block's own address and
its destination — and records it in state. Changing any part of a receiver
changes the fingerprint, and that is a reason to replace the key rather than to
leave a live credential in a destination the configuration no longer names.

[`docs/receiver-protocol.md`](receiver-protocol.md) is the contract for writing
a command receiver, and describes the `caller` receiver in full.

## Value rules

**Budgets and intervals** go together. A reset interval with no budget is
rejected everywhere: there is nothing to reset. The other direction differs by
kind. A guardrail budget must name a `reset_interval` — OpenRouter refuses to
create or update a guardrail limit that has none. A key budget need not: the
API defines a key with no `limit_reset` as a spending cap that never refills.

**USD amounts** (`limit_usd`) accept an integer or a float; `10`, `10.50`, and
`1e1` are all legal. An amount must be non-negative, at most 1 000 000 000, and
no finer than a millionth of a dollar. Infinities and NaN are refused.

**Model and provider slugs** are trimmed and lowercased, then must be printable
ASCII with no spaces, at most 200 characters — `google/gemini-2.5-flash` is the
shape. Slug lists are sorted and deduplicated before they are compared or sent,
so reordering one changes nothing. An **omitted** list is unmanaged; a list
written as `[]` is managed and empty, which is sent as an explicit clear and
means "restricts nothing".

**Remote names** (`name`) are trimmed, 1 to 200 characters, and carry no control
characters. Two blocks of the same kind may not share one: two workspaces, two
guardrails, two keys, or two log destinations. The check is per kind, so a key
and a guardrail may.

**Descriptions** are trimmed, must not be empty, carry no control characters,
and are at most 1000 characters. `description = ""` is an error rather than a
way to remove one — name it in `clear` instead.

**Timestamps** are RFC 3339 with an offset — `2027-01-01T00:00:00Z` — and are
converted to UTC, so two spellings of the same instant compare equal.

**UUIDs** are the canonical 8-4-4-4-12 hexadecimal form, lowercased on parse.

**References** — `guardrail` and `receiver` on a key, `workspace` on a key, a
guardrail, or a log destination, and `default_guardrail` on a workspace — must
match a declared table key exactly, including letter case. A dangling reference
is an error naming the block to add.

**Setting a field and listing it in `clear`** is an error rather than a
precedence rule. Pick one, or omit the field to leave the remote value alone.
