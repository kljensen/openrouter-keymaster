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

**Nothing here may be secret.** The management credential comes from the
environment and a new key's plaintext goes to a receiver. Any value containing
`sk-or-` — an inference key or a management key, in any letter case — is
refused, as is any field this schema does not define.

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

The table key in `[guardrails.NAME]`, `[keys.NAME]`, and `[receivers.NAME]` is a
**local address**. It is Keymaster's name for the resource, it is never sent to
OpenRouter, and it is what `state forget`, `rotate`, `retire`, and `import` take
as an argument. Changing one is not a rename — it is a new address bound to
nothing, and the old binding becomes an orphan.

An address is 1 to 64 characters of ASCII letters, digits, `_`, and `-`,
starting with a letter or a digit, and may not contain `sk-or-`. Two addresses
of the same kind may not differ only by letter case.

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
| `workspace_id` | UUID string | no | no | |
| `creator_user_id` | string | no | no | The organization member the key is created for. |
| `guardrail` | local address | no | yes | Names a `[guardrails.*]` block. Clearing unassigns. |
| `receiver` | local address | no | no | Names a `[receivers.*]` block. |
| `generation` | integer ≥ 1 | no (default `1`) | no | Raise it to ask for a replacement. |
| `include_byok_in_limit` | bool | no | no | Inherits `defaults`. Always managed. |
| `clear` | array of string | no | — | `"limit_usd"`, `"limit_reset"`, `"expires_at"`, `"guardrail"`. |

**`expires_at`, `workspace_id`, and `creator_user_id` are fixed at creation.**
`POST /keys` accepts them and `PATCH /keys/{hash}` has no field for any of them,
so changing one here plans a replacement rather than an update. So does raising
`generation` or changing which receiver the key delivers to.

**A key with no `receiver` can be managed and imported but never created.**
There is no fallback destination for a plaintext key and Keymaster will not
print one.

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
characters are fine. `destination` is trimmed, must not be empty, and carries no
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
characters. Two guardrails may not share a remote name, and neither may two
keys; the check is per kind, so a key and a guardrail may.

**Timestamps** are RFC 3339 with an offset — `2027-01-01T00:00:00Z` — and are
converted to UTC, so two spellings of the same instant compare equal.

**UUIDs** are the canonical 8-4-4-4-12 hexadecimal form, lowercased on parse.

**References** (`guardrail`, `receiver`) must match a declared table key exactly,
including letter case. A dangling reference is an error naming the block to add.

**Setting a field and listing it in `clear`** is an error rather than a
precedence rule. Pick one, or omit the field to leave the remote value alone.
