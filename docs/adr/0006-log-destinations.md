# ADR-0006: Log destinations as a managed resource

- **Date:** 2026-08-27
- **Status:** Proposed

## Context

OpenRouter can forward request logs to an observability sink
(`/observability/destinations`: Datadog, S3, a webhook, and others). The live
OpenAPI document shows: `POST` takes `type`, `name`, `config` (a
provider-specific object validated server-side), `enabled`, `privacy_mode`,
`sampling_rate`, an optional `api_key_hashes` allowlist, and `workspace_id`;
`PATCH` accepts neither `type` nor `workspace_id`; reads return `config` with
secret fields masked.

`config` is the first configuration value Keymaster would hold that can
contain a third-party credential (a Datadog API key, a webhook token). That is
a different thing from the OpenRouter credentials ADR-0001 keeps out of
configuration, and it needs its own rule.

## Decision

1. **A log destination is a managed resource.** `[log_destinations.NAME]`
   carries `type`, `name`, `config` (a TOML table passed through as JSON),
   `enabled`, `privacy_mode`, `sampling_rate`, and `workspace` (local address,
   or raw `workspace_id`). Identity is the destination ID; import by ID,
   orphaning on removal, and explicit `delete log-destination --id ID` follow
   the workspace rules of ADR-0004, and the planner orders destinations
   after workspaces and holds one back until its workspace is bound. The
   `api_key_hashes` allowlist is managed as always empty — a destination
   forwards all keys in its workspace — so an observed non-empty allowlist,
   on an imported destination or after an out-of-band edit, is drift that
   apply clears by sending `null`.
2. **`type` and `workspace` are immutable.** A change to either is planned as
   held-back drift that names the field and says the destination must be
   deleted and recreated explicitly. Nothing does that for the operator.
3. **`config` is write-only.** State records a digest of the canonical JSON of
   the desired `config`. The planner compares the desired digest to the stored
   one, never to the masked value OpenRouter returns: a changed digest is an
   `update` whose diff says `config: changed` and nothing else; an equal digest
   is converged. An imported destination has no stored digest, so its first
   apply writes `config` once and records the digest. Apply does not read
   `config` back to verify it — it verifies the other fields and treats a `2xx`
   on the write as the config having landed, which is the only evidence the
   API offers.
4. **`config` is a secret-bearing type.** In the public `Config`, a
   destination's `config` is a `DestinationConfig` that deserializes from TOML
   through its own visitor, whose errors are fixed text — a value never enters
   a deserializer message, the same rule the create-response parser follows —
   prints `[redacted]` from `Debug`, has no public `Serialize`, and zeroizes
   its strings on drop. The only serialization is a crate-private one that
   builds the request body and the canonical JSON for the digest, into
   buffers that are zeroized afterwards, and `Config::load` reads the file
   into a buffer that is zeroized as well. The plan fingerprint takes the
   digest, never the value. The existing
   redactor recognizes only OpenRouter's `sk-or-` marker, so in addition, when
   an op loads a destination block it registers every string value in
   `config` of sixteen characters or more with the redactor for the rest of
   the run, and redaction scrubs them by exact match from every error,
   warning, and report. The length bound is a heuristic and is stated as one:
   credentials are long, and short values such as a region or a flag would
   otherwise be scrubbed out of every sentence that happens to contain them. Errors from
   destination writes carry the HTTP status and OpenRouter's error code only —
   never the response body, which may quote the submitted value. What the file itself
   holds is outside Keymaster's reach: the configuration reference says which
   types need a credential in `config` and that such a file must be kept out
   of version control or encrypted like any other secret.

## Consequences

- Log forwarding for a workspace is one block, applied like anything else.
- Redaction of `config` values is by exact match, so a value that also
  appears legitimately elsewhere (a hostname, a region) is scrubbed wherever
  it shows up. Harmless, occasionally puzzling.
- Verification is weaker for `config` than for every other managed field:
  a write that returned `2xx` but did not take effect is not detected. That
  is the API's limit, and the docs state it.
- Out-of-band edits to `config` in the dashboard are invisible to Keymaster,
  which will not overwrite them until the configuration changes.
- The immutable fields make the first wrong `type` a delete-and-recreate.

## Alternatives considered

**Read `config` from the environment or a file at apply time.** Keeps the
credential out of the TOML but adds a second secret channel with its own rules.
Rejected for v0.3; it is additive if the write-only file proves unworkable.

**Compare against the masked value.** Rejected: masked fields compare equal to
anything and unmasked ones would echo into diffs; a digest of the desired
value is simpler and never prints a secret.

**Model the key allowlist.** Rejected for v0.3: it needs a key → destination
dependency and hashes that only exist after issuance. Workspace scoping covers
the club case.

## References

- [ADR-0004](0004-workspaces.md)
- OpenAPI: <https://openrouter.ai/openapi.json>
