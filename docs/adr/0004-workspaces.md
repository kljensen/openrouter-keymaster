# ADR-0004: Workspaces as a managed resource

- **Date:** 2026-08-27
- **Status:** Proposed

## Context

A web application will issue capped inference keys to student clubs. Each club
gets an OpenRouter workspace: the unit that carries a pooled spending cap and a
default guardrail. Students never become organization members, because every
member automatically gets the Default workspace and can create keys there.

What the live OpenAPI document offers:

- `POST /workspaces` (`name`, `slug` required; `description`), `PATCH
  /workspaces/{id}`, `DELETE /workspaces/{id}`.
- Budgets: `PUT`/`DELETE /workspaces/{id}/budgets/{daily|weekly|monthly|lifetime}`
  with `limit_usd`; the server requires lifetime > monthly > weekly > daily. A
  met budget returns `403` on every request. The docs list budgets as an
  Enterprise feature. `include_byok_in_budgets` is a workspace-wide setting,
  readable on the workspace but writable only in a budget `PUT`.
- Every workspace has a `default_guardrail_id`, a deterministic ID derived
  from the workspace ID. The guardrail does not appear in listings until its
  configuration is first written; after that it is an ordinary guardrail that
  governs all traffic in the workspace.
- `GET /keys` and `GET /guardrails` accept a `workspace_id` filter.

Keymaster manages keys and guardrails (ADR-0001) and exposes them to hosts
through `ops` (ADR-0003). Keys and guardrails already carry a raw
`workspace_id`. Nothing creates a workspace, sets a budget, configures a
default guardrail, or keeps one club's view separate from another's.

## Decision

1. **A workspace is a managed resource.** `[workspaces.NAME]` carries `name`,
   `slug`, `description`, `budgets` (a table with any of `daily`, `weekly`,
   `monthly`, `lifetime` in USD; ordering validated offline), and
   `include_byok_in_budgets` (allowed only when at least one budget is
   configured, because only a budget `PUT` can write it). Identity is the
   workspace UUID. `import workspace NAME --id UUID` binds an existing one;
   removing the block orphans the binding; `delete workspace --id UUID` is the
   only deletion. It refuses while the remote workspace contains any key,
   guardrail, or log destination (ADR-0006) — tracked or not, since deleting
   a workspace can take its children with it and ADR-0001 forbids destroying
   what Keymaster does not manage — except the workspace's own default
   guardrail, which is part of the workspace: deleting the workspace removes
   that binding with it, since the guardrail cannot outlive its workspace and
   cannot be deleted on its own.
2. **Keys and guardrails name their workspace by local address.**
   `workspace = "club_x"` resolves through the binding at plan time; the raw
   `workspace_id` form stays for workspaces Keymaster does not manage; both on
   one block is a validation error. The planner orders workspaces before
   guardrails before keys, and holds back a key or guardrail whose workspace
   is not yet bound.
3. **The default guardrail is a guardrail block bound to
   `default_guardrail_id`.** `default_guardrail = "<guardrail address>"` on a
   workspace binds that block to the workspace's deterministic ID. A guardrail
   address may be named as the default of exactly one workspace, and its
   workspace is that one: the block omits `workspace`, or names the same
   workspace; naming another is a validation error. The planner
   has one rule for it: a guardrail bound to the `default_guardrail_id` of a
   workspace that exists remotely is never `missing`; when absent from the
   listing it is planned as `create`, and apply performs that create as the
   first `PATCH` to the ID, which is how OpenRouter materializes it. Once
   listed, it is an ordinary guardrail. It is never imported by name, never
   created by `POST`, and never deleted on its own.
4. **Budgets are written per interval, in an order the server accepts, and
   refusals are definite.** Each configured interval is one `PUT` (carrying
   `include_byok_in_budgets`); a removed interval is one `DELETE`. Because
   the server checks lifetime > monthly > weekly > daily on every write,
   apply orders them so no intermediate state violates it: deletes first,
   then increases from the widest interval to the narrowest, then decreases
   from the narrowest to the widest. A `403` or plan-restriction response is a
   definite failure naming the interval — never ambiguity. Independent work
   continues, but in a workspace whose configured budget did not converge
   every action the planner classifies as *issuing* or *expanding* is held
   back — creating or replacing a key, enabling one, raising or clearing a
   limit, shortening a reset interval, excluding BYOK spend, removing or
   widening a guardrail, raising a guardrail's limit — using the safety
   classification that already exists. The workspace's own budget writes are
   exempt, since they are what converges it. Routine writes and reports
   proceed.
   Spend enabled under a cap that is not in force is exactly what the budget
   was for. So an account without the
   feature sees which writes were refused on every run, and no new keys in
   that workspace, until the budget leaves the configuration.
5. **`Context` gains an optional workspace scope, applied to reporting and
   placement, not to state.** With `workspace: Some(id)`: validation rejects a
   configuration whose keys, guardrails, log destinations (ADR-0006), or
   workspace blocks name any other workspace, and rejects a workspace block
   that is not already bound to that ID — a scoped run cannot create its own workspace, because the created
   UUID could never equal the scope; the operator applies unscoped once, or
   imports, and scopes from then on. Every created key, guardrail, and log
   destination is placed in the scope; reports omit `unmanaged` resources
   outside it; and matching by name — adoption candidates, the collision
   check before a guarded recreation — considers only resources in the
   scope, so another club's identically named key cannot block this one.
   Matching by identity, which decides whether a bound resource is present
   or missing, uses the full snapshot as before. The snapshot itself is still the
   whole organization, so a bound resource is judged present or missing
   exactly as it is today, and a shared state file cannot make another
   scope's bindings look orphaned. A host that wants separate clubs to stay
   separate keeps one config and one state file per club; the scope is a
   guard on placement and a filter on noise, not an isolation mechanism.
   Without a scope, behavior is unchanged. The plan fingerprint (ADR-0003)
   includes the scope.

Not decided here: workspace members, guardrail assignments to members, and
the workspace's model defaults and I/O-logging settings. Each is additive.

## Consequences

- The club case becomes one workspace block per club, applied like any other
  resource, and one scoped `Context` per club in the host.
- A third managed resource means a third set of planner, state, import, and
  delete paths that must agree; the ordering rule is the only new dependency.
- Budgets refused by the account's plan are visible as failed writes on every
  apply until removed. Honest, and noisy.
- The default-guardrail rule is a deliberate exception to "bound but absent
  means missing". It is narrow — it applies only to an ID the workspace object
  itself names — and it is the only way to reach that guardrail at all.
- The scope does not isolate: an operator who points two scopes at one state
  file gets correct but mixed plans. The documentation says so.

## Alternatives considered

**Imperative workspace calls for the host to drive.** Rejected: the CLI needs
workspaces too, and the declarative model — UUID identity, import, no implicit
deletion, planned diffs — is what makes a second run safe. Two paths would
mean two sets of rules.

**Filter state by scope.** Rejected: state does not record a workspace per
binding, and filtering the snapshot without the state makes every out-of-scope
binding look missing. Filtering reports and guarding placement gives the host
what it needs without a second state model.

**Pooled caps enforced by Keymaster.** Rejected: OpenRouter enforces per-key
and per-workspace limits; a pooled cap across keys would be Keymaster's own
accounting racing spend it does not control. Where the plan allows, the
workspace budget is that cap; otherwise the host sizes per-key limits.

## References

- [ADR-0001](0001-native-reconciliation.md), [ADR-0003](0003-core-library-split.md)
- Workspace budgets: <https://openrouter.ai/docs/guides/features/workspaces/workspace-budgets>
- Guardrails: <https://openrouter.ai/docs/guides/features/guardrails>
- OpenAPI: <https://openrouter.ai/openapi.json>
