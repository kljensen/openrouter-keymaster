# ADR-0004: Workspaces as a managed resource

- **Date:** 2026-08-27
- **Status:** Accepted

Accepted on 2026-08-27, through automated code review of the two commits that
implement it. This repository currently has a single maintainer committing
directly to `main`, so that review stands in for a second human reviewer; see
[the ADR convention](README.md#review).

The status changed only after the last of those commits, so nothing was binding
while the shape was still moving.

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

### Implementation checks

Both steps are merged. These checks exist and run in `just check`. The decision
above is unchanged; this section records where each part of it is enforced, and
what is still unverified.

- **The workspace as a managed resource** (item 1) —
  `crates/core/src/config/mod.rs` and `crates/core/src/config/validate.rs` for
  the block, `crates/core/src/plan/` for the diff, `crates/core/src/ops/apply.rs`
  for the create and update, `crates/core/src/ops/import.rs::import_workspace`,
  and `crates/core/src/ops/lifecycle.rs::delete_workspace` and `forget`. Covered
  by `crates/cli/tests/workspaces.rs`: the identity is recorded before anything
  else, removing the block orphans the binding and deletes nothing, a delete is
  refused while the workspace still holds a key, a guardrail, or a log
  destination, and a bound workspace that vanished is reported rather than
  recreated.
- **Workspace by local address, and the ordering** (item 2) —
  `crates/core/src/plan/mod.rs` orders workspaces before guardrails before keys,
  and `mark_blocked` holds back a block whose workspace is not bound.
  *Refined on 2026-08-28, after the first live run.* "Not yet bound" is read as
  the state the workspace's own action leaves it in, rather than as the absence
  of a binding at plan time: when this plan creates the workspace, its contents
  depend on that create and run after it, resolving their placement from the
  binding apply records before anything else — the same shape as a key create
  depending on a guardrail create in the same plan. A workspace only an operator
  can bind — an adoption, one nobody can find — still holds everything in it
  back. Without this a fresh configuration needed two applies to converge, which
  the decision never intended. Covered by
  `everything_in_a_workspace_this_plan_creates_depends_on_it_rather_than_waiting`,
  `a_workspace_waiting_on_an_adoption_still_holds_everything_in_it_back`,
  `a_bound_workspace_that_is_gone_is_missing_rather_than_recreated`, and
  `a_workspace_its_default_guardrail_and_a_key_all_converge_in_one_apply`.
  A guardrail OpenRouter has in another workspace is held back rather than
  patched, and `import guardrail` refuses it
  (`importing_a_guardrail_from_another_workspace_binds_nothing`).
  *Refined again on 2026-08-28.* The same-run exception is for creates and only
  creates. A guardrail, key, or destination this plan creates takes its
  placement from the binding apply records a phase earlier; one that already
  exists cannot be moved, because OpenRouter fixes its workspace at creation. So
  every resource that already exists and whose block names a workspace nothing
  binds yet is held back until there is a binding to judge the placement
  against — otherwise the run would converge its fields, leave it in a workspace
  the configuration no longer names, and report success. A key's `replace`
  creates a key, so it is a create here too. The rule is read from each block's
  configured placement rather than from the plan's dependency edges, because the
  edges are not where it shows: a resource whose fields already match has no
  edges and a `no_op` action, and a key's update carries no workspace dependency
  either, yet both would otherwise be reported as converged — or, for the key,
  widened — in the wrong workspace. An assignment is placed where its key is,
  and is held back with it: it is planned at its own address, a removal depends
  on nothing and an assignment only on its guardrail, so neither would have been
  reached through the key. The assignment beside a key this plan creates or
  replaces is exempt with that key, because it belongs to the successor rather
  than to the predecessor whose binding the placement lookup would otherwise
  find. Covered by
  `a_bound_resource_moved_into_a_workspace_this_plan_creates_is_held_back`,
  `a_converged_resource_in_a_workspace_this_plan_creates_is_held_back_too`,
  `an_assignment_is_held_back_with_the_key_whose_workspace_is_unresolved`, and
  `a_replaced_key_and_its_assignment_run_in_the_workspace_this_plan_creates`.
- **The default guardrail** (item 3) — planned as a create carrying
  `default_guardrail_unmaterialized` and performed as the first `PATCH` to the
  identity the workspace names
  (`a_default_guardrail_is_materialized_by_patching_the_identity_its_workspace_names`),
  bound by `import workspace`
  (`importing_a_workspace_records_its_default_guardrail_and_binds_the_block`),
  held back when the address owns another guardrail, and released with the
  workspace by both `delete workspace` and `state forget`.
  *Refined on 2026-08-28, after probing a throwaway workspace on the live API.*
  Two facts the decision assumed otherwise:
  1. **The name is the server's.** OpenRouter names a workspace's default
     guardrail `Workspace <workspace-uuid> Default`, and `PATCH` with a `name`
     answers `400 A workspace default guardrail's name is not editable`, while
     the same `PATCH` with `allowed_models`, `limit_usd`, `reset_interval`, or
     `description` returns `200` and materializes the guardrail. So `name` is
     optional on a guardrail block and refused on a default one, it is never
     sent, and it is never diffed there; every other guardrail still requires
     it, and `status` reports the observed name read-only. Without this the
     first apply of any workspace scenario failed on the create.
  2. **It is in one listing and one only: its own workspace's.** A materialized
     default guardrail is absent from an unscoped `GET /guardrails` (tested to
     `limit=100`) and present in `GET /guardrails?workspace_id=<its
     workspace>`, with its fields and its `workspace_id`. Before it is
     materialized it is in neither, and `GET /guardrails/{id}` answers `404`.
     That is one instance of the listing rule under item 5 below, so it needs
     no mechanism of its own: the snapshot's per-workspace listings observe it.
     "Absent from the listing" therefore reads "absent from the observation"
     throughout: a materialized default guardrail is present and diffs like any
     other, an unmaterialized one is the create-by-`PATCH` case, and a default
     guardrail is never a name candidate for a recreation — matched by the
     `default_guardrail_id` its workspace carries, never by name, because its
     name is not one any configuration can ask for. Covered by
     `a_materialized_default_guardrail_converges_without_ever_diffing_its_name`
     and
     `a_default_guardrail_has_no_name_of_its_own_and_every_other_guardrail_needs_one`.
  A third refinement is about the run rather than the API: when a workspace
  create's response carries no `default_guardrail_id`, the guardrail is held
  back — there is no identity to `PATCH` — and everything depending on it is now
  held back with it, rather than reaching issuance with no guardrail to secure
  the key
  (`a_workspace_create_that_discloses_no_default_guardrail_holds_back_what_waits_on_it`).
- **Budgets, their order, and definite refusals** (item 4) —
  `crates/core/src/ops/apply.rs` (`budget_writes` and `Budgets`) with
  `crates/core/src/api/mod.rs::put_workspace_budget` and
  `delete_workspace_budget`; the offline ordering rule is in
  `crates/core/src/config/validate.rs`. Covered by
  `budget_increases_are_written_widest_first_and_decreases_narrowest_first`,
  `an_interval_the_table_drops_is_deleted_before_anything_is_raised`,
  `a_refused_budget_interval_fails_alone_and_holds_back_everything_it_would_have_capped`,
  and `a_budget_write_that_never_got_an_answer_is_unverified_rather_than_refused`
  — which is the line between a definite refusal and an unsettled write.
  *Refined on 2026-08-28.* The holdback is applied at execution time as well as
  at plan time. A workspace this run creates has no binding when the plan is
  computed, so the planner cannot judge its budget; if a `PUT` is then refused
  or left unsettled, apply records that workspace and holds back every issuing
  or expanding write placed in it for the rest of the run, naming it. Routine
  writes still proceed, and the workspace's own writes are still exempt. Covered
  by `a_refused_budget_on_a_workspace_this_run_creates_holds_back_the_key_inside_it`.
- **The scope** (item 5) — `crates/core/src/ops/mod.rs`
  (`refuse_other_workspaces`, `refuse_out_of_scope`) with the filtering in
  `crates/core/src/plan/` and `crates/core/src/report/`. Covered by
  `crates/cli/tests/scope.rs`: reports omit another workspace's `unmanaged`
  resources, an identically named resource elsewhere is neither a candidate nor
  a collision, a bound key is judged present or missing the same way either way,
  the plan fingerprint separates a scoped plan from an unscoped one, and a
  misplaced block is refused before any request.
  *Refined on 2026-08-28, after the fourth live run.* "The snapshot is the whole
  organization" needs more than one request per resource. `GET /keys` and
  `GET /guardrails` answer for the credential's default workspace unless
  `workspace_id` names another — an unscoped `GET /keys` does not return a
  workspace's keys, `include_disabled` or not — so both are now read once
  without a workspace and once per workspace the run found, deduplicated by
  identity, exactly as `GET /observability/destinations` already was. Without
  it the verification read after a scoped key create could not see the key it
  had just made, and reported it as accepted but unconfirmed; a plan computed
  from that snapshot would have offered to create a second one. A per-workspace
  listing that answers `404` is skipped — the workspace was deleted underneath
  the snapshot, and a workspace that is gone holds nothing — and any other
  failure fails the snapshot rather than truncating it. `recover inspect` reads
  the same union, because a leaked key in another workspace is exactly what its
  candidate listing exists to find. Covered by
  `every_workspace_is_listed_and_the_union_is_deduplicated` and
  `a_workspace_that_is_gone_by_the_time_its_listing_runs_holds_nothing`.

What no local check can reach is whether the real API behaves this way. The
opt-in `live_workspace_create_budget_default_guardrail_and_scoped_key` in
`crates/cli/tests/live.rs` covers the create, the default guardrail, one budget
`PUT`, the update, a scoped key, and the import.

*Updated 2026-08-28.* It has now been run against a real organization. The
workspace create and the budget `PUT` were both accepted: budgets are documented
as Enterprise, and they were accepted on the tested account, so item 4's
holdback path is still asserted from the documentation rather than observed. No
workspace delete has been sent by an operation, though the acceptance suite's
own sweep deletes the workspaces it creates. The same runs found the two-apply
behavior corrected under item 2, the two default-guardrail facts under item 3,
and the per-workspace listing rule under item 5 — the last of which is what made
a scoped key create report itself as accepted but unconfirmed. Still unverified:
whether OpenRouter allows a `DELETE` on a workspace's own default guardrail. The
sweep now asks once per run and journals the answer. See
[`docs/live-tests.md`](../live-tests.md).
