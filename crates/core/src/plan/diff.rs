//! Managed-field comparison.
//!
//! Only fields the desired model represents are compared. Everything else a
//! remote object carries — usage counters, per-provider ZDR flags, timestamps,
//! anything OpenRouter adds tomorrow — is left alone, because a field
//! Keymaster cannot express is a field it must not overwrite.
//!
//! Both sides are normalized before they are compared, so an equality test is
//! the whole comparison: names are trimmed, an absent collection and an empty
//! one both mean "no restriction", a reset schedule and a budget arrive as the
//! same types the configuration parsed, and a value the configuration does not
//! manage is skipped rather than compared against a default.
//!
//! A [`Diff`] also decides, per field, whether the change widens what a
//! credential may do. Doing it here rather than in a later pass is what makes
//! the judgement typed: the code that knows a budget rose is the code that
//! compared the two budgets.

use std::collections::BTreeSet;

use time::OffsetDateTime;

use super::{Expansion, FieldChange, FieldValue};
use crate::api::{
    ObservedDestination, ObservedGuardrail, ObservedKey, ObservedWorkspace, ResetPolicy,
};
use crate::config::{
    BUDGET_INTERVALS, Guardrail, Key, LogDestination, Managed, ResetInterval, SamplingRate, Usd,
    Workspace,
};
use crate::ids::{RemoteName, UserId, Uuid};

/// Key fields OpenRouter fixes when the key is created.
///
/// A difference in one of these cannot be patched, so it is a reason to
/// replace the key rather than to update it.
pub(super) const IMMUTABLE_KEY_FIELDS: [&str; 3] =
    ["expires_at", "workspace_id", "creator_user_id"];

/// Log destination fields OpenRouter fixes when the destination is created.
///
/// `PATCH /observability/destinations/{id}` accepts neither, and unlike a key a
/// destination is never replaced automatically — replacing one would silently
/// stop and restart log forwarding — so a difference in one is drift nothing
/// can converge (ADR-0006, item 2).
pub(super) const IMMUTABLE_DESTINATION_FIELDS: [&str; 2] = ["type", "workspace_id"];

/// What a destination's write-only `config` shows on either side of a change.
///
/// A digest comparison has no values to print, and printing one is exactly what
/// the field exists to prevent, so both sides are fixed text (ADR-0006, item 3).
const CONFIG_UNREADABLE: &str = "(write-only)";
const CONFIG_CHANGED: &str = "changed";

/// Every managed difference between a desired key and the observed one.
///
/// `observed` is `None` when the key does not exist, which makes the same
/// function describe a create: every managed field differs from nothing.
///
/// `workspace` is the workspace the key belongs to once the block's `workspace`
/// address has been resolved through its binding — or the raw `workspace_id` it
/// names, or nothing. It is passed in rather than read from `desired` because
/// resolving an address needs state, which a pure comparison does not have.
pub fn key_changes(
    desired: &Key,
    observed: Option<&ObservedKey>,
    workspace: Option<&Uuid>,
) -> Vec<FieldChange> {
    let mut diff = Diff::new(observed.is_some());
    diff.name("name", observed.map(|key| key.name.as_str()), &desired.name);
    diff.budget(
        "limit_usd",
        observed.and_then(|key| key.limit),
        &desired.limit,
    );
    diff.interval(
        "limit_reset",
        observed.map(|key| &key.limit_reset),
        &desired.limit_reset,
    );
    diff.flag(
        "disabled",
        observed.map(|key| key.disabled),
        desired.disabled,
        Expansion::KeyEnabled,
    );
    diff.flag(
        "include_byok_in_limit",
        observed.map(|key| key.include_byok_in_limit),
        desired.include_byok_in_limit,
        Expansion::ByokExcludedFromLimit,
    );
    diff.timestamp(
        "expires_at",
        observed.and_then(|key| key.expires_at),
        &desired.expires_at,
    );
    diff.uuid(
        "workspace_id",
        observed.and_then(|key| key.workspace_id.as_ref()),
        workspace,
    );
    diff.user(
        "creator_user_id",
        observed.and_then(|key| key.creator_user_id.as_ref()),
        desired.creator_user_id.as_ref(),
    );
    diff.changes
}

/// Every managed difference between a desired guardrail and the observed one.
pub fn guardrail_changes(
    desired: &Guardrail,
    observed: Option<&ObservedGuardrail>,
) -> Vec<FieldChange> {
    let mut diff = Diff::new(observed.is_some());
    // A workspace's default guardrail has no configured name and its remote one
    // cannot be written, so there is nothing here to converge (ADR-0004,
    // item 3). `status` reports the name OpenRouter gave it.
    if let Some(name) = &desired.name {
        diff.name("name", observed.map(|rail| rail.name.as_str()), name);
    }
    diff.text(
        "description",
        observed.and_then(|rail| rail.description.as_deref()),
        &desired.description,
    );
    diff.allowed(
        "allowed_models",
        observed.and_then(|rail| rail.allowed_models.as_ref()),
        desired.allowed_models.as_ref(),
    );
    diff.denied(
        "denied_models",
        observed.and_then(|rail| rail.ignored_models.as_ref()),
        desired.denied_models.as_ref(),
    );
    diff.allowed(
        "allowed_providers",
        observed.and_then(|rail| rail.allowed_providers.as_ref()),
        desired.allowed_providers.as_ref(),
    );
    diff.denied(
        "denied_providers",
        observed.and_then(|rail| rail.ignored_providers.as_ref()),
        desired.denied_providers.as_ref(),
    );
    diff.budget(
        "limit_usd",
        observed.and_then(|rail| rail.limit),
        &desired.limit,
    );
    diff.interval(
        "reset_interval",
        observed.map(|rail| &rail.reset_interval),
        &desired.reset_interval,
    );
    diff.flag(
        "include_byok_in_limit",
        observed.map(|rail| rail.include_byok_in_budgets),
        desired.include_byok_in_limit,
        Expansion::ByokExcludedFromLimit,
    );
    // Only the single flag the configuration models. OpenRouter's per-provider
    // ZDR fields are not desired state, so they are preserved rather than
    // compared.
    diff.optional_flag(
        "require_zdr",
        observed.map(|rail| rail.zero_data_retention.any.unwrap_or(false)),
        desired.require_zdr,
        Expansion::ZdrWeakened,
    );
    diff.changes
}

/// Every managed difference between a desired workspace and the observed one.
///
/// The budgets are one field per interval, because that is how they are written
/// — one request each, in an order the server accepts (ADR-0004, item 4) — and
/// a single "budgets" field would hide which interval an apply could not set.
pub fn workspace_changes(
    desired: &Workspace,
    observed: Option<&ObservedWorkspace>,
) -> Vec<FieldChange> {
    let mut diff = Diff::new(observed.is_some());
    diff.name(
        "name",
        observed.map(|workspace| workspace.name.as_str()),
        &desired.name,
    );
    diff.plain(
        "slug",
        observed.map(|workspace| workspace.slug.as_str()),
        &desired.slug,
    );
    diff.text(
        "description",
        observed.and_then(|workspace| workspace.description.as_deref()),
        &desired.description,
    );
    if let Some(budgets) = &desired.budgets {
        for interval in BUDGET_INTERVALS {
            diff.budget_interval(
                interval.field(),
                observed.and_then(|workspace| workspace.budgets.get(&interval).copied()),
                budgets.get(&interval).copied(),
            );
        }
    }
    diff.optional_flag(
        "include_byok_in_budgets",
        observed.map(|workspace| workspace.include_byok_in_budgets),
        desired.include_byok_in_budgets,
        Expansion::ByokExcludedFromLimit,
    );
    diff.changes
}

/// Every managed difference between a desired log destination and the observed
/// one.
///
/// `workspace` is the workspace the destination belongs to once the block's
/// `workspace` address has been resolved, exactly as for a key.
///
/// `stored_digest` is the digest of the `config` this address last wrote, which
/// state records. It is the whole of the `config` comparison: the value
/// OpenRouter returns is masked, so it is never read, and a digest that differs
/// — or is absent, which is what an imported destination has — is the one thing
/// that puts `config` in the body of a write (ADR-0006, item 3).
pub fn log_destination_changes(
    desired: &LogDestination,
    observed: Option<&ObservedDestination>,
    workspace: Option<&Uuid>,
    stored_digest: Option<&str>,
) -> Vec<FieldChange> {
    let mut diff = Diff::new(observed.is_some());
    diff.plain(
        "type",
        observed.map(|destination| destination.kind.as_str()),
        desired.kind.as_str(),
    );
    diff.name(
        "name",
        observed.map(|destination| destination.name.as_str()),
        &desired.name,
    );
    // Neither flag is an [`Expansion`]: that vocabulary is about what a
    // credential may spend or reach, and a destination spends nothing and
    // reaches nothing. Turning `privacy_mode` off widens what leaves
    // OpenRouter, which the diff shows plainly and the safety class does not
    // pretend to grade.
    diff.simple_flag(
        "enabled",
        observed.map(|destination| destination.enabled),
        desired.enabled,
    );
    diff.simple_flag(
        "privacy_mode",
        observed.map(|destination| destination.privacy_mode),
        desired.privacy_mode,
    );
    diff.sampling_rate(
        "sampling_rate",
        observed.and_then(|destination| destination.sampling_rate),
        desired.sampling_rate,
    );
    diff.uuid(
        "workspace_id",
        observed.and_then(|destination| destination.workspace_id.as_ref()),
        workspace,
    );
    // The allowlist is managed as always empty, so anything OpenRouter has in
    // it is drift an apply clears by sending `null` (ADR-0006, item 1).
    diff.allowlist(
        "api_key_hashes",
        observed.map(|destination| &destination.api_key_hashes),
    );
    diff.config(desired, observed.is_some(), stored_digest);
    diff.changes
}

/// Accumulates the differences of one resource, in field order.
struct Diff {
    changes: Vec<FieldChange>,
    /// Whether the remote resource exists. When it does not, every field
    /// differs from nothing, and none of those differences widens anything:
    /// there is no credential yet to widen.
    exists: bool,
}

impl Diff {
    fn new(exists: bool) -> Self {
        Self {
            changes: Vec::new(),
            exists,
        }
    }

    /// Records a difference, if there is one.
    fn push(
        &mut self,
        field: &'static str,
        from: FieldValue,
        to: FieldValue,
        expansion: Option<Expansion>,
    ) {
        if from == to {
            return;
        }
        self.changes.push(FieldChange {
            field,
            from,
            to,
            expansion: if self.exists { expansion } else { None },
        });
    }

    /// A display name, which is always managed.
    fn name(&mut self, field: &'static str, from: Option<&str>, to: &RemoteName) {
        self.push(field, text_value(from), FieldValue::text(to.as_str()), None);
    }

    /// A plain string that is always managed, and is not a display name.
    fn plain(&mut self, field: &'static str, from: Option<&str>, to: &str) {
        self.push(field, text_value(from), FieldValue::text(to), None);
    }

    /// One workspace budget interval, which is managed as a whole or not at
    /// all: an interval the table does not name is removed.
    fn budget_interval(&mut self, field: &'static str, from: Option<Usd>, to: Option<Usd>) {
        let raised = budget_raised(from, to);
        self.push(
            field,
            from.map_or(FieldValue::Absent, FieldValue::Money),
            to.map_or(FieldValue::Absent, FieldValue::Money),
            raised.then_some(Expansion::BudgetRaised { field }),
        );
    }

    fn text(&mut self, field: &'static str, from: Option<&str>, to: &Managed<String>) {
        let Some(to) = managed(to, |value| FieldValue::text(value)) else {
            return;
        };
        self.push(field, text_value(from), to, None);
    }

    fn budget(&mut self, field: &'static str, from: Option<Usd>, to: &Managed<Usd>) {
        let Some(to_value) = managed(to, |amount| FieldValue::Money(*amount)) else {
            return;
        };
        let raised = budget_raised(from, to.value().copied());
        self.push(
            field,
            from.map_or(FieldValue::Absent, FieldValue::Money),
            to_value,
            raised.then_some(Expansion::BudgetRaised { field }),
        );
    }

    fn interval(
        &mut self,
        field: &'static str,
        from: Option<&ResetPolicy>,
        to: &Managed<ResetInterval>,
    ) {
        let Some(to_value) = managed(to, |interval| FieldValue::Interval(*interval)) else {
            return;
        };
        // A shorter period is a recurring budget rather than a lifetime one,
        // so the same limit permits more spending.
        let shortened = from
            .and_then(policy_rank)
            .is_some_and(|before| interval_rank(to.value().copied()) > before);
        self.push(
            field,
            from.map_or(FieldValue::Absent, policy_value),
            to_value,
            shortened.then_some(Expansion::BudgetResetShortened { field }),
        );
    }

    fn flag(&mut self, field: &'static str, from: Option<bool>, to: bool, relaxed: Expansion) {
        self.push(
            field,
            from.map_or(FieldValue::Absent, FieldValue::Flag),
            FieldValue::Flag(to),
            (from == Some(true) && !to).then_some(relaxed),
        );
    }

    fn optional_flag(
        &mut self,
        field: &'static str,
        from: Option<bool>,
        to: Option<bool>,
        relaxed: Expansion,
    ) {
        let Some(to) = to else { return };
        self.flag(field, from, to, relaxed);
    }

    /// A flag that is always managed and whose direction widens nothing a
    /// credential may do.
    fn simple_flag(&mut self, field: &'static str, from: Option<bool>, to: bool) {
        self.push(
            field,
            from.map_or(FieldValue::Absent, FieldValue::Flag),
            FieldValue::Flag(to),
            None,
        );
    }

    /// A sampling rate, compared only when the configuration manages one.
    fn sampling_rate(
        &mut self,
        field: &'static str,
        from: Option<SamplingRate>,
        to: Option<SamplingRate>,
    ) {
        let Some(to) = to else { return };
        self.push(
            field,
            from.map_or(FieldValue::Absent, |rate| {
                FieldValue::text(&rate.to_string())
            }),
            FieldValue::text(&to.to_string()),
            None,
        );
    }

    /// A list Keymaster manages as always empty: whatever is in it is drift.
    fn allowlist(&mut self, field: &'static str, from: Option<&BTreeSet<String>>) {
        let from = from.cloned().unwrap_or_default();
        self.push(
            field,
            FieldValue::Slugs(from),
            FieldValue::Slugs(BTreeSet::new()),
            None,
        );
    }

    /// A write-only configuration, compared by digest and never by value.
    ///
    /// Three cases, and they collapse to one question — does the digest state
    /// records match the digest of what the configuration now says? A create
    /// has no remote resource and writes the configuration as part of itself. An
    /// imported destination has no stored digest, so its first apply writes the
    /// configuration once. Anything else compares.
    fn config(&mut self, desired: &LogDestination, exists: bool, stored: Option<&str>) {
        if exists && stored == Some(desired.config.digest().as_str()) {
            return;
        }
        self.push(
            "config",
            if exists {
                FieldValue::text(CONFIG_UNREADABLE)
            } else {
                FieldValue::Absent
            },
            FieldValue::text(CONFIG_CHANGED),
            None,
        );
    }

    fn timestamp(
        &mut self,
        field: &'static str,
        from: Option<OffsetDateTime>,
        to: &Managed<OffsetDateTime>,
    ) {
        let Some(to_value) = managed(to, |when| FieldValue::Timestamp(*when)) else {
            return;
        };
        self.push(
            field,
            from.map_or(FieldValue::Absent, FieldValue::Timestamp),
            to_value,
            None,
        );
    }

    fn uuid(&mut self, field: &'static str, from: Option<&Uuid>, to: Option<&Uuid>) {
        let Some(to) = to else { return };
        self.push(
            field,
            from.map_or(FieldValue::Absent, |id| FieldValue::Guardrail(id.clone())),
            FieldValue::Guardrail(to.clone()),
            None,
        );
    }

    /// An organization member, compared only when the configuration names one.
    ///
    /// Like `uuid`: an unmanaged field is skipped rather than compared against
    /// nothing, because a configuration that says nothing about a key's creator
    /// must not read as "this key should have none" — which, the field being
    /// immutable, would propose replacing a live credential.
    fn user(&mut self, field: &'static str, from: Option<&UserId>, to: Option<&UserId>) {
        let Some(to) = to else { return };
        self.push(
            field,
            from.map_or(FieldValue::Absent, |user| FieldValue::text(user.as_str())),
            FieldValue::text(to.as_str()),
            None,
        );
    }

    /// A permit list, where an absent or empty list permits everything.
    fn allowed(
        &mut self,
        field: &'static str,
        from: Option<&BTreeSet<String>>,
        to: Option<&BTreeSet<String>>,
    ) {
        let Some(to) = to else { return };
        let from = from.cloned().unwrap_or_default();
        let widened = if to.is_empty() {
            !from.is_empty()
        } else {
            !from.is_empty() && !to.is_subset(&from)
        };
        self.push(
            field,
            FieldValue::Slugs(from),
            FieldValue::Slugs(to.clone()),
            widened.then_some(Expansion::AllowlistWidened { field }),
        );
    }

    /// A refusal list, where dropping an entry permits something new.
    fn denied(
        &mut self,
        field: &'static str,
        from: Option<&BTreeSet<String>>,
        to: Option<&BTreeSet<String>>,
    ) {
        let Some(to) = to else { return };
        let from = from.cloned().unwrap_or_default();
        let narrowed = !from.is_subset(to);
        self.push(
            field,
            FieldValue::Slugs(from),
            FieldValue::Slugs(to.clone()),
            narrowed.then_some(Expansion::DenylistNarrowed { field }),
        );
    }
}

/// The desired side of a managed field: `None` when Keymaster does not manage
/// it, and [`FieldValue::Absent`] when it is explicitly cleared.
fn managed<T>(value: &Managed<T>, to_value: impl FnOnce(&T) -> FieldValue) -> Option<FieldValue> {
    match value {
        Managed::Unmanaged => None,
        Managed::Cleared => Some(FieldValue::Absent),
        Managed::Set(value) => Some(to_value(value)),
    }
}

/// An observed string, where blank and absent are the same thing.
fn text_value(value: Option<&str>) -> FieldValue {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or(FieldValue::Absent, FieldValue::text)
}

/// Whether a budget change permits more spending. No limit is the largest
/// budget there is, so clearing one raises it.
fn budget_raised(from: Option<Usd>, to: Option<Usd>) -> bool {
    match (from, to) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(before), Some(after)) => after > before,
    }
}

fn policy_value(policy: &ResetPolicy) -> FieldValue {
    match policy {
        ResetPolicy::Never => FieldValue::Absent,
        ResetPolicy::Every(interval) => FieldValue::Interval(*interval),
        ResetPolicy::Unrecognized(spelling) => FieldValue::text(spelling),
    }
}

/// How permissive a reset schedule is. `None` for a schedule this build does
/// not know, so an unrecognized one is drift without a claim about direction.
fn policy_rank(policy: &ResetPolicy) -> Option<u8> {
    match policy {
        ResetPolicy::Never => Some(0),
        ResetPolicy::Every(interval) => Some(interval_rank(Some(*interval))),
        ResetPolicy::Unrecognized(_) => None,
    }
}

fn interval_rank(interval: Option<ResetInterval>) -> u8 {
    match interval {
        None => 0,
        Some(ResetInterval::Monthly) => 1,
        Some(ResetInterval::Weekly) => 2,
        Some(ResetInterval::Daily) => 3,
    }
}
