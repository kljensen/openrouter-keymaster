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
use crate::api::{ObservedGuardrail, ObservedKey, ResetPolicy};
use crate::config::{Guardrail, Key, Managed, ResetInterval, Usd};
use crate::ids::{RemoteName, Uuid};

/// Key fields OpenRouter fixes when the key is created.
///
/// A difference in one of these cannot be patched, so it is a reason to
/// replace the key rather than to update it.
pub(super) const IMMUTABLE_KEY_FIELDS: [&str; 2] = ["expires_at", "workspace_id"];

/// Every managed difference between a desired key and the observed one.
///
/// `observed` is `None` when the key does not exist, which makes the same
/// function describe a create: every managed field differs from nothing.
pub(super) fn key_changes(desired: &Key, observed: Option<&ObservedKey>) -> Vec<FieldChange> {
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
        desired.workspace_id.as_ref(),
    );
    diff.changes
}

/// Every managed difference between a desired guardrail and the observed one.
pub(super) fn guardrail_changes(
    desired: &Guardrail,
    observed: Option<&ObservedGuardrail>,
) -> Vec<FieldChange> {
    let mut diff = Diff::new(observed.is_some());
    diff.name(
        "name",
        observed.map(|rail| rail.name.as_str()),
        &desired.name,
    );
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
