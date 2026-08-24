//! The `keymaster apply` result document.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::plan::{ChangeReport, ExpansionReport, ReasonReport};
use super::plural;
use crate::plan::{Action, ActionKind, Identity, Plan};

/// What happened to one planned action.
///
/// Six states rather than two, because "not applied" covers five very
/// different things and an operator has to be able to tell them apart: a write
/// that failed, a write apply deliberately did not make, a write that never got
/// its turn because an earlier one failed, a write the plan holds back until an
/// operator resolves something, and something that was never a write at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The write was made and OpenRouter accepted it.
    Applied,
    /// Apply chose not to make this write, and says why.
    Skipped,
    /// The write was attempted and did not succeed.
    Failed,
    /// An earlier failure stopped apply before this action's turn.
    NotAttempted,
    /// A write the planner held back: something it depends on needs an
    /// operator, or an unfinished operation stands in its way. Apply never
    /// offers to resolve that for them.
    HeldBack,
    /// Not a write: something the plan reports and apply never touches.
    Reported,
}

impl Status {
    /// The spelling used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
            Self::NotAttempted => "not_attempted",
            Self::HeldBack => "held_back",
            Self::Reported => "reported",
        }
    }

    /// Whether apply sent a request for this action. Only an attempted action
    /// is worth verifying, and only an attempted action can be unverified.
    #[must_use]
    pub const fn was_attempted(self) -> bool {
        matches!(self, Self::Applied | Self::Failed)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether an action widened what a credential may do — and whether anything
/// establishes that it did.
///
/// Three states rather than a flag, because the two failure shapes of a write
/// land on opposite sides of a boolean and both would be wrong. An expanding
/// PATCH that returned 500 and took effect anyway did widen the credential; an
/// expanding PATCH that returned 200 and did not show up in the read that
/// followed may not have. Reporting the first as nothing is silence where it
/// matters most, and reporting the second as fact is a claim nothing supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeExpansion {
    /// This action widens nothing, or nothing was attempted, so nothing about
    /// a live credential changed here.
    None,
    /// The write was attempted and the read that followed did not confirm the
    /// configured state. It may have widened the credential; nobody can say it
    /// did not.
    Unconfirmed,
    /// The write was attempted and a fresh read confirms the configured state.
    Occurred,
}

impl PrivilegeExpansion {
    /// The spelling used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Unconfirmed => "unconfirmed",
            Self::Occurred => "occurred",
        }
    }

    /// Classifies one action's expansion from what became of its write.
    ///
    /// The verification result decides it, not the status: a failed write that
    /// a fresh read shows took effect is an expansion that occurred, and an
    /// accepted write the read does not confirm is one nobody can vouch for.
    /// Only an action apply never attempted is `None`, and that one is
    /// certain — no request was sent.
    fn of(action: &Action, outcome: &ActionOutcome) -> Self {
        if !action.safety.expands_privilege() || !outcome.was_attempted() {
            return Self::None;
        }
        if outcome.is_verified() {
            return Self::Occurred;
        }
        Self::Unconfirmed
    }
}

impl fmt::Display for PrivilegeExpansion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What apply did about one planned action, and what the check afterwards
/// found.
///
/// One of these exists for every action in the plan, in the plan's order, so
/// the report can never quietly omit something that was planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionOutcome {
    status: Status,
    detail: Option<String>,
    verified: Option<bool>,
}

impl ActionOutcome {
    /// A write that was made.
    #[must_use]
    pub fn applied(detail: impl Into<String>) -> Self {
        Self::new(Status::Applied, Some(detail.into()))
    }

    /// A write apply deliberately did not make.
    #[must_use]
    pub fn skipped(detail: impl Into<String>) -> Self {
        Self::new(Status::Skipped, Some(detail.into()))
    }

    /// A write that was attempted and failed.
    #[must_use]
    pub fn failed(detail: impl Into<String>) -> Self {
        Self::new(Status::Failed, Some(detail.into()))
    }

    /// A write that never got its turn.
    #[must_use]
    pub fn not_attempted(detail: impl Into<String>) -> Self {
        Self::new(Status::NotAttempted, Some(detail.into()))
    }

    /// A write the planner held back until an operator resolves something.
    #[must_use]
    pub fn held_back(detail: impl Into<String>) -> Self {
        Self::new(Status::HeldBack, Some(detail.into()))
    }

    /// Something the plan reports and apply never touches.
    #[must_use]
    pub fn reported() -> Self {
        Self::new(Status::Reported, None)
    }

    /// Records what the verification read found about this action.
    pub fn record_verification(&mut self, converged: bool) {
        self.verified = Some(converged);
    }

    /// Whether apply sent a request for this action.
    #[must_use]
    pub const fn was_attempted(&self) -> bool {
        self.status.was_attempted()
    }

    fn new(status: Status, detail: Option<String>) -> Self {
        Self {
            status,
            detail,
            verified: None,
        }
    }

    /// Whether this action is known to have reached the configured state.
    const fn is_verified(&self) -> bool {
        matches!(self.verified, Some(true))
    }
}

/// What apply did, and what it could prove afterwards.
///
/// The document answers three questions in order: what the plan computed under
/// the lock, what apply did about each part of it, and what a fresh read of
/// OpenRouter says about the result. The third is the one that matters — a
/// write that returned 200 and did not take is a write that did not take — so
/// every attempted action carries `verified` and the summary counts the
/// unverified separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyReport {
    /// Which command produced this document.
    command: &'static str,
    /// What this apply achieved.
    outcome: Outcome,
    /// Whether an operation of unknown outcome stopped the run.
    blocked: bool,
    /// How many actions apply was allowed to execute.
    planned: usize,
    /// How many writes were made.
    applied: usize,
    /// How many writes apply deliberately did not make.
    skipped: usize,
    /// How many writes failed.
    failed: usize,
    /// How many writes the plan held back until an operator resolves what
    /// blocks them.
    held_back: usize,
    /// How many attempted actions a fresh read confirmed.
    verified: usize,
    /// How many attempted actions a fresh read did not confirm.
    unverified: usize,
    /// How many actions widened what a credential may do, confirmed by the
    /// read that followed.
    expansions_occurred: usize,
    /// How many attempted actions may have widened what a credential may do
    /// and were not confirmed either way.
    expansions_unconfirmed: usize,
    /// Why nothing could be verified, when the check itself failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_failure: Option<String>,
    /// How many actions of each kind the plan held.
    counts: BTreeMap<&'static str, usize>,
    /// Diagnostics an operator should see. Human runs write these to stderr;
    /// under `--json` they travel here, because a stream carries exactly one
    /// document.
    warnings: Vec<String>,
    /// Every action the plan held, in the plan's order, with what apply did.
    actions: Vec<ActionReport>,
}

impl ApplyReport {
    /// Describes one apply.
    ///
    /// `outcomes` is index-aligned with `plan.actions()`.
    ///
    /// # Panics
    ///
    /// Panics if `outcomes` is shorter than the plan, which would mean apply
    /// lost track of an action it was given.
    #[must_use]
    pub fn new(
        plan: &Plan,
        outcomes: &[ActionOutcome],
        verification_failure: Option<String>,
    ) -> Self {
        assert_eq!(
            plan.actions().len(),
            outcomes.len(),
            "every planned action needs an outcome"
        );
        let blocked = plan.is_blocked();
        let actions: Vec<ActionReport> = plan
            .actions()
            .iter()
            .zip(outcomes)
            .map(|(action, outcome)| ActionReport::new(action, outcome))
            .collect();

        let mut counts = BTreeMap::new();
        for action in plan.actions() {
            *counts.entry(action.kind.as_str()).or_insert(0) += 1;
        }

        let mut report = Self {
            command: "apply",
            outcome: Outcome::Converged,
            blocked,
            planned: plan.executable().count(),
            applied: count(outcomes, Status::Applied),
            skipped: count(outcomes, Status::Skipped),
            failed: count(outcomes, Status::Failed),
            held_back: count(outcomes, Status::HeldBack),
            verified: outcomes
                .iter()
                .filter(|outcome| outcome.is_verified())
                .count(),
            unverified: outcomes
                .iter()
                .filter(|outcome| outcome.was_attempted() && !outcome.is_verified())
                .count(),
            expansions_occurred: expansions(&actions, PrivilegeExpansion::Occurred),
            expansions_unconfirmed: expansions(&actions, PrivilegeExpansion::Unconfirmed),
            verification_failure,
            counts,
            warnings: Vec::new(),
            actions,
        };
        report.outcome = Outcome::of(&report);
        report.warnings = report.build_warnings();
        report
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Adds something the run did before it planned.
    ///
    /// Apply completes a delivered operation's promotion under its lock, before
    /// the plan exists, so no action can carry it. It still has to be reported:
    /// the run changed what the address owns.
    pub fn note(&mut self, note: Option<String>) {
        if let Some(note) = note {
            self.warnings.insert(0, note);
        }
    }

    /// Whether this apply finished without a write failing or an unfinished
    /// operation stopping it.
    ///
    /// True for an apply that left work behind, as long as nothing went wrong:
    /// a write apply deliberately skipped and a write an operator has to
    /// unblock are both reported, conspicuously, and neither is a failure of this run.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(
            self.outcome,
            Outcome::Converged | Outcome::Applied | Outcome::Incomplete | Outcome::HeldBack
        )
    }

    /// Whether an unfinished operation stopped the run.
    #[must_use]
    pub const fn blocked(&self) -> bool {
        self.blocked
    }

    /// How many writes failed or could not be confirmed.
    #[must_use]
    pub const fn unresolved(&self) -> (usize, usize) {
        (self.failed, self.unverified)
    }

    fn build_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.blocked {
            warnings.push(
                "an operation of unknown outcome stops this run; nothing was applied, and \
                 `keymaster recover` resolves it"
                    .to_owned(),
            );
        }
        if self.skipped > 0 {
            warnings.push(format!(
                "{} not made; `keymaster apply` does not replace an inference key yet, so the \
                 configuration is not fully converged",
                plural(self.skipped, "planned write was")
            ));
        }
        if self.held_back > 0 {
            warnings.push(format!(
                "{} held back until an operator resolves what blocks {them}: {addresses}",
                plural(self.held_back, "planned write was"),
                them = if self.held_back == 1 { "it" } else { "them" },
                addresses = self.held_back_addresses().join(", "),
            ));
        }
        if self.failed > 0 {
            warnings.push(format!("{} failed", plural(self.failed, "write")));
        }
        if self.unverified > 0 {
            warnings.push(format!(
                "{} not confirmed by the read that followed",
                plural(self.unverified, "attempted write was")
            ));
        }
        if let Some(failure) = &self.verification_failure {
            warnings.push(failure.clone());
        }
        if self.expansions_occurred > 0 {
            warnings.push(format!(
                "{} what a credential may do",
                plural(self.expansions_occurred, "action widened")
            ));
        }
        if self.expansions_unconfirmed > 0 {
            // The louder of the two, deliberately. A confirmed expansion is a
            // change an operator can read; an unconfirmed one is a live
            // credential whose privileges nobody can currently state.
            warnings.push(format!(
                "{} what a credential may do and was NOT confirmed by the read that followed; \
                 it may have taken effect, so check {resource} before assuming it did not: \
                 {addresses}",
                plural(self.expansions_unconfirmed, "attempted write would widen"),
                resource = if self.expansions_unconfirmed == 1 {
                    "the resource"
                } else {
                    "those resources"
                },
                addresses = self
                    .expanding_addresses(PrivilegeExpansion::Unconfirmed)
                    .join(", "),
            ));
        }
        warnings
    }

    /// How many actions are neither a write nor a no-op: the things an
    /// operator has to read.
    fn reported(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| action.status == Status::Reported && !action.is_no_op())
            .count()
    }

    /// The addresses of the writes the plan held back.
    fn held_back_addresses(&self) -> Vec<&str> {
        self.actions
            .iter()
            .filter(|action| action.status == Status::HeldBack)
            .map(|action| action.address.as_str())
            .collect()
    }

    fn lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "apply: {planned} to execute, {total} in the plan",
            planned = plural(self.planned, "action"),
            total = self.actions.len(),
        )];
        for action in &self.actions {
            lines.push(String::new());
            lines.extend(action.lines());
        }
        lines.extend(self.expansion_lines());
        lines.push(String::new());
        lines.push(self.summary());
        lines
    }

    /// The section that makes a privilege expansion impossible to miss.
    ///
    /// Each line says whether the expansion is confirmed, because the two are
    /// different facts: one is a credential that now may do more, the other is
    /// a credential nobody can currently describe.
    fn expansion_lines(&self) -> Vec<String> {
        let expanding: Vec<&ActionReport> = self
            .actions
            .iter()
            .filter(|action| action.privilege_expansion != PrivilegeExpansion::None)
            .collect();
        if expanding.is_empty() {
            return Vec::new();
        }

        let mut lines = vec![
            String::new(),
            format!("! privilege expansions ({count}):", count = expanding.len()),
        ];
        for action in expanding {
            for expansion in &action.expansions {
                lines.push(format!(
                    "  ! {address}  {expansion}  ({status}, {confirmation})",
                    address = action.address,
                    status = action.status.as_str(),
                    confirmation = action.privilege_expansion.as_str(),
                ));
            }
        }
        lines
    }

    /// The addresses whose expansion is in one state.
    fn expanding_addresses(&self, state: PrivilegeExpansion) -> Vec<&str> {
        self.actions
            .iter()
            .filter(|action| action.privilege_expansion == state)
            .map(|action| action.address.as_str())
            .collect()
    }

    /// The last line: what this apply achieved.
    fn summary(&self) -> String {
        match self.outcome {
            Outcome::Blocked => "blocked: an unfinished operation of unknown outcome stops this \
                                 run; nothing was applied."
                .to_owned(),
            Outcome::Converged => {
                "converged: OpenRouter already matches the configuration; nothing was written."
                    .to_owned()
            }
            Outcome::Applied => format!(
                "applied {applied}, all verified.",
                applied = plural(self.applied, "change")
            ),
            Outcome::Incomplete => format!(
                "applied {applied} and skipped {skipped}; the configuration is not fully \
                 converged.",
                applied = plural(self.applied, "change"),
                skipped = plural(self.skipped, "write"),
            ),
            Outcome::HeldBack if self.held_back > 0 => format!(
                "held back: applied {applied}, and {held} waiting on something an operator has \
                 to resolve; the configuration is not fully converged.",
                applied = plural(self.applied, "change"),
                held = plural(self.held_back, "planned write is"),
            ),
            Outcome::HeldBack => format!(
                "held back: nothing was applied, and {} an operator's attention or name a \
                 resource Keymaster will not change.",
                plural(self.reported(), "action needs"),
            ),
            Outcome::Failed => format!(
                "incomplete: {failed} and {unverified}.",
                failed = plural(self.failed, "write failed"),
                unverified = plural(self.unverified, "attempted write is unverified"),
            ),
        }
    }
}

/// What an apply achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    /// An unfinished operation stopped the run before anything was written.
    Blocked,
    /// There was nothing to do.
    Converged,
    /// Every planned write was made and verified.
    Applied,
    /// Nothing failed, but a write apply deliberately did not make was
    /// skipped.
    Incomplete,
    /// Nothing failed, and work remains that only an operator can unblock —
    /// an adoption, a missing resource, an unfinished operation, or a
    /// dependency on one of those.
    HeldBack,
    /// A write failed, or one that was made could not be confirmed.
    Failed,
}

impl Outcome {
    /// Classifies an apply from what became of every action in its plan.
    ///
    /// `converged` is the strict one, and deliberately so: it means the plan
    /// held nothing but no-ops, which is the same thing `keymaster plan` calls
    /// converged. An apply that wrote nothing because everything it wanted to
    /// write was held back behind an adoption, a missing resource, or an
    /// unfinished operation has *not* converged anything, and saying so would
    /// tell an operator the opposite of what is true.
    fn of(report: &ApplyReport) -> Self {
        if report.blocked {
            return Self::Blocked;
        }
        if report.failed > 0 || report.unverified > 0 {
            return Self::Failed;
        }
        if report.skipped > 0 {
            return Self::Incomplete;
        }
        if report.held_back > 0 {
            return Self::HeldBack;
        }
        if report.applied > 0 {
            return Self::Applied;
        }
        if report.actions.iter().all(ActionReport::is_no_op) {
            return Self::Converged;
        }
        // Nothing to write and nothing written, but the plan is not made of
        // no-ops: what is left needs an operator, or names a resource
        // Keymaster will not change.
        Self::HeldBack
    }
}

impl fmt::Display for ApplyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lines().join("\n"))
    }
}

/// One planned action and what apply did about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ActionReport {
    /// What apply did.
    status: Status,
    /// The action's kind, in its stable spelling.
    kind: &'static str,
    /// The resource it is about, as the configuration addresses it.
    address: String,
    /// The immutable remote identity, when one is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    /// How much care executing it needs.
    safety: &'static str,
    /// Whether this action widened what a credential may do, and whether a
    /// fresh read says so.
    privilege_expansion: PrivilegeExpansion,
    /// Every way it widens one, when it was attempted. Empty for an action
    /// nothing executed: the ways a write *would* widen a credential belong to
    /// `keymaster plan`, and repeating them here would read as a fact.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    expansions: Vec<ExpansionReport>,
    /// Whether a fresh read confirmed the result. Absent for an action apply
    /// never attempted, because there is nothing to confirm.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    /// What apply did, or why it did not. Never contains secret material.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    /// The managed fields that differ, and which way.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    changes: Vec<ChangeReport>,
    /// Why the planner proposed it.
    reasons: Vec<ReasonReport>,
}

impl ActionReport {
    fn new(action: &Action, outcome: &ActionOutcome) -> Self {
        let privilege_expansion = PrivilegeExpansion::of(action, outcome);
        Self {
            status: outcome.status,
            kind: action.kind.as_str(),
            address: action.address.to_string(),
            identity: action.identity.as_ref().map(Identity::to_string),
            safety: action.safety.class().as_str(),
            privilege_expansion,
            expansions: if privilege_expansion == PrivilegeExpansion::None {
                Vec::new()
            } else {
                action
                    .safety
                    .expansions()
                    .iter()
                    .copied()
                    .map(ExpansionReport::new)
                    .collect()
            },
            verified: outcome.verified,
            detail: outcome.detail.clone(),
            changes: action.changes.iter().map(ChangeReport::new).collect(),
            reasons: action.rationale.iter().map(ReasonReport::new).collect(),
        }
    }

    /// Whether this action is one the planner had nothing to say about.
    fn is_no_op(&self) -> bool {
        self.kind == ActionKind::NoOp.as_str()
    }

    fn lines(&self) -> Vec<String> {
        let marker = if self.privilege_expansion == PrivilegeExpansion::None {
            " "
        } else {
            "!"
        };
        let verified = match self.verified {
            Some(true) => "  verified",
            Some(false) => "  UNVERIFIED",
            None => "",
        };
        let mut lines = vec![format!(
            "{marker} {status:<13}  {kind:<17}  {address}  [{safety}]{verified}",
            // `as_str` rather than the value: a `Display` implementation that
            // writes a string directly does not honour a width.
            status = self.status.as_str(),
            kind = self.kind,
            address = self.address,
            safety = self.safety,
        )];

        if let Some(identity) = &self.identity {
            lines.push(format!("      identity: {identity}"));
        }
        for change in &self.changes {
            lines.push(format!("      {}", change.describe()));
        }
        if let Some(detail) = &self.detail {
            lines.push(format!("      {detail}"));
        }
        for reason in &self.reasons {
            lines.push(format!("      reason: {}", reason.sentence()));
        }
        lines
    }
}

/// How many actions report one expansion state.
fn expansions(actions: &[ActionReport], state: PrivilegeExpansion) -> usize {
    actions
        .iter()
        .filter(|action| action.privilege_expansion == state)
        .count()
}

/// How many outcomes are in one state.
fn count(outcomes: &[ActionOutcome], status: Status) -> usize {
    outcomes
        .iter()
        .filter(|outcome| outcome.status == status)
        .count()
}
