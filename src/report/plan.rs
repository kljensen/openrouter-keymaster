//! The `keymaster plan` result document.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::{RecoveryReport, plural, scrubbed, timestamp};
use crate::plan::{
    Action, ActionKind, Expansion, FieldChange, Identity, Plan, Reason, ResourceAddress,
};
use crate::state::Phase;

/// What an apply would do, and what an operator should look at first.
///
/// A plan writes nothing, so this document is the whole product of the
/// command: every action the planner produced, why, what it would risk, and
/// which ones an apply would actually execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanReport {
    /// Which command produced this document.
    command: &'static str,
    /// Whether an operation of unknown outcome stops the whole run.
    blocked: bool,
    /// What this plan means for the next apply.
    outcome: Outcome,
    /// Whether an apply would write anything at all.
    has_changes: bool,
    /// Whether any action would widen what a credential may do.
    expands_privilege: bool,
    /// How many actions of each kind, keyed by the kind's stable spelling.
    counts: BTreeMap<&'static str, usize>,
    /// Diagnostics an operator should see. Human runs write these to stderr;
    /// under `--json` they travel here, because a stream carries exactly one
    /// document.
    warnings: Vec<String>,
    /// Every action, dependencies before dependents, in the planner's order.
    actions: Vec<ActionReport>,
}

impl PlanReport {
    /// Describes a computed plan.
    #[must_use]
    pub fn new(plan: &Plan) -> Self {
        let blocked = plan.is_blocked();
        let actions: Vec<ActionReport> = plan
            .actions()
            .iter()
            .map(|action| ActionReport::new(action, blocked))
            .collect();

        let mut counts = BTreeMap::new();
        for action in plan.actions() {
            *counts.entry(action.kind.as_str()).or_insert(0) += 1;
        }

        let has_changes = plan.has_changes();
        let mut report = Self {
            command: "plan",
            blocked,
            outcome: Outcome::of(plan, has_changes),
            has_changes,
            expands_privilege: actions.iter().any(|action| action.expands_privilege),
            counts,
            warnings: Vec::new(),
            actions,
        };
        report.warnings = report.build_warnings();
        report
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Whether an apply would write anything.
    #[must_use]
    pub const fn has_changes(&self) -> bool {
        self.has_changes
    }

    fn build_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let recovery = self.count_of(ActionKind::RecoveryRequired);
        if recovery > 0 {
            warnings.push(format!(
                "{} left unfinished; nothing will be applied until an operator resolves it",
                plural(recovery, "operation")
            ));
        }
        let missing = self.count_of(ActionKind::Missing);
        if missing > 0 {
            warnings.push(format!(
                "{} bound but absent from OpenRouter; Keymaster will not recreate one",
                plural(missing, "resource")
            ));
        }
        let expanding = self
            .actions
            .iter()
            .filter(|action| action.expands_privilege)
            .count();
        if expanding > 0 {
            warnings.push(format!(
                "{} would widen what a credential may do",
                plural(expanding, "action")
            ));
        }
        warnings
    }

    fn count_of(&self, kind: ActionKind) -> usize {
        self.counts.get(kind.as_str()).copied().unwrap_or_default()
    }

    /// How many actions an apply would execute.
    fn executable(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| action.executable)
            .count()
    }

    fn lines(&self) -> Vec<String> {
        let executable = self.executable();
        let mut lines = vec![format!(
            "plan: {total}, {executable} to apply, {reports} to report",
            total = plural(self.actions.len(), "action"),
            reports = self.actions.len() - executable,
        )];

        for action in &self.actions {
            lines.push(String::new());
            lines.extend(action.lines());
        }
        lines.extend(self.expansion_lines());
        lines.extend(self.recovery_lines());
        lines.push(String::new());
        lines.push(self.summary());
        lines
    }

    /// The section that makes a privilege expansion impossible to miss.
    fn expansion_lines(&self) -> Vec<String> {
        let expanding: Vec<&ActionReport> = self
            .actions
            .iter()
            .filter(|action| action.expands_privilege)
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
                    "  ! {address}  {expansion}",
                    address = action.address
                ));
            }
        }
        lines
    }

    /// The section an operator has to act on before anything else runs.
    fn recovery_lines(&self) -> Vec<String> {
        let unfinished: Vec<&ActionReport> = self
            .actions
            .iter()
            .filter(|action| action.recovery.is_some())
            .collect();
        if unfinished.is_empty() {
            return Vec::new();
        }

        let mut lines = vec![
            String::new(),
            format!("unfinished operations ({count}):", count = unfinished.len()),
        ];
        for action in unfinished {
            lines.push(format!("  {address}", address = action.address));
            if let Some(recovery) = &action.recovery {
                lines.extend(recovery.lines("    "));
            }
        }
        lines
    }

    /// The last line: what this plan means for the next apply.
    fn summary(&self) -> String {
        if self.blocked {
            return "blocked: an unfinished operation of unknown outcome stops this run; \
                    nothing would be applied."
                .to_owned();
        }
        match self.outcome {
            Outcome::Converged => "converged: OpenRouter matches the configuration, and there \
                                   is nothing to apply."
                .to_owned(),
            Outcome::ChangesPending => {
                format!("{} to apply.", plural(self.executable(), "change"))
            }
            Outcome::HeldBack => format!(
                "held back: nothing can be applied, and {} an operator's attention or name a \
                 resource Keymaster will not change.",
                plural(self.reported(), "action needs"),
            ),
        }
    }

    /// How many actions are neither executable nor a no-op: the things an
    /// operator has to read.
    fn reported(&self) -> usize {
        self.actions.len() - self.count_of(ActionKind::NoOp) - self.executable()
    }
}

/// What a plan means for the next apply.
///
/// Three outcomes rather than two, because "nothing to apply" has two very
/// different causes. A converged project is finished. A project whose only
/// writes are held back — behind an adoption, a missing resource, an
/// unfinished operation, or a dependency on one of those — is not finished at
/// all, and reporting it as a match would be telling an operator the opposite
/// of what is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    /// Every action is a no-op: what the configuration describes is what
    /// OpenRouter has.
    Converged,
    /// An apply would execute at least one action.
    ChangesPending,
    /// There is work to do and none of it can run.
    HeldBack,
}

impl Outcome {
    fn of(plan: &Plan, has_changes: bool) -> Self {
        if has_changes {
            return Self::ChangesPending;
        }
        if plan
            .actions()
            .iter()
            .all(|action| action.kind == ActionKind::NoOp)
        {
            return Self::Converged;
        }
        Self::HeldBack
    }
}

impl fmt::Display for PlanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lines().join("\n"))
    }
}

/// One intended change, or one thing worth reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ActionReport {
    /// The action's kind, in its stable spelling.
    kind: &'static str,
    /// The resource it is about, as the configuration addresses it.
    address: String,
    /// The immutable remote identity, when one is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    /// How much care executing it needs.
    safety: &'static str,
    /// Whether it widens what a credential may do.
    expands_privilege: bool,
    /// Every way it does, if it does.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    expansions: Vec<ExpansionReport>,
    /// Whether an apply would execute it: it writes, nothing holds it back,
    /// and no unfinished operation stops the run.
    executable: bool,
    /// Whether something it needs is unresolved.
    blocked: bool,
    /// The resources that must be settled before it runs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
    /// The managed fields that differ, and which way.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    changes: Vec<ChangeReport>,
    /// Why the planner proposes it.
    reasons: Vec<ReasonReport>,
    /// The unfinished operation at this address, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery: Option<RecoveryReport>,
}

impl ActionReport {
    fn new(action: &Action, plan_blocked: bool) -> Self {
        let blocked = action.is_blocked();
        Self {
            kind: action.kind.as_str(),
            address: action.address.to_string(),
            identity: action.identity.as_ref().map(Identity::to_string),
            safety: action.safety.class().as_str(),
            expands_privilege: action.safety.expands_privilege(),
            expansions: action
                .safety
                .expansions()
                .iter()
                .copied()
                .map(ExpansionReport::new)
                .collect(),
            executable: action.is_executable(plan_blocked),
            blocked,
            depends_on: action
                .depends_on
                .iter()
                .map(ResourceAddress::to_string)
                .collect(),
            changes: action.changes.iter().map(ChangeReport::new).collect(),
            reasons: action.rationale.iter().map(ReasonReport::new).collect(),
            recovery: recovery_of(action),
        }
    }

    fn lines(&self) -> Vec<String> {
        let marker = if self.expands_privilege { "!" } else { " " };
        let mut lines = vec![format!(
            "{marker} {kind:<17}  {address}  [{safety}]{held}",
            kind = self.kind,
            address = self.address,
            safety = self.safety,
            held = if self.blocked { "  (held back)" } else { "" },
        )];

        if let Some(identity) = &self.identity {
            lines.push(format!("      identity: {identity}"));
        }
        for change in &self.changes {
            lines.push(format!("      {}", change.describe()));
        }
        for reason in &self.reasons {
            lines.push(format!("      reason: {}", reason.sentence()));
        }
        if !self.depends_on.is_empty() {
            lines.push(format!("      depends on: {}", self.depends_on.join(", ")));
        }
        if let Some(recovery) = &self.recovery {
            lines.extend(recovery.lines("      "));
        }
        lines
    }
}

/// The unfinished operation an action reports, if it reports one.
///
/// Both reasons that carry one are read here: an operation whose outcome only
/// an operator can establish, and one that finished remotely and is waiting on
/// local promotion. An operator needs the same five facts about either.
fn recovery_of(action: &Action) -> Option<RecoveryReport> {
    let address = match &action.address {
        ResourceAddress::Key(address) | ResourceAddress::Assignment(address) => Some(address),
        ResourceAddress::Guardrail(_)
        | ResourceAddress::RemoteKey(_)
        | ResourceAddress::RemoteGuardrail(_) => None,
    };
    let hash = match &action.identity {
        Some(Identity::Key(hash)) => Some(hash),
        _ => None,
    };

    action.rationale.iter().find_map(|reason| match reason {
        Reason::OperationIncomplete {
            operation,
            phase,
            phase_at,
        } => Some(RecoveryReport::new(
            operation, *phase, *phase_at, hash, address,
        )),
        Reason::PromotionPending {
            operation,
            delivered_at,
        } => Some(RecoveryReport::new(
            operation,
            Phase::Delivered,
            *delivered_at,
            hash,
            address,
        )),
        _ => None,
    })
}

/// One way an action widens what a credential may do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ExpansionReport {
    /// The expansion's stable spelling.
    pub(super) expansion: &'static str,
    /// The field that carries it, for the expansions that name one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) field: Option<&'static str>,
}

impl ExpansionReport {
    pub(super) const fn new(expansion: Expansion) -> Self {
        let field = match expansion {
            Expansion::BudgetRaised { field }
            | Expansion::BudgetResetShortened { field }
            | Expansion::AllowlistWidened { field }
            | Expansion::DenylistNarrowed { field } => Some(field),
            Expansion::KeyEnabled
            | Expansion::ZdrWeakened
            | Expansion::ByokExcludedFromLimit
            | Expansion::GuardrailRemoved => None,
        };
        Self {
            expansion: expansion.as_str(),
            field,
        }
    }
}

impl fmt::Display for ExpansionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.field {
            Some(field) => write!(f, "{} ({field})", self.expansion),
            None => f.write_str(self.expansion),
        }
    }
}

/// One managed field that differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ChangeReport {
    /// The configuration's name for the field.
    field: &'static str,
    /// What OpenRouter has now.
    from: String,
    /// What the configuration asks for.
    to: String,
    /// How this change widens what a credential may do, if it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    expansion: Option<ExpansionReport>,
}

impl ChangeReport {
    pub(super) fn new(change: &FieldChange) -> Self {
        // `from` is whatever OpenRouter has — a display name, a description, a
        // provider slug, a reset schedule this build does not recognize — and
        // `to` can be one too, since a name is only ever as trustworthy as the
        // file it was written in. Both go through the same scrub.
        Self {
            field: change.field,
            from: scrubbed(&change.from.to_string()),
            to: scrubbed(&change.to.to_string()),
            expansion: change.expansion.map(ExpansionReport::new),
        }
    }

    pub(super) fn describe(&self) -> String {
        let expansion = self
            .expansion
            .as_ref()
            .map_or_else(String::new, |expansion| format!("  ! {expansion}"));
        format!(
            "{field}: {from} -> {to}{expansion}",
            field = self.field,
            from = self.from,
            to = self.to
        )
    }
}

/// Why the planner proposes an action.
///
/// One variant per [`Reason`], so a reason added to the planner fails to
/// compile here rather than disappearing from the output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub(super) enum ReasonReport {
    InSync,
    Drift,
    NotCreatedYet,
    AbsentRemotely,
    NoNameCollision,
    NameCollision {
        holders: Vec<String>,
    },
    NameMatches {
        candidates: Vec<String>,
    },
    GenerationRaised {
        from: u32,
        to: u32,
    },
    ReceiverChanged,
    ImmutableFieldChanged {
        field: &'static str,
    },
    NoReceiver,
    ReceiverUnspecified {
        delivered: String,
    },
    AssignmentMissing,
    AssignmentUndesired,
    RemovedFromConfiguration,
    NotConfigured,
    PromotionPending {
        operation: String,
        delivered_at: String,
    },
    OperationIncomplete {
        operation: String,
        phase: &'static str,
        phase_at: String,
    },
    DeliveryRefused {
        at: String,
    },
    PlaintextLost,
    BlockedBy {
        dependency: String,
    },
}

impl ReasonReport {
    pub(super) fn new(reason: &Reason) -> Self {
        match reason {
            Reason::InSync => Self::InSync,
            Reason::Drift => Self::Drift,
            Reason::NotCreatedYet => Self::NotCreatedYet,
            Reason::AbsentRemotely => Self::AbsentRemotely,
            Reason::NoNameCollision => Self::NoNameCollision,
            Reason::NameCollision { holders } => Self::NameCollision {
                holders: holders.iter().map(Identity::to_string).collect(),
            },
            Reason::NameMatches { candidates } => Self::NameMatches {
                candidates: candidates.iter().map(Identity::to_string).collect(),
            },
            Reason::GenerationRaised { from, to } => Self::GenerationRaised {
                from: *from,
                to: *to,
            },
            Reason::ReceiverChanged => Self::ReceiverChanged,
            Reason::ImmutableFieldChanged { field } => Self::ImmutableFieldChanged { field },
            Reason::NoReceiver => Self::NoReceiver,
            Reason::ReceiverUnspecified { delivered } => Self::ReceiverUnspecified {
                delivered: delivered.as_str().to_owned(),
            },
            Reason::AssignmentMissing => Self::AssignmentMissing,
            Reason::AssignmentUndesired => Self::AssignmentUndesired,
            Reason::RemovedFromConfiguration => Self::RemovedFromConfiguration,
            Reason::NotConfigured => Self::NotConfigured,
            Reason::PromotionPending {
                operation,
                delivered_at,
            } => Self::PromotionPending {
                operation: operation.as_str().to_owned(),
                delivered_at: timestamp(*delivered_at),
            },
            Reason::OperationIncomplete {
                operation,
                phase,
                phase_at,
            } => Self::OperationIncomplete {
                operation: operation.as_str().to_owned(),
                phase: phase.as_str(),
                phase_at: timestamp(*phase_at),
            },
            Reason::DeliveryRefused { at } => Self::DeliveryRefused { at: timestamp(*at) },
            Reason::PlaintextLost => Self::PlaintextLost,
            Reason::BlockedBy { dependency } => Self::BlockedBy {
                dependency: dependency.to_string(),
            },
        }
    }

    /// The human sentence for this reason.
    pub(super) fn sentence(&self) -> String {
        match self {
            Self::InSync => "everything the configuration manages already matches".to_owned(),
            Self::Drift => "managed fields differ from the configuration".to_owned(),
            Self::NotCreatedYet => {
                "nothing is bound and nothing remote carries the configured name".to_owned()
            }
            Self::AbsentRemotely => "the bound remote resource is not in the snapshot".to_owned(),
            Self::NoNameCollision => {
                "no remote resource carries the configured name, so recreating one cannot collide"
                    .to_owned()
            }
            Self::NameCollision { holders } => format!(
                "a remote resource already carries the configured name: {}",
                holders.join(", ")
            ),
            Self::NameMatches { candidates } => format!(
                "unbound, and a remote resource carries the configured name; bind one with \
                 `keymaster import`: {}",
                candidates.join(", ")
            ),
            Self::GenerationRaised { from, to } => {
                format!("the configuration raises the generation from {from} to {to}")
            }
            Self::ReceiverChanged => {
                "the plaintext was delivered somewhere the configuration no longer describes"
                    .to_owned()
            }
            Self::ImmutableFieldChanged { field } => {
                format!("`{field}` is fixed at creation and differs")
            }
            Self::NoReceiver => {
                "the key has no receiver, so a created plaintext would have nowhere to go"
                    .to_owned()
            }
            Self::ReceiverUnspecified { delivered } => format!(
                "the key was delivered to receiver {delivered}, which the configuration no \
                 longer names"
            ),
            Self::AssignmentMissing => {
                "the key is not assigned to the configured guardrail".to_owned()
            }
            Self::AssignmentUndesired => {
                "the key is assigned to a guardrail the configuration does not ask for".to_owned()
            }
            Self::RemovedFromConfiguration => {
                "the configuration no longer describes this address; nothing is deleted or \
                 forgotten"
                    .to_owned()
            }
            Self::NotConfigured => "no local address owns this remote resource".to_owned(),
            Self::PromotionPending {
                operation,
                delivered_at,
            } => format!(
                "operation {operation} delivered at {delivered_at} and is waiting on local \
                 promotion"
            ),
            Self::OperationIncomplete {
                operation,
                phase,
                phase_at,
            } => format!(
                "operation {operation} stopped in phase `{phase}` at {phase_at}, and what \
                 happened to it is an operator's to establish"
            ),
            Self::DeliveryRefused { at } => {
                format!("the receiver definitely refused the plaintext at {at}")
            }
            Self::PlaintextLost => {
                "the key's plaintext no longer exists, so the key can never be delivered".to_owned()
            }
            Self::BlockedBy { dependency } => {
                format!("{dependency} is unresolved, so this will not run")
            }
        }
    }
}
