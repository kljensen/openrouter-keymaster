//! The planner: what Keymaster intends to do, and why.
//!
//! [`plan`] is a pure function of three inputs — the validated desired
//! configuration, the local identity and lifecycle state, and one complete
//! freshly observed snapshot of OpenRouter. It reads no clock, no environment
//! variable, no file, and no socket, and it prints nothing. Identical inputs
//! produce an identical plan, so a plan can be recomputed under a lock and
//! compared with the one an operator read.
//!
//! The rules it implements come from ADR-0001 and ADR-0002:
//!
//! - Identity is what state records, never a display name. A desired object
//!   with no binding is never adopted because a remote name matches; the match
//!   is reported as [`ActionKind::AdoptionRequired`] and an operator binds it
//!   with `import`.
//! - One remote object belongs to exactly one local address. A remote object
//!   another address owns is never offered as an adoption candidate, and never
//!   reported as unmanaged.
//! - A remote object no address owns is reported as [`ActionKind::Unmanaged`]
//!   and never changed.
//! - A run scoped to one workspace reports and matches names only there. The
//!   snapshot is still the whole organization, so identity — which decides
//!   whether a bound object is present or missing — is unaffected (ADR-0004,
//!   item 5).
//! - Removing a block from the configuration does not delete or forget
//!   anything; the binding is reported as [`ActionKind::OrphanedBinding`] and
//!   stays tracked.
//! - A key that is bound but absent from the snapshot is
//!   [`ActionKind::Missing`], never a create: recreating it would issue a new
//!   secret to a consumer that still holds the old one.
//! - An incomplete create or delivery holds back exactly as much as its phase
//!   leaves undecided. The five ambiguous phases stop everything:
//!   [`ActionKind::RecoveryRequired`] is reported first and
//!   [`Plan::executable`] yields nothing. `secured` does not — the journal
//!   already says the key exists, is restricted, and can never be delivered —
//!   so it is a [`ActionKind::Replace`] for `openrouter-keymaster recover replace` to
//!   perform, or a report saying why not even that is possible, and it holds
//!   back only the other creates state would refuse beside it. `delivered`
//!   holds back nothing: promotion is a local state
//!   operation, which apply completes under its lock before it plans (#16).
//!   See [`Plan::executable`] for the three widths.
//! - An action whose dependency needs an operator is held back with it, and
//!   so is anything depending on *that*. It stays in the plan, carrying
//!   [`Reason::BlockedBy`], and [`Plan::executable`] does not yield it.
//!
//! Drift is a reason on an action, not an action of its own: an
//! [`ActionKind::Update`] carries the managed-field difference that justifies
//! it, and so does a [`ActionKind::Replace`] or a [`ActionKind::Create`].
//!
//! One limitation is worth naming. A create or replace records the generation
//! the configuration asks for, and state refuses a generation an address has
//! already used. The planner does not pre-check that: it proposes the
//! rotation, and apply reports the refusal.

mod diff;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::api::{ObservedAssignment, ObservedGuardrail, ObservedKey};
use crate::config::{Config, Guardrail, Key, Managed, ResetInterval, Usd};
use crate::ids::{Address, KeyHash, OperationId, ReceiverFingerprint, RemoteName, Uuid};
use crate::state::{CurrentKey, KeyBinding, PendingOperation, Phase, State};

// The comparison itself, for the two commands that need one resource's managed
// difference without a whole plan: `import`, which shows what a later apply
// would reconcile, and apply, which builds the request body that reconciles it.
pub use diff::{guardrail_changes, key_changes};

/// A complete, freshly observed picture of the resources Keymaster manages.
///
/// Completeness matters: a partial read makes a key that exists look like one
/// that does not, and this planner reports the difference as
/// [`ActionKind::Missing`]. Assembling one is [`crate::api::Reader`]'s job.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    /// Every API key, disabled ones included.
    pub keys: Vec<ObservedKey>,
    /// Every guardrail.
    pub guardrails: Vec<ObservedGuardrail>,
    /// Every key-to-guardrail assignment.
    pub assignments: Vec<ObservedAssignment>,
}

/// What Keymaster intends to do, in the order it intends to do it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    actions: Vec<Action>,
}

impl Plan {
    /// Every action, dependencies before dependents.
    #[must_use]
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// Whether an operation of unknown outcome stops this run (ADR-0002).
    ///
    /// This is the widest of the three things an unfinished operation can do,
    /// and the only one that stops everything: an operator has to establish
    /// what happened before Keymaster touches anything at all. An operation
    /// whose outcome the journal already settles does less — see
    /// [`Plan::executable`].
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.actions
            .iter()
            .any(|action| action.kind == ActionKind::RecoveryRequired)
    }

    /// The actions apply may execute, in order.
    ///
    /// Empty while the plan is blocked, and never yields an action something
    /// unresolved holds back. Both are expressed here rather than left to each
    /// caller to remember, because a caller that iterated [`Plan::actions`]
    /// instead would create a key whose guardrail an operator has not bound
    /// yet.
    ///
    /// An unfinished operation reaches this in one of three widths, matching
    /// what its phase actually leaves undecided:
    ///
    /// - Unknown outcome — the five ambiguous phases. Nothing runs: the plan
    ///   is blocked and this yields nothing.
    /// - Known outcome, unresolved — `secured`. The key exists, is
    ///   restricted, and can never be delivered. Its own replacement is held
    ///   back — as is the report that stands in for one when the
    ///   configuration cannot supply it — and so is every other key create or
    ///   replace, because state refuses to start a second operation beside the
    ///   one that stands. The updates and assignments this run would otherwise
    ///   make still run.
    /// - Settled — `delivered`. Nothing is held back here, but state still
    ///   refuses a create until the operation is cleared, so apply must
    ///   promote it under its lock and replan before executing anything (#16).
    ///   Issuance unblocks on that replan, because the operation is gone.
    pub fn executable(&self) -> impl Iterator<Item = &Action> {
        let blocked = self.is_blocked();
        self.actions
            .iter()
            .filter(move |action| action.is_executable(blocked))
    }

    /// Whether anything would be written if this plan were applied.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.executable().next().is_some()
    }
}

/// One intended change, or one thing worth reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// What kind of action this is.
    pub kind: ActionKind,
    /// The resource it is about.
    pub address: ResourceAddress,
    /// The immutable remote identity, when one is known. A create has none
    /// yet.
    pub identity: Option<Identity>,
    /// The managed fields that differ, and which way.
    pub changes: Vec<FieldChange>,
    /// Resources that must be settled before this action runs.
    pub depends_on: Vec<ResourceAddress>,
    /// Why the planner proposes this.
    pub rationale: Vec<Reason>,
    /// What executing it would risk.
    pub safety: Safety,
}

impl Action {
    /// Whether something this action needs is unresolved: a dependency that
    /// needs an operator, or an incomplete operation at its own address.
    ///
    /// A blocked action stays in the plan — an operator needs to see what will
    /// not happen and why — but [`Plan::executable`] never yields it.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.rationale.iter().any(|reason| {
            matches!(
                reason,
                Reason::BlockedBy { .. } | Reason::OperationIncomplete { .. }
            )
        })
    }

    /// Whether this action keeps the run from being finished.
    ///
    /// A write is work the configuration asks for. A blocker — an adoption, a
    /// missing resource, an unfinished operation — is work only an operator
    /// can clear. An action waiting on either is in the same position.
    ///
    /// Everything else is a pure report: an unmanaged remote resource, an
    /// orphaned binding with nothing pending, a no-op. None of those is work
    /// Keymaster or an operator owes the configuration, so none of them keeps
    /// a run out of convergence. An orphaned binding that still carries an
    /// unfinished operation does, because that operation is unsettled.
    #[must_use]
    pub fn holds_back(&self) -> bool {
        self.kind.writes() || self.kind.blocks_dependents() || self.is_blocked()
    }

    /// Whether apply may execute this action, given whether the plan it
    /// belongs to is blocked.
    ///
    /// The one definition of "executable", so that [`Plan::executable`], the
    /// plan report, and apply itself cannot drift apart on what an apply would
    /// do — which is the difference between a report an operator can trust and
    /// one they cannot.
    #[must_use]
    pub fn is_executable(&self, plan_blocked: bool) -> bool {
        !plan_blocked && self.kind.writes() && !self.is_blocked()
    }
}

/// The kinds of action a plan can contain.
///
/// The derived order is the tie-break between two actions at one address,
/// which only ever separates the removals of a key's assignments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActionKind {
    /// An earlier run left a create or a delivery unfinished. Nothing else
    /// runs until an operator resolves it.
    RecoveryRequired,
    /// Create the remote resource.
    Create,
    /// Bring an existing remote resource's managed fields to the desired
    /// values.
    Update,
    /// Create a successor key and deliver it. The predecessor is left as it
    /// is until an explicit retirement.
    Replace,
    /// Remove a key's assignment to a guardrail, because the configuration
    /// asks for none.
    Unassign,
    /// Assign a key to a guardrail, replacing whatever direct assignment it
    /// has: a key has at most one, and assigning is what moves it.
    Assign,
    /// A remote resource carries the configured name, but nothing binds it.
    /// An operator binds it explicitly with `import`.
    AdoptionRequired,
    /// The resource this address is bound to is not in the snapshot, and
    /// Keymaster will not recreate it.
    Missing,
    /// State binds an address the configuration no longer describes.
    OrphanedBinding,
    /// A remote resource no local address owns. Reported, never changed.
    Unmanaged,
    /// Nothing to do.
    NoOp,
}

impl ActionKind {
    /// The spelling used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryRequired => "recovery_required",
            Self::Create => "create",
            Self::Update => "update",
            Self::Replace => "replace",
            Self::Unassign => "unassign",
            Self::Assign => "assign",
            Self::AdoptionRequired => "adoption_required",
            Self::Missing => "missing",
            Self::OrphanedBinding => "orphaned_binding",
            Self::Unmanaged => "unmanaged",
            Self::NoOp => "no_op",
        }
    }

    /// Whether executing this action writes to OpenRouter.
    #[must_use]
    pub const fn writes(self) -> bool {
        matches!(
            self,
            Self::Create | Self::Update | Self::Replace | Self::Unassign | Self::Assign
        )
    }

    /// Whether this action leaves its resource in a state nothing may be built
    /// on: it needs an operator, so anything depending on it cannot run.
    const fn blocks_dependents(self) -> bool {
        matches!(
            self,
            Self::RecoveryRequired | Self::AdoptionRequired | Self::Missing
        )
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What an action is about.
///
/// A managed resource is addressed the way the configuration names it. A
/// remote resource nothing owns has no local name, so it is addressed by its
/// immutable identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceAddress {
    /// A configured or bound guardrail.
    Guardrail(Address),
    /// A configured or bound key.
    Key(Address),
    /// The guardrail assignment of one key.
    Assignment(Address),
    /// A remote key no local address owns.
    RemoteKey(KeyHash),
    /// A remote guardrail no local address owns.
    RemoteGuardrail(Uuid),
}

impl fmt::Display for ResourceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guardrail(address) => write!(f, "guardrails.{address}"),
            Self::Key(address) => write!(f, "keys.{address}"),
            Self::Assignment(address) => write!(f, "keys.{address}.guardrail"),
            Self::RemoteKey(hash) => write!(f, "remote key {hash}"),
            Self::RemoteGuardrail(id) => write!(f, "remote guardrail {id}"),
        }
    }
}

/// An immutable remote identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Identity {
    /// A key, by hash.
    Key(KeyHash),
    /// A guardrail, by UUID.
    Guardrail(Uuid),
    /// One key's assignment to one guardrail.
    Assignment {
        /// The key's hash.
        key: KeyHash,
        /// The guardrail's UUID.
        guardrail: Uuid,
    },
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(hash) => write!(f, "key {hash}"),
            Self::Guardrail(id) => write!(f, "guardrail {id}"),
            Self::Assignment { key, guardrail } => write!(f, "key {key} on guardrail {guardrail}"),
        }
    }
}

/// One managed field that differs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldChange {
    /// The configuration's name for the field.
    pub field: &'static str,
    /// What OpenRouter has now.
    pub from: FieldValue,
    /// What the configuration asks for.
    pub to: FieldValue,
    /// How this change widens what a credential may do, if it does.
    pub expansion: Option<Expansion>,
}

/// A value on either side of a difference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldValue {
    /// Nothing: unset remotely, or explicitly cleared.
    Absent,
    Flag(bool),
    Money(Usd),
    Interval(ResetInterval),
    Text(String),
    Timestamp(OffsetDateTime),
    /// A set of model or provider slugs.
    Slugs(BTreeSet<String>),
    /// A guardrail or workspace identity.
    Guardrail(Uuid),
    /// A local address, when the remote identity is not known yet.
    Address(Address),
}

impl FieldValue {
    fn text(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("(none)"),
            Self::Flag(flag) => write!(f, "{flag}"),
            Self::Money(amount) => write!(f, "{amount}"),
            Self::Interval(interval) => f.write_str(interval.as_str()),
            Self::Text(text) => f.write_str(text),
            Self::Timestamp(when) => {
                let rendered = when.format(&Rfc3339).unwrap_or_else(|_| when.to_string());
                f.write_str(&rendered)
            }
            Self::Slugs(slugs) if slugs.is_empty() => f.write_str("(none)"),
            Self::Slugs(slugs) => {
                let joined: Vec<&str> = slugs.iter().map(String::as_str).collect();
                f.write_str(&joined.join(", "))
            }
            Self::Guardrail(id) => write!(f, "{id}"),
            Self::Address(address) => write!(f, "{address}"),
        }
    }
}

/// Why the planner proposes an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Everything the configuration manages already matches.
    InSync,
    /// Managed fields differ from the configuration.
    Drift,
    /// Nothing is bound and nothing remote carries the configured name.
    NotCreatedYet,
    /// The bound remote object is not in the snapshot.
    AbsentRemotely,
    /// No remote object carries the configured name, so recreating one cannot
    /// collide with an existing resource.
    NoNameCollision,
    /// A remote object already carries the configured name.
    NameCollision {
        /// The remote objects that carry it.
        holders: Vec<Identity>,
    },
    /// Unbound, and a remote object carries the configured name. Binding it is
    /// an operator's decision, made with `import`.
    NameMatches {
        /// The remote objects that could be imported.
        candidates: Vec<Identity>,
    },
    /// The configuration asks for a higher generation than the bound key's.
    GenerationRaised {
        /// The generation the bound key has.
        from: u32,
        /// The generation the configuration asks for.
        to: u32,
    },
    /// The key's plaintext was delivered somewhere the configuration no longer
    /// describes. A delivered secret cannot be moved, only replaced.
    ReceiverChanged,
    /// A field OpenRouter fixes at creation differs.
    ImmutableFieldChanged {
        /// The configuration's name for the field.
        field: &'static str,
    },
    /// The key has no receiver, so a created plaintext would have nowhere to
    /// go. Such a key can be imported and managed, never created.
    NoReceiver,
    /// The key was delivered somewhere, and the configuration no longer names
    /// a receiver at all. Nothing is replaced over it — the destination still
    /// holds a working key — but the configuration no longer says who does.
    ReceiverUnspecified {
        /// The destination the plaintext was delivered to, as the non-secret
        /// digest state recorded.
        delivered: ReceiverFingerprint,
    },
    /// The key is not assigned to the configured guardrail.
    AssignmentMissing,
    /// The key is assigned to a guardrail the configuration does not ask for.
    AssignmentUndesired,
    /// The configuration no longer describes this address.
    RemovedFromConfiguration,
    /// No local address owns this remote object.
    NotConfigured,
    /// An earlier run delivered a key and stopped before promoting it. The
    /// transaction is complete; promotion is a local state operation with no
    /// external effect, which apply completes before it plans (#16).
    PromotionPending {
        /// The operation's identifier.
        operation: OperationId,
        /// When the receiver acknowledged the delivery.
        delivered_at: OffsetDateTime,
    },
    /// An earlier run left this operation unfinished, and what happened to it
    /// is an operator's to establish. Nothing runs while one stands.
    OperationIncomplete {
        /// The operation's identifier, as journaled before the request.
        operation: OperationId,
        /// How far it got.
        phase: Phase,
        /// When it reached that phase.
        phase_at: OffsetDateTime,
    },
    /// The receiver definitely refused the plaintext, which is therefore gone.
    DeliveryRefused {
        /// When the refusal was recorded.
        at: OffsetDateTime,
    },
    /// The key's plaintext no longer exists, so the key can never be
    /// delivered: recovery means replacing it (ADR-0002).
    PlaintextLost,
    /// Something this action needs is unresolved, so it will not run.
    BlockedBy {
        /// The resource that needs an operator first.
        dependency: ResourceAddress,
    },
}

/// What executing an action would risk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Safety {
    class: SafetyClass,
    expansions: BTreeSet<Expansion>,
}

impl Safety {
    /// The action's broad class.
    #[must_use]
    pub const fn class(&self) -> SafetyClass {
        self.class
    }

    /// Every way this action widens what a credential may do.
    #[must_use]
    pub fn expansions(&self) -> &BTreeSet<Expansion> {
        &self.expansions
    }

    /// Whether this action widens what a credential may do.
    #[must_use]
    pub fn expands_privilege(&self) -> bool {
        !self.expansions.is_empty()
    }

    /// Classifies an action from what it would write.
    fn classify(kind: ActionKind, address: &ResourceAddress, changes: &[FieldChange]) -> Self {
        if !kind.writes() {
            // A report writes nothing, so it cannot widen anything, whatever
            // difference it happens to carry for the operator to read.
            return Self {
                class: SafetyClass::Report,
                expansions: BTreeSet::new(),
            };
        }
        let expansions: BTreeSet<Expansion> = changes
            .iter()
            .filter_map(|change| change.expansion)
            .collect();

        let class = if issues_credential(kind, address) {
            SafetyClass::Issuing
        } else if expansions.is_empty() {
            SafetyClass::Routine
        } else {
            SafetyClass::Expanding
        };
        Self { class, expansions }
    }
}

/// How much care an action needs, from least to most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SafetyClass {
    /// Writes nothing.
    Report,
    /// A write that cannot widen what any credential may do.
    Routine,
    /// A write that widens what an existing credential may do.
    Expanding,
    /// Issues new secret material.
    Issuing,
}

impl SafetyClass {
    /// The spelling used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Routine => "routine",
            Self::Expanding => "expanding",
            Self::Issuing => "issuing",
        }
    }
}

impl fmt::Display for SafetyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One way an action widens what a credential may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Expansion {
    /// A disabled key becomes enabled.
    KeyEnabled,
    /// A spending limit rose, or was removed entirely.
    BudgetRaised {
        /// The field that carries the limit.
        field: &'static str,
    },
    /// A limit that reset less often now resets more often, so the same number
    /// permits more spending.
    BudgetResetShortened {
        /// The field that carries the schedule.
        field: &'static str,
    },
    /// A permit list grew, or stopped restricting anything.
    AllowlistWidened {
        /// The list that grew.
        field: &'static str,
    },
    /// A refusal list lost an entry.
    DenylistNarrowed {
        /// The list that shrank.
        field: &'static str,
    },
    /// Zero-data-retention enforcement was turned off.
    ZdrWeakened,
    /// Spend on the operator's own provider keys stops counting against the
    /// limit.
    ByokExcludedFromLimit,
    /// A key loses the guardrail that restricted it.
    GuardrailRemoved,
}

impl Expansion {
    /// The spelling used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyEnabled => "key_enabled",
            Self::BudgetRaised { .. } => "budget_raised",
            Self::BudgetResetShortened { .. } => "budget_reset_shortened",
            Self::AllowlistWidened { .. } => "allowlist_widened",
            Self::DenylistNarrowed { .. } => "denylist_narrowed",
            Self::ZdrWeakened => "zdr_weakened",
            Self::ByokExcludedFromLimit => "byok_excluded_from_limit",
            Self::GuardrailRemoved => "guardrail_removed",
        }
    }
}

impl fmt::Display for Expansion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Computes the plan.
///
/// Pure: the same inputs always produce the same plan.
///
/// `workspace` is the run's scope (ADR-0004, item 5). With `Some(id)`, matching
/// by name and the report of unmanaged resources consider only remote
/// resources in that workspace; matching by identity, which decides whether a
/// bound resource is present or missing, still uses the whole snapshot.
#[must_use]
pub fn plan(config: &Config, state: &State, observed: &Snapshot, workspace: Option<&Uuid>) -> Plan {
    let index = Index::build(config, state, observed, workspace);
    let mut actions = Vec::new();

    plan_guardrails(&index, &mut actions);
    plan_keys(&index, &mut actions);
    plan_orphans(&index, &mut actions);
    plan_unmanaged(&index, &mut actions);

    mark_blocked(&mut actions);
    actions.sort_by(|left, right| ordering_key(left).cmp(&ordering_key(right)));
    Plan { actions }
}

/// Records, on every action, which of the things it needs is unresolved.
///
/// An address is unresolved when its own action needs an operator — an
/// adoption, a missing resource, a recovery — or when it depends on an address
/// that is. Creating a key whose guardrail nobody has bound yet would leave a
/// live credential without the restrictions it was supposed to be secured
/// with, so the dependent is held back with the dependency.
///
/// One thing that holds an action back is not a dependency at all: an
/// operation standing at another address. Keymaster creates and delivers one
/// key at a time, so while one is unfinished `begin_create` refuses every
/// other create — and a plan that offered one would be promising a write the
/// state API would decline.
fn mark_blocked(actions: &mut [Action]) {
    if let Some(pending) = issuance_blocker(actions) {
        for action in actions.iter_mut() {
            if action.address != pending && issues_credential(action.kind, &action.address) {
                action.rationale.push(Reason::BlockedBy {
                    dependency: pending.clone(),
                });
            }
        }
    }

    let mut unresolved: BTreeSet<ResourceAddress> = actions
        .iter()
        .filter(|action| action.kind.blocks_dependents() || action.is_blocked())
        .map(|action| action.address.clone())
        .collect();

    // A fixpoint, so the block reaches a dependent's dependents.
    loop {
        let widened: Vec<ResourceAddress> = actions
            .iter()
            .filter(|action| !unresolved.contains(&action.address))
            .filter(|action| {
                action
                    .depends_on
                    .iter()
                    .any(|dependency| unresolved.contains(dependency))
            })
            .map(|action| action.address.clone())
            .collect();
        if widened.is_empty() {
            break;
        }
        unresolved.extend(widened);
    }

    for action in actions.iter_mut() {
        if action.kind.blocks_dependents() {
            continue;
        }
        let blockers: Vec<ResourceAddress> = action
            .depends_on
            .iter()
            .filter(|dependency| unresolved.contains(*dependency))
            .cloned()
            .collect();
        action.rationale.extend(
            blockers
                .into_iter()
                .map(|dependency| Reason::BlockedBy { dependency }),
        );
    }
}

/// The address of an operation that stops other keys from being created
/// without stopping the run.
///
/// The ambiguous phases do not appear here: they are reported as
/// [`ActionKind::RecoveryRequired`] and [`Plan::is_blocked`] holds everything
/// back already. A delivered operation does not either: apply clears it before
/// it plans. What is left is an operation whose outcome is known and whose
/// resolution is an operator's, which state will not let a create run beside.
fn issuance_blocker(actions: &[Action]) -> Option<ResourceAddress> {
    actions
        .iter()
        .find(|action| {
            action.kind != ActionKind::RecoveryRequired
                && action
                    .rationale
                    .iter()
                    .any(|reason| matches!(reason, Reason::OperationIncomplete { .. }))
        })
        .map(|action| action.address.clone())
}

/// Whether an action puts new secret material into the world.
fn issues_credential(kind: ActionKind, address: &ResourceAddress) -> bool {
    matches!(kind, ActionKind::Create | ActionKind::Replace)
        && matches!(address, ResourceAddress::Key(_))
}

/// Where an action sits in the dependency order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    /// An unresolved operation stops everything, so it is reported first.
    Recovery,
    /// Guardrails exist before the keys that must be secured by them.
    Guardrail,
    /// Keys exist before their assignments.
    Key,
    /// Assignments need both ends.
    Assignment,
    /// Reports about resources no address owns.
    Remote,
}

/// The total order actions are emitted in.
///
/// Stage first, so dependencies precede dependents; then the resource address,
/// so the order does not depend on the order resources were planned in; then
/// the kind and the identity, which only ever separate two actions on one
/// key's assignments.
fn ordering_key(action: &Action) -> (Stage, &ResourceAddress, ActionKind, Option<&Identity>) {
    let stage = if action.kind == ActionKind::RecoveryRequired {
        Stage::Recovery
    } else {
        match action.address {
            ResourceAddress::Guardrail(_) => Stage::Guardrail,
            ResourceAddress::Key(_) => Stage::Key,
            ResourceAddress::Assignment(_) => Stage::Assignment,
            ResourceAddress::RemoteKey(_) | ResourceAddress::RemoteGuardrail(_) => Stage::Remote,
        }
    };
    (
        stage,
        &action.address,
        action.kind,
        action.identity.as_ref(),
    )
}

/// What an action carries besides its kind and address.
#[derive(Debug, Default)]
struct Proposal {
    identity: Option<Identity>,
    changes: Vec<FieldChange>,
    depends_on: Vec<ResourceAddress>,
    rationale: Vec<Reason>,
}

impl Proposal {
    /// Finishes an action, classifying its safety from what it would write.
    fn into_action(self, kind: ActionKind, address: ResourceAddress) -> Action {
        let safety = Safety::classify(kind, &address, &self.changes);
        Action {
            kind,
            address,
            identity: self.identity,
            changes: self.changes,
            depends_on: self.depends_on,
            rationale: self.rationale,
            safety,
        }
    }
}

/// The three inputs, indexed by identity.
///
/// Everything is a `BTreeMap` so that iteration order is the identity order
/// rather than the order OpenRouter happened to return.
struct Index<'a> {
    config: &'a Config,
    state: &'a State,
    /// The one workspace this run reports on and matches names in, when it is
    /// scoped to one.
    workspace: Option<&'a Uuid>,
    keys: BTreeMap<&'a KeyHash, &'a ObservedKey>,
    guardrails: BTreeMap<&'a Uuid, &'a ObservedGuardrail>,
    assignments: BTreeMap<&'a KeyHash, BTreeMap<&'a Uuid, &'a ObservedAssignment>>,
    key_owner: BTreeMap<&'a KeyHash, &'a Address>,
    guardrail_owner: BTreeMap<&'a Uuid, &'a Address>,
}

impl<'a> Index<'a> {
    fn build(
        config: &'a Config,
        state: &'a State,
        observed: &'a Snapshot,
        workspace: Option<&'a Uuid>,
    ) -> Self {
        let mut assignments: BTreeMap<&KeyHash, BTreeMap<&Uuid, &ObservedAssignment>> =
            BTreeMap::new();
        for assignment in &observed.assignments {
            assignments
                .entry(&assignment.key_hash)
                .or_default()
                .insert(&assignment.guardrail_id, assignment);
        }

        Self {
            config,
            state,
            workspace,
            keys: observed.keys.iter().map(|key| (&key.hash, key)).collect(),
            guardrails: observed
                .guardrails
                .iter()
                .map(|guardrail| (&guardrail.id, guardrail))
                .collect(),
            assignments,
            key_owner: state
                .keys()
                .iter()
                .flat_map(|(address, binding)| binding.hashes().map(move |hash| (hash, address)))
                .collect(),
            guardrail_owner: state
                .guardrails()
                .iter()
                .map(|(address, binding)| (&binding.id, address))
                .collect(),
        }
    }

    /// Whether a remote resource in `workspace` is one this run reports on and
    /// matches names against.
    ///
    /// Everything is, without a scope. With one, only what is in it: another
    /// club's identically named key must not block this one, and must not be
    /// reported as noise either (ADR-0004, item 5).
    fn in_scope(&self, workspace: Option<&Uuid>) -> bool {
        self.workspace.is_none_or(|scope| workspace == Some(scope))
    }

    /// Remote keys carrying `name`, in scope, that no local address owns.
    fn unowned_keys_named(&self, name: &RemoteName) -> Vec<Identity> {
        self.keys
            .values()
            .filter(|key| self.in_scope(key.workspace_id.as_ref()))
            .filter(|key| key.name.trim() == name.as_str())
            .filter(|key| !self.key_owner.contains_key(&key.hash))
            .map(|key| Identity::Key(key.hash.clone()))
            .collect()
    }

    /// Remote guardrails carrying `name` that no local address owns.
    ///
    /// Ownership filters adoption candidates, and only those: a guardrail
    /// somebody else owns is not one this address may import.
    fn unowned_guardrails_named(&self, name: &RemoteName) -> Vec<Identity> {
        self.guardrails_named(name)
            .into_iter()
            .filter(|identity| match identity {
                Identity::Guardrail(id) => !self.guardrail_owner.contains_key(id),
                Identity::Key(_) | Identity::Assignment { .. } => true,
            })
            .collect()
    }

    /// Every remote guardrail carrying `name` and in scope, owned or not.
    ///
    /// What a recreation has to be checked against: a guardrail another
    /// address owns and someone renamed still collides, and creating a second
    /// one under the same name is exactly the confusion a display name cannot
    /// be trusted to resolve.
    fn guardrails_named(&self, name: &RemoteName) -> Vec<Identity> {
        self.guardrails
            .values()
            .filter(|guardrail| self.in_scope(guardrail.workspace_id.as_ref()))
            .filter(|guardrail| guardrail.name.trim() == name.as_str())
            .map(|guardrail| Identity::Guardrail(guardrail.id.clone()))
            .collect()
    }

    /// Whether the guardrail bound at this local address will enforce zero
    /// data retention once the plan has run.
    fn will_enforce_zdr(&self, address: &Address) -> bool {
        if let Some(managed) = self
            .config
            .guardrails
            .get(address)
            .and_then(|guardrail| guardrail.require_zdr)
        {
            return managed;
        }
        self.state
            .guardrail(address)
            .and_then(|binding| self.guardrails.get(&binding.id).copied())
            .is_some_and(Self::enforced)
    }

    /// Whether a remote guardrail enforces zero data retention now.
    fn enforces_zdr(&self, id: &Uuid) -> bool {
        self.guardrails.get(id).copied().is_some_and(Self::enforced)
    }

    /// Only the single flag the configuration models; the per-provider flags
    /// are OpenRouter's.
    fn enforced(guardrail: &ObservedGuardrail) -> bool {
        guardrail.zero_data_retention.any == Some(true)
    }

    /// Whether the key's plaintext was delivered somewhere the configuration
    /// no longer describes.
    ///
    /// Only a recorded destination can have changed: an imported key has none,
    /// and that absence is not a reason to replace a live credential (#13).
    fn receiver_changed(&self, desired: &Key, current: &CurrentKey) -> bool {
        let (Some(delivered), Some(address)) = (&current.receiver, &desired.receiver) else {
            return false;
        };
        self.config
            .receivers
            .get(address)
            .is_some_and(|receiver| receiver.fingerprint() != *delivered)
    }
}

// --- guardrails ------------------------------------------------------------

fn plan_guardrails(index: &Index<'_>, actions: &mut Vec<Action>) {
    for (address, desired) in &index.config.guardrails {
        actions.push(plan_guardrail(address, desired, index));
    }
}

fn plan_guardrail(address: &Address, desired: &Guardrail, index: &Index<'_>) -> Action {
    let at = ResourceAddress::Guardrail(address.clone());
    let Some(binding) = index.state.guardrail(address) else {
        return plan_unbound_guardrail(desired, index, at);
    };

    let Some(observed) = index.guardrails.get(&binding.id) else {
        // Bound to a guardrail that is not there. Recreating is safe only if
        // nothing else already answers to the name, whoever owns it.
        let holders = index.guardrails_named(&desired.name);
        let identity = Some(Identity::Guardrail(binding.id.clone()));
        if !holders.is_empty() {
            return Proposal {
                identity,
                rationale: vec![Reason::AbsentRemotely, Reason::NameCollision { holders }],
                ..Proposal::default()
            }
            .into_action(ActionKind::Missing, at);
        }
        return Proposal {
            changes: diff::guardrail_changes(desired, None),
            rationale: vec![Reason::AbsentRemotely, Reason::NoNameCollision],
            ..Proposal::default()
        }
        .into_action(ActionKind::Create, at);
    };

    let changes = diff::guardrail_changes(desired, Some(observed));
    let identity = Some(Identity::Guardrail(binding.id.clone()));
    let (kind, reason) = if changes.is_empty() {
        (ActionKind::NoOp, Reason::InSync)
    } else {
        (ActionKind::Update, Reason::Drift)
    };
    Proposal {
        identity,
        changes,
        rationale: vec![reason],
        ..Proposal::default()
    }
    .into_action(kind, at)
}

/// A configured guardrail that state does not bind.
fn plan_unbound_guardrail(desired: &Guardrail, index: &Index<'_>, at: ResourceAddress) -> Action {
    let candidates = index.unowned_guardrails_named(&desired.name);
    if !candidates.is_empty() {
        // A name is mutable and not unique, so a match is a candidate for
        // `import`, never an adoption (ADR-0001).
        return Proposal {
            rationale: vec![Reason::NameMatches { candidates }],
            ..Proposal::default()
        }
        .into_action(ActionKind::AdoptionRequired, at);
    }
    Proposal {
        changes: diff::guardrail_changes(desired, None),
        rationale: vec![Reason::NotCreatedYet],
        ..Proposal::default()
    }
    .into_action(ActionKind::Create, at)
}

// --- keys ------------------------------------------------------------------

fn plan_keys(index: &Index<'_>, actions: &mut Vec<Action>) {
    let pending = index.state.pending_operation();
    for (address, desired) in &index.config.keys {
        if let Some((blocking, operation)) = pending
            && blocking == address
        {
            // The address is on hold until the operation is settled, and so is
            // its assignment: the key it would name is the one in question.
            actions.push(plan_pending(address, Some(desired), operation));
            continue;
        }

        let binding = index.state.key(address);
        let observed = binding
            .and_then(KeyBinding::current)
            .and_then(|current| index.keys.get(&current.hash).copied());
        let action = plan_key(address, desired, binding, index);
        let kind = action.kind;
        actions.push(action);
        plan_assignment(address, desired, observed, kind, index, actions);
    }
}

fn plan_key(
    address: &Address,
    desired: &Key,
    binding: Option<&KeyBinding>,
    index: &Index<'_>,
) -> Action {
    let at = ResourceAddress::Key(address.clone());
    let Some(current) = binding.and_then(KeyBinding::current) else {
        return plan_unbound_key(desired, index, at);
    };

    let identity = Some(Identity::Key(current.hash.clone()));
    let Some(observed) = index.keys.get(&current.hash) else {
        // ADR-0001: a delivered key that is missing remotely is reported, not
        // recreated. The read may simply have been incomplete, and a
        // replacement would issue a second live credential.
        return Proposal {
            identity,
            rationale: vec![Reason::AbsentRemotely],
            ..Proposal::default()
        }
        .into_action(ActionKind::Missing, at);
    };

    let changes = diff::key_changes(desired, Some(observed));
    let mut rationale = replacement_reasons(index, desired, current, &changes);
    if rationale.is_empty() {
        let kind = if changes.is_empty() {
            ActionKind::NoOp
        } else {
            ActionKind::Update
        };
        return Proposal {
            identity,
            rationale: convergence_reasons(desired, current, &changes),
            changes,
            ..Proposal::default()
        }
        .into_action(kind, at);
    }

    // A replacement is a create, so it needs somewhere to deliver the new
    // plaintext.
    if desired.receiver.is_none() {
        rationale.push(Reason::NoReceiver);
        return Proposal {
            identity,
            changes,
            rationale,
            depends_on: Vec::new(),
        }
        .into_action(ActionKind::NoOp, at);
    }
    Proposal {
        identity,
        changes,
        depends_on: guardrail_dependency(desired),
        rationale,
    }
    .into_action(ActionKind::Replace, at)
}

/// Why a key that can be patched into shape is left as it is, or updated.
fn convergence_reasons(
    desired: &Key,
    current: &CurrentKey,
    changes: &[FieldChange],
) -> Vec<Reason> {
    let mut reasons = Vec::new();
    if !changes.is_empty() {
        reasons.push(Reason::Drift);
    }
    // The key's plaintext went somewhere the configuration no longer names.
    // Not a reason to replace a working credential — the destination is still
    // whatever it was — but not silence either: nobody can tell from the
    // configuration alone who holds this key.
    if let (Some(delivered), None) = (&current.receiver, &desired.receiver) {
        reasons.push(Reason::ReceiverUnspecified {
            delivered: delivered.clone(),
        });
    }
    if reasons.is_empty() {
        reasons.push(Reason::InSync);
    }
    reasons
}

/// Why this key cannot be patched into shape, if it cannot.
fn replacement_reasons(
    index: &Index<'_>,
    desired: &Key,
    current: &CurrentKey,
    changes: &[FieldChange],
) -> Vec<Reason> {
    let mut reasons = Vec::new();
    if desired.generation > current.generation {
        reasons.push(Reason::GenerationRaised {
            from: current.generation,
            to: desired.generation,
        });
    }
    if index.receiver_changed(desired, current) {
        reasons.push(Reason::ReceiverChanged);
    }
    for change in changes {
        if diff::IMMUTABLE_KEY_FIELDS.contains(&change.field) {
            reasons.push(Reason::ImmutableFieldChanged {
                field: change.field,
            });
        }
    }
    reasons
}

/// A configured key that state does not bind to a current hash.
fn plan_unbound_key(desired: &Key, index: &Index<'_>, at: ResourceAddress) -> Action {
    let candidates = index.unowned_keys_named(&desired.name);
    if !candidates.is_empty() {
        return Proposal {
            rationale: vec![Reason::NameMatches { candidates }],
            ..Proposal::default()
        }
        .into_action(ActionKind::AdoptionRequired, at);
    }

    let changes = diff::key_changes(desired, None);
    if desired.receiver.is_none() {
        // A key with no receiver can be imported and managed, never created:
        // OpenRouter discloses the plaintext once, and Keymaster does not
        // create a secret it has nowhere to put.
        return Proposal {
            changes,
            rationale: vec![Reason::NoReceiver],
            ..Proposal::default()
        }
        .into_action(ActionKind::NoOp, at);
    }
    Proposal {
        changes,
        depends_on: guardrail_dependency(desired),
        rationale: vec![Reason::NotCreatedYet],
        ..Proposal::default()
    }
    .into_action(ActionKind::Create, at)
}

/// A key is secured — restricted and guardrailed — before its plaintext is
/// delivered (ADR-0002), so its guardrail must exist first.
fn guardrail_dependency(desired: &Key) -> Vec<ResourceAddress> {
    desired
        .guardrail
        .value()
        .map(|address| vec![ResourceAddress::Guardrail(address.clone())])
        .unwrap_or_default()
}

/// What an address with an unfinished operation gets, by phase.
///
/// Two of ADR-0002's phases are not ambiguous, and reporting them as though
/// they were would send an operator to inspect OpenRouter for an answer the
/// journal already has.
fn plan_pending(address: &Address, desired: Option<&Key>, operation: &PendingOperation) -> Action {
    let at = ResourceAddress::Key(address.clone());
    let identity = operation.hash.clone().map(Identity::Key);

    if operation.phase == Phase::Delivered {
        // The transaction finished: the key exists, its restrictions were
        // verified, and the receiver acknowledged the plaintext. What is left
        // is promotion, which touches nothing outside this file.
        return Proposal {
            identity,
            rationale: vec![Reason::PromotionPending {
                operation: operation.id.clone(),
                delivered_at: operation.phase_at,
            }],
            ..Proposal::default()
        }
        .into_action(ActionKind::NoOp, at);
    }

    if operation.phase == Phase::Secured {
        return plan_dead_key(desired, operation, identity, at);
    }
    recovery_action(operation, identity, at)
}

/// A key that exists, is restricted, and can never be delivered.
///
/// `secured` is reached after the create response, so the plaintext existed
/// only in memory and is gone — whether the receiver definitely refused it or
/// the run was interrupted before delivery began. Nothing an operator can
/// discover changes that, so this is never a recovery: it is a replacement,
/// or a report saying why not even that is possible (ADR-0002).
///
/// The replacement is blocked whichever it is. The operation is on the
/// address, and `begin_create` refuses to start another while one stands, so
/// it is `openrouter-keymaster recover replace`'s to perform (#17): that clears the
/// operation and creates the successor under the same lock. Reporting the
/// replacement as executable here would promise apply something the state API
/// would refuse.
fn plan_dead_key(
    desired: Option<&Key>,
    operation: &PendingOperation,
    identity: Option<Identity>,
    at: ResourceAddress,
) -> Action {
    let mut rationale = vec![Reason::OperationIncomplete {
        operation: operation.id.clone(),
        phase: operation.phase,
        phase_at: operation.phase_at,
    }];
    if let Some(refused) = operation.delivery_rejected_at {
        rationale.push(Reason::DeliveryRefused { at: refused });
    }
    rationale.push(Reason::PlaintextLost);

    let Some(desired) = desired else {
        // The configuration dropped the address, so there is nothing to
        // replace the key with. Nothing is deleted or forgotten either
        // (ADR-0001): the binding stays tracked, carrying the operation that
        // an explicit command still has to settle.
        rationale.push(Reason::RemovedFromConfiguration);
        return Proposal {
            identity,
            rationale,
            ..Proposal::default()
        }
        .into_action(ActionKind::OrphanedBinding, at);
    };

    if desired.receiver.is_none() {
        // A replacement is a create, and Keymaster does not create a secret it
        // has nowhere to put. Reporting `replace` here would name an action
        // that cannot be performed at all, rather than one waiting on
        // recovery.
        rationale.push(Reason::NoReceiver);
        return Proposal {
            identity,
            rationale,
            ..Proposal::default()
        }
        .into_action(ActionKind::NoOp, at);
    }

    Proposal {
        identity,
        depends_on: guardrail_dependency(desired),
        rationale,
        ..Proposal::default()
    }
    .into_action(ActionKind::Replace, at)
}

/// An operation whose outcome only an operator can establish.
fn recovery_action(
    operation: &PendingOperation,
    identity: Option<Identity>,
    at: ResourceAddress,
) -> Action {
    let mut rationale = vec![Reason::OperationIncomplete {
        operation: operation.id.clone(),
        phase: operation.phase,
        phase_at: operation.phase_at,
    }];
    if let Some(refused) = operation.delivery_rejected_at {
        rationale.push(Reason::DeliveryRefused { at: refused });
    }
    // Past `created` the plaintext existed only in memory, so whatever the
    // operator finds, this key can never be delivered (ADR-0002). `created`
    // itself is still a halt rather than a replacement: the key's restrictions
    // were never verified, so it may be an unrestricted live credential.
    // `secured` never reaches here — see [`plan_dead_key`].
    if matches!(
        operation.phase,
        Phase::Created | Phase::DeliveryStarted | Phase::DeliveryAmbiguous
    ) {
        rationale.push(Reason::PlaintextLost);
    }

    Proposal {
        identity,
        rationale,
        ..Proposal::default()
    }
    .into_action(ActionKind::RecoveryRequired, at)
}

// --- assignments -----------------------------------------------------------

fn plan_assignment(
    address: &Address,
    desired: &Key,
    observed: Option<&ObservedKey>,
    key_action: ActionKind,
    index: &Index<'_>,
    actions: &mut Vec<Action>,
) {
    let at = ResourceAddress::Assignment(address.clone());
    let wanted = match &desired.guardrail {
        // Not modelled, so not Keymaster's to change.
        Managed::Unmanaged => return,
        Managed::Set(guardrail) => Some(guardrail),
        Managed::Cleared => None,
    };

    // A key that is about to exist needs its guardrail before its plaintext is
    // delivered (ADR-0002). A predecessor keeps the assignment it has until an
    // explicit retirement, so nothing is unassigned here.
    if matches!(key_action, ActionKind::Create | ActionKind::Replace) {
        if let Some(guardrail) = wanted {
            actions.push(assign_to_new_key(address, guardrail, at));
        }
        return;
    }

    let Some(observed) = observed else { return };

    // Only a guardrail that is bound *and* present can be the target: a
    // binding to a guardrail that is being recreated has an identity the plan
    // cannot know yet, and claiming the dead one would address the write to a
    // resource that is not there.
    let target = wanted
        .and_then(|guardrail| index.state.guardrail(guardrail))
        .map(|binding| &binding.id)
        .filter(|id| index.guardrails.contains_key(*id));
    let held = index.assignments.get(&observed.hash);

    let Some(guardrail) = wanted else {
        // Nothing is desired, so every assignment on the key has to go. There
        // is no assignment update endpoint; removal is per guardrail.
        let mut removed = false;
        for id in held.into_iter().flatten().map(|(id, _)| *id) {
            removed = true;
            actions.push(unassign(&observed.hash, id, at.clone()));
        }
        if !removed {
            actions.push(in_sync(at));
        }
        return;
    };

    if target.is_some_and(|id| held.is_some_and(|held| held.contains_key(id))) {
        actions.push(in_sync(at));
        return;
    }

    // A key has at most one direct guardrail, and assigning replaces the one
    // it has. So a move is one write, not a removal followed by an assignment
    // that would leave the key unrestricted in between.
    let current = held.and_then(|held| held.keys().next().copied());
    actions.push(assign(
        &observed.hash,
        guardrail,
        current,
        target,
        index,
        at,
    ));
}

fn in_sync(at: ResourceAddress) -> Action {
    Proposal {
        rationale: vec![Reason::InSync],
        ..Proposal::default()
    }
    .into_action(ActionKind::NoOp, at)
}

/// The assignment a key that does not exist yet will need.
fn assign_to_new_key(address: &Address, guardrail: &Address, at: ResourceAddress) -> Action {
    Proposal {
        changes: vec![FieldChange {
            field: "guardrail",
            from: FieldValue::Absent,
            to: FieldValue::Address(guardrail.clone()),
            expansion: None,
        }],
        depends_on: vec![
            ResourceAddress::Key(address.clone()),
            ResourceAddress::Guardrail(guardrail.clone()),
        ],
        rationale: vec![Reason::AssignmentMissing],
        ..Proposal::default()
    }
    .into_action(ActionKind::Assign, at)
}

/// Assigns an existing key, replacing whatever direct assignment it has.
fn assign(
    key: &KeyHash,
    guardrail: &Address,
    current: Option<&Uuid>,
    target: Option<&Uuid>,
    index: &Index<'_>,
    at: ResourceAddress,
) -> Action {
    // Moving between guardrails keeps the key restricted, so it is ordinary —
    // unless the guardrail it lands on will not enforce zero data retention
    // and the one it leaves does.
    let weakened =
        current.is_some_and(|id| index.enforces_zdr(id)) && !index.will_enforce_zdr(guardrail);
    let reason = if current.is_some() {
        Reason::AssignmentUndesired
    } else {
        Reason::AssignmentMissing
    };
    Proposal {
        identity: target.map(|id| Identity::Assignment {
            key: key.clone(),
            guardrail: id.clone(),
        }),
        changes: vec![FieldChange {
            field: "guardrail",
            from: current.map_or(FieldValue::Absent, |id| FieldValue::Guardrail(id.clone())),
            to: FieldValue::Address(guardrail.clone()),
            expansion: weakened.then_some(Expansion::ZdrWeakened),
        }],
        depends_on: vec![ResourceAddress::Guardrail(guardrail.clone())],
        rationale: vec![reason],
    }
    .into_action(ActionKind::Assign, at)
}

/// Removes one assignment, because the configuration asks for none.
fn unassign(key: &KeyHash, guardrail: &Uuid, at: ResourceAddress) -> Action {
    Proposal {
        identity: Some(Identity::Assignment {
            key: key.clone(),
            guardrail: guardrail.clone(),
        }),
        changes: vec![FieldChange {
            field: "guardrail",
            from: FieldValue::Guardrail(guardrail.clone()),
            to: FieldValue::Absent,
            expansion: Some(Expansion::GuardrailRemoved),
        }],
        rationale: vec![Reason::AssignmentUndesired],
        ..Proposal::default()
    }
    .into_action(ActionKind::Unassign, at)
}

// --- what the configuration no longer describes ----------------------------

/// Bindings the configuration dropped. Nothing is deleted or forgotten: the
/// binding stays tracked until an explicit command acts on it (ADR-0001).
fn plan_orphans(index: &Index<'_>, actions: &mut Vec<Action>) {
    let pending = index.state.pending_operation();
    for (address, binding) in index.state.keys() {
        if index.config.keys.contains_key(address) {
            continue;
        }
        if let Some((blocking, operation)) = pending
            && blocking == address
        {
            // No desired key to replace it with, so a dead key here is an
            // operator's to resolve like any other unfinished operation.
            actions.push(plan_pending(address, None, operation));
            continue;
        }
        actions.push(
            Proposal {
                identity: binding
                    .current()
                    .map(|current| Identity::Key(current.hash.clone())),
                rationale: vec![Reason::RemovedFromConfiguration],
                ..Proposal::default()
            }
            .into_action(
                ActionKind::OrphanedBinding,
                ResourceAddress::Key(address.clone()),
            ),
        );
    }

    for (address, binding) in index.state.guardrails() {
        if index.config.guardrails.contains_key(address) {
            continue;
        }
        actions.push(
            Proposal {
                identity: Some(Identity::Guardrail(binding.id.clone())),
                rationale: vec![Reason::RemovedFromConfiguration],
                ..Proposal::default()
            }
            .into_action(
                ActionKind::OrphanedBinding,
                ResourceAddress::Guardrail(address.clone()),
            ),
        );
    }
}

/// Remote resources no local address owns. Reported so an operator can see
/// them, and never changed.
///
/// A scoped run reports only what is in its workspace: another club's keys are
/// not this operator's to see, and reporting them as unmanaged would make every
/// run noise (ADR-0004, item 5).
fn plan_unmanaged(index: &Index<'_>, actions: &mut Vec<Action>) {
    for key in index.keys.values() {
        if index.key_owner.contains_key(&key.hash) || !index.in_scope(key.workspace_id.as_ref()) {
            continue;
        }
        actions.push(
            Proposal {
                identity: Some(Identity::Key(key.hash.clone())),
                rationale: vec![Reason::NotConfigured],
                ..Proposal::default()
            }
            .into_action(
                ActionKind::Unmanaged,
                ResourceAddress::RemoteKey(key.hash.clone()),
            ),
        );
    }

    for guardrail in index.guardrails.values() {
        if index.guardrail_owner.contains_key(&guardrail.id)
            || !index.in_scope(guardrail.workspace_id.as_ref())
        {
            continue;
        }
        actions.push(
            Proposal {
                identity: Some(Identity::Guardrail(guardrail.id.clone())),
                rationale: vec![Reason::NotConfigured],
                ..Proposal::default()
            }
            .into_action(
                ActionKind::Unmanaged,
                ResourceAddress::RemoteGuardrail(guardrail.id.clone()),
            ),
        );
    }
}
