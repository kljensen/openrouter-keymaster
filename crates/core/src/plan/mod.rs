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

use crate::api::{
    ObservedAssignment, ObservedDestination, ObservedGuardrail, ObservedKey, ObservedWorkspace,
};
use crate::config::{
    Config, Guardrail, Key, LogDestination, Managed, ResetInterval, Usd, Workspace,
};
use crate::ids::{Address, KeyHash, OperationId, ReceiverFingerprint, RemoteName, Uuid};
use crate::state::{CurrentKey, KeyBinding, PendingOperation, Phase, State};

// The comparison itself, for the two commands that need one resource's managed
// difference without a whole plan: `import`, which shows what a later apply
// would reconcile, and apply, which builds the request body that reconciles it.
pub use diff::{guardrail_changes, key_changes, log_destination_changes, workspace_changes};

/// Where a block's workspace stands, once its `workspace` address has been
/// looked up (ADR-0004, item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// The block names no workspace, so this run's scope decides where a create
    /// goes.
    Unspecified,
    /// A workspace this run can address: a raw `workspace_id`, or an address
    /// state binds.
    In(Uuid),
    /// The block names a workspace block nothing is bound to yet. The planner
    /// has no identity to show, so a create in this workspace depends on the
    /// workspace's own action and resolves its placement from the binding
    /// apply records; only a workspace this run cannot create holds it back.
    Unbound(Address),
}

impl Placement {
    /// The workspace this block is in, when one is known.
    #[must_use]
    pub const fn identity(&self) -> Option<&Uuid> {
        match self {
            Self::In(id) => Some(id),
            Self::Unspecified | Self::Unbound(_) => None,
        }
    }
}

/// Where a block naming `workspace` and `workspace_id` is placed.
///
/// Validation refuses both on one block, so at most one arm can apply. Public
/// because apply and `import` resolve the same reference the planner does, and
/// resolving it twice by hand is how the two would come to disagree.
#[must_use]
pub fn placement(
    state: &State,
    workspace: Option<&Address>,
    workspace_id: Option<&Uuid>,
) -> Placement {
    if let Some(id) = workspace_id {
        return Placement::In(id.clone());
    }
    let Some(address) = workspace else {
        return Placement::Unspecified;
    };
    state.workspace(address).map_or_else(
        || Placement::Unbound(address.clone()),
        |binding| Placement::In(binding.id.clone()),
    )
}

/// The workspace a guardrail belongs to, in the order the answers are decided:
/// what its block names, then the workspace that names it as a default, then
/// the scope this run places everything it creates in.
///
/// Public, and the only copy of the rule. The planner compares a guardrail
/// OpenRouter already has against it and `import guardrail` compares a fetched
/// one, and a second hand-written copy is how the two would come to disagree —
/// which would mean importing a guardrail that every later plan then held back.
///
/// The scope belongs here rather than being left to the create. A scoped run
/// places what it creates in the scope, so the scope *is* what the
/// configuration says about where a block's guardrail lives; without it, a
/// bound guardrail sitting in another workspace would be patched from a run
/// that is not allowed to touch anything there.
#[must_use]
pub fn configured_workspace_of(
    state: &State,
    desired: &Guardrail,
    default_of: Option<&Address>,
    scope: Option<&Uuid>,
) -> Option<Uuid> {
    guardrail_placement(state, desired)
        .identity()
        .cloned()
        .or_else(|| {
            default_of
                .and_then(|workspace| state.workspace(workspace))
                .map(|binding| binding.id.clone())
        })
        .or_else(|| scope.cloned())
}

/// The workspace block that names `guardrail` as its `default_guardrail`.
#[must_use]
pub fn workspace_defaulting_to<'a>(config: &'a Config, guardrail: &Address) -> Option<&'a Address> {
    config
        .workspaces
        .iter()
        .find(|(_, workspace)| workspace.default_guardrail.as_ref() == Some(guardrail))
        .map(|(address, _)| address)
}

/// Where a key is placed, before this run's scope has its say.
#[must_use]
pub fn key_placement(state: &State, desired: &Key) -> Placement {
    placement(
        state,
        desired.workspace.as_ref(),
        desired.workspace_id.as_ref(),
    )
}

/// Where a guardrail is placed, before this run's scope has its say.
#[must_use]
pub fn guardrail_placement(state: &State, desired: &Guardrail) -> Placement {
    placement(
        state,
        desired.workspace.as_ref(),
        desired.workspace_id.as_ref(),
    )
}

/// Where a log destination is placed, before this run's scope has its say.
#[must_use]
pub fn destination_placement(state: &State, desired: &LogDestination) -> Placement {
    placement(
        state,
        desired.workspace.as_ref(),
        desired.workspace_id.as_ref(),
    )
}

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
    /// Every workspace, each with the budgets it has.
    pub workspaces: Vec<ObservedWorkspace>,
    /// Every observability log destination.
    pub log_destinations: Vec<ObservedDestination>,
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
                Reason::BlockedBy { .. }
                    | Reason::OperationIncomplete { .. }
                    | Reason::BudgetNotConverged { .. }
                    | Reason::DefaultGuardrailConflict { .. }
                    | Reason::DefaultGuardrailOwnedElsewhere { .. }
                    | Reason::WorkspaceFixedAtCreation { .. }
                    | Reason::DestinationFixedAtCreation { .. }
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
    /// A configured or bound workspace.
    Workspace(Address),
    /// A configured or bound guardrail.
    Guardrail(Address),
    /// A configured or bound key.
    Key(Address),
    /// A configured or bound log destination.
    LogDestination(Address),
    /// The guardrail assignment of one key.
    Assignment(Address),
    /// A remote key no local address owns.
    RemoteKey(KeyHash),
    /// A remote guardrail no local address owns.
    RemoteGuardrail(Uuid),
    /// A remote workspace no local address owns.
    RemoteWorkspace(Uuid),
    /// A remote log destination no local address owns.
    RemoteLogDestination(Uuid),
}

impl fmt::Display for ResourceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(address) => write!(f, "workspaces.{address}"),
            Self::Guardrail(address) => write!(f, "guardrails.{address}"),
            Self::Key(address) => write!(f, "keys.{address}"),
            Self::LogDestination(address) => write!(f, "log_destinations.{address}"),
            Self::Assignment(address) => write!(f, "keys.{address}.guardrail"),
            Self::RemoteKey(hash) => write!(f, "remote key {hash}"),
            Self::RemoteGuardrail(id) => write!(f, "remote guardrail {id}"),
            Self::RemoteWorkspace(id) => write!(f, "remote workspace {id}"),
            Self::RemoteLogDestination(id) => write!(f, "remote log destination {id}"),
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
    /// A workspace, by UUID.
    Workspace(Uuid),
    /// A log destination, by UUID.
    LogDestination(Uuid),
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
            Self::Workspace(id) => write!(f, "workspace {id}"),
            Self::LogDestination(id) => write!(f, "log destination {id}"),
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
    /// This guardrail is the default of a workspace that exists or that this
    /// plan creates, and OpenRouter has not materialized it yet — it is in no
    /// listing until its configuration is first written, and in its own
    /// workspace's from then on. The one exception to "bound but absent means
    /// missing" (ADR-0004, item 3).
    DefaultGuardrailUnmaterialized {
        /// The workspace whose default guardrail this is.
        workspace: ResourceAddress,
    },
    /// This guardrail block is a workspace's `default_guardrail`, but the
    /// address already owns a different guardrail. Nothing can be written
    /// until an operator resolves which resource the address means.
    DefaultGuardrailConflict {
        /// The guardrail the address owns now.
        bound: Uuid,
        /// The identity its workspace names as its default.
        expected: Uuid,
    },
    /// This guardrail block is a workspace's `default_guardrail`, and the
    /// identity that workspace names is already owned by another address.
    DefaultGuardrailOwnedElsewhere {
        /// The identity the workspace names as its default.
        id: Uuid,
        /// The address that owns it.
        owner: Address,
    },
    /// OpenRouter has this guardrail in one workspace and the configuration
    /// places it in another. A guardrail's workspace is fixed at creation, and
    /// unlike a key a guardrail is never replaced, so nothing can converge it.
    WorkspaceFixedAtCreation {
        /// The workspace OpenRouter has it in, if any.
        observed: Option<Uuid>,
        /// The workspace the configuration places it in.
        desired: Uuid,
    },
    /// The workspace's configured budget has not converged, so this run will
    /// not issue or widen anything inside it (ADR-0004, item 4).
    BudgetNotConverged {
        /// The workspace whose budget is not in force.
        workspace: ResourceAddress,
    },
    /// A log destination field OpenRouter fixes at creation differs. `PATCH`
    /// accepts neither `type` nor `workspace_id`, and nothing here replaces a
    /// destination on its own, so the drift is held back until an operator
    /// deletes it and lets the next apply create it again (ADR-0006, item 2).
    DestinationFixedAtCreation {
        /// The configuration's name for the field.
        field: &'static str,
        /// The destination that would have to be deleted.
        id: Uuid,
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

    plan_workspaces(&index, &mut actions);
    plan_log_destinations(&index, &mut actions);
    plan_guardrails(&index, &mut actions);
    plan_keys(&index, &mut actions);
    plan_orphans(&index, &mut actions);
    plan_unmanaged(&index, &mut actions);

    mark_blocked(&index, &mut actions);
    hold_back_unbudgeted(&index, &mut actions);
    actions.sort_by(|left, right| ordering_key(left).cmp(&ordering_key(right)));
    Plan { actions }
}

/// Holds back every issuing or expanding write inside a workspace whose
/// configured budget is not in force (ADR-0004, item 4).
///
/// Spend enabled under a cap that has not converged is exactly what the budget
/// was for. So a run that could not set one goes on doing routine work — a
/// rename, a narrowed allowlist, a lowered limit — and stops issuing keys and
/// widening what the existing ones may do, in that workspace and nowhere else.
///
/// The workspace's own writes are exempt, since they are what converges it.
fn hold_back_unbudgeted(index: &Index<'_>, actions: &mut [Action]) {
    let unconverged: BTreeMap<Uuid, Address> = actions
        .iter()
        .filter_map(|action| {
            let ResourceAddress::Workspace(address) = &action.address else {
                return None;
            };
            let budgets_differ = action.changes.iter().any(is_budget_field);
            let binding = index.state.workspace(address)?;
            (budgets_differ).then(|| (binding.id.clone(), address.clone()))
        })
        .collect();
    if unconverged.is_empty() {
        return;
    }

    for action in actions.iter_mut() {
        if !matches!(
            action.safety.class(),
            SafetyClass::Issuing | SafetyClass::Expanding
        ) {
            continue;
        }
        let Some(placed) = index.placed_in(&action.address) else {
            continue;
        };
        if let Some(workspace) = unconverged.get(&placed) {
            action.rationale.push(Reason::BudgetNotConverged {
                workspace: ResourceAddress::Workspace(workspace.clone()),
            });
        }
    }
}

/// Whether a change is one of the four per-interval budgets or the
/// workspace-wide BYOK setting a budget write carries.
fn is_budget_field(change: &FieldChange) -> bool {
    change.field.starts_with("budgets.") || change.field == "include_byok_in_budgets"
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
fn mark_blocked(index: &Index<'_>, actions: &mut [Action]) {
    if let Some(pending) = issuance_blocker(actions) {
        for action in actions.iter_mut() {
            if action.address != pending && issues_credential(action.kind, &action.address) {
                action.rationale.push(Reason::BlockedBy {
                    dependency: pending.clone(),
                });
            }
        }
    }

    // A workspace nothing binds yet is not a blocker of its own: if this plan
    // creates it, apply records its identity before the guardrails and keys
    // inside it run, and those read their placement from state at execution
    // time — exactly how a key create depending on a guardrail create in the
    // same plan already works. What holds a dependent back is the state its own
    // dependency is left in, which its action already says: an adoption, a
    // resource nobody can find, or a create something else holds back
    // (ADR-0004, item 2).
    let mut unresolved: BTreeSet<ResourceAddress> = actions
        .iter()
        .filter(|action| action.kind.blocks_dependents() || action.is_blocked())
        .map(|action| action.address.clone())
        .collect();

    let unplaceable = unresolved_placements(index, actions);
    unresolved.extend(unplaceable.keys().cloned());

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
        let mut blockers: Vec<ResourceAddress> = action
            .depends_on
            .iter()
            .filter(|dependency| unresolved.contains(*dependency))
            .cloned()
            .collect();
        if let Some(workspace) = unplaceable.get(&action.address)
            && !blockers.contains(workspace)
        {
            blockers.push(workspace.clone());
        }
        action.rationale.extend(
            blockers
                .into_iter()
                .map(|dependency| Reason::BlockedBy { dependency }),
        );
    }
}

/// Whether this action brings its resource into existence, which is what makes
/// the workspace it is placed in a binding apply records rather than a
/// difference nothing can converge. A key's `replace` creates one too.
const fn creates_its_resource(kind: ActionKind) -> bool {
    matches!(kind, ActionKind::Create | ActionKind::Replace)
}

/// Every resource that already exists and whose block names a workspace nothing
/// binds yet, with the workspace each one waits on.
///
/// The same-run exception is for creates, and for creates only. A guardrail,
/// key, or destination this plan creates takes its placement from the binding
/// apply records a phase earlier; one that already exists cannot be moved at
/// all, because OpenRouter fixes a workspace when the resource is created. So
/// until that workspace has an identity there is nothing to judge the placement
/// against, and the honest answer is to write nothing and say what is missing.
/// The run after reports `workspace_fixed_at_creation` if the resource really
/// is somewhere else (ADR-0004, item 2).
///
/// Read from the configuration rather than from the plan's dependency edges,
/// because the edges are not where the problem shows. A resource whose fields
/// already match has no edges at all and a `no_op` action, and a key's update
/// carries no workspace dependency either — yet both would report a converged
/// resource sitting in a workspace the configuration no longer names, and the
/// key's update could widen it there.
fn unresolved_placements(
    index: &Index<'_>,
    actions: &[Action],
) -> BTreeMap<ResourceAddress, ResourceAddress> {
    // The assignment beside a key this plan creates or replaces belongs to the
    // successor, which is created in the workspace the binding will name — so
    // it is exempt exactly as the key's own action is. Without this the
    // predecessor's binding is what the placement lookup finds, and a
    // converged first apply would report held-back work.
    let issuing_keys: BTreeSet<&Address> = actions
        .iter()
        .filter(|action| creates_its_resource(action.kind))
        .filter_map(|action| match &action.address {
            ResourceAddress::Key(address) => Some(address),
            _ => None,
        })
        .collect();

    actions
        .iter()
        .filter(|action| !creates_its_resource(action.kind))
        .filter(|action| match &action.address {
            ResourceAddress::Assignment(address) => !issuing_keys.contains(address),
            _ => true,
        })
        .filter_map(|action| {
            let workspace = index.unbound_placement(&action.address)?;
            Some((
                action.address.clone(),
                ResourceAddress::Workspace(workspace),
            ))
        })
        .collect()
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
    /// Workspaces exist before the guardrails, keys, and log destinations they
    /// hold, because a workspace is fixed at creation on all three (ADR-0004,
    /// item 2; ADR-0006, item 1).
    Workspace,
    /// Log destinations sit directly inside a workspace and nothing else
    /// depends on one, so they come next.
    LogDestination,
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
            ResourceAddress::Workspace(_) => Stage::Workspace,
            ResourceAddress::LogDestination(_) => Stage::LogDestination,
            ResourceAddress::Guardrail(_) => Stage::Guardrail,
            ResourceAddress::Key(_) => Stage::Key,
            ResourceAddress::Assignment(_) => Stage::Assignment,
            ResourceAddress::RemoteKey(_)
            | ResourceAddress::RemoteGuardrail(_)
            | ResourceAddress::RemoteWorkspace(_)
            | ResourceAddress::RemoteLogDestination(_) => Stage::Remote,
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
    workspaces: BTreeMap<&'a Uuid, &'a ObservedWorkspace>,
    destinations: BTreeMap<&'a Uuid, &'a ObservedDestination>,
    assignments: BTreeMap<&'a KeyHash, BTreeMap<&'a Uuid, &'a ObservedAssignment>>,
    key_owner: BTreeMap<&'a KeyHash, &'a Address>,
    guardrail_owner: BTreeMap<&'a Uuid, &'a Address>,
    workspace_owner: BTreeMap<&'a Uuid, &'a Address>,
    destination_owner: BTreeMap<&'a Uuid, &'a Address>,
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
            workspaces: observed
                .workspaces
                .iter()
                .map(|workspace| (&workspace.id, workspace))
                .collect(),
            destinations: observed
                .log_destinations
                .iter()
                .map(|destination| (&destination.id, destination))
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
            workspace_owner: state
                .workspaces()
                .iter()
                .map(|(address, binding)| (&binding.id, address))
                .collect(),
            destination_owner: state
                .log_destinations()
                .iter()
                .map(|(address, binding)| (&binding.id, address))
                .collect(),
        }
    }

    /// Every remote log destination carrying `name` and in scope, owned or not.
    fn destinations_named(&self, name: &RemoteName) -> Vec<Identity> {
        self.destinations
            .values()
            .filter(|destination| self.in_scope(destination.workspace_id.as_ref()))
            .filter(|destination| destination.name.trim() == name.as_str())
            .map(|destination| Identity::LogDestination(destination.id.clone()))
            .collect()
    }

    /// Remote log destinations carrying `name`, in scope, that no local address
    /// owns.
    fn unowned_destinations_named(&self, name: &RemoteName) -> Vec<Identity> {
        self.destinations_named(name)
            .into_iter()
            .filter(|identity| match identity {
                Identity::LogDestination(id) => !self.destination_owner.contains_key(id),
                Identity::Key(_)
                | Identity::Guardrail(_)
                | Identity::Workspace(_)
                | Identity::Assignment { .. } => true,
            })
            .collect()
    }

    /// Remote workspaces carrying `name`, in scope, that no local address owns.
    fn unowned_workspaces_named(&self, name: &RemoteName) -> Vec<Identity> {
        self.workspaces_named(name)
            .into_iter()
            .filter(|identity| match identity {
                Identity::Workspace(id) => !self.workspace_owner.contains_key(id),
                Identity::Key(_)
                | Identity::Guardrail(_)
                | Identity::LogDestination(_)
                | Identity::Assignment { .. } => true,
            })
            .collect()
    }

    /// Every remote workspace carrying `name` and in scope, owned or not.
    ///
    /// A workspace is in scope when it *is* the scope: a scoped run reports and
    /// matches names in one workspace, and for a workspace block that is the
    /// workspace itself.
    fn workspaces_named(&self, name: &RemoteName) -> Vec<Identity> {
        self.workspaces
            .values()
            .filter(|workspace| self.in_scope(Some(&workspace.id)))
            .filter(|workspace| workspace.name.trim() == name.as_str())
            .map(|workspace| Identity::Workspace(workspace.id.clone()))
            .collect()
    }

    /// The configured workspace that names this guardrail block as its default,
    /// if one does. Validation allows at most one.
    fn workspace_defaulting_to_block(&self, guardrail: &Address) -> Option<&'a Address> {
        workspace_defaulting_to(self.config, guardrail)
    }

    /// The workspace whose default guardrail `id` is, when that workspace is
    /// bound and OpenRouter has it.
    ///
    /// The whole of ADR-0004 item 3's exception: a guardrail bound to this
    /// identity is never `missing`, because until its configuration is first
    /// written no listing carries it — and the only way to write it is to
    /// `PATCH` this identity.
    fn workspace_defaulting_to(&self, id: &Uuid) -> Option<&'a Address> {
        self.state
            .workspaces()
            .iter()
            .find(|(_, binding)| {
                binding.default_guardrail_id.as_ref() == Some(id)
                    && self.workspaces.contains_key(&binding.id)
            })
            .map(|(address, _)| address)
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
                Identity::Key(_)
                | Identity::Workspace(_)
                | Identity::LogDestination(_)
                | Identity::Assignment { .. } => true,
            })
            .collect()
    }

    /// Every remote guardrail carrying `name` and in scope, owned or not.
    ///
    /// What a recreation has to be checked against: a guardrail another
    /// address owns and someone renamed still collides, and creating a second
    /// one under the same name is exactly the confusion a display name cannot
    /// be trusted to resolve.
    ///
    /// A workspace's default guardrail is never a candidate. Its name is
    /// OpenRouter's — `Workspace <uuid> Default` — so it is not a name any
    /// configuration can ask for, and it is not a guardrail any create could
    /// be confused with (ADR-0004, item 3).
    fn guardrails_named(&self, name: &RemoteName) -> Vec<Identity> {
        self.guardrails
            .values()
            .filter(|guardrail| self.in_scope(guardrail.workspace_id.as_ref()))
            .filter(|guardrail| !self.is_workspace_default(&guardrail.id))
            .filter(|guardrail| guardrail.name.trim() == name.as_str())
            .map(|guardrail| Identity::Guardrail(guardrail.id.clone()))
            .collect()
    }

    /// Whether some observed workspace names this guardrail as its default.
    fn is_workspace_default(&self, id: &Uuid) -> bool {
        self.workspaces
            .values()
            .any(|workspace| workspace.default_guardrail_id.as_ref() == Some(id))
    }

    /// The workspace this run places a guardrail in, when anything says which.
    fn configured_workspace(&self, address: &Address, desired: &Guardrail) -> Option<Uuid> {
        configured_workspace_of(
            self.state,
            desired,
            self.workspace_defaulting_to_block(address),
            self.workspace,
        )
    }

    /// The workspace block a resource that already exists is placed in, when
    /// nothing binds that workspace yet.
    ///
    /// Only for a resource state binds: one that does not exist has no
    /// placement to be wrong about, and its create is what gives it one.
    fn unbound_placement(&self, address: &ResourceAddress) -> Option<Address> {
        let placement = match address {
            // An assignment is placed where its key is: assigning or removing a
            // guardrail while the key's own workspace is unresolved would
            // change what a credential may do without knowing where it lives.
            ResourceAddress::Key(address) | ResourceAddress::Assignment(address) => {
                self.state.key(address)?;
                key_placement(self.state, self.config.keys.get(address)?)
            }
            ResourceAddress::Guardrail(address) => {
                self.state.guardrail(address)?;
                guardrail_placement(self.state, self.config.guardrails.get(address)?)
            }
            ResourceAddress::LogDestination(address) => {
                self.state.log_destination(address)?;
                destination_placement(self.state, self.config.log_destinations.get(address)?)
            }
            ResourceAddress::Workspace(_)
            | ResourceAddress::RemoteKey(_)
            | ResourceAddress::RemoteGuardrail(_)
            | ResourceAddress::RemoteWorkspace(_)
            | ResourceAddress::RemoteLogDestination(_) => return None,
        };
        match placement {
            Placement::Unbound(workspace) => Some(workspace),
            Placement::In(_) | Placement::Unspecified => None,
        }
    }

    /// The workspace an action's resource is placed in, when the configuration
    /// says which.
    fn placed_in(&self, address: &ResourceAddress) -> Option<Uuid> {
        placed_in(self.config, self.state, self.workspace, address)
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
            .is_some_and(|receiver| receiver.fingerprint(address) != *delivered)
    }
}

// --- workspaces ------------------------------------------------------------

fn plan_workspaces(index: &Index<'_>, actions: &mut Vec<Action>) {
    for (address, desired) in &index.config.workspaces {
        actions.push(plan_workspace(address, desired, index));
    }
}

fn plan_workspace(address: &Address, desired: &Workspace, index: &Index<'_>) -> Action {
    let at = ResourceAddress::Workspace(address.clone());
    let Some(binding) = index.state.workspace(address) else {
        let candidates = index.unowned_workspaces_named(&desired.name);
        if !candidates.is_empty() {
            return Proposal {
                rationale: vec![Reason::NameMatches { candidates }],
                ..Proposal::default()
            }
            .into_action(ActionKind::AdoptionRequired, at);
        }
        return Proposal {
            changes: diff::workspace_changes(desired, None),
            rationale: vec![Reason::NotCreatedYet],
            ..Proposal::default()
        }
        .into_action(ActionKind::Create, at);
    };

    let identity = Some(Identity::Workspace(binding.id.clone()));
    let Some(observed) = index.workspaces.get(&binding.id) else {
        // Bound to a workspace that is not there, and never recreated. A
        // guardrail may be, because a guardrail is policy and a new one governs
        // the same keys; a workspace is a *container*, and a new one has a new
        // UUID — so every key, guardrail, and budget the old one held would be
        // somewhere Keymaster could no longer reach, and the deterministic
        // default-guardrail identity the binding records would name nothing.
        // ADR-0001's rule stands: bound but absent is reported, not recreated.
        let mut rationale = vec![Reason::AbsentRemotely];
        let holders = index.workspaces_named(&desired.name);
        if !holders.is_empty() {
            rationale.push(Reason::NameCollision { holders });
        }
        return Proposal {
            identity,
            rationale,
            ..Proposal::default()
        }
        .into_action(ActionKind::Missing, at);
    };

    let changes = diff::workspace_changes(desired, Some(observed));
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

// --- log destinations -------------------------------------------------------

fn plan_log_destinations(index: &Index<'_>, actions: &mut Vec<Action>) {
    for (address, desired) in &index.config.log_destinations {
        actions.push(plan_log_destination(address, desired, index));
    }
}

/// The plan for one `[log_destinations.<address>]` block (ADR-0006).
///
/// The shape is a workspace's: bound or not, present or not, drifted or not.
/// Two things are its own. `config` is write-only, so the comparison reads the
/// digest state records rather than anything OpenRouter returned. And `type`
/// and the workspace are fixed at creation on a resource nothing here replaces,
/// so a difference in either is held back rather than patched.
fn plan_log_destination(address: &Address, desired: &LogDestination, index: &Index<'_>) -> Action {
    let at = ResourceAddress::LogDestination(address.clone());
    let depends_on = workspace_dependency(desired.workspace.as_ref());
    // Where the configuration puts it, in the same order every other block
    // resolves: what the block names, then this run's scope.
    let placed = destination_placement(index.state, desired)
        .identity()
        .cloned()
        .or_else(|| index.workspace.cloned());

    let Some(binding) = index.state.log_destination(address) else {
        let candidates = index.unowned_destinations_named(&desired.name);
        if !candidates.is_empty() {
            // A name is mutable and not unique, so a match is a candidate for
            // `import`, never an adoption (ADR-0001).
            return Proposal {
                rationale: vec![Reason::NameMatches { candidates }],
                ..Proposal::default()
            }
            .into_action(ActionKind::AdoptionRequired, at);
        }
        return Proposal {
            changes: diff::log_destination_changes(desired, None, placed.as_ref(), None),
            depends_on,
            rationale: vec![Reason::NotCreatedYet],
            ..Proposal::default()
        }
        .into_action(ActionKind::Create, at);
    };

    let identity = Some(Identity::LogDestination(binding.id.clone()));
    let Some(observed) = index.destinations.get(&binding.id) else {
        // Bound but absent, and never recreated: a new destination would have a
        // new UUID, and recreating one silently would restart log forwarding
        // under an identity nothing recorded.
        let mut rationale = vec![Reason::AbsentRemotely];
        let holders = index.destinations_named(&desired.name);
        if !holders.is_empty() {
            rationale.push(Reason::NameCollision { holders });
        }
        return Proposal {
            identity,
            rationale,
            ..Proposal::default()
        }
        .into_action(ActionKind::Missing, at);
    };

    let changes = diff::log_destination_changes(
        desired,
        Some(observed),
        placed.as_ref(),
        binding.config_digest.as_deref(),
    );

    if let Some(field) = changes
        .iter()
        .map(|change| change.field)
        .find(|field| diff::IMMUTABLE_DESTINATION_FIELDS.contains(field))
    {
        return Proposal {
            identity,
            changes,
            depends_on,
            rationale: vec![Reason::DestinationFixedAtCreation {
                field,
                id: binding.id.clone(),
            }],
        }
        .into_action(ActionKind::NoOp, at);
    }

    let (kind, reason) = if changes.is_empty() {
        (ActionKind::NoOp, Reason::InSync)
    } else {
        (ActionKind::Update, Reason::Drift)
    };
    Proposal {
        identity,
        changes,
        depends_on,
        rationale: vec![reason],
    }
    .into_action(kind, at)
}

// --- guardrails ------------------------------------------------------------

fn plan_guardrails(index: &Index<'_>, actions: &mut Vec<Action>) {
    for (address, desired) in &index.config.guardrails {
        actions.push(plan_guardrail(address, desired, index));
    }
}

fn plan_guardrail(address: &Address, desired: &Guardrail, index: &Index<'_>) -> Action {
    let at = ResourceAddress::Guardrail(address.clone());
    // A guardrail's workspace is the one its block names — or, for a default
    // guardrail, the workspace that names *it*, whose block validation requires
    // to agree.
    let default_of = index.workspace_defaulting_to_block(address);
    let depends_on = workspace_dependency(desired.workspace.as_ref().or(default_of));
    let id = match guardrail_identity(index, address, default_of) {
        GuardrailIdentity::Conflict { bound, expected } => {
            // The address already owns some other guardrail. Neither identity
            // is safe to write: the bound one is not the workspace's default,
            // and writing the workspace's would leave two guardrails at one
            // address. An operator picks another address or releases this one.
            return Proposal {
                identity: Some(Identity::Guardrail(bound.clone())),
                depends_on,
                rationale: vec![Reason::DefaultGuardrailConflict { bound, expected }],
                ..Proposal::default()
            }
            .into_action(ActionKind::NoOp, at);
        }
        GuardrailIdentity::OwnedElsewhere { id, owner } => {
            return Proposal {
                identity: Some(Identity::Guardrail(id.clone())),
                depends_on,
                rationale: vec![Reason::DefaultGuardrailOwnedElsewhere { id, owner }],
                ..Proposal::default()
            }
            .into_action(ActionKind::NoOp, at);
        }
        GuardrailIdentity::At(id) => Some(id),
        GuardrailIdentity::Unbound => None,
    };
    let Some(id) = id else {
        if let Some(workspace) = default_of {
            // A default guardrail is never `POST`ed. Its identity is the one
            // its workspace names, and nothing here knows it yet — so this is
            // the same create-by-`PATCH` as any other unmaterialized default
            // guardrail, addressed to the identity the workspace binding will
            // carry by the time the guardrail phase runs (ADR-0004, item 3).
            // Whether that binding will exist is the workspace's action to
            // say, and `mark_blocked` reads it from the dependency below.
            return Proposal {
                changes: diff::guardrail_changes(desired, None),
                depends_on,
                rationale: vec![Reason::DefaultGuardrailUnmaterialized {
                    workspace: ResourceAddress::Workspace(workspace.clone()),
                }],
                ..Proposal::default()
            }
            .into_action(ActionKind::Create, at);
        }
        return plan_unbound_guardrail(desired, index, depends_on, at);
    };

    // Where the configuration puts this guardrail, in the one order every
    // caller resolves it in. Read before the snapshot is consulted, because a
    // guardrail that is not there yet has a placement too.
    let placed = index.configured_workspace(address, desired);

    let Some(observed) = index.guardrails.get(&id) else {
        return plan_absent_guardrail(desired, index, &id, placed.as_ref(), depends_on, at);
    };

    // A guardrail's workspace is fixed when it is created, and a guardrail is
    // never replaced — a key can be, because a key is a credential and a
    // successor can be delivered, while a guardrail is policy other resources
    // are attached to. So a guardrail in the wrong workspace is a difference
    // nothing here can converge, and the plan says so rather than offering an
    // update that would leave it exactly where it is.
    if let Some(placed) = placed
        && observed.workspace_id.as_ref() != Some(&placed)
    {
        return Proposal {
            identity: Some(Identity::Guardrail(id.clone())),
            depends_on,
            rationale: vec![Reason::WorkspaceFixedAtCreation {
                observed: observed.workspace_id.clone(),
                desired: placed,
            }],
            ..Proposal::default()
        }
        .into_action(ActionKind::NoOp, at);
    }

    let changes = diff::guardrail_changes(desired, Some(observed));
    let identity = Some(Identity::Guardrail(id.clone()));
    let (kind, reason) = if changes.is_empty() {
        (ActionKind::NoOp, Reason::InSync)
    } else {
        (ActionKind::Update, Reason::Drift)
    };
    Proposal {
        identity,
        changes,
        depends_on,
        rationale: vec![reason],
    }
    .into_action(kind, at)
}

/// Which identity a guardrail block writes to, once its address and any
/// workspace naming it as a default have both had their say.
enum GuardrailIdentity {
    /// The identity every write and comparison is addressed to.
    At(Uuid),
    /// Nothing binds the address and nothing supplies an identity for it.
    Unbound,
    /// The address owns one guardrail and its workspace names another.
    Conflict {
        /// The guardrail the address owns now.
        bound: Uuid,
        /// The identity its workspace names as its default.
        expected: Uuid,
    },
    /// The workspace's default guardrail is already owned by another address.
    OwnedElsewhere {
        /// The identity the workspace names as its default.
        id: Uuid,
        /// The address that owns it.
        owner: Address,
    },
}

/// Resolves the identity a guardrail block is about.
///
/// A default guardrail's identity is its workspace's to supply, and the
/// workspace binding records it — so an address named as one is bound in effect
/// from the moment its workspace is, whether or not a run has got round to
/// writing that binding down (ADR-0004, item 3).
fn guardrail_identity(
    index: &Index<'_>,
    address: &Address,
    default_of: Option<&Address>,
) -> GuardrailIdentity {
    let bound = index
        .state
        .guardrail(address)
        .map(|binding| binding.id.clone());
    let named = default_of
        .and_then(|workspace| index.state.workspace(workspace))
        .and_then(|binding| binding.default_guardrail_id.clone());

    match (bound, named) {
        (Some(bound), Some(expected)) if bound != expected => {
            GuardrailIdentity::Conflict { bound, expected }
        }
        (Some(id), _) => GuardrailIdentity::At(id),
        // Nothing binds this address, and the identity its workspace names
        // belongs to another one. One remote object belongs to exactly one
        // local address (ADR-0001), so writing here would be writing to a
        // guardrail somebody else owns.
        (None, Some(id)) => match index.guardrail_owner.get(&id) {
            Some(owner) => GuardrailIdentity::OwnedElsewhere {
                id,
                owner: (*owner).clone(),
            },
            None => GuardrailIdentity::At(id),
        },
        (None, None) => GuardrailIdentity::Unbound,
    }
}

/// A guardrail this address is bound to that OpenRouter does not have.
///
/// Two answers, and the difference is whether the identity means anything on
/// its own. A workspace's default guardrail exists as an identity from the
/// moment the workspace does and is absent from the observation until its
/// configuration is first written, so it is written rather than reported — the
/// one exception to "bound but absent means missing" (ADR-0004, item 3).
/// Anything else is recreated only when nothing already answers to the name.
fn plan_absent_guardrail(
    desired: &Guardrail,
    index: &Index<'_>,
    id: &Uuid,
    placed: Option<&Uuid>,
    depends_on: Vec<ResourceAddress>,
    at: ResourceAddress,
) -> Action {
    // The one exception to "bound but absent means missing": a workspace's
    // own default guardrail exists as an identity from the moment the
    // workspace does, and is in no listing — not even its own workspace's —
    // until its configuration is first written (ADR-0004, item 3).
    if let Some(workspace) = index.workspace_defaulting_to(id) {
        let owner = index
            .state
            .workspace(workspace)
            .map(|binding| binding.id.clone());
        // The exception is about writing *that* workspace's default guardrail.
        // A block that has since been moved — its `default_guardrail`
        // relationship dropped and its own `workspace`, or this run's scope,
        // naming another one — would materialize the first workspace's default
        // while the configuration asks for a guardrail in the second, and no
        // write could ever close the gap.
        if let (Some(placed), Some(owner)) = (placed, &owner)
            && placed != owner
        {
            return Proposal {
                identity: Some(Identity::Guardrail(id.clone())),
                depends_on,
                rationale: vec![Reason::WorkspaceFixedAtCreation {
                    observed: Some(owner.clone()),
                    desired: placed.clone(),
                }],
                ..Proposal::default()
            }
            .into_action(ActionKind::NoOp, at);
        }
        return Proposal {
            identity: Some(Identity::Guardrail(id.clone())),
            changes: diff::guardrail_changes(desired, None),
            depends_on,
            rationale: vec![Reason::DefaultGuardrailUnmaterialized {
                workspace: ResourceAddress::Workspace(workspace.clone()),
            }],
        }
        .into_action(ActionKind::Create, at);
    }

    // Bound to a guardrail that is not there. Recreating is safe only if
    // nothing else already answers to the name, whoever owns it.
    let identity = Some(Identity::Guardrail(id.clone()));
    let Some(name) = &desired.name else {
        // A block with no name of its own is some workspace's default, and the
        // exception above did not apply: the workspace it belongs to is not
        // one this run can see. Such a guardrail is never `POST`ed and has no
        // name to recreate it under, so an operator resolves it.
        return Proposal {
            identity,
            rationale: vec![Reason::AbsentRemotely],
            ..Proposal::default()
        }
        .into_action(ActionKind::Missing, at);
    };
    let holders = index.guardrails_named(name);
    if !holders.is_empty() {
        return Proposal {
            identity,
            rationale: vec![Reason::AbsentRemotely, Reason::NameCollision { holders }],
            ..Proposal::default()
        }
        .into_action(ActionKind::Missing, at);
    }
    Proposal {
        changes: diff::guardrail_changes(desired, None),
        depends_on,
        rationale: vec![Reason::AbsentRemotely, Reason::NoNameCollision],
        ..Proposal::default()
    }
    .into_action(ActionKind::Create, at)
}

/// The workspace an action's resource is placed in, when the configuration says
/// which.
///
/// Read from the configuration rather than from the snapshot: the rule it
/// serves is about what this run would write into a workspace, and a key this
/// run is about to create is not in any snapshot yet. `scope` is the run's
/// workspace, which is where a block that names none is created.
///
/// Public because apply asks the same question at execution time, about a
/// workspace whose budget writes this run has just made (ADR-0004, item 4).
#[must_use]
pub fn placed_in(
    config: &Config,
    state: &State,
    scope: Option<&Uuid>,
    address: &ResourceAddress,
) -> Option<Uuid> {
    let placement = match address {
        ResourceAddress::Key(address) | ResourceAddress::Assignment(address) => {
            key_placement(state, config.keys.get(address)?)
        }
        ResourceAddress::Guardrail(address) => {
            let placement = guardrail_placement(state, config.guardrails.get(address)?);
            // A default guardrail names no workspace because it *is* one
            // workspace's, and validation makes sure the two agree.
            if matches!(placement, Placement::Unspecified)
                && let Some(workspace) = workspace_defaulting_to(config, address)
                && let Some(binding) = state.workspace(workspace)
            {
                return Some(binding.id.clone());
            }
            placement
        }
        ResourceAddress::LogDestination(address) => {
            destination_placement(state, config.log_destinations.get(address)?)
        }
        ResourceAddress::Workspace(_)
        | ResourceAddress::RemoteKey(_)
        | ResourceAddress::RemoteGuardrail(_)
        | ResourceAddress::RemoteWorkspace(_)
        | ResourceAddress::RemoteLogDestination(_) => return None,
    };
    match placement {
        Placement::In(id) => Some(id),
        // A block that names no workspace is created wherever this run is
        // scoped, so a scoped run's budget rule reaches it too.
        Placement::Unspecified => scope.cloned(),
        // Unbound: the workspace has no identity to compare a budget against
        // yet, and a workspace this run creates has no budget to have failed.
        Placement::Unbound(_) => None,
    }
}

/// A configured guardrail that state does not bind.
fn plan_unbound_guardrail(
    desired: &Guardrail,
    index: &Index<'_>,
    depends_on: Vec<ResourceAddress>,
    at: ResourceAddress,
) -> Action {
    let Some(name) = &desired.name else {
        // A block with no name of its own is some workspace's default, and
        // `plan_guardrail` answers those before it reaches here: such a
        // guardrail is never `POST`ed, and there is no name to match one by.
        return Proposal {
            rationale: vec![Reason::AbsentRemotely],
            ..Proposal::default()
        }
        .into_action(ActionKind::Missing, at);
    };
    let candidates = index.unowned_guardrails_named(name);
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
        depends_on,
        rationale: vec![Reason::NotCreatedYet],
        ..Proposal::default()
    }
    .into_action(ActionKind::Create, at)
}

/// The workspace block a resource names, as a dependency.
///
/// A workspace is fixed at creation on both a key and a guardrail, so a create
/// cannot run before the workspace has an identity. When this plan creates the
/// workspace, that is an ordering constraint apply already honours; when it
/// cannot, the dependency is what holds the contents back (ADR-0004, item 2).
fn workspace_dependency(workspace: Option<&Address>) -> Vec<ResourceAddress> {
    workspace
        .map(|address| vec![ResourceAddress::Workspace(address.clone())])
        .unwrap_or_default()
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
    let workspace = key_placement(index.state, desired);
    let Some(current) = binding.and_then(KeyBinding::current) else {
        return plan_unbound_key(desired, index, &workspace, at);
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

    let changes = diff::key_changes(desired, Some(observed), workspace.identity());
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
        depends_on: key_dependencies(desired),
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
fn plan_unbound_key(
    desired: &Key,
    index: &Index<'_>,
    workspace: &Placement,
    at: ResourceAddress,
) -> Action {
    let candidates = index.unowned_keys_named(&desired.name);
    if !candidates.is_empty() {
        return Proposal {
            rationale: vec![Reason::NameMatches { candidates }],
            ..Proposal::default()
        }
        .into_action(ActionKind::AdoptionRequired, at);
    }

    let changes = diff::key_changes(desired, None, workspace.identity());
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
        depends_on: key_dependencies(desired),
        rationale: vec![Reason::NotCreatedYet],
        ..Proposal::default()
    }
    .into_action(ActionKind::Create, at)
}

/// What has to exist before a key can be created.
///
/// Its guardrail, because a key is secured — restricted and guardrailed —
/// before its plaintext is delivered (ADR-0002); and the workspace block it
/// names, because OpenRouter fixes a key's workspace at creation.
fn key_dependencies(desired: &Key) -> Vec<ResourceAddress> {
    let mut dependencies = workspace_dependency(desired.workspace.as_ref());
    if let Some(address) = desired.guardrail.value() {
        dependencies.push(ResourceAddress::Guardrail(address.clone()));
    }
    dependencies
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
        depends_on: key_dependencies(desired),
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

    for (address, binding) in index.state.workspaces() {
        if index.config.workspaces.contains_key(address) {
            continue;
        }
        actions.push(
            Proposal {
                identity: Some(Identity::Workspace(binding.id.clone())),
                rationale: vec![Reason::RemovedFromConfiguration],
                ..Proposal::default()
            }
            .into_action(
                ActionKind::OrphanedBinding,
                ResourceAddress::Workspace(address.clone()),
            ),
        );
    }

    for (address, binding) in index.state.log_destinations() {
        if index.config.log_destinations.contains_key(address) {
            continue;
        }
        actions.push(
            Proposal {
                identity: Some(Identity::LogDestination(binding.id.clone())),
                rationale: vec![Reason::RemovedFromConfiguration],
                ..Proposal::default()
            }
            .into_action(
                ActionKind::OrphanedBinding,
                ResourceAddress::LogDestination(address.clone()),
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

    for workspace in index.workspaces.values() {
        if index.workspace_owner.contains_key(&workspace.id) || !index.in_scope(Some(&workspace.id))
        {
            continue;
        }
        actions.push(
            Proposal {
                identity: Some(Identity::Workspace(workspace.id.clone())),
                rationale: vec![Reason::NotConfigured],
                ..Proposal::default()
            }
            .into_action(
                ActionKind::Unmanaged,
                ResourceAddress::RemoteWorkspace(workspace.id.clone()),
            ),
        );
    }

    for destination in index.destinations.values() {
        if index.destination_owner.contains_key(&destination.id)
            || !index.in_scope(destination.workspace_id.as_ref())
        {
            continue;
        }
        actions.push(
            Proposal {
                identity: Some(Identity::LogDestination(destination.id.clone())),
                rationale: vec![Reason::NotConfigured],
                ..Proposal::default()
            }
            .into_action(
                ActionKind::Unmanaged,
                ResourceAddress::RemoteLogDestination(destination.id.clone()),
            ),
        );
    }
}
