//! `openrouter-keymaster apply`: converging guardrails, existing keys, and assignments.
//!
//! # The plan that runs is not the plan an operator read
//!
//! Apply takes the exclusive state lock, reloads the configuration and state
//! under it, reads a fresh snapshot of OpenRouter, and computes the plan again.
//! Whatever `openrouter-keymaster plan` printed a minute ago is history: it was computed
//! against a snapshot that has since been replaced, and executing it would be
//! executing a stale observation. Nothing carries a plan across that boundary,
//! so there is nothing to go stale.
//!
//! # Three phases, in order, one request at a time
//!
//! Guardrails first, because a key is secured by one; then existing keys; then
//! assignments, which need both ends to exist. The planner already orders its
//! actions that way, and this module walks that order phase by phase so the
//! sequence is visible rather than implied.
//!
//! A created guardrail's UUID is persisted before anything else happens. A
//! guardrail that exists and is not recorded is one only its mutable name could
//! find again, which is exactly the situation ADR-0001 exists to avoid.
//!
//! # Issuing a key is its own transaction
//!
//! A planned key `create` or `replace` runs the journaled transaction in
//! [`super::issuance`], which is the only thing here that issues secret
//! material. It sits inside the key phase like any other write, but it obeys
//! ADR-0002's rules rather than this module's: exactly one `POST /keys`, a
//! durable journal entry on either side of every non-idempotent step, and no
//! second attempt at anything. Any outcome other than a delivered, promoted key
//! ends the whole run, because an unresolved operation may have made a live
//! credential no local record names.
//!
//! A `replace` differs from a `create` in one respect and one only: the address
//! already owns a key. That key is *not* touched. It is not disabled, not
//! deleted, and not unassigned; the successor is created, secured, verified,
//! and delivered first, and only the promotion that follows a confirmed
//! delivery moves the predecessor to `retained.awaiting_retirement`, where it
//! stays as it was until an operator runs `openrouter-keymaster retire`. So a rotation that
//! fails at any phase leaves the working credential working.
//!
//! # What apply will not do
//!
//! - **Retire, disable, or delete a predecessor.** Rotation stages; retirement
//!   is always explicit. See `openrouter-keymaster retire` and `openrouter-keymaster delete key`.
//! - **Resolve what holds a write back.** An action whose dependency needs an
//!   operator — an adoption, a missing resource, an unfinished operation — is
//!   reported as held back, naming what it waits on. An apply that wrote
//!   nothing for that reason has converged nothing, and never says otherwise.
//! - **Touch anything unmanaged.** Only actions the planner produced are
//!   executed, and the planner never proposes a write to a remote object no
//!   local address owns.
//! - **Delete, disable, or forget anything because a configuration block
//!   disappeared.** That is an orphaned binding, which is reported.
//! - **Repeat an ambiguous write.** A write is sent exactly once. Whether it
//!   landed is answered by the read that follows, never by sending it again.
//!
//! # A shown plan can be made binding
//!
//! Nothing carries a plan across the lock, and nothing here ever will. What a
//! caller may carry is a [`PlanFingerprint`] — a digest of the inputs that
//! decide what an apply would write. Given one, this run recomputes the plan
//! under the lock as it always does, compares the digests, and executes only if
//! they match; a mismatch returns the fresh plan with every write held back,
//! having written nothing. The credential check and the comparison both come
//! before the first write, including the promotion below, so a refused run
//! costs the reads it made and nothing else (ADR-0003).
//!
//! # Verification
//!
//! When anything was attempted, apply reads a second complete snapshot and
//! recomputes the plan against it. An attempted action counts as verified when
//! every action the recomputed plan has at its address is a no-op — the same
//! question the next run will ask, so a verified apply is one whose successor
//! is a no-op. Anything else is reported as unverified rather than assumed,
//! and that read is also what decides whether a privilege expansion is
//! reported as having happened: a response is not evidence either way.

use std::cell::RefCell;
use std::collections::BTreeSet;

use time::OffsetDateTime;

use crate::api::{BudgetBody, GuardrailBody, Reader, UpdateKey, WorkspaceBody, Writer};
use crate::client::Client;
use crate::config::{BUDGET_INTERVALS, BudgetInterval, Config, Receiver, Usd};
use crate::error::Error;
use crate::ids::{Address, KeyHash, Uuid};
use crate::plan::{self, Action, ActionKind, Identity, Plan, Reason, ResourceAddress, Snapshot};
use crate::receiver::Deliver;
use crate::report::{ActionOutcome, ApplyReport, PlanReport};
use crate::state::{KeyBinding, Origin, Phase as JournalPhase, State, StateFile, StateLock};

use super::issuance::Issuer;
use super::{Context, Outcome, PlanFingerprint, fingerprint};

/// Why an assignment beside a completed creation needs no separate write.
const ASSIGNMENT_ISSUED: &str = "the key was attached to its guardrail as part of the journaled \
                                 creation, and verified, before its plaintext was delivered";

/// Why an assignment whose key does not exist is not made.
const ASSIGNMENT_WITHOUT_KEY: &str =
    "skipped: this address owns no key, so there is nothing to assign";

/// Runs `apply`.
///
/// `expected` makes the run binding: with a fingerprint given, apply takes its
/// lock, recomputes the plan, compares, and writes only on a match. Every check
/// is ahead of every write, so a mismatch — including an operation that became
/// pending after the plan was shown — refuses with nothing written and returns
/// the fresh plan. With `None` it applies whatever the recomputed plan says, as
/// the CLI does.
///
/// # Errors
///
/// Returns the configuration, state, and API errors of the steps before the
/// first write, none of which change anything, and `missing_credential` when
/// the context carries none. A run that got as far as a report returns it
/// instead, with the failure beside it: [`ApplyError`] when an unfinished
/// operation stopped the run, when a write failed or could not be confirmed,
/// or when the plan no longer matches the fingerprint.
pub fn apply(
    mut context: Context,
    expected: Option<PlanFingerprint>,
) -> Result<Outcome<ApplyReport>, Error> {
    // The lock comes first, and everything the plan is computed from is read
    // after it. Loading the configuration before taking the lock would leave a
    // window in which an edit lands between the read and the lock, and apply
    // would then converge OpenRouter to a file that has already been
    // superseded — the same staleness the recomputed plan exists to prevent,
    // one input over.
    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let config = context.config()?;
    let mut state = lock.read()?;
    context.check_scope(&config, &state)?;

    // The credential, before the first write of any kind. Apply always needs
    // the API to plan, so an apply without one converges nothing — and the
    // promotion below is a state write like any other (ADR-0003).
    let client = context.client()?;
    let reader = Reader::new(&client);
    let writer = Writer::new(&client);

    // Before anything is planned: a delivered operation is finished remotely,
    // and what is left of it — promotion — touches nothing outside this file.
    // Completing it here means the plan this run executes describes the world
    // as it now is, rather than one holding an operation that is already over.
    //
    // A bound run does not do it. Its comparison comes before every write, and
    // a pending operation of any phase makes a plan unbindable, so a bound run
    // that meets one refuses below rather than promoting first.
    let promoted = if expected.is_some() {
        None
    } else {
        fast_forward(&lock, &mut state)?
    };

    // Read and planned here, under the lock, from this run's own snapshot.
    let snapshot = super::snapshot(&reader)?;

    // Also before anything is planned, and local for the same reason: a
    // workspace binding that never learned its default guardrail's identity
    // learns it from the snapshot. A bound run skips it, as it skips the
    // promotion above, so its comparison stays a comparison.
    let backfilled = if expected.is_some() {
        None
    } else {
        record_default_identities(&lock, &mut state, &snapshot)?
    };

    let plan = plan::plan(&config, &state, &snapshot, context.scope());

    if let Some(expected) = &expected
        && let Some(refusal) = refuse_changed_plan(&context, &config, &state, &plan, expected)
    {
        return Ok(refusal);
    }
    debug_assert!(
        expected.is_none() || backfilled.is_none(),
        "a bound run skips the backfill, so a refusal cannot be hiding one"
    );

    // Before the first remote write, not inside the transaction that would
    // discover it: a plan is a sequence, and a guardrail create ahead of the
    // issuance would already have landed by then (ADR-0005, item 3). The
    // promotion above is older than the plan and is carried into the refusal's
    // report rather than hidden by it.
    if let Some(refusal) = refuse_undeliverable_issuance(
        &config,
        &plan,
        context.deliver.is_some(),
        promoted.as_deref(),
        backfilled.as_deref(),
    ) {
        return Ok(refusal);
    }

    // The host's delivery callback, taken out of the context so one closure
    // serves every key this apply issues (ADR-0005, item 2). A run that carries
    // none applies everything that is not an issuance through a `caller`
    // receiver exactly as before.
    let deliver = context.deliver.take().map(RefCell::new);
    let mut apply = Apply {
        config: &config,
        client: &client,
        reader: &reader,
        writer: &writer,
        lock: &lock,
        snapshot: &snapshot,
        workspace: context.scope(),
        deliver: deliver.as_ref(),
        stopped: false,
        issued: BTreeSet::new(),
    };
    let mut outcomes = apply.execute(&plan, &mut state);
    let failure = verify(
        &plan,
        &config,
        &state,
        &reader,
        context.scope(),
        &mut outcomes,
    );

    let mut report = ApplyReport::new(&plan, &outcomes, failure);
    report.note(backfilled);
    report.note(promoted);

    if report.succeeded() {
        return Ok(Outcome::ok(report));
    }
    if report.blocked() {
        return Ok(Outcome::failed(report, ApplyError::Blocked));
    }
    let (failed, unverified) = report.unresolved();
    Ok(Outcome::failed(
        report,
        ApplyError::Unresolved { failed, unverified },
    ))
}

/// What a refused action's outcome says.
const PLAN_CHANGED: &str = "held back: an input changed after the fingerprint this run was bound \
                            to was taken, so nothing was written";

/// Refuses a bound apply whose inputs are no longer the ones the caller saw.
///
/// The comparison happens here, after the lock and the reads and before the
/// first write, so a refusal costs the reads it has already made and changes
/// nothing — locally or remotely. The report it returns is the fresh plan, with
/// every write held back, which is what a caller needs to show and bind again.
fn refuse_changed_plan(
    context: &Context,
    config: &Config,
    state: &State,
    plan: &Plan,
    expected: &PlanFingerprint,
) -> Option<Outcome<ApplyReport>> {
    let fresh = PlanReport::new(plan);
    if fingerprint::of(context, config, state, &fresh).as_ref() == Some(expected) {
        return None;
    }

    let outcomes: Vec<ActionOutcome> = plan
        .actions()
        .iter()
        .map(|action| {
            if action.kind.writes() {
                ActionOutcome::held_back(PLAN_CHANGED)
            } else {
                ActionOutcome::reported()
            }
        })
        .collect();
    Some(Outcome::failed(
        ApplyReport::new(plan, &outcomes, None),
        ApplyError::PlanChanged,
    ))
}

/// What a refused action's outcome says when the run has no host callback.
const NO_HOST_CALLBACK: &str = "held back: this plan issues a key through a `caller` receiver and \
                                this run carries no host callback, so nothing was written";

/// Refuses, before any remote write and before any issuance, a plan that would
/// issue a key through a `caller` receiver in a run that carries no callback to
/// deliver it to.
///
/// The issuance preflight refuses this too, and for `rotate` and `recover
/// replace` that is enough: each issues one key and writes nothing before its
/// preflight. An apply is a sequence — guardrails, then keys, then assignments
/// — so by the time the transaction for one key ran its preflight, a guardrail
/// create and an unrelated key's update would already have landed. ADR-0005
/// item 3 says the refusal comes before any remote write, so the whole plan is
/// scanned here, ahead of every phase. The one write that can precede it is
/// local and older than the plan: the promotion of an already-delivered key,
/// which [`fast_forward`] completes under the lock and which the report this
/// returns carries.
///
/// It reads configuration only: which receiver a planned key names, and what
/// kind that receiver is. No request is sent and nothing is journaled, so a
/// refusal costs the reads this run has already made and changes nothing.
fn refuse_undeliverable_issuance(
    config: &Config,
    plan: &Plan,
    has_callback: bool,
    promoted: Option<&str>,
    backfilled: Option<&str>,
) -> Option<Outcome<ApplyReport>> {
    if has_callback {
        return None;
    }
    let blocked = plan.is_blocked();
    let address = plan
        .actions()
        .iter()
        .find_map(|action| issued_through_a_caller(config, action, blocked))?;

    let outcomes: Vec<ActionOutcome> = plan
        .actions()
        .iter()
        .map(|action| {
            if action.kind.writes() {
                ActionOutcome::held_back(NO_HOST_CALLBACK)
            } else {
                ActionOutcome::reported()
            }
        })
        .collect();
    let mut report = ApplyReport::new(plan, &outcomes, None);
    // The local writes this run completed before it planned anything are
    // reported here exactly as a converging run reports them. A refusal that
    // swallowed one would tell an operator nothing had changed when the
    // address's current key just had.
    report.note(backfilled.map(str::to_owned));
    report.note(promoted.map(str::to_owned));
    Some(Outcome::failed(
        report,
        ApplyError::Undeliverable {
            address: address.clone(),
            promoted: promoted.is_some(),
        },
    ))
}

/// The key this action would issue, when it would issue one through a `caller`
/// receiver.
fn issued_through_a_caller<'a>(
    config: &Config,
    action: &'a Action,
    plan_blocked: bool,
) -> Option<&'a Address> {
    let ResourceAddress::Key(address) = &action.address else {
        return None;
    };
    if !matches!(action.kind, ActionKind::Create | ActionKind::Replace)
        || !action.is_executable(plan_blocked)
    {
        return None;
    }
    let receiver = config.keys.get(address)?.receiver.as_ref()?;
    matches!(config.receivers.get(receiver)?, Receiver::Caller { .. }).then_some(address)
}

/// Completes a delivered operation, before this run plans anything.
///
/// `delivered` is the one unfinished phase that needs no operator. The key
/// exists, its restrictions were verified, and the receiver acknowledged the
/// plaintext; all that is left is promoting the hash to current, which is a
/// local state operation with no external effect (ADR-0002). The planner
/// documents this contract — it reports the phase as
/// [`crate::plan::Reason::PromotionPending`] and holds nothing back — and this
/// is the other half of it.
///
/// It must happen before the plan is computed rather than during the run,
/// because the operation is also what `begin_create` refuses to start a second
/// one beside: planning first would produce a plan whose creates state would
/// then decline.
///
/// Returns the sentence explaining what was completed, when anything was.
///
/// # Errors
///
/// Returns [`ApplyError::Promotion`] when the promotion is refused, and the
/// state errors of making it durable. Nothing remote is touched either way.
fn fast_forward(lock: &StateLock<'_>, state: &mut State) -> Result<Option<String>, Error> {
    let Some((address, pending)) = state.pending_operation() else {
        return Ok(None);
    };
    if pending.phase != JournalPhase::Delivered {
        return Ok(None);
    }
    let (address, operation) = (address.clone(), pending.id.clone());

    state
        .promote_key(&address, now())
        .map_err(|error| ApplyError::Promotion {
            address: address.clone(),
            message: error.to_string(),
        })?;
    lock.write(state)?;

    Ok(Some(format!(
        "operation {operation} delivered `{address}`'s key and stopped before promoting it; this \
         run completed that promotion locally, which touches nothing remote"
    )))
}

/// Records a `default_guardrail_id` a workspace binding never learned.
///
/// `POST /workspaces` is documented to return one, and the create records it —
/// but a response that omitted it would leave the binding with nothing, and a
/// workspace's default guardrail is reachable *only* through that identity. It
/// is never listed until its configuration is written, never `POST`ed, and
/// never imported by name, so a binding without it would hold that guardrail
/// back for good (ADR-0004, item 3).
///
/// The listing carries the identity too, so this fills it in from the snapshot
/// before anything is planned — which is what makes the guardrail plannable on
/// this run rather than the next one. It is local, it touches nothing remote,
/// and it only ever fills a gap: a binding that already records an identity is
/// left exactly as it is.
///
/// Returns the sentence explaining what was recorded, when anything was.
///
/// # Errors
///
/// Returns the state errors of making the change durable. Nothing remote is
/// touched either way.
fn record_default_identities(
    lock: &StateLock<'_>,
    state: &mut State,
    snapshot: &Snapshot,
) -> Result<Option<String>, Error> {
    let learned: Vec<(Address, Uuid, Uuid, Origin)> = state
        .workspaces()
        .iter()
        .filter(|(_, binding)| binding.default_guardrail_id.is_none())
        .filter_map(|(address, binding)| {
            let observed = snapshot
                .workspaces
                .iter()
                .find(|workspace| workspace.id == binding.id)?;
            let default = observed.default_guardrail_id.clone()?;
            Some((address.clone(), binding.id.clone(), default, binding.origin))
        })
        .collect();
    if learned.is_empty() {
        return Ok(None);
    }

    let mut recorded = Vec::new();
    for (address, id, default, origin) in learned {
        // Re-binding an address to the identity it already holds is how a
        // binding takes a `default_guardrail_id` it did not have; it changes
        // nothing else.
        state
            .bind_workspace(&address, id, Some(default.clone()), origin, now())
            .map_err(|error| ApplyError::Backfill {
                address: address.clone(),
                message: error.to_string(),
            })?;
        recorded.push(format!("`{address}` ({default})"));
    }
    lock.write(state)?;

    Ok(Some(format!(
        "recorded the default guardrail identity of {recorded}, which is the only handle on that \
         guardrail there is and which this run read from the workspace itself; that is a local \
         state write and touches nothing remote",
        recorded = recorded.join(", ")
    )))
}

/// The fixed order the phases run in.
///
/// Dependencies before dependents: a guardrail exists before the key it
/// secures, and both exist before the assignment that joins them.
const PHASES: [Phase; 4] = [
    Phase::Workspaces,
    Phase::Guardrails,
    Phase::Keys,
    Phase::Assignments,
];

/// One phase of an apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Workspaces,
    Guardrails,
    Keys,
    Assignments,
}

/// Which phase an action belongs to, or `None` for one apply never executes.
const fn phase_of(address: &ResourceAddress) -> Option<Phase> {
    match address {
        ResourceAddress::Workspace(_) => Some(Phase::Workspaces),
        ResourceAddress::Guardrail(_) => Some(Phase::Guardrails),
        ResourceAddress::Key(_) => Some(Phase::Keys),
        ResourceAddress::Assignment(_) => Some(Phase::Assignments),
        ResourceAddress::RemoteKey(_)
        | ResourceAddress::RemoteGuardrail(_)
        | ResourceAddress::RemoteWorkspace(_) => None,
    }
}

/// One apply's writes.
struct Apply<'a> {
    config: &'a Config,
    client: &'a Client,
    reader: &'a Reader<'a>,
    writer: &'a Writer<'a>,
    lock: &'a StateLock<'a>,
    /// The read this run planned from. Kept so a report can state what was
    /// observed about a key apply does not write — a replacement's
    /// predecessor — instead of asserting it.
    snapshot: &'a Snapshot,
    /// The workspace every create this run makes is placed in, when it is
    /// scoped to one (ADR-0004, item 5).
    workspace: Option<&'a Uuid>,
    /// The host callback a `caller` receiver delivers through, when the context
    /// carried one (ADR-0005). Lent to every issuance this apply runs.
    deliver: Option<&'a RefCell<Deliver>>,
    /// Set by the first failed write. Nothing is attempted after it: a later
    /// action may depend on the one that failed, and a run that pressed on
    /// would report a second failure caused by the first.
    ///
    /// An unresolved key creation sets it too, and there the rule is not
    /// merely tidy: ADR-0002 stops the whole apply at the first operation whose
    /// outcome nobody knows.
    stopped: bool,
    /// Key addresses whose issuance completed during this run.
    ///
    /// Their assignment was made and verified inside the transaction, before
    /// the plaintext was delivered, so the assignment action beside the create
    /// has nothing left to send.
    issued: BTreeSet<Address>,
}

impl Apply<'_> {
    /// Executes the plan, phase by phase, and reports what happened to every
    /// action in it.
    ///
    /// Every action starts out with the outcome it gets if nothing runs. For a
    /// write the planner held back that is [`ActionOutcome::held_back`] rather
    /// than a bare report: an apply that wrote nothing because everything it
    /// wanted to write is waiting on an operator has not converged anything,
    /// and the report must not be able to say it did.
    fn execute(&mut self, plan: &Plan, state: &mut State) -> Vec<ActionOutcome> {
        let blocked = plan.is_blocked();
        let mut outcomes: Vec<ActionOutcome> = plan
            .actions()
            .iter()
            .map(|action| unexecuted(action, blocked))
            .collect();
        if blocked {
            return outcomes;
        }

        for phase in PHASES {
            for (index, action) in plan.actions().iter().enumerate() {
                if !action.is_executable(false) || phase_of(&action.address) != Some(phase) {
                    continue;
                }
                outcomes[index] = self.perform(action, state);
            }
        }
        outcomes
    }

    /// Performs one action, unless an earlier one already failed.
    fn perform(&mut self, action: &Action, state: &mut State) -> ActionOutcome {
        if self.stopped {
            return ActionOutcome::not_attempted(
                "not attempted: an earlier write failed and apply stopped",
            );
        }
        match self.attempt(action, state) {
            Ok(outcome) => outcome,
            Err(message) => {
                self.stopped = true;
                ActionOutcome::failed(message)
            }
        }
    }

    /// Dispatches one action to the write that performs it.
    fn attempt(&mut self, action: &Action, state: &mut State) -> Result<ActionOutcome, String> {
        match (&action.address, action.kind) {
            (ResourceAddress::Workspace(address), ActionKind::Create) => {
                self.create_workspace(address, action, state)
            }
            (ResourceAddress::Workspace(address), ActionKind::Update) => {
                self.update_workspace(address, action)
            }
            (ResourceAddress::Guardrail(address), ActionKind::Create) => {
                self.create_guardrail(address, state)
            }
            (ResourceAddress::Guardrail(address), ActionKind::Update) => {
                self.update_guardrail(address, action, state)
            }
            (ResourceAddress::Key(address), ActionKind::Create | ActionKind::Replace) => {
                self.issue_key(address, state)
            }
            (ResourceAddress::Key(address), ActionKind::Update) => self.update_key(address, action),
            (ResourceAddress::Assignment(address), ActionKind::Assign) => {
                self.assign(address, state)
            }
            (ResourceAddress::Assignment(_), ActionKind::Unassign) => self.unassign(action),
            _ => Ok(ActionOutcome::skipped(
                "skipped: apply does not know how to execute this action",
            )),
        }
    }

    /// Creates, secures, delivers, and promotes one key.
    ///
    /// The whole of ADR-0002 is in [`Issuer::issue`]; what this adds is the
    /// consequence for the run. Any outcome other than a delivered key is a
    /// failed action, which stops apply — and that is the ADR's rule, not a
    /// convenience: while an operation stands, the state API refuses to start
    /// another, and an attempt whose outcome nobody knows must not be buried
    /// under a second one.
    ///
    /// This is also how a planned `replace` runs, and the predecessor's hash is
    /// read *before* the transaction so the report can name what the promotion
    /// moved aside. Nothing here retires it: the successor's creation and the
    /// predecessor's retirement are separate operator-visible steps, and only
    /// the first is Keymaster's to take.
    fn issue_key(&mut self, address: &Address, state: &mut State) -> Result<ActionOutcome, String> {
        let issuer = Issuer {
            config: self.config,
            client: self.client,
            reader: self.reader,
            writer: self.writer,
            lock: self.lock,
            workspace: self.workspace,
            deliver: self.deliver,
        };
        let predecessor = state
            .key(address)
            .and_then(KeyBinding::current)
            .map(|current| current.hash.clone());

        let issued = issuer.issue(address, state, now())?;
        self.issued.insert(address.clone());
        Ok(ActionOutcome::applied(match predecessor {
            None => issued.detail,
            Some(hash) => format!(
                "{detail} {predecessor}",
                detail = issued.detail,
                predecessor = predecessor_note(
                    address,
                    &hash,
                    issued.promoted,
                    self.observed_disabled(&hash),
                )
            ),
        }))
    }

    /// The identity a guardrail block is written to when that identity is a
    /// workspace's to give rather than a `POST`'s to return.
    ///
    /// Two ways in, and the planner resolves the same two: the address is bound
    /// to an identity some workspace names as its default, or the block is a
    /// workspace's `default_guardrail` and the workspace binding supplies the
    /// identity even though nothing has written the guardrail binding down yet
    /// (ADR-0004, item 3).
    fn workspace_default(&self, address: &Address, state: &State) -> Option<Uuid> {
        match state.guardrail(address).map(|binding| binding.id.clone()) {
            Some(id) => state
                .workspaces()
                .values()
                .any(|binding| binding.default_guardrail_id.as_ref() == Some(&id))
                .then_some(id),
            None => {
                let workspace = self
                    .config
                    .workspaces
                    .iter()
                    .find(|(_, workspace)| workspace.default_guardrail.as_ref() == Some(address))
                    .map(|(address, _)| address)?;
                state.workspace(workspace)?.default_guardrail_id.clone()
            }
        }
    }

    /// Records the binding a default guardrail's identity implies, when state
    /// does not hold it yet.
    ///
    /// After the write rather than before it, unlike a created guardrail's
    /// UUID: this identity cannot be lost. The workspace object carries it and
    /// the workspace binding records it, so a run that wrote the guardrail and
    /// died before this would derive the same identity again next time. What
    /// this buys is that `status` names the guardrail and `delete workspace`
    /// releases it with the workspace it belongs to.
    fn record_default_binding(
        &self,
        address: &Address,
        id: &Uuid,
        origin: Origin,
        state: &mut State,
    ) -> Result<(), String> {
        if state.guardrail(address).is_some() {
            return Ok(());
        }
        state
            .bind_guardrail(address, id.clone(), origin, now())
            .map_err(|error| untracked(id, &error.to_string()))?;
        self.lock
            .write(state)
            .map_err(|error| untracked(id, &error.to_string()))
    }

    /// The workspace a created guardrail is placed in: the one its block names,
    /// or this run's scope.
    ///
    /// A block naming a workspace nothing binds yet resolves to nothing, and
    /// falls back to the scope like a block that names none — which is
    /// unreachable, because the planner holds such a create back until the
    /// binding exists (ADR-0004, item 2).
    fn placement(&self, desired: &crate::config::Guardrail, state: &State) -> Option<Uuid> {
        plan::guardrail_placement(state, desired)
            .identity()
            .cloned()
            .or_else(|| self.workspace.cloned())
    }

    /// What this run's read said about a key's `disabled`, if it saw the key.
    ///
    /// The only caller is the predecessor note, and the snapshot is the one
    /// this run planned from — taken under the lock, before any write, and a
    /// replacement writes nothing to the predecessor. `None` means the key was
    /// not in the snapshot, and then the report says nothing about it.
    fn observed_disabled(&self, hash: &KeyHash) -> Option<bool> {
        self.snapshot
            .keys
            .iter()
            .find(|key| key.hash == *hash)
            .map(|key| key.disabled)
    }

    /// Creates a workspace, records its identity, and sets its budgets.
    ///
    /// Two things are persisted before anything else runs, and for the same
    /// reason a created guardrail's UUID is: the workspace's own identity, and
    /// the `default_guardrail_id` it names. The second is the only handle on
    /// the workspace's default guardrail there is, and the guardrail block that
    /// is its default is bound to it here, so the guardrail phase that follows
    /// can materialize it (ADR-0004, item 3).
    fn create_workspace(
        &self,
        address: &Address,
        action: &Action,
        state: &mut State,
    ) -> Result<ActionOutcome, String> {
        let desired = self
            .config
            .workspaces
            .get(address)
            .ok_or_else(|| unconfigured("workspace", address))?;

        let created = self
            .writer
            .create_workspace(&WorkspaceBody::create(desired))
            .map_err(|error| {
                format!(
                    "the workspace could not be created: {error}. It may exist all the same — the \
                     request was sent once and is never repeated — and the next plan reports a \
                     name collision if it does."
                )
            })?;

        let id = created.id.clone();
        state
            .bind_workspace(
                address,
                id.clone(),
                created.default_guardrail_id.clone(),
                Origin::Created,
                now(),
            )
            .and_then(|()| {
                super::import::bind_default_guardrail(
                    state,
                    desired.default_guardrail.as_ref(),
                    created.default_guardrail_id.as_ref(),
                    Origin::Created,
                )
            })
            .map_err(|error| untracked_workspace(&id, &error.to_string()))?;
        self.lock
            .write(state)
            .map_err(|error| untracked_workspace(&id, &error.to_string()))?;

        let budgets = self.write_budgets(&id, desired, action);
        Ok(budgets.outcome(format!(
            "created workspace {id}, and recorded its identity before anything else ran"
        )))
    }

    /// Brings an existing workspace's managed fields to the configured values.
    fn update_workspace(
        &self,
        address: &Address,
        action: &Action,
    ) -> Result<ActionOutcome, String> {
        let desired = self
            .config
            .workspaces
            .get(address)
            .ok_or_else(|| unconfigured("workspace", address))?;
        let Some(Identity::Workspace(id)) = &action.identity else {
            return Err(
                "the workspace's identity is not known, so it cannot be patched".to_owned(),
            );
        };

        // The workspace's own `PATCH` carries the name, the slug, and the
        // description; nothing else it manages can travel in one. A run whose
        // only difference is a budget sends no `PATCH` at all.
        let patched = action
            .changes
            .iter()
            .any(|change| matches!(change.field, "name" | "slug" | "description"));
        if patched {
            self.writer
                .update_workspace(id, &WorkspaceBody::update(desired))
                .map_err(|error| ambiguous("workspace", &error.to_string()))?;
        }

        let budgets = self.write_budgets(id, desired, action);
        Ok(budgets.outcome(if patched {
            format!("patched workspace {id}")
        } else {
            format!("workspace {id} needed no patch of its own")
        }))
    }

    /// Writes every budget interval this action changes, in an order the server
    /// accepts.
    ///
    /// Deletes first, then increases from the widest interval to the narrowest,
    /// then decreases from the narrowest to the widest. OpenRouter checks
    /// lifetime > monthly > weekly > daily on *every* write, so any other order
    /// can pass through an intermediate state it refuses — raising the daily
    /// budget before the monthly one it will exceed, say.
    ///
    /// A refusal is definite and names its interval, and the intervals that
    /// follow are still attempted: the writes are independent, and a plan the
    /// account cannot buy should not hide the ones it can. Because the planner
    /// already held back every issuing and expanding write in this workspace
    /// (ADR-0004, item 4), a refused budget leaves nothing widened behind it.
    fn write_budgets(
        &self,
        id: &Uuid,
        desired: &crate::config::Workspace,
        action: &Action,
    ) -> Budgets {
        let byok = action
            .changes
            .iter()
            .find(|change| change.field == "include_byok_in_budgets")
            .and_then(|change| match change.to {
                plan::FieldValue::Flag(flag) => Some(flag),
                _ => None,
            });

        let mut written = Budgets::default();
        for (interval, amount) in budget_writes(desired, action) {
            let attempt = match amount {
                None => self.writer.delete_workspace_budget(id, interval),
                Some(limit) => {
                    self.writer
                        .put_workspace_budget(id, interval, &BudgetBody::new(limit, byok))
                }
            };
            let Err(error) = attempt else {
                written.done.push(interval.as_str());
                continue;
            };
            let named = format!("{interval}: {error}", interval = interval.as_str());
            // Only a well-formed 4xx — a plan restriction among them — says the
            // server saw the write and declined it. A timeout, a reset, or a
            // 5xx leaves it unknown whether the budget took, and calling that a
            // refusal would tell an operator a cap is not in force when it may
            // be. The read that follows the apply settles it, as it does for
            // every other ambiguous write.
            if error.is_definite_rejection() {
                written.refused.push(named);
            } else {
                written.ambiguous.push(named);
            }
        }
        written
    }

    /// Creates a guardrail and records its identity before anything else runs.
    fn create_guardrail(
        &self,
        address: &Address,
        state: &mut State,
    ) -> Result<ActionOutcome, String> {
        let desired = self
            .config
            .guardrails
            .get(address)
            .ok_or_else(|| unconfigured("guardrail", address))?;

        // A workspace's default guardrail is never `POST`ed. It exists as an
        // identity from the moment its workspace does, and OpenRouter
        // materializes it the first time its configuration is written — so the
        // create the planner proposed is one `PATCH` to an identity state
        // already binds (ADR-0004, item 3).
        if let Some(id) = self.workspace_default(address, state) {
            self.writer
                .update_guardrail(&id, &GuardrailBody::create(desired, None))
                .map_err(|error| ambiguous("guardrail", &error.to_string()))?;
            self.record_default_binding(address, &id, Origin::Created, state)?;
            return Ok(ActionOutcome::applied(format!(
                "materialized guardrail {id}, the default guardrail of the workspace that names \
                 it, by writing its configuration for the first time"
            )));
        }

        let created = self
            .writer
            .create_guardrail(&GuardrailBody::create(
                desired,
                self.placement(desired, state).as_ref(),
            ))
            .map_err(|error| {
                format!(
                    "the guardrail could not be created: {error}. It may exist all the same — the \
                     request was sent once and is never repeated — and the next plan reports a \
                     name collision if it does."
                )
            })?;

        // `replace_guardrail` rather than `bind_guardrail`, because a create is
        // also what a recreation looks like: the planner proposes one when the
        // bound guardrail is absent from a complete snapshot and no remote
        // guardrail carries the configured name, and the dead UUID has to give
        // way to the new one.
        let id = created.id.clone();
        state
            .replace_guardrail(address, id.clone(), now())
            .map_err(|error| untracked(&created.id, &error.to_string()))?;
        self.lock
            .write(state)
            .map_err(|error| untracked(&created.id, &error.to_string()))?;

        Ok(ActionOutcome::applied(format!(
            "created guardrail {id}, and recorded its identity before anything else ran"
        )))
    }

    /// Brings an existing guardrail's managed fields to the configured values.
    fn update_guardrail(
        &self,
        address: &Address,
        action: &Action,
        state: &mut State,
    ) -> Result<ActionOutcome, String> {
        let desired = self
            .config
            .guardrails
            .get(address)
            .ok_or_else(|| unconfigured("guardrail", address))?;
        let Some(Identity::Guardrail(id)) = &action.identity else {
            return Err(
                "the guardrail's identity is not known, so it cannot be patched".to_owned(),
            );
        };

        self.writer
            .update_guardrail(id, &GuardrailBody::update(desired))
            .map_err(|error| ambiguous("guardrail", &error.to_string()))?;
        // A default guardrail that already existed when its block was added:
        // the identity came from the workspace binding, and this run is the
        // first to write it down.
        if self.workspace_default(address, state).as_ref() == Some(id) {
            self.record_default_binding(address, id, Origin::Imported, state)?;
        }
        Ok(ActionOutcome::applied(format!("patched guardrail {id}")))
    }

    /// Brings an existing key's managed fields to the configured values.
    fn update_key(&self, address: &Address, action: &Action) -> Result<ActionOutcome, String> {
        let desired = self
            .config
            .keys
            .get(address)
            .ok_or_else(|| unconfigured("key", address))?;
        let Some(Identity::Key(hash)) = &action.identity else {
            return Err("the key's identity is not known, so it cannot be patched".to_owned());
        };

        self.writer
            .update_key(hash, &UpdateKey::new(desired))
            .map_err(|error| ambiguous("key", &error.to_string()))?;
        Ok(ActionOutcome::applied(format!("patched key {hash}")))
    }

    /// Attaches a key to the guardrail the configuration names.
    ///
    /// A key has at most one direct guardrail and assigning replaces the one it
    /// has, so a move is one write rather than a removal followed by an
    /// assignment — which would leave the key unrestricted in between.
    ///
    /// The assignment planned beside a create or a replace belongs to the key
    /// that issuance produces, and the transaction already made and verified it
    /// before the plaintext went anywhere — so there is nothing left to send.
    /// An issuance that failed stopped the run, so this is never reached with a
    /// predecessor standing in for a successor that does not exist.
    fn assign(&self, address: &Address, state: &State) -> Result<ActionOutcome, String> {
        if self.issued.contains(address) {
            return Ok(ActionOutcome::applied(ASSIGNMENT_ISSUED));
        }
        let desired = self
            .config
            .keys
            .get(address)
            .ok_or_else(|| unconfigured("key", address))?;
        let Some(guardrail) = desired.guardrail.value() else {
            return Ok(ActionOutcome::skipped(
                "skipped: the configuration names no guardrail for this key",
            ));
        };
        let Some(binding) = state.guardrail(guardrail) else {
            return Ok(ActionOutcome::skipped(
                "skipped: this key's guardrail is not bound, so there is nothing to assign it to",
            ));
        };
        let Some(current) = state.key(address).and_then(KeyBinding::current) else {
            return Ok(ActionOutcome::skipped(ASSIGNMENT_WITHOUT_KEY));
        };

        self.writer
            .assign_key(&binding.id, &current.hash)
            .map_err(|error| ambiguous("assignment", &error.to_string()))?;
        Ok(ActionOutcome::applied(format!(
            "assigned key {hash} to guardrail {id}",
            hash = current.hash,
            id = binding.id
        )))
    }

    /// Detaches a key from a guardrail the configuration does not ask for.
    fn unassign(&self, action: &Action) -> Result<ActionOutcome, String> {
        let Some(Identity::Assignment { key, guardrail }) = &action.identity else {
            return Err(
                "the assignment's identity is not known, so it cannot be removed".to_owned(),
            );
        };
        self.writer
            .unassign_key(guardrail, key)
            .map_err(|error| ambiguous("assignment", &error.to_string()))?;
        Ok(ActionOutcome::applied(format!(
            "removed key {key} from guardrail {guardrail}"
        )))
    }
}

/// Reads OpenRouter again and records what each attempted action achieved.
///
/// Verification is a replan rather than a field-by-field comparison, because
/// "did this converge?" is exactly the question the planner answers, and asking
/// it the same way here means a verified apply is one whose successor is a
/// no-op.
///
/// Returns the reason nothing could be checked, when the check itself failed.
fn verify(
    plan: &Plan,
    config: &Config,
    state: &State,
    reader: &Reader<'_>,
    workspace: Option<&Uuid>,
    outcomes: &mut [ActionOutcome],
) -> Option<String> {
    if !outcomes.iter().any(ActionOutcome::was_attempted) {
        return None;
    }

    let after = match super::snapshot(reader) {
        Ok(after) => after,
        Err(error) => {
            return Some(format!(
                "nothing could be verified: the read that follows an apply failed: {error}"
            ));
        }
    };

    let replan = plan::plan(config, state, &after, workspace);
    let settled = settled_addresses(&replan);

    for (outcome, action) in outcomes.iter_mut().zip(plan.actions()) {
        if outcome.was_attempted() {
            outcome.record_verification(settled.contains(&action.address));
        }
    }
    None
}

/// The addresses the recomputed plan has nothing left to say about.
///
/// An address qualifies when it appears in the plan and every action on it is
/// a no-op. Nothing weaker will do. "No *executable* action here" would count
/// a key that vanished between the write and the read as verified — the
/// planner reports that as `missing` precisely because it will not act on it —
/// and so would an address the plan stopped describing at all, which is what a
/// key's assignment becomes when the key is no longer in the snapshot. Neither
/// is confirmation of anything; both are questions.
fn settled_addresses(replan: &Plan) -> BTreeSet<&ResourceAddress> {
    let mut settled: BTreeSet<&ResourceAddress> = BTreeSet::new();
    let mut unsettled: BTreeSet<&ResourceAddress> = BTreeSet::new();

    for action in replan.actions() {
        if action.kind == ActionKind::NoOp {
            settled.insert(&action.address);
        } else {
            unsettled.insert(&action.address);
        }
    }
    settled.retain(|address| !unsettled.contains(address));
    settled
}

/// The outcome an action has before anything runs.
///
/// A write the planner held back is distinguished from a report, because the
/// two mean opposite things about convergence: a report is something an
/// operator may want to know, while a held-back write is work the
/// configuration asks for that this run could not even attempt.
fn unexecuted(action: &Action, plan_blocked: bool) -> ActionOutcome {
    if !action.kind.writes() || action.is_executable(plan_blocked) {
        return ActionOutcome::reported();
    }
    let blockers = blockers(action);
    if blockers.is_empty() {
        return ActionOutcome::held_back(
            "held back: the plan does not offer this write until an operator resolves what stands \
             in its way",
        );
    }
    ActionOutcome::held_back(format!("held back: waiting on {}", blockers.join(", ")))
}

/// What the planner says holds an action back.
fn blockers(action: &Action) -> Vec<String> {
    action
        .rationale
        .iter()
        .filter_map(|reason| match reason {
            Reason::BlockedBy { dependency } => Some(dependency.to_string()),
            Reason::OperationIncomplete {
                operation, phase, ..
            } => Some(format!(
                "operation {operation}, unfinished in phase `{phase}`"
            )),
            _ => None,
        })
        .collect()
}

/// What became of the key a replacement moved aside.
///
/// Promotion is a durable write of its own, after the one recording the
/// delivery, and it can fail on its own. Until it lands the predecessor is
/// still the address's current key — so the confident sentence would be telling
/// an operator that a hash is retired when it is in service, and pointing them
/// at `retire` for the key everything is using. The two sentences differ in
/// exactly the one thing that must not be guessed.
fn predecessor_note(
    address: &Address,
    hash: &KeyHash,
    promoted: bool,
    disabled: Option<bool>,
) -> String {
    if !promoted {
        return format!(
            "Key {hash} is unchanged and is still `{address}`'s current key, because the promotion \
             did not land; do not retire it until the next `openrouter-keymaster apply` completes \
             that and reports it as `awaiting_retirement`."
        );
    }
    format!(
        "Key {hash} is unchanged — a replacement never disables or deletes a predecessor — and is \
         now tracked as `awaiting_retirement`.{observed} Retire it with \
         `openrouter-keymaster retire {address} --hash {hash}` once every consumer holds the new \
         key.",
        observed = observed_note(disabled),
    )
}

/// What the run's read said about the predecessor, and nothing when it did not
/// see it.
///
/// Keymaster does not touch a predecessor, which is not the same as knowing it
/// is enabled: a key created disabled stays disabled, and a report that
/// asserted otherwise would be wrong (#23). So the sentence exists only when an
/// observation backs it, and it says which read made it.
fn observed_note(disabled: Option<bool>) -> String {
    match disabled {
        None => String::new(),
        Some(true) => " The read this run planned from showed it disabled.".to_owned(),
        Some(false) => " The read this run planned from showed it enabled.".to_owned(),
    }
}

/// An address the plan named and the configuration does not describe.
///
/// The planner reads the same configuration this does, so reaching this means
/// the two disagree about what exists — a bug rather than an operator error,
/// reported as a failed write rather than silently skipped.
fn unconfigured(resource: &str, address: &Address) -> String {
    format!("the configuration no longer describes the {resource} `{address}`")
}

/// A write whose outcome the response did not settle.
fn ambiguous(resource: &str, error: &str) -> String {
    format!(
        "the {resource} write failed: {error}. It was sent once and is never repeated; the read \
         that follows reports whether it took effect."
    )
}

/// What became of one workspace's budget writes.
#[derive(Debug, Default)]
struct Budgets {
    /// The intervals a write settled, in the order they were written.
    done: Vec<&'static str>,
    /// The intervals the server definitely declined, each with the refusal.
    refused: Vec<String>,
    /// The intervals whose write never got an answer that settles anything.
    ambiguous: Vec<String>,
}

impl Budgets {
    /// The action's outcome, given what the rest of the action achieved.
    ///
    /// A refused budget is a failed action rather than an error, so the run
    /// carries on: the refusal is definite and belongs to one interval, and the
    /// planner has already held back everything that would have spent under the
    /// cap it could not set (ADR-0004, item 4).
    fn outcome(self, detail: String) -> ActionOutcome {
        let written = if self.done.is_empty() {
            String::new()
        } else {
            format!(" Budgets written: {}.", self.done.join(", "))
        };
        if self.refused.is_empty() && self.ambiguous.is_empty() {
            return ActionOutcome::applied(format!("{detail}.{written}"));
        }

        let mut trouble = String::new();
        if !self.refused.is_empty() {
            trouble.push_str(&format!(
                " OpenRouter refused {count}: {refusals}. Workspace budgets are a plan feature, \
                 and a refusal that persists means removing the `budgets` table is the only way \
                 this configuration converges.",
                count = crate::report::plural(self.refused.len(), "budget write"),
                refusals = self.refused.join("; "),
            ));
        }
        if !self.ambiguous.is_empty() {
            trouble.push_str(&format!(
                " {count} got no answer that settles anything: {failures}. Whether the budget \
                 took effect is unknown, and the read that follows this apply reports it.",
                count = crate::report::plural(self.ambiguous.len(), "budget write"),
                failures = self.ambiguous.join("; "),
            ));
        }
        ActionOutcome::failed(format!(
            "{detail}.{written}{trouble} Each was sent once and is never repeated. Nothing was \
             issued or widened in this workspace."
        ))
    }
}

/// The budget writes one workspace action calls for, in the order the server
/// accepts them.
///
/// Deletes first, then increases from the widest interval to the narrowest,
/// then decreases from the narrowest to the widest, so no intermediate state
/// violates lifetime > monthly > weekly > daily.
///
/// A changed `include_byok_in_budgets` adds one more pass. The setting is
/// workspace-wide and only a budget `PUT` can carry it, so an interval that is
/// otherwise converged is written again with the value it already has —
/// otherwise a configuration that changed nothing but the flag would drift
/// forever with no request able to fix it. Rewriting a value the server already
/// holds cannot break the ordering rule, so those go last.
fn budget_writes(
    desired: &crate::config::Workspace,
    action: &Action,
) -> Vec<(BudgetInterval, Option<Usd>)> {
    let mut deletes = Vec::new();
    let mut increases = Vec::new();
    let mut decreases = Vec::new();

    for change in &action.changes {
        let Some(interval) = BUDGET_INTERVALS
            .into_iter()
            .find(|interval| interval.field() == change.field)
        else {
            continue;
        };
        match (&change.from, &change.to) {
            (_, plan::FieldValue::Absent) => deletes.push((interval, None)),
            (plan::FieldValue::Money(before), plan::FieldValue::Money(after)) if after < before => {
                decreases.push((interval, Some(*after)));
            }
            (_, plan::FieldValue::Money(after)) => increases.push((interval, Some(*after))),
            _ => {}
        }
    }

    // `BudgetInterval` is ordered narrowest first, so widest-first is simply
    // the reverse.
    increases.sort_by(|left, right| right.0.cmp(&left.0));
    decreases.sort_by(|left, right| left.0.cmp(&right.0));
    deletes.extend(increases);
    deletes.extend(decreases);

    if action
        .changes
        .iter()
        .any(|change| change.field == "include_byok_in_budgets")
    {
        let mut carriers: Vec<(BudgetInterval, Option<Usd>)> = desired
            .budgets
            .iter()
            .flatten()
            .filter(|(interval, _)| !deletes.iter().any(|(written, _)| written == *interval))
            .map(|(interval, limit)| (*interval, Some(*limit)))
            .collect();
        carriers.sort_by(|left, right| right.0.cmp(&left.0));
        deletes.extend(carriers);
    }
    deletes
}

/// A workspace that exists remotely and could not be recorded locally.
fn untracked_workspace(id: &Uuid, why: &str) -> String {
    format!(
        "workspace {id} was created but its identity could not be recorded: {why}. Bind it with \
         `openrouter-keymaster import workspace <address> --id {id}` before applying again, or a \
         second workspace will be created under the same name."
    )
}

/// A guardrail that exists remotely and could not be recorded locally.
fn untracked(id: &crate::ids::Uuid, why: &str) -> String {
    format!(
        "guardrail {id} was created but its identity could not be recorded: {why}. Bind it with \
         `openrouter-keymaster import guardrail <address> --id {id}` before applying again, or a \
         second guardrail will be created under the same name."
    )
}

/// When a binding was recorded. The only clock apply reads.
fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// What an undeliverable refusal established about this run.
///
/// The refusal comes before every remote write and before any issuance, but
/// not before the one local write that precedes the plan itself: an apply
/// completes a delivered operation's promotion under its lock before it plans
/// anything (ADR-0002). Claiming nothing was written would be false in exactly
/// that case, so the message says which of the two happened.
const fn undeliverable_consequence(promoted: bool) -> &'static str {
    if promoted {
        "no remote write was made and no key was issued; a previously delivered key was promoted \
         to current, which is a local state write this run completed before it planned anything, \
         and the result document names it"
    } else {
        "no remote write was made, no key was issued, and nothing was written locally either"
    }
}

/// Why an apply did not converge the configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApplyError {
    /// An operation of unknown outcome stopped the run.
    #[error(
        "nothing was applied: an earlier run left an operation whose outcome only an operator can \
         establish. Resolve it with `openrouter-keymaster recover`, then apply again."
    )]
    Blocked,

    /// A write failed, or one that was made could not be confirmed.
    #[error(
        "apply did not converge: {failed} failed and {unverified} unconfirmed by the read that \
         followed. The result document lists exactly which, and what each one left behind."
    )]
    Unresolved {
        /// How many writes failed.
        failed: usize,
        /// How many attempted writes could not be confirmed.
        unverified: usize,
    },

    /// The plan is not the one the caller was given a fingerprint for.
    #[error(
        "the plan changed after the fingerprint this apply was bound to was taken, so nothing was \
         written. The result document holds the plan as it is now: read it, and apply that one."
    )]
    PlanChanged,

    /// A planned issuance needs host code this run does not carry.
    #[error(
        "`{address}` is issued through a receiver that hands the plaintext to the host's own code, \
         and this run carries no callback to hand it to: {consequence}. A host sets \
         `Context.deliver` before applying a plan that creates or replaces that key; the \
         `openrouter-keymaster` command line never does.",
        consequence = undeliverable_consequence(*promoted)
    )]
    Undeliverable {
        /// The key the plan would have issued.
        address: Address,
        /// Whether this run completed a delivered operation's promotion before
        /// it refused. That promotion is local, it happens before the plan
        /// exists, and the report names it — so the message has to say it
        /// happened rather than claim the run wrote nothing at all.
        promoted: bool,
    },

    /// A workspace's default guardrail identity could not be recorded.
    #[error(
        "`{address}`'s default guardrail identity could not be recorded: {message}. Nothing \
         remote is outstanding — the identity was read from the workspace itself — but apply will \
         not plan against a binding it could not complete."
    )]
    Backfill {
        /// The local address.
        address: Address,
        /// Why the state API refused it.
        message: String,
    },

    /// A delivered key could not be promoted to current.
    #[error(
        "`{address}` has a delivered key that could not be promoted to current: {message}. \
         Nothing remote is outstanding — promotion is a local state operation — but apply will \
         not plan against an operation it could not complete."
    )]
    Promotion {
        /// The local address.
        address: Address,
        /// Why the promotion was refused.
        message: String,
    },
}

impl ApplyError {
    /// A stable machine-readable category.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Blocked => "apply_blocked",
            Self::Unresolved { .. } => "apply_unresolved",
            Self::PlanChanged => "plan_changed",
            Self::Undeliverable { .. } => "apply_undeliverable",
            Self::Promotion { .. } => "apply_promotion",
            Self::Backfill { .. } => "apply_backfill",
        }
    }
}
