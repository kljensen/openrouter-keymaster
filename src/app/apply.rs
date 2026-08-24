//! `keymaster apply`: converging guardrails, existing keys, and assignments.
//!
//! # The plan that runs is not the plan an operator read
//!
//! Apply takes the exclusive state lock, reloads the configuration and state
//! under it, reads a fresh snapshot of OpenRouter, and computes the plan again.
//! Whatever `keymaster plan` printed a minute ago is history: it was computed
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
//! # What apply will not do
//!
//! - **Create or replace an inference key.** That is a one-time secret with a
//!   journal of its own (ADR-0002), and it belongs to #16 and #19. A planned
//!   create or replace is skipped, conspicuously, and the run says the
//!   configuration is not fully converged.
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
//! # Verification
//!
//! When anything was attempted, apply reads a second complete snapshot and
//! recomputes the plan against it. An attempted action counts as verified when
//! every action the recomputed plan has at its address is a no-op — the same
//! question the next run will ask, so a verified apply is one whose successor
//! is a no-op. Anything else is reported as unverified rather than assumed,
//! and that read is also what decides whether a privilege expansion is
//! reported as having happened: a response is not evidence either way.

use std::collections::BTreeSet;
use std::io::Write;

use time::OffsetDateTime;

use crate::api::{GuardrailBody, Reader, UpdateKey, Writer};
use crate::cli::Cli;
use crate::client::Client;
use crate::config::Config;
use crate::error::Error;
use crate::ids::Address;
use crate::output::Renderer;
use crate::plan::{self, Action, ActionKind, Identity, Plan, Reason, ResourceAddress};
use crate::report::{ActionOutcome, ApplyReport};
use crate::state::{KeyBinding, State, StateFile, StateLock};

/// Why a planned key create or replace is not made.
const ISSUANCE_SKIPPED: &str = "skipped: `keymaster apply` does not create or replace inference \
                                keys yet, because issuing a one-time secret needs the journaled \
                                transaction of #16";

/// Why an assignment planned beside a skipped create or replace is not made.
const ASSIGNMENT_AWAITING_ISSUANCE: &str = "not attempted: this assignment belongs to the key the skipped create or replace would have \
     produced, and #16 owns that. Assigning what the address holds now would point a key the \
     configuration is replacing at its successor's guardrail.";

/// Why an assignment whose key does not exist is not made.
const ASSIGNMENT_WITHOUT_KEY: &str =
    "skipped: this address owns no key, so there is nothing to assign";

/// Runs `apply`.
///
/// # Errors
///
/// Returns [`ApplyError`] when an unfinished operation stops the run, or when
/// a write failed or could not be confirmed. The result document is written
/// before either, because what did happen is what an operator needs. Also
/// returns the configuration, state, and API errors of the steps before the
/// first write, none of which change anything.
pub(super) fn run<O: Write, E: Write>(
    cli: &Cli,
    renderer: &mut Renderer<O, E>,
) -> Result<(), Error> {
    // The lock comes first, and everything the plan is computed from is read
    // after it. Loading the configuration before taking the lock would leave a
    // window in which an edit lands between the read and the lock, and apply
    // would then converge OpenRouter to a file that has already been
    // superseded — the same staleness the recomputed plan exists to prevent,
    // one input over.
    let file = StateFile::new(&cli.state);
    let lock = file.lock()?;
    let config = Config::load(&cli.config)?;
    let mut state = lock.read()?;

    let client = Client::from_env()?;
    let reader = Reader::new(&client);
    let writer = Writer::new(&client);

    // Read and planned here, under the lock, from this run's own snapshot.
    let snapshot = super::snapshot(&reader)?;
    let plan = plan::plan(&config, &state, &snapshot);

    let mut apply = Apply {
        config: &config,
        writer: &writer,
        lock: &lock,
        stopped: false,
        awaiting_issuance: BTreeSet::new(),
    };
    let mut outcomes = apply.execute(&plan, &mut state);
    let failure = verify(&plan, &config, &state, &reader, &mut outcomes);

    let report = ApplyReport::new(&plan, &outcomes, failure);
    super::write(renderer, &report, report.warnings())?;

    if report.succeeded() {
        return Ok(());
    }
    if report.blocked() {
        return Err(ApplyError::Blocked.into());
    }
    let (failed, unverified) = report.unresolved();
    Err(ApplyError::Unresolved { failed, unverified }.into())
}

/// The fixed order the phases run in.
///
/// Dependencies before dependents: a guardrail exists before the key it
/// secures, and both exist before the assignment that joins them.
const PHASES: [Phase; 3] = [Phase::Guardrails, Phase::Keys, Phase::Assignments];

/// One phase of an apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Guardrails,
    Keys,
    Assignments,
}

/// Which phase an action belongs to, or `None` for one apply never executes.
const fn phase_of(address: &ResourceAddress) -> Option<Phase> {
    match address {
        ResourceAddress::Guardrail(_) => Some(Phase::Guardrails),
        ResourceAddress::Key(_) => Some(Phase::Keys),
        ResourceAddress::Assignment(_) => Some(Phase::Assignments),
        ResourceAddress::RemoteKey(_) | ResourceAddress::RemoteGuardrail(_) => None,
    }
}

/// One apply's writes.
struct Apply<'a> {
    config: &'a Config,
    writer: &'a Writer<'a>,
    lock: &'a StateLock<'a>,
    /// Set by the first failed write. Nothing is attempted after it: a later
    /// action may depend on the one that failed, and a run that pressed on
    /// would report a second failure caused by the first.
    stopped: bool,
    /// Key addresses whose create or replace was skipped.
    ///
    /// The assignment an issuance is planned with belongs to the key that
    /// issuance would produce, not to whatever the address holds now. For a
    /// replacement that is a live predecessor, and assigning *it* to the
    /// successor's guardrail would change what an existing credential may do —
    /// on the strength of a key that was never created.
    awaiting_issuance: BTreeSet<Address>,
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
            (ResourceAddress::Guardrail(address), ActionKind::Create) => {
                self.create_guardrail(address, state)
            }
            (ResourceAddress::Guardrail(address), ActionKind::Update) => {
                self.update_guardrail(address, action)
            }
            (ResourceAddress::Key(address), ActionKind::Create | ActionKind::Replace) => {
                self.awaiting_issuance.insert(address.clone());
                Ok(ActionOutcome::skipped(ISSUANCE_SKIPPED))
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

        let created = self
            .writer
            .create_guardrail(&GuardrailBody::create(desired))
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
    /// that issuance would produce. While issuance is skipped, so is this: the
    /// hash at the address is either absent or the predecessor's, and pointing
    /// a live predecessor at the successor's guardrail would change what an
    /// existing credential may do for a key that does not exist.
    fn assign(&self, address: &Address, state: &State) -> Result<ActionOutcome, String> {
        if self.awaiting_issuance.contains(address) {
            return Ok(ActionOutcome::not_attempted(ASSIGNMENT_AWAITING_ISSUANCE));
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

    let replan = plan::plan(config, state, &after);
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

/// A guardrail that exists remotely and could not be recorded locally.
fn untracked(id: &crate::ids::Uuid, why: &str) -> String {
    format!(
        "guardrail {id} was created but its identity could not be recorded: {why}. Bind it with \
         `keymaster import guardrail <address> --id {id}` before applying again, or a second \
         guardrail will be created under the same name."
    )
}

/// When a binding was recorded. The only clock apply reads.
fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Why an apply did not converge the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// An operation of unknown outcome stopped the run.
    #[error(
        "nothing was applied: an earlier run left an operation whose outcome only an operator can \
         establish. Resolve it with `keymaster recover`, then apply again."
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
}

impl ApplyError {
    /// A stable machine-readable category.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Blocked => "apply_blocked",
            Self::Unresolved { .. } => "apply_unresolved",
        }
    }
}
