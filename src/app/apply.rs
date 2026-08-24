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
//! stays enabled until an operator runs `keymaster retire`. So a rotation that
//! fails at any phase leaves the working credential working.
//!
//! # What apply will not do
//!
//! - **Retire, disable, or delete a predecessor.** Rotation stages; retirement
//!   is always explicit. See `keymaster retire` and `keymaster delete key`.
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
use crate::ids::{Address, KeyHash};
use crate::output::Renderer;
use crate::plan::{self, Action, ActionKind, Identity, Plan, Reason, ResourceAddress};
use crate::report::{ActionOutcome, ApplyReport};
use crate::state::{KeyBinding, Phase as JournalPhase, State, StateFile, StateLock};

use super::issuance::Issuer;

/// Why an assignment beside a completed creation needs no separate write.
const ASSIGNMENT_ISSUED: &str = "the key was attached to its guardrail as part of the journaled \
                                 creation, and verified, before its plaintext was delivered";

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

    // Before anything is planned: a delivered operation is finished remotely,
    // and what is left of it — promotion — touches nothing outside this file.
    // Completing it here means the plan this run executes describes the world
    // as it now is, rather than one holding an operation that is already over.
    let promoted = fast_forward(&lock, &mut state)?;

    let client = Client::from_env()?;
    let reader = Reader::new(&client);
    let writer = Writer::new(&client);

    // Read and planned here, under the lock, from this run's own snapshot.
    let snapshot = super::snapshot(&reader)?;
    let plan = plan::plan(&config, &state, &snapshot);

    let mut apply = Apply {
        config: &config,
        client: &client,
        reader: &reader,
        writer: &writer,
        lock: &lock,
        stopped: false,
        issued: BTreeSet::new(),
    };
    let mut outcomes = apply.execute(&plan, &mut state);
    let failure = verify(&plan, &config, &state, &reader, &mut outcomes);

    let mut report = ApplyReport::new(&plan, &outcomes, failure);
    report.note(promoted);
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
    client: &'a Client,
    reader: &'a Reader<'a>,
    writer: &'a Writer<'a>,
    lock: &'a StateLock<'a>,
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
            (ResourceAddress::Guardrail(address), ActionKind::Create) => {
                self.create_guardrail(address, state)
            }
            (ResourceAddress::Guardrail(address), ActionKind::Update) => {
                self.update_guardrail(address, action)
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
                predecessor = predecessor_note(address, &hash, issued.promoted)
            ),
        }))
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

/// What became of the key a replacement moved aside.
///
/// Promotion is a durable write of its own, after the one recording the
/// delivery, and it can fail on its own. Until it lands the predecessor is
/// still the address's current key — so the confident sentence would be telling
/// an operator that a hash is retired when it is in service, and pointing them
/// at `retire` for the key everything is using. The two sentences differ in
/// exactly the one thing that must not be guessed.
fn predecessor_note(address: &Address, hash: &KeyHash, promoted: bool) -> String {
    if !promoted {
        return format!(
            "Key {hash} is untouched and is still `{address}`'s current key, because the \
             promotion did not land; do not retire it until the next `keymaster apply` completes \
             that and reports it as `awaiting_retirement`."
        );
    }
    format!(
        "Key {hash} is untouched — still enabled, now tracked as `awaiting_retirement` — because \
         rotation never disables a predecessor; retire it with `keymaster retire {address} \
         --hash {hash}` once every consumer holds the new key."
    )
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
            Self::Promotion { .. } => "apply_promotion",
        }
    }
}
