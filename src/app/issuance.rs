//! The journaled one-shot key creation transaction (ADR-0002).
//!
//! This is the only place in Keymaster that sends `POST /keys`, and the only
//! place that holds a live inference key. Everything about it is shaped by two
//! facts about the OpenRouter API: the plaintext is returned once and nowhere
//! else, and there is no idempotency token, so a request whose response is lost
//! can never be told apart from one that was never applied.
//!
//! # A straight line with checkpoints
//!
//! The transaction is written as a straight line on purpose. Each step either
//! moves to the next one or ends the run, and every arrow between two steps
//! that a crash could fall through is a durable write:
//!
//! ```text
//! validate ─▶ create_started ─▶ POST /keys ─▶ created ─▶ PATCH + assign
//!                                                            │
//!         delivered ◀─ receiver ◀─ delivery_started ◀─ secured ◀─ verify
//!             │
//!             └─▶ promote to current
//! ```
//!
//! Intent markers — `create_started`, `delivery_started` — land *before* the
//! non-idempotent action they announce. Outcome phases land *after* the result
//! they record is known. That ordering is the whole guarantee: an interruption
//! anywhere leaves a phase on disk that the next run can read, and ADR-0002's
//! interruption table says what each one means.
//!
//! # What ends the run, and why all of it does
//!
//! Every failure here stops the whole apply. That is deliberate and it is not
//! merely conservative: an unresolved create may have made a live spending
//! credential that no local record names, and starting a second operation
//! beside it buries the evidence under another ambiguous attempt. The state API
//! enforces the same rule from below — `begin_create` refuses while any
//! operation stands — so a run that pressed on would be promising writes that
//! would then be declined.
//!
//! # What is never done
//!
//! - **A second `POST /keys`.** Not on a timeout, not on a 5xx, not on a
//!   connection reset. [`Client::create_key_once`] has no retry loop and the
//!   transport's own is off; this module never calls it twice for one address.
//! - **A second receiver invocation.** Delivery is at-most-once. An
//!   acknowledgement that was lost is journaled and left for an operator.
//! - **Printing the plaintext.** There is no fallback destination. A key whose
//!   delivery failed is disabled where possible, kept tracked, and replaced.
//! - **Adopting a key by name.** An ambiguous create is resolved by an
//!   operator through `keymaster recover`, never by looking for something that
//!   carries the right display name.
//!
//! # The plaintext's lifetime
//!
//! It exists between [`Client::create_key_once`] parsing the response and the
//! receiver returning, and nowhere else. [`CreatedKey`] has no `Serialize`,
//! prints redacted, and clears its buffer on drop, so every early return below
//! destroys it on the way out; the delivered path drops it explicitly the
//! moment the receiver is done, before promotion and the final read.

use time::OffsetDateTime;

use crate::api::{Reader, UpdateKey, Writer};
use crate::client::{ApiError, Client, CreateKeyRequest, CreatedKey};
use crate::config::{Config, Key, Managed, Usd};
use crate::ids::{Address, KeyHash, OperationId, ReceiverFingerprint, Uuid};
use crate::plan;
use crate::receiver::{Acknowledgement, DeliveryMetadata, SecretReceiver};
use crate::state::{BeginCreate, KeyBinding, State, StateLock, Transition, TransitionError};

/// Everything one transaction writes through, gathered so the steps below read
/// as a sequence rather than as a parameter list.
pub(super) struct Issuer<'a> {
    /// The configuration this run validated, under the lock.
    pub(super) config: &'a Config,
    /// The one client that may send `POST /keys`.
    pub(super) client: &'a Client,
    /// Fresh reads, for the verification this transaction depends on.
    pub(super) reader: &'a Reader<'a>,
    /// The follow-up restriction and assignment writes.
    pub(super) writer: &'a Writer<'a>,
    /// The exclusive lock every journal entry is written under.
    pub(super) lock: &'a StateLock<'a>,
}

/// What one completed transaction produced.
///
/// Non-secret by construction: a hash, a generation, an operation name, and
/// sentences this module wrote. There is nowhere here to put a plaintext, and
/// the type has no `Serialize` either, so a report has to say explicitly what
/// it publishes.
#[derive(Debug, Clone)]
pub(super) struct Issued {
    /// The attempt's journaled name.
    pub(super) operation: OperationId,
    /// The new key's immutable identity.
    pub(super) hash: KeyHash,
    /// The generation it was created as.
    pub(super) generation: u32,
    /// The destination, as the receiver describes itself. Never secret.
    pub(super) receiver: String,
    /// Whether the new hash became the address's current key.
    pub(super) promoted: bool,
    /// What the run should tell an operator about this issuance.
    pub(super) detail: String,
}

/// Why a transaction did not finish, and what it left behind.
///
/// One sentence rather than a structure, and deliberately a long one. Every
/// failure here is something an operator has to act on with a command Keymaster
/// cannot run for them, so the message names the phase the journal now holds,
/// the hash when there is one, and the exact next step. Nothing reads it back
/// programmatically, and giving it fields nothing reads would be pretending
/// otherwise.
pub(super) type IssueFailure = String;

impl Issuer<'_> {
    /// Creates one key, secures it, delivers it, and promotes it.
    ///
    /// # Errors
    ///
    /// Returns [`IssueFailure`] for every outcome that is not a delivered,
    /// promoted key. Each one stops the run that called this.
    pub(super) fn issue(
        &self,
        address: &Address,
        state: &mut State,
        at: OffsetDateTime,
    ) -> Result<Issued, IssueFailure> {
        let prepared = self
            .preflight(address, state)
            .map_err(|message| format!("nothing was created: {message}"))?;
        self.issue_prepared(address, state, prepared, at)
    }

    /// Creates the key a passed [`Issuer::preflight`] described.
    ///
    /// For the caller that has to know the successor is creatable before it
    /// changes anything else. Everything after the first line here is
    /// non-idempotent, so nothing may reach this that the preflight has not
    /// already cleared.
    ///
    /// # Errors
    ///
    /// As [`Issuer::issue`].
    pub(super) fn issue_prepared(
        &self,
        address: &Address,
        state: &mut State,
        mut prepared: Prepared<'_>,
        at: OffsetDateTime,
    ) -> Result<Issued, IssueFailure> {
        // Read again rather than trusted from the preflight. Retiring a dead
        // candidate between the two moves its generation from the operation to
        // the retained list, which leaves the highest recorded generation
        // unchanged — but the number a live key is staked on should come from
        // the state the journal entry is actually written against, not from an
        // argument that happens to still be right.
        prepared.generation = next_generation(address, state, prepared.desired)
            .map_err(|message| format!("nothing was created: {message}"))?;

        let operation = OperationId::mint(at);
        self.begin(address, state, &prepared, &operation, at)?;

        // Exactly one request. Everything from here on has a journal entry
        // behind it, so an interruption is visible to the next run.
        let created = match self.client.create_key_once(&prepared.request()) {
            Ok(created) => created,
            Err(error) => return Err(self.classify_create(address, state, &operation, &error, at)),
        };

        let hash = created.hash().clone();
        self.record_hash(address, state, &hash, at)?;
        self.secure(address, state, &prepared, &hash, at)?;
        self.deliver(address, state, &prepared, created, &operation, at)
    }

    /// Checks everything that can be checked before a request is sent.
    ///
    /// Nothing here writes — not to state, not to OpenRouter — so a
    /// configuration or dependency problem costs a read and stops, with no
    /// journal entry, no `POST /keys`, and nothing for an operator to resolve.
    ///
    /// It is separate from [`Issuer::issue_prepared`] because one caller needs
    /// the two apart. `keymaster recover replace` closes a dead operation and
    /// disables its key before staging the successor; discovering only then
    /// that the successor cannot be created — no receiver configured, a
    /// guardrail that has drifted — would leave the address with a disabled key
    /// and nothing to replace it. So it runs this first, and touches nothing
    /// until it passes.
    pub(super) fn preflight<'cfg>(
        &'cfg self,
        address: &Address,
        state: &State,
    ) -> Result<Prepared<'cfg>, String> {
        let desired =
            self.config.keys.get(address).ok_or_else(|| {
                format!("the configuration no longer describes the key `{address}`")
            })?;
        let receiver_address = desired.receiver.as_ref().ok_or_else(|| {
            format!(
                "`{address}` names no receiver, and Keymaster does not create a secret it has \
                 nowhere to put"
            )
        })?;
        let spec = self.config.receivers.get(receiver_address).ok_or_else(|| {
            format!("the configuration does not describe the receiver `{receiver_address}`")
        })?;

        Ok(Prepared {
            desired,
            fingerprint: spec.fingerprint(),
            receiver: crate::receiver::from_config(spec),
            guardrail: self.converged_guardrail(desired, state)?,
            generation: next_generation(address, state, desired)?,
        })
    }

    /// The guardrail this key will be secured by, once a fresh read shows it
    /// converged.
    ///
    /// A key is restricted before its plaintext is delivered (ADR-0002), and a
    /// guardrail that is bound but drifted restricts something other than what
    /// the configuration asked for. Checking it here rather than trusting the
    /// snapshot the plan was computed from costs one read and closes the window
    /// between them.
    fn converged_guardrail(&self, desired: &Key, state: &State) -> Result<Option<Uuid>, String> {
        let Managed::Set(address) = &desired.guardrail else {
            return Ok(None);
        };
        let wanted = self.config.guardrails.get(address).ok_or_else(|| {
            format!("the configuration does not describe the guardrail `{address}`")
        })?;
        let binding = state.guardrail(address).ok_or_else(|| {
            format!(
                "the guardrail `{address}` is not bound, so this key cannot be secured by it; \
                 run `keymaster apply` to create or import it first"
            )
        })?;
        let id = &binding.id;

        let observed = self
            .reader
            .get_guardrail(id)
            .map_err(|error| format!("guardrail {id} could not be read: {error}"))?;
        let differences = plan::guardrail_changes(wanted, Some(&observed));
        if !differences.is_empty() {
            let fields: Vec<&str> = differences.iter().map(|change| change.field).collect();
            return Err(format!(
                "guardrail {id} has not converged ({fields}), so a key secured by it would be \
                 restricted by something other than what the configuration asks for; run \
                 `keymaster apply` first",
                fields = fields.join(", ")
            ));
        }
        Ok(Some(id.clone()))
    }

    /// Journals the intent to create, before any request is sent.
    fn begin(
        &self,
        address: &Address,
        state: &mut State,
        prepared: &Prepared<'_>,
        operation: &OperationId,
        at: OffsetDateTime,
    ) -> Result<(), IssueFailure> {
        let begin = BeginCreate {
            operation: operation.clone(),
            generation: prepared.generation,
            name: prepared.desired.name.clone(),
            workspace: prepared.desired.workspace_id.clone(),
            receiver: prepared.fingerprint.clone(),
        };
        self.journal(state, |state| state.begin_create(address, begin, at))
            .map_err(|why| {
                format!(
                    "no key was created: the attempt could not be journaled, and ADR-0002 sends \
                     no `POST /keys` until it is. {why}"
                )
            })
    }

    /// Classifies a create that did not return a usable response.
    ///
    /// One question decides it: does this answer prove the server did not apply
    /// the request? Only a well-formed 4xx does. Everything else — a timeout, a
    /// reset, a 5xx, a redirect, a success whose body cannot be read — leaves it
    /// unknown whether a key now exists, and ADR-0002 refuses to guess.
    fn classify_create(
        &self,
        address: &Address,
        state: &mut State,
        operation: &OperationId,
        error: &ApiError,
        at: OffsetDateTime,
    ) -> IssueFailure {
        if error.is_definite_rejection() {
            // The server saw the request, declined it, and said so in a
            // response that arrived whole, so no key exists and the attempt can
            // be forgotten. A 429 belongs here too: rate limiting refuses a
            // request rather than performing it.
            return match self.journal(state, |state| state.abandon_create(address)) {
                Ok(()) => {
                    format!("OpenRouter refused to create the key, and no key was created: {error}")
                }
                Err(why) => format!(
                    "OpenRouter refused to create the key ({error}), and clearing the journalled \
                     attempt failed: {why}. No key exists; resolve the attempt with `keymaster \
                     recover resolve {address} --no-resource-created`."
                ),
            };
        }

        let recorded = self.journal(state, |state| {
            state.advance_key(address, Transition::CreateAmbiguous, at)
        });
        let note = match recorded {
            Ok(()) => String::new(),
            Err(why) => format!(
                " Recording that classification failed ({why}), but the attempt is journaled as \
                 `create_started`, which recovery treats identically."
            ),
        };
        format!(
            "the create request's outcome is unknown, so a key may or may not exist: {error}. The \
             request was sent exactly once and is never repeated. Inspect OpenRouter with \
             `keymaster recover inspect {address}` — operation {operation} — and attest what you \
             find.{note}"
        )
    }

    /// Persists the returned hash before anything else happens.
    ///
    /// Until this lands, the process holds the only record that the key exists.
    /// If it fails, a key exists whose identity may be lost, which ADR-0002
    /// classifies as ambiguous — so the journal says so, and the message names
    /// the hash, which is the one thing that can still find the key.
    ///
    /// **Nothing is sent to OpenRouter on the failure path, not even a
    /// disable.** ADR-0002's rule is that the hash is durable before *any*
    /// follow-up call, and here it is not: a PATCH would be exactly the call
    /// that rule forbids, aimed at a key whose identity this process is about
    /// to lose, and its own outcome would then be a second unknown nobody
    /// records. Cleanup is the recovery flow's, in the order that keeps the key
    /// tracked: `recover resolve --leaked-hash` binds the hash first and
    /// disables it after.
    fn record_hash(
        &self,
        address: &Address,
        state: &mut State,
        hash: &KeyHash,
        at: OffsetDateTime,
    ) -> Result<(), IssueFailure> {
        let recorded = self.journal(state, |state| {
            state.advance_key(address, Transition::Created { hash: hash.clone() }, at)
        });
        let Err(why) = recorded else {
            return Ok(());
        };

        let classified = self.journal(state, |state| {
            state.advance_key(address, Transition::CreateAmbiguous, at)
        });
        let note = match classified {
            Ok(()) => String::new(),
            Err(second) => format!(
                " Recording that classification failed too ({second}), but the journal holds \
                 `create_started`, which recovery treats identically."
            ),
        };
        Err(format!(
            "a key was created and its identity could not be recorded: {why}. The key is {hash}, \
             and Keymaster has sent nothing further about it: nothing may touch a key whose hash \
             is not durable. Bind it with `keymaster recover resolve {address} --leaked-hash \
             {hash}`, which tracks it and then disables it.{note}"
        ))
    }

    /// Applies the restrictions the create body could not carry, attaches the
    /// guardrail, and proves both by reading them back.
    fn secure(
        &self,
        address: &Address,
        state: &mut State,
        prepared: &Prepared<'_>,
        hash: &KeyHash,
        at: OffsetDateTime,
    ) -> Result<(), IssueFailure> {
        // `disabled` is the one managed field `POST /keys` has no place for, so
        // a key the configuration disables is born enabled and is restricted
        // here — before its plaintext goes anywhere.
        let update = self
            .writer
            .update_key(hash, &UpdateKey::new(prepared.desired));
        if let Err(error) = update {
            return Err(self.undeliverable(
                hash,
                address,
                &format!("the new key's restrictions could not be applied: {error}"),
            ));
        }
        if let Some(guardrail) = &prepared.guardrail
            && let Err(error) = self.writer.assign_key(guardrail, hash)
        {
            return Err(self.undeliverable(
                hash,
                address,
                &format!("the new key could not be assigned to guardrail {guardrail}: {error}"),
            ));
        }
        if let Err(why) = self.verify_secured(prepared, hash) {
            return Err(self.undeliverable(hash, address, &why));
        }

        self.journal(state, |state| {
            state.advance_key(address, Transition::Secured, at)
        })
        .map_err(|why| {
            self.undeliverable(
                hash,
                address,
                &format!("the verified restrictions could not be journaled: {why}"),
            )
        })
    }

    /// Reads the new key and its assignment back, and says what does not match.
    fn verify_secured(&self, prepared: &Prepared<'_>, hash: &KeyHash) -> Result<(), String> {
        let observed = self
            .reader
            .get_key(hash)
            .map_err(|error| format!("the new key could not be read back: {error}"))?;
        let differences = plan::key_changes(prepared.desired, Some(&observed));
        if !differences.is_empty() {
            let fields: Vec<&str> = differences.iter().map(|change| change.field).collect();
            return Err(format!(
                "the new key does not match the configuration after the update: {}",
                fields.join(", ")
            ));
        }

        let Some(guardrail) = &prepared.guardrail else {
            return Ok(());
        };
        let attached = self
            .reader
            .list_assignments_of(guardrail)
            .map_err(|error| format!("the new key's assignment could not be read back: {error}"))?;
        if attached
            .iter()
            .any(|assignment| assignment.key_hash == *hash)
        {
            return Ok(());
        }
        Err(format!(
            "the new key is not attached to guardrail {guardrail} after the assignment"
        ))
    }

    /// Journals the intent to deliver, invokes the receiver once, and records
    /// what the acknowledgement proved.
    fn deliver(
        &self,
        address: &Address,
        state: &mut State,
        prepared: &Prepared<'_>,
        created: CreatedKey,
        operation: &OperationId,
        at: OffsetDateTime,
    ) -> Result<Issued, IssueFailure> {
        let hash = created.hash().clone();
        self.journal(state, |state| {
            state.advance_key(address, Transition::DeliveryStarted, at)
        })
        .map_err(|why| {
            self.undeliverable(
                &hash,
                address,
                &format!("the intent to deliver could not be journaled: {why}"),
            )
        })?;

        let metadata = DeliveryMetadata::new(
            address.clone(),
            hash.clone(),
            prepared.generation,
            operation.clone(),
        );
        let outcome = prepared.receiver.receive(&metadata, created.plaintext());
        // The plaintext has been where it was going, or it never will. Either
        // way this run has no further use for it.
        drop(created);

        match outcome.acknowledgement() {
            Acknowledgement::Delivered => self.promote(
                address,
                state,
                prepared,
                &hash,
                operation,
                outcome.detail(),
                at,
            ),
            Acknowledgement::Rejected => {
                Err(self.record_rejection(address, state, &hash, outcome.detail(), at))
            }
            Acknowledgement::Ambiguous => {
                Err(self.record_ambiguity(address, state, &hash, outcome.detail(), at))
            }
        }
    }

    /// Records a delivery that definitely committed, then makes the new key
    /// current.
    ///
    /// Two writes, not one. `delivered` and the promotion that follows it are
    /// separate journal entries because a crash between them is a real state
    /// with a defined answer: the transaction is over, and the next run
    /// completes the promotion under its lock without touching anything remote.
    #[allow(
        clippy::too_many_arguments,
        reason = "these are the transaction's own values; gathering them into a struct would add \
                  a type whose only purpose is to satisfy a count, and would hide which of them \
                  this step reads"
    )]
    fn promote(
        &self,
        address: &Address,
        state: &mut State,
        prepared: &Prepared<'_>,
        hash: &KeyHash,
        operation: &OperationId,
        delivery: &str,
        at: OffsetDateTime,
    ) -> Result<Issued, IssueFailure> {
        self.journal(state, |state| {
            state.advance_key(address, Transition::Delivered, at)
        })
        .map_err(|why| {
            format!(
                "key {hash} was delivered and the acknowledgement could not be journaled: {why}. \
                 The journal holds `delivery_started`, which the next run cannot tell apart from \
                 a lost acknowledgement, so it will ask for a replacement even though this \
                 delivery succeeded."
            )
        })?;

        let promoted = self.journal(state, |state| state.promote_key(address, at));
        let note = match promoted {
            Ok(()) => String::new(),
            Err(why) => format!(
                " The key was not promoted to current ({why}); the next `keymaster apply` \
                 completes that under its lock, and nothing remote is outstanding."
            ),
        };
        Ok(Issued {
            operation: operation.clone(),
            hash: hash.clone(),
            generation: prepared.generation,
            receiver: prepared.receiver.describe(),
            promoted: note.is_empty(),
            detail: format!(
                "created key {hash} at generation {generation}, verified its restrictions and \
                 guardrail, and delivered it once: {delivery}.{note}",
                generation = prepared.generation
            ),
        })
    }

    /// Records a receiver that definitely committed nothing.
    ///
    /// The operation returns to `secured`, carrying a refusal marker the state
    /// API reads to refuse a second invocation. Nothing was written at the
    /// destination, so no cleanup is owed there; the key is disabled where
    /// possible and stays tracked, and only a replacement can fix the address.
    fn record_rejection(
        &self,
        address: &Address,
        state: &mut State,
        hash: &KeyHash,
        delivery: &str,
        at: OffsetDateTime,
    ) -> IssueFailure {
        let recorded = self.journal(state, |state| {
            state.advance_key(address, Transition::DeliveryRejected, at)
        });
        let note = match recorded {
            Ok(()) => String::new(),
            Err(why) => format!(" Recording the refusal failed: {why}."),
        };
        let disable = self.attempt_disable(hash);
        format!(
            "the receiver refused the plaintext, which committed nothing and no longer exists: \
             {delivery}. Key {hash} is tracked and can never be delivered; {disable}{note} \
             Replace it with `keymaster recover replace {address}`."
        )
    }

    /// Records a receiver whose acknowledgement proved nothing.
    ///
    /// The receiver may hold the secret and may not, so it is never invoked
    /// again: re-delivering could overwrite a live destination with a duplicate,
    /// and the plaintext is gone in any case. The key is left enabled and
    /// tracked, because it may be the one a consumer is now using.
    fn record_ambiguity(
        &self,
        address: &Address,
        state: &mut State,
        hash: &KeyHash,
        delivery: &str,
        at: OffsetDateTime,
    ) -> IssueFailure {
        let recorded = self.journal(state, |state| {
            state.advance_key(address, Transition::DeliveryAmbiguous, at)
        });
        let note = match recorded {
            Ok(()) => String::new(),
            Err(why) => format!(
                " Recording that classification failed ({why}), but the journal holds \
                 `delivery_started`, which recovery treats identically."
            ),
        };
        format!(
            "the receiver's acknowledgement was lost, so key {hash} may or may not have reached \
             its destination: {delivery}. The receiver is never invoked again, and the plaintext \
             no longer exists. Establish what the destination holds, then replace the key with \
             `keymaster recover replace {address}`.{note}"
        )
    }

    /// The failure shape shared by everything that goes wrong after the hash is
    /// durable: try to make the key harmless, and keep it tracked.
    fn undeliverable(&self, hash: &KeyHash, address: &Address, why: &str) -> IssueFailure {
        let disable = self.attempt_disable(hash);
        format!(
            "{why}. Key {hash} exists and its plaintext no longer does, so it can never be \
             delivered; {disable} It stays tracked. Replace it with `keymaster recover replace \
             {address}`."
        )
    }

    /// Disables a key that must not be usable, and says what became of the
    /// attempt.
    fn attempt_disable(&self, hash: &KeyHash) -> String {
        disable_and_confirm(self.reader, self.writer, hash).1
    }

    /// Applies one change to state and makes it durable, or leaves state
    /// exactly as it was.
    ///
    /// Rolling the in-memory value back on a failed write is what keeps the
    /// rest of the run honest: the plan recomputed afterwards is computed
    /// against a state that matches what a reader would find, rather than
    /// against a phase that was never written.
    fn journal<T>(
        &self,
        state: &mut State,
        change: impl FnOnce(&mut State) -> Result<T, TransitionError>,
    ) -> Result<T, String> {
        let restore = state.clone();
        let value = match change(state) {
            Ok(value) => value,
            Err(error) => {
                *state = restore;
                return Err(format!("the state API refused the transition: {error}"));
            }
        };
        match self.lock.write(state) {
            Ok(()) => Ok(value),
            Err(error) => {
                *state = restore;
                Err(format!(
                    "the journal entry could not be made durable: {error}"
                ))
            }
        }
    }
}

/// Disables a key that must not be usable, and reports what that established.
///
/// Shared by the transaction and by `keymaster recover`, because both reach it
/// for the same reason: a key exists whose plaintext is gone or was never
/// received, and the safe thing is to make it unusable while keeping it
/// tracked. Best effort by nature — every caller is already handling a failure
/// — so it reports rather than propagates.
///
/// Returns whether the disable is *confirmed*, which is decided by a fresh read
/// and never by the PATCH's own response, and the sentence to show an operator.
/// A key that could not be confirmed disabled stays tracked as a failed
/// candidate so a later explicit `retire` or `delete` can finish the job.
pub(super) fn disable_and_confirm(
    reader: &Reader<'_>,
    writer: &Writer<'_>,
    hash: &KeyHash,
) -> (bool, String) {
    if let Err(error) = writer.disable_key(hash) {
        return (
            false,
            format!("Keymaster could not disable it ({error}), so disable it yourself."),
        );
    }
    match reader.get_key(hash) {
        Ok(observed) if observed.disabled => (
            true,
            "Keymaster disabled it, and confirmed that by reading it back.".to_owned(),
        ),
        Ok(_) => (
            false,
            "Keymaster asked OpenRouter to disable it and the read that followed still shows it \
             enabled, so disable it yourself."
                .to_owned(),
        ),
        Err(error) => (
            false,
            format!(
                "Keymaster asked OpenRouter to disable it and could not confirm that ({error}), \
                 so check it yourself."
            ),
        ),
    }
}

/// The generation a new key at `address` takes.
///
/// A generation names one remote key at one address and only ever moves
/// upward, so a create takes the configured number or the next free one,
/// whichever is higher. The difference matters after a failed attempt: the dead
/// candidate is retained at the generation it was created as, and the successor
/// cannot reuse it even though the configuration still asks for the same
/// number.
///
/// # Errors
///
/// Returns the sentence to report when the address has no generation left.
fn next_generation(address: &Address, state: &State, desired: &Key) -> Result<u32, String> {
    let recorded = state.key(address).map_or(0, KeyBinding::highest_generation);

    // Checked, not saturating. Saturating would hand back a number the address
    // has already used, which `begin_create` then refuses — but only after the
    // caller has acted on the preflight's answer. For `keymaster recover
    // replace` that is the dead end the preflight exists to prevent: the old
    // key retired and disabled, and no successor possible.
    let next = recorded.checked_add(1).ok_or_else(|| {
        format!(
            "`{address}` has recorded generation {recorded}, the highest there is, so no further \
             key can be created at this address: a generation names one remote key and only ever \
             moves upward. No amount of ordinary use reaches this, so the state file has been \
             edited or corrupted."
        )
    })?;
    Ok(desired.generation.max(next))
}

/// Everything the transaction needs, checked before anything is journaled.
pub(super) struct Prepared<'a> {
    /// The desired key, as the configuration describes it.
    desired: &'a Key,
    /// Where the plaintext goes. Selected explicitly; there is no fallback.
    receiver: Box<dyn SecretReceiver>,
    /// The non-secret digest of that destination, for the journal.
    fingerprint: ReceiverFingerprint,
    /// The guardrail the new key is attached to, when one is configured.
    guardrail: Option<Uuid>,
    /// The generation this attempt would become.
    generation: u32,
}

impl Prepared<'_> {
    /// The one create request this transaction sends.
    ///
    /// `disabled` is absent because `POST /keys` has no such field; the
    /// update-only restrictions that follow carry it, before delivery.
    fn request(&self) -> CreateKeyRequest {
        CreateKeyRequest {
            name: self.desired.name.clone(),
            limit: self.desired.limit.value().copied().map(Usd::dollars),
            limit_reset: self.desired.limit_reset.value().copied(),
            include_byok_in_limit: self.desired.include_byok_in_limit,
            expires_at: self.desired.expires_at.value().copied(),
            workspace_id: self.desired.workspace_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    /// One creatable key, with the generation the configuration asks for.
    fn configured(generation: u32) -> (Address, Config) {
        let source = format!(
            "version = 1\n\n[receivers.vault]\ntype = \"file\"\n\
             path = \"/var/lib/keymaster/vault.key\"\n\n[keys.jobfeed]\n\
             name = \"golf-jobfeed\"\nreceiver = \"vault\"\ngeneration = {generation}\n"
        );
        (
            Address::parse("jobfeed").expect("a valid address"),
            Config::parse(&source).expect("a valid test configuration"),
        )
    }

    /// State whose one address already owns a key at `generation`.
    fn owning(address: &Address, generation: u32) -> State {
        let mut state = State::new();
        state
            .bind_key(
                address,
                KeyHash::parse("hash-one").expect("a valid hash"),
                generation,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("binding a key");
        state
    }

    #[test]
    fn a_generation_is_the_higher_of_the_configured_one_and_the_next_free_one() {
        let (address, config) = configured(1);
        let desired = &config.keys[&address];

        assert_eq!(
            next_generation(&address, &State::new(), desired),
            Ok(1),
            "a fresh address takes the configured number"
        );
        assert_eq!(
            next_generation(&address, &owning(&address, 4), desired),
            Ok(5),
            "an address that has used higher numbers takes the next free one, so a \
             successor cannot collide with a key the address still owns"
        );

        let (_, higher) = configured(9);
        assert_eq!(
            next_generation(&address, &owning(&address, 4), &higher.keys[&address]),
            Ok(9),
            "and a configuration asking for more than that gets what it asked for"
        );
    }

    #[test]
    fn an_address_at_the_highest_generation_has_no_successor_to_offer() {
        // Saturating here would return a number the address already owns, which
        // `begin_create` refuses — but only after the caller has acted on this
        // answer. `recover replace` would by then have retired and disabled the
        // old key, leaving the address with neither it nor a successor. So the
        // preflight refuses instead, before anything is touched.
        let (address, config) = configured(1);
        let state = owning(&address, u32::MAX);

        let refused = next_generation(&address, &state, &config.keys[&address])
            .expect_err("there is no generation above the highest one");

        assert!(refused.contains("highest there is"), "{refused}");
        assert!(refused.contains("jobfeed"), "{refused}");
    }
}
