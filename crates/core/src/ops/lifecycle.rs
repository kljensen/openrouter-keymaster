//! The four explicit end-of-life commands: `retire`, `decommission`,
//! `delete key`, and `state forget`.
//!
//! Nothing here is ever planned, proposed, or performed as a side effect of
//! something else. A predecessor left behind by a rotation stays untouched
//! forever unless an operator names it; a configuration block that disappears
//! is an orphaned binding and nothing more. Keymaster cannot know when a
//! downstream deployment stopped using a credential, so it never decides that
//! for one.
//!
//! Each command is a different kind of ending, and the difference is the point:
//!
//! - **`retire NAME --hash HASH`** makes a tracked key unusable and keeps it.
//!   The hash stays in state, visible to an audit and to a later `delete`.
//! - **`decommission NAME --hash HASH [--delete]`** does the same to the key an
//!   address is *using*, which is the one thing `retire` refuses. It exists
//!   because rotation replaces a credential and nothing else ended one: after
//!   it the address is bound and owns no key.
//! - **`delete key --hash HASH`** removes the remote key permanently, and only
//!   then stops tracking it. The order is not negotiable: state is what makes a
//!   spending credential findable, so it is the last thing to go.
//! - **`state forget ADDRESS`** relinquishes ownership and makes no remote call
//!   at all. Nothing is disabled and nothing is deleted; Keymaster simply stops
//!   claiming the resources, which every later plan then reports as unmanaged.
//!
//! # Immutable identity, always
//!
//! Every remote mutation takes a hash, never a name. A display name is mutable
//! and not unique (ADR-0001), and these are the operations where addressing the
//! wrong key is unrecoverable. `delete key` takes no address either: the hash
//! alone identifies the key, and the address it belongs to is looked up rather
//! than asserted, so an operator cannot delete one address's key by typing
//! another address's name. `decommission` is the strictest of the three: the
//! hash it is given has to be the address's current one, because a hash that
//! merely belongs to the address is not evidence that the operator knows which
//! credential they are switching off.
//!
//! # Only a key Keymaster tracks
//!
//! Every one of these refuses a hash no local address owns. Keymaster manages
//! what it was told to manage; a stray key in the organization belongs to
//! whoever made it, and the tool that reports it as unmanaged must not also be
//! the tool that deletes it.

use time::OffsetDateTime;

use crate::api::{Reader, Writer};
use crate::client::ApiError;
use crate::error::Error;
use crate::ids::{Address, IdError, KeyHash, Uuid};
use crate::report::{
    DecommissionReport, DeleteAttempt, DeleteOutcome, DeleteReport, DeleteWorkspaceReport, Ending,
    ForgetReport, Released, RetireReport,
};
use crate::state::{
    KeyBinding, Phase, RetainedKey, RetainedStatus, State, StateFile, StateLock, TransitionError,
};

use super::issuance::{Disabled, disable_and_confirm};
use super::{Context, Outcome, Resolution};

// --- retire ------------------------------------------------------------------

/// Disables one retained hash and proves it by reading the key back.
///
/// # Errors
///
/// Returns [`LifecycleError`] for a value this command cannot use, a hash the
/// address does not retain, or an attempt on the current key; and the state and
/// API errors of the steps it performs, including `missing_credential`. A
/// disable that could not be confirmed is reported beside the result document
/// rather than in place of it.
pub fn retire(context: Context, name: &str, hash: &str) -> Result<Outcome<RetireReport>, Error> {
    let attempt = retire_hash(&context, name, hash)?;
    if attempt.report.confirmed() {
        return Ok(Outcome::ok(attempt.report));
    }
    Ok(Outcome::failed(
        attempt.report,
        LifecycleError::RetireUnconfirmed {
            address: attempt.address,
            hash: attempt.hash,
        },
    ))
}

/// One retirement's result document and the identities it acted on.
///
/// The two identities travel with the report because the run has to write the
/// document *and then* fail when the disable was not confirmed — what happened
/// is what an operator needs, and an error that replaced it would throw that
/// away.
struct Retirement {
    report: RetireReport,
    address: Address,
    hash: KeyHash,
}

/// Disables one retained hash and proves it by reading the key back.
///
/// The configuration is deliberately not loaded. Retirement acts on a hash the
/// state file records, and the commonest thing to retire is a predecessor whose
/// address the configuration may have stopped describing entirely; requiring a
/// desired-state block would refuse exactly the cleanup an orphaned binding
/// needs.
fn retire_hash(context: &Context, name: &str, hash: &str) -> Result<Retirement, Error> {
    let address = Address::parse(name).map_err(|error| argument("NAME", &error))?;
    let hash = KeyHash::parse(hash).map_err(|error| argument("--hash", &error))?;

    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let mut state = lock.read()?;

    let retained = retirable(&state, &address, &hash)?;

    let client = context.client()?;
    let (reader, writer) = (Reader::new(&client), Writer::new(&client));
    let observed = reader
        .get_key(&hash)
        .map_err(|error| absent_or(error, &hash))?;

    // A key OpenRouter already has disabled needs no write, which is what makes
    // a repeated `retire` cost one read and change nothing. The answer comes
    // from a fresh read either way: this branch and the one below establish the
    // same fact by the same means.
    let outcome = if observed.disabled {
        Disabled::already_disabled()
    } else {
        disable_and_confirm(&reader, &writer, &hash)
    };

    let status = if outcome.confirmed {
        RetainedStatus::Retired
    } else {
        RetainedStatus::RetirementFailed
    };
    record_status(&lock, &mut state, &address, &retained, status)?;

    Ok(Retirement {
        report: RetireReport::new(
            &address,
            &hash,
            retained.generation,
            status,
            outcome.confirmed,
            outcome.detail,
        ),
        address,
        hash,
    })
}

/// The retained entry `retire` may act on, or why it may not.
///
/// The current hash is refused outright. Disabling it is an outage for whoever
/// holds the credential, and Keymaster has no way to know they have stopped
/// needing it — that judgement belongs to a rotation followed by a deliberate
/// retirement of the *predecessor*, in that order. v0.1 has no policy that
/// permits the shortcut, so there is no flag for it.
fn retirable(
    state: &State,
    address: &Address,
    hash: &KeyHash,
) -> Result<RetainedKey, LifecycleError> {
    let binding = state.key(address).ok_or_else(|| LifecycleError::NotBound {
        address: address.clone(),
    })?;
    check_not_in_use(binding, address, hash)?;

    binding
        .retained()
        .iter()
        .find(|retained| &retained.hash == hash)
        .cloned()
        .ok_or_else(|| LifecycleError::NotRetained {
            address: address.clone(),
            hash: hash.clone(),
        })
}

/// Refuses a hash that is the address's working key or an unfinished attempt's.
fn check_not_in_use(
    binding: &KeyBinding,
    address: &Address,
    hash: &KeyHash,
) -> Result<(), LifecycleError> {
    if binding
        .current()
        .is_some_and(|current| &current.hash == hash)
    {
        return Err(LifecycleError::KeyInUse {
            address: address.clone(),
            hash: hash.clone(),
        });
    }
    if let Some(pending) = binding.pending()
        && pending.hash.as_ref() == Some(hash)
    {
        return Err(LifecycleError::KeyUnderOperation {
            address: address.clone(),
            hash: hash.clone(),
            phase: pending.phase,
            resolution: Resolution::of(pending.phase).instruction(address),
        });
    }
    Ok(())
}

/// Records a new status for a retained hash, writing nothing when it already
/// says that.
///
/// Re-running a command that already succeeded must not advance the serial or
/// move the timestamp: an operator repeating a documented step should be able
/// to see that nothing happened.
fn record_status(
    lock: &StateLock<'_>,
    state: &mut State,
    address: &Address,
    retained: &RetainedKey,
    status: RetainedStatus,
) -> Result<(), Error> {
    if retained.status == status {
        return Ok(());
    }
    state
        .set_retained_status(address, &retained.hash, status, now())
        .map_err(LifecycleError::Refused)?;
    lock.write(state)?;
    Ok(())
}

// --- delete key ----------------------------------------------------------------

/// Deletes one tracked key permanently.
///
/// # Errors
///
/// Returns [`LifecycleError`] for a value this command cannot use, a hash no
/// local address tracks, or an attempt on a key that is in use; and the state
/// and API errors of the steps it performs, including `missing_credential`. A
/// deletion that could not be confirmed is reported beside the result document
/// rather than in place of it.
pub fn delete_key(context: Context, hash: &str) -> Result<Outcome<DeleteReport>, Error> {
    let attempt = delete_tracked_key(&context, hash)?;
    if attempt.report.settled() {
        return Ok(Outcome::ok(attempt.report));
    }
    Ok(Outcome::failed(
        attempt.report,
        LifecycleError::DeleteUnconfirmed { hash: attempt.hash },
    ))
}

/// One deletion's result document and the hash it acted on.
struct Deletion {
    report: DeleteReport,
    hash: KeyHash,
}

/// Deletes one tracked key permanently, and stops tracking it only once
/// OpenRouter says it is gone.
fn delete_tracked_key(context: &Context, hash: &str) -> Result<Deletion, Error> {
    let hash = KeyHash::parse(hash).map_err(|error| argument("--hash", &error))?;

    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let mut state = lock.read()?;

    let address = state
        .address_owning(&hash)
        .cloned()
        .ok_or_else(|| LifecycleError::Untracked { hash: hash.clone() })?;
    let retained = retirable(&state, &address, &hash)?;

    let client = context.client()?;
    let (reader, writer) = (Reader::new(&client), Writer::new(&client));
    let (outcome, detail) = attempt_delete(&reader, &writer, &hash);

    if outcome.is_gone() {
        state
            .drop_retained(&address, &hash)
            .map_err(LifecycleError::Refused)?;
        lock.write(&mut state)?;
    } else {
        // A delete that did not land leaves the hash tracked, and says so in the
        // status: the key may still be a live spending credential, and the one
        // thing that can still find it is this record.
        record_status(
            &lock,
            &mut state,
            &address,
            &retained,
            RetainedStatus::RetirementFailed,
        )?;
    }

    Ok(Deletion {
        report: DeleteReport::new(&address, &hash, retained.generation, outcome, detail),
        hash,
    })
}

/// Sends the one `DELETE` and establishes what it achieved by reading back.
///
/// The delete's own status is never the answer on its own. A 2xx is checked
/// against a fresh read, because a write's response is not evidence anywhere
/// else in Keymaster either; a 404 *is* an answer, and the only one that proves
/// absence — it says OpenRouter has no such key, which is exactly the end state
/// asked for.
fn attempt_delete(
    reader: &Reader<'_>,
    writer: &Writer<'_>,
    hash: &KeyHash,
) -> (DeleteOutcome, String) {
    if let Err(error) = writer.delete_key(hash) {
        if error.status() == Some(404) {
            return (
                DeleteOutcome::AlreadyAbsent,
                "OpenRouter has no such key, so there was nothing to delete; the hash is no \
                 longer tracked."
                    .to_owned(),
            );
        }
        return (
            DeleteOutcome::Failed,
            format!(
                "the delete failed and was sent exactly once: {error}. Whether it took effect is \
                 unknown, so the hash stays tracked."
            ),
        );
    }

    match reader.get_key(hash) {
        Err(error) if error.status() == Some(404) => (
            DeleteOutcome::Deleted,
            "OpenRouter returned 404 for the key after the delete, which is what proves it is \
             gone; the hash is no longer tracked."
                .to_owned(),
        ),
        Ok(_) => (
            DeleteOutcome::Unconfirmed,
            "OpenRouter accepted the delete and still returns the key, so it is not confirmed \
             gone; the hash stays tracked and the delete is never resent automatically."
                .to_owned(),
        ),
        Err(error) => (
            DeleteOutcome::Unconfirmed,
            format!(
                "OpenRouter accepted the delete and the read that would confirm it failed: \
                 {error}. The hash stays tracked."
            ),
        ),
    }
}

// --- delete workspace ----------------------------------------------------------

/// Deletes one tracked workspace permanently.
///
/// Refused while OpenRouter shows the workspace holding anything — a key, a
/// guardrail, and, once ADR-0006 lands, a log destination — whether or not
/// Keymaster tracks it, because deleting a workspace takes its children with it
/// and ADR-0001 forbids destroying what Keymaster does not manage. The one
/// exception is the workspace's own default guardrail: it is part of the
/// workspace, cannot outlive it, and cannot be deleted on its own, so its
/// binding is released along with the workspace's (ADR-0004, item 1).
///
/// # Errors
///
/// Returns [`LifecycleError`] for a value this command cannot use, a UUID no
/// local address tracks, or a workspace that still holds something; and the
/// state and API errors of the steps it performs, including
/// `missing_credential`. A deletion that could not be confirmed is reported
/// beside the result document rather than in place of it.
pub fn delete_workspace(
    context: Context,
    id: &str,
) -> Result<Outcome<DeleteWorkspaceReport>, Error> {
    let attempt = delete_tracked_workspace(&context, id)?;
    if attempt.report.settled() {
        return Ok(Outcome::ok(attempt.report));
    }
    Ok(Outcome::failed(
        attempt.report,
        LifecycleError::WorkspaceDeleteUnconfirmed { id: attempt.id },
    ))
}

/// One workspace deletion's result document and the identity it acted on.
struct WorkspaceDeletion {
    report: DeleteWorkspaceReport,
    id: Uuid,
}

fn delete_tracked_workspace(context: &Context, id: &str) -> Result<WorkspaceDeletion, Error> {
    let id = Uuid::parse(id).map_err(|error| argument("--id", &error))?;

    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let mut state = lock.read()?;

    let address = state
        .address_owning_workspace(&id)
        .cloned()
        .ok_or_else(|| LifecycleError::WorkspaceUntracked { id: id.clone() })?;
    let default_guardrail = state
        .workspace(&address)
        .and_then(|binding| binding.default_guardrail_id.clone());

    let client = context.client()?;
    let (reader, writer) = (Reader::new(&client), Writer::new(&client));
    let children = observed_children(&reader, &id, default_guardrail.as_ref())?;
    if !children.is_empty() {
        return Err(LifecycleError::WorkspaceInhabited {
            address,
            id,
            children,
        }
        .into());
    }

    let (outcome, detail) = attempt_workspace_delete(&reader, &writer, &id);
    let mut released = Vec::new();
    if outcome.is_gone() {
        if let Some(binding) = state.forget_workspace(&address) {
            released.push(format!("workspaces.{address} ({id})", id = binding.id));
        }
        // The default guardrail goes with the workspace: it cannot outlive one,
        // and there is no request that deletes it on its own.
        if let Some(default) = &default_guardrail
            && let Some(guardrail) = state.address_owning_guardrail(default).cloned()
        {
            state.forget_guardrail(&guardrail);
            released.push(format!("guardrails.{guardrail} ({default})"));
        }
        lock.write(&mut state)?;
    }

    Ok(WorkspaceDeletion {
        report: DeleteWorkspaceReport::new(&address, &id, outcome, detail, released),
        id,
    })
}

/// What OpenRouter shows the workspace holding, other than its own default
/// guardrail.
///
/// Read rather than taken from state: a key another operator made in this
/// workspace is exactly the thing this refusal exists for, and state does not
/// know about it. Log destinations (ADR-0006) join this list when they exist.
fn observed_children(
    reader: &Reader<'_>,
    id: &Uuid,
    default_guardrail: Option<&Uuid>,
) -> Result<Vec<String>, ApiError> {
    let mut children: Vec<String> = reader
        .list_keys(Some(id))?
        .into_iter()
        .map(|key| format!("key {hash}", hash = key.hash))
        .collect();
    children.extend(
        reader
            .list_guardrails(Some(id))?
            .into_iter()
            .filter(|guardrail| Some(&guardrail.id) != default_guardrail)
            .map(|guardrail| format!("guardrail {id}", id = guardrail.id)),
    );
    Ok(children)
}

/// Sends the one `DELETE` and establishes what it achieved by reading back.
///
/// The same rule as [`attempt_delete`]: a 2xx is checked against a fresh read,
/// and only a 404 proves absence.
fn attempt_workspace_delete(
    reader: &Reader<'_>,
    writer: &Writer<'_>,
    id: &Uuid,
) -> (DeleteOutcome, String) {
    if let Err(error) = writer.delete_workspace(id) {
        if error.status() == Some(404) {
            return (
                DeleteOutcome::AlreadyAbsent,
                "OpenRouter has no such workspace, so there was nothing to delete; the binding is \
                 no longer tracked."
                    .to_owned(),
            );
        }
        return (
            DeleteOutcome::Failed,
            format!(
                "the delete failed and was sent exactly once: {error}. Whether it took effect is \
                 unknown, so the binding stays tracked."
            ),
        );
    }

    match reader.get_workspace(id) {
        Err(error) if error.status() == Some(404) => (
            DeleteOutcome::Deleted,
            "OpenRouter returned 404 for the workspace after the delete, which is what proves it \
             is gone; the binding is no longer tracked."
                .to_owned(),
        ),
        Ok(_) => (
            DeleteOutcome::Unconfirmed,
            "OpenRouter accepted the delete and still returns the workspace, so it is not \
             confirmed gone; the binding stays tracked and the delete is never resent \
             automatically."
                .to_owned(),
        ),
        Err(error) => (
            DeleteOutcome::Unconfirmed,
            format!(
                "OpenRouter accepted the delete and the read that would confirm it failed: \
                 {error}. The binding stays tracked."
            ),
        ),
    }
}

// --- decommission ------------------------------------------------------------

/// Takes an address's working key out of service, and optionally deletes it.
///
/// # Errors
///
/// Returns [`LifecycleError`] for a value this command cannot use, a hash that
/// is not the address's working key, or an operation in progress anywhere; and
/// the state and API errors of the steps it performs, including
/// `missing_credential`. A disable or a deletion that could not be confirmed is
/// reported beside the result document rather than in place of it.
pub fn decommission(
    context: Context,
    name: &str,
    hash: &str,
    delete: bool,
) -> Result<Outcome<DecommissionReport>, Error> {
    let attempt = decommission_key(&context, name, hash, delete)?;
    if attempt.report.settled() {
        return Ok(Outcome::ok(attempt.report));
    }
    let failure = attempt.failure();
    Ok(Outcome::failed(attempt.report, failure))
}

/// One decommission's result document and what it would take to finish.
struct Decommissioning {
    report: DecommissionReport,
    address: Address,
    hash: KeyHash,
    /// Whether a read proved the key is out of service.
    disabled: bool,
    /// Whether `--delete` asked for the removal too.
    delete: bool,
}

impl Decommissioning {
    /// The error a run that could not prove a step exits with.
    ///
    /// Which step it stopped at decides the command an operator runs next, and
    /// they are different commands: a disable that did not take leaves the key
    /// current, so the whole decommission is repeated, while a delete that did
    /// not take leaves a retained hash that `delete key` alone can finish.
    fn failure(&self) -> LifecycleError {
        if self.disabled {
            return LifecycleError::DecommissionDeleteUnconfirmed {
                address: self.address.clone(),
                hash: self.hash.clone(),
            };
        }
        LifecycleError::DecommissionUnconfirmed {
            address: self.address.clone(),
            hash: self.hash.clone(),
            retry: retry_command(&self.address, &self.hash, self.delete),
        }
    }
}

/// Takes an address's working key out of service, and optionally deletes it.
///
/// The configuration is deliberately not loaded, as in `retire`: this ends a
/// key, and an address whose block someone already removed is exactly the case
/// that needs it most.
///
/// State moves once and only on evidence. A disable nothing proved leaves the
/// binding byte for byte as it was — the address goes on using the key it was
/// using, which is the truth — and the hash becomes retained only after a read
/// says the key cannot be used.
fn decommission_key(
    context: &Context,
    name: &str,
    hash: &str,
    delete: bool,
) -> Result<Decommissioning, Error> {
    let address = Address::parse(name).map_err(|error| argument("NAME", &error))?;
    let hash = KeyHash::parse(hash).map_err(|error| argument("--hash", &error))?;

    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let mut state = lock.read()?;

    check_nothing_pending(&state)?;
    let generation = in_service(&state, &address, &hash)?;

    let client = context.client()?;
    let (reader, writer) = (Reader::new(&client), Writer::new(&client));
    let service = take_out_of_service(&reader, &writer, &hash)?;

    let deletion = if service.confirmed {
        let retained = state
            .decommission_current(&address, &hash, RetainedStatus::Retired, now())
            .map_err(LifecycleError::Refused)?;
        lock.write(&mut state)?;
        delete
            .then(|| {
                let attempt = delete_result(&reader, &writer, &hash, service.absent);
                record_deletion(&lock, &mut state, &address, &retained, attempt)
            })
            .transpose()?
    } else {
        None
    };

    Ok(Decommissioning {
        report: DecommissionReport::new(
            &address,
            &hash,
            generation,
            Ending {
                disabled: service.confirmed,
                disable_detail: service.detail,
                deletion,
                retry: retry_command(&address, &hash, delete),
            },
        ),
        address,
        hash,
        disabled: service.confirmed,
        delete,
    })
}

/// The generation of the key the address is using, or why this may not act.
///
/// The hash has to be the current one exactly. Decommission switches off a
/// working credential, so it never searches and never infers: an operator who
/// names a hash the address does not use is told which one it does, and nothing
/// is sent.
fn in_service(state: &State, address: &Address, hash: &KeyHash) -> Result<u32, LifecycleError> {
    let Some(current) = state.key(address).and_then(KeyBinding::current) else {
        return Err(LifecycleError::DecommissionNoCurrentKey {
            address: address.clone(),
        });
    };
    if &current.hash != hash {
        return Err(LifecycleError::DecommissionNotCurrent {
            address: address.clone(),
            hash: hash.clone(),
            current: current.hash.clone(),
        });
    }
    Ok(current.generation)
}

/// Refuses a decommission while any address has an operation in progress.
///
/// Global, like the rule it protects: an unresolved attempt may have made a live
/// key nobody can name, and a rotation halfway through would promote its
/// successor into the slot this command empties. The phase is read through
/// [`Resolution`], so this refusal names the same command as every other one.
fn check_nothing_pending(state: &State) -> Result<(), LifecycleError> {
    let Some((blocking, pending)) = state.pending_operation() else {
        return Ok(());
    };
    Err(LifecycleError::DecommissionPending {
        blocking: blocking.clone(),
        phase: pending.phase,
        resolution: Resolution::of(pending.phase).instruction(blocking),
    })
}

/// Establishes that the key cannot be used, sending a disable only if one is
/// needed.
///
/// Three answers count, and a read establishes each: OpenRouter already has the
/// key disabled, Keymaster disabled it and the read that followed said so, or
/// OpenRouter has no such key at all. The last is the same evidence
/// `delete key` requires before it drops a hash — a confirmed 404 is the only
/// thing that proves absence — so a current key someone already removed in the
/// dashboard can be finished here rather than leaving the address stuck.
fn take_out_of_service(
    reader: &Reader<'_>,
    writer: &Writer<'_>,
    hash: &KeyHash,
) -> Result<Disabled, ApiError> {
    match reader.get_key(hash) {
        Ok(observed) if observed.disabled => Ok(Disabled::already_disabled()),
        Ok(_) => Ok(disable_and_confirm(reader, writer, hash)),
        Err(error) if error.status() == Some(404) => Ok(Disabled::absent(
            "OpenRouter has no such key, which is what proves it cannot be used; nothing was sent."
                .to_owned(),
        )),
        Err(error) => Err(error),
    }
}

/// What deleting a key already out of service establishes.
///
/// A run whose read already returned 404 sends nothing at all. A `DELETE` is
/// sent to establish that OpenRouter does not have the key, and that answer is
/// already in hand; sending one anyway could only lose it, because a refusal or
/// a timeout on a request nothing needed would turn a key known to be gone into
/// one that may still exist and has to stay tracked.
fn delete_result(
    reader: &Reader<'_>,
    writer: &Writer<'_>,
    hash: &KeyHash,
    known_absent: bool,
) -> (DeleteOutcome, String) {
    if known_absent {
        return (
            DeleteOutcome::AlreadyAbsent,
            "OpenRouter had no such key when this run read it, so there was nothing to delete and \
             no request was sent; the hash is no longer tracked."
                .to_owned(),
        );
    }
    attempt_delete(reader, writer, hash)
}

/// Records what became of the key, and stops tracking it only once OpenRouter
/// is known not to have it.
///
/// The same order `delete key` keeps, for the same reason: a hash that may
/// still name a live spending credential stays in state, here as
/// `retirement_failed`, which is exactly the shape `delete key --hash` picks up.
fn record_deletion(
    lock: &StateLock<'_>,
    state: &mut State,
    address: &Address,
    retained: &RetainedKey,
    (outcome, detail): (DeleteOutcome, String),
) -> Result<DeleteAttempt, Error> {
    if outcome.is_gone() {
        state
            .drop_retained(address, &retained.hash)
            .map_err(LifecycleError::Refused)?;
        lock.write(state)?;
    } else {
        record_status(
            lock,
            state,
            address,
            retained,
            RetainedStatus::RetirementFailed,
        )?;
    }
    Ok(DeleteAttempt { outcome, detail })
}

/// The exact command that repeats a decommission this run could not prove.
fn retry_command(address: &Address, hash: &KeyHash, delete: bool) -> String {
    let flag = if delete { " --delete" } else { "" };
    format!("openrouter-keymaster decommission {address} --hash {hash}{flag}")
}

// --- state forget ----------------------------------------------------------------

/// Relinquishes local ownership of everything an address is bound to.
///
/// Needs no credential, no network, and no configuration: it exists to correct
/// state that is wrong, which is when those may all be unavailable.
///
/// # Errors
///
/// Returns [`LifecycleError`] for an address this command cannot use, an
/// ambiguous bare address, or an address with an operation in progress; and the
/// state errors of writing the file.
pub fn forget(context: Context, address: &str) -> Result<Outcome<ForgetReport>, Error> {
    Ok(Outcome::ok(forget_address(&context, address)?))
}

/// Which bindings an operator's address names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// `keys.NAME`.
    Key(Address),
    /// `guardrails.NAME`.
    Guardrail(Address),
    /// `workspaces.NAME`.
    Workspace(Address),
    /// A bare `NAME`, which is whichever of the three is bound.
    Either(Address),
}

/// Removes a binding, writing nothing anywhere else.
///
/// No client is built and no configuration is read. Forget is the command for
/// state that is wrong — a binding to a resource someone deleted in the
/// dashboard, a key another system has taken over — so it must work when the
/// credential is gone, the network is unreachable, and the configuration no
/// longer parses.
fn forget_address(context: &Context, address: &str) -> Result<ForgetReport, Error> {
    let target = parse_target(address)?;

    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let mut state = lock.read()?;

    let (kind, local) = resolve(&state, &target)?;
    let Some(kind) = kind else {
        // Nothing is bound there. A repeated forget is a clear no-op rather than
        // an error: an operator re-running a documented command should not have
        // to wonder whether the first run took.
        return Ok(ForgetReport::nothing(address));
    };

    let released = release(&mut state, kind, local)?;
    lock.write(&mut state)?;
    Ok(ForgetReport::released(
        address,
        kind.as_str(),
        local,
        released,
    ))
}

/// Which of the two maps a `forget` acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resource {
    Key,
    Guardrail,
    Workspace,
}

impl Resource {
    /// The spelling used in output.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Guardrail => "guardrail",
            Self::Workspace => "workspace",
        }
    }
}

/// Splits `keys.NAME` and `guardrails.NAME` from a bare address.
///
/// A local address names a resource within its kind, so the same word can be a
/// key and a guardrail. The qualified spellings are the ones every report and
/// diagnostic prints, so they are the ones this accepts; a bare name is allowed
/// because it is what an operator types, and it is resolved only when it is
/// unambiguous.
fn parse_target(value: &str) -> Result<Target, LifecycleError> {
    if let Some(name) = value.strip_prefix("keys.") {
        return Ok(Target::Key(local_address(name)?));
    }
    if let Some(name) = value.strip_prefix("guardrails.") {
        return Ok(Target::Guardrail(local_address(name)?));
    }
    if let Some(name) = value.strip_prefix("workspaces.") {
        return Ok(Target::Workspace(local_address(name)?));
    }
    Ok(Target::Either(local_address(value)?))
}

/// Which binding the target names, and the address it names it at.
fn resolve<'a>(
    state: &State,
    target: &'a Target,
) -> Result<(Option<Resource>, &'a Address), LifecycleError> {
    match target {
        Target::Key(address) => Ok((state.key(address).map(|_| Resource::Key), address)),
        Target::Guardrail(address) => Ok((
            state.guardrail(address).map(|_| Resource::Guardrail),
            address,
        )),
        Target::Workspace(address) => Ok((
            state.workspace(address).map(|_| Resource::Workspace),
            address,
        )),
        Target::Either(address) => {
            let bound: Vec<Resource> = [
                state.key(address).map(|_| Resource::Key),
                state.guardrail(address).map(|_| Resource::Guardrail),
                state.workspace(address).map(|_| Resource::Workspace),
            ]
            .into_iter()
            .flatten()
            .collect();
            match bound.as_slice() {
                [] => Ok((None, address)),
                [only] => Ok((Some(*only), address)),
                several => Err(LifecycleError::ForgetAmbiguous {
                    address: address.clone(),
                    kinds: several.iter().map(|kind| kind.as_str()).collect(),
                }),
            }
        }
    }
}

/// Removes the binding and lists every remote identity it released.
fn release(
    state: &mut State,
    kind: Resource,
    address: &Address,
) -> Result<Vec<Released>, LifecycleError> {
    match kind {
        Resource::Guardrail => Ok(state
            .forget_guardrail(address)
            .map(|binding| vec![Released::guardrail(&binding.id, binding.origin)])
            .unwrap_or_default()),
        Resource::Workspace => {
            let Some(binding) = state.forget_workspace(address) else {
                return Ok(Vec::new());
            };
            let mut released = vec![Released::workspace(&binding.id, binding.origin)];
            // The workspace's default guardrail goes with it, wherever it is
            // bound: it cannot outlive the workspace, and nothing else can
            // reach it (ADR-0004, item 1).
            if let Some(default) = &binding.default_guardrail_id
                && let Some(guardrail) = state.address_owning_guardrail(default).cloned()
                && let Some(guardrail) = state.forget_guardrail(&guardrail)
            {
                released.push(Released::guardrail(&guardrail.id, guardrail.origin));
            }
            Ok(released)
        }
        Resource::Key => {
            let binding = state.forget_key(address).map_err(|error| match error {
                TransitionError::AlreadyPending { phase, .. } => LifecycleError::ForgetPending {
                    address: address.clone(),
                    phase,
                    resolution: Resolution::of(phase).instruction(address),
                },
                other => LifecycleError::Refused(other),
            })?;
            Ok(binding.as_ref().map(released_keys).unwrap_or_default())
        }
    }
}

/// Every hash a forgotten key binding held, in the order an operator reads
/// them: the working key first, then everything it still retained.
fn released_keys(binding: &KeyBinding) -> Vec<Released> {
    binding
        .current()
        .map(|current| Released::current(&current.hash, current.generation))
        .into_iter()
        .chain(binding.retained().iter().map(Released::retained))
        .collect()
}

// --- shared -----------------------------------------------------------------

/// Parses the local address an operator typed.
fn local_address(value: &str) -> Result<Address, LifecycleError> {
    Address::parse(value).map_err(|error| argument("ADDRESS", &error))
}

/// Reports a command-line value this command cannot use.
fn argument(value: &'static str, error: &IdError) -> LifecycleError {
    LifecycleError::Argument {
        value,
        message: error.to_string(),
    }
}

/// Turns a confirmed 404 into "there is no such key", and nothing else into it.
fn absent_or(error: ApiError, hash: &KeyHash) -> Error {
    if error.status() == Some(404) {
        return LifecycleError::Absent { hash: hash.clone() }.into();
    }
    error.into()
}

/// When a status was recorded. The only clock this module reads.
fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Why an explicit end-of-life command could not be performed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LifecycleError {
    /// A command-line value is not the kind of identifier it names.
    #[error("`{value}` is not usable: {message}")]
    Argument {
        /// Which value: `NAME`, `--hash`, or `ADDRESS`.
        value: &'static str,
        /// Why it was rejected. Never repeats the value.
        message: String,
    },

    /// The address owns nothing at all.
    #[error("`{address}` owns no key, so there is nothing tracked there to retire")]
    NotBound {
        /// The local address.
        address: Address,
    },

    /// The hash named is the address's working key.
    #[error(
        "key {hash} is what `{address}` currently uses, and neither `retire` nor `delete key` will \
         touch a working credential: neither can know that nothing is still using it. Rotate first \
         with `openrouter-keymaster rotate {address}`, which stages a successor and leaves this \
         key enabled as the predecessor, then retire the predecessor once every consumer holds the \
         new key. If this key is meant to end with no successor, say so explicitly: \
         `openrouter-keymaster decommission {address} --hash {hash}`, which leaves the address \
         owning no key."
    )]
    KeyInUse {
        /// The local address.
        address: Address,
        /// The hash that was named.
        hash: KeyHash,
    },

    /// The hash named belongs to an unfinished operation.
    #[error(
        "key {hash} belongs to the operation in progress at `{address}`, in phase `{phase}`. \
         Close that first: {resolution}. Whichever way it goes, the hash stays tracked."
    )]
    KeyUnderOperation {
        /// The local address.
        address: Address,
        /// The hash that was named.
        hash: KeyHash,
        /// The phase the operation is in.
        phase: Phase,
        /// The command that clears it, from [`Resolution`].
        resolution: String,
    },

    /// The address does not retain the hash named.
    #[error(
        "`{address}` does not retain key {hash}; `openrouter-keymaster status` lists the hashes it \
         holds. A retirement names an exact immutable identity, and Keymaster will not search for \
         one."
    )]
    NotRetained {
        /// The local address.
        address: Address,
        /// The hash that was named.
        hash: KeyHash,
    },

    /// No local address owns the hash named.
    #[error(
        "no local address tracks key {hash}, so Keymaster will not delete it. A key it does not \
         own belongs to whoever made it; `openrouter-keymaster plan` reports such keys as \
         unmanaged, and `openrouter-keymaster import key NAME --hash {hash}` is how one becomes \
         Keymaster's."
    )]
    Untracked {
        /// The hash that was named.
        hash: KeyHash,
    },

    /// OpenRouter has no such key, so there is nothing to disable.
    #[error(
        "OpenRouter has no key {hash}, so there is nothing to disable and state is unchanged. If \
         the key is genuinely gone, `openrouter-keymaster delete key --hash {hash}` confirms that \
         and stops tracking it."
    )]
    Absent {
        /// The hash that was looked up.
        hash: KeyHash,
    },

    /// The disable did not take, or could not be proved to have taken.
    #[error(
        "key {hash} at `{address}` is not confirmed disabled; it stays tracked as \
         `retirement_failed` so it can be retried, and the result document says what the attempt \
         established. Disable it yourself if this persists."
    )]
    RetireUnconfirmed {
        /// The local address.
        address: Address,
        /// The hash that was named.
        hash: KeyHash,
    },

    /// The delete did not take, or could not be proved to have taken.
    #[error(
        "key {hash} is not confirmed deleted, so it stays tracked; the request was sent exactly \
         once and is never resent automatically. The result document says what the attempt \
         established."
    )]
    DeleteUnconfirmed {
        /// The hash that was named.
        hash: KeyHash,
    },

    /// The address is using no key, so there is nothing to decommission.
    #[error(
        "`{address}` is using no key, so there is nothing to decommission; \
         `openrouter-keymaster status` lists what it holds. A key it merely retains is ended with \
         `openrouter-keymaster retire {address} --hash HASH` and `openrouter-keymaster delete key \
         --hash HASH`."
    )]
    DecommissionNoCurrentKey {
        /// The local address.
        address: Address,
    },

    /// The hash named is not the address's working key.
    #[error(
        "`{address}` is not using key {hash}; the key it uses is {current}. Decommission switches \
         off a working credential, so it acts on the exact immutable identity you name and never \
         searches for one. If {hash} is a hash this address retains, `openrouter-keymaster retire \
         {address} --hash {hash}` disables it."
    )]
    DecommissionNotCurrent {
        /// The local address.
        address: Address,
        /// The hash that was named.
        hash: KeyHash,
        /// The hash the address is actually using.
        current: KeyHash,
    },

    /// An unfinished operation stands, so no key may be taken out of service.
    #[error(
        "`{blocking}` has an operation in progress, in phase `{phase}`, and decommissioning \
         beside one would switch off a credential while another is being created. Close it first: \
         {resolution}. Nothing was disabled and nothing was deleted."
    )]
    DecommissionPending {
        /// The address that holds the unfinished operation.
        blocking: Address,
        /// The phase it stopped in.
        phase: Phase,
        /// The command that clears it, from [`Resolution`].
        resolution: String,
    },

    /// The disable did not take, or could not be proved to have taken.
    #[error(
        "key {hash} is not confirmed out of service, so `{address}` still uses it and no state \
         was written; the disable was sent at most once and is never retried automatically. Run \
         `{retry}` again, or disable the key yourself. The result document says what the attempt \
         established."
    )]
    DecommissionUnconfirmed {
        /// The local address.
        address: Address,
        /// The hash that was named.
        hash: KeyHash,
        /// The exact command that repeats the attempt.
        retry: String,
    },

    /// The key is out of service and the deletion asked for is not confirmed.
    #[error(
        "key {hash} is out of service and `{address}` no longer uses it, but it is not confirmed \
         deleted, so the hash stays tracked as `retirement_failed`; the request was sent exactly \
         once and is never resent automatically. Finish it with `openrouter-keymaster delete key \
         --hash {hash}`."
    )]
    DecommissionDeleteUnconfirmed {
        /// The local address.
        address: Address,
        /// The hash that was named.
        hash: KeyHash,
    },

    /// A bare address is bound as more than one kind of resource.
    #[error(
        "`{address}` is bound as more than one kind of resource ({kinds}), so it is not clear \
         which to forget; say `keys.{address}`, `guardrails.{address}`, or `workspaces.{address}`",
        kinds = kinds.join(", ")
    )]
    ForgetAmbiguous {
        /// The local address.
        address: Address,
        /// The kinds that are bound there.
        kinds: Vec<&'static str>,
    },

    /// The address has an operation in progress.
    #[error(
        "`{address}` has an operation in progress, in phase `{phase}`, and forgetting it would \
         destroy the only record that the attempt happened — including, in the create phases, \
         the only evidence that a live key may exist. Close it first: {resolution}."
    )]
    ForgetPending {
        /// The local address.
        address: Address,
        /// The phase the operation is in.
        phase: Phase,
        /// The command that clears it, from [`Resolution`].
        resolution: String,
    },

    /// No local address owns the workspace named.
    #[error(
        "no local address tracks workspace {id}, so Keymaster will not delete it. A workspace it \
         does not own belongs to whoever made it; `openrouter-keymaster import workspace NAME \
         --id {id}` is how one becomes Keymaster's."
    )]
    WorkspaceUntracked {
        /// The UUID that was named.
        id: Uuid,
    },

    /// The workspace still holds resources, so deleting it would destroy them.
    #[error(
        "workspace {id} at `{address}` still holds {count}, and deleting a workspace permanently \
         deletes what is in it — tracked or not. Remove {them} first: {children}. Only the \
         workspace's own default guardrail is exempt, because it cannot outlive the workspace or \
         be deleted on its own.",
        count = crate::report::plural(children.len(), "resource"),
        them = if children.len() == 1 { "it" } else { "them" },
        children = children.join(", "),
    )]
    WorkspaceInhabited {
        /// The local address.
        address: Address,
        /// The UUID that was named.
        id: Uuid,
        /// What OpenRouter shows the workspace holding.
        children: Vec<String>,
    },

    /// The workspace delete did not take, or could not be proved to have taken.
    #[error(
        "workspace {id} is not confirmed deleted, so it stays tracked; the request was sent \
         exactly once and is never resent automatically. The result document says what the \
         attempt established."
    )]
    WorkspaceDeleteUnconfirmed {
        /// The UUID that was named.
        id: Uuid,
    },

    /// The state API refused the change.
    #[error(transparent)]
    Refused(#[from] TransitionError),
}

impl LifecycleError {
    /// A stable machine-readable category.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Argument { .. } => "lifecycle_argument",
            Self::NotBound { .. } => "retire_not_bound",
            Self::KeyInUse { .. } => "lifecycle_key_in_use",
            Self::KeyUnderOperation { .. } => "lifecycle_key_under_operation",
            Self::NotRetained { .. } => "retire_not_retained",
            Self::Untracked { .. } => "delete_untracked",
            Self::Absent { .. } => "retire_absent",
            Self::RetireUnconfirmed { .. } => "retire_unconfirmed",
            Self::DeleteUnconfirmed { .. } => "delete_unconfirmed",
            Self::DecommissionNoCurrentKey { .. } => "decommission_no_current_key",
            Self::DecommissionNotCurrent { .. } => "decommission_not_current",
            Self::DecommissionPending { .. } => "decommission_pending",
            Self::DecommissionUnconfirmed { .. } => "decommission_unconfirmed",
            Self::DecommissionDeleteUnconfirmed { .. } => "decommission_delete_unconfirmed",
            Self::WorkspaceUntracked { .. } => "delete_workspace_untracked",
            Self::WorkspaceInhabited { .. } => "delete_workspace_inhabited",
            Self::WorkspaceDeleteUnconfirmed { .. } => "delete_workspace_unconfirmed",
            Self::ForgetAmbiguous { .. } => "forget_ambiguous",
            Self::ForgetPending { .. } => "forget_pending",
            Self::Refused(_) => "lifecycle_refused",
        }
    }
}
