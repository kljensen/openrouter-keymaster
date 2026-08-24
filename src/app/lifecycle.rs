//! The three explicit end-of-life commands: `retire`, `delete key`, and
//! `state forget`.
//!
//! Nothing here is ever planned, proposed, or performed as a side effect of
//! something else. A predecessor left behind by a rotation stays enabled
//! forever unless an operator names it; a configuration block that disappears
//! is an orphaned binding and nothing more. Keymaster cannot know when a
//! downstream deployment stopped using a credential, so it never decides that
//! for one.
//!
//! Each command is a different kind of ending, and the difference is the point:
//!
//! - **`retire NAME --hash HASH`** makes a tracked key unusable and keeps it.
//!   The hash stays in state, visible to an audit and to a later `delete`.
//! - **`delete key --hash HASH`** removes the remote key permanently, and only
//!   then stops tracking it. The order is not negotiable: state is what makes a
//!   spending credential findable, so it is the last thing to go.
//! - **`state forget ADDRESS`** relinquishes ownership and makes no remote call
//!   at all. Nothing is disabled and nothing is deleted; Keymaster simply stops
//!   claiming the resources, which every later plan then reports as unmanaged.
//!
//! # Immutable identity, always
//!
//! Both remote mutations take a hash, never a name. A display name is mutable
//! and not unique (ADR-0001), and these are the two operations where addressing
//! the wrong key is unrecoverable. `delete key` takes no address either: the
//! hash alone identifies the key, and the address it belongs to is looked up
//! rather than asserted, so an operator cannot delete one address's key by
//! typing another address's name.
//!
//! # Only a key Keymaster tracks
//!
//! Every one of these refuses a hash no local address owns. Keymaster manages
//! what it was told to manage; a stray key in the organization belongs to
//! whoever made it, and the tool that reports it as unmanaged must not also be
//! the tool that deletes it.

use std::io::Write;

use time::OffsetDateTime;

use crate::api::{Reader, Writer};
use crate::cli::Cli;
use crate::client::{ApiError, Client};
use crate::error::Error;
use crate::ids::{Address, IdError, KeyHash};
use crate::output::Renderer;
use crate::report::{DeleteOutcome, DeleteReport, ForgetReport, Released, RetireReport};
use crate::state::{
    KeyBinding, Phase, RetainedKey, RetainedStatus, State, StateFile, StateLock, TransitionError,
};

use super::Resolution;
use super::issuance::disable_and_confirm;

// --- retire ------------------------------------------------------------------

/// Runs `retire`.
///
/// # Errors
///
/// Returns [`LifecycleError`] for a value this command cannot use, a hash the
/// address does not retain, an attempt on the current key, or a disable that
/// could not be confirmed; and the state and API errors of the steps it
/// performs.
pub(super) fn retire<O: Write, E: Write>(
    cli: &Cli,
    name: &str,
    hash: &str,
    renderer: &mut Renderer<O, E>,
) -> Result<(), Error> {
    let attempt = retire_hash(cli, name, hash)?;
    super::write(renderer, &attempt.report, attempt.report.warnings())?;
    if attempt.report.confirmed() {
        return Ok(());
    }
    Err(LifecycleError::RetireUnconfirmed {
        address: attempt.address,
        hash: attempt.hash,
    }
    .into())
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
fn retire_hash(cli: &Cli, name: &str, hash: &str) -> Result<Retirement, Error> {
    let address = Address::parse(name).map_err(|error| argument("NAME", &error))?;
    let hash = KeyHash::parse(hash).map_err(|error| argument("--hash", &error))?;

    let file = StateFile::new(&cli.state);
    let lock = file.lock()?;
    let mut state = lock.read()?;

    let retained = retirable(&state, &address, &hash)?;

    let client = Client::from_env()?;
    let (reader, writer) = (Reader::new(&client), Writer::new(&client));
    let observed = reader
        .get_key(&hash)
        .map_err(|error| absent_or(error, &hash))?;

    // A key OpenRouter already has disabled needs no write, which is what makes
    // a repeated `retire` cost one read and change nothing. The answer comes
    // from a fresh read either way: this branch and the one below establish the
    // same fact by the same means.
    let (confirmed, detail) = if observed.disabled {
        (
            true,
            "OpenRouter already has this key disabled; a read confirmed it and nothing was sent."
                .to_owned(),
        )
    } else {
        disable_and_confirm(&reader, &writer, &hash)
    };

    let status = if confirmed {
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
            confirmed,
            detail,
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

/// Runs `delete key`.
///
/// # Errors
///
/// Returns [`LifecycleError`] for a value this command cannot use, a hash no
/// local address tracks, an attempt on a key that is in use, or a deletion that
/// could not be confirmed; and the state and API errors of the steps it
/// performs.
pub(super) fn delete_key<O: Write, E: Write>(
    cli: &Cli,
    hash: &str,
    renderer: &mut Renderer<O, E>,
) -> Result<(), Error> {
    let attempt = delete_tracked_key(cli, hash)?;
    super::write(renderer, &attempt.report, attempt.report.warnings())?;
    if attempt.report.settled() {
        return Ok(());
    }
    Err(LifecycleError::DeleteUnconfirmed { hash: attempt.hash }.into())
}

/// One deletion's result document and the hash it acted on.
struct Deletion {
    report: DeleteReport,
    hash: KeyHash,
}

/// Deletes one tracked key permanently, and stops tracking it only once
/// OpenRouter says it is gone.
fn delete_tracked_key(cli: &Cli, hash: &str) -> Result<Deletion, Error> {
    let hash = KeyHash::parse(hash).map_err(|error| argument("--hash", &error))?;

    let file = StateFile::new(&cli.state);
    let lock = file.lock()?;
    let mut state = lock.read()?;

    let address = state
        .address_owning(&hash)
        .cloned()
        .ok_or_else(|| LifecycleError::Untracked { hash: hash.clone() })?;
    let retained = retirable(&state, &address, &hash)?;

    let client = Client::from_env()?;
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

// --- state forget ----------------------------------------------------------------

/// Runs `state forget`.
///
/// # Errors
///
/// Returns [`LifecycleError`] for an address this command cannot use, an
/// ambiguous bare address, or an address with an operation in progress; and the
/// state errors of writing the file.
pub(super) fn forget<O: Write, E: Write>(
    cli: &Cli,
    address: &str,
    renderer: &mut Renderer<O, E>,
) -> Result<(), Error> {
    let report = forget_address(cli, address)?;
    super::write(renderer, &report, report.warnings())
}

/// Which bindings an operator's address names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// `keys.NAME`.
    Key(Address),
    /// `guardrails.NAME`.
    Guardrail(Address),
    /// A bare `NAME`, which is whichever of the two is bound.
    Either(Address),
}

/// Removes a binding, writing nothing anywhere else.
///
/// No client is built and no configuration is read. Forget is the command for
/// state that is wrong — a binding to a resource someone deleted in the
/// dashboard, a key another system has taken over — so it must work when the
/// credential is gone, the network is unreachable, and the configuration no
/// longer parses.
fn forget_address(cli: &Cli, address: &str) -> Result<ForgetReport, Error> {
    let target = parse_target(address)?;

    let file = StateFile::new(&cli.state);
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
}

impl Resource {
    /// The spelling used in output.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Guardrail => "guardrail",
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
        Target::Either(address) => {
            let key = state.key(address).is_some();
            let guardrail = state.guardrail(address).is_some();
            match (key, guardrail) {
                (true, true) => Err(LifecycleError::ForgetAmbiguous {
                    address: address.clone(),
                }),
                (true, false) => Ok((Some(Resource::Key), address)),
                (false, true) => Ok((Some(Resource::Guardrail), address)),
                (false, false) => Ok((None, address)),
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
        "key {hash} is what `{address}` currently uses, and Keymaster will not disable or delete a \
         working credential: it cannot know that nothing is still using it. Rotate first with \
         `openrouter-keymaster rotate {address}`, which stages a successor and leaves this key \
         enabled as the predecessor, then retire the predecessor once every consumer holds the new \
         key."
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

    /// A bare address is bound as both a key and a guardrail.
    #[error(
        "`{address}` is bound as both a key and a guardrail, so it is not clear which to forget; \
         say `keys.{address}` or `guardrails.{address}`"
    )]
    ForgetAmbiguous {
        /// The local address.
        address: Address,
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
            Self::ForgetAmbiguous { .. } => "forget_ambiguous",
            Self::ForgetPending { .. } => "forget_pending",
            Self::Refused(_) => "lifecycle_refused",
        }
    }
}
