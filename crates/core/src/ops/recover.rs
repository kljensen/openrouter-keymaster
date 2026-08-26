//! `openrouter-keymaster recover`: looking at an unfinished operation, and closing it.
//!
//! An operation reaches these commands because something Keymaster did had no
//! answer. A create request whose response was lost, a receiver that never
//! acknowledged, a run that died between two journal entries — in every case
//! the journal records what was *attempted* and nothing about what happened.
//! ADR-0002 makes that gap an operator's to close, and this module is the only
//! way to close it.
//!
//! # Three commands, one rule
//!
//! Keymaster never decides what happened. `inspect` reads and reports;
//! `resolve` records what an operator says they found; `replace` acts on an
//! outcome that is already established. Nothing here adopts a remote key
//! because its name matches, sends a second `POST /keys` to find out, or
//! invokes a receiver again to see whether it works this time.
//!
//! # What a candidate is, and is not
//!
//! `inspect` lists remote keys that could be the one a lost create made. They
//! are possibilities. A display name is mutable and not unique (ADR-0001), and
//! a creation timestamp near an attempt is a coincidence as easily as a
//! consequence, so the listing exists to save an operator a search — not to
//! make a choice. Binding one is an explicit act: `--leaked-hash HASH`, by
//! immutable identity, exactly like `import`.
//!
//! # A found hash is not a recovered key
//!
//! OpenRouter discloses a key's plaintext once, in the create response. A hash
//! an operator supplies identifies a key for cleanup and can never recover its
//! secret, so it is bound as a *failed candidate*: tracked, disabled where
//! possible, never promoted, and never delivered. The address gets a working
//! key the only way there is — a new one.
//!
//! # Delivery ambiguity has no attestation
//!
//! When a receiver's acknowledgement is lost, the receiver may hold the secret
//! and may not. ADR-0002 allows that to be resolved as delivered only through a
//! receiver-specific idempotency or query contract — one that accepts the
//! operation ID and can be asked authoritatively whether it committed. **v0.1
//! defines no such contract**, so there is deliberately no
//! `resolve --delivered` flag: the only resolution is `recover replace`, which
//! creates a successor and delivers it. That costs a rotation even when the
//! original delivery in fact succeeded, and that cost is the honest one.

use time::OffsetDateTime;

use crate::api::{ObservedKey, Reader, Writer};
use crate::client::ApiError;
use crate::config::Config;
use crate::error::Error;
use crate::ids::{Address, IdError, KeyHash};
use crate::report::{
    CandidateReport, InspectReport, ReplaceReport, ResolveReport, RetainedReport, Retired,
    Successor, created_near,
};
use crate::state::{
    KeyBinding, PendingOperation, Phase, RetainedKey, RetainedStatus, State, StateFile, StateLock,
    TransitionError,
};

use super::issuance::{Disabled, Issuer, disable_and_confirm};
use super::{Context, Outcome};

/// What an operator found about an ambiguous create.
///
/// Two findings and no third state: Keymaster never guesses which happened, and
/// a caller that cannot say has nothing to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// OpenRouter holds no key from the attempt. Keymaster cannot verify this;
    /// it is the operator's word.
    NoResourceCreated,
    /// This exact hash is the key the attempt made, found by an operator.
    LeakedHash(String),
}

// --- inspect ----------------------------------------------------------------

/// Reports one unfinished operation and the remote keys that could belong to
/// it.
///
/// Read-only in the strongest sense: no lock, no state write, and no remote
/// write. State is read the way `plan` reads it, because observing OpenRouter
/// is not a reason to rewrite a journal.
///
/// It reaches the network only when there is something to search for. Every
/// fact this reports comes from the journal; the candidate listing is the sole
/// exception, and it is meaningless once the journal records a hash. Asking for
/// one anyway would make the command that explains a broken operation require a
/// management credential and a reachable API — precisely when an operator may
/// have neither and needs the report most.
///
/// # Errors
///
/// Returns [`RecoverError`] for an address this command cannot use, and the
/// state and API errors of the steps it performs. It needs a credential only
/// when there is something to search for, so an operation whose hash the
/// journal records is reported with none.
pub fn recover_inspect(context: Context, name: &str) -> Result<Outcome<InspectReport>, Error> {
    let address = local_address(name)?;
    let state = StateFile::new(&context.paths.state).read()?;

    let Some(operation) = pending_at(&state, &address) else {
        return Ok(Outcome::ok(InspectReport::settled(&address)));
    };
    if !existence_unknown(operation.phase) {
        return Ok(Outcome::ok(InspectReport::found(
            &address,
            operation,
            Vec::new(),
        )));
    }

    // A fresh snapshot, every time. A candidate listing computed from anything
    // older would be describing an organization that has since changed, which
    // is the one thing an operator must not be handed here.
    let client = context.client()?;
    let observed = Reader::new(&client).list_keys(None)?;

    let candidates = candidates(&state, operation, &observed);
    Ok(Outcome::ok(InspectReport::found(
        &address, operation, candidates,
    )))
}

/// Whether the journal leaves it unknown that a key exists at all.
///
/// The two create phases and no others: past them the create response arrived
/// and its hash is recorded, so nothing about the key's existence is in
/// question. This is what decides whether there is anything to search
/// OpenRouter for, and whether an operator has a leaked hash to attest.
const fn existence_unknown(phase: Phase) -> bool {
    matches!(phase, Phase::CreateStarted | Phase::CreateAmbiguous)
}

/// The remote keys worth showing an operator, and why each one is shown.
///
/// Three filters, in the order they matter. A key some local address already
/// owns is not a stray — it is something Keymaster is already managing, and
/// offering it would invite an operator to bind one remote key to two
/// addresses. A key in a workspace the attempt did not name cannot be the one
/// the attempt made. What is left is shown when it carries the intended name or
/// was created near the attempt; the two are reported separately, because one
/// of them is a much weaker signal than the other and an operator should be
/// able to tell which they are looking at.
fn candidates(
    state: &State,
    operation: &PendingOperation,
    observed: &[ObservedKey],
) -> Vec<CandidateReport> {
    // Past the two create phases the journal already records the hash, so there
    // is nothing to search for and a listing would only invite a second guess.
    // `inspect` checks this before it builds a client; the guard is repeated
    // here so the function is correct on its own terms rather than because of
    // its one caller.
    if !existence_unknown(operation.phase) {
        return Vec::new();
    }

    observed
        .iter()
        .filter(|key| state.address_owning(&key.hash).is_none())
        .filter(|key| {
            operation
                .workspace
                .as_ref()
                .is_none_or(|workspace| key.workspace_id.as_ref() == Some(workspace))
        })
        .filter_map(|key| {
            let mut matched = Vec::new();
            if key.name.trim() == operation.name.as_str() {
                matched.push("carries the intended name");
            }
            if created_near(key.timestamps.created_at, operation.phase_at) {
                matched.push("was created near the attempt");
            }
            (!matched.is_empty()).then(|| CandidateReport::new(key, matched))
        })
        .collect()
}

// --- resolve ----------------------------------------------------------------

/// Records what an operator found about an ambiguous create.
///
/// # Errors
///
/// Returns [`RecoverError`] for a value or a phase this command cannot act on,
/// and the state and API errors of the steps it performs, including
/// `missing_credential`.
pub fn recover_resolve(
    context: Context,
    name: &str,
    finding: &Finding,
) -> Result<Outcome<ResolveReport>, Error> {
    let address = local_address(name)?;
    let report = match finding {
        Finding::LeakedHash(hash) => resolve_leaked(&context, &address, hash),
        Finding::NoResourceCreated => resolve_absence(&context, &address),
    }?;
    Ok(Outcome::ok(report))
}

/// Clears an ambiguous create on an operator's word that no key was made.
fn resolve_absence(context: &Context, address: &Address) -> Result<ResolveReport, Error> {
    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let mut state = lock.read()?;

    // Repeating a resolution that already succeeded is a clear no-op, not an
    // error: an operator re-running a documented command should not have to
    // wonder whether the first run took.
    let Some(operation) = pending_at(&state, address).cloned() else {
        return Ok(ResolveReport::settled(address, "no_resource_created"));
    };

    state
        .clear_ambiguous_create(address)
        .map_err(RecoverError::Refused)?;
    lock.write(&mut state)?;

    Ok(ResolveReport::absence(address, &operation))
}

/// Binds the exact key an operator found, then tries to make it harmless.
///
/// The order is the safety argument. The hash is fetched by immutable identity
/// — never a name lookup — so a key that is not there leaves state untouched;
/// it is then recorded as a failed candidate *before* any cleanup, so a disable
/// that fails, or a run that dies attempting one, still leaves the key tracked.
fn resolve_leaked(
    context: &Context,
    address: &Address,
    hash: &str,
) -> Result<ResolveReport, Error> {
    let hash = KeyHash::parse(hash).map_err(|error| argument("--leaked-hash", &error))?;

    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let mut state = lock.read()?;

    let Some(operation) = pending_at(&state, address).cloned() else {
        return Ok(ResolveReport::settled(address, "leaked_hash"));
    };
    if !existence_unknown(operation.phase) {
        return Err(RecoverError::HashAlreadyKnown {
            address: address.clone(),
            phase: operation.phase,
        }
        .into());
    }

    let client = context.client()?;
    let (reader, writer) = (Reader::new(&client), Writer::new(&client));
    reader
        .get_key(&hash)
        .map_err(|error| absent_or(error, &hash))?;

    let retained = state
        .retain_leaked_candidate(address, hash.clone(), now())
        .map_err(RecoverError::Refused)?;
    lock.write(&mut state)?;

    let cleanup = clean_up(&reader, &writer, &lock, &mut state, address, &retained)?;
    Ok(ResolveReport::leaked(
        address,
        &operation,
        cleanup.report,
        cleanup.detail,
    ))
}

// --- replace ----------------------------------------------------------------

/// Retires a dead operation and stages a successor, under one lock.
///
/// "Dead" is precise: the journal records a hash, so a key definitely exists,
/// and it is past the create response, so its plaintext existed only in memory
/// and is gone. Nothing an operator can discover changes either fact, which is
/// why this needs no attestation — and why the two phases where a key's
/// existence is still *unknown* are refused. Resolve those first.
///
/// # Errors
///
/// Returns [`RecoverError`] for an address or a phase this command cannot act
/// on, and the configuration, state, and API errors of the steps it performs,
/// including `missing_credential`.
pub fn recover_replace(context: Context, name: &str) -> Result<Outcome<ReplaceReport>, Error> {
    let address = local_address(name)?;

    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let config = Config::load(&context.paths.config)?;
    let mut state = lock.read()?;

    let operation =
        pending_at(&state, &address)
            .cloned()
            .ok_or_else(|| RecoverError::NothingToReplace {
                address: address.clone(),
            })?;
    check_replaceable(&address, operation.phase)?;

    let client = context.client()?;
    let (reader, writer) = (Reader::new(&client), Writer::new(&client));
    let issuer = Issuer {
        config: &config,
        client: &client,
        reader: &reader,
        writer: &writer,
        lock: &lock,
    };

    // Everything the successor needs is checked before anything is closed or
    // disabled, and this is the step that makes the ordering matter. The key
    // about to be retired may be a live credential — `created` means its
    // restrictions were never even verified — and disabling it is an outage for
    // whoever holds it. Doing that first and only then discovering that the
    // configuration names no receiver, or that the guardrail has drifted, would
    // leave the address with a disabled key and nothing to replace it. The
    // preflight writes nothing and sends no write, so a failure here costs a
    // read and changes not one thing.
    let prepared =
        issuer
            .preflight(&address, &state)
            .map_err(|message| RecoverError::Unstageable {
                address: address.clone(),
                message,
            })?;

    // Retired before anything is disabled and before anything is created: the
    // hash moves from an operation nobody can finish to a retained entry an
    // explicit `retire` or `delete` can reach, and at no point is it a live key
    // that state does not name.
    let dead = state
        .retire_candidate(&address, now())
        .map_err(RecoverError::Refused)?;
    lock.write(&mut state)?;
    let cleanup = clean_up(&reader, &writer, &lock, &mut state, &address, &dead)?;

    let issued = issuer
        .issue_prepared(&address, &mut state, prepared, now())
        .map_err(|message| RecoverError::Issuance { message })?;

    Ok(Outcome::ok(ReplaceReport::new(
        &address,
        Retired {
            operation: operation.id.as_str().to_owned(),
            key: cleanup.report,
            cleanup: cleanup.detail,
        },
        Successor {
            operation: issued.operation.as_str().to_owned(),
            hash: issued.hash.as_str().to_owned(),
            generation: issued.generation,
            receiver: issued.receiver,
            promoted: issued.promoted,
        },
    )))
}

/// Refuses a replacement for an operation whose outcome is not settled yet.
fn check_replaceable(address: &Address, phase: Phase) -> Result<(), RecoverError> {
    match phase {
        // A key exists and can never be delivered. Nothing to establish.
        Phase::Created | Phase::Secured | Phase::DeliveryStarted | Phase::DeliveryAmbiguous => {
            Ok(())
        }
        // Whether a key exists at all is unknown. Replacing now would leave a
        // possible live credential that nothing tracks, which is exactly the
        // outcome ADR-0002's recovery exists to prevent.
        Phase::CreateStarted | Phase::CreateAmbiguous => Err(RecoverError::AmbiguityUnresolved {
            address: address.clone(),
            phase,
        }),
        // The transaction finished. Promotion is local, and apply does it.
        Phase::Delivered => Err(RecoverError::AlreadyDelivered {
            address: address.clone(),
        }),
    }
}

// --- shared -----------------------------------------------------------------

/// A retained hash and what became of the attempt to disable it.
struct CleanedUp {
    report: RetainedReport,
    detail: String,
}

/// Disables a retained key, confirms it by reading it back, and records the
/// result.
///
/// A confirmed disable moves the entry to `retired`; anything else leaves it a
/// failed candidate, which is what keeps it visible to a later explicit
/// `retire` or `delete`. Neither outcome stops the caller: a key that could not
/// be disabled is a problem to report, not a reason to leave an address without
/// a working credential.
fn clean_up(
    reader: &Reader<'_>,
    writer: &Writer<'_>,
    lock: &StateLock<'_>,
    state: &mut State,
    address: &Address,
    retained: &RetainedKey,
) -> Result<CleanedUp, Error> {
    let Disabled {
        confirmed, detail, ..
    } = disable_and_confirm(reader, writer, &retained.hash);
    let mut status = retained.status;

    if confirmed {
        status = RetainedStatus::Retired;
        state
            .set_retained_status(address, &retained.hash, status, now())
            .map_err(RecoverError::Refused)?;
        lock.write(state)?;
    }
    Ok(CleanedUp {
        report: RetainedReport::new(&retained.hash, retained.generation, status),
        detail,
    })
}

/// The operation an address has in progress, if it has one.
fn pending_at<'a>(state: &'a State, address: &Address) -> Option<&'a PendingOperation> {
    state.key(address).and_then(KeyBinding::pending)
}

/// Parses the local address an operator typed.
fn local_address(name: &str) -> Result<Address, RecoverError> {
    Address::parse(name).map_err(|error| argument("NAME", &error))
}

/// Reports a command-line value this command cannot use.
fn argument(value: &'static str, error: &IdError) -> RecoverError {
    RecoverError::Argument {
        value,
        message: error.to_string(),
    }
}

/// Turns a confirmed 404 into "there is no such key", and nothing else into it.
///
/// Only a 404 proves absence. Reporting any other failure as absence would tell
/// an operator that the key they are looking at in the dashboard is not there.
fn absent_or(error: ApiError, hash: &KeyHash) -> Error {
    if error.status() == Some(404) {
        return RecoverError::Absent { hash: hash.clone() }.into();
    }
    error.into()
}

/// When a resolution was recorded. The only clock this module reads.
fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Why a recovery could not be performed.
#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    /// A command-line value is not the kind of identifier it names.
    #[error("`{value}` is not usable: {message}")]
    Argument {
        /// Which value: `NAME` or `--leaked-hash`.
        value: &'static str,
        /// Why it was rejected. Never repeats the value.
        message: String,
    },

    /// Neither finding was given.
    ///
    /// An `ops` caller cannot produce this — [`Finding`] has no such state —
    /// but a command line can be handed it, and guessing which the operator
    /// meant is precisely what this command exists not to do.
    #[error(
        "say what you found: `--no-resource-created` if OpenRouter holds no key from the \
         attempt, or `--leaked-hash HASH` if it does. Keymaster does not guess which."
    )]
    NoFinding,

    /// A leaked hash was offered for an operation that already records one.
    #[error(
        "`{address}` is in phase `{phase}`, where the create response already recorded the key's \
         hash, so there is no leaked key to bind. Replace it with `openrouter-keymaster recover \
         replace {address}`."
    )]
    HashAlreadyKnown {
        /// The local address.
        address: Address,
        /// The phase the operation is in.
        phase: Phase,
    },

    /// OpenRouter has no such key.
    #[error(
        "OpenRouter has no key {hash}; nothing was bound and state is unchanged. Check the hash, \
         or attest with `--no-resource-created` if the attempt created nothing."
    )]
    Absent {
        /// The hash that was looked up.
        hash: KeyHash,
    },

    /// There is no operation to replace.
    #[error(
        "`{address}` has no operation in progress, so there is nothing to replace. \
         `openrouter-keymaster rotate {address}` stages a successor for a key that is working."
    )]
    NothingToReplace {
        /// The local address.
        address: Address,
    },

    /// A replacement was asked for while it is still unknown whether a key
    /// exists.
    #[error(
        "`{address}` is in phase `{phase}`, so it is not yet known whether the attempt created a \
         key. Creating a successor now could leave a live credential nothing tracks. Run \
         `openrouter-keymaster recover inspect {address}`, then resolve it with \
         `openrouter-keymaster recover resolve {address}` before replacing."
    )]
    AmbiguityUnresolved {
        /// The local address.
        address: Address,
        /// The phase the operation is in.
        phase: Phase,
    },

    /// A replacement was asked for after a successful delivery.
    #[error(
        "`{address}`'s key was delivered; only its local promotion is outstanding, and the next \
         `openrouter-keymaster apply` completes that. There is nothing here to replace."
    )]
    AlreadyDelivered {
        /// The local address.
        address: Address,
    },

    /// The successor cannot be created, so nothing was retired or disabled.
    #[error(
        "`{address}` cannot be replaced: {message}. Nothing was changed — the operation still \
         stands and its key is untouched — because retiring and disabling a key before \
         discovering that its successor cannot be created would leave the address with neither."
    )]
    Unstageable {
        /// The local address.
        address: Address,
        /// The preflight's own explanation, already secret-free.
        message: String,
    },

    /// The state API refused the transition.
    #[error(transparent)]
    Refused(#[from] TransitionError),

    /// The replacement's journaled creation did not finish.
    #[error("the replacement was not created: {message}")]
    Issuance {
        /// The transaction's own explanation, already secret-free.
        message: String,
    },
}

impl RecoverError {
    /// A stable machine-readable category.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Argument { .. } => "recover_argument",
            Self::NoFinding => "recover_no_finding",
            Self::HashAlreadyKnown { .. } => "recover_hash_already_known",
            Self::Absent { .. } => "recover_absent",
            Self::NothingToReplace { .. } => "recover_nothing_to_replace",
            Self::AmbiguityUnresolved { .. } => "recover_ambiguity_unresolved",
            Self::AlreadyDelivered { .. } => "recover_already_delivered",
            Self::Unstageable { .. } => "recover_unstageable",
            Self::Refused(_) => "recover_refused",
            Self::Issuance { .. } => "recover_issuance",
        }
    }
}
