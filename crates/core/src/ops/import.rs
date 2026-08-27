//! `openrouter-keymaster import`: binding an existing remote object to a local address.
//!
//! Import is the operator's authority to say "this remote object is the one
//! that address means". Keymaster never decides that for itself: a display
//! name is mutable and not unique, so a matching name is reported as a
//! candidate and nothing more (ADR-0001). That is why this command takes an
//! immutable identity — a key hash, a guardrail UUID — and looks up exactly
//! that object rather than listing and filtering by name.
//!
//! **It makes no remote write.** It reads one object and records one binding.
//! Whatever the configuration asks for that the remote object does not already
//! have is reported as the difference a later `openrouter-keymaster apply` would
//! reconcile; nothing is reconciled here.
//!
//! The order below is the whole safety argument, and each step exists because
//! skipping it loses something:
//!
//! 1. Parse the address and the identifier. Neither reads a file, so a value
//!    this command cannot use is refused before it takes a lock or a
//!    credential.
//! 2. Take the exclusive state lock.
//! 3. Load and validate the configuration, and reload state, both under the
//!    lock. The address has to be described in the configuration — a binding
//!    whose desired state nobody wrote is a binding no plan can act on, and a
//!    key's generation comes from the configuration, so the file this records
//!    a binding from must be the one nothing can edit out from under it.
//! 4. Fetch that exact remote identity. A 404 is the end of it: state is left
//!    as it was.
//! 5. Refuse an address already bound to a different object, and refuse an
//!    object another address already owns. One remote object belongs to
//!    exactly one local address, and either violation names both addresses.
//! 6. Compare the managed fields, and report the difference.
//! 7. Record the binding and write state atomically. Repeating an import that
//!    changes nothing writes nothing.

use time::OffsetDateTime;

use crate::api::{ObservedGuardrail, Reader};
use crate::client::ApiError;
use crate::config::Config;
use crate::error::Error;
use crate::ids::{Address, IdError, KeyHash, Uuid};
use crate::plan;
use crate::report::ImportReport;
use crate::state::{BindError, KeyBinding, Origin, State, StateFile, StateLock};

use super::{Context, Outcome};

/// Binds one API key to a local address, by its immutable hash.
///
/// Makes no remote write: it reads that one key and records a binding.
///
/// # Errors
///
/// Returns [`ImportError`] for a value this command cannot use, and the
/// configuration, state, and API errors of the steps it performs, including
/// `missing_credential`. Every one of them leaves state exactly as it was.
pub fn import_key(
    context: Context,
    name: &str,
    hash: &str,
) -> Result<Outcome<ImportReport>, Error> {
    let address = local_address(name)?;
    let hash = KeyHash::parse(hash).map_err(|error| identifier("--hash", &error))?;

    // The lock first, then everything read from a file. See the module
    // documentation: the generation this records comes from the configuration,
    // so the configuration has to be the one that cannot change underneath it.
    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let config = context.config()?;
    let desired = config
        .keys
        .get(&address)
        .ok_or_else(|| ImportError::not_configured("key", &address))?;
    let mut state = lock.read()?;
    context.check_scope(&config, &state)?;

    let client = context.client()?;
    let observed = Reader::new(&client)
        .get_key(&hash)
        .map_err(|error| absent_or(error, &format!("key {hash}")))?;
    check_key_bindings(&state, &address, &hash)?;

    let workspace = plan::key_placement(&state, desired);
    let changes = plan::key_changes(desired, Some(&observed), workspace.identity());
    let bound = record(&lock, &mut state, |state| {
        state.bind_key(&address, hash.clone(), desired.generation, now())
    })?;

    Ok(Outcome::ok(ImportReport::key(
        &address,
        &hash,
        origin_of(state.key(&address).map(KeyBinding::origin)),
        &observed.name,
        &changes,
        bound,
    )))
}

/// Binds one guardrail to a local address, by its immutable UUID.
///
/// # Errors
///
/// As [`import_key`].
pub fn import_guardrail(
    context: Context,
    name: &str,
    id: &str,
) -> Result<Outcome<ImportReport>, Error> {
    let address = local_address(name)?;
    let id = Uuid::parse(id).map_err(|error| identifier("--id", &error))?;

    // As in `import_key`: the lock, then the two files the binding is derived
    // from.
    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let config = context.config()?;
    let desired = config
        .guardrails
        .get(&address)
        .ok_or_else(|| ImportError::not_configured("guardrail", &address))?;
    let mut state = lock.read()?;
    context.check_scope(&config, &state)?;

    let client = context.client()?;
    let observed = Reader::new(&client)
        .get_guardrail(&id)
        .map_err(|error| absent_or(error, &format!("guardrail {id}")))?;
    check_guardrail_bindings(&state, &address, &id)?;
    check_guardrail_workspace(&context, &config, &state, &address, desired, &observed)?;

    let changes = plan::guardrail_changes(desired, Some(&observed));
    let bound = record(&lock, &mut state, |state| {
        state.bind_guardrail(&address, id.clone(), Origin::Imported, now())
    })?;

    Ok(Outcome::ok(ImportReport::guardrail(
        &address,
        &id,
        origin_of(state.guardrail(&address).map(|binding| binding.origin)),
        &observed.name,
        &changes,
        bound,
    )))
}

/// Binds one workspace to a local address, by its immutable UUID.
///
/// Records the workspace's `default_guardrail_id` with the binding, and — when
/// the block names a `default_guardrail` — binds that guardrail block to it in
/// the same write. The default guardrail is not a resource an operator can
/// import by name: it appears in no listing until its configuration is first
/// written, and the only handle on it is the identity the workspace names
/// (ADR-0004, item 3).
///
/// # Errors
///
/// As [`import_key`].
pub fn import_workspace(
    context: Context,
    name: &str,
    id: &str,
) -> Result<Outcome<ImportReport>, Error> {
    let address = local_address(name)?;
    let id = Uuid::parse(id).map_err(|error| identifier("--id", &error))?;

    let file = StateFile::new(&context.paths.state);
    let lock = file.lock()?;
    let config = context.config()?;
    let desired = config
        .workspaces
        .get(&address)
        .ok_or_else(|| ImportError::not_configured("workspace", &address))?;
    let mut state = lock.read()?;
    context.check_scope(&config, &state)?;

    let client = context.client()?;
    let observed = Reader::new(&client)
        .get_workspace(&id)
        .map_err(|error| absent_or(error, &format!("workspace {id}")))?;
    check_workspace_bindings(&state, &address, &id)?;

    let changes = plan::workspace_changes(desired, Some(&observed));
    let default = desired.default_guardrail.clone();
    let default_id = observed.default_guardrail_id.clone();
    let bound = record(&lock, &mut state, |state| {
        state.bind_workspace(
            &address,
            id.clone(),
            default_id.clone(),
            Origin::Imported,
            now(),
        )?;
        bind_default_guardrail(
            state,
            default.as_ref(),
            default_id.as_ref(),
            Origin::Imported,
        )
    })?;

    Ok(Outcome::ok(ImportReport::workspace(
        &address,
        &id,
        origin_of(state.workspace(&address).map(|binding| binding.origin)),
        &observed.name,
        &changes,
        bound,
    )))
}

/// Binds the guardrail block a workspace names as its default to the
/// deterministic identity the workspace object carries.
///
/// Shared by `import workspace` and by apply's workspace create, because both
/// are moments a workspace binding is recorded and both have to leave the
/// default guardrail reachable. Repeating it is a no-op.
pub(super) fn bind_default_guardrail(
    state: &mut State,
    address: Option<&Address>,
    id: Option<&Uuid>,
    origin: Origin,
) -> Result<(), BindError> {
    let (Some(address), Some(id)) = (address, id) else {
        return Ok(());
    };
    state.bind_guardrail(address, id.clone(), origin, now())
}

/// Applies a binding and writes state only if the binding changed it.
///
/// The comparison is what makes a repeated import a no-op rather than a write:
/// the state API already treats rebinding the same identity as success, so
/// without this the second run would advance the serial and rewrite the file to
/// say exactly what it already said.
fn record(
    lock: &StateLock<'_>,
    state: &mut State,
    bind: impl FnOnce(&mut State) -> Result<(), BindError>,
) -> Result<bool, Error> {
    let before = state.clone();
    bind(state).map_err(ImportError::Refused)?;
    if *state == before {
        return Ok(false);
    }
    lock.write(state)?;
    Ok(true)
}

/// Refuses a key binding that would break the one-to-one rule.
fn check_key_bindings(state: &State, address: &Address, hash: &KeyHash) -> Result<(), ImportError> {
    if let Some(owner) = state.address_owning(hash)
        && owner != address
    {
        return Err(ImportError::OwnedElsewhere {
            identity: format!("key {hash}"),
            address: address.clone(),
            owner: owner.clone(),
        });
    }
    if let Some(current) = state.key(address).and_then(KeyBinding::current)
        && current.hash != *hash
    {
        return Err(ImportError::AddressBound {
            address: address.clone(),
            bound: format!("key {hash}", hash = current.hash),
            offered: format!("key {hash}"),
        });
    }
    Ok(())
}

/// Refuses a guardrail binding that would break the one-to-one rule.
fn check_guardrail_bindings(
    state: &State,
    address: &Address,
    id: &Uuid,
) -> Result<(), ImportError> {
    if let Some((owner, _)) = state
        .guardrails()
        .iter()
        .find(|(owner, binding)| binding.id == *id && *owner != address)
    {
        return Err(ImportError::OwnedElsewhere {
            identity: format!("guardrail {id}"),
            address: address.clone(),
            owner: owner.clone(),
        });
    }
    if let Some(binding) = state.guardrail(address)
        && binding.id != *id
    {
        return Err(ImportError::AddressBound {
            address: address.clone(),
            bound: format!("guardrail {id}", id = binding.id),
            offered: format!("guardrail {id}"),
        });
    }
    Ok(())
}

/// Refuses a guardrail whose workspace is not the one the address would place
/// it in.
///
/// A guardrail's workspace is fixed when it is created and a guardrail is never
/// replaced, so binding one that sits somewhere else would record a difference
/// no later apply could ever converge. Both halves are checked: the workspace
/// the block names — a raw UUID, an address state binds, or the workspace whose
/// `default_guardrail` this block is — and the run's own scope, since a scoped
/// run manages nothing outside it.
fn check_guardrail_workspace(
    context: &Context,
    config: &Config,
    state: &State,
    address: &Address,
    desired: &crate::config::Guardrail,
    observed: &ObservedGuardrail,
) -> Result<(), ImportError> {
    let default_of = plan::workspace_defaulting_to(config, address);
    let expected =
        plan::configured_workspace_of(state, desired, default_of, context.workspace.as_ref());
    let Some(expected) = expected else {
        return Ok(());
    };
    if observed.workspace_id.as_ref() == Some(&expected) {
        return Ok(());
    }
    Err(ImportError::WorkspaceMismatch {
        address: address.clone(),
        identity: format!("guardrail {id}", id = observed.id),
        observed: observed
            .workspace_id
            .as_ref()
            .map_or_else(|| "no workspace".to_owned(), |id| format!("workspace {id}")),
        expected,
    })
}

/// Refuses a workspace binding that would break the one-to-one rule.
fn check_workspace_bindings(
    state: &State,
    address: &Address,
    id: &Uuid,
) -> Result<(), ImportError> {
    if let Some(owner) = state.address_owning_workspace(id)
        && owner != address
    {
        return Err(ImportError::OwnedElsewhere {
            identity: format!("workspace {id}"),
            address: address.clone(),
            owner: owner.clone(),
        });
    }
    if let Some(binding) = state.workspace(address)
        && binding.id != *id
    {
        return Err(ImportError::AddressBound {
            address: address.clone(),
            bound: format!("workspace {id}", id = binding.id),
            offered: format!("workspace {id}"),
        });
    }
    Ok(())
}

/// Parses the local address an operator typed.
fn local_address(name: &str) -> Result<Address, ImportError> {
    Address::parse(name).map_err(|error| ImportError::Argument {
        value: "NAME",
        message: error.to_string(),
    })
}

/// Reports an identifier this command cannot use.
fn identifier(option: &'static str, error: &IdError) -> ImportError {
    ImportError::Argument {
        value: option,
        message: error.to_string(),
    }
}

/// Turns a confirmed 404 into "there is nothing there to import".
///
/// Only a 404. Any other failure leaves it unknown whether the object exists,
/// and reporting one as absent would invite an operator to go looking for a
/// resource that is there.
fn absent_or(error: ApiError, identity: &str) -> Error {
    if error.status() == Some(404) {
        return ImportError::Absent {
            identity: identity.to_owned(),
        }
        .into();
    }
    error.into()
}

/// The origin a binding ended up with, for the report.
fn origin_of(origin: Option<Origin>) -> Origin {
    // Every path through this command has just written or confirmed the
    // binding, so the `None` arm is unreachable; `imported` is what an import
    // records, and is the honest answer if it were ever reached.
    origin.unwrap_or(Origin::Imported)
}

/// When the binding was recorded. The only clock this command reads.
fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Why an import could not be performed. Every variant leaves state unchanged.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ImportError {
    /// A command-line value is not the kind of identifier it names.
    #[error("`{value}` is not usable: {message}")]
    Argument {
        /// Which value: `NAME`, `--hash`, or `--id`.
        value: &'static str,
        /// Why it was rejected. Never repeats the value.
        message: String,
    },

    /// The configuration does not describe the address being imported.
    #[error(
        "the configuration does not describe `{address}`; add the {resource} block first, so \
         that the binding this records has a desired state to converge to"
    )]
    NotConfigured {
        /// The resource kind, for the message.
        resource: &'static str,
        /// The local address.
        address: Address,
    },

    /// OpenRouter has no such object.
    #[error("OpenRouter has no {identity}; nothing was imported and state is unchanged")]
    Absent {
        /// The identity that was looked up.
        identity: String,
    },

    /// Another local address already owns the remote object.
    #[error(
        "cannot bind {identity} to `{address}`: `{owner}` already owns it. One remote object \
         belongs to exactly one local address; release it with `openrouter-keymaster state forget \
         {owner}` if the binding is wrong."
    )]
    OwnedElsewhere {
        /// The remote object, as it is addressed.
        identity: String,
        /// The address the import was for.
        address: Address,
        /// The address that already owns it.
        owner: Address,
    },

    /// The address already owns a different remote object.
    #[error(
        "`{address}` is already bound to {bound}, so {offered} cannot be imported over it; one \
         local address owns exactly one remote object"
    )]
    AddressBound {
        /// The local address.
        address: Address,
        /// What it is bound to now.
        bound: String,
        /// What the import offered.
        offered: String,
    },

    /// The remote object is in a workspace this address could never place it
    /// in.
    #[error(
        "{identity} is in {observed}, and `{address}` places it in workspace {expected}. A \
         guardrail's workspace is fixed when it is created and a guardrail is never replaced, so \
         binding this one would record a difference no apply could converge. Nothing was imported \
         and state is unchanged."
    )]
    WorkspaceMismatch {
        /// The local address.
        address: Address,
        /// The remote object, as it is addressed.
        identity: String,
        /// Where OpenRouter has it.
        observed: String,
        /// Where the configuration and the run's scope put it.
        expected: Uuid,
    },

    /// The state API refused the binding.
    #[error(transparent)]
    Refused(#[from] BindError),
}

impl ImportError {
    /// A stable machine-readable category.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Argument { .. } => "import_argument",
            Self::NotConfigured { .. } => "import_not_configured",
            Self::Absent { .. } => "import_absent",
            Self::OwnedElsewhere { .. } => "import_owned_elsewhere",
            Self::AddressBound { .. } => "import_address_bound",
            Self::WorkspaceMismatch { .. } => "import_workspace_mismatch",
            Self::Refused(_) => "import_refused",
        }
    }

    fn not_configured(resource: &'static str, address: &Address) -> Self {
        Self::NotConfigured {
            resource,
            address: address.clone(),
        }
    }
}
