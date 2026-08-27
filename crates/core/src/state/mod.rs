//! Local state: which remote object each address is bound to, and which
//! lifecycle transitions are incomplete.
//!
//! State is an inventory and a journal, not a cache of the OpenRouter API
//! (ADR-0001). It answers two questions and no others: which immutable remote
//! identity does this local address own, and what did the last run start that
//! it did not finish. Observed policy, budgets, and usage are read fresh from
//! OpenRouter every run and are deliberately absent here, so a stale copy can
//! never be planned against.
//!
//! **No field of any type in this module can hold a credential.** A key's
//! plaintext is returned once, by the create response, and goes straight to a
//! receiver; nothing here has anywhere to put it. [`crate::ids::KeyHash`]
//! refuses credential-shaped input, so even a caller that confused a key with
//! its hash cannot write one to disk.
//!
//! Phase transitions implement ADR-0002 exactly. Every legal move is a
//! `Transition`; there is no way to set a phase directly, so a caller cannot
//! record `delivered` for an operation that never reached `delivery_started`.
//! Both the transitions and the write path are crate-private (ADR-0003, item
//! 7): a host reads state with [`StateFile::read`] and changes it only by
//! calling an operation in [`crate::ops`], which journals what it did.
//!
//! [`StateFile`] owns durability: an exclusive lock for writers, a temporary
//! file, an fsync, and an atomic rename.
//!
//! The format is pre-release. Migrations begin at v0.1: until it ships there
//! is no population of state files to carry forward, so a shape an earlier
//! development build wrote and this one cannot interpret is rejected as
//! corrupt rather than migrated. Refusing it is the safe answer — every field
//! here identifies a live spending credential — and it keeps the invariants
//! below unconditional instead of split across versions.

/// Defines one entry point to changing state, with the visibility the build
/// calls for: `pub(crate)` normally, `pub` under `test-support`.
///
/// ADR-0003, item 7: a host reads state with [`StateFile::read`] and moves a
/// key's lifecycle only through `ops`, which journals what it did. Both crates'
/// test suites build state fixtures by calling these directly, and a test
/// binary is an external consumer, so the feature — which no shipped build
/// turns on — opens them. Visibility is not a position a macro can expand into,
/// so the two arms are cfg'd around one body written once here.
macro_rules! mutation {
    ($(#[$attribute:meta])* fn $name:ident $($rest:tt)*) => {
        #[cfg(feature = "test-support")]
        $(#[$attribute])*
        pub fn $name $($rest)*

        #[cfg(not(feature = "test-support"))]
        $(#[$attribute])*
        pub(crate) fn $name $($rest)*
    };
}

mod persist;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;

use crate::ids::{Address, KeyHash, OperationId, ReceiverFingerprint, RemoteName, Uuid};

pub use persist::StateFile;

// The write path. A host reads state with [`StateFile::read`]; taking the lock
// and writing through it are reachable only from `ops`, which journals every
// change (ADR-0003, item 7). `test-support` opens them to the test suites.
#[cfg(feature = "test-support")]
pub use persist::StateLock;
#[cfg(not(feature = "test-support"))]
pub(crate) use persist::StateLock;

/// Names the durable phase a test asks a run to be interrupted at.
///
/// Present only for the crate's own tests and for the `fault-injection`
/// feature; see [`StateFile`].
#[cfg(any(test, feature = "fault-injection"))]
pub use persist::STATE_FAULT_VAR;

/// The only state schema version this build understands.
///
/// A file claiming a higher version is refused rather than reinterpreted: a
/// newer Keymaster may be tracking a live credential in a field this build
/// would silently drop.
pub const SCHEMA_VERSION: u32 = 1;

/// Where a binding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// An operator bound an existing remote object with `import`.
    Imported,
    /// Keymaster created the remote object itself.
    Created,
}

impl Origin {
    /// The spelling used in state and in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Imported => "imported",
            Self::Created => "created",
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A phase of the journaled create-and-deliver protocol (ADR-0002).
///
/// Intent phases (`create_started`, `delivery_started`) are persisted before
/// the non-idempotent action they announce. Outcome phases are persisted after
/// the result they record is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// About to send exactly one `POST /keys`.
    CreateStarted,
    /// The create request may or may not have created a key.
    CreateAmbiguous,
    /// A key exists and its hash is known.
    Created,
    /// Restrictions and guardrail assignment are applied and verified.
    Secured,
    /// About to invoke the receiver exactly once.
    DeliveryStarted,
    /// The receiver may or may not have committed the secret.
    DeliveryAmbiguous,
    /// The receiver definitely committed the secret.
    Delivered,
}

impl Phase {
    /// The spelling used in state and in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateStarted => "create_started",
            Self::CreateAmbiguous => "create_ambiguous",
            Self::Created => "created",
            Self::Secured => "secured",
            Self::DeliveryStarted => "delivery_started",
            Self::DeliveryAmbiguous => "delivery_ambiguous",
            Self::Delivered => "delivered",
        }
    }

    /// Whether a key is known to exist in this phase, and so whether the
    /// pending operation must carry its hash.
    ///
    /// The two create phases must not: a hash arrives with the create
    /// response, and in `create_ambiguous` that response never did.
    const fn requires_hash(self) -> bool {
        match self {
            Self::CreateStarted | Self::CreateAmbiguous => false,
            Self::Created
            | Self::Secured
            | Self::DeliveryStarted
            | Self::DeliveryAmbiguous
            | Self::Delivered => true,
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The two values that drive a key's lifecycle forward.
///
/// They live in a private module so their visibility can follow the crate's:
/// `pub` for the test suites that drive state directly, `pub(crate)`
/// otherwise, which is what makes mutation reachable only through `ops`
/// (ADR-0003, item 7).
mod transition {
    use super::{KeyHash, OperationId, Phase, ReceiverFingerprint, RemoteName, Uuid};

    /// A move from one phase to the next.
    ///
    /// Each variant names the outcome that justifies it, so the ADR's rules are
    /// expressed in the type rather than checked at the call site. A phase cannot
    /// be assigned any other way.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Transition {
        /// The create request's outcome could not be determined.
        CreateAmbiguous,
        /// A well-formed create response returned this hash.
        Created {
            /// The new key's immutable identity.
            hash: KeyHash,
        },
        /// Restrictions and assignment were applied and verified.
        Secured,
        /// The receiver is about to be invoked, exactly once.
        DeliveryStarted,
        /// The receiver's acknowledgement was lost.
        DeliveryAmbiguous,
        /// The receiver definitely refused and committed nothing, so the operation
        /// returns to `secured`: the key exists and is restricted, and its
        /// plaintext is gone (ADR-0002).
        DeliveryRejected,
        /// The receiver definitely committed the secret.
        Delivered,
    }

    impl Transition {
        /// The phase this transition moves to.
        pub(super) const fn target(&self) -> Phase {
            match self {
                Self::CreateAmbiguous => Phase::CreateAmbiguous,
                Self::Created { .. } => Phase::Created,
                Self::Secured | Self::DeliveryRejected => Phase::Secured,
                Self::DeliveryStarted => Phase::DeliveryStarted,
                Self::DeliveryAmbiguous => Phase::DeliveryAmbiguous,
                Self::Delivered => Phase::Delivered,
            }
        }

        /// The one phase this transition may be applied from.
        pub(super) const fn requires(&self) -> Phase {
            match self {
                Self::CreateAmbiguous | Self::Created { .. } => Phase::CreateStarted,
                Self::Secured => Phase::Created,
                Self::DeliveryStarted => Phase::Secured,
                Self::DeliveryAmbiguous | Self::DeliveryRejected | Self::Delivered => {
                    Phase::DeliveryStarted
                }
            }
        }
    }

    /// What the journal records before a create request is sent.
    ///
    /// The intended name and workspace are here because the hash is not: if the
    /// create response is lost, they are all an operator has to recognize the key
    /// the request may have made (ADR-0002).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BeginCreate {
        /// Identifies this attempt, in the journal and to the receiver.
        pub operation: OperationId,
        /// The generation this attempt would become.
        pub generation: u32,
        /// The display name the key was to be created with.
        pub name: RemoteName,
        /// The workspace the key was to be created in, when one was configured.
        pub workspace: Option<Uuid>,
        /// Where the plaintext is destined, described without secret material.
        pub receiver: ReceiverFingerprint,
    }
}

#[cfg(feature = "test-support")]
pub use transition::{BeginCreate, Transition};
#[cfg(not(feature = "test-support"))]
pub(crate) use transition::{BeginCreate, Transition};

/// The key an address currently owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentKey {
    /// The key's immutable identity.
    pub hash: KeyHash,
    /// Which generation this key is.
    pub generation: u32,
    /// When this hash became current.
    #[serde(with = "time::serde::rfc3339")]
    pub bound_at: OffsetDateTime,
    /// Where this key's plaintext was delivered, as a non-secret digest of the
    /// receiver's specification.
    ///
    /// Recorded on promotion, because a delivered secret cannot be moved: if
    /// the configuration later names a different destination, the only way to
    /// honour it is to create a replacement key. Absent for an imported key,
    /// whose plaintext Keymaster never held, and that absence is never a
    /// reason to replace anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<ReceiverFingerprint>,
}

/// Why a hash is still tracked after it stopped being current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedStatus {
    /// A predecessor Keymaster left alone. Rotation never disables one; an
    /// explicit `retire` does.
    AwaitingRetirement,
    /// Disabled, and the disable was verified.
    Retired,
    /// A disable or delete was attempted and failed. Still tracked so it can
    /// be retried.
    RetirementFailed,
    /// A key that exists but can never be used: its plaintext was lost, or an
    /// operator supplied it as the leaked result of an ambiguous create. Kept
    /// so it can be disabled and deleted.
    FailedCandidate,
}

impl RetainedStatus {
    /// The spelling used in state and in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingRetirement => "awaiting_retirement",
            Self::Retired => "retired",
            Self::RetirementFailed => "retirement_failed",
            Self::FailedCandidate => "failed_candidate",
        }
    }
}

impl fmt::Display for RetainedStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A hash an address still owns but no longer uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedKey {
    /// The key's immutable identity.
    pub hash: KeyHash,
    /// Which generation this key was.
    pub generation: u32,
    /// Why it is still tracked.
    pub status: RetainedStatus,
    /// When it reached this status.
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
}

/// An incomplete create-and-deliver operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingOperation {
    /// Identifies this attempt.
    pub id: OperationId,
    /// The generation this attempt would become.
    pub generation: u32,
    /// How far the attempt got.
    pub phase: Phase,
    /// When it reached that phase.
    #[serde(with = "time::serde::rfc3339")]
    pub phase_at: OffsetDateTime,
    /// The display name the key was to be created with. Recorded before the
    /// request, so recovery can describe an attempt whose response was lost.
    pub name: RemoteName,
    /// The workspace the key was to be created in, when one was configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<Uuid>,
    /// The created key's identity, once the create response supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<KeyHash>,
    /// When the receiver definitely refused this delivery, if it did.
    ///
    /// Set, the operation is back at `secured` and can never leave it for
    /// delivery again: the plaintext existed only in memory between the create
    /// response and the receiver, and a definite rejection means it is gone.
    /// ADR-0002 makes invocation at-most-once, so the marker is what stops a
    /// second attempt rather than a convention the caller has to remember. The
    /// only remediation is replacing the key.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub delivery_rejected_at: Option<OffsetDateTime>,

    /// Where the plaintext was destined.
    pub receiver: ReceiverFingerprint,
}

/// What one local key address owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBinding {
    origin: Origin,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    current: Option<CurrentKey>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<PendingOperation>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retained: Vec<RetainedKey>,

    /// The highest generation this address has ever recorded, including keys it
    /// no longer holds.
    ///
    /// A high-water mark, because the entries the other three fields hold are
    /// not one: `delete key` drops a retained hash once OpenRouter confirms the
    /// key is gone, and without this the highest generation on record would
    /// fall back down with it. The next create would then hand a *different*
    /// remote key a number an earlier one already used at this address —
    /// silently, and in exactly the place an audit would go looking.
    ///
    /// It only ever grows, and it is deliberately not checked against the
    /// generations the binding holds: it outranks them by design, and a
    /// binding whose keys have all been deleted keeps nothing else.
    ///
    /// Absent from a file written before this field existed, and zero is the
    /// right answer there: every such file's floor is whatever its own entries
    /// say, which is what [`KeyBinding::highest_generation`] already computes.
    #[serde(default, skip_serializing_if = "is_zero")]
    generation_floor: u32,
}

/// Whether a generation is unset, for `skip_serializing_if`.
const fn is_zero(generation: &u32) -> bool {
    *generation == 0
}

impl KeyBinding {
    /// Whether this binding was imported or created by Keymaster.
    #[must_use]
    pub const fn origin(&self) -> Origin {
        self.origin
    }

    /// The key this address currently owns, if any.
    #[must_use]
    pub const fn current(&self) -> Option<&CurrentKey> {
        self.current.as_ref()
    }

    /// The incomplete operation, if the last run left one.
    #[must_use]
    pub const fn pending(&self) -> Option<&PendingOperation> {
        self.pending.as_ref()
    }

    /// Hashes this address still owns but no longer uses.
    #[must_use]
    pub fn retained(&self) -> &[RetainedKey] {
        &self.retained
    }

    /// The generation of the current key; zero when none is bound yet.
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.current
            .as_ref()
            .map_or(0, |current| current.generation)
    }

    /// The highest generation among the keys this address holds — its current
    /// key and everything it still retains, but not an unfinished operation.
    ///
    /// A predecessor or a failed candidate can outrank the current key: an
    /// abandoned rotation leaves a retained generation above the one still in
    /// use. Reusing that number would give two different remote keys the same
    /// generation at the same address.
    #[must_use]
    pub fn settled_generation(&self) -> u32 {
        self.current
            .iter()
            .map(|current| current.generation)
            .chain(self.retained.iter().map(|retained| retained.generation))
            .max()
            .unwrap_or(0)
    }

    /// The highest generation this address has ever recorded, whether or not it
    /// still holds the key.
    ///
    /// This is the number every new key at the address must exceed. It counts
    /// the keys the binding holds now, the unfinished operation, and the
    /// high-water mark left by keys that have been deleted — because a
    /// generation names one remote key at one address for good, and a key
    /// leaving state does not release its number.
    #[must_use]
    pub fn highest_generation(&self) -> u32 {
        self.settled_generation()
            .max(
                self.pending
                    .as_ref()
                    .map_or(0, |pending| pending.generation),
            )
            .max(self.generation_floor)
    }

    /// The high-water mark left by keys this address no longer holds.
    ///
    /// Zero until a key is deleted. Public because it is part of what an
    /// address records: a generation at or below it is unavailable even though
    /// nothing the binding holds is using it.
    #[must_use]
    pub const fn generation_floor(&self) -> u32 {
        self.generation_floor
    }

    /// Every hash this binding names, in any role.
    ///
    /// Public because owning a hash in any role is what makes a remote key
    /// managed: the planner reports every key no binding names as unmanaged,
    /// and a retained predecessor is not a stranger's key.
    pub fn hashes(&self) -> impl Iterator<Item = &KeyHash> {
        self.current
            .iter()
            .map(|current| &current.hash)
            .chain(self.pending.iter().filter_map(|op| op.hash.as_ref()))
            .chain(self.retained.iter().map(|retained| &retained.hash))
    }
}

/// What one local guardrail address owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardrailBinding {
    /// The guardrail's immutable identity.
    pub id: Uuid,
    /// Whether it was imported or created by Keymaster.
    pub origin: Origin,
    /// When the binding was recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub bound_at: OffsetDateTime,
}

/// What one local workspace address owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceBinding {
    /// The workspace's immutable identity.
    pub id: Uuid,
    /// Whether it was imported or created by Keymaster.
    pub origin: Origin,
    /// When the binding was recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub bound_at: OffsetDateTime,
    /// The deterministic identity of this workspace's default guardrail, as
    /// the workspace object named it.
    ///
    /// Recorded because it is the only handle on that guardrail there is: it
    /// does not appear in `GET /guardrails` until its configuration is first
    /// written, it is never created by `POST`, and it cannot outlive its
    /// workspace (ADR-0004, items 1 and 3). A guardrail address bound to this
    /// identity is the workspace's own, which is what lets `delete workspace`
    /// tell it apart from a child it must refuse to destroy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_guardrail_id: Option<Uuid>,
}

/// What one local log destination address owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationBinding {
    /// The destination's immutable identity.
    pub id: Uuid,
    /// Whether it was imported or created by Keymaster.
    pub origin: Origin,
    /// When the binding was recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub bound_at: OffsetDateTime,
    /// The lowercase hexadecimal SHA-256 of the canonical JSON of the `config`
    /// this address last wrote.
    ///
    /// A digest rather than the value, because the value may be a third-party
    /// credential and reads mask it, so there is nothing to compare against
    /// remotely (ADR-0006, item 3). Absent on an imported destination, and on
    /// one whose configuration has never been written: the planner reads that
    /// absence as "write it once".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
}

/// The whole local state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    version: u32,
    serial: u64,
    #[serde(deserialize_with = "distinct_addresses")]
    keys: BTreeMap<Address, KeyBinding>,
    #[serde(deserialize_with = "distinct_addresses")]
    guardrails: BTreeMap<Address, GuardrailBinding>,
    #[serde(default, deserialize_with = "distinct_addresses")]
    workspaces: BTreeMap<Address, WorkspaceBinding>,
    #[serde(default, deserialize_with = "distinct_addresses")]
    log_destinations: BTreeMap<Address, DestinationBinding>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// State that owns nothing and has never been written.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            version: SCHEMA_VERSION,
            serial: 0,
            keys: BTreeMap::new(),
            guardrails: BTreeMap::new(),
            workspaces: BTreeMap::new(),
            log_destinations: BTreeMap::new(),
        }
    }

    /// The schema version this state was read as.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// How many times this state has been written. Zero means never.
    #[must_use]
    pub const fn serial(&self) -> u64 {
        self.serial
    }

    /// Every key binding, by local address.
    #[must_use]
    pub const fn keys(&self) -> &BTreeMap<Address, KeyBinding> {
        &self.keys
    }

    /// Every guardrail binding, by local address.
    #[must_use]
    pub const fn guardrails(&self) -> &BTreeMap<Address, GuardrailBinding> {
        &self.guardrails
    }

    /// One key binding.
    #[must_use]
    pub fn key(&self, address: &Address) -> Option<&KeyBinding> {
        self.keys.get(address)
    }

    /// Every workspace binding, by local address.
    #[must_use]
    pub const fn workspaces(&self) -> &BTreeMap<Address, WorkspaceBinding> {
        &self.workspaces
    }

    /// One guardrail binding.
    #[must_use]
    pub fn guardrail(&self, address: &Address) -> Option<&GuardrailBinding> {
        self.guardrails.get(address)
    }

    /// One workspace binding.
    #[must_use]
    pub fn workspace(&self, address: &Address) -> Option<&WorkspaceBinding> {
        self.workspaces.get(address)
    }

    /// Which address owns a workspace UUID, if any.
    #[must_use]
    pub fn address_owning_workspace(&self, id: &Uuid) -> Option<&Address> {
        self.workspaces
            .iter()
            .find(|(_, binding)| binding.id == *id)
            .map(|(address, _)| address)
    }

    /// Every log destination binding, by local address.
    #[must_use]
    pub const fn log_destinations(&self) -> &BTreeMap<Address, DestinationBinding> {
        &self.log_destinations
    }

    /// One log destination binding.
    #[must_use]
    pub fn log_destination(&self, address: &Address) -> Option<&DestinationBinding> {
        self.log_destinations.get(address)
    }

    /// Which address owns a log destination UUID, if any.
    #[must_use]
    pub fn address_owning_log_destination(&self, id: &Uuid) -> Option<&Address> {
        self.log_destinations
            .iter()
            .find(|(_, binding)| binding.id == *id)
            .map(|(address, _)| address)
    }

    /// Which address owns a guardrail UUID, if any.
    #[must_use]
    pub fn address_owning_guardrail(&self, id: &Uuid) -> Option<&Address> {
        self.guardrails
            .iter()
            .find(|(_, binding)| binding.id == *id)
            .map(|(address, _)| address)
    }

    /// Which address owns a key hash, if any.
    ///
    /// One remote object belongs to exactly one local address (ADR-0001), so
    /// this is what an import consults before binding.
    #[must_use]
    pub fn address_owning(&self, hash: &KeyHash) -> Option<&Address> {
        self.keys
            .iter()
            .find(|(_, binding)| binding.hashes().any(|owned| owned == hash))
            .map(|(address, _)| address)
    }

    mutation! {
        /// Binds an existing key hash to an address as its current key.
        ///
        /// This is what `import` records, and it makes no remote call. The caller
        /// passes the generation the configuration asks for, not a counter of its
        /// own: an operator rebuilding lost state (ADR-0001) imports a key whose
        /// configuration is already at generation 3, and recording 1 would make
        /// the next plan see a stale key and propose replacing a live credential.
        ///
        /// Repeating the same binding is a no-op; repeating it after the
        /// configured generation rose records the higher one.
        ///
        /// The origin is always `imported`, and is not the caller's to choose. A
        /// key Keymaster created is bound by [`State::promote_key`], which is the
        /// only place that knows where the plaintext went; binding one here would
        /// record a created key with no delivery destination, which is the one
        /// shape the reader refuses.
        ///
        /// # Errors
        ///
        /// Returns [`BindError`] when the generation is zero or unavailable, when
        /// the address already owns a different hash, when the hash already
        /// belongs to another address or is one this address retains, or when the
        /// address has an operation in progress.
        fn bind_key(
            &mut self,
            address: &Address,
            hash: KeyHash,
            generation: u32,
            at: OffsetDateTime,
        ) -> Result<(), BindError> {
            if generation == 0 {
                return Err(BindError::GenerationInvalid {
                    address: address.clone(),
                });
            }
            if let Some(owner) = self.address_owning(&hash)
                && owner != address
            {
                return Err(BindError::HashOwnedElsewhere {
                    hash,
                    owner: owner.clone(),
                });
            }
            self.check_bindable(address, &hash, generation)?;

            // `check_bindable` has established that a current key, if there is
            // one, is this same hash, so only its generation can move.
            if let Some(current) = self
                .keys
                .get_mut(address)
                .and_then(|binding| binding.current.as_mut())
            {
                current.generation = generation;
                return Ok(());
            }

            // An address can hold retained hashes with nothing current — it still
            // owns them, so binding must not drop them on the floor. The
            // high-water mark comes with them: it is the record of keys this
            // address has already spent generations on, and rebuilding the binding
            // without it would release those numbers.
            let (retained, floor) = self
                .keys
                .get_mut(address)
                .map(|binding| {
                    (
                        std::mem::take(&mut binding.retained),
                        binding.generation_floor,
                    )
                })
                .unwrap_or_default();
            self.keys.insert(
                address.clone(),
                KeyBinding {
                    origin: Origin::Imported,
                    current: Some(CurrentKey {
                        hash,
                        generation,
                        bound_at: at,
                        // An imported key's plaintext was never Keymaster's to
                        // deliver, so it records no destination (ADR-0001).
                        receiver: None,
                    }),
                    pending: None,
                    retained,
                    generation_floor: floor,
                },
            );
            Ok(())
        }
    }

    /// Whether `hash` may take `generation` at `address`.
    ///
    /// A generation names one remote key at one address, so a new binding has
    /// to clear every generation the address records. The single exception is
    /// the key that is already bound keeping the number it already has, which
    /// is what re-running an import does and what makes it a no-op. Equality
    /// on any other footing would let two distinct hashes — a current key and
    /// a retained candidate from an abandoned rotation — answer to the same
    /// generation.
    fn check_bindable(
        &self,
        address: &Address,
        hash: &KeyHash,
        generation: u32,
    ) -> Result<(), BindError> {
        let Some(binding) = self.keys.get(address) else {
            return Ok(());
        };
        if binding.pending.is_some() {
            return Err(BindError::OperationInProgress {
                address: address.clone(),
            });
        }
        if binding
            .retained
            .iter()
            .any(|retained| &retained.hash == hash)
        {
            return Err(BindError::HashRetained {
                address: address.clone(),
                hash: hash.clone(),
            });
        }
        if let Some(current) = &binding.current {
            if current.hash != *hash {
                return Err(BindError::AddressBound {
                    address: address.clone(),
                    hash: current.hash.clone(),
                });
            }
            if current.generation == generation {
                return Ok(());
            }
        }

        let recorded = binding.highest_generation();
        if generation <= recorded {
            return Err(BindError::GenerationUnavailable {
                address: address.clone(),
                recorded,
                requested: generation,
            });
        }
        Ok(())
    }

    mutation! {
        /// Binds a guardrail UUID to an address. Repeating it is a no-op.
        ///
        /// # Errors
        ///
        /// Returns [`BindError`] when the address or the UUID already belongs to
        /// something else.
        fn bind_guardrail(
            &mut self,
            address: &Address,
            id: Uuid,
            origin: Origin,
            at: OffsetDateTime,
        ) -> Result<(), BindError> {
            if let Some((owner, _)) = self
                .guardrails
                .iter()
                .find(|(owner, binding)| binding.id == id && *owner != address)
            {
                return Err(BindError::GuardrailOwnedElsewhere {
                    id,
                    owner: owner.clone(),
                });
            }
            if let Some(existing) = self.guardrails.get(address) {
                return if existing.id == id {
                    Ok(())
                } else {
                    Err(BindError::GuardrailBound {
                        address: address.clone(),
                        id: existing.id.clone(),
                    })
                };
            }

            self.guardrails.insert(
                address.clone(),
                GuardrailBinding {
                    id,
                    origin,
                    bound_at: at,
                },
            );
            Ok(())
        }
    }

    mutation! {
        /// Binds a workspace UUID to an address. Repeating it is a no-op.
        ///
        /// `default_guardrail_id` is the deterministic identity the workspace
        /// object names, and it is recorded with the binding because it is the
        /// only handle on that guardrail there is (ADR-0004, item 3). Re-binding
        /// the same workspace records it if the first binding did not have it.
        ///
        /// # Errors
        ///
        /// Returns [`BindError`] when the address or the UUID already belongs to
        /// something else.
        fn bind_workspace(
            &mut self,
            address: &Address,
            id: Uuid,
            default_guardrail_id: Option<Uuid>,
            origin: Origin,
            at: OffsetDateTime,
        ) -> Result<(), BindError> {
            if let Some(owner) = self.address_owning_workspace(&id)
                && owner != address
            {
                return Err(BindError::WorkspaceOwnedElsewhere {
                    id,
                    owner: owner.clone(),
                });
            }
            if let Some(existing) = self.workspaces.get_mut(address) {
                if existing.id != id {
                    return Err(BindError::WorkspaceBound {
                        address: address.clone(),
                        id: existing.id.clone(),
                    });
                }
                if existing.default_guardrail_id.is_none() {
                    existing.default_guardrail_id = default_guardrail_id;
                }
                return Ok(());
            }

            self.workspaces.insert(
                address.clone(),
                WorkspaceBinding {
                    id,
                    origin,
                    bound_at: at,
                    default_guardrail_id,
                },
            );
            Ok(())
        }
    }

    mutation! {
        /// Relinquishes the workspace this address owns.
        ///
        /// As [`State::forget_guardrail`]: purely local, and with nothing to
        /// refuse.
        fn forget_workspace(&mut self, address: &Address) -> Option<WorkspaceBinding> {
            self.workspaces.remove(address)
        }
    }

    mutation! {
        /// Binds a log destination UUID to an address, and records the digest of
        /// the `config` this run wrote.
        ///
        /// One mutation covers the three moments a digest is recorded, because
        /// they differ only in what they have to record. A create knows the
        /// digest it just wrote. An import knows none — its first apply writes
        /// the configuration once (ADR-0006, item 3) — and passes `None`. An
        /// update that carried a new `config` re-binds the identity it already
        /// holds and passes the new digest.
        ///
        /// `digest` of `None` therefore leaves whatever digest the binding has;
        /// only a write knows a better answer than the last one.
        ///
        /// # Errors
        ///
        /// Returns [`BindError`] when the address or the UUID already belongs to
        /// something else.
        fn bind_log_destination(
            &mut self,
            address: &Address,
            id: Uuid,
            digest: Option<String>,
            origin: Origin,
            at: OffsetDateTime,
        ) -> Result<(), BindError> {
            if let Some(owner) = self.address_owning_log_destination(&id)
                && owner != address
            {
                return Err(BindError::DestinationOwnedElsewhere {
                    id,
                    owner: owner.clone(),
                });
            }
            if let Some(existing) = self.log_destinations.get_mut(address) {
                if existing.id != id {
                    return Err(BindError::DestinationBound {
                        address: address.clone(),
                        id: existing.id.clone(),
                    });
                }
                if digest.is_some() {
                    existing.config_digest = digest;
                }
                return Ok(());
            }

            self.log_destinations.insert(
                address.clone(),
                DestinationBinding {
                    id,
                    origin,
                    bound_at: at,
                    config_digest: digest,
                },
            );
            Ok(())
        }
    }

    mutation! {
        /// Relinquishes the log destination this address owns.
        ///
        /// As [`State::forget_workspace`]: purely local, and with nothing to
        /// refuse.
        fn forget_log_destination(&mut self, address: &Address) -> Option<DestinationBinding> {
            self.log_destinations.remove(address)
        }
    }

    mutation! {
        /// Binds a guardrail Keymaster has just created, over a binding to one
        /// that is gone.
        ///
        /// [`State::bind_guardrail`] refuses to rebind an address, which is what
        /// makes an import safe: an operator who names the wrong address is told,
        /// rather than having a live guardrail quietly forgotten. Recreation is the
        /// one case where replacing a binding is right, and it is not the caller's
        /// judgement to make casually — the planner proposes a guardrail create
        /// only when the bound UUID is absent from a complete snapshot *and* no
        /// remote guardrail carries the configured name, so the identity being
        /// overwritten is one that no longer exists.
        ///
        /// The origin becomes `created`, because the guardrail it now names is one
        /// Keymaster created.
        ///
        /// # Errors
        ///
        /// Returns [`BindError::GuardrailOwnedElsewhere`] when another address
        /// already owns the new UUID.
        fn replace_guardrail(
            &mut self,
            address: &Address,
            id: Uuid,
            at: OffsetDateTime,
        ) -> Result<(), BindError> {
            if let Some((owner, _)) = self
                .guardrails
                .iter()
                .find(|(owner, binding)| binding.id == id && *owner != address)
            {
                return Err(BindError::GuardrailOwnedElsewhere {
                    id,
                    owner: owner.clone(),
                });
            }
            self.guardrails.insert(
                address.clone(),
                GuardrailBinding {
                    id,
                    origin: Origin::Created,
                    bound_at: at,
                },
            );
            Ok(())
        }
    }

    mutation! {
        /// Journals the intent to create a key, before any request is sent.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError`] when this or any other address already has
        /// an operation in progress, or when the requested generation does not
        /// exceed the highest the address records.
        fn begin_create(
            &mut self,
            address: &Address,
            begin: BeginCreate,
            at: OffsetDateTime,
        ) -> Result<(), TransitionError> {
            self.check_nothing_pending(address)?;

            let recorded = self
                .keys
                .get(address)
                .map_or(0, KeyBinding::highest_generation);
            if begin.generation <= recorded {
                return Err(TransitionError::GenerationNotMonotonic {
                    address: address.clone(),
                    recorded,
                    requested: begin.generation,
                });
            }

            // Every check is done, so the entry below is the only mutation: a
            // refused create must not leave an empty binding behind.
            let binding = self.keys.entry(address.clone()).or_insert(KeyBinding {
                origin: Origin::Created,
                current: None,
                pending: None,
                retained: Vec::new(),
                generation_floor: 0,
            });
            binding.pending = Some(PendingOperation {
                id: begin.operation,
                generation: begin.generation,
                phase: Phase::CreateStarted,
                phase_at: at,
                name: begin.name,
                workspace: begin.workspace,
                hash: None,
                delivery_rejected_at: None,
                receiver: begin.receiver,
            });
            Ok(())
        }
    }

    mutation! {
        /// Moves a pending operation to its next phase.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError`] when there is no pending operation, when
        /// the transition is not legal from the current phase, or when the hash a
        /// create returned already belongs to another address.
        fn advance_key(
            &mut self,
            address: &Address,
            transition: Transition,
            at: OffsetDateTime,
        ) -> Result<(), TransitionError> {
            let from = self.pending_phase(address)?;
            if from != transition.requires() {
                return Err(TransitionError::IllegalPhase {
                    address: address.clone(),
                    from,
                    to: transition.target(),
                });
            }
            if let Transition::Created { hash } = &transition
                && let Some(owner) = self.address_owning(hash)
            {
                return Err(TransitionError::HashOwnedElsewhere {
                    hash: hash.clone(),
                    owner: owner.clone(),
                });
            }

            let Some(pending) = self.keys.get_mut(address).and_then(|b| b.pending.as_mut()) else {
                return Err(TransitionError::NotPending {
                    address: address.clone(),
                });
            };
            // A definite rejection returns the operation to `secured`, which is
            // the phase delivery starts from — so without this the type would
            // happily allow a second invocation of a receiver that already
            // refused, for a key whose plaintext no longer exists.
            if matches!(transition, Transition::DeliveryStarted)
                && pending.delivery_rejected_at.is_some()
            {
                return Err(TransitionError::DeliveryRefused {
                    address: address.clone(),
                });
            }

            pending.phase = transition.target();
            if let Transition::Created { hash } = transition {
                pending.hash = Some(hash);
            } else if matches!(transition, Transition::DeliveryRejected) {
                pending.delivery_rejected_at = Some(at);
            }
            pending.phase_at = at;
            Ok(())
        }
    }

    mutation! {
        /// Clears a pending create that the server definitely rejected.
        ///
        /// Only legal from `create_started`: a well-formed 4xx says the request
        /// was seen and declined, so no key exists (ADR-0002).
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError`] when there is no pending operation, or when
        /// it has already passed `create_started`.
        fn abandon_create(&mut self, address: &Address) -> Result<(), TransitionError> {
            let from = self.pending_phase(address)?;
            if from != Phase::CreateStarted {
                return Err(TransitionError::CannotAbandon {
                    address: address.clone(),
                    phase: from,
                });
            }
            if let Some(binding) = self.keys.get_mut(address) {
                binding.pending = None;
            }
            Ok(())
        }
    }

    mutation! {
        /// Clears a create after an operator attested that no key was made.
        ///
        /// Legal only from `create_started` and `create_ambiguous` — the two phases
        /// in which the journal does not know whether a key exists. Past them the
        /// hash is recorded, so there is nothing to attest and forgetting the
        /// operation would forget a live credential.
        ///
        /// Separate from [`State::abandon_create`], which the same phase would
        /// allow, because the authority is different and that difference is the
        /// whole point of the command that calls this. A definite 4xx is
        /// OpenRouter saying it declined; this is an operator saying they looked.
        /// Keymaster cannot check the second one, so it must be spelled out at the
        /// call site rather than borrowed from a function that means the first.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError`] when there is no pending operation, or when
        /// it has passed the phases where a key's existence is still unknown.
        fn clear_ambiguous_create(
            &mut self,
            address: &Address,
        ) -> Result<(), TransitionError> {
            let from = self.pending_phase(address)?;
            if !matches!(from, Phase::CreateStarted | Phase::CreateAmbiguous) {
                return Err(TransitionError::NothingToAttest {
                    address: address.clone(),
                    phase: from,
                });
            }
            if let Some(binding) = self.keys.get_mut(address) {
                binding.pending = None;
            }
            Ok(())
        }
    }

    mutation! {
        /// Binds the key an operator found as the leaked result of an ambiguous
        /// create, and closes the operation.
        ///
        /// The hash is retained as a [`RetainedStatus::FailedCandidate`], never
        /// promoted: OpenRouter disclosed this key's plaintext once, in a response
        /// nobody received, so the key exists, can never be used, and is kept only
        /// so it can be disabled and deleted (ADR-0002).
        ///
        /// Legal from the same two phases as [`State::clear_ambiguous_create`]. Past
        /// them the operation already carries a hash, and binding a second one
        /// would claim the address owns two keys from one attempt.
        ///
        /// Returns the retained entry it recorded.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError`] when there is no pending operation, when it
        /// has passed the phases where the hash is still unknown, or when the hash
        /// already belongs to some address.
        fn retain_leaked_candidate(
            &mut self,
            address: &Address,
            hash: KeyHash,
            at: OffsetDateTime,
        ) -> Result<RetainedKey, TransitionError> {
            let from = self.pending_phase(address)?;
            if !matches!(from, Phase::CreateStarted | Phase::CreateAmbiguous) {
                return Err(TransitionError::NothingToAttest {
                    address: address.clone(),
                    phase: from,
                });
            }
            if let Some(owner) = self.address_owning(&hash) {
                return Err(TransitionError::HashOwnedElsewhere {
                    hash,
                    owner: owner.clone(),
                });
            }

            let Some(binding) = self.keys.get_mut(address) else {
                return Err(TransitionError::NotPending {
                    address: address.clone(),
                });
            };
            let Some(pending) = binding.pending.take() else {
                return Err(TransitionError::NotPending {
                    address: address.clone(),
                });
            };
            let retained = RetainedKey {
                hash,
                generation: pending.generation,
                status: RetainedStatus::FailedCandidate,
                recorded_at: at,
            };
            binding.retained.push(retained.clone());
            Ok(retained)
        }
    }

    mutation! {
        /// Closes an operation whose key exists and can never be delivered, keeping
        /// the hash tracked.
        ///
        /// This is what stands between a dead operation and its replacement. The
        /// key is real — the create response arrived and its hash is journaled —
        /// and its plaintext is gone, so nothing can rescue it; but forgetting it
        /// would leave a live budgeted credential nothing names. It moves to
        /// [`RetainedStatus::FailedCandidate`], where an explicit `retire` or
        /// `delete` can still reach it, and the address is free to stage a
        /// successor.
        ///
        /// Legal from every phase that carries a hash except `delivered`, which is
        /// not dead at all: [`State::promote_key`] finishes that one.
        ///
        /// Returns the retained entry, so the caller can attempt to disable it.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError`] when there is no pending operation, or when
        /// its phase is not one this closes.
        fn retire_candidate(
            &mut self,
            address: &Address,
            at: OffsetDateTime,
        ) -> Result<RetainedKey, TransitionError> {
            let from = self.pending_phase(address)?;
            if !matches!(
                from,
                Phase::Created | Phase::Secured | Phase::DeliveryStarted | Phase::DeliveryAmbiguous
            ) {
                return Err(TransitionError::CannotRetireCandidate {
                    address: address.clone(),
                    phase: from,
                });
            }

            let Some(binding) = self.keys.get_mut(address) else {
                return Err(TransitionError::NotPending {
                    address: address.clone(),
                });
            };
            let Some(pending) = binding.pending.take() else {
                return Err(TransitionError::NotPending {
                    address: address.clone(),
                });
            };
            // The four phases above all require a hash, so this is unreachable;
            // restoring the operation is the honest answer if it ever is reached,
            // because dropping it would forget an attempt nobody has resolved.
            let Some(hash) = pending.hash.clone() else {
                binding.pending = Some(pending);
                return Err(TransitionError::CannotRetireCandidate {
                    address: address.clone(),
                    phase: from,
                });
            };
            let retained = RetainedKey {
                hash,
                generation: pending.generation,
                status: RetainedStatus::FailedCandidate,
                recorded_at: at,
            };
            binding.retained.push(retained.clone());
            Ok(retained)
        }
    }

    mutation! {
        /// Promotes a delivered key to current.
        ///
        /// Any previous current hash moves to `awaiting_retirement`; rotation
        /// never disables a predecessor.
        ///
        /// The binding's origin becomes `created`, because the key it now names is
        /// one Keymaster created and delivered. Rotating a key an operator
        /// imported replaces it with Keymaster's own; the imported hash stays
        /// tracked as the predecessor, and the origin describes what is current.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError`] when there is no pending operation or it
        /// has not reached `delivered`.
        fn promote_key(
            &mut self,
            address: &Address,
            at: OffsetDateTime,
        ) -> Result<(), TransitionError> {
            let from = self.pending_phase(address)?;
            if from != Phase::Delivered {
                return Err(TransitionError::CannotPromote {
                    address: address.clone(),
                    phase: from,
                });
            }

            let Some(binding) = self.keys.get_mut(address) else {
                return Err(TransitionError::NotPending {
                    address: address.clone(),
                });
            };
            let Some(pending) = binding.pending.take() else {
                return Err(TransitionError::NotPending {
                    address: address.clone(),
                });
            };
            let Some(hash) = pending.hash else {
                return Err(TransitionError::CannotPromote {
                    address: address.clone(),
                    phase: from,
                });
            };

            if let Some(previous) = binding.current.take() {
                binding.retained.push(RetainedKey {
                    hash: previous.hash,
                    generation: previous.generation,
                    status: RetainedStatus::AwaitingRetirement,
                    recorded_at: at,
                });
            }
            binding.origin = Origin::Created;
            binding.current = Some(CurrentKey {
                hash,
                generation: pending.generation,
                bound_at: at,
                receiver: Some(pending.receiver),
            });
            Ok(())
        }
    }

    mutation! {
        /// Takes the key an address uses out of service, keeping the hash tracked.
        ///
        /// The one transition that empties a binding's current slot without putting
        /// another key in it, and the whole of what `openrouter-keymaster
        /// decommission` writes: rotation *replaces* a credential, and this *ends*
        /// one. The address stays bound and keeps everything else it holds — its
        /// other retained hashes and its generation floor — so a key created here
        /// later still takes a higher number than this one had.
        ///
        /// `status` is the caller's finding about the remote key, established by a
        /// read: [`RetainedStatus::Retired`] once one proved the key is out of
        /// service. Nothing here talks to OpenRouter, so nothing here can establish
        /// that.
        ///
        /// Returns the retained entry it recorded.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError::AlreadyPending`] while an operation is in
        /// progress at the address, whose successor would otherwise be promoted
        /// into the slot this empties; and [`TransitionError::HashNotCurrent`] when
        /// the hash named is not the one the address is using. The hash is required
        /// rather than implied because this is the one ending that acts on a
        /// working credential.
        fn decommission_current(
            &mut self,
            address: &Address,
            hash: &KeyHash,
            status: RetainedStatus,
            at: OffsetDateTime,
        ) -> Result<RetainedKey, TransitionError> {
            let not_current = || TransitionError::HashNotCurrent {
                address: address.clone(),
                hash: hash.clone(),
            };

            let Some(binding) = self.keys.get_mut(address) else {
                return Err(not_current());
            };
            if let Some(pending) = &binding.pending {
                return Err(TransitionError::AlreadyPending {
                    address: address.clone(),
                    phase: pending.phase,
                });
            }
            let Some(current) = binding.current.take_if(|current| &current.hash == hash) else {
                return Err(not_current());
            };

            let retained = RetainedKey {
                hash: current.hash,
                generation: current.generation,
                status,
                recorded_at: at,
            };
            binding.retained.push(retained.clone());
            Ok(retained)
        }
    }

    mutation! {
        /// Stops tracking a retained hash, after its remote key is confirmed gone.
        ///
        /// The last step of `openrouter-keymaster delete key`, and only ever that. A hash
        /// leaves state when OpenRouter no longer has the key and a read has said
        /// so; dropping it on the strength of a delete response would be how a live
        /// spending credential ends up with no local record naming it.
        ///
        /// Returns the entry it removed, so the caller can report what it released.
        ///
        /// The removed generation is kept as a high-water mark
        /// ([`KeyBinding::generation_floor`]). The key is gone, but the number is
        /// spent: handing it to a successor would give two different remote keys the
        /// same generation at one address, and the evidence that the first one ever
        /// existed has just been deleted.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError::HashNotRetained`] when the address does not
        /// retain that hash. A current hash and an operation's hash are deliberately
        /// out of reach here: neither is a key whose life is over.
        fn drop_retained(
            &mut self,
            address: &Address,
            hash: &KeyHash,
        ) -> Result<RetainedKey, TransitionError> {
            let position = self
                .keys
                .get(address)
                .and_then(|binding| binding.retained.iter().position(|r| &r.hash == hash));

            let (Some(binding), Some(position)) = (self.keys.get_mut(address), position) else {
                return Err(TransitionError::HashNotRetained {
                    address: address.clone(),
                    hash: hash.clone(),
                });
            };
            let removed = binding.retained.remove(position);
            binding.generation_floor = binding.generation_floor.max(removed.generation);
            Ok(removed)
        }
    }

    mutation! {
        /// Relinquishes every key this address owns, recording nothing in its place.
        ///
        /// This is `openrouter-keymaster state forget`, and it is purely local: the remote keys
        /// go on existing, enabled, and are simply no longer Keymaster's. Returns
        /// the binding it removed so the caller can list what it released, or
        /// `None` when the address owned nothing.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError::AlreadyPending`] when an operation is in
        /// progress at the address. An unfinished attempt may have made a key whose
        /// hash nobody has yet, and forgetting the journal would destroy the only
        /// record that the attempt happened — the exact outcome ADR-0002's recovery
        /// exists to prevent. Resolve it first.
        fn forget_key(
            &mut self,
            address: &Address,
        ) -> Result<Option<KeyBinding>, TransitionError> {
            if let Some(pending) = self
                .keys
                .get(address)
                .and_then(|binding| binding.pending.as_ref())
            {
                return Err(TransitionError::AlreadyPending {
                    address: address.clone(),
                    phase: pending.phase,
                });
            }
            Ok(self.keys.remove(address))
        }
    }

    mutation! {
        /// Relinquishes the guardrail this address owns.
        ///
        /// As [`State::forget_key`], and with nothing to refuse: a guardrail has no
        /// journal and no one-time secret.
        fn forget_guardrail(&mut self, address: &Address) -> Option<GuardrailBinding> {
            self.guardrails.remove(address)
        }
    }

    mutation! {
        /// Records why a retained hash is still tracked.
        ///
        /// # Errors
        ///
        /// Returns [`TransitionError::HashNotRetained`] when the address does not
        /// retain that hash.
        fn set_retained_status(
            &mut self,
            address: &Address,
            hash: &KeyHash,
            status: RetainedStatus,
            at: OffsetDateTime,
        ) -> Result<(), TransitionError> {
            let retained = self
                .keys
                .get_mut(address)
                .and_then(|binding| binding.retained.iter_mut().find(|r| &r.hash == hash));

            let Some(retained) = retained else {
                return Err(TransitionError::HashNotRetained {
                    address: address.clone(),
                    hash: hash.clone(),
                });
            };
            retained.status = status;
            retained.recorded_at = at;
            Ok(())
        }
    }

    /// Checks that at most one operation is in progress across the whole file.
    ///
    /// The rule `begin_create` enforces as state is built, applied to a file
    /// that could have been merged, hand-edited, or written by a build from
    /// before the rule existed. Two unresolved operations would mean recovery
    /// has to reason about which of two ambiguous creates it is looking at.
    fn check_one_operation(&self) -> Result<(), String> {
        let mut pending = self
            .keys
            .iter()
            .filter(|(_, binding)| binding.pending.is_some())
            .map(|(address, _)| address);

        let Some(first) = pending.next() else {
            return Ok(());
        };
        if let Some(second) = pending.next() {
            return Err(format!(
                "`{first}` and `{second}` both have an operation in progress; Keymaster creates \
                 and delivers one key at a time, and an apply stops at the first unresolved \
                 operation"
            ));
        }
        Ok(())
    }

    /// Refuses when any address has an operation in progress.
    ///
    /// Keymaster creates and delivers one key at a time, and an apply stops at
    /// the first unresolved operation (ADR-0002). The rule is global rather
    /// than per-address because the thing it protects is global: an
    /// unacknowledged create may have made a key nobody can name, and starting
    /// a second one buries that evidence under another ambiguous attempt.
    fn check_nothing_pending(&self, address: &Address) -> Result<(), TransitionError> {
        let Some((blocking, pending)) = self.pending_operation() else {
            return Ok(());
        };
        if blocking == address {
            return Err(TransitionError::AlreadyPending {
                address: address.clone(),
                phase: pending.phase,
            });
        }
        Err(TransitionError::AnotherOperationPending {
            address: address.clone(),
            blocking: blocking.clone(),
            operation: pending.id.clone(),
            phase: pending.phase,
        })
    }

    /// The operation in progress, if a run left one. There is at most one.
    #[must_use]
    pub fn pending_operation(&self) -> Option<(&Address, &PendingOperation)> {
        self.keys
            .iter()
            .find_map(|(address, binding)| binding.pending().map(|pending| (address, pending)))
    }

    /// The phase of an address's pending operation.
    fn pending_phase(&self, address: &Address) -> Result<Phase, TransitionError> {
        self.keys
            .get(address)
            .and_then(|binding| binding.pending.as_ref())
            .map(|pending| pending.phase)
            .ok_or_else(|| TransitionError::NotPending {
                address: address.clone(),
            })
    }

    /// Checks the invariants a file on disk could violate.
    ///
    /// Deserialization proves each value is well formed; this proves the
    /// values are consistent with each other. A state that fails here is
    /// corrupt, not merely out of date.
    fn check_invariants(&self) -> Result<(), String> {
        self.check_one_operation()?;

        let mut seen: BTreeSet<&KeyHash> = BTreeSet::new();
        for (address, binding) in &self.keys {
            check_binding(address, binding)?;
            for hash in binding.hashes() {
                if !seen.insert(hash) {
                    return Err(format!(
                        "the key hash bound at `{address}` is bound more than once; one remote \
                         key belongs to exactly one local address"
                    ));
                }
            }
        }

        let mut identities: BTreeSet<&Uuid> = BTreeSet::new();
        for (address, binding) in &self.guardrails {
            if !identities.insert(&binding.id) {
                return Err(format!(
                    "the guardrail bound at `{address}` is bound more than once; one remote \
                     guardrail belongs to exactly one local address"
                ));
            }
        }

        let mut workspaces: BTreeSet<&Uuid> = BTreeSet::new();
        for (address, binding) in &self.workspaces {
            if !workspaces.insert(&binding.id) {
                return Err(format!(
                    "the workspace bound at `{address}` is bound more than once; one remote \
                     workspace belongs to exactly one local address"
                ));
            }
        }

        let mut destinations: BTreeSet<&Uuid> = BTreeSet::new();
        for (address, binding) in &self.log_destinations {
            if !destinations.insert(&binding.id) {
                return Err(format!(
                    "the log destination bound at `{address}` is bound more than once; one remote \
                     log destination belongs to exactly one local address"
                ));
            }
        }
        Ok(())
    }
}

/// Deserializes a map keyed by local address, refusing a repeated key.
///
/// JSON permits an object to name the same key twice, and the derived
/// implementation would keep whichever came last. Here that is not a parsing
/// nicety: the discarded entry is a binding to a live remote key, and the next
/// write would persist the file without it — Keymaster would have quietly
/// forgotten a credential it owns. A merged or hand-edited file is exactly
/// where this happens, and it is the one case the reader exists to catch.
fn distinct_addresses<'de, D, V>(deserializer: D) -> Result<BTreeMap<Address, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct DistinctAddresses<V>(std::marker::PhantomData<fn() -> V>);

    impl<'de, V: Deserialize<'de>> Visitor<'de> for DistinctAddresses<V> {
        type Value = BTreeMap<Address, V>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map keyed by distinct local addresses")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut map = BTreeMap::new();
            while let Some(address) = access.next_key::<Address>()? {
                if map.contains_key(&address) {
                    return Err(A::Error::custom(format!(
                        "`{address}` appears more than once; a local address names one resource, \
                         and keeping either entry would silently discard the other"
                    )));
                }
                let value = access.next_value::<V>()?;
                map.insert(address, value);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(DistinctAddresses(std::marker::PhantomData))
}

/// Checks one key binding's internal consistency.
fn check_binding(address: &Address, binding: &KeyBinding) -> Result<(), String> {
    check_generations(address, binding)?;
    check_distinct_generations(address, binding)?;
    check_delivery_record(address, binding)?;

    let Some(pending) = &binding.pending else {
        return Ok(());
    };
    if pending.phase.requires_hash() != pending.hash.is_some() {
        return Err(format!(
            "the operation pending at `{address}` is in phase `{}` with{} a key hash, which \
             cannot happen",
            pending.phase,
            if pending.hash.is_some() { "" } else { "out" }
        ));
    }
    if pending.delivery_rejected_at.is_some() && pending.phase != Phase::Secured {
        return Err(format!(
            "the operation pending at `{address}` records a refused delivery but is in phase \
             `{}`; a refused delivery holds at `secured` until the key is replaced",
            pending.phase
        ));
    }
    if pending.generation <= binding.settled_generation() {
        return Err(format!(
            "the operation pending at `{address}` is generation {} but the address already \
             records generation {}; a generation only moves upward",
            pending.generation,
            binding.settled_generation()
        ));
    }
    Ok(())
}

/// Checks that the current key's delivery record matches its origin.
///
/// A key Keymaster created was delivered somewhere, and promotion records
/// where; a key an operator imported was never Keymaster's to deliver, so it
/// records nothing. The two shapes are what the planner reads to decide
/// whether a changed destination is a reason to replace a live credential, and
/// a created key with no destination would read exactly like an imported one —
/// silently turning "the receiver moved" into "nothing to do".
///
/// So the ambiguous shape is refused rather than interpreted. A file written
/// by an early build of this unreleased version can hold one; it is rejected,
/// not migrated (see the module documentation).
fn check_delivery_record(address: &Address, binding: &KeyBinding) -> Result<(), String> {
    let Some(current) = &binding.current else {
        return Ok(());
    };
    match (binding.origin, current.receiver.is_some()) {
        (Origin::Created, false) => Err(format!(
            "the key current at `{address}` was created by Keymaster but records no receiver; a \
             created key was delivered somewhere, and promotion records where"
        )),
        (Origin::Imported, true) => Err(format!(
            "the key current at `{address}` was imported but records a receiver; Keymaster never \
             held an imported key's plaintext, so it cannot have delivered it"
        )),
        (Origin::Created, true) | (Origin::Imported, false) => Ok(()),
    }
}

/// Checks that no recorded generation is zero.
///
/// A generation counts a key that exists, and they are counted from one, so
/// zero means the file was written by something that was not Keymaster. It is
/// worth refusing rather than tolerating: the planner reads a generation to
/// decide whether a live credential should be replaced.
fn check_generations(address: &Address, binding: &KeyBinding) -> Result<(), String> {
    let current = binding
        .current
        .iter()
        .map(|current| ("the current key", current.generation));
    let retained = binding
        .retained
        .iter()
        .map(|retained| ("a retained key", retained.generation));
    let pending = binding
        .pending
        .iter()
        .map(|pending| ("the operation pending", pending.generation));

    for (role, generation) in current.chain(retained).chain(pending) {
        if generation == 0 {
            return Err(format!(
                "{role} at `{address}` records generation 0; generations are counted from 1"
            ));
        }
    }
    Ok(())
}

/// Checks that no two keys the address holds claim the same generation.
///
/// A generation names one remote key at one address, which is the rule
/// `State::bind_key` and `State::begin_create` enforce as state is built. A
/// file can still arrive holding a current key and a retained predecessor at
/// the same number — hand-edited, or written by a build from before the rule
/// existed — and that ambiguity would reach the planner as a question about
/// which key a configured generation refers to.
///
/// The pending operation is not included: it is already required to outrank
/// every settled generation, so it cannot equal one.
fn check_distinct_generations(address: &Address, binding: &KeyBinding) -> Result<(), String> {
    let settled = binding
        .current
        .iter()
        .map(|current| current.generation)
        .chain(binding.retained.iter().map(|retained| retained.generation));

    let mut seen = BTreeSet::new();
    for generation in settled {
        if !seen.insert(generation) {
            return Err(format!(
                "`{address}` records generation {generation} for more than one key; a \
                 generation names exactly one remote key at an address"
            ));
        }
    }
    Ok(())
}

/// Why a state operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// The state file could not be read.
    #[error("cannot read state {}: {message}", path.display())]
    Read {
        /// The file Keymaster tried to read.
        path: std::path::PathBuf,
        /// The operating system's explanation.
        message: String,
    },

    /// The state file is not the JSON this schema describes.
    #[error("state {} is not readable as version {SCHEMA_VERSION}: {message}", path.display())]
    Parse {
        /// The file that could not be parsed.
        path: std::path::PathBuf,
        /// The deserializer's explanation, redacted.
        message: String,
    },

    /// The state file was written by a build this one does not understand.
    #[error(
        "state {} is version {found}, but this Keymaster understands version {expected}; \
         upgrade Keymaster rather than letting it reinterpret the file",
        path.display()
    )]
    UnsupportedVersion {
        /// The file that was refused.
        path: std::path::PathBuf,
        /// The version the file claims.
        found: u32,
        /// The version this build understands.
        expected: u32,
    },

    /// The state file is internally inconsistent.
    #[error("state {} is corrupt: {message}", path.display())]
    Corrupt {
        /// The file that was refused.
        path: std::path::PathBuf,
        /// Which invariant it violates.
        message: String,
    },

    /// The state a run built is internally inconsistent, so it was not
    /// written.
    #[error("refusing to write state {}: {message}", path.display())]
    Inconsistent {
        /// The file that was left as it was.
        path: std::path::PathBuf,
        /// Which invariant the state in memory violates.
        message: String,
    },

    /// Another writer holds the exclusive lock.
    #[error("{message}")]
    Locked {
        /// The lock file.
        path: std::path::PathBuf,
        /// What to do about it.
        message: String,
    },

    /// State could not be made durable.
    #[error("cannot write state {}: {message}", path.display())]
    Write {
        /// The file Keymaster tried to write.
        path: std::path::PathBuf,
        /// The operating system's explanation.
        message: String,
    },

    /// The serial cannot advance, so a further write could not be told apart
    /// from the one already on disk.
    #[error(
        "state {} is at serial {serial}, the highest there is, so it cannot record another \
         write; conflict detection depends on the serial advancing. No amount of ordinary use \
         reaches this, so the file has been edited or corrupted.",
        path.display()
    )]
    SerialExhausted {
        /// The file that cannot be written.
        path: std::path::PathBuf,
        /// The serial it has reached.
        serial: u64,
    },

    /// The file changed since this state was read.
    #[error(
        "state {} moved from serial {expected} to {found} while this run held it; another \
         Keymaster wrote the same file",
        path.display()
    )]
    Conflict {
        /// The file that changed.
        path: std::path::PathBuf,
        /// The serial this run read.
        expected: u64,
        /// The serial now on disk.
        found: u64,
    },
}

impl StateError {
    /// A stable machine-readable category.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Read { .. } => "state_read",
            Self::Parse { .. } => "state_parse",
            Self::UnsupportedVersion { .. } => "state_unsupported_version",
            Self::Corrupt { .. } => "state_corrupt",
            Self::Inconsistent { .. } => "state_inconsistent",
            Self::Locked { .. } => "state_locked",
            Self::Write { .. } => "state_write",
            Self::SerialExhausted { .. } => "state_serial_exhausted",
            Self::Conflict { .. } => "state_conflict",
        }
    }
}

/// Why a binding could not be recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BindError {
    /// The address already owns a different key.
    #[error("`{address}` is already bound to key {hash}")]
    AddressBound {
        /// The local address.
        address: Address,
        /// The hash it is already bound to.
        hash: KeyHash,
    },

    /// Another address already owns this key.
    #[error("key {hash} is already bound to `{owner}`; one remote key belongs to one address")]
    HashOwnedElsewhere {
        /// The hash that is already owned.
        hash: KeyHash,
        /// The address that owns it.
        owner: Address,
    },

    /// The address already owns a different guardrail.
    #[error("`{address}` is already bound to guardrail {id}")]
    GuardrailBound {
        /// The local address.
        address: Address,
        /// The UUID it is already bound to.
        id: Uuid,
    },

    /// Another address already owns this guardrail.
    #[error(
        "guardrail {id} is already bound to `{owner}`; one remote guardrail belongs to one address"
    )]
    GuardrailOwnedElsewhere {
        /// The UUID that is already owned.
        id: Uuid,
        /// The address that owns it.
        owner: Address,
    },

    /// The address already owns a different workspace.
    #[error("`{address}` is already bound to workspace {id}")]
    WorkspaceBound {
        /// The local address.
        address: Address,
        /// The UUID it is already bound to.
        id: Uuid,
    },

    /// Another address already owns this workspace.
    #[error(
        "workspace {id} is already bound to `{owner}`; one remote workspace belongs to one address"
    )]
    WorkspaceOwnedElsewhere {
        /// The UUID that is already owned.
        id: Uuid,
        /// The address that owns it.
        owner: Address,
    },

    /// The address already owns a different log destination.
    #[error("`{address}` is already bound to log destination {id}")]
    DestinationBound {
        /// The local address.
        address: Address,
        /// The UUID it is already bound to.
        id: Uuid,
    },

    /// Another address already owns this log destination.
    #[error(
        "log destination {id} is already bound to `{owner}`; one remote log destination belongs \
         to one address"
    )]
    DestinationOwnedElsewhere {
        /// The UUID that is already owned.
        id: Uuid,
        /// The address that owns it.
        owner: Address,
    },

    /// The address has an incomplete operation, which must be closed first.
    ///
    /// The message names `recover inspect` rather than a resolution, because
    /// which one applies depends on the phase and this layer does not carry it:
    /// one phase, `delivered`, needs no recovery at all. `inspect` reads the
    /// journal, needs no credential once a hash is known, and reports the
    /// command that phase actually takes.
    #[error(
        "`{address}` has an operation in progress; close it first, and `openrouter-keymaster \
         recover inspect {address}` names the one command that does"
    )]
    OperationInProgress {
        /// The local address.
        address: Address,
    },

    /// A hash the address already retains was offered as its current key.
    #[error(
        "`{address}` already retains key {hash}; a retained key is disabled or awaiting \
         retirement, so bind a replacement rather than the same key again"
    )]
    HashRetained {
        /// The local address.
        address: Address,
        /// The hash that is already retained.
        hash: KeyHash,
    },

    /// A generation of zero was offered. Generations are counted from one.
    #[error("`{address}` cannot be bound at generation 0; generations are counted from 1")]
    GenerationInvalid {
        /// The local address.
        address: Address,
    },

    /// A binding asked for a generation the address cannot give it.
    #[error(
        "`{address}` already records generation {recorded}, so generation {requested} cannot be \
         bound; a generation must be higher than every one the address records, unless it is the \
         key already bound keeping its own"
    )]
    GenerationUnavailable {
        /// The local address.
        address: Address,
        /// The generation the address holds now.
        recorded: u32,
        /// The generation that was requested.
        requested: u32,
    },
}

/// Why a lifecycle transition was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransitionError {
    /// A new operation was started while one was still pending.
    #[error("`{address}` already has an operation in progress, in phase `{phase}`")]
    AlreadyPending {
        /// The local address.
        address: Address,
        /// The phase the existing operation is in.
        phase: Phase,
    },

    /// A create was started while another address had an operation running.
    #[error(
        "`{address}` cannot start an operation while `{blocking}` has one in progress \
         (operation {operation}, phase `{phase}`); Keymaster creates and delivers one key at a \
         time, and stops until that one is resolved"
    )]
    AnotherOperationPending {
        /// The address whose create was refused.
        address: Address,
        /// The address that already has an operation in progress.
        blocking: Address,
        /// That operation's identifier.
        operation: OperationId,
        /// The phase that operation is in.
        phase: Phase,
    },

    /// A transition was applied to an address with no pending operation.
    #[error("`{address}` has no operation in progress")]
    NotPending {
        /// The local address.
        address: Address,
    },

    /// The transition is not legal from the current phase.
    #[error("`{address}` cannot move from phase `{from}` to `{to}`")]
    IllegalPhase {
        /// The local address.
        address: Address,
        /// The phase the operation is in.
        from: Phase,
        /// The phase the caller asked for.
        to: Phase,
    },

    /// A generation did not increase.
    #[error(
        "`{address}` has recorded generation {recorded}, so generation {requested} cannot be \
         created; a generation only moves upward"
    )]
    GenerationNotMonotonic {
        /// The local address.
        address: Address,
        /// The highest generation the address has recorded, in any role.
        recorded: u32,
        /// The generation that was requested.
        requested: u32,
    },

    /// A created hash already belongs to another address.
    #[error("key {hash} is already bound to `{owner}`; one remote key belongs to one address")]
    HashOwnedElsewhere {
        /// The hash that is already owned.
        hash: KeyHash,
        /// The address that owns it.
        owner: Address,
    },

    /// A create was abandoned after it could have produced a key.
    #[error(
        "`{address}` is in phase `{phase}`, so its create cannot be abandoned; a key may exist"
    )]
    CannotAbandon {
        /// The local address.
        address: Address,
        /// The phase the operation is in.
        phase: Phase,
    },

    /// An operator's attestation was offered for an operation whose key is
    /// already known to exist.
    #[error(
        "`{address}` is in phase `{phase}`, where the create response already recorded a key, so \
         there is nothing left for an operator to attest about whether one exists"
    )]
    NothingToAttest {
        /// The local address.
        address: Address,
        /// The phase the operation is in.
        phase: Phase,
    },

    /// A candidate was retired from a phase that does not carry a hash, or from
    /// one that is not dead.
    #[error(
        "`{address}` is in phase `{phase}`, so its operation cannot be retired; only an \
         operation whose key exists and can never be delivered is retired this way"
    )]
    CannotRetireCandidate {
        /// The local address.
        address: Address,
        /// The phase the operation is in.
        phase: Phase,
    },

    /// Promotion was attempted before delivery was confirmed.
    #[error("`{address}` is in phase `{phase}`, so its key cannot be promoted to current")]
    CannotPromote {
        /// The local address.
        address: Address,
        /// The phase the operation is in.
        phase: Phase,
    },

    /// Delivery was attempted again after the receiver definitely refused.
    #[error(
        "`{address}`'s receiver refused this delivery, so the key's plaintext is gone and it \
         cannot be delivered again; the key has to be replaced"
    )]
    DeliveryRefused {
        /// The local address.
        address: Address,
    },

    /// A hash was named as an address's working key when it is not one.
    #[error("`{address}` is not using key {hash}")]
    HashNotCurrent {
        /// The local address.
        address: Address,
        /// The hash that was named.
        hash: KeyHash,
    },

    /// A retained hash was named that the address does not hold.
    #[error("`{address}` does not retain key {hash}")]
    HashNotRetained {
        /// The local address.
        address: Address,
        /// The hash that was named.
        hash: KeyHash,
    },
}
