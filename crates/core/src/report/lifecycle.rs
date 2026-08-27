//! The result documents of the five lifecycle commands: `rotate`, `retire`,
//! `decommission`, `delete key`, and `state forget`.
//!
//! Every one of them is about a credential, and none of them can print one.
//! There is nowhere here to put a plaintext: each field is a hash, a UUID, an
//! address, a generation, a status this crate spelled, or a sentence this
//! module wrote. No string in these documents comes from OpenRouter, so unlike
//! the plan and status reports there is nothing to scrub.
//!
//! What the documents do carry, deliberately and in every case, is the *phase*
//! an operator needs to reason about what happened next: which hash is current
//! and which is retained, whether a disable was confirmed by a read, and
//! whether a deletion is proven rather than merely accepted.

use std::fmt;

use serde::Serialize;

use super::recover::{RetainedReport, Successor};
use crate::ids::{Address, KeyHash, Uuid};
use crate::state::{Origin, RetainedKey, RetainedStatus};

/// The key an address held before a rotation.
///
/// The status is optional because promotion is its own durable write: a run
/// that delivered and then failed to promote leaves this key still current, and
/// saying it was retained would tell an operator to retire the key still in use.
#[derive(Debug, Clone)]
pub struct Predecessor {
    /// The predecessor's immutable identity.
    pub hash: String,
    /// The generation it was created as.
    pub generation: u32,
    /// Why it is now tracked, once promotion moved it.
    pub status: Option<RetainedStatus>,
}

/// What `rotate` staged, and what it left alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RotateReport {
    command: &'static str,
    /// The local address rotated.
    address: String,
    /// The new operation's identifier.
    operation: String,
    /// The new key's immutable identity.
    hash: String,
    /// The generation it was created as.
    generation: u32,
    /// Where its plaintext went, as the receiver describes itself.
    receiver: String,
    /// Whether the new hash became the address's current key.
    promoted: bool,
    /// The key the address held. Rotation leaves it exactly as it was.
    predecessor: RetainedReport,
    /// What this run established.
    summary: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl RotateReport {
    /// Describes one staged rotation.
    #[must_use]
    pub(crate) fn new(address: &Address, predecessor: Predecessor, successor: Successor) -> Self {
        let status = predecessor.status;
        Self {
            command: "rotate",
            address: format!("keys.{address}"),
            summary: rotation_summary(address, &predecessor, &successor),
            warnings: rotation_warnings(&predecessor, &successor),
            predecessor: RetainedReport::rotated(&predecessor.hash, predecessor.generation, status),
            operation: successor.operation,
            hash: successor.hash,
            generation: successor.generation,
            receiver: successor.receiver,
            promoted: successor.promoted,
        }
    }

    /// Why the predecessor is now tracked, or `still_current` when the
    /// promotion did not land.
    #[must_use]
    pub const fn predecessor_status(&self) -> &'static str {
        self.predecessor.status()
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// What the rotation established, which is not the same sentence when the
/// promotion did not land.
///
/// The promotion is a durable write of its own, after the one that records the
/// delivery, and it can fail on its own. Until it lands the address is still
/// using the predecessor — so the confident version of this sentence would be
/// telling an operator that a key is in service when it is not, and inviting
/// them to retire the one that is.
fn rotation_summary(address: &Address, predecessor: &Predecessor, successor: &Successor) -> String {
    if predecessor.status.is_none() {
        return format!(
            "key {hash} was created at generation {generation} and delivered to {receiver}, and \
             the record that it is now `{address}`'s key could not be written. Nothing remote is \
             outstanding and nothing needs re-delivering; the next `openrouter-keymaster apply` \
             completes the promotion locally. Until it does, `{address}` is still using key {old} \
             — do not retire it yet.",
            hash = successor.hash,
            generation = successor.generation,
            receiver = successor.receiver,
            address = address.as_str(),
            old = predecessor.hash,
        );
    }
    // Never "still enabled". Rotation does not read the predecessor, so this
    // run observed nothing about it; a key created disabled would make the
    // confident sentence false (#23).
    format!(
        "`{address}` now uses key {hash} at generation {generation}, delivered to {receiver}. Key \
         {old} is unchanged: Keymaster neither disabled nor deleted it, and did not read it, so \
         it is whatever it already was. Keymaster cannot know when the consumers of a credential \
         have adopted its successor, so it never retires one for you. Retire it with \
         `openrouter-keymaster retire {address} --hash {old}` once they have.",
        address = address.as_str(),
        hash = successor.hash,
        generation = successor.generation,
        receiver = successor.receiver,
        old = predecessor.hash,
    )
}

/// What an operator must be told about a rotation that did not fully land.
fn rotation_warnings(predecessor: &Predecessor, successor: &Successor) -> Vec<String> {
    let mut warnings = Vec::new();
    if !successor.promoted {
        warnings.push(format!(
            "key {hash} was delivered but not promoted to current; the next `openrouter-keymaster \
             apply` completes that locally, and nothing remote is outstanding",
            hash = successor.hash
        ));
    }
    if predecessor.status.is_none() {
        warnings.push(format!(
            "key {hash} is still recorded as the current key, because the promotion did not land; \
             do not retire it until `openrouter-keymaster status` shows it as \
             `awaiting_retirement`",
            hash = predecessor.hash
        ));
    }
    warnings
}

impl fmt::Display for RotateReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines = [
            format!("rotate {address}", address = self.address),
            format!("  operation:   {}", self.operation),
            format!(
                "  created:     {hash} at generation {generation}",
                hash = self.hash,
                generation = self.generation
            ),
            format!("  delivered:   {}", self.receiver),
            format!("  promoted:    {}", self.promoted),
            format!(
                "  predecessor: {hash} at generation {generation}, now `{status}`",
                hash = self.predecessor.hash(),
                generation = self.predecessor.generation(),
                status = self.predecessor.status()
            ),
            String::new(),
            self.summary.clone(),
        ];
        f.write_str(&lines.join("\n"))
    }
}

/// What `retire` established about one tracked hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetireReport {
    command: &'static str,
    /// The local address the hash belongs to.
    address: String,
    /// The hash that was retired.
    hash: String,
    /// The generation it was created as.
    generation: u32,
    /// Why it is still tracked, after this run.
    status: &'static str,
    /// Whether a fresh read proved the key is disabled.
    confirmed: bool,
    /// What the attempt established. Never contains secret material.
    detail: String,
    /// What this run established.
    summary: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl RetireReport {
    /// Describes one retirement.
    #[must_use]
    pub(crate) fn new(
        address: &Address,
        hash: &KeyHash,
        generation: u32,
        status: RetainedStatus,
        confirmed: bool,
        detail: String,
    ) -> Self {
        Self {
            command: "retire",
            address: format!("keys.{address}"),
            hash: hash.as_str().to_owned(),
            generation,
            status: status.as_str(),
            confirmed,
            detail,
            summary: if confirmed {
                format!(
                    "key {hash} is disabled and a read confirmed it. It stays tracked so an audit \
                     can still see it; `openrouter-keymaster delete key --hash {hash}` removes it \
                     permanently."
                )
            } else {
                format!(
                    "key {hash} is not confirmed disabled and stays tracked as \
                     `retirement_failed`. Nothing is retried automatically; run this command \
                     again, or disable the key yourself."
                )
            },
            warnings: if confirmed {
                Vec::new()
            } else {
                vec![format!(
                    "key {hash} may still be usable: the disable was sent once and a read did not \
                     prove it took"
                )]
            },
        }
    }

    /// Whether a fresh read proved the key is disabled.
    #[must_use]
    pub const fn confirmed(&self) -> bool {
        self.confirmed
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

impl fmt::Display for RetireReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines = [
            format!("retire {address}", address = self.address),
            format!(
                "  key:       {hash} at generation {generation}",
                hash = self.hash,
                generation = self.generation
            ),
            format!("  status:    {}", self.status),
            format!("  confirmed: {}", self.confirmed),
            format!("  detail:    {}", self.detail),
            String::new(),
            self.summary.clone(),
        ];
        f.write_str(&lines.join("\n"))
    }
}

/// What a `delete key` established about the remote key.
///
/// Four outcomes rather than two, because "not deleted" and "deleted" do not
/// cover it: a key OpenRouter never had is the desired end state reached
/// without a deletion, and a delete it accepted but a read still finds is
/// neither a success nor a failure.
/// What `delete workspace` established, and what it released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteWorkspaceReport {
    command: &'static str,
    /// The local address that tracked the workspace.
    address: String,
    /// The UUID that was named.
    id: String,
    /// What the attempt established.
    outcome: DeleteOutcome,
    /// Whether Keymaster still tracks the workspace after this run.
    tracked: bool,
    /// The bindings this run released: the workspace, and the default guardrail
    /// that cannot outlive it.
    released: Vec<String>,
    /// How the outcome was established. Never contains secret material.
    detail: String,
    /// What this run established.
    summary: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl DeleteWorkspaceReport {
    /// Describes one workspace deletion attempt.
    #[must_use]
    pub(crate) fn new(
        address: &Address,
        id: &Uuid,
        outcome: DeleteOutcome,
        detail: String,
        released: Vec<String>,
    ) -> Self {
        let gone = outcome.is_gone();
        Self {
            command: "delete workspace",
            address: format!("workspaces.{address}"),
            id: id.as_str().to_owned(),
            outcome,
            tracked: !gone,
            released,
            detail,
            summary: if gone {
                format!(
                    "OpenRouter has no workspace {id}, and `{address}` no longer tracks it. \
                     Deletion is permanent: the workspace's budgets and its default guardrail went \
                     with it, and there is nothing left to recover."
                )
            } else {
                format!(
                    "workspace {id} is not confirmed gone, so `{address}` still tracks it. The \
                     request was sent exactly once and is never resent automatically."
                )
            },
            warnings: if gone {
                Vec::new()
            } else {
                vec![format!(
                    "workspace {id} may or may not still exist; the binding stays tracked so this \
                     can be retried"
                )]
            },
        }
    }

    /// Whether the run reached a state OpenRouter confirmed.
    #[must_use]
    pub const fn settled(&self) -> bool {
        self.outcome.is_gone()
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "delete workspace: {address}  {id}  {outcome}",
                address = self.address,
                id = self.id,
                outcome = self.outcome.as_str()
            ),
            format!("  {}", self.detail),
        ];
        for released in &self.released {
            lines.push(format!("  released: {released}"));
        }
        lines.push(format!("  {}", self.summary));
        lines
    }
}

impl fmt::Display for DeleteWorkspaceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lines().join("\n"))
    }
}

/// What `delete log-destination` established, and what it released.
///
/// The shape of [`DeleteWorkspaceReport`], because the command is the same
/// shape: one `DELETE`, a read that proves it, and a binding released only when
/// the read did. What it does not carry is an inhabitant list — a log
/// destination holds nothing — and what its summary says instead is that log
/// forwarding for the workspace has stopped (ADR-0006, item 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteDestinationReport {
    command: &'static str,
    /// The local address that tracked the destination.
    address: String,
    /// The UUID that was named.
    id: String,
    /// What the attempt established.
    outcome: DeleteOutcome,
    /// Whether Keymaster still tracks the destination after this run.
    tracked: bool,
    /// The bindings this run released.
    released: Vec<String>,
    /// How the outcome was established. Carries an HTTP status and an
    /// OpenRouter error code at most, never a response body.
    detail: String,
    /// What this run established.
    summary: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl DeleteDestinationReport {
    /// Describes one log destination deletion attempt.
    #[must_use]
    pub(crate) fn new(
        address: &Address,
        id: &Uuid,
        outcome: DeleteOutcome,
        detail: String,
        released: Vec<String>,
    ) -> Self {
        let gone = outcome.is_gone();
        Self {
            command: "delete log-destination",
            address: format!("log_destinations.{address}"),
            id: id.as_str().to_owned(),
            outcome,
            tracked: !gone,
            released,
            detail,
            summary: if gone {
                format!(
                    "OpenRouter has no log destination {id}, and `{address}` no longer tracks it. \
                     Nothing is being forwarded through it any more. If the configuration still \
                     describes the block, the next `openrouter-keymaster apply` creates a new \
                     destination for it."
                )
            } else {
                format!(
                    "log destination {id} is not confirmed gone, so `{address}` still tracks it. \
                     The request was sent exactly once and is never resent automatically."
                )
            },
            warnings: if gone {
                Vec::new()
            } else {
                vec![format!(
                    "log destination {id} may or may not still exist; the binding stays tracked so \
                     this can be retried"
                )]
            },
        }
    }

    /// Whether the run reached a state OpenRouter confirmed.
    #[must_use]
    pub const fn settled(&self) -> bool {
        self.outcome.is_gone()
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

impl fmt::Display for DeleteDestinationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut lines = vec![
            format!(
                "delete log-destination: {address}  {id}  {outcome}",
                address = self.address,
                id = self.id,
                outcome = self.outcome.as_str()
            ),
            format!("  {}", self.detail),
        ];
        for released in &self.released {
            lines.push(format!("  released: {released}"));
        }
        lines.push(format!("  {}", self.summary));
        f.write_str(&lines.join("\n"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteOutcome {
    /// The delete was accepted and a read returned 404.
    Deleted,
    /// OpenRouter had no such key, so there was nothing to delete.
    AlreadyAbsent,
    /// The delete was accepted and its effect could not be proved.
    Unconfirmed,
    /// The delete was refused or never answered.
    Failed,
}

impl DeleteOutcome {
    /// The spelling used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::AlreadyAbsent => "already_absent",
            Self::Unconfirmed => "unconfirmed",
            Self::Failed => "failed",
        }
    }

    /// Whether OpenRouter is known not to have the key any more.
    ///
    /// The only two outcomes that let a hash leave state. Anything else may
    /// still be a live spending credential, and the local record is the one
    /// thing that can find it.
    #[must_use]
    pub const fn is_gone(self) -> bool {
        matches!(self, Self::Deleted | Self::AlreadyAbsent)
    }
}

impl fmt::Display for DeleteOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What `delete key` did to one tracked hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteReport {
    command: &'static str,
    /// The local address that tracked the hash.
    address: String,
    /// The hash that was named.
    hash: String,
    /// The generation it was created as.
    generation: u32,
    /// What the attempt established.
    outcome: DeleteOutcome,
    /// Whether Keymaster still tracks the hash after this run.
    tracked: bool,
    /// How the outcome was established. Never contains secret material.
    detail: String,
    /// What this run established.
    summary: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl DeleteReport {
    /// Describes one deletion attempt.
    #[must_use]
    pub(crate) fn new(
        address: &Address,
        hash: &KeyHash,
        generation: u32,
        outcome: DeleteOutcome,
        detail: String,
    ) -> Self {
        let gone = outcome.is_gone();
        Self {
            command: "delete key",
            address: format!("keys.{address}"),
            hash: hash.as_str().to_owned(),
            generation,
            outcome,
            tracked: !gone,
            detail,
            summary: if gone {
                format!(
                    "OpenRouter has no key {hash}, and `{address}` no longer tracks it. Deletion \
                     is permanent and there is nothing left to recover. Generation {generation} \
                     stays spent at this address — a generation names one remote key for good, so \
                     the next one created here takes a higher number."
                )
            } else {
                format!(
                    "key {hash} is not confirmed gone, so `{address}` still tracks it. The \
                     request was sent exactly once and is never resent automatically; state is \
                     never dropped ahead of the confirmation, because the record is what can \
                     still find a live key."
                )
            },
            warnings: if gone {
                Vec::new()
            } else {
                vec![format!(
                    "key {hash} may or may not still exist; the hash stays tracked as \
                     `retirement_failed` so this can be retried"
                )]
            },
        }
    }

    /// Whether the run reached a state OpenRouter confirmed.
    #[must_use]
    pub const fn settled(&self) -> bool {
        self.outcome.is_gone()
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

impl fmt::Display for DeleteReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines = [
            format!("delete key {hash}", hash = self.hash),
            format!("  address:   {}", self.address),
            format!("  generation: {}", self.generation),
            format!("  outcome:   {}", self.outcome),
            format!("  tracked:   {}", self.tracked),
            format!("  detail:    {}", self.detail),
            String::new(),
            self.summary.clone(),
        ];
        f.write_str(&lines.join("\n"))
    }
}

/// What a `decommission` run established, step by step.
///
/// The two findings travel together because the second is conditional on the
/// first: nothing is deleted until a read has proved the key is out of service,
/// so a `deletion` beside `disabled: false` is a shape this command cannot
/// produce.
#[derive(Debug, Clone)]
pub struct Ending {
    /// Whether a fresh read proved the key is out of service.
    pub disabled: bool,
    /// How that was established. Never contains secret material.
    pub disable_detail: String,
    /// The deletion that followed, when `--delete` asked for one.
    pub deletion: Option<DeleteAttempt>,
    /// The exact command that repeats this run, `--delete` and all.
    ///
    /// Built by the caller and carried here so that the summary an operator
    /// reads and the diagnostic a script reads cannot name different commands.
    pub retry: String,
}

/// What the one `DELETE` of a `decommission --delete` established.
#[derive(Debug, Clone)]
pub struct DeleteAttempt {
    /// What the attempt established.
    pub outcome: DeleteOutcome,
    /// How. Never contains secret material.
    pub detail: String,
}

/// The hash is no longer tracked at all, which only a confirmed deletion does.
const UNTRACKED: &str = "untracked";

/// What `decommission` did to the key an address was using.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecommissionReport {
    command: &'static str,
    /// The local address the key belonged to.
    address: String,
    /// The hash that was named, which had to be the current one.
    hash: String,
    /// The generation it was created as. Spent at this address for good.
    generation: u32,
    /// Whether a fresh read proved the key is out of service.
    disabled: bool,
    /// What the delete established, when `--delete` asked for one.
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted: Option<DeleteOutcome>,
    /// What the address records for the hash now: `current` when the disable
    /// was not confirmed and nothing moved, a retained status when it was, and
    /// `untracked` once OpenRouter is known not to have the key.
    status: &'static str,
    /// Whether Keymaster still tracks the hash after this run.
    tracked: bool,
    /// How the disable was established. Never contains secret material.
    disable_detail: String,
    /// How the deletion was established, when one was attempted.
    #[serde(skip_serializing_if = "Option::is_none")]
    delete_detail: Option<String>,
    /// What this run established.
    summary: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl DecommissionReport {
    /// Describes one decommission.
    #[must_use]
    pub(crate) fn new(address: &Address, hash: &KeyHash, generation: u32, ending: Ending) -> Self {
        let status = tracking(&ending);
        Self {
            command: "decommission",
            address: format!("keys.{address}"),
            hash: hash.as_str().to_owned(),
            generation,
            disabled: ending.disabled,
            deleted: ending.deletion.as_ref().map(|attempt| attempt.outcome),
            status,
            tracked: status != UNTRACKED,
            summary: ending_summary(address, hash, generation, &ending),
            warnings: ending_warnings(address, hash, &ending),
            disable_detail: ending.disable_detail,
            delete_detail: ending.deletion.map(|attempt| attempt.detail),
        }
    }

    /// Whether every step this run took was proved by a read.
    #[must_use]
    pub fn settled(&self) -> bool {
        self.disabled
            && self
                .deleted
                .is_none_or(|outcome: DeleteOutcome| outcome.is_gone())
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// What the address records for the hash after the run.
fn tracking(ending: &Ending) -> &'static str {
    if !ending.disabled {
        // Nothing moved: a disable that was not proved leaves the address using
        // the key it was already using.
        return "current";
    }
    match &ending.deletion {
        None => RetainedStatus::Retired.as_str(),
        Some(attempt) if attempt.outcome.is_gone() => UNTRACKED,
        Some(_) => RetainedStatus::RetirementFailed.as_str(),
    }
}

/// What this run established, which is a different sentence at every step it
/// could have stopped at.
fn ending_summary(address: &Address, hash: &KeyHash, generation: u32, ending: &Ending) -> String {
    if !ending.disabled {
        return format!(
            "key {hash} is not confirmed out of service, so `{address}` still uses it and no \
             state was written. Nothing is retried automatically: run `{retry}` again, or disable \
             the key yourself.",
            retry = ending.retry
        );
    }
    let replacement = replacement_note(address);
    match &ending.deletion {
        None => format!(
            "`{address}` no longer uses key {hash}: a read proved it is out of service, and the \
             address now owns no key. The hash stays tracked as `retired`, so an audit can still \
             see it and `openrouter-keymaster delete key --hash {hash}` can remove it \
             permanently. {replacement}"
        ),
        Some(attempt) if attempt.outcome.is_gone() => format!(
            "OpenRouter has no key {hash}, `{address}` no longer tracks it, and the address now \
             owns no key. Deletion is permanent and there is nothing left to recover. Generation \
             {generation} stays spent at this address — a generation names one remote key for \
             good, so the next one created here takes a higher number. {replacement}"
        ),
        Some(_) => format!(
            "key {hash} is out of service and `{address}` no longer uses it, but it is not \
             confirmed gone, so the hash stays tracked as `retirement_failed`. The delete was \
             sent exactly once and is never resent automatically; `openrouter-keymaster delete \
             key --hash {hash}` retries it. {replacement}"
        ),
    }
}

/// The consequence an operator has to be told about: the address is bound and
/// owns nothing, which is a shape only this command produces.
fn replacement_note(address: &Address) -> String {
    format!(
        "If `keys.{address}` is still in the configuration, the next `openrouter-keymaster apply` \
         creates a replacement key there — a real create, at the next generation, delivered to \
         the configured receiver. Remove the `[keys.{address}]` block first if what you meant was \
         to stop having this key at all."
    )
}

/// What an operator must be told about a decommission, whether it landed or not.
fn ending_warnings(address: &Address, hash: &KeyHash, ending: &Ending) -> Vec<String> {
    if !ending.disabled {
        return vec![format!(
            "key {hash} may still be usable: the disable was sent once and a read did not prove \
             it took, so `{address}` still uses it"
        )];
    }

    let mut warnings = vec![format!(
        "`{address}` now owns no key; the next `openrouter-keymaster apply` creates a replacement \
         there if the configuration still describes it"
    )];
    if ending
        .deletion
        .as_ref()
        .is_some_and(|attempt| !attempt.outcome.is_gone())
    {
        warnings.push(format!(
            "key {hash} may or may not still exist; the hash stays tracked as \
             `retirement_failed` so the delete can be retried"
        ));
    }
    warnings
}

impl fmt::Display for DecommissionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut lines = vec![
            format!("decommission {address}", address = self.address),
            format!(
                "  key:        {hash} at generation {generation}",
                hash = self.hash,
                generation = self.generation
            ),
            format!("  disabled:   {}", self.disabled),
            format!("  disable:    {}", self.disable_detail),
        ];
        if let (Some(outcome), Some(detail)) = (self.deleted, &self.delete_detail) {
            lines.push(format!("  deleted:    {outcome}"));
            lines.push(format!("  delete:     {detail}"));
        }
        lines.push(format!("  status:     {}", self.status));
        lines.push(format!("  tracked:    {}", self.tracked));
        lines.push(String::new());
        lines.push(self.summary.clone());
        f.write_str(&lines.join("\n"))
    }
}

/// One remote identity a `forget` stopped claiming.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Released {
    /// What the identity was to the binding: `current`, a retained status, or
    /// the guardrail's origin.
    role: &'static str,
    /// The immutable identity, as it is addressed.
    identity: String,
    /// The generation, for a key.
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u32>,
}

impl Released {
    /// The key the address was using.
    #[must_use]
    pub(crate) fn current(hash: &KeyHash, generation: u32) -> Self {
        Self {
            role: "current",
            identity: hash.as_str().to_owned(),
            generation: Some(generation),
        }
    }

    /// A key the address still held but no longer used.
    #[must_use]
    pub(crate) fn retained(retained: &RetainedKey) -> Self {
        Self {
            role: retained.status.as_str(),
            identity: retained.hash.as_str().to_owned(),
            generation: Some(retained.generation),
        }
    }

    /// The workspace the address owned.
    #[must_use]
    pub(crate) fn workspace(id: &Uuid, origin: Origin) -> Self {
        Self::by_identity(id, origin)
    }

    /// The guardrail the address owned.
    #[must_use]
    pub(crate) fn guardrail(id: &Uuid, origin: Origin) -> Self {
        Self::by_identity(id, origin)
    }

    /// The log destination the address owned.
    #[must_use]
    pub(crate) fn log_destination(id: &Uuid, origin: Origin) -> Self {
        Self::by_identity(id, origin)
    }

    /// A resource whose whole local record is a UUID and where it came from.
    fn by_identity(id: &Uuid, origin: Origin) -> Self {
        Self {
            role: origin.as_str(),
            identity: id.as_str().to_owned(),
            generation: None,
        }
    }

    fn line(&self) -> String {
        match self.generation {
            Some(generation) => format!(
                "  {identity}  generation {generation}  ({role})",
                identity = self.identity,
                role = self.role
            ),
            None => format!(
                "  {identity}  ({role})",
                identity = self.identity,
                role = self.role
            ),
        }
    }
}

/// What `state forget` relinquished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgetReport {
    command: &'static str,
    /// The address as the operator wrote it.
    address: String,
    /// The resource kind, when something was bound there.
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<&'static str>,
    /// Whether this run removed a binding.
    forgotten: bool,
    /// Every remote identity the binding named. Keymaster no longer owns any of
    /// them, and this run changed none of them — it made no request at all.
    released: Vec<Released>,
    /// What this run established.
    summary: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl ForgetReport {
    /// Describes a binding that was removed.
    #[must_use]
    pub(crate) fn released(
        written: &str,
        resource: &'static str,
        address: &Address,
        released: Vec<Released>,
    ) -> Self {
        let count = super::plural(released.len(), "remote resource");
        Self {
            command: "state forget",
            address: written.to_owned(),
            resource: Some(resource),
            forgotten: true,
            // Never "still live". Forget sends no request, so this run
            // observed nothing about whether any of these resources is still
            // there (#24).
            summary: format!(
                "`{address}` is no longer bound to anything. {count} released and not changed by \
                 this run: forget makes no API call and invokes no receiver, so nothing here was \
                 disabled or deleted, and each may still exist remotely — no request was made to \
                 find out. `openrouter-keymaster plan` now reports whichever of them OpenRouter \
                 still has as unmanaged, and no Keymaster command will touch them again."
            ),
            warnings: forget_warnings(&released),
            released,
        }
    }

    /// Describes an address that was bound to nothing.
    #[must_use]
    pub(crate) fn nothing(written: &str) -> Self {
        Self {
            command: "state forget",
            address: written.to_owned(),
            resource: None,
            forgotten: false,
            released: Vec::new(),
            summary: format!(
                "nothing to forget: `{written}` is not bound to anything, and state was not \
                 written. Repeating a forget that already succeeded changes nothing."
            ),
            warnings: Vec::new(),
        }
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// The warning a release deserves, which depends on whether it let go of
/// anything real.
fn forget_warnings(released: &[Released]) -> Vec<String> {
    if released.is_empty() {
        return Vec::new();
    }
    vec![format!(
        "{count} released and no longer tracked; each may still exist remotely, and no request \
         was made — nothing was disabled or deleted",
        count = super::plural(released.len(), "remote resource")
    )]
}

impl fmt::Display for ForgetReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut lines = vec![format!("state forget {address}", address = self.address)];
        if !self.forgotten {
            lines.push(String::new());
            lines.push(self.summary.clone());
            return f.write_str(&lines.join("\n"));
        }

        lines.push(format!("  resource: {}", self.resource.unwrap_or("(none)")));
        lines.push(format!(
            "released ({count}) — no longer tracked; each may still exist remotely:",
            count = self.released.len()
        ));
        if self.released.is_empty() {
            lines.push("  (none)".to_owned());
        }
        lines.extend(self.released.iter().map(Released::line));
        lines.push(String::new());
        lines.push(self.summary.clone());
        f.write_str(&lines.join("\n"))
    }
}
