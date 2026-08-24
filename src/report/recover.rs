//! The `keymaster recover` result documents.
//!
//! Recovery is the one place where Keymaster tells an operator about a key it
//! cannot account for, so these documents are unusually careful about the
//! difference between a fact and a guess. A *candidate* is a remote key that
//! could be the one an unacknowledged attempt made; it is never called a match,
//! never selected, and never acted on. A *retained* hash is a fact: an operator
//! named it, or the journal recorded it, and Keymaster owns it now.
//!
//! Nothing here can hold a plaintext. The one field written by someone other
//! than Keymaster is a candidate's display name, which goes through
//! [`super::scrubbed`] like every other string OpenRouter chose.

use std::fmt;

use serde::Serialize;
use time::OffsetDateTime;

use super::{plural, scrubbed, timestamp};
use crate::api::ObservedKey;
use crate::ids::{Address, KeyHash};
use crate::state::{PendingOperation, Phase, RetainedStatus};

/// What is known about one unfinished operation.
///
/// Every field is journaled rather than observed: this is what the run that
/// started the attempt wrote down before it sent anything, which is exactly
/// what survives a lost response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationReport {
    /// The attempt's identifier.
    id: String,
    /// How far it got.
    phase: &'static str,
    /// When it reached that phase, RFC 3339.
    phase_at: String,
    /// The generation the attempt would have become.
    generation: u32,
    /// The display name the key was to be created with.
    intended_name: String,
    /// The workspace it was to be created in, when one was configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    intended_workspace: Option<String>,
    /// The created key's hash, when the journal records one.
    #[serde(skip_serializing_if = "Option::is_none")]
    known_hash: Option<String>,
    /// The non-secret digest of the destination the plaintext was bound for.
    receiver_fingerprint: String,
    /// When the receiver definitely refused the delivery, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_rejected_at: Option<String>,
}

impl OperationReport {
    /// Describes one journaled operation.
    #[must_use]
    pub fn new(operation: &PendingOperation) -> Self {
        Self {
            id: operation.id.as_str().to_owned(),
            phase: operation.phase.as_str(),
            phase_at: timestamp(operation.phase_at),
            generation: operation.generation,
            // Journaled through `RemoteName`, which refuses credential-shaped
            // input, so this is checked text rather than whatever a snapshot
            // happened to carry. Scrubbed all the same: the file it was read
            // from is not necessarily one this build wrote.
            intended_name: scrubbed(operation.name.as_str()),
            intended_workspace: operation
                .workspace
                .as_ref()
                .map(|workspace| workspace.as_str().to_owned()),
            known_hash: operation.hash.as_ref().map(|hash| hash.as_str().to_owned()),
            receiver_fingerprint: operation.receiver.as_str().to_owned(),
            delivery_rejected_at: operation.delivery_rejected_at.map(timestamp),
        }
    }

    fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("  operation:  {}", self.id),
            format!("  phase:      {} at {}", self.phase, self.phase_at),
            format!("  generation: {}", self.generation),
            format!("  intended:   name {}", self.intended_name),
        ];
        if let Some(workspace) = &self.intended_workspace {
            lines.push(format!("              workspace {workspace}"));
        }
        lines.push(format!(
            "  known hash: {}",
            self.known_hash.as_deref().unwrap_or(
                "(none — the create response never arrived, so no key is known to exist)"
            )
        ));
        lines.push(format!("  receiver:   {}", self.receiver_fingerprint));
        if let Some(refused) = &self.delivery_rejected_at {
            lines.push(format!("  refused:    the receiver refused at {refused}"));
        }
        lines
    }
}

/// A remote key that could be the one an unacknowledged attempt made.
///
/// Never a match. A display name is mutable and not unique (ADR-0001), and a
/// creation timestamp near an attempt is a coincidence as easily as a
/// consequence. Selecting one is an operator's act, spelled
/// `keymaster recover resolve NAME --leaked-hash HASH`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateReport {
    /// The remote key's immutable identity.
    hash: String,
    /// Its display name, as OpenRouter has it. Scrubbed.
    name: String,
    /// When OpenRouter says it was created, when it says.
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    /// Which workspace it is in.
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<String>,
    /// Whether it is currently disabled.
    disabled: bool,
    /// Why it is being shown: the intended name, the attempt's timing, or both.
    matched_on: Vec<&'static str>,
}

impl CandidateReport {
    /// Describes one candidate and why it is listed.
    #[must_use]
    pub fn new(key: &ObservedKey, matched_on: Vec<&'static str>) -> Self {
        Self {
            hash: key.hash.as_str().to_owned(),
            name: scrubbed(&key.name),
            created_at: key.timestamps.created_at.map(timestamp),
            workspace: key
                .workspace_id
                .as_ref()
                .map(|workspace| workspace.as_str().to_owned()),
            disabled: key.disabled,
            matched_on,
        }
    }

    fn line(&self) -> String {
        format!(
            "  {hash}  name {name}  created {created}  {state}  ({why})",
            hash = self.hash,
            name = self.name,
            created = self.created_at.as_deref().unwrap_or("(unknown)"),
            state = if self.disabled { "disabled" } else { "enabled" },
            why = self.matched_on.join(" and "),
        )
    }
}

/// A hash Keymaster now owns and no longer uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetainedReport {
    /// The key's immutable identity.
    hash: String,
    /// The generation it was created as.
    generation: u32,
    /// Why it is still tracked.
    status: &'static str,
}

impl RetainedReport {
    /// Describes one retained hash.
    #[must_use]
    pub fn new(hash: &KeyHash, generation: u32, status: RetainedStatus) -> Self {
        Self {
            hash: hash.as_str().to_owned(),
            generation,
            status: status.as_str(),
        }
    }
}

/// What `recover inspect` found. Reads only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectReport {
    command: &'static str,
    /// The local address inspected.
    address: String,
    /// The unfinished operation, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<OperationReport>,
    /// Remote keys that could be the one the attempt made. Never matches.
    candidates: Vec<CandidateReport>,
    /// What an operator should do next. Never contains secret material.
    remediation: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl InspectReport {
    /// Reports an address with an unfinished operation.
    #[must_use]
    pub fn found(
        address: &Address,
        operation: &PendingOperation,
        candidates: Vec<CandidateReport>,
    ) -> Self {
        let remediation = super::remediation(operation.phase, Some(address));
        let warnings = candidate_warnings(operation.phase, candidates.len());
        Self {
            command: "recover inspect",
            address: address.as_str().to_owned(),
            operation: Some(OperationReport::new(operation)),
            candidates,
            remediation,
            warnings,
        }
    }

    /// Reports an address with nothing to recover.
    #[must_use]
    pub fn settled(address: &Address) -> Self {
        Self {
            command: "recover inspect",
            address: address.as_str().to_owned(),
            operation: None,
            candidates: Vec::new(),
            remediation: format!(
                "nothing to recover: `{address}` has no operation in progress. `keymaster plan` \
                 reports what an apply would do with it.",
                address = address.as_str()
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

/// The warnings a candidate listing deserves, which depend on how many there
/// are and on whether a hash is already known.
fn candidate_warnings(phase: Phase, candidates: usize) -> Vec<String> {
    if !matches!(phase, Phase::CreateStarted | Phase::CreateAmbiguous) {
        return Vec::new();
    }
    if candidates == 0 {
        return vec![
            "no remote key resembles this attempt. That is not proof it created none: a \
             candidate outside the search window, in another workspace, or already renamed \
             would not be listed. Check OpenRouter yourself before attesting."
                .to_owned(),
        ];
    }
    vec![format!(
        "{} listed as a candidate, not as a match; a display name is mutable and not unique, and \
         a creation time near the attempt proves nothing. Keymaster will not choose one.",
        plural(candidates, "remote key is")
    )]
}

impl fmt::Display for InspectReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut lines = vec![format!("recover inspect {address}", address = self.address)];
        match &self.operation {
            None => lines.push("  no operation in progress".to_owned()),
            Some(operation) => lines.extend(operation.lines()),
        }
        lines.push(String::new());
        lines.push(format!(
            "candidates ({count}) — these are possibilities, not matches:",
            count = self.candidates.len()
        ));
        if self.candidates.is_empty() {
            lines.push("  (none)".to_owned());
        }
        lines.extend(self.candidates.iter().map(CandidateReport::line));
        lines.push(String::new());
        lines.push(format!("remediation: {}", self.remediation));
        f.write_str(&lines.join("\n"))
    }
}

/// What an operator attested, and what Keymaster did about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolveReport {
    command: &'static str,
    /// The local address resolved.
    address: String,
    /// Which attestation this was.
    resolution: &'static str,
    /// The operation that was resolved, when one was.
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    /// The phase it was resolved from.
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_from: Option<&'static str>,
    /// The hash now tracked as a failed candidate, when one was bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    retained: Option<RetainedReport>,
    /// What became of the attempt to make that key harmless.
    #[serde(skip_serializing_if = "Option::is_none")]
    cleanup: Option<String>,
    /// What this run established.
    summary: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl ResolveReport {
    /// An attestation that no resource was created.
    #[must_use]
    pub fn absence(address: &Address, operation: &PendingOperation) -> Self {
        Self {
            command: "recover resolve",
            address: address.as_str().to_owned(),
            resolution: "no_resource_created",
            operation: Some(operation.id.as_str().to_owned()),
            resolved_from: Some(operation.phase.as_str()),
            retained: None,
            cleanup: None,
            summary: format!(
                "operation {operation} is cleared on your attestation that OpenRouter holds no \
                 key from it. Keymaster cannot verify that; if a key does exist, it is now one \
                 nothing tracks. The next `keymaster apply` will create `{address}` afresh.",
                operation = operation.id,
                address = address.as_str()
            ),
            warnings: vec![
                "an attestation is taken at face value: Keymaster has no way to check it, and a \
                 wrong one leaves a live key nothing owns"
                    .to_owned(),
            ],
        }
    }

    /// A leaked hash bound as a failed candidate.
    #[must_use]
    pub fn leaked(
        address: &Address,
        operation: &PendingOperation,
        retained: RetainedReport,
        cleanup: String,
    ) -> Self {
        let hash = retained.hash.clone();
        Self {
            command: "recover resolve",
            address: address.as_str().to_owned(),
            resolution: "leaked_hash",
            operation: Some(operation.id.as_str().to_owned()),
            resolved_from: Some(operation.phase.as_str()),
            retained: Some(retained),
            cleanup: Some(cleanup),
            summary: format!(
                "key {hash} is bound to `{address}` as a failed candidate and operation \
                 {operation} is cleared. Its plaintext was disclosed once, in a response nobody \
                 received, so the key can never be used and is kept only so it can be disabled \
                 and deleted. Create a working key with `keymaster apply`.",
                address = address.as_str(),
                operation = operation.id
            ),
            warnings: Vec::new(),
        }
    }

    /// Nothing was pending, so there was nothing to resolve.
    #[must_use]
    pub fn settled(address: &Address, resolution: &'static str) -> Self {
        Self {
            command: "recover resolve",
            address: address.as_str().to_owned(),
            resolution,
            operation: None,
            resolved_from: None,
            retained: None,
            cleanup: None,
            summary: format!(
                "nothing to resolve: `{address}` has no operation in progress. Repeating a \
                 resolution that already succeeded changes nothing.",
                address = address.as_str()
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

impl fmt::Display for ResolveReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut lines = vec![
            format!("recover resolve {address}", address = self.address),
            format!("  resolution: {}", self.resolution),
        ];
        if let Some(operation) = &self.operation {
            lines.push(format!("  operation:  {operation}"));
        }
        if let Some(retained) = &self.retained {
            lines.push(format!(
                "  retained:   {hash} at generation {generation} as `{status}`",
                hash = retained.hash,
                generation = retained.generation,
                status = retained.status
            ));
        }
        if let Some(cleanup) = &self.cleanup {
            lines.push(format!("  cleanup:    {cleanup}"));
        }
        lines.push(String::new());
        lines.push(self.summary.clone());
        f.write_str(&lines.join("\n"))
    }
}

/// A successor key created for an address whose predecessor is dead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplaceReport {
    command: &'static str,
    /// The local address replaced.
    address: String,
    /// The operation that was retired to make room.
    retired_operation: String,
    /// The dead key, now tracked as a failed candidate.
    retired: RetainedReport,
    /// What became of the attempt to make that key harmless.
    cleanup: String,
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
    /// What this run established.
    summary: String,
    /// Diagnostics an operator should see.
    warnings: Vec<String>,
}

impl ReplaceReport {
    /// Describes one replacement.
    #[must_use]
    pub fn new(address: &Address, retired: Retired, issued: Successor) -> Self {
        Self {
            command: "recover replace",
            address: address.as_str().to_owned(),
            retired_operation: retired.operation,
            retired: retired.key,
            cleanup: retired.cleanup,
            summary: format!(
                "`{address}` now owns key {hash} at generation {generation}, delivered to \
                 {receiver}. The key it replaces stays tracked so it can be deleted explicitly.",
                address = address.as_str(),
                hash = issued.hash,
                generation = issued.generation,
                receiver = issued.receiver
            ),
            warnings: if issued.promoted {
                Vec::new()
            } else {
                vec![
                    "the new key was delivered but not promoted to current; the next `keymaster \
                     apply` completes that locally, and nothing remote is outstanding"
                        .to_owned(),
                ]
            },
            operation: issued.operation,
            hash: issued.hash,
            generation: issued.generation,
            receiver: issued.receiver,
            promoted: issued.promoted,
        }
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// The dead operation a replacement cleared out of the way.
#[derive(Debug, Clone)]
pub struct Retired {
    /// The operation that was retired.
    pub operation: String,
    /// The hash it created, now retained.
    pub key: RetainedReport,
    /// What became of the attempt to disable that hash.
    pub cleanup: String,
}

/// The key a replacement created.
#[derive(Debug, Clone)]
pub struct Successor {
    /// The new operation's identifier.
    pub operation: String,
    /// The new key's immutable identity.
    pub hash: String,
    /// The generation it was created as.
    pub generation: u32,
    /// Where its plaintext went.
    pub receiver: String,
    /// Whether it became the address's current key.
    pub promoted: bool,
}

impl fmt::Display for ReplaceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines = vec![
            format!("recover replace {address}", address = self.address),
            format!(
                "  retired:   operation {operation}, key {hash} as `{status}`",
                operation = self.retired_operation,
                hash = self.retired.hash,
                status = self.retired.status
            ),
            format!("  cleanup:   {}", self.cleanup),
            format!("  operation: {}", self.operation),
            format!(
                "  created:   {hash} at generation {generation}",
                hash = self.hash,
                generation = self.generation
            ),
            format!("  delivered: {}", self.receiver),
            format!("  promoted:  {}", self.promoted),
            String::new(),
            self.summary.clone(),
        ];
        f.write_str(&lines.join("\n"))
    }
}

/// Whether a remote key was created close enough to an attempt to be worth
/// showing.
///
/// Deliberately generous. A candidate that is shown and dismissed costs an
/// operator a glance; one that is not shown costs them a live key nobody owns.
#[must_use]
pub fn created_near(created_at: Option<OffsetDateTime>, attempt: OffsetDateTime) -> bool {
    let Some(created_at) = created_at else {
        // OpenRouter documents the field as free-form text, so a value that did
        // not parse is unknown rather than distant.
        return true;
    };
    (created_at - attempt).abs() <= CANDIDATE_WINDOW
}

/// How far from the journaled attempt a remote key may have been created and
/// still be listed.
///
/// An hour, not a minute. The journal records when the attempt *began*, the
/// snapshot records when OpenRouter says the key was made, and neither clock is
/// the other's; a tight window would silently drop the one candidate that
/// matters.
const CANDIDATE_WINDOW: time::Duration = time::Duration::hours(1);
