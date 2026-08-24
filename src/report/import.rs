//! The `keymaster import` result document.

use std::fmt;

use serde::Serialize;

use super::plan::ChangeReport;
use super::{plural, scrubbed};
use crate::ids::{Address, KeyHash, Uuid};
use crate::plan::FieldChange;
use crate::state::Origin;

/// What an import bound, and what a later apply would still reconcile.
///
/// Nothing here can carry secret material: an address, an immutable identity,
/// an origin, a scrubbed display name, and the managed-field difference the
/// planner computed. An imported key's plaintext was never Keymaster's — that
/// is what `imported` means — so there is nothing to disclose even in
/// principle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    /// Which command produced this document.
    command: &'static str,
    /// The resource kind: `key` or `guardrail`.
    resource: &'static str,
    /// The local address, as the configuration addresses it.
    address: String,
    /// The immutable remote identity that is now bound.
    identity: String,
    /// Where the binding came from. An import records `imported`; a binding
    /// Keymaster created and this run merely confirmed keeps `created`.
    origin: &'static str,
    /// Whether this run recorded a binding. False when the binding already
    /// said exactly this, in which case no state was written.
    bound: bool,
    /// The remote display name, scrubbed. Reported because a mismatch with the
    /// configured name is the most common reason an operator imported the
    /// wrong object.
    remote_name: String,
    /// The managed fields a later apply would reconcile.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    changes: Vec<ChangeReport>,
    /// Diagnostics an operator should see. Human runs write these to stderr;
    /// under `--json` they travel here, because a stream carries exactly one
    /// document.
    warnings: Vec<String>,
}

impl ImportReport {
    /// Describes an imported API key.
    #[must_use]
    pub fn key(
        address: &Address,
        hash: &KeyHash,
        origin: Origin,
        remote_name: &str,
        changes: &[FieldChange],
        bound: bool,
    ) -> Self {
        Self::new(
            "key",
            format!("keys.{address}"),
            format!("key {hash}"),
            origin,
            remote_name,
            changes,
            bound,
        )
    }

    /// Describes an imported guardrail.
    #[must_use]
    pub fn guardrail(
        address: &Address,
        id: &Uuid,
        origin: Origin,
        remote_name: &str,
        changes: &[FieldChange],
        bound: bool,
    ) -> Self {
        Self::new(
            "guardrail",
            format!("guardrails.{address}"),
            format!("guardrail {id}"),
            origin,
            remote_name,
            changes,
            bound,
        )
    }

    fn new(
        resource: &'static str,
        address: String,
        identity: String,
        origin: Origin,
        remote_name: &str,
        changes: &[FieldChange],
        bound: bool,
    ) -> Self {
        let mut report = Self {
            command: "import",
            resource,
            address,
            identity,
            origin: origin.as_str(),
            bound,
            remote_name: scrubbed(remote_name),
            changes: changes.iter().map(ChangeReport::new).collect(),
            warnings: Vec::new(),
        };
        report.warnings = report.build_warnings();
        report
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Whether this run recorded a binding.
    #[must_use]
    pub const fn bound(&self) -> bool {
        self.bound
    }

    fn build_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.changes.is_empty() {
            warnings.push(format!(
                "{} differ from the configuration; `keymaster apply` reconciles them, and \
                 `keymaster plan` shows what it would do",
                plural(self.changes.len(), "managed field")
            ));
        }
        if self.resource == "key" {
            // Worth saying plainly rather than leaving to be discovered: an
            // operator who expects `import` to also hand them the key is going
            // to be disappointed, and the reason is permanent (ADR-0002).
            warnings.push(
                "an imported key's plaintext was never Keymaster's to hold, so it cannot be \
                 delivered to a receiver; raise the key's `generation` to have Keymaster create \
                 and deliver a replacement"
                    .to_owned(),
            );
        }
        warnings
    }

    fn lines(&self) -> Vec<String> {
        let headline = if self.bound {
            format!(
                "imported: {address} is bound to {identity}",
                address = self.address,
                identity = self.identity
            )
        } else {
            format!(
                "unchanged: {address} was already bound to {identity}",
                address = self.address,
                identity = self.identity
            )
        };

        let mut lines = vec![
            headline,
            format!("  origin: {origin}", origin = self.origin),
            format!("  remote name: {name}", name = self.remote_name),
        ];
        if self.changes.is_empty() {
            lines.push("  managed fields: nothing to reconcile".to_owned());
            return lines;
        }
        lines.push(format!(
            "  apply would reconcile {}:",
            plural(self.changes.len(), "managed field")
        ));
        lines.extend(
            self.changes
                .iter()
                .map(|change| format!("    {}", change.describe())),
        );
        lines
    }
}

impl fmt::Display for ImportReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lines().join("\n"))
    }
}
