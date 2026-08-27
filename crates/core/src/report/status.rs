//! The `openrouter-keymaster status` result document.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::{RecoveryReport, money, plural, scrubbed, timestamp};
use crate::api::{
    KeyUsage, ObservedDestination, ObservedGuardrail, ObservedKey, ObservedWorkspace,
};
use crate::config::Config;
use crate::ids::{Address, KeyHash, Uuid};
use crate::plan::Snapshot;
use crate::state::{KeyBinding, PendingOperation, RetainedKey, State};

/// What Keymaster tracks, what OpenRouter has, and what is unfinished.
///
/// Status proposes nothing. It answers four questions an operator asks before
/// deciding anything: which local address owns which remote resource, whether
/// that resource is still there, what each key has spent against its budget,
/// and whether an earlier run left something incomplete.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StatusReport {
    /// Which command produced this document.
    command: &'static str,
    /// Diagnostics an operator should see. Human runs write these to stderr;
    /// under `--json` they travel here, because a stream carries exactly one
    /// document.
    warnings: Vec<String>,
    /// Every workspace address the configuration or state names.
    workspaces: Vec<WorkspaceStatus>,
    /// Every key address the configuration or state names, in address order.
    keys: Vec<KeyStatus>,
    /// Every guardrail address the configuration or state names.
    guardrails: Vec<GuardrailStatus>,
    /// Every log destination address the configuration or state names.
    log_destinations: Vec<DestinationStatus>,
    /// Remote resources no local address owns.
    unmanaged: Vec<UnmanagedStatus>,
    /// The one operation an earlier run left unfinished, if it left one.
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<OperationStatus>,
}

impl StatusReport {
    /// Describes the three read-only inputs, under this run's workspace scope.
    ///
    /// The scope reaches exactly one section: `unmanaged`, which a scoped run
    /// reports only for its own workspace. Bindings are judged from the whole
    /// snapshot either way (ADR-0004, item 5).
    #[must_use]
    pub(crate) fn new(
        config: &Config,
        state: &State,
        observed: &Snapshot,
        workspace: Option<&Uuid>,
    ) -> Self {
        let index = Observed::build(observed);
        let mut report = Self {
            command: "status",
            warnings: Vec::new(),
            workspaces: workspace_statuses(config, state, &index),
            keys: key_statuses(config, state, &index),
            guardrails: guardrail_statuses(config, state, &index),
            log_destinations: destination_statuses(config, state, &index),
            unmanaged: unmanaged_statuses(state, &index, workspace),
            operation: state
                .pending_operation()
                .map(|(address, pending)| OperationStatus::new(address, pending)),
        };
        report.warnings = report.build_warnings();
        report
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn build_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.operation.is_some() {
            warnings.push(
                "an earlier run left an operation unfinished; see the `incomplete operation` \
                 section"
                    .to_owned(),
            );
        }
        let absent = self
            .keys
            .iter()
            .filter(|key| key.present_remotely == Some(false))
            .count();
        if absent > 0 {
            warnings.push(format!(
                "{} bound to a key that is not in the snapshot",
                plural(absent, "address")
            ));
        }
        let unmanaged = self.unmanaged.len();
        if unmanaged > 0 {
            warnings.push(format!(
                "{} that no local address owns; Keymaster will never change one",
                plural(unmanaged, "remote resource")
            ));
        }
        warnings
    }

    fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.workspaces.is_empty() {
            lines.push(format!(
                "workspaces ({count}):",
                count = self.workspaces.len()
            ));
            for workspace in &self.workspaces {
                lines.extend(workspace.lines());
            }
            lines.push(String::new());
        }

        lines.push(format!("keys ({count}):", count = self.keys.len()));
        if self.keys.is_empty() {
            lines.push("  (none)".to_owned());
        }
        for key in &self.keys {
            lines.extend(key.lines());
        }

        lines.push(String::new());
        lines.push(format!(
            "guardrails ({count}):",
            count = self.guardrails.len()
        ));
        if self.guardrails.is_empty() {
            lines.push("  (none)".to_owned());
        }
        for guardrail in &self.guardrails {
            lines.extend(guardrail.lines());
        }

        if !self.log_destinations.is_empty() {
            lines.push(String::new());
            lines.push(format!(
                "log destinations ({count}):",
                count = self.log_destinations.len()
            ));
            for destination in &self.log_destinations {
                lines.extend(destination.lines());
            }
        }

        if !self.unmanaged.is_empty() {
            lines.push(String::new());
            lines.push(format!(
                "unmanaged ({count}):",
                count = self.unmanaged.len()
            ));
            for resource in &self.unmanaged {
                lines.push(format!("  {resource}"));
            }
        }

        if let Some(operation) = &self.operation {
            lines.push(String::new());
            lines.push("incomplete operation:".to_owned());
            lines.push(format!("  {address}", address = operation.address));
            lines.extend(operation.recovery.lines("    "));
        }
        lines
    }
}

impl fmt::Display for StatusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lines().join("\n"))
    }
}

/// One local key address.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct KeyStatus {
    /// The address, as the configuration writes it.
    address: String,
    /// Whether the configuration still describes it.
    configured: bool,
    /// Whether state binds it to a remote key.
    bound: bool,
    /// Bound but no longer configured: tracked, and never touched.
    orphaned: bool,
    /// Whether the binding was imported or created by Keymaster.
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<&'static str>,
    /// The bound key's immutable identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    /// Which generation the bound key is.
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u32>,
    /// Whether the bound key is in the snapshot. Absent when nothing is bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    present_remotely: Option<bool>,
    /// OpenRouter's display name for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_name: Option<String>,
    /// Whether OpenRouter has it disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<bool>,
    /// What it has spent, and what is left. Observed, never desired.
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<UsageStatus>,
    /// The guardrails it is assigned to, by UUID.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    assigned_guardrails: Vec<String>,
    /// Hashes this address still owns but no longer uses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    retained: Vec<RetainedStatus>,
}

impl KeyStatus {
    fn new(
        address: &Address,
        configured: bool,
        binding: Option<&KeyBinding>,
        index: &Observed<'_>,
    ) -> Self {
        let current = binding.and_then(KeyBinding::current);
        let observed = current.and_then(|current| index.keys.get(&current.hash).copied());
        Self {
            address: format!("keys.{address}"),
            configured,
            bound: current.is_some(),
            orphaned: !configured,
            origin: binding.map(|binding| binding.origin().as_str()),
            hash: current.map(|current| current.hash.as_str().to_owned()),
            generation: current.map(|current| current.generation),
            present_remotely: current.map(|_| observed.is_some()),
            remote_name: observed.map(|key| scrubbed(&key.name)),
            disabled: observed.map(|key| key.disabled),
            usage: observed.map(UsageStatus::new),
            assigned_guardrails: observed
                .and_then(|key| index.assignments.get(&key.hash))
                .map(|guardrails| guardrails.iter().map(|id| id.as_str().to_owned()).collect())
                .unwrap_or_default(),
            retained: binding
                .map(|binding| {
                    binding
                        .retained()
                        .iter()
                        .map(|retained| RetainedStatus::new(retained, index))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn lines(&self) -> Vec<String> {
        let mut headline = format!("  {address}", address = self.address);
        match (&self.hash, self.generation, self.origin) {
            (Some(hash), Some(generation), Some(origin)) => {
                headline.push_str(&format!("  {hash}  generation {generation}  {origin}"));
            }
            _ if self.configured => headline.push_str("  not bound"),
            _ => headline.push_str("  tracked, no current key"),
        }
        if self.orphaned {
            headline.push_str("  (orphaned: no longer in the configuration)");
        }
        let mut lines = vec![headline];

        match self.present_remotely {
            Some(true) => {
                let state = if self.disabled == Some(true) {
                    "disabled"
                } else {
                    "enabled"
                };
                let name = self.remote_name.as_deref().unwrap_or("");
                lines.push(format!("      remote: present, {state}, named \"{name}\""));
            }
            Some(false) => lines.push("      remote: absent from the snapshot".to_owned()),
            None => {}
        }
        if let Some(usage) = &self.usage {
            lines.extend(usage.lines("      "));
        }
        if !self.assigned_guardrails.is_empty() {
            lines.push(format!(
                "      assigned to: {}",
                self.assigned_guardrails.join(", ")
            ));
        }
        for retained in &self.retained {
            lines.extend(retained.lines());
        }
        lines
    }
}

/// What a key has spent and what is left of its budget.
///
/// Every amount here is OpenRouter's, read fresh. None of it is ever compared
/// with a desired value: a plan that proposed "fixing" recorded spend would be
/// nonsense.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct UsageStatus {
    /// The limit OpenRouter has, in dollars, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<f64>,
    /// What is left of that limit, in dollars.
    #[serde(skip_serializing_if = "Option::is_none")]
    limit_remaining: Option<f64>,
    total: f64,
    daily: f64,
    weekly: f64,
    monthly: f64,
    byok_total: f64,
    byok_daily: f64,
    byok_weekly: f64,
    byok_monthly: f64,
}

impl UsageStatus {
    fn new(key: &ObservedKey) -> Self {
        let KeyUsage {
            total,
            daily,
            weekly,
            monthly,
            byok_total,
            byok_daily,
            byok_weekly,
            byok_monthly,
            limit_remaining,
        } = key.usage;
        Self {
            limit: key.limit.map(crate::config::Usd::dollars),
            limit_remaining,
            total,
            daily,
            weekly,
            monthly,
            byok_total,
            byok_daily,
            byok_weekly,
            byok_monthly,
        }
    }

    fn lines(&self, indent: &str) -> Vec<String> {
        let budget = match (self.limit, self.limit_remaining) {
            (Some(limit), Some(remaining)) => format!(
                "limit {limit}, remaining {remaining}",
                limit = money(limit),
                remaining = money(remaining)
            ),
            (Some(limit), None) => format!("limit {}, remaining unknown", money(limit)),
            (None, _) => "no limit".to_owned(),
        };
        vec![
            format!(
                "{indent}usage: total {total}, daily {daily}, weekly {weekly}, monthly {monthly}",
                total = money(self.total),
                daily = money(self.daily),
                weekly = money(self.weekly),
                monthly = money(self.monthly)
            ),
            format!("{indent}byok usage: total {}", money(self.byok_total)),
            format!("{indent}budget: {budget}"),
        ]
    }
}

/// A hash an address still owns but no longer uses.
///
/// A retained key is a live credential until something disables it — a
/// predecessor waiting for retirement is the ordinary case — so it is joined
/// against the snapshot like any other key the address owns. Local metadata
/// alone would not answer the two questions worth asking about one: is it
/// still there, and is it still spending?
#[derive(Debug, Clone, PartialEq, Serialize)]
struct RetainedStatus {
    hash: String,
    generation: u32,
    /// Why it is still tracked.
    status: &'static str,
    /// When it reached that status.
    recorded_at: String,
    /// Whether it is still in the snapshot.
    present_remotely: bool,
    /// Whether OpenRouter has it disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<bool>,
    /// What it has spent, and what is left. Absent when it is not there.
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<UsageStatus>,
}

impl RetainedStatus {
    fn new(retained: &RetainedKey, index: &Observed<'_>) -> Self {
        let observed = index.keys.get(&retained.hash).copied();
        Self {
            hash: retained.hash.as_str().to_owned(),
            generation: retained.generation,
            status: retained.status.as_str(),
            recorded_at: timestamp(retained.recorded_at),
            present_remotely: observed.is_some(),
            disabled: observed.map(|key| key.disabled),
            usage: observed.map(UsageStatus::new),
        }
    }

    fn lines(&self) -> Vec<String> {
        let remote = match (self.present_remotely, self.disabled) {
            (false, _) => "absent from the snapshot".to_owned(),
            (true, Some(true)) => "present, disabled".to_owned(),
            (true, _) => "present, enabled".to_owned(),
        };
        let mut lines = vec![format!(
            "      retained: {hash} (generation {generation}, {status} at {recorded_at}); \
             remote: {remote}",
            hash = self.hash,
            generation = self.generation,
            status = self.status,
            recorded_at = self.recorded_at
        )];
        if let Some(usage) = &self.usage {
            lines.extend(usage.lines("        "));
        }
        lines
    }
}

/// One local guardrail address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GuardrailStatus {
    address: String,
    configured: bool,
    bound: bool,
    orphaned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    present_remotely: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_name: Option<String>,
}

impl GuardrailStatus {
    fn lines(&self) -> Vec<String> {
        let mut headline = format!("  {address}", address = self.address);
        match (&self.id, self.origin) {
            (Some(id), Some(origin)) => headline.push_str(&format!("  {id}  {origin}")),
            _ => headline.push_str("  not bound"),
        }
        if self.orphaned {
            headline.push_str("  (orphaned: no longer in the configuration)");
        }
        let mut lines = vec![headline];
        match self.present_remotely {
            Some(true) => lines.push(format!(
                "      remote: present, named \"{name}\"",
                name = self.remote_name.as_deref().unwrap_or("")
            )),
            Some(false) => lines.push("      remote: absent from the snapshot".to_owned()),
            None => {}
        }
        lines
    }
}

/// One local log destination address.
///
/// `config` appears nowhere, and cannot: OpenRouter masks it on read and
/// Keymaster holds only a digest of what it wrote (ADR-0006, item 3). What an
/// operator can check here is everything else — that the destination is there,
/// that it is enabled, and that its allowlist is the empty one Keymaster
/// manages it as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DestinationStatus {
    address: String,
    configured: bool,
    bound: bool,
    orphaned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<&'static str>,
    /// Whether Keymaster has ever written this destination's configuration.
    /// False on an imported one until the first apply.
    config_digest_recorded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    present_remotely: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    privacy_mode: Option<bool>,
    /// How many key hashes OpenRouter has in the allowlist Keymaster manages as
    /// always empty. Anything but zero is drift the next apply clears.
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key_hashes: Option<usize>,
}

impl DestinationStatus {
    fn lines(&self) -> Vec<String> {
        let mut headline = format!("  {address}", address = self.address);
        match (&self.id, self.origin) {
            (Some(id), Some(origin)) => headline.push_str(&format!("  {id}  {origin}")),
            _ => headline.push_str("  not bound"),
        }
        if self.orphaned {
            headline.push_str("  (orphaned: no longer in the configuration)");
        }
        let mut lines = vec![headline];
        match self.present_remotely {
            Some(true) => {
                lines.push(format!(
                    "      remote: present, {state}, type \"{kind}\", named \"{name}\"",
                    state = if self.enabled == Some(true) {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    kind = self.kind.as_deref().unwrap_or(""),
                    name = self.remote_name.as_deref().unwrap_or(""),
                ));
                lines.push(format!(
                    "      privacy mode: {privacy}; key allowlist: {allowlist}",
                    privacy = self.privacy_mode.unwrap_or(false),
                    allowlist = match self.api_key_hashes.unwrap_or(0) {
                        0 => "empty, as Keymaster manages it".to_owned(),
                        count => format!("{count} hashes, which the next apply clears"),
                    }
                ));
            }
            Some(false) => lines.push("      remote: absent from the snapshot".to_owned()),
            None => {}
        }
        if self.bound {
            lines.push(format!(
                "      configuration written by Keymaster: {}",
                self.config_digest_recorded
            ));
        }
        lines
    }
}

/// One local workspace address, with the budgets OpenRouter has in force.
///
/// The budgets are observed rather than desired, like a key's usage: they are
/// what an operator checks before deciding whether spend in the workspace is
/// actually capped.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct WorkspaceStatus {
    address: String,
    configured: bool,
    bound: bool,
    orphaned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    present_remotely: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slug: Option<String>,
    /// The workspace's default guardrail, which governs every key in it.
    #[serde(skip_serializing_if = "Option::is_none")]
    default_guardrail_id: Option<String>,
    /// Whether BYOK spend counts against those budgets.
    #[serde(skip_serializing_if = "Option::is_none")]
    include_byok_in_budgets: Option<bool>,
    /// The budgets in force, by interval, in dollars.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    budgets: BTreeMap<&'static str, f64>,
}

impl WorkspaceStatus {
    fn lines(&self) -> Vec<String> {
        let mut headline = format!("  {address}", address = self.address);
        match (&self.id, self.origin) {
            (Some(id), Some(origin)) => headline.push_str(&format!("  {id}  {origin}")),
            _ => headline.push_str("  not bound"),
        }
        if self.orphaned {
            headline.push_str("  (orphaned: no longer in the configuration)");
        }
        let mut lines = vec![headline];
        match self.present_remotely {
            Some(true) => lines.push(format!(
                "      remote: present, named \"{name}\", slug \"{slug}\"",
                name = self.remote_name.as_deref().unwrap_or(""),
                slug = self.slug.as_deref().unwrap_or(""),
            )),
            Some(false) => lines.push("      remote: absent from the snapshot".to_owned()),
            None => {}
        }
        if let Some(id) = &self.default_guardrail_id {
            lines.push(format!("      default guardrail: {id}"));
        }
        if self.present_remotely == Some(true) {
            let budgets = if self.budgets.is_empty() {
                "none".to_owned()
            } else {
                self.budgets
                    .iter()
                    .map(|(interval, amount)| format!("{interval} {}", money(*amount)))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            lines.push(format!(
                "      budgets: {budgets} (byok counted: {byok})",
                byok = self.include_byok_in_budgets.unwrap_or(false)
            ));
        }
        lines
    }
}

/// A remote resource no local address owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UnmanagedStatus {
    /// `key` or `guardrail`.
    resource: &'static str,
    /// The immutable identity: a hash or a UUID.
    identity: String,
    /// OpenRouter's display name for it.
    name: String,
}

impl fmt::Display for UnmanagedStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "remote {resource} {identity}  named \"{name}\"",
            resource = self.resource,
            identity = self.identity,
            name = self.name
        )
    }
}

/// The one operation an earlier run left unfinished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct OperationStatus {
    /// The address it belongs to.
    address: String,
    /// The generation it would have become.
    generation: u32,
    /// The display name the key was to be created with.
    intended_name: String,
    /// When the receiver definitely refused the plaintext, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_rejected_at: Option<String>,
    /// The operation, its phase, its timestamp, its known hash, and what to
    /// do about it.
    #[serde(flatten)]
    recovery: RecoveryReport,
}

impl OperationStatus {
    fn new(address: &Address, pending: &PendingOperation) -> Self {
        Self {
            address: format!("keys.{address}"),
            generation: pending.generation,
            intended_name: pending.name.as_str().to_owned(),
            delivery_rejected_at: pending.delivery_rejected_at.map(timestamp),
            recovery: RecoveryReport::new(
                &pending.id,
                pending.phase,
                pending.phase_at,
                pending.hash.as_ref(),
                Some(address),
            ),
        }
    }
}

/// The snapshot, indexed by immutable identity so iteration is deterministic.
struct Observed<'a> {
    keys: BTreeMap<&'a KeyHash, &'a ObservedKey>,
    guardrails: BTreeMap<&'a Uuid, &'a ObservedGuardrail>,
    workspaces: BTreeMap<&'a Uuid, &'a ObservedWorkspace>,
    destinations: BTreeMap<&'a Uuid, &'a ObservedDestination>,
    assignments: BTreeMap<&'a KeyHash, BTreeSet<&'a Uuid>>,
}

impl<'a> Observed<'a> {
    fn build(observed: &'a Snapshot) -> Self {
        let mut assignments: BTreeMap<&KeyHash, BTreeSet<&Uuid>> = BTreeMap::new();
        for assignment in &observed.assignments {
            assignments
                .entry(&assignment.key_hash)
                .or_default()
                .insert(&assignment.guardrail_id);
        }
        Self {
            keys: observed.keys.iter().map(|key| (&key.hash, key)).collect(),
            guardrails: observed
                .guardrails
                .iter()
                .map(|guardrail| (&guardrail.id, guardrail))
                .collect(),
            workspaces: observed
                .workspaces
                .iter()
                .map(|workspace| (&workspace.id, workspace))
                .collect(),
            destinations: observed
                .log_destinations
                .iter()
                .map(|destination| (&destination.id, destination))
                .collect(),
            assignments,
        }
    }
}

/// Every key address either input names, in address order.
fn key_statuses(config: &Config, state: &State, index: &Observed<'_>) -> Vec<KeyStatus> {
    addresses(config.keys.keys(), state.keys().keys())
        .map(|address| {
            KeyStatus::new(
                address,
                config.keys.contains_key(address),
                state.key(address),
                index,
            )
        })
        .collect()
}

/// Every guardrail address either input names, in address order.
fn guardrail_statuses(
    config: &Config,
    state: &State,
    index: &Observed<'_>,
) -> Vec<GuardrailStatus> {
    addresses(config.guardrails.keys(), state.guardrails().keys())
        .map(|address| {
            let binding = state.guardrail(address);
            let observed = binding.and_then(|binding| index.guardrails.get(&binding.id).copied());
            GuardrailStatus {
                address: format!("guardrails.{address}"),
                configured: config.guardrails.contains_key(address),
                bound: binding.is_some(),
                orphaned: !config.guardrails.contains_key(address),
                id: binding.map(|binding| binding.id.as_str().to_owned()),
                origin: binding.map(|binding| binding.origin.as_str()),
                present_remotely: binding.map(|_| observed.is_some()),
                remote_name: observed.map(|guardrail| scrubbed(&guardrail.name)),
            }
        })
        .collect()
}

/// Every workspace address either input names, in address order.
fn workspace_statuses(
    config: &Config,
    state: &State,
    index: &Observed<'_>,
) -> Vec<WorkspaceStatus> {
    addresses(config.workspaces.keys(), state.workspaces().keys())
        .map(|address| {
            let binding = state.workspace(address);
            let observed = binding.and_then(|binding| index.workspaces.get(&binding.id).copied());
            WorkspaceStatus {
                address: format!("workspaces.{address}"),
                configured: config.workspaces.contains_key(address),
                bound: binding.is_some(),
                orphaned: !config.workspaces.contains_key(address),
                id: binding.map(|binding| binding.id.as_str().to_owned()),
                origin: binding.map(|binding| binding.origin.as_str()),
                present_remotely: binding.map(|_| observed.is_some()),
                remote_name: observed.map(|workspace| scrubbed(&workspace.name)),
                slug: observed.map(|workspace| scrubbed(&workspace.slug)),
                default_guardrail_id: binding
                    .and_then(|binding| binding.default_guardrail_id.as_ref())
                    .map(|id| id.as_str().to_owned()),
                include_byok_in_budgets: observed.map(|w| w.include_byok_in_budgets),
                budgets: observed
                    .map(|workspace| {
                        workspace
                            .budgets
                            .iter()
                            .map(|(interval, amount)| (interval.as_str(), amount.dollars()))
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect()
}

/// Every log destination address either input names, in address order.
fn destination_statuses(
    config: &Config,
    state: &State,
    index: &Observed<'_>,
) -> Vec<DestinationStatus> {
    addresses(
        config.log_destinations.keys(),
        state.log_destinations().keys(),
    )
    .map(|address| {
        let binding = state.log_destination(address);
        let observed = binding.and_then(|binding| index.destinations.get(&binding.id).copied());
        DestinationStatus {
            address: format!("log_destinations.{address}"),
            configured: config.log_destinations.contains_key(address),
            bound: binding.is_some(),
            orphaned: !config.log_destinations.contains_key(address),
            id: binding.map(|binding| binding.id.as_str().to_owned()),
            origin: binding.map(|binding| binding.origin.as_str()),
            config_digest_recorded: binding.is_some_and(|binding| binding.config_digest.is_some()),
            present_remotely: binding.map(|_| observed.is_some()),
            remote_name: observed.map(|destination| scrubbed(&destination.name)),
            kind: observed.map(|destination| scrubbed(&destination.kind)),
            enabled: observed.map(|destination| destination.enabled),
            privacy_mode: observed.map(|destination| destination.privacy_mode),
            api_key_hashes: observed.map(|destination| destination.api_key_hashes.len()),
        }
    })
    .collect()
}

/// Remote resources no local address owns, by immutable identity.
///
/// A scoped run leaves out everything outside its workspace: those resources
/// are another operator's, and nothing here would ever act on them.
fn unmanaged_statuses(
    state: &State,
    index: &Observed<'_>,
    workspace: Option<&Uuid>,
) -> Vec<UnmanagedStatus> {
    let in_scope = |observed: Option<&Uuid>| workspace.is_none_or(|scope| observed == Some(scope));
    let owned_guardrails: BTreeSet<&Uuid> = state
        .guardrails()
        .values()
        .map(|binding| &binding.id)
        .collect();

    index
        .keys
        .values()
        .filter(|key| in_scope(key.workspace_id.as_ref()))
        .filter(|key| state.address_owning(&key.hash).is_none())
        .map(|key| UnmanagedStatus {
            resource: "key",
            identity: key.hash.as_str().to_owned(),
            name: scrubbed(&key.name),
        })
        .chain(
            index
                .guardrails
                .values()
                .filter(|guardrail| in_scope(guardrail.workspace_id.as_ref()))
                .filter(|guardrail| !owned_guardrails.contains(&guardrail.id))
                .map(|guardrail| UnmanagedStatus {
                    resource: "guardrail",
                    identity: guardrail.id.as_str().to_owned(),
                    name: scrubbed(&guardrail.name),
                }),
        )
        .chain(
            index
                .workspaces
                .values()
                // A workspace is in scope when it *is* the scope.
                .filter(|workspace| in_scope(Some(&workspace.id)))
                .filter(|workspace| state.address_owning_workspace(&workspace.id).is_none())
                .map(|workspace| UnmanagedStatus {
                    resource: "workspace",
                    identity: workspace.id.as_str().to_owned(),
                    name: scrubbed(&workspace.name),
                }),
        )
        .chain(
            index
                .destinations
                .values()
                .filter(|destination| in_scope(destination.workspace_id.as_ref()))
                .filter(|destination| {
                    state
                        .address_owning_log_destination(&destination.id)
                        .is_none()
                })
                .map(|destination| UnmanagedStatus {
                    resource: "log destination",
                    identity: destination.id.as_str().to_owned(),
                    name: scrubbed(&destination.name),
                }),
        )
        .collect()
}

/// The union of two ordered address sets, still ordered and without repeats.
fn addresses<'a>(
    configured: impl Iterator<Item = &'a Address>,
    bound: impl Iterator<Item = &'a Address>,
) -> impl Iterator<Item = &'a Address> {
    configured.chain(bound).collect::<BTreeSet<_>>().into_iter()
}
