//! Rendering tests.
//!
//! The three inputs are built by hand and given to the real planner, so the
//! cases below assert what an operator actually sees rather than what a
//! hand-built DTO could be made to say.

use serde_json::Value;
use time::OffsetDateTime;

use super::recover::Successor;
use super::{
    ActionOutcome, ApplyReport, DeleteOutcome, DeleteReport, ForgetReport, ImportReport,
    PlanReport, Predecessor, Released, RetireReport, RotateReport, StatusReport,
};
use crate::api::{
    KeyUsage, ObservedAssignment, ObservedGuardrail, ObservedKey, RemoteTimestamps, ResetPolicy,
    ZeroDataRetention,
};
use crate::config::{Config, Usd};
use crate::ids::{Address, KeyHash, OperationId, ReceiverFingerprint, RemoteName, Uuid};
use crate::plan::{Expansion, FieldValue, Identity, Plan, Reason, ResourceAddress, Snapshot};
use crate::state::{BeginCreate, Origin, Phase, RetainedKey, RetainedStatus, State, Transition};

/// The planner, unscoped: these cases are about what a report renders, and the
/// workspace scope has its own tests.
fn compute(config: &Config, state: &State, observed: &Snapshot) -> Plan {
    crate::plan::plan(config, state, observed, None)
}

const JOBFEED_HASH: &str = "hash-jobfeed-1";
const STEADY_HASH: &str = "hash-steady-1";
const ROTATE_HASH: &str = "hash-rotate-1";
const SOLO_HASH: &str = "hash-solo-1";
const GONE_HASH: &str = "hash-gone-1";
const ADOPT_HASH: &str = "hash-adopt-1";
const STRANGER_HASH: &str = "hash-stranger-1";
const OLD_HASH: &str = "hash-old-1";

const RAIL_ID: &str = "11111111-1111-4111-8111-111111111111";
const OTHER_RAIL_ID: &str = "22222222-2222-4222-8222-222222222222";
const TAKEN_RAIL_ID: &str = "33333333-3333-4333-8333-333333333333";
const ASSIGNMENT_ID: &str = "44444444-4444-4444-8444-444444444444";
const OTHER_ASSIGNMENT_ID: &str = "55555555-5555-4555-8555-555555555555";

/// A configuration that reaches ten of the eleven action kinds. The eleventh,
/// `recovery_required`, needs an unfinished operation, which stops everything
/// else — so it has a scenario of its own.
const WIDE: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[guardrails.new_rail]
name = "new-rail"

[guardrails.taken]
name = "taken-rail"

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 10
receiver = "vault"
guardrail = "cheap"

[keys.steady]
name = "steady-key"
receiver = "vault"
guardrail = "cheap"

[keys.rotate]
name = "rotate-key"
receiver = "vault"
guardrail = "cheap"
generation = 2

[keys.solo]
name = "solo-key"
receiver = "vault"
clear = ["guardrail"]

[keys.fresh]
name = "fresh-key"
receiver = "vault"
guardrail = "cheap"

[keys.adopt]
name = "adopt-me"
receiver = "vault"

[keys.gone]
name = "gone-key"
receiver = "vault"
"#;

/// One key and one guardrail, so a case can drift either one's display name.
const SCRUB: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
"#;

/// Two key addresses, for the rotation cases.
const RETAINED: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
generation = 2

[keys.steady]
name = "steady-key"
receiver = "vault"
generation = 2
"#;

/// The configuration of the recovery scenario: one key, one operation.
const NARROW: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
"#;

fn address(value: &str) -> Address {
    Address::parse(value).expect("a valid test address")
}

fn hash(value: &str) -> KeyHash {
    KeyHash::parse(value).expect("a valid test hash")
}

fn usd(dollars: f64) -> Usd {
    Usd::from_dollars(dollars).expect("a valid test amount")
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse(value).expect("a valid test UUID")
}

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_767_225_600 + seconds).expect("a valid instant")
}

fn config(source: &str) -> Config {
    Config::parse(source).expect("a valid test configuration")
}

/// The state and snapshot of a scenario, assembled a piece at a time.
struct World {
    state: State,
    snapshot: Snapshot,
}

impl World {
    fn new() -> Self {
        Self {
            state: State::new(),
            snapshot: Snapshot::default(),
        }
    }

    fn observe_key(&mut self, key_hash: &str, name: &str) -> &mut ObservedKey {
        self.snapshot.keys.push(ObservedKey {
            hash: hash(key_hash),
            name: name.to_owned(),
            disabled: false,
            limit: None,
            limit_reset: ResetPolicy::Never,
            include_byok_in_limit: false,
            expires_at: None,
            workspace_id: None,
            creator_user_id: None,
            usage: KeyUsage {
                total: 1.25,
                daily: 0.25,
                weekly: 0.5,
                monthly: 1.25,
                byok_total: 0.0,
                byok_daily: 0.0,
                byok_weekly: 0.0,
                byok_monthly: 0.0,
                limit_remaining: Some(3.75),
            },
            timestamps: RemoteTimestamps::default(),
        });
        self.snapshot.keys.last_mut().expect("the key just pushed")
    }

    fn observe_guardrail(&mut self, id: &str, name: &str) {
        self.snapshot.guardrails.push(ObservedGuardrail {
            id: uuid(id),
            name: name.to_owned(),
            description: None,
            allowed_models: None,
            ignored_models: None,
            allowed_providers: None,
            ignored_providers: None,
            limit: None,
            reset_interval: ResetPolicy::Never,
            include_byok_in_budgets: false,
            zero_data_retention: ZeroDataRetention::default(),
            workspace_id: None,
            timestamps: RemoteTimestamps::default(),
        });
    }

    fn observe_assignment(&mut self, id: &str, key: &str, guardrail: &str) {
        self.snapshot.assignments.push(ObservedAssignment {
            id: uuid(id),
            key_hash: hash(key),
            guardrail_id: uuid(guardrail),
            created_at: None,
        });
    }

    fn bind_key(&mut self, local: &str, key_hash: &str, generation: u32) {
        self.state
            .bind_key(&address(local), hash(key_hash), generation, at(0))
            .expect("binding a key");
    }

    fn bind_guardrail(&mut self, local: &str, id: &str) {
        self.state
            .bind_guardrail(&address(local), uuid(id), Origin::Imported, at(0))
            .expect("binding a guardrail");
    }

    /// Leaves an unfinished operation behind, at whatever phase the
    /// transitions reach.
    fn pending(&mut self, local: &str, transitions: &[Transition]) {
        let local = address(local);
        self.state
            .begin_create(
                &local,
                BeginCreate {
                    operation: OperationId::parse("op-0007").expect("an operation id"),
                    generation: 1,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([1; 32]),
                },
                at(3),
            )
            .expect("starting a create");
        for transition in transitions {
            self.state
                .advance_key(&local, transition.clone(), at(4))
                .expect("advancing the operation");
        }
    }

    /// Runs a whole create-and-deliver through to promotion, which is the only
    /// way an address comes to retain a predecessor.
    fn rotate(&mut self, local: &str, operation: &str, generation: u32, to: &str) {
        let local = address(local);
        self.state
            .begin_create(
                &local,
                BeginCreate {
                    operation: OperationId::parse(operation).expect("an operation id"),
                    generation,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: ReceiverFingerprint::from_digest([2; 32]),
                },
                at(5),
            )
            .expect("starting a create");
        for transition in [
            Transition::Created { hash: hash(to) },
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::Delivered,
        ] {
            self.state
                .advance_key(&local, transition, at(6))
                .expect("advancing the operation");
        }
        self.state
            .promote_key(&local, at(7))
            .expect("promoting the successor");
    }
}

/// A world reaching every action kind but `recovery_required`.
fn wide_world() -> World {
    let mut world = World::new();

    world.bind_guardrail("cheap", RAIL_ID);
    // Bound, and the configuration no longer describes it: an orphan.
    world.bind_guardrail("dropped", OTHER_RAIL_ID);
    world.bind_key("jobfeed", JOBFEED_HASH, 1);
    world.bind_key("steady", STEADY_HASH, 1);
    world.bind_key("rotate", ROTATE_HASH, 1);
    world.bind_key("solo", SOLO_HASH, 1);
    world.bind_key("gone", GONE_HASH, 1);
    world.bind_key("old", OLD_HASH, 1);

    world.observe_guardrail(RAIL_ID, "cheap-rail");
    world.observe_guardrail(OTHER_RAIL_ID, "other-rail");
    world.observe_guardrail(TAKEN_RAIL_ID, "taken-rail");

    // Drift that raises a budget: an update, and a privilege expansion.
    world.observe_key(JOBFEED_HASH, "golf-jobfeed").limit = Some(usd(5.0));
    world.observe_key(STEADY_HASH, "steady-key");
    world.observe_key(ROTATE_HASH, "rotate-key");
    world.observe_key(SOLO_HASH, "solo-key");
    world.observe_key(OLD_HASH, "old-key");
    world.observe_key(ADOPT_HASH, "adopt-me");
    world.observe_key(STRANGER_HASH, "stranger");

    // In sync, so its assignment is a no-op.
    world.observe_assignment(ASSIGNMENT_ID, STEADY_HASH, RAIL_ID);
    // Assigned to the guardrail the configuration cleared: an unassign.
    world.observe_assignment(OTHER_ASSIGNMENT_ID, SOLO_HASH, RAIL_ID);
    world
}

fn wide_report() -> PlanReport {
    let world = wide_world();
    PlanReport::new(&compute(&config(WIDE), &world.state, &world.snapshot))
}

fn document(report: &PlanReport) -> Value {
    serde_json::to_value(report).expect("the report serializes")
}

fn kinds(document: &Value) -> Vec<String> {
    document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .map(|action| action["kind"].as_str().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn every_action_kind_reaches_both_formats() {
    let report = wide_report();
    let human = report.to_string();
    let document = document(&report);
    let kinds = kinds(&document);

    for kind in [
        "create",
        "update",
        "replace",
        "unassign",
        "assign",
        "adoption_required",
        "missing",
        "orphaned_binding",
        "unmanaged",
        "no_op",
    ] {
        assert!(kinds.iter().any(|found| found == kind), "missing {kind}");
        assert!(human.contains(kind), "human output omits {kind}: {human}");
    }
}

#[test]
fn every_safety_class_reaches_both_formats() {
    let report = wide_report();
    let human = report.to_string();
    let document = document(&report);
    let classes: Vec<&str> = document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .filter_map(|action| action["safety"].as_str())
        .collect();

    for class in ["report", "routine", "expanding", "issuing"] {
        assert!(classes.contains(&class), "missing safety class {class}");
        assert!(human.contains(class), "human output omits {class}");
    }
}

#[test]
fn a_privilege_expansion_is_conspicuous_in_both_formats() {
    let report = wide_report();
    let human = report.to_string();
    let document = document(&report);

    assert_eq!(document["expands_privilege"], Value::Bool(true));
    let expanding: Vec<&Value> = document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .filter(|action| action["expands_privilege"] == Value::Bool(true))
        .collect();
    assert!(!expanding.is_empty(), "no action reports an expansion");
    for action in expanding {
        let expansions = action["expansions"]
            .as_array()
            .expect("an explicit expansion array");
        assert!(!expansions.is_empty());
        assert!(
            expansions
                .iter()
                .all(|entry| entry["expansion"].is_string())
        );
    }

    assert!(
        human.contains("! privilege expansions ("),
        "the human form needs a section that cannot be missed: {human}"
    );
    assert!(
        human.lines().any(|line| line.starts_with("! ")),
        "an expanding action needs its own marker: {human}"
    );
    assert!(
        report
            .warnings()
            .iter()
            .any(|warning| warning.contains("widen")),
        "an expansion is worth a warning: {:?}",
        report.warnings()
    );
}

#[test]
fn a_budget_raise_names_the_field_it_widens() {
    let document = document(&wide_report());
    let raised = document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == "keys.jobfeed")
        .expect("the drifting key")
        .clone();

    assert_eq!(raised["kind"], "update");
    assert_eq!(raised["safety"], "expanding");
    assert_eq!(raised["expansions"][0]["expansion"], "budget_raised");
    assert_eq!(raised["expansions"][0]["field"], "limit_usd");
}

#[test]
fn a_converged_plan_says_so_and_still_succeeds() {
    let mut world = World::new();
    world.bind_key("jobfeed", JOBFEED_HASH, 1);
    world.observe_key(JOBFEED_HASH, "golf-jobfeed");

    let report = PlanReport::new(&compute(&config(NARROW), &world.state, &world.snapshot));

    assert!(!report.has_changes());
    assert_eq!(document(&report)["has_changes"], Value::Bool(false));
    assert_eq!(document(&report)["outcome"], "converged");
    assert!(
        report
            .to_string()
            .contains("converged: everything the configuration describes matches"),
        "{report}"
    );
}

/// An empty configuration against an organization full of keys nobody
/// declared: there is nothing to write and nothing for an operator to clear,
/// so the run is converged and the unmanaged keys are reported as what they
/// are.
#[test]
fn unmanaged_resources_alone_are_converged() {
    let mut world = World::new();
    world.observe_key(STRANGER_HASH, "somebody-elses-key");
    world.observe_guardrail(OTHER_RAIL_ID, "somebody-elses-rail");

    let report = PlanReport::new(&compute(
        &config("version = 1\n"),
        &world.state,
        &world.snapshot,
    ));
    let document = document(&report);

    assert_eq!(document["outcome"], "converged");
    assert!(kinds(&document).contains(&"unmanaged".to_owned()));
    assert!(report.to_string().contains("unmanaged"), "{report}");
}

/// The live case that #22 came from: everything the configuration describes
/// matches, and the organization also holds keys Keymaster will never touch.
#[test]
fn a_satisfied_configuration_beside_unmanaged_resources_is_converged() {
    let mut world = World::new();
    world.bind_key("jobfeed", JOBFEED_HASH, 1);
    world.observe_key(JOBFEED_HASH, "golf-jobfeed");
    world.observe_key(STRANGER_HASH, "somebody-elses-key");

    let document = document(&PlanReport::new(&compute(
        &config(NARROW),
        &world.state,
        &world.snapshot,
    )));

    assert_eq!(document["outcome"], "converged");
    assert!(kinds(&document).contains(&"unmanaged".to_owned()));
}

/// An orphaned binding is a report, not work: the configuration dropped the
/// address, and only an explicit command ends the resource.
#[test]
fn an_orphaned_binding_with_nothing_pending_is_converged() {
    let mut world = World::new();
    world.bind_key("dropped", JOBFEED_HASH, 1);
    world.observe_key(JOBFEED_HASH, "golf-jobfeed");

    let document = document(&PlanReport::new(&compute(
        &config("version = 1\n"),
        &world.state,
        &world.snapshot,
    )));

    assert_eq!(document["outcome"], "converged");
    assert!(kinds(&document).contains(&"orphaned_binding".to_owned()));
}

#[test]
fn a_plan_whose_work_is_all_held_back_does_not_claim_a_match() {
    // Nothing is bound, and a remote key carries the configured name: the
    // only action is one an operator has to take, so there is nothing to
    // apply — and saying "matches the configuration" would be the opposite of
    // what is true.
    let mut world = World::new();
    world.observe_key(JOBFEED_HASH, "golf-jobfeed");

    let report = PlanReport::new(&compute(&config(NARROW), &world.state, &world.snapshot));
    let document = document(&report);

    assert_eq!(document["has_changes"], Value::Bool(false));
    assert_eq!(document["outcome"], "held_back");
    assert!(kinds(&document).contains(&"adoption_required".to_owned()));
    let human = report.to_string();
    assert!(human.contains("held back:"), "{human}");
    assert!(!human.contains("matches the configuration"), "{human}");
}

#[test]
fn a_plan_with_executable_work_reports_changes_pending() {
    let document = document(&wide_report());

    assert_eq!(document["has_changes"], Value::Bool(true));
    assert_eq!(document["outcome"], "changes_pending");
    assert!(wide_report().to_string().contains(" to apply."));
}

#[test]
fn a_blocked_plan_is_held_back_rather_than_converged() {
    let mut world = World::new();
    world.pending("jobfeed", &[]);
    world.observe_key(JOBFEED_HASH, "golf-jobfeed");

    let document = document(&PlanReport::new(&compute(
        &config(NARROW),
        &world.state,
        &world.snapshot,
    )));

    assert_eq!(document["blocked"], Value::Bool(true));
    assert_eq!(document["outcome"], "held_back");
}

#[test]
fn a_remote_name_cannot_smuggle_a_credential_or_an_escape_into_output() {
    // Both halves of the threat, in one snapshot: a key whose display name is
    // a credential somebody pasted into the dashboard, and a guardrail whose
    // name carries an ANSI escape that would rewrite the operator's terminal.
    let mut world = World::new();
    world.bind_key("jobfeed", JOBFEED_HASH, 1);
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_key(JOBFEED_HASH, "sk-or-v1-LEAKEDFROMANAME");
    world.observe_guardrail(RAIL_ID, "cheap-rail\u{1b}[2K");

    let plan = compute(&config(SCRUB), &world.state, &world.snapshot);
    let rendered = [
        PlanReport::new(&plan).to_string(),
        serde_json::to_string(&PlanReport::new(&plan)).expect("json"),
        StatusReport::new(&config(SCRUB), &world.state, &world.snapshot, None).to_string(),
        serde_json::to_string(&StatusReport::new(
            &config(SCRUB),
            &world.state,
            &world.snapshot,
            None,
        ))
        .expect("json"),
    ];

    for output in &rendered {
        assert!(
            !output.contains("LEAKEDFROMANAME"),
            "a credential in a display name reached output: {output}"
        );
        assert!(output.contains("[redacted]"), "{output}");
        assert!(
            !output.contains('\u{1b}'),
            "a control character reached output: {output}"
        );
        assert!(
            output.contains("\\u{1b}"),
            "the escape should be shown, escaped: {output}"
        );
    }
}

#[test]
fn a_retained_key_is_joined_against_the_snapshot() {
    let mut world = World::new();
    // One address whose predecessor is still there, disabled; one whose
    // predecessor OpenRouter no longer has.
    world.bind_key("jobfeed", OLD_HASH, 1);
    world.rotate("jobfeed", "op-0011", 2, JOBFEED_HASH);
    world.bind_key("steady", GONE_HASH, 1);
    world.rotate("steady", "op-0012", 2, STEADY_HASH);

    world.observe_key(JOBFEED_HASH, "golf-jobfeed");
    world.observe_key(STEADY_HASH, "steady-key");
    world
        .observe_key(OLD_HASH, "golf-jobfeed-predecessor")
        .disabled = true;

    let report = StatusReport::new(&config(RETAINED), &world.state, &world.snapshot, None);
    let document = serde_json::to_value(&report).expect("the report serializes");
    let keys = document["keys"].as_array().expect("a key array");

    let present = &keys
        .iter()
        .find(|key| key["address"] == "keys.jobfeed")
        .expect("the rotated key")["retained"][0];
    assert_eq!(present["hash"], OLD_HASH);
    assert_eq!(present["generation"], 1);
    assert_eq!(present["present_remotely"], Value::Bool(true));
    assert_eq!(present["disabled"], Value::Bool(true));
    assert_eq!(present["usage"]["total"], 1.25);

    let absent = &keys
        .iter()
        .find(|key| key["address"] == "keys.steady")
        .expect("the other rotated key")["retained"][0];
    assert_eq!(absent["present_remotely"], Value::Bool(false));
    assert!(absent["usage"].is_null());
    assert!(absent["disabled"].is_null());

    let human = report.to_string();
    assert!(
        human.contains(&format!(
            "retained: {OLD_HASH} (generation 1, awaiting_retirement"
        )),
        "{human}"
    );
    assert!(human.contains("remote: present, disabled"), "{human}");
    assert!(
        human.contains("remote: absent from the snapshot"),
        "{human}"
    );
}

#[test]
fn rendering_is_deterministic() {
    let first = wide_report();
    let second = wide_report();

    assert_eq!(first.to_string(), second.to_string());
    assert_eq!(
        serde_json::to_string(&first).expect("json"),
        serde_json::to_string(&second).expect("json")
    );
}

#[test]
fn a_recovery_required_action_reports_the_five_facts() {
    let mut world = World::new();
    world.pending(
        "jobfeed",
        &[Transition::Created {
            hash: hash(JOBFEED_HASH),
        }],
    );
    world.observe_key(JOBFEED_HASH, "golf-jobfeed");

    let report = PlanReport::new(&compute(&config(NARROW), &world.state, &world.snapshot));
    let document = document(&report);
    let action = &document["actions"][0];

    assert_eq!(action["kind"], "recovery_required");
    assert_eq!(document["blocked"], Value::Bool(true));
    assert_eq!(document["has_changes"], Value::Bool(false));

    let recovery = &action["recovery"];
    assert_eq!(recovery["operation"], "op-0007");
    assert_eq!(recovery["phase"], Phase::Created.as_str());
    assert_eq!(recovery["phase_at"], "2026-01-01T00:00:04Z");
    assert_eq!(recovery["known_hash"], JOBFEED_HASH);
    // `created` records a hash, so `recover resolve` refuses it and `recover
    // replace` is what accepts it. The remediation has to name the command that
    // will actually run.
    let remediation = recovery["remediation"].as_str().unwrap_or_default();
    assert!(
        remediation.contains("openrouter-keymaster recover replace jobfeed"),
        "{remediation}"
    );
    assert!(
        !remediation.contains("recover resolve"),
        "a phase whose hash is known has nothing to attest: {remediation}"
    );

    let human = report.to_string();
    for expected in [
        "op-0007",
        "created",
        "2026-01-01T00:00:04Z",
        JOBFEED_HASH,
        "remediation:",
        "unfinished operations (1):",
    ] {
        assert!(human.contains(expected), "human output omits {expected}");
    }
    assert!(
        report
            .warnings()
            .iter()
            .any(|warning| warning.contains("unfinished"))
    );
}

#[test]
fn a_delivered_operation_reports_promotion_rather_than_recovery() {
    let mut world = World::new();
    world.pending(
        "jobfeed",
        &[
            Transition::Created {
                hash: hash(JOBFEED_HASH),
            },
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::Delivered,
        ],
    );
    world.observe_key(JOBFEED_HASH, "golf-jobfeed");

    let document = document(&PlanReport::new(&compute(
        &config(NARROW),
        &world.state,
        &world.snapshot,
    )));
    let action = &document["actions"][0];

    assert_eq!(action["kind"], "no_op");
    assert_eq!(document["blocked"], Value::Bool(false));
    assert_eq!(action["recovery"]["phase"], Phase::Delivered.as_str());
    assert_eq!(action["reasons"][0]["reason"], "promotion_pending");
}

#[test]
fn every_reason_renders_a_sentence_and_a_tagged_object() {
    let identity = Identity::Key(hash(JOBFEED_HASH));
    let operation = OperationId::parse("op-0007").expect("an operation id");
    let reasons = [
        Reason::InSync,
        Reason::Drift,
        Reason::NotCreatedYet,
        Reason::AbsentRemotely,
        Reason::NoNameCollision,
        Reason::NameCollision {
            holders: vec![identity.clone()],
        },
        Reason::NameMatches {
            candidates: vec![identity],
        },
        Reason::GenerationRaised { from: 1, to: 2 },
        Reason::ReceiverChanged,
        Reason::ImmutableFieldChanged {
            field: "expires_at",
        },
        Reason::NoReceiver,
        Reason::ReceiverUnspecified {
            delivered: ReceiverFingerprint::from_digest([1; 32]),
        },
        Reason::AssignmentMissing,
        Reason::AssignmentUndesired,
        Reason::RemovedFromConfiguration,
        Reason::NotConfigured,
        Reason::PromotionPending {
            operation: operation.clone(),
            delivered_at: at(0),
        },
        Reason::OperationIncomplete {
            operation,
            phase: Phase::Secured,
            phase_at: at(0),
        },
        Reason::DeliveryRefused { at: at(0) },
        Reason::PlaintextLost,
        Reason::BlockedBy {
            dependency: ResourceAddress::Guardrail(address("cheap")),
        },
    ];

    for reason in reasons {
        let report = super::plan::ReasonReport::new(&reason);
        assert!(
            !report.sentence().is_empty(),
            "every reason needs a sentence"
        );
        let document = serde_json::to_value(&report).expect("the reason serializes");
        assert!(
            document["reason"].is_string(),
            "every reason is a tagged object: {document}"
        );
    }
}

#[test]
fn every_expansion_names_its_field_when_it_has_one() {
    let with_field = [
        Expansion::BudgetRaised { field: "limit_usd" },
        Expansion::BudgetResetShortened {
            field: "reset_interval",
        },
        Expansion::AllowlistWidened {
            field: "allowed_models",
        },
        Expansion::DenylistNarrowed {
            field: "denied_models",
        },
    ];
    for expansion in with_field {
        let report = super::plan::ExpansionReport::new(expansion);
        assert_eq!(report.expansion, expansion.as_str());
        assert!(report.field.is_some(), "{expansion} should name its field");
        assert!(report.to_string().contains('('));
    }

    for expansion in [
        Expansion::KeyEnabled,
        Expansion::ZdrWeakened,
        Expansion::ByokExcludedFromLimit,
        Expansion::GuardrailRemoved,
    ] {
        let report = super::plan::ExpansionReport::new(expansion);
        assert!(report.field.is_none(), "{expansion} names no field");
        assert_eq!(report.to_string(), expansion.as_str());
    }
}

#[test]
fn a_field_value_reaches_output_as_its_own_rendering() {
    // Guards the assumption the change DTO rests on: a field value renders to
    // a string, and nothing in it is secret-bearing.
    assert_eq!(FieldValue::Absent.to_string(), "(none)");
    assert_eq!(FieldValue::Flag(true).to_string(), "true");
}

#[test]
fn status_reports_bindings_presence_usage_and_unmanaged() {
    let world = wide_world();
    let report = StatusReport::new(&config(WIDE), &world.state, &world.snapshot, None);
    let document = serde_json::to_value(&report).expect("the report serializes");

    let keys = document["keys"].as_array().expect("a key array");
    let jobfeed = keys
        .iter()
        .find(|key| key["address"] == "keys.jobfeed")
        .expect("the bound key");
    assert_eq!(jobfeed["bound"], Value::Bool(true));
    assert_eq!(jobfeed["present_remotely"], Value::Bool(true));
    assert_eq!(jobfeed["hash"], JOBFEED_HASH);
    assert_eq!(jobfeed["origin"], Origin::Imported.as_str());
    assert_eq!(jobfeed["usage"]["total"], 1.25);
    assert_eq!(jobfeed["usage"]["limit_remaining"], 3.75);

    let gone = keys
        .iter()
        .find(|key| key["address"] == "keys.gone")
        .expect("the absent key");
    assert_eq!(gone["present_remotely"], Value::Bool(false));

    let orphan = keys
        .iter()
        .find(|key| key["address"] == "keys.old")
        .expect("the orphaned binding");
    assert_eq!(orphan["orphaned"], Value::Bool(true));
    assert_eq!(orphan["configured"], Value::Bool(false));

    let unmanaged: Vec<&str> = document["unmanaged"]
        .as_array()
        .expect("an unmanaged array")
        .iter()
        .filter_map(|entry| entry["identity"].as_str())
        .collect();
    assert!(unmanaged.contains(&STRANGER_HASH));
    assert!(unmanaged.contains(&TAKEN_RAIL_ID));
    assert!(
        !unmanaged.contains(&OTHER_RAIL_ID),
        "a guardrail an address owns is not unmanaged"
    );

    let human = report.to_string();
    for expected in [
        "keys.jobfeed",
        "guardrails.cheap",
        "usage: total 1.250000",
        "remaining 3.750000",
        "remote: absent from the snapshot",
        "unmanaged (",
        "(orphaned",
    ] {
        assert!(human.contains(expected), "status omits {expected}: {human}");
    }
}

#[test]
fn status_reports_an_unfinished_operation_with_its_remediation() {
    let mut world = World::new();
    world.pending("jobfeed", &[]);

    let report = StatusReport::new(&config(NARROW), &world.state, &world.snapshot, None);
    let document = serde_json::to_value(&report).expect("the report serializes");
    let operation = &document["operation"];

    assert_eq!(operation["address"], "keys.jobfeed");
    assert_eq!(operation["operation"], "op-0007");
    assert_eq!(operation["phase"], Phase::CreateStarted.as_str());
    assert_eq!(operation["phase_at"], "2026-01-01T00:00:03Z");
    assert_eq!(operation["intended_name"], "golf-jobfeed");
    assert!(operation["known_hash"].is_null(), "no hash is known yet");
    assert!(
        operation["remediation"]
            .as_str()
            .is_some_and(|text| text.contains("openrouter-keymaster recover")),
    );

    let human = report.to_string();
    assert!(human.contains("incomplete operation:"));
    assert!(
        report
            .warnings()
            .iter()
            .any(|warning| warning.contains("unfinished"))
    );
}

#[test]
fn status_of_an_empty_project_renders_both_formats() {
    let world = World::new();
    let report = StatusReport::new(&config(NARROW), &world.state, &world.snapshot, None);

    let human = report.to_string();
    assert!(human.contains("keys (1):"));
    assert!(human.contains("not bound"));
    assert!(human.contains("guardrails (0):"));
    serde_json::to_value(&report).expect("the report serializes");
}

// --- import ----------------------------------------------------------------

/// The observed key `NARROW`'s address would be bound to.
fn imported_key(name: &str) -> ObservedKey {
    let mut world = World::new();
    world.observe_key(JOBFEED_HASH, name);
    world.snapshot.keys.pop().expect("the key just observed")
}

#[test]
fn an_import_renders_the_binding_and_the_difference_in_both_formats() {
    let desired = config(NARROW);
    let observed = imported_key("an-older-name");
    let key = desired
        .keys
        .get(&address("jobfeed"))
        .expect("the configured key");
    let changes = crate::plan::key_changes(key, Some(&observed));

    let report = ImportReport::key(
        &address("jobfeed"),
        &hash(JOBFEED_HASH),
        Origin::Imported,
        &observed.name,
        &changes,
        true,
    );

    let human = report.to_string();
    assert!(
        human.contains("imported: keys.jobfeed is bound to key"),
        "{human}"
    );
    assert!(human.contains("origin: imported"), "{human}");
    assert!(
        human.contains("name: an-older-name -> golf-jobfeed"),
        "{human}"
    );

    let document: Value = serde_json::to_value(&report).expect("the report serializes");
    assert_eq!(document["command"], "import");
    assert_eq!(document["resource"], "key");
    assert_eq!(document["bound"], Value::Bool(true));
    assert_eq!(document["changes"][0]["field"], "name");
    assert!(
        report
            .warnings()
            .iter()
            .any(|warning| warning.contains("cannot be delivered")),
        "an imported key's plaintext is permanently unavailable"
    );
}

#[test]
fn a_repeated_import_renders_as_unchanged_with_nothing_to_reconcile() {
    let report = ImportReport::guardrail(
        &address("cheap"),
        &uuid(RAIL_ID),
        Origin::Imported,
        "cheap-rail",
        &[],
        false,
    );

    let human = report.to_string();
    assert!(
        human.contains("unchanged: guardrails.cheap was already bound"),
        "{human}"
    );
    assert!(
        human.contains("managed fields: nothing to reconcile"),
        "{human}"
    );
    assert!(
        report.warnings().is_empty(),
        "a guardrail import with nothing to reconcile warns about nothing"
    );
    serde_json::to_value(&report).expect("the report serializes");
}

// --- apply -----------------------------------------------------------------

#[test]
fn an_apply_renders_every_outcome_in_both_formats() {
    let world = wide_world();
    let plan = compute(&config(WIDE), &world.state, &world.snapshot);

    // One of each state apply can report, spread across the plan's actions.
    let states: [fn() -> ActionOutcome; 5] = [
        || ActionOutcome::applied("patched it"),
        || ActionOutcome::skipped("skipped: #16 owns this"),
        || ActionOutcome::failed("the write failed"),
        || ActionOutcome::not_attempted("not attempted: an earlier write failed"),
        || ActionOutcome::held_back("held back: waiting on guardrails.cheap"),
    ];
    let mut outcomes: Vec<ActionOutcome> = plan
        .actions()
        .iter()
        .enumerate()
        .map(|(index, _)| states[index % states.len()]())
        .collect();
    for outcome in &mut outcomes {
        if outcome.was_attempted() {
            outcome.record_verification(true);
        }
    }

    let report = ApplyReport::new(&plan, &outcomes, None);
    let human = report.to_string();
    for expected in [
        "apply:",
        "applied",
        "skipped",
        "failed",
        "not_attempted",
        "verified",
    ] {
        assert!(
            human.contains(expected),
            "apply output omits {expected}:\n{human}"
        );
    }

    let document: Value = serde_json::to_value(&report).expect("the report serializes");
    assert_eq!(document["command"], "apply");
    assert_eq!(
        document["actions"].as_array().map(Vec::len),
        Some(plan.actions().len()),
        "every planned action is reported"
    );
    assert!(!report.succeeded(), "a failed write is not a success");
    assert_eq!(
        report.unresolved().0,
        outcomes
            .iter()
            .filter(|outcome| outcome.was_attempted())
            .count()
            / 2
    );
}

#[test]
fn an_apply_that_only_reported_unmanaged_resources_is_converged() {
    let mut world = World::new();
    world.bind_key("jobfeed", JOBFEED_HASH, 1);
    world.observe_key(JOBFEED_HASH, "golf-jobfeed");
    world.observe_key(STRANGER_HASH, "somebody-elses-key");
    let plan = compute(&config(NARROW), &world.state, &world.snapshot);
    let outcomes: Vec<ActionOutcome> = plan
        .actions()
        .iter()
        .map(|_| ActionOutcome::reported())
        .collect();

    let report = ApplyReport::new(&plan, &outcomes, None);
    let document: Value = serde_json::to_value(&report).expect("the report serializes");

    assert_eq!(document["outcome"], "converged");
    assert!(report.succeeded());
    assert!(
        report
            .to_string()
            .contains("converged: everything the configuration describes already matches"),
        "{report}"
    );
}

#[test]
fn an_apply_that_wrote_nothing_because_a_write_is_blocked_is_held_back() {
    // The key carries the configured name and nothing binds it: the plan's
    // only work is an adoption, which apply never performs.
    let mut world = World::new();
    world.observe_key(JOBFEED_HASH, "golf-jobfeed");
    let plan = compute(&config(NARROW), &world.state, &world.snapshot);
    let outcomes: Vec<ActionOutcome> = plan
        .actions()
        .iter()
        .map(|_| ActionOutcome::reported())
        .collect();

    let report = ApplyReport::new(&plan, &outcomes, None);
    let document: Value = serde_json::to_value(&report).expect("the report serializes");

    assert_eq!(document["outcome"], "held_back");
    assert!(report.to_string().contains("held back:"), "{report}");
}

#[test]
fn an_apply_that_could_not_verify_says_so() {
    let world = wide_world();
    let plan = compute(&config(WIDE), &world.state, &world.snapshot);
    let outcomes: Vec<ActionOutcome> = plan
        .actions()
        .iter()
        .map(|_| ActionOutcome::reported())
        .collect();

    let report = ApplyReport::new(
        &plan,
        &outcomes,
        Some("nothing could be verified: the read failed".to_owned()),
    );
    assert!(
        report
            .warnings()
            .iter()
            .any(|warning| warning.contains("nothing could be verified")),
        "a failed verification read is a warning of its own"
    );
    let document: Value = serde_json::to_value(&report).expect("the report serializes");
    assert!(document["verification_failure"].is_string());
}

// --- rotate, retire, delete, forget ------------------------------------------

/// One document of each lifecycle command, all acting on `OLD_HASH`.
fn lifecycle_documents() -> (RotateReport, RetireReport, DeleteReport, ForgetReport) {
    let jobfeed = address("jobfeed");
    (
        RotateReport::new(
            &jobfeed,
            Predecessor {
                hash: OLD_HASH.to_owned(),
                generation: 1,
                status: Some(RetainedStatus::AwaitingRetirement),
            },
            Successor {
                operation: "op-0002".to_owned(),
                hash: JOBFEED_HASH.to_owned(),
                generation: 2,
                receiver: "the file /var/lib/keymaster/vault.key".to_owned(),
                promoted: true,
            },
        ),
        RetireReport::new(
            &jobfeed,
            &hash(OLD_HASH),
            1,
            RetainedStatus::Retired,
            true,
            "Keymaster disabled it, and confirmed that by reading it back.".to_owned(),
        ),
        DeleteReport::new(
            &jobfeed,
            &hash(OLD_HASH),
            1,
            DeleteOutcome::Deleted,
            "a read returned 404".to_owned(),
        ),
        ForgetReport::released(
            "keys.jobfeed",
            "key",
            &jobfeed,
            vec![
                Released::current(&hash(JOBFEED_HASH), 2),
                Released::retained(&RetainedKey {
                    hash: hash(OLD_HASH),
                    generation: 1,
                    status: RetainedStatus::AwaitingRetirement,
                    recorded_at: at(0),
                }),
            ],
        ),
    )
}

/// The four lifecycle documents, in both formats, with a hash in every one and
/// a plaintext in none.
///
/// One test rather than four because they share the property that matters: each
/// says which immutable identity it acted on, and none of them has anywhere to
/// put a secret.
#[test]
fn every_lifecycle_document_reports_its_hash_in_both_formats() {
    let (rotated, retired, deleted, forgotten) = lifecycle_documents();

    let documents: [(&str, String, Value); 4] = [
        (
            "rotate",
            rotated.to_string(),
            serde_json::to_value(&rotated).expect("the report serializes"),
        ),
        (
            "retire",
            retired.to_string(),
            serde_json::to_value(&retired).expect("the report serializes"),
        ),
        (
            "delete key",
            deleted.to_string(),
            serde_json::to_value(&deleted).expect("the report serializes"),
        ),
        (
            "state forget",
            forgotten.to_string(),
            serde_json::to_value(&forgotten).expect("the report serializes"),
        ),
    ];

    for (command, human, document) in documents {
        assert_eq!(document["command"], command);
        assert!(
            human.contains(OLD_HASH),
            "{command} must name the hash it acted on:\n{human}"
        );
        assert!(
            !human.contains("sk-or"),
            "{command} rendered something credential-shaped:\n{human}"
        );
    }
}

/// Each document also says what phase the identity it names is now in, which is
/// what an operator reads to decide what to do next.
#[test]
fn every_lifecycle_document_reports_the_phase_its_identity_is_now_in() {
    let (rotated, retired, deleted, forgotten) = lifecycle_documents();

    assert_eq!(rotated.predecessor_status(), "awaiting_retirement");
    assert!(rotated.to_string().contains("awaiting_retirement"));
    assert!(retired.confirmed());
    assert_eq!(
        serde_json::to_value(&retired).expect("the report serializes")["status"],
        "retired"
    );
    assert!(deleted.settled());
    assert_eq!(
        serde_json::to_value(&deleted).expect("the report serializes")["tracked"],
        Value::Bool(false)
    );
    assert_eq!(
        serde_json::to_value(&forgotten).expect("the report serializes")["released"][1]["role"],
        "awaiting_retirement"
    );
    assert!(
        forgotten
            .warnings()
            .iter()
            .any(|warning| warning.contains("may still exist remotely")),
        "forget makes no request, so it says what it let go of and no more"
    );
}

/// A rotation whose promotion landed says the successor is in use.
#[test]
fn a_promoted_rotation_says_the_address_now_uses_the_successor() {
    let (rotated, ..) = lifecycle_documents();
    let summary = serde_json::to_value(&rotated).expect("the report serializes")["summary"]
        .as_str()
        .unwrap_or_default()
        .to_owned();

    assert!(
        summary.contains(&format!("now uses key {JOBFEED_HASH}")),
        "{summary}"
    );
    assert!(
        summary.contains(&format!(
            "openrouter-keymaster retire keys.jobfeed --hash {OLD_HASH}"
        )) || summary.contains(&format!("--hash {OLD_HASH}")),
        "the summary names the command that ends the predecessor: {summary}"
    );
    assert!(rotated.warnings().is_empty(), "{:?}", rotated.warnings());
}

/// And one whose promotion did not must not say it, because it is not true:
/// the address is still using the predecessor, and telling an operator
/// otherwise invites them to retire the key in service.
#[test]
fn an_unpromoted_rotation_says_the_predecessor_is_still_the_key_in_use() {
    let rotated = RotateReport::new(
        &address("jobfeed"),
        Predecessor {
            hash: OLD_HASH.to_owned(),
            generation: 1,
            status: None,
        },
        Successor {
            operation: "op-0002".to_owned(),
            hash: JOBFEED_HASH.to_owned(),
            generation: 2,
            receiver: "a file".to_owned(),
            promoted: false,
        },
    );
    let summary = serde_json::to_value(&rotated).expect("the report serializes")["summary"]
        .as_str()
        .unwrap_or_default()
        .to_owned();

    assert_eq!(rotated.predecessor_status(), "still_current");
    assert!(
        !summary.contains("now uses"),
        "the successor is not in use yet: {summary}"
    );
    assert!(summary.contains("delivered"), "{summary}");
    assert!(
        summary.contains("could not be written"),
        "the summary says which write failed: {summary}"
    );
    assert!(
        summary.contains(&format!("still using key {OLD_HASH}")),
        "{summary}"
    );
    assert!(summary.contains("do not retire it yet"), "{summary}");

    let warnings = rotated.warnings().join("\n");
    assert!(warnings.contains("not promoted to current"), "{warnings}");
    assert!(warnings.contains("do not retire it"), "{warnings}");
}

#[test]
fn forgetting_an_unbound_address_renders_as_a_no_op_in_both_formats() {
    let report = ForgetReport::nothing("keys.jobfeed");
    let document: Value = serde_json::to_value(&report).expect("the report serializes");

    assert_eq!(document["forgotten"], Value::Bool(false));
    assert!(document["resource"].is_null());
    assert!(
        document["released"]
            .as_array()
            .expect("an array")
            .is_empty()
    );
    assert!(report.warnings().is_empty());
    assert!(report.to_string().contains("nothing to forget"));
}

#[test]
fn a_delete_that_is_not_confirmed_keeps_the_hash_tracked_in_both_formats() {
    let report = DeleteReport::new(
        &address("jobfeed"),
        &hash(OLD_HASH),
        1,
        DeleteOutcome::Unconfirmed,
        "the key still reads back".to_owned(),
    );
    let document: Value = serde_json::to_value(&report).expect("the report serializes");

    assert_eq!(document["outcome"], "unconfirmed");
    assert_eq!(document["tracked"], Value::Bool(true));
    assert!(!report.settled());
    assert!(report.to_string().contains("still tracks it"));
}
