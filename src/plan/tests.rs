//! Planner tests.
//!
//! Every case builds the three inputs by hand and calls [`plan`]. There is no
//! harness because there is nothing to mock: the planner reads no clock, no
//! file, and no socket.

use super::*;
use crate::api::{KeyUsage, RemoteTimestamps, ResetPolicy, ZeroDataRetention};
use crate::config::Usd;
use crate::ids::{OperationId, ReceiverFingerprint, RemoteName, UserId};
use crate::state::{BeginCreate, Origin, Transition};

/// An observed key's hash. Printable ASCII, as OpenRouter's hashes are.
const KEY_HASH: &str = "hash-jobfeed-1";
const OTHER_HASH: &str = "hash-stranger-1";
const RAIL_ID: &str = "11111111-1111-4111-8111-111111111111";
const OTHER_RAIL_ID: &str = "22222222-2222-4222-8222-222222222222";
const ASSIGNMENT_ID: &str = "33333333-3333-4333-8333-333333333333";
const OTHER_ASSIGNMENT_ID: &str = "44444444-4444-4444-8444-444444444444";

/// A configuration with one guardrail, one key, and one receiver.
const BASE: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
guardrail = "cheap"
"#;

fn address(value: &str) -> Address {
    Address::parse(value).expect("a valid test address")
}

fn hash(value: &str) -> KeyHash {
    KeyHash::parse(value).expect("a valid test hash")
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse(value).expect("a valid test UUID")
}

fn usd(dollars: f64) -> Usd {
    Usd::from_dollars(dollars).expect("a valid test amount")
}

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_767_225_600 + seconds).expect("a valid instant")
}

/// The three planner inputs, assembled a piece at a time.
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

    /// An observed key with nothing set, returned so a case can set what it is
    /// about.
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
                total: 0.0,
                daily: 0.0,
                weekly: 0.0,
                monthly: 0.0,
                byok_total: 0.0,
                byok_daily: 0.0,
                byok_weekly: 0.0,
                byok_monthly: 0.0,
                limit_remaining: None,
            },
            timestamps: RemoteTimestamps::default(),
        });
        self.snapshot.keys.last_mut().expect("the key just pushed")
    }

    fn observe_guardrail(&mut self, id: &str, name: &str) -> &mut ObservedGuardrail {
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
        self.snapshot
            .guardrails
            .last_mut()
            .expect("the guardrail just pushed")
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

    /// Journals a create through to a promoted current key, which is the only
    /// way a binding records where the plaintext went.
    fn deliver_key(
        &mut self,
        local: &str,
        key_hash: &str,
        generation: u32,
        receiver: ReceiverFingerprint,
    ) {
        let local = address(local);
        self.state
            .begin_create(
                &local,
                BeginCreate {
                    operation: OperationId::parse("op-0001").expect("an operation id"),
                    generation,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver,
                },
                at(0),
            )
            .expect("starting a create");
        for transition in [
            Transition::Created {
                hash: hash(key_hash),
            },
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::Delivered,
        ] {
            self.state
                .advance_key(&local, transition, at(1))
                .expect("advancing the operation");
        }
        self.state.promote_key(&local, at(2)).expect("promoting");
    }

    /// Leaves an unfinished operation behind, at whatever phase `transitions`
    /// reaches.
    fn pending(&mut self, local: &str, generation: u32, transitions: &[Transition]) {
        let local = address(local);
        self.state
            .begin_create(
                &local,
                BeginCreate {
                    operation: OperationId::parse("op-0007").expect("an operation id"),
                    generation,
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

    /// Leaves an operation at `create_started`: sent, unacknowledged.
    fn begin_create(&mut self, local: &str, generation: u32) {
        self.pending(local, generation, &[]);
    }

    fn plan(&self, config: &str) -> Plan {
        let config = Config::parse(config).expect("a valid test configuration");
        plan(&config, &self.state, &self.snapshot)
    }
}

/// The fingerprint of the `vault` receiver [`BASE`] configures.
fn vault_fingerprint() -> ReceiverFingerprint {
    Config::parse(BASE)
        .expect("a valid test configuration")
        .receivers
        .get(&address("vault"))
        .expect("the configured receiver")
        .fingerprint()
}

/// A key and a guardrail that are bound, present, and already correct.
fn converged(world: &mut World) {
    world.bind_guardrail("cheap", RAIL_ID);
    world.bind_key("jobfeed", KEY_HASH, 1);
    world.observe_guardrail(RAIL_ID, "cheap-rail");
    world.observe_key(KEY_HASH, "golf-jobfeed");
    world.observe_assignment(ASSIGNMENT_ID, KEY_HASH, RAIL_ID);
}

/// One table row: inputs, and the actions the planner must produce in order.
struct Case {
    name: &'static str,
    config: &'static str,
    build: fn(&mut World),
    expect: &'static [(&'static str, ActionKind)],
}

const CASES: &[Case] = &[
    Case {
        name: "nothing to do",
        config: BASE,
        build: converged,
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::NoOp),
            ("keys.jobfeed.guardrail", ActionKind::NoOp),
        ],
    },
    Case {
        name: "nothing exists yet",
        config: BASE,
        build: |_| {},
        expect: &[
            ("guardrails.cheap", ActionKind::Create),
            ("keys.jobfeed", ActionKind::Create),
            ("keys.jobfeed.guardrail", ActionKind::Assign),
        ],
    },
    Case {
        name: "a matching remote name is never adopted by itself",
        config: BASE,
        build: |world| {
            world.observe_guardrail(RAIL_ID, "cheap-rail");
            world.observe_key(KEY_HASH, "golf-jobfeed");
        },
        // The candidates are still unowned, so they are reported as unmanaged
        // too: nothing is Keymaster's until an operator imports it.
        expect: &[
            ("guardrails.cheap", ActionKind::AdoptionRequired),
            ("keys.jobfeed", ActionKind::AdoptionRequired),
            ("remote key hash-jobfeed-1", ActionKind::Unmanaged),
            (
                "remote guardrail 11111111-1111-4111-8111-111111111111",
                ActionKind::Unmanaged,
            ),
        ],
    },
    Case {
        name: "drift in managed fields",
        config: BASE,
        build: |world| {
            converged(world);
            world.snapshot.guardrails[0].name = "renamed-in-the-dashboard".to_owned();
            world.snapshot.keys[0].name = "renamed-too".to_owned();
        },
        expect: &[
            ("guardrails.cheap", ActionKind::Update),
            ("keys.jobfeed", ActionKind::Update),
            ("keys.jobfeed.guardrail", ActionKind::NoOp),
        ],
    },
    Case {
        name: "a raised generation replaces the key",
        config: r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
guardrail = "cheap"
generation = 2
"#,
        build: converged,
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::Replace),
            ("keys.jobfeed.guardrail", ActionKind::Assign),
        ],
    },
    Case {
        name: "an immutable field replaces the key",
        config: r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
guardrail = "cheap"
expires_at = "2027-01-01T00:00:00Z"
"#,
        build: converged,
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::Replace),
            ("keys.jobfeed.guardrail", ActionKind::Assign),
        ],
    },
    Case {
        // `creator_user_id` is accepted by `POST /keys` and by nothing else, so
        // a key created for one member can never be moved to another: the only
        // way to honour a changed creator is a replacement.
        name: "a changed creator replaces the key",
        config: r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
guardrail = "cheap"
creator_user_id = "user_2dHFtVWx2n56w6HkM0000000000"
"#,
        build: converged,
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::Replace),
            ("keys.jobfeed.guardrail", ActionKind::Assign),
        ],
    },
    Case {
        // The mirror of the case above, and the one that matters more: a
        // creator that already matches must not read as drift, or every plan
        // for an organization-owned key would propose replacing it.
        name: "a creator that already matches is no reason to replace anything",
        config: r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
guardrail = "cheap"
creator_user_id = "user_2dHFtVWx2n56w6HkM0000000000"
"#,
        build: |world| {
            converged(world);
            world
                .snapshot
                .keys
                .last_mut()
                .expect("the observed key")
                .creator_user_id =
                Some(UserId::parse("user_2dHFtVWx2n56w6HkM0000000000").expect("a valid user id"));
        },
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::NoOp),
            ("keys.jobfeed.guardrail", ActionKind::NoOp),
        ],
    },
    Case {
        name: "a delivered key that vanished is reported, never recreated",
        config: BASE,
        build: |world| {
            converged(world);
            world.snapshot.keys.clear();
            world.snapshot.assignments.clear();
        },
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::Missing),
        ],
    },
    Case {
        name: "a guardrail that vanished is recreated when no name collides",
        config: BASE,
        build: |world| {
            converged(world);
            // Deleting a guardrail takes its assignments with it.
            world.snapshot.guardrails.clear();
            world.snapshot.assignments.clear();
        },
        expect: &[
            ("guardrails.cheap", ActionKind::Create),
            ("keys.jobfeed", ActionKind::NoOp),
            ("keys.jobfeed.guardrail", ActionKind::Assign),
        ],
    },
    Case {
        name: "a guardrail that vanished is not recreated over a name collision",
        config: BASE,
        build: |world| {
            converged(world);
            world.snapshot.guardrails.clear();
            world.snapshot.assignments.clear();
            world.observe_guardrail(OTHER_RAIL_ID, "cheap-rail");
        },
        expect: &[
            ("guardrails.cheap", ActionKind::Missing),
            ("keys.jobfeed", ActionKind::NoOp),
            ("keys.jobfeed.guardrail", ActionKind::Assign),
            (
                "remote guardrail 22222222-2222-4222-8222-222222222222",
                ActionKind::Unmanaged,
            ),
        ],
    },
    Case {
        name: "clearing the guardrail unassigns the key",
        config: r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
clear = ["guardrail"]
"#,
        build: converged,
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::NoOp),
            ("keys.jobfeed.guardrail", ActionKind::Unassign),
        ],
    },
    Case {
        name: "a key assigned to the wrong guardrail is moved",
        config: BASE,
        build: |world| {
            converged(world);
            world.snapshot.assignments.clear();
            world.observe_guardrail(OTHER_RAIL_ID, "another-rail");
            world.observe_assignment(OTHER_ASSIGNMENT_ID, KEY_HASH, OTHER_RAIL_ID);
        },
        // One write, not a removal and an assignment: a key has at most one
        // direct guardrail, and assigning replaces it.
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::NoOp),
            ("keys.jobfeed.guardrail", ActionKind::Assign),
            (
                "remote guardrail 22222222-2222-4222-8222-222222222222",
                ActionKind::Unmanaged,
            ),
        ],
    },
    Case {
        name: "a binding the configuration dropped stays tracked",
        config: r#"
version = 1

[guardrails.cheap]
name = "cheap-rail"
"#,
        build: converged,
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::OrphanedBinding),
        ],
    },
    Case {
        name: "remote resources nothing owns are reported and left alone",
        config: BASE,
        build: |world| {
            converged(world);
            world.observe_key(OTHER_HASH, "someone-elses-key");
            world.observe_guardrail(OTHER_RAIL_ID, "someone-elses-rail");
        },
        expect: &[
            ("guardrails.cheap", ActionKind::NoOp),
            ("keys.jobfeed", ActionKind::NoOp),
            ("keys.jobfeed.guardrail", ActionKind::NoOp),
            ("remote key hash-stranger-1", ActionKind::Unmanaged),
            (
                "remote guardrail 22222222-2222-4222-8222-222222222222",
                ActionKind::Unmanaged,
            ),
        ],
    },
    Case {
        name: "an unfinished operation is reported first and blocks the run",
        config: BASE,
        build: |world| {
            converged(world);
            world.begin_create("jobfeed", 2);
        },
        expect: &[
            ("keys.jobfeed", ActionKind::RecoveryRequired),
            ("guardrails.cheap", ActionKind::NoOp),
        ],
    },
    Case {
        name: "a key with nowhere to deliver is never created",
        config: r#"
version = 1

[keys.jobfeed]
name = "golf-jobfeed"
"#,
        build: |_| {},
        expect: &[("keys.jobfeed", ActionKind::NoOp)],
    },
];

#[test]
fn every_case_produces_exactly_the_expected_actions_in_order() {
    for case in CASES {
        let mut world = World::new();
        (case.build)(&mut world);
        let plan = world.plan(case.config);

        let produced: Vec<(String, ActionKind)> = plan
            .actions()
            .iter()
            .map(|action| (action.address.to_string(), action.kind))
            .collect();
        let expected: Vec<(String, ActionKind)> = case
            .expect
            .iter()
            .map(|(address, kind)| ((*address).to_owned(), *kind))
            .collect();
        assert_eq!(produced, expected, "{}", case.name);
    }
}

#[test]
fn the_table_covers_every_action_kind() {
    let covered: BTreeSet<ActionKind> = CASES
        .iter()
        .flat_map(|case| case.expect.iter().map(|(_, kind)| *kind))
        .collect();

    let all = [
        ActionKind::RecoveryRequired,
        ActionKind::Create,
        ActionKind::Update,
        ActionKind::Replace,
        ActionKind::Unassign,
        ActionKind::Assign,
        ActionKind::AdoptionRequired,
        ActionKind::Missing,
        ActionKind::OrphanedBinding,
        ActionKind::Unmanaged,
        ActionKind::NoOp,
    ];
    for kind in all {
        assert!(covered.contains(&kind), "no case produces `{kind}`");
    }
}

#[test]
fn empty_drift_produces_only_no_ops() {
    let mut world = World::new();
    converged(&mut world);
    let plan = world.plan(BASE);

    assert!(
        plan.actions()
            .iter()
            .all(|action| action.kind == ActionKind::NoOp),
        "{:?}",
        plan.actions()
    );
    assert!(!plan.has_changes());
    assert_eq!(plan.executable().count(), 0);
}

#[test]
fn replanning_identical_inputs_produces_an_identical_plan() {
    for case in CASES {
        let mut world = World::new();
        (case.build)(&mut world);

        let first = world.plan(case.config);
        let second = world.plan(case.config);
        assert_eq!(first, second, "{}", case.name);
        // Byte-identical when rendered, not merely equal by `PartialEq`.
        assert_eq!(format!("{first:?}"), format!("{second:?}"), "{}", case.name);
    }
}

#[test]
fn the_order_of_the_snapshot_does_not_change_the_plan() {
    let mut world = World::new();
    converged(&mut world);
    world.observe_key(OTHER_HASH, "someone-elses-key");
    world.observe_guardrail(OTHER_RAIL_ID, "someone-elses-rail");
    world.observe_assignment(OTHER_ASSIGNMENT_ID, OTHER_HASH, OTHER_RAIL_ID);
    let planned = world.plan(BASE);

    world.snapshot.keys.reverse();
    world.snapshot.guardrails.reverse();
    world.snapshot.assignments.reverse();
    assert_eq!(planned, world.plan(BASE));
}

#[test]
fn dependencies_are_planned_before_the_actions_that_need_them() {
    let plan = World::new().plan(BASE);

    let positions: Vec<&ResourceAddress> = plan
        .actions()
        .iter()
        .map(|action| &action.address)
        .collect();
    for (index, action) in plan.actions().iter().enumerate() {
        for dependency in &action.depends_on {
            let at = positions.iter().position(|address| *address == dependency);
            assert!(
                at.is_some_and(|at| at < index),
                "{} depends on {dependency}, which is not planned before it",
                action.address
            );
        }
    }

    // The assignment names both ends, and both are earlier.
    let assign = plan
        .actions()
        .iter()
        .find(|action| action.kind == ActionKind::Assign)
        .expect("an assignment");
    assert_eq!(
        assign.depends_on,
        vec![
            ResourceAddress::Key(address("jobfeed")),
            ResourceAddress::Guardrail(address("cheap")),
        ]
    );
}

#[test]
fn an_unresolved_dependency_holds_back_everything_that_needs_it() {
    // The guardrail's name matches a remote one, so it needs an operator. The
    // key would be created and assigned to it, and neither may happen: a key
    // created now would be delivered without the restrictions it was supposed
    // to be secured with.
    let mut world = World::new();
    world.observe_guardrail(RAIL_ID, "cheap-rail");
    let plan = world.plan(BASE);

    let guardrail = action_at(&plan, "guardrails.cheap");
    assert_eq!(guardrail.kind, ActionKind::AdoptionRequired);
    assert!(!guardrail.is_blocked(), "the blocker is not itself blocked");

    let key = action_at(&plan, "keys.jobfeed");
    assert_eq!(key.kind, ActionKind::Create);
    assert!(key.is_blocked());
    assert!(key.rationale.contains(&Reason::BlockedBy {
        dependency: ResourceAddress::Guardrail(address("cheap")),
    }));

    // Transitive: the assignment needs the key, which needs the guardrail.
    let assignment = action_at(&plan, "keys.jobfeed.guardrail");
    assert_eq!(assignment.kind, ActionKind::Assign);
    assert!(assignment.rationale.contains(&Reason::BlockedBy {
        dependency: ResourceAddress::Key(address("jobfeed")),
    }));

    // Everything is still described, and nothing is executable.
    assert_eq!(plan.actions().len(), 4);
    assert!(!plan.has_changes());
    assert_eq!(plan.executable().count(), 0);
}

#[test]
fn a_resolved_dependency_holds_nothing_back() {
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_guardrail(RAIL_ID, "cheap-rail");
    let plan = world.plan(BASE);

    assert_eq!(action_at(&plan, "guardrails.cheap").kind, ActionKind::NoOp);
    for address in ["keys.jobfeed", "keys.jobfeed.guardrail"] {
        assert!(!action_at(&plan, address).is_blocked(), "{address}");
    }
    assert_eq!(plan.executable().count(), 2);
}

#[test]
fn a_guardrail_another_address_owns_still_blocks_a_recreation() {
    // `other` owns a guardrail somebody renamed in the dashboard, and the name
    // they gave it is the one `cheap` is configured with. `cheap`'s own
    // guardrail is gone. Recreating it would put a second guardrail under a
    // name that is already taken, so ownership does not make the collision go
    // away — it only decides who could import it.
    let config = r#"
version = 1

[guardrails.cheap]
name = "cheap-rail"

[guardrails.other]
name = "other-rail"
"#;
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    world.bind_guardrail("other", OTHER_RAIL_ID);
    world.observe_guardrail(OTHER_RAIL_ID, "cheap-rail");

    let plan = world.plan(config);
    let action = action_at(&plan, "guardrails.cheap");
    assert_eq!(action.kind, ActionKind::Missing);
    assert_eq!(
        action.rationale,
        vec![
            Reason::AbsentRemotely,
            Reason::NameCollision {
                holders: vec![Identity::Guardrail(uuid(OTHER_RAIL_ID))],
            },
        ]
    );
    // The owner is still reconciled: it is the rename that has to go first.
    assert_eq!(
        action_at(&plan, "guardrails.other").kind,
        ActionKind::Update
    );
}

#[test]
fn a_remote_object_another_address_owns_is_never_offered_to_a_second_one() {
    // `jobfeed` owns the key and `cheap` the guardrail. `spare` and `backup`
    // are unbound and carry names that match nothing else, so nothing they
    // could adopt exists.
    let config = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[guardrails.backup]
name = "cheap-rail-too"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"

[keys.spare]
name = "golf-jobfeed-too"
receiver = "vault"
"#;
    let mut world = World::new();
    world.bind_key("jobfeed", KEY_HASH, 1);
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_key(KEY_HASH, "golf-jobfeed-too");
    world.observe_guardrail(RAIL_ID, "cheap-rail-too");
    let plan = world.plan(config);

    // Both remote objects now carry the *other* address's configured name.
    // Neither may be offered to it: they already belong to somebody.
    for (address, kind) in [
        ("keys.spare", ActionKind::Create),
        ("guardrails.backup", ActionKind::Create),
    ] {
        let action = action_at(&plan, address);
        assert_eq!(action.kind, kind, "{address}");
        assert_eq!(action.rationale, vec![Reason::NotCreatedYet], "{address}");
    }
    // And the owners see the rename as ordinary drift.
    assert_eq!(action_at(&plan, "keys.jobfeed").kind, ActionKind::Update);
    assert_eq!(
        action_at(&plan, "guardrails.cheap").kind,
        ActionKind::Update
    );
    // Nothing is unmanaged: every remote object has an owner.
    assert!(
        !plan
            .actions()
            .iter()
            .any(|action| action.kind == ActionKind::Unmanaged)
    );
}

#[test]
fn a_retained_predecessor_is_managed_rather_than_unmanaged() {
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_guardrail(RAIL_ID, "cheap-rail");
    world.deliver_key("jobfeed", OTHER_HASH, 1, vault_fingerprint());
    world.deliver_key("jobfeed", KEY_HASH, 2, vault_fingerprint());
    world.observe_key(KEY_HASH, "golf-jobfeed");
    world.observe_key(OTHER_HASH, "golf-jobfeed");
    world.observe_assignment(ASSIGNMENT_ID, KEY_HASH, RAIL_ID);

    let config = BASE.replace(
        "receiver = \"vault\"",
        "receiver = \"vault\"\ngeneration = 2",
    );
    let plan = world.plan(&config);
    assert!(
        !plan
            .actions()
            .iter()
            .any(|action| action.kind == ActionKind::Unmanaged),
        "{:?}",
        plan.actions()
    );
    assert_eq!(action_at(&plan, "keys.jobfeed").kind, ActionKind::NoOp);
}

#[test]
fn a_changed_delivery_destination_replaces_the_key() {
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_guardrail(RAIL_ID, "cheap-rail");
    world.deliver_key(
        "jobfeed",
        KEY_HASH,
        1,
        ReceiverFingerprint::from_digest([9; 32]),
    );
    world.observe_key(KEY_HASH, "golf-jobfeed");
    world.observe_assignment(ASSIGNMENT_ID, KEY_HASH, RAIL_ID);

    let plan = world.plan(BASE);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::Replace);
    assert_eq!(action.rationale, vec![Reason::ReceiverChanged]);
    assert_eq!(action.safety.class(), SafetyClass::Issuing);
}

#[test]
fn a_delivered_key_the_configuration_stops_describing_is_reported() {
    // Dropping the `receiver` line does not move a secret that has already
    // been delivered, so nothing is replaced over it. But the configuration no
    // longer says who holds this key, and a plan that answered "in sync" would
    // be the only place that could have said so.
    let config = r#"
version = 1

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
guardrail = "cheap"
"#;
    let delivered = ReceiverFingerprint::from_digest([9; 32]);
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_guardrail(RAIL_ID, "cheap-rail");
    world.deliver_key("jobfeed", KEY_HASH, 1, delivered.clone());
    world.observe_key(KEY_HASH, "golf-jobfeed");
    world.observe_assignment(ASSIGNMENT_ID, KEY_HASH, RAIL_ID);

    let plan = world.plan(config);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::NoOp);
    assert_eq!(
        action.rationale,
        vec![Reason::ReceiverUnspecified {
            delivered: delivered.clone()
        }]
    );

    // Drift is still reported alongside it, and still only an update.
    world.snapshot.keys[0].name = "renamed-in-the-dashboard".to_owned();
    let plan = world.plan(config);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::Update);
    assert_eq!(
        action.rationale,
        vec![Reason::Drift, Reason::ReceiverUnspecified { delivered }]
    );
}

#[test]
fn an_imported_key_is_not_replaced_for_want_of_delivery_metadata() {
    let mut world = World::new();
    converged(&mut world);
    let plan = world.plan(BASE);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::NoOp);
    assert_eq!(action.rationale, vec![Reason::InSync]);
}

#[test]
fn an_unfinished_operation_stops_the_whole_run() {
    let mut world = World::new();
    world.begin_create("jobfeed", 1);
    let plan = world.plan(BASE);

    assert!(plan.is_blocked());
    assert!(!plan.has_changes());
    assert_eq!(plan.executable().count(), 0);

    // Reported first, whatever else the plan found.
    let first = &plan.actions()[0];
    assert_eq!(first.kind, ActionKind::RecoveryRequired);
    assert_eq!(first.address, ResourceAddress::Key(address("jobfeed")));
    assert_eq!(
        first.rationale,
        vec![Reason::OperationIncomplete {
            operation: OperationId::parse("op-0007").expect("an operation id"),
            phase: Phase::CreateStarted,
            phase_at: at(3),
        }]
    );
    // The guardrail would otherwise be created; it is still described, and
    // still not executable.
    assert_eq!(
        action_at(&plan, "guardrails.cheap").kind,
        ActionKind::Create
    );
}

/// Every phase an unfinished operation can be left in, and what the journal
/// justifies planning for it (ADR-0002's interruption table).
#[test]
fn each_unfinished_phase_gets_the_outcome_its_journal_justifies() {
    let created = Transition::Created {
        hash: hash(KEY_HASH),
    };
    let secured = [created.clone(), Transition::Secured];
    let delivering = [
        created.clone(),
        Transition::Secured,
        Transition::DeliveryStarted,
    ];
    let cases: [(&str, Vec<Transition>, ActionKind); 8] = [
        ("create_started", vec![], ActionKind::RecoveryRequired),
        (
            "create_ambiguous",
            vec![Transition::CreateAmbiguous],
            ActionKind::RecoveryRequired,
        ),
        ("created", vec![created], ActionKind::RecoveryRequired),
        ("secured", secured.to_vec(), ActionKind::Replace),
        (
            "secured after a definite refusal",
            [delivering.as_slice(), &[Transition::DeliveryRejected]].concat(),
            ActionKind::Replace,
        ),
        (
            "delivery_started",
            delivering.to_vec(),
            ActionKind::RecoveryRequired,
        ),
        (
            "delivery_ambiguous",
            [delivering.as_slice(), &[Transition::DeliveryAmbiguous]].concat(),
            ActionKind::RecoveryRequired,
        ),
        (
            "delivered",
            [delivering.as_slice(), &[Transition::Delivered]].concat(),
            ActionKind::NoOp,
        ),
    ];

    for (phase, transitions, kind) in cases {
        let mut world = World::new();
        world.bind_guardrail("cheap", RAIL_ID);
        world.observe_guardrail(RAIL_ID, "cheap-rail");
        world.pending("jobfeed", 1, &transitions);

        let plan = world.plan(BASE);
        let action = action_at(&plan, "keys.jobfeed");
        assert_eq!(action.kind, kind, "{phase}");

        // Only an operation of unknown outcome stops the whole run; the two
        // the journal settles hold back less, or nothing.
        assert_eq!(
            plan.is_blocked(),
            kind == ActionKind::RecoveryRequired,
            "{phase}"
        );
        assert_eq!(action.is_blocked(), kind != ActionKind::NoOp, "{phase}");

        // Whatever the phase, nothing writes to the address in question.
        assert!(
            !plan
                .executable()
                .any(|action| action.address == ResourceAddress::Key(address("jobfeed"))),
            "{phase}"
        );
        // And its assignment is on hold with it.
        assert!(
            !plan
                .actions()
                .iter()
                .any(|action| action.address == ResourceAddress::Assignment(address("jobfeed"))),
            "{phase}"
        );
    }
}

#[test]
fn a_key_that_can_never_be_delivered_is_reported_as_a_replacement() {
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_guardrail(RAIL_ID, "cheap-rail");
    world.pending(
        "jobfeed",
        1,
        &[
            Transition::Created {
                hash: hash(KEY_HASH),
            },
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::DeliveryRejected,
        ],
    );

    let plan = world.plan(BASE);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::Replace);
    assert_eq!(action.identity, Some(Identity::Key(hash(KEY_HASH))));
    assert_eq!(
        action.rationale,
        vec![
            Reason::OperationIncomplete {
                operation: OperationId::parse("op-0007").expect("an operation id"),
                phase: Phase::Secured,
                phase_at: at(4),
            },
            Reason::DeliveryRefused { at: at(4) },
            Reason::PlaintextLost,
        ]
    );
    assert_eq!(
        action.depends_on,
        vec![ResourceAddress::Guardrail(address("cheap"))]
    );
    assert_eq!(action.safety.class(), SafetyClass::Issuing);

    // Visible, and still not something apply may run: the operation is on the
    // address, and `begin_create` refuses to start another beside it. The
    // replacement is `recover replace`'s to perform.
    assert!(action.is_blocked());
    assert_eq!(plan.executable().count(), 0);
    // Held back, but not a halt: the journal says what happened here.
    assert!(!plan.is_blocked());
}

/// An operation interrupted at `secured`: the key exists, it is restricted,
/// and its plaintext is gone.
fn secured_at_jobfeed(world: &mut World) {
    world.pending(
        "jobfeed",
        1,
        &[
            Transition::Created {
                hash: hash(KEY_HASH),
            },
            Transition::Secured,
        ],
    );
}

#[test]
fn a_key_that_can_never_be_delivered_stops_only_the_creates_beside_it() {
    // `secured` is not a mystery: state refuses to start a second create while
    // it stands, so no key is issued anywhere. Everything else — a guardrail
    // to reconcile, a key to patch, an assignment to make — is untouched by
    // it, and holding those back would be a halt the journal does not justify.
    let config = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
guardrail = "cheap"

[keys.laptop]
name = "golf-laptop"
receiver = "vault"
guardrail = "cheap"

[keys.spare]
name = "golf-spare"
receiver = "vault"
"#;
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_guardrail(RAIL_ID, "renamed-in-the-dashboard");
    world.bind_key("laptop", OTHER_HASH, 1);
    world.observe_key(OTHER_HASH, "renamed-too");
    secured_at_jobfeed(&mut world);

    let plan = world.plan(config);
    assert!(!plan.is_blocked());

    // The one create in this plan is held back, and says by what.
    let spare = action_at(&plan, "keys.spare");
    assert_eq!(spare.kind, ActionKind::Create);
    assert!(spare.rationale.contains(&Reason::BlockedBy {
        dependency: ResourceAddress::Key(address("jobfeed")),
    }));

    // The work that has nothing to do with issuing a credential still runs.
    let executable: Vec<String> = plan
        .executable()
        .map(|action| action.address.to_string())
        .collect();
    assert_eq!(
        executable,
        vec![
            "guardrails.cheap".to_owned(),
            "keys.laptop".to_owned(),
            "keys.laptop.guardrail".to_owned(),
        ]
    );
}

#[test]
fn a_dead_key_the_configuration_dropped_stays_tracked_without_halting() {
    // There is nothing to replace it with, and nothing is deleted or forgotten
    // over it either: the binding stays tracked, carrying the operation an
    // explicit command still has to settle. That is a report, not a mystery,
    // so it must not stop the run the way an ambiguous phase does.
    let config = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.spare]
name = "golf-spare"
receiver = "vault"
"#;
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_guardrail(RAIL_ID, "renamed-in-the-dashboard");
    secured_at_jobfeed(&mut world);

    let plan = world.plan(config);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::OrphanedBinding);
    assert_eq!(action.identity, Some(Identity::Key(hash(KEY_HASH))));
    assert_eq!(
        action.rationale,
        vec![
            Reason::OperationIncomplete {
                operation: OperationId::parse("op-0007").expect("an operation id"),
                phase: Phase::Secured,
                phase_at: at(4),
            },
            Reason::PlaintextLost,
            Reason::RemovedFromConfiguration,
        ]
    );
    assert!(!plan.is_blocked());

    // It still stops the creates state would refuse beside it, and nothing
    // else.
    assert!(
        action_at(&plan, "keys.spare")
            .rationale
            .contains(&Reason::BlockedBy {
                dependency: ResourceAddress::Key(address("jobfeed")),
            })
    );
    let executable: Vec<String> = plan
        .executable()
        .map(|action| action.address.to_string())
        .collect();
    assert_eq!(executable, vec!["guardrails.cheap".to_owned()]);
}

#[test]
fn a_dead_key_with_nowhere_to_deliver_a_successor_proposes_nothing() {
    // The replacement a `secured` operation calls for is a create, and a key
    // with no receiver is never created. Reporting `replace` would name an
    // action that cannot happen at all rather than one waiting on recovery.
    let config = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"

[keys.spare]
name = "golf-spare"
receiver = "vault"
"#;
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    world.observe_guardrail(RAIL_ID, "cheap-rail");
    secured_at_jobfeed(&mut world);

    let plan = world.plan(config);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::NoOp);
    assert_eq!(
        action.rationale,
        vec![
            Reason::OperationIncomplete {
                operation: OperationId::parse("op-0007").expect("an operation id"),
                phase: Phase::Secured,
                phase_at: at(4),
            },
            Reason::PlaintextLost,
            Reason::NoReceiver,
        ]
    );
    assert!(action.depends_on.is_empty());
    assert_eq!(action.safety.class(), SafetyClass::Report);

    // The operation is still there, so it still holds back the one create.
    assert!(!plan.is_blocked());
    assert!(action_at(&plan, "keys.spare").is_blocked());
    assert_eq!(plan.executable().count(), 0);
}

#[test]
fn a_delivered_operation_waits_only_for_promotion() {
    // The guardrail is unbound, so there is ordinary work in this plan. A
    // delivered operation must not stop it: promotion touches nothing outside
    // the state file, and apply completes it before it plans.
    let mut world = World::new();
    world.pending(
        "jobfeed",
        1,
        &[
            Transition::Created {
                hash: hash(KEY_HASH),
            },
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::Delivered,
        ],
    );

    let plan = world.plan(BASE);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::NoOp);
    assert_eq!(action.identity, Some(Identity::Key(hash(KEY_HASH))));
    assert_eq!(
        action.rationale,
        vec![Reason::PromotionPending {
            operation: OperationId::parse("op-0007").expect("an operation id"),
            delivered_at: at(4),
        }]
    );
    assert!(!action.is_blocked());
    assert!(!plan.is_blocked());

    let executable: Vec<&ResourceAddress> =
        plan.executable().map(|action| &action.address).collect();
    assert_eq!(
        executable,
        vec![&ResourceAddress::Guardrail(address("cheap"))]
    );
}

#[test]
fn recovery_reports_what_an_operator_needs_and_no_secret() {
    let mut world = World::new();
    world.begin_create("jobfeed", 1);
    world
        .state
        .advance_key(
            &address("jobfeed"),
            Transition::Created {
                hash: hash(KEY_HASH),
            },
            at(4),
        )
        .expect("recording the created hash");

    let plan = world.plan(BASE);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.identity, Some(Identity::Key(hash(KEY_HASH))));
    // Past `created` the plaintext is gone, so the remedy is a replacement.
    assert!(action.rationale.contains(&Reason::PlaintextLost));
    assert_eq!(action.safety.class(), SafetyClass::Report);
}

#[test]
fn an_orphaned_binding_keeps_its_identity() {
    let mut world = World::new();
    converged(&mut world);
    let plan = world.plan(
        r#"
version = 1

[guardrails.cheap]
name = "cheap-rail"
"#,
    );

    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::OrphanedBinding);
    assert_eq!(action.identity, Some(Identity::Key(hash(KEY_HASH))));
    assert_eq!(action.rationale, vec![Reason::RemovedFromConfiguration]);
    assert_eq!(action.safety.class(), SafetyClass::Report);
    // The key it names is still managed, so it is not also reported as
    // somebody else's.
    assert!(
        !plan
            .actions()
            .iter()
            .any(|action| action.kind == ActionKind::Unmanaged)
    );
}

// --- managed-field comparison ----------------------------------------------

#[test]
fn only_fields_the_configuration_models_are_compared() {
    let mut world = World::new();
    converged(&mut world);
    let key = &mut world.snapshot.keys[0];
    key.usage.total = 41.5;
    key.usage.limit_remaining = Some(8.5);
    key.timestamps.updated_at = Some(at(500));

    let guardrail = &mut world.snapshot.guardrails[0];
    guardrail.zero_data_retention.anthropic = Some(true);
    guardrail.description = Some("written in the dashboard".to_owned());
    guardrail.allowed_models = Some(["a/b".to_owned()].into_iter().collect());

    let plan = world.plan(BASE);
    assert_eq!(action_at(&plan, "keys.jobfeed").kind, ActionKind::NoOp);
    assert_eq!(action_at(&plan, "guardrails.cheap").kind, ActionKind::NoOp);
}

#[test]
fn normalization_happens_before_the_comparison() {
    let config = r#"
version = 1

[guardrails.cheap]
name = "cheap-rail"
description = "the cheap one"
allowed_models = ["A/B", " c/d "]
denied_providers = []
limit_usd = 10
reset_interval = "daily"
"#;
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    let guardrail = world.observe_guardrail(RAIL_ID, "  cheap-rail  ");
    guardrail.description = Some("  the cheap one  ".to_owned());
    guardrail.allowed_models = Some(["a/b".to_owned(), "c/d".to_owned()].into_iter().collect());
    // An absent refusal list and an empty one both refuse nothing.
    guardrail.ignored_providers = None;
    guardrail.limit = Some(usd(10.0));
    guardrail.reset_interval = ResetPolicy::Every(ResetInterval::Daily);

    let plan = world.plan(config);
    let action = action_at(&plan, "guardrails.cheap");
    assert_eq!(action.kind, ActionKind::NoOp, "{:?}", action.changes);
}

/// The privilege expansions issue #12 has to mark, each from one field.
#[test]
fn privilege_expansion_is_marked_field_by_field() {
    let config = r#"
version = 1

[guardrails.cheap]
name = "cheap-rail"
allowed_models = ["a/b", "e/f"]
denied_providers = ["one"]
limit_usd = 20
require_zdr = false
include_byok_in_limit = false
"#;
    let mut world = World::new();
    world.bind_guardrail("cheap", RAIL_ID);
    let guardrail = world.observe_guardrail(RAIL_ID, "cheap-rail");
    guardrail.allowed_models = Some(["a/b".to_owned()].into_iter().collect());
    guardrail.ignored_providers = Some(["one".to_owned(), "two".to_owned()].into_iter().collect());
    guardrail.limit = Some(usd(10.0));
    guardrail.zero_data_retention.any = Some(true);
    guardrail.include_byok_in_budgets = true;

    let plan = world.plan(config);
    let action = action_at(&plan, "guardrails.cheap");
    assert_eq!(action.kind, ActionKind::Update);
    assert!(action.safety.expands_privilege());
    assert_eq!(action.safety.class(), SafetyClass::Expanding);
    let expected: BTreeSet<Expansion> = [
        Expansion::AllowlistWidened {
            field: "allowed_models",
        },
        Expansion::DenylistNarrowed {
            field: "denied_providers",
        },
        Expansion::BudgetRaised { field: "limit_usd" },
        Expansion::ZdrWeakened,
        Expansion::ByokExcludedFromLimit,
    ]
    .into_iter()
    .collect();
    assert_eq!(action.safety.expansions(), &expected);
}

#[test]
fn enabling_a_key_and_clearing_its_limit_expand_its_privilege() {
    let config = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
disabled = false
clear = ["limit_usd"]
"#;
    let mut world = World::new();
    world.bind_key("jobfeed", KEY_HASH, 1);
    let key = world.observe_key(KEY_HASH, "golf-jobfeed");
    key.disabled = true;
    key.limit = Some(usd(5.0));

    let plan = world.plan(config);
    let action = action_at(&plan, "keys.jobfeed");
    assert_eq!(action.kind, ActionKind::Update);
    assert_eq!(
        action.safety.expansions(),
        &[
            Expansion::KeyEnabled,
            Expansion::BudgetRaised { field: "limit_usd" }
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
}

#[test]
fn a_restricting_change_is_routine_and_a_new_key_is_issuing() {
    let config = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
disabled = true
limit_usd = 1
"#;
    let mut world = World::new();
    world.bind_key("jobfeed", KEY_HASH, 1);
    let key = world.observe_key(KEY_HASH, "golf-jobfeed");
    key.limit = Some(usd(5.0));

    let plan = world.plan(config);
    let tightened = action_at(&plan, "keys.jobfeed");
    assert_eq!(tightened.kind, ActionKind::Update);
    assert!(!tightened.safety.expands_privilege());
    assert_eq!(tightened.safety.class(), SafetyClass::Routine);

    // The same configuration with nothing bound creates a key instead, and a
    // create issues secret material however restricted it is.
    let fresh_plan = World::new().plan(config);
    let fresh = action_at(&fresh_plan, "keys.jobfeed");
    assert_eq!(fresh.kind, ActionKind::Create);
    assert_eq!(fresh.safety.class(), SafetyClass::Issuing);
    assert!(!fresh.safety.expands_privilege());
}

#[test]
fn dropping_a_keys_only_guardrail_expands_its_privilege() {
    let config = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
clear = ["guardrail"]
"#;
    let mut world = World::new();
    converged(&mut world);

    let plan = world.plan(config);
    let action = plan
        .actions()
        .iter()
        .find(|action| action.kind == ActionKind::Unassign)
        .expect("an unassignment");
    assert_eq!(
        action.identity,
        Some(Identity::Assignment {
            key: hash(KEY_HASH),
            guardrail: uuid(RAIL_ID),
        })
    );
    assert_eq!(
        action.safety.expansions(),
        &[Expansion::GuardrailRemoved]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn moving_a_key_between_guardrails_is_one_write() {
    // A key has at most one direct guardrail and assigning replaces it, so a
    // move must not remove the old assignment first: that would leave a live
    // key unrestricted between two writes.
    let mut world = World::new();
    converged(&mut world);
    world.snapshot.assignments.clear();
    world.observe_guardrail(OTHER_RAIL_ID, "another-rail");
    world.observe_assignment(OTHER_ASSIGNMENT_ID, KEY_HASH, OTHER_RAIL_ID);

    let plan = world.plan(BASE);
    let assignments: Vec<&Action> = plan
        .actions()
        .iter()
        .filter(|action| action.address == ResourceAddress::Assignment(address("jobfeed")))
        .collect();

    assert_eq!(assignments.len(), 1, "{assignments:?}");
    let action = assignments[0];
    assert_eq!(action.kind, ActionKind::Assign);
    assert_eq!(action.rationale, vec![Reason::AssignmentUndesired]);
    // Both ends are visible, so the operator sees what the key is moving from.
    assert_eq!(
        action.changes,
        vec![FieldChange {
            field: "guardrail",
            from: FieldValue::Guardrail(uuid(OTHER_RAIL_ID)),
            to: FieldValue::Address(address("cheap")),
            expansion: None,
        }]
    );
    assert_eq!(
        action.identity,
        Some(Identity::Assignment {
            key: hash(KEY_HASH),
            guardrail: uuid(RAIL_ID),
        })
    );
    assert_eq!(action.safety.class(), SafetyClass::Routine);
}

#[test]
fn moving_a_key_to_a_guardrail_that_drops_zdr_expands_its_privilege() {
    let config = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[guardrails.cheap]
name = "cheap-rail"
require_zdr = false

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
guardrail = "cheap"
"#;
    let mut world = World::new();
    converged(&mut world);
    world.snapshot.assignments.clear();
    world
        .observe_guardrail(OTHER_RAIL_ID, "another-rail")
        .zero_data_retention
        .any = Some(true);
    world.observe_assignment(OTHER_ASSIGNMENT_ID, KEY_HASH, OTHER_RAIL_ID);

    let plan = world.plan(config);
    let action = plan
        .actions()
        .iter()
        .find(|action| action.kind == ActionKind::Assign)
        .expect("an assignment");
    assert_eq!(
        action.safety.expansions(),
        &[Expansion::ZdrWeakened]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );

    // The same move onto a guardrail that keeps enforcing it is ordinary.
    let enforcing = config.replace("require_zdr = false", "require_zdr = true");
    let plan = world.plan(&enforcing);
    let action = plan
        .actions()
        .iter()
        .find(|action| action.kind == ActionKind::Assign)
        .expect("an assignment");
    assert_eq!(action.safety.class(), SafetyClass::Routine);
}

#[test]
fn a_report_never_claims_to_expand_privilege() {
    for case in CASES {
        let mut world = World::new();
        (case.build)(&mut world);
        for action in world.plan(case.config).actions() {
            if !action.kind.writes() {
                assert!(
                    !action.safety.expands_privilege(),
                    "{} reports `{}` and claims an expansion",
                    case.name,
                    action.kind
                );
                assert_eq!(action.safety.class(), SafetyClass::Report, "{}", case.name);
            }
        }
    }
}

fn action_at<'plan>(plan: &'plan Plan, address: &str) -> &'plan Action {
    plan.actions()
        .iter()
        .find(|action| action.address.to_string() == address)
        .unwrap_or_else(|| panic!("no action at {address}"))
}
