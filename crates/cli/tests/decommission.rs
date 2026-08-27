//! Binary-level tests for `decommission`: the one command that ends the key an
//! address is using.
//!
//! Every other ending refuses a current hash, which is what makes this one
//! dangerous and what every case below is about. Two rules run through all of
//! them. **State moves only on evidence a read produced** — a disable nothing
//! proved leaves the address using the key it already had, and a hash stops
//! being tracked only after a 404. And **the address is left owning no key**,
//! which is a shape nothing else produces, so the runs afterwards have to make
//! sense: the next plan proposes a create, and the next apply makes a real one
//! at a generation this address has never used.
//!
//! The receiver is the purpose-built helper binary and writes outside the
//! project directory, because what it writes is a live credential and the
//! project directory is scanned for exactly that.

mod support;

use std::fs;
use std::path::Path;

use openrouter_keymaster_core::ids::{OperationId, ReceiverFingerprint, RemoteName};
use openrouter_keymaster_core::state::{BeginCreate, RetainedStatus, Transition};
use serde_json::{Value, json};
use support::fixtures::{api_key, created_key};
use support::http::{Scripted, json_response};
use support::project::{Project, address, at, hash};
use support::sentinel::SECRET_SENTINEL_KEY;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// The key the address is using when a decommission starts.
const HASH: &str = "hash-jobfeed-1";
/// The key a later apply creates in its place.
const REPLACEMENT_HASH: &str = "hash-jobfeed-2";
/// A hash the address does not use.
const OTHER_HASH: &str = "hash-nobodys";

/// A project whose one key delivers through the helper binary.
struct World {
    project: Project,
    vault: TempDir,
}

impl World {
    /// A project whose address is using `HASH` at generation 1.
    fn new() -> Self {
        let world = Self::empty();
        world.project.write_state(|state| {
            state
                .bind_key(&address("jobfeed"), hash(HASH), 1, at(0))
                .expect("binding the working key");
        });
        world
    }

    /// The same project with no state at all, for a fixture of its own.
    fn empty() -> Self {
        let vault = tempfile::tempdir().expect("a temporary vault directory");
        let project = Project::new(&configuration(vault.path()));
        Self { project, vault }
    }

    /// The fingerprint of the receiver this project configures.
    fn receiver_fingerprint(&self) -> ReceiverFingerprint {
        let source = fs::read_to_string(self.project.config_path()).expect("the configuration");
        openrouter_keymaster_core::config::Config::parse(&source)
            .expect("a valid test configuration")
            .receivers
            .iter()
            .next()
            .map(|(address, spec)| spec.fingerprint(address))
            .expect("one receiver")
    }

    /// The key binding as the state file now holds it.
    fn binding(&self) -> openrouter_keymaster_core::state::KeyBinding {
        self.project
            .read_state()
            .key(&address("jobfeed"))
            .cloned()
            .expect("a binding at `jobfeed`")
    }

    /// The hash the address currently uses, if it uses one.
    fn current(&self) -> Option<String> {
        self.binding()
            .current()
            .map(|current| current.hash.as_str().to_owned())
    }

    /// Every retained hash and its status, in state order.
    fn retained(&self) -> Vec<(String, RetainedStatus)> {
        self.binding()
            .retained()
            .iter()
            .map(|retained| (retained.hash.as_str().to_owned(), retained.status))
            .collect()
    }

    /// How many times the receiver program ran. Absent means never.
    fn deliveries(&self) -> usize {
        fs::read_to_string(self.vault.path().join("runs.txt"))
            .map(|runs| runs.lines().count())
            .unwrap_or_default()
    }

    /// The state file's bytes, for a case that must not write one.
    fn state_bytes(&self) -> Vec<u8> {
        fs::read(self.project.state_path()).expect("the state file")
    }
}

/// One key at generation 1, delivered to the helper.
fn configuration(vault: &Path) -> String {
    format!(
        r#"
version = 1

[receivers.vault]
type = "command"
program = "{program}"
args = ["record", "{vault}"]

[keys.jobfeed]
name = "golf-jobfeed"
limit_usd = 5
limit_reset = "monthly"
disabled = true
receiver = "vault"
"#,
        program = env!("CARGO_BIN_EXE_openrouter-keymaster-test-receiver"),
        vault = vault.display(),
    )
}

/// A key as OpenRouter has it once it is disabled.
fn disabled_key(hash: &str) -> Value {
    let mut key = api_key(hash, "golf-jobfeed");
    key["disabled"] = json!(true);
    key
}

/// A confirmed 404 for one hash.
fn missing() -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_json(json!({
        "error": { "code": 404, "message": "no such key" }
    }))
}

/// Answers `GET /keys/{hash}` with each response in turn, the last repeating.
fn serve_reads(
    project: &Project,
    hash: &str,
    responses: impl IntoIterator<Item = ResponseTemplate>,
) {
    project.server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(Scripted::new(responses)),
    );
}

/// Answers the `PATCH` a disable sends.
fn serve_disable(project: &Project, hash: &str, response: ResponseTemplate) {
    project.server.mount(
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(response),
    );
}

/// Answers the one `DELETE`.
fn serve_delete(project: &Project, hash: &str, response: ResponseTemplate) {
    project.server.mount(
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/keys/{hash}")))
            .respond_with(response),
    );
}

/// The reads a decommission makes when the key is enabled and the disable
/// takes: one to see the key, one to confirm the disable.
fn serve_a_disable_that_takes(project: &Project) {
    serve_disable(project, HASH, json_response(200, &json!({})));
    serve_reads(
        project,
        HASH,
        [
            json_response(200, &json!({ "data": api_key(HASH, "golf-jobfeed") })),
            json_response(200, &json!({ "data": disabled_key(HASH) })),
        ],
    );
}

#[test]
fn decommission_disables_the_current_key_and_keeps_it_tracked_as_retired() {
    let world = World::new();
    serve_a_disable_that_takes(&world.project);

    let streams = world
        .project
        .succeed(&["--json", "decommission", "jobfeed", "--hash", HASH]);
    let document = streams.document();

    assert_eq!(document["command"], "decommission");
    assert_eq!(document["hash"], HASH);
    assert_eq!(document["generation"], 1);
    assert_eq!(document["disabled"], Value::Bool(true));
    assert_eq!(document["status"], "retired");
    assert_eq!(document["tracked"], Value::Bool(true));
    assert!(
        document["deleted"].is_null(),
        "no deletion was asked for: {document}"
    );
    assert!(
        document["summary"]
            .as_str()
            .is_some_and(|text| text.contains("creates a replacement key")),
        "the operator is told what the next apply will do: {document}"
    );
    assert!(
        document["warnings"]
            .as_array()
            .expect("a warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|text| text.contains("owns no key"))),
        "the address is left owning nothing, and that is a warning: {document}"
    );

    assert_eq!(
        world.current(),
        None,
        "the address is bound and owns no key afterwards"
    );
    assert_eq!(
        world.retained(),
        vec![(HASH.to_owned(), RetainedStatus::Retired)],
        "the hash stays tracked so `delete key` can finish it later"
    );
    assert_eq!(world.deliveries(), 0, "nothing was created or delivered");

    // And running it again is a clear refusal rather than a second attempt: the
    // address is using no key now, so there is nothing to decommission.
    let serial = world.project.read_state().serial();
    let streams = world
        .project
        .fail(&["--json", "decommission", "jobfeed", "--hash", HASH]);
    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "decommission_no_current_key"
    );
    assert_eq!(
        world.project.read_state().serial(),
        serial,
        "a repeated decommission writes no state"
    );
}

/// The human form is not a contract, but it is what an operator reads, and the
/// warning belongs on the other stream.
#[test]
fn the_human_result_says_what_the_address_is_left_holding() {
    let world = World::new();
    serve_a_disable_that_takes(&world.project);

    let streams = world
        .project
        .succeed(&["decommission", "jobfeed", "--hash", HASH]);

    assert!(
        streams.out.contains("decommission keys.jobfeed"),
        "{}",
        streams.out
    );
    assert!(streams.out.contains("retired"), "{}", streams.out);
    assert!(
        streams.err.starts_with("warning: "),
        "the diagnostics belong on stderr: {}",
        streams.err
    );
}

#[test]
fn decommission_with_delete_drops_the_hash_and_keeps_the_generation_spent() {
    let world = World::new();
    serve_disable(&world.project, HASH, json_response(200, &json!({})));
    serve_delete(&world.project, HASH, json_response(200, &json!({})));
    serve_reads(
        &world.project,
        HASH,
        [
            json_response(200, &json!({ "data": api_key(HASH, "golf-jobfeed") })),
            json_response(200, &json!({ "data": disabled_key(HASH) })),
            // The read after the delete, which is the only thing that proves it.
            missing(),
        ],
    );

    let document = world
        .project
        .succeed(&[
            "--json",
            "decommission",
            "jobfeed",
            "--hash",
            HASH,
            "--delete",
        ])
        .document();

    assert_eq!(document["disabled"], Value::Bool(true));
    assert_eq!(document["deleted"], "deleted");
    assert_eq!(document["status"], "untracked");
    assert_eq!(document["tracked"], Value::Bool(false));

    let trace = world.project.request_trace();
    let disable = trace.iter().position(|seen| seen.starts_with("PATCH "));
    let delete = trace.iter().position(|seen| seen.starts_with("DELETE "));
    assert!(
        disable < delete,
        "nothing is deleted before a read proves it is out of service: {trace:?}"
    );

    assert_eq!(world.current(), None);
    assert_eq!(world.retained(), Vec::new(), "the hash is gone from state");
    assert_eq!(
        world.binding().generation_floor(),
        1,
        "the deleted key's number stays spent at this address"
    );
    assert_eq!(world.binding().highest_generation(), 1);
}

/// A current key OpenRouter no longer has is settled rather than refused.
///
/// A confirmed 404 is the one answer that proves a key cannot be used, and it is
/// the same evidence `delete key` requires before dropping a hash. Refusing here
/// would leave the address stuck holding a record of a key that does not exist.
#[test]
fn a_current_key_openrouter_no_longer_has_is_settled_by_its_404() {
    let world = World::new();
    serve_reads(&world.project, HASH, [missing()]);
    // A delete that fails, so that sending one at all is a visible mistake: the
    // read has already proved the key is gone, and a failed request nothing
    // needed would downgrade that to "may still exist".
    serve_delete(
        &world.project,
        HASH,
        ResponseTemplate::new(500).set_body_json(json!({
            "error": { "code": 500, "message": "server exploded" }
        })),
    );

    let document = world
        .project
        .succeed(&[
            "--json",
            "decommission",
            "jobfeed",
            "--hash",
            HASH,
            "--delete",
        ])
        .document();

    assert_eq!(document["disabled"], Value::Bool(true));
    assert_eq!(document["deleted"], "already_absent");
    assert_eq!(document["tracked"], Value::Bool(false));
    assert!(
        world.project.write_trace().is_empty(),
        "a key a read has already proved absent needs no disable and no delete: {:?}",
        world.project.write_trace()
    );
    assert_eq!(world.current(), None);
    assert_eq!(world.retained(), Vec::new());
    assert_eq!(
        world.binding().generation_floor(),
        1,
        "the number the missing key held is still spent"
    );
}

/// A 404 on the read that confirms a disable is proof, not a failure.
///
/// The key was there when the run looked and is gone by the time it checks —
/// someone deleted it in the dashboard, or another run did. Absence is the
/// strongest form of "cannot be used", so it settles the decommission instead
/// of leaving a nonexistent key recorded as the address's working credential.
#[test]
fn a_confirming_read_that_returns_404_settles_the_decommission() {
    let world = World::new();
    serve_disable(&world.project, HASH, json_response(200, &json!({})));
    serve_reads(
        &world.project,
        HASH,
        [
            json_response(200, &json!({ "data": api_key(HASH, "golf-jobfeed") })),
            missing(),
        ],
    );

    let streams = world
        .project
        .succeed(&["--json", "decommission", "jobfeed", "--hash", HASH]);
    let document = streams.document();

    assert_eq!(document["disabled"], Value::Bool(true));
    assert_eq!(document["status"], "retired");
    assert!(
        document["disable_detail"]
            .as_str()
            .is_some_and(|text| text.contains("404")),
        "the detail says what the read established: {document}"
    );
    assert!(
        !streams.out.contains("may still be usable"),
        "a key OpenRouter does not have cannot still be usable: {}",
        streams.out
    );
    assert_eq!(world.current(), None);
    assert_eq!(
        world.retained(),
        vec![(HASH.to_owned(), RetainedStatus::Retired)]
    );
}

#[test]
fn decommission_refuses_a_hash_the_address_is_not_using() {
    let world = World::new();
    let before = world.state_bytes();

    let streams = world
        .project
        .fail(&["--json", "decommission", "jobfeed", "--hash", OTHER_HASH]);

    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "decommission_not_current"
    );
    assert!(
        streams.err.contains(HASH),
        "the refusal names the hash the address does use: {}",
        streams.err
    );
    world.project.server.assert_request_count(0);
    assert_eq!(before, world.state_bytes(), "nothing was written");
}

/// The refusal every command shares for an operation in progress, and the two
/// different commands it names.
#[test]
fn decommission_is_refused_while_an_operation_is_pending() {
    for (last, promote, resolution) in [
        (Transition::Secured, false, "recover inspect jobfeed"),
        (Transition::Delivered, false, "apply"),
    ] {
        let world = staged(last, promote);
        let before = world.state_bytes();

        let streams = world
            .project
            .fail(&["--json", "decommission", "jobfeed", "--hash", HASH]);

        assert_eq!(
            streams.diagnostic()["error"]["kind"],
            "decommission_pending",
            "{}",
            streams.err
        );
        assert!(
            streams.err.contains(resolution),
            "the refusal names the command that clears the phase: {}",
            streams.err
        );
        world.project.server.assert_request_count(0);
        assert_eq!(before, world.state_bytes(), "nothing was written");
    }
}

/// A disable nothing proved changes nothing at all.
///
/// The key may still be a working credential, and state saying the address uses
/// it is then the truth. Recording the ending early would tell the next plan to
/// create a replacement beside a key that is still live.
#[test]
fn a_disable_that_is_not_confirmed_leaves_the_key_current() {
    let world = World::new();
    serve_reads(
        &world.project,
        HASH,
        [json_response(
            200,
            &json!({ "data": api_key(HASH, "golf-jobfeed") }),
        )],
    );
    serve_disable(
        &world.project,
        HASH,
        ResponseTemplate::new(500).set_body_json(json!({
            "error": { "code": 500, "message": "server exploded" }
        })),
    );
    let before = world.state_bytes();

    let streams = world
        .project
        .fail(&["--json", "decommission", "jobfeed", "--hash", HASH]);

    // The result document is written even though the run failed: what happened
    // is what an operator needs.
    let document = streams.document();
    assert_eq!(document["disabled"], Value::Bool(false));
    assert_eq!(document["status"], "current");
    assert_eq!(document["tracked"], Value::Bool(true));

    assert!(
        document["summary"]
            .as_str()
            .is_some_and(|text| text.contains(&format!(
                "openrouter-keymaster decommission jobfeed --hash {HASH}`"
            ))),
        "the summary names the command that repeats it: {document}"
    );

    let diagnostic = streams.diagnostic();
    assert_eq!(diagnostic["error"]["kind"], "decommission_unconfirmed");
    assert!(
        streams.err.contains(&format!(
            "openrouter-keymaster decommission jobfeed --hash {HASH}"
        )),
        "the diagnostic names the exact command that repeats it: {}",
        streams.err
    );
    assert_eq!(
        world.current(),
        Some(HASH.to_owned()),
        "the address still uses the key nothing disabled"
    );
    assert_eq!(before, world.state_bytes(), "no state was written");
}

/// The command an operator is told to run again is the one they ran, `--delete`
/// and all, in the result document as well as the diagnostic.
#[test]
fn an_unconfirmed_disable_repeats_the_command_that_was_asked_for() {
    let world = World::new();
    serve_reads(
        &world.project,
        HASH,
        [json_response(
            200,
            &json!({ "data": api_key(HASH, "golf-jobfeed") }),
        )],
    );
    serve_disable(
        &world.project,
        HASH,
        ResponseTemplate::new(500).set_body_json(json!({
            "error": { "code": 500, "message": "server exploded" }
        })),
    );

    let streams = world.project.fail(&[
        "--json",
        "decommission",
        "jobfeed",
        "--hash",
        HASH,
        "--delete",
    ]);

    let expected = format!("openrouter-keymaster decommission jobfeed --hash {HASH} --delete");
    assert!(
        streams.document()["summary"]
            .as_str()
            .is_some_and(|text| text.contains(&expected)),
        "the summary keeps the flag: {}",
        streams.out
    );
    assert!(
        streams.err.contains(&expected),
        "and so does the diagnostic: {}",
        streams.err
    );
    assert!(
        world
            .project
            .write_trace()
            .iter()
            .all(|request| !request.starts_with("DELETE ")),
        "nothing is deleted while the key may still be in service: {:?}",
        world.project.write_trace()
    );
}

/// A delete that is not confirmed keeps the hash tracked, and `delete key`
/// finishes it — the path that already exists.
#[test]
fn a_delete_that_is_not_confirmed_keeps_the_hash_tracked_for_delete_key() {
    let world = World::new();
    serve_disable(&world.project, HASH, json_response(200, &json!({})));
    serve_delete(&world.project, HASH, json_response(200, &json!({})));
    serve_reads(
        &world.project,
        HASH,
        [
            json_response(200, &json!({ "data": api_key(HASH, "golf-jobfeed") })),
            // The disable is confirmed; the delete is not, because the key is
            // still there when the run that sent it looks.
            json_response(200, &json!({ "data": disabled_key(HASH) })),
            json_response(200, &json!({ "data": disabled_key(HASH) })),
            // And it is gone by the time `delete key` retries.
            missing(),
        ],
    );

    let streams = world.project.fail(&[
        "--json",
        "decommission",
        "jobfeed",
        "--hash",
        HASH,
        "--delete",
    ]);

    assert_eq!(streams.document()["deleted"], "unconfirmed");
    assert_eq!(streams.document()["status"], "retirement_failed");
    assert_eq!(
        streams.diagnostic()["error"]["kind"],
        "decommission_delete_unconfirmed"
    );
    assert!(
        streams
            .err
            .contains(&format!("openrouter-keymaster delete key --hash {HASH}")),
        "the diagnostic names the command that finishes it: {}",
        streams.err
    );
    assert_eq!(world.current(), None);
    assert_eq!(
        world.retained(),
        vec![(HASH.to_owned(), RetainedStatus::RetirementFailed)]
    );

    // And that command does finish it, because the hash is retained now.
    world
        .project
        .succeed(&["--json", "delete", "key", "--hash", HASH]);
    assert_eq!(world.retained(), Vec::new());
    assert_eq!(world.binding().generation_floor(), 1);
}

/// The address is left bound and owning nothing, so the runs afterwards have to
/// make sense.
///
/// A configuration that still describes the key means the next apply creates
/// one — a real create, at a generation the address has never used, delivered to
/// the receiver. That is the consequence the decommission's own summary warns
/// about, checked here by performing it.
#[test]
fn the_next_apply_creates_a_replacement_at_the_next_generation() {
    let world = World::new();
    serve_disable(&world.project, HASH, json_response(200, &json!({})));
    serve_delete(&world.project, HASH, json_response(200, &json!({})));
    serve_reads(
        &world.project,
        HASH,
        [
            json_response(200, &json!({ "data": api_key(HASH, "golf-jobfeed") })),
            json_response(200, &json!({ "data": disabled_key(HASH) })),
            missing(),
        ],
    );
    world.project.observe_sequence(
        // The plan's read, the apply's read, and the read that verifies it.
        vec![Vec::new(), Vec::new(), vec![disabled_key(REPLACEMENT_HASH)]],
        vec![Vec::new()],
        vec![Vec::new()],
    );
    world.project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                200,
                &created_key(REPLACEMENT_HASH, "golf-jobfeed", SECRET_SENTINEL_KEY),
            )),
    );
    serve_disable(
        &world.project,
        REPLACEMENT_HASH,
        json_response(200, &json!({})),
    );
    serve_reads(
        &world.project,
        REPLACEMENT_HASH,
        [json_response(
            200,
            &json!({ "data": disabled_key(REPLACEMENT_HASH) }),
        )],
    );

    world.project.succeed(&[
        "--json",
        "decommission",
        "jobfeed",
        "--hash",
        HASH,
        "--delete",
    ]);

    let plan = world.project.succeed(&["--json", "plan"]).document();
    let action = plan["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == "keys.jobfeed")
        .unwrap_or_else(|| panic!("no action at keys.jobfeed in {plan}"));
    assert_eq!(
        action["kind"], "create",
        "a configured key with no current hash is created: {plan}"
    );

    world.project.succeed(&["--json", "apply"]);

    assert_eq!(world.current(), Some(REPLACEMENT_HASH.to_owned()));
    assert_eq!(
        world.binding().generation(),
        2,
        "generation 1 is spent for good, even though its key was deleted"
    );
    assert_eq!(world.deliveries(), 1, "the replacement was delivered once");
}

/// A project whose rotation stopped after `last`, leaving an operation the
/// journal records.
fn staged(last: Transition, promote: bool) -> World {
    let world = World::empty();
    let fingerprint = world.receiver_fingerprint();
    world.project.write_state(|state| {
        let jobfeed = address("jobfeed");
        state
            .bind_key(&jobfeed, hash(HASH), 1, at(0))
            .expect("binding the working key");
        state
            .begin_create(
                &jobfeed,
                BeginCreate {
                    operation: OperationId::parse("op-0002").expect("an operation id"),
                    generation: 2,
                    name: RemoteName::parse("golf-jobfeed").expect("a remote name"),
                    workspace: None,
                    receiver: fingerprint,
                },
                at(10),
            )
            .expect("journaling the successor's creation");
        for (step, transition) in [
            Transition::Created {
                hash: hash(REPLACEMENT_HASH),
            },
            Transition::Secured,
            Transition::DeliveryStarted,
            Transition::Delivered,
        ]
        .into_iter()
        .enumerate()
        {
            let reached = transition == last;
            state
                .advance_key(&jobfeed, transition, at(11 + step as i64))
                .expect("replaying the transaction");
            if reached {
                break;
            }
        }
        if promote {
            state
                .promote_key(&jobfeed, at(20))
                .expect("promoting the successor");
        }
    });
    world
}
