//! Opt-in acceptance tests against a real OpenRouter organization.
//!
//! Everything else in `tests/` runs against the local harness, which is where
//! Keymaster's behavior is specified and where a regression should be caught.
//! This suite exists for the one thing a local harness cannot check: whether
//! the real management API behaves the way the documentation says it does.
//!
//! **It creates and deletes real resources and spends a real credential**, so
//! it is gated twice. Every test carries `#[ignore]`, which keeps it out of
//! `cargo test`, `just check`, and CI; and every test then asks [`gate`] for
//! permission, which requires `KEYMASTER_LIVE_TESTS=1` *and* a usable
//! `OPENROUTER_MANAGEMENT_KEY`. Running with `--ignored` but no opt-in prints a
//! skip notice and passes without touching the network. Opting in without a
//! credential fails loudly, because that is a misconfigured live run rather
//! than a decision not to make one.
//!
//! Safety rules the suite holds itself to:
//!
//! - **Every remote name carries a unique run prefix**, `km-live-<random>`, and
//!   the sweep touches nothing whose name does not start with it.
//! - **Every created identity is journaled to a file before it is used**, and
//!   the prefix itself is journaled before the first resource exists, so a run
//!   killed between the create and the record can still be swept by prefix.
//! - **Keys are created with a zero USD limit.** A key that cannot spend is the
//!   only kind worth leaving behind by accident.
//! - **Cleanup runs from `Drop`**, so it happens on the panic path too, and it
//!   verifies each deletion by reading the immutable identity back until
//!   OpenRouter answers 404. Log destinations go first, so forwarding stops
//!   before the keys it watched are deleted; then the keys; then the
//!   workspaces, because a workspace that still holds either cannot be
//!   deleted at all.
//! - **Cleanup never logs a response body.** Bodies are drained by the client
//!   and discarded; a failure is reported as an identity and an error kind.
//!
//! See [`docs/live-tests.md`](../docs/live-tests.md) for how to run it and what
//! a test organization needs.

mod support;

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{self, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use openrouter_keymaster::app::env;
use openrouter_keymaster_core::api::pagination::PageLimits;
use openrouter_keymaster_core::api::{Reader, Writer};
use openrouter_keymaster_core::client::{ApiError, Client};
use openrouter_keymaster_core::config::BudgetInterval;
use openrouter_keymaster_core::ids::{KeyHash, Uuid};
use openrouter_keymaster_core::ops::{
    self, Context, DeliveryMetadata, DeliveryOutcome, KeyPlaintext, Paths,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use support::project::Streams;
use tempfile::TempDir;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Set this to `1` to opt in. Anything else, including unset, skips.
const OPT_IN_VAR: &str = "KEYMASTER_LIVE_TESTS";

/// Names a prefix from an earlier run for [`live_sweep_named_prefix`].
const SWEEP_VAR: &str = "KEYMASTER_LIVE_SWEEP";

/// The first component of every remote name this suite creates. Nothing
/// outside a live run should ever be named this way.
const RUN_PREFIX: &str = "km-live";

/// Hex digits in a run identifier, after `km-live-`.
const RUN_ID_DIGITS: usize = 8;

/// Page size used where the point is to prove pagination assembles a complete
/// snapshot. One record per page turns a handful of resources into a real
/// multi-page read — on the endpoints that accept a limit. `GET /keys` takes
/// only an offset, so a key listing pages at whatever size the server chooses
/// and this only exercises the offset arithmetic.
const SMALL_PAGE: usize = 1;

/// Distinguishes two runs started inside the same nanosecond.
static RUNS: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------- the tests

/// Guardrail create, paginated read, exact get by UUID, import, and update.
///
/// The import step is the one that proves a *remote* read: the address is
/// forgotten, the configuration is edited, and the import has to report the
/// description OpenRouter still holds rather than the one on disk.
#[test]
#[ignore = "live: set KEYMASTER_LIVE_TESTS=1 and see docs/live-tests.md"]
fn live_guardrail_create_read_import_update() {
    let Some(live) = gate() else { return };
    let project = Project::new();
    let original = format!("{run} original description", run = live.run);

    project.write_config(&guardrail_config(&live.run, &original));
    let applied = project.succeed(&["--json", "apply"]);
    assert_eq!(applied.document()["outcome"], "applied");

    let found = live.adopt_guardrails();
    assert_eq!(found.len(), 3, "apply should have created three guardrails");

    live.assert_guardrail_listing_is_complete(&found);
    live.assert_exact_guardrail_get(&found);

    let alpha = live.guardrail_named(&format!("{run}-alpha", run = live.run));
    import_reports_the_remote_value(&live, &project, &alpha, &original);
}

/// The full key lifecycle: create, deliver, enable, rotate, retire, delete.
///
/// One address carries the whole thing, because that is how the operations
/// compose in practice and because each step's precondition is the previous
/// step's result.
#[test]
#[ignore = "live: set KEYMASTER_LIVE_TESTS=1 and see docs/live-tests.md"]
fn live_key_create_rotate_retire_delete() {
    let Some(live) = gate() else { return };
    let project = Project::new();
    let sink = project.secrets.path().join("jobfeed.key");

    project.write_config(&key_config(&live.run, &sink, true));
    let applied = project.succeed(&["--json", "apply"]);
    assert_eq!(applied.document()["outcome"], "applied");

    let guardrail = live.adopt_one_guardrail();
    let created = live.adopt_new_keys();
    let [first] = created.as_slice() else {
        panic!("apply should have created exactly one key, not {created:?}");
    };

    live.assert_key_created_disabled_and_assigned(first, &guardrail);
    project.assert_delivered_secret_stayed_put(&sink, &live);

    // Enabling is an ordinary update, and it is what makes the rotation step
    // meaningful: a predecessor that was already disabled could not show that
    // rotation leaves it alone.
    project.write_config(&key_config(&live.run, &sink, false));
    let enabled = project.succeed(&["--json", "apply"]);
    assert_eq!(enabled.document()["outcome"], "applied");
    assert!(!live.key(first).disabled, "the key should now be enabled");

    let second = rotation_leaves_the_predecessor_alone(&live, &project, first);
    live.assert_key_listing_is_complete(&[first.clone(), second]);
    project.assert_delivered_secret_stayed_put(&sink, &live);

    retire_then_delete(&live, &project, first);
}

/// One workspace, all the way through: create, default guardrail, budget,
/// update, a key placed inside it by a scoped run, and an import.
///
/// One workspace carries the whole thing for the reason one address carries the
/// key lifecycle — each step's precondition is the previous step's result. The
/// scoped run in the middle is only reachable once the block is bound, which is
/// the rule ADR-0004 item 5 states and this proves against the real API.
#[test]
#[ignore = "live: set KEYMASTER_LIVE_TESTS=1 and see docs/live-tests.md"]
fn live_workspace_create_budget_default_guardrail_and_scoped_key() {
    let Some(live) = gate() else { return };
    let project = Project::new();
    let mut club = Club::new(&live.run);

    project.write_config(&club.toml());
    let applied = project.succeed(&["--json", "apply"]);
    assert_eq!(applied.document()["outcome"], "applied");

    let id = live.adopt_one_workspace();
    assert_default_guardrail_materialized(&live, &id);

    budget_write_is_definite_and_the_rest_lands(&live, &project, &mut club, &id);
    scoped_run_places_a_key_in_the_workspace(&live, &project, &mut club, &id);
    workspace_import_reports_the_remote_value(&live, &project, &mut club, &id);
}

/// A `caller` receiver, end to end: the host's own code takes delivery of a
/// real key's plaintext.
///
/// The command line cannot reach this path — it supplies no callback — so the
/// test calls `ops` directly, which is what a web host does (ADR-0005). Nothing
/// here records the plaintext: what is recorded is its shape, and the report is
/// searched for the marker every OpenRouter credential carries.
#[test]
#[ignore = "live: set KEYMASTER_LIVE_TESTS=1 and see docs/live-tests.md"]
fn live_caller_receiver_hands_a_key_to_host_code() {
    let Some(live) = gate() else { return };
    let project = Project::new();
    project.write_config(&caller_config(&live.run));

    let handed: Arc<Mutex<Vec<Handed>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&handed);
    let context = Context {
        paths: Paths {
            config: project.config_path(),
            state: project.state_path(),
        },
        options: env::options().expect("the endpoint this run is pointed at"),
        key: Some(env::management_key().expect("the credential the gate already accepted")),
        workspace: None,
        deliver: Some(Box::new(move |metadata: &DeliveryMetadata, plaintext| {
            recorded
                .lock()
                .expect("the recorder is not poisoned")
                .push(Handed::of(metadata, plaintext));
            DeliveryOutcome::delivered("the live test took delivery and kept nothing")
        })),
    };

    let outcome = ops::apply(context, None).expect("an apply report");
    // Journal whatever was created before judging the run: a failure after the
    // create is exactly when the record matters most.
    let created = live.adopt_new_keys();
    if let Some(error) = &outcome.error {
        panic!("the apply failed ({kind})", kind = error.kind());
    }

    let document = serde_json::to_value(&outcome.report).expect("the report serializes");
    assert_eq!(document["outcome"], "applied", "{document}");
    assert!(
        !document.to_string().contains("sk-or-"),
        "no part of a delivered key may reach a report"
    );

    let calls = handed.lock().expect("the recorder is not poisoned").clone();
    let ([call], [key]) = (calls.as_slice(), created.as_slice()) else {
        panic!("one call and one key were expected, not {calls:?} and {created:?}");
    };
    assert_eq!(call.address, "hostkey");
    assert_eq!(
        call.destination.as_deref(),
        Some("live/caller"),
        "the host routes on the destination its configuration names"
    );
    assert_eq!(
        call.hash,
        key.as_str(),
        "the metadata names the key that was created"
    );
    assert!(
        call.looks_like_a_key,
        "the host is handed the real plaintext, not a placeholder"
    );
}

/// A `webhook` log destination: create, a write-only `config` update, and the
/// explicit delete.
#[test]
#[ignore = "live: set KEYMASTER_LIVE_TESTS=1 and see docs/live-tests.md"]
fn live_log_destination_webhook_create_update_delete() {
    let Some(live) = gate() else { return };
    let project = Project::new();
    let first = format!("https://example.invalid/{run}/one", run = live.run);

    project.write_config(&destination_config(&live.run, &first));
    let applied = project.succeed(&["--json", "apply"]);
    assert_eq!(applied.document()["outcome"], "applied");

    let id = live.adopt_one_destination();
    let observed = live.destination(&id);
    assert_eq!(observed.kind, "webhook");
    assert!(observed.enabled, "a destination is created forwarding");
    assert!(
        observed.api_key_hashes.is_empty(),
        "the allowlist is managed as empty, so a destination forwards its whole workspace"
    );

    config_update_travels_alone(&live, &project, &id);

    project.succeed(&["--json", "delete", "log-destination", "--id", id.as_str()]);
    assert_eq!(
        live.destination_status(&id),
        Some(404),
        "a deleted destination must be gone, not merely reported gone"
    );
    live.forget_destination(&id);

    // The `config` value is registered with the redactor by exact match
    // (ADR-0006, item 4), and nothing prints it in the first place. Both would
    // have to fail for it to be here.
    for (index, captured) in project.transcript.borrow().iter().enumerate() {
        assert!(
            !captured.contains(&first),
            "a destination's config reached stream {index}"
        );
    }
}

/// `spend`: the balance, the analytics vocabulary this organization offers, and
/// numbers that are numbers.
#[test]
#[ignore = "live: set KEYMASTER_LIVE_TESTS=1 and see docs/live-tests.md"]
fn live_spend_reports_credits_and_key_costs() {
    let Some(live) = gate() else { return };
    let project = Project::new();
    let sink = project.secrets.path().join("spend.key");

    project.write_config(&key_config(&live.run, &sink, true));
    let applied = project.succeed(&["--json", "apply"]);
    assert_eq!(applied.document()["outcome"], "applied");
    live.adopt_one_guardrail();
    live.adopt_new_keys();

    let reported = project.succeed(&["--json", "spend", "--granularity", "day"]);
    let document = reported.document();
    assert_eq!(document["command"], "spend");
    assert!(
        document["credits"]["total_credits"].is_number()
            && document["credits"]["remaining"].is_number(),
        "the balance is read from `GET /credits`: {document}"
    );

    // The three names are discovered per organization, so what they turn out to
    // be is the finding. They are asserted rather than printed because a report
    // built from a different vocabulary answers a different question.
    let columns = &document["columns"];
    assert_eq!(columns["key_dimension"], "api_key_id", "{document}");
    assert_eq!(columns["tokens_metric"], "tokens_total", "{document}");
    assert!(
        ["total_usage", "credits_usage", "openrouter_usage"]
            .contains(&columns["cost_metric"].as_str().expect("a cost metric")),
        "{document}"
    );

    let rows = document["rows"].as_array().expect("a row array");
    for row in rows {
        assert!(
            row["cost_usd"].is_number() && row["tokens"].is_number(),
            "OpenRouter quotes its integral metrics, and a report carries numbers: {row}"
        );
        for period in row["periods"].as_array().expect("a period array") {
            assert!(
                period["cost_usd"].is_number() && period["tokens"].is_number(),
                "{period}"
            );
        }
    }

    // A key that has never been used has no spend, and a test organization with
    // no credits produces none, so the run's own rows are checked when they are
    // there and reported when they are not. Their absence is a fact about the
    // organization rather than a failure of the report.
    let mine: Vec<&Value> = rows
        .iter()
        .filter(|row| row["key"].as_str().is_some_and(|key| live.owns(key)))
        .collect();
    if mine.is_empty() {
        eprintln!(
            "live: analytics returned no row for {run}'s keys, which is what a key with no \
             traffic looks like",
            run = live.run
        );
    }
}

/// Sweeps a prefix left behind by a crashed run.
///
/// Not a test of Keymaster; a tool for the operator who has a journal file in
/// `target/live-runs/` and no process left to clean up after itself. Give it
/// the prefix, which is the journal file's name.
#[test]
#[ignore = "live: set KEYMASTER_LIVE_SWEEP=<prefix> and see docs/live-tests.md"]
fn live_sweep_named_prefix() {
    // Read the prefix first: with no prefix there is nothing to sweep, and
    // `just live` runs the whole file.
    let Ok(prefix) = std::env::var(SWEEP_VAR) else {
        eprintln!("no {SWEEP_VAR} set; nothing to sweep");
        return;
    };
    assert!(
        is_run_id(&prefix),
        "refusing to sweep {prefix:?}: a run identifier is {RUN_PREFIX}- followed by exactly \
         {RUN_ID_DIGITS} lowercase hex digits, and it is the name of a journal file in \
         target/live-runs/. A partial one such as {RUN_PREFIX:?} would match every live run's \
         resources, and this would delete keys belonging to a run still in progress."
    );
    let Some(mut live) = gate() else { return };

    // Everything that can refuse has to refuse *before* `live.run` is
    // reassigned. `Live` sweeps from `Drop`, so a panic after that line would
    // still sweep the named run — against whatever endpoint is configured
    // now, which is exactly what the check below exists to prevent. Until the
    // reassignment, `live.run` is this invocation's own fresh identifier and a
    // sweep of it finds nothing.
    let records = read_journal(&prefix).unwrap_or_else(|| {
        panic!(
            "no journal at {path}. A sweep reads the run's journal to learn which endpoint it \
             used, so it cannot proceed without one.",
            path = journal_directory()
                .join(format!("{prefix}.jsonl"))
                .display()
        )
    });
    if let Some(refusal) = endpoint_mismatch(&records, live.client.base_url()) {
        panic!("refusing to sweep {prefix}: {refusal}");
    }

    live.run = prefix;
    live.record("sweep", &live.run, "requested by KEYMASTER_LIVE_SWEEP");
    // A listing by prefix finds most of it, but not a resource whose remote
    // name is not what the sweep filters on. The crashed run wrote down what
    // it made; read that too.
    live.adopt_from_journal(&records);
}

// ------------------------------------------------------------------ scenarios

/// Forgets a bound guardrail, changes its description on disk, and imports it
/// back by UUID.
///
/// The reported difference has to name what OpenRouter holds. A planner
/// working from the file alone could not produce `original`, so seeing it is
/// proof the import read the remote object.
fn import_reports_the_remote_value(
    live: &Live,
    project: &Project,
    guardrail: &Uuid,
    original: &str,
) {
    project.succeed(&["--json", "state", "forget", "guardrails.alpha"]);

    let edited = format!("{run} edited description", run = live.run);
    project.write_config(&guardrail_config(&live.run, &edited));

    let imported = project.succeed(&[
        "--json",
        "import",
        "guardrail",
        "alpha",
        "--id",
        guardrail.as_str(),
    ]);
    let document = imported.document();
    let changes = document["changes"]
        .as_array()
        .expect("an import reports the fields an apply would reconcile");
    let description = changes
        .iter()
        .find(|change| change["field"] == "description")
        .unwrap_or_else(|| panic!("no description change in {changes:?}"));
    assert_eq!(
        description["from"], *original,
        "the import must report the description OpenRouter holds"
    );
    assert_eq!(description["to"], edited);

    let converged = project.succeed(&["--json", "apply"]);
    assert_eq!(converged.document()["outcome"], "applied");
    assert_eq!(
        live.guardrail(guardrail).description.as_deref(),
        Some(edited.as_str()),
        "the update should have landed"
    );
}

/// Rotates the key and returns the successor's hash.
///
/// The assertion that matters is the negative one: the predecessor is still
/// enabled afterwards. Keymaster stages a successor and stops, because it
/// cannot know when whatever reads the receiver has picked the new key up.
fn rotation_leaves_the_predecessor_alone(
    live: &Live,
    project: &Project,
    predecessor: &KeyHash,
) -> KeyHash {
    let rotated = project.succeed(&["--json", "rotate", "jobfeed"]);
    let successors = live.adopt_new_keys();
    let [successor] = successors.as_slice() else {
        panic!("rotate should have created exactly one key, not {successors:?}");
    };
    assert_ne!(successor, predecessor);
    assert!(
        !live.key(predecessor).disabled,
        "rotation must not disable the predecessor"
    );

    let status = project.succeed(&["--json", "status"]);
    assert!(
        status.out.contains(predecessor.as_str()),
        "the predecessor must stay tracked after rotation"
    );
    assert!(rotated.out.contains(successor.as_str()));
    successor.clone()
}

/// Retires the predecessor, then deletes it and proves the 404.
fn retire_then_delete(live: &Live, project: &Project, predecessor: &KeyHash) {
    project.succeed(&[
        "--json",
        "retire",
        "jobfeed",
        "--hash",
        predecessor.as_str(),
    ]);
    assert!(
        live.key(predecessor).disabled,
        "retire must disable the predecessor and prove it by reading it back"
    );

    project.succeed(&["--json", "delete", "key", "--hash", predecessor.as_str()]);
    assert_eq!(
        live.status_of(predecessor),
        Some(404),
        "a deleted key must be gone, not merely reported gone"
    );
    live.forget_key(predecessor);
}

/// Proves the workspace's default guardrail was materialized.
///
/// It has no `POST`: OpenRouter derives the identity from the workspace and the
/// guardrail appears in no listing until its configuration is first written, so
/// finding it in one is the proof that the first `PATCH` created it.
fn assert_default_guardrail_materialized(live: &Live, workspace: &Uuid) {
    let id = live
        .workspace(workspace)
        .default_guardrail_id
        .expect("every workspace carries a default guardrail identity");

    let guardrail = live.guardrail(&id);
    assert!(
        live.owns(&guardrail.name),
        "the default guardrail should carry the name its block configures"
    );
    let listed = live
        .reader()
        .list_guardrails(None)
        .expect("listing guardrails");
    assert!(
        listed.iter().any(|item| item.id == id),
        "a materialized default guardrail is an ordinary guardrail from then on"
    );
}

/// Writes a budget and an edited description in one apply, and keeps the
/// budget only if OpenRouter accepted it.
///
/// The shape of the answer is what matters here, not which answer it is.
/// Workspace budgets are documented as an Enterprise feature, so a plan
/// restriction is a perfectly good outcome — as long as it arrives as a
/// *definite* `403` naming the interval, and as long as the rest of the same
/// action still landed. Two things this must not see: a write that settles
/// nothing, since ADR-0004 item 4 promises a budget refusal is never ambiguous;
/// and a definite refusal that is not a `403`, which would be OpenRouter
/// objecting to the request rather than the account's plan.
fn budget_write_is_definite_and_the_rest_lands(
    live: &Live,
    project: &Project,
    club: &mut Club,
    workspace: &Uuid,
) {
    club.description = format!("{run} budgeted description", run = live.run);
    club.budgets = MONTHLY_BUDGET;
    project.write_config(&club.toml());

    let attempted = Streams::of(&project.run(&["--json", "apply"]));
    let document = attempted.document();
    let action = action_at(&document, "workspaces.club");
    let detail = action["detail"].as_str().expect("an action detail");
    assert!(
        !detail.contains("no answer that settles anything"),
        "a budget write is definite or it is a finding: {detail}"
    );

    match action["status"].as_str() {
        Some("applied") => {
            assert!(detail.contains("Budgets written: monthly"), "{detail}");
            assert_eq!(
                live.workspace(workspace)
                    .budgets
                    .get(&BudgetInterval::Monthly)
                    .map(|limit| limit.micros()),
                Some(1_000_000),
                "the budget OpenRouter reports back is the one that was written"
            );
        }
        Some("failed") => {
            assert!(
                detail.contains("OpenRouter refused") && detail.contains("monthly"),
                "a refusal names the interval it refused: {detail}"
            );
            // Only one refusal is an expected outcome, and it is the documented
            // one: budgets are an Enterprise feature and an account without it
            // is answered `403`. Every other definite `4xx` says the request
            // itself was wrong — a malformed body, an interval OpenRouter does
            // not take, a workspace it will not budget — and passing that off
            // as "your plan" would hide a real finding behind a shrug.
            assert!(
                detail.contains("HTTP 403"),
                "a budget write is accepted or refused with 403; anything else is a finding \
                 about the request rather than about the account's plan: {detail}"
            );
            eprintln!("live: this organization's plan refused a workspace budget: {detail}");
            // Removing the table is the only way a refused budget converges,
            // and everything after this step is placed in this workspace —
            // which the planner holds back while a budget has not converged.
            club.budgets = "";
            project.write_config(&club.toml());
        }
        other => panic!("a budget write is applied or refused, not {other:?}: {document}"),
    }

    assert_eq!(
        live.workspace(workspace).description.as_deref(),
        Some(club.description.as_str()),
        "the rest of the workspace write lands whatever became of the budget"
    );
}

/// Creates a key inside the workspace under `--workspace`.
///
/// A scoped run places what it creates in its scope, which is the only reason
/// the key ends up there: the block names the workspace by address, and the
/// scope is what a host running one club per `Context` would set.
fn scoped_run_places_a_key_in_the_workspace(
    live: &Live,
    project: &Project,
    club: &mut Club,
    workspace: &Uuid,
) {
    club.sink = Some(project.secrets.path().join("club.key"));
    project.write_config(&club.toml());

    let applied = project.succeed(&["--json", "--workspace", workspace.as_str(), "apply"]);
    assert_eq!(applied.document()["outcome"], "applied");

    let created = live.adopt_new_keys();
    let [key] = created.as_slice() else {
        panic!("the scoped apply should have created exactly one key, not {created:?}");
    };
    assert_eq!(
        live.key(key).workspace_id.as_ref(),
        Some(workspace),
        "a scoped run places what it creates in its scope"
    );
    let sink = club.sink.clone().expect("the receiver was just configured");
    project.assert_delivered_secret_stayed_put(&sink, live);
}

/// Forgets the workspace, edits its description on disk, and imports it back by
/// UUID.
///
/// The reported difference has to name what OpenRouter holds, as it does for a
/// guardrail. The import is run unscoped on purpose: a scoped run refuses a
/// workspace block that is not already bound to the scope, and forgetting one
/// is exactly how a block stops being bound.
fn workspace_import_reports_the_remote_value(
    live: &Live,
    project: &Project,
    club: &mut Club,
    workspace: &Uuid,
) {
    let remembered = club.description.clone();
    project.succeed(&["--json", "state", "forget", "workspaces.club"]);

    club.description = format!("{run} imported description", run = live.run);
    project.write_config(&club.toml());

    let imported = project.succeed(&[
        "--json",
        "import",
        "workspace",
        "club",
        "--id",
        workspace.as_str(),
    ]);
    let document = imported.document();
    let changes = document["changes"]
        .as_array()
        .expect("an import reports the fields an apply would reconcile");
    let description = changes
        .iter()
        .find(|change| change["field"] == "description")
        .unwrap_or_else(|| panic!("no description change in {changes:?}"));
    assert_eq!(
        description["from"], remembered,
        "the import must report the description OpenRouter holds"
    );
    assert_eq!(description["to"], club.description);

    let converged = project.succeed(&["--json", "apply"]);
    assert_eq!(converged.document()["outcome"], "applied");
    assert_eq!(
        live.workspace(workspace).description.as_deref(),
        Some(club.description.as_str()),
        "the update should have landed"
    );
}

/// Changes a destination's `config` and nothing else, and proves the write is
/// the only difference the plan sees.
///
/// `config` is write-only: OpenRouter masks it on read, so the comparison is
/// between the digest state records and the digest of what is configured now
/// (ADR-0006, item 3). The apply that follows has to leave the plan converged,
/// which is the only evidence available that the write landed.
fn config_update_travels_alone(live: &Live, project: &Project, destination: &Uuid) {
    let second = format!("https://example.invalid/{run}/two", run = live.run);
    project.write_config(&destination_config(&live.run, &second));

    let planned = project.succeed(&["--json", "plan"]);
    let document = planned.document();
    let action = action_at(&document, "log_destinations.hook");
    let changed: Vec<&str> = action["changes"]
        .as_array()
        .expect("a change list")
        .iter()
        .map(|change| change["field"].as_str().expect("a field name"))
        .collect();
    assert_eq!(
        changed,
        vec!["config"],
        "a masked field is compared by digest, and nothing else moved: {document}"
    );

    let applied = project.succeed(&["--json", "apply"]);
    assert_eq!(applied.document()["outcome"], "applied");
    assert_eq!(
        live.destination(destination).name,
        format!("{run}-hook", run = live.run),
        "the update leaves the destination the same one"
    );

    let again = project.succeed(&["--json", "plan"]);
    assert_eq!(
        again.document()["outcome"],
        "converged",
        "the digest recorded by the write is what makes the next plan quiet"
    );
}

/// The one action at `address` in a plan or apply document.
fn action_at<'a>(document: &'a Value, address: &str) -> &'a Value {
    document["actions"]
        .as_array()
        .expect("an action array")
        .iter()
        .find(|action| action["address"] == address)
        .unwrap_or_else(|| panic!("no action at {address} in {document}"))
}

/// What the host's code was handed, with the plaintext reduced to the one fact
/// a test needs about it.
///
/// The secret itself is never recorded. A record holding it would be a second
/// copy of a live credential, and the scan of the report would pass for the
/// wrong reason.
#[derive(Clone, Debug)]
struct Handed {
    address: String,
    hash: String,
    destination: Option<String>,
    looks_like_a_key: bool,
}

impl Handed {
    fn of(metadata: &DeliveryMetadata, plaintext: &KeyPlaintext) -> Self {
        Self {
            address: metadata.address().to_string(),
            hash: metadata.hash().to_string(),
            destination: metadata.destination().map(str::to_owned),
            looks_like_a_key: plaintext.expose().starts_with("sk-or-"),
        }
    }
}

// ------------------------------------------------------------------ the gate

/// Returns a live run, or [`None`] when this is not a live invocation.
///
/// The two gates answer different questions. `#[ignore]` answers "was this
/// suite asked for at all", and is what keeps a live test out of every default
/// run. The opt-in variable answers "did a person mean it", and is checked
/// again here because `--ignored` is a blunt instrument that a wrapper script
/// or a curious `cargo test -- --ignored` can reach for.
fn gate() -> Option<Live> {
    let opted_in = std::env::var(OPT_IN_VAR).is_ok_and(|value| value == "1");
    if !opted_in {
        eprintln!(
            "skipping the live suite: set {OPT_IN_VAR}=1 and OPENROUTER_MANAGEMENT_KEY to run it \
             against a dedicated test organization (docs/live-tests.md)"
        );
        return None;
    }
    let client = match client_from_env() {
        Ok(client) => client,
        Err(error) => panic!(
            "{OPT_IN_VAR}=1 asks for a live run, but the credential is unusable ({kind}). \
             Export OPENROUTER_MANAGEMENT_KEY for a dedicated test organization.",
            kind = error.kind()
        ),
    };
    Some(Live::new(client))
}

/// The live client, from the same two variables the binary reads.
fn client_from_env() -> Result<Client, ApiError> {
    Client::new(env::options()?, &env::management_key()?)
}

// ------------------------------------------------------------- the live run

/// One live run: its prefix, its client, and everything it has created.
struct Live {
    /// `km-live-<random>`. Every remote name this run creates starts with it,
    /// and the sweep refuses to touch anything that does not.
    run: String,
    client: Client,
    /// Append-only record of what exists, so a killed run leaves evidence.
    journal: PathBuf,
    keys: RefCell<Vec<KeyHash>>,
    /// UUID and remote name. The name is carried because the sweep cannot
    /// delete a guardrail and has to hand the operator something they can find
    /// in a dashboard, where a UUID alone is not much help.
    guardrails: RefCell<Vec<(Uuid, String)>>,
    /// Workspaces this run created, by UUID and remote name.
    workspaces: RefCell<Vec<(Uuid, String)>>,
    /// Log destinations this run created, by UUID and remote name.
    destinations: RefCell<Vec<(Uuid, String)>>,
    /// The `default_guardrail_id` of each workspace above.
    ///
    /// A workspace's own default guardrail is deleted with the workspace and
    /// cannot be deleted on its own, so it must not be reported to the operator
    /// as a guardrail to remove by hand.
    default_guardrails: RefCell<Vec<Uuid>>,
}

impl Live {
    fn new(client: Client) -> Self {
        let run = new_run_id();
        let journal = journal_path(&run);
        let live = Self {
            run,
            client,
            journal,
            keys: RefCell::new(Vec::new()),
            guardrails: RefCell::new(Vec::new()),
            workspaces: RefCell::new(Vec::new()),
            destinations: RefCell::new(Vec::new()),
            default_guardrails: RefCell::new(Vec::new()),
        };
        // Before anything exists: a run that dies between the create and the
        // record is swept by prefix, and the prefix is the one fact that
        // cannot be recovered afterwards.
        live.record("run", &live.run, live.client.base_url());
        eprintln!(
            "live run {run}: journal {journal}",
            run = live.run,
            journal = live.journal.display()
        );
        live
    }

    /// Appends one line to the run journal and flushes it to disk.
    fn record(&self, kind: &str, identity: &str, detail: &str) {
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("unknown"));
        let line = serde_json::json!({
            "at": now,
            "run": self.run,
            "kind": kind,
            "identity": identity,
            "detail": detail,
        });
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal)
            .unwrap_or_else(|error| {
                panic!(
                    "opening the run journal {path}: {error}",
                    path = self.journal.display()
                )
            });
        writeln!(file, "{line}").expect("writing the run journal");
        file.sync_all().expect("flushing the run journal");
    }

    /// True when `name` belongs to this run. Exact prefix, then a separator:
    /// `km-live-1a2b3c4d` must not match `km-live-1a2b3c4de`.
    fn owns(&self, name: &str) -> bool {
        name.starts_with(&format!("{run}-", run = self.run))
    }

    fn reader(&self) -> Reader<'_> {
        Reader::new(&self.client)
    }

    /// A reader that pages one record at a time, so a listing of three
    /// resources is a real multi-page read.
    fn paging_reader(&self) -> Reader<'_> {
        Reader::with_limits(
            &self.client,
            PageLimits {
                page_size: SMALL_PAGE,
                ..PageLimits::default()
            },
        )
    }

    /// Journals every guardrail this run owns that it has not recorded yet,
    /// and returns the new ones.
    fn adopt_guardrails(&self) -> Vec<Uuid> {
        let observed = self
            .reader()
            .list_guardrails(None)
            .expect("listing guardrails");
        let mut adopted = Vec::new();
        for guardrail in observed.iter().filter(|item| self.owns(&item.name)) {
            if self.tracks_guardrail(&guardrail.id) {
                continue;
            }
            self.guardrails
                .borrow_mut()
                .push((guardrail.id.clone(), guardrail.name.clone()));
            self.record("guardrail", guardrail.id.as_str(), &guardrail.name);
            adopted.push(guardrail.id.clone());
        }
        adopted
    }

    // Both of these exist to end the `RefCell` borrow before they return.
    // Inlining either into a condition would hold the `Ref` for the whole
    // `if`, and the branch that follows takes a `borrow_mut()`.
    fn tracks_guardrail(&self, id: &Uuid) -> bool {
        self.guardrails
            .borrow()
            .iter()
            .any(|(tracked, _)| tracked == id)
    }

    fn tracks_key(&self, hash: &KeyHash) -> bool {
        self.keys.borrow().contains(hash)
    }

    fn tracks_workspace(&self, id: &Uuid) -> bool {
        self.workspaces
            .borrow()
            .iter()
            .any(|(tracked, _)| tracked == id)
    }

    fn tracks_destination(&self, id: &Uuid) -> bool {
        self.destinations
            .borrow()
            .iter()
            .any(|(tracked, _)| tracked == id)
    }

    /// Journals every workspace this run owns that it has not recorded yet.
    ///
    /// Each one's default guardrail identity is recorded beside it, from the
    /// same listing, so the sweep knows which guardrail goes with the
    /// workspace and which is left for the operator.
    fn adopt_workspaces(&self) -> Vec<Uuid> {
        let observed = self.reader().list_workspaces().expect("listing workspaces");
        let mut adopted = Vec::new();
        for workspace in observed.iter().filter(|item| self.owns(&item.name)) {
            if self.tracks_workspace(&workspace.id) {
                continue;
            }
            self.workspaces
                .borrow_mut()
                .push((workspace.id.clone(), workspace.name.clone()));
            self.record("workspace", workspace.id.as_str(), &workspace.name);
            if let Some(default) = &workspace.default_guardrail_id {
                self.default_guardrails.borrow_mut().push(default.clone());
            }
            adopted.push(workspace.id.clone());
        }
        adopted
    }

    fn adopt_one_workspace(&self) -> Uuid {
        let adopted = self.adopt_workspaces();
        let [workspace] = adopted.as_slice() else {
            panic!("expected exactly one new workspace, not {adopted:?}");
        };
        workspace.clone()
    }

    /// Journals every log destination this run owns that it has not recorded
    /// yet.
    ///
    /// Destinations are listed one workspace at a time, so the question is
    /// asked of the credential's default workspace and of every workspace this
    /// run has made.
    fn adopt_destinations(&self) -> Vec<Uuid> {
        let observed = self
            .reader()
            .list_log_destinations(&self.workspace_ids())
            .expect("listing log destinations");
        let mut adopted = Vec::new();
        for destination in observed.iter().filter(|item| self.owns(&item.name)) {
            if self.tracks_destination(&destination.id) {
                continue;
            }
            self.destinations
                .borrow_mut()
                .push((destination.id.clone(), destination.name.clone()));
            self.record(
                "log-destination",
                destination.id.as_str(),
                &destination.name,
            );
            adopted.push(destination.id.clone());
        }
        adopted
    }

    fn adopt_one_destination(&self) -> Uuid {
        let adopted = self.adopt_destinations();
        let [destination] = adopted.as_slice() else {
            panic!("expected exactly one new log destination, not {adopted:?}");
        };
        destination.clone()
    }

    /// The workspaces this run tracks, as the destination listing takes them.
    fn workspace_ids(&self) -> Vec<Uuid> {
        self.workspaces
            .borrow()
            .iter()
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Loads the identities an earlier run journaled.
    ///
    /// A sweep by prefix reads what OpenRouter lists; this reads what the
    /// crashed run said it made. The two disagree exactly where it matters —
    /// a listing that fails, or a resource whose remote name is not the one
    /// being filtered on — so the sweep takes the union.
    ///
    /// It reads the earlier run's records and keeps writing to this
    /// invocation's own journal, so the record of what happened is not
    /// overwritten by the record of cleaning it up.
    fn adopt_from_journal(&self, records: &[Value]) {
        // Two passes. A key the crashed run already deleted and verified gone
        // needs no second attempt, and the line saying so comes after the line
        // that created it, so the deletions have to be known first.
        let deleted: Vec<&str> = records
            .iter()
            .filter(|record| {
                matches!(
                    record["kind"].as_str(),
                    Some("key-deleted" | "workspace-deleted" | "destination-deleted")
                )
            })
            .filter_map(|record| record["identity"].as_str())
            .collect();
        for record in records {
            self.adopt_journal_record(record, &deleted);
        }
    }

    fn adopt_journal_record(&self, record: &Value, deleted: &[&str]) {
        let (Some(kind), Some(identity)) = (record["kind"].as_str(), record["identity"].as_str())
        else {
            return;
        };
        let name = record["detail"].as_str().unwrap_or("unknown");
        match kind {
            "key" if !deleted.contains(&identity) => {
                if let Ok(hash) = KeyHash::parse(identity)
                    && !self.tracks_key(&hash)
                {
                    self.record("recovered-key", identity, name);
                    self.keys.borrow_mut().push(hash);
                }
            }
            "guardrail" => {
                if let Ok(id) = Uuid::parse(identity)
                    && !self.tracks_guardrail(&id)
                {
                    self.record("recovered-guardrail", identity, name);
                    self.guardrails.borrow_mut().push((id, name.to_owned()));
                }
            }
            "workspace" if !deleted.contains(&identity) => {
                if let Ok(id) = Uuid::parse(identity)
                    && !self.tracks_workspace(&id)
                {
                    self.record("recovered-workspace", identity, name);
                    self.workspaces.borrow_mut().push((id, name.to_owned()));
                }
            }
            "log-destination" if !deleted.contains(&identity) => {
                if let Ok(id) = Uuid::parse(identity)
                    && !self.tracks_destination(&id)
                {
                    self.record("recovered-log-destination", identity, name);
                    self.destinations.borrow_mut().push((id, name.to_owned()));
                }
            }
            _ => {}
        }
    }

    fn adopt_one_guardrail(&self) -> Uuid {
        let adopted = self.adopt_guardrails();
        let [guardrail] = adopted.as_slice() else {
            panic!("expected exactly one new guardrail, not {adopted:?}");
        };
        guardrail.clone()
    }

    /// Records every key this run owns that is not tracked yet.
    ///
    /// Two keys at one address share a remote name during a rotation, so
    /// identity — never the name — decides which one is new.
    fn adopt_new_keys(&self) -> Vec<KeyHash> {
        let observed = self.reader().list_keys(None).expect("listing keys");
        let mut adopted = Vec::new();
        for key in observed.iter().filter(|item| self.owns(&item.name)) {
            if self.keys.borrow().contains(&key.hash) {
                continue;
            }
            self.keys.borrow_mut().push(key.hash.clone());
            self.record("key", key.hash.as_str(), &key.name);
            adopted.push(key.hash.clone());
        }
        adopted
    }

    fn forget_key(&self, hash: &KeyHash) {
        self.keys.borrow_mut().retain(|tracked| tracked != hash);
        self.record("key-deleted", hash.as_str(), "verified 404");
    }

    fn forget_workspace(&self, id: &Uuid) {
        self.workspaces
            .borrow_mut()
            .retain(|(tracked, _)| tracked != id);
        self.record("workspace-deleted", id.as_str(), "verified 404");
    }

    fn forget_destination(&self, id: &Uuid) {
        self.destinations
            .borrow_mut()
            .retain(|(tracked, _)| tracked != id);
        self.record("destination-deleted", id.as_str(), "verified 404");
    }

    fn key(&self, hash: &KeyHash) -> openrouter_keymaster_core::api::ObservedKey {
        self.reader().get_key(hash).expect("reading a key by hash")
    }

    fn guardrail(&self, id: &Uuid) -> openrouter_keymaster_core::api::ObservedGuardrail {
        self.reader()
            .get_guardrail(id)
            .expect("reading a guardrail by UUID")
    }

    fn workspace(&self, id: &Uuid) -> openrouter_keymaster_core::api::ObservedWorkspace {
        self.reader()
            .get_workspace(id)
            .expect("reading a workspace by UUID")
    }

    fn destination(&self, id: &Uuid) -> openrouter_keymaster_core::api::ObservedDestination {
        self.reader()
            .get_log_destination(id)
            .expect("reading a log destination by UUID")
    }

    /// The HTTP status of a destination read, or [`None`] when it succeeded.
    fn destination_status(&self, id: &Uuid) -> Option<u16> {
        match self.reader().get_log_destination(id) {
            Ok(_) => None,
            Err(error) => Some(error.status().unwrap_or_else(|| {
                panic!("expected an HTTP status, got {kind}", kind = error.kind())
            })),
        }
    }

    fn guardrail_named(&self, name: &str) -> Uuid {
        let observed = self
            .reader()
            .list_guardrails(None)
            .expect("listing guardrails");
        observed
            .into_iter()
            .find(|guardrail| guardrail.name == name)
            .unwrap_or_else(|| panic!("no guardrail named {name}"))
            .id
    }

    /// The HTTP status of a read, or [`None`] when the read succeeded.
    fn status_of(&self, hash: &KeyHash) -> Option<u16> {
        match self.reader().get_key(hash) {
            Ok(_) => None,
            Err(error) => Some(error.status().unwrap_or_else(|| {
                panic!("expected an HTTP status, got {kind}", kind = error.kind())
            })),
        }
    }

    /// Proves a one-record-per-page listing still returns every guardrail once.
    fn assert_guardrail_listing_is_complete(&self, expected: &[Uuid]) {
        let observed = self
            .paging_reader()
            .list_guardrails(None)
            .expect("paginating guardrails");
        let mine: Vec<&Uuid> = observed
            .iter()
            .filter(|guardrail| self.owns(&guardrail.name))
            .map(|guardrail| &guardrail.id)
            .collect();
        assert_eq!(mine.len(), expected.len(), "pagination dropped or repeated");
        for id in expected {
            assert!(mine.contains(&id), "{id} missing from a paginated listing");
        }
    }

    fn assert_key_listing_is_complete(&self, expected: &[KeyHash]) {
        let observed = self
            .paging_reader()
            .list_keys(None)
            .expect("paginating keys");
        let mine: Vec<&KeyHash> = observed
            .iter()
            .filter(|key| self.owns(&key.name))
            .map(|key| &key.hash)
            .collect();
        assert_eq!(mine.len(), expected.len(), "pagination dropped or repeated");
        for hash in expected {
            assert!(
                mine.contains(&hash),
                "{hash} missing from a paginated listing"
            );
        }
    }

    /// A listing is a different endpoint from a get; both have to agree.
    fn assert_exact_guardrail_get(&self, expected: &[Uuid]) {
        for id in expected {
            let guardrail = self.guardrail(id);
            assert_eq!(&guardrail.id, id);
            assert!(self.owns(&guardrail.name), "swept the wrong guardrail");
        }
    }

    /// The state a created key must be in before its plaintext may be
    /// delivered: disabled by the update that follows the create, budgeted at
    /// zero, and carrying its guardrail.
    fn assert_key_created_disabled_and_assigned(&self, hash: &KeyHash, guardrail: &Uuid) {
        let key = self.key(hash);
        assert!(
            key.disabled,
            "`POST /keys` has no disabled field, so the update-only policy has to have landed"
        );
        assert_eq!(
            key.limit
                .map(openrouter_keymaster_core::config::Usd::micros),
            Some(0),
            "a live test key must not be able to spend"
        );
        let assignments = self
            .reader()
            .list_assignments_of(guardrail)
            .expect("reading the guardrail's assignments");
        assert!(
            assignments
                .iter()
                .any(|assignment| &assignment.key_hash == hash),
            "the key should be assigned to its guardrail"
        );
    }
}

// ------------------------------------------------------------------- cleanup

impl Drop for Live {
    fn drop(&mut self) {
        let swept = self.sweep();
        // Guardrails are expected to survive a sweep, so they are reported and
        // journaled but do not fail anything. A key that outlived cleanup is a
        // different matter: it is a live credential nothing tracks.
        for notice in &swept.notices {
            eprintln!("live cleanup: {notice}");
            self.record("left-behind", &self.run, notice);
        }
        if swept.failures.is_empty() {
            self.record("swept", &self.run, "every key deleted and verified gone");
            return;
        }
        for failure in &swept.failures {
            eprintln!("live cleanup FAILED: {failure}");
            self.record("cleanup-failed", &self.run, failure);
        }
        // Never mask the failure that caused the panic that got us here.
        assert!(
            std::thread::panicking(),
            "live cleanup did not finish; see the messages above and the journal \
             at {journal}",
            journal = self.journal.display()
        );
    }
}

/// What a sweep could not finish, split by whether it is a problem.
struct Swept {
    /// What this run created and could not remove: a key, a log destination, or
    /// a workspace. Each one fails the run.
    failures: Vec<String>,
    /// Resources deliberately left in place, named so an operator can remove
    /// them by hand.
    notices: Vec<String>,
}

impl Live {
    /// Deletes everything this run owns and returns what could not be removed,
    /// as non-secret identities an operator can act on.
    ///
    /// Response bodies are drained by the client and never reproduced here: a
    /// failure is reported as an identity plus an error kind, because a body
    /// from a failed cleanup call is exactly the place a stray credential
    /// echo would end up.
    fn sweep(&self) -> Swept {
        // Destinations first. A destination is the thing that *watches* the
        // keys, so removing it before they are deleted means the run stops
        // forwarding before it starts churning what was being forwarded —
        // rather than aiming a burst of log traffic at an endpoint that, in
        // this suite, deliberately cannot answer.
        let mut failures = self.delete_destinations();

        let mut hashes = self.keys.borrow().clone();
        match self.reader().list_keys(None) {
            Ok(observed) => {
                for key in observed.iter().filter(|key| self.owns(&key.name)) {
                    if !hashes.contains(&key.hash) {
                        hashes.push(key.hash.clone());
                    }
                }
            }
            Err(error) => failures.push(format!(
                "could not list keys to sweep {run} ({kind}); run `just live-sweep {run}`",
                run = self.run,
                kind = error.kind()
            )),
        }
        for hash in &hashes {
            if let Err(reason) = self.delete_and_verify(hash) {
                failures.push(reason);
            }
        }
        // Workspaces last, because OpenRouter refuses to delete one that still
        // holds anything, and everything above may have been placed in one.
        failures.extend(self.delete_workspaces());
        let guardrails = self.report_guardrails();
        failures.extend(guardrails.failures);
        Swept {
            failures,
            notices: guardrails.notices,
        }
    }

    /// Deletes the log destinations this run created, each verified by a 404.
    ///
    /// The first step of the sweep: nothing else has to wait for it, and it
    /// stops log forwarding before the keys it was forwarding are deleted.
    ///
    /// Unlike a guardrail, a destination has a delete, so one left behind is a
    /// failure rather than a notice: Keymaster can remove it and this run made
    /// it.
    fn delete_destinations(&self) -> Vec<String> {
        let mut failures = Vec::new();
        let mut named: Vec<(Uuid, String)> = self.destinations.borrow().clone();
        match self.reader().list_log_destinations(&self.workspace_ids()) {
            Ok(observed) => {
                for destination in observed.iter().filter(|item| self.owns(&item.name)) {
                    if !named.iter().any(|(id, _)| id == &destination.id) {
                        named.push((destination.id.clone(), destination.name.clone()));
                    }
                }
            }
            Err(error) => failures.push(format!(
                "could not list log destinations while sweeping {run} ({kind}); run \
                 `just live-sweep {run}`",
                run = self.run,
                kind = error.kind()
            )),
        }

        let writer = Writer::new(&self.client);
        for (id, name) in named {
            match writer.delete_log_destination(&id) {
                Ok(()) => {}
                Err(error) if error.status() == Some(404) => {}
                Err(error) => {
                    failures.push(format!(
                        "log destination {id} (\"{name}\") not deleted ({kind}); delete it by ID",
                        kind = error.kind()
                    ));
                    continue;
                }
            }
            match self.destination_status_quietly(&id) {
                Some(404) => self.forget_destination(&id),
                Some(status) => failures.push(format!(
                    "log destination {id} (\"{name}\") still readable after delete (HTTP \
                     {status}); delete it by ID"
                )),
                None => failures.push(format!(
                    "log destination {id} (\"{name}\") still exists after a successful delete; \
                     delete it by ID"
                )),
            }
        }
        failures
    }

    /// Deletes the workspaces this run created, each verified by a 404.
    ///
    /// A workspace that still holds a key, a guardrail, or a destination is
    /// refused, which is the point of running this after both. Its own default
    /// guardrail is not an occupant and goes with it.
    fn delete_workspaces(&self) -> Vec<String> {
        let mut failures = Vec::new();
        let mut named: Vec<(Uuid, String)> = self.workspaces.borrow().clone();
        match self.reader().list_workspaces() {
            Ok(observed) => {
                for workspace in observed.iter().filter(|item| self.owns(&item.name)) {
                    if !named.iter().any(|(id, _)| id == &workspace.id) {
                        named.push((workspace.id.clone(), workspace.name.clone()));
                    }
                }
            }
            Err(error) => failures.push(format!(
                "could not list workspaces while sweeping {run} ({kind}); run \
                 `just live-sweep {run}`",
                run = self.run,
                kind = error.kind()
            )),
        }

        let writer = Writer::new(&self.client);
        for (id, name) in named {
            match writer.delete_workspace(&id) {
                Ok(()) => {}
                Err(error) if error.status() == Some(404) => {}
                Err(error) => {
                    failures.push(format!(
                        "workspace {id} (\"{name}\") not deleted ({kind}); it may still hold a \
                         key, a guardrail, or a log destination — empty it and delete it by ID",
                        kind = error.kind()
                    ));
                    continue;
                }
            }
            match self.workspace_status_quietly(&id) {
                Some(404) => self.forget_workspace(&id),
                Some(status) => failures.push(format!(
                    "workspace {id} (\"{name}\") still readable after delete (HTTP {status}); \
                     delete it by ID"
                )),
                None => failures.push(format!(
                    "workspace {id} (\"{name}\") still exists after a successful delete; delete \
                     it by ID"
                )),
            }
        }
        failures
    }

    /// Like [`Live::destination_status`], but reports rather than panics.
    fn destination_status_quietly(&self, id: &Uuid) -> Option<u16> {
        match self.reader().get_log_destination(id) {
            Ok(_) => None,
            Err(error) => error.status().or(Some(0)),
        }
    }

    /// The same, for a workspace.
    fn workspace_status_quietly(&self, id: &Uuid) -> Option<u16> {
        match self.reader().get_workspace(id) {
            Ok(_) => None,
            Err(error) => error.status().or(Some(0)),
        }
    }

    /// Deletes one key and reads it back until OpenRouter answers 404.
    ///
    /// A 2xx on the delete is not the proof; the absence of the immutable
    /// identity is, which is the same rule `openrouter-keymaster delete key` follows.
    fn delete_and_verify(&self, hash: &KeyHash) -> Result<(), String> {
        let writer = Writer::new(&self.client);
        match writer.delete_key(hash) {
            Ok(()) => {}
            Err(error) if error.status() == Some(404) => {}
            Err(error) => {
                return Err(format!(
                    "key {hash} not deleted ({kind}); delete it by hash",
                    kind = error.kind()
                ));
            }
        }
        match self.status_of_quietly(hash) {
            Some(404) => Ok(()),
            Some(status) => Err(format!(
                "key {hash} still readable after delete (HTTP {status}); delete it by hash"
            )),
            None => Err(format!(
                "key {hash} still exists after a successful delete; delete it by hash"
            )),
        }
    }

    /// Like [`Live::status_of`], but reports rather than panics: a sweep that
    /// panicked would abandon the resources it had not reached yet.
    fn status_of_quietly(&self, hash: &KeyHash) -> Option<u16> {
        match self.reader().get_key(hash) {
            Ok(_) => None,
            Err(error) => error.status().or(Some(0)),
        }
    }

    /// Nothing in Keymaster deletes a guardrail — a guardrail spends nothing
    /// and config removal is deliberately not authority to destroy one — so
    /// the sweep names the ones this run created and leaves them.
    ///
    /// The listing is not decoration. What this run journaled covers only the
    /// guardrails it got as far as recording; a run that died between the
    /// create and the record left one that *only* the listing can name. So a
    /// failed listing is a cleanup failure, exactly as it is on the key path:
    /// the alternative is a sweep that reports success while something it
    /// created stays behind unnamed.
    fn report_guardrails(&self) -> Swept {
        let mut failures = Vec::new();
        let mut named: Vec<(Uuid, String)> = self.guardrails.borrow().clone();
        match self.reader().list_guardrails(None) {
            Ok(observed) => {
                for guardrail in observed.iter().filter(|item| self.owns(&item.name)) {
                    if !named.iter().any(|(id, _)| id == &guardrail.id) {
                        named.push((guardrail.id.clone(), guardrail.name.clone()));
                    }
                }
            }
            Err(error) => failures.push(format!(
                "could not list guardrails while sweeping {run} ({kind}), so a guardrail this \
                 run created but did not journal would go unnamed; run `just live-sweep {run}` \
                 or search the dashboard for names starting {run}-",
                run = self.run,
                kind = error.kind()
            )),
        }
        // A workspace's own default guardrail is not one of these. It cannot be
        // deleted on its own and the workspace deletion above took it, so
        // naming it would send an operator looking for something that is not
        // there — or, if that deletion failed, to a guardrail they cannot
        // remove until the workspace goes.
        let defaults = self.default_guardrails.borrow();
        let notices = named
            .into_iter()
            .filter(|(id, _)| !defaults.contains(id))
            .map(|(id, name)| {
                format!(
                    "guardrail {id} (\"{name}\") of run {run} left in place; Keymaster deletes \
                     no guardrail, so remove it in the OpenRouter dashboard",
                    run = self.run
                )
            })
            .collect();
        Swept { failures, notices }
    }
}

// ------------------------------------------------------------------- project

/// A throwaway project directory and the runs made in it.
///
/// Named for the directory rather than for anything remote: in this file a
/// *workspace* is an OpenRouter workspace, which is a resource these runs
/// create.
///
/// Two directories, not one. The project directory holds the configuration and
/// the state file and is scanned for the delivered plaintext; the receiver
/// writes into the other one, because what it writes is a live credential and
/// finding it in the scanned tree is supposed to be a failure.
struct Project {
    directory: TempDir,
    secrets: TempDir,
    transcript: RefCell<Vec<String>>,
}

impl Project {
    fn new() -> Self {
        Self {
            directory: TempDir::new().expect("a project directory"),
            secrets: TempDir::new().expect("a receiver directory"),
            transcript: RefCell::new(Vec::new()),
        }
    }

    fn config_path(&self) -> PathBuf {
        self.directory.path().join("openrouter-keymaster.toml")
    }

    fn state_path(&self) -> PathBuf {
        self.directory.path().join("state.json")
    }

    fn write_config(&self, contents: &str) {
        fs::write(self.config_path(), contents).expect("writing the configuration");
    }

    /// Runs the real binary against the real API.
    ///
    /// The credential is inherited rather than passed: it stays in the
    /// environment this process was started with and never enters a test
    /// variable, an argument vector, or a temporary file. The fault-injection
    /// variable is removed because a live run must never be interrupted at a
    /// journal phase on purpose.
    fn run(&self, arguments: &[&str]) -> Output {
        let mut command =
            Command::cargo_bin("openrouter-keymaster").expect("the openrouter-keymaster binary");
        command
            .env_remove("KEYMASTER_STATE_FAULT")
            .arg("--config")
            .arg(self.config_path())
            .arg("--state")
            .arg(self.state_path())
            .args(arguments);
        let output = command.output().expect("running openrouter-keymaster");
        let streams = Streams::of(&output);
        self.transcript.borrow_mut().push(streams.out);
        self.transcript.borrow_mut().push(streams.err);
        output
    }

    fn succeed(&self, arguments: &[&str]) -> Streams {
        let output = self.run(arguments);
        let streams = Streams::of(&output);
        assert!(
            output.status.success(),
            "openrouter-keymaster {arguments:?} failed: {err}",
            err = streams.err
        );
        streams
    }

    /// Reads the delivered key and proves it went nowhere else.
    ///
    /// This is the live counterpart of the sentinel scan. The sentinel cannot
    /// help here — the secret is whatever OpenRouter just issued — so the
    /// delivered plaintext itself is the needle, and the haystacks are every
    /// stream this workspace has produced, every file it has written, and the
    /// run journal.
    fn assert_delivered_secret_stayed_put(&self, sink: &Path, live: &Live) {
        let metadata = fs::symlink_metadata(sink).expect("the receiver wrote its file");
        assert!(
            metadata.is_file(),
            "a receiver target must be a regular file"
        );
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o600,
            "a delivered key must be readable only by its owner"
        );
        let secret = fs::read_to_string(sink).expect("reading the delivered key");
        assert!(!secret.trim().is_empty(), "the receiver wrote nothing");

        for (index, captured) in self.transcript.borrow().iter().enumerate() {
            assert!(
                !captured.contains(secret.trim()),
                "the delivered key reached stream {index}"
            );
        }
        assert_absent_under(self.directory.path(), secret.trim());
        assert_absent_in(&live.journal, secret.trim());
    }
}

/// Fails when `needle` appears in any file at or under `path`, or in a name.
fn assert_absent_under(path: &Path, needle: &str) {
    let label = path.display().to_string();
    assert!(!label.contains(needle), "the delivered key reached a path");
    let metadata = fs::symlink_metadata(path).expect("scanning the project directory");
    if metadata.is_dir() {
        let entries = fs::read_dir(path).expect("listing the project directory");
        for entry in entries {
            let entry = entry.expect("listing the project directory");
            assert_absent_under(&entry.path(), needle);
        }
    } else if metadata.is_file() {
        assert_absent_in(path, needle);
    }
}

fn assert_absent_in(path: &Path, needle: &str) {
    let label = path.display().to_string();
    let contents = fs::read(path).unwrap_or_else(|error| panic!("reading {label}: {error}"));
    assert!(
        !String::from_utf8_lossy(&contents).contains(needle),
        "the delivered key reached {label}"
    );
}

// ------------------------------------------------------------ configurations

/// The smallest guardrail budget OpenRouter accepts, in USD.
///
/// `POST /guardrails` answers `limit_usd = 0` with a 400, "Too small: expected
/// number to be >0" — a minimum its OpenAPI document does not state. So a
/// guardrail cannot cap spending at nothing the way a key can, and one cent is
/// as close as this suite gets.
const GUARDRAIL_LIMIT_USD: &str = "0.01";

/// Three guardrails, so a one-record page size has something to page through.
fn guardrail_config(run: &str, description: &str) -> String {
    let mut config = String::from("version = 1\n");
    for name in ["alpha", "beta", "gamma"] {
        config.push_str(&format!(
            "\n[guardrails.{name}]\nname = \"{run}-{name}\"\ndescription = \"{description}\"\n\
             limit_usd = {GUARDRAIL_LIMIT_USD}\nreset_interval = \"daily\"\n"
        ));
    }
    config
}

/// One guardrail, one zero-budget key, and a file receiver.
///
/// The key's limit is zero on purpose: a key this suite loses track of has to
/// be one that cannot spend anything. The guardrail over it can only go down to
/// [`GUARDRAIL_LIMIT_USD`], which is why the key carries its own cap rather
/// than leaning on the guardrail's. `disabled` is the field the create cannot
/// set, so it is what proves the update-only policy ran.
fn key_config(run: &str, sink: &Path, disabled: bool) -> String {
    format!(
        "version = 1\n\
         \n[guardrails.cap]\n\
         name = \"{run}-cap\"\n\
         limit_usd = {GUARDRAIL_LIMIT_USD}\n\
         reset_interval = \"daily\"\n\
         \n[keys.jobfeed]\n\
         name = \"{run}-jobfeed\"\n\
         limit_usd = 0\n\
         limit_reset = \"daily\"\n\
         disabled = {disabled}\n\
         guardrail = \"cap\"\n\
         receiver = \"sink\"\n\
         \n[receivers.sink]\n\
         type = \"file\"\n\
         path = \"{sink}\"\n",
        sink = sink.display()
    )
}

/// The `budgets` table the workspace scenario asks for: one dollar a month.
///
/// A workspace budget has to be greater than zero, which the API documents. It
/// caps a workspace whose default guardrail already holds everything in it to
/// [`GUARDRAIL_LIMIT_USD`] a day, and whose only key cannot spend at all.
const MONTHLY_BUDGET: &str = "budgets = { monthly = 1 }\n";

/// The club workspace's configuration, as the scenario edits it.
///
/// A struct rather than four arguments, because each step changes one field and
/// leaves the rest as the previous step left them — which is what the file on
/// disk does too.
struct Club {
    run: String,
    description: String,
    /// The `budgets` line, kept only while OpenRouter accepts it.
    budgets: &'static str,
    /// Where the key inside the workspace is delivered, once there is one.
    sink: Option<PathBuf>,
}

impl Club {
    fn new(run: &str) -> Self {
        Self {
            run: run.to_owned(),
            description: format!("{run} original description"),
            budgets: "",
            sink: None,
        }
    }

    /// One workspace, its default guardrail, and — once a sink is named — one
    /// disabled zero-budget key inside it.
    fn toml(&self) -> String {
        let key = self.sink.as_ref().map_or(String::new(), |sink| {
            format!(
                "\n[keys.member]\n\
                 name = \"{run}-member\"\n\
                 limit_usd = 0\n\
                 limit_reset = \"daily\"\n\
                 disabled = true\n\
                 workspace = \"club\"\n\
                 receiver = \"sink\"\n\
                 \n[receivers.sink]\n\
                 type = \"file\"\n\
                 path = \"{sink}\"\n",
                run = self.run,
                sink = sink.display()
            )
        });
        format!(
            "version = 1\n\
             \n[workspaces.club]\n\
             name = \"{run}-club\"\n\
             slug = \"{run}-club\"\n\
             description = \"{description}\"\n\
             {budgets}\
             default_guardrail = \"house\"\n\
             \n[guardrails.house]\n\
             name = \"{run}-house\"\n\
             limit_usd = {GUARDRAIL_LIMIT_USD}\n\
             reset_interval = \"daily\"\n\
             {key}",
            run = self.run,
            description = self.description,
            budgets = self.budgets,
        )
    }
}

/// One zero-budget key delivered to the host's own code (ADR-0005).
fn caller_config(run: &str) -> String {
    format!(
        "version = 1\n\
         \n[keys.hostkey]\n\
         name = \"{run}-hostkey\"\n\
         limit_usd = 0\n\
         limit_reset = \"daily\"\n\
         disabled = true\n\
         receiver = \"host\"\n\
         \n[receivers.host]\n\
         type = \"caller\"\n\
         destination = \"live/caller\"\n"
    )
}

/// One `webhook` log destination, in the credential's default workspace.
///
/// `.invalid` is reserved so that a name in it can never resolve, which is what
/// makes this endpoint harmless: nothing is listening and nothing can be. What
/// OpenRouter makes of an unreachable URL at create time is one of the things a
/// live run is here to find out — if it validates reachability, the create
/// fails and that is a finding about the API rather than a bug in this test.
/// See [`docs/live-tests.md`](../docs/live-tests.md).
fn destination_config(run: &str, url: &str) -> String {
    format!(
        "version = 1\n\
         \n[log_destinations.hook]\n\
         type = \"webhook\"\n\
         name = \"{run}-hook\"\n\
         config = {{ url = \"{url}\" }}\n"
    )
}

// ----------------------------------------------------------------- run identity

/// `km-live-<8 hex>`, unique per test in a run and across runs.
///
/// Derived from the clock, the process, and a counter rather than a random
/// number generator: the suite needs a name nothing else will collide with,
/// not an unpredictable one, and this avoids a dependency for it.
fn new_run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(process::id().to_le_bytes());
    hasher.update(RUNS.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let digest = hasher.finalize();
    let mut id = String::from(RUN_PREFIX);
    id.push('-');
    for byte in digest.iter().take(RUN_ID_DIGITS / 2) {
        id.push_str(&format!("{byte:02x}"));
    }
    id
}

/// Whether `value` is a complete run identifier: `km-live-` and exactly eight
/// lowercase hex digits.
///
/// The whole safety model rests on this. [`Live::owns`] answers "is this
/// resource mine" by matching `<run>-` against a remote name, so a *truncated*
/// identifier owns far more than it should: `km-live` matches every live run
/// there has ever been, and sweeping it would delete the keys of a run
/// happening right now in another terminal. Nothing that is not exactly one
/// run's name gets to be a run's name.
fn is_run_id(value: &str) -> bool {
    let Some(digits) = value.strip_prefix(&format!("{RUN_PREFIX}-")) else {
        return false;
    };
    digits.len() == RUN_ID_DIGITS
        && digits
            .bytes()
            .all(|digit| digit.is_ascii_digit() || (b'a'..=b'f').contains(&digit))
}

/// Not a live test: [`is_run_id`] is a pure function and the refusal it backs
/// is the one thing in this file that must not need a credential to check.
#[test]
fn only_a_complete_run_identifier_is_accepted() {
    assert!(is_run_id("km-live-1a2b3c4d"));
    assert!(is_run_id(&new_run_id()), "a minted identifier must pass");

    for refused in [
        // The finding: a partial prefix owns every run's resources.
        "km-live",
        "km-live-",
        "km-live-1a2b3c4",
        // A longer one is not a different run, it is a typo that owns nothing
        // — but `owns` matches by prefix, so it must not be trusted either.
        "km-live-1a2b3c4de",
        "km-live-1a2b3c4d-alpha",
        // Uppercase never comes out of `new_run_id`, so it is not one of ours.
        "km-live-1A2B3C4D",
        "km-live-zzzzzzzz",
        "km-live-1a2b3c4 ",
        "",
        "km-liveXX1a2b3c4d",
        "prod-key",
    ] {
        assert!(!is_run_id(refused), "{refused:?} must be refused");
    }
}

/// Also not a live test. A sweep pointed at the wrong endpoint reads 404 as
/// proof of deletion, so this refusal is the difference between a clean report
/// and a silent pile of live keys.
#[test]
fn a_sweep_refuses_an_endpoint_the_run_did_not_use() {
    let production = "https://openrouter.ai/api/v1";
    let opened = |detail: &str| {
        vec![serde_json::json!({
            "kind": "run", "identity": "km-live-1a2b3c4d", "detail": detail,
        })]
    };

    assert_eq!(endpoint_mismatch(&opened(production), production), None);

    let gateway = "https://gateway.example/api/v1";
    let refusal = endpoint_mismatch(&opened(gateway), production)
        .expect("a different endpoint must be refused");
    assert!(refusal.contains(gateway), "{refusal}");
    assert!(refusal.contains(production), "{refusal}");
    assert!(refusal.contains("OPENROUTER_BASE_URL"), "{refusal}");

    // A journal with no `run` record cannot say which endpoint was used, so it
    // is refused rather than swept hopefully. No such journal exists yet; this
    // is what happens when one written before this check turns up.
    let unopened = vec![serde_json::json!({
        "kind": "key", "identity": "hash-orphan", "detail": "km-live-1a2b3c4d-jobfeed",
    })];
    let refusal =
        endpoint_mismatch(&unopened, production).expect("an endpoint-less journal must be refused");
    assert!(refusal.contains("predates endpoint recording"), "{refusal}");
}

/// Where run journals live: next to the build output, and out of git.
///
/// `CARGO_MANIFEST_DIR` is this crate's directory, and the build output is the
/// workspace's, two levels up.
fn journal_directory() -> PathBuf {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join("live-runs");
    fs::create_dir_all(&directory).expect("creating the live-run journal directory");
    directory
}

/// `target/live-runs/<run>.jsonl`, created empty for this run.
fn journal_path(run: &str) -> PathBuf {
    let path = journal_directory().join(format!("{run}.jsonl"));
    File::create(&path).expect("creating the run journal");
    path
}

/// Reads a run's journal records, or [`None`] when it has no journal.
///
/// A line that does not parse is skipped rather than fatal: a run killed
/// mid-write can leave a truncated last line, and the records before it are
/// still the best evidence of what exists.
fn read_journal(run: &str) -> Option<Vec<Value>> {
    let contents = fs::read_to_string(journal_directory().join(format!("{run}.jsonl"))).ok()?;
    Some(
        contents
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect(),
    )
}

/// Why these records may not be swept against `current`, if they may not be.
///
/// A sweep proves a key is gone by reading its hash back and getting a 404.
/// That proof is only worth anything against the endpoint the key was created
/// on: run the sweep against a different `OPENROUTER_BASE_URL` — or against
/// production when the run used a gateway, which is what an unset variable
/// gives you — and *every* hash 404s. The sweep would report a clean run while
/// every resource it was asked to delete survived at the original endpoint.
///
/// So the endpoint is compared, not assumed. The first line a run journals is
/// the one carrying it.
fn endpoint_mismatch(records: &[Value], current: &str) -> Option<String> {
    let recorded = records
        .iter()
        .find(|record| record["kind"] == "run")
        .and_then(|record| record["detail"].as_str());
    match recorded {
        Some(recorded) if recorded == current => None,
        Some(recorded) => Some(format!(
            "the run used {recorded} and this sweep is pointed at {current}. Every hash would \
             404 against the wrong endpoint and the sweep would call that success. Re-run it \
             with OPENROUTER_BASE_URL={recorded}"
        )),
        None => Some(String::from(
            "its journal records no endpoint, so it predates endpoint recording; sweep it with \
             OPENROUTER_BASE_URL set explicitly to the endpoint that run used",
        )),
    }
}
