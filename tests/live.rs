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
//!   OpenRouter answers 404.
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
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use openrouter_keymaster::api::pagination::PageLimits;
use openrouter_keymaster::api::{Reader, Writer};
use openrouter_keymaster::app::env;
use openrouter_keymaster::client::{ApiError, Client};
use openrouter_keymaster::ids::{KeyHash, Uuid};
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
    let workspace = Workspace::new();
    let original = format!("{run} original description", run = live.run);

    workspace.write_config(&guardrail_config(&live.run, &original));
    let applied = workspace.succeed(&["--json", "apply"]);
    assert_eq!(applied.document()["outcome"], "applied");

    let found = live.adopt_guardrails();
    assert_eq!(found.len(), 3, "apply should have created three guardrails");

    live.assert_guardrail_listing_is_complete(&found);
    live.assert_exact_guardrail_get(&found);

    let alpha = live.guardrail_named(&format!("{run}-alpha", run = live.run));
    import_reports_the_remote_value(&live, &workspace, &alpha, &original);
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
    let workspace = Workspace::new();
    let sink = workspace.secrets.path().join("jobfeed.key");

    workspace.write_config(&key_config(&live.run, &sink, true));
    let applied = workspace.succeed(&["--json", "apply"]);
    assert_eq!(applied.document()["outcome"], "applied");

    let guardrail = live.adopt_one_guardrail();
    let created = live.adopt_new_keys();
    let [first] = created.as_slice() else {
        panic!("apply should have created exactly one key, not {created:?}");
    };

    live.assert_key_created_disabled_and_assigned(first, &guardrail);
    workspace.assert_delivered_secret_stayed_put(&sink, &live);

    // Enabling is an ordinary update, and it is what makes the rotation step
    // meaningful: a predecessor that was already disabled could not show that
    // rotation leaves it alone.
    workspace.write_config(&key_config(&live.run, &sink, false));
    let enabled = workspace.succeed(&["--json", "apply"]);
    assert_eq!(enabled.document()["outcome"], "applied");
    assert!(!live.key(first).disabled, "the key should now be enabled");

    let second = rotation_leaves_the_predecessor_alone(&live, &workspace, first);
    live.assert_key_listing_is_complete(&[first.clone(), second]);
    workspace.assert_delivered_secret_stayed_put(&sink, &live);

    retire_then_delete(&live, &workspace, first);
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
    workspace: &Workspace,
    guardrail: &Uuid,
    original: &str,
) {
    workspace.succeed(&["--json", "state", "forget", "guardrails.alpha"]);

    let edited = format!("{run} edited description", run = live.run);
    workspace.write_config(&guardrail_config(&live.run, &edited));

    let imported = workspace.succeed(&[
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

    let converged = workspace.succeed(&["--json", "apply"]);
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
    workspace: &Workspace,
    predecessor: &KeyHash,
) -> KeyHash {
    let rotated = workspace.succeed(&["--json", "rotate", "jobfeed"]);
    let successors = live.adopt_new_keys();
    let [successor] = successors.as_slice() else {
        panic!("rotate should have created exactly one key, not {successors:?}");
    };
    assert_ne!(successor, predecessor);
    assert!(
        !live.key(predecessor).disabled,
        "rotation must not disable the predecessor"
    );

    let status = workspace.succeed(&["--json", "status"]);
    assert!(
        status.out.contains(predecessor.as_str()),
        "the predecessor must stay tracked after rotation"
    );
    assert!(rotated.out.contains(successor.as_str()));
    successor.clone()
}

/// Retires the predecessor, then deletes it and proves the 404.
fn retire_then_delete(live: &Live, workspace: &Workspace, predecessor: &KeyHash) {
    workspace.succeed(&[
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

    workspace.succeed(&["--json", "delete", "key", "--hash", predecessor.as_str()]);
    assert_eq!(
        live.status_of(predecessor),
        Some(404),
        "a deleted key must be gone, not merely reported gone"
    );
    live.forget_key(predecessor);
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
            .filter(|record| record["kind"] == "key-deleted")
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

    fn key(&self, hash: &KeyHash) -> openrouter_keymaster::api::ObservedKey {
        self.reader().get_key(hash).expect("reading a key by hash")
    }

    fn guardrail(&self, id: &Uuid) -> openrouter_keymaster::api::ObservedGuardrail {
        self.reader()
            .get_guardrail(id)
            .expect("reading a guardrail by UUID")
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
            key.limit.map(openrouter_keymaster::config::Usd::micros),
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
    /// Keys still out there. Each one fails the run.
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
        let mut failures = Vec::new();
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
        let guardrails = self.report_guardrails();
        failures.extend(guardrails.failures);
        Swept {
            failures,
            notices: guardrails.notices,
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
        let notices = named
            .into_iter()
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

// ----------------------------------------------------------------- workspace

/// A throwaway project directory and the runs made in it.
///
/// Two directories, not one. The project directory holds the configuration and
/// the state file and is scanned for the delivered plaintext; the receiver
/// writes into the other one, because what it writes is a live credential and
/// finding it in the scanned tree is supposed to be a failure.
struct Workspace {
    directory: TempDir,
    secrets: TempDir,
    transcript: RefCell<Vec<String>>,
}

impl Workspace {
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
            .arg(self.directory.path().join("state.json"))
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

/// Three guardrails, so a one-record page size has something to page through.
fn guardrail_config(run: &str, description: &str) -> String {
    let mut config = String::from("version = 1\n");
    for name in ["alpha", "beta", "gamma"] {
        config.push_str(&format!(
            "\n[guardrails.{name}]\nname = \"{run}-{name}\"\ndescription = \"{description}\"\n\
             limit_usd = 0\nreset_interval = \"daily\"\n"
        ));
    }
    config
}

/// One guardrail, one zero-budget key, and a file receiver.
///
/// The limit is zero on purpose: a key this suite loses track of has to be one
/// that cannot spend anything. `disabled` is the field the create cannot set,
/// so it is what proves the update-only policy ran.
fn key_config(run: &str, sink: &Path, disabled: bool) -> String {
    format!(
        "version = 1\n\
         \n[guardrails.cap]\n\
         name = \"{run}-cap\"\n\
         limit_usd = 0\n\
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
fn journal_directory() -> PathBuf {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
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
