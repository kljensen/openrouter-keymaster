//! Opt-in, exact-identity live acceptance test for Token Fund issue #12.
//!
//! This file intentionally does not use `live.rs`: its crash-recovery sweep is
//! appropriate only for an empty test organization.  The issue #12 probe owns
//! only immutable identities it has durably recorded and never discovers
//! resources by listing or by a name prefix.

mod support;

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use openrouter_keymaster::app::env;
use openrouter_keymaster_core::api::{
    BudgetBody, GuardrailBody, Reader, ResetPolicy, UpdateKey, WorkspaceBody, Writer,
};
use openrouter_keymaster_core::client::{Client, CreateKeyRequest, CreatedKey};
use openrouter_keymaster_core::config::{BudgetInterval, Config, Key};
use openrouter_keymaster_core::ids::Address;
use openrouter_keymaster_core::ids::{KeyHash, Uuid};
use openrouter_keymaster_core::ops::PRODUCTION_BASE_URL;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroizing;

const OPT_IN_VAR: &str = "KEYMASTER_ISSUE12_LIVE";
const RECOVER_VAR: &str = "KEYMASTER_ISSUE12_RECOVER";
const JOURNAL_DIR: &str = "target/issue12-live-runs";
const RUN_PREFIX: &str = "tf-i12";

/// Immutable, non-secret identities the probe is authorized to delete.
///
/// There is deliberately no resource name here.  Names make an incident
/// searchable for a human, but are not authority for a destructive request.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owned {
    keys: BTreeSet<KeyHash>,
    guardrails: BTreeSet<Uuid>,
    workspace: Option<Uuid>,
}

impl Owned {
    fn empty(&self) -> bool {
        self.keys.is_empty() && self.guardrails.is_empty() && self.workspace.is_none()
    }

    fn cleanup_plan(&self) -> Vec<CleanupStep> {
        self.keys
            .iter()
            .cloned()
            .map(CleanupStep::Key)
            .chain(self.guardrails.iter().cloned().map(CleanupStep::Guardrail))
            .chain(self.workspace.iter().cloned().map(CleanupStep::Workspace))
            .collect()
    }
}

/// Destructive operations are planned from journaled immutable identities only.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CleanupStep {
    Key(KeyHash),
    Guardrail(Uuid),
    Workspace(Uuid),
}

/// One line of the append-only, non-secret journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalLine {
    run: String,
    base_url: String,
    event: Event,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Event {
    Started,
    Workspace { id: Uuid },
    Guardrail { id: Uuid },
    Key { hash: KeyHash },
    DeletedKey { hash: KeyHash },
    DeletedGuardrail { id: Uuid },
    DeletedWorkspace { id: Uuid },
}

impl Event {
    fn apply(&self, owned: &mut Owned) {
        match self {
            Self::Started => {}
            Self::Workspace { id } => owned.workspace = Some(id.clone()),
            Self::Guardrail { id } => {
                owned.guardrails.insert(id.clone());
            }
            Self::Key { hash } => {
                owned.keys.insert(hash.clone());
            }
            Self::DeletedKey { hash } => {
                owned.keys.remove(hash);
            }
            Self::DeletedGuardrail { id } => {
                owned.guardrails.remove(id);
            }
            Self::DeletedWorkspace { id } if owned.workspace.as_ref() == Some(id) => {
                owned.workspace = None;
            }
            Self::DeletedWorkspace { .. } => {}
        }
    }
}

struct Journal {
    path: PathBuf,
    run: String,
    base_url: String,
}

impl Journal {
    fn create(run: String, base_url: String) -> Self {
        let path = journal_path(&run);
        let journal = Self {
            path,
            run,
            base_url,
        };
        journal.append(Event::Started);
        journal
    }

    fn append(&self, event: Event) {
        let line = JournalLine {
            run: self.run.clone(),
            base_url: self.base_url.clone(),
            event,
        };
        let encoded = serde_json::to_string(&line).expect("a journal line serializes");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .unwrap_or_else(|error| panic!("opening {}: {error}", self.path.display()));
        file.write_all(encoded.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .unwrap_or_else(|error| panic!("writing {}: {error}", self.path.display()));
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("protecting {}: {error}", self.path.display()));
    }

    fn read(path: &Path) -> Result<(String, String, Owned), String> {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("reading {}: {error}", path.display()))?;
        let mut expected_run = None;
        let mut expected_base = None;
        let mut owned = Owned::default();
        for raw in text.lines() {
            let line: JournalLine = serde_json::from_str(raw)
                .map_err(|error| format!("parsing {}: {error}", path.display()))?;
            if let Some(run) = &expected_run {
                if run != &line.run {
                    return Err("journal mixes run identifiers".to_owned());
                }
            } else {
                expected_run = Some(line.run.clone());
            }
            if let Some(base) = &expected_base {
                if base != &line.base_url {
                    return Err("journal mixes API endpoints".to_owned());
                }
            } else {
                expected_base = Some(line.base_url.clone());
            }
            line.event.apply(&mut owned);
        }
        Ok((
            expected_run.ok_or_else(|| "journal is empty".to_owned())?,
            expected_base.ok_or_else(|| "journal is empty".to_owned())?,
            owned,
        ))
    }
}

fn journal_path(run: &str) -> PathBuf {
    let directory = Path::new(JOURNAL_DIR);
    fs::create_dir_all(directory).expect("creating issue #12 journal directory");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .expect("protecting issue #12 journal directory");
    directory.join(format!("{run}.jsonl"))
}

fn new_run() -> String {
    format!("{RUN_PREFIX}-{}", uuid::Uuid::new_v4())
}

/// The three explicit, non-secret inputs that make a real inference probe
/// reproducible.  A model pair is intentionally not baked into the suite: the
/// catalog changes and a stale pair would turn a model-policy test into a
/// false success or an unrelated 404.
struct Settings {
    allowed_model: String,
    denied_model: String,
}

impl Settings {
    fn from_env() -> Result<Self, String> {
        let allowed_model = required("KEYMASTER_ISSUE12_ALLOWED_MODEL")?;
        let denied_model = required("KEYMASTER_ISSUE12_DENIED_MODEL")?;
        if allowed_model == denied_model {
            return Err("the allowed and denied models must differ".to_owned());
        }
        Ok(Self {
            allowed_model,
            denied_model,
        })
    }
}

fn required(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("set {name} to a current text-capable OpenRouter model slug"))
}

/// An inference request's status only.  Bodies are drained and discarded so a
/// surprising response cannot put a credential in a test failure or journal.
struct Probe {
    client: reqwest::blocking::Client,
    endpoint: String,
}

impl Probe {
    fn new(base_url: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("building the bounded inference probe client");
        Self {
            client,
            endpoint: format!("{base_url}/chat/completions"),
        }
    }

    fn request(&self, secret: &str, model: &str, max_tokens: u16) -> Result<u16, String> {
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(secret)
            .json(&serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
                "max_tokens": max_tokens,
                "temperature": 0,
            }))
            .send()
            .map_err(|error| format!("inference request failed: {error}"))?;
        let status = response.status().as_u16();
        // Drain without formatting.  Error bodies are an untrusted remote
        // surface and may contain text Keymaster must never print.
        let _discarded = Zeroizing::new(response.bytes().unwrap_or_default().to_vec());
        Ok(status)
    }
}

fn authorization_rejection(status: u16) -> bool {
    matches!(status, 401 | 403)
}

/// A live run with deletion authority limited to the identities in its own
/// journal.  It never calls a listing endpoint.
struct Run {
    client: Client,
    journal: Journal,
    owned: Owned,
}

impl Run {
    fn new(client: Client) -> Self {
        let journal = Journal::create(new_run(), client.base_url().to_owned());
        Self {
            client,
            journal,
            owned: Owned::default(),
        }
    }

    fn writer(&self) -> Writer<'_> {
        Writer::new(&self.client)
    }
    fn reader(&self) -> Reader<'_> {
        Reader::new(&self.client)
    }

    fn record_workspace(&mut self, id: Uuid) {
        self.journal.append(Event::Workspace { id: id.clone() });
        self.owned.workspace = Some(id);
    }

    fn record_guardrail(&mut self, id: Uuid) {
        self.journal.append(Event::Guardrail { id: id.clone() });
        self.owned.guardrails.insert(id);
    }

    fn record_key(&mut self, hash: KeyHash) {
        self.journal.append(Event::Key { hash: hash.clone() });
        self.owned.keys.insert(hash);
    }

    fn cleanup(&mut self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for hash in self.owned.keys.clone() {
            if let Err(error) = self.writer().disable_key(&hash)
                && error.status() != Some(404)
            {
                errors.push(format!("disable key {hash}: {}", error.kind()));
                continue;
            }
            if let Err(error) = self.writer().delete_key(&hash)
                && error.status() != Some(404)
            {
                errors.push(format!("delete key {hash}: {}", error.kind()));
                continue;
            }
            match self.reader().get_key(&hash) {
                Err(error) if error.status() == Some(404) => {
                    self.journal
                        .append(Event::DeletedKey { hash: hash.clone() });
                    self.owned.keys.remove(&hash);
                }
                Ok(_) => errors.push(format!("key {hash} still exists after delete")),
                Err(error) => errors.push(format!("verify key {hash}: {}", error.kind())),
            }
        }
        for id in self.owned.guardrails.clone() {
            if let Err(error) = self.writer().delete_guardrail_for_tests(&id)
                && error.status() != Some(404)
            {
                errors.push(format!("delete guardrail {id}: {}", error.kind()));
                continue;
            }
            match self.reader().get_guardrail(&id) {
                Err(error) if error.status() == Some(404) => {
                    self.journal
                        .append(Event::DeletedGuardrail { id: id.clone() });
                    self.owned.guardrails.remove(&id);
                }
                Ok(_) => errors.push(format!("guardrail {id} still exists after delete")),
                Err(error) => errors.push(format!("verify guardrail {id}: {}", error.kind())),
            }
        }
        if let Some(id) = self.owned.workspace.clone() {
            if let Err(error) = self.writer().delete_workspace(&id)
                && error.status() != Some(404)
            {
                errors.push(format!("delete workspace {id}: {}", error.kind()));
            } else {
                match self.reader().get_workspace(&id) {
                    Err(error) if error.status() == Some(404) => {
                        self.journal
                            .append(Event::DeletedWorkspace { id: id.clone() });
                        self.owned.workspace = None;
                    }
                    Ok(_) => errors.push(format!("workspace {id} still exists after delete")),
                    Err(error) => errors.push(format!("verify workspace {id}: {}", error.kind())),
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn cleanup_or_panic(&mut self) {
        if let Err(errors) = self.cleanup() {
            panic!("issue #12 exact-ID cleanup failed: {}", errors.join("; "));
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if self.owned.empty() {
            return;
        }
        if let Err(errors) = self.cleanup() {
            for error in errors {
                eprintln!("issue #12 exact-ID cleanup failed: {error}");
            }
        }
    }
}

struct IssuedKey {
    hash: KeyHash,
    created: CreatedKey,
}

impl IssuedKey {
    fn secret(&self) -> &str {
        self.created.plaintext().expose()
    }
}

fn config(source: &str) -> Config {
    Config::parse(source).expect("valid test configuration")
}

fn address(value: &str) -> Address {
    Address::parse(value).expect("test address")
}

fn workspace_config(run: &str, lifetime: &str) -> Config {
    config(&format!(
        "version = 1\n[workspaces.fund]\nname = \"{run}-workspace\"\nslug = \"{run}\"\n\
         budgets = {{ lifetime = {lifetime} }}\ninclude_byok_in_budgets = false\n"
    ))
}

fn guardrail_config(run: &str, allowed_model: &str) -> Config {
    let allowed_model =
        serde_json::to_string(allowed_model).expect("model slug encodes as TOML string");
    config(&format!(
        "version = 1\n[guardrails.policy]\nname = \"{run}-policy\"\n\
         allowed_models = [{allowed_model}]\nlimit_usd = 0.25\nreset_interval = \"daily\"\n\
         include_byok_in_limit = false\n"
    ))
}

fn key_config(run: &str, name: &str, limit: &str, disabled: bool) -> Config {
    config(&format!(
        "version = 1\n[keys.key]\nname = \"{run}-{name}\"\nlimit_usd = {limit}\n\
         disabled = {disabled}\ninclude_byok_in_limit = false\n"
    ))
}

fn monthly_zero_key_config(run: &str, name: &str, disabled: bool) -> Config {
    config(&format!(
        "version = 1\n[keys.key]\nname = \"{run}-{name}\"\nlimit_usd = 0\n\
         limit_reset = \"monthly\"\ndisabled = {disabled}\ninclude_byok_in_limit = false\n"
    ))
}

fn one_key(config: &Config) -> &Key {
    config.keys.get(&address("key")).expect("key config")
}

fn create_key(
    run: &mut Run,
    desired: &Key,
    workspace: &Uuid,
    guardrail: &Uuid,
    expiry: Option<OffsetDateTime>,
) -> IssuedKey {
    let request = CreateKeyRequest {
        name: desired.name.clone(),
        limit: Some(0.0),
        limit_reset: None,
        include_byok_in_limit: false,
        expires_at: expiry,
        workspace_id: Some(workspace.clone()),
        creator_user_id: None,
    };
    let created = run
        .client
        .create_key_once(&request)
        .expect("creating exact-ID zero-limit key");
    let hash = created.hash().clone();
    run.record_key(hash.clone());
    let secured = zero_key_state(desired, true);
    run.writer()
        .update_key(&hash, &UpdateKey::new(one_key(&secured)))
        .expect("disabling zero-limit key");
    run.writer()
        .assign_key(guardrail, &hash)
        .expect("assigning exact guardrail");
    let observed = run.reader().get_key(&hash).expect("reading exact key");
    assert!(observed.disabled && observed.limit.is_some_and(|limit| limit.micros() == 0));
    assert!(
        run.reader()
            .list_assignments_of(guardrail)
            .expect("reading exact guardrail assignment")
            .iter()
            .any(|assignment| assignment.key_hash == hash)
    );
    IssuedKey { hash, created }
}

fn zero_key_state(key: &Key, disabled: bool) -> Config {
    let reset = key.limit_reset.value().map_or(String::new(), |interval| {
        format!("limit_reset = \"{}\"\n", interval.as_str())
    });
    config(&format!(
        "version = 1\n[keys.key]\nname = \"{}\"\nlimit_usd = 0\ndisabled = {disabled}\n\
         include_byok_in_limit = false\n{reset}",
        key.name.as_str(),
    ))
}

fn enable_zero(run: &Run, key: &IssuedKey, desired: &Key) {
    let desired = zero_key_state(desired, false);
    run.writer()
        .update_key(&key.hash, &UpdateKey::new(one_key(&desired)))
        .expect("enabling exact zero-limit key");
}

fn raise_and_enable(run: &Run, key: &IssuedKey, limit: &str) {
    let desired = config(&format!(
        "version = 1\n[keys.key]\nname = \"{}\"\nlimit_usd = {limit}\ndisabled = false\n\
         include_byok_in_limit = false\n",
        run.reader()
            .get_key(&key.hash)
            .expect("read exact key name")
            .name
    ));
    run.writer()
        .update_key(&key.hash, &UpdateKey::new(one_key(&desired)))
        .expect("raising exact key cap after policy attachment");
    let observed = run.reader().get_key(&key.hash).expect("reading raised key");
    assert!(
        !observed.disabled
            && observed
                .limit
                .is_some_and(|observed_limit| observed_limit.dollars()
                    == limit.parse::<f64>().expect("configured key cap"))
    );
}

fn settled_workspace_usage(run: &Run, keys: &[&IssuedKey]) -> f64 {
    for _ in 0..60 {
        let usage: f64 = keys
            .iter()
            .map(|key| {
                run.reader()
                    .get_key(&key.hash)
                    .expect("reading exact created key")
                    .usage
                    .total
            })
            .sum();
        if usage > 0.0 {
            return usage;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("exact created-key usage did not settle to a nonzero value within 30 seconds");
}

fn narrow_workspace_lifetime(run: &Run, workspace: &Uuid, usage: f64) -> f64 {
    const INCREMENT: f64 = 0.000_001;
    let target = usage + INCREMENT;
    assert!(
        target < 0.50,
        "settled usage left no safe room to narrow the test workspace"
    );
    let desired = workspace_config(&run.journal.run, &format!("{target:.6}"));
    let limit = desired.workspaces[&address("fund")]
        .budgets
        .as_ref()
        .and_then(|budgets| budgets.get(&BudgetInterval::Lifetime))
        .copied()
        .expect("narrowed lifetime budget");
    run.writer()
        .put_workspace_budget(
            workspace,
            BudgetInterval::Lifetime,
            &BudgetBody::new(limit, Some(false)),
        )
        .expect("narrowing exact workspace lifetime budget");
    assert_eq!(
        run.reader()
            .get_workspace(workspace)
            .expect("reading narrowed workspace")
            .budgets
            .get(&BudgetInterval::Lifetime)
            .copied(),
        Some(limit)
    );
    target
}

#[test]
fn journal_round_trip_owns_only_returned_immutable_ids() {
    let directory = TempDir::new().expect("temporary directory");
    let path = directory.path().join("run.jsonl");
    let lines = [
        r#"{"run":"tf-i12-a","base_url":"https://openrouter.ai/api/v1","event":{"kind":"started"}}"#,
        r#"{"run":"tf-i12-a","base_url":"https://openrouter.ai/api/v1","event":{"kind":"workspace","id":"00000000-0000-4000-8000-000000000001"}}"#,
        r#"{"run":"tf-i12-a","base_url":"https://openrouter.ai/api/v1","event":{"kind":"guardrail","id":"00000000-0000-4000-8000-000000000002"}}"#,
        r#"{"run":"tf-i12-a","base_url":"https://openrouter.ai/api/v1","event":{"kind":"key","hash":"hash-one"}}"#,
        r#"{"run":"tf-i12-a","base_url":"https://openrouter.ai/api/v1","event":{"kind":"deleted_key","hash":"hash-one"}}"#,
    ];
    fs::write(&path, lines.join("\n")).expect("journal fixture");
    let (run, base, owned) = Journal::read(&path).expect("valid journal");
    assert_eq!(run, "tf-i12-a");
    assert_eq!(base, "https://openrouter.ai/api/v1");
    assert!(owned.keys.is_empty());
    assert_eq!(owned.guardrails.len(), 1);
    assert!(owned.workspace.is_some());
}

#[test]
fn journal_refuses_mixed_endpoints() {
    let directory = TempDir::new().expect("temporary directory");
    let path = directory.path().join("run.jsonl");
    fs::write(&path, concat!(
        r#"{"run":"tf-i12-a","base_url":"https://openrouter.ai/api/v1","event":{"kind":"started"}}"#, "\n",
        r#"{"run":"tf-i12-a","base_url":"https://other.example/api/v1","event":{"kind":"started"}}"#,
    )).expect("journal fixture");
    assert!(Journal::read(&path).is_err());
}

#[test]
fn journal_has_no_secret_field_or_name_based_authority() {
    let value = serde_json::to_value(JournalLine {
        run: "tf-i12-a".to_owned(),
        base_url: "https://openrouter.ai/api/v1".to_owned(),
        event: Event::Key {
            hash: KeyHash::parse("hash-one").expect("valid hash"),
        },
    })
    .expect("journal serializes");
    let rendered = value.to_string();
    assert!(!rendered.contains("\"plaintext\""));
    assert!(!rendered.contains("\"secret\""));
    assert!(!rendered.contains("name"));
    assert!(!rendered.contains("sk-or-"));
}

#[test]
fn cleanup_plan_is_exact_id_only_and_dependency_ordered() {
    let mut owned = Owned::default();
    let first = KeyHash::parse("hash-one").expect("valid hash");
    let second = KeyHash::parse("hash-two").expect("valid hash");
    let guardrail = Uuid::parse("00000000-0000-4000-8000-000000000002").expect("valid UUID");
    let workspace = Uuid::parse("00000000-0000-4000-8000-000000000001").expect("valid UUID");
    owned.keys.extend([first.clone(), second.clone()]);
    owned.guardrails.insert(guardrail.clone());
    owned.workspace = Some(workspace.clone());
    assert_eq!(
        owned.cleanup_plan(),
        vec![
            CleanupStep::Key(first),
            CleanupStep::Key(second),
            CleanupStep::Guardrail(guardrail),
            CleanupStep::Workspace(workspace),
        ]
    );
}

#[test]
fn zero_state_toggle_preserves_name_and_monthly_reset() {
    let desired = monthly_zero_key_config("tf-i12-test", "monthly-zero", true);
    let enabled = zero_key_state(one_key(&desired), false);
    let key = one_key(&enabled);
    assert_eq!(key.name, one_key(&desired).name);
    assert!(!key.disabled);
    assert!(matches!(
        key.limit_reset,
        openrouter_keymaster_core::config::Managed::Set(
            openrouter_keymaster_core::config::ResetInterval::Monthly
        )
    ));
}

#[test]
#[ignore = "live: set KEYMASTER_ISSUE12_LIVE=1; see docs/issue12-live-test.md"]
#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "one ordered live protocol is clearer and safer as one scenario"
)]
fn live_issue12_controls() {
    if !std::env::var(OPT_IN_VAR).is_ok_and(|value| value == "1") {
        eprintln!("skipping issue #12 live test: set {OPT_IN_VAR}=1");
        return;
    }
    let settings = Settings::from_env().expect("explicit current model pair");
    let client = Client::new(
        env::options().expect("valid OpenRouter endpoint"),
        &env::management_key().expect("usable management credential"),
    )
    .expect("bounded management client");
    assert_eq!(
        client.base_url(),
        PRODUCTION_BASE_URL,
        "issue #12 live testing requires the exact production OpenRouter API endpoint"
    );
    let probe = Probe::new(client.base_url());
    let mut run = Run::new(client);

    // No listing call occurs before or after this.  Every destructive request
    // below receives an ID returned by the preceding create and journaled
    // synchronously before the resource is used.
    let workspace_desired = workspace_config(&run.journal.run, "0.50");
    let workspace = run
        .writer()
        .create_workspace(&WorkspaceBody::create(
            workspace_desired
                .workspaces
                .get(&address("fund"))
                .expect("workspace config"),
        ))
        .expect("creating exact-ID test workspace");
    let workspace_id = workspace.id;
    run.record_workspace(workspace_id.clone());
    let lifetime = workspace_desired.workspaces[&address("fund")]
        .budgets
        .as_ref()
        .and_then(|budgets| budgets.get(&BudgetInterval::Lifetime))
        .copied()
        .expect("lifetime budget config");
    run.writer()
        .put_workspace_budget(
            &workspace_id,
            BudgetInterval::Lifetime,
            &BudgetBody::new(lifetime, Some(false)),
        )
        .expect("workspace budget entitlement: a 403 is an issue #12 failure");
    assert_eq!(
        run.reader()
            .get_workspace(&workspace_id)
            .expect("read exact workspace")
            .budgets
            .get(&BudgetInterval::Lifetime)
            .copied(),
        Some(lifetime)
    );

    let policy_desired = guardrail_config(&run.journal.run, &settings.allowed_model);
    let policy = run
        .writer()
        .create_guardrail(&GuardrailBody::create(
            policy_desired
                .guardrails
                .get(&address("policy"))
                .expect("guardrail config"),
            Some(&workspace_id),
        ))
        .expect("creating exact-ID model guardrail");
    let policy_id = policy.id;
    run.record_guardrail(policy_id.clone());
    assert_eq!(
        run.reader()
            .get_guardrail(&policy_id)
            .expect("read exact guardrail")
            .workspace_id
            .as_ref(),
        Some(&workspace_id)
    );

    // A zero-limit enabled key must reject before an inference request can
    // spend.  Disabled would test the wrong gate, so it is enabled only after
    // the zero limit and assignment are read back.
    let zero_desired = key_config(&run.journal.run, "zero", "0", false);
    let zero = create_key(
        &mut run,
        one_key(&zero_desired),
        &workspace_id,
        &policy_id,
        Some(OffsetDateTime::now_utc() + TimeDuration::minutes(10)),
    );
    enable_zero(&run, &zero, one_key(&zero_desired));
    assert!(
        probe
            .request(zero.secret(), &settings.allowed_model, 1)
            .map(authorization_rejection)
            .expect("zero-limit probe"),
        "an enabled zero-limit key accepted inference"
    );

    // Expiry is immutable at create.  The non-zero cap prevents the zero-limit
    // result from masking expiry, but this request occurs only after expiry and
    // therefore must not spend.
    let expiry_desired = key_config(&run.journal.run, "expiry", "0", true);
    let expiry_at = OffsetDateTime::now_utc() + TimeDuration::seconds(30);
    let expiry = create_key(
        &mut run,
        one_key(&expiry_desired),
        &workspace_id,
        &policy_id,
        Some(expiry_at),
    );
    raise_and_enable(&run, &expiry, "0.10");
    assert!(
        probe
            .request(expiry.secret(), &settings.allowed_model, 1)
            .expect("pre-expiry probe")
            < 300,
        "the same key did not work before its explicit expiry"
    );
    let remaining = expiry_at - OffsetDateTime::now_utc() + TimeDuration::seconds(1);
    if remaining.is_positive() {
        std::thread::sleep(Duration::from_millis(
            remaining.whole_milliseconds().unsigned_abs() as u64,
        ));
    }
    assert!(
        probe
            .request(expiry.secret(), &settings.allowed_model, 1)
            .map(authorization_rejection)
            .expect("expired-key probe"),
        "an expired key accepted inference"
    );

    // The denied model is supplied afresh by the operator.  It must be a
    // catalog-valid text model distinct from `allowed`; rejection therefore
    // exercises the assigned guardrail rather than model lookup.
    let recurring_desired = monthly_zero_key_config(&run.journal.run, "monthly-zero", false);
    let recurring = create_key(
        &mut run,
        one_key(&recurring_desired),
        &workspace_id,
        &policy_id,
        Some(OffsetDateTime::now_utc() + TimeDuration::minutes(10)),
    );
    enable_zero(&run, &recurring, one_key(&recurring_desired));
    assert!(matches!(
        run.reader()
            .get_key(&recurring.hash)
            .expect("reading recurring zero-limit key")
            .limit_reset,
        ResetPolicy::Every(openrouter_keymaster_core::config::ResetInterval::Monthly)
    ));
    assert!(
        probe
            .request(recurring.secret(), &settings.allowed_model, 1)
            .map(authorization_rejection)
            .expect("monthly zero-limit probe"),
        "a zero-limit monthly-reset key accepted inference"
    );

    let model_desired = key_config(&run.journal.run, "model", "0", true);
    let model = create_key(
        &mut run,
        one_key(&model_desired),
        &workspace_id,
        &policy_id,
        Some(OffsetDateTime::now_utc() + TimeDuration::minutes(10)),
    );
    raise_and_enable(&run, &model, "0.10");
    assert!(
        probe
            .request(model.secret(), &settings.denied_model, 1)
            .expect("denied-model probe")
            == 403,
        "the assigned model guardrail accepted its denied model"
    );

    // A successful allowed-model request establishes a live credential before
    // timing disable propagation.  At most six sequential one-token requests
    // can occur after the management write; the key and workspace caps remain
    // the last-resort financial bounds.
    assert!(
        probe
            .request(model.secret(), &settings.allowed_model, 1)
            .expect("allowed-model probe")
            < 300,
        "the allowed model did not accept one bounded request"
    );
    run.writer()
        .disable_key(&model.hash)
        .expect("disable exact key");
    assert!(
        run.reader()
            .get_key(&model.hash)
            .expect("read disabled key")
            .disabled
    );
    let narrowed_at = std::time::Instant::now();
    let mut rejected_after = None;
    for _ in 0..6 {
        if authorization_rejection(
            probe
                .request(model.secret(), &settings.allowed_model, 1)
                .expect("disable-latency probe"),
        ) {
            rejected_after = Some(narrowed_at.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(
        rejected_after.is_some(),
        "disable did not reach an inference edge within 3 seconds"
    );
    eprintln!(
        "issue #12 observed disable latency: {} ms",
        rejected_after.expect("checked").as_millis()
    );

    // The management API reports exact per-key usage.  Sum only this run's
    // exact IDs, then narrow the workspace to that settled amount plus one
    // millionth of a dollar. This proves a runtime narrowing rather than
    // hoping a static cap
    // happens to be reached by a one-token request.
    let settled_usage = settled_workspace_usage(&run, &[&expiry, &model]);
    let narrowed_limit = narrow_workspace_lifetime(&run, &workspace_id, settled_usage);
    let narrowed_at = std::time::Instant::now();

    // These keys are created after the narrower workspace limit is read back.
    // The earlier success proves the model/key path worked before narrowing;
    // a 403 here proves the parent workspace now rejects a freshly created,
    // read-back-enabled child. We deliberately do not require the provider to
    // allow an overage before it starts rejecting. Each cap is $0.25, and
    // probes are strictly sequential; the aggregate worst-case configured
    // exposure, including the earlier $0.10 keys, stays below a few dollars
    // even though OpenRouter's in-flight overage is not numerically bounded.
    let aggregate_one_desired = key_config(&run.journal.run, "aggregate-one", "0", true);
    let aggregate_one = create_key(
        &mut run,
        one_key(&aggregate_one_desired),
        &workspace_id,
        &policy_id,
        Some(OffsetDateTime::now_utc() + TimeDuration::minutes(10)),
    );
    let aggregate_two_desired = key_config(&run.journal.run, "aggregate-two", "0", true);
    let aggregate_two = create_key(
        &mut run,
        one_key(&aggregate_two_desired),
        &workspace_id,
        &policy_id,
        Some(OffsetDateTime::now_utc() + TimeDuration::minutes(10)),
    );
    raise_and_enable(&run, &aggregate_one, "0.25");
    raise_and_enable(&run, &aggregate_two, "0.25");
    let mut rejected = false;
    for key in [
        &aggregate_one,
        &aggregate_two,
        &aggregate_one,
        &aggregate_two,
        &aggregate_one,
        &aggregate_two,
        &aggregate_one,
        &aggregate_two,
    ] {
        let status = probe
            .request(key.secret(), &settings.allowed_model, 256)
            .expect("aggregate-budget probe");
        rejected |= status == 403;
        if rejected {
            break;
        }
    }
    assert!(
        rejected,
        "the narrowed workspace budget did not reject a freshly created key"
    );
    eprintln!(
        "issue #12 observed workspace-budget narrowing latency at ${narrowed_limit:.6}: {} ms",
        narrowed_at.elapsed().as_millis()
    );
    run.cleanup_or_panic();
}

#[test]
#[ignore = "live recovery: set KEYMASTER_ISSUE12_RECOVER to a journal path"]
fn live_issue12_recover_exact_journal() {
    let Ok(path) = std::env::var(RECOVER_VAR) else {
        return;
    };
    assert!(
        std::env::var(OPT_IN_VAR).is_ok_and(|value| value == "1"),
        "set {OPT_IN_VAR}=1 as well as {RECOVER_VAR}; recovery deletes exact IDs"
    );
    let (recorded_run, base_url, owned) =
        Journal::read(Path::new(&path)).expect("valid exact-ID journal");
    assert!(
        !owned.empty(),
        "journal has no remaining identities to recover"
    );
    let client = Client::new(
        env::options().expect("valid OpenRouter endpoint"),
        &env::management_key().expect("usable management credential"),
    )
    .expect("bounded management client");
    assert_eq!(
        client.base_url(),
        base_url,
        "refusing recovery against a different API endpoint"
    );
    let journal = Journal {
        path: PathBuf::from(path),
        run: recorded_run,
        base_url,
    };
    let mut run = Run {
        client,
        journal,
        owned,
    };
    run.cleanup_or_panic();
}
