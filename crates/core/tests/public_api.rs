//! The curated public API, exercised the way a host would.
//!
//! This is the only test binary that does *not* turn on `test-support`, and
//! that is the whole point of it. Under the feature the internal modules —
//! `client`, `api`, `plan`, `receiver`, `redaction` — are `pub` so both test
//! suites can drive them; here they do not exist, so anything this file needs
//! has to come from the surface ADR-0003 decided a host may rely on. If a
//! future change moves something a caller needs out of that surface, this test
//! stops compiling.
//!
//! It therefore brings its own server rather than the shared harness: thirty
//! lines of `TcpListener` answering every listing with an empty page, which is
//! all a plan against an empty organization reads.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;

use openrouter_keymaster_core::config::{Config, Receiver};
use openrouter_keymaster_core::ids::Address;
use openrouter_keymaster_core::ops::{
    self, Acknowledgement, Context, DeliveryMetadata, DeliveryOutcome, KeyPlaintext, ManagementKey,
    Options, Paths,
};
/// The host callback type, spelled out here because core does not export an alias for it.
type Deliver = Box<dyn FnMut(&DeliveryMetadata, &KeyPlaintext) -> DeliveryOutcome + Send>;

use openrouter_keymaster_core::state::{self, StateFile};
use tempfile::TempDir;
use zeroize::Zeroizing;

/// A configuration a host would hand to `ops`: one guardrail, one key, one
/// receiver.
const CONFIG: &str = r#"
version = 1

[receivers.vault]
type = "file"
path = "/var/lib/keymaster/vault.key"

[receivers.host]
type = "caller"
destination = "vault/jobfeed"

[guardrails.cheap]
name = "cheap-rail"

[keys.jobfeed]
name = "golf-jobfeed"
receiver = "vault"
"#;

/// A credential shaped like a real one and belonging to nobody.
const FAKE_KEY: &str = "sk-or-v1-PUBLIC-API-TEST-NEVER-A-REAL-CREDENTIAL";

/// Answers every request with an empty collection page, forever.
///
/// An empty page is what ends pagination, so each of the three listings a plan
/// reads finishes on its first request.
fn empty_openrouter() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local port");
    let base_url = format!(
        "http://{}/api/v1",
        listener.local_addr().expect("an address")
    );

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            thread::spawn(move || answer_requests(stream));
        }
    });

    base_url
}

/// Serves every request on one keep-alive connection until it closes.
fn answer_requests(mut stream: TcpStream) {
    const BODY: &str = r#"{"data":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{BODY}",
        BODY.len()
    );

    let mut pending = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => pending.extend_from_slice(&chunk[..read]),
        }
        // A request with no body ends at the blank line; a client that
        // pipelines would send several, so answer one per terminator seen.
        while let Some(end) = find_blank_line(&pending) {
            pending.drain(..end);
            if stream.write_all(response.as_bytes()).is_err() {
                return;
            }
        }
    }
}

/// Where the first request in `buffer` ends, if one has arrived whole.
fn find_blank_line(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start + 4)
}

/// Everything a host holds: the two paths, the endpoint, the credential, and
/// the optional workspace scope.
fn context(directory: &Path, base_url: String) -> Context {
    Context {
        paths: Paths {
            config: directory.join("keymaster.toml"),
            state: directory.join("state.json"),
        },
        options: Options::new(base_url),
        key: Some(
            ManagementKey::from_secret(Zeroizing::new(FAKE_KEY.to_owned()))
                .expect("a well-formed credential"),
        ),
        workspace: None,
        deliver: Some(host_callback()),
    }
}

/// The callback a `caller` receiver delivers through (ADR-0005).
///
/// A host writes exactly this: a closure that reads the non-secret metadata,
/// takes the plaintext through its one accessor, and answers with what its own
/// storage proved. Every type it names has to be reachable from the curated
/// surface, which is what this file is for.
fn host_callback() -> Deliver {
    Box::new(
        |metadata: &DeliveryMetadata, plaintext: &KeyPlaintext| -> DeliveryOutcome {
            if plaintext.expose().is_empty() {
                return DeliveryOutcome::rejected("the host was handed nothing to store");
            }
            DeliveryOutcome::delivered(format!(
                "the host stored {address} generation {generation} (operation {operation}) at \
                 {destination}",
                address = metadata.address(),
                generation = metadata.generation(),
                operation = metadata.operation(),
                destination = metadata.destination().unwrap_or("nowhere"),
            ))
        },
    )
}

#[test]
fn a_host_can_plan_and_read_configuration_and_state() {
    let directory = TempDir::new().expect("a temporary directory");
    let paths = directory.path();
    let config_path = paths.join("keymaster.toml");
    std::fs::write(&config_path, CONFIG).expect("writing the configuration");

    // Configuration, as a host reads it: the desired state, typed.
    let config = Config::load(&config_path).expect("a valid configuration");
    let jobfeed = Address::parse("jobfeed").expect("a valid address");
    let vault = Address::parse("vault").expect("a valid address");
    assert!(config.keys.contains_key(&jobfeed));
    assert!(matches!(
        config.receivers.get(&vault),
        Some(Receiver::File { .. })
    ));
    let host = Address::parse("host").expect("a valid address");
    assert!(
        matches!(
            config.receivers.get(&host),
            Some(Receiver::Caller { destination }) if destination == "vault/jobfeed"
        ),
        "a host reads the destination its own callback routes on"
    );

    // The classification a callback answers with: the other half of the
    // delivery surface ADR-0005 makes public.
    assert_eq!(
        DeliveryOutcome::delivered("stored").acknowledgement(),
        Acknowledgement::Delivered
    );

    // State, as a host reads it: no lock, no write, nothing to promote.
    let state = StateFile::new(paths.join("state.json"))
        .read()
        .expect("an absent state file reads as an empty one");
    assert_eq!(state.version(), state::SCHEMA_VERSION);
    assert!(state.keys().is_empty());
    assert!(state.pending_operation().is_none());

    // And the operation itself, through `ops`.
    let outcome = ops::plan(context(paths, empty_openrouter())).expect("a plan is readable");
    assert!(
        outcome.error.is_none(),
        "planning reported {:?}",
        outcome.error
    );
    assert!(
        outcome.report.has_changes(),
        "an empty organization needs both resources created"
    );
    assert!(
        outcome.report.fingerprint().is_some(),
        "a plan computed with no operation pending is bindable, so a host can \
         hand it back to `ops::apply`"
    );
}
