//! Facts about how the crate is built, asserted like any other behaviour.
//!
//! These are guarantees no other test can reach. `clippy.toml` is the only thing
//! standing between the codebase and an HTTP client with no timeout, no
//! redirect policy, and no `Authorization` header. And the transport's own
//! retry policy only shows itself over HTTP/2, which the local harness does not
//! speak — so the line that disables it is checked where it is written. The
//! last two belong to ADR-0003: a library consumer gets no argument parser, and
//! the modules behind `ops` stay behind it.

use std::fs;
use std::process::Command;

#[test]
fn unbounded_http_clients_are_refused_by_the_lint_configuration() {
    let configuration = fs::read_to_string("../../clippy.toml").expect("clippy.toml is readable");

    for banned in ["reqwest::blocking::Client::new", "reqwest::Client::new"] {
        assert!(
            configuration.contains(banned),
            "clippy.toml must keep `{banned}` in disallowed-methods so an HTTP client cannot be \
             built outside openrouter_keymaster_core::client"
        );
    }
    assert!(
        configuration.contains("disallowed-methods"),
        "the ban is only enforced through the disallowed-methods list"
    );
}

#[test]
fn the_transport_does_no_retrying_of_its_own() {
    // `reqwest` retransmits a request up to twice by default when HTTP/2 NACKs
    // the stream. That happens below `openrouter_keymaster_core::client`, so a
    // create could be transmitted three times while every test here counted one
    // — and no test could catch it, because the harness serves HTTP/1.1. The
    // guarantee rests on one line, so its absence is a failure.
    let client = fs::read_to_string("src/client/mod.rs").expect("the client is readable");
    assert!(
        client.contains(".retry(reqwest::retry::never())"),
        "openrouter_keymaster_core::client::build_http must disable the transport's own retries: a \
         replayed POST /keys can create a live credential nobody knows about (ADR-0002)"
    );
}

#[test]
fn a_library_consumer_gets_no_argument_parser() {
    // ADR-0003, item 1: `clap` belongs to the binary. `cargo tree --invert`
    // fails outright when the package is not in this crate's graph, which is
    // the answer this test wants.
    let inverted = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--locked",
            "--package",
            "openrouter-keymaster-core",
            "--invert",
            "clap",
        ])
        .current_dir("../..")
        .output()
        .expect("cargo tree runs");

    assert!(
        !inverted.status.success(),
        "clap is in openrouter-keymaster-core's dependency graph:\n{}",
        String::from_utf8_lossy(&inverted.stdout)
    );
}

#[test]
fn the_modules_behind_ops_are_not_part_of_the_public_surface() {
    // ADR-0003, item 7. `tests/public_api.rs` proves the curated surface is
    // enough for a host; this proves it is all a host gets. The declarations
    // are paired — `pub` under `test-support` for the test suites, `pub(crate)`
    // otherwise — so only the second of each pair is checked here.
    let lib = fs::read_to_string("src/lib.rs").expect("the crate root is readable");

    for internal in ["api", "client", "plan", "receiver", "redaction"] {
        assert!(
            lib.contains(&format!("pub(crate) mod {internal};")),
            "`{internal}` is reachable by a host; ADR-0003 keeps it behind `ops`"
        );
    }
}
