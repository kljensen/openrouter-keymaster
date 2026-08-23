//! Two configuration facts that are part of the security policy, asserted like
//! any other behaviour.
//!
//! Both are guarantees no other test can reach. `clippy.toml` is the only thing
//! standing between the codebase and an HTTP client with no timeout, no
//! redirect policy, and no `Authorization` header. And the transport's own
//! retry policy only shows itself over HTTP/2, which the local harness does not
//! speak — so the line that disables it is checked where it is written.

use std::fs;

#[test]
fn unbounded_http_clients_are_refused_by_the_lint_configuration() {
    let configuration = fs::read_to_string("clippy.toml").expect("clippy.toml is readable");

    for banned in ["reqwest::blocking::Client::new", "reqwest::Client::new"] {
        assert!(
            configuration.contains(banned),
            "clippy.toml must keep `{banned}` in disallowed-methods so an HTTP client cannot be \
             built outside keymaster::client"
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
    // the stream. That happens below `keymaster::client`, so a create could be
    // transmitted three times while every test here counted one — and no test
    // could catch it, because the harness serves HTTP/1.1. The guarantee rests
    // on one line, so its absence is a failure.
    let client = fs::read_to_string("src/client/mod.rs").expect("the client is readable");
    assert!(
        client.contains(".retry(reqwest::retry::never())"),
        "keymaster::client::build_http must disable the transport's own retries: a replayed \
         POST /keys can create a live credential nobody knows about (ADR-0002)"
    );
}
