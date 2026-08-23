//! One demonstration test per capability of the shared test harness.
//!
//! These tests are the harness's own contract. Keymaster's HTTP client does
//! not exist yet (issue #8), so the requests below are made with a blocking
//! `reqwest` client configured the way that client will be. When the real
//! client lands it takes their place through its base-URL override; the
//! harness does not change.

mod support;

use std::io::Read;
use std::panic::{self, AssertUnwindSafe};
use std::time::Duration;

use serde_json::{Value, json};
use support::clock::FakeClock;
use support::fixtures::{
    self, FAKE_GUARDRAIL_ID, FAKE_INFERENCE_KEY, FAKE_MANAGEMENT_KEY, api_error, api_key,
    empty_page, guardrail, key_pages, page,
};
use support::http::{
    RemoteCollection, Scripted, TestServer, body_json, connection_lost, delayed, describe_request,
    header, json_response, malformed_json, oversized_body, rate_limited,
};
use support::receiver::{Delivery, FakeReceiver, ReceiverOutcome};
use support::sentinel::{
    SECRET_SENTINEL_KEY, assert_absent, assert_absent_in_file, assert_absent_under, assert_present,
};
use wiremock::matchers::{body_json_string, header as header_matcher, method, path};
use wiremock::{Mock, ResponseTemplate};

/// A client shaped like the one issue #8 will build.
fn client(timeout: Duration) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("keymaster-tests")
        .build()
        .expect("a blocking client")
}

fn get(url: &str) -> reqwest::Result<reqwest::blocking::Response> {
    client(Duration::from_secs(5)).get(url).send()
}

#[test]
fn routes_and_methods_are_matched_and_counted() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(200, &page(vec![api_key("sha256:a", "one")]))),
    );

    for _ in 0..2 {
        let response = get(&server.api_url("keys")).expect("the request reaches the server");
        assert_eq!(response.status(), 200);
    }

    // An unmatched route is a 404, not a silent success.
    let unmatched = get(&server.api_url("guardrails")).expect("the request reaches the server");
    assert_eq!(unmatched.status(), 404);

    server.assert_request_count(3);
}

#[test]
fn headers_and_bodies_are_captured_structurally() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .and(header_matcher("content-type", "application/json"))
            .and(body_json_string(r#"{"name":"jobfeed","limit":5.0}"#))
            .respond_with(json_response(
                200,
                &fixtures::created_key("sha256:a", "jobfeed", FAKE_INFERENCE_KEY),
            )),
    );

    let response = client(Duration::from_secs(5))
        .post(server.api_url("keys"))
        .json(&json!({ "name": "jobfeed", "limit": 5.0 }))
        .send()
        .expect("the request reaches the server");
    assert_eq!(response.status(), 200);

    let request = server.request(0);
    assert_eq!(
        header(&request, "content-type").as_deref(),
        Some("application/json")
    );
    // Structural, not a byte comparison: field order and spacing do not matter.
    assert_eq!(body_json(&request)["name"], "jobfeed");
    assert_eq!(body_json(&request)["limit"], 5.0);
}

#[test]
fn scripted_responses_are_returned_in_order() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(Scripted::new([
                ResponseTemplate::new(500),
                json_response(200, &empty_page()),
            ])),
    );

    let url = server.api_url("keys");
    assert_eq!(get(&url).expect("a response").status(), 500);
    assert_eq!(get(&url).expect("a response").status(), 200);
    // The last scripted response repeats.
    assert_eq!(get(&url).expect("a response").status(), 200);
}

#[test]
fn pagination_pages_can_be_empty_repeated_or_overlapping() {
    let shapes: [(&str, &[&[&str]]); 3] = [
        ("empty first page", &[&[]]),
        ("no progress", &[&["a", "b"], &["a", "b"], &[]]),
        ("overlapping", &[&["a", "b"], &["b", "c"], &[]]),
    ];

    for (name, pages) in shapes {
        let server = TestServer::start();
        let bodies = key_pages(pages);
        server.mount(
            Mock::given(method("GET"))
                .and(path("/api/v1/keys"))
                .respond_with(Scripted::json(bodies.clone())),
        );

        for expected in &bodies {
            let observed: Value = get(&server.api_url("keys"))
                .expect("a response")
                .json()
                .expect("a JSON page");
            assert_eq!(&observed, expected, "{name}");
        }
    }
}

#[test]
fn mutable_remote_state_produces_drift_between_reads() {
    let server = TestServer::start();
    let remote = RemoteCollection::new();
    remote.put("sha256:a", api_key("sha256:a", "jobfeed"));
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(remote.clone()),
    );

    let first: Value = get(&server.api_url("keys"))
        .expect("a response")
        .json()
        .expect("JSON");
    assert_eq!(first["data"][0]["name"], "jobfeed");

    // Someone renames the key in the dashboard and adds another.
    remote.put("sha256:a", api_key("sha256:a", "jobfeed-renamed"));
    remote.put("sha256:b", api_key("sha256:b", "laptop"));

    let second: Value = get(&server.api_url("keys"))
        .expect("a response")
        .json()
        .expect("JSON");
    assert_eq!(second["data"][0]["name"], "jobfeed-renamed");
    assert_eq!(second["data"].as_array().map(Vec::len), Some(2));

    remote.remove("sha256:b");
    let third: Value = get(&server.api_url("keys"))
        .expect("a response")
        .json()
        .expect("JSON");
    assert_eq!(third["data"].as_array().map(Vec::len), Some(1));
}

#[test]
fn the_server_normalizes_collections_so_ordering_is_not_drift() {
    let server = TestServer::start();
    let remote = RemoteCollection::new();
    remote.put(
        FAKE_GUARDRAIL_ID,
        guardrail(FAKE_GUARDRAIL_ID, "cheap", &["z/model", "a/model"]),
    );
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/guardrails"))
            .respond_with(remote),
    );

    let observed: Value = get(&server.api_url("guardrails"))
        .expect("a response")
        .json()
        .expect("JSON");
    assert_eq!(
        observed["data"][0]["allowed_models"],
        json!(["a/model", "z/model"])
    );
}

#[test]
fn a_delayed_response_trips_the_client_timeout() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(delayed(200, &empty_page(), Duration::from_secs(30))),
    );

    let error = client(Duration::from_millis(150))
        .get(server.api_url("keys"))
        .send()
        .expect_err("the request times out");
    assert!(error.is_timeout(), "expected a timeout, got {error}");
    server.assert_request_count(1);
}

#[test]
fn a_lost_connection_is_a_transport_error_after_exactly_one_request() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with_err(connection_lost),
    );

    let error = client(Duration::from_secs(5))
        .post(server.api_url("keys"))
        .json(&json!({ "name": "jobfeed" }))
        .send()
        .expect_err("the connection is lost");
    assert!(
        !error.is_timeout(),
        "expected a transport error, got {error}"
    );
    // The ambiguous case: the request arrived, the acknowledgement did not.
    server.assert_request_count(1);
}

#[test]
fn a_malformed_body_fails_to_parse() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(malformed_json()),
    );

    let response = get(&server.api_url("keys")).expect("a response");
    assert_eq!(response.status(), 200);
    response
        .json::<Value>()
        .expect_err("a truncated body is not JSON");
}

#[test]
fn an_oversized_body_can_be_read_under_a_bound() {
    const LIMIT: usize = 1024;
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(oversized_body(64 * LIMIT)),
    );

    let response = get(&server.api_url("keys")).expect("a response");
    assert_eq!(response.content_length(), Some(64 * LIMIT as u64));

    let mut bounded = Vec::new();
    std::io::copy(&mut response.take(LIMIT as u64), &mut bounded).expect("a bounded read");
    assert_eq!(bounded.len(), LIMIT);
}

#[test]
fn client_errors_carry_a_structured_api_error() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys/sha256:missing"))
            .respond_with(json_response(404, &api_error(404, "No such key"))),
    );

    let response = get(&server.api_url("keys/sha256:missing")).expect("a response");
    assert_eq!(response.status(), 404);
    let body: Value = response.json().expect("a JSON error body");
    assert_eq!(body["error"]["code"], 404);
    assert_eq!(body["error"]["message"], "No such key");
}

#[test]
fn rate_limiting_carries_retry_after() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(rate_limited(7)),
    );

    let response = get(&server.api_url("keys")).expect("a response");
    assert_eq!(response.status(), 429);
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .map(|v| v.to_str().ok()),
        Some(Some("7"))
    );
}

#[test]
fn server_errors_reach_the_client_as_5xx() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(ResponseTemplate::new(503)),
    );

    assert_eq!(
        get(&server.api_url("keys")).expect("a response").status(),
        503
    );
}

#[test]
fn a_harness_failure_explains_the_requests_it_saw_without_the_credential() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(200, &empty_page())),
    );
    client(Duration::from_secs(5))
        .get(server.api_url("keys"))
        .bearer_auth(SECRET_SENTINEL_KEY)
        .send()
        .expect("a response");

    let failure = panic::catch_unwind(AssertUnwindSafe(|| server.assert_request_count(2)))
        .expect_err("the count is wrong");
    let message = failure
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(message.contains("expected 2 request(s)"), "{message}");
    assert!(message.contains("GET /api/v1/keys"), "{message}");
    // The harness asserts counts itself precisely so this stays redacted:
    // wiremock's own expectation failure dumps recorded requests verbatim.
    assert!(message.contains("authorization: <redacted>"), "{message}");
    assert_absent("a harness failure message", &message);
}

#[test]
fn the_fake_clock_moves_only_when_the_test_moves_it() {
    let clock = FakeClock::new();
    let start = clock.now();
    assert_eq!(start.to_string(), "2026-01-01 0:00:00.0 +00:00:00");

    let shared = clock.clone();
    assert_eq!(shared.now(), start);

    clock.advance(time::Duration::seconds(90));
    assert_eq!(shared.now() - start, time::Duration::seconds(90));

    shared.set(start);
    assert_eq!(clock.now(), start);
}

#[test]
fn the_fake_receiver_records_every_outcome_without_keeping_plaintext() {
    let receiver = FakeReceiver::scripted(
        [
            ReceiverOutcome::Delivered,
            ReceiverOutcome::Rejected,
            ReceiverOutcome::TimedOut,
        ],
        ReceiverOutcome::AcknowledgementLost,
    );

    let outcomes: Vec<_> = (0..4)
        .map(|generation| {
            let delivery = Delivery {
                address: "keys.jobfeed".to_owned(),
                hash: "sha256:a".to_owned(),
                generation,
                operation_id: "op-1".to_owned(),
            };
            receiver.receive(delivery, SECRET_SENTINEL_KEY)
        })
        .collect();

    assert_eq!(
        outcomes,
        [
            ReceiverOutcome::Delivered,
            ReceiverOutcome::Rejected,
            ReceiverOutcome::TimedOut,
            ReceiverOutcome::AcknowledgementLost,
        ]
    );
    assert_eq!(receiver.deliveries().len(), 4);
    assert_eq!(
        receiver.plaintext_lengths(),
        vec![SECRET_SENTINEL_KEY.len(); 4]
    );
    // The receiver saw the secret; its records must not have kept it.
    assert_absent("the fake receiver's records", &format!("{receiver:?}"));
}

#[test]
fn the_sentinel_scanner_checks_strings_files_and_directories() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let clean = directory.path().join("state.json");
    std::fs::write(&clean, r#"{"keys":{"jobfeed":{"hash":"sha256:a"}}}"#).expect("a written file");

    assert_absent("a clean string", "nothing secret here");
    assert_absent_in_file(&clean);
    assert_absent_under(directory.path());
    assert_present("a string that should carry it", SECRET_SENTINEL_KEY);

    // The scanner must actually fail when the sentinel is there.
    let leaked = directory.path().join("leaked.json");
    std::fs::write(&leaked, format!(r#"{{"key":"{SECRET_SENTINEL_KEY}"}}"#))
        .expect("a written file");
    panic::catch_unwind(AssertUnwindSafe(|| assert_absent_under(directory.path())))
        .expect_err("the scanner finds the leak");
}

#[test]
fn authentication_reaches_the_server_but_not_the_diagnostics() {
    let server = TestServer::start();
    let bearer = format!("Bearer {SECRET_SENTINEL_KEY}");
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .and(header_matcher("authorization", bearer.as_str()))
            .respond_with(json_response(200, &page(vec![api_key("sha256:a", "one")]))),
    );

    let response = client(Duration::from_secs(5))
        .get(server.api_url("keys"))
        .bearer_auth(SECRET_SENTINEL_KEY)
        .send()
        .expect("the request reaches the server");
    assert_eq!(
        response.status(),
        200,
        "the mock only matches the right bearer"
    );
    server.assert_request_count(1);

    // The server really received the credential.
    let request = server.request(0);
    assert_present(
        "the Authorization header on the wire",
        &header(&request, "authorization").expect("an Authorization header"),
    );

    // The harness's own diagnostics redact it, and so must any artifact.
    let diagnostics = describe_request(&request);
    assert!(
        diagnostics.contains("authorization: <redacted>"),
        "{diagnostics}"
    );
    assert_absent("the request diagnostics", &diagnostics);

    let directory = tempfile::tempdir().expect("a temporary directory");
    let artifact = directory.path().join("diagnostics.log");
    std::fs::write(&artifact, &diagnostics).expect("a written artifact");
    assert_absent_under(directory.path());

    // The management-key fixture is fake, and is not the sentinel.
    assert_absent("the fixture credential", FAKE_MANAGEMENT_KEY);
}
