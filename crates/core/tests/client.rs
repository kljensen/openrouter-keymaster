//! The blocking OpenRouter client, against the local HTTP harness.
//!
//! Every case here drives the real [`Client`] over a real socket, so what is
//! asserted is what OpenRouter would see and what an operator would read.
//!
//! The client is built with the secret sentinel as its management credential.
//! That is deliberate: it makes every "no secret leaked" assertion in this file
//! mean something, because the value being scanned for is the one the client is
//! actually holding and sending.

use openrouter_keymaster_core::test_support as support;

use std::time::{Duration, Instant};

use openrouter_keymaster_core::client::retry::{
    backoff, is_retryable_status, next_delay, retry_after,
};
use openrouter_keymaster_core::client::{
    ApiError, Client, CreateKeyRequest, ManagementKey, Options, PRODUCTION_BASE_URL, RetryPolicy,
};
use openrouter_keymaster_core::ids::RemoteName;
use serde_json::{Value, json};
use support::clock::FakeClock;
use support::fixtures::{api_error, api_key, created_key, page};
use support::http::{
    RawServer, Scripted, TestServer, connection_lost, delayed, describe_request, header,
    json_response, malformed_json, oversized_body, rate_limited, truncated_body,
    truncated_body_with_status, whole_body,
};
use support::sentinel::{SECRET_SENTINEL_KEY, assert_absent, assert_present};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};
use zeroize::Zeroizing;

/// Options for a test: the harness's base URL, short timeouts, and a retry
/// policy with every delay flattened to zero, so a case that exercises the
/// retry path does not spend the policy's real backoff doing it.
fn options(server: &TestServer) -> Options {
    Options {
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(10),
        retry: RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        },
        ..Options::new(server.api_base_url())
    }
}

fn client_with(options: Options) -> Client {
    let key = ManagementKey::from_secret(Zeroizing::new(SECRET_SENTINEL_KEY.to_owned()))
        .expect("a usable fake credential");
    Client::new(options, &key).expect("a client")
}

fn client(server: &TestServer) -> Client {
    client_with(options(server))
}

/// Answers every `GET /api/v1/keys` with one template or responder.
fn mount_keys(server: &TestServer, responder: ResponseTemplate) {
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(responder),
    );
}

/// The smallest create request: a name and nothing else.
fn create_request() -> CreateKeyRequest {
    CreateKeyRequest::new(RemoteName::parse("jobfeed").expect("a valid name"))
}

fn one_key_page() -> Value {
    page(vec![api_key("hash-one", "one")])
}

#[test]
fn a_successful_read_returns_the_parsed_body() {
    let server = TestServer::start();
    mount_keys(&server, json_response(200, &one_key_page()));

    let body: Value = client(&server)
        .get_json(&["keys"], &[])
        .expect("the page parses");

    assert_eq!(body["data"][0]["hash"], "hash-one");
    server.assert_request_count(1);
}

#[test]
fn the_request_carries_the_credential_and_no_diagnostic_repeats_it() {
    let server = TestServer::start();
    mount_keys(
        &server,
        json_response(401, &api_error(401, "Invalid API key")),
    );

    let client = client(&server);
    let failure = client
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a 401 is an error");

    // The credential reached the server …
    let sent = server.request(0);
    let authorization = header(&sent, "authorization").expect("an Authorization header");
    assert_eq!(authorization, format!("Bearer {SECRET_SENTINEL_KEY}"));
    assert_present("the Authorization header", &authorization);

    // … and nothing an operator or a log could see repeats it.
    assert_absent("the error message", &failure.to_string());
    assert_absent("the error's Debug output", &format!("{failure:?}"));
    assert_absent("the client's Debug output", &format!("{client:?}"));
    assert_absent(
        "the harness's request description",
        &describe_request(&sent),
    );

    assert_eq!(failure.kind(), "authentication");
    assert_eq!(failure.status(), Some(401));
    assert!(failure.to_string().contains("Invalid API key"), "{failure}");
}

#[test]
fn the_request_announces_keymaster_and_asks_for_json() {
    let server = TestServer::start();
    mount_keys(&server, json_response(200, &one_key_page()));
    let _: Value = client(&server)
        .get_json(&["keys"], &[])
        .expect("the page parses");

    let sent = server.request(0);
    assert_eq!(header(&sent, "accept").as_deref(), Some("application/json"));
    let agent = header(&sent, "user-agent").expect("a user agent");
    assert!(
        agent.starts_with(&format!(
            "openrouter-keymaster/{}",
            env!("CARGO_PKG_VERSION")
        )),
        "{agent}"
    );
}

#[test]
fn every_documented_error_status_has_a_category() {
    for (status, kind) in [
        (400, "http_status"),
        (401, "authentication"),
        (403, "authentication"),
        (404, "http_status"),
        (409, "http_status"),
        (429, "http_status"),
        (500, "http_status"),
    ] {
        let server = TestServer::start();
        mount_keys(
            &server,
            json_response(status, &api_error(status, "something went wrong")),
        );

        let failure = client(&server)
            .get_json::<Value>(&["keys"], &[])
            .expect_err("an error status is an error");
        assert_eq!(failure.kind(), kind, "HTTP {status}");
        assert_eq!(failure.status(), Some(status), "HTTP {status}");
    }
}

#[test]
fn a_structured_api_error_keeps_its_code_and_message() {
    let server = TestServer::start();
    mount_keys(&server, json_response(404, &api_error(404, "Not found")));

    let failure = client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a 404 is an error");

    match failure {
        ApiError::Status {
            status,
            code,
            message,
            body_complete,
        } => {
            assert_eq!(status, 404);
            assert_eq!(code, Some(404));
            assert_eq!(message.as_deref(), Some("Not found"));
            assert!(body_complete, "this body arrived whole");
        }
        other => panic!("expected a status error, got {other:?}"),
    }
}

#[test]
fn an_error_body_that_is_not_json_still_produces_a_status_error() {
    let server = TestServer::start();
    mount_keys(
        &server,
        ResponseTemplate::new(503).set_body_raw("<html>gateway</html>", "text/html"),
    );

    let failure = client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a 503 is an error");
    assert_eq!(failure.kind(), "http_status");
    // The body is not repeated: only what Keymaster could parse is.
    assert!(!failure.to_string().contains("gateway"), "{failure}");
}

#[test]
fn a_success_that_is_not_json_is_an_invalid_response() {
    let server = TestServer::start();
    mount_keys(
        &server,
        ResponseTemplate::new(200).set_body_raw("welcome to the login page", "text/html"),
    );

    let failure = client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("HTML is not a key page");
    assert_eq!(failure.kind(), "invalid_response");
}

#[test]
fn a_truncated_json_body_is_an_invalid_response() {
    let server = TestServer::start();
    mount_keys(&server, malformed_json());

    let failure = client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("truncated JSON is not a key page");
    assert_eq!(failure.kind(), "invalid_response");
}

#[test]
fn a_body_past_the_cap_is_refused_rather_than_read() {
    let server = TestServer::start();
    mount_keys(&server, oversized_body(64 * 1024));

    let client = client_with(Options {
        max_response_bytes: 4 * 1024,
        ..options(&server)
    });
    let failure = client
        .get_json::<Value>(&["keys"], &[])
        .expect_err("an oversized body is refused");

    match failure {
        ApiError::OversizedResponse { limit } => assert_eq!(limit, 4 * 1024),
        other => panic!("expected an oversized-response error, got {other:?}"),
    }
}

#[test]
fn a_body_exactly_at_the_cap_is_accepted() {
    let server = TestServer::start();
    let body = one_key_page().to_string();
    mount_keys(
        &server,
        ResponseTemplate::new(200).set_body_raw(body.clone(), "application/json"),
    );

    let client = client_with(Options {
        max_response_bytes: body.len(),
        ..options(&server)
    });
    let parsed: Value = client
        .get_json(&["keys"], &[])
        .expect("a body that exactly fills the budget is still a body");
    assert_eq!(parsed["data"][0]["hash"], "hash-one");
}

#[test]
fn a_redirect_is_refused_and_never_followed() {
    let server = TestServer::start();
    mount_keys(
        &server,
        ResponseTemplate::new(302).insert_header("location", "/api/v1/elsewhere"),
    );
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/elsewhere"))
            .respond_with(json_response(200, &one_key_page())),
    );

    let failure = client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a redirect is refused");

    assert_eq!(failure.kind(), "redirected");
    assert_eq!(failure.status(), Some(302));
    // The credential was not carried to the redirect target.
    server.assert_request_count(1);
}

#[test]
fn a_response_that_never_arrives_times_out() {
    let server = TestServer::start();
    mount_keys(
        &server,
        delayed(200, &one_key_page(), Duration::from_secs(30)),
    );

    let client = client_with(Options {
        request_timeout: Duration::from_millis(200),
        ..options(&server)
    });
    let failure = client
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a response that never arrives is a timeout");

    assert_eq!(failure.kind(), "timeout");
    // A timeout is not retried: the request may already have been acted on.
    server.assert_request_count(1);
}

#[test]
fn path_segments_and_query_values_are_percent_encoded() {
    let server = TestServer::start();
    server.mount(Mock::given(method("GET")).respond_with(json_response(200, &json!({}))));

    let _: Value = client(&server)
        .get_json(
            &["keys", "a b/../c?d#e"],
            &[("workspace_id", "x&y=z".to_owned())],
        )
        .expect("the request is made");

    let sent = server.request(0);
    assert_eq!(sent.url.path(), "/api/v1/keys/a%20b%2F..%2Fc%3Fd%23e");
    assert_eq!(sent.url.query(), Some("workspace_id=x%26y%3Dz"));
}

#[test]
fn a_read_retries_a_server_error_and_then_succeeds() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(Scripted::new([
                ResponseTemplate::new(500),
                json_response(200, &one_key_page()),
            ])),
    );

    let body: Value = client(&server)
        .get_json(&["keys"], &[])
        .expect("the second attempt succeeds");
    assert_eq!(body["data"][0]["hash"], "hash-one");
    server.assert_request_count(2);
}

#[test]
fn a_read_retries_a_rate_limit_without_waiting_for_the_servers_answer() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(Scripted::new([
                // Two minutes: honoured as a signal, clamped to the policy.
                rate_limited(120),
                json_response(200, &one_key_page()),
            ])),
    );

    let started = Instant::now();
    let _: Value = client(&server)
        .get_json(&["keys"], &[])
        .expect("the second attempt succeeds");

    server.assert_request_count(2);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the server's Retry-After must be clamped to the policy, not obeyed"
    );
}

#[test]
fn a_read_retries_a_lost_connection_and_gives_up_within_the_policy() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with_err(connection_lost),
    );

    let failure = client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("the connection never holds");

    assert_eq!(failure.kind(), "transport");
    server.assert_request_count(3);
}

#[test]
fn a_read_retries_a_body_that_stops_partway_through_a_success() {
    // A good status and good headers, then the connection closes mid-body: the
    // failure a reset in the middle of a large page produces. Giving up here
    // would hand the planner a snapshot with records missing from it.
    let server = RawServer::scripted(vec![
        truncated_body(r#"{"data": [{"hash": "hash-o"#),
        whole_body(&one_key_page().to_string()),
    ]);

    let client = client_with(Options {
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(10),
        retry: RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        },
        ..Options::new(server.api_base_url())
    });
    let body: Value = client
        .get_json(&["keys"], &[])
        .expect("the second attempt returns a whole page");

    assert_eq!(body["data"][0]["hash"], "hash-one");
    server.assert_request_count(2);
}

#[test]
fn an_oversized_body_is_not_downloaded_again_because_the_status_was_transient() {
    let server = TestServer::start();
    mount_keys(
        &server,
        // A retryable status carrying a body past the cap. The status alone
        // would say "try again"; the body says the next attempt would be
        // identical, only slower.
        ResponseTemplate::new(503).set_body_raw(vec![b'x'; 64 * 1024], "application/json"),
    );

    let client = client_with(Options {
        max_response_bytes: 4 * 1024,
        ..options(&server)
    });
    let failure = client
        .get_json::<Value>(&["keys"], &[])
        .expect_err("an oversized body is refused");

    assert_eq!(failure.kind(), "oversized_response");
    server.assert_request_count(1);
}

#[test]
fn a_body_that_stalls_is_a_timeout_and_the_timeout_is_spent_once() {
    // Headers arrive, then the body stops and the connection stays open: the
    // whole-request timeout expires partway through. Reported as a transport
    // failure it would be retried, and each attempt would spend the timeout
    // again.
    let server = RawServer::holding(
        vec![truncated_body(r#"{"data": [{"hash": "hash-o"#)],
        Duration::from_secs(3),
    );

    let request_timeout = Duration::from_millis(250);
    let client = client_with(Options {
        connect_timeout: Duration::from_secs(2),
        request_timeout,
        retry: RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        },
        ..Options::new(server.api_base_url())
    });

    let started = Instant::now();
    let failure = client
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a stalled body is a timeout");

    assert_eq!(failure.kind(), "timeout");
    server.assert_request_count(1);
    assert!(
        started.elapsed() < request_timeout * 3,
        "the timeout must be spent once, not once per attempt"
    );
}

#[test]
fn a_create_is_issued_exactly_once_when_the_body_stops_partway_through() {
    let server = RawServer::scripted(vec![truncated_body(r#"{"data": {"hash": "hash-o"#)]);

    let client = client_with(Options {
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(10),
        retry: RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        },
        ..Options::new(server.api_base_url())
    });
    let failure = client
        .create_key_once(&create_request())
        .expect_err("a truncated create response is ambiguous");

    assert_eq!(failure.kind(), "transport");
    // The retry policy above is generous, and it still does not reach a write.
    server.assert_request_count(1);
}

/// Names the half of the proxy test that runs in a subprocess.
const PROXY_CHILD: &str = "the_child_half_of_the_proxy_test_reaches_the_server_directly";

#[test]
fn an_ambient_proxy_cannot_intercept_a_management_request() {
    // `reqwest` reads HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY by default, and a
    // proxy named there terminates TLS to see what passes through — including
    // the `Authorization` header. So the environment must not be able to
    // redirect a request, and this proves it with an environment that tries.
    //
    // The variables have to be set by whoever spawns the process, because
    // `std::env::set_var` is `unsafe` in Rust 2024 and this crate forbids
    // unsafe. So this half stands up the proxy that must stay untouched and
    // runs the other half — an ignored test in this same binary — as a child
    // with the environment set.
    let proxy = RawServer::scripted(vec![whole_body(
        r#"{"data":[{"hash":"through-the-proxy"}]}"#,
    )]);
    let binary = std::env::current_exe().expect("this test binary's own path");

    let child = std::process::Command::new(binary)
        .args(["--exact", "--ignored", "--nocapture", PROXY_CHILD])
        .env("HTTP_PROXY", proxy.origin())
        .env("http_proxy", proxy.origin())
        .env("HTTPS_PROXY", proxy.origin())
        .env("ALL_PROXY", proxy.origin())
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("the child half runs");

    assert!(
        child.status.success(),
        "the child half failed, so the request did not go direct:\n{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
    proxy.assert_request_count(0);
}

#[test]
#[ignore = "the parent half runs this in a subprocess with the proxy variables set"]
fn the_child_half_of_the_proxy_test_reaches_the_server_directly() {
    let server = TestServer::start();
    mount_keys(&server, json_response(200, &one_key_page()));

    let body: Value = client(&server)
        .get_json(&["keys"], &[])
        .expect("the request reaches the server, not the proxy");

    // Both halves of the proof: the answer came from the server the client was
    // pointed at, and the request was recorded there rather than at the proxy.
    assert_eq!(body["data"][0]["hash"], "hash-one");
    server.assert_request_count(1);
}

#[test]
fn a_read_does_not_retry_a_definite_rejection() {
    let server = TestServer::start();
    mount_keys(&server, json_response(404, &api_error(404, "Not found")));

    let _ = client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a 404 is an error");
    server.assert_request_count(1);
}

#[test]
fn a_created_keys_plaintext_reaches_the_caller_and_no_diagnostic() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                201,
                &created_key("hash-one", "jobfeed", SECRET_SENTINEL_KEY),
            )),
    );

    let created = client(&server)
        .create_key_once(&create_request())
        .expect("the key is created");

    // The identity is ordinary data, and the plaintext reaches the one caller
    // entitled to it — so the absence assertions below cannot pass vacuously.
    assert_eq!(created.hash().as_str(), "hash-one");
    assert_present(
        "the caller that will deliver it",
        created.plaintext().expose(),
    );

    // Nothing that could be logged, rendered, or persisted carries it. There is
    // no `Serialize` on either type, so `Debug` is the only way out.
    assert_absent("the created key's Debug output", &format!("{created:?}"));
    assert_absent(
        "the plaintext's Debug output",
        &format!("{:?}", created.plaintext()),
    );
    assert_absent(
        "the request the harness recorded",
        &describe_request(&server.request(0)),
    );
}

#[test]
fn a_create_response_whose_identity_is_malformed_fails_without_repeating_the_secret() {
    // The plaintext is present and the identity is not, so serde populates the
    // secret field and then fails on the next one. The half-built response is
    // dropped; nothing about that may reach a diagnostic, and — since the
    // create was still sent — the outcome stays a single ambiguous attempt.
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                201,
                &json!({ "key": SECRET_SENTINEL_KEY, "data": { "no_hash_here": true } }),
            )),
    );

    let failure = client(&server)
        .create_key_once(&create_request())
        .expect_err("a create response with no identity is unusable");

    assert_eq!(failure.kind(), "invalid_response");
    assert_absent("the error message", &failure.to_string());
    assert_absent("the error's Debug output", &format!("{failure:?}"));
    server.assert_request_count(1);
}

#[test]
fn a_create_parse_error_cannot_quote_the_key_back_at_the_operator() {
    // `serde_json` puts the offending value in several of its messages. Here
    // the offending value is where the key would be, so the message it wants to
    // write is the secret itself.
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                201,
                &json!({ "key": SECRET_SENTINEL_KEY, "data": SECRET_SENTINEL_KEY }),
            )),
    );

    let failure = client(&server)
        .create_key_once(&create_request())
        .expect_err("a create response with no identity is unusable");

    assert_eq!(failure.kind(), "invalid_response");
    assert_absent("the error message", &failure.to_string());
    assert_absent("the error's Debug output", &format!("{failure:?}"));
    server.assert_request_count(1);
}

#[test]
fn a_create_response_that_is_nothing_but_the_key_is_refused_without_echoing_it() {
    // The whole body is a bare string, so the value rejected at the very top
    // level *is* the secret. A derived deserializer would name it in the
    // message it hands back inside the error object; the hand-written one
    // rejects the shape without ever looking at the contents.
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(201, &json!(SECRET_SENTINEL_KEY))),
    );

    let failure = client(&server)
        .create_key_once(&create_request())
        .expect_err("a bare string is not a create response");

    assert_eq!(failure.kind(), "invalid_response");
    assert_absent("the error message", &failure.to_string());
    assert_absent("the error's Debug output", &format!("{failure:?}"));
    server.assert_request_count(1);
}

/// A client pointed at a raw server, with a policy generous enough that a
/// retry would be obvious if one happened.
fn raw_client(server: &RawServer) -> Client {
    client_with(Options {
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(10),
        retry: RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        },
        ..Options::new(server.api_base_url())
    })
}

#[test]
fn a_status_survives_a_body_that_cannot_be_read() {
    // The status is the most informative thing left when the body stops
    // partway through, so it is what gets reported: "HTTP 400" names what
    // happened, "the connection dropped" does not. What it is *not* is proof —
    // see `a_rejection_whose_body_stopped_short_is_not_a_definite_rejection`.
    let server = RawServer::scripted(vec![truncated_body_with_status(
        400,
        r#"{"error": {"code": 400, "mess"#,
    )]);

    let failure = raw_client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a 400 is an error");

    assert_eq!(failure.kind(), "http_status");
    assert_eq!(failure.status(), Some(400));
    // 4xx is not retried whatever became of its body.
    server.assert_request_count(1);
}

#[test]
fn a_redirect_stays_a_redirect_when_its_body_cannot_be_read() {
    let server = RawServer::scripted(vec![truncated_body_with_status(302, "{\"partia")]);

    let failure = raw_client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a redirect is refused");

    assert_eq!(failure.kind(), "redirected");
    assert_eq!(failure.status(), Some(302));
    server.assert_request_count(1);
}

#[test]
fn an_unauthorized_response_stays_authentication_when_its_body_cannot_be_read() {
    let server = RawServer::scripted(vec![truncated_body_with_status(401, "{\"err")]);

    let failure = raw_client(&server)
        .get_json::<Value>(&["keys"], &[])
        .expect_err("a 401 is an error");

    assert_eq!(failure.kind(), "authentication");
    assert_eq!(failure.status(), Some(401));
    server.assert_request_count(1);
}

#[test]
fn a_rate_limit_with_an_unreadable_body_is_still_retried() {
    // 429 is a rejection by status class and transient by meaning. Preserving
    // the status must not cost the retry that makes it useful.
    let server = RawServer::scripted(vec![
        truncated_body_with_status(429, "{\"err"),
        whole_body(r#"{"data":[{"hash":"hash-one"}]}"#),
    ]);

    let body: Value = raw_client(&server)
        .get_json(&["keys"], &[])
        .expect("the second attempt succeeds");

    assert_eq!(body["data"][0]["hash"], "hash-one");
    server.assert_request_count(2);
}

#[test]
fn a_rejection_whose_body_stopped_short_is_not_a_definite_rejection() {
    // The case ADR-0002 turns on, and the direction is the opposite of what the
    // status alone suggests. A definite rejection needs a *well-formed* 4xx:
    // the server saw the request, refused it, and said so in a response that
    // arrived whole. Here the status line arrived and the exchange then failed,
    // so what the server did with the request is unknown — and a create
    // classified as definite on that evidence would clear a journal entry for
    // an attempt that may have made a live key.
    let server = RawServer::scripted(vec![truncated_body_with_status(
        400,
        r#"{"error": {"code": 400, "mess"#,
    )]);

    let failure = raw_client(&server)
        .create_key_once(&create_request())
        .expect_err("a 400 refuses the create");

    assert_eq!(failure.kind(), "http_status");
    assert_eq!(
        failure.status(),
        Some(400),
        "the status is still the most useful thing to report"
    );
    assert!(
        !failure.is_definite_rejection(),
        "but it is not proof the request was declined: {failure}"
    );
    assert!(
        failure
            .to_string()
            .contains("stopped before its body finished"),
        "and the message says why: {failure}"
    );
    server.assert_request_count(1);
}

#[test]
fn a_rejection_whose_body_arrived_whole_is_a_definite_rejection() {
    // The other side of the same rule, so the one above cannot pass by making
    // every 4xx ambiguous. This response completes, so the server processed the
    // request and declined it, and no key exists.
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(
                400,
                &api_error(400, "limit_reset is not valid"),
            )),
    );

    let failure = client(&server)
        .create_key_once(&create_request())
        .expect_err("a 400 refuses the create");

    assert!(
        failure.is_definite_rejection(),
        "a complete 4xx proves nothing was created: {failure}"
    );
    assert!(
        !failure
            .to_string()
            .contains("stopped before its body finished"),
        "{failure}"
    );
    server.assert_request_count(1);
}

#[test]
fn a_body_that_arrived_whole_is_a_definite_rejection_even_if_it_is_not_json() {
    // What makes a rejection definite is that the response *finished*, not that
    // its body parsed. A server that answers 400 with a plain sentence has
    // still processed the request and declined it.
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(ResponseTemplate::new(400).set_body_raw("nope", "text/plain")),
    );

    let failure = client(&server)
        .create_key_once(&create_request())
        .expect_err("a 400 refuses the create");

    assert!(failure.is_definite_rejection(), "{failure}");
}

#[test]
fn a_server_error_is_never_a_definite_rejection_however_complete_its_body() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(json_response(500, &api_error(500, "server exploded"))),
    );

    let failure = client(&server)
        .create_key_once(&create_request())
        .expect_err("a 500 is an error");

    assert!(
        !failure.is_definite_rejection(),
        "a 5xx says nothing about whether the request was applied: {failure}"
    );
}

#[test]
fn a_create_is_issued_exactly_once_when_the_connection_is_lost() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with_err(connection_lost),
    );

    let failure = client(&server)
        .create_key_once(&create_request())
        .expect_err("the acknowledgement is lost");

    assert_eq!(failure.kind(), "transport");
    // The whole point: a key may exist now, and a second POST could make two.
    server.assert_request_count(1);
}

#[test]
fn a_create_is_issued_exactly_once_on_a_server_error() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(ResponseTemplate::new(500)),
    );

    let failure = client(&server)
        .create_key_once(&create_request())
        .expect_err("a 500 after a create is ambiguous");

    assert_eq!(failure.kind(), "http_status");
    server.assert_request_count(1);
}

#[test]
fn a_create_is_issued_exactly_once_when_the_success_is_malformed() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/keys"))
            .respond_with(malformed_json()),
    );

    let failure = client(&server)
        .create_key_once(&create_request())
        .expect_err("a truncated create response is ambiguous");

    assert_eq!(failure.kind(), "invalid_response");
    server.assert_request_count(1);
}

#[test]
fn retry_timing_is_deterministic_under_the_fake_clock_and_never_sleeps() {
    // 1994-11-06T08:49:37Z: the instant in RFC 9110's own `Retry-After`
    // example, so the three date formats below are the specification's.
    let clock = FakeClock::at_unix(784_111_777);
    let started = Instant::now();
    let now = clock.now();

    assert_eq!(retry_after("120", now), Some(Duration::from_secs(120)));
    assert_eq!(retry_after("  7 ", now), Some(Duration::from_secs(7)));
    assert_eq!(
        retry_after("Sun, 06 Nov 1994 08:49:47 GMT", now),
        Some(Duration::from_secs(10)),
        "IMF-fixdate"
    );
    assert_eq!(
        retry_after("Sunday, 06-Nov-94 08:49:47 GMT", now),
        None,
        "a two-digit year has no unambiguous reading, so the policy decides"
    );
    assert_eq!(
        retry_after("Sun Nov  6 08:49:47 1994", now),
        Some(Duration::from_secs(10)),
        "asctime"
    );
    assert_eq!(
        retry_after("Sun, 06 Nov 1994 08:00:00 GMT", now),
        Some(Duration::ZERO),
        "an instant already past is no wait at all"
    );
    assert_eq!(retry_after("soon", now), None);
    assert_eq!(retry_after("", now), None);

    // Moving the clock forward moves the answer, and nothing else does.
    clock.advance(time::Duration::seconds(5));
    assert_eq!(
        retry_after("Sun, 06 Nov 1994 08:49:47 GMT", clock.now()),
        Some(Duration::from_secs(5))
    );

    assert!(
        started.elapsed() < Duration::from_millis(100),
        "retry policy functions must compute, not wait"
    );
}

#[test]
fn backoff_doubles_and_stops_at_the_policy_bound() {
    let policy = RetryPolicy {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(250),
    };
    assert_eq!(backoff(&policy, 1), Duration::from_millis(100));
    assert_eq!(backoff(&policy, 2), Duration::from_millis(200));
    assert_eq!(backoff(&policy, 3), Duration::from_millis(250));
    assert_eq!(backoff(&policy, 1_000), Duration::from_millis(250));
}

#[test]
fn the_policy_bounds_both_the_delay_and_the_number_of_attempts() {
    let now = FakeClock::new().now();
    let policy = RetryPolicy {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(250),
    };

    assert_eq!(
        next_delay(&policy, 1, None, now),
        Some(Duration::from_millis(100))
    );
    assert_eq!(
        next_delay(&policy, 1, Some("3600"), now),
        Some(Duration::from_millis(250)),
        "an hour asked for is a quarter second waited"
    );
    assert_eq!(next_delay(&policy, 2, Some("0"), now), Some(Duration::ZERO));
    assert_eq!(
        next_delay(&policy, 3, None, now),
        None,
        "the third attempt is the last one the policy allows"
    );
    assert_eq!(next_delay(&RetryPolicy::never(), 1, None, now), None);
}

#[test]
fn only_transient_statuses_are_retryable() {
    for retryable in [429, 500, 502, 503, 504] {
        assert!(is_retryable_status(retryable), "{retryable}");
    }
    for permanent in [200, 301, 400, 401, 403, 404, 409, 422, 501, 505] {
        assert!(!is_retryable_status(permanent), "{permanent}");
    }
}

#[test]
fn a_credential_is_checked_without_ever_being_quoted() {
    for blank in ["", "   ", "\t\n"] {
        let missing = ManagementKey::from_secret(Zeroizing::new(blank.to_owned()))
            .expect_err("a blank credential is no credential");
        assert_eq!(missing.kind(), "missing_credential", "{blank:?}");
    }

    // A header value cannot carry a space or a control character, and a
    // newline in one would let the value forge a second header.
    for unusable in [
        format!("{SECRET_SENTINEL_KEY} trailing words"),
        format!("{SECRET_SENTINEL_KEY}\nX-Evil: 1"),
        format!("{SECRET_SENTINEL_KEY}\u{7}"),
    ] {
        let refused = ManagementKey::from_secret(Zeroizing::new(unusable))
            .expect_err("a credential that cannot be sent as a header is refused");
        assert_eq!(refused.kind(), "unusable_credential");
        assert_absent("the credential error", &refused.to_string());
    }

    let key = ManagementKey::from_secret(Zeroizing::new(SECRET_SENTINEL_KEY.to_owned()))
        .expect("a credential-shaped value is accepted");
    assert_absent("the credential's Debug output", &format!("{key:?}"));
}

#[test]
fn the_base_url_must_be_an_absolute_http_url() {
    let key = ManagementKey::from_secret(Zeroizing::new(SECRET_SENTINEL_KEY.to_owned()))
        .expect("a usable fake credential");
    for rejected in ["openrouter.ai/api/v1", "", "https://ai?token=x"] {
        let failure = Client::new(Options::new(rejected), &key)
            .err()
            .unwrap_or_else(|| panic!("{rejected} should be refused"));
        assert_eq!(failure.kind(), "invariant", "{rejected}");
    }

    let client = Client::new(Options::default(), &key).expect("the production client builds");
    assert_eq!(client.base_url(), PRODUCTION_BASE_URL);
}
