//! Read-only key, guardrail, and assignment reads, against the local harness.
//!
//! Pagination is what most of this file is about. Planning compares what exists
//! remotely with what should exist, so a record missed by pagination reads as a
//! record that is not there — and the plan that follows would propose creating
//! a second one. Each case below is a way a server can make that happen.

mod support;

use std::time::Duration;

use keymaster::api::pagination::PageLimits;
use keymaster::api::{ObservedKey, Reader, ResetPolicy};
use keymaster::client::{Client, ManagementKey, Options, RetryPolicy};
use keymaster::config::{ResetInterval, Usd};
use keymaster::ids::{KeyHash, Uuid};
use serde_json::{Value, json};
use support::fixtures::{
    FAKE_GUARDRAIL_ID, FAKE_WORKSPACE_ID, OTHER_FAKE_GUARDRAIL_ID, api_error, api_key, assignment,
    counted_page, empty_page, guardrail, key_pages, page,
};
use support::http::{Scripted, TestServer, json_response};
use support::sentinel::SECRET_SENTINEL_KEY;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn client(server: &TestServer) -> Client {
    let key = ManagementKey::for_tests(SECRET_SENTINEL_KEY).expect("a usable fake credential");
    let options = Options {
        request_timeout: Duration::from_secs(10),
        retry: RetryPolicy::never(),
        ..Options::new(server.api_base_url())
    };
    Client::new(options, &key).expect("a client")
}

/// Answers `GET /api/v1/keys` with each page in turn.
fn mount_key_pages(server: &TestServer, pages: Vec<Value>) {
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .respond_with(Scripted::json(pages)),
    );
}

fn hashes(keys: &[ObservedKey]) -> Vec<&str> {
    keys.iter().map(|key| key.hash.as_str()).collect()
}

/// The `offset` query parameter of each request the server received.
fn offsets(server: &TestServer) -> Vec<String> {
    server
        .requests()
        .iter()
        .map(|request| {
            request
                .url
                .query_pairs()
                .find(|(name, _)| name == "offset")
                .map_or_else(|| "-".to_owned(), |(_, value)| value.into_owned())
        })
        .collect()
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse(value).expect("a valid fake UUID")
}

#[test]
fn one_page_is_read_and_the_listing_ends() {
    let server = TestServer::start();
    mount_key_pages(&server, key_pages(&[&["a", "b"], &[]]));

    let keys = Reader::new(&client(&server))
        .list_keys(None)
        .expect("a snapshot");

    assert_eq!(hashes(&keys), vec!["a", "b"]);
    assert_eq!(offsets(&server), vec!["0", "2"]);
}

#[test]
fn several_pages_are_joined_and_the_offset_follows_what_arrived() {
    let server = TestServer::start();
    mount_key_pages(
        &server,
        key_pages(&[&["a", "b", "c"], &["d", "e"], &["f"], &[]]),
    );

    let keys = Reader::new(&client(&server))
        .list_keys(None)
        .expect("a snapshot");

    assert_eq!(hashes(&keys), vec!["a", "b", "c", "d", "e", "f"]);
    // Advanced by what was returned, not by the page size asked for.
    assert_eq!(offsets(&server), vec!["0", "3", "5", "6"]);
}

#[test]
fn an_empty_page_ends_the_listing_without_another_request() {
    let server = TestServer::start();
    mount_key_pages(
        &server,
        vec![empty_page(), page(vec![api_key("a", "late")])],
    );

    let keys = Reader::new(&client(&server))
        .list_keys(None)
        .expect("an empty snapshot");

    assert!(keys.is_empty());
    server.assert_request_count(1);
}

#[test]
fn overlapping_pages_are_deduplicated_by_hash() {
    let server = TestServer::start();
    mount_key_pages(
        &server,
        key_pages(&[&["a", "b", "c"], &["c", "d"], &["d", "e"], &[]]),
    );

    let keys = Reader::new(&client(&server))
        .list_keys(None)
        .expect("a snapshot");

    assert_eq!(hashes(&keys), vec!["a", "b", "c", "d", "e"]);
}

#[test]
fn duplicate_identities_within_one_page_are_collapsed() {
    let server = TestServer::start();
    mount_key_pages(&server, key_pages(&[&["a", "a", "b"], &[]]));

    let keys = Reader::new(&client(&server))
        .list_keys(None)
        .expect("a snapshot");

    assert_eq!(hashes(&keys), vec!["a", "b"]);
}

#[test]
fn a_page_that_repeats_itself_forever_is_an_error_not_a_loop() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            // The same page whatever the offset: a server ignoring pagination.
            .respond_with(json_response(200, &page(vec![api_key("a", "one")]))),
    );

    let failure = Reader::new(&client(&server))
        .list_keys(None)
        .expect_err("a stalled listing is not a snapshot");

    assert_eq!(failure.kind(), "invalid_response");
    assert!(failure.to_string().contains("no progress"), "{failure}");
    // Two requests: the first page, then the one that proved nothing moved.
    server.assert_request_count(2);
}

#[test]
fn a_total_count_that_disagrees_with_the_records_does_not_truncate_the_snapshot() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/guardrails"))
            .respond_with(Scripted::json(vec![
                // The server claims one guardrail and then sends three.
                counted_page(
                    vec![
                        guardrail(FAKE_GUARDRAIL_ID, "cheap", &["a/model"]),
                        guardrail(OTHER_FAKE_GUARDRAIL_ID, "other", &[]),
                    ],
                    1,
                ),
                counted_page(
                    vec![guardrail(
                        "33333333-3333-4333-8333-333333333333",
                        "third",
                        &[],
                    )],
                    1,
                ),
                counted_page(Vec::new(), 1),
            ])),
    );

    let guardrails = Reader::new(&client(&server))
        .list_guardrails(None)
        .expect("a snapshot");

    assert_eq!(guardrails.len(), 3, "a wrong total must not drop records");
}

#[test]
fn a_listing_that_never_ends_stops_at_the_sanity_cap() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            // Every page is new, so nothing but the cap can stop this.
            .respond_with(Scripted::json(
                (0..10)
                    .map(|index| page(vec![api_key(&format!("hash-{index}"), "one")]))
                    .collect::<Vec<_>>(),
            )),
    );

    let limits = PageLimits {
        page_size: 1,
        max_pages: 3,
        max_items: 1_000,
    };
    let failure = Reader::with_limits(&client(&server), limits)
        .list_keys(None)
        .expect_err("an endless listing is not a snapshot");

    assert_eq!(failure.kind(), "invalid_response");
    assert!(failure.to_string().contains("3 pages"), "{failure}");
    server.assert_request_count(3);
}

#[test]
fn a_record_with_no_identity_is_a_typed_invalid_response() {
    let server = TestServer::start();
    mount_key_pages(
        &server,
        vec![page(vec![json!({ "name": "a key with no hash" })])],
    );

    let failure = Reader::new(&client(&server))
        .list_keys(None)
        .expect_err("a key without a hash is not a key");

    assert_eq!(failure.kind(), "invalid_response");
    assert!(failure.to_string().contains("hash"), "{failure}");
}

#[test]
fn a_hash_that_is_key_plaintext_is_refused() {
    let server = TestServer::start();
    mount_key_pages(
        &server,
        vec![page(vec![api_key(SECRET_SENTINEL_KEY, "a leaked key")])],
    );

    let failure = Reader::new(&client(&server))
        .list_keys(None)
        .expect_err("plaintext is not an identity");

    assert_eq!(failure.kind(), "invalid_response");
    support::sentinel::assert_absent("the error message", &failure.to_string());
}

#[test]
fn fields_this_build_does_not_know_do_not_break_a_read() {
    let server = TestServer::start();
    let mut key = api_key("a", "one");
    key["a_field_added_next_year"] = json!({ "nested": [1, 2, 3] });
    key["limit_reset"] = json!("fortnightly");
    mount_key_pages(&server, vec![page(vec![key]), empty_page()]);

    let keys = Reader::new(&client(&server))
        .list_keys(None)
        .expect("an unknown field is not a failure");

    assert_eq!(hashes(&keys), vec!["a"]);
    assert_eq!(
        keys[0].limit_reset,
        ResetPolicy::Unrecognized("fortnightly".to_owned()),
        "an interval this build does not know is reported, not rejected"
    );
}

#[test]
fn a_key_is_read_into_managed_fields_and_read_only_observations() {
    let server = TestServer::start();
    mount_key_pages(&server, key_pages(&[&["a"], &[]]));

    let keys = Reader::new(&client(&server))
        .list_keys(None)
        .expect("a snapshot");
    let key = &keys[0];

    // Managed fields, normalized the way the configuration normalizes them.
    assert_eq!(key.name, "key-a");
    assert!(!key.disabled);
    assert_eq!(key.limit.map(Usd::micros), Some(5_000_000));
    assert_eq!(key.limit_reset, ResetPolicy::Every(ResetInterval::Monthly));
    assert_eq!(key.expires_at, None);
    assert_eq!(key.workspace_id, Some(uuid(FAKE_WORKSPACE_ID)));

    // Remote read-only observations, kept apart from them.
    assert!((key.usage.total - 1.25).abs() < f64::EPSILON);
    assert_eq!(key.usage.limit_remaining, Some(3.75));
    assert!(key.timestamps.created_at.is_some());
    assert!(key.timestamps.updated_at.is_some());
}

#[test]
fn one_key_is_fetched_by_its_hash() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys/sha256%3Aabc"))
            .respond_with(json_response(
                200,
                &json!({ "data": api_key("sha256:abc", "one") }),
            )),
    );

    let hash = KeyHash::parse("sha256:abc").expect("a valid hash");
    let key = Reader::new(&client(&server))
        .get_key(&hash)
        .expect("the key is found");

    assert_eq!(key.hash, hash);
    assert_eq!(server.request(0).url.path(), "/api/v1/keys/sha256%3Aabc");
}

#[test]
fn a_missing_key_is_reported_as_the_status_it_was() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .respond_with(json_response(404, &api_error(404, "Resource not found"))),
    );

    let hash = KeyHash::parse("gone").expect("a valid hash");
    let failure = Reader::new(&client(&server))
        .get_key(&hash)
        .expect_err("a missing key is an error");

    assert_eq!(failure.kind(), "http_status");
    assert_eq!(failure.status(), Some(404));
}

#[test]
fn guardrails_are_read_with_their_collections_normalized() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/guardrails"))
            .respond_with(Scripted::json(vec![
                counted_page(
                    vec![guardrail(
                        FAKE_GUARDRAIL_ID,
                        "cheap",
                        &["Z/Model", "a/model"],
                    )],
                    1,
                ),
                counted_page(Vec::new(), 1),
            ])),
    );

    let guardrails = Reader::new(&client(&server))
        .list_guardrails(None)
        .expect("a snapshot");
    let observed = &guardrails[0];

    assert_eq!(observed.id, uuid(FAKE_GUARDRAIL_ID));
    let models: Vec<&str> = observed
        .allowed_models
        .as_ref()
        .expect("an allow-list")
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        models,
        vec!["a/model", "z/model"],
        "slugs are lowercased and sorted, as the configuration stores them"
    );
    assert_eq!(observed.limit.map(Usd::micros), Some(10_000_000));
    assert_eq!(
        observed.reset_interval,
        ResetPolicy::Every(ResetInterval::Monthly)
    );
    assert_eq!(observed.zero_data_retention.anthropic, Some(true));
    assert_eq!(observed.zero_data_retention.any, None);
}

#[test]
fn one_guardrail_is_fetched_by_its_uuid() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/guardrails/{FAKE_GUARDRAIL_ID}")))
            .respond_with(json_response(
                200,
                &json!({ "data": guardrail(FAKE_GUARDRAIL_ID, "cheap", &[]) }),
            )),
    );

    let observed = Reader::new(&client(&server))
        .get_guardrail(&uuid(FAKE_GUARDRAIL_ID))
        .expect("the guardrail is found");
    assert_eq!(observed.name, "cheap");
}

#[test]
fn global_assignments_are_listed_and_paginated() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/guardrails/assignments/keys"))
            .respond_with(Scripted::json(vec![
                counted_page(
                    vec![assignment(
                        "44444444-4444-4444-8444-444444444444",
                        "a",
                        FAKE_GUARDRAIL_ID,
                    )],
                    2,
                ),
                counted_page(
                    vec![assignment(
                        "55555555-5555-4555-8555-555555555555",
                        "b",
                        OTHER_FAKE_GUARDRAIL_ID,
                    )],
                    2,
                ),
                counted_page(Vec::new(), 2),
            ])),
    );

    let assignments = Reader::new(&client(&server))
        .list_assignments()
        .expect("a snapshot");

    assert_eq!(assignments.len(), 2);
    assert_eq!(assignments[0].key_hash.as_str(), "a");
    assert_eq!(assignments[0].guardrail_id, uuid(FAKE_GUARDRAIL_ID));
    assert_eq!(assignments[1].guardrail_id, uuid(OTHER_FAKE_GUARDRAIL_ID));
    assert_eq!(offsets(&server), vec!["0", "1", "2"]);
}

#[test]
fn the_assignments_of_one_guardrail_are_listed_from_its_own_endpoint() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/guardrails/{FAKE_GUARDRAIL_ID}/assignments/keys"
            )))
            .respond_with(Scripted::json(vec![
                counted_page(
                    vec![assignment(
                        "44444444-4444-4444-8444-444444444444",
                        "a",
                        FAKE_GUARDRAIL_ID,
                    )],
                    1,
                ),
                counted_page(Vec::new(), 1),
            ])),
    );

    let assignments = Reader::new(&client(&server))
        .list_assignments_of(&uuid(FAKE_GUARDRAIL_ID))
        .expect("a snapshot");

    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].key_hash.as_str(), "a");
}

#[test]
fn a_workspace_filter_is_passed_through_without_disturbing_pagination() {
    let server = TestServer::start();
    mount_key_pages(&server, key_pages(&[&["a"], &[]]));

    let _ = Reader::new(&client(&server))
        .list_keys(Some(&uuid(FAKE_WORKSPACE_ID)))
        .expect("a snapshot");

    for request in server.requests() {
        let query: Vec<(String, String)> = request
            .url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        assert!(
            query.contains(&("workspace_id".to_owned(), FAKE_WORKSPACE_ID.to_owned())),
            "{query:?}"
        );
        assert!(
            query.contains(&("include_disabled".to_owned(), "true".to_owned())),
            "a disabled key is still Keymaster's to see: {query:?}"
        );
    }
    assert_eq!(offsets(&server), vec!["0", "1"]);
}

#[test]
fn reading_never_writes() {
    let server = TestServer::start();
    server.mount(Mock::given(method("GET")).respond_with(
        ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
            "total_count": 0,
        })),
    ));

    let client = client(&server);
    let reader = Reader::new(&client);
    let _ = reader.list_keys(None).expect("a snapshot");
    let _ = reader.list_guardrails(None).expect("a snapshot");
    let _ = reader.list_assignments().expect("a snapshot");

    for request in server.requests() {
        assert_eq!(request.method.as_str(), "GET", "a read must not write");
    }
}
