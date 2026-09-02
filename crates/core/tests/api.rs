//! Read-only key, guardrail, and assignment reads, against the local harness.
//!
//! Pagination is what most of this file is about. Planning compares what exists
//! remotely with what should exist, so a record missed by pagination reads as a
//! record that is not there — and the plan that follows would propose creating
//! a second one. Each case below is a way a server can make that happen.

use openrouter_keymaster_core::test_support as support;

use std::time::Duration;

use openrouter_keymaster_core::api::pagination::PageLimits;
use openrouter_keymaster_core::api::{
    AnalyticsFilter, AnalyticsQuery, ObservedKey, Reader, ResetPolicy, Writer,
};
use openrouter_keymaster_core::client::{Client, ManagementKey, Options, RetryPolicy};
use openrouter_keymaster_core::config::{ResetInterval, Usd};
use openrouter_keymaster_core::ids::{KeyHash, Uuid};
use serde_json::{Value, json};
use support::fixtures::{
    FAKE_DESTINATION_ID, FAKE_GUARDRAIL_ID, FAKE_WORKSPACE_ID, OTHER_FAKE_DESTINATION_ID,
    OTHER_FAKE_GUARDRAIL_ID, api_error, api_key, assignment, counted_page, empty_page, guardrail,
    key_pages, log_destination, page,
};
use support::http::{Scripted, TestServer, json_response};
use support::sentinel::SECRET_SENTINEL_KEY;
use time::OffsetDateTime;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, ResponseTemplate};
use zeroize::Zeroizing;

fn client(server: &TestServer) -> Client {
    let key = ManagementKey::from_secret(Zeroizing::new(SECRET_SENTINEL_KEY.to_owned()))
        .expect("a usable fake credential");
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
        .list_keys_in(None)
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
        .list_keys_in(None)
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
        .list_keys_in(None)
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
        .list_keys_in(None)
        .expect("a snapshot");

    assert_eq!(hashes(&keys), vec!["a", "b", "c", "d", "e"]);
}

#[test]
fn duplicate_identities_within_one_page_are_collapsed() {
    let server = TestServer::start();
    mount_key_pages(&server, key_pages(&[&["a", "a", "b"], &[]]));

    let keys = Reader::new(&client(&server))
        .list_keys_in(None)
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
        .list_keys_in(None)
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
        .list_guardrails_in(None)
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
        .list_keys_in(None)
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
        .list_keys_in(None)
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
        .list_keys_in(None)
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
        .list_keys_in(None)
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
        .list_keys_in(None)
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
        .list_guardrails_in(None)
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
        .list_keys_in(Some(&uuid(FAKE_WORKSPACE_ID)))
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
fn every_workspace_is_listed_and_the_union_is_deduplicated() {
    // `GET /keys` and `GET /guardrails` answer for one workspace at a time —
    // the credential's default workspace unless `workspace_id` names another —
    // so the organization is the union of one unscoped listing and one per
    // workspace. A record two of them carry is one record (ADR-0004, item 5).
    let server = TestServer::start();
    let workspace = uuid(FAKE_WORKSPACE_ID);
    for (matcher, first) in [
        (
            Mock::given(method("GET"))
                .and(path("/api/v1/keys"))
                .and(query_param("workspace_id", FAKE_WORKSPACE_ID)),
            vec![api_key("inside", "the club's key")],
        ),
        (
            Mock::given(method("GET"))
                .and(path("/api/v1/keys"))
                .and(query_param_is_missing("workspace_id")),
            vec![api_key("default", "the default workspace's key")],
        ),
    ] {
        server.mount(matcher.respond_with(Scripted::json(vec![page(first), empty_page()])));
    }

    let keys = Reader::new(&client(&server))
        .list_keys(std::slice::from_ref(&workspace))
        .expect("a snapshot");

    assert_eq!(hashes(&keys), vec!["default", "inside"]);
}

#[test]
fn a_workspace_that_is_gone_by_the_time_its_listing_runs_holds_nothing() {
    // The workspace came from this run's own listing, so a 404 is one deleted
    // underneath the snapshot. Anything else fails the snapshot rather than
    // truncating it.
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .and(query_param("workspace_id", FAKE_WORKSPACE_ID))
            .respond_with(json_response(404, &api_error(404, "no such workspace"))),
    );
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/keys"))
            .and(query_param_is_missing("workspace_id"))
            .respond_with(Scripted::json(vec![
                page(vec![api_key("default", "still here")]),
                empty_page(),
            ])),
    );

    let keys = Reader::new(&client(&server))
        .list_keys(&[uuid(FAKE_WORKSPACE_ID)])
        .expect("a snapshot");

    assert_eq!(hashes(&keys), vec!["default"]);
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

    // Every listing here is a `GET`. The one request `Reader` makes that is
    // not is `analytics_query`, which reads through a `POST` because the
    // question does not fit a query string; it changes nothing either.
    let client = client(&server);
    let reader = Reader::new(&client);
    let _ = reader.list_keys_in(None).expect("a snapshot");
    let _ = reader.list_guardrails_in(None).expect("a snapshot");
    let _ = reader.list_assignments().expect("a snapshot");

    for request in server.requests() {
        assert_eq!(request.method.as_str(), "GET", "a read must not write");
    }
}

#[test]
fn deleting_a_key_sends_one_bodiless_delete_addressed_by_hash() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("DELETE"))
            .and(path("/api/v1/keys/hash-jobfeed-1"))
            .respond_with(json_response(200, &json!({}))),
    );

    let client = client(&server);
    Writer::new(&client)
        .delete_key(&KeyHash::parse("hash-jobfeed-1").expect("a valid hash"))
        .expect("the delete is accepted");

    server.assert_request_count(1);
    let request = server.request(0);
    assert_eq!(request.method.as_str(), "DELETE");
    assert_eq!(request.url.path(), "/api/v1/keys/hash-jobfeed-1");
    assert!(
        request.body.is_empty(),
        "the resource is named in the path; a body would be a second statement of it"
    );
}

#[test]
fn a_delete_that_is_refused_reports_the_status_and_is_never_repeated() {
    let server = TestServer::start();
    server.mount(Mock::given(method("DELETE")).respond_with(
        ResponseTemplate::new(404).set_body_json(json!({
            "error": { "code": 404, "message": "no such key" }
        })),
    ));

    let client = client(&server);
    let error = Writer::new(&client)
        .delete_key(&KeyHash::parse("hash-gone").expect("a valid hash"))
        .expect_err("OpenRouter has no such key");

    assert_eq!(
        error.status(),
        Some(404),
        "the caller decides what a 404 means for a delete: {error}"
    );
    server.assert_request_count(1);
}

// --- log destinations (ADR-0006) --------------------------------------------

/// `GET /observability/destinations` answers for one workspace at a time — the
/// credential's default workspace unless `workspace_id` names another — so a
/// complete picture is that listing once with no workspace and once per
/// workspace the snapshot found.
#[test]
fn every_workspace_is_listed_and_a_destination_seen_twice_is_reported_once() {
    let server = TestServer::start();
    let other_workspace = "00000000-0000-4000-8000-00000000000e";
    // The default workspace's listing and `FAKE_WORKSPACE_ID`'s return the same
    // destination, which is what makes the deduplication observable.
    for query in ["", FAKE_WORKSPACE_ID] {
        server.mount(
            Mock::given(method("GET"))
                .and(path("/api/v1/observability/destinations"))
                .and(wiremock::matchers::query_param("offset", "0"))
                .and(match_workspace(query))
                .respond_with(json_response(
                    200,
                    &page(vec![log_destination(
                        FAKE_DESTINATION_ID,
                        "datadog",
                        "audit",
                    )]),
                ))
                .with_priority(1),
        );
    }
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/observability/destinations"))
            .and(wiremock::matchers::query_param("offset", "0"))
            .and(match_workspace(other_workspace))
            .respond_with(json_response(
                200,
                &page(vec![log_destination(
                    OTHER_FAKE_DESTINATION_ID,
                    "webhook",
                    "other",
                )]),
            ))
            .with_priority(1),
    );
    // Anything else — every second page — ends its listing.
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/observability/destinations"))
            .respond_with(json_response(200, &empty_page()))
            .with_priority(9),
    );

    let client = client(&server);
    let workspaces = [
        Uuid::parse(FAKE_WORKSPACE_ID).expect("a valid UUID"),
        Uuid::parse(other_workspace).expect("a valid UUID"),
    ];
    let destinations = Reader::new(&client)
        .list_log_destinations(&workspaces)
        .expect("the destinations");

    let identities: Vec<&str> = destinations
        .iter()
        .map(|destination| destination.id.as_str())
        .collect();
    assert_eq!(
        identities,
        vec![FAKE_DESTINATION_ID, OTHER_FAKE_DESTINATION_ID],
        "one entry per identity, in identity order"
    );
    assert_eq!(destinations[0].kind, "datadog");
    assert!(
        destinations[0].api_key_hashes.is_empty(),
        "a `null` allowlist is the empty one Keymaster manages"
    );
}

/// Matches the `workspace_id` query parameter, or its absence for `""`.
fn match_workspace(workspace: &str) -> impl wiremock::Match + use<> {
    let expected = workspace.to_owned();
    move |request: &wiremock::Request| {
        let found = request
            .url
            .query_pairs()
            .find(|(name, _)| name == "workspace_id")
            .map(|(_, value)| value.into_owned());
        found.unwrap_or_default() == expected
    }
}

#[test]
fn a_destination_whose_identity_or_sampling_rate_cannot_be_read_fails_the_snapshot() {
    for (description, mut record) in [
        (
            "an unusable id",
            log_destination("not-a-uuid", "datadog", "audit"),
        ),
        (
            "a sampling rate outside the documented range",
            log_destination(FAKE_DESTINATION_ID, "datadog", "audit"),
        ),
    ] {
        if description.starts_with("a sampling") {
            record["sampling_rate"] = json!(7.5);
        }
        let server = TestServer::start();
        server.mount(
            Mock::given(method("GET"))
                .and(path("/api/v1/observability/destinations"))
                .respond_with(json_response(200, &page(vec![record]))),
        );

        let client = client(&server);
        let error = Reader::new(&client)
            .list_log_destinations(&[])
            .expect_err(description);
        assert_eq!(error.kind(), "invalid_response", "{description}");
    }
}

// --- the three reads a spend report is made of ------------------------------

#[test]
fn credits_and_meta_are_read_from_their_own_endpoints() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/credits"))
            .respond_with(json_response(
                200,
                // The extra field is what a future release adds; an unknown one
                // must never stop a read.
                &json!({ "data": { "total_credits": 100.5, "total_usage": 25.75, "plan": "team" } }),
            )),
    );
    server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/analytics/meta"))
            .respond_with(json_response(
                200,
                &json!({
                    "data": {
                        "metrics": [
                            { "name": "total_usage", "display_label": "Total usage" },
                            { "name": "tokens_total", "display_label": "Tokens" },
                        ],
                        "dimensions": [{ "name": "api_key_id", "display_label": "API key" }],
                        "operators": [{ "name": "eq", "value_type": "scalar" }],
                        "granularities": [{ "name": "day", "display_label": "Day" }],
                    }
                }),
            )),
    );

    let client = client(&server);
    let reader = Reader::new(&client);

    let credits = reader.credits().expect("the balance");
    assert!((credits.total_credits - 100.5).abs() < f64::EPSILON);
    assert!((credits.total_usage - 25.75).abs() < f64::EPSILON);

    let meta = reader.analytics_meta().expect("the vocabulary");
    assert_eq!(
        meta.first_metric(&["total_usage", "credits_usage"]),
        Some("total_usage")
    );
    assert_eq!(meta.first_dimension(&["api_key_id"]), Some("api_key_id"));
    assert!(!meta.has_dimension("workspace"));
}

#[test]
fn an_analytics_query_is_one_post_whose_body_says_what_was_asked() {
    let server = TestServer::start();
    server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/analytics/query"))
            .respond_with(json_response(
                200,
                &json!({
                    "data": {
                        "data": [{
                            "date__day": "2026-08-01T00:00:00.000Z",
                            "api_key_id": "golf-jobfeed",
                            "total_usage": 1.5,
                            "tokens_total": "1200",
                        }],
                        "metadata": { "query_time_ms": 42, "row_count": 1, "truncated": true },
                        "warnings": ["one filter value could not be resolved"],
                    }
                }),
            )),
    );

    let client = client(&server);
    let answered = Reader::new(&client)
        .analytics_query(&AnalyticsQuery {
            metrics: vec!["total_usage".to_owned(), "tokens_total".to_owned()],
            dimensions: vec!["api_key_id".to_owned()],
            filters: vec![AnalyticsFilter {
                field: "workspace".to_owned(),
                operator: "eq".to_owned(),
                value: FAKE_WORKSPACE_ID.to_owned(),
            }],
            granularity: "day".to_owned(),
            start: OffsetDateTime::from_unix_timestamp(1_785_542_400).expect("a start"),
            end: OffsetDateTime::from_unix_timestamp(1_785_628_800).expect("an end"),
        })
        .expect("an answer");

    server.assert_request_count(1);
    let sent: Value = serde_json::from_slice(&server.request(0).body).expect("a JSON request body");
    assert_eq!(sent["metrics"], json!(["total_usage", "tokens_total"]));
    assert_eq!(sent["dimensions"], json!(["api_key_id"]));
    assert_eq!(sent["granularity"], "day");
    assert_eq!(
        sent["filters"],
        json!([{ "field": "workspace", "operator": "eq", "value": FAKE_WORKSPACE_ID }])
    );
    assert_eq!(sent["time_range"]["start"], "2026-08-01T00:00:00Z");
    assert_eq!(sent["time_range"]["end"], "2026-08-02T00:00:00Z");

    assert!(answered.metadata_present);
    assert!(answered.truncated);
    assert_eq!(answered.warnings.len(), 1);
    let row = answered.rows.first().expect("one row");
    assert_eq!(row.dimension("api_key_id"), Some("golf-jobfeed"));
    assert_eq!(row.period(), Some("2026-08-01T00:00:00.000Z"));
    assert!((row.metric("total_usage") - 1.5).abs() < f64::EPSILON);
    assert!(
        (row.metric("tokens_total") - 1200.0).abs() < f64::EPSILON,
        "an integral metric arrives quoted and is still a number"
    );
}
