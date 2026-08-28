//! Binary-level tests for `openrouter-keymaster spend`.
//!
//! Spend is the one command that asks OpenRouter a question instead of
//! describing what it manages, so what these cases assert is mostly about the
//! three requests it makes: that the query says what the report claims it says,
//! that a vocabulary the organization does not have is refused before the query
//! is sent, and that the run stays read-only — one `POST`, which is the
//! analytics query, and not a byte written to state.

mod support;

use std::fs;

use serde_json::{Value, json};
use support::fixtures::FAKE_WORKSPACE_ID;
use support::http::json_response;
use support::project::{Project, address, at, hash};
use support::sentinel::SECRET_SENTINEL_KEY;
use wiremock::Mock;
use wiremock::matchers::{method, path};

/// Spend reads no configuration, so this is only what a project directory has.
const CONFIG: &str = "version = 1\n";

const JOBFEED_HASH: &str = "hash-jobfeed-1";
const START: &str = "2026-08-01T00:00:00Z";
const END: &str = "2026-08-03T00:00:00Z";

/// The vocabulary a real organization's analytics offers, trimmed to the names
/// that decide anything here.
const METRICS: [&str; 5] = [
    "request_count",
    "total_usage",
    "credits_usage",
    "tokens_total",
    "tokens_prompt",
];
const DIMENSIONS: [&str; 2] = ["api_key_id", "model"];

/// A project whose server answers the three reads a spend report makes.
fn project_with(rows: Vec<Value>, dimensions: &[&str]) -> Project {
    let project = Project::new(CONFIG);
    mount_credits(&project, 100.5, 25.75);
    mount_meta(&project, &METRICS, dimensions);
    mount_query(&project, &answer(rows, false, &[]));
    project
}

fn mount_credits(project: &Project, purchased: f64, used: f64) {
    project.server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/credits"))
            .respond_with(json_response(
                200,
                &json!({ "data": { "total_credits": purchased, "total_usage": used } }),
            )),
    );
}

fn mount_meta(project: &Project, metrics: &[&str], dimensions: &[&str]) {
    let named = |names: &[&str]| -> Vec<Value> {
        names
            .iter()
            .map(|name| json!({ "name": name, "display_label": name }))
            .collect()
    };
    project.server.mount(
        Mock::given(method("GET"))
            .and(path("/api/v1/analytics/meta"))
            .respond_with(json_response(
                200,
                &json!({
                    "data": {
                        "metrics": named(metrics),
                        "dimensions": named(dimensions),
                        "operators": [{ "name": "eq", "value_type": "scalar" }],
                        "granularities": [{ "name": "day", "display_label": "Day" }],
                    }
                }),
            )),
    );
}

fn mount_query(project: &Project, body: &Value) {
    project.server.mount(
        Mock::given(method("POST"))
            .and(path("/api/v1/analytics/query"))
            .respond_with(json_response(200, body)),
    );
}

/// One `POST /analytics/query` answer, shaped as the API documents it.
fn answer(rows: Vec<Value>, truncated: bool, warnings: &[&str]) -> Value {
    let count = rows.len();
    json!({
        "data": {
            "data": rows,
            "metadata": { "query_time_ms": 42, "row_count": count, "truncated": truncated },
            "warnings": warnings,
        }
    })
}

/// One row of the answer, shaped as a real organization returns one.
///
/// The two metrics are typed differently on the wire and that is not a
/// mistake in the fixture: OpenRouter sends a fractional metric as a JSON
/// number and an integral one as a quoted string, so a harness that sent both
/// as numbers would pass while the real thing reported no tokens at all.
fn row(day: &str, key: &str, cost: f64, tokens: u64) -> Value {
    json!({
        "date__day": day,
        "api_key_id": key,
        "total_usage": cost,
        "tokens_total": tokens.to_string(),
        "request_count": "3",
    })
}

/// The body of the one analytics query the run sent.
fn query_body(project: &Project) -> Value {
    let requests = project.server.requests();
    let sent = requests
        .iter()
        .find(|request| request.method == "POST")
        .expect("the analytics query was sent");
    serde_json::from_slice(&sent.body).expect("a JSON request body")
}

/// The arguments every case that fixes its own range passes.
fn over_the_range<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut arguments = vec!["spend", "--since", START, "--until", END];
    arguments.extend_from_slice(extra);
    arguments
}

/// The same range, as a `--json` run.
fn json_over_the_range() -> Vec<&'static str> {
    let mut arguments = vec!["--json"];
    arguments.extend(over_the_range(&[]));
    arguments
}

#[test]
fn the_run_reads_credits_then_meta_then_asks_one_query() {
    let project = project_with(
        vec![row("2026-08-01T00:00:00.000Z", "golf-jobfeed", 1.5, 1200)],
        &DIMENSIONS,
    );
    project.write_state(|_| {});
    let before = fs::read(project.state_path()).expect("the state fixture");

    let streams = project.succeed(&over_the_range(&[]));

    assert_eq!(
        project.request_trace(),
        vec![
            "GET /api/v1/credits".to_owned(),
            "GET /api/v1/analytics/meta".to_owned(),
            "POST /api/v1/analytics/query".to_owned(),
        ]
    );
    assert_eq!(
        project.write_trace(),
        vec!["POST /api/v1/analytics/query".to_owned()],
        "the analytics query is the only non-GET a read-only command makes"
    );

    let body = query_body(&project);
    assert_eq!(body["metrics"], json!(["total_usage", "tokens_total"]));
    assert_eq!(body["dimensions"], json!(["api_key_id"]));
    assert_eq!(body["granularity"], "day");
    assert_eq!(body["time_range"]["start"], START);
    assert_eq!(body["time_range"]["end"], END);
    assert_eq!(
        body.get("filters"),
        None,
        "an unscoped run filters on nothing: {body}"
    );

    assert!(
        streams
            .out
            .contains("credits: purchased 100.500000, used 25.750000"),
        "{}",
        streams.out
    );
    assert_eq!(
        fs::read(project.state_path()).expect("the state file"),
        before,
        "spend writes no state"
    );
}

#[test]
fn the_granularity_travels_to_the_query_and_the_report() {
    let project = project_with(Vec::new(), &DIMENSIONS);

    let streams = project.succeed(&over_the_range(&["--granularity", "month"]));

    assert_eq!(query_body(&project)["granularity"], "month");
    assert!(streams.out.contains("by month"), "{}", streams.out);
    assert!(
        streams.out.contains("(nothing was spent in this range)"),
        "{}",
        streams.out
    );
}

#[test]
fn an_omitted_range_is_the_last_thirty_days() {
    let project = project_with(Vec::new(), &DIMENSIONS);

    project.succeed(&["spend"]);

    let body = query_body(&project);
    let start = time::OffsetDateTime::parse(
        body["time_range"]["start"].as_str().expect("a start"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("an RFC 3339 start");
    let end = time::OffsetDateTime::parse(
        body["time_range"]["end"].as_str().expect("an end"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("an RFC 3339 end");
    assert_eq!(end - start, time::Duration::days(30));
}

#[test]
fn a_meta_missing_a_metric_stops_the_run_before_the_query() {
    let project = Project::new(CONFIG);
    mount_credits(&project, 10.0, 1.0);
    mount_meta(
        &project,
        &["request_count", "total_usage", "credits_usage"],
        &DIMENSIONS,
    );
    mount_query(&project, &answer(Vec::new(), false, &[]));

    let streams = project.fail(&["--json", "spend", "--since", START, "--until", END]);

    let diagnostic = streams.diagnostic();
    assert_eq!(diagnostic["error"]["kind"], "invalid_response");
    let message = diagnostic["error"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(message.contains("a token metric"), "{message}");
    assert!(message.contains("`tokens_total`"), "{message}");
    assert!(
        project.write_trace().is_empty(),
        "a vocabulary this organization does not have is refused before the query: {:?}",
        project.request_trace()
    );
}

#[test]
fn a_tracked_hash_carries_its_address_and_an_unknown_identifier_does_not() {
    let project = project_with(
        vec![
            row("2026-08-01T00:00:00.000Z", JOBFEED_HASH, 1.5, 1200),
            row("2026-08-02T00:00:00.000Z", JOBFEED_HASH, 0.25, 300),
            row("2026-08-02T00:00:00.000Z", "Someone else's key", 4.0, 90),
        ],
        &DIMENSIONS,
    );
    project.write_state(|state| {
        state
            .bind_key(&address("jobfeed"), hash(JOBFEED_HASH), 1, at(0))
            .expect("binding the key");
    });

    let document = project.succeed(&json_over_the_range()).document();

    assert_eq!(document["command"], "spend");
    assert_eq!(document["credits"]["remaining"], json!(74.75));
    assert_eq!(document["granularity"], "day");
    assert_eq!(document["columns"]["cost_metric"], "total_usage");
    assert_eq!(document["columns"]["tokens_metric"], "tokens_total");

    let rows = document["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2, "one row per key identifier: {document}");

    let tracked = rows
        .iter()
        .find(|entry| entry["key"] == JOBFEED_HASH)
        .expect("the tracked key");
    assert_eq!(tracked["address"], "keys.jobfeed");
    assert_eq!(tracked["cost_usd"], json!(1.75));
    assert_eq!(tracked["tokens"], json!(1500.0));
    assert_eq!(tracked["periods"].as_array().expect("periods").len(), 2);
    assert_eq!(tracked["periods"][0]["start"], "2026-08-01T00:00:00.000Z");
    assert_eq!(tracked["periods"][1]["cost_usd"], json!(0.25));

    let untracked = rows
        .iter()
        .find(|entry| entry["key"] == "Someone else's key")
        .expect("the identifier OpenRouter returned, reported as it arrived");
    assert_eq!(
        untracked.get("address"),
        None,
        "an identifier no address tracks carries none: {untracked}"
    );

    let human = project.succeed(&over_the_range(&[])).out;
    assert!(human.contains("keys.jobfeed"), "{human}");
    assert!(human.contains("(no local address)"), "{human}");
}

#[test]
fn a_row_openrouter_attributed_to_no_key_is_reported_as_unattributed() {
    let project = project_with(
        vec![json!({
            "date__day": "2026-08-01T00:00:00.000Z",
            "api_key_id": Value::Null,
            "total_usage": 0.5,
            "tokens_total": "40",
        })],
        &DIMENSIONS,
    );

    let human = project.succeed(&over_the_range(&[])).out;

    assert!(human.contains("(unattributed)"), "{human}");
}

#[test]
fn a_key_named_like_the_unattributed_placeholder_stays_its_own_row() {
    let project = project_with(
        vec![
            json!({
                "date__day": "2026-08-01T00:00:00.000Z",
                "api_key_id": Value::Null,
                "total_usage": 0.5,
                "tokens_total": "40",
            }),
            row("2026-08-01T00:00:00.000Z", "(unattributed)", 2.0, 90),
        ],
        &DIMENSIONS,
    );

    let document = project.succeed(&json_over_the_range()).document();

    let rows = document["rows"].as_array().expect("rows");
    assert_eq!(
        rows.len(),
        2,
        "the placeholder is a rendering, not an identifier: {document}"
    );
    let costs: Vec<Value> = rows.iter().map(|entry| entry["cost_usd"].clone()).collect();
    assert!(
        costs.contains(&json!(0.5)) && costs.contains(&json!(2.0)),
        "{document}"
    );
}

#[test]
fn two_labels_that_render_alike_are_still_two_keys() {
    // Both identifiers scrub to the same text, because `redact` replaces every
    // credential-shaped token. Folding on the rendered form would report one
    // club's spend as the other's.
    let project = project_with(
        vec![
            row(
                "2026-08-01T00:00:00.000Z",
                &format!("club {SECRET_SENTINEL_KEY}-alpha"),
                1.0,
                10,
            ),
            row(
                "2026-08-01T00:00:00.000Z",
                &format!("club {SECRET_SENTINEL_KEY}-beta"),
                3.0,
                30,
            ),
        ],
        &DIMENSIONS,
    );

    let document = project.succeed(&json_over_the_range()).document();

    let rows = document["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2, "{document}");
    for entry in rows {
        assert_eq!(entry["key"], "club [redacted]", "{document}");
    }
    let costs: Vec<Value> = rows.iter().map(|entry| entry["cost_usd"].clone()).collect();
    assert!(
        costs.contains(&json!(1.0)) && costs.contains(&json!(3.0)),
        "{document}"
    );
}

#[test]
fn one_key_and_bucket_seen_twice_is_summed_not_overwritten() {
    let project = project_with(
        vec![
            row("2026-08-01T00:00:00.000Z", "golf-jobfeed", 1.0, 10),
            row("2026-08-01T00:00:00.000Z", "golf-jobfeed", 0.5, 5),
        ],
        &DIMENSIONS,
    );

    let document = project.succeed(&json_over_the_range()).document();

    let entry = &document["rows"][0];
    assert_eq!(entry["periods"].as_array().expect("periods").len(), 1);
    assert_eq!(entry["periods"][0]["cost_usd"], json!(1.5), "{document}");
    assert_eq!(entry["periods"][0]["tokens"], json!(15.0), "{document}");
    assert_eq!(entry["cost_usd"], json!(1.5), "{document}");
}

#[test]
fn a_metric_that_cannot_be_read_fails_the_run_instead_of_reporting_zero() {
    let project = Project::new(CONFIG);
    mount_credits(&project, 10.0, 1.0);
    mount_meta(&project, &METRICS, &DIMENSIONS);
    mount_query(
        &project,
        &answer(
            vec![json!({
                "date__day": "2026-08-01T00:00:00.000Z",
                "api_key_id": "mac-secrets",
                "total_usage": 12.284044,
                "tokens_total": "lots",
            })],
            false,
            &[],
        ),
    );

    let streams = project.fail(&["--json", "spend", "--since", START, "--until", END]);

    let diagnostic = streams.diagnostic();
    assert_eq!(diagnostic["error"]["kind"], "invalid_response");
    let message = diagnostic["error"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(
        message.contains("`tokens_total`"),
        "the unreadable metric is named: {message}"
    );
}

#[test]
fn a_scoped_run_filters_the_query_to_its_workspace() {
    let project = project_with(Vec::new(), &["api_key_id", "workspace"]);

    project.succeed(&{
        let mut arguments = vec!["--workspace", FAKE_WORKSPACE_ID];
        arguments.extend(over_the_range(&[]));
        arguments
    });

    assert_eq!(
        query_body(&project)["filters"],
        json!([{ "field": "workspace", "operator": "eq", "value": FAKE_WORKSPACE_ID }])
    );
}

#[test]
fn a_scope_the_analytics_api_cannot_express_warns_instead_of_dropping_it() {
    let project = project_with(Vec::new(), &DIMENSIONS);

    let streams = project.succeed(&{
        let mut arguments = vec!["--workspace", FAKE_WORKSPACE_ID];
        arguments.extend(over_the_range(&[]));
        arguments
    });

    assert_eq!(
        query_body(&project).get("filters"),
        None,
        "no filter is sent on a dimension the meta does not list"
    );
    assert!(
        streams.err.contains("warning:") && streams.err.contains("whole organization"),
        "a scope that could not be applied is said out loud: {}",
        streams.err
    );
}

#[test]
fn a_truncated_answer_says_the_rows_are_incomplete() {
    let project = Project::new(CONFIG);
    mount_credits(&project, 10.0, 1.0);
    mount_meta(&project, &METRICS, &DIMENSIONS);
    mount_query(
        &project,
        &answer(
            vec![row("2026-08-01T00:00:00.000Z", "golf-jobfeed", 1.0, 10)],
            true,
            &["the api_key_id filter value could not be resolved"],
        ),
    );

    let document = project.succeed(&json_over_the_range()).document();

    let warnings = document["warnings"].as_array().expect("warnings");
    assert_eq!(warnings.len(), 2, "{document}");
    assert!(
        warnings[0].as_str().expect("text").contains("truncated"),
        "{document}"
    );
    assert!(
        warnings[1]
            .as_str()
            .expect("text")
            .contains("could not be resolved"),
        "{document}"
    );
}

#[test]
fn text_openrouter_wrote_is_scrubbed_before_it_is_printed() {
    let project = Project::new(CONFIG);
    mount_credits(&project, 10.0, 1.0);
    mount_meta(&project, &METRICS, &DIMENSIONS);
    mount_query(
        &project,
        &answer(
            vec![row(
                "2026-08-01T00:00:00.000Z",
                &format!("pasted {SECRET_SENTINEL_KEY} into the label"),
                1.0,
                10,
            )],
            false,
            &[&format!("filter {SECRET_SENTINEL_KEY} was unresolvable")],
        ),
    );

    // `Project::succeed` scans stdout, stderr, and every file under the project
    // for the sentinel; this asserts what took its place.
    let streams = project.succeed(&over_the_range(&[]));

    assert!(streams.out.contains("[redacted]"), "{}", streams.out);
    assert!(streams.err.contains("[redacted]"), "{}", streams.err);
}

#[test]
fn an_inverted_range_is_refused_before_anything_is_read() {
    let project = project_with(Vec::new(), &DIMENSIONS);

    let streams = project.fail_silently(&["--json", "spend", "--since", END, "--until", START]);

    assert_eq!(streams.diagnostic()["error"]["kind"], "invariant");
    assert!(
        project.server.requests().is_empty(),
        "a range that cannot be answered costs no request: {:?}",
        project.request_trace()
    );
}

#[test]
fn a_since_that_is_not_a_timestamp_is_a_usage_error() {
    let project = Project::new(CONFIG);

    let output = project.run(&["spend", "--since", "yesterday"]);

    assert_eq!(output.status.code(), Some(2), "clap reports usage errors");
}
