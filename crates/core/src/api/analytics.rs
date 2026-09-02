//! The three read-only endpoints a spend report is made of.
//!
//! `GET /credits` is the organization's balance. `GET /analytics/meta` is the
//! vocabulary one organization's analytics accepts, and it is the reason this
//! module exists at all: OpenRouter's specification documents the *shape* of an
//! analytics query and not one metric or dimension name, so the names are
//! discovered rather than assumed, and a report is built only from names the
//! meta lists. `POST /analytics/query` answers the question.
//!
//! Rows are typed loosely on purpose. The specification says a row is "an
//! object with metric/dimension values" and nothing more, so a row is read as
//! the metrics that were asked for, as numbers, and everything else as text.
//! What a row *means* is decided where the report is built.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use super::{Reader, wire};
use crate::client::ApiError;

/// The prefix OpenRouter puts on a row's time bucket: `date__day` at a daily
/// granularity, `date__week` at a weekly one, and so on.
const PERIOD_PREFIX: &str = "date__";

/// What the organization has bought and what it has spent.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Credits {
    /// Total credits purchased, in dollars.
    pub total_credits: f64,
    /// Total credits used, in dollars.
    pub total_usage: f64,
}

/// The metric and dimension names one organization's analytics accepts.
///
/// Only the two vocabularies a spend report needs are kept. Granularities and
/// filter operators are in the response too and are deliberately not modelled:
/// nothing here would decide anything from them, and a field nothing reads is
/// a field that goes stale.
///
/// The two sets are `pub(crate)` rather than private so an operation's own
/// tests can state a vocabulary directly; readers go through the methods.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyticsMeta {
    pub(crate) metrics: BTreeSet<String>,
    pub(crate) dimensions: BTreeSet<String>,
}

impl AnalyticsMeta {
    /// The first of `candidates` this organization offers as a metric.
    ///
    /// Candidates are ordered best first: the names are undocumented, so
    /// Keymaster knows several spellings of the same quantity and uses
    /// whichever one the meta actually lists.
    #[must_use]
    pub fn first_metric<'name>(&self, candidates: &[&'name str]) -> Option<&'name str> {
        first_listed(&self.metrics, candidates)
    }

    /// The first of `candidates` this organization offers as a dimension.
    #[must_use]
    pub fn first_dimension<'name>(&self, candidates: &[&'name str]) -> Option<&'name str> {
        first_listed(&self.dimensions, candidates)
    }

    /// Whether this organization groups and filters by `name`.
    #[must_use]
    pub fn has_dimension(&self, name: &str) -> bool {
        self.dimensions.contains(name)
    }
}

/// The first candidate `listed` contains.
fn first_listed<'name>(listed: &BTreeSet<String>, candidates: &[&'name str]) -> Option<&'name str> {
    candidates
        .iter()
        .copied()
        .find(|candidate| listed.contains(*candidate))
}

/// One analytics question.
///
/// Deliberately not a query language: a caller names the metrics and dimensions
/// it has already confirmed exist, the range, and the bucket size. Everything
/// the endpoint also accepts — classifiers, ordering, row limits — is left at
/// the server's default.
#[derive(Debug, Clone)]
pub struct AnalyticsQuery {
    /// Metric names, as `/analytics/meta` spells them.
    pub metrics: Vec<String>,
    /// Dimension names to group by, as `/analytics/meta` spells them.
    pub dimensions: Vec<String>,
    /// Filters, each on a dimension the meta lists.
    pub filters: Vec<AnalyticsFilter>,
    /// The time bucket: `day`, `week`, or `month`.
    pub granularity: String,
    /// The inclusive start of the range.
    pub start: OffsetDateTime,
    /// The exclusive end of the range.
    pub end: OffsetDateTime,
}

/// One filter on one dimension.
///
/// The value is a string because every filter Keymaster sends is an equality
/// test on an identifier. OpenRouter documents that a filter takes the
/// underlying id rather than the enriched label a response carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalyticsFilter {
    /// The dimension to filter on.
    pub field: String,
    /// The operator, as `/analytics/meta` spells it.
    pub operator: String,
    /// The identifier to match.
    pub value: String,
}

/// What one analytics query answered.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AnalyticsResult {
    /// The rows, in the order OpenRouter returned them.
    pub rows: Vec<AnalyticsRow>,
    /// Whether the provider explicitly supplied query metadata.
    ///
    /// A safety-sensitive caller must not infer completeness from absent
    /// metadata: only `metadata_present && !truncated` proves the provider
    /// represented the result as complete.
    pub metadata_present: bool,
    /// Whether OpenRouter stopped short of answering the whole question.
    pub truncated: bool,
    /// OpenRouter's own warnings about the query, such as a filter value it
    /// could not resolve. Free text it wrote, so it is scrubbed before it is
    /// reported.
    pub warnings: Vec<String>,
}

/// One row: the metrics that were asked for, and the values that identify them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AnalyticsRow {
    /// Every field that is not a requested metric, as text.
    pub dimensions: BTreeMap<String, String>,
    /// Every requested metric that the row carried, as a number.
    pub metrics: BTreeMap<String, f64>,
}

impl AnalyticsRow {
    /// The value of one dimension, when the row carries it.
    #[must_use]
    pub fn dimension(&self, name: &str) -> Option<&str> {
        self.dimensions.get(name).map(String::as_str)
    }

    /// One metric's value, or zero for a row that omitted it.
    ///
    /// Zero rather than `None` because a bucket with no spend and a bucket
    /// OpenRouter left out of the row are the same fact, and reporting them
    /// differently would suggest a distinction there is no evidence for.
    #[must_use]
    pub fn metric(&self, name: &str) -> f64 {
        self.metrics.get(name).copied().unwrap_or(0.0)
    }

    /// The row's time bucket, whatever the granularity spells it.
    #[must_use]
    pub fn period(&self) -> Option<&str> {
        self.dimensions
            .iter()
            .find(|(name, _)| name.starts_with(PERIOD_PREFIX))
            .map(|(_, value)| value.as_str())
    }

    /// Reads one row, sorting its fields by what was asked for.
    ///
    /// A field named in `metrics` is a number; anything else identifies the
    /// row and is kept as text, because a dimension value may be a label, a
    /// hash, or a numeric id and only OpenRouter knows which.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::InvalidResponse`] naming the field when a requested
    /// metric is neither a number nor a string holding one.
    fn from_value(value: &Value, metrics: &[String]) -> Result<Self, ApiError> {
        let mut row = Self::default();
        let Some(fields) = value.as_object() else {
            return Ok(row);
        };
        for (name, field) in fields {
            if metrics.iter().any(|metric| metric == name) {
                row.metrics.insert(name.clone(), as_number(name, field)?);
            } else if let Some(text) = as_text(field) {
                row.dimensions.insert(name.clone(), text);
            }
        }
        Ok(row)
    }
}

/// A metric value, as OpenRouter actually sends one.
///
/// Both spellings arrive in the same row: a fractional metric is a JSON number
/// (`"total_usage": 12.284044`) and an integral one is a quoted string
/// (`"tokens_total": "18993032"`), so both are read as the number they are.
///
/// Anything else fails the read rather than defaulting. A metric that silently
/// became zero would be reported as "this key used no tokens" beside a real
/// cost — a wrong answer that looks like a right one, which is the one outcome
/// a spend report must never produce.
fn as_number(name: &str, value: &Value) -> Result<f64, ApiError> {
    let read = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    };
    read.filter(|number: &f64| number.is_finite())
        .ok_or_else(|| ApiError::InvalidResponse {
            message: format!(
                "an analytics row carries `{name}` as {kind}, and a metric is read only as a                  number or a string holding one",
                kind = kind_of(value)
            )
            .into(),
        })
}

/// What a value is, for a message that must not quote what it holds.
const fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number this build cannot read",
        Value::String(_) => "a string that is not a number",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// A dimension value as text, or nothing for a value that identifies nothing.
fn as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// The request body, as `POST /analytics/query` takes it.
#[derive(Debug, Serialize)]
struct QueryBody<'query> {
    metrics: &'query [String],
    dimensions: &'query [String],
    #[serde(skip_serializing_if = "<[AnalyticsFilter]>::is_empty")]
    filters: &'query [AnalyticsFilter],
    granularity: &'query str,
    time_range: TimeRange,
}

/// The range, RFC 3339 at both ends.
#[derive(Debug, Serialize)]
struct TimeRange {
    #[serde(with = "time::serde::rfc3339")]
    start: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    end: OffsetDateTime,
}

impl Reader<'_> {
    /// What the organization has purchased and used, in dollars.
    ///
    /// # Errors
    ///
    /// Returns the client's errors.
    pub fn credits(&self) -> Result<Credits, ApiError> {
        let one: wire::One<wire::Credits> = self.client.get_json(&["credits"], &[])?;
        Ok(Credits {
            total_credits: one.data.total_credits,
            total_usage: one.data.total_usage,
        })
    }

    /// The metric and dimension names this organization's analytics accepts.
    ///
    /// # Errors
    ///
    /// Returns the client's errors.
    pub fn analytics_meta(&self) -> Result<AnalyticsMeta, ApiError> {
        let one: wire::One<wire::AnalyticsMeta> =
            self.client.get_json(&["analytics", "meta"], &[])?;
        Ok(AnalyticsMeta {
            metrics: one.data.metrics.into_iter().map(|item| item.name).collect(),
            dimensions: one
                .data
                .dimensions
                .into_iter()
                .map(|item| item.name)
                .collect(),
        })
    }

    /// Runs one analytics query.
    ///
    /// A `POST` that reads: the question does not fit a query string, so it
    /// travels in a body. It therefore goes down the write path and is sent
    /// exactly once with no retry — which for a read costs a report rather
    /// than a duplicated write.
    ///
    /// # Errors
    ///
    /// Returns the client's errors.
    pub fn analytics_query(&self, query: &AnalyticsQuery) -> Result<AnalyticsResult, ApiError> {
        let body = QueryBody {
            metrics: &query.metrics,
            dimensions: &query.dimensions,
            filters: &query.filters,
            granularity: &query.granularity,
            time_range: TimeRange {
                start: query.start,
                end: query.end,
            },
        };
        let answered: wire::One<wire::Analytics> =
            self.client.post_json_once(&["analytics", "query"], &body)?;
        Ok(AnalyticsResult {
            rows: answered
                .data
                .data
                .iter()
                .map(|row| AnalyticsRow::from_value(row, &query.metrics))
                .collect::<Result<Vec<AnalyticsRow>, ApiError>>()?,
            metadata_present: answered.data.metadata.is_some(),
            truncated: answered.data.metadata.is_some_and(|meta| meta.truncated),
            warnings: answered.data.warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta() -> AnalyticsMeta {
        AnalyticsMeta {
            metrics: ["total_usage", "credits_usage", "tokens_total"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            dimensions: ["api_key_id", "model"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    #[test]
    fn the_first_listed_candidate_wins() {
        assert_eq!(
            meta().first_metric(&["credits_usage", "total_usage"]),
            Some("credits_usage"),
            "the caller's order decides, not the meta's"
        );
        assert_eq!(meta().first_metric(&["requests"]), None);
        assert_eq!(
            meta().first_dimension(&["api_key", "api_key_id"]),
            Some("api_key_id")
        );
        assert!(meta().has_dimension("model"));
        assert!(!meta().has_dimension("workspace"));
    }

    #[test]
    fn a_row_separates_requested_metrics_from_everything_else() {
        let metrics = vec!["total_usage".to_owned(), "tokens_total".to_owned()];
        // The shape a real organization answers with: a fractional metric as a
        // JSON number, an integral one quoted.
        let row = AnalyticsRow::from_value(
            &json!({
                "date__month": "2026-08-01",
                "api_key_id": "mac-secrets",
                "total_usage": 12.284044,
                "tokens_total": "18993032",
                "model": null,
            }),
            &metrics,
        )
        .expect("a readable row");

        assert_eq!(row.metric("total_usage"), 12.284_044);
        assert_eq!(
            row.metric("tokens_total"),
            18_993_032.0,
            "a quoted integer is the number it holds, not text"
        );
        assert_eq!(row.metric("absent"), 0.0);
        assert_eq!(row.dimension("api_key_id"), Some("mac-secrets"));
        assert_eq!(row.period(), Some("2026-08-01"));
        assert_eq!(row.dimension("model"), None, "a null identifies nothing");
    }

    #[test]
    fn a_metric_that_is_not_a_number_fails_the_read_rather_than_reading_zero() {
        let metrics = vec!["tokens_total".to_owned()];
        for unreadable in [json!(null), json!("many"), json!(true), json!([1])] {
            let failure =
                AnalyticsRow::from_value(&json!({ "tokens_total": unreadable }), &metrics)
                    .expect_err("a metric that cannot be read is not zero");

            assert_eq!(failure.kind(), "invalid_response");
            let message = failure.to_string();
            assert!(message.contains("`tokens_total`"), "{message}");
        }
    }

    #[test]
    fn a_numeric_identifier_is_kept_as_text() {
        let row =
            AnalyticsRow::from_value(&json!({ "api_key_id": 4321 }), &["total_usage".to_owned()])
                .expect("a readable row");
        assert_eq!(row.dimension("api_key_id"), Some("4321"));
    }
}
