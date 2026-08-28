//! `spend`: what OpenRouter says the organization and each key have spent.
//!
//! A read-only operation in the strictest sense. It takes no lock, writes no
//! state, and makes no request that changes anything: three reads, one of which
//! is a `POST` because an analytics question does not fit a query string.
//!
//! Two things about the OpenRouter analytics API decide the shape of this.
//!
//! The vocabulary is not documented. The specification describes the shape of a
//! query — metrics, dimensions, filters, a granularity, a time range — and
//! names no metric or dimension at all; `GET /analytics/meta` is where they
//! come from. The names below were read from a real organization's meta rather
//! than inferred, and each list is still a list: Keymaster asks the meta which
//! of the names it has, in preference order, and refuses with
//! `invalid_response` when it has none of them, naming what it looked for.
//!
//! And a grouped row does not carry a key hash. OpenRouter documents several
//! dimensions as *enriched* — returned as a human-readable label rather than
//! the underlying identifier — with `api_key_id` among them, and a live
//! organization confirms it: a grouped query answers with the key's **display
//! name**, while a *filter* on the same dimension takes the numeric id or the
//! 64-character hash. So the value a row carries is reported exactly as it
//! arrived and never treated as an identity.
//!
//! A local address is attached only in the rare case where that value happens
//! to be a hash some address already tracks. The mapping stays because it costs
//! one lookup of state that is read anyway, but most rows will carry no
//! address, and a row without one is not an unmanaged key.

use time::OffsetDateTime;

use super::{Context, Outcome};
use crate::api::{AnalyticsFilter, AnalyticsMeta, AnalyticsQuery, Reader};
use crate::client::ApiError;
use crate::error::Error;
use crate::report::{SpendObservation, SpendReport};
use crate::state::StateFile;

/// The cost metric names Keymaster knows, best first.
///
/// `total_usage` is the whole cost of the traffic — inference paid for with
/// credits plus the credit-equivalent of BYOK usage and its fees — which is the
/// number a spend report is about. `credits_usage` counts only what came out of
/// the credit balance and `openrouter_usage` only OpenRouter's own share, so
/// each is a narrower answer and each is a fallback rather than a preference.
const COST_METRICS: [&str; 3] = ["total_usage", "credits_usage", "openrouter_usage"];

/// The token metric names Keymaster knows, best first.
///
/// One name, because that is what OpenRouter offers: `tokens_total` is prompt
/// plus completion. The per-direction metrics beside it — `tokens_prompt`,
/// `tokens_completion`, `reasoning_tokens`, `cached_tokens` — are a breakdown
/// this report deliberately does not ask for.
const TOKEN_METRICS: [&str; 1] = ["tokens_total"];

/// The api-key dimension names Keymaster knows, best first.
///
/// One name, like the token metric: `api_key_id` is what OpenRouter lists, and
/// a fallback spelling nothing has ever answered to would be a guess dressed as
/// a compatibility measure.
const KEY_DIMENSIONS: [&str; 1] = ["api_key_id"];

/// The dimension a scoped run filters on.
const WORKSPACE_DIMENSION: &str = "workspace";

/// The operator every filter Keymaster sends uses.
const EQUALS: &str = "eq";

/// How a spend report buckets time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    Day,
    Week,
    Month,
}

impl Granularity {
    /// The name `POST /analytics/query` takes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
        }
    }
}

/// What one spend report covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendQuery {
    /// The start of the range, inclusive.
    pub start: OffsetDateTime,
    /// The end of the range, exclusive.
    pub end: OffsetDateTime,
    /// The size of each bucket inside the range.
    pub granularity: Granularity,
}

/// The three names this run found in the meta and asked its query in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Columns {
    key_dimension: &'static str,
    cost_metric: &'static str,
    tokens_metric: &'static str,
}

impl Columns {
    /// Picks the names from what this organization's analytics offers.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::InvalidResponse`] naming every quantity the meta
    /// listed no spelling of. Failing here rather than sending the query is
    /// what turns a silently empty report into an answerable complaint.
    fn of(meta: &AnalyticsMeta) -> Result<Self, ApiError> {
        let cost = meta.first_metric(&COST_METRICS);
        let tokens = meta.first_metric(&TOKEN_METRICS);
        let key = meta.first_dimension(&KEY_DIMENSIONS);

        let missing: Vec<String> = [
            (cost, "a cost metric", COST_METRICS.as_slice()),
            (tokens, "a token metric", TOKEN_METRICS.as_slice()),
            (key, "an api-key dimension", KEY_DIMENSIONS.as_slice()),
        ]
        .into_iter()
        .filter(|(found, _, _)| found.is_none())
        .map(|(_, what, candidates)| format!("{what} (looked for {})", quoted(candidates)))
        .collect();

        match (cost, tokens, key) {
            (Some(cost_metric), Some(tokens_metric), Some(key_dimension)) => Ok(Self {
                key_dimension,
                cost_metric,
                tokens_metric,
            }),
            _ => Err(ApiError::InvalidResponse {
                message: format!(
                    "`GET /analytics/meta` lists no {missing}, so this organization's analytics \
                     cannot answer a spend report",
                    missing = missing.join(", and no ")
                )
                .into(),
            }),
        }
    }
}

/// Candidate names, as a message quotes them.
fn quoted(candidates: &[&str]) -> String {
    candidates
        .iter()
        .map(|candidate| format!("`{candidate}`"))
        .collect::<Vec<String>>()
        .join(", ")
}

/// Reports the organization's balance and each key's cost over a range.
///
/// State is read — without the writer lock, like every other read-only
/// operation — for one purpose only: turning a returned key identifier into
/// the local address that owns it, when the identifier happens to be a tracked
/// hash. Nothing about a row changes what state says.
///
/// # Errors
///
/// Returns [`ApiError::Invariant`] for a range that does not start before it
/// ends, the state and API errors of the reads it makes, `missing_credential`
/// when the context carries no credential, and `invalid_response` when this
/// organization's analytics lists none of the metric or dimension names a spend
/// report is made of.
pub fn spend(context: Context, query: SpendQuery) -> Result<Outcome<SpendReport>, Error> {
    if query.start >= query.end {
        return Err(ApiError::invariant(
            "a spend range must start before it ends; check `--since` and `--until`",
        )
        .into());
    }

    // Local and cheap first, exactly as the other read-only commands order it:
    // a state file that cannot be read stops the run before a credential is
    // sent anywhere.
    let state = StateFile::new(&context.paths.state).read()?;

    let client = context.client()?;
    let reader = Reader::new(&client);
    let credits = reader.credits()?;
    let meta = reader.analytics_meta()?;
    let columns = Columns::of(&meta)?;

    let mut warnings = Vec::new();
    let filters = scope_filter(&context, &meta, &mut warnings);
    let result = reader.analytics_query(&AnalyticsQuery {
        metrics: vec![
            columns.cost_metric.to_owned(),
            columns.tokens_metric.to_owned(),
        ],
        dimensions: vec![columns.key_dimension.to_owned()],
        filters,
        granularity: query.granularity.as_str().to_owned(),
        start: query.start,
        end: query.end,
    })?;

    Ok(Outcome::ok(SpendReport::new(SpendObservation {
        start: query.start,
        end: query.end,
        granularity: query.granularity.as_str(),
        credits: &credits,
        key_dimension: columns.key_dimension,
        cost_metric: columns.cost_metric,
        tokens_metric: columns.tokens_metric,
        result: &result,
        state: &state,
        warnings,
    })))
}

/// The workspace filter a scoped run adds, when the analytics API has one.
///
/// A scope that cannot be expressed as a filter is reported rather than
/// silently dropped: the numbers would then be the whole organization's, which
/// is a different question from the one that was asked.
fn scope_filter(
    context: &Context,
    meta: &AnalyticsMeta,
    warnings: &mut Vec<String>,
) -> Vec<AnalyticsFilter> {
    let Some(workspace) = context.scope() else {
        return Vec::new();
    };
    if !meta.has_dimension(WORKSPACE_DIMENSION) {
        warnings.push(format!(
            "this run is scoped to workspace {workspace}, but `GET /analytics/meta` lists no \
             `{WORKSPACE_DIMENSION}` dimension to filter on, so this report covers the whole \
             organization"
        ));
        return Vec::new();
    }
    vec![AnalyticsFilter {
        field: WORKSPACE_DIMENSION.to_owned(),
        operator: EQUALS.to_owned(),
        value: workspace.as_str().to_owned(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(metrics: &[&str], dimensions: &[&str]) -> AnalyticsMeta {
        AnalyticsMeta {
            metrics: metrics.iter().copied().map(str::to_owned).collect(),
            dimensions: dimensions.iter().copied().map(str::to_owned).collect(),
        }
    }

    #[test]
    fn the_columns_are_the_first_spelling_the_meta_lists() {
        let columns = Columns::of(&meta(
            &[
                "request_count",
                "total_usage",
                "credits_usage",
                "tokens_total",
            ],
            &["api_key_id", "model"],
        ))
        .expect("a usable vocabulary");

        assert_eq!(columns.cost_metric, "total_usage");
        assert_eq!(columns.tokens_metric, "tokens_total");
        assert_eq!(columns.key_dimension, "api_key_id");
    }

    #[test]
    fn a_meta_missing_a_quantity_names_what_it_looked_for() {
        let failure = Columns::of(&meta(&["total_usage"], &["api_key_id"]))
            .expect_err("a meta with no token metric cannot answer this");

        assert_eq!(failure.kind(), "invalid_response");
        let message = failure.to_string();
        assert!(message.contains("a token metric"), "{message}");
        assert!(message.contains("`tokens_total`"), "{message}");
        assert!(!message.contains("a cost metric"), "{message}");
    }
}
