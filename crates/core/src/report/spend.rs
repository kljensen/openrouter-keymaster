//! The `openrouter-keymaster spend` result document.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;
use time::OffsetDateTime;

use super::{money, scrubbed, timestamp};
use crate::api::{AnalyticsResult, Credits};
use crate::ids::KeyHash;
use crate::state::State;

/// What a row shows when OpenRouter attributed it to no key at all.
const UNATTRIBUTED: &str = "(unattributed)";

/// Everything a spend report is built from.
///
/// A struct rather than nine arguments, and it carries the three column names
/// as text because the vocabulary is discovered at runtime: the operation
/// picked them out of `GET /analytics/meta`, and the report has to say which
/// ones the numbers came from.
pub(crate) struct SpendObservation<'a> {
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
    pub granularity: &'static str,
    pub credits: &'a Credits,
    pub key_dimension: &'a str,
    pub cost_metric: &'a str,
    pub tokens_metric: &'a str,
    pub result: &'a AnalyticsResult,
    pub state: &'a State,
    pub warnings: Vec<String>,
}

/// The organization's balance, and what each API key cost over a range.
///
/// Spend proposes nothing and owns nothing. Every number here is OpenRouter's,
/// read fresh, and none of it is ever compared with a desired value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpendReport {
    /// Which command produced this document.
    command: &'static str,
    /// Diagnostics an operator should see. Human runs write these to stderr;
    /// under `--json` they travel here, because a stream carries exactly one
    /// document.
    warnings: Vec<String>,
    /// What the organization has bought and used, for all time.
    credits: CreditsReport,
    /// The range this report covers.
    range: RangeReport,
    /// The bucket each period in a row is.
    granularity: &'static str,
    /// The analytics vocabulary this run found and asked its question in.
    columns: ColumnsReport,
    /// One row per key identifier, in identifier order.
    rows: Vec<KeySpend>,
}

impl SpendReport {
    /// Builds the document from one balance and one analytics answer.
    #[must_use]
    pub(crate) fn new(observed: SpendObservation<'_>) -> Self {
        let rows = rows(&observed);
        let mut warnings = observed.warnings;
        if observed.result.truncated {
            warnings.push(
                "OpenRouter truncated this analytics answer, so the rows below are incomplete; \
                 narrow the range or widen the granularity"
                    .to_owned(),
            );
        }
        warnings.extend(observed.result.warnings.iter().map(|warning| {
            format!(
                "OpenRouter reported a problem with this query: {}",
                scrubbed(warning)
            )
        }));

        Self {
            command: "spend",
            warnings,
            credits: CreditsReport::new(observed.credits),
            range: RangeReport {
                start: timestamp(observed.start),
                end: timestamp(observed.end),
            },
            granularity: observed.granularity,
            columns: ColumnsReport {
                key_dimension: observed.key_dimension.to_owned(),
                cost_metric: observed.cost_metric.to_owned(),
                tokens_metric: observed.tokens_metric.to_owned(),
            },
            rows,
        }
    }

    /// The diagnostics that belong on stderr in a human run.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            self.credits.line(),
            format!(
                "range: {start} to {end} by {granularity}",
                start = self.range.start,
                end = self.range.end,
                granularity = self.granularity
            ),
            self.columns.line(),
            String::new(),
            format!(
                "keys ({count})  \u{2014} `key` is OpenRouter's own label for the key, not its \
                 hash:",
                count = self.rows.len()
            ),
        ];
        if self.rows.is_empty() {
            lines.push("  (nothing was spent in this range)".to_owned());
        }
        for row in &self.rows {
            lines.extend(row.lines());
        }
        lines
    }
}

impl fmt::Display for SpendReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lines().join("\n"))
    }
}

/// The organization's lifetime balance, as `GET /credits` reports it.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct CreditsReport {
    total_credits: f64,
    total_usage: f64,
    /// What is left: purchased less used, which OpenRouter does not report.
    remaining: f64,
}

impl CreditsReport {
    fn new(credits: &Credits) -> Self {
        Self {
            total_credits: credits.total_credits,
            total_usage: credits.total_usage,
            remaining: credits.total_credits - credits.total_usage,
        }
    }

    fn line(&self) -> String {
        format!(
            "credits: purchased {purchased}, used {used}, remaining {remaining}",
            purchased = money(self.total_credits),
            used = money(self.total_usage),
            remaining = money(self.remaining)
        )
    }
}

/// The range a report covers, RFC 3339 at both ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RangeReport {
    start: String,
    end: String,
}

/// The metric and dimension names this run's query was asked in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ColumnsReport {
    key_dimension: String,
    cost_metric: String,
    tokens_metric: String,
}

impl ColumnsReport {
    fn line(&self) -> String {
        format!(
            "grouped by `{key}`, cost from `{cost}`, tokens from `{tokens}`",
            key = self.key_dimension,
            cost = self.cost_metric,
            tokens = self.tokens_metric
        )
    }
}

/// One API key's spend over the range.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct KeySpend {
    /// The key as the analytics API names it, scrubbed and otherwise untouched.
    ///
    /// In practice this is the key's **display name**: OpenRouter enriches the
    /// api-key dimension, so a grouped query answers with the label rather than
    /// the hash, and it promises the underlying id only for a *filter* value.
    /// Nothing here interprets it.
    key: String,
    /// The local address that tracks this key, when the identifier is a hash
    /// some address owns.
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    /// The range's total cost, in dollars.
    cost_usd: f64,
    /// The range's total tokens.
    tokens: f64,
    /// One entry per bucket the key was active in, earliest first.
    periods: Vec<PeriodSpend>,
}

impl KeySpend {
    fn lines(&self) -> Vec<String> {
        let owner = self.address.as_deref().unwrap_or("(no local address)");
        let mut lines = vec![format!(
            "  {key}  {owner}  cost {cost}  tokens {tokens}",
            key = self.key,
            cost = money(self.cost_usd),
            tokens = tokens(self.tokens)
        )];
        for period in &self.periods {
            lines.push(format!(
                "      {start}  cost {cost}  tokens {tokens}",
                start = period.start,
                cost = money(period.cost_usd),
                tokens = tokens(period.tokens)
            ));
        }
        lines
    }
}

/// One key's spend in one time bucket.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct PeriodSpend {
    /// The bucket's start, as OpenRouter labelled it.
    start: String,
    cost_usd: f64,
    tokens: f64,
}

/// Groups the answer's rows by key identifier, in identifier order.
///
/// The grouping key is the identifier **as OpenRouter returned it** — `None`
/// for a row it attributed to no key — and never the text the report prints.
/// Scrubbing and the unattributed placeholder are display decisions: two
/// identifiers that differ only in a credential-shaped token render the same
/// and are still two keys, and a key literally named `(unattributed)` is not
/// the unattributed bucket. Folding on the rendered text would silently merge
/// either pair and report one key's spend as another's.
///
/// Two rows for one key are two buckets of the same key's spend, so buckets are
/// ordered by their labels — RFC 3339 instants, which sort chronologically —
/// and a key and bucket seen twice is summed rather than overwritten.
fn rows(observed: &SpendObservation<'_>) -> Vec<KeySpend> {
    let mut grouped: BTreeMap<Option<String>, BTreeMap<Option<String>, Amounts>> = BTreeMap::new();
    for row in &observed.result.rows {
        let key = row.dimension(observed.key_dimension).map(str::to_owned);
        let start = row.period().map(str::to_owned);
        let amounts = grouped.entry(key).or_default().entry(start).or_default();
        amounts.cost_usd += row.metric(observed.cost_metric);
        amounts.tokens += row.metric(observed.tokens_metric);
    }

    grouped
        .into_iter()
        .map(|(identifier, buckets)| {
            let periods: Vec<PeriodSpend> = buckets
                .into_iter()
                .map(|(start, amounts)| PeriodSpend {
                    start: start.as_deref().map_or_else(String::new, scrubbed),
                    cost_usd: amounts.cost_usd,
                    tokens: amounts.tokens,
                })
                .collect();
            KeySpend {
                key: identifier
                    .as_deref()
                    .map_or_else(|| UNATTRIBUTED.to_owned(), scrubbed),
                address: identifier
                    .as_deref()
                    .and_then(|raw| address_owning(observed.state, raw)),
                cost_usd: periods.iter().map(|period| period.cost_usd).sum(),
                tokens: periods.iter().map(|period| period.tokens).sum(),
                periods,
            }
        })
        .collect()
}

/// What one key spent in one bucket, while the rows are still being folded.
#[derive(Debug, Clone, Copy, Default)]
struct Amounts {
    cost_usd: f64,
    tokens: f64,
}

/// The local address that owns `identifier`, when the identifier is a hash one
/// tracks.
///
/// Matched against the raw identifier, before scrubbing: what state records is
/// what OpenRouter returned, and the rendered form is for a reader. The lookup
/// is exact and one-directional — a returned identifier that is not a tracked
/// hash gets no address, and no name, label, or prefix is ever matched against
/// local state instead.
fn address_owning(state: &State, identifier: &str) -> Option<String> {
    let hash = KeyHash::parse(identifier).ok()?;
    state
        .address_owning(&hash)
        .map(|address| format!("keys.{address}"))
}

/// A token count, which is a whole number OpenRouter reports as a double.
fn tokens(count: f64) -> String {
    format!("{count:.0}")
}
