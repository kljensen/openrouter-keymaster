//! A log destination's provider-specific `config`, which may hold a
//! third-party credential.
//!
//! This is the only value in a Keymaster configuration that is allowed to be a
//! secret (ADR-0006, item 4). ADR-0001 keeps OpenRouter's own credentials out
//! of the file entirely; a Datadog API key or a webhook token is a different
//! thing, because there is no other channel through which OpenRouter could be
//! told what to send logs to.
//!
//! So the type is built to leak nothing:
//!
//! - It deserializes through its own visitors, whose every rejection is fixed
//!   text. A derived implementation would format the offending value into
//!   `Error::invalid_type`, and `toml` keeps that message inside the error
//!   object — the same rule the create-response parser follows.
//! - `Debug` prints `[redacted]`, so it cannot reach a log by being part of
//!   something else's `Debug`.
//! - There is no `Serialize`. The only serialization is [`DestinationConfig::
//!   canonical_json`], which renders into a buffer that is cleared when it is
//!   dropped, and which the request body and the digest are both built from.
//! - Every string it holds is cleared when it is dropped.
//!
//! What it does *not* do is pretend the value never existed elsewhere: it was
//! read from a file, and it is sent over the wire. The guarantee is about what
//! Keymaster writes down, returns, and prints.
//!
//! Floats are refused. Every other TOML scalar has one exact spelling in JSON,
//! and a digest of a rendered `f64` would be a comparison that depends on
//! formatting; `Usd` is an integer for the same reason. A provider
//! configuration that needs a fractional number is not one v0.3 supports.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

/// The destination types OpenRouter accepts, as its OpenAPI document lists
/// them.
///
/// Hardcoded rather than inferred from the shape of the token: a `type` this
/// build does not know is a configuration mistake an operator wants told about
/// before a create is sent, not a value to pass through and have refused
/// remotely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum DestinationType {
    Arize,
    Braintrust,
    Clickhouse,
    Datadog,
    Grafana,
    Langfuse,
    Langsmith,
    Newrelic,
    Opik,
    OtelCollector,
    Posthog,
    Ramp,
    S3,
    Sentry,
    Snowflake,
    Weave,
    Webhook,
}

/// Every type, in the order the configuration reference lists them.
pub(crate) const DESTINATION_TYPES: [DestinationType; 17] = [
    DestinationType::Arize,
    DestinationType::Braintrust,
    DestinationType::Clickhouse,
    DestinationType::Datadog,
    DestinationType::Grafana,
    DestinationType::Langfuse,
    DestinationType::Langsmith,
    DestinationType::Newrelic,
    DestinationType::Opik,
    DestinationType::OtelCollector,
    DestinationType::Posthog,
    DestinationType::Ramp,
    DestinationType::S3,
    DestinationType::Sentry,
    DestinationType::Snowflake,
    DestinationType::Weave,
    DestinationType::Webhook,
];

impl DestinationType {
    /// The spelling used in configuration and on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arize => "arize",
            Self::Braintrust => "braintrust",
            Self::Clickhouse => "clickhouse",
            Self::Datadog => "datadog",
            Self::Grafana => "grafana",
            Self::Langfuse => "langfuse",
            Self::Langsmith => "langsmith",
            Self::Newrelic => "newrelic",
            Self::Opik => "opik",
            Self::OtelCollector => "otel-collector",
            Self::Posthog => "posthog",
            Self::Ramp => "ramp",
            Self::S3 => "s3",
            Self::Sentry => "sentry",
            Self::Snowflake => "snowflake",
            Self::Weave => "weave",
            Self::Webhook => "webhook",
        }
    }

    /// Parses the configured spelling.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        DESTINATION_TYPES
            .into_iter()
            .find(|kind| kind.as_str() == value)
    }
}

impl fmt::Display for DestinationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The fraction of requests a destination forwards, held as whole millionths.
///
/// An integer for the reason [`super::Usd`] is one: it is compared for equality
/// on every plan, and `0.5`, `0.50`, and `5e-1` have to normalize to the same
/// value whether they came from a TOML file or from a JSON response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SamplingRate {
    millionths: u32,
}

/// Millionths in a whole rate.
const MILLIONTHS: f64 = 1_000_000.0;

/// The narrowest sampling rate OpenRouter accepts, in millionths.
const SAMPLING_MIN: u32 = 100;

/// The widest sampling rate there is: every request.
const SAMPLING_MAX: u32 = 1_000_000;

/// The largest rounding error tolerated when converting a written rate.
const SAMPLING_SLOP: f64 = 1e-9;

impl SamplingRate {
    /// The rate as a fraction, for building a request body.
    #[must_use]
    pub fn rate(self) -> f64 {
        f64::from(self.millionths) / MILLIONTHS
    }

    /// The rate in whole millionths.
    #[must_use]
    pub const fn millionths(self) -> u32 {
        self.millionths
    }

    /// Builds a rate from a fraction.
    ///
    /// Also used to read one back from the API, so an observed rate and a
    /// desired one normalize the same way.
    pub(crate) fn from_rate(rate: f64) -> Result<Self, SamplingProblem> {
        if !rate.is_finite() {
            return Err(SamplingProblem::OutOfRange);
        }
        let exact = rate * MILLIONTHS;
        let rounded = exact.round();
        if (exact - rounded).abs() > SAMPLING_SLOP * MILLIONTHS {
            return Err(SamplingProblem::TooPrecise);
        }
        if !(f64::from(SAMPLING_MIN)..=f64::from(SAMPLING_MAX)).contains(&rounded) {
            return Err(SamplingProblem::OutOfRange);
        }
        // Bounded above by `SAMPLING_MAX`, so the cast is exact.
        Ok(Self {
            millionths: rounded as u32,
        })
    }
}

impl fmt::Display for SamplingRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6}", self.rate())
    }
}

/// Why a sampling rate was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SamplingProblem {
    OutOfRange,
    TooPrecise,
}

impl SamplingProblem {
    /// A message that describes the rule without quoting the value.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::OutOfRange => "a sampling rate must be between 0.0001 and 1",
            Self::TooPrecise => "a sampling rate must not be finer than a millionth",
        }
    }
}

/// A string that clears itself when dropped.
///
/// Every string inside a [`DestinationConfig`] is one of these, keys included:
/// a field name is not itself a secret, but a half-built configuration dropped
/// on a parse failure should leave nothing of the block in freed memory.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Secret(String);

impl Secret {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// One value inside a destination `config`.
///
/// The TOML types that have an unambiguous JSON spelling, and no others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigValue {
    Text(Secret),
    Integer(i64),
    Boolean(bool),
    Array(Vec<ConfigValue>),
    Table(Vec<(Secret, ConfigValue)>),
}

/// A log destination's provider-specific configuration.
///
/// Write-only: state records a digest of it and nothing compares it against
/// what OpenRouter returns, which is masked (ADR-0006, item 3).
#[derive(Clone, PartialEq, Eq)]
pub struct DestinationConfig {
    /// The top-level fields, sorted by name and each name appearing once,
    /// which is what makes [`DestinationConfig::canonical_json`] canonical.
    entries: Vec<(Secret, ConfigValue)>,
}

impl DestinationConfig {
    /// The canonical JSON of this configuration, in a buffer that is cleared
    /// when it is dropped.
    ///
    /// Crate-private, and the only serialization there is: the request body and
    /// the digest are both built from it, and nothing else may render it.
    /// Canonical means fields in name order, one spelling per value, and no
    /// insignificant whitespace, so the same configuration always digests to
    /// the same bytes.
    pub(crate) fn canonical_json(&self) -> Zeroizing<String> {
        let mut rendered = Zeroizing::new(String::new());
        write_table(&mut rendered, &self.entries);
        rendered
    }

    /// The lowercase hexadecimal SHA-256 of [`DestinationConfig::
    /// canonical_json`].
    ///
    /// Not a secret: it is what state records so a later plan can tell whether
    /// the desired configuration changed, without ever holding the value.
    #[must_use]
    pub fn digest(&self) -> String {
        let canonical = self.canonical_json();
        let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

    /// Every string value this configuration holds, at any depth.
    ///
    /// What [`crate::redaction::register`] is fed when a configuration is
    /// loaded. Field *names* are deliberately not included: a name is chosen by
    /// the provider, not by the operator, and registering one would scrub the
    /// word out of every message that mentions it.
    pub(crate) fn string_values(&self) -> Vec<&str> {
        let mut values = Vec::new();
        collect_strings(&self.entries, &mut values);
        values
    }

    /// Whether the configuration has no fields at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for DestinationConfig {
    /// Never the value, and never even how many fields it has.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DestinationConfig([redacted])")
    }
}

/// Serializes a destination configuration as its digest.
///
/// [`super::Config`] is serialized whole to build a plan fingerprint (ADR-0003),
/// and this is what keeps the value out of that preimage while still binding a
/// change to it: two configurations differing only in a destination's `config`
/// have different digests, so they have different fingerprints (ADR-0006,
/// item 4).
pub(super) fn serialize_digest<S: Serializer>(
    config: &DestinationConfig,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&config.digest())
}

/// Appends every string value under `entries` to `values`.
fn collect_strings<'a>(entries: &'a [(Secret, ConfigValue)], values: &mut Vec<&'a str>) {
    for (_, value) in entries {
        collect_value_strings(value, values);
    }
}

fn collect_value_strings<'a>(value: &'a ConfigValue, values: &mut Vec<&'a str>) {
    match value {
        ConfigValue::Text(text) => values.push(text.as_str()),
        ConfigValue::Array(items) => {
            for item in items {
                collect_value_strings(item, values);
            }
        }
        ConfigValue::Table(entries) => collect_strings(entries, values),
        ConfigValue::Integer(_) | ConfigValue::Boolean(_) => {}
    }
}

/// Renders one table as a JSON object.
fn write_table(rendered: &mut String, entries: &[(Secret, ConfigValue)]) {
    rendered.push('{');
    for (index, (name, value)) in entries.iter().enumerate() {
        if index > 0 {
            rendered.push(',');
        }
        write_json_string(rendered, name.as_str());
        rendered.push(':');
        write_value(rendered, value);
    }
    rendered.push('}');
}

fn write_value(rendered: &mut String, value: &ConfigValue) {
    match value {
        ConfigValue::Text(text) => write_json_string(rendered, text.as_str()),
        ConfigValue::Integer(number) => {
            use fmt::Write as _;
            let _ = write!(rendered, "{number}");
        }
        ConfigValue::Boolean(flag) => rendered.push_str(if *flag { "true" } else { "false" }),
        ConfigValue::Array(items) => {
            rendered.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    rendered.push(',');
                }
                write_value(rendered, item);
            }
            rendered.push(']');
        }
        ConfigValue::Table(entries) => write_table(rendered, entries),
    }
}

/// Writes one JSON string, escaping exactly what RFC 8259 requires.
///
/// Crate-visible because the request body a destination write sends is rendered
/// by the same rules, into the same kind of buffer, and two escapers that had
/// to agree is one more than there needs to be.
pub(crate) fn write_json_string(rendered: &mut String, value: &str) {
    rendered.push('"');
    for character in value.chars() {
        match character {
            '"' => rendered.push_str("\\\""),
            '\\' => rendered.push_str("\\\\"),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            control if control < '\u{20}' => {
                use fmt::Write as _;
                let _ = write!(rendered, "\\u{:04x}", control as u32);
            }
            other => rendered.push(other),
        }
    }
    rendered.push('"');
}

// ===== deserialization, written out rather than derived =====
//
// Every rejection below is a fixed string. A derived implementation reports a
// value of the wrong shape with `Error::invalid_type(Unexpected::Str(value),
// …)`, which formats the value into the message — and `toml` keeps that message
// inside the error object it returns, out of reach of anything this crate could
// clear or redact afterwards. A destination `config` is the one configuration
// value that may be a credential, so no part of it may ever enter one.
//
// Each entry point asks for `deserialize_any` rather than the shape it wants,
// for the reason the create-response parser does: `deserialize_map` on a string
// never reaches the visitor, because the deserializer recognizes the mismatch
// itself and raises `invalid_type` with the string already formatted in.

/// The rejection every visitor here returns.
fn wrong_shape<E: de::Error>(expected: &'static str) -> E {
    E::custom(expected)
}

/// What a `config` table may hold.
const EXPECTED_VALUE: &str = "a destination `config` value must be a string, a whole number, a boolean, an array, or a \
     table; a fractional number, a datetime, and a binary value are not supported";

/// What a `config` itself must be.
const EXPECTED_TABLE: &str = "`config` must be a table of provider-specific configuration";

/// What a field name must be.
const EXPECTED_NAME: &str = "a destination `config` field name must be a string";

/// The prefix `toml` gives the private markers it wraps its own types in.
///
/// A TOML datetime does not arrive as a scalar: it arrives as a one-entry map
/// whose key is such a marker, so a visitor that only refused scalars would
/// canonicalize a datetime into a nested table and digest it as one. Any key
/// with this prefix is refused instead.
const TOML_PRIVATE_PREFIX: &str = "$__toml_private";

/// Rejects each named shape with one fixed message.
///
/// Serde's default `visit_*` reports a rejection as
/// `invalid_type(Unexpected::Signed(value), …)`, which formats the value into
/// the message — and the deserializer keeps that message inside the error object
/// it returns, out of reach of anything this crate could clear or redact. So
/// every shape a visitor does not accept is refused explicitly, and this macro
/// is what makes "every" a list one can read.
///
/// `visit_borrowed_str` and `visit_borrowed_bytes` are deliberately absent:
/// their defaults forward to `visit_str` and `visit_bytes`, which every visitor
/// below either accepts or refuses by name, so neither can reach serde's own
/// message. `visit_string` and `visit_byte_buf` are written out rather than
/// generated, because a rejected owned value has to be cleared before it drops.
macro_rules! reject_shapes {
    ($message:expr; $($method:ident($value:ty)),* $(,)?) => {
        $(
            fn $method<E: de::Error>(self, _value: $value) -> Result<Self::Value, E> {
                Err(wrong_shape($message))
            }
        )*
    };
}

/// The shapes no `config` visitor accepts, whatever else it does.
///
/// Two of them are owned and may hold secret bytes, so they are cleared before
/// the rejection drops them. The rest are `Copy` scalars with nothing to clear.
macro_rules! reject_shapes_no_visitor_accepts {
    ($message:expr) => {
        reject_shapes!(
            $message;
            visit_f32(f32),
            visit_f64(f64),
            visit_char(char),
            visit_i128(i128),
            visit_u128(u128),
            visit_bytes(&[u8]),
        );

        fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            let _cleared = Zeroizing::new(value);
            Err(wrong_shape($message))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Err(wrong_shape($message))
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Err(wrong_shape($message))
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            _deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            Err(wrong_shape($message))
        }

        fn visit_newtype_struct<D: Deserializer<'de>>(
            self,
            _deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            Err(wrong_shape($message))
        }

        fn visit_enum<A: de::EnumAccess<'de>>(self, _access: A) -> Result<Self::Value, A::Error> {
            Err(wrong_shape($message))
        }
    };
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SecretVisitor)
    }
}

struct SecretVisitor;

impl<'de> Visitor<'de> for SecretVisitor {
    type Value = Secret;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(EXPECTED_NAME)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Secret(value.to_owned()))
    }

    /// Takes ownership rather than copying, so the allocation the deserializer
    /// had to build is owned by something that clears it.
    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(Secret(value))
    }

    reject_shapes_no_visitor_accepts!(EXPECTED_NAME);

    reject_shapes!(
        EXPECTED_NAME;
        visit_bool(bool),
        visit_i8(i8),
        visit_i16(i16),
        visit_i32(i32),
        visit_i64(i64),
        visit_u8(u8),
        visit_u16(u16),
        visit_u32(u32),
        visit_u64(u64),
    );

    fn visit_seq<A: SeqAccess<'de>>(self, _access: A) -> Result<Self::Value, A::Error> {
        Err(wrong_shape(EXPECTED_NAME))
    }

    fn visit_map<A: MapAccess<'de>>(self, _access: A) -> Result<Self::Value, A::Error> {
        Err(wrong_shape(EXPECTED_NAME))
    }
}

impl<'de> Deserialize<'de> for ConfigValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ConfigValueVisitor)
    }
}

struct ConfigValueVisitor;

impl<'de> Visitor<'de> for ConfigValueVisitor {
    type Value = ConfigValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(EXPECTED_VALUE)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(ConfigValue::Text(Secret(value.to_owned())))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(ConfigValue::Text(Secret(value)))
    }

    /// The narrower signed widths reach this through serde's own forwarding.
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(ConfigValue::Integer(value))
    }

    /// As `visit_i64`, for the unsigned widths.
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        i64::try_from(value)
            .map(ConfigValue::Integer)
            .map_err(|_| wrong_shape("a whole number a 64-bit signed integer can hold"))
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(ConfigValue::Boolean(value))
    }

    reject_shapes_no_visitor_accepts!(EXPECTED_VALUE);

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element::<ConfigValue>()? {
            items.push(item);
        }
        Ok(ConfigValue::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        Ok(ConfigValue::Table(read_table(access)?))
    }
}

impl<'de> Deserialize<'de> for DestinationConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DestinationConfigVisitor)
    }
}

struct DestinationConfigVisitor;

impl<'de> Visitor<'de> for DestinationConfigVisitor {
    type Value = DestinationConfig;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(EXPECTED_TABLE)
    }

    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        Ok(DestinationConfig {
            entries: read_table(access)?,
        })
    }

    fn visit_str<E: de::Error>(self, _value: &str) -> Result<Self::Value, E> {
        Err(wrong_shape(EXPECTED_TABLE))
    }

    /// Cleared before the rejection drops it: the whole `config` written as one
    /// string would be exactly the value that must not be left in freed memory.
    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        let _cleared = Zeroizing::new(value);
        Err(wrong_shape(EXPECTED_TABLE))
    }

    reject_shapes_no_visitor_accepts!(EXPECTED_TABLE);

    reject_shapes!(
        EXPECTED_TABLE;
        visit_bool(bool),
        visit_i8(i8),
        visit_i16(i16),
        visit_i32(i32),
        visit_i64(i64),
        visit_u8(u8),
        visit_u16(u16),
        visit_u32(u32),
        visit_u64(u64),
    );

    fn visit_seq<A: SeqAccess<'de>>(self, _access: A) -> Result<Self::Value, A::Error> {
        Err(wrong_shape(EXPECTED_TABLE))
    }
}

/// Reads one table, sorted by field name, refusing a repeated name.
///
/// The sort is what makes the rendering canonical; the refusal is because
/// keeping either of two entries with one name would silently discard the
/// other, and one of them may be the credential.
///
/// A key carrying [`TOML_PRIVATE_PREFIX`] is refused too. That is how `toml`
/// hands over a datetime — a one-entry map, not a scalar — and accepting it
/// would canonicalize a datetime as a nested table whose field name is an
/// implementation detail of the parser.
fn read_table<'de, A: MapAccess<'de>>(
    mut access: A,
) -> Result<Vec<(Secret, ConfigValue)>, A::Error> {
    let mut entries: Vec<(Secret, ConfigValue)> = Vec::new();
    while let Some(name) = access.next_key::<Secret>()? {
        if name.as_str().starts_with(TOML_PRIVATE_PREFIX) {
            return Err(de::Error::custom(
                "a datetime is not a destination `config` value; write it as a string",
            ));
        }
        let value = access.next_value::<ConfigValue>()?;
        if entries.iter().any(|(existing, _)| *existing == name) {
            return Err(de::Error::custom(
                "a destination `config` names one field twice",
            ));
        }
        entries.push((name, value));
    }
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses one `config` table out of a TOML document.
    fn config(source: &str) -> Result<DestinationConfig, toml::de::Error> {
        #[derive(Deserialize)]
        struct Document {
            config: DestinationConfig,
        }
        toml::from_str::<Document>(source).map(|document| document.config)
    }

    #[test]
    fn a_configuration_renders_one_canonical_json_whatever_order_it_was_written_in() {
        let first = config("config = { site = \"a\", apiKey = \"b\", retries = 3, tls = true }")
            .expect("a valid configuration");
        let second = config("config = { tls = true, retries = 3, apiKey = \"b\", site = \"a\" }")
            .expect("a valid configuration");

        assert_eq!(
            first.canonical_json().as_str(),
            r#"{"apiKey":"b","retries":3,"site":"a","tls":true}"#
        );
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.digest().len(), 64);
    }

    #[test]
    fn nested_tables_and_arrays_render_and_digest() {
        let nested = config(
            "config = { headers = { Authorization = \"Bearer x\" }, hosts = [\"b\", \"a\"] }",
        )
        .expect("a valid configuration");
        assert_eq!(
            nested.canonical_json().as_str(),
            r#"{"headers":{"Authorization":"Bearer x"},"hosts":["b","a"]}"#,
            "an array keeps the order it was written in; only field names are sorted"
        );
    }

    #[test]
    fn a_string_is_escaped_the_way_json_requires() {
        let quoted =
            config("config = { note = \"a\\\"b\\\\c\\td\" }").expect("a valid configuration");
        assert_eq!(quoted.canonical_json().as_str(), r#"{"note":"a\"b\\c\td"}"#);
    }

    #[test]
    fn debug_never_prints_a_value() {
        let secret = config("config = { apiKey = \"dd-XXXXXXXXXXXXXXXXXXXX\" }")
            .expect("a valid configuration");
        let printed = format!("{secret:?}");
        assert_eq!(printed, "DestinationConfig([redacted])");
        assert!(!printed.contains("dd-"), "{printed}");
    }

    #[test]
    fn a_rejected_value_never_reaches_the_error_message() {
        for (source, refused) in [
            (
                "config = { apiKey = 1.5, marker = \"dd-XXXXXXXXXXXXXXXXXXXX\" }",
                "1.5",
            ),
            ("config = \"dd-XXXXXXXXXXXXXXXXXXXX\"", "dd-"),
        ] {
            let error = config(source).expect_err("this configuration is refused");
            let message = error.message().to_owned();
            assert!(
                !message.contains(refused),
                "the deserializer message quoted the value: {message}"
            );
        }
    }

    #[test]
    fn a_scalar_where_a_table_belongs_is_refused_without_naming_it() {
        // Serde's default `visit_i64` and `visit_bool` format the value into
        // the message, and the deserializer keeps that message; the root
        // visitor refuses every shape by name so that cannot happen.
        for (source, refused) in [
            ("config = 1234567890123456789", "1234567890123456789"),
            ("config = true", "true"),
            ("config = -42", "42"),
            ("config = 1.5", "1.5"),
            ("config = [1, 2]", "1"),
        ] {
            let error = config(source).expect_err("this configuration is refused");
            let message = error.message().to_owned();
            assert!(
                !message.contains(refused),
                "`{source}` quoted the value it refused: {message}"
            );
            assert!(message.contains("must be a table"), "`{source}`: {message}");
        }
    }

    #[test]
    fn a_value_of_a_shape_no_config_holds_is_refused_without_naming_it() {
        for (source, refused) in [
            ("config = { at = 1.5 }", "1.5"),
            ("config = { at = 1979-05-27T07:32:00Z }", "1979"),
            ("config = { at = 1979-05-27 }", "1979"),
            ("config = { at = 07:32:00 }", "07:32"),
        ] {
            let error = config(source).expect_err("this configuration is refused");
            let message = error.message().to_owned();
            assert!(
                !message.contains(refused),
                "`{source}` quoted the value it refused: {message}"
            );
        }
    }

    #[test]
    fn a_datetime_is_refused_rather_than_canonicalized_as_a_table() {
        // `toml` hands a datetime over as a one-entry map keyed by a private
        // marker, so a visitor that only refused scalars would digest it as a
        // nested table whose field name is a parser implementation detail.
        let error = config("config = { at = 1979-05-27T07:32:00Z }")
            .expect_err("a datetime is not a config value");
        let message = error.message().to_owned();
        assert_eq!(
            message, "a datetime is not a destination `config` value; write it as a string",
            "the marker path is what refuses it, so the message is that refusal"
        );
        assert!(
            !message.contains(TOML_PRIVATE_PREFIX),
            "and the marker itself is not repeated either: {message}"
        );
    }

    #[test]
    fn a_repeated_field_is_refused_without_naming_it() {
        // TOML itself refuses a repeated key in one table, so the refusal this
        // parser adds is reached through a nested table written twice.
        let error = config("config = { a = \"one\" }\n[config]\nb = \"two\"\n")
            .expect_err("a document cannot define `config` twice");
        assert!(!error.message().contains("one"), "{error}");
    }

    #[test]
    fn every_string_value_is_collected_for_the_redactor() {
        let secret = config(
            "config = { apiKey = \"dd-XXXXXXXXXXXXXXXXXXXX\", nested = { token = \"t-YYYY\" }, \
             hosts = [\"h-ZZZZ\"], retries = 2 }",
        )
        .expect("a valid configuration");
        let mut values = secret.string_values();
        values.sort_unstable();
        assert_eq!(values, vec!["dd-XXXXXXXXXXXXXXXXXXXX", "h-ZZZZ", "t-YYYY"]);
    }

    #[test]
    fn a_sampling_rate_normalizes_the_way_a_budget_does() {
        assert_eq!(
            SamplingRate::from_rate(0.5).expect("a valid rate"),
            SamplingRate::from_rate(0.50).expect("a valid rate")
        );
        assert_eq!(
            SamplingRate::from_rate(1.0).expect("a valid rate").rate(),
            1.0
        );
        assert_eq!(
            SamplingRate::from_rate(0.0),
            Err(SamplingProblem::OutOfRange)
        );
        assert_eq!(
            SamplingRate::from_rate(1.5),
            Err(SamplingProblem::OutOfRange)
        );
        assert_eq!(
            SamplingRate::from_rate(0.00001),
            Err(SamplingProblem::OutOfRange)
        );
    }

    #[test]
    fn every_documented_type_round_trips_through_its_spelling() {
        for kind in DESTINATION_TYPES {
            assert_eq!(DestinationType::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(DestinationType::parse("Datadog"), None);
        assert_eq!(DestinationType::parse("splunk"), None);
    }
}
