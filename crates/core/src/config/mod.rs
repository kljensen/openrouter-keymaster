//! The desired-state configuration: what OpenRouter should look like.
//!
//! Parsing and validation are pure. They read one string of TOML, touch no
//! other file, read no environment variable or credential, and make no network
//! call, so a configuration mistake is reported before Keymaster has done
//! anything at all. [`Config::load`] is the one function that reads a file, and
//! it only reads.
//!
//! Two properties matter downstream. First, every value is normalized on the
//! way in — sets are sorted and deduplicated, slugs are lowercased, timestamps
//! are converted to UTC, and money becomes an integer — so that comparing a
//! desired value with an observed one is an equality test rather than a
//! judgement call, and so replanning identical input produces identical output.
//! Second, a field that is absent is not the same as a field that is empty:
//! see [`Managed`].
//!
//! Nothing here accepts credential plaintext. Unknown fields are rejected
//! outright, every string is checked against
//! [`crate::redaction::looks_like_credential`], and no error message repeats a
//! value read from the file.

mod validate;
mod wire;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::ids::{Address, ReceiverFingerprint, RemoteName, UserId, Uuid};

/// The only schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// A validated desired configuration.
///
/// It serializes deterministically — every collection is a `BTreeMap` or a
/// `BTreeSet`, and every value was normalized on the way in — which is what
/// lets a plan fingerprint bind the whole configuration rather than a list of
/// fields (ADR-0003). No field of it can hold credential plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Config {
    /// Values that individual resources inherit unless they say otherwise.
    pub defaults: Defaults,
    /// Guardrails by local address.
    pub guardrails: BTreeMap<Address, Guardrail>,
    /// Keys by local address.
    pub keys: BTreeMap<Address, Key>,
    /// Secret receivers by local address.
    pub receivers: BTreeMap<Address, Receiver>,
}

impl Config {
    /// Parses and validates a configuration from TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Syntax`] when the text is not the TOML this
    /// schema describes, or [`ConfigError::Invalid`] carrying every domain
    /// problem found in one pass.
    pub fn parse(source: &str) -> Result<Self, ConfigError> {
        let document: wire::Document = toml::from_str(source).map_err(ConfigError::from_toml)?;
        validate::validate(document).map_err(|problems| ConfigError::Invalid { problems })
    }

    /// Reads and validates a configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] when the file cannot be read, or the
    /// errors of [`Config::parse`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let source = std::fs::read_to_string(path).map_err(|error| ConfigError::Read {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        Self::parse(&source)
    }
}

/// Values inherited by resources that do not override them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Defaults {
    /// Whether spend on the operator's own provider keys counts against a
    /// USD limit.
    pub include_byok_in_limit: bool,
}

/// How a managed remote field is treated.
///
/// TOML cannot write a null, so the three states are spelled by presence:
/// omitting a field leaves the remote value alone, giving it a value sets it,
/// and naming it in the block's `clear` list clears it. The distinction is
/// what lets Keymaster remove a budget or an expiry without also claiming
/// ownership of every field it does not mention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Managed<T> {
    /// Absent from the configuration; the remote value is not Keymaster's.
    Unmanaged,
    /// Set to this value.
    Set(T),
    /// Explicitly cleared: the remote field should hold nothing.
    Cleared,
}

impl<T> Managed<T> {
    /// The desired value, if one was given.
    pub const fn value(&self) -> Option<&T> {
        match self {
            Self::Set(value) => Some(value),
            Self::Unmanaged | Self::Cleared => None,
        }
    }

    /// Whether Keymaster manages this field at all.
    pub const fn is_managed(&self) -> bool {
        !matches!(self, Self::Unmanaged)
    }
}

/// A guardrail: the model, provider, and budget policy assigned to keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Guardrail {
    /// Remote display name. Mutable remotely, never an identifier.
    pub name: RemoteName,
    /// Remote description.
    pub description: Managed<String>,
    /// Models this guardrail permits, as normalized slugs.
    pub allowed_models: Option<BTreeSet<String>>,
    /// Models this guardrail refuses.
    pub denied_models: Option<BTreeSet<String>>,
    /// Providers this guardrail permits.
    pub allowed_providers: Option<BTreeSet<String>>,
    /// Providers this guardrail refuses.
    pub denied_providers: Option<BTreeSet<String>>,
    /// USD spending limit.
    pub limit: Managed<Usd>,
    /// How often the limit resets.
    pub reset_interval: Managed<ResetInterval>,
    /// Whether BYOK spend counts against the limit, after inheriting
    /// [`Defaults::include_byok_in_limit`].
    pub include_byok_in_limit: bool,
    /// Whether inference is restricted to zero-data-retention providers.
    /// Absent means Keymaster does not manage the setting.
    pub require_zdr: Option<bool>,
}

/// An OpenRouter inference key Keymaster manages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Key {
    /// Remote display name. Mutable remotely, never an identifier.
    pub name: RemoteName,
    /// USD spending limit.
    pub limit: Managed<Usd>,
    /// How often the limit resets.
    pub limit_reset: Managed<ResetInterval>,
    /// When the key stops working, normalized to UTC.
    pub expires_at: Managed<OffsetDateTime>,
    /// Whether the key is disabled. Always managed; defaults to enabled.
    pub disabled: bool,
    /// Workspace the key belongs to. Immutable once the key exists.
    pub workspace_id: Option<Uuid>,
    /// The organization member the key is created on behalf of. `POST /keys`
    /// accepts it and `PATCH /keys/{hash}` has no field for it, so it is
    /// immutable once the key exists: changing it replaces the key.
    pub creator_user_id: Option<UserId>,
    /// The guardrail assigned to this key. Clearing it unassigns.
    pub guardrail: Managed<Address>,
    /// Where this key's plaintext is delivered. A key with no receiver can be
    /// managed and imported, but never created: Keymaster does not create a
    /// secret it has nowhere to put.
    pub receiver: Option<Address>,
    /// Monotonic replacement counter. Raising it asks for a new key.
    pub generation: u32,
    /// Whether BYOK spend counts against the limit, after inheriting
    /// [`Defaults::include_byok_in_limit`].
    pub include_byok_in_limit: bool,
}

/// Where a newly created key's plaintext is delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Receiver {
    /// Write the plaintext to one file, for local development and tests.
    File {
        /// Absolute path of the file to write.
        path: PathBuf,
    },
    /// Run a program and hand it the plaintext on stdin. Arguments never
    /// carry secret material.
    Command {
        /// Absolute path of the program to run.
        program: PathBuf,
        /// Arguments, passed as a vector; no shell is involved.
        args: Vec<String>,
    },
}

impl Receiver {
    /// A stable, non-secret fingerprint of this receiver: the lowercase hex
    /// SHA-256 of its specification.
    ///
    /// State records this so that changing where a key is delivered is
    /// recognizable as a reason to replace it. A digest rather than a rendered
    /// description, for two reasons: it is a fixed-length, printable value
    /// whatever a path or argument contains, and it cannot carry any part of
    /// the configuration into a state file or an error message.
    ///
    /// The preimage length-prefixes every component — the kind, the path or
    /// program, and each argument separately — so no two different receivers
    /// can produce the same bytes. Joining the arguments with a separator
    /// would not do: `["a b"]` and `["a", "b"]` are different receivers.
    #[must_use]
    pub fn fingerprint(&self) -> ReceiverFingerprint {
        ReceiverFingerprint::from_digest(self.digest())
    }

    /// The SHA-256 of this receiver's unambiguously encoded specification.
    fn digest(&self) -> [u8; 32] {
        /// Adds one component so it cannot run into the next.
        fn absorb(hasher: &mut Sha256, component: &[u8]) {
            hasher.update(
                u64::try_from(component.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            hasher.update(component);
        }

        let mut hasher = Sha256::new();
        match self {
            Self::File { path } => {
                absorb(&mut hasher, b"file");
                absorb(&mut hasher, path.as_os_str().as_encoded_bytes());
            }
            Self::Command { program, args } => {
                absorb(&mut hasher, b"command");
                absorb(&mut hasher, program.as_os_str().as_encoded_bytes());
                for arg in args {
                    absorb(&mut hasher, arg.as_bytes());
                }
            }
        }
        hasher.finalize().into()
    }
}

/// How often a USD limit resets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ResetInterval {
    Daily,
    Weekly,
    Monthly,
}

impl ResetInterval {
    /// The spelling used in configuration and on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }

    /// Parses the configured spelling. Also used to read the same word back
    /// from the API, so a desired interval and an observed one compare equal.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "daily" => Some(Self::Daily),
            "weekly" => Some(Self::Weekly),
            "monthly" => Some(Self::Monthly),
            _ => None,
        }
    }
}

impl fmt::Display for ResetInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An amount of US dollars, held as whole millionths.
///
/// A budget is compared for equality on every plan, so it is stored as an
/// integer rather than a float: `10`, `10.0`, and `1e1` normalize to the same
/// value, and no comparison depends on float rounding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Usd {
    micros: i64,
}

/// Millionths of a dollar in one dollar.
const MICROS_PER_USD: f64 = 1_000_000.0;

/// The largest budget Keymaster will accept, in dollars. Far above any real
/// key limit, and low enough that the micro-dollar representation cannot
/// overflow.
const USD_MAX: f64 = 1_000_000_000.0;

/// The largest rounding error tolerated when converting a written amount to
/// millionths. Anything larger means the operator wrote more precision than a
/// USD amount can carry.
const USD_ROUNDING_SLOP: f64 = 1e-3;

impl Usd {
    /// The amount in whole millionths of a dollar.
    #[must_use]
    pub const fn micros(self) -> i64 {
        self.micros
    }

    /// The amount in dollars, for building a request body.
    ///
    /// The conversion is exact: `USD_MAX` keeps the stored millionths well
    /// inside the range where `f64` represents every integer.
    #[must_use]
    pub fn dollars(self) -> f64 {
        self.micros as f64 / MICROS_PER_USD
    }

    /// Builds an amount from whole dollars.
    ///
    /// Also used to read a budget back from the API, which reports one as a
    /// JSON number: an observed amount and a desired one have to normalize the
    /// same way, or every plan would show a difference that is not there.
    pub(crate) fn from_dollars(dollars: f64) -> Result<Self, UsdProblem> {
        if !dollars.is_finite() {
            return Err(UsdProblem::NotFinite);
        }
        if dollars < 0.0 {
            return Err(UsdProblem::Negative);
        }
        if dollars > USD_MAX {
            return Err(UsdProblem::TooLarge);
        }

        let exact = dollars * MICROS_PER_USD;
        let rounded = exact.round();
        if (exact - rounded).abs() > USD_ROUNDING_SLOP {
            return Err(UsdProblem::TooPrecise);
        }

        // Finite, rounded, and bounded by `USD_MAX`, so the cast is exact.
        Ok(Self {
            micros: rounded as i64,
        })
    }
}

impl fmt::Display for Usd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6}", self.dollars())
    }
}

/// Why an amount of money was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UsdProblem {
    NotFinite,
    Negative,
    TooLarge,
    TooPrecise,
}

impl UsdProblem {
    /// A message that describes the rule without quoting the value.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::NotFinite => "expected a number of US dollars, not an infinity or a NaN",
            Self::Negative => "a USD amount must not be negative",
            Self::TooLarge => "a USD amount must not exceed 1000000000",
            Self::TooPrecise => "a USD amount must not be finer than a millionth of a dollar",
        }
    }
}

/// One problem with the desired configuration.
///
/// Sorted by path, so a run reports its problems in the same order every time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Problem {
    /// The configuration path, for example `keys.jobfeed.limit_usd`.
    pub path: String,
    /// What is wrong. Never contains a value read from the configuration.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Why a configuration could not be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read {}: {message}", path.display())]
    Read {
        /// The file Keymaster tried to read.
        path: PathBuf,
        /// The operating system's explanation.
        message: String,
    },

    /// The text is not the TOML this schema describes.
    #[error("the configuration is not valid TOML: {message}")]
    Syntax {
        /// The deserializer's explanation, with credential-shaped tokens
        /// redacted and its quoted source line dropped.
        message: String,
    },

    /// The configuration parsed but does not describe a usable desired state.
    #[error("{}", render_problems(.problems))]
    Invalid {
        /// Every problem found, sorted by configuration path.
        problems: Vec<Problem>,
    },
}

impl ConfigError {
    /// A stable machine-readable category.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Read { .. } => "config_read",
            Self::Syntax { .. } => "config_syntax",
            Self::Invalid { .. } => "config_invalid",
        }
    }

    /// Every problem, when this error carries a set of them.
    #[must_use]
    pub fn problems(&self) -> &[Problem] {
        match self {
            Self::Invalid { problems } => problems,
            Self::Read { .. } | Self::Syntax { .. } => &[],
        }
    }

    /// Converts a deserializer error without repeating the source text.
    ///
    /// `toml`'s `Display` renders the offending line from the file; only its
    /// message is kept, and that is redacted, so a secret written into the
    /// configuration cannot travel out through the error.
    fn from_toml(error: toml::de::Error) -> Self {
        Self::Syntax {
            message: crate::redaction::redact(error.message()),
        }
    }
}

/// Renders a problem list as one indented block.
fn render_problems(problems: &[Problem]) -> String {
    let mut rendered = format!(
        "the configuration has {count} problem{plural}:",
        count = problems.len(),
        plural = if problems.len() == 1 { "" } else { "s" }
    );
    for problem in problems {
        rendered.push_str("\n  - ");
        rendered.push_str(&problem.to_string());
    }
    rendered
}

#[cfg(test)]
mod tests;
