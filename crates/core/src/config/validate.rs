//! One-pass domain validation.
//!
//! Every check appends to a list instead of returning early, so an operator
//! sees everything wrong with a configuration in one run rather than fixing
//! one mistake per attempt. A block that produced any problem is dropped
//! rather than half-built; the run is failing anyway, and a placeholder value
//! would only invite a cascade of follow-on complaints.
//!
//! Two rules constrain every message here: it names the configuration path it
//! is about, and it describes the rule rather than quoting the value that
//! broke it. A rejected value may be a pasted credential.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use super::wire;
use super::{
    Config, Defaults, Guardrail, Key, Managed, Problem, Receiver, ResetInterval, SCHEMA_VERSION,
    Usd,
};
use crate::ids::{Address, RemoteName, UserId, Uuid};
use crate::redaction::{looks_like_credential, printable};

/// Guardrail fields whose remote value can be cleared.
const GUARDRAIL_CLEARABLE: &[&str] = &["description", "limit_usd", "reset_interval"];

/// Key fields whose remote value can be cleared. Clearing `guardrail`
/// unassigns the key.
const KEY_CLEARABLE: &[&str] = &["limit_usd", "limit_reset", "expires_at", "guardrail"];

/// Whether a USD limit obliges the block to name a reset interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BudgetPairing {
    ResetRequired,
    ResetOptional,
}

/// Longest accepted description.
const DESCRIPTION_MAX: usize = 1_000;

/// Longest accepted model or provider slug.
const SLUG_MAX: usize = 200;

/// Longest accepted filesystem path or command argument.
const PATH_MAX: usize = 4_096;

/// Most arguments a command receiver may carry.
const ARGS_MAX: usize = 64;

/// Longest accepted `caller` receiver destination. It is a label a host routes
/// by and Keymaster passes through, not a document.
const DESTINATION_MAX: usize = 200;

/// Longest path segment echoed back in an error message.
const SEGMENT_MAX: usize = 64;

/// Validates a parsed document, or reports every problem it has.
pub(super) fn validate(document: wire::Document) -> Result<Config, Vec<Problem>> {
    let mut validator = Validator::default();
    validator.version(document.version);

    let declared_guardrails: BTreeSet<String> = document.guardrails.keys().cloned().collect();
    let declared_receivers: BTreeSet<String> = document.receivers.keys().cloned().collect();

    let defaults = Defaults {
        include_byok_in_limit: document.defaults.include_byok_in_limit.unwrap_or(false),
    };

    validator.duplicate_addresses("guardrails", &declared_guardrails);
    validator.duplicate_addresses("keys", document.keys.keys());
    validator.duplicate_addresses("receivers", &declared_receivers);

    let receivers = validator.receivers(document.receivers);
    let guardrails = validator.guardrails(document.guardrails, defaults);
    let keys = validator.keys(
        document.keys,
        defaults,
        &declared_guardrails,
        &declared_receivers,
    );

    validator.duplicate_names("guardrails", guardrails.iter().map(|(a, g)| (a, &g.name)));
    validator.duplicate_names("keys", keys.iter().map(|(a, k)| (a, &k.name)));

    validator.finish(Config {
        defaults,
        guardrails,
        keys,
        receivers,
    })
}

/// Accumulates problems while building the domain configuration.
#[derive(Debug, Default)]
struct Validator {
    problems: Vec<Problem>,
}

impl Validator {
    fn problem(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.problems.push(Problem {
            path: path.into(),
            message: message.into(),
        });
    }

    /// How many problems have been recorded, so a caller can tell whether the
    /// block it just validated is safe to build.
    fn count(&self) -> usize {
        self.problems.len()
    }

    fn finish(mut self, config: Config) -> Result<Config, Vec<Problem>> {
        if self.problems.is_empty() {
            return Ok(config);
        }
        self.problems.sort();
        self.problems.dedup();
        Err(self.problems)
    }

    fn version(&mut self, version: Option<u32>) {
        match version {
            Some(SCHEMA_VERSION) => {}
            Some(other) => self.problem(
                "version",
                format!(
                    "unsupported schema version {other}; this build understands version \
                     {SCHEMA_VERSION}"
                ),
            ),
            None => self.problem("version", format!("expected `version = {SCHEMA_VERSION}`")),
        }
    }

    fn duplicate_addresses<'a>(
        &mut self,
        kind: &str,
        addresses: impl IntoIterator<Item = &'a String>,
    ) {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for raw in addresses {
            let folded = raw.to_ascii_lowercase();
            if let Some(first) = seen.get(&folded) {
                self.problem(
                    format!("{kind}.{}", safe_segment(raw)),
                    format!(
                        "duplicates the local address `{}`; two addresses may not differ by \
                         letter case alone",
                        safe_segment(first)
                    ),
                );
            } else {
                seen.insert(folded, raw.clone());
            }
        }
    }

    fn duplicate_names<'a>(
        &mut self,
        kind: &str,
        named: impl IntoIterator<Item = (&'a Address, &'a RemoteName)>,
    ) {
        let mut seen: BTreeMap<&str, &Address> = BTreeMap::new();
        for (address, name) in named {
            if let Some(first) = seen.get(name.as_str()) {
                self.problem(
                    format!("{kind}.{address}.name"),
                    format!("duplicates the remote name configured for `{first}`"),
                );
            } else {
                seen.insert(name.as_str(), address);
            }
        }
    }

    fn receivers(&mut self, wire: BTreeMap<String, wire::Receiver>) -> BTreeMap<Address, Receiver> {
        wire.into_iter()
            .filter_map(|(raw, block)| {
                let address = self.address("receivers", &raw)?;
                let receiver = self.receiver(&raw, block)?;
                Some((address, receiver))
            })
            .collect()
    }

    fn guardrails(
        &mut self,
        wire: BTreeMap<String, wire::Guardrail>,
        defaults: Defaults,
    ) -> BTreeMap<Address, Guardrail> {
        wire.into_iter()
            .filter_map(|(raw, block)| {
                let address = self.address("guardrails", &raw)?;
                let guardrail = self.guardrail(&raw, block, defaults)?;
                Some((address, guardrail))
            })
            .collect()
    }

    fn keys(
        &mut self,
        wire: BTreeMap<String, wire::Key>,
        defaults: Defaults,
        guardrails: &BTreeSet<String>,
        receivers: &BTreeSet<String>,
    ) -> BTreeMap<Address, Key> {
        wire.into_iter()
            .filter_map(|(raw, block)| {
                let address = self.address("keys", &raw)?;
                let key = self.key(&raw, block, defaults, guardrails, receivers)?;
                Some((address, key))
            })
            .collect()
    }

    fn address(&mut self, kind: &str, raw: &str) -> Option<Address> {
        // `Address::parse` refuses this too. Catching it here first is for the
        // wording: a configuration mistake deserves an answer about
        // configuration, not about what an address may contain.
        if looks_like_credential(raw) {
            self.problem(
                format!("{kind}.{}", safe_segment(raw)),
                "a local address must not look like a credential; Keymaster never accepts \
                 secret material in configuration",
            );
            return None;
        }
        match Address::parse(raw) {
            Ok(address) => Some(address),
            Err(error) => {
                self.problem(format!("{kind}.{}", safe_segment(raw)), error.to_string());
                None
            }
        }
    }

    fn guardrail(
        &mut self,
        raw: &str,
        block: wire::Guardrail,
        defaults: Defaults,
    ) -> Option<Guardrail> {
        let path = format!("guardrails.{}", safe_segment(raw));
        let before = self.count();
        let cleared = self.clears(&path, &block.clear, GUARDRAIL_CLEARABLE);

        let name = self.name(&format!("{path}.name"), block.name);
        let description_path = format!("{path}.description");
        let described = block.description.is_some();
        let description = block
            .description
            .and_then(|value| self.text(&description_path, value, DESCRIPTION_MAX));
        let description = self.managed(
            &description_path,
            described,
            description,
            &cleared,
            "description",
        );
        // OpenRouter rejects `POST /guardrails` with "Reset interval is
        // required when setting a budget limit", so the pairing is mandatory
        // here even though the OpenAPI document only marks `name` required.
        let (limit, reset_interval) = self.budget(
            &path,
            ("limit_usd", block.limit_usd),
            ("reset_interval", block.reset_interval),
            &cleared,
            BudgetPairing::ResetRequired,
        );
        let allowed_models = self.slugs(&path, "allowed_models", block.allowed_models);
        let denied_models = self.slugs(&path, "denied_models", block.denied_models);
        let allowed_providers = self.slugs(&path, "allowed_providers", block.allowed_providers);
        let denied_providers = self.slugs(&path, "denied_providers", block.denied_providers);

        let guardrail = Guardrail {
            name: name?,
            description,
            allowed_models,
            denied_models,
            allowed_providers,
            denied_providers,
            limit,
            reset_interval,
            include_byok_in_limit: block
                .include_byok_in_limit
                .unwrap_or(defaults.include_byok_in_limit),
            require_zdr: block.require_zdr,
        };
        (self.count() == before).then_some(guardrail)
    }

    fn key(
        &mut self,
        raw: &str,
        block: wire::Key,
        defaults: Defaults,
        guardrails: &BTreeSet<String>,
        receivers: &BTreeSet<String>,
    ) -> Option<Key> {
        let path = format!("keys.{}", safe_segment(raw));
        let before = self.count();
        let cleared = self.clears(&path, &block.clear, KEY_CLEARABLE);

        let name = self.name(&format!("{path}.name"), block.name);
        // A key budget stands on its own: the OpenAPI document defines
        // `limit_reset` as "daily, weekly, monthly, or null for no reset", so
        // a key limit with no reset interval is a spending cap that never
        // refills. Only guardrails require the pair.
        let (limit, limit_reset) = self.budget(
            &path,
            ("limit_usd", block.limit_usd),
            ("limit_reset", block.limit_reset),
            &cleared,
            BudgetPairing::ResetOptional,
        );

        let expiring = block.expires_at.is_some();
        let expires_at = self.timestamp(&format!("{path}.expires_at"), block.expires_at);
        let expires_at = self.managed(
            &format!("{path}.expires_at"),
            expiring,
            expires_at,
            &cleared,
            "expires_at",
        );

        let guardrail_path = format!("{path}.guardrail");
        let guarded = block.guardrail.is_some();
        let guardrail = self.reference(&guardrail_path, block.guardrail, guardrails, "guardrail");
        let guardrail = self.managed(&guardrail_path, guarded, guardrail, &cleared, "guardrail");

        let workspace_id = self.uuid(&format!("{path}.workspace_id"), block.workspace_id);
        let creator_user_id =
            self.user_id(&format!("{path}.creator_user_id"), block.creator_user_id);
        let receiver = self.reference(
            &format!("{path}.receiver"),
            block.receiver,
            receivers,
            "receiver",
        );
        let generation = self.generation(&format!("{path}.generation"), block.generation);

        let key = Key {
            name: name?,
            limit,
            limit_reset,
            expires_at,
            disabled: block.disabled.unwrap_or(false),
            workspace_id,
            creator_user_id,
            guardrail,
            receiver,
            generation,
            include_byok_in_limit: block
                .include_byok_in_limit
                .unwrap_or(defaults.include_byok_in_limit),
        };
        (self.count() == before).then_some(key)
    }

    fn receiver(&mut self, raw: &str, block: wire::Receiver) -> Option<Receiver> {
        let path = format!("receivers.{}", safe_segment(raw));
        match block {
            wire::Receiver::File { path: file } => Some(Receiver::File {
                path: self.absolute_path(&format!("{path}.path"), file)?,
            }),
            wire::Receiver::Command { program, args } => {
                let program = self.absolute_path(&format!("{path}.program"), program);
                let args = self.args(&format!("{path}.args"), args);
                Some(Receiver::Command {
                    program: program?,
                    args: args?,
                })
            }
            wire::Receiver::Caller { destination } => {
                let path = format!("{path}.destination");
                let Some(destination) = destination else {
                    self.problem(path, "is required");
                    return None;
                };
                Some(Receiver::Caller {
                    destination: self.text(&path, destination, DESTINATION_MAX)?,
                })
            }
        }
    }

    /// A USD limit and its reset interval, which are only meaningful together.
    fn budget(
        &mut self,
        path: &str,
        limit: (&str, Option<wire::Number>),
        reset: (&str, Option<String>),
        cleared: &BTreeSet<String>,
        pairing: BudgetPairing,
    ) -> (Managed<Usd>, Managed<ResetInterval>) {
        let (limit_field, limit_value) = limit;
        let (reset_field, reset_value) = reset;
        let limit_path = format!("{path}.{limit_field}");
        let reset_path = format!("{path}.{reset_field}");

        let limit_given = limit_value.is_some();
        let limit_parsed = self.usd(&limit_path, limit_value);
        let limit = self.managed(&limit_path, limit_given, limit_parsed, cleared, limit_field);

        let reset_given = reset_value.is_some();
        let reset_parsed = self.interval(&reset_path, reset_value);
        let reset = self.managed(&reset_path, reset_given, reset_parsed, cleared, reset_field);

        if matches!(reset, Managed::Set(_)) && !matches!(limit, Managed::Set(_)) {
            self.problem(
                &reset_path,
                format!("a reset interval needs `{limit_field}`; there is no budget to reset"),
            );
        } else if pairing == BudgetPairing::ResetRequired
            && matches!(limit, Managed::Set(_))
            && !matches!(reset, Managed::Set(_))
        {
            self.problem(
                &reset_path,
                format!(
                    "a budget needs `{reset_field}`; OpenRouter refuses a guardrail limit with \
                     no reset interval"
                ),
            );
        }
        (limit, reset)
    }

    /// Combines a parsed value with the block's `clear` list.
    fn managed<T>(
        &mut self,
        path: &str,
        given: bool,
        parsed: Option<T>,
        cleared: &BTreeSet<String>,
        field: &str,
    ) -> Managed<T> {
        let cleared = cleared.contains(field);
        if given && cleared {
            self.problem(
                path,
                format!(
                    "is both set and listed in `clear`; choose one, or omit `{field}` to \
                         leave the remote value alone"
                ),
            );
            return Managed::Unmanaged;
        }
        if cleared {
            return Managed::Cleared;
        }
        parsed.map_or(Managed::Unmanaged, Managed::Set)
    }

    fn clears(&mut self, path: &str, list: &[String], allowed: &[&str]) -> BTreeSet<String> {
        let mut cleared = BTreeSet::new();
        for (index, field) in list.iter().enumerate() {
            if allowed.contains(&field.as_str()) {
                cleared.insert(field.clone());
            } else {
                self.problem(
                    format!("{path}.clear[{index}]"),
                    format!(
                        "cannot be cleared; clearable fields are {}",
                        joined(allowed)
                    ),
                );
            }
        }
        cleared
    }

    fn name(&mut self, path: &str, value: Option<String>) -> Option<RemoteName> {
        let Some(value) = value else {
            self.problem(path, "is required");
            return None;
        };
        match RemoteName::parse(&value) {
            Ok(name) => Some(name),
            Err(error) => {
                self.problem(path, error.to_string());
                None
            }
        }
    }

    /// A single-line human string: trimmed, bounded, and never a credential.
    fn text(&mut self, path: &str, value: String, limit: usize) -> Option<String> {
        let value = value.trim().to_owned();
        if value.is_empty() {
            self.problem(path, "must not be empty");
            return None;
        }
        if value.chars().count() > limit {
            self.problem(path, format!("must be at most {limit} characters"));
            return None;
        }
        if value.chars().any(char::is_control) {
            self.problem(path, "must not contain control characters");
            return None;
        }
        if looks_like_credential(&value) {
            self.problem(path, CREDENTIAL_REFUSAL);
            return None;
        }
        Some(value)
    }

    fn usd(&mut self, path: &str, value: Option<wire::Number>) -> Option<Usd> {
        // An integer too large for `f64` to hold exactly is far past the
        // maximum budget, so `Usd::from_dollars` rejects it either way.
        let dollars = match value? {
            wire::Number::Integer(whole) => whole as f64,
            wire::Number::Float(fractional) => fractional,
        };
        match Usd::from_dollars(dollars) {
            Ok(amount) => Some(amount),
            Err(problem) => {
                self.problem(path, problem.message());
                None
            }
        }
    }

    fn interval(&mut self, path: &str, value: Option<String>) -> Option<ResetInterval> {
        let value = value?;
        match ResetInterval::parse(&value) {
            Some(interval) => Some(interval),
            None => {
                self.problem(path, "expected `daily`, `weekly`, or `monthly`");
                None
            }
        }
    }

    fn timestamp(&mut self, path: &str, value: Option<String>) -> Option<OffsetDateTime> {
        let value = value?;
        match OffsetDateTime::parse(&value, &Rfc3339) {
            Ok(parsed) => Some(parsed.to_offset(UtcOffset::UTC)),
            Err(_) => {
                self.problem(
                    path,
                    "expected an RFC 3339 timestamp, for example 2027-01-01T00:00:00Z",
                );
                None
            }
        }
    }

    fn uuid(&mut self, path: &str, value: Option<String>) -> Option<Uuid> {
        let value = value?;
        match Uuid::parse(&value) {
            Ok(uuid) => Some(uuid),
            Err(error) => {
                self.problem(path, error.to_string());
                None
            }
        }
    }

    /// An OpenRouter organization member identifier.
    fn user_id(&mut self, path: &str, value: Option<String>) -> Option<UserId> {
        let value = value?;
        match UserId::parse(&value) {
            Ok(user) => Some(user),
            Err(error) => {
                self.problem(path, error.to_string());
                None
            }
        }
    }

    fn generation(&mut self, path: &str, value: Option<i64>) -> u32 {
        let Some(generation) = value else {
            return 1;
        };
        match u32::try_from(generation) {
            Ok(generation) if generation >= 1 => generation,
            _ => {
                self.problem(path, "must be a whole number of at least 1");
                1
            }
        }
    }

    fn slugs(
        &mut self,
        path: &str,
        field: &str,
        value: Option<Vec<String>>,
    ) -> Option<BTreeSet<String>> {
        let value = value?;
        let mut slugs = BTreeSet::new();
        for (index, raw) in value.iter().enumerate() {
            let slug = raw.trim().to_ascii_lowercase();
            let entry = format!("{path}.{field}[{index}]");
            if slug.is_empty() {
                self.problem(entry, "must not be empty");
            } else if slug.chars().count() > SLUG_MAX {
                self.problem(entry, format!("must be at most {SLUG_MAX} characters"));
            } else if !slug.bytes().all(|byte| byte.is_ascii_graphic()) {
                // Printable ASCII with no spaces covers whitespace, control
                // characters, and anything non-ASCII in one rule. A slug is an
                // identifier OpenRouter publishes, not free text, and an
                // escape sequence in one would reach a plan and a log.
                self.problem(
                    entry,
                    "must be printable ASCII with no spaces; a model or provider slug looks \
                     like `google/gemini-2.5-flash`",
                );
            } else if looks_like_credential(&slug) {
                self.problem(entry, CREDENTIAL_REFUSAL);
            } else {
                slugs.insert(slug);
            }
        }
        Some(slugs)
    }

    fn reference(
        &mut self,
        path: &str,
        value: Option<String>,
        declared: &BTreeSet<String>,
        kind: &str,
    ) -> Option<Address> {
        let value = value?;
        if !declared.contains(&value) {
            self.problem(
                path,
                format!("names a {kind} that is not configured; add a `[{kind}s.…]` block"),
            );
            return None;
        }
        match Address::parse(&value) {
            Ok(address) => Some(address),
            Err(error) => {
                self.problem(path, error.to_string());
                None
            }
        }
    }

    fn absolute_path(&mut self, path: &str, value: Option<String>) -> Option<PathBuf> {
        let Some(value) = value else {
            self.problem(path, "is required");
            return None;
        };
        let candidate = PathBuf::from(&value);
        if value.is_empty() {
            self.problem(path, "must not be empty");
        } else if value.len() > PATH_MAX {
            self.problem(path, format!("must be at most {PATH_MAX} bytes"));
        } else if looks_like_credential(&value) {
            self.problem(path, CREDENTIAL_REFUSAL);
        } else if value.chars().any(char::is_control) {
            self.problem(path, CONTROL_REFUSAL);
        } else if !candidate.is_absolute() {
            self.problem(
                path,
                "must be an absolute path; a relative path would depend on the directory \
                 Keymaster happens to run from",
            );
        } else if candidate
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        {
            self.problem(path, "must not contain a `..` component");
        } else {
            return Some(candidate);
        }
        None
    }

    fn args(&mut self, path: &str, values: Vec<String>) -> Option<Vec<String>> {
        let before = self.count();
        if values.len() > ARGS_MAX {
            self.problem(path, format!("must hold at most {ARGS_MAX} arguments"));
        }
        for (index, value) in values.iter().enumerate() {
            let entry = format!("{path}[{index}]");
            if value.len() > PATH_MAX {
                self.problem(entry, format!("must be at most {PATH_MAX} bytes"));
            } else if looks_like_credential(value) {
                self.problem(entry, CREDENTIAL_REFUSAL);
            } else if value.chars().any(char::is_control) {
                self.problem(entry, CONTROL_REFUSAL);
            }
        }
        (self.count() == before).then_some(values)
    }
}

/// What every refusal of a control character in a path or argument says.
///
/// Unlike a slug, a path or an argument may legitimately hold a space or
/// non-ASCII text, so only control characters are refused. A NUL cannot
/// survive the conversion the operating system requires and would fail at
/// delivery — after a key exists and its plaintext is in hand, which is the
/// worst moment to discover a configuration mistake. The rest would corrupt
/// the log line or error that names the path.
const CONTROL_REFUSAL: &str = "must not contain control characters; a receiver is reached \
                               through this exact value, so it cannot be discovered to be \
                               unusable at delivery time";

/// What every refusal of credential-shaped input says.
const CREDENTIAL_REFUSAL: &str = "looks like a credential; Keymaster never accepts secret \
                                  material in configuration, and a key's plaintext is delivered \
                                  through a receiver instead";

/// Renders a field list for an error message.
fn joined(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|field| format!("`{field}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A configuration path segment that is safe to print back to an operator.
///
/// A table's name comes from the file, so it can be anything at all: a pasted
/// credential, which must not be echoed; an unbounded string, which must not
/// fill the terminal; or a control sequence, which must not reach the terminal
/// as a control sequence. The segment is truncated first and escaped second,
/// so the bound applies to what was written rather than to what escaping made
/// of it.
fn safe_segment(raw: &str) -> String {
    if looks_like_credential(raw) {
        return "[redacted]".to_owned();
    }
    let truncated: String = raw.chars().take(SEGMENT_MAX).collect();
    printable(&truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_segment_never_carries_a_control_sequence_to_the_terminal() {
        let segment = safe_segment("job\u{1b}[2Kfeed\nname");
        assert_eq!(segment, "job\\u{1b}[2Kfeed\\nname");
        assert!(!segment.contains('\u{1b}'));
        assert!(!segment.contains('\n'));
    }

    #[test]
    fn a_path_segment_is_redacted_bounded_and_left_alone_when_it_is_ordinary() {
        assert_eq!(safe_segment("golf_jobfeed"), "golf_jobfeed");
        assert_eq!(safe_segment("sk-or-v1-leaked"), "[redacted]");

        let long = "a".repeat(SEGMENT_MAX * 2);
        assert_eq!(safe_segment(&long), "a".repeat(SEGMENT_MAX));
    }
}
