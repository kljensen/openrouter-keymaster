//! The digest that makes a shown plan binding.
//!
//! A host that shows a plan and an "apply" button has to be able to say "apply
//! *this*". The fingerprint is how: it covers every input that decides what an
//! apply would write and where, so two plans computed from the same inputs
//! share one, and a change to any of them between the plan and the apply does
//! not (ADR-0003).
//!
//! What it covers, and why that is enough: the endpoint and a non-reversible
//! digest of the management credential (the same plan against a different
//! account is a different plan), the workspace scope (the same plan placed
//! somewhere else is a different plan), the state file path, the whole
//! normalized configuration, the whole state as read — its serial advances on
//! every write, so any state change is a different plan — and the executable
//! actions.
//! Binding the whole configuration and the whole state rather than a list of
//! fields is deliberate: every value apply resolves while issuing a key — the
//! bound guardrail's UUID, the effective generation, the receiver destination —
//! comes from one of them, so nothing has to be enumerated and nothing can be
//! forgotten.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Context;
use crate::config::Config;
use crate::ids::Uuid;
use crate::report::PlanReport;
use crate::state::State;

/// Separates this preimage from every other SHA-256 in Keymaster, and pins the
/// set of inputs: a build that binds something else must not produce a digest
/// an older one could match.
const DOMAIN: &[u8] = b"openrouter-keymaster plan fingerprint v2";

/// How many characters a fingerprint has: SHA-256, lowercase hexadecimal.
const LENGTH: usize = 64;

/// The digest of everything that decides what an apply would write.
///
/// Opaque by design: it is compared for equality and nothing else. It carries
/// no part of the configuration, the state, or the credential — only a digest
/// of them — so it is safe to hand to a browser and to read back.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PlanFingerprint(String);

impl PlanFingerprint {
    /// Parses a fingerprint a caller is handing back.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintError`] unless the value is exactly 64 lowercase
    /// hexadecimal characters.
    pub fn parse(value: &str) -> Result<Self, FingerprintError> {
        let shaped = value.len() == LENGTH
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !shaped {
            return Err(FingerprintError);
        }
        Ok(Self(value.to_owned()))
    }

    /// The fingerprint as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Builds a fingerprint from a digest of the plan's inputs.
    fn from_digest(digest: [u8; 32]) -> Self {
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Self(hex)
    }
}

impl TryFrom<String> for PlanFingerprint {
    type Error = FingerprintError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PlanFingerprint> for String {
    fn from(value: PlanFingerprint) -> Self {
        value.0
    }
}

impl fmt::Display for PlanFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A value offered as a fingerprint that cannot be one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a plan fingerprint is 64 lowercase hexadecimal characters")]
pub struct FingerprintError;

/// The fingerprint of one plan, or `None` when the plan cannot be bound.
///
/// A plan is bindable only when no operation is pending: while one stands — in
/// any phase, including `delivered`, which a plain apply promotes before
/// planning — what an apply would do is not what this plan describes. Settle it
/// with a plain apply or `recover`, then plan again.
///
/// `None` is also the honest answer when an input cannot be encoded — a
/// configuration path that is not valid UTF-8, say, or a caller with no
/// credential. Nothing can be bound to an input nothing can digest, and a bound
/// apply refuses rather than matching, which is the safe direction.
pub(super) fn of(
    context: &Context,
    config: &Config,
    state: &State,
    report: &PlanReport,
) -> Option<PlanFingerprint> {
    if state.pending_operation().is_some() {
        return None;
    }
    let key = context.key.as_ref()?;
    let config = serde_json::to_vec(config).ok()?;
    let state = serde_json::to_vec(state).ok()?;
    let actions = report.executable_actions().ok()?;

    let mut hasher = Sha256::new();
    for component in [
        DOMAIN,
        context.options.base_url.as_bytes(),
        &key.digest(),
        context
            .workspace
            .as_ref()
            .map_or("", Uuid::as_str)
            .as_bytes(),
        context.paths.state.as_os_str().as_encoded_bytes(),
        &config,
        &state,
        &actions,
    ] {
        // Length-prefixed, so no two different sets of inputs can produce the
        // same bytes by one component running into the next.
        hasher.update(
            u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(component);
    }
    Some(PlanFingerprint::from_digest(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_is_sixty_four_lowercase_hexadecimal_characters() {
        let fingerprint = PlanFingerprint::from_digest([0xab; 32]);
        assert_eq!(fingerprint.as_str().len(), LENGTH);
        assert_eq!(
            PlanFingerprint::parse(fingerprint.as_str()),
            Ok(fingerprint)
        );

        assert!(PlanFingerprint::parse("ABC").is_err());
        assert!(
            PlanFingerprint::parse(&"AB".repeat(32)).is_err(),
            "uppercase is not the spelling this produces, so it is not one it accepts"
        );
    }
}
