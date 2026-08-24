//! The output DTOs the read-only commands render.
//!
//! These types exist so that adding a field to a domain type cannot change the
//! output contract or leak something that must not be printed. Nothing here
//! borrows a secret-bearing type: the plan, state, and observation types the
//! builders read have no field that can hold credential plaintext, and every
//! value that reaches a DTO is a hash, a UUID, an address, a name, an amount,
//! a timestamp, or a fixed string this module wrote itself.
//!
//! Most of those were checked by a parser that rejects credential-shaped and
//! control-bearing input. The exception is text OpenRouter wrote — a display
//! name, a description, a slug — which nothing has checked, so every one of
//! those goes through [`scrubbed`] on its way into a DTO.
//!
//! Every DTO implements both `Serialize` and `Display`, which is what
//! [`crate::output::Renderer`] requires: neither format can be forgotten.
//! Rendering is deterministic — no clock is read, and every collection is
//! either already ordered by the planner or ordered here — so two runs over
//! the same three inputs produce byte-identical output.

mod apply;
mod import;
mod plan;
mod status;

#[cfg(test)]
mod tests;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ids::{Address, KeyHash, OperationId};
use crate::state::Phase;

pub use apply::{ActionOutcome, ApplyReport};
pub use import::ImportReport;
pub use plan::PlanReport;
pub use status::StatusReport;

/// An unfinished create-or-deliver operation, and what to do about it.
///
/// The five fields are the ones an operator needs to act: which attempt it was,
/// how far it got, when, which remote key it is known to have produced if any,
/// and the command that resolves it. None of them is secret — the plaintext an
/// operation carries is exactly what is never recorded anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    /// The operation's identifier, as journaled before the request.
    operation: String,
    /// How far it got.
    phase: &'static str,
    /// When it reached that phase, RFC 3339.
    phase_at: String,
    /// The created key's immutable hash, when the journal records one.
    #[serde(skip_serializing_if = "Option::is_none")]
    known_hash: Option<String>,
    /// What an operator should do next. Never contains secret material.
    remediation: String,
}

impl RecoveryReport {
    /// Describes one incomplete operation at `address`.
    fn new(
        operation: &OperationId,
        phase: Phase,
        phase_at: OffsetDateTime,
        known_hash: Option<&KeyHash>,
        address: Option<&Address>,
    ) -> Self {
        Self {
            operation: operation.as_str().to_owned(),
            phase: phase.as_str(),
            phase_at: timestamp(phase_at),
            known_hash: known_hash.map(|hash| hash.as_str().to_owned()),
            remediation: remediation(phase, address),
        }
    }

    /// The human form, as lines under a caller-supplied indent.
    fn lines(&self, indent: &str) -> Vec<String> {
        let mut lines = vec![format!(
            "{indent}operation {operation} in phase `{phase}` at {phase_at}",
            operation = self.operation,
            phase = self.phase,
            phase_at = self.phase_at
        )];
        if let Some(hash) = &self.known_hash {
            lines.push(format!("{indent}known key hash: {hash}"));
        }
        lines.push(format!("{indent}remediation: {}", self.remediation));
        lines
    }
}

/// What resolves an operation stopped in `phase`.
///
/// Keyed to the phase because the phases differ in what they leave undecided:
/// two of them are settled by the journal alone, and the rest need an operator
/// to establish what OpenRouter and the receiver actually did (ADR-0002).
fn remediation(phase: Phase, address: Option<&Address>) -> String {
    let name = address.map_or("NAME", Address::as_str);
    match phase {
        Phase::CreateStarted | Phase::CreateAmbiguous => format!(
            "the create request may or may not have created a key. Run `keymaster recover \
             inspect {name}` to see the remote keys that carry the recorded name, then attest \
             what you found with `keymaster recover resolve {name}`."
        ),
        Phase::Created => format!(
            "a key exists but its restrictions were never verified, so it may be an \
             unrestricted live credential. Run `keymaster recover inspect {name}`, then attest \
             the outcome with `keymaster recover resolve {name}`."
        ),
        Phase::Secured => format!(
            "the key exists and is restricted, and its plaintext no longer exists anywhere, so \
             it can never be delivered. Create a successor with `keymaster recover replace \
             {name}`."
        ),
        Phase::DeliveryStarted | Phase::DeliveryAmbiguous => format!(
            "the receiver may or may not hold the plaintext, and it can never be delivered \
             again. Establish what the receiver has, run `keymaster recover resolve {name}` to \
             record it, then `keymaster recover replace {name}`."
        ),
        Phase::Delivered => format!(
            "the delivery finished and only local promotion is left; the next `keymaster apply` \
             completes it under its lock. Nothing remote is outstanding for `{name}`."
        ),
    }
}

/// Makes a string OpenRouter wrote safe to put in a report.
///
/// A snapshot string is the one class of text in a report that Keymaster did
/// not write and no parser has checked: a display name, a description, a
/// provider slug, and a reset schedule this build does not recognize are all
/// free text chosen by whoever last edited the resource. Two things can be
/// wrong with one.
///
/// It can quote a credential. An operator who pasted a key into a key's name —
/// or an attacker with dashboard access who wants one echoed into a log — would
/// otherwise have it read back verbatim by the one command an operator runs
/// most and pipes somewhere.
///
/// And it can carry a control character, which is not cosmetic: an ANSI escape
/// rewrites the line an operator is reading, and a bidirectional override makes
/// a name render as something other than what it is.
///
/// [`crate::redaction::redact`] answers both — it replaces every
/// credential-shaped token and escapes everything it does not replace — and it
/// is applied here, where a snapshot string enters a DTO, so nothing
/// downstream has to remember to.
fn scrubbed(value: &str) -> String {
    crate::redaction::redact(value)
}

/// An RFC 3339 timestamp, or the value's own rendering if it cannot be one.
fn timestamp(when: OffsetDateTime) -> String {
    when.format(&Rfc3339).unwrap_or_else(|_| when.to_string())
}

/// A dollar amount, rendered the way [`crate::config::Usd`] renders one so the
/// same number reads the same wherever it appears.
fn money(dollars: f64) -> String {
    format!("{dollars:.6}")
}

/// A count with a plural `s` when it needs one.
fn plural(count: usize, noun: &str) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("{count} {noun}{suffix}")
}
