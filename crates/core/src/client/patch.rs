//! The three states a field of a `PATCH` body can be in.
//!
//! JSON distinguishes an absent field from one whose value is `null`, and
//! OpenRouter's `PATCH` endpoints act on that difference: an absent field is
//! left as it is, and a `null` clears it. Getting this wrong is not a cosmetic
//! bug — serializing an unmanaged field as `null` would erase a budget or an
//! expiry that Keymaster was never asked to touch — so the distinction is a
//! type rather than an `Option` convention.
//!
//! [`Patch`] is the wire spelling of [`crate::config::Managed`], which is the
//! same three states as an operator writes them in TOML.

use serde::{Serialize, Serializer};

use crate::config::Managed;

/// One field of a `PATCH` body.
///
/// A field must be marked `#[serde(skip_serializing_if = "Patch::is_omitted")]`
/// for [`Patch::Omit`] to actually vanish from the body; serde has no other way
/// to leave a field out. [`Patch::serialize`] would otherwise write `null`,
/// which is the safest of the two wrong answers to write by accident, since it
/// is at least visible in a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Patch<T> {
    /// Leave the remote field alone: do not send it.
    Omit,
    /// Set the remote field to this value.
    Set(T),
    /// Clear the remote field: send `null`.
    Clear,
}

impl<T> Patch<T> {
    /// Whether this field should be left out of the body entirely.
    #[must_use]
    pub const fn is_omitted(&self) -> bool {
        matches!(self, Self::Omit)
    }

    /// Converts a desired field into its wire form.
    ///
    /// The conversion is a total function on purpose: every state an operator
    /// can express has exactly one spelling on the wire, and there is nowhere
    /// for a fourth case to hide.
    pub fn from_managed<D>(managed: &Managed<D>, to_wire: impl FnOnce(&D) -> T) -> Self {
        match managed {
            Managed::Unmanaged => Self::Omit,
            Managed::Set(value) => Self::Set(to_wire(value)),
            Managed::Cleared => Self::Clear,
        }
    }

    /// Turns an explicit clear into an omission.
    ///
    /// For a create body: there is no remote value yet, so "this field should
    /// hold nothing" and "do not mention this field" describe the same
    /// resource. Sending `null` at creation would be asking a server that has
    /// never seen the field to unset it, which some endpoints reject and none
    /// needs.
    #[must_use]
    pub fn omit_clears(self) -> Self {
        match self {
            Self::Clear => Self::Omit,
            other => other,
        }
    }
}

impl<T: Serialize> Serialize for Patch<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Set(value) => value.serialize(serializer),
            Self::Omit | Self::Clear => serializer.serialize_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Usd;
    use serde::Serialize;
    use serde_json::json;

    #[derive(Serialize)]
    struct Body {
        #[serde(skip_serializing_if = "Patch::is_omitted")]
        name: Patch<&'static str>,
        #[serde(skip_serializing_if = "Patch::is_omitted")]
        limit: Patch<f64>,
        #[serde(skip_serializing_if = "Patch::is_omitted")]
        limit_reset: Patch<&'static str>,
    }

    #[test]
    fn omitted_fields_vanish_and_cleared_fields_are_null() {
        let body = Body {
            name: Patch::Set("jobfeed"),
            limit: Patch::Clear,
            limit_reset: Patch::Omit,
        };
        assert_eq!(
            serde_json::to_value(&body).expect("a serializable body"),
            json!({ "name": "jobfeed", "limit": null })
        );
    }

    #[test]
    fn a_create_body_omits_what_an_update_body_would_clear() {
        let body = Body {
            name: Patch::Set("jobfeed"),
            limit: Patch::<f64>::Clear.omit_clears(),
            limit_reset: Patch::<&str>::Omit.omit_clears(),
        };
        assert_eq!(
            serde_json::to_value(&body).expect("a serializable body"),
            json!({ "name": "jobfeed" })
        );
        assert_eq!(Patch::Set(5.0).omit_clears(), Patch::Set(5.0));
    }

    #[test]
    fn every_desired_state_has_one_wire_spelling() {
        let dollars = |usd: &Usd| usd.dollars();
        assert_eq!(
            Patch::from_managed(&Managed::<Usd>::Unmanaged, dollars),
            Patch::Omit
        );
        assert_eq!(
            Patch::from_managed(&Managed::<Usd>::Cleared, dollars),
            Patch::Clear
        );

        let five = Usd::from_dollars(5.0).expect("five dollars");
        assert_eq!(
            Patch::from_managed(&Managed::Set(five), dollars),
            Patch::Set(5.0)
        );
    }
}
