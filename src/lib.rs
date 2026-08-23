//! Keymaster: declarative OpenRouter key and guardrail management.
//!
//! The binary is a thin wrapper over these modules. Only [`output`] writes to
//! stdout or stderr; everything else returns values.
//!
//! v0.1 is a Unix tool. The guarantees it makes about state — the durability
//! of an atomic write, and the `0700`/`0600` permissions on the file that
//! binds a local address to a live spending credential — are implemented with
//! Unix primitives and are only claimed there.

// Refusing to build is the honest response to a platform whose guarantees this
// version has not implemented. A build that compiled but silently skipped the
// directory fsync and the permission bits would look like a supported port.
#[cfg(not(unix))]
compile_error!(
    "keymaster v0.1 supports Unix platforms only; state durability and permission guarantees \
     are implemented for Unix"
);

pub mod api;
pub mod app;
pub mod cli;
pub mod client;
pub mod config;
pub mod error;
pub mod ids;
pub mod output;
pub mod plan;
pub mod redaction;
pub mod report;
pub mod state;
