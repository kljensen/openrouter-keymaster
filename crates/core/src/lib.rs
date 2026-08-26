//! Keymaster's core: declarative OpenRouter key and guardrail management,
//! without a command line.
//!
//! [`ops`] is the entry point — one function per operation, each taking a
//! [`Context`](ops::Context) and returning the operation's report. Nothing
//! here parses arguments, reads the environment, or writes to a terminal; the
//! `openrouter-keymaster` binary does all three.
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
    "openrouter-keymaster v0.1 supports Unix platforms only; state durability and permission \
     guarantees are implemented for Unix"
);

pub mod api;
pub mod client;
pub mod config;
pub mod error;
pub(crate) mod files;
pub mod ids;
pub mod ops;
pub mod plan;
pub mod receiver;
pub mod redaction;
pub mod report;
pub mod state;

/// The shared test harness: a local HTTP server, JSON fixtures, a fake clock,
/// a fake secret receiver, and the secret sentinel.
///
/// Compiled only with the `test-support` feature, which the CLI crate's
/// dev-dependency turns on. It lives here rather than beside either crate's
/// tests so there is one copy, and so the fake receiver keeps its access to
/// the crate-private receiver types.
#[cfg(feature = "test-support")]
pub mod test_support;
