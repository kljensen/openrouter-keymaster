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

// The public surface is curated (ADR-0003, item 7): what the `ops` signatures
// expose, plus what a host needs to *read* configuration and state. Everything
// else — the HTTP client, the OpenRouter resource layer, the planner, the
// receivers, redaction — is an implementation detail behind `ops`.
//
// Those five are declared twice. Under `test-support` they are `pub`, because
// both crates' test suites drive them directly and a test is an external
// consumer; without it — the shape every non-test build has, and the one a
// host compiles against — they are `pub(crate)`. The feature pulls a mock HTTP
// server into the dependency graph, so no shipped build turns it on.
//
// The `pub(crate)` arm allows dead code because an accessor only the test
// suites reach is unused there. The other arm never caught one either: a `pub`
// item in a `pub` module is never dead.
#[cfg(feature = "test-support")]
pub mod api;
#[cfg(not(feature = "test-support"))]
#[allow(dead_code)]
pub(crate) mod api;

#[cfg(feature = "test-support")]
pub mod client;
#[cfg(not(feature = "test-support"))]
#[allow(dead_code)]
pub(crate) mod client;

#[cfg(feature = "test-support")]
pub mod plan;
#[cfg(not(feature = "test-support"))]
#[allow(dead_code)]
pub(crate) mod plan;

#[cfg(feature = "test-support")]
pub mod receiver;
#[cfg(not(feature = "test-support"))]
#[allow(dead_code)]
pub(crate) mod receiver;

#[cfg(feature = "test-support")]
pub mod redaction;
#[cfg(not(feature = "test-support"))]
#[allow(dead_code)]
pub(crate) mod redaction;

pub mod config;
pub mod error;
pub(crate) mod files;
pub mod ids;
pub mod ops;
pub mod report;
pub mod state;

/// The exit code a receiver command uses to say it refused the secret and
/// committed nothing.
///
/// Re-exported here because a host that writes a receiver command needs it and
/// the receiver implementations themselves are internal.
pub use crate::receiver::command::REJECTED_EXIT_CODE;

/// The shared test harness: a local HTTP server, JSON fixtures, a fake clock,
/// a fake secret receiver, and the secret sentinel.
///
/// Compiled only with the `test-support` feature, which the CLI crate's
/// dev-dependency turns on. It lives here rather than beside either crate's
/// tests so there is one copy, and so the fake receiver keeps its access to
/// the crate-private receiver types.
#[cfg(feature = "test-support")]
pub mod test_support;
