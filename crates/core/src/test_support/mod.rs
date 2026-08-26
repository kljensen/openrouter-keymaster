//! Shared test support: a local HTTP server, JSON fixtures, a fake clock, a
//! fake secret receiver, and the secret sentinel.
//!
//! Compiled only under the `test-support` feature. Every test binary that
//! needs any of this reaches it through the feature rather than through a copy
//! of its own. Nothing here reaches the network or reads a real credential.
//!
//! The `Project` harness that runs the compiled binary is not here: it lives
//! in the CLI crate's tests, because `Command::cargo_bin` only finds a binary
//! of the package under test.

#![allow(
    dead_code,
    reason = "each test binary uses a different part of the shared harness"
)]

pub mod clock;
pub mod fixtures;
pub mod http;
pub mod receiver;
pub mod sentinel;
