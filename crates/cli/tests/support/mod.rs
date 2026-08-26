//! The test harness, as the binary crate's tests see it.
//!
//! The shared parts — the local HTTP server, the fixtures, the fake clock, the
//! fake receiver, and the secret sentinel — come from core's `test_support`
//! module, which the dev-dependency's `test-support` feature compiles in.
//! Only [`project`], which runs the compiled binary, is local to this crate.

#![allow(
    dead_code,
    reason = "each test binary uses a different part of the shared harness"
)]

pub use openrouter_keymaster_core::test_support::*;

pub mod project;
