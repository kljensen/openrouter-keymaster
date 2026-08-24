//! Shared test support: a local HTTP server, JSON fixtures, a fake clock, a
//! fake secret receiver, and the secret sentinel.
//!
//! Every integration test that needs any of this declares `mod support;`.
//! Nothing here reaches the network or reads a real credential.

#![allow(
    dead_code,
    reason = "each test binary uses a different part of the shared harness"
)]

pub mod clock;
pub mod fixtures;
pub mod http;
pub mod project;
pub mod receiver;
pub mod sentinel;
