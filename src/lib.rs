//! Keymaster: declarative OpenRouter key and guardrail management.
//!
//! The binary is a thin wrapper over these modules. Only [`output`] writes to
//! stdout or stderr; everything else returns values.

pub mod app;
pub mod cli;
pub mod config;
pub mod error;
pub mod ids;
pub mod output;
pub mod redaction;
