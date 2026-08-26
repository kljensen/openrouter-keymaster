//! The `openrouter-keymaster` command line: argument parsing, dispatch, and
//! rendering.
//!
//! Everything that decides what an operation does lives in
//! [`openrouter_keymaster_core`]. This crate reads the environment, builds a
//! core context from the parsed arguments, calls one `ops` function, and
//! renders what it returned. Only [`output`] writes to stdout or stderr.
//!
//! It is a library as well as a binary so the integration tests — including
//! the live suite, which builds its client from the same two variables the
//! binary reads — can call into it.

pub mod app;
pub mod cli;
pub mod output;
