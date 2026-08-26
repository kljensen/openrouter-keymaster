//! The process output boundary and the DTOs written through it.
//!
//! Core modules never print. They return values; [`Renderer`] writes them.
//! Stdout carries requested results only — human text, or exactly one JSON
//! document per run. Stderr carries diagnostics. Nothing written here is ever
//! colored, so `--json` output is machine-readable on a terminal too.
//!
//! Results are rendered from dedicated DTOs rather than internal types, so
//! adding a field to a domain type cannot silently change the output contract
//! or leak secret-bearing data into it.

use std::fmt::Display;
use std::io::{self, Write};

use serde::Serialize;

use openrouter_keymaster_core::error::Error;

/// How results are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Human-readable text.
    Human,
    /// Exactly one JSON document.
    Json,
}

impl Format {
    /// Selects the format the `--json` flag asks for.
    #[must_use]
    pub fn from_json_flag(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }
}

/// The JSON diagnostic DTO. Wrapped in an object so future runs can add
/// sibling fields without changing the shape of `error`.
#[derive(Debug, Serialize)]
struct ErrorDocument<'a> {
    error: ErrorBody<'a>,
}

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    kind: &'a str,
    message: String,
}

/// Writes command results to stdout and diagnostics to stderr.
///
/// Generic over both writers so the rendering contract can be unit tested
/// without spawning the binary.
#[derive(Debug)]
pub struct Renderer<O, E> {
    format: Format,
    out: O,
    err: E,
}

impl<O: Write, E: Write> Renderer<O, E> {
    /// Builds a renderer over the two output streams.
    pub fn new(format: Format, out: O, err: E) -> Self {
        Self { format, out, err }
    }

    /// Writes one command result to stdout.
    ///
    /// `Display` renders the human form and `Serialize` the JSON form; a
    /// result type must implement both so neither format can be forgotten.
    ///
    /// # Errors
    ///
    /// Returns the underlying write error, or an error whose kind reflects a
    /// failed serialization.
    pub fn result<T: Serialize + Display>(&mut self, report: &T) -> io::Result<()> {
        match self.format {
            Format::Human => writeln!(self.out, "{report}"),
            Format::Json => {
                let document = serde_json::to_string(report).map_err(io::Error::other)?;
                writeln!(self.out, "{document}")
            }
        }
    }

    /// Writes one warning to stderr, in human format only.
    ///
    /// Under `--json` a stream carries exactly one document, so a warning
    /// cannot be a second one on stderr. JSON results carry their warnings in
    /// the result document's `warnings` field instead, which is why this is a
    /// no-op there rather than an error.
    ///
    /// # Errors
    ///
    /// Returns the underlying write error.
    pub fn warning(&mut self, message: &str) -> io::Result<()> {
        match self.format {
            Format::Human => writeln!(self.err, "warning: {message}"),
            Format::Json => Ok(()),
        }
    }

    /// Writes one diagnostic to stderr.
    ///
    /// # Errors
    ///
    /// Returns the underlying write error.
    pub fn error(&mut self, error: &Error) -> io::Result<()> {
        match self.format {
            Format::Human => writeln!(self.err, "error: {error}"),
            Format::Json => {
                let document = ErrorDocument {
                    error: ErrorBody {
                        kind: error.kind(),
                        message: error.to_string(),
                    },
                };
                let document = serde_json::to_string(&document).map_err(io::Error::other)?;
                writeln!(self.err, "{document}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    /// Stands in for the result DTOs that feature issues will add.
    #[derive(Serialize)]
    struct Example {
        address: &'static str,
    }

    impl fmt::Display for Example {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "address {}", self.address)
        }
    }

    fn render(format: Format, report: &Example) -> (String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut renderer = Renderer::new(format, &mut out, &mut err);
        renderer.result(report).expect("writing to a vector");
        renderer
            .error(&Error::output(&io::Error::other("the pipe closed")))
            .expect("writing to a vector");
        (
            String::from_utf8(out).expect("utf-8"),
            String::from_utf8(err).expect("utf-8"),
        )
    }

    #[test]
    fn human_output_separates_results_from_diagnostics() {
        let (out, err) = render(Format::Human, &Example { address: "jobfeed" });
        assert_eq!(out, "address jobfeed\n");
        assert_eq!(err, "error: cannot write output: the pipe closed\n");
    }

    #[test]
    fn json_output_is_one_uncolored_document_per_stream() {
        let (out, err) = render(Format::Json, &Example { address: "jobfeed" });

        let result: serde_json::Value = serde_json::from_str(&out).expect("one JSON document");
        assert_eq!(result["address"], "jobfeed");

        let diagnostic: serde_json::Value = serde_json::from_str(&err).expect("one JSON document");
        assert_eq!(diagnostic["error"]["kind"], "output");

        assert!(!out.contains('\u{1b}'), "JSON results must not be colored");
        assert!(
            !err.contains('\u{1b}'),
            "JSON diagnostics must not be colored"
        );
    }
}
