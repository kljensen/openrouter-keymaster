//! The command receiver: one program, one JSON envelope on its stdin.
//!
//! This is the receiver for real integrations. Keymaster knows nothing about
//! Ansible Vault, a cloud secret manager, or whatever else the operator keeps
//! credentials in; it runs a program they nominated and hands it the key on a
//! pipe. `docs/receiver-protocol.md` is the contract that program implements.
//!
//! # How the key travels
//!
//! One JSON object, on stdin, then stdin is closed. Nowhere else. Not in
//! `argv`, which every user on the machine can read out of the process list;
//! not in the environment, which is nearly as exposed and is inherited by
//! whatever the adapter runs next; not in a temporary file, a working
//! directory name, or a command line assembled for a shell. There is no shell:
//! the program is executed directly with the exact argument vector the
//! configuration lists, so there is no string for quoting to go wrong in.
//!
//! # The environment is empty
//!
//! The child starts with no environment variables at all — not a filtered
//! copy, an empty one. Keymaster's own process holds
//! `OPENROUTER_MANAGEMENT_KEY`, a credential that can create and delete every
//! key in the organization, and an adapter has no business seeing it. Since
//! there is no allowlist to get wrong and no passthrough to configure, an
//! adapter that needs configuration reads it from a file it knows the path of,
//! or is a wrapper script that sets its own variables.
//!
//! This means `PATH` is empty too, which is why the program must be an
//! absolute path: there is nothing to search.
//!
//! One honest caveat: "empty" describes what Keymaster passes, not always what
//! the child observes. macOS's runtime adds `__CF_USER_TEXT_ENCODING` to a
//! process it starts, below the level of anything this program controls.
//! Nothing of Keymaster's own environment survives, which is the property that
//! matters.
//!
//! # What each ending proves
//!
//! ADR-0002 makes ambiguity the default, and this is the receiver that
//! decision was written about. The adapter is a program Keymaster did not
//! write, so an exit status is a claim, not evidence — and only two of them
//! are claims the protocol lets Keymaster believe:
//!
//! - **Exit 0, after the whole envelope was written.** Delivered. The protocol
//!   says exit 0 means the adapter committed the key.
//! - **Exit [`REJECTED_EXIT_CODE`], after the whole envelope was written.**
//!   Rejected. That code has exactly one documented meaning — refused, nothing
//!   committed — and an adapter that uses it for anything else has broken the
//!   contract it opted into.
//! - **Any other nonzero exit.** Ambiguous. ADR-0002 is explicit: "an ordinary
//!   nonzero exit after the envelope was written" is `delivery_ambiguous`,
//!   because a program that failed at step three may well have committed at
//!   step two. A generic failure code says nothing about what was written.
//! - **A timeout, a signal, a lost status, or a broken pipe.** Ambiguous.
//! - **The program could not be started at all.** Rejected. Nothing ran, so
//!   nothing was committed — the one failure here where that is a fact about
//!   the mechanism rather than a claim by the adapter.
//!
//! Nothing is retried. A receiver that may already hold the key must not be
//! handed a second one.
//!
//! # Diagnostics cannot leak the key
//!
//! A bounded amount of the child's stdout and stderr is captured for the
//! operator, and the plaintext is removed from it before it goes anywhere —
//! by exact match, not by shape, because the one thing certain about the
//! echoed value is that Keymaster knows it. Beyond the cap the streams are
//! drained and discarded, so a chatty adapter cannot fill a pipe and hang.
//! What this cannot defend against is an adapter that transforms the key
//! before printing it; nothing can.
//!
//! # Nothing here can outlast the bound
//!
//! The output pipes belong to the adapter, but a descendant it started inherits
//! them and can hold them open after the adapter itself is gone. Waiting for
//! end-of-file on those pipes would therefore be waiting on a process Keymaster
//! never launched, has no handle for, and cannot kill — which would put an
//! unbounded wait immediately after the bounded one. So the two reader threads
//! hand their bytes back over a channel, and the collection is itself bounded
//! by [`CAPTURE_GRACE`]. When that expires the delivery is classified without
//! them.
//!
//! The envelope is written from a third thread for the mirror-image reason. An
//! adapter that stays alive without reading its stdin fills the pipe, and a
//! write performed inline would block there before the timeout could be
//! enforced — the bound would be enforced only against adapters that were
//! already cooperating. Writing beside the wait means the timeout kills the
//! child, the blocked write fails with a broken pipe, and the delivery is
//! classified ambiguously, because the envelope never arrived whole.
//!
//! The cost is a thread that may outlive the call, and this is the honest
//! statement of it: at most three per delivery, each holding a capped buffer or
//! the envelope, cleared when the thread ends, and each ending on its own when
//! the last handle to the pipe closes. Keymaster creates keys one at
//! a time and exits soon after, so these cannot accumulate. Killing the
//! descendant instead would need its process group, and putting the child in
//! one of its own needs `pre_exec`, which is `unsafe` and forbidden here.

use std::fmt::Write as _;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::{Zeroize as _, Zeroizing};

use super::{DeliveryMetadata, Outcome, SecretReceiver};
use crate::client::KeyPlaintext;

/// The envelope schema version. An adapter that does not recognize it must
/// refuse the delivery rather than guess at the fields.
pub const ENVELOPE_VERSION: u32 = 1;

/// The one exit code that means "refused, and nothing was committed".
///
/// Any other nonzero code is ambiguous, so an adapter that cannot promise it
/// committed nothing should simply not use this one.
pub const REJECTED_EXIT_CODE: i32 = 10;

/// How long a delivery may take before the child is killed.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How much of each stream is captured. Beyond this the output is drained and
/// discarded so the child never blocks on a full pipe.
const CAPTURED_BYTES: usize = 4096;

/// How much of each stream reaches a diagnostic.
const REPORTED_CHARS: usize = 200;

/// Longest pause between checks on a running child.
const POLL_INTERVAL_MAX: Duration = Duration::from_millis(20);

/// How long the captured output is waited for once the child is gone.
///
/// Normally the pipes close with the child and this is not reached at all. It
/// exists for the case where a descendant of the adapter inherited them and is
/// still running: the delivery must be classified anyway.
const CAPTURE_GRACE: Duration = Duration::from_secs(2);

/// How the child process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ending {
    /// It exited with this status code.
    Exited(i32),
    /// It was killed by a signal.
    Signalled(String),
    /// It outlived the timeout and was killed.
    TimedOut,
    /// Its status could not be collected.
    Lost(String),
}

impl Ending {
    fn of(status: ExitStatus) -> Self {
        match status.code() {
            Some(code) => Self::Exited(code),
            None => Self::Signalled(describe_signal(status)),
        }
    }
}

/// Names the signal that killed a process, when the platform will say.
fn describe_signal(status: ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        match status.signal() {
            Some(signal) => format!("signal {signal}"),
            None => "an unknown signal".to_owned(),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        "an unknown signal".to_owned()
    }
}

/// A receiver that runs a program and writes one envelope to its stdin.
#[derive(Debug, Clone)]
pub struct CommandReceiver {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

impl CommandReceiver {
    /// A receiver that runs `program` with exactly `args`.
    ///
    /// No shell, no `PATH` search, no argument rewriting: this vector is the
    /// child's `argv` after its own name, verbatim.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The same receiver with a different execution bound.
    #[must_use]
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    /// The program this receiver runs.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The arguments it is run with.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Prefixes a message with the receiver and its program.
    fn say(&self, message: &str) -> String {
        format!("command receiver {}: {message}", self.program.display())
    }

    /// Starts the program with an empty environment and every stream piped.
    fn spawn(&self) -> io::Result<Child> {
        Command::new(&self.program)
            .args(&self.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    /// Waits for the child, killing it if it outlives the timeout.
    ///
    /// Polling rather than a waiting thread: the killer needs the handle, and
    /// a CLI that runs one adapter at a time can afford to look twice a
    /// hundredth of a second.
    fn wait(&self, child: &mut Child) -> Ending {
        let deadline = Instant::now() + self.timeout;
        let mut interval = Duration::from_millis(1);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ending::of(status),
                Ok(None) => {}
                Err(error) => return Ending::Lost(error.to_string()),
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let _ = child.kill();
                let _ = child.wait();
                return Ending::TimedOut;
            }
            thread::sleep(interval.min(remaining));
            interval = (interval * 2).min(POLL_INTERVAL_MAX);
        }
    }

    /// Turns what happened into what it proves.
    fn classify(&self, written: Result<(), String>, ending: &Ending, diagnostic: &str) -> Outcome {
        let seconds = self.timeout.as_secs_f32();
        let detail = |message: &str| self.say(&format!("{message}{diagnostic}"));

        if let Err(error) = written {
            // ADR-0002 lists a broken pipe among the ambiguous endings: the
            // adapter may have read and acted on part of what it got.
            return Outcome::ambiguous(detail(&format!(
                "the envelope could not be written in full, so nothing it did can be trusted \
                 either way: {error}"
            )));
        }

        match ending {
            Ending::Exited(0) => Outcome::delivered(detail("the program exited 0")),
            Ending::Exited(code) if *code == REJECTED_EXIT_CODE => {
                Outcome::rejected(detail(&format!(
                    "the program exited {code}, the protocol's refused-nothing-committed code"
                )))
            }
            Ending::Exited(code) => Outcome::ambiguous(detail(&format!(
                "the program exited {code}, which the protocol does not define, so whether it \
                 committed the key is unknown"
            ))),
            Ending::Signalled(signal) => Outcome::ambiguous(detail(&format!(
                "the program was killed by {signal} and may have committed the key first"
            ))),
            Ending::TimedOut => Outcome::ambiguous(detail(&format!(
                "the program did not finish within {seconds:.1}s and was killed; it may have \
                 committed the key first"
            ))),
            Ending::Lost(error) => Outcome::ambiguous(detail(&format!(
                "the program's exit status could not be collected: {error}"
            ))),
        }
    }
}

impl SecretReceiver for CommandReceiver {
    fn describe(&self) -> String {
        format!(
            "command receiver {} with {} argument(s)",
            self.program.display(),
            self.args.len()
        )
    }

    fn receive(&self, metadata: &DeliveryMetadata, plaintext: &KeyPlaintext) -> Outcome {
        if !self.program.is_absolute() {
            // With an empty environment there is no `PATH` to search, and a
            // relative program would be resolved against a working directory
            // nobody chose deliberately.
            return Outcome::rejected(
                self.say("refusing to run: the configured program path is not absolute"),
            );
        }

        let mut child = match self.spawn() {
            Ok(child) => child,
            Err(error) => {
                return Outcome::rejected(self.say(&format!(
                    "the program could not be started, so it received nothing: {error}"
                )));
            }
        };

        let stdout = child.stdout.take().map(capture);
        let stderr = child.stderr.take().map(capture);
        // The write runs beside the wait rather than before it. An adapter that
        // stays alive without reading its stdin fills the pipe and blocks the
        // writer forever, and a write done here would block *before* the
        // timeout could be enforced. This way the timeout kills the child, the
        // blocked write fails with a broken pipe, and the delivery is
        // classified — ambiguously, since the envelope never arrived whole.
        let writer = write_envelope(child.stdin.take(), envelope(metadata, plaintext));

        let ending = self.wait(&mut child);

        // One deadline for the writer and both streams, so a stuck pipe costs
        // the grace period once rather than three times.
        let deadline = Instant::now() + CAPTURE_GRACE;
        let written = collect_write(writer, deadline);
        let diagnostic = summarize(
            &collect(stdout, deadline),
            &collect(stderr, deadline),
            plaintext.expose(),
        );
        self.classify(written, &ending, &diagnostic)
    }
}

/// Starts writing the envelope, reporting the result over a channel.
///
/// On its own thread for the same reason the readers are: this can block for
/// as long as the adapter refuses to read, and the delivery has a bound to
/// keep. The envelope is moved in, so it is cleared when the thread finishes
/// whether the write succeeded, failed, or was still blocked when the child
/// was killed.
fn write_envelope(
    stdin: Option<ChildStdin>,
    envelope: Zeroizing<String>,
) -> Receiver<Result<(), String>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let written = match stdin {
            Some(mut stdin) => stdin
                .write_all(envelope.as_bytes())
                .and_then(|()| stdin.flush()),
            None => Err(io::Error::other("the child process has no stdin")),
        };
        let _ = sender.send(written.map_err(|error| error.to_string()));
        // `stdin` is dropped here, which closes the pipe: an adapter reading to
        // end-of-file needs that to happen before it can act.
    });
    receiver
}

/// Collects the write's result, or calls it unfinished if it does not arrive.
///
/// A writer still blocked at the deadline means the envelope did not arrive
/// whole — the read end is held by something that is not reading it — which is
/// as ambiguous as a broken pipe and is reported the same way.
fn collect_write(writer: Receiver<Result<(), String>>, deadline: Instant) -> Result<(), String> {
    writer
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_else(|_| Err("the write did not finish".to_owned()))
}

/// Starts reading one stream, handing the bytes back over a channel.
///
/// A channel rather than a join handle because the caller must be able to stop
/// waiting: see the module's note on descendants that inherit the pipes.
fn capture(stream: impl io::Read + Send + 'static) -> Receiver<Zeroizing<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        // A failed send means the delivery was already classified without this
        // stream; the buffer is dropped here, and dropping it clears it.
        let _ = sender.send(drain(stream));
    });
    receiver
}

/// Reads up to [`CAPTURED_BYTES`], then drains the rest into nothing.
///
/// The buffer is zeroizing because an adapter may echo the key into it, and a
/// diagnostic buffer is not a place a credential should be left lying in freed
/// memory.
fn drain(stream: impl io::Read) -> Zeroizing<Vec<u8>> {
    let mut stream = stream;
    let mut captured = Zeroizing::new(Vec::with_capacity(CAPTURED_BYTES));
    let _ = io::Read::by_ref(&mut stream)
        .take(CAPTURED_BYTES as u64)
        .read_to_end(&mut captured);
    // Keeping the pipe empty matters even though the bytes are thrown away: a
    // child blocked writing to a full pipe would never reach its own exit.
    let _ = io::copy(&mut stream, &mut io::sink());
    captured
}

/// Collects one stream's bytes, or nothing if they do not arrive in time.
fn collect(reader: Option<Receiver<Zeroizing<Vec<u8>>>>, deadline: Instant) -> Zeroizing<Vec<u8>> {
    reader
        .and_then(|channel| {
            channel
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .ok()
        })
        .unwrap_or_else(|| Zeroizing::new(Vec::new()))
}

/// Builds the diagnostic excerpt, with the key taken out of it.
fn summarize(stdout: &[u8], stderr: &[u8], secret: &str) -> String {
    let mut summary = String::new();
    for (name, bytes) in [("stdout", stdout), ("stderr", stderr)] {
        let excerpt = excerpt(bytes, secret);
        if !excerpt.is_empty() {
            let _ = write!(summary, " [{name}: {excerpt}]");
        }
    }
    summary
}

/// One stream, with every occurrence of the key removed and the rest cut down
/// to something an operator can read.
fn excerpt(bytes: &[u8], secret: &str) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    // The scrub is by exact match rather than by credential shape: the shape
    // rule in `redaction` is a backstop for text Keymaster did not choose, and
    // here Keymaster knows precisely what must not appear.
    let mut raw = String::from_utf8_lossy(bytes).into_owned();
    let mut scrubbed = if secret.is_empty() {
        raw.clone()
    } else {
        raw.replace(secret, "[redacted]")
    };
    raw.zeroize();

    let mut excerpt: String = scrubbed.chars().take(REPORTED_CHARS).collect();
    if scrubbed.chars().nth(REPORTED_CHARS).is_some() {
        excerpt.push('…');
    }
    scrubbed.zeroize();
    excerpt
}

/// Builds the JSON envelope: metadata first, the key last.
///
/// The buffer is sized before the key goes into it and never grows, so the
/// plaintext is written once, into one allocation, which is cleared when the
/// value is dropped. A `serde_json::Value` would have made an untracked copy
/// of it on the way through.
fn envelope(metadata: &DeliveryMetadata, plaintext: &KeyPlaintext) -> Zeroizing<String> {
    let key = plaintext.expose();
    let address = metadata.address().as_str();
    let hash = metadata.hash().as_str();
    let operation = metadata.operation().as_str();

    // Six bytes per character is the worst a JSON escape can do (``).
    let capacity = 128 + 6 * (key.len() + address.len() + hash.len() + operation.len());
    let mut out = Zeroizing::new(String::with_capacity(capacity));

    let _ = write!(
        out,
        r#"{{"envelope_version":{ENVELOPE_VERSION},"operation_id":"#
    );
    push_json_string(&mut out, operation);
    out.push_str(r#","address":"#);
    push_json_string(&mut out, address);
    out.push_str(r#","hash":"#);
    push_json_string(&mut out, hash);
    let _ = write!(out, r#","generation":{},"key":"#, metadata.generation());
    push_json_string(&mut out, key);
    out.push('}');

    debug_assert!(
        out.len() <= capacity,
        "the envelope buffer grew, which would leave a copy of the key behind"
    );
    out
}

/// Appends a JSON string literal without allocating anything of its own.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control < '\u{20}' => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::ids::{Address, KeyHash, OperationId};
    use crate::receiver::Acknowledgement;

    /// The plaintext every case here delivers. Unit tests cannot reach the
    /// shared sentinel in `test_support`, so it is repeated.
    const SENTINEL_KEY: &str = "sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE";

    fn metadata() -> DeliveryMetadata {
        DeliveryMetadata::new(
            Address::parse("jobfeed").expect("a valid address"),
            KeyHash::parse("keyhash-0001").expect("a valid hash"),
            7,
            OperationId::parse("op-0001").expect("a valid operation id"),
            None,
        )
    }

    fn receiver() -> CommandReceiver {
        CommandReceiver::new("/usr/local/bin/store-key", vec!["--stdin".to_owned()])
    }

    #[test]
    fn the_envelope_is_versioned_json_carrying_the_metadata_and_the_key() {
        let built = envelope(&metadata(), &KeyPlaintext::for_tests(SENTINEL_KEY));
        let parsed: Value = serde_json::from_str(&built).expect("the envelope is JSON");

        assert_eq!(parsed["envelope_version"], Value::from(ENVELOPE_VERSION));
        assert_eq!(parsed["operation_id"], Value::from("op-0001"));
        assert_eq!(parsed["address"], Value::from("jobfeed"));
        assert_eq!(parsed["hash"], Value::from("keyhash-0001"));
        assert_eq!(parsed["generation"], Value::from(7));
        assert_eq!(parsed["key"], Value::from(SENTINEL_KEY));
        assert_eq!(
            parsed.as_object().expect("an object").len(),
            6,
            "an adapter should not have to ignore fields it was never told about"
        );
    }

    #[test]
    fn an_envelope_escapes_whatever_a_key_might_contain() {
        let awkward = "line\"one\\\ntab\there\u{1}";
        let built = envelope(&metadata(), &KeyPlaintext::for_tests(awkward));
        let parsed: Value = serde_json::from_str(&built).expect("the envelope is JSON");
        assert_eq!(parsed["key"], Value::from(awkward));
    }

    #[test]
    fn a_relative_program_is_refused_without_running_anything() {
        let outcome = CommandReceiver::new("store-key", Vec::new())
            .receive(&metadata(), &KeyPlaintext::for_tests(SENTINEL_KEY));
        assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
        assert!(outcome.detail().contains("not absolute"), "{outcome}");
    }

    #[test]
    fn a_program_that_cannot_be_started_committed_nothing() {
        let outcome = CommandReceiver::new("/nonexistent/keymaster-adapter", Vec::new())
            .receive(&metadata(), &KeyPlaintext::for_tests(SENTINEL_KEY));
        assert_eq!(outcome.acknowledgement(), Acknowledgement::Rejected);
        assert!(outcome.detail().contains("received nothing"), "{outcome}");
    }

    #[test]
    fn only_a_clean_exit_after_a_complete_write_is_a_delivery() {
        let receiver = receiver();
        let cases = [
            (Ok(()), Ending::Exited(0), Acknowledgement::Delivered),
            (
                Ok(()),
                Ending::Exited(REJECTED_EXIT_CODE),
                Acknowledgement::Rejected,
            ),
            (Ok(()), Ending::Exited(1), Acknowledgement::Ambiguous),
            (Ok(()), Ending::Exited(255), Acknowledgement::Ambiguous),
            (
                Ok(()),
                Ending::Signalled("signal 9".to_owned()),
                Acknowledgement::Ambiguous,
            ),
            (Ok(()), Ending::TimedOut, Acknowledgement::Ambiguous),
            (
                Ok(()),
                Ending::Lost("no child processes".to_owned()),
                Acknowledgement::Ambiguous,
            ),
            // A write that did not complete makes every ending ambiguous,
            // including the ones that would otherwise be definite.
            (
                Err("broken pipe".to_owned()),
                Ending::Exited(0),
                Acknowledgement::Ambiguous,
            ),
            (
                Err("broken pipe".to_owned()),
                Ending::Exited(REJECTED_EXIT_CODE),
                Acknowledgement::Ambiguous,
            ),
        ];

        for (written, ending, expected) in cases {
            let outcome = receiver.classify(written.clone(), &ending, "");
            assert_eq!(
                outcome.acknowledgement(),
                expected,
                "{written:?} then {ending:?}: {outcome}"
            );
            assert!(
                outcome.detail().contains("command receiver"),
                "every message names the receiver: {outcome}"
            );
        }
    }

    #[test]
    fn captured_output_loses_the_key_and_keeps_its_size_in_hand() {
        let noisy = format!(
            "committed op-0001 with {SENTINEL_KEY}\n{}",
            "x".repeat(9000)
        );
        let excerpt = excerpt(noisy.as_bytes(), SENTINEL_KEY);

        assert!(!excerpt.contains("sk-or-"), "{excerpt}");
        assert!(excerpt.contains("[redacted]"), "{excerpt}");
        // The non-secret part of what the adapter said survives: that is the
        // whole point of capturing anything.
        assert!(excerpt.contains("committed op-0001"), "{excerpt}");
        assert!(excerpt.chars().count() <= REPORTED_CHARS + 1, "{excerpt}");
    }

    #[test]
    fn a_silent_program_produces_no_diagnostic_noise() {
        assert_eq!(summarize(b"", b"", SENTINEL_KEY), "");
        assert_eq!(
            summarize(b"", b"denied\n", SENTINEL_KEY),
            " [stderr: denied\n]"
        );
    }
}
