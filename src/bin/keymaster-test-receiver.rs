//! A receiver adapter that exists to be tested against.
//!
//! Not a tool. This is the purpose-built helper the command-receiver tests
//! run: it implements the protocol in `docs/receiver-protocol.md`, records
//! exactly what it was given — its argument vector, the names of every
//! environment variable it inherited, and the envelope on its stdin — and then
//! ends in whatever way the test asked for, including badly.
//!
//! It is a real `[[bin]]` because that is the only way a test gets a path to a
//! program it can trust: `CARGO_BIN_EXE_keymaster-test-receiver` is set by
//! Cargo for binaries of this package. A shell script written from a string
//! literal would be testing the shell, and a script on disk would not be
//! compiled, linted, or reviewed with everything else here.
//!
//! Every mode takes a directory to record into. That path is not secret, which
//! is the point: it travels in `argv`, where the key never does.
//!
//! ```text
//! record <dir>            read the envelope, record everything, exit 0
//! reject <dir>            read the envelope, exit with the refusal code
//! fail   <dir> <code>     read the envelope, exit with <code>
//! hang   <dir> <ms>       read the envelope, sleep, exit 0
//! abort  <dir>            read the envelope, then die by signal
//! spew   <dir> <bytes>    read the envelope, write <bytes> to both streams
//! echo   <dir>            read the envelope, print it to both streams
//! deaf   <dir> <code>     never read stdin; exit with <code>
//! mute   <dir> <ms>       never read stdin; stay alive <ms>, then mark done
//! orphan <dir> <ms>       leave a descendant holding both pipes, then exit 0
//! linger <dir> <ms>       that descendant: hold the pipes for <ms>, silently
//! ```

use std::env;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use keymaster::receiver::command::REJECTED_EXIT_CODE;

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    let mode = argv.get(1).cloned().unwrap_or_default();
    let directory = PathBuf::from(argv.get(2).cloned().unwrap_or_else(|| ".".to_owned()));
    let number = |index: usize, fallback: u64| -> u64 {
        argv.get(index)
            .and_then(|value| value.parse().ok())
            .unwrap_or(fallback)
    };

    if mode == "linger" {
        // The descendant `orphan` leaves behind. It records nothing — its whole
        // job is to hold the inherited stdout and stderr open after the adapter
        // Keymaster actually spawned has been reaped.
        thread::sleep(Duration::from_millis(number(3, 1_000)));
        return ExitCode::SUCCESS;
    }

    record_context(&directory, &argv);

    if mode == "mute" {
        // Alive, and deliberately not reading: an envelope larger than the pipe
        // buffer blocks its writer here until something kills this process.
        // `done.txt` appears only if that never happened.
        thread::sleep(Duration::from_millis(number(3, 60_000)));
        write_file(directory.join("done.txt").as_path(), b"finished");
        return ExitCode::SUCCESS;
    }

    if mode == "deaf" {
        // Exits without ever reading stdin. Whether Keymaster's write reaches
        // the pipe buffer before the process is gone is a race; the exit code
        // is not, which is what the test asserts on.
        return exit_code(number(3, 3));
    }

    let envelope = read_stdin();
    write_file(&directory.join("envelope.json"), envelope.as_bytes());

    match mode.as_str() {
        "record" => ExitCode::SUCCESS,
        "reject" => exit_code(REJECTED_EXIT_CODE.unsigned_abs().into()),
        "fail" => exit_code(number(3, 1)),
        "hang" => {
            thread::sleep(Duration::from_millis(number(3, 60_000)));
            ExitCode::SUCCESS
        }
        // Dies by SIGABRT. A receiver killed mid-commit is exactly the case
        // ADR-0002 refuses to classify as either success or rejection.
        "abort" => std::process::abort(),
        "spew" => {
            let noise = "n".repeat(usize::try_from(number(3, 1024)).unwrap_or(1024));
            say(noise.as_bytes());
            ExitCode::SUCCESS
        }
        // Exits at once, leaving a descendant with the same stdout and stderr.
        // Keymaster must not wait on pipes held by a process it never started.
        "orphan" => {
            let program = env::current_exe().expect("this program has a path");
            let held = argv.get(3).cloned().unwrap_or_else(|| "1000".to_owned());
            #[allow(
                clippy::zombie_processes,
                reason = "not waiting is the case under test: the descendant must outlive the \
                          adapter and keep the inherited pipes open"
            )]
            let _descendant = std::process::Command::new(program)
                .args(["linger", ".", &held])
                .spawn()
                .expect("the descendant starts");
            ExitCode::SUCCESS
        }
        // The malicious case: an adapter that prints the secret it was given.
        "echo" => {
            say(envelope.as_bytes());
            ExitCode::SUCCESS
        }
        other => {
            let _ = writeln!(io::stderr(), "unknown mode: {other}");
            ExitCode::from(64)
        }
    }
}

/// Records the argument vector and the names of every inherited environment
/// variable, so a test can prove what the child could and could not see.
///
/// Names only, never values: a helper that wrote environment values to a file
/// would be a way for a real credential to reach disk if this ever ran
/// somewhere it should not.
fn record_context(directory: &Path, argv: &[String]) {
    // One line per invocation, appended: a test that ends ambiguously asserts
    // on this to prove Keymaster did not quietly run the adapter twice.
    let runs = directory.join("runs.txt");
    let previous = fs::read_to_string(&runs).unwrap_or_default();
    write_file(runs.as_path(), format!("{previous}ran\n").as_bytes());

    write_file(
        directory.join("argv.txt").as_path(),
        argv.join("\n").as_bytes(),
    );

    let mut names: Vec<String> = env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    write_file(
        directory.join("env.txt").as_path(),
        names.join("\n").as_bytes(),
    );
}

/// Reads stdin to end of file.
fn read_stdin() -> String {
    let mut buffer = String::new();
    let _ = io::stdin().read_to_string(&mut buffer);
    buffer
}

/// Writes both streams, so a test can prove neither can carry the key out.
fn say(bytes: &[u8]) {
    let _ = io::stdout().write_all(bytes);
    let _ = io::stdout().flush();
    let _ = io::stderr().write_all(bytes);
    let _ = io::stderr().flush();
}

fn write_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|error| panic!("writing {}: {error}", path.display()));
}

fn exit_code(code: u64) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX))
}
