//! A local HTTP server for tests, built on `wiremock`.
//!
//! The point of an HTTP server rather than a fake client is that the code
//! under test is the real client: it serializes real requests, opens real
//! connections, and parses real responses. Nothing here knows about
//! Keymaster's types, so it stays usable as the client grows.
//!
//! `wiremock` is async and Keymaster's client is blocking, so [`TestServer`]
//! owns a runtime and exposes a synchronous surface. Tests never write
//! `async`.
//!
//! [`RawServer`] is the exception to all of that: a few failures live below the
//! level `wiremock` models — a response whose body stops before its declared
//! length — so that one writes bytes onto a socket directly.

use std::collections::BTreeMap;
use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use tokio::runtime::{Builder, Runtime};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// What [`describe_request`] prints in place of a credential.
pub const REDACTED: &str = "<redacted>";

/// Headers whose values are credentials and are never printed.
const SECRET_HEADERS: [&str; 2] = ["authorization", "proxy-authorization"];

/// Longest request body [`describe_request`] prints.
const BODY_EXCERPT_BYTES: usize = 512;

/// A local HTTP server with a synchronous interface.
pub struct TestServer {
    // Declared before `runtime` so the server shuts down first.
    server: MockServer,
    runtime: Runtime,
}

impl TestServer {
    /// Starts a server on an unused local port.
    #[must_use]
    pub fn start() -> Self {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a tokio runtime for the test server");
        let server = runtime.block_on(MockServer::start());
        Self { server, runtime }
    }

    /// The server's root URL, for example `http://127.0.0.1:53019`.
    #[must_use]
    pub fn base_url(&self) -> String {
        self.server.uri()
    }

    /// The server's root URL with OpenRouter's API prefix, so a client under
    /// test can be pointed at it with one base-URL override.
    #[must_use]
    pub fn api_base_url(&self) -> String {
        format!("{}/api/v1", self.server.uri())
    }

    /// The full URL of one path below the API prefix.
    #[must_use]
    pub fn api_url(&self, path: &str) -> String {
        format!("{}/{}", self.api_base_url(), path.trim_start_matches('/'))
    }

    /// Registers a mock. It stays active until the server is dropped.
    ///
    /// Do not give the mock a `Mock::expect` count. `wiremock` verifies those
    /// on drop and its failure message dumps every recorded request verbatim,
    /// `Authorization` header included, which defeats the redaction in
    /// [`describe_request`]. Assert counts with [`Self::assert_request_count`]
    /// instead; without an expectation, `wiremock`'s verification has nothing
    /// to report.
    pub fn mount(&self, mock: Mock) {
        self.runtime.block_on(self.server.register(mock));
    }

    /// Every request the server received, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<Request> {
        self.runtime
            .block_on(self.server.received_requests())
            .unwrap_or_default()
    }

    /// The request at `index`, or a panic naming every request received.
    #[must_use]
    pub fn request(&self, index: usize) -> Request {
        let requests = self.requests();
        requests.get(index).cloned().unwrap_or_else(|| {
            panic!(
                "no request at index {index}; the server received {count}:\n{received}",
                count = requests.len(),
                received = describe_requests(&requests)
            )
        })
    }

    /// Fails unless exactly `expected` requests arrived, naming each one with
    /// credentials redacted. This is the harness's replacement for
    /// `wiremock`'s own expectation verification.
    pub fn assert_request_count(&self, expected: usize) {
        let requests = self.requests();
        assert!(
            requests.len() == expected,
            "expected {expected} request(s) but the server received {count}:\n{received}",
            count = requests.len(),
            received = describe_requests(&requests)
        );
    }
}

/// One request rendered for a failure message, with credentials redacted.
#[must_use]
pub fn describe_request(request: &Request) -> String {
    let mut description = format!("{} {}", request.method, request.url.path());
    if let Some(query) = request.url.query() {
        description.push('?');
        description.push_str(query);
    }

    let mut names: Vec<&str> = request.headers.keys().map(|name| name.as_str()).collect();
    names.sort_unstable();
    for name in names {
        let value = if SECRET_HEADERS.contains(&name) {
            REDACTED.to_owned()
        } else {
            header(request, name).unwrap_or_else(|| "<not printable>".to_owned())
        };
        description.push_str(&format!("\n  {name}: {value}"));
    }

    if !request.body.is_empty() {
        let excerpt = String::from_utf8_lossy(&request.body);
        let excerpt: String = excerpt.chars().take(BODY_EXCERPT_BYTES).collect();
        description.push_str(&format!("\n  body: {excerpt}"));
    }
    description
}

/// Several requests rendered for a failure message.
#[must_use]
pub fn describe_requests(requests: &[Request]) -> String {
    if requests.is_empty() {
        return "  (no requests)".to_owned();
    }
    requests
        .iter()
        .enumerate()
        .map(|(index, request)| format!("[{index}] {}", describe_request(request)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One header's value, or `None` when it is absent or not printable.
#[must_use]
pub fn header(request: &Request, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// A request's body as JSON, so tests assert structure rather than bytes.
#[must_use]
pub fn body_json(request: &Request) -> Value {
    request.body_json().unwrap_or_else(|error| {
        panic!(
            "request body is not JSON ({error}):\n{}",
            describe_request(request)
        )
    })
}

/// A JSON response.
#[must_use]
pub fn json_response(status: u16, body: &Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

/// A JSON response that arrives late, for timeout tests.
#[must_use]
pub fn delayed(status: u16, body: &Value, delay: Duration) -> ResponseTemplate {
    json_response(status, body).set_delay(delay)
}

/// A success whose body claims to be JSON but is truncated.
#[must_use]
pub fn malformed_json() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(r#"{"data": [{"hash": "#, "application/json")
}

/// A success with a body far larger than any real response, for bounded-read
/// tests.
#[must_use]
pub fn oversized_body(bytes: usize) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(vec![b'x'; bytes], "application/json")
}

/// A 429 carrying `Retry-After` in seconds.
#[must_use]
pub fn rate_limited(retry_after_seconds: u32) -> ResponseTemplate {
    ResponseTemplate::new(429)
        .insert_header("retry-after", retry_after_seconds.to_string().as_str())
        .set_body_raw("rate limited", "text/plain")
}

/// Aborts the connection instead of replying: the request was sent and the
/// acknowledgement is lost. Pass to `MockBuilder::respond_with_err`.
pub fn connection_lost(_request: &Request) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the test server dropped the connection",
    )
}

/// Replies with each template in turn, then repeats the last one.
///
/// This is how a test scripts a sequence: a 500 then a success, a page then an
/// empty page, drift appearing on the second read.
pub struct Scripted {
    templates: Vec<ResponseTemplate>,
    next: Mutex<usize>,
}

impl Scripted {
    /// Builds a responder from an ordered sequence. Panics if it is empty.
    #[must_use]
    pub fn new(templates: impl IntoIterator<Item = ResponseTemplate>) -> Self {
        let templates: Vec<_> = templates.into_iter().collect();
        assert!(
            !templates.is_empty(),
            "a scripted responder needs at least one response"
        );
        Self {
            templates,
            next: Mutex::new(0),
        }
    }

    /// Builds a responder that returns each JSON body in turn with status 200.
    #[must_use]
    pub fn json(bodies: impl IntoIterator<Item = Value>) -> Self {
        Self::new(
            bodies
                .into_iter()
                .map(|body| json_response(200, &body))
                .collect::<Vec<_>>(),
        )
    }
}

impl Respond for Scripted {
    // The request is unused: the sequence depends on call order, not content.
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let mut next = self.next.lock().expect("the responder is not poisoned");
        let index = (*next).min(self.templates.len() - 1);
        *next += 1;
        self.templates
            .get(index)
            .cloned()
            .unwrap_or_else(|| panic!("scripted response {index} is missing"))
    }
}

/// A response whose declared length is longer than the bytes that follow.
///
/// The client reads a good status line and good headers, starts reading the
/// body, and the connection closes underneath it. That is what a reset in the
/// middle of a large page looks like, and it is not the same failure as a
/// request that never arrived: the read is safe to repeat, and a client that
/// gives up here returns a partial snapshot.
#[must_use]
pub fn truncated_body(body: &str) -> Vec<u8> {
    truncated_body_with_status(200, body)
}

/// A truncated body under a status of the caller's choosing.
///
/// Separate from [`truncated_body`] because the status is the whole point of
/// some cases: a rejection and a redirect mean what they mean whether or not
/// their body arrives.
#[must_use]
pub fn truncated_body_with_status(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} STATUS\r\nContent-Type: application/json\r\n\
         Content-Length: {declared}\r\n\r\n{body}",
        // Twice what is actually written, so the body always stops early.
        declared = body.len() * 2 + 16,
    )
    .into_bytes()
}

/// A complete raw response carrying `body`.
#[must_use]
pub fn whole_body(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\
         Connection: close\r\n\r\n{body}",
        length = body.len(),
    )
    .into_bytes()
}

/// A server that writes raw bytes, for responses `wiremock` cannot express.
///
/// One scripted response per connection, the last one repeating. It reads the
/// whole request first — headers and any declared body — so the client is never
/// answered before it has finished asking.
pub struct RawServer {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
}

impl RawServer {
    /// Starts a server on an unused local port.
    #[must_use]
    pub fn scripted(responses: Vec<Vec<u8>>) -> Self {
        Self::holding(responses, Duration::ZERO)
    }

    /// As [`RawServer::scripted`], but the connection stays open for `hold`
    /// after the bytes are written instead of closing.
    ///
    /// With a body that stops short of its declared length, this is a stall
    /// rather than a reset: the client is left waiting for bytes that never
    /// come, which is what expires a whole-request timeout partway through a
    /// response.
    #[must_use]
    pub fn holding(responses: Vec<Vec<u8>>, hold: Duration) -> Self {
        assert!(!responses.is_empty(), "a raw server needs a response");
        let listener = TcpListener::bind("127.0.0.1:0").expect("a local port");
        let address = listener.local_addr().expect("the bound address");
        listener
            .set_nonblocking(true)
            .expect("a pollable listener, so the server can be stopped");

        let requests = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let served = Self {
            address,
            requests: Arc::clone(&requests),
            stopped: Arc::clone(&stopped),
        };

        thread::spawn(move || {
            let mut answered = 0_usize;
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        requests.fetch_add(1, Ordering::Relaxed);
                        let response = responses
                            .get(answered.min(responses.len() - 1))
                            .cloned()
                            .expect("a scripted response");
                        answered += 1;
                        // Each connection is answered on its own thread. A
                        // server that held the accept loop while stalling one
                        // response would leave a retried request waiting in the
                        // kernel's backlog — arriving, but never counted — and
                        // a test asserting "exactly one request" would pass
                        // whether or not the client retried.
                        thread::spawn(move || answer(&stream, &response, hold));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return,
                }
            }
        });
        served
    }

    /// The server's root URL with OpenRouter's API prefix.
    #[must_use]
    pub fn api_base_url(&self) -> String {
        format!("http://{}/api/v1", self.address)
    }

    /// The server's origin, with no path — the shape a proxy is named in.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    /// How many connections the server has answered.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }

    /// Fails unless exactly `expected` requests arrived.
    pub fn assert_request_count(&self, expected: usize) {
        assert_eq!(
            self.request_count(),
            expected,
            "the raw server answered a different number of requests than expected"
        );
    }
}

impl Drop for RawServer {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
}

/// Reads one whole request, writes `response`, waits `hold`, then closes.
fn answer(stream: &TcpStream, response: &[u8], hold: Duration) {
    stream
        .set_nonblocking(false)
        .expect("a blocking accepted socket");
    let mut reader = BufReader::new(stream);
    let mut length = 0_usize;

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    // Draining the request body matters: answering before the client has
    // finished writing turns the test's scripted response into a reset.
    let mut body = vec![0_u8; length];
    let _ = reader.read_exact(&mut body);

    let mut stream = stream;
    let _ = stream.write_all(response);
    let _ = stream.flush();
    thread::sleep(hold);
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Mutable remote state, for drift tests.
///
/// A test seeds it, reads through the client, changes it, and reads again —
/// exactly what happens when someone edits a key in the OpenRouter dashboard
/// between two Keymaster runs. Stored values are normalized the way a server
/// normalizes them, so an ordering difference cannot be mistaken for drift.
#[derive(Clone, Default)]
pub struct RemoteCollection(Arc<Mutex<BTreeMap<String, Value>>>);

impl RemoteCollection {
    /// An empty collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces one resource, keyed by its immutable identity.
    pub fn put(&self, identity: &str, resource: Value) {
        self.lock()
            .insert(identity.to_owned(), super::fixtures::normalize(resource));
    }

    /// Removes one resource, as a deletion in the dashboard would.
    pub fn remove(&self, identity: &str) {
        self.lock().remove(identity);
    }

    /// The resources currently present, in identity order.
    #[must_use]
    pub fn items(&self) -> Vec<Value> {
        self.lock().values().cloned().collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Value>> {
        self.0
            .lock()
            .expect("the remote collection is not poisoned")
    }
}

impl Respond for RemoteCollection {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        json_response(200, &super::fixtures::page(self.items()))
    }
}
