//! The supported low-level boundary, built without the Wiremock test harness.
//!
//! The server is deliberately std-only: this test proves the feature gives a
//! consumer the blocking API without bringing `test-support` into its build.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::thread;

use openrouter_keymaster_core::api::{Reader, Writer};
use openrouter_keymaster_core::client::{
    ApiError, Client, CreateKeyRequest, CreatedKey, KeyPlaintext, ManagementKey, Options,
};
use openrouter_keymaster_core::ids::RemoteName;
use zeroize::Zeroizing;

const MANAGEMENT_KEY: &str = "not-a-real-management-key";
const CREATED_KEY: &str = "sk-or-v1-not-a-real-created-key";

#[test]
fn low_level_api_is_public_without_test_support() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("an unused local port");
    let base_url = format!(
        "http://{}/api/v1",
        listener.local_addr().expect("the server address")
    );
    let server = thread::spawn(move || answer_create(listener));

    let credential = ManagementKey::from_secret(Zeroizing::new(MANAGEMENT_KEY.to_owned()))
        .expect("a usable fake credential");
    let client = Client::new(Options::new(base_url), &credential).expect("a local client");
    let _reader = Reader::new(&client);
    let _writer = Writer::new(&client);
    assert_eq!(ApiError::MissingCredential.kind(), "missing_credential");

    let request = CreateKeyRequest::new(RemoteName::parse("fund-grant").expect("a valid name"));
    let created: CreatedKey = client
        .create_key_once(&request)
        .expect("the local server returns a create response");
    let plaintext: &KeyPlaintext = created.plaintext();
    assert_eq!(created.hash().as_str(), "created-hash");
    assert_eq!(plaintext.expose(), CREATED_KEY);

    server.join().expect("the local server finishes");
}

fn answer_create(listener: TcpListener) {
    let (mut stream, _) = listener.accept().expect("the client connects");
    read_headers(&mut stream);

    let body = format!(r#"{{"data":{{"hash":"created-hash"}},"key":"{CREATED_KEY}"}}"#);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("writing the create response");
}

fn read_headers(stream: &mut TcpStream) {
    let mut received = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !received.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream.read(&mut chunk).expect("reading the request");
        assert!(count > 0, "the request ended before its headers arrived");
        received.extend_from_slice(&chunk[..count]);
    }
}
