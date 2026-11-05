//! The receiver over real loopback sockets.

use super::*;
use std::sync::mpsc;

struct Fixture {
    receiver: Arc<Receiver>,
    settings: Arc<Mutex<Settings>>,
    events: mpsc::Receiver<Vec<ActivityEvent>>,
}

fn fixture(enabled: bool) -> Fixture {
    let settings = Arc::new(Mutex::new(Settings {
        enabled,
        log_prompts: false,
        chats: HashSet::new(),
    }));
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let sink: Sink = Arc::new(move |events| {
        let _ = tx.lock().unwrap().send(events);
    });
    let receiver = Receiver::start(settings.clone(), sink).unwrap();
    Fixture {
        receiver,
        settings,
        events: rx,
    }
}

fn logs_json(tool: &str) -> Vec<u8> {
    serde_json::json!({ "resourceLogs": [{ "scopeLogs": [{ "logRecords": [{
        "timeUnixNano": "5000000",
        "attributes": [
            { "key": "event.name", "value": { "stringValue": "tool_result" } },
            { "key": "tool_name", "value": { "stringValue": tool } },
            { "key": "success", "value": { "stringValue": "true" } }
        ]
    }]}]}]})
    .to_string()
    .into_bytes()
}

/// Sends raw bytes and returns the status code of the reply.
fn send_raw(port: u16, bytes: &[u8]) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let _ = stream.write_all(bytes);
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    reply
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

fn post(port: u16, path: &str, headers: &[(&str, &str)], body: &[u8]) -> u16 {
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body);
    send_raw(port, &bytes)
}

#[test]
fn a_chats_events_arrive_attributed_by_token() {
    let f = fixture(true);
    let token = f.receiver.token_for("chat-1", "claude").unwrap();
    let status = post(
        f.receiver.port(),
        "/v1/logs",
        &[
            ("content-type", "application/json"),
            ("x-derm-token", &token),
        ],
        &logs_json("Bash"),
    );
    assert_eq!(status, 200);
    let events = f.events.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].chat_id, "chat-1");
    assert_eq!(events[0].harness, "claude");
    assert_eq!(events[0].kind, "tool.call");
    // Stamped when received, not when the harness says (security review S4).
    assert_eq!(events[0].detail["harnessAt"], 5);
    assert!(events[0].at > 1_700_000_000_000);
}

#[test]
fn bearer_header_works_too() {
    let f = fixture(true);
    let token = f.receiver.token_for("chat-2", "codex").unwrap();
    let auth = format!("Bearer {token}");
    let status = post(
        f.receiver.port(),
        "/v1/logs",
        &[
            ("content-type", "application/json"),
            ("authorization", &auth),
        ],
        &logs_json("shell"),
    );
    assert_eq!(status, 200);
    assert_eq!(
        f.events.recv_timeout(Duration::from_secs(5)).unwrap()[0].harness,
        "codex"
    );
}

#[test]
fn protobuf_body_is_decoded() {
    use super::decode::encode::*;
    let f = fixture(true);
    let token = f.receiver.token_for("chat-3", "codex").unwrap();
    let body = request(
        &[],
        &[(
            1_000_000,
            vec![
                key_value("event.name", &any_string("codex.tool_result")),
                key_value("tool_name", &any_string("shell")),
            ],
        )],
    );
    let status = post(
        f.receiver.port(),
        "/v1/logs",
        &[
            ("content-type", "application/x-protobuf"),
            ("x-derm-token", &token),
        ],
        &body,
    );
    assert_eq!(status, 200);
    assert_eq!(
        f.events.recv_timeout(Duration::from_secs(5)).unwrap()[0].summary,
        "shell done"
    );
}

#[test]
fn no_token_or_a_wrong_one_is_refused_before_the_body() {
    let f = fixture(true);
    f.receiver.token_for("chat-1", "claude").unwrap();
    let port = f.receiver.port();
    // A head claiming a large body and sending none: refused at once, not
    // after the body deadline.
    let started = Instant::now();
    let head = format!("POST /v1/logs HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\ncontent-type: application/json\r\ncontent-length: 1000000\r\n\r\n");
    assert_eq!(send_raw(port, head.as_bytes()), 401);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        post(
            port,
            "/v1/logs",
            &[
                ("content-type", "application/json"),
                ("x-derm-token", "nope")
            ],
            &logs_json("x")
        ),
        401
    );
    assert_eq!(
        post(
            port,
            "/v1/logs",
            &[
                ("content-type", "application/json"),
                ("authorization", "Basic abc")
            ],
            &logs_json("x")
        ),
        401
    );
    assert!(f.events.recv_timeout(Duration::from_millis(300)).is_err());
    assert_eq!(f.receiver.counters.refused_token.load(Ordering::Relaxed), 3);
}

#[test]
fn wrong_host_method_path_type_encoding_and_size_are_refused() {
    let f = fixture(true);
    let token = f.receiver.token_for("c", "claude").unwrap();
    let port = f.receiver.port();
    let json = [
        ("content-type", "application/json"),
        ("x-derm-token", token.as_str()),
    ];
    // DNS rebinding: a page's request carries its own host name.
    let rebound = format!("POST /v1/logs HTTP/1.1\r\nhost: evil.example:{port}\r\nx-derm-token: {token}\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{{}}");
    assert_eq!(send_raw(port, rebound.as_bytes()), 403);
    // A browser preflight.
    let preflight = format!("OPTIONS /v1/logs HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\n\r\n");
    assert_eq!(send_raw(port, preflight.as_bytes()), 405);
    assert_eq!(post(port, "/v2/other", &json, b"{}"), 404);
    assert_eq!(
        post(
            port,
            "/v1/logs",
            &[("content-type", "text/plain"), ("x-derm-token", &token)],
            b"{}"
        ),
        415
    );
    assert_eq!(
        post(
            port,
            "/v1/logs",
            &[
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
                ("x-derm-token", &token)
            ],
            b"{}"
        ),
        415
    );
    let big = format!("POST /v1/logs HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nx-derm-token: {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", MAX_BODY_BYTES + 1);
    assert_eq!(send_raw(port, big.as_bytes()), 413);
    let no_length = format!("POST /v1/logs HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nx-derm-token: {token}\r\ncontent-type: application/json\r\n\r\n");
    assert_eq!(send_raw(port, no_length.as_bytes()), 411);
    // A chunk size near usize::MAX must not wrap past the limit.
    let chunked = format!("POST /v1/logs HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nx-derm-token: {token}\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\nffffffffffffffff\r\n");
    assert_eq!(send_raw(port, chunked.as_bytes()), 413);
    assert_eq!(post(port, "/v1/logs", &json, b"not json"), 400);
    let huge_head = format!(
        "POST /v1/logs HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nx-pad: {}\r\n\r\n",
        "a".repeat(MAX_HEAD_BYTES)
    );
    assert_eq!(send_raw(port, huge_head.as_bytes()), 413);
}

#[test]
fn chunked_body_is_read() {
    let f = fixture(true);
    let token = f.receiver.token_for("c", "claude").unwrap();
    let port = f.receiver.port();
    let body = logs_json("Read");
    let mut req = format!("POST /v1/logs HTTP/1.1\r\nhost: localhost:{port}\r\nx-derm-token: {token}\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n", body.len()).into_bytes();
    req.extend_from_slice(&body);
    req.extend_from_slice(b"\r\n0\r\n\r\n");
    assert_eq!(send_raw(port, &req), 200);
    assert_eq!(
        f.events.recv_timeout(Duration::from_secs(5)).unwrap()[0].summary,
        "Read ok"
    );
}

#[test]
fn metrics_and_traces_are_accepted_and_dropped() {
    let f = fixture(true);
    let token = f.receiver.token_for("c", "claude").unwrap();
    let headers = [
        ("content-type", "application/json"),
        ("x-derm-token", token.as_str()),
    ];
    assert_eq!(
        post(
            f.receiver.port(),
            "/v1/metrics",
            &headers,
            b"{\"resourceMetrics\":[]}"
        ),
        200
    );
    assert_eq!(post(f.receiver.port(), "/v1/traces", &headers, b"{}"), 200);
    assert!(f.events.recv_timeout(Duration::from_millis(300)).is_err());
}

#[test]
fn switched_off_drops_what_still_arrives() {
    let f = fixture(false);
    let token = f.receiver.token_for("c", "claude").unwrap();
    let status = post(
        f.receiver.port(),
        "/v1/logs",
        &[
            ("content-type", "application/json"),
            ("x-derm-token", &token),
        ],
        &logs_json("Bash"),
    );
    assert_eq!(status, 200);
    assert!(f.events.recv_timeout(Duration::from_millis(300)).is_err());
    f.settings.lock().unwrap().enabled = true;
    post(
        f.receiver.port(),
        "/v1/logs",
        &[
            ("content-type", "application/json"),
            ("x-derm-token", &token),
        ],
        &logs_json("Bash"),
    );
    assert!(f.events.recv_timeout(Duration::from_secs(5)).is_ok());
}

#[test]
fn tokens_are_per_chat_and_harness_stable_and_bounded() {
    let f = fixture(true);
    let a = f.receiver.token_for("a", "claude").unwrap();
    assert_eq!(f.receiver.token_for("a", "claude").unwrap(), a);
    assert_ne!(f.receiver.token_for("a", "codex").unwrap(), a);
    assert_ne!(f.receiver.token_for("b", "claude").unwrap(), a);
    assert_eq!(a.len(), 64);
    for i in 0..MAX_TOKENS {
        f.receiver.token_for(&format!("chat-{i}"), "claude");
    }
    // "a" was the oldest and gave way: its old token no longer posts.
    assert!(f.receiver.holder(&a).is_none());
    assert!(f.receiver.holders.lock().unwrap().len() <= MAX_TOKENS);
    assert_ne!(f.receiver.token_for("a", "claude").unwrap(), a);
}

#[test]
fn rate_cap_answers_429_after_the_burst() {
    let f = fixture(true);
    let token = f.receiver.token_for("c", "claude").unwrap();
    let headers = [
        ("content-type", "application/json"),
        ("x-derm-token", token.as_str()),
    ];
    let mut limited = 0;
    for _ in 0..(RATE_BURST as usize + 60) {
        if post(f.receiver.port(), "/v1/traces", &headers, b"{}") == 429 {
            limited += 1;
        }
    }
    assert!(limited > 0, "no request was rate limited");
}

#[test]
fn connection_cap_answers_503() {
    let f = fixture(true);
    let port = f.receiver.port();
    // Idle connections hold their slots until the head deadline.
    let held: Vec<TcpStream> = (0..MAX_CONNECTIONS)
        .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    let status = send_raw(port, b"POST /v1/logs HTTP/1.1\r\n\r\n");
    assert_eq!(status, 503);
    drop(held);
}

#[test]
fn a_trickled_head_is_cut_at_its_deadline() {
    // The deadline is re-armed per read, so a byte every second does not
    // extend it. Takes the full head deadline (10 seconds). The reply is
    // read to its end: a first read alone can hold part of it (Mac 0.5).
    let f = fixture(true);
    let mut stream = TcpStream::connect(("127.0.0.1", f.receiver.port())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let started = Instant::now();
    let mut reply = Vec::new();
    loop {
        if stream.write_all(b"P").is_err() {
            break;
        }
        let mut buf = [0u8; 256];
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                reply.extend_from_slice(&buf[..n]);
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                reply.extend(read_reply(&mut stream));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(_) => {}
        }
        if started.elapsed() > Duration::from_secs(20) {
            panic!("the receiver kept a trickled head past its deadline");
        }
    }
    assert!(started.elapsed() < HEAD_DEADLINE + Duration::from_secs(3));
    assert!(
        reply.starts_with(b"HTTP/1.1 408 ") || reply.is_empty(),
        "reply: {:?}",
        String::from_utf8_lossy(&reply)
    );
}

#[test]
fn a_read_timeout_is_408_by_its_kind() {
    use std::io::{Error, ErrorKind};
    assert_eq!(read_failure(&Error::from(ErrorKind::WouldBlock)), 408);
    assert_eq!(read_failure(&Error::from(ErrorKind::TimedOut)), 408);
    assert_eq!(read_failure(&Error::from(ErrorKind::UnexpectedEof)), 400);
    assert_eq!(read_failure(&Error::from(ErrorKind::ConnectionReset)), 400);
}

#[test]
fn status_has_no_port_or_token() {
    let value = serde_json::to_value(harness_telemetry_status()).unwrap();
    let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
    assert!(keys
        .iter()
        .all(|k| !k.contains("port") && !k.contains("token") || k.as_str() == "refusedToken"));
}

#[test]
fn configure_caps_and_filters_chat_ids() {
    let long = "x".repeat(300);
    harness_telemetry_configure(true, false, vec!["".into(), long.clone(), "ok".into()]).unwrap();
    let s = settings();
    let s = s.lock().unwrap();
    assert!(s.chats.contains("ok"));
    assert!(!s.chats.contains(&long));
    assert!(!s.chats.contains(""));
}

/// Records each call a writer gets, so a test can count them.
#[derive(Default)]
struct Recorder {
    writes: Vec<Vec<u8>>,
}

impl Write for Recorder {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writes.push(buf.to_vec());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_whole_reply_goes_out_in_one_write() {
    // In pieces, macOS loopback can hand a client only `HTTP/1.1 ` before
    // the socket closes (Mac test 0.5).
    for (status, kind) in [
        (408, None),
        (200, Some(BodyKind::Json)),
        (200, Some(BodyKind::Protobuf)),
    ] {
        let mut out = Recorder::default();
        respond(&mut out, status, kind.map(Answer::Otlp)).unwrap();
        assert_eq!(
            out.writes.len(),
            1,
            "{status}: {:?}",
            out.writes
                .iter()
                .map(|w| String::from_utf8_lossy(w).into_owned())
                .collect::<Vec<_>>()
        );
        assert!(out.writes[0].starts_with(format!("HTTP/1.1 {status} ").as_bytes()));
    }
}

/// Reads a reply to its end. A reset after the reply counts as the end.
fn read_reply(stream: &mut TcpStream) -> Vec<u8> {
    let mut reply = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => reply.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    reply
}

#[test]
fn an_error_reply_survives_unread_input() {
    // A head past the cap is refused with input still unread. Closing at
    // once then resets the connection, which can cost the client the reply
    // (RFC 9112 section 9.6); the receiver closes its write side first and
    // drains.
    let f = fixture(true);
    let mut stream = TcpStream::connect(("127.0.0.1", f.receiver.port())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut req = format!(
        "POST /v1/logs HTTP/1.1\r\nhost: 127.0.0.1:{}\r\n",
        f.receiver.port()
    )
    .into_bytes();
    req.extend(std::iter::repeat_n(b'a', MAX_HEAD_BYTES + 4096));
    let _ = stream.write_all(&req);
    // The client is still sending when the reply comes.
    std::thread::sleep(Duration::from_millis(200));
    let _ = stream.write_all(&[b'b'; 2048]);
    let reply = read_reply(&mut stream);
    assert!(
        reply.starts_with(b"HTTP/1.1 413 "),
        "reply: {:?}",
        String::from_utf8_lossy(&reply)
    );
}

#[cfg(unix)]
#[test]
fn the_headers_helper_is_private_new_and_prints_the_header() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("otel-helper-{}", uuid::Uuid::new_v4()));
    let dir = root.join("otel-helper");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("stale.sh"), "old").unwrap();
    fresh_private_dir(&dir).unwrap();
    assert!(!dir.join("stale.sh").exists());
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let token = "0123456789abcdef0123456789abcdef";
    let path = write_helper(&dir, token).unwrap();
    assert!(!path.to_string_lossy().contains(token));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let out = Command::new(&path).output().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value[harness_env::TOKEN_HEADER], token);
    // Never over an existing file, and never through a link.
    assert!(write_helper(&dir, token).is_err());
    let other = "fedcba9876543210fedcba9876543210";
    let target = root.join("target");
    std::fs::write(&target, "x").unwrap();
    let name: String = hash(other)[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::os::unix::fs::symlink(&target, dir.join(format!("{name}.sh"))).unwrap();
    assert!(write_helper(&dir, other).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");
    // A link in the folder's place is removed, not followed.
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("keep"), "k").unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
    fresh_private_dir(&dir).unwrap();
    assert!(elsewhere.join("keep").exists());
    assert!(std::fs::symlink_metadata(&dir).unwrap().is_dir());
    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn quitting_removes_the_helper_folder_and_never_follows_a_link() {
    // Security review X12: the scripts print the chats' tokens. They go at
    // quit, not only at the next start.
    let root = std::env::temp_dir().join(format!("otel-helper-{}", uuid::Uuid::new_v4()));
    let dir = root.join("otel-helper");
    fresh_private_dir(&dir).unwrap();
    let token = "0123456789abcdef0123456789abcdef";
    let script = write_helper(&dir, token).unwrap();
    let mut helpers = Helpers {
        dir: Some(dir.clone()),
        scripts: HashMap::from([(hash(token), script)]),
    };
    clear_helpers(&mut helpers);
    assert!(!dir.exists(), "the folder is gone");
    assert!(helpers.dir.is_none() && helpers.scripts.is_empty());
    clear_helpers(&mut helpers);

    // A link in the folder's place is removed, its target kept.
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("keep"), "k").unwrap();
    std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
    helpers.dir = Some(dir.clone());
    clear_helpers(&mut helpers);
    assert!(std::fs::symlink_metadata(&dir).is_err());
    assert!(elsewhere.join("keep").exists());
    std::fs::remove_dir_all(&root).unwrap();
}

// ---------------------------------------------------------------- tk lane B

const DERM_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn args_of(cmd: &Command) -> Vec<String> {
    cmd.get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

fn env_of(cmd: &Command, name: &str) -> Option<Option<String>> {
    cmd.get_envs()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
}

#[test]
fn only_a_loopback_http_endpoint_is_usable() {
    assert!(loopback_endpoint("http://127.0.0.1:4318"));
    for bad in [
        "http://127.0.0.1:0",
        "http://127.0.0.1:99999",
        "https://127.0.0.1:4318",
        "http://localhost:4318",
        "http://203.0.113.9:4318",
        "http://127.0.0.1:4318/v1/logs",
        "http://127.0.0.1.evil.test:4318",
    ] {
        assert!(!loopback_endpoint(bad), "{bad}");
    }
}

#[test]
fn codex_gets_the_endpoint_in_flags_and_the_token_only_in_its_environment() {
    let home = std::env::temp_dir().join(format!("derm-codex-home-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::new("codex");
    cmd.env("CODEX_HOME", &home);
    let applied = apply_export(
        &Export {
            harness: "codex",
            endpoint: "http://127.0.0.1:4318",
            token: DERM_TOKEN,
            log_prompts: false,
            helper_dir: None,
        },
        &[],
        &mut cmd,
    );
    assert_eq!(applied, Applied::Codex);
    let args = args_of(&cmd);
    assert!(args
        .iter()
        .any(|a| a.contains("http://127.0.0.1:4318/v1/logs")));
    assert!(
        args.iter().all(|a| !a.contains(DERM_TOKEN)),
        "no token in an argument"
    );
    assert_eq!(
        env_of(&cmd, "OTEL_EXPORTER_OTLP_HEADERS"),
        Some(Some(format!("x-derm-token={DERM_TOKEN}")))
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn claude_code_gets_a_private_helper_and_no_token_in_arguments() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("derm-helper-{}", uuid::Uuid::new_v4()));
    let dir = root.join("run-1");
    let mut cmd = Command::new("claude");
    let applied = apply_export(
        &Export {
            harness: "claude-code",
            endpoint: "http://127.0.0.1:4318",
            token: DERM_TOKEN,
            log_prompts: false,
            helper_dir: Some(&dir),
        },
        &[],
        &mut cmd,
    );
    let Applied::Claude {
        helper: Some(helper),
    } = applied
    else {
        panic!("{applied:?}");
    };
    assert!(helper.starts_with(&dir));
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let args = args_of(&cmd);
    assert!(args.iter().all(|a| !a.contains(DERM_TOKEN)));
    assert!(args.iter().any(|a| a.contains("otelHeadersHelper")));
    assert_eq!(
        env_of(&cmd, "OTEL_EXPORTER_OTLP_HEADERS"),
        Some(None),
        "removed"
    );
    assert!(std::fs::read_to_string(&helper)
        .unwrap()
        .contains("x-derm-token"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_export_stands_down_for_a_users_own_otel_and_for_other_harnesses() {
    let export = |harness| Export {
        harness,
        endpoint: "http://127.0.0.1:4318",
        token: DERM_TOKEN,
        log_prompts: false,
        helper_dir: None,
    };
    let mut cmd = Command::new("claude");
    cmd.env("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example");
    assert!(matches!(
        apply_export(&export("claude-code"), &[], &mut cmd),
        Applied::StoodDown(_)
    ));
    assert!(args_of(&cmd).is_empty());
    let mut cmd = Command::new("pi");
    assert!(matches!(
        apply_export(&export("pi"), &[], &mut cmd),
        Applied::StoodDown(_)
    ));
    let mut cmd = Command::new("claude");
    let bad = Export {
        endpoint: "http://203.0.113.9:4318",
        ..export("claude-code")
    };
    assert!(matches!(
        apply_export(&bad, &[], &mut cmd),
        Applied::StoodDown(_)
    ));
    assert!(cmd.get_envs().next().is_none(), "nothing set");
}

#[test]
fn minted_tokens_are_fresh_and_name_their_chat() {
    let f = fixture(true);
    let a = f.receiver.mint("c1", "pi").unwrap();
    let b = f.receiver.mint("c1", "pi").unwrap();
    assert_ne!(a, b);
    assert!(derm_core::token::well_formed(&a));
    assert_eq!(f.receiver.holder_of(&a), Some(("c1".to_string(), "pi")));
    assert_eq!(f.receiver.holder_of(&"0".repeat(64)), None);
    assert_eq!(harness_env::harness_id("pi"), Some("pi"));
    assert_eq!(
        harness_env::harness_id("claude"),
        None,
        "derm uses the preset ids"
    );
    assert_eq!(normalize::short_name("pi.tool_result"), "tool_result");
}

/// Mac test w4, MW4-6: the daemon minted tokens only for the 14 ids of
/// session 0's table, so `derm run` could not start 9 of its 21 agents, nor
/// an unknown program (case 80). Every id of the preset table, in either
/// list, and `derm run`'s `other` are harness ids a token can carry.
#[test]
fn every_preset_id_and_other_can_get_a_token() {
    let index: serde_json::Value = serde_json::from_str(include_str!(
        "../../../derm-cli/src/connect/presets/index.json"
    ))
    .unwrap();
    let mut ids: Vec<String> = Vec::new();
    for list in ["harnesses", "planned"] {
        for id in index[list].as_array().unwrap() {
            ids.push(id.as_str().unwrap().to_string());
        }
    }
    ids.push("other".into());
    let missing: Vec<&String> = ids
        .iter()
        .filter(|id| harness_env::harness_id(id).is_none())
        .collect();
    assert!(missing.is_empty(), "no token for {missing:?}");
    let f = fixture(true);
    for id in &ids {
        let h = harness_env::harness_id(id).unwrap();
        let t = f.receiver.mint("c-mw46", h).unwrap();
        assert_eq!(f.receiver.holder_of(&t), Some(("c-mw46".to_string(), h)));
    }
}

/// P4-R1 (integration w5, continue): the derm routes answer 503 until the
/// daemon sets its ops, take JSON only, and hold at most `MAX_APPROVING`
/// approve requests at once, so a chat cannot hold every connection.
#[test]
fn the_derm_routes_wait_for_the_daemon_and_bound_waiting_asks() {
    let f = fixture(true);
    let port = f.receiver.port();
    let token = f.receiver.mint("chat-d", "claude-code").unwrap();
    let json = [
        ("x-derm-token", token.as_str()),
        ("content-type", "application/json"),
    ];
    let ask = br#"{"request":{"id":"a","chat":"","harness":"","tool":"bash","summary":"s","timeoutSeconds":5}}"#;
    assert_eq!(post(port, "/derm/v1/event", &json, br#"{"event":{}}"#), 503);
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let held = release.clone();
    f.receiver.set_ops(Arc::new(move |chat, harness, op| {
        assert_eq!((chat, harness), ("chat-d", "claude-code"));
        if let ChatOp::Approve(_) = op {
            let (lock, cv) = &*held;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
        }
        serde_json::json!({"ok": true})
    }));
    let proto = [
        ("x-derm-token", token.as_str()),
        ("content-type", "application/x-protobuf"),
    ];
    assert_eq!(post(port, "/derm/v1/event", &proto, b""), 415);
    assert_eq!(post(port, "/derm/v1/event", &json, br#"{"event":{}}"#), 200);
    let waiting: Vec<_> = (0..MAX_APPROVING)
        .map(|_| {
            let t = token.clone();
            std::thread::spawn(move || {
                post(
                    port,
                    "/derm/v1/approve",
                    &[
                        ("x-derm-token", t.as_str()),
                        ("content-type", "application/json"),
                    ],
                    ask,
                )
            })
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    while f.receiver.approving.load(Ordering::SeqCst) < MAX_APPROVING && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(f.receiver.approving.load(Ordering::SeqCst), MAX_APPROVING);
    assert_eq!(post(port, "/derm/v1/approve", &json, ask), 503);
    // Events still go through while the asks wait.
    assert_eq!(post(port, "/derm/v1/event", &json, br#"{"event":{}}"#), 200);
    {
        let (lock, cv) = &*release;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    for w in waiting {
        assert_eq!(w.join().unwrap(), 200);
    }
    assert_eq!(f.receiver.approving.load(Ordering::SeqCst), 0);
    // A body over the socket's line cap is refused before it is read.
    let big = format!(r#"{{"event":"{}"}}"#, "x".repeat(MAX_DERM_BODY_BYTES));
    assert_eq!(post(port, "/derm/v1/event", &json, big.as_bytes()), 413);
}

/// Lane S's request 3's rest (integration w5, continue): the content switch
/// replaces `DERM_LOG_CONTENT`. A record never keeps prompt or reply text;
/// with the switch on the text goes to a content file (0600, in the chat's
/// 0700 folder) and the record says `contentKept`; off, it is dropped, and a
/// harness's redaction mark is never kept as content.
#[test]
fn prompt_text_goes_to_a_content_file_only_with_the_switch_on() {
    let f = fixture(true);
    let port = f.receiver.port();
    let token = f.receiver.mint("chat-c", "claude-code").unwrap();
    let root = std::env::temp_dir().join(format!("derm-otel-content-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let on = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let switch = on.clone();
    let data = root.clone();
    f.receiver.set_content(Arc::new(move |chat| {
        assert_eq!(chat, "chat-c");
        switch
            .load(Ordering::SeqCst)
            .then(|| derm_tap::content::Target {
                root: data.clone(),
                retention_days: 2,
            })
    }));
    let body = |name: &str, key: &str, text: &str| {
        serde_json::json!({ "resourceLogs": [{ "scopeLogs": [{ "logRecords": [{
            "timeUnixNano": "5000000",
            "attributes": [
                { "key": "event.name", "value": { "stringValue": name } },
                { "key": key, "value": { "stringValue": text } },
                { "key": "prompt_length", "value": { "stringValue": "14" } }
            ]
        }]}]}]})
        .to_string()
        .into_bytes()
    };
    let headers = [
        ("x-derm-token", token.as_str()),
        ("content-type", "application/json"),
    ];
    let next = || {
        f.events
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .remove(0)
    };
    // Off: the text is dropped and nothing is written.
    assert_eq!(
        post(
            port,
            "/v1/logs",
            &headers,
            &body("user_prompt", "prompt", "my secret plan")
        ),
        200
    );
    let e = next();
    assert!(e.detail["attributes"].get("prompt").is_none());
    assert!(e.detail.get("contentKept").is_none());
    assert!(!root.join("content").exists());
    // On: the prompt and the reply go to their files, never the record.
    on.store(true, Ordering::SeqCst);
    assert_eq!(
        post(
            port,
            "/v1/logs",
            &headers,
            &body("user_prompt", "prompt", "my secret plan")
        ),
        200
    );
    let e = next();
    assert!(e.detail["attributes"].get("prompt").is_none());
    assert_eq!(e.detail["contentKept"], true);
    let name = e.detail["contentFiles"][0].as_str().unwrap().to_string();
    assert!(
        name.ends_with(".request") && name.contains("-r2-"),
        "{name}"
    );
    let file = root.join("content").join("chat-c").join(&name);
    assert!(std::fs::read_to_string(&file)
        .unwrap()
        .contains("my secret plan"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(root.join("content/chat-c"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    assert_eq!(
        post(
            port,
            "/v1/logs",
            &headers,
            &body("assistant_response", "response", "the answer")
        ),
        200
    );
    let e = next();
    assert!(e.detail["attributes"].get("response").is_none());
    assert!(e.detail["contentFiles"][0]
        .as_str()
        .unwrap()
        .ends_with(".response"));
    // A redaction mark is not content.
    assert_eq!(
        post(
            port,
            "/v1/logs",
            &headers,
            &body("user_prompt", "prompt", "<REDACTED>")
        ),
        200
    );
    let e = next();
    assert!(e.detail.get("contentKept").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// A call's whole input (`tool_input`, Claude Code's with
/// `OTEL_LOG_TOOL_DETAILS`, Pi's with the switch on) is content: it leaves
/// the record, and goes to a content file only with the switch on.
#[test]
fn a_calls_whole_input_is_content_too() {
    let f = fixture(true);
    let port = f.receiver.port();
    let token = f.receiver.mint("chat-i", "claude-code").unwrap();
    let body = serde_json::json!({ "resourceLogs": [{ "scopeLogs": [{ "logRecords": [{
        "timeUnixNano": "5000000",
        "attributes": [
            { "key": "event.name", "value": { "stringValue": "tool_result" } },
            { "key": "tool_name", "value": { "stringValue": "Write" } },
            { "key": "success", "value": { "stringValue": "true" } },
            { "key": "tool_input", "value": { "stringValue": "{\"content\":\"my private notes\"}" } },
            { "key": "tool_input_size_bytes", "value": { "stringValue": "30" } }
        ]
    }]}]}]})
    .to_string();
    let headers = [
        ("x-derm-token", token.as_str()),
        ("content-type", "application/json"),
    ];
    assert_eq!(post(port, "/v1/logs", &headers, body.as_bytes()), 200);
    let e = f
        .events
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .remove(0);
    assert!(e.detail["attributes"].get("tool_input").is_none());
    assert_eq!(e.detail["attributes"]["tool_input_size_bytes"], "30");
    assert!(!serde_json::to_string(&e).unwrap().contains("private notes"));
}

/// Security finding W5C-S5 (integration w5 continue): Codex's `arguments`
/// and `output` on its tool events, and Claude Code's `tool_parameters`
/// (with `OTEL_LOG_TOOL_DETAILS`, which `derm run` sets: the Bash command
/// line, `full_command` and its description, per Claude Code's monitoring
/// page), are a call's arguments and result, which the contract keeps out of
/// every record. Off, they are dropped; on, they go to the content files, the
/// result to the `.response` one.
#[test]
fn a_calls_arguments_and_output_are_content_for_codex_and_claude_code() {
    let f = fixture(true);
    let port = f.receiver.port();
    let token = f.receiver.mint("chat-a", "codex").unwrap();
    let root =
        std::env::temp_dir().join(format!("derm-otel-args-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&root).unwrap();
    let on = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let switch = on.clone();
    let data = root.clone();
    f.receiver.set_content(Arc::new(move |_| {
        switch
            .load(Ordering::SeqCst)
            .then(|| derm_tap::content::Target {
                root: data.clone(),
                retention_days: 1,
            })
    }));
    let body = |name: &str, attrs: &[(&str, &str)]| {
        let mut a =
            vec![serde_json::json!({ "key": "event.name", "value": { "stringValue": name } })];
        for (k, v) in attrs {
            a.push(serde_json::json!({ "key": k, "value": { "stringValue": v } }));
        }
        serde_json::json!({ "resourceLogs": [{ "scopeLogs": [{ "logRecords": [{
            "timeUnixNano": "5000000", "attributes": a
        }]}]}]})
        .to_string()
        .into_bytes()
    };
    let headers = [
        ("x-derm-token", token.as_str()),
        ("content-type", "application/json"),
    ];
    let next = || {
        f.events
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .remove(0)
    };
    let codex = body(
        "codex.tool_result",
        &[
            ("tool_name", "shell"),
            ("call_id", "call_1"),
            ("arguments", "{\"command\":[\"cat\",\"secret-arg.txt\"]}"),
            ("output", "the private output"),
            ("success", "true"),
        ],
    );
    let claude = body(
        "claude_code.tool_result",
        &[
            ("tool_name", "Bash"),
            (
                "tool_parameters",
                "{\"bash_command\":\"curl\",\"full_command\":\"curl -H 'x: secret-param'\"}",
            ),
            ("success", "true"),
        ],
    );
    for b in [&codex, &claude] {
        assert_eq!(post(port, "/v1/logs", &headers, b), 200);
        let e = next();
        let attrs = &e.detail["attributes"];
        for key in ["arguments", "output", "tool_parameters"] {
            assert!(attrs.get(key).is_none(), "{key} stayed in {attrs}");
        }
        let text = serde_json::to_string(&e).unwrap();
        for secret in ["secret-arg", "private output", "secret-param"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        assert!(e.detail.get("contentKept").is_none());
    }
    assert!(!root.join("content").exists());
    on.store(true, Ordering::SeqCst);
    assert_eq!(post(port, "/v1/logs", &headers, &codex), 200);
    let e = next();
    assert_eq!(e.detail["contentKept"], true);
    let files: Vec<String> = e.detail["contentFiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let dir = root.join("content").join("chat-a");
    let read = |suffix: &str| {
        let name = files.iter().find(|n| n.ends_with(suffix)).unwrap();
        std::fs::read_to_string(dir.join(name)).unwrap()
    };
    assert!(read(".request").contains("secret-arg"));
    assert!(!read(".request").contains("private output"));
    assert!(read(".response").contains("the private output"));
    assert!(!serde_json::to_string(&e).unwrap().contains("secret-arg"));
    let _ = std::fs::remove_dir_all(&root);
}
