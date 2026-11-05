//! The tap end to end on loopback: a client, the tap, and a fake upstream
//! that records what reached it and answers from a script.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use derm_core::event::Event;
use derm_tap::upstream::Upstream;
use derm_tap::{content, http, route, Chat, Config, Tap};
use serde_json::{json, Value};

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// What the fake upstream sends back: a status, headers, and the body in
/// pieces; `cut` closes the socket after the pieces without ending the
/// chunked body.
#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    pieces: Vec<Vec<u8>>,
    cut: bool,
}

struct Upstream_ {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn fake_upstream(replies: Vec<Reply>) -> Upstream_ {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let replies = Arc::new(Mutex::new(replies));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let seen = seen2.clone();
            let replies = replies.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut w = stream;
                while let Ok(req) = http::read_request(&mut reader, || Ok(())) {
                    seen.lock().unwrap().push(Seen {
                        method: req.method.clone(),
                        target: req.target.clone(),
                        headers: req.headers.clone(),
                        body: req.body.clone(),
                    });
                    let reply = {
                        let mut r = replies.lock().unwrap();
                        if r.len() > 1 { r.remove(0) } else { r[0].clone() }
                    };
                    let headers: Vec<(String, String)> =
                        reply.headers.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
                    http::write_head(&mut w, reply.status, &headers, true, false).unwrap();
                    for p in &reply.pieces {
                        http::write_chunk(&mut w, p).unwrap();
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    if reply.cut {
                        let _ = w.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                    http::end_chunks(&mut w).unwrap();
                }
            });
        }
    });
    Upstream_ { base, seen }
}

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Rig {
    tap: Tap,
    events: Arc<Mutex<Vec<Event>>>,
    route: String,
    up: Upstream_,
}

fn rig(replies: Vec<Reply>, local: bool, content_root: Option<std::path::PathBuf>) -> Rig {
    let up = fake_upstream(replies);
    let route = route::of_token(TOKEN);
    let want = route.clone();
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = events.clone();
    let mut config = Config::new(
        Arc::new(move |r: &str| {
            (r == want).then(|| Chat {
                id: "chat-t".into(),
                harness: "claude-code".into(),
            })
        }),
        Arc::new(move |e: Vec<Event>| sink_events.lock().unwrap().extend(e)),
    );
    let mut table = BTreeMap::new();
    table.insert("anthropic".to_string(), Upstream { base: up.base.clone(), local });
    table.insert("openai".to_string(), Upstream { base: format!("{}/v1", up.base), local });
    config.upstreams = table;
    if let Some(root) = content_root {
        config.content = Arc::new(move |_| Some(content::Target { root: root.clone(), retention_days: 2 }));
    }
    let tap = Tap::start(config).unwrap();
    Rig { tap, events, route, up }
}

/// Sends one request over a new connection and returns the status, the
/// response headers and the de-chunked body (whatever arrived).
fn send(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>, bool) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: {}\r\n", body.len());
    for (n, v) in headers {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status: u16 = line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut hs = Vec::new();
    loop {
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        let l = l.trim_end().to_string();
        if l.is_empty() {
            break;
        }
        let (n, v) = l.split_once(':').unwrap();
        hs.push((n.to_ascii_lowercase(), v.trim().to_string()));
    }
    let chunked = hs.iter().any(|(n, v)| n == "transfer-encoding" && v == "chunked");
    let mut out = Vec::new();
    let mut ended = false;
    if chunked {
        loop {
            let mut size = String::new();
            if r.read_line(&mut size).unwrap_or(0) == 0 {
                break;
            }
            let n = usize::from_str_radix(size.trim(), 16).unwrap();
            if n == 0 {
                ended = true;
                break;
            }
            let mut buf = vec![0; n + 2];
            if r.read_exact(&mut buf).is_err() {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    } else if let Some((_, len)) = hs.iter().find(|(n, _)| n == "content-length") {
        let mut buf = vec![0; len.parse().unwrap()];
        r.read_exact(&mut buf).unwrap();
        out = buf;
        ended = true;
    }
    (status, hs, out, ended)
}

fn sse(events: &[Value]) -> Vec<Vec<u8>> {
    events
        .iter()
        .map(|e| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap()).into_bytes())
        .collect()
}

fn anthropic_tool_stream() -> Vec<Vec<u8>> {
    sse(&[
        json!({"type":"message_start","message":{"model":"claude-x","usage":{"input_tokens":10,"output_tokens":1}}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Read","input":{}}}),
        json!({"type":"ping"}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"file_path\":\"/p/a.rs\"}"}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":5}}),
        json!({"type":"message_stop"}),
    ])
}

fn sse_reply(pieces: Vec<Vec<u8>>, cut: bool) -> Reply {
    Reply {
        status: 200,
        headers: vec![("content-type", "text/event-stream"), ("anthropic-ratelimit-unified-status", "allowed")],
        pieces,
        cut,
    }
}

fn wait_events(rig: &Rig, n: usize) -> Vec<Event> {
    for _ in 0..200 {
        let e = rig.events.lock().unwrap().clone();
        if e.len() >= n {
            return e;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    rig.events.lock().unwrap().clone()
}

#[test]
fn a_stream_passes_through_unchanged_and_its_call_is_recorded_then_joined_to_its_result() {
    let pieces = anthropic_tool_stream();
    let text_only = sse(&[
        json!({"type":"message_start","message":{"model":"claude-x","usage":{"input_tokens":20,"output_tokens":1}}}),
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}),
        json!({"type":"message_stop"}),
    ]);
    let rig = rig(vec![sse_reply(pieces.clone(), false), sse_reply(text_only, false)], false, None);
    let path = format!("/r/{}/anthropic/v1/messages?beta=true", rig.route);
    let body = json!({"model":"claude-x","stream":true,"tools":[{"name":"Read"},{"name":"Bash"}],"messages":[{"role":"user","content":"read it"}]});
    let (status, headers, got, ended) = send(
        rig.tap.port(),
        "POST",
        &path,
        &[("anthropic-beta", "oauth-2025-04-20,x"), ("authorization", "Bearer SECRET-TOKEN"), ("accept-encoding", "gzip")],
        body.to_string().as_bytes(),
    );
    assert_eq!(status, 200);
    assert!(ended);
    assert_eq!(got, pieces.concat(), "the stream reaches the client byte for byte");
    assert!(headers.iter().any(|(n, v)| n == "anthropic-ratelimit-unified-status" && v == "allowed"));

    let seen = rig.up.seen.lock().unwrap()[0].clone();
    assert_eq!(seen.target, "/v1/messages?beta=true");
    let h = |name: &str| seen.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());
    assert_eq!(h("anthropic-beta").as_deref(), Some("oauth-2025-04-20,x"));
    assert_eq!(h("authorization").as_deref(), Some("Bearer SECRET-TOKEN"));
    assert_eq!(h("accept-encoding").as_deref(), Some("identity"));
    assert_eq!(h(route::HEADER), None);
    assert_eq!(seen.body, body.to_string().into_bytes(), "a hosted upstream gets the body as sent");

    let ev = wait_events(&rig, 2);
    assert_eq!(ev[0].kind, "tap.request");
    assert_eq!(ev[0].detail["toolsOffered"], 2);
    assert_eq!(ev[0].detail["toolCalls"], 1);
    assert_eq!(ev[0].detail["incomplete"], false);
    assert_eq!(ev[0].detail["inputTokens"], 10);
    assert_eq!(ev[1].kind, "tap.call");
    assert_eq!(ev[1].id, "tap-chat-t-toolu_1");
    assert_eq!(ev[1].detail["paths"], json!(["/p/a.rs"]));
    assert_eq!(ev[1].detail["resultSha256"], Value::Null);
    assert_eq!(ev[1].detail["request"], json!(ev[0].id));

    // The next request carries the result: the call's record comes again,
    // under the same id, with the result's hash; once, however often the
    // history repeats it.
    let next = json!({"model":"claude-x","messages":[
        {"role":"user","content":"read it"},
        {"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/p/a.rs"}}]},
        {"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"fn main() {}"}]}
    ]});
    for _ in 0..2 {
        send(rig.tap.port(), "POST", &path, &[], next.to_string().as_bytes());
    }
    let ev = wait_events(&rig, 6);
    let joined: Vec<&Event> = ev.iter().filter(|e| e.kind == "tap.call" && e.detail["resultSha256"] != Value::Null).collect();
    assert_eq!(joined.len(), 1, "{ev:#?}");
    assert_eq!(joined[0].id, "tap-chat-t-toolu_1");
    assert_eq!(joined[0].detail["resultBytes"], 12);

    let all = serde_json::to_string(&ev).unwrap();
    for secret in ["SECRET-TOKEN", "fn main", "read it", "oauth-2025", "/v1/messages", "beta=true"] {
        assert!(!all.contains(secret), "records hold {secret}");
    }
}

#[test]
fn a_stream_cut_mid_call_is_recorded_incomplete_and_the_client_sees_the_cut() {
    let pieces = anthropic_tool_stream()[..3].to_vec();
    let rig = rig(vec![sse_reply(pieces.clone(), true)], false, None);
    let path = format!("/r/{}/anthropic/v1/messages", rig.route);
    let (status, _, got, ended) = send(rig.tap.port(), "POST", &path, &[], br#"{"model":"claude-x","stream":true}"#);
    assert_eq!(status, 200);
    assert!(!ended, "the client sees a cut, not a clean end");
    assert_eq!(got, pieces.concat());
    let ev = wait_events(&rig, 2);
    assert_eq!(ev[0].detail["incomplete"], true);
    assert_eq!(ev[1].detail["callId"], "toolu_1");
    assert_eq!(ev[1].detail["incomplete"], true);
    assert_eq!(rig.tap.counters().cut.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn requests_the_tap_cannot_place_are_refused_with_a_reason_and_never_forwarded() {
    let rig = rig(vec![sse_reply(anthropic_tool_stream(), false)], false, None);
    let other = route::of_token(&"f".repeat(64));
    let cases = [
        ("/anthropic/v1/messages".to_string(), 403, "no derm route"),
        (format!("/r/{other}/anthropic/v1/messages"), 403, "no running chat"),
        (format!("/r/{}/gemini/v1/x", rig.route), 404, "no upstream named gemini"),
        (format!("/r/{}/evil.example/v1", rig.route), 404, "names no upstream"),
        (format!("/r/{}/anthropic/v1/../../x", rig.route), 400, "cannot be forwarded"),
        (format!("/r/{}/anthropic@evil.example/v1", rig.route), 404, "names no upstream"),
    ];
    for (path, want, why) in cases {
        let (status, _, body, _) = send(rig.tap.port(), "POST", &path, &[], b"{}");
        assert_eq!(status, want, "{path}");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains(why), "{path}: {text}");
        assert!(text.starts_with("{\"error\""), "an Anthropic-shaped error: {text}");
    }
    assert!(rig.up.seen.lock().unwrap().is_empty());
    assert!(rig.events.lock().unwrap().is_empty());
    // A WebSocket upgrade is refused, not proxied.
    let (status, _, _, _) = send(rig.tap.port(), "GET", &format!("/r/{}/openai/responses", rig.route), &[("upgrade", "websocket"), ("connection", "Upgrade")], b"");
    assert_eq!(status, 501);
}

#[test]
fn the_header_form_of_the_route_works_and_is_not_forwarded() {
    let body = sse(&[
        json!({"type":"response.created","response":{"model":"gpt-x"}}),
        json!({"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"shell","arguments":""}}),
        json!({"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"shell","arguments":"{\"command\":[\"ls\"]}"}}),
        json!({"type":"response.completed","response":{"model":"gpt-x","usage":{"input_tokens":3,"output_tokens":4}}}),
    ]);
    let rig = rig(vec![sse_reply(body, false)], false, None);
    let route = rig.route.clone();
    let (status, _, _, _) = send(rig.tap.port(), "POST", "/openai/responses", &[(route::HEADER, &route)], br#"{"model":"gpt-x","stream":true,"input":"hi"}"#);
    assert_eq!(status, 200);
    let seen = rig.up.seen.lock().unwrap()[0].clone();
    assert_eq!(seen.target, "/v1/responses");
    assert!(!seen.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(route::HEADER)));
    let ev = wait_events(&rig, 2);
    assert_eq!(ev[1].detail["api"], "openai-responses");
    assert_eq!(ev[1].detail["callId"], "call_1");
}

#[test]
fn errors_and_other_paths_pass_through_untouched_and_unrecorded() {
    let err = Reply {
        status: 429,
        headers: vec![("content-type", "application/json"), ("retry-after", "7"), ("x-should-retry", "true")],
        pieces: vec![br#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#.to_vec()],
        cut: false,
    };
    let rig = rig(vec![err.clone()], false, None);
    let (status, headers, body, _) = send(rig.tap.port(), "POST", &format!("/r/{}/anthropic/v1/messages", rig.route), &[], b"{}");
    assert_eq!(status, 429);
    assert!(headers.iter().any(|(n, v)| n == "retry-after" && v == "7"));
    assert!(headers.iter().any(|(n, v)| n == "x-should-retry" && v == "true"));
    assert_eq!(body, err.pieces[0]);
    let ev = wait_events(&rig, 1);
    assert_eq!(ev[0].detail["status"], 429);
    assert_eq!(ev[0].detail["toolCalls"], 0);
    // count_tokens and HEAD pass, with no record.
    send(rig.tap.port(), "POST", &format!("/r/{}/anthropic/v1/messages/count_tokens", rig.route), &[], b"{}");
    send(rig.tap.port(), "HEAD", &format!("/r/{}/anthropic/api/hello", rig.route), &[], b"");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(rig.events.lock().unwrap().len(), 1);
    assert_eq!(rig.up.seen.lock().unwrap().len(), 3);
    assert_eq!(rig.up.seen.lock().unwrap()[2].method, "HEAD");
}

#[test]
fn an_upstream_that_does_not_answer_is_a_502_with_the_host_only() {
    let mut config = Config::new(Arc::new(|_| Some(Chat { id: "c".into(), harness: "h".into() })), Arc::new(|_| {}));
    // A port nothing listens on.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);
    let mut table = BTreeMap::new();
    table.insert("anthropic".to_string(), Upstream { base: format!("http://127.0.0.1:{port}"), local: false });
    config.upstreams = table;
    let tap = Tap::start(config).unwrap();
    let r = route::of_token(TOKEN);
    let (status, _, body, _) = send(tap.port(), "POST", &format!("/r/{r}/anthropic/v1/messages?key=SECRET"), &[], b"{}");
    assert_eq!(status, 502);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains(&format!("127.0.0.1:{port}")));
    assert!(!text.contains("SECRET") && !text.contains("/v1/messages"));
}

#[test]
fn a_local_upstream_gets_case_94s_fold_and_a_hosted_one_does_not() {
    let reply = Reply { status: 200, headers: vec![("content-type", "application/json")], pieces: vec![br#"{"content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#.to_vec()], cut: false };
    let body = json!({"model":"qwen","system":"s","messages":[{"role":"user","content":"hi"},{"role":"system","content":"late note"}]});
    for local in [true, false] {
        let rig = rig(vec![reply.clone()], local, None);
        send(rig.tap.port(), "POST", &format!("/r/{}/anthropic/v1/messages", rig.route), &[], body.to_string().as_bytes());
        let sent: Value = serde_json::from_slice(&rig.up.seen.lock().unwrap()[0].body).unwrap();
        let roles: Vec<&str> = sent["messages"].as_array().unwrap().iter().map(|m| m["role"].as_str().unwrap()).collect();
        if local {
            assert_eq!(roles, vec!["user"]);
            assert_eq!(sent["system"][1]["text"], "late note");
        } else {
            assert_eq!(sent, body);
        }
    }
}

#[test]
fn content_on_keeps_the_bodies_in_private_files_and_never_a_header() {
    let root = std::env::temp_dir().join(format!("derm-tap-server-content-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let pieces = anthropic_tool_stream();
    let rig = rig(vec![sse_reply(pieces.clone(), false)], false, Some(root.clone()));
    let body = br#"{"model":"claude-x","stream":true,"messages":[{"role":"user","content":"PROMPT-TEXT"}]}"#;
    send(rig.tap.port(), "POST", &format!("/r/{}/anthropic/v1/messages", rig.route), &[("authorization", "Bearer SECRET-TOKEN")], body);
    let ev = wait_events(&rig, 2);
    assert_eq!(ev[0].detail["contentKept"], true);
    assert_eq!(ev[1].detail["contentKept"], true);
    let dir = root.join("content/chat-t");
    let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    assert_eq!(files.len(), 2);
    let req = std::fs::read(files.iter().find(|p| p.to_string_lossy().ends_with(".request")).unwrap()).unwrap();
    let resp = std::fs::read(files.iter().find(|p| p.to_string_lossy().ends_with(".response")).unwrap()).unwrap();
    assert_eq!(req, body);
    assert_eq!(resp, pieces.concat());
    for f in &files {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(f).unwrap().mode() & 0o777, 0o600);
        let name = f.file_name().unwrap().to_str().unwrap();
        assert_eq!(content::parse_name(name).map(|(_, d)| d), Some(2));
        assert!(!String::from_utf8_lossy(&std::fs::read(f).unwrap()).contains("SECRET-TOKEN"));
    }
    let _ = std::fs::remove_dir_all(root);
}
