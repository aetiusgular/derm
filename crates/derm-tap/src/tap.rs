//! The tap: a loopback HTTP/1.1 server that forwards each request to its
//! chat's upstream and records what the model asked for.
//!
//! - Bytes pass through as they arrive, both ways: the response is never
//!   buffered (Claude Code's gateway guide: a buffering gateway stalls it).
//!   The parser reads a copy.
//! - The request body goes upstream as it came, except case 94's fold for a
//!   local upstream. `anthropic-*` headers and every other end-to-end header
//!   pass unchanged; hop-by-hop headers, `Host`, the route header and
//!   `Accept-Encoding` do not (the tap asks for `identity`, so it reads what
//!   it passes on).
//! - Error bodies, status codes and response headers pass unchanged, so a
//!   harness's own retry logic reads the upstream's words.
//! - No header, URL, query or body is ever logged, recorded or echoed
//!   (case 114). The only body copies are content files, when the user
//!   turned content on.
//! - A request the tap cannot place (no route, an ended chat, an upstream
//!   the table does not name) fails with a reason the harness shows. It is
//!   never sent anywhere untapped (case 117).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use derm_core::event::Event;
use serde_json::{json, Value};

use crate::apis::{self, ResponseParser};
use crate::content;
use crate::fold;
use crate::http::{self, ReadError};
use crate::record::{digest_result, Api, CallRecord, RequestRecord};
use crate::route;
use crate::upstream::{self, Upstream};

/// A chat the tap records for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chat {
    pub id: String,
    pub harness: String,
}

/// Where records go: the daemon's `ingest`, as the OTLP receiver's sink.
pub type Sink = Arc<dyn Fn(Vec<Event>) + Send + Sync>;
/// A route to its chat; `None` for a route no running chat holds.
pub type Resolver = Arc<dyn Fn(&str) -> Option<Chat> + Send + Sync>;
/// Whether a chat's content is kept, and for how long.
pub type ContentPolicy = Arc<dyn Fn(&Chat) -> Option<content::Target> + Send + Sync>;

/// Calls one chat keeps in memory to join their results to (oldest go first).
pub const MAX_CALLS_PER_CHAT: usize = 4_096;
/// Chats with calls in memory at once.
pub const MAX_CHATS: usize = 512;
const IDLE: Duration = Duration::from_secs(600);
const CHUNK: usize = 16 * 1024;

pub struct Config {
    pub bind: IpAddr,
    /// The port of the last run, kept across a daemon restart so a running
    /// harness's base URL still answers (case 86); a busy port falls back to
    /// a free one.
    pub preferred_port: Option<u16>,
    pub upstreams: BTreeMap<String, Upstream>,
    pub resolve: Resolver,
    pub sink: Sink,
    pub content: ContentPolicy,
    pub max_connections: usize,
    /// The upstream client; `None` builds the default (`default_agent`).
    pub agent: Option<ureq::Agent>,
}

impl Config {
    pub fn new(resolve: Resolver, sink: Sink) -> Self {
        Config {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            preferred_port: None,
            upstreams: upstream::builtin(),
            resolve,
            sink,
            content: Arc::new(|_| None),
            max_connections: 256,
            agent: None,
        }
    }
}

/// The upstream client: no redirect followed (a credential never follows a
/// `Location`), every status passed on as data, the OS trust store, the
/// environment's proxy and `NO_PROXY`, no compression asked for, and no
/// limit on a stream's length or on how long a model may think.
pub fn default_agent() -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .tls_config(tls)
        .accept_encoding("")
        .user_agent("")
        .allow_non_standard_methods(true)
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_per_read(Some(IDLE))
        .build();
    ureq::Agent::new_with_config(config)
}

#[derive(Default)]
struct ChatCalls {
    calls: HashMap<String, CallRecord>,
    order: VecDeque<String>,
}

impl ChatCalls {
    fn keep(&mut self, rec: CallRecord) {
        if !self.calls.contains_key(&rec.call_id) {
            self.order.push_back(rec.call_id.clone());
            while self.order.len() > MAX_CALLS_PER_CHAT {
                if let Some(old) = self.order.pop_front() {
                    self.calls.remove(&old);
                }
            }
        }
        self.calls.insert(rec.call_id.clone(), rec);
    }
}

/// Counts for `report` and tests.
#[derive(Debug, Default)]
pub struct Counters {
    pub requests: AtomicU64,
    pub refused: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub cut: AtomicU64,
    pub results_unmatched: AtomicU64,
}

struct Inner {
    upstreams: BTreeMap<String, Upstream>,
    resolve: Resolver,
    sink: Sink,
    content: ContentPolicy,
    agent: ureq::Agent,
    max_connections: usize,
    open: AtomicUsize,
    stop: AtomicBool,
    chats: Mutex<HashMap<String, ChatCalls>>,
    counters: Counters,
}

/// A running tap.
pub struct Tap {
    inner: Arc<Inner>,
    addr: SocketAddr,
    accept: Option<JoinHandle<()>>,
}

impl Tap {
    pub fn start(config: Config) -> Result<Tap, String> {
        no_core_dumps();
        let listener = config
            .preferred_port
            .and_then(|p| TcpListener::bind(SocketAddr::new(config.bind, p)).ok())
            .map(Ok)
            .unwrap_or_else(|| TcpListener::bind(SocketAddr::new(config.bind, 0)))
            .map_err(|e| format!("derm tap: bind {}: {e}", config.bind))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let inner = Arc::new(Inner {
            upstreams: config.upstreams,
            resolve: config.resolve,
            sink: config.sink,
            content: config.content,
            agent: config.agent.unwrap_or_else(default_agent),
            max_connections: config.max_connections.max(1),
            open: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
            chats: Mutex::new(HashMap::new()),
            counters: Counters::default(),
        });
        let accept_inner = inner.clone();
        let accept = std::thread::Builder::new()
            .name("derm-tap-accept".into())
            .spawn(move || accept_loop(listener, accept_inner))
            .map_err(|e| e.to_string())?;
        Ok(Tap {
            inner,
            addr,
            accept: Some(accept),
        })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// `http://127.0.0.1:<port>`, what the daemon publishes as
    /// `tap.endpoint` beside `otlp.endpoint`.
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn counters(&self) -> &Counters {
        &self.inner.counters
    }

    /// Drops a chat's calls from memory (at its `run.stop`).
    pub fn forget_chat(&self, chat: &str) {
        if let Ok(mut chats) = self.inner.chats.lock() {
            chats.remove(chat);
        }
    }

    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Case 114: a crash leaves no core file, which would hold tokens and
/// bodies. The limit is the process's, so it holds for the daemon the tap
/// runs in (recorded as a request for integration to set at start too).
fn no_core_dumps() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads one valid struct; failure leaves the limit as it was.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
}

fn accept_loop(listener: TcpListener, inner: Arc<Inner>) {
    for stream in listener.incoming() {
        if inner.stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = stream else { continue };
        if inner.open.load(Ordering::SeqCst) >= inner.max_connections {
            let mut s = stream;
            let _ = http::write_json(&mut s, 503, &error_body("too many connections to the tap"), true);
            continue;
        }
        inner.open.fetch_add(1, Ordering::SeqCst);
        let conn_inner = inner.clone();
        let spawned = std::thread::Builder::new()
            .name("derm-tap-conn".into())
            .spawn(move || {
                serve(stream, &conn_inner);
                conn_inner.open.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            inner.open.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn error_body(message: &str) -> String {
    json!({"type": "error", "error": {"type": "api_error", "message": format!("derm tap: {message}")}}).to_string()
}

fn serve(stream: TcpStream, inner: &Inner) {
    let _ = stream.set_read_timeout(Some(IDLE));
    let _ = stream.set_nodelay(true);
    let Ok(read_half) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    loop {
        if inner.stop.load(Ordering::SeqCst) {
            return;
        }
        let req = {
            let w = &mut writer;
            http::read_request(&mut reader, || {
                w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
                w.flush()
            })
        };
        let req = match req {
            Ok(r) => r,
            Err(ReadError::Closed) | Err(ReadError::Io(_)) => return,
            Err(ReadError::Bad(why)) => {
                inner.counters.refused.fetch_add(1, Ordering::Relaxed);
                let _ = http::write_json(&mut writer, 400, &error_body(why), true);
                return;
            }
        };
        let close = req.wants_close();
        let keep = handle(inner, req, &mut writer, close);
        if close || !keep {
            let _ = writer.shutdown(Shutdown::Both);
            return;
        }
    }
}

/// Headers a proxy never forwards (RFC 9110 7.6.1), plus what the tap sets
/// or reads itself.
fn hop_by_hop(name: &str, listed: &[String]) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "expect"
            | "accept-encoding"
    ) || n == route::HEADER
        || listed.iter().any(|l| *l == n)
}

fn connection_listed(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// One request. Returns whether the connection can carry another.
fn handle(inner: &Inner, req: http::Request, w: &mut TcpStream, close: bool) -> bool {
    inner.counters.requests.fetch_add(1, Ordering::Relaxed);
    let refuse = |w: &mut TcpStream, status: u16, why: &str| {
        inner.counters.refused.fetch_add(1, Ordering::Relaxed);
        let _ = http::write_json(w, status, &error_body(why), close);
        !close
    };
    if req.header("upgrade").is_some() {
        // Codex is started with `supports_websockets = false` (Decisions);
        // the tap does not speak WebSocket in this version.
        refuse(w, 501, "the tap does not speak WebSocket; use the HTTP transport");
        return false;
    }
    let (route_text, rest): (String, String) = match route::split_path(&req.target) {
        Some((r, rest)) => (r.to_string(), rest.to_string()),
        None => match req.header(route::HEADER).map(str::trim) {
            Some(r) if route::well_formed(r) => (r.to_string(), req.target.clone()),
            _ => return refuse(w, 403, "this request carries no derm route; start the harness with derm run"),
        },
    };
    let Some(chat) = (inner.resolve)(&route_text) else {
        return refuse(w, 403, "no running chat holds this route (the chat ended, or derm-daemon restarted without it)");
    };
    let Some((key, tail)) = upstream::split_key(&rest) else {
        return refuse(w, 404, "the path names no upstream");
    };
    let key = if key == upstream::OPENAI_AUTO {
        upstream::openai_auto_key(req.header("chatgpt-account-id").is_some(), req.header("authorization"))
    } else {
        key
    };
    let Some(up) = inner.upstreams.get(key).cloned() else {
        return refuse(w, 404, &format!("no upstream named {key} is configured"));
    };
    if !upstream::tail_is_safe(tail) {
        return refuse(w, 400, "the path cannot be forwarded");
    }
    let url = format!("{}{}", up.base, tail);
    let tail_path = tail.split('?').next().unwrap_or("");
    let api = apis::api_of(&req.method, tail_path);
    let started = Instant::now();
    let at = now_ms();
    let suffix = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
    let request_id = format!("tap-req-{}-{suffix}", chat.id);

    // The request: what it offers and what results it carries back.
    let mut body = req.body;
    let mut req_info = None;
    if let Some(api) = api {
        if let Ok(mut v) = serde_json::from_slice::<Value>(&body) {
            req_info = Some(apis::inspect_request(api, tail, &v));
            if up.local && api == Api::AnthropicMessages && fold::fold_system_messages(&mut v) {
                if let Ok(b) = serde_json::to_vec(&v) {
                    body = b;
                }
            }
        }
    }
    let target = api.and_then(|_| (inner.content)(&chat));
    let mut req_file = target
        .as_ref()
        .and_then(|t| content::open(t, &chat.id, at, &suffix, "request").ok());
    if let Some(f) = req_file.as_mut() {
        f.append(&body);
    }
    if let (Some(api), Some(info)) = (api, &req_info) {
        record_results(inner, &chat, api, info, req_file.as_ref().is_some_and(|f| !f.failed));
    }

    // Forward.
    let listed = connection_listed(&req.headers);
    let mut builder = ureq::http::Request::builder().method(req.method.as_str()).uri(url.as_str());
    for (n, v) in &req.headers {
        if !hop_by_hop(n, &listed) {
            builder = builder.header(n.as_str(), v.as_str());
        }
    }
    builder = builder.header("accept-encoding", "identity");
    let sent = if body.is_empty() {
        builder.body(()).map_err(|_| ()).and_then(|r| inner.agent.run(r).map_err(|_| ()))
    } else {
        builder.body(body).map_err(|_| ()).and_then(|r| inner.agent.run(r).map_err(|_| ()))
    };
    let mut rec = RequestRecord {
        id: request_id.clone(),
        api,
        upstream: up.host(),
        model: req_info.as_ref().map(|i| i.model.clone()).unwrap_or_default(),
        tools_offered: req_info.as_ref().map_or(0, |i| i.tools_offered),
        ..Default::default()
    };
    let resp = match sent {
        Ok(r) => r,
        Err(()) => {
            inner.counters.upstream_errors.fetch_add(1, Ordering::Relaxed);
            let _ = http::write_json(w, 502, &error_body(&format!("the upstream {} did not answer", up.host())), close);
            if api.is_some() {
                rec.duration_ms = started.elapsed().as_millis() as u64;
                (inner.sink)(vec![rec.event(&chat.id, &chat.harness, now_ms())]);
            }
            return !close;
        }
    };
    let status = resp.status().as_u16();
    rec.status = Some(status);
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(n, v)| v.to_str().ok().map(|v| (n.as_str().to_string(), v.to_string())))
        .collect();
    let event_stream = resp_headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.to_ascii_lowercase().starts_with("text/event-stream"));
    let resp_listed = connection_listed(&resp_headers);
    let out_headers: Vec<(String, String)> = resp_headers
        .into_iter()
        .filter(|(n, _)| !hop_by_hop(n, &resp_listed))
        .collect();
    let has_body = req.method != "HEAD" && status != 204 && status != 304 && status >= 200;
    if http::write_head(w, status, &out_headers, has_body, close).is_err() {
        return false;
    }
    let mut parser = api.map(|a| ResponseParser::new(a, event_stream, &format!("gemini-{suffix}")));
    let mut resp_file = target
        .as_ref()
        .and_then(|t| content::open(t, &chat.id, at, &suffix, "response").ok());
    let mut cut = false;
    let mut client_gone = false;
    if has_body {
        let mut reader = resp.into_body().into_reader();
        let mut buf = vec![0u8; CHUNK];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let bytes = &buf[..n];
                    if let Some(p) = parser.as_mut() {
                        p.feed(bytes);
                    }
                    if let Some(f) = resp_file.as_mut() {
                        f.append(bytes);
                    }
                    if http::write_chunk(w, bytes).is_err() {
                        client_gone = true;
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    cut = true;
                    break;
                }
            }
        }
        if !cut && !client_gone && http::end_chunks(w).is_err() {
            client_gone = true;
        }
    }
    if cut || client_gone {
        inner.counters.cut.fetch_add(1, Ordering::Relaxed);
    }

    // Records.
    if let (Some(api), Some(parser)) = (api, parser) {
        let info = parser.finish();
        let content_kept = req_file.as_ref().is_some_and(|f| !f.failed) && resp_file.as_ref().is_some_and(|f| !f.failed);
        rec.duration_ms = started.elapsed().as_millis() as u64;
        if let Some(m) = info.model.clone().filter(|m| !m.is_empty()) {
            rec.model = m;
        }
        rec.input_tokens = info.input_tokens;
        rec.output_tokens = info.output_tokens;
        rec.tool_calls = info.calls.len() as u64;
        let stream_open = event_stream && (200..300).contains(&status) && !info.complete;
        rec.incomplete = cut || client_gone || stream_open;
        rec.content_kept = content_kept;
        let at = now_ms();
        let mut events = vec![rec.event(&chat.id, &chat.harness, at)];
        if let Ok(mut chats) = inner.chats.lock() {
            if !chats.contains_key(&chat.id) && chats.len() >= MAX_CHATS {
                if let Some(k) = chats.keys().next().cloned() {
                    chats.remove(&k);
                }
            }
            let calls = chats.entry(chat.id.clone()).or_default();
            for call in &info.calls {
                let mut c = CallRecord::new(api, &rec.model, Some(request_id.clone()), &chat.harness, call);
                c.content_kept = content_kept;
                events.push(c.event(&chat.id, &chat.harness, at));
                calls.keep(c);
            }
        }
        (inner.sink)(events);
    }
    !(cut || client_gone)
}

/// Results the harness sent back: each fills its call's record once, and
/// the record is posted again under the call's id (case 35).
fn record_results(inner: &Inner, chat: &Chat, api: Api, info: &apis::RequestInfo, content_kept: bool) {
    let mut events = Vec::new();
    let at = now_ms();
    let Ok(mut chats) = inner.chats.lock() else { return };
    let Some(calls) = chats.get_mut(&chat.id) else {
        if !info.results.is_empty() {
            inner.counters.results_unmatched.fetch_add(info.results.len() as u64, Ordering::Relaxed);
        }
        return;
    };
    // Gemini's model sends no ids, and Gemini CLI 0.66.0 gives each call one
    // of its own in its history (`run_shell_command_<ms>_0`, run 4 Nov), so
    // an id the tap never saw falls back to the name: the history repeats
    // every result in order, so the k-th result named N in the request is
    // the k-th call named N in the chat.
    let mut nth: HashMap<String, usize> = HashMap::new();
    for r in &info.results {
        let by_name = |nth: &mut HashMap<String, usize>| {
            r.name.as_ref().and_then(|name| {
                let k = nth.entry(name.clone()).or_insert(0);
                let found = calls
                    .order
                    .iter()
                    .filter(|id| calls.calls.get(*id).is_some_and(|c| c.api == api && &c.tool == name))
                    .nth(*k)
                    .cloned();
                *k += 1;
                found
            })
        };
        let id = match &r.call_id {
            Some(id) if calls.calls.contains_key(id) => {
                if r.name.is_some() {
                    let _ = by_name(&mut nth);
                }
                Some(id.clone())
            }
            _ => by_name(&mut nth),
        };
        let Some(rec) = id.and_then(|id| calls.calls.get_mut(&id)) else {
            inner.counters.results_unmatched.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        if rec.result.is_some() {
            continue;
        }
        rec.result = Some((digest_result(&r.value), r.is_error));
        rec.content_kept = rec.content_kept || content_kept;
        events.push(rec.event(&chat.id, &chat.harness, at));
    }
    drop(chats);
    if !events.is_empty() {
        (inner.sink)(events);
    }
}
