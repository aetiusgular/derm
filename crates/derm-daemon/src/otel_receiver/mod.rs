//! Harness telemetry: a loopback OTLP receiver. Copied from the fork
//! (`otel_receiver.rs` at `159ef3e`, wave 3 lane A) and taken out of Tauri
//! by tk lane B: the sink is the daemon's ingest instead of a window event,
//! `apply_export` replaces `apply_to_child` for a harness `derm run` starts,
//! and the daemon's `token.mint` mints chat tokens here.
//!
//! Claude Code, Codex and Pi (lane A's emitter) export their OpenTelemetry
//! log events (tool calls, approvals, model requests) here. Each record
//! becomes an activity event, which the daemon writes to the log and
//! streams to `tail`.
//!
//! - Listens on 127.0.0.1 only, on a free port, started on first use. It
//!   makes no outbound call of any kind.
//! - Each chat gets its own random token, never in an argument
//!   (`harness_env`): Claude Code reads it from an `otelHeadersHelper`
//!   script in a private folder, Codex from its environment, which its
//!   shell commands do not inherit. A request without a known token is
//!   refused before any of its body is read. The token names the chat, so a
//!   process can only post into the chat whose token it holds.
//! - Requests whose `Host` is not this listener are refused (DNS rebinding),
//!   and a browser's preflight gets no CORS answer.
//! - Bounded: 16 connections, a 16 KiB head, a 4 MiB body, deadlines re-armed
//!   before every read, a request rate cap, 2,000 records per request.
//! - Off in Settings means no harness is pointed here and anything still
//!   arriving is dropped.
//! - Two more routes, for a gate inside an sbx VM, which cannot see the
//!   daemon's socket (lane T's P4-R1, integration w5 continue):
//!   `POST /derm/v1/event` and `POST /derm/v1/approve`, a JSON body holding
//!   the socket op's one field (`event` or `request`), the same chat token,
//!   and the socket's chat-scope rules, applied by the daemon (`ops`). A
//!   reply is the socket's reply line as the body. sbx's proxy turns
//!   `host.docker.internal` into `localhost` (Docker's "Develop and test
//!   locally" page), and these routes also take `Host: host.docker.internal:
//!   <port>`, which a client that bypasses the forward proxy may send.

#[path = "decode.rs"]
pub mod decode;
#[path = "harness_env.rs"]
pub mod harness_env;
#[path = "normalize.rs"]
pub mod normalize;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::activity::types::ActivityEvent;

const MAX_HEAD_BYTES: usize = 16 * 1024;
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Connections open at once, before a token is known. A chat's own share of
/// them is [`MAX_OPEN_PER_CHAT`] (security finding W5C-S4, integration w5
/// continue: 16 slow bodies from one chat's token held them all).
const MAX_CONNECTIONS: usize = 64;
/// Requests one chat's token may have open at once, counted from its head.
const MAX_OPEN_PER_CHAT: usize = 8;
const HEAD_DEADLINE: Duration = Duration::from_secs(10);
const BODY_DEADLINE: Duration = Duration::from_secs(30);
/// Chats with a token. The oldest gives way; its harness's next start gets a
/// new one.
const MAX_TOKENS: usize = 512;
/// Chats the window may name in one configure call.
const MAX_CHATS: usize = 5000;
/// A derm route's body: the socket's line cap (`daemon-protocol.md`, 2).
pub const MAX_DERM_BODY_BYTES: usize = 1024 * 1024;
/// `approve` requests waiting at once over HTTP; each holds a connection
/// until it is answered, so they may not take every slot.
const MAX_APPROVING: usize = 16;
/// Of those, one chat's (W5C-S3, integration w5 continue: one chat held all
/// four the cap allowed before, and every other chat's ask got 503).
const MAX_APPROVING_PER_CHAT: usize = 2;
/// How often a waiting approve looks whether its client has hung up; one
/// that has lets go of its slot (W5C-S3). The daemon's wait uses it.
pub(crate) const GONE_CHECK: Duration = Duration::from_millis(250);
/// Requests per second over all chats, with this many in a burst.
const RATE_PER_SEC: f64 = 40.0;
const RATE_BURST: f64 = 200.0;
/// One chat's own bucket inside that (W5C-S4): a chat spends at most this,
/// so it cannot spend every other chat's share.
const RATE_PER_CHAT_SEC: f64 = 10.0;
const RATE_BURST_PER_CHAT: f64 = 50.0;

/// What the window set: the switch, the prompt text switch, and which
/// session ids are chats (helpers and probes are not).
#[derive(Default)]
pub struct Settings {
    pub enabled: bool,
    pub log_prompts: bool,
    pub chats: HashSet<String>,
}

#[derive(Clone)]
struct Holder {
    chat_id: String,
    harness: &'static str,
}

/// Where each request's batch of normalized events goes.
pub type Sink = Arc<dyn Fn(Vec<ActivityEvent>) + Send + Sync>;

/// A chat's socket op, arrived over HTTP (P4-R1): the one field of the
/// socket's line, not yet checked.
pub enum ChatOp {
    Event(serde_json::Value),
    Approve(serde_json::Value),
}

/// The daemon's answer to a `ChatOp` for the token's chat and harness: the
/// socket's reply line, as JSON. The last argument says whether the client
/// has hung up; a waiting approve asks it now and then and stops waiting
/// when it has (W5C-S3).
pub type Ops =
    Arc<dyn Fn(&str, &'static str, ChatOp, &dyn Fn() -> bool) -> serde_json::Value + Send + Sync>;

/// Per chat: its open requests, its waiting approves, and its rate bucket.
#[derive(Default)]
struct PerChat {
    open: HashMap<String, usize>,
    approving: HashMap<String, usize>,
    rate: HashMap<String, (f64, Instant)>,
}

#[derive(Clone, Copy)]
enum Count {
    Open,
    Approving,
}

/// A chat's place in one of its counts, given back when dropped.
struct Held<'a> {
    receiver: &'a Receiver,
    chat: String,
    count: Count,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Ok(mut per) = self.receiver.per_chat.lock() {
            let map = match self.count {
                Count::Open => &mut per.open,
                Count::Approving => &mut per.approving,
            };
            if let Some(n) = map.get_mut(&self.chat) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&self.chat);
                }
            }
        }
    }
}

/// Where a chat's prompt and reply text goes while the content switch is on
/// (`contracts/events.md` section 5, case 85 as changed): the daemon reads
/// `~/.derm/settings.json` per request, as the tap does. `None`: content is
/// off, and the text is dropped.
pub type ContentFor = Arc<dyn Fn(&str) -> Option<derm_tap::content::Target> + Send + Sync>;

/// One receiver: its port, its tokens, its counters.
pub struct Receiver {
    port: u16,
    /// sha256(token) to its chat. Looked up by hash, so a lookup's timing
    /// says nothing about the token itself.
    holders: Mutex<HashMap<[u8; 32], Holder>>,
    /// (chat, harness) to token, oldest first.
    tokens: Mutex<VecDeque<((String, &'static str), String)>>,
    settings: Arc<Mutex<Settings>>,
    sink: Sink,
    open: AtomicUsize,
    rate: Mutex<(f64, Instant)>,
    /// The daemon's ops for the derm routes; until set, they answer 503.
    ops: OnceLock<Ops>,
    /// Content capture for prompt and reply text; unset, it is dropped.
    content: OnceLock<ContentFor>,
    approving: AtomicUsize,
    per_chat: Mutex<PerChat>,
    pub counters: Counters,
}

#[derive(Default)]
pub struct Counters {
    pub requests: AtomicU64,
    pub events: AtomicU64,
    pub refused_token: AtomicU64,
    pub refused_other: AtomicU64,
    pub dropped_records: AtomicU64,
}

static SETTINGS: OnceLock<Arc<Mutex<Settings>>> = OnceLock::new();
static RECEIVER: OnceLock<Result<Arc<Receiver>, String>> = OnceLock::new();

fn settings() -> Arc<Mutex<Settings>> {
    SETTINGS
        .get_or_init(|| Arc::new(Mutex::new(Settings::default())))
        .clone()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl Receiver {
    /// Binds 127.0.0.1 on a free port and serves on its own thread.
    pub fn start(settings: Arc<Mutex<Settings>>, sink: Sink) -> Result<Arc<Self>, String> {
        Self::start_on(settings, sink, None)
    }

    /// As `start`, trying `preferred` first: the port the daemon had before
    /// a restart, so a running harness's `DERM_OTLP_ENDPOINT` still reaches it
    /// (integration w2, box finding BX8). Any port when that one is taken.
    pub fn start_on(
        settings: Arc<Mutex<Settings>>,
        sink: Sink,
        preferred: Option<u16>,
    ) -> Result<Arc<Self>, String> {
        let listener = preferred
            .filter(|p| *p != 0)
            .and_then(|p| TcpListener::bind(("127.0.0.1", p)).ok())
            .map_or_else(|| TcpListener::bind(("127.0.0.1", 0)), Ok)
            .map_err(|e| format!("telemetry receiver could not listen: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("telemetry receiver has no port: {e}"))?
            .port();
        let receiver = Arc::new(Self {
            port,
            holders: Mutex::new(HashMap::new()),
            tokens: Mutex::new(VecDeque::new()),
            settings,
            sink,
            open: AtomicUsize::new(0),
            rate: Mutex::new((RATE_BURST, Instant::now())),
            ops: OnceLock::new(),
            content: OnceLock::new(),
            approving: AtomicUsize::new(0),
            per_chat: Mutex::new(PerChat::default()),
            counters: Counters::default(),
        });
        let serving = receiver.clone();
        std::thread::Builder::new()
            .name("otel-receiver".into())
            .spawn(move || serving.serve(listener))
            .map_err(|e| format!("telemetry receiver could not start: {e}"))?;
        Ok(receiver)
    }

    #[cfg(test)]
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The token for a chat's harness: the same one across restarts, while
    /// it is among the newest `MAX_TOKENS`.
    pub fn token_for(&self, chat_id: &str, harness: &'static str) -> Option<String> {
        let mut tokens = self.tokens.lock().ok()?;
        let mut holders = self.holders.lock().ok()?;
        let key = (chat_id.to_string(), harness);
        if let Some((_, token)) = tokens.iter().find(|(k, _)| *k == key) {
            return Some(token.clone());
        }
        while tokens.len() >= MAX_TOKENS {
            if let Some((_, old)) = tokens.pop_front() {
                holders.remove(&hash(&old));
            }
        }
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        holders.insert(
            hash(&token),
            Holder {
                chat_id: chat_id.to_string(),
                harness,
            },
        );
        tokens.push_back((key, token.clone()));
        Some(token)
    }

    fn holder(&self, token: &str) -> Option<Holder> {
        self.holders.lock().ok()?.get(&hash(token)).cloned()
    }

    /// A fresh token for a chat's harness (the daemon's `token.mint`). Unlike
    /// `token_for` it never hands back an earlier one: each `derm run` gets its
    /// own. The oldest of the newest `MAX_TOKENS` gives way. `harness` must
    /// be a known harness id (`harness_env::harness_id`).
    pub fn mint(&self, chat_id: &str, harness: &'static str) -> Option<String> {
        let mut tokens = self.tokens.lock().ok()?;
        let mut holders = self.holders.lock().ok()?;
        while tokens.len() >= MAX_TOKENS {
            if let Some((_, old)) = tokens.pop_front() {
                holders.remove(&hash(&old));
            }
        }
        let token = derm_core::token::mint().ok()?;
        holders.insert(
            hash(&token),
            Holder {
                chat_id: chat_id.to_string(),
                harness,
            },
        );
        tokens.push_back(((chat_id.to_string(), harness), token.clone()));
        Some(token)
    }

    /// Drops every token minted for `chat_id` (the daemon calls it at the
    /// chat's `run.stop`). A later hello or OTLP post with one of them is
    /// refused. Returns how many were dropped.
    pub fn revoke_chat(&self, chat_id: &str) -> usize {
        let (Ok(mut tokens), Ok(mut holders)) = (self.tokens.lock(), self.holders.lock()) else {
            return 0;
        };
        tokens.retain(|((chat, _), _)| chat != chat_id);
        // By chat, not by the plaintext list: a token restored after a
        // restart has only its hash here (BX8).
        let before = holders.len();
        holders.retain(|_, h| h.chat_id != chat_id);
        before - holders.len()
    }

    /// Every live token's hash with its chat and harness, for the daemon's
    /// state file (BX8). Hashes only: a token itself is never written.
    pub fn holders_snapshot(&self) -> Vec<([u8; 32], String, &'static str)> {
        self.holders
            .lock()
            .map(|h| {
                h.iter()
                    .map(|(k, v)| (*k, v.chat_id.clone(), v.harness))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Takes back a token by its hash after a restart (BX8). At most
    /// `MAX_TOKENS` are held; past that the restore is refused.
    pub fn restore(&self, token_sha256: [u8; 32], chat_id: &str, harness: &'static str) -> bool {
        let Ok(mut holders) = self.holders.lock() else {
            return false;
        };
        if holders.len() >= MAX_TOKENS {
            return false;
        }
        holders.insert(
            token_sha256,
            Holder {
                chat_id: chat_id.to_string(),
                harness,
            },
        );
        true
    }

    /// The SHA-256 the holders are keyed by.
    pub fn token_hash(token: &str) -> [u8; 32] {
        hash(token)
    }

    /// The daemon's ops for the derm routes (P4-R1). Set once.
    pub fn set_ops(&self, ops: Ops) {
        let _ = self.ops.set(ops);
    }

    /// Content capture for prompt and reply text (lane S's request 3's
    /// rest). Set once.
    pub fn set_content(&self, content: ContentFor) {
        let _ = self.content.set(content);
    }

    /// The chat and harness a token was minted for, by its hash.
    pub fn holder_of(&self, token: &str) -> Option<(String, &'static str)> {
        self.holder(token).map(|h| (h.chat_id, h.harness))
    }

    /// One request from `chat`: its own bucket first, then everyone's. A
    /// request the chat's bucket refuses spends nothing of everyone's
    /// (W5C-S4).
    fn take_rate(&self, chat: &str) -> bool {
        let now = Instant::now();
        let fill = |b: &mut (f64, Instant), per_sec: f64, burst: f64| {
            let refill = now.saturating_duration_since(b.1).as_secs_f64() * per_sec;
            b.0 = (b.0 + refill).min(burst);
            b.1 = now;
        };
        let Ok(mut per) = self.per_chat.lock() else {
            return false;
        };
        if !per.rate.contains_key(chat) && per.rate.len() >= MAX_TOKENS {
            // Buckets that are full again say nothing; drop them first.
            per.rate.retain(|_, b| {
                let refill = now.saturating_duration_since(b.1).as_secs_f64() * RATE_PER_CHAT_SEC;
                b.0 + refill < RATE_BURST_PER_CHAT
            });
            if per.rate.len() >= MAX_TOKENS {
                return false;
            }
        }
        let mine = per
            .rate
            .entry(chat.to_string())
            .or_insert((RATE_BURST_PER_CHAT, now));
        fill(mine, RATE_PER_CHAT_SEC, RATE_BURST_PER_CHAT);
        if mine.0 < 1.0 {
            return false;
        }
        let Ok(mut all) = self.rate.lock() else {
            return false;
        };
        fill(&mut all, RATE_PER_SEC, RATE_BURST);
        if all.0 < 1.0 {
            return false;
        }
        all.0 -= 1.0;
        mine.0 -= 1.0;
        true
    }

    /// A place in one of `chat`'s counts, or none when it holds `cap`.
    fn hold(&self, chat: &str, count: Count, cap: usize) -> Option<Held<'_>> {
        let mut per = self.per_chat.lock().ok()?;
        let map = match count {
            Count::Open => &mut per.open,
            Count::Approving => &mut per.approving,
        };
        let n = map.entry(chat.to_string()).or_insert(0);
        if *n >= cap {
            if *n == 0 {
                map.remove(chat);
            }
            return None;
        }
        *n += 1;
        Some(Held {
            receiver: self,
            chat: chat.to_string(),
            count,
        })
    }

    fn serve(self: Arc<Self>, listener: TcpListener) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            if !stream.peer_addr().is_ok_and(|a| a.ip().is_loopback()) {
                continue;
            }
            if self.open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                self.open.fetch_sub(1, Ordering::SeqCst);
                let mut stream = stream;
                let _ = respond(&mut stream, 503, None);
                // On the accept thread: drain only what is already here.
                close_without_waiting(&stream);
                continue;
            }
            let slot = OpenSlot(self.clone());
            let receiver = self.clone();
            let _ = std::thread::Builder::new()
                .name("otel-receiver-conn".into())
                .spawn(move || {
                    let _slot = slot;
                    let mut stream = stream;
                    let status = receiver.handle(&stream);
                    let (code, kind) = match status {
                        Ok(answer) => (200, Some(answer)),
                        Err(code) => {
                            if code == 401 {
                                receiver
                                    .counters
                                    .refused_token
                                    .fetch_add(1, Ordering::Relaxed);
                            } else {
                                receiver
                                    .counters
                                    .refused_other
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            (code, None)
                        }
                    };
                    let _ = respond(&mut stream, code, kind);
                    if code != 200 {
                        close_gently(&stream);
                    }
                });
        }
    }

    /// One request. `Ok` holds what to answer with.
    fn handle(&self, stream: &TcpStream) -> Result<Answer, u16> {
        self.counters.requests.fetch_add(1, Ordering::Relaxed);
        let mut reader = BufReader::new(Armed::new(stream, Instant::now() + HEAD_DEADLINE));
        let head = read_head(&mut reader)?;
        let path = head.target.split('?').next().unwrap_or("");
        let signal = match path {
            "/v1/logs" => Signal::Logs,
            "/v1/metrics" | "/v1/traces" => Signal::Other,
            "/derm/v1/event" => Signal::DermEvent,
            "/derm/v1/approve" => Signal::DermApprove,
            _ => Signal::Unknown,
        };
        let derm = matches!(signal, Signal::DermEvent | Signal::DermApprove);
        let host_ok = head.header("host").is_some_and(|host| {
            host == format!("127.0.0.1:{}", self.port)
                || host.eq_ignore_ascii_case(&format!("localhost:{}", self.port))
                || (derm
                    && host.eq_ignore_ascii_case(&format!("host.docker.internal:{}", self.port)))
        });
        if !host_ok {
            return Err(403);
        }
        if head.method != "POST" {
            return Err(405);
        }
        if signal == Signal::Unknown {
            return Err(404);
        }
        // The token, before any of the body is read.
        let holder = token_from(&head)
            .and_then(|t| self.holder(&t))
            .ok_or(401u16)?;
        // The chat's share of the open requests (W5C-S4), held to the end.
        let _open = self
            .hold(&holder.chat_id, Count::Open, MAX_OPEN_PER_CHAT)
            .ok_or(503u16)?;
        if !self.take_rate(&holder.chat_id) {
            return Err(429);
        }
        if head
            .header("content-encoding")
            .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
        {
            return Err(415);
        }
        let kind = match head.header("content-type").map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        }) {
            Some(t) if t == "application/json" => BodyKind::Json,
            Some(t) if t == "application/x-protobuf" || t == "application/protobuf" => {
                BodyKind::Protobuf
            }
            _ => return Err(415),
        };
        if derm {
            if kind != BodyKind::Json {
                return Err(415);
            }
            let body = read_body(
                &mut reader,
                &head,
                Instant::now() + BODY_DEADLINE,
                MAX_DERM_BODY_BYTES,
            )?;
            return self
                .derm_op(signal, &body, &holder, &|| peer_gone(stream))
                .map(Answer::Json);
        }
        let body = read_body(
            &mut reader,
            &head,
            Instant::now() + BODY_DEADLINE,
            MAX_BODY_BYTES,
        )?;
        if signal == Signal::Other {
            return Ok(Answer::Otlp(kind));
        }
        let (enabled, log_prompts) = match self.settings.lock() {
            Ok(s) => (s.enabled, s.log_prompts),
            Err(_) => (false, false),
        };
        let decoded = match kind {
            BodyKind::Json => decode::decode_json(&body),
            BodyKind::Protobuf => decode::decode_protobuf(&body),
        }
        .map_err(|_| 400u16)?;
        self.counters
            .dropped_records
            .fetch_add(decoded.dropped as u64, Ordering::Relaxed);
        if !enabled {
            return Ok(Answer::Otlp(kind));
        }
        let received = now_ms();
        // The content switch decides once per request, as the tap's does.
        let target = self.content.get().and_then(|c| c(&holder.chat_id));
        let events: Vec<ActivityEvent> = decoded
            .logs
            .iter()
            .filter_map(|log| {
                let mut event = normalize::to_activity(
                    log,
                    &holder.chat_id,
                    holder.harness,
                    log_prompts,
                    received,
                )?;
                if let Some(t) = &target {
                    keep_content(t, &holder.chat_id, log, &mut event, received);
                }
                Some(event)
            })
            .collect();
        if !events.is_empty() {
            self.counters
                .events
                .fetch_add(events.len() as u64, Ordering::Relaxed);
            (self.sink)(events);
        }
        Ok(Answer::Otlp(kind))
    }

    /// A derm route's body, `{"event": {...}}` or `{"request": {...}}` and
    /// nothing else (the socket refuses unknown fields too), handed to the
    /// daemon's ops for the token's chat. The reply line is the body; a
    /// refusal by the daemon is still a 200 with `ok: false`, as on the
    /// socket.
    fn derm_op(
        &self,
        signal: Signal,
        body: &[u8],
        holder: &Holder,
        gone: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, u16> {
        let ops = self.ops.get().ok_or(503u16)?;
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| 400u16)?;
        let serde_json::Value::Object(mut map) = value else {
            return Err(400);
        };
        let field = if signal == Signal::DermEvent {
            "event"
        } else {
            "request"
        };
        if map.len() != 1 {
            return Err(400);
        }
        let inner = map.remove(field).ok_or(400u16)?;
        let reply = if signal == Signal::DermEvent {
            ops(
                &holder.chat_id,
                holder.harness,
                ChatOp::Event(inner),
                &|| false,
            )
        } else {
            let _mine = self
                .hold(&holder.chat_id, Count::Approving, MAX_APPROVING_PER_CHAT)
                .ok_or(503u16)?;
            if self.approving.fetch_add(1, Ordering::SeqCst) >= MAX_APPROVING {
                self.approving.fetch_sub(1, Ordering::SeqCst);
                return Err(503);
            }
            struct Done<'a>(&'a AtomicUsize);
            impl Drop for Done<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _done = Done(&self.approving);
            ops(
                &holder.chat_id,
                holder.harness,
                ChatOp::Approve(inner),
                gone,
            )
        };
        serde_json::to_vec(&reply).map_err(|_| 500u16)
    }
}

/// Whether the client of a request still being answered has hung up: a
/// peek that reads the end of the stream. Bytes waiting (a pipelined
/// request) or nothing yet both mean it is still there. Only the thread
/// answering the request calls it, so switching the stream to non-blocking
/// for the peek races nothing.
fn peer_gone(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let mut byte = [0u8; 1];
    let gone = match stream.peek(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ),
    };
    let _ = stream.set_nonblocking(false);
    gone
}

/// A redaction mark a harness sends in place of text (`normalize`'s note).
fn is_mark(v: &serde_json::Value) -> bool {
    v.as_str()
        .is_some_and(|t| matches!(t.trim(), "<REDACTED>" | "[REDACTED]" | ""))
}

/// Writes a record's prompt and reply text to content files (the part
/// `request` for a prompt, `response` for a reply), as the tap keeps bodies,
/// and marks the record `contentKept: true` with the files' names. Text a
/// record already holds (only in tests, `log_prompts`) stays as it is. A
/// file that cannot be written keeps nothing and says so in the record.
pub(crate) fn keep_content(
    target: &derm_tap::content::Target,
    chat: &str,
    log: &decode::OtelLog,
    event: &mut ActivityEvent,
    at: i64,
) {
    let mut parts: [(&str, serde_json::Map<String, serde_json::Value>); 2] = [
        ("request", serde_json::Map::new()),
        ("response", serde_json::Map::new()),
    ];
    for (key, value) in &log.attributes {
        if !normalize::is_prompt_text(key) || is_mark(value) {
            continue;
        }
        let i = usize::from(normalize::is_reply_text(key));
        parts[i].1.insert(key.clone(), value.clone());
    }
    let id: String = event
        .id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let mut kept = Vec::new();
    let mut failed = false;
    for (part, fields) in parts {
        if fields.is_empty() {
            continue;
        }
        match derm_tap::content::open(target, chat, at, &id, part) {
            Ok(mut f) => {
                f.append(serde_json::Value::Object(fields).to_string().as_bytes());
                if f.failed {
                    failed = true;
                } else if let Some(name) = f.path.file_name() {
                    kept.push(serde_json::Value::String(
                        name.to_string_lossy().into_owned(),
                    ));
                }
            }
            Err(_) => failed = true,
        }
    }
    if let serde_json::Value::Object(detail) = &mut event.detail {
        if !kept.is_empty() {
            detail.insert("contentKept".into(), serde_json::Value::Bool(true));
            detail.insert("contentFiles".into(), serde_json::Value::Array(kept));
        }
        if failed {
            detail.insert("contentFailed".into(), serde_json::Value::Bool(true));
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Signal {
    Logs,
    Other,
    DermEvent,
    DermApprove,
    Unknown,
}

/// What a request is answered with: an OTLP reply of its kind, or a derm
/// route's JSON body.
enum Answer {
    Otlp(BodyKind),
    Json(Vec<u8>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Json,
    Protobuf,
}

struct OpenSlot(Arc<Receiver>);

impl Drop for OpenSlot {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

fn token_from(head: &Head) -> Option<String> {
    if let Some(t) = head.header(harness_env::TOKEN_HEADER) {
        return Some(t.trim().to_string()).filter(|t| !t.is_empty());
    }
    let auth = head.header("authorization")?;
    let (scheme, token) = auth.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// The whole reply in one buffer and one `write_all`: written in pieces,
/// a close right after can leave the client holding only the first of them
/// (Mac test 0.5).
fn respond<W: Write>(stream: &mut W, status: u16, answer: Option<Answer>) -> std::io::Result<()> {
    let json;
    let (content_type, body): (&str, &[u8]) = match answer {
        Some(Answer::Otlp(BodyKind::Protobuf)) => ("application/x-protobuf", b""),
        Some(Answer::Json(bytes)) => {
            json = bytes;
            ("application/json", json.as_slice())
        }
        _ => ("application/json", b"{}"),
    };
    let mut reply = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reason(status),
        body.len()
    )
    .into_bytes();
    reply.extend_from_slice(body);
    stream.write_all(&reply)?;
    stream.flush()
}

const LINGER_DEADLINE: Duration = Duration::from_secs(1);
const LINGER_BYTES: usize = 8 * 1024;

/// `close_gently` for the accept thread, which must not wait: whatever
/// input has already arrived is read, then the socket goes.
fn close_without_waiting(stream: &TcpStream) {
    if stream.shutdown(std::net::Shutdown::Write).is_err() || stream.set_nonblocking(true).is_err()
    {
        return;
    }
    let mut buf = [0u8; 1024];
    let mut drained = 0;
    let mut stream = stream;
    while drained < LINGER_BYTES {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

/// After an error reply, with the request maybe not all read: close the
/// write side, then read what the client still sends, for a short while,
/// until it closes. Closing at once with input unread resets the connection,
/// and the reset can cost the client the reply (RFC 9112 section 9.6).
/// `set_linger` is not stable, so this is done by hand.
fn close_gently(stream: &TcpStream) {
    if stream.shutdown(std::net::Shutdown::Write).is_err() {
        return;
    }
    let deadline = Instant::now() + LINGER_DEADLINE;
    let mut drained = 0;
    let mut buf = [0u8; 1024];
    let mut reader = Armed::new(stream, deadline);
    while drained < LINGER_BYTES {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

// ---------------------------------------------------------------- HTTP

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The socket with a deadline re-armed before every single read, so a
/// client sending a byte at a time cannot hold a slot past the deadline.
struct Armed<'a> {
    stream: &'a TcpStream,
    deadline: std::cell::Cell<Instant>,
}

impl<'a> Armed<'a> {
    fn new(stream: &'a TcpStream, deadline: Instant) -> Self {
        Self {
            stream,
            deadline: std::cell::Cell::new(deadline),
        }
    }
}

impl Read for Armed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self
            .deadline
            .get()
            .saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        let mut stream = self.stream;
        stream.read(buf)
    }
}

type Reader<'a> = BufReader<Armed<'a>>;

/// 408 when the read timed out, by the error's kind: a socket timeout is
/// `WouldBlock` or `TimedOut`, and `Armed` answers `TimedOut` itself when no
/// time is left. Re-reading the clock here could call a timeout that fired
/// a moment early a bad request. Anything else is a bad request.
fn read_failure(error: &std::io::Error) -> u16 {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => 408,
        _ => 400,
    }
}

fn read_head(reader: &mut Reader) -> Result<Head, u16> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let room = (MAX_HEAD_BYTES + 1).saturating_sub(head.len()) as u64;
        let n = reader
            .by_ref()
            .take(room)
            .read_until(b'\n', &mut line)
            .map_err(|e| read_failure(&e))?;
        if n == 0 {
            return Err(400);
        }
        head.extend_from_slice(&line);
        if head.len() > MAX_HEAD_BYTES {
            return Err(413);
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }
    let head = String::from_utf8(head).map_err(|_| 400u16)?;
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let target = first.next().unwrap_or("").to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok(Head {
        method,
        target,
        headers,
    })
}

fn read_body(
    reader: &mut Reader,
    head: &Head,
    deadline: Instant,
    max: usize,
) -> Result<Vec<u8>, u16> {
    reader.get_ref().deadline.set(deadline);
    let chunked = head
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size_line = String::new();
            reader
                .by_ref()
                .take(256)
                .read_line(&mut size_line)
                .map_err(|e| read_failure(&e))?;
            let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| 400u16)?;
            let total = body.len().checked_add(size).ok_or(413u16)?;
            if total > max {
                return Err(413);
            }
            let mut chunk = vec![0; size.checked_add(2).ok_or(413u16)?];
            reader
                .read_exact(&mut chunk)
                .map_err(|e| read_failure(&e))?;
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else {
        let length: usize = head
            .header("content-length")
            .ok_or(411u16)?
            .parse()
            .map_err(|_| 400u16)?;
        if length > max {
            return Err(413);
        }
        reader
            .by_ref()
            .take(length as u64)
            .read_to_end(&mut body)
            .map_err(|e| read_failure(&e))?;
        if body.len() < length {
            return Err(400);
        }
    }
    Ok(body)
}

// ---------------------------------------------------------------- the app

/// Starts the process's receiver once, with the switches set by
/// `harness_telemetry_configure`, sending each batch to `sink`. A second call
/// returns the first receiver and ignores its `sink`.
pub fn start_with_sink(sink: Sink) -> Result<Arc<Receiver>, String> {
    RECEIVER
        .get_or_init(|| Receiver::start(settings(), sink))
        .clone()
}

/// The receiver `start_with_sink` started, if it did.
pub fn receiver() -> Option<Arc<Receiver>> {
    RECEIVER.get().and_then(|r| r.as_ref().ok()).cloned()
}

/// The effective `CODEX_HOME` for a spawn: what the command sets, else the
/// app's environment, else `~/.codex`.
fn codex_home(cmd: &Command) -> Option<std::path::PathBuf> {
    let set = cmd
        .get_envs()
        .find(|(k, _)| *k == "CODEX_HOME")
        .and_then(|(_, v)| v.map(std::path::PathBuf::from));
    set.or_else(|| std::env::var_os("CODEX_HOME").map(std::path::PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".codex")))
}

/// A variable as the child will see it: set on the command, else inherited.
fn child_var(cmd: &Command, name: &str) -> Option<String> {
    for (k, v) in cmd.get_envs() {
        if k == name {
            return v.map(|v| v.to_string_lossy().into_owned());
        }
    }
    std::env::var(name).ok()
}

/// What a process that starts a harness passes so the harness exports to
/// the daemon's receiver (lane D's `derm run`). The token comes from the
/// daemon's `token.mint`, the endpoint from `otlp.endpoint` beside its
/// socket.
pub struct Export<'a> {
    /// `claude-code` or `codex`. Pi exports through lane A's emitter, which
    /// reads `DERM_OTLP_ENDPOINT` and `DERM_CHAT_TOKEN` itself.
    pub harness: &'a str,
    pub endpoint: &'a str,
    pub token: &'a str,
    pub log_prompts: bool,
    /// A private folder for this run's `otelHeadersHelper` script. It is
    /// emptied and made again 0700, so it must be this run's alone, never a
    /// folder another run uses. `None` puts the token in the header variable.
    pub helper_dir: Option<&'a std::path::Path>,
}

/// What `apply_export` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// Claude Code points here; the helper script's path when one was made.
    Claude {
        helper: Option<std::path::PathBuf>,
    },
    Codex,
    /// Nothing changed, and why: the user already exports OTel, the endpoint
    /// is not loopback, or the harness has no OTel export here.
    StoodDown(&'static str),
}

/// True for `http://127.0.0.1:<port>` and nothing else: the receiver binds
/// only there, and an export anywhere else would leave the machine.
pub fn loopback_endpoint(endpoint: &str) -> bool {
    endpoint
        .strip_prefix("http://127.0.0.1:")
        .and_then(|port| port.parse::<u16>().ok())
        .is_some_and(|port| port != 0)
}

/// Points a Claude Code or Codex child at the receiver, or does nothing.
/// Never fails the start: whatever cannot be set leaves the harness without
/// telemetry (corner case 9). The token never goes in an argument. It stands
/// down when the user already exports OTel (the fork's
/// `harness_env.rs:40-60`).
pub fn apply_export(export: &Export, args: &[String], cmd: &mut Command) -> Applied {
    if !loopback_endpoint(export.endpoint) || !derm_core::token::well_formed(export.token) {
        return Applied::StoodDown("endpoint or token not usable");
    }
    if !matches!(export.harness, "claude-code" | "codex") {
        return Applied::StoodDown("no OTel export for this harness");
    }
    if harness_env::has_own_env_telemetry(&|name| child_var(cmd, name)) {
        return Applied::StoodDown("the user already exports OTel");
    }
    if export.harness == "codex" {
        let codex_config =
            codex_home(cmd).and_then(|home| std::fs::read_to_string(home.join("config.toml")).ok());
        if harness_env::has_own_codex_otel(codex_config.as_deref()) {
            return Applied::StoodDown("the user already exports OTel");
        }
        cmd.args(harness_env::codex_args(export.endpoint, export.log_prompts));
        cmd.args(harness_env::codex_shell_env_args(codex_config.as_deref()));
        for (k, v) in harness_env::codex_env(export.token) {
            cmd.env(k, v);
        }
        return Applied::Codex;
    }
    let (set, remove) = harness_env::claude_env(export.endpoint, export.log_prompts);
    for name in remove {
        cmd.env_remove(name);
    }
    for (k, v) in set {
        cmd.env(k, v);
    }
    // The token through `otelHeadersHelper`, as Claude Code's docs ask; the
    // header variable only where the script cannot be made.
    let helper = export
        .helper_dir
        .and_then(|dir| helper_in(dir, export.token));
    let settings = helper
        .as_ref()
        .and_then(|h| harness_env::settings_with_helper(args, &h.to_string_lossy()));
    match settings {
        Some(settings) => {
            cmd.env_remove("OTEL_EXPORTER_OTLP_HEADERS");
            cmd.args(["--settings", &settings]);
            Applied::Claude { helper }
        }
        None => {
            let (k, v) = harness_env::claude_header_var(export.token);
            cmd.env(k, v);
            Applied::Claude { helper: None }
        }
    }
}

/// This app run's helper scripts, by token hash. The folder is emptied on
/// first use, so a token from an earlier run is never left on disk past it.
/// The folder, once made, and each token's script.
#[derive(Default)]
struct Helpers {
    dir: Option<std::path::PathBuf>,
    scripts: HashMap<[u8; 32], std::path::PathBuf>,
}

static HELPERS: OnceLock<Mutex<Helpers>> = OnceLock::new();

/// The chat's `otelHeadersHelper` script in `dir`, written once per
/// process. The folder is emptied on first use, so a token from an earlier
/// run is never left on disk past it.
#[cfg(unix)]
fn helper_in(dir: &std::path::Path, token: &str) -> Option<std::path::PathBuf> {
    let helpers = HELPERS.get_or_init(Default::default);
    let mut helpers = helpers.lock().ok()?;
    if let Some(path) = helpers.scripts.get(&hash(token)) {
        return Some(path.clone());
    }
    if helpers.dir.as_deref() != Some(dir) {
        clear_helpers(&mut helpers);
        fresh_private_dir(dir).ok()?;
        helpers.dir = Some(dir.to_path_buf());
    }
    let path = write_helper(dir, token).ok()?;
    helpers.scripts.insert(hash(token), path.clone());
    Some(path)
}

#[cfg(not(unix))]
fn helper_in(_dir: &std::path::Path, _token: &str) -> Option<std::path::PathBuf> {
    None
}

/// Removes this process's helper folder. The caller runs it when its harness
/// exits (security review X12): the scripts print the chats' tokens, so none
/// outlives the run. The wipe at first use stays for a run that crashed.
pub fn remove_helpers() {
    if let Some(helpers) = HELPERS.get() {
        let mut helpers = match helpers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        clear_helpers(&mut helpers);
    }
}

/// Removes the folder (a link there is removed, never followed) and forgets
/// its scripts.
fn clear_helpers(helpers: &mut Helpers) {
    if let Some(dir) = helpers.dir.take() {
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {
                let _ = std::fs::remove_dir_all(&dir);
            }
            Ok(_) => {
                let _ = std::fs::remove_file(&dir);
            }
            Err(_) => {}
        }
    }
    helpers.scripts.clear();
}

/// Empties `dir` (a link there is removed, never followed) and makes it
/// again, 0700.
#[cfg(unix)]
fn fresh_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(dir)?,
        Ok(_) => std::fs::remove_file(dir)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

/// One chat's script in `dir`: a new file (never an existing one or a link),
/// 0700, named by a hash so the name says nothing of the token.
#[cfg(unix)]
fn write_helper(dir: &std::path::Path, token: &str) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    let name: String = hash(token)[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let path = dir.join(format!("{name}.sh"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(harness_env::headers_helper_script(token).as_bytes())?;
    file.sync_all()?;
    Ok(path)
}

/// The switch, the prompt text switch, and which sessions are chats. The
/// daemon turns the receiver on at start with `log_prompts` false: records
/// never keep prompt text; the content switch sends it to files instead
/// (`keep_content`).
pub fn harness_telemetry_configure(
    enabled: bool,
    log_prompts: bool,
    chats: Vec<String>,
) -> Result<(), String> {
    let chats: HashSet<String> = chats
        .into_iter()
        .filter(|c| !c.is_empty() && c.len() <= 200)
        .take(MAX_CHATS)
        .collect();
    let state = settings();
    let mut s = state.lock().map_err(|_| "telemetry settings lock")?;
    s.enabled = enabled;
    s.log_prompts = log_prompts;
    s.chats = chats;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryStatus {
    listening: bool,
    requests: u64,
    events: u64,
    refused_token: u64,
    refused_other: u64,
    dropped_records: u64,
}

/// For `derm status`: whether the receiver runs and what it has seen. No port
/// and no token.
pub fn harness_telemetry_status() -> TelemetryStatus {
    match RECEIVER.get() {
        Some(Ok(r)) => TelemetryStatus {
            listening: true,
            requests: r.counters.requests.load(Ordering::Relaxed),
            events: r.counters.events.load(Ordering::Relaxed),
            refused_token: r.counters.refused_token.load(Ordering::Relaxed),
            refused_other: r.counters.refused_other.load(Ordering::Relaxed),
            dropped_records: r.counters.dropped_records.load(Ordering::Relaxed),
        },
        _ => TelemetryStatus {
            listening: false,
            requests: 0,
            events: 0,
            refused_token: 0,
            refused_other: 0,
            dropped_records: 0,
        },
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
