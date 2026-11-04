//! The stdio proxy: newline-delimited JSON-RPC 2.0 between an ACP client
//! (Orca's structured chats, Zed) and the agent `derm run` started (ACP v1
//! `docs/protocol/v1/transports.mdx:16-21`: "Messages are delimited by
//! newlines (`\n`), and MUST NOT contain embedded newlines").
//!
//! Client to agent: every line passes through unchanged, answers to the
//! permission requests derm passed on included, but under srt or sbx the
//! client's `initialize` says it reads, writes and runs nothing (security
//! review L2).
//!
//! Agent to client, fail closed (security review L1, L17):
//! - a line derm cannot read as JSON, or longer than `MAX_LINE`, is dropped:
//!   a JavaScript client's `JSON.parse` reads lines serde_json refuses;
//! - what passes is the message derm judged, written again, so both ends
//!   read the same thing;
//! - only the methods ACP v1 (schema 1.29.1) has the agent send the client
//!   pass; any other request is refused and any other notification dropped;
//! - `session/request_permission` that derm answers itself (allow or deny):
//!   the answer goes back to the agent and the client never sees the request;
//! - `fs/read_text_file`, `fs/write_text_file` and `terminal/create`, which
//!   the client runs outside any boundary: refused under srt or sbx, and
//!   elsewhere when the policy denies them (or asks, in full access).
//!
//! Every `tool_call` and `tool_call_update` the agent sends, and every
//! answer derm gives, is posted to the daemon as an adapter record on the
//! chat token (`contracts/events.md` section 4), from a thread of its own so
//! the proxy never waits on the daemon. A call the agent never asks about
//! is recorded "logged, not gated".

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use derm_core::event::{Event, Source};
use serde_json::{json, Value};

use super::decide::{self, Answer, Ctx, ToolInfo};

/// derm's own error code for a request it refused (ACP v1 `error.mdx:37`:
/// implementation errors use codes outside -32768 to -32000 and -32899 to
/// -32800).
pub const REFUSED: i64 = -31001;

/// Calls remembered per process; past it the oldest half is dropped (a long
/// session cannot grow the map without bound).
const MAX_CALLS: usize = 20_000;

type Shared = Arc<Mutex<Option<Box<dyn Write + Send>>>>;

/// The poster thread's end of the log channel, with the socket and the
/// chat token it posts with.
pub type LogEnd = (Receiver<Event>, PathBuf, String);

/// What both directions share.
pub struct State {
    pub ctx: Ctx,
    calls: Mutex<Calls>,
    log: Mutex<Option<Sender<Event>>>,
}

#[derive(Default)]
struct Calls {
    info: HashMap<(String, String), ToolInfo>,
    order: Vec<(String, String)>,
    asked: HashSet<(String, String)>,
    /// A random part per call for its record's id (security review L16).
    nonce: HashMap<(String, String), String>,
}

impl State {
    pub fn new(ctx: Ctx, log: Option<Sender<Event>>) -> State {
        State {
            ctx,
            calls: Mutex::new(Calls::default()),
            log: Mutex::new(log),
        }
    }

    fn post(&self, e: Event) {
        if let Some(tx) = self.log.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            let _ = tx.send(e);
        }
    }

    /// Ends the poster thread once both directions are done.
    pub fn close_log(&self) {
        self.log.lock().unwrap_or_else(|p| p.into_inner()).take();
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The characters the daemon keeps in an id (`clean_id`; the hook core's
/// `decisionId`), cut to `max`.
fn id_part(s: &str, max: usize) -> String {
    let c: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_.:-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(max)
        .collect();
    if c.is_empty() {
        "unknown".into()
    } else {
        c
    }
}

/// `<harness>-<call>-decision-<128 random bits>`, as the hook core's
/// `decisionId` makes it: the agent holds the same chat token, so the id of
/// a decision must not be one it can post first (box test w2, BW2).
pub fn decision_id(harness: &str, call: &str) -> String {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let room = 128usize.saturating_sub(harness.len() + "--decision-".len() + nonce.len());
    format!("{harness}-{}-decision-{nonce}", id_part(call, room.max(1)))
}

fn adapter_event(st: &State, id: String, kind: &str, summary: String, detail: Value) -> Event {
    let mut detail = detail;
    detail["trust"] = json!("client");
    detail["via"] = json!("acp");
    Event {
        id,
        at: now_ms(),
        chat_id: st.ctx.chat.clone(),
        harness: st.ctx.harness.clone(),
        source: Source::Adapter,
        kind: kind.to_string(),
        summary: summary.chars().take(200).collect(),
        detail,
        pid: None,
        approval_id: None,
    }
}

fn write_line(to: &mut dyn Write, v: &Value) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(v).map_err(std::io::Error::other)?;
    line.push(b'\n');
    to.write_all(&line)?;
    to.flush()
}

fn to_agent(agent: &Shared, v: &Value) {
    if let Some(w) = agent.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
        let _ = write_line(w.as_mut(), v);
    }
}

/// The longest line derm reads (security review L17). A text file the agent
/// writes through the client is one line, so the cap is generous; past it
/// the line is dropped whole, never cut and passed on.
pub const MAX_LINE: usize = 32 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    Read,
    TooLong,
    Eof,
}

/// One newline-ended line into `buf`, holding at most `cap` bytes: a longer
/// one is read to its end and dropped (`TooLong`). A last line with no
/// newline counts as read.
pub fn read_line_capped(
    r: &mut impl BufRead,
    buf: &mut Vec<u8>,
    cap: usize,
) -> std::io::Result<Line> {
    buf.clear();
    let mut over = false;
    loop {
        let chunk = match r.fill_buf() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            return Ok(if over {
                Line::TooLong
            } else if buf.is_empty() {
                Line::Eof
            } else {
                Line::Read
            });
        }
        let (take, done) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if !over && buf.len() + take <= cap {
            buf.extend_from_slice(&chunk[..take]);
        } else {
            over = true;
            buf.clear();
        }
        r.consume(take);
        if done {
            return Ok(if over { Line::TooLong } else { Line::Read });
        }
    }
}

fn sha256_hex(v: Option<&Value>) -> Option<String> {
    use sha2::{Digest, Sha256};
    let v = v?;
    let text = serde_json::to_string(v).ok()?;
    Some(format!("{:x}", Sha256::digest(text.as_bytes())))
}

/// Client to agent: every line, unchanged, but `initialize` under srt or sbx
/// (`confined`). At the client's end of input the agent's stdin is closed,
/// so the agent sees it too.
pub fn client_to_agent(from_client: impl Read, agent: Shared, confined: bool) {
    let mut r = BufReader::new(from_client);
    let mut line = Vec::new();
    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let out = if confined {
                    no_client_tools(&line)
                } else {
                    None
                };
                let mut g = agent.lock().unwrap_or_else(|p| p.into_inner());
                let Some(w) = g.as_mut() else { break };
                let sent = match &out {
                    Some(v) => write_line(w.as_mut(), v),
                    None => w.write_all(&line).and_then(|_| w.flush()),
                };
                if sent.is_err() {
                    break;
                }
            }
        }
    }
    agent.lock().unwrap_or_else(|p| p.into_inner()).take();
}

/// The client's `initialize` (alone or in a batch) with `fs.readTextFile`,
/// `fs.writeTextFile` and `terminal` false: the agent then uses its own tools,
/// inside the boundary. `None` leaves the line as it is. The agent's requests
/// are refused anyway; this only tells it so up front.
fn no_client_tools(line: &[u8]) -> Option<Value> {
    fn fix(m: &mut Value) -> bool {
        if m.get("method").and_then(Value::as_str) != Some("initialize") {
            return false;
        }
        let Some(params) = m.get_mut("params").and_then(Value::as_object_mut) else {
            return false;
        };
        let caps = params
            .entry("clientCapabilities")
            .or_insert_with(|| json!({}));
        if !caps.is_object() {
            *caps = json!({});
        }
        caps["fs"] = json!({"readTextFile": false, "writeTextFile": false});
        caps["terminal"] = json!(false);
        true
    }
    let mut v: Value = serde_json::from_slice(line).ok()?;
    let changed = match &mut v {
        Value::Array(items) => items.iter_mut().fold(false, |c, m| fix(m) | c),
        m => fix(m),
    };
    changed.then_some(v)
}

/// Agent to client: what derm can read, written again; the requests derm
/// answers itself kept back. Records each tool call and each answer.
pub fn agent_to_client(
    from_agent: impl Read,
    to_client: &mut dyn Write,
    agent: Shared,
    st: &State,
) {
    let mut r = BufReader::new(from_agent);
    let mut line = Vec::new();
    loop {
        match read_line_capped(&mut r, &mut line, MAX_LINE) {
            Ok(Line::Eof) | Err(_) => break,
            Ok(Line::TooLong) => {
                eprintln!("derm acp: dropped a line from the agent longer than {MAX_LINE} bytes");
                continue;
            }
            Ok(Line::Read) => {}
        }
        let messages = match serde_json::from_slice::<Value>(&line) {
            // A batch: each message on its own (JSON-RPC 2.0 allows them;
            // ACP never shows one). What derm keeps goes on line by line.
            Ok(Value::Array(items)) => items,
            Ok(v) => vec![v],
            Err(e) => {
                eprintln!(
                    "derm acp: dropped a line from the agent that is not JSON derm reads ({e})"
                );
                continue;
            }
        };
        for m in messages {
            if let Some(out) = handle(m, &agent, st) {
                if write_line(to_client, &out).is_err() {
                    return;
                }
            }
        }
    }
}

/// The methods ACP v1 (schema 1.29.1, `CLIENT_METHOD_NAMES` in
/// `src/v1/client.rs:3945-3961` at `0e486bc`) has the agent send the client,
/// apart from the ones derm judges: they pass. `mcp/message` and
/// `auth/status_update` are unstable there and do not.
const PASSED: &[&str] = &[
    "session/update",
    "elicitation/create",
    "elicitation/complete",
];

/// A terminal's later calls: they act on a terminal derm let through.
const TERMINAL_LATER: &[&str] = &[
    "terminal/output",
    "terminal/release",
    "terminal/wait_for_exit",
    "terminal/kill",
];

/// One message from the agent. `Some(message)` passes it to the client;
/// `None` means derm answered it or dropped it.
fn handle(v: Value, agent: &Shared, st: &State) -> Option<Value> {
    let Some(method) = v.get("method").and_then(Value::as_str).map(str::to_string) else {
        // A response to the client's request.
        return Some(v);
    };
    let id = v.get("id").cloned().filter(|i| !i.is_null());
    let params = v.get("params").cloned().unwrap_or(Value::Null);
    let method = method.as_str();
    match method {
        "session/update" => {
            note_update(&params, st);
            Some(v)
        }
        m if PASSED.contains(&m) => Some(v),
        "session/request_permission" => match id {
            Some(id) => permission(v, id, &params, agent, st),
            None => None,
        },
        "fs/read_text_file" | "fs/write_text_file" | "terminal/create" => {
            let id = id?;
            let (tool, (refuse, reason)) = if st.ctx.confined {
                let why = "the client would run it outside the boundary (srt or sbx); the agent's own tools run inside".to_string();
                (client_tool(method), (Some(why.clone()), why))
            } else {
                match method {
                    "fs/read_text_file" => ("read", decide::client_read(&st.ctx, &params)),
                    "fs/write_text_file" => ("write", decide::client_write(&st.ctx, &params)),
                    _ => ("bash", decide::client_terminal(&st.ctx, &params)),
                }
            };
            st.post(adapter_event(
                st,
                decision_id(&st.ctx.harness, method),
                "approval",
                format!(
                    "{tool} {} ({method})",
                    if refuse.is_some() {
                        "deny"
                    } else {
                        "passed on"
                    }
                ),
                json!({
                    "tool": tool,
                    "decision": if refuse.is_some() { "deny" } else { "client" },
                    "reason": reason,
                    "request": method,
                }),
            ));
            match refuse {
                Some(why) => {
                    refuse_to(agent, id, &why);
                    None
                }
                None => Some(v),
            }
        }
        m if TERMINAL_LATER.contains(&m) => {
            if !st.ctx.confined {
                return Some(v);
            }
            if let Some(id) = id {
                refuse_to(
                    agent,
                    id,
                    "no terminal runs in the client inside a boundary",
                );
            }
            None
        }
        _ => {
            if let Some(id) = id {
                let why = format!("{} is not a method ACP v1 has an agent send its client; derm passes only those", id_part(method, 64));
                st.post(adapter_event(
                    st,
                    decision_id(&st.ctx.harness, "method"),
                    "approval",
                    "request deny (not an ACP method)".into(),
                    json!({"tool": "acp", "decision": "deny", "reason": why, "request": id_part(method, 64)}),
                ));
                refuse_to(agent, id, &why);
            }
            None
        }
    }
}

fn client_tool(method: &str) -> &'static str {
    match method {
        "fs/read_text_file" => "read",
        "fs/write_text_file" => "write",
        _ => "bash",
    }
}

fn refuse_to(agent: &Shared, id: Value, why: &str) {
    to_agent(
        agent,
        &json!({"jsonrpc": "2.0", "id": id, "error": {
            "code": REFUSED,
            "message": format!("derm: {why}"),
        }}),
    );
}

/// A `session/request_permission`: answered from the policy, or passed on.
fn permission(v: Value, id: Value, params: &Value, agent: &Shared, st: &State) -> Option<Value> {
    let session = params
        .get("sessionId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let tc = params.get("toolCall").cloned().unwrap_or(Value::Null);
    let call = tc
        .get("toolCallId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let info = {
        let mut calls = st.calls.lock().unwrap_or_else(|p| p.into_inner());
        let key = (session.clone(), call.clone());
        calls.asked.insert(key.clone());
        let mut info = calls.info.get(&key).cloned().unwrap_or_default();
        info.merge(&tc);
        info
    };
    let verdict = decide::permission(&st.ctx, &info);
    let options: Vec<Value> = params
        .get("options")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let ans = decide::answer(&verdict, &options);
    let (sent, outcome) = match &ans {
        Answer::Select { option_id, .. } => {
            (true, json!({"outcome": "selected", "optionId": option_id}))
        }
        Answer::Cancelled => (true, json!({"outcome": "cancelled"})),
        Answer::Forward => (false, Value::Null),
    };
    st.post(adapter_event(
        st,
        decision_id(&st.ctx.harness, &call),
        "approval",
        format!("{} {}", verdict.tool, verdict.decision),
        json!({
            "tool": verdict.tool,
            "decision": verdict.decision,
            "policyAction": format!("{:?}", verdict.action).to_lowercase(),
            "reason": verdict.reason,
            "named": verdict.named,
            "kind": info.kind,
            "toolUseId": call,
            "answeredBy": if sent { "derm" } else { "client" },
        }),
    ));
    if sent {
        to_agent(
            agent,
            &json!({"jsonrpc": "2.0", "id": id, "result": {"outcome": outcome}}),
        );
        None
    } else {
        Some(v)
    }
}

/// A `session/update` with a `tool_call` or `tool_call_update`: kept for the
/// permission request that may follow, and recorded.
fn note_update(params: &Value, st: &State) {
    let update = params.get("update").cloned().unwrap_or(Value::Null);
    let which = update
        .get("sessionUpdate")
        .and_then(Value::as_str)
        .unwrap_or("");
    if which != "tool_call" && which != "tool_call_update" {
        return;
    }
    let session = params
        .get("sessionId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let Some(call) = update.get("toolCallId").and_then(Value::as_str) else {
        return;
    };
    let key = (session.clone(), call.to_string());
    let (info, asked, nonce) = {
        let mut calls = st.calls.lock().unwrap_or_else(|p| p.into_inner());
        if !calls.info.contains_key(&key) {
            if calls.order.len() >= MAX_CALLS {
                let drop: Vec<_> = calls.order.drain(..MAX_CALLS / 2).collect();
                for k in drop {
                    calls.info.remove(&k);
                    calls.asked.remove(&k);
                    calls.nonce.remove(&k);
                }
            }
            calls.order.push(key.clone());
        }
        let nonce = calls
            .nonce
            .entry(key.clone())
            .or_insert_with(|| uuid::Uuid::new_v4().simple().to_string())
            .clone();
        let info = calls.info.entry(key.clone()).or_default();
        info.merge(&update);
        (info.clone(), calls.asked.contains(&key), nonce)
    };
    let status = update.get("status").and_then(Value::as_str);
    let label = info
        .name
        .clone()
        .or_else(|| info.kind.clone())
        .unwrap_or_else(|| "tool".into());
    // The id joins the call's records (case 35: the last copy per id wins);
    // the session keeps two sessions' calls apart; the random part keeps the
    // agent, which holds the same token, from posting a copy first or later
    // (security review L16).
    let id = format!(
        "{}-acp-{}-{}-{nonce}",
        st.ctx.harness,
        id_part(&session, 16),
        id_part(call, 48)
    );
    st.post(adapter_event(
        st,
        id,
        "tool.call",
        format!("{label} {}", status.unwrap_or("pending")),
        json!({
            "toolUseId": call,
            "name": info.name,
            "kind": info.kind,
            "status": status,
            "rawInputSha256": sha256_hex(info.raw_input.as_ref()),
            "gate": if asked { "asked" } else { "logged, not gated" },
        }),
    ));
}

/// Posts each record on the chat token, reconnecting once per record when
/// the connection dropped; a record that cannot be posted is dropped.
pub fn poster(rx: Receiver<Event>, socket: PathBuf, token: String) {
    use derm_audit_linux::client::Client;
    let mut conn: Option<Client> = None;
    for e in rx {
        for _ in 0..2 {
            if conn.is_none() {
                conn = Client::connect(&socket, &token, "derm acp")
                    .ok()
                    .map(|(c, _)| c);
            }
            match conn.as_mut().map(|c| c.post(&e)) {
                Some(Ok(_)) => break,
                _ => conn = None,
            }
        }
    }
}

/// Starts the three threads on a started agent.
pub fn start(
    st: Arc<State>,
    agent_in: Box<dyn Write + Send>,
    agent_out: impl Read + Send + 'static,
    client_in: impl Read + Send + 'static,
    client_out: impl Write + Send + 'static,
    log: Option<LogEnd>,
) -> Vec<JoinHandle<()>> {
    let agent: Shared = Arc::new(Mutex::new(Some(agent_in)));
    let mut handles = Vec::new();
    if let Some((rx, socket, token)) = log {
        handles.push(std::thread::spawn(move || poster(rx, socket, token)));
    }
    let a1 = agent.clone();
    let st1 = st.clone();
    handles.push(std::thread::spawn(move || {
        let mut out = client_out;
        agent_to_client(agent_out, &mut out, a1, &st1);
        st1.close_log();
    }));
    // Not joined: it may sit on the client's input after the agent is gone.
    let confined = st.ctx.confined;
    std::thread::spawn(move || client_to_agent(client_in, agent, confined));
    handles
}

/// A channel for the records, when there is a daemon to post them to.
pub fn log_channel(
    socket: Option<PathBuf>,
    token: Option<String>,
) -> (Option<Sender<Event>>, Option<LogEnd>) {
    match (socket, token) {
        (Some(s), Some(t)) => {
            let (tx, rx) = mpsc::channel();
            (Some(tx), Some((rx, s, t)))
        }
        _ => (None, None),
    }
}
