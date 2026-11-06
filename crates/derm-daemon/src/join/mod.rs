//! The join (wave 5, lane S; `plans/toolkit_universal_plan.md` miss 10, rules
//! cases 115, 123, 124): intent to decision on the call id, decision to
//! effect by process tree, then path, then time window, under case 35's
//! rule. An effect that fits more than one call is recorded as a candidate
//! set (`kind: "join.candidates"`, `contracts/events.md` section 5), never as
//! the nearest call.
//!
//! What it reads, per chat, as the daemon ingests it:
//! - `run.start` (the chat's folder, for relative paths, and the harness's
//!   pid, the root of the tree);
//! - `tap.call` (the call the model asked for: its id, tool, the paths it
//!   names; its result's arrival ends it);
//! - the gate's `approval` record (`detail.toolUseId`; the call starts) and
//!   its `tool.call` record (the call ran; it ends);
//! - the OS feed's effects (`auditd`, `eslogger`): `exec`, `fork`, writes,
//!   renames, unlinks, links, connects.
//!
//! Intent and decision share the call id (`tap.call`'s `callId` is the
//! hook's `toolUseId`), so a reader joins them by key; the join writes a
//! record only for effects.
//!
//! How an effect is credited:
//! 1. **Tree.** A process the harness starts while exactly one call is
//!    running belongs to that call, and so do its descendants. With two
//!    calls running, a new child belongs to neither (window, below).
//! 2. **Path.** A write to a path exactly one running call names is that
//!    call's; several calls naming it make a candidate set.
//! 3. **MCP server.** A child the harness started while no call ran (a stdio
//!    MCP server, started with the session) is credited, for each effect, to
//!    every MCP call (`server/tool`) running then (`by: "mcp-server"`).
//! 4. **Window.** Otherwise every call running at the effect's time.
//!
//! `chosen` names a call only when the tree or a path picks exactly one.
//! An effect no running call fits gets no record. Memory is bounded per chat
//! and in chats; `forget` drops a chat at its `run.stop`.

use std::collections::{HashMap, VecDeque};

use derm_core::event::{Event, Source};
use serde_json::{json, Value};

/// Calls one chat keeps (oldest go first).
pub const MAX_CALLS: usize = 4_096;
/// Processes one chat keeps an owner for.
pub const MAX_PIDS: usize = 8_192;
/// Chats with state at once.
pub const MAX_CHATS: usize = 512;
/// Candidates in one record (the schema's `maxItems`).
pub const MAX_CANDIDATES: usize = 64;
/// A call with no end seen is taken as running this long after its start.
pub const OPEN_CALL_MS: i64 = 10 * 60 * 1000;
/// How far before a call's recorded start an effect may fall (the OS feed
/// and the hook each stamp with some delay).
pub const SLACK_BEFORE_MS: i64 = 500;
/// How far after a call's recorded end.
pub const SLACK_AFTER_MS: i64 = 2_000;

/// Effect kinds that get a join record.
const EFFECTS: &[&str] = &[
    "exec",
    "create",
    "write",
    "truncate",
    "rename",
    "unlink",
    "link",
    "net.connect",
];

#[derive(Clone, Debug, Default)]
struct Call {
    /// The event id a candidate names: the tap's record, else the gate's.
    event: String,
    tool: String,
    paths: Vec<String>,
    start: Option<i64>,
    end: Option<i64>,
}

impl Call {
    fn mcp(&self) -> bool {
        self.tool.contains('/')
    }

    /// A shell tool (`derm_core::policy::SHELL_TOOLS`, by normalized name).
    fn shell(&self) -> bool {
        let t = self.tool.to_ascii_lowercase();
        derm_core::policy::SHELL_TOOLS.contains(&t.as_str())
    }

    fn window(&self) -> Option<(i64, i64)> {
        let s = self.start?;
        let e = self.end.unwrap_or(s + OPEN_CALL_MS);
        Some((s - SLACK_BEFORE_MS, e.max(s) + SLACK_AFTER_MS))
    }

    fn running_at(&self, t: i64) -> bool {
        self.window().is_some_and(|(a, b)| a <= t && t <= b)
    }
}

/// Who a process is credited to.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Owner {
    Call(String),
    /// Started while no call ran: an MCP server or a helper of the session.
    Session,
    /// Started while two or more calls ran: no single owner.
    Ambiguous,
    /// A shell started while these shell calls ran: each may own it, none
    /// is chosen (fix pass 1's review, F1). Shared, since every descendant
    /// holds it (re-review: at most 64 ids, up to 8,192 processes a chat).
    Among(std::sync::Arc<[String]>),
}

#[derive(Default)]
struct ChatState {
    cwd: Option<String>,
    root_pid: Option<u32>,
    calls: HashMap<String, Call>,
    order: VecDeque<String>,
    owners: HashMap<u32, Owner>,
    owner_order: VecDeque<u32>,
}

impl ChatState {
    fn call_mut(&mut self, id: &str) -> &mut Call {
        if !self.calls.contains_key(id) {
            self.order.push_back(id.to_string());
            while self.order.len() > MAX_CALLS {
                if let Some(old) = self.order.pop_front() {
                    self.calls.remove(&old);
                }
            }
        }
        self.calls.entry(id.to_string()).or_default()
    }

    fn own(&mut self, pid: u32, owner: Owner) {
        if !self.owners.contains_key(&pid) {
            self.owner_order.push_back(pid);
            while self.owner_order.len() > MAX_PIDS {
                if let Some(old) = self.owner_order.pop_front() {
                    self.owners.remove(&old);
                }
            }
        }
        self.owners.insert(pid, owner);
    }

    fn running(&self, t: i64) -> Vec<(&String, &Call)> {
        let mut v: Vec<(&String, &Call)> = self
            .order
            .iter()
            .filter_map(|id| self.calls.get(id).map(|c| (id, c)))
            .filter(|(_, c)| c.running_at(t))
            .collect();
        v.truncate(MAX_CANDIDATES);
        v
    }

    fn absolute(&self, path: &str) -> String {
        let p = path.strip_prefix("./").unwrap_or(path);
        if p.starts_with('/') {
            return p.to_string();
        }
        match &self.cwd {
            Some(c) => format!("{}/{p}", c.trim_end_matches('/')),
            None => p.to_string(),
        }
    }
}

/// The join's state over every chat.
#[derive(Default)]
pub struct Join {
    chats: HashMap<String, ChatState>,
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// An effect's own time: the OS's stamp when the feed kept it.
fn effect_time(e: &Event) -> i64 {
    e.detail
        .get("auditAt")
        .or_else(|| e.detail.get("osAt"))
        .and_then(Value::as_i64)
        .unwrap_or(e.at)
}

/// A shell's own program, by file name: what a harness runs a shell tool's
/// command in (and Codex's Linux sandbox helper, which execs the shell).
fn shell_program(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "mksh"
            | "ash"
            | "fish"
            | "pwsh"
            | "codex-linux-sandbox"
    )
}

impl Join {
    pub fn new() -> Self {
        Join::default()
    }

    /// Drops a chat's state (at its `run.stop`).
    pub fn forget(&mut self, chat: &str) {
        self.chats.remove(chat);
    }

    fn chat(&mut self, chat: &str) -> &mut ChatState {
        if !self.chats.contains_key(chat) && self.chats.len() >= MAX_CHATS {
            if let Some(k) = self.chats.keys().next().cloned() {
                self.chats.remove(&k);
            }
        }
        self.chats.entry(chat.to_string()).or_default()
    }

    /// Reads one ingested event; returns the join records it makes (source
    /// `derm`, for the daemon to ingest; they are not read back).
    pub fn observe(&mut self, e: &Event) -> Vec<Event> {
        if e.chat_id.is_empty() {
            return Vec::new();
        }
        match (&e.source, e.kind.as_str()) {
            (Source::Run, "run.start") => {
                let st = self.chat(&e.chat_id);
                st.cwd = str_at(&e.detail, "cwd").map(str::to_string);
                st.root_pid = e.pid;
                Vec::new()
            }
            (Source::Run, "run.stop") => {
                self.forget(&e.chat_id);
                Vec::new()
            }
            (Source::Tap, "tap.call") => {
                let Some(id) = str_at(&e.detail, "callId") else {
                    return Vec::new();
                };
                let tool = str_at(&e.detail, "toolNormalized")
                    .unwrap_or("")
                    .to_string();
                let paths: Vec<String> = e
                    .detail
                    .get("paths")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let has_result = e.detail.get("resultSha256").is_some_and(|r| !r.is_null());
                let st = self.chat(&e.chat_id);
                let paths: Vec<String> = paths.iter().map(|p| st.absolute(p)).collect();
                let c = st.call_mut(id);
                c.event = e.id.clone();
                c.tool = tool;
                c.paths = paths;
                c.start.get_or_insert(e.at);
                if has_result {
                    c.end = Some(c.end.map_or(e.at, |x| x.min(e.at)));
                }
                Vec::new()
            }
            (Source::Adapter, "approval") | (Source::Adapter, "tool.call") => {
                let Some(id) = str_at(&e.detail, "toolUseId") else {
                    return Vec::new();
                };
                let ran = e.kind == "tool.call";
                let decision = str_at(&e.detail, "decision").unwrap_or("");
                let tool = str_at(&e.detail, "tool").unwrap_or("").to_string();
                let st = self.chat(&e.chat_id);
                let c = st.call_mut(id);
                if c.event.is_empty() {
                    c.event = e.id.clone();
                }
                // The tap's name wins; an untapped chat has only the gate's.
                if c.tool.is_empty() {
                    c.tool = tool;
                }
                if ran {
                    c.end = Some(c.end.map_or(e.at, |x| x.min(e.at)));
                } else if decision == "deny" {
                    // A denied call runs nothing: it ends where it starts.
                    c.start = Some(e.at);
                    c.end = Some(e.at);
                } else if decision != "deferred" {
                    // The decision is when the call can start running.
                    c.start = Some(e.at);
                }
                Vec::new()
            }
            (Source::Auditd | Source::Eslogger, kind) => self.effect(e, kind),
            _ => Vec::new(),
        }
    }

    fn effect(&mut self, e: &Event, kind: &str) -> Vec<Event> {
        let t = effect_time(e);
        let pid = e.pid;
        let ppid = e
            .detail
            .get("ppid")
            .and_then(Value::as_u64)
            .map(|p| p as u32);
        // A new process inherits its parent's owner; a child of the harness
        // itself is placed by what runs now.
        if kind == "fork" || kind == "exec" {
            let child = match kind {
                "fork" => e
                    .detail
                    .get("child")
                    .and_then(Value::as_u64)
                    .map(|c| c as u32),
                _ => pid,
            };
            let st = self.chat(&e.chat_id);
            if let Some(child) = child {
                let parent = if kind == "fork" { pid } else { ppid };
                let inherited = parent.and_then(|p| st.owners.get(&p).cloned());
                let program = str_at(&e.detail, "exe").or_else(|| str_at(&e.detail, "comm"));
                let owner = match inherited {
                    Some(o) => Some(o),
                    None if parent.is_some() && parent == st.root_pid => {
                        // A child of the harness while a call runs belongs to
                        // that call only with certainty (case 43): a shell
                        // started for a shell call. The harness also starts
                        // its own helpers then, such as MCP servers, which
                        // are no call's (box test w5, BW5-11). At the fork the
                        // program is not known yet, so its exec decides.
                        // A shell while several shell calls run is theirs
                        // together, so one more call open (a parallel one,
                        // or an approval posted with no call after it) does
                        // not take its writes from every install (review F1).
                        let running = st.running(t);
                        let shells: Vec<String> = running
                            .iter()
                            .filter(|(_, c)| c.shell())
                            .map(|(id, _)| id.to_string())
                            .collect();
                        match (running.len(), kind) {
                            (0, _) => Some(Owner::Session),
                            (_, "fork") => None,
                            _ if program.is_some_and(shell_program) => match shells.len() {
                                0 => Some(Owner::Ambiguous),
                                1 => Some(Owner::Call(shells[0].clone())),
                                _ => Some(Owner::Among(shells.into())),
                            },
                            _ => Some(Owner::Ambiguous),
                        }
                    }
                    None => None,
                };
                if let Some(o) = owner {
                    if !(kind == "exec" && st.owners.contains_key(&child)) {
                        st.own(child, o);
                    }
                }
            }
            if kind == "fork" {
                return Vec::new();
            }
        }
        if !EFFECTS.contains(&kind) {
            return Vec::new();
        }
        let st = self.chat(&e.chat_id);
        let running = st.running(t);
        if running.is_empty() {
            return Vec::new();
        }
        let mut candidates: Vec<(String, &'static str, String)> = Vec::new();
        let mut chosen: Option<String> = None;
        let owner = pid.and_then(|p| st.owners.get(&p).cloned());
        // 1. Tree.
        if let Some(Owner::Call(id)) = &owner {
            if let Some(c) = st.calls.get(id) {
                candidates.push((
                    c.event.clone(),
                    "tree",
                    "a process this call started".into(),
                ));
                chosen = Some(c.event.clone());
            }
        }
        // Each of the shell's calls stays a candidate after it ends, as a
        // tree owner does, and none is chosen: a call still open at the
        // write may be one a chat token posted with no call after it
        // (re-review N1).
        if let Some(Owner::Among(ids)) = &owner {
            for c in ids.iter().filter_map(|id| st.calls.get(id)) {
                candidates.push((
                    c.event.clone(),
                    "tree",
                    "a shell started while this call and others ran".into(),
                ));
            }
        }
        // 2. Path.
        if chosen.is_none() {
            let paths: Vec<String> = ["path", "dest"]
                .iter()
                .filter_map(|k| str_at(&e.detail, k))
                .map(|p| st.absolute(p))
                .collect();
            let named: Vec<&Call> = running
                .iter()
                .map(|(_, c)| *c)
                .filter(|c| c.paths.iter().any(|p| paths.contains(p)))
                .collect();
            for c in &named {
                candidates.push((
                    c.event.clone(),
                    "path",
                    "names this path in its arguments".into(),
                ));
            }
            if named.len() == 1 {
                chosen = Some(named[0].event.clone());
            }
        }
        // 3. MCP server, 4. window.
        if candidates.is_empty() {
            let session = matches!(owner, Some(Owner::Session));
            for (_, c) in &running {
                if session && c.mcp() {
                    candidates.push((
                        c.event.clone(),
                        "mcp-server",
                        "an MCP call running while a session process acted".into(),
                    ));
                } else if !session {
                    candidates.push((
                        c.event.clone(),
                        "window",
                        "running at the time of the effect".into(),
                    ));
                }
            }
        }
        if candidates.is_empty() {
            return Vec::new();
        }
        candidates.truncate(MAX_CANDIDATES);
        let n = candidates.len();
        let summary = match &chosen {
            Some(_) => format!("{kind} credited to 1 call"),
            None if n == 1 => format!("{kind} fits 1 call"),
            None => format!("{kind} fits {n} calls"),
        };
        vec![Event {
            id: format!("join-{}", e.id),
            at: e.at,
            chat_id: e.chat_id.clone(),
            harness: e.harness.clone(),
            source: Source::Derm,
            kind: "join.candidates".into(),
            summary,
            detail: json!({
                "trust": "daemon",
                "effect": e.id,
                "effectKind": kind,
                "candidates": candidates
                    .iter()
                    .map(|(call, by, why)| json!({"call": call, "by": by, "why": why}))
                    .collect::<Vec<_>>(),
                "chosen": chosen,
            }),
            pid: e.pid,
            approval_id: None,
        }]
    }
}

#[cfg(test)]
mod tests;
