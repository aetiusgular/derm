//! The daemon's half of step P (lane PE's; `contracts/daemon-protocol.md`
//! section 6, `contracts/project-tools.md`, `contracts/events.md` section 7).
//!
//! What it holds, all in memory but the map:
//!
//! - **The chat-to-project map**, from `token.mint`'s `project` (an id or
//!   `""`), kept in `chats.json` too (`saved`, `restore`; daemon-protocol
//!   6.1). `stamp` sets every stored event's `project` from it, over any
//!   client value, and counts a non-empty client value that differed
//!   (`report.projectOverwritten`; events.md 7.1, Tony's C2 call). A chat's
//!   project stays in the map after its `run.stop`, so the stop record and
//!   the OS events that arrive late still carry it; only `token.mint`
//!   changes it.
//! - **Messages** (`derm_message`, P6): from a chat to a chat of its
//!   project, or `"*"` (every other running chat of the project), waiting
//!   until the target takes them, at most 64 messages and 256 KiB a chat,
//!   the oldest dropped and counted. Every message is marked as from an
//!   agent; its text is cleaned by `derm_core::project::screen::clean`
//!   before it waits.
//! - **Screens** (`derm_terminal_read`, P5's daemon half): the last
//!   `screen.put` of each running chat, from `derm run` (daemon scope only),
//!   cleaned again before a reply leaves (project-tools 3.4).
//! - **Asks across projects** (P7, Tony's call 20): a message to, or a read
//!   of, a chat of another project asks the person through the approver; a
//!   `no`, a timeout or no approver delivers nothing (case 63). A grant
//!   "for this session" is kept here for the ordered pair (the caller's
//!   project, the target's) and the caller's chat, ends at that chat's
//!   `run.stop`, and is recorded as `project.grant` (with `ended: true` at
//!   the end), never written to a file (P-C7).
//!
//! Who a caller is comes from its token only (`Caller`, resolved by
//! `daemon.rs`); nothing in an op line names the caller or its project.
//!
//! The daemon reaches the approver, the log and a chat's socket share
//! through `Host`, which `crate::daemon` implements
//! (`daemon/approver/project.rs`) and hands over with `attach`. Until a host
//! is attached (the one line `daemon.rs` needs, request PE-R1), an ask
//! answers `no` and nothing is recorded; messages and screens inside one
//! project still work.
//!
//! The red tests are `crates/derm-daemon/tests/contracts_acctp.rs`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use derm_core::event::{Event, Source};
use derm_core::project::{kinds, screen, valid_field};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::daemon::error;
use crate::protocol::{ApprovalRequest, Reply};

pub mod mcp;

#[cfg(test)]
mod tests;

/// Longest message text, in bytes of UTF-8 (project-tools 2.1).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Most messages waiting for one chat.
pub const MAX_WAITING: usize = 64;
/// Most bytes of message text waiting for one chat.
pub const MAX_WAITING_BYTES: usize = 256 * 1024;
/// Most chats the map holds; a stopped chat leaves first, then the oldest.
pub const MAX_CHATS: usize = 4_096;
/// How long an ask across projects waits for the person.
pub const ASK_SECONDS: u32 = 120;
/// The tools as the gate and the approver name them (policy step 1).
pub const TOOL_MESSAGE: &str = "derm_project/derm_message";
pub const TOOL_READ: &str = "derm_project/derm_terminal_read";

/// Who sent an op line, as `daemon.rs` resolved the connection's token.
#[derive(Clone, Copy, Debug)]
pub enum Caller<'a> {
    Daemon,
    Chat { chat: &'a str, harness: &'a str },
}

/// The person's answer to an ask across projects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asked {
    /// No, a timeout, or no approver (case 63).
    No,
    /// Yes, this once.
    Once,
    /// Yes, for the rest of the caller's chat (P7).
    Session,
}

/// What the project layer needs from the daemon around it.
pub trait Host: Send + Sync {
    /// Asks the person through the approver, as the gate's `approve` does,
    /// and records the ask and its answer as the daemon records any
    /// approval. Blocks until the answer or the request's timeout.
    fn ask(&self, request: ApprovalRequest) -> Asked;
    /// Stores one record the daemon wrote (source `derm`).
    fn record(&self, event: Event);
    /// Takes `bytes` from the chat's share of the socket (daemon-protocol
    /// section 2, rule 2), or says why not.
    fn quota(&self, chat: &str, bytes: usize) -> Result<(), String>;
}

#[derive(Clone, Debug, Default)]
struct Chat {
    project: String,
    /// From the chat's daemon-scope `run.start`, or its own ops.
    harness: String,
    /// The agent account's slug, `""` for a chat that runs as the person.
    account: String,
    /// The project folder's real path, from `run.start`'s `detail.project`.
    folder: String,
    /// Minted, started, or seen acting since a restart.
    live: bool,
    /// Its `run.stop` came; only a new `token.mint` or `run.start` makes it
    /// live again.
    stopped: bool,
    /// Insertion order, for eviction.
    seq: u64,
}

#[derive(Clone, Debug)]
struct Waiting {
    id: String,
    from: String,
    harness: String,
    account: String,
    at: i64,
    text: String,
    reply_to: Option<String>,
}

#[derive(Clone, Debug)]
struct Screen {
    rows: u16,
    cols: u16,
    text: String,
    scrollback_lines: u32,
    at: i64,
}

#[derive(Default)]
struct Inner {
    chats: HashMap<String, Chat>,
    seq: u64,
    inbox: HashMap<String, VecDeque<Waiting>>,
    screens: HashMap<String, Screen>,
    /// (caller's chat, caller's project, target's project).
    grants: HashSet<(String, String, String)>,
}

impl Inner {
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn entry(&mut self, chat: &str) -> &mut Chat {
        if !self.chats.contains_key(chat) {
            let seq = self.next_seq();
            self.chats.insert(
                chat.to_string(),
                Chat {
                    seq,
                    ..Chat::default()
                },
            );
            self.evict();
        }
        self.chats.entry(chat.to_string()).or_default()
    }

    /// Keeps the map under `MAX_CHATS`: a stopped chat leaves first, then
    /// the oldest one.
    fn evict(&mut self) {
        while self.chats.len() > MAX_CHATS {
            let victim = self
                .chats
                .iter()
                .min_by_key(|(_, c)| (!c.stopped, c.seq))
                .map(|(k, _)| k.clone());
            let Some(k) = victim else { break };
            self.chats.remove(&k);
            self.inbox.remove(&k);
            self.screens.remove(&k);
            self.grants.retain(|g| g.0 != k);
        }
    }

    fn project(&self, chat: &str) -> String {
        self.chats
            .get(chat)
            .map(|c| c.project.clone())
            .unwrap_or_default()
    }

    fn running(&self, chat: &str) -> bool {
        self.chats.get(chat).is_some_and(|c| c.live && !c.stopped)
    }

    /// A chat's op is a sign of life: its token came back after a restart.
    fn seen(&mut self, chat: &str, harness: &str) {
        if let Some(c) = self.chats.get_mut(chat) {
            if !c.stopped {
                c.live = true;
            }
            if c.harness.is_empty() {
                c.harness = harness.to_string();
            }
        }
    }

    /// The folder, or the id, a card names a project by.
    fn label(&self, project: &str) -> String {
        self.chats
            .values()
            .find(|c| c.project == project && !c.folder.is_empty())
            .map(|c| c.folder.clone())
            .unwrap_or_else(|| project.to_string())
    }
}

/// The project layer's state, held by the daemon.
#[derive(Default)]
pub struct State {
    inner: Mutex<Inner>,
    overwritten: AtomicU64,
    /// Waiting messages dropped for room (the oldest first).
    dropped: AtomicU64,
    host: OnceLock<Weak<dyn Host>>,
}

/// A target of one `msg.send` and what decides it.
struct Target {
    chat: String,
    project: String,
    /// Same project, or a session grant held.
    open: bool,
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn ok_result(result: Value) -> Reply {
    let mut r = error("");
    r.ok = true;
    r.error = None;
    r.result = Some(result);
    r
}

fn ok_plain() -> Reply {
    let mut r = error("");
    r.ok = true;
    r.error = None;
    r
}

/// A message id or a chat id: 1 to 128 of `[A-Za-z0-9_.:-]`.
fn valid_name(text: &str) -> bool {
    crate::activity::registry::valid_chat_id(text)
}

fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((i, _)) => text[..i].to_string(),
        None => text.to_string(),
    }
}

/// The account a `run.start`'s `runsAs` names: `derm-<slug>` gives the
/// slug; `you` or nothing gives `""`.
fn account_of(run_start_detail: &Value) -> String {
    let runs_as = run_start_detail
        .get("runsAs")
        .and_then(Value::as_str)
        .unwrap_or("");
    match runs_as.strip_prefix("derm-") {
        Some(slug)
            if !slug.is_empty()
                && slug.len() <= 15
                && slug
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') =>
        {
            slug.to_string()
        }
        _ => String::new(),
    }
}

/// `run.start`'s `detail.project.folder`, when it is an absolute path of at
/// most 4,096 bytes with no control character (it goes on a card).
fn folder_of(run_start_detail: &Value) -> String {
    let folder = run_start_detail
        .pointer("/project/folder")
        .and_then(Value::as_str)
        .unwrap_or("");
    if folder.starts_with('/') && folder.len() <= 4_096 && !folder.chars().any(char::is_control) {
        folder.to_string()
    } else {
        String::new()
    }
}

/// The last `lines` lines of `text`, or with none the screen without its
/// scrollback (the first `scrollback` lines).
fn select(text: &str, lines: Option<u32>, scrollback: u32) -> String {
    let all: Vec<&str> = text.split('\n').collect();
    let keep = match lines {
        Some(n) => (n as usize).min(all.len()),
        None => all.len().saturating_sub(scrollback as usize),
    };
    all[all.len() - keep..].join("\n")
}

impl State {
    /// Hands the state the daemon it lives in (request PE-R1: one line in
    /// `Daemon::new_with_state`, `approver::project::attach(&daemon)`).
    /// The first attach holds.
    pub fn attach(&self, host: Weak<dyn Host>) {
        let _ = self.host.set(host);
    }

    fn host(&self) -> Option<Arc<dyn Host>> {
        self.host.get().and_then(Weak::upgrade)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `token.mint`'s `project` (an id or `""`; checked by the caller), kept
    /// beside the token and in `chats.json` (daemon-protocol 6.1). A new
    /// mint makes the chat live again.
    pub fn note_mint(&self, chat: &str, project: &str) {
        let mut g = self.lock();
        let seq = g.next_seq();
        let c = g.entry(chat);
        if c.project != project {
            c.folder.clear();
        }
        c.project = project.to_string();
        c.live = true;
        c.stopped = false;
        c.seq = seq;
    }

    /// A daemon-scope `run.start` (only the daemon scope posts `run`
    /// records, `daemon.rs` `op_event`): the chat's harness, account and
    /// project folder. A chat the map does not hold (after a restart with
    /// no `chats.json`, request PE-R4) takes its project from
    /// `detail.project.id`; a held one keeps the project its mint gave.
    pub fn note_run_start(&self, event: &Event) {
        if event.source != Source::Run || event.kind != "run.start" {
            return;
        }
        let mut g = self.lock();
        let known = g.chats.contains_key(&event.chat_id);
        let claimed = event
            .detail
            .pointer("/project/id")
            .and_then(Value::as_str)
            .filter(|p| valid_field(p))
            .unwrap_or("")
            .to_string();
        let c = g.entry(&event.chat_id);
        if !known {
            c.project = claimed.clone();
        }
        if c.project == claimed {
            let folder = folder_of(&event.detail);
            if !folder.is_empty() {
                c.folder = folder;
            }
        }
        c.harness = event.harness.clone();
        c.account = account_of(&event.detail);
        c.live = true;
        c.stopped = false;
    }

    /// The project the daemon holds for `chat`, `""` when none.
    pub fn project_of(&self, chat: &str) -> String {
        self.lock().project(chat)
    }

    /// Whether `chat` is a target now: held, not stopped, and seen acting
    /// since the daemon started or since its mint.
    pub fn running(&self, chat: &str) -> bool {
        self.lock().running(chat)
    }

    /// The log's `run.start` and `run.stop` records, oldest first, after a
    /// restart (request PE-R4, case 211). A chat the map does not hold yet
    /// takes its project, harness, account and folder from its `run.start`
    /// and is not a target until it shows life (as one restored from
    /// `chats.json`); a chat whose `run.stop` follows is stopped. A chat the
    /// map already holds (from `chats.json`, or minted or seen since the
    /// start) is left as it is: the log read can be older than what arrived
    /// while it was read.
    pub fn replay(&self, events: &[Event]) {
        let mut replayed: std::collections::HashSet<String> = std::collections::HashSet::new();
        for event in events {
            if event.source != Source::Run || !valid_name(&event.chat_id) {
                continue;
            }
            let held = self.lock().chats.contains_key(&event.chat_id);
            match event.kind.as_str() {
                "run.start" if !held || replayed.contains(&event.chat_id) => {
                    self.note_run_start(event);
                    let mut g = self.lock();
                    if let Some(c) = g.chats.get_mut(&event.chat_id) {
                        c.live = false;
                    }
                    replayed.insert(event.chat_id.clone());
                }
                "run.stop" if replayed.contains(&event.chat_id) => {
                    self.forget_chat(&event.chat_id);
                }
                _ => {}
            }
        }
    }

    /// Sets `event.project` to the project of its chat, whatever the client
    /// sent, and counts an event whose client value was another project
    /// (events.md 7.1). An event with no `project` (every client older than
    /// step P) is not counted. A `run.start` is noted first; a chat's own
    /// telemetry or adapter record is a sign of life for a chat restored
    /// from `chats.json` (its token came back).
    pub fn stamp(&self, event: &mut Event) {
        self.note_run_start(event);
        if matches!(event.source, Source::Adapter | Source::Otel) {
            let harness = event.harness.clone();
            self.lock().seen(&event.chat_id, &harness);
        }
        let ours = self.project_of(&event.chat_id);
        if !event.project.is_empty() && event.project != ours {
            self.overwritten.fetch_add(1, Ordering::Relaxed);
        }
        event.project = ours;
    }

    /// How many events arrived with a `project` other than the daemon's.
    pub fn overwritten(&self) -> u64 {
        self.overwritten.load(Ordering::Relaxed)
    }

    /// How many waiting messages were dropped for room.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn record(
        &self,
        chat: &str,
        harness: &str,
        project: &str,
        kind: &str,
        summary: String,
        mut detail: Value,
    ) {
        let Some(host) = self.host() else { return };
        if let Value::Object(m) = &mut detail {
            m.insert("trust".into(), Value::from("daemon"));
        }
        host.record(Event {
            id: format!(
                "derm-{}-{}",
                kind.replace('.', "-"),
                uuid::Uuid::new_v4().simple()
            ),
            at: 0,
            chat_id: chat.to_string(),
            harness: harness.to_string(),
            source: Source::Derm,
            kind: kind.to_string(),
            summary,
            detail,
            pid: None,
            approval_id: None,
            project: project.to_string(),
        });
    }

    fn ask(&self, tool: &str, chat: &str, harness: &str, summary: String) -> Asked {
        let Some(host) = self.host() else {
            return Asked::No;
        };
        host.ask(ApprovalRequest {
            id: format!("derm-project-{}", uuid::Uuid::new_v4().simple()),
            chat: chat.to_string(),
            harness: harness.to_string(),
            tool: tool.to_string(),
            summary: clip(&summary, 500),
            timeout_seconds: ASK_SECONDS,
            boundary_only: false,
            offers: Vec::new(),
        })
    }

    fn quota(&self, chat: &str, bytes: usize) -> Result<(), String> {
        match self.host() {
            Some(h) => h.quota(chat, bytes),
            None => Ok(()),
        }
    }

    /// A session grant: kept for the pair and the caller's chat, recorded.
    fn grant(&self, chat: &str, harness: &str, from: &str, to: &str) {
        let fresh = self
            .lock()
            .grants
            .insert((chat.to_string(), from.to_string(), to.to_string()));
        if fresh {
            self.record(
                chat,
                harness,
                from,
                kinds::GRANT,
                format!("project.grant: chat {chat}, project {from} to {to}, for the session"),
                json!({"from": from, "to": to, "chat": chat, "until": "session"}),
            );
        }
    }

    /// `msg.send {to, text, replyTo?}`, chat scope (project-tools 2.1).
    pub fn msg_send(
        &self,
        caller: Caller<'_>,
        to: &str,
        text: &str,
        reply_to: Option<&str>,
    ) -> Reply {
        let Caller::Chat { chat, harness } = caller else {
            return error("msg.send: chat scope only");
        };
        if to != "*" && !valid_name(to) {
            return error("msg.send: to is a chat id (1 to 128 of [A-Za-z0-9_.:-]) or \"*\"");
        }
        if text.is_empty() || text.len() > MAX_MESSAGE_BYTES {
            return error("msg.send: text is 1 byte to 16 KiB");
        }
        if reply_to.is_some_and(|r| !valid_name(r)) {
            return error("msg.send: replyTo is a message id (1 to 128 of [A-Za-z0-9_.:-])");
        }
        if let Err(why) = self.quota(chat, text.len()) {
            return error(why);
        }
        let text = screen::clean(text).text;
        if text.is_empty() {
            return error("msg.send: nothing is left of the text once control characters go");
        }
        let (mine, account, targets) = {
            let mut g = self.lock();
            g.seen(chat, harness);
            let mine = g.project(chat);
            if mine.is_empty() {
                return error("msg.send: this chat is in no project, so it reaches no chat");
            }
            let account = g
                .chats
                .get(chat)
                .map(|c| c.account.clone())
                .unwrap_or_default();
            let mut targets = Vec::new();
            if to == "*" {
                let mut same: Vec<String> = g
                    .chats
                    .iter()
                    .filter(|(k, c)| {
                        k.as_str() != chat && c.project == mine && c.live && !c.stopped
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                same.sort();
                targets.extend(same.into_iter().map(|t| Target {
                    chat: t,
                    project: mine.clone(),
                    open: true,
                }));
            } else {
                if to == chat {
                    return error("msg.send: a chat does not message itself");
                }
                if !g.running(to) {
                    return error(format!("msg.send: no running chat {to}"));
                }
                let theirs = g.project(to);
                if theirs.is_empty() {
                    return error(format!(
                        "msg.send: chat {to} is in no project, so no chat reaches it"
                    ));
                }
                let open = theirs == mine
                    || g.grants
                        .contains(&(chat.to_string(), mine.clone(), theirs.clone()));
                targets.push(Target {
                    chat: to.to_string(),
                    project: theirs,
                    open,
                });
            }
            (mine, account, targets)
        };
        let id = format!("m-{}", uuid::Uuid::new_v4().simple());
        let at = crate::activity::store::now_ms();
        let digest = sha256_hex(text.as_bytes());
        let mut delivered = Vec::new();
        let mut asked = Vec::new();
        for t in targets {
            let mut answer = None;
            let go = if t.open {
                true
            } else {
                asked.push(t.chat.clone());
                let (here, there) = {
                    let g = self.lock();
                    (g.label(&mine), g.label(&t.project))
                };
                let a = self.ask(
                    TOOL_MESSAGE,
                    chat,
                    harness,
                    format!(
                        "agent chat {chat} in project {here} asks to send a message ({} bytes) to agent chat {} in project {there}",
                        text.len(),
                        t.chat
                    ),
                );
                if a == Asked::Session {
                    self.grant(chat, harness, &mine, &t.project);
                }
                answer = Some(if a == Asked::No { "no" } else { "yes" });
                a != Asked::No
            };
            if go
                && self.deliver(
                    &t.chat,
                    Waiting {
                        id: id.clone(),
                        from: chat.to_string(),
                        harness: harness.to_string(),
                        account: account.clone(),
                        at,
                        text: text.clone(),
                        reply_to: reply_to.map(str::to_string),
                    },
                )
            {
                delivered.push(t.chat.clone());
            }
            let mut detail = json!({
                "from": chat,
                "to": t.chat,
                "bytes": text.len(),
                "sha256": digest,
                "asked": !t.open,
            });
            if let (Some(a), Value::Object(m)) = (answer, &mut detail) {
                m.insert("answer".into(), Value::from(a));
            }
            self.record(
                chat,
                harness,
                &mine,
                kinds::MESSAGE,
                format!(
                    "project.message: {chat} to {}, {} bytes",
                    t.chat,
                    text.len()
                ),
                detail,
            );
        }
        ok_result(json!({"id": id, "delivered": delivered, "asked": asked}))
    }

    /// Queues a message for a running chat, under the per-chat bounds.
    fn deliver(&self, to: &str, message: Waiting) -> bool {
        let mut g = self.lock();
        if !g.running(to) {
            return false;
        }
        let queue = g.inbox.entry(to.to_string()).or_default();
        queue.push_back(message);
        let mut dropped = 0;
        while queue.len() > MAX_WAITING
            || queue.iter().map(|m| m.text.len()).sum::<usize>() > MAX_WAITING_BYTES
        {
            queue.pop_front();
            dropped += 1;
        }
        if dropped > 0 {
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
        }
        true
    }

    /// `msg.take {}`, chat scope: the chat's waiting messages, removed as
    /// they are returned.
    pub fn msg_take(&self, caller: Caller<'_>) -> Reply {
        let Caller::Chat { chat, harness } = caller else {
            return error("msg.take: chat scope only");
        };
        if let Err(why) = self.quota(chat, 0) {
            return error(why);
        }
        let mut g = self.lock();
        g.seen(chat, harness);
        let waiting = g.inbox.remove(chat).unwrap_or_default();
        let messages: Vec<Value> = waiting
            .into_iter()
            .map(|m| {
                let mut v = json!({
                    "id": m.id,
                    "from": {"chat": m.from, "harness": m.harness, "account": m.account, "agent": true},
                    "at": m.at,
                    "text": m.text,
                });
                if let (Some(r), Value::Object(map)) = (m.reply_to, &mut v) {
                    map.insert("replyTo".into(), Value::from(r));
                }
                v
            })
            .collect();
        ok_result(json!({"messages": messages}))
    }

    /// `screen.put {...}`, daemon scope only (`derm run`, lane PD's client).
    pub fn screen_put(&self, caller: Caller<'_>, put: &crate::protocol::ScreenPut) -> Reply {
        if !matches!(caller, Caller::Daemon) {
            return error("screen.put needs daemon scope");
        }
        if !valid_name(&put.chat) {
            return error("screen.put: chat id: 1 to 128 of [A-Za-z0-9_.:-]");
        }
        if put.text.len() > screen::MAX_TEXT_BYTES {
            return error("screen.put: text over 512 KiB; derm run cuts it from the top first");
        }
        if put.rows == 0 || put.cols == 0 {
            return error("screen.put: rows and cols are at least 1");
        }
        let mut g = self.lock();
        if !g.running(&put.chat) {
            return error(format!("screen.put: no running chat {}", put.chat));
        }
        g.screens.insert(
            put.chat.clone(),
            Screen {
                rows: put.rows,
                cols: put.cols,
                text: put.text.clone(),
                scrollback_lines: put.scrollback_lines,
                at: put.at,
            },
        );
        ok_plain()
    }

    /// `screen.read {chat, lines?}`, chat scope.
    pub fn screen_read(&self, caller: Caller<'_>, target: &str, lines: Option<u32>) -> Reply {
        let Caller::Chat { chat, harness } = caller else {
            return error("screen.read: chat scope only");
        };
        if !valid_name(target) {
            return error("screen.read: chat id: 1 to 128 of [A-Za-z0-9_.:-]");
        }
        if lines.is_some_and(|n| n == 0 || n > screen::MAX_READ_LINES) {
            return error("screen.read: lines is 1 to 2000");
        }
        if let Err(why) = self.quota(chat, 0) {
            return error(why);
        }
        let (mine, theirs, target_harness, open) = {
            let mut g = self.lock();
            g.seen(chat, harness);
            let mine = g.project(chat);
            if mine.is_empty() {
                return error("screen.read: this chat is in no project, so it reads no chat");
            }
            if !g.running(target) || !g.screens.contains_key(target) {
                return error(format!("screen.read: chat {target} serves no screen"));
            }
            let theirs = g.project(target);
            if theirs.is_empty() {
                return error(format!(
                    "screen.read: chat {target} is in no project, so no chat reads it"
                ));
            }
            let open = theirs == mine
                || g.grants
                    .contains(&(chat.to_string(), mine.clone(), theirs.clone()));
            let th = g
                .chats
                .get(target)
                .map(|c| c.harness.clone())
                .unwrap_or_default();
            (mine, theirs, th, open)
        };
        let mut answer = None;
        if !open {
            let (here, there) = {
                let g = self.lock();
                (g.label(&mine), g.label(&theirs))
            };
            let a = self.ask(
                TOOL_READ,
                chat,
                harness,
                format!(
                    "agent chat {chat} in project {here} asks to read the terminal of agent chat {target} in project {there}"
                ),
            );
            if a == Asked::Session {
                self.grant(chat, harness, &mine, &theirs);
            }
            answer = Some(if a == Asked::No { "no" } else { "yes" });
            if a == Asked::No {
                self.record(
                    target,
                    &target_harness,
                    &theirs,
                    kinds::READ,
                    format!("project.read: {chat} read {target}: asked, no"),
                    json!({"reader": chat, "target": target, "bytes": 0,
                           "sha256": sha256_hex(b""), "asked": true, "answer": "no"}),
                );
                return error(format!(
                    "screen.read: the person did not allow chat {target}'s terminal to be read from this project"
                ));
            }
        }
        let Some(s) = self.lock().screens.get(target).cloned() else {
            return error(format!("screen.read: chat {target} serves no screen"));
        };
        // The daemon's second pass (project-tools 3.4): whatever
        // `screen.put` sent, no control byte leaves for an agent.
        let c = screen::clean(&select(&s.text, lines, s.scrollback_lines));
        let mut detail = json!({
            "reader": chat,
            "target": target,
            "bytes": c.text.len(),
            "sha256": sha256_hex(c.text.as_bytes()),
            "asked": !open,
        });
        if let (Some(a), Value::Object(m)) = (answer, &mut detail) {
            m.insert("answer".into(), Value::from(a));
        }
        self.record(
            target,
            &target_harness,
            &theirs,
            kinds::READ,
            format!("project.read: {chat} read {target}, {} bytes", c.text.len()),
            detail,
        );
        ok_result(json!({
            "chat": target,
            "rows": s.rows,
            "cols": s.cols,
            "text": c.text,
            "truncated": c.truncated,
            "at": s.at,
        }))
    }

    /// `screen.list {}`, chat scope: the chats of the caller's project that
    /// serve a screen, the caller excluded.
    pub fn screen_list(&self, caller: Caller<'_>) -> Reply {
        let Caller::Chat { chat, harness } = caller else {
            return error("screen.list: chat scope only");
        };
        if let Err(why) = self.quota(chat, 0) {
            return error(why);
        }
        let mut g = self.lock();
        g.seen(chat, harness);
        let mine = g.project(chat);
        if mine.is_empty() {
            return ok_result(json!({"chats": []}));
        }
        let mut chats: Vec<Value> = g
            .screens
            .iter()
            .filter(|(k, _)| k.as_str() != chat && g.running(k) && g.project(k) == mine)
            .map(|(k, s)| {
                let c = g.chats.get(k).cloned().unwrap_or_default();
                json!({"chat": k, "harness": c.harness, "account": c.account,
                       "rows": s.rows, "cols": s.cols, "at": s.at})
            })
            .collect();
        chats.sort_by(|a, b| a["chat"].as_str().cmp(&b["chat"].as_str()));
        ok_result(json!({"chats": chats}))
    }

    /// What `chats.json` keeps of the map (`daemon.rs` `save_state`): the
    /// chats that have not stopped, never a message, a screen or a grant.
    pub fn saved(&self) -> Value {
        let g = self.lock();
        let mut chats: Vec<(&String, &Chat)> = g.chats.iter().filter(|(_, c)| !c.stopped).collect();
        chats.sort_by_key(|(_, c)| c.seq);
        let list: Vec<Value> = chats
            .into_iter()
            .map(|(k, c)| {
                json!({"chat": k, "project": c.project, "harness": c.harness,
                       "account": c.account, "folder": c.folder})
            })
            .collect();
        json!({"version": 1, "chats": list})
    }

    /// The map back from `chats.json`'s `projects` after a restart (case
    /// 211). A restored chat is not a target until it is seen acting (its
    /// token came back) or starts again: one whose harness died while the
    /// daemon was down never is. A file that is not this shape adds nothing.
    pub fn restore(&self, saved: &Value) {
        if saved.get("version").and_then(Value::as_u64) != Some(1) {
            return;
        }
        let Some(list) = saved.get("chats").and_then(Value::as_array) else {
            return;
        };
        let mut g = self.lock();
        for item in list.iter().take(MAX_CHATS) {
            let text = |k: &str| {
                item.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            let (chat, project) = (text("chat"), text("project"));
            if !valid_name(&chat) || !valid_field(&project) || g.chats.contains_key(&chat) {
                continue;
            }
            let folder = folder_of(&json!({"project": {"folder": text("folder")}}));
            let account = account_of(&json!({"runsAs": format!("derm-{}", text("account"))}));
            let harness = clip(&text("harness"), 64);
            let c = g.entry(&chat);
            c.project = project;
            c.folder = folder;
            c.account = account;
            c.harness = harness;
            c.live = false;
            c.stopped = false;
        }
    }

    /// A chat's `run.stop`: its screen, its waiting messages and the session
    /// grants it holds end (P-C7); its project stays for the records that
    /// follow.
    pub fn forget_chat(&self, chat: &str) {
        let (ended, harness) = {
            let mut g = self.lock();
            if let Some(c) = g.chats.get_mut(chat) {
                c.stopped = true;
                c.live = false;
            }
            g.inbox.remove(chat);
            g.screens.remove(chat);
            let ended: Vec<(String, String, String)> =
                g.grants.iter().filter(|x| x.0 == chat).cloned().collect();
            g.grants.retain(|x| x.0 != chat);
            let harness = g
                .chats
                .get(chat)
                .map(|c| c.harness.clone())
                .unwrap_or_default();
            (ended, harness)
        };
        for (c, from, to) in ended {
            self.record(
                &c,
                &harness,
                &from,
                kinds::GRANT,
                format!("project.grant ended: chat {c}, project {from} to {to}"),
                json!({"from": from, "to": to, "chat": c, "until": "session", "ended": true}),
            );
        }
    }
}
