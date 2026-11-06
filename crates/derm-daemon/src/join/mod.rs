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
//! 1. **Tree.** A shell the harness starts while exactly one shell call is
//!    running belongs to that call, and so do its descendants; with several
//!    shell calls, to them together, none chosen. The harness is `run.start`'s
//!    pid, or, under a boundary or the agents' user, the process under its
//!    wrappers that execs the program `derm run` started (`harnessExe`,
//!    MW5-16). Until that process is seen, a shell any process under the
//!    wrappers starts is a candidate of the shell calls running, none chosen
//!    (review FP3-S2).
//! 2. **Path.** A write to a path exactly one running call names is that
//!    call's; several calls naming it make a candidate set.
//! 3. **MCP server.** A child the harness started while no call ran (a stdio
//!    MCP server, started with the session) is credited, for each effect, to
//!    every MCP call (`server/tool`) running then (`by: "mcp-server"`).
//! 4. **Window.** Otherwise every call running at the effect's time.
//!
//! `chosen` names a call only when the tree or a path picks exactly one.
//! An effect no running call fits gets no record. Memory is bounded per chat
//! and in chats; a chat is kept `STOPPED_KEEP_MS` after its `run.stop` for
//! effects the OS feed delivers late (MW5-17), then dropped.

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
/// How long a stopped chat's calls are kept for effects that reach the
/// daemon after its `run.stop` (Mac test w5 retest 2, MW5-17: the Mac's OS
/// events arrived 2 to 8 s late, 7 to 17 s after a burst), by the daemon's
/// own clock (`Event::at` of what arrives).
pub const STOPPED_KEEP_MS: i64 = 30_000;
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
    /// A shell a process under a boundary's wrappers started while these
    /// shell calls ran, before the harness was found by its executable:
    /// derm cannot tell the harness from a helper it started there, so each
    /// call is a candidate and none is chosen (review FP3-S2, re-review R1).
    Unplaced(std::sync::Arc<[String]>),
}

#[derive(Default)]
struct ChatState {
    cwd: Option<String>,
    root_pid: Option<u32>,
    /// Whether the run's root is a wrapper rather than the harness: under a
    /// boundary (`run.start`'s `boundary` other than `none`) or the agents'
    /// user (`agentUser`). With no boundary the root is the harness.
    line_on: bool,
    /// The processes between the run's root and the harness, and the
    /// harness (Mac test w5 retest 2, MW5-16): under srt, `run.start`'s pid is
    /// srt's own, then its wrappers (`sandbox-exec`, `bwrap`, a shell's `-c`,
    /// `env`), and the harness under them; under the agents' user, `sudo`.
    /// Every process started from one of these while no call runs joins
    /// them until the harness is found, at most `MAX_PIDS` (review FP3-S4).
    line: std::collections::HashSet<u32>,
    /// The harness's executable as `derm run` resolved it (`harnessExe`).
    harness_exe: Option<String>,
    /// The line process that exec'd `harness_exe`; from then on only it
    /// (and the root) places children. Never learned from what a process
    /// does: an MCP server started with the session is a line process too,
    /// and a chat token can post a call for any shell it starts (FP3-S2).
    harness: Option<u32>,
    /// When the chat's `run.stop` arrived (daemon time); its state is kept
    /// `STOPPED_KEEP_MS` after it (MW5-17).
    stopped_at: Option<i64>,
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
/// A program a boundary or a launcher runs between the run's root and the
/// harness, by file name: never the harness's own executable.
fn wrapper_program(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "env"
            | "sandbox-exec"
            | "bwrap"
            | "sudo"
            | "sudo-rs"
            | "doas"
            | "su"
            | "runuser"
            | "setpriv"
            | "unshare"
            | "nsenter"
            | "nice"
            | "nohup"
            | "timeout"
            | "stdbuf"
            | "script"
            | "socat"
            | "apply-seccomp"
    )
}

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

    /// Drops a chat's state.
    pub fn forget(&mut self, chat: &str) {
        self.chats.remove(chat);
    }

    /// Drops the chats stopped longer than `STOPPED_KEEP_MS` before `now`.
    fn sweep(&mut self, now: i64) {
        self.chats
            .retain(|_, st| st.stopped_at.is_none_or(|s| now - s <= STOPPED_KEEP_MS));
    }

    fn chat(&mut self, chat: &str) -> &mut ChatState {
        if !self.chats.contains_key(chat) && self.chats.len() >= MAX_CHATS {
            // A stopped chat goes first, then any.
            let k = self
                .chats
                .iter()
                .find(|(_, st)| st.stopped_at.is_some())
                .map(|(k, _)| k.clone())
                .or_else(|| self.chats.keys().next().cloned());
            if let Some(k) = k {
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
        self.sweep(e.at);
        match (&e.source, e.kind.as_str()) {
            (Source::Run, "run.start") => {
                // A chat id started again begins afresh.
                self.forget(&e.chat_id);
                let st = self.chat(&e.chat_id);
                st.cwd = str_at(&e.detail, "cwd").map(str::to_string);
                st.root_pid = e.pid;
                let boundary = str_at(&e.detail, "boundary");
                st.line_on = boundary.is_some_and(|b| b != "none")
                    || e.detail.get("agentUser").is_some_and(|v| !v.is_null());
                if st.line_on {
                    st.line.extend(e.pid);
                    // A shell or a wrapper program names no harness: srt's
                    // own `bash -c` and its wrappers exec those before the
                    // harness (second re-review S1), so the harness stays
                    // not found and its shells are candidates.
                    st.harness_exe = str_at(&e.detail, "harnessExe")
                        .filter(|p| p.starts_with('/') && p.len() <= 4096)
                        .filter(|p| !shell_program(p) && !wrapper_program(p))
                        .map(str::to_string);
                }
                Vec::new()
            }
            (Source::Run, "run.stop") => {
                // Kept a while for effects that arrive after it (MW5-17); a
                // chat no record ever named is not made here.
                if let Some(st) = self.chats.get_mut(&e.chat_id) {
                    st.stopped_at.get_or_insert(e.at);
                }
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
                let program = str_at(&e.detail, "exe").or_else(|| str_at(&e.detail, "comm"));
                // MW5-16: under a boundary the processes between the run's
                // root and the harness place children as the root does.
                // Until the harness is found, anything a line process starts
                // while no call runs joins the line (a wrapper, the harness,
                // or a helper started with the session). The harness is the
                // line process that execs the program `derm run` started
                // (`harnessExe`); from then on only the root and the harness
                // place children, so an MCP server started with the session
                // keeps its children the session's (BW5-11). Until then a
                // line process's shell is a candidate of the shell calls
                // running, never chosen: derm cannot tell the harness from a
                // helper it started (review FP3-S2).
                let line_place = |st: &ChatState, p: u32| {
                    st.line_on && st.harness.is_none() && st.line.contains(&p)
                };
                if kind == "exec"
                    && Some(child) != st.root_pid
                    && line_place(st, child)
                    && st.harness_exe.is_some()
                    && program == st.harness_exe.as_deref()
                {
                    st.harness = Some(child);
                    st.line.clear();
                }
                let by_root =
                    parent.is_some_and(|p| Some(p) == st.root_pid || Some(p) == st.harness);
                let by_line = !by_root && parent.is_some_and(|p| line_place(st, p));
                let places = by_root || by_line;
                if places
                    && st.line_on
                    && st.harness.is_none()
                    && st.running(t).is_empty()
                    && st.line.len() < MAX_PIDS
                {
                    st.line.insert(child);
                }
                let inherited = if places {
                    None
                } else {
                    parent.and_then(|p| st.owners.get(&p).cloned())
                };
                let owner = match inherited {
                    Some(o) => Some(o),
                    None if places => {
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
                                _ if by_line => Some(Owner::Unplaced(shells.into())),
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
        let owner = pid.and_then(|p| st.owners.get(&p).cloned());
        // A process a call's tree owns is that call's after the call's
        // window closes too, so a chat token's early "it ran" for a running
        // install cannot drop its own shell's later writes (second
        // re-review S3); with no tree owner, no call running fits none.
        let tree_owned = matches!(
            owner,
            Some(Owner::Call(_)) | Some(Owner::Among(_)) | Some(Owner::Unplaced(_))
        );
        if running.is_empty() && !tree_owned {
            return Vec::new();
        }
        let mut candidates: Vec<(String, &'static str, String)> = Vec::new();
        let mut chosen: Option<String> = None;
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
        if let Some(Owner::Unplaced(ids)) = &owner {
            for c in ids.iter().filter_map(|id| st.calls.get(id)) {
                candidates.push((
                    c.event.clone(),
                    "tree",
                    "a shell a process under the boundary started while this call ran (the harness was not found there)".into(),
                ));
            }
        }
        // 2. Path. With tree candidates (a shell several calls, or calls
        // under a boundary, may own), a call naming the path joins them and
        // is not chosen: the kernel says which process wrote, and a Read the
        // model runs beside an install must not take the install's write
        // (second re-review S2).
        let tree_set = !candidates.is_empty();
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
            if named.len() == 1 && !tree_set {
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
        let mut detail = json!({
            "trust": "daemon",
            "effect": e.id,
            "effectKind": kind,
            "candidates": candidates
                .iter()
                .map(|(call, by, why)| json!({"call": call, "by": by, "why": why}))
                .collect::<Vec<_>>(),
            "chosen": chosen,
        });
        // Under a boundary with the harness not found by its executable:
        // the tree candidates are every shell call running then.
        if matches!(owner, Some(Owner::Unplaced(_))) {
            detail["harnessFound"] = json!(false);
        }
        vec![Event {
            id: format!("join-{}", e.id),
            at: e.at,
            chat_id: e.chat_id.clone(),
            harness: e.harness.clone(),
            source: Source::Derm,
            kind: "join.candidates".into(),
            summary,
            detail,
            pid: e.pid,
            approval_id: None,
        }]
    }
}

#[cfg(test)]
mod tests;
