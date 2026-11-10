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
//!   its `tool.call` record (the call ran; it ends). A chat token can post
//!   these for any call id it reads from its own tail (case 66), so they
//!   never move a call's start later, a deny never ends it before its start,
//!   and a code tool call takes its times from the tap alone (fix pass 6,
//!   FP5R-3, FP5R-4);
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
//!    shell calls, to them together, none chosen. With no shell call running,
//!    a harness's code tool call takes the shell's place (MW5-27): one running
//!    then, or one whose cell may still run after its result (fix pass 6,
//!    FP5R-1, FP5R-2: Codex's Code Mode `exec` can yield and leave its cell
//!    running; the tap reads the result's header). One cell's calls choose
//!    the one running, else the first; calls that may be different cells
//!    share it, none chosen. The harness is `run.start`'s
//!    pid, or, under a boundary or the agents' user, the process under its
//!    wrappers that execs the program `derm run` started (`harnessExe`,
//!    MW5-16). Until that process is seen, a shell any process under the
//!    wrappers starts is a candidate of the shell calls running, none chosen
//!    (review FP3-S2). Where a launcher starts the harness as its child
//!    (Codex 0.163.0's npm launcher), the child that execs the binary
//!    `derm run` named (`harnessChildExe`) while no call runs places shells
//!    too (MW5-28). A sandbox the harness runs a command in (`sandbox-exec`,
//!    `bwrap`, or its own binary run again, Codex's Linux helper) is placed
//!    by what it runs, as of when the harness started it (MW5-29).
//!    Only for `WRAP_MS` after that start, and the harness's own binary only
//!    when it is no interpreter (fix pass 7's review, FP7-S1, FP7-S4). A fork
//!    that names the launched harness's or the harness's pid later than it
//!    was learned ends that role (FP7-S2).
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
pub(crate) use derm_core::policy::code_tool;
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

/// Harnesses whose gate `allow` only means "not blocked": their own
/// approval prompt still runs after it (rules case 72), so the person's
/// answer reaches no derm record (re-review of fix pass 6, FP6R2-1).
const ALLOW_LEAVES_PROMPT: &[&str] = &["codex", "gemini", "qwen-code", "grok"];
/// How long a stopped chat's calls are kept for effects that reach the
/// daemon after its `run.stop` (Mac test w5 retest 2, MW5-17: the Mac's OS
/// events arrived 2 to 8 s late, 7 to 17 s after a burst), by the daemon's
/// own clock (`Event::at` of what arrives).
pub const STOPPED_KEEP_MS: i64 = 30_000;

/// The longest a stopped chat waits for an OS feed that is behind (Mac test
/// w5 retest 9, MW5-34): past `STOPPED_KEEP_MS` a stopped chat is kept until
/// the feed has delivered an event the OS stamped after the chat's stop, or
/// this long after the stop, whichever comes first. What still comes after
/// that is counted and named (`late_for`).
pub const STOPPED_FEED_CAP_MS: i64 = 600_000;

/// How many dropped chats' late counts are kept.
const MAX_LATE: usize = 256;

/// Why the join let a stopped chat go (fix pass 11's review, FP11-S2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LetGo {
    /// The OS feed had passed the stop: what still comes was done after it.
    FeedPassed,
    /// The wait for a feed that was behind ran out (`STOPPED_FEED_CAP_MS`).
    Capped,
}

/// A chat the join let go, why, and how many of its OS events came after.
#[derive(Clone, Debug)]
struct Gone {
    chat: String,
    why: LetGo,
    late: u64,
}

/// Whether a chat stopped at `stopped` (daemon time) is still kept at `now`
/// (daemon time), when the OS feeds have delivered events stamped up to
/// `os_seen` (the OS's time). MW5-34: a 30 s keep by the daemon's clock lost
/// the effects of a chat whose feed was 40 s behind.
pub fn keep_stopped(stopped: i64, now: i64, os_seen: i64) -> bool {
    keep_why(stopped, now, os_seen).is_none()
}

/// None while a stopped chat is kept; else why it is let go.
pub fn keep_why(stopped: i64, now: i64, os_seen: i64) -> Option<LetGo> {
    let waited = now - stopped;
    if waited <= STOPPED_KEEP_MS {
        return None;
    }
    if os_seen > stopped + SLACK_AFTER_MS {
        return Some(LetGo::FeedPassed);
    }
    (waited > STOPPED_FEED_CAP_MS).then_some(LetGo::Capped)
}

/// The OS's own time of an OS feed's event, for the feed's progress; None
/// for any other source.
pub fn os_feed_time(e: &Event) -> Option<i64> {
    matches!(e.source, Source::Auditd | Source::Eslogger).then(|| effect_time(e))
}

/// The feed's progress from one event: its OS time, unless it is ahead of
/// the daemon's clock by more than the slack (fix pass 11's review,
/// FP11-S4: one event stamped in the future, a clock step, moved the
/// running maximum for good and turned MW5-34's wait off for every later
/// chat). OS feeds run on the daemon's host, so their clocks are one.
///
/// A feed's own `feed.gap` is no OS event: it carries no OS time, and its
/// `at` is when it was posted, before the feed reads what it fell behind on
/// (fp13's review, FP13R-5).
pub fn feed_progress(e: &Event) -> Option<i64> {
    if e.kind == "feed.gap" {
        return None;
    }
    os_feed_time(e).filter(|t| *t <= e.at + SLACK_AFTER_MS)
}
/// How far before a call's recorded start an effect may fall (the OS feed
/// and the hook each stamp with some delay).
pub const SLACK_BEFORE_MS: i64 = 500;
/// How far after a call's recorded end.
pub const SLACK_AFTER_MS: i64 = 2_000;
/// How far after the tap's result a new process may still be placed on a
/// call (box test w5 retest, BW5R-7). The result reaches the tap only after
/// the call's command ended, so a shell the harness starts later is a hook's
/// or a helper's, not the call's; this covers the two clocks only (the tap
/// stamps with the daemon's, the OS feed with the kernel's, on one host).
pub const TAP_END_SLACK_MS: i64 = 250;

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
    /// A harness's code tool, which runs shells through nested calls
    /// (`derm_core::policy::CODE_TOOLS`). Only the tap's record marks one.
    code: bool,
    /// The tap's result ended the call (`end` is the tap's).
    tap_ended: bool,
    /// When the tap's result came, apart from `end`, which a gate record a
    /// chat token posts can move earlier (review FP9-S3).
    tap_end: Option<i64>,
    /// A gate's `allow` was seen.
    allowed: bool,
    /// The tap recorded the call, so its result will end it.
    tapped: bool,
    /// A record says the call's gate records cannot be taken at their word:
    /// a gate decision `ask` (the harness's own prompt, whose answer no derm
    /// record carries) or a conflict copy naming the call (re-review of fix
    /// pass 6, FP6R-1, FP6R-2).
    contested: bool,
    /// For a contested tapped call, the earliest end a gate record posted:
    /// the call stays open until the tap's result, and a shell started after
    /// this is a candidate of the call, never chosen (`Owner::Posted`).
    posted_end: Option<i64>,
    /// A code call's cell (Codex's cell id, from `wait`'s arguments or its
    /// result's header), when the tap read one.
    cell: Option<String>,
    /// A code call's result, as the tap read its header: whether its cell
    /// may still run after it.
    result: Option<CodeResult>,
}

/// What a code call's result says of its cell (`tap.call`'s `codeStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodeResult {
    /// The cell yielded and keeps running (Codex's `Script running with cell
    /// ID <id>`): its shells can start after the call ends.
    Running,
    /// The cell completed, failed or was terminated.
    Ended,
    /// No header the tap could read: taken as running (fails safe toward
    /// more candidates, never toward none).
    Unknown,
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

    /// Whether a process the harness starts at `t` may be placed on this
    /// call: while it runs, but not after the tap's result beyond
    /// `TAP_END_SLACK_MS` (BW5R-7), by the tap's own time, never an end a
    /// gate record set (FP9-S3). A code call whose cell may still run is
    /// still an owner after its result (`ChatState::code_owners`).
    fn places_at(&self, t: i64) -> bool {
        self.running_at(t) && !self.tap_end.is_some_and(|e| t > e + TAP_END_SLACK_MS)
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
    /// A shell started with no shell call running while these code calls'
    /// cells may have run, more than one cell among them: each may own it,
    /// none is chosen (fix pass 6, FP5R-1).
    Cells(std::sync::Arc<[String]>),
    /// A shell started while these shell calls ran: each may own it, none
    /// is chosen (fix pass 1's review, F1). Shared, since every descendant
    /// holds it (re-review: at most 64 ids, up to 8,192 processes a chat).
    Among(std::sync::Arc<[String]>),
    /// A shell a process under a boundary's wrappers started while these
    /// shell calls ran, before the harness was found by its executable:
    /// derm cannot tell the harness from a helper it started there, so each
    /// call is a candidate and none is chosen (review FP3-S2, re-review R1).
    Unplaced(std::sync::Arc<[String]>),
    /// A shell started while this contested shell call ran, after a gate
    /// record said it ended and before the tap's result: the end may be a
    /// chat token's, so the call is a candidate and is not chosen (re-review
    /// of fix pass 6, FP6R-1, FP6R-2).
    Posted(String),
    /// A sandbox wrapper the harness started at this time while a call ran
    /// (`ChatState::sandbox_launcher`): what it runs is placed at its exec as
    /// the harness's own child would have been then (Mac test w5 retest 6,
    /// MW5-29). Its own effects fit by path and window, as `Ambiguous`.
    Wrapped(i64),
    /// The harness's own executable (never an interpreter) started again at
    /// this time while a call ran (Codex's Linux sandbox helper): its own next
    /// exec is placed as a wrapper's would be (`bwrap`, then the shell); its
    /// children are `Spawned`.
    Pending(i64),
    /// A child a `Pending` process forked (Codex's outer stage forks `bwrap`
    /// when the sandbox has protected-create targets, review FP7-S4): only a
    /// sandbox wrapper at its exec is placed, as of that time; anything else
    /// is `Ambiguous`.
    Spawned(i64),
}

/// How long after the harness starts a sandbox wrapper (or its own binary)
/// the processes under it are still placed as of that time (review FP7-S1):
/// the launch is a chain of execs in milliseconds (`sandbox-exec` then the
/// shell; Codex's helper, `bwrap`, its pid 1's fork, the helper again, the
/// shell's fork). An exec later than this under one is no launch: `Ambiguous`.
pub const WRAP_MS: i64 = 5_000;

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
    /// The binary a launcher starts as the harness, as `derm run` resolved it
    /// (`harnessChildExe`, MW5-28), until a child of the root or the harness
    /// execs it while no call runs, or the root or the harness execs it
    /// itself; then `None`.
    harness_child: Option<String>,
    /// That child: it places children as the root does.
    launched: Option<u32>,
    /// The OS time `launched` and `harness` were learned at: a later fork
    /// that names either pid is a new process, and the role goes (review
    /// FP7-S2); an earlier one is its own fork, delivered late (T1).
    launched_at: i64,
    harness_at: i64,
    /// The harness's own executables (`harnessExe`, `harnessChildExe`): a
    /// child that runs one again while a call runs is a command launcher
    /// (MW5-29), whatever the boundary.
    own_exes: Vec<String>,
    /// When the chat's `run.stop` arrived (daemon time); its state is kept
    /// `STOPPED_KEEP_MS` after it (MW5-17).
    stopped_at: Option<i64>,
    calls: HashMap<String, Call>,
    order: VecDeque<String>,
    owners: HashMap<u32, Owner>,
    owner_order: VecDeque<u32>,
    /// The OS time each owner was set at, so a fork clears only what an
    /// earlier process held (T1), not its own child's exec that the feed
    /// delivered first.
    owned_at: HashMap<u32, i64>,
    /// Processes the harness itself started (its fork or exec names the root,
    /// the harness found under the wrappers, or the launched harness as the
    /// parent), at most `MAX_PIDS`, with whether its one exec so far was a
    /// shell: a write such a shell makes may be the harness's own, such as
    /// Claude Code's shell snapshot (BW5R-2), or the call's command line's
    /// own redirection, so it is marked, never trusted (review FP9-S1). When
    /// full, none is added.
    direct: HashMap<u32, (Direct, i64)>,
}

/// A process the harness itself started, by what it has run (BW5R-2,
/// reviews FP9-S1 and FP9R-1), with the OS time that was set at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direct {
    /// Forked, nothing run yet.
    Forked,
    /// Its one exec so far is a shell.
    Shell,
    /// It ran something else, or a second program: a command, until a new
    /// fork from the harness starts the pid over.
    Spent,
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

    fn own(&mut self, pid: u32, owner: Owner, at: i64) {
        if !self.owners.contains_key(&pid) {
            self.owner_order.push_back(pid);
            while self.owner_order.len() > MAX_PIDS {
                if let Some(old) = self.owner_order.pop_front() {
                    self.owners.remove(&old);
                    self.owned_at.remove(&old);
                }
            }
        }
        self.owners.insert(pid, owner);
        self.owned_at.insert(pid, at);
    }

    /// Forgets what a pid held before `at`, for a new process forked under
    /// it then.
    fn disown(&mut self, pid: u32, at: i64) {
        if self.owned_at.get(&pid).is_some_and(|set| *set < at) {
            self.owners.remove(&pid);
            self.owned_at.remove(&pid);
            self.owner_order.retain(|p| *p != pid);
            self.line.remove(&pid);
            self.direct.remove(&pid);
        }
    }

    /// The calls a process the harness starts at `t` may be placed on
    /// (`Call::places_at`).
    fn placing(&self, t: i64) -> Vec<(&String, &Call)> {
        let mut v: Vec<(&String, &Call)> = self
            .order
            .iter()
            .filter_map(|id| self.calls.get(id).map(|c| (id, c)))
            .filter(|(_, c)| c.places_at(t))
            .collect();
        v.truncate(MAX_CANDIDATES);
        v
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

    /// The code calls whose cell may run at `t`, and the one chosen when
    /// they are all one cell (fix pass 6, FP5R-1, FP5R-2). A code call
    /// counts while it runs, and after its result while that result says
    /// its cell keeps running (or the tap read no header), until a later
    /// call on the same cell says it ended. Calls on one known cell choose
    /// the one running then, else the first; calls that may be different
    /// cells choose none.
    fn code_owners(&self, t: i64) -> (Vec<String>, Option<String>) {
        // One pass over the calls: the code calls running or whose cell may
        // run, and per cell the ended results seen by `t`. Then each open
        // call is checked against its own cell's ends by a binary search, so
        // a chat with thousands of yielded cells costs O(n log n) per event,
        // not O(n^2) (fix pass 6's review, FP6-S3).
        let mut live: Vec<(&String, &Call, bool)> = Vec::new();
        let mut ends: HashMap<&str, Vec<(i64, i64)>> = HashMap::new();
        for (id, c) in self
            .order
            .iter()
            .filter_map(|id| self.calls.get(id).map(|c| (id, c)))
            .filter(|(_, c)| c.code)
        {
            if let (Some(cell), Some(CodeResult::Ended), Some(s), Some(e)) =
                (&c.cell, c.result, c.start, c.end)
            {
                if e <= t {
                    ends.entry(cell.as_str()).or_default().push((s, e));
                }
            }
            if c.places_at(t) {
                live.push((id, c, true));
                continue;
            }
            let after = c.end.is_some_and(|e| e <= t);
            let open = matches!(c.result, Some(CodeResult::Running | CodeResult::Unknown));
            if after && open {
                live.push((id, c, false));
            }
        }
        // Per cell: ends sorted by start, with the earliest end from each
        // start on, so "an end on this cell that started at or after `from`
        // and came by `t`" is one search.
        let index: HashMap<&str, (Vec<i64>, Vec<i64>)> = ends
            .into_iter()
            .map(|(cell, mut v)| {
                v.sort_unstable();
                let starts: Vec<i64> = v.iter().map(|(s, _)| *s).collect();
                let mut min_end: Vec<i64> = v.iter().map(|(_, e)| *e).collect();
                for i in (0..min_end.len().saturating_sub(1)).rev() {
                    min_end[i] = min_end[i].min(min_end[i + 1]);
                }
                (cell, (starts, min_end))
            })
            .collect();
        let closed = |c: &Call| -> bool {
            let (Some(cell), Some(from)) = (&c.cell, c.start) else {
                return false;
            };
            let Some((starts, min_end)) = index.get(cell.as_str()) else {
                return false;
            };
            let i = starts.partition_point(|s| *s < from);
            i < starts.len() && min_end[i] <= t
        };
        let mut live: Vec<(&String, &Call)> = live
            .into_iter()
            .filter(|(_, c, running)| *running || !closed(c))
            .map(|(id, c, _)| (id, c))
            .collect();
        live.truncate(MAX_CANDIDATES);
        let key = |(id, c): &(&String, &Call)| match &c.cell {
            Some(cell) => format!("cell:{cell}"),
            None => format!("call:{id}"),
        };
        let one_cell = live
            .first()
            .is_some_and(|first| live.iter().all(|x| key(x) == key(first)));
        let chosen = one_cell.then(|| {
            let running: Vec<&String> = live
                .iter()
                .filter(|(_, c)| c.places_at(t))
                .map(|(id, _)| *id)
                .collect();
            match running.as_slice() {
                [only] => (*only).clone(),
                _ => live[0].0.clone(),
            }
        });
        (live.iter().map(|(id, _)| id.to_string()).collect(), chosen)
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

    /// A fork at `at` that names `pid` starts a new process: if the launched
    /// harness or the harness found under the wrappers had that pid before
    /// `at`, it has exited and its role goes with it (review FP7-S2: a process
    /// of a call's tree that got the pid again placed children by time).
    fn drop_roles(&mut self, pid: u32, at: i64) {
        if self.launched == Some(pid) && self.launched_at < at {
            self.launched = None;
        }
        if self.harness == Some(pid) && self.harness_at < at {
            self.harness = None;
        }
    }

    /// Forgets a pid's owner and its place in the line.
    fn forget_pid(&mut self, pid: u32) {
        self.owners.remove(&pid);
        self.owned_at.remove(&pid);
        self.owner_order.retain(|p| *p != pid);
        self.line.remove(&pid);
        self.direct.remove(&pid);
    }

    /// Whether `child`, exec'ing `program` at `t`, is the program a launcher
    /// starts as the harness (Mac test w5 retest 6, MW5-28): Codex 0.163.0's
    /// npm launcher spawns its native binary as a child (`@openai/codex`
    /// `bin/codex.js:241`), so the run's root (or, under a boundary, the
    /// process that exec'd `harnessExe`) is node and the harness is its child.
    /// Named, never learned (case 177): only the binary `derm run` resolved
    /// (`harnessChildExe`), only once, only for a child of the root (with no
    /// boundary) or of the harness found under the wrappers, and only when
    /// that child started while no call ran. When the root or the harness
    /// itself execs it (0.167.0's launcher replaces node, `bin/codex.js:236-243`),
    /// the handoff is spent: the harness is already the one placing.
    fn hand_off(&mut self, child: u32, parent: Option<u32>, program: Option<&str>, t: i64) -> bool {
        if self.harness_child.is_none() || program != self.harness_child.as_deref() {
            return false;
        }
        if [self.root_pid, self.harness, self.launched].contains(&Some(child)) {
            self.harness_child = None;
            return false;
        }
        let placer = parent.is_some_and(|p| {
            (!self.line_on && Some(p) == self.root_pid) || Some(p) == self.harness
        });
        let started_idle = match self.owners.get(&child) {
            Some(Owner::Session) => true,
            None => self.placing(t).is_empty() && self.code_owners(t).0.is_empty(),
            _ => false,
        };
        if !(placer && started_idle) {
            return false;
        }
        self.launched = Some(child);
        self.launched_at = t;
        self.harness_child = None;
        self.forget_pid(child);
        true
    }

    /// Places a process a fork or exec names (`child`, started or run by
    /// `parent`), as the module's header says.
    /// Whether the join has placed this pid in the chat's tree: the root,
    /// the harness or the launched child, a process between the root and the
    /// harness, or one the tree gave an owner or marked as the root's child.
    fn knows(&self, pid: u32) -> bool {
        Some(pid) == self.root_pid
            || Some(pid) == self.harness
            || Some(pid) == self.launched
            || self.line.contains(&pid)
            || self.owners.contains_key(&pid)
            || self.direct.contains_key(&pid)
    }

    fn place_child(
        &mut self,
        kind: &str,
        child: u32,
        parent: Option<u32>,
        program: Option<&str>,
        t: i64,
    ) {
        // MW5-16: under a boundary the processes between the run's root and
        // the harness place children as the root does. Until the harness is
        // found, anything a line process starts while no call runs joins the
        // line (a wrapper, the harness, or a helper started with the
        // session). The harness is the line process that execs the program
        // `derm run` started (`harnessExe`); from then on only the root and
        // the harness place children, so an MCP server started with the
        // session keeps its children the session's (BW5-11). Until then a
        // line process's shell is a candidate of the shell calls running,
        // never chosen: derm cannot tell the harness from a helper it started
        // (review FP3-S2).
        let line_place =
            |st: &ChatState, p: u32| st.line_on && st.harness.is_none() && st.line.contains(&p);
        if kind == "exec"
            && Some(child) != self.root_pid
            && line_place(self, child)
            && self.harness_exe.is_some()
            && program == self.harness_exe.as_deref()
        {
            self.harness = Some(child);
            self.harness_at = t;
            self.line.clear();
        }
        // The launched harness's own fork, delivered after its exec (T1): it
        // has no owner (review FP7-S3).
        if kind == "fork" && Some(child) == self.launched {
            return;
        }
        let held = self.owners.get(&child).cloned();
        let by_root = parent.is_some_and(|p| {
            Some(p) == self.root_pid || Some(p) == self.harness || Some(p) == self.launched
        });
        let by_line = !by_root && parent.is_some_and(|p| line_place(self, p));
        // The harness's own child, or no longer one (a fork or an exec under
        // another parent, or with none named, is another process's): BW5R-2.
        // Only a child whose one exec is a shell keeps the mark: bash runs a
        // lone command in its own pid (`bash -lc "pip install x"` execs pip
        // there, run with bash 5.2), so a second exec, or a first one that is
        // no shell, is a command the call ran (review FP9-S1, FP9-S8).
        match (by_root, kind) {
            (true, "fork") => {
                // A fork delivered after its child's exec keeps what that exec
                // set (T1; review FP9R-3).
                let later_exec = self
                    .direct
                    .get(&child)
                    .is_some_and(|(d, at)| *d != Direct::Forked && *at >= t);
                if !later_exec && (self.direct.len() < MAX_PIDS || self.direct.contains_key(&child))
                {
                    self.direct.insert(child, (Direct::Forked, t));
                }
            }
            (true, "exec") => {
                let shell = program
                    .is_some_and(|p| shell_program(p) && !p.ends_with("/codex-linux-sandbox"));
                let next = match self.direct.get(&child).map(|(d, _)| *d) {
                    None | Some(Direct::Forked) if shell => Direct::Shell,
                    _ => Direct::Spent,
                };
                if self.direct.len() < MAX_PIDS || self.direct.contains_key(&child) {
                    self.direct.insert(child, (next, t));
                }
            }
            _ => {
                self.direct.remove(&child);
            }
        }
        // What a child of the harness's own binary run again inherits is no
        // decision: only a sandbox wrapper at its exec is (`Spawned`).
        let inherited = if by_root || by_line {
            None
        } else {
            parent
                .and_then(|p| self.owners.get(&p).cloned())
                .map(|o| match o {
                    Owner::Pending(t0) => Owner::Spawned(t0),
                    o => o,
                })
        };
        // A process a harness's sandbox wrapper runs (MW5-29) is placed as
        // the harness's own child, by when the harness started the wrapper:
        // the wrapper itself when it execs again (`sandbox-exec` then `zsh`
        // in one pid), and a wrapper's children at their exec (`bwrap`'s
        // pid 1's child). The harness's own binary run again decides at its
        // own next exec (Codex's Linux helper then execs `bwrap`) and its
        // children's (it forks `bwrap`). Only within `WRAP_MS` of that start
        // (review FP7-S1): later, the process is `Ambiguous`.
        let deferred = match (kind, &held, &inherited) {
            ("exec", Some(o @ (Owner::Wrapped(_) | Owner::Pending(_) | Owner::Spawned(_))), _)
            | (_, None, Some(o @ (Owner::Wrapped(_) | Owner::Spawned(_)))) => Some(o.clone()),
            _ => None,
        };
        let since = |o: &Owner| match o {
            Owner::Wrapped(t0) | Owner::Pending(t0) | Owner::Spawned(t0) => *t0,
            _ => t,
        };
        if deferred.as_ref().is_some_and(|o| t - since(o) > WRAP_MS) {
            self.own(child, Owner::Ambiguous, t);
            return;
        }
        let wrapped = deferred.as_ref().filter(|_| kind == "exec").map(since);
        // Under a sandbox the harness started, its own binary is the
        // sandbox's inner stage (Codex's `--apply-seccomp-then-exec`, which
        // forks the command, `linux-sandbox/src/linux_run_main.rs:247-256`):
        // still a wrapper. A `Spawned` process that runs no sandbox wrapper
        // is no launch.
        let in_sandbox = matches!(deferred, Some(Owner::Wrapped(_)));
        let spawned = matches!(deferred, Some(Owner::Spawned(_)));
        if kind == "exec" && spawned && !program.is_some_and(sandbox_wrapper) {
            self.own(child, Owner::Ambiguous, t);
            return;
        }
        let places = by_root || by_line || wrapped.is_some();
        let at = wrapped.unwrap_or(t);
        // What may own a child placed now: the calls running, and, with no
        // shell call among them, the code calls whose cell may run (FP5R-1,
        // FP5R-2).
        let (cells, cell_chosen) = if places {
            self.code_owners(at)
        } else {
            (Vec::new(), None)
        };
        let idle = self.placing(at).is_empty() && cells.is_empty();
        if places
            && wrapped.is_none()
            && self.line_on
            && self.harness.is_none()
            && idle
            && self.line.len() < MAX_PIDS
        {
            self.line.insert(child);
        }
        let owner = match inherited {
            Some(o) if wrapped.is_none() => Some(o),
            _ if places => {
                // A child of the harness while a call runs belongs to that
                // call only with certainty (case 43): a shell started for a
                // shell call. The harness also starts its own helpers then,
                // such as MCP servers, which are no call's (box test w5,
                // BW5-11). At the fork the program is not known yet, so its
                // exec decides; a sandbox wrapper the harness runs a command
                // through defers it to what the wrapper runs (MW5-29). A shell
                // while several shell calls run is theirs together, so one
                // more call open (a parallel one, or an approval posted with
                // no call after it) does not take its writes from every
                // install (review F1). A shell call running is the shell's
                // owner; with none, a code tool call is (its nested shell,
                // MW5-27), running then or with its cell possibly still
                // running after its result (FP5R-1, FP5R-2): a nested call
                // the gate reports as a shell call is the more precise of the
                // two.
                let running = self.placing(at);
                let shells: Vec<String> = running
                    .iter()
                    .filter(|(_, c)| c.shell())
                    .map(|(id, _)| id.to_string())
                    .collect();
                let shell = program.is_some_and(shell_program);
                if idle {
                    Some(Owner::Session)
                } else if kind == "fork" {
                    None
                } else if !by_line && program.is_some_and(sandbox_wrapper) {
                    Some(Owner::Wrapped(at))
                } else if !by_line && program.is_some_and(|p| self.own_exes.iter().any(|x| x == p))
                {
                    if in_sandbox {
                        Some(Owner::Wrapped(at))
                    } else {
                        Some(Owner::Pending(at))
                    }
                } else if shell && !shells.is_empty() {
                    if by_line {
                        Some(Owner::Unplaced(shells.into()))
                    } else if shells.len() == 1 {
                        let posted = self
                            .calls
                            .get(&shells[0])
                            .and_then(|c| c.posted_end)
                            .is_some_and(|p| p < at);
                        if posted {
                            Some(Owner::Posted(shells[0].clone()))
                        } else {
                            Some(Owner::Call(shells[0].clone()))
                        }
                    } else {
                        Some(Owner::Among(shells.into()))
                    }
                } else if shell && !cells.is_empty() {
                    if by_line {
                        Some(Owner::Unplaced(cells.into()))
                    } else if let Some(id) = cell_chosen {
                        Some(Owner::Call(id))
                    } else {
                        Some(Owner::Cells(cells.into()))
                    }
                } else if running.is_empty() {
                    // A helper the harness starts while only a cell may run,
                    // such as an MCP server: the session's.
                    Some(Owner::Session)
                } else {
                    Some(Owner::Ambiguous)
                }
            }
            _ => None,
        };
        if let Some(o) = owner {
            // An exec keeps the owner its fork or first exec set, but for a
            // wrapper's, which its next exec decides. A fork keeps what the
            // child's own exec set when the feed delivered that first (T1;
            // `disown` left only an owner set at or after the fork): review
            // FP7-S5.
            let exec_keeps = kind == "exec" && held.is_some() && wrapped.is_none();
            let fork_keeps = kind == "fork" && held.is_some();
            if !(exec_keeps || fork_keeps) {
                self.own(child, o, t);
            }
        }
    }
}

/// The join's state over every chat.
#[derive(Default)]
pub struct Join {
    chats: HashMap<String, ChatState>,
    /// The latest OS time an OS feed's event carried (MW5-34), never ahead
    /// of the daemon's clock (`feed_progress`).
    os_seen: i64,
    /// Chats let go after their stop, why, and how many OS events of theirs
    /// came after that, at most `MAX_LATE` chats, oldest first out.
    late: VecDeque<Gone>,
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

/// A sandbox the harness runs a command in before the command itself (Mac
/// test w5 retest 6, MW5-29), by file name: Codex's `/usr/bin/sandbox-exec`
/// (`sandboxing/src/seatbelt.rs:62` at 0.163.0) and `bwrap`, system or
/// bundled (`linux-sandbox/src/launcher.rs:222-244`). Codex's Linux helper
/// runs before `bwrap` as Codex's own binary, through the
/// `codex-linux-sandbox` link (`arg0/src/lib.rs:360-410`): the harness's own
/// executable (`ChatState::own_exes`, `Owner::Pending`).
fn sandbox_wrapper(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(name, "sandbox-exec" | "bwrap")
}

/// A general interpreter, by file name: a harness that runs as one (node for
/// npm installs) shares it with the helpers it starts, so running it again
/// says nothing about a sandbox (review FP7-S1).
fn interpreter_program(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "bun" | "deno" | "ruby" | "perl" | "php" | "java" | "lua" | "luajit"
    ) || name.starts_with("python")
        || name.starts_with("node")
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

    /// Drops the stopped chats `keep_why` lets go at `now`, and remembers
    /// them, so their later records are counted, not made a chat again.
    fn sweep(&mut self, now: i64) {
        let os_seen = self.os_seen;
        let gone: Vec<(String, LetGo)> = self
            .chats
            .iter()
            .filter_map(|(k, st)| {
                let why = keep_why(st.stopped_at?, now, os_seen)?;
                Some((k.clone(), why))
            })
            .collect();
        for (k, why) in gone {
            self.chats.remove(&k);
            self.late.retain(|g| g.chat != k);
            self.late.push_back(Gone {
                chat: k,
                why,
                late: 0,
            });
            while self.late.len() > MAX_LATE {
                self.late.pop_front();
            }
        }
    }

    /// How many OS events of `chat` came after the join stopped waiting for
    /// a feed that was behind (MW5-34; `STOPPED_FEED_CAP_MS`); None when it
    /// was not let go that way.
    pub fn late_for(&self, chat: &str) -> Option<u64> {
        self.late
            .iter()
            .find(|g| g.chat == chat && g.why == LetGo::Capped)
            .map(|g| g.late)
    }

    /// How many OS events of `chat` came after the join let it go with the
    /// feed past its stop: work done after the run stopped (FP11-S2).
    pub fn after_for(&self, chat: &str) -> Option<u64> {
        self.late
            .iter()
            .find(|g| g.chat == chat && g.why == LetGo::FeedPassed)
            .map(|g| g.late)
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
        if let Some(t) = feed_progress(e) {
            self.os_seen = self.os_seen.max(t);
        }
        if e.chat_id.is_empty() {
            return Vec::new();
        }
        self.sweep(e.at);
        // A chat already let go is never made again by a later record: an
        // OS event of it is counted, and any other record but its own run's
        // next start is dropped here (FP11-S1: a chat token's socket can
        // still post after run.stop, and a record of it made the chat again
        // with no stop, so its later OS events were neither joined nor
        // counted, and it was never swept). A new run starts afresh, its
        // old count gone (FP11-S3).
        if !self.chats.contains_key(&e.chat_id) {
            if let Some(i) = self.late.iter().position(|g| g.chat == e.chat_id) {
                if e.source == Source::Run && e.kind == "run.start" {
                    self.late.remove(i);
                } else {
                    if os_feed_time(e).is_some() {
                        self.late[i].late += 1;
                    }
                    return Vec::new();
                }
            }
        }
        match (&e.source, e.kind.as_str()) {
            (Source::Run, "run.start") => {
                // A chat id started again begins afresh.
                self.forget(&e.chat_id);
                let st = self.chat(&e.chat_id);
                st.cwd = str_at(&e.detail, "cwd").map(str::to_string);
                st.root_pid = e.pid;
                // A shell or a wrapper program names no harness: srt's own
                // `bash -c` and its wrappers exec those before the harness
                // (second re-review S1).
                let exe_ok = |p: &&str| {
                    p.starts_with('/')
                        && p.len() <= 4096
                        && !shell_program(p)
                        && !wrapper_program(p)
                };
                st.harness_child = str_at(&e.detail, "harnessChildExe")
                    .filter(exe_ok)
                    .map(str::to_string);
                // An interpreter is no harness's own binary: an npm harness's
                // `harnessExe` is node, which its MCP servers run too (review
                // FP7-S1, FP7-S4).
                st.own_exes = [str_at(&e.detail, "harnessExe"), st.harness_child.as_deref()]
                    .into_iter()
                    .flatten()
                    .filter(exe_ok)
                    .filter(|p| !interpreter_program(p))
                    .map(str::to_string)
                    .collect();
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
                let cell = str_at(&e.detail, "cellId")
                    .filter(|c| derm_core::policy::cell_id_ok(c))
                    .map(str::to_string);
                let status = str_at(&e.detail, "codeStatus");
                let st = self.chat(&e.chat_id);
                let paths: Vec<String> = paths.iter().map(|p| st.absolute(p)).collect();
                let c = st.call_mut(id);
                c.event = e.id.clone();
                c.code = code_tool(&e.harness, &tool);
                c.tool = tool;
                c.paths = paths;
                // The tap sees the call first: no record moves its start
                // later (FP5R-3).
                c.start = Some(c.start.map_or(e.at, |s| s.min(e.at)));
                c.tapped = true;
                if c.contested && !c.code && !c.tap_ended {
                    if let Some(x) = c.end.take() {
                        c.posted_end = Some(c.posted_end.map_or(x, |p| p.min(x)));
                    }
                }
                if c.code {
                    // A code call's times are the tap's alone (FP5R-4): an
                    // end an adapter record set before the tap's is dropped.
                    if !c.tap_ended {
                        c.end = None;
                    }
                    if cell.is_some() {
                        c.cell = cell;
                    }
                    if has_result {
                        c.result = Some(match status {
                            Some("running") => CodeResult::Running,
                            Some("ended") => CodeResult::Ended,
                            _ => CodeResult::Unknown,
                        });
                    }
                }
                if has_result {
                    c.end = Some(c.end.map_or(e.at, |x| x.min(e.at)));
                    c.tap_ended = true;
                    c.tap_end = Some(c.tap_end.map_or(e.at, |x| x.min(e.at)));
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
                // Never a code tool from a gate record: Codex sends no
                // hook for Code Mode's `exec` (its default hook payload is
                // for function calls only, `core/src/tools/registry.rs:150-159`
                // at 0.163.0), so such a record is a chat token's, and a
                // chat token cannot post the tap's.
                if c.tool.is_empty() {
                    c.tool = tool;
                }
                // A code call's times are the tap's alone: Codex sends no
                // hook for Code Mode's `exec` or `wait`, so a record naming
                // one is a chat token's, and its cell's nested shells keep
                // starting until the tap's result (FP5R-3, FP5R-4).
                if c.code {
                    return Vec::new();
                }
                // A chat token can post these for a call it read from its own
                // tail, after its shell started and before the OS feed
                // delivers that shell (MW5-17), so no record moves a call's
                // start later, and a deny ends a call no earlier than its
                // start (FP5R-3). An early end drops only new harness
                // children; a call's own tree keeps its writes (S3).
                // A gate `ask` (the harness's own prompt: the person's yes
                // reaches no derm record) or a conflict copy naming the call
                // makes the call contested: a tapped one is then ended by the
                // tap's result alone, and an end a gate record posts only
                // stops it being chosen for later shells (FP6R-1, FP6R-2).
                // An `allow` from a gate whose allow only means "not
                // blocked", so the harness's own prompt still runs after it
                // (case 72: Codex, Gemini, Qwen Code, Grok; derm's Codex gate
                // says nothing on allow, `packages/derm-codex-plugin/src/
                // hook.ts:110-111`), is a person's prompt too (FP6R2-1).
                let prompt_after =
                    decision == "allow" && ALLOW_LEAVES_PROMPT.contains(&e.harness.as_str());
                if decision == "ask" || prompt_after || e.detail.get("conflictsWith").is_some() {
                    c.contested = true;
                    if c.tapped && !c.tap_ended {
                        if let Some(x) = c.end.take() {
                            c.posted_end = Some(c.posted_end.map_or(x, |p| p.min(x)));
                        }
                    }
                }
                let soft = c.contested && c.tapped && !c.tap_ended;
                if soft && (ran || decision == "deny") {
                    let s = c.start.map_or(e.at, |s| s.min(e.at));
                    c.start = Some(s);
                    c.posted_end = Some(c.posted_end.map_or(e.at, |p| p.min(e.at)).max(s));
                } else if ran {
                    c.end = Some(c.end.map_or(e.at, |x| x.min(e.at)));
                } else if decision == "deny" {
                    // A denied call runs nothing: it ends at the deny.
                    let s = c.start.map_or(e.at, |s| s.min(e.at));
                    c.start = Some(s);
                    c.end = Some(c.end.map_or(e.at, |x| x.min(e.at)).max(s));
                } else if decision != "deferred" {
                    // The decision is when an untapped call can start; a
                    // later one never moves it. An end posted before the
                    // gate's allow (a chat token's `tool.call` or `deny` for a
                    // call it read in its tail while an ask waited) is not
                    // the call's: the call runs from the allow, so it is open
                    // again until a later end (fix pass 6's review, FP6-S2).
                    // Only the call's first allow re-opens it, so a late
                    // allow a chat token posts after the call's real end
                    // cannot make a finished call own later shells.
                    c.start = Some(c.start.map_or(e.at, |s| s.min(e.at)));
                    if !c.allowed && !c.tap_ended && c.end.is_some_and(|x| x < e.at) {
                        c.end = None;
                    }
                    if decision == "allow" {
                        c.allowed = true;
                    }
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
        // Box retest of fix pass 13r, BW5R5-4: a process forked inside a PID
        // namespace (bubblewrap's, under srt or Codex's own sandbox on Linux)
        // is named in its parent's fork record by the namespace's pid, which
        // the audit log keeps as the syscall's return (Linux 7.0
        // `kernel/auditsc.c:1629-1632`; `kernel/fork.c:2666`), so the join
        // never placed it. Each record names its own process and its parent
        // by the host's pids (`auditsc.c:1635-1638`): a process the tree has
        // not placed whose parent it has is placed now, as that parent's
        // fork would have placed it. An exec places itself by its parent.
        if kind != "exec" {
            if let (Some(p), Some(pp)) = (pid, ppid) {
                let st = self.chat(&e.chat_id);
                if p != pp && !st.knows(p) && st.knows(pp) {
                    st.place_child("fork", p, Some(pp), None, t);
                }
            }
        }
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
                // A fork is a new process: whatever an earlier process with
                // this pid owned or was in the line is not its (third
                // re-review T1: a reused pid kept an old call's owner and
                // was chosen for it).
                if kind == "fork" {
                    st.drop_roles(child, t);
                    st.disown(child, t);
                }
                let parent = if kind == "fork" { pid } else { ppid };
                let program = str_at(&e.detail, "exe").or_else(|| str_at(&e.detail, "comm"));
                if kind == "exec" && st.hand_off(child, parent, program, t) {
                    // The launcher's child that execs the binary `derm run`
                    // named is the harness: no owner, and it places children
                    // as the root does (MW5-28).
                } else {
                    st.place_child(kind, child, parent, program, t);
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
            Some(Owner::Call(_))
                | Some(Owner::Among(_))
                | Some(Owner::Unplaced(_))
                | Some(Owner::Cells(_))
                | Some(Owner::Posted(_))
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
        if let Some(Owner::Posted(id)) = &owner {
            if let Some(c) = st.calls.get(id) {
                candidates.push((
                    c.event.clone(),
                    "tree",
                    "a shell started while this call ran, after a gate record said it ended (that record may be a chat token's)".into(),
                ));
            }
        }
        if let Some(Owner::Cells(ids)) = &owner {
            for c in ids.iter().filter_map(|id| st.calls.get(id)) {
                candidates.push((
                    c.event.clone(),
                    "tree",
                    "a shell started while this code call's cell may have run, beside others"
                        .into(),
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
        // The harness's own child wrote (BW5R-2): its own shell, not a
        // process a call's command started.
        // The write's own record names the harness as the parent too, so a
        // reused pid whose fork record is still to come is not taken for
        // the old shell (review FP9R-2).
        let parent_is_harness = ppid.is_some_and(|p| {
            Some(p) == st.root_pid || Some(p) == st.harness || Some(p) == st.launched
        });
        if parent_is_harness
            && pid.is_some_and(|p| st.direct.get(&p).is_some_and(|(d, _)| *d == Direct::Shell))
        {
            detail["harnessChild"] = json!(true);
        }
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
