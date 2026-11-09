//! The pure part of the feed: audit lines and the daemon's `run.start` and
//! `run.stop` records in, daemon events out. No I/O here; the binary
//! (`src/bin/derm-audit-feed.rs`) reads the log and talks to the socket.

use derm_core::event::{Event, Source};
use serde_json::Value;

use crate::action::{self, Action};
use crate::assemble::{Assembler, AuditEvent};
use crate::checks::Checker;
use crate::map::to_event;
use crate::record::parse_line;
use crate::tree::{Placement, Root, Tracker};

pub struct Feed {
    home: String,
    runtime_dir: Option<String>,
    assembler: Assembler,
    tracker: Tracker,
    checker: Checker,
    /// Lines that were not audit records.
    pub skipped_lines: u64,
    /// The `(time, serial)` of the last line read that was an audit record.
    last_key: Option<(i64, u64)>,
    /// The feed's own process: the derm rules record every process of the
    /// user, the feed's own place saves too, and those must neither wait for
    /// a chat nor move the place, or each save causes the next (the
    /// re-review's FP13RR-1: 413 KB of audit log a minute, all the feed's).
    own_pid: Option<u32>,
    /// The keys of the feed's own events seen lately (a bounded set).
    own_keys: std::collections::HashSet<(i64, u64)>,
    own_order: std::collections::VecDeque<(i64, u64)>,
    last_own: bool,
}

/// How many of the feed's own event keys are remembered.
const OWN_KEYS: usize = 4096;

impl Feed {
    /// `home` is the user's home folder (`$HOME`), `runtime_dir` their
    /// `$XDG_RUNTIME_DIR` when set.
    pub fn new(home: &str, runtime_dir: Option<&str>) -> Feed {
        Feed {
            home: home.to_string(),
            runtime_dir: runtime_dir.map(str::to_string),
            assembler: Assembler::new(),
            tracker: Tracker::new(),
            checker: Checker::new(),
            skipped_lines: 0,
            last_key: None,
            own_pid: None,
            own_keys: std::collections::HashSet::new(),
            own_order: std::collections::VecDeque::new(),
            last_own: false,
        }
    }

    /// The feed's own process id: its records are never a chat's and do
    /// not move the kept place (FP13RR-1).
    pub fn set_own_pid(&mut self, pid: u32) {
        self.own_pid = Some(pid);
    }

    /// Whether the last line read belongs to one of the feed's own events.
    pub fn last_line_own(&self) -> bool {
        self.last_own
    }

    /// The `(time, serial)` of the last audit record read.
    pub fn last_key(&self) -> Option<(i64, u64)> {
        self.last_key
    }

    /// Every event read and not yet posted: open in the assembler, or
    /// waiting in the tracker for its chat's `run.start`. A place kept for a
    /// restart must not pass the first line of any of them (fp13's review,
    /// FP13R-3, FP13R-12).
    pub fn unposted(&self) -> std::collections::HashSet<(i64, u64)> {
        self.assembler
            .open_keys()
            .chain(self.tracker.pending_keys())
            .collect()
    }

    pub fn tracker(&self) -> &Tracker {
        &self.tracker
    }

    /// Audit events begun and not yet ended: while any is open, the lines
    /// read so far are not all posted (BW5R4-1).
    pub fn open_events(&self) -> usize {
        self.assembler.open_count()
    }

    /// The newest audit time read.
    pub fn log_ms(&self) -> i64 {
        self.tracker.log_ms()
    }

    /// One line of the audit log.
    pub fn push_line(&mut self, line: &str) -> Vec<Event> {
        let Some(record) = parse_line(line) else {
            if !line.trim().is_empty() {
                self.skipped_lines += 1;
            }
            self.last_own = false;
            return Vec::new();
        };
        let key = record.event_key();
        self.last_key = Some(key);
        // An event's SYSCALL record comes first (0 of 14,969 events with one
        // had it elsewhere in this workspace's logs, fp13's second re-review)
        // and its `pid=` is the process id, not the thread's (run there: a
        // thread with tid 9724 logged `pid=9723`), so every thread of the
        // feed is its own pid. A record of the same event written before
        // its SYSCALL (an LSM's) would not be marked own (FP13RR2-7, open,
        // none seen).
        if self.own_pid.is_some()
            && record.kind == "SYSCALL"
            && record.get_u32("pid") == self.own_pid
            && self.own_keys.insert(key)
        {
            self.own_order.push_back(key);
            while self.own_order.len() > OWN_KEYS {
                if let Some(old) = self.own_order.pop_front() {
                    self.own_keys.remove(&old);
                }
            }
        }
        self.last_own = self.own_keys.contains(&key);
        let done = self.assembler.push(record);
        self.handle(done)
    }

    /// Ends every open event (at the end of input, or after a quiet second).
    pub fn flush(&mut self) -> Vec<Event> {
        let done = self.assembler.flush();
        self.handle(done)
    }

    fn handle(&mut self, done: Vec<AuditEvent>) -> Vec<Event> {
        let mut out = Vec::new();
        for ev in done {
            if self.own_keys.contains(&(ev.ts_ms, ev.serial)) {
                continue;
            }
            let Some(a) = action::read(&ev) else { continue };
            if let Some(p) = self.tracker.place(&a) {
                out.push(self.emit(&a, &p));
            }
        }
        out
    }

    fn emit(&mut self, a: &Action, p: &Placement) -> Event {
        let reasons = match self.tracker.root(p.root_pid) {
            Some(root) => {
                let root = root.clone();
                self.checker
                    .check(&root, a, &self.home, self.runtime_dir.as_deref())
            }
            None => Vec::new(),
        };
        to_event(a, p, &reasons)
    }

    /// A chat started: its root process and folders. Returns the actions
    /// that were waiting for it.
    pub fn register(&mut self, root: Root) -> Vec<Event> {
        let placed = self.tracker.register(root);
        placed.iter().map(|(a, p)| self.emit(a, p)).collect()
    }

    pub fn unregister(&mut self, chat: &str) {
        self.tracker.unregister(chat);
        self.checker.forget(chat);
    }

    /// Drops members that no longer run (`Tracker::prune`); the binary
    /// calls it once a minute.
    pub fn prune(&mut self, alive: &dyn Fn(u32) -> bool) {
        self.tracker.prune(alive);
        self.forget_gone();
    }

    fn forget_gone(&mut self) {
        let chats: std::collections::HashSet<String> =
            self.tracker.roots().map(|r| r.chat.clone()).collect();
        self.checker.retain_chats(&chats);
    }

    /// Reads a record the daemon streamed (`tail`). `run.start` with a
    /// `pid` registers a root; `run.stop` drops it. Anything else is
    /// ignored. Returns the events that were waiting for a new root.
    ///
    /// `alive(pid)` says whether a process still runs: members alive at a
    /// stop stay the chat's. Every `run` record is taken as it comes: only
    /// the daemon scope posts them (`contracts/daemon-protocol.md` rule 2;
    /// `op_event` refuses them from a chat token), and a later `run.start`
    /// on the same pid is a reused pid. That guarantee is the boundary's,
    /// not the protocol's: under `--boundary none` the agent is the user and
    /// can read `daemon.token` (case 66's class; the re-review's FP13RR-8),
    /// and with it could post any record at all, which the refusal below
    /// never closed. Until fp13's review the feed refused
    /// a stop whose root pid was alive and a start on a pid a live chat
    /// held; with the pid reused (a backlog replayed at the feed's start),
    /// that kept the old chat on the pid and credited the live chat's
    /// processes to it (FP13R-6).
    pub fn on_daemon_event(&mut self, e: &Event, alive: &dyn Fn(u32) -> bool) -> Vec<Event> {
        if e.source != Source::Run || e.chat_id.is_empty() {
            return Vec::new();
        }
        match e.kind.as_str() {
            "run.start" => {
                let Some(pid) = e.pid else { return Vec::new() };
                let strings = |key: &str| -> Vec<String> {
                    e.detail
                        .get(key)
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .filter(|s| s.starts_with('/'))
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default()
                };
                self.register(Root {
                    chat: e.chat_id.clone(),
                    harness: e.harness.clone(),
                    pid,
                    folders: strings("folders"),
                    state: strings("stateDirs"),
                    at: e.at,
                    stopped: false,
                })
            }
            "run.stop" => {
                // The stop's own time: lines stamped before it are still the
                // chat's when the feed reads them later (BW5R4-2).
                self.tracker.stop(&e.chat_id, e.at, alive);
                self.forget_gone();
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
}
