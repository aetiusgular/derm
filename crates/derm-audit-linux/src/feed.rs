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
    refused: u64,
    /// Audit events stamped at or before this were read in an earlier run
    /// (BW5R4-1: a restart that reads the log again from its beginning).
    floor_ms: i64,
}

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
            refused: 0,
            floor_ms: i64::MIN,
        }
    }

    /// Skips audit events stamped at or before `ms`: an earlier run of the
    /// feed read and posted them, and posting them again would join them
    /// again (BW5R4-1).
    pub fn skip_through(&mut self, ms: i64) {
        self.floor_ms = ms;
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
            return Vec::new();
        };
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
            if ev.ts_ms <= self.floor_ms {
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
    /// `alive(pid)` says whether a process still runs. A `run.stop` for a
    /// root that is still alive is ignored, and a `run.start` for a pid that
    /// another live chat already holds is refused: a chat token can post
    /// `run` records into its own chat (`contracts/daemon-protocol.md`
    /// rule 2 only rewrites the chat), and must not be able to switch the
    /// feed off for itself or take another chat's processes.
    pub fn on_daemon_event(&mut self, e: &Event, alive: &dyn Fn(u32) -> bool) -> Vec<Event> {
        if e.source != Source::Run || e.chat_id.is_empty() {
            return Vec::new();
        }
        match e.kind.as_str() {
            "run.start" => {
                let Some(pid) = e.pid else { return Vec::new() };
                if let Some(held) = self.tracker.root(pid) {
                    if held.chat != e.chat_id && alive(pid) {
                        self.refused += 1;
                        return Vec::new();
                    }
                }
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
                let live = self
                    .tracker
                    .roots()
                    .filter(|r| r.chat == e.chat_id && !r.stopped)
                    .any(|r| alive(r.pid));
                if live {
                    self.refused += 1;
                } else {
                    // The stop's own time: lines stamped before it are still
                    // the chat's when the feed reads them later (BW5R4-2).
                    self.tracker.stop(&e.chat_id, e.at, alive);
                    self.forget_gone();
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// `run` records refused by the checks in `on_daemon_event`.
    pub fn refused(&self) -> u64 {
        self.refused
    }
}
