//! The daemon's state and the protocol's ops (`contracts/daemon-protocol.md`,
//! section 2). `socket.rs` reads lines and hands each request here; this file
//! decides the reply, stores events, streams `tail` and runs `approve`.
//!
//! - One process: the OTLP receiver (`otel_receiver`), the activity log
//!   (`activity`) and the socket. Every event, from the receiver or a socket
//!   client, goes through `ingest`: bounded, stamped, written, then streamed.
//! - Nothing here blocks on a slow client. A `tail` that falls more than
//!   `MAX_PENDING_LINES` behind is dropped; an approver that has gone is
//!   skipped (rules, section 4, case 9).
//! - One outbound path only: the model tap (`derm_tap`, wave 5 lane S),
//!   which forwards a harness's model requests to the four hosts in
//!   `derm_tap::upstream::builtin()` and nowhere else (rules, section 5,
//!   item 8, as changed by integration w5's phase 2). Nothing else here
//!   connects out.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver as Rx, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use derm_core::event::{Event, Source};
use serde_json::{json, Map, Value};

use crate::activity::check::ChatContext;
use crate::activity::commands::{clean_context, flags_report};
use crate::activity::store::{self, ActivityLog, Entry};
use crate::activity::types::{ApprovalRecord, ApprovalScope, ApprovalSubject};
use crate::otel_receiver::{self, harness_env, Receiver, Settings};
use crate::protocol::{
    Answer, AnsweredBy, ApprovalRequest, CuAction, DaemonInfo, Push, Reply, Request, Scope,
    PROTOCOL_VERSION,
};

// The approver (wave 5 lane V's folder; moved unchanged by the wave 5 base).
#[path = "approver/mod.rs"]
mod approver;

/// Events kept in memory for `tail`'s backlog, beside the log on disk. At
/// least the log's queue, so an event not yet written is still here.
pub const RING_CAPACITY: usize = 4_096;
/// A `tail` this many lines behind is dropped.
pub const MAX_PENDING_LINES: usize = 4_096;
/// At most this many events in one `tail` backlog.
pub const MAX_BACKLOG: usize = 5_000;
/// Events one `report` reads.
pub const REPORT_READ_LIMIT: usize = 20_000;

/// The most a report reply holds, in bytes: every client reads at most 1 MiB
/// a line (`socket::MAX_LINE_BYTES`, `derm_audit_linux::client::MAX_LINE`),
/// and a busy window's flags with the events they name passed that (Mac
/// test w5 retest 4, MW5-25).
pub const REPORT_BUDGET: usize = 896 * 1024;

/// How many entries a count map (`byKind`, `bySource`, `approvals`) keeps
/// in a report cut to fit: the largest counts. A chat token can post kinds
/// of its own, each a new key (fix pass 4's review, FP4-S3).
pub const REPORT_MAP_KEEP: usize = 256;

/// How much of a named event's text a report cut to fit keeps.
const CUT_TEXT: usize = 300;

/// A flag's weight when a report is cut, by its reason.
fn flag_rank(f: &Value) -> u8 {
    match f.get("reason").and_then(Value::as_str).unwrap_or("") {
        "sensitivePath" => 0,
        "appNotGranted" => 1,
        "recordingOff" => 2,
        "newHost" => 3,
        "leftRunning" => 4,
        _ => 5,
    }
}

/// What a cut report knows about a flag: whether a chat token could have
/// posted its event (an `adapter` or `otel` record), and whether it touched
/// a path that is always listed (derm's guarded folders, and the places a
/// process persists itself: `ALWAYS_LISTED`).
pub struct FlagSource<'a> {
    pub chat_postable: &'a dyn Fn(&Value) -> bool,
    pub always_listed: &'a dyn Fn(&Value) -> bool,
}

/// Paths a cut report lists first, after derm's guarded folders: what a
/// process writes to keep itself or reach the user's sign-ins (the
/// re-review's R2-1). Each is a prefix: under the daemon's own home for the
/// relative ones, from the root for the absolute ones, so an agent cannot
/// earn the first bucket with a `.ssh` folder of its own under `/tmp`.
pub const ALWAYS_LISTED: &[&str] = &[
    ".ssh/",
    ".gnupg/",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".config/fish/config.fish",
    "Library/LaunchAgents/",
    ".config/systemd/user/",
    ".config/autostart/",
    ".aws/",
    ".kube/",
    ".docker/config.json",
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
    "/etc/",
    "/var/spool/cron",
];

/// How many distinct always-listed paths a cut report names when it cut
/// their rows.
pub const ALWAYS_LISTED_KEEP: usize = 200;

/// Whether `path` is under one of `ALWAYS_LISTED`, with `home` the
/// daemon's own home folder.
pub fn always_listed_path(path: &str, home: Option<&str>) -> bool {
    ALWAYS_LISTED.iter().any(|entry| {
        if entry.starts_with('/') {
            path.starts_with(entry)
        } else {
            home.is_some_and(|h| {
                let h = h.trim_end_matches('/');
                !h.is_empty()
                    && path
                        .strip_prefix(h)
                        .and_then(|rest| rest.strip_prefix('/'))
                        .is_some_and(|rest| rest.starts_with(entry))
            })
        }
    })
}

#[cfg(test)]
mod always_listed_tests {
    use super::always_listed_path;

    #[test]
    fn only_the_homes_own_places_and_system_ones_are_always_listed() {
        let home = Some("/home/t");
        assert!(always_listed_path("/home/t/.ssh/authorized_keys", home));
        assert!(always_listed_path("/home/t/.zshrc", home));
        assert!(always_listed_path("/etc/cron.d/x", home));
        assert!(!always_listed_path("/tmp/x/.ssh/authorized_keys", home));
        assert!(!always_listed_path("/home/t/proj/.ssh/x", home));
        assert!(!always_listed_path("/home/tony/.ssh/x", home));
        assert!(!always_listed_path("/home/t/.ssh/x", None));
    }
}

/// The order a cut report keeps flags in (fix pass 4's review, FP4-S2 and
/// its re-reviews' R2, R2-1 to R2-3). Each chat's flags fall into buckets: a
/// flag on an OS feed's or the daemon's event that touched a guarded or
/// always-listed path first (`ALWAYS_LISTED`), then by whether a chat token
/// could have posted the event (records it cannot post first), then by
/// reason. A chat's
/// list takes one flag from each bucket in turn, so no burst in one bucket,
/// such as new hosts a chat token names in bulk, pushes out a lone flag of
/// another; inside a bucket it takes the newest, then the oldest, then the
/// next of each. The chats are taken one at a time in turn. Ties in time go
/// to the later row.
pub fn flag_keep_order(flags: &[Value], src: &FlagSource) -> Vec<usize> {
    use std::collections::{BTreeMap, VecDeque};
    let at = |i: usize| {
        let f = &flags[i];
        f.get("lastAt")
            .and_then(Value::as_i64)
            .filter(|t| *t > 0)
            .or_else(|| f.get("at").and_then(Value::as_i64))
            .unwrap_or(0)
    };
    let bucket = |i: usize| {
        let f = &flags[i];
        (
            !(src.always_listed)(f),
            (src.chat_postable)(f),
            flag_rank(f),
        )
    };
    // A bucket: not always listed, a chat token could post it, its rank.
    type Buckets = BTreeMap<(bool, bool, u8), Vec<usize>>;
    let mut by_chat: BTreeMap<&str, Buckets> = BTreeMap::new();
    for (i, f) in flags.iter().enumerate() {
        let chat = f.get("chatId").and_then(Value::as_str).unwrap_or("");
        by_chat
            .entry(chat)
            .or_default()
            .entry(bucket(i))
            .or_default()
            .push(i);
    }
    let mut chats: Vec<VecDeque<usize>> = Vec::new();
    for buckets in by_chat.into_values() {
        // Newest, oldest, next newest, next oldest, ... in each bucket.
        let mut queues: Vec<VecDeque<usize>> = buckets
            .into_values()
            .map(|mut v| {
                v.sort_by_key(|&i| (at(i), i));
                let mut out = Vec::with_capacity(v.len());
                let (mut lo, mut hi) = (0usize, v.len());
                while lo < hi {
                    hi -= 1;
                    out.push(v[hi]);
                    if lo < hi {
                        out.push(v[lo]);
                        lo += 1;
                    }
                }
                out.into()
            })
            .collect();
        let mut chat = VecDeque::new();
        while queues.iter().any(|q| !q.is_empty()) {
            for q in queues.iter_mut() {
                if let Some(i) = q.pop_front() {
                    chat.push_back(i);
                }
            }
        }
        chats.push(chat);
    }
    let mut order = Vec::with_capacity(flags.len());
    while order.len() < flags.len() {
        for q in chats.iter_mut() {
            if let Some(i) = q.pop_front() {
                order.push(i);
            }
        }
    }
    order
}

/// A named event as a cut report keeps it: what it is and where, without
/// its detail (FP4-S2: a context event's 16 KiB detail made every kept
/// flag cost more).
fn slim_event(e: &Value) -> Value {
    let clip = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .map(|t| Value::String(t.chars().take(CUT_TEXT).collect()))
    };
    let mut out = Map::new();
    for k in ["id", "at", "chatId", "harness", "source", "kind", "pid"] {
        if let Some(v) = e.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    if let Some(v) = clip(e.get("summary")) {
        out.insert("summary".into(), v);
    }
    let mut detail = Map::new();
    for k in ["path", "host", "tier"] {
        if let Some(v) = clip(e.get("detail").and_then(|d| d.get(k))) {
            detail.insert(k.into(), v);
        }
    }
    out.insert("detail".into(), Value::Object(detail));
    out.insert("cut".into(), json!(true));
    Value::Object(out)
}

/// Keeps the `keep` largest counts of a count map and returns how many it
/// left out.
fn bound_counts(m: &mut Map<String, Value>, keep: usize) -> usize {
    if m.len() <= keep {
        return 0;
    }
    let mut all: Vec<(String, Value)> = std::mem::take(m).into_iter().collect();
    all.sort_by(|a, b| {
        let n = |v: &Value| v.as_u64().unwrap_or(0);
        n(&b.1).cmp(&n(&a.1)).then_with(|| a.0.cmp(&b.0))
    });
    let left = all.len() - keep;
    m.extend(all.into_iter().take(keep));
    left
}

/// Keeps a report under `budget` bytes once serialized, and never returns
/// one over it (FP4-S3). Past the budget, in order:
/// 1. the count maps keep their `REPORT_MAP_KEEP` largest entries
///    (`byKindOmitted`, `bySourceOmitted`, `approvalsOmitted` say how many
///    keys went), and the events the check names keep only what they are and
///    where (`cut: true` on each);
/// 2. the check's hidden rows go, then its flags are cut to the ones that
///    fit, chosen by `flag_keep_order` (rank, newest, each chat in turn) and
///    listed in the check's own order; only the events the kept rows name
///    stay; `check.flagsOmitted` and `check.expectedOmitted` say how many
///    rows were left out;
/// 3. if even no rows do not fit, the check keeps its counts only, then the
///    count maps go, then the report keeps its totals only, each with
///    `reportCut: true`.
///
/// The totals (`flags`, `events`) stay whole.
pub fn fit_report(report: &mut Value, budget: usize) {
    fit_report_with(report, budget, None)
}

/// `fit_report`, with `data_dir` naming derm's guarded folders for the
/// flag order (`check::guarded_path`).
pub fn fit_report_with(report: &mut Value, budget: usize, data_dir: Option<&str>) {
    let size = |r: &Value| serde_json::to_vec(r).map_or(usize::MAX, |v| v.len());
    if size(report) <= budget {
        return;
    }
    let Some(top) = report.as_object_mut() else {
        return;
    };
    for (k, omitted) in [
        ("byKind", "byKindOmitted"),
        ("bySource", "bySourceOmitted"),
        ("approvals", "approvalsOmitted"),
    ] {
        if let Some(Value::Object(m)) = top.get_mut(k) {
            let left = bound_counts(m, REPORT_MAP_KEEP);
            top.insert(omitted.into(), json!(left));
        }
    }
    let take = |k: &str, c: &mut Map<String, Value>| match c.remove(k) {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    let (flags, expected, events) = match top.get_mut("check").and_then(Value::as_object_mut) {
        Some(check) => (
            take("flags", check),
            take("expected", check),
            take("events", check),
        ),
        None => (Vec::new(), Vec::new(), Vec::new()),
    };
    let full_events = events;
    let events: Vec<Value> = full_events.iter().map(slim_event).collect();
    let has_check = top.get("check").is_some_and(Value::is_object);
    // What each named event is, read before the events are slimmed. The flag
    // carries its own `guarded` and `chatPostable` (R2-2, R2-3); the event,
    // always in the flag's own context now, adds its source and paths.
    let mut postable_ids = std::collections::HashSet::new();
    let mut listed_ids = std::collections::HashSet::new();
    // The always-listed path each such event named, for the list of paths a
    // cut left out (the third re-review's R3-1).
    let mut listed_paths: std::collections::HashMap<String, String> = Default::default();
    let home = derm_core::runtime::home_dir().map(|h| h.to_string_lossy().into_owned());
    for e in &full_events {
        let Some(id) = e.get("id").and_then(Value::as_str) else {
            continue;
        };
        let source = e.get("source").and_then(Value::as_str).unwrap_or("");
        if matches!(source, "adapter" | "otel") {
            postable_ids.insert(id.to_string());
        }
        let detail = e.get("detail");
        let listed = ["path", "dest", "target", "source"].iter().find_map(|k| {
            detail
                .and_then(|d| d.get(*k))
                .and_then(Value::as_str)
                .filter(|p| {
                    crate::activity::check::guarded_path(p, data_dir)
                        || always_listed_path(p, home.as_deref())
                })
        });
        if let Some(p) = listed {
            listed_ids.insert(id.to_string());
            listed_paths.insert(id.to_string(), p.chars().take(CUT_TEXT).collect());
        }
    }
    let event_of = |f: &Value| {
        f.get("eventId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let flag_true = |f: &Value, k: &str| f.get(k).and_then(Value::as_bool) == Some(true);
    let postable = |f: &Value| flag_true(f, "chatPostable") || postable_ids.contains(&event_of(f));
    // A chat token's own record never earns the first bucket by naming a
    // path there: only a flag on an OS feed's or the daemon's event does.
    let listed =
        |f: &Value| !postable(f) && (flag_true(f, "guarded") || listed_ids.contains(&event_of(f)));
    let order = flag_keep_order(
        &flags,
        &FlagSource {
            chat_postable: &postable,
            always_listed: &listed,
        },
    );
    let mut keep_flags = flags.len();
    let mut keep_expected = expected.len();
    if has_check {
        loop {
            let chosen: std::collections::HashSet<usize> =
                order[..keep_flags].iter().copied().collect();
            let kept: Vec<Value> = flags
                .iter()
                .enumerate()
                .filter(|(i, _)| chosen.contains(i))
                .map(|(_, f)| f.clone())
                .collect();
            let named: std::collections::HashSet<String> = kept
                .iter()
                .chain(&expected[..keep_expected])
                .flat_map(|r| {
                    r.get("eventId")
                        .and_then(Value::as_str)
                        .into_iter()
                        .chain(
                            r.get("context")
                                .and_then(Value::as_array)
                                .into_iter()
                                .flatten()
                                .filter_map(Value::as_str),
                        )
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .collect();
            let kept_events: Vec<Value> = events
                .iter()
                .filter(|e| {
                    e.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|i| named.contains(i))
                })
                .cloned()
                .collect();
            let check = report
                .get_mut("check")
                .and_then(Value::as_object_mut)
                .expect("check is an object");
            check.insert("flags".into(), Value::Array(kept));
            check.insert(
                "expected".into(),
                Value::Array(expected[..keep_expected].to_vec()),
            );
            check.insert("events".into(), Value::Array(kept_events));
            check.insert("flagsOmitted".into(), json!(flags.len() - keep_flags));
            // Every always-listed path a cut row named, once, so a real
            // persistence target is named even when its row is cut (R3-1).
            let mut left: std::collections::BTreeSet<&str> = Default::default();
            for (i, f) in flags.iter().enumerate() {
                if chosen.contains(&i) || !listed(f) {
                    continue;
                }
                if let Some(p) = listed_paths.get(&event_of(f)) {
                    left.insert(p.as_str());
                }
            }
            if !left.is_empty() {
                let total = left.len();
                let named: Vec<&str> = left.into_iter().take(ALWAYS_LISTED_KEEP).collect();
                check.insert("alwaysListedOmitted".into(), json!(named));
                check.insert("alwaysListedOmittedTotal".into(), json!(total));
            } else {
                check.remove("alwaysListedOmitted");
                check.remove("alwaysListedOmittedTotal");
            }
            check.insert(
                "expectedOmitted".into(),
                json!(expected.len() - keep_expected),
            );
            if size(report) <= budget || (keep_flags == 0 && keep_expected == 0) {
                break;
            }
            if keep_expected > 0 {
                keep_expected = 0;
            } else {
                keep_flags /= 2;
            }
        }
    }
    if size(report) <= budget {
        return;
    }
    // Even no rows do not fit: the check keeps its counts, then the maps go,
    // then only the totals are left (FP4-S3).
    if let Some(check) = report.get_mut("check").and_then(Value::as_object_mut) {
        // The hidden rows' counts by reason become one sum (the re-review's R3).
        let suppressed: u64 = check
            .get("suppressed")
            .and_then(Value::as_object)
            .map(|m| m.values().filter_map(Value::as_u64).sum())
            .unwrap_or(0);
        check.retain(|_, v| !(v.is_array() || v.is_object()));
        check.insert("suppressedTotal".into(), json!(suppressed));
        check.insert("reportCut".into(), json!(true));
    }
    if size(report) <= budget {
        return;
    }
    if let Some(top) = report.as_object_mut() {
        for k in ["byKind", "bySource", "approvals"] {
            if let Some(Value::Object(m)) = top.get_mut(k) {
                let left = m.len();
                m.clear();
                let omitted = format!("{k}Omitted");
                let before = top.get(&omitted).and_then(Value::as_u64).unwrap_or(0);
                top.insert(omitted, json!(before + left as u64));
            }
        }
        top.insert("reportCut".into(), json!(true));
    }
    if size(report) <= budget {
        return;
    }
    let keep: Map<String, Value> = report
        .as_object()
        .map(|m| {
            m.iter()
                .filter(|(_, v)| match v {
                    Value::Array(_) | Value::Object(_) => false,
                    Value::String(t) => t.len() <= 200,
                    _ => true,
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    *report = Value::Object(keep);
    report["reportCut"] = json!(true);
}
/// Approval waits are held to this range, in seconds.
pub const MIN_APPROVE_SECONDS: u32 = 1;
pub const MAX_APPROVE_SECONDS: u32 = 3_600;
/// Approvals waiting at once, over all connections.
pub const MAX_PENDING_APPROVALS: usize = 256;
/// Approvals one chat may have waiting at once, so one chat cannot use up
/// the rest (each refused one is `no`, never a hang).
pub const MAX_PENDING_PER_CHAT: usize = 16;

/// A running chat's harness: its pid and, where the OS says, when that
/// process started, so a reused pid is not taken for it after a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunPid {
    pub pid: u32,
    pub start_time: Option<u64>,
}

impl RunPid {
    fn of(pid: u32) -> Self {
        RunPid {
            pid,
            start_time: derm_core::platform::peer::start_time(pid),
        }
    }

    /// Still the same process: it runs, and its start time matches when one
    /// was recorded.
    fn alive(&self) -> bool {
        match (
            self.start_time,
            derm_core::platform::peer::start_time(self.pid),
        ) {
            (Some(was), Some(now)) => was == now,
            (None, Some(_)) => true,
            (_, None) => false,
        }
    }
}

/// How long a minted token with no `run.start` yet survives a restart.
pub const UNSTARTED_TOKEN_MS: i64 = 3_600_000;
/// The state file is read only up to this size.
const STATE_FILE_MAX: u64 = 1024 * 1024;

/// Who a connection is, after `hello`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Who {
    Daemon,
    Chat { chat: String, harness: String },
}

/// One connection's way back to its client: whole lines, sent by the
/// connection's writer thread. `pending` counts lines queued and not yet
/// written, so a slow reader can be dropped instead of growing memory.
#[derive(Clone)]
pub struct Outbox {
    tx: Sender<String>,
    pending: Arc<AtomicUsize>,
    pub conn: u64,
    /// Who connected, for a socket connection (read at accept, S2). `None`
    /// for the daemon's own in-process clients (the collector, computer
    /// use), which are not a process an agent can start.
    pub peer: Option<Arc<ConnPeer>>,
}

/// The process on the other end of a socket connection, read when it was
/// accepted (integration w2, security finding S2).
#[derive(Debug, Default)]
pub struct ConnPeer {
    /// `SO_PEERCRED` / `LOCAL_PEERCRED`; `None` when the OS call failed.
    pub cred: Option<derm_core::platform::peer::Peer>,
    /// The connecting process itself, on Linux 6.5 and later.
    pub pidfd: Option<derm_core::platform::Pidfd>,
    pub program: Option<String>,
    pub start_time: Option<u64>,
}

impl ConnPeer {
    /// Reads the peer of an accepted connection.
    pub fn of(stream: &derm_core::platform::Stream) -> Self {
        let cred = derm_core::platform::peer::of(stream);
        let pid = cred.as_ref().and_then(|c| c.pid);
        ConnPeer {
            pidfd: derm_core::platform::peer::pidfd_of(stream),
            program: pid
                .and_then(derm_core::platform::peer::program)
                .map(|p| p.to_string_lossy().into_owned()),
            start_time: pid.and_then(derm_core::platform::peer::start_time),
            cred,
        }
    }

    /// What the log records about the peer.
    pub fn record(&self) -> Value {
        json!({
            "pid": self.cred.as_ref().and_then(|c| c.pid),
            "uid": self.cred.as_ref().map(|c| &c.uid),
            "program": self.program.as_deref().map(|p| clip(p, 300)),
            "startTime": self.start_time,
            "pidfd": self.pidfd.is_some(),
        })
    }
}

impl Outbox {
    pub fn new(conn: u64) -> (Self, Rx<String>, Arc<AtomicUsize>) {
        Self::with_peer(conn, None)
    }

    /// An outbox for a socket connection, with who connected.
    pub fn with_peer(
        conn: u64,
        peer: Option<Arc<ConnPeer>>,
    ) -> (Self, Rx<String>, Arc<AtomicUsize>) {
        let (tx, rx) = mpsc::channel();
        let pending = Arc::new(AtomicUsize::new(0));
        (
            Outbox {
                tx,
                pending: pending.clone(),
                conn,
                peer,
            },
            rx,
            pending,
        )
    }

    /// Queues one line. False when the connection has gone.
    pub fn send_line(&self, line: String) -> bool {
        self.pending.fetch_add(1, Ordering::SeqCst);
        if self.tx.send(line).is_err() {
            self.pending.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        true
    }

    pub fn send<T: serde::Serialize>(&self, value: &T) -> bool {
        match serde_json::to_string(value) {
            Ok(line) => self.send_line(line),
            Err(_) => false,
        }
    }

    pub fn pending(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }
}

struct TailSub {
    chat: Option<String>,
    out: Outbox,
}

struct Pending {
    /// The answer and who gave it (the approver's peer record, S2).
    answer: SyncSender<(Answer, Value)>,
    chat: String,
}

/// Where the daemon keeps its files.
#[derive(Clone, Debug)]
pub struct Paths {
    /// The socket; `daemon.pid`, `daemon.token` and `otlp.endpoint` sit
    /// beside it.
    pub socket: PathBuf,
    /// The data folder; the log is `<data>/activity`.
    pub data: PathBuf,
}

impl Paths {
    pub fn runtime_dir(&self) -> &Path {
        self.socket.parent().unwrap_or(Path::new("/"))
    }
    pub fn pid_file(&self) -> PathBuf {
        self.runtime_dir().join("daemon.pid")
    }
    pub fn token_file(&self) -> PathBuf {
        self.runtime_dir().join("daemon.token")
    }
    pub fn endpoint_file(&self) -> PathBuf {
        self.runtime_dir().join("otlp.endpoint")
    }

    /// The model tap's endpoint (wave 5 lane S), read by `derm run`.
    pub fn tap_endpoint_file(&self) -> PathBuf {
        self.runtime_dir().join("tap.endpoint")
    }
    /// Running chats kept across a restart (BX8; integration w2).
    pub fn state_file(&self) -> PathBuf {
        self.runtime_dir().join("chats.json")
    }
    pub fn log_dir(&self) -> PathBuf {
        self.data.join("activity")
    }
}

/// The daemon's data folder per OS: macOS
/// `~/Library/Application Support/derm`, else `$XDG_DATA_HOME/derm`, else
/// `~/.local/share/derm`. The socket folder on Linux is `$XDG_RUNTIME_DIR`,
/// which is emptied at logout, so the log never lives there.
pub fn default_data_dir() -> Option<PathBuf> {
    let home = derm_core::runtime::home_dir();
    if cfg!(target_os = "macos") {
        return home.map(|h| h.join("Library/Application Support/derm"));
    }
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home.map(|h| h.join(".local/share")))
        .map(|d| d.join("derm"))
}

/// A chat token's records a second over the socket, and its burst
/// (re-review W5R-3). A hook posts a few records per tool call.
pub const SOCKET_RATE_PER_CHAT_SEC: f64 = 50.0;
pub const SOCKET_BURST_PER_CHAT: f64 = 500.0;
/// A chat token's bytes of records a day over the socket (W5R-3).
pub const SOCKET_BYTES_PER_CHAT_DAY: usize = 128 * 1024 * 1024;
/// Chats with a quota at once.
const MAX_QUOTA_CHATS: usize = 2_048;

struct Quota {
    tokens: f64,
    at: std::time::Instant,
    day: i64,
    bytes: usize,
}

pub struct Daemon {
    token_hash: String,
    log: &'static ActivityLog,
    log_dir: PathBuf,
    data_dir: String,
    receiver: Arc<Receiver>,
    /// Serializes ingest's ring and broadcast with a tail's backlog, so a
    /// tail neither misses nor repeats an event.
    order: Mutex<VecDeque<Event>>,
    tails: Mutex<Vec<TailSub>>,
    approvers: Mutex<Vec<Outbox>>,
    /// Waiting approvals by (chat, request id): two chats may wait on the
    /// same client id (S8).
    pending: Mutex<HashMap<(String, String), Pending>>,
    chats: Mutex<HashMap<String, ChatContext>>,
    /// Each running chat's harness pid, from its daemon-scope `run.start`
    /// until its `run.stop` (S2: an approver may not be one of them or run
    /// under one).
    runs: Mutex<HashMap<String, RunPid>>,
    /// A chat that runs as the person with no boundary has started since the
    /// daemon did: what it left running may hold `daemon.token`, so every
    /// `yes` needs the person check from then on (S2 part b, lane V).
    ran_as_you: std::sync::atomic::AtomicBool,
    /// Each chat token's share of the socket (re-review W5R-3): its records
    /// a second and its bytes a day.
    chat_quota: Mutex<HashMap<String, Quota>>,
    /// What `derm status` shows for each running chat, from its `run.start`:
    /// harness, boundary, when, full-access flags (box test w2, BW3: the
    /// tail's backlog lost a chat behind a flood of newer events).
    run_info: Mutex<HashMap<String, Value>>,
    /// When each live chat token was minted, by its hash (hex), for the
    /// state file (BX8).
    minted_at: Mutex<HashMap<String, i64>>,
    /// `<socket folder>/chats.json` when the daemon keeps its chats across a
    /// restart (BX8); `None` in tests that build a daemon by hand.
    state_file: Option<PathBuf>,
    next_conn: AtomicU64,
    /// The model tap (wave 5 lane S), `None` when it could not bind: chats
    /// then run untapped and say so (`derm run` finds no `tap.endpoint`).
    tap: Option<derm_tap::Tap>,
    /// The join (lane S): intent to effect, fed by every ingested event.
    join: Mutex<crate::join::Join>,
    /// Install records (lane X): control-path flags and lockfile diffs.
    installs: Mutex<crate::installs::ingest::InstallRecords>,
    /// Content capture's purge (lane S), run by the service's timer.
    purger: Mutex<crate::content::Purger>,
    /// In-process watchers of `derm run`'s own records (`run.start`,
    /// `run.stop`): the collector's registration (Mac test w5, MW5-18). Not a
    /// `tail`: a tail is dropped when it falls behind, and the in-process
    /// one never counted a line as read, so a flood of OS records ended it
    /// and no later chat reached the collector until a restart.
    run_watchers: Mutex<Vec<Sender<Event>>>,
    pub counters: Counters,
}

/// The chat a tap route belongs to: the running chat whose token hashes to
/// it (`derm_tap::route::of_token_hash`). Read from the receiver's own token
/// table, so a revoked token's route dies with it and a token restored after
/// a restart (BX8) brings its route back, with no second table to keep in
/// step (integration w5, phase 2; lane S's request 1 proposed a route map).
pub fn chat_for_route(receiver: &Receiver, route: &str) -> Option<derm_tap::Chat> {
    if !derm_tap::route::well_formed(route) {
        return None;
    }
    receiver
        .holders_snapshot()
        .into_iter()
        .find(|(hash, _, _)| derm_tap::route::of_token_hash(&hex(hash)) == route)
        .map(|(_, chat, harness)| derm_tap::Chat {
            id: chat,
            harness: harness.to_string(),
        })
}

/// Content capture's target for a chat, from `~/.derm/settings.json` read
/// at each request (lane S): `None` while content is off.
fn content_target(home: Option<&str>, data: &Path) -> Option<derm_tap::content::Target> {
    let home = home?;
    let (prefs, _) = derm_tap::settings::load(&derm_tap::settings::path_for(home));
    prefs.content_days.map(|days| derm_tap::content::Target {
        root: data.to_path_buf(),
        retention_days: days,
    })
}

#[derive(Default)]
pub struct Counters {
    pub events: AtomicU64,
    pub refused_events: AtomicU64,
    pub tails_dropped: AtomicU64,
    pub approvals: AtomicU64,
    /// Whether the collector's registration follower runs (MW5-18): set by
    /// the follower itself, shown by `report`. Off where there is none.
    pub registration_running: std::sync::atomic::AtomicBool,
    /// Set once a registration follower has run, so `report` can tell
    /// "stopped" from "none on this system".
    pub registration_started: std::sync::atomic::AtomicBool,
}

/// The id prefixes the OS feeds write under: the Mac collector's
/// (`es-<day>-<seq>`), the Linux feed's (`auditd-<ms>-<serial>`), the
/// Windows feed's (`sysmon-...`). No chat token posts under them (FP2-S1).
const OS_FEED_ID_PREFIXES: &[&str] = &["es-", "auditd-", "sysmon-"];

fn now_ms() -> i64 {
    store::now_ms()
}

fn ok() -> Reply {
    Reply {
        ok: true,
        error: None,
        scope: None,
        chat: None,
        daemon: None,
        id: None,
        token: None,
        answer: None,
        by: None,
        report: None,
    }
}

pub fn error(message: impl Into<String>) -> Reply {
    Reply {
        ok: false,
        error: Some(message.into()),
        ..ok()
    }
}

/// Text for a log line or a summary: one line, bounded.
fn clip(text: &str, max: usize) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect()
}

/// What a connection does after its reply.
pub enum After {
    Continue,
    Close,
}

impl Daemon {
    /// Builds the daemon around a started log and its own receiver. The
    /// receiver's sink is this daemon's `ingest`; it binds 127.0.0.1 on a
    /// free port.
    pub fn new(
        token: &str,
        log: &'static ActivityLog,
        data_dir: &Path,
        log_prompts: bool,
    ) -> Result<Arc<Self>, String> {
        Self::new_with_state(token, log, data_dir, log_prompts, None)
    }

    /// As `new`, keeping running chats across a restart in `state_file`
    /// (integration w2, box finding BX8): the chat tokens' hashes (never a
    /// token), each running chat's harness pid and start time, and the OTLP
    /// port. At start it takes back the tokens of chats whose harness still
    /// runs, and of tokens minted in the last hour whose chat has not
    /// started, and binds the old port when it is free. The file is used only
    /// when it is a regular file of this user's, mode 0600 or tighter.
    pub fn new_with_state(
        token: &str,
        log: &'static ActivityLog,
        data_dir: &Path,
        log_prompts: bool,
        state_file: Option<PathBuf>,
    ) -> Result<Arc<Self>, String> {
        let saved = state_file.as_deref().and_then(read_state);
        let preferred = saved
            .as_ref()
            .and_then(|v| v.get("otlpPort"))
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok());
        let settings = Arc::new(Mutex::new(Settings {
            enabled: true,
            log_prompts,
            chats: HashSet::new(),
        }));
        let cell: Arc<Mutex<Option<std::sync::Weak<Daemon>>>> = Arc::new(Mutex::new(None));
        let sink_cell = cell.clone();
        let sink: otel_receiver::Sink = Arc::new(move |events| {
            let daemon = sink_cell
                .lock()
                .ok()
                .and_then(|d| d.as_ref().and_then(std::sync::Weak::upgrade));
            if let Some(daemon) = daemon {
                for event in events {
                    daemon.ingest(event);
                }
            }
        });
        let tap_port = saved
            .as_ref()
            .and_then(|v| v.get("tapPort"))
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok());
        let tap_sink: derm_tap::Sink = sink.clone();
        let receiver = Receiver::start_on(settings, sink, preferred)?;
        // Prompt and reply text from a harness's OTel goes to content files
        // while the content switch is on, never into a record (lane S's
        // request 3's rest: the switch replaces DERM_LOG_CONTENT).
        {
            let home = std::env::var("HOME").ok().filter(|h| h.starts_with('/'));
            let data = data_dir.to_path_buf();
            receiver.set_content(Arc::new(move |_| content_target(home.as_deref(), &data)));
        }
        let tap = {
            let routes = receiver.clone();
            let resolve: derm_tap::Resolver = Arc::new(move |route| chat_for_route(&routes, route));
            let home = std::env::var("HOME").ok().filter(|h| h.starts_with('/'));
            let data = data_dir.to_path_buf();
            let content: derm_tap::ContentPolicy =
                Arc::new(move |_| content_target(home.as_deref(), &data));
            let mut config = derm_tap::Config::new(resolve, tap_sink);
            config.preferred_port = tap_port;
            config.content = content;
            match derm_tap::Tap::start(config) {
                Ok(t) => Some(t),
                Err(e) => {
                    eprintln!("derm-daemon: the model tap did not start ({e}); chats run untapped");
                    None
                }
            }
        };
        let daemon = Arc::new(Daemon {
            token_hash: derm_core::token::hash(token),
            log,
            log_dir: log.dir().to_path_buf(),
            data_dir: data_dir.to_string_lossy().into_owned(),
            receiver,
            order: Mutex::new(VecDeque::new()),
            tails: Mutex::new(Vec::new()),
            approvers: Mutex::new(Vec::new()),
            pending: Mutex::new(HashMap::new()),
            chats: Mutex::new(HashMap::new()),
            runs: Mutex::new(HashMap::new()),
            ran_as_you: std::sync::atomic::AtomicBool::new(false),
            chat_quota: Mutex::new(HashMap::new()),
            run_info: Mutex::new(HashMap::new()),
            minted_at: Mutex::new(HashMap::new()),
            state_file,
            next_conn: AtomicU64::new(1),
            tap,
            join: Mutex::new(crate::join::Join::new()),
            installs: Mutex::new(crate::installs::ingest::InstallRecords::new()),
            purger: Mutex::new(crate::content::Purger::new(data_dir)),
            run_watchers: Mutex::new(Vec::new()),
            counters: Counters::default(),
        });
        if let Ok(mut c) = cell.lock() {
            *c = Some(Arc::downgrade(&daemon));
        }
        // Lane T's P4-R1 (integration w5, continue): a chat's `event` and
        // `approve` over the receiver's HTTP port, for a gate inside an sbx
        // VM. The body is parsed as the socket's line is, and answered under
        // the chat scope the same token gets on the socket (rule 2).
        let weak = Arc::downgrade(&daemon);
        daemon
            .receiver
            .set_ops(Arc::new(move |chat, harness, op, gone| {
                let reply = match weak.upgrade() {
                    Some(d) => d.http_op(chat, harness, op, gone),
                    None => error("the daemon is stopping"),
                };
                serde_json::to_value(reply).unwrap_or(Value::Null)
            }));
        if let Some(saved) = saved {
            daemon.restore_state(&saved);
        }
        daemon.save_state();
        Ok(daemon)
    }

    /// Takes back what `save_state` wrote, keeping only chats that still
    /// run (BX8). Returns how many tokens came back.
    fn restore_state(&self, saved: &Value) -> usize {
        let now = now_ms();
        let mut runs: HashMap<String, RunPid> = HashMap::new();
        let mut infos: HashMap<String, Value> = HashMap::new();
        // Chats that had started, running or not: a started chat comes back
        // only while its harness runs.
        let mut started: HashSet<String> = HashSet::new();
        for r in saved
            .get("runs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(chat), Some(pid)) = (
                r.get("chat").and_then(Value::as_str),
                r.get("pid")
                    .and_then(Value::as_u64)
                    .and_then(|p| u32::try_from(p).ok()),
            ) else {
                continue;
            };
            let run = RunPid {
                pid,
                start_time: r.get("startTime").and_then(Value::as_u64),
            };
            if let Some(i) = r.get("info").map(run_info_restored) {
                infos.insert(chat.to_string(), i);
            }
            started.insert(chat.to_string());
            // A run comes back only with the start time it was recorded with
            // and never as pid 1 or 0 (review W2-S9: a planted run with no
            // start time would match any live process for good).
            if crate::activity::registry::valid_chat_id(chat)
                && pid > 1
                && run.start_time.is_some()
                && run.alive()
            {
                runs.insert(chat.to_string(), run);
            }
        }
        let mut restored = 0;
        let mut minted_at = HashMap::new();
        for t in saved
            .get("tokens")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(sha), Some(chat), Some(harness), Some(at)) = (
                t.get("sha256").and_then(Value::as_str),
                t.get("chat").and_then(Value::as_str),
                t.get("harness")
                    .and_then(Value::as_str)
                    .and_then(harness_env::harness_id),
                t.get("mintedAt").and_then(Value::as_i64),
            ) else {
                continue;
            };
            let Some(hash) = parse_sha256(sha) else {
                continue;
            };
            let keep = runs.contains_key(chat)
                || (!started.contains(chat) && now.saturating_sub(at) < UNSTARTED_TOKEN_MS);
            if keep
                && crate::activity::registry::valid_chat_id(chat)
                && self.receiver.restore(hash, chat, harness)
            {
                minted_at.insert(sha.to_string(), at);
                restored += 1;
            }
        }
        if let Ok(mut m) = self.minted_at.lock() {
            *m = minted_at;
        }
        infos.retain(|chat, _| runs.contains_key(chat));
        if let Ok(mut i) = self.run_info.lock() {
            *i = infos;
        }
        if let Ok(mut r) = self.runs.lock() {
            *r = runs;
        }
        restored
    }

    /// The chats `derm run` started that still run: chat, pid, whether that
    /// process is still the one that started (its start time), and what its
    /// `run.start` said. Daemon scope only (in `report`).
    pub fn running(&self) -> Vec<Value> {
        let runs = self.runs.lock().map(|r| r.clone()).unwrap_or_default();
        let info = self.run_info.lock().map(|i| i.clone()).unwrap_or_default();
        let mut out: Vec<Value> = runs
            .iter()
            .map(|(chat, run)| {
                let mut row = info.get(chat).cloned().unwrap_or_else(|| json!({}));
                if let Value::Object(m) = &mut row {
                    m.insert("chat".into(), Value::String(chat.clone()));
                    m.insert("pid".into(), Value::from(run.pid));
                    m.insert("alive".into(), Value::Bool(run.alive()));
                }
                row
            })
            .collect();
        out.sort_by(|a, b| {
            a.get("since")
                .and_then(Value::as_i64)
                .cmp(&b.get("since").and_then(Value::as_i64))
                .then_with(|| a["chat"].as_str().cmp(&b["chat"].as_str()))
        });
        out
    }

    /// Writes the state file (BX8): token hashes, running chats, the port.
    /// Best effort; a failure leaves the old file, and the next change
    /// writes again.
    fn save_state(&self) {
        let Some(path) = self.state_file.as_deref() else {
            return;
        };
        let minted = self.minted_at.lock().map(|m| m.clone()).unwrap_or_default();
        let tokens: Vec<Value> = self
            .receiver
            .holders_snapshot()
            .into_iter()
            .filter_map(|(hash, chat, harness)| {
                let sha = hex(&hash);
                minted.get(&sha).map(
                    |at| json!({"sha256": sha, "chat": chat, "harness": harness, "mintedAt": at}),
                )
            })
            .collect();
        let info = self.run_info.lock().map(|i| i.clone()).unwrap_or_default();
        let runs: Vec<Value> = self
            .runs
            .lock()
            .map(|r| {
                r.iter()
                    .map(|(chat, run)| {
                        let mut row =
                            json!({"chat": chat, "pid": run.pid, "startTime": run.start_time});
                        if let (Some(i), Value::Object(m)) = (info.get(chat), &mut row) {
                            m.insert("info".into(), i.clone());
                        }
                        row
                    })
                    .collect()
            })
            .unwrap_or_default();
        let port = self
            .receiver
            .endpoint()
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok());
        let tap_port = self.tap.as_ref().map(derm_tap::Tap::port);
        let text = json!({
            "version": 1,
            "otlpPort": port,
            "tapPort": tap_port,
            "tokens": tokens,
            "runs": runs,
        })
        .to_string();
        let _ = crate::service::write_private(path, &text);
    }

    pub fn endpoint(&self) -> String {
        self.receiver.endpoint()
    }

    /// The model tap's loopback URL, which the service publishes as
    /// `tap.endpoint`; `None` when the tap did not start.
    pub fn tap_endpoint(&self) -> Option<String> {
        self.tap.as_ref().map(derm_tap::Tap::endpoint)
    }

    /// One pass of content capture's purge (lane S, case 126): the files past
    /// their retention go, and each chat's `content.purge` is recorded.
    pub fn content_pass(&self, now: i64) -> usize {
        let made = self
            .purger
            .lock()
            .map(|mut p| p.pass(now))
            .unwrap_or_default();
        let n = made.len();
        for e in made {
            self.ingest(e);
        }
        n
    }

    pub fn next_conn(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// The collector registration's state for `report` (MW5-18): `running`,
    /// `stopped` (no new chat reaches the collector until a restart), or
    /// null where none was started (Linux, tests).
    pub fn registration_state(&self) -> Value {
        if !self.counters.registration_started.load(Ordering::SeqCst) {
            return Value::Null;
        }
        if self.counters.registration_running.load(Ordering::SeqCst) {
            json!("running")
        } else {
            json!("stopped")
        }
    }

    /// Every `derm run` record (`Source::Run`) the daemon takes from now on,
    /// in order, for an in-process watcher that must not miss one (MW5-18).
    /// Dropping the receiver ends the watch.
    pub fn watch_runs(&self) -> Rx<Event> {
        let (tx, rx) = mpsc::channel();
        if let Ok(mut watchers) = self.run_watchers.lock() {
            watchers.push(tx);
        }
        rx
    }

    /// Stores one event and streams it. The daemon stamps `at` (case 35);
    /// a client's own time moves to `detail.harnessAt`. Returns the id kept.
    pub fn ingest(&self, mut event: Event) -> String {
        // The OS feeds' exec records keep the argv's shape only, whatever the
        // content switch (box test w5, BW5-12; case 85): a harness's prompt
        // and an agent's commands were in the log as typed.
        if event.kind == "exec" && matches!(event.source, Source::Auditd | Source::Eslogger) {
            shape_exec(&mut event);
        }
        if event.at > 0 {
            if let Value::Object(map) = &mut event.detail {
                map.entry("harnessAt").or_insert(Value::from(event.at));
            }
        }
        event.at = now_ms();
        let event = store::bound_event(event);
        self.log.submit(Entry::Event(event.clone()));
        self.counters.events.fetch_add(1, Ordering::Relaxed);
        let line = serde_json::to_string(&Push::Event(event.clone())).ok();
        let Ok(mut ring) = self.order.lock() else {
            return event.id;
        };
        ring.push_back(event.clone());
        while ring.len() > RING_CAPACITY {
            ring.pop_front();
        }
        if let (Some(line), Ok(mut tails)) = (line, self.tails.lock()) {
            tails.retain(|sub| {
                if sub.chat.as_deref().is_some_and(|c| c != event.chat_id) {
                    return true;
                }
                if sub.out.pending() >= MAX_PENDING_LINES || !sub.out.send_line(line.clone()) {
                    self.counters.tails_dropped.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                true
            });
        }
        drop(ring);
        // `derm run`'s own records to the in-process watchers (MW5-18). Only
        // the daemon scope posts `run` records (`op_event` refuses them from a
        // chat token), so this stays small (review FP3-S6).
        if event.source == Source::Run {
            if let Ok(mut watchers) = self.run_watchers.lock() {
                watchers.retain(|w| w.send(event.clone()).is_ok());
            }
        }
        // Install records (lane X's request 4, integration w5 continue): the
        // control-path flags and the lockfile diffs read every event, the
        // join's candidate sets included, before the join sees it, so a write
        // is held when the join's set for it arrives. The working folder is
        // the chat's from its daemon-scope run.start, never the record's.
        if event.source != Source::Derm || event.kind == "join.candidates" {
            let cwd = |chat: &str| {
                self.chats
                    .lock()
                    .ok()
                    .and_then(|c| c.get(chat).and_then(|x| x.folders.first().cloned()))
            };
            let made = self
                .installs
                .lock()
                .map(|mut r| r.observe(&event, cwd, event.at))
                .unwrap_or_default();
            for e in made {
                self.ingest(e);
            }
        }
        // The join (lane S) reads every event but its own; what it makes is
        // ingested after its lock is released, and `observe` ignores the
        // `derm` records it gets back, so this never loops.
        if event.source != Source::Derm {
            let made = self
                .join
                .lock()
                .map(|mut j| j.observe(&event))
                .unwrap_or_default();
            for e in made {
                self.ingest(e);
            }
        }
        event.id
    }

    fn record_approval(&self, record: ApprovalRecord) {
        self.log.submit(Entry::Approval(record));
    }

    /// `hello`: the daemon's token gives the daemon scope, a minted chat
    /// token the chat scope. Anything else closes the connection.
    pub fn hello(&self, token: &str) -> Option<Who> {
        if !derm_core::token::well_formed(token) {
            return None;
        }
        if derm_core::token::hash(token) == self.token_hash {
            return Some(Who::Daemon);
        }
        self.receiver
            .holder_of(token)
            .map(|(chat, harness)| Who::Chat {
                chat,
                harness: harness.to_string(),
            })
    }

    pub fn hello_reply(who: &Who) -> Reply {
        match who {
            Who::Daemon => Reply {
                scope: Some(Scope::Daemon),
                daemon: Some(DaemonInfo {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    pid: std::process::id(),
                    protocol: PROTOCOL_VERSION,
                }),
                ..ok()
            },
            Who::Chat { chat, .. } => Reply {
                scope: Some(Scope::Chat),
                chat: Some(chat.clone()),
                ..ok()
            },
        }
    }

    /// One request after `hello`. The reply goes out first; `tail` and
    /// `approver` then push on `out`.
    pub fn handle(self: &Arc<Self>, who: &Who, request: Request, out: &Outbox) -> After {
        match request {
            Request::Hello { .. } => {
                out.send(&error("hello once"));
            }
            Request::Event { event } => {
                out.send(&self.op_event(who, event));
            }
            Request::Tail { since, chat } => self.op_tail(who, since, chat, out),
            Request::Report { chat, since, until } => {
                out.send(&self.op_report(who, chat, since, until));
            }
            Request::Approve { request } => {
                out.send(&self.op_approve(who, request));
            }
            Request::Approver {} => {
                if *who != Who::Daemon {
                    out.send(&error("approver needs daemon scope"));
                } else if let Some(why) = out.peer.as_deref().and_then(|p| self.approver_refusal(p))
                {
                    self.approver_event(out, false, Some(&why));
                    out.send(&error(format!("approver refused: {why}")));
                } else if let Ok(mut approvers) = self.approvers.lock() {
                    approvers.retain(|a| a.conn != out.conn);
                    approvers.push(out.clone());
                    drop(approvers);
                    self.approver_event(out, true, None);
                    out.send(&ok());
                }
            }
            Request::Answer {
                id,
                answer,
                chat,
                proof,
            } => {
                // S2 part b (lane V): a yes an agent could forge needs the
                // person's password; the bytes are wiped once checked.
                let mut password = proof.map(|p| p.password.into_bytes());
                let ran_as_you = self.ran_as_you.load(Ordering::SeqCst);
                out.send(&self.op_answer_proved(
                    out.conn,
                    &id,
                    chat.as_deref(),
                    answer,
                    password.as_mut(),
                    ran_as_you,
                ));
            }
            Request::TokenMint { chat, harness } => {
                out.send(&self.op_mint(who, &chat, &harness));
            }
            Request::Cu { action, chat, app } => {
                out.send(&op_cu(who, action, chat.as_deref(), app.as_deref()));
            }
        }
        After::Continue
    }

    /// A chat's op over HTTP (P4-R1): the field is read as the socket reads
    /// its line, with `deny_unknown_fields`, then answered as the socket's
    /// chat scope answers it.
    fn http_op(
        &self,
        chat: &str,
        harness: &str,
        op: otel_receiver::ChatOp,
        gone: &dyn Fn() -> bool,
    ) -> Reply {
        let who = Who::Chat {
            chat: chat.to_string(),
            harness: harness.to_string(),
        };
        let line = match op {
            otel_receiver::ChatOp::Event(event) => json!({"op": "event", "event": event}),
            otel_receiver::ChatOp::Approve(request) => {
                json!({"op": "approve", "request": request})
            }
        };
        match serde_json::from_value::<Request>(line) {
            Ok(Request::Event { event }) => self.op_event(&who, event),
            Ok(Request::Approve { request }) => self.op_approve_until(&who, request, gone),
            Ok(_) => error("not an op this route takes"),
            Err(e) => error(format!("bad request: {e}")),
        }
    }

    /// Takes one record of `bytes` from a chat's share of the socket.
    fn take_chat_quota(
        &self,
        chat: &str,
        bytes: usize,
        now_ms: i64,
        now: std::time::Instant,
    ) -> Result<(), &'static str> {
        let Ok(mut all) = self.chat_quota.lock() else {
            return Err("busy");
        };
        if !all.contains_key(chat) && all.len() >= MAX_QUOTA_CHATS {
            // A chat at rest gives way first; else the one with the least
            // spent today.
            if let Some(k) = all
                .iter()
                .min_by_key(|(_, q)| q.bytes)
                .map(|(k, _)| k.clone())
            {
                all.remove(&k);
            }
        }
        let day = now_ms.div_euclid(86_400_000);
        let q = all.entry(chat.to_string()).or_insert(Quota {
            tokens: SOCKET_BURST_PER_CHAT,
            at: now,
            day,
            bytes: 0,
        });
        q.tokens = (q.tokens
            + now.saturating_duration_since(q.at).as_secs_f64() * SOCKET_RATE_PER_CHAT_SEC)
            .min(SOCKET_BURST_PER_CHAT);
        q.at = now;
        if q.day != day {
            q.day = day;
            q.bytes = 0;
        }
        if q.tokens < 1.0 {
            return Err("this chat posts too fast; record dropped");
        }
        if q.bytes.saturating_add(bytes) > SOCKET_BYTES_PER_CHAT_DAY {
            return Err("this chat has posted its day's share of records; record dropped");
        }
        q.tokens -= 1.0;
        q.bytes += bytes;
        Ok(())
    }

    fn op_event(&self, who: &Who, mut event: Event) -> Reply {
        // A computer-use action record is the daemon's own (lane U's request
        // R1; `trust: daemon` in `contracts/wave5-records.schema.json`): no
        // socket client posts one, under any source, in either scope.
        if event.kind == "cu.action" {
            self.counters.refused_events.fetch_add(1, Ordering::Relaxed);
            return error("cu.action events are written by the daemon");
        }
        match who {
            Who::Chat { chat, harness } => {
                // A chat token sits in a harness's environment: it may post
                // its own telemetry and adapter records, in its own chat,
                // and nothing a kernel feed, computer use or `derm run` writes
                // (the fork's review U2).
                if !matches!(event.source, Source::Adapter | Source::Otel) {
                    self.counters.refused_events.fetch_add(1, Ordering::Relaxed);
                    return error("a chat token posts only adapter and otel events");
                }
                // Nor under an OS feed's id (fix pass 2's review, FP2-S1):
                // those ids are predictable, and the log keeps the first
                // record under an id, so a record posted first would hide
                // the kernel's. Checked as the log will write the id.
                let id = store::bound_event(Event {
                    detail: Value::Null,
                    ..event.clone()
                })
                .id
                .to_ascii_lowercase();
                if OS_FEED_ID_PREFIXES.iter().any(|p| id.starts_with(p)) {
                    self.counters.refused_events.fetch_add(1, Ordering::Relaxed);
                    return error("ids starting es-, auditd- or sysmon- are the OS feeds'");
                }
                event.chat_id = chat.clone();
                event.harness = harness.clone();
                // A chat token is the agent's too (case 66), so its posts are
                // bounded per chat: the reviewer's agent wrote 1.3 GB in
                // 22 s over the socket (re-review W5R-3).
                let bytes = serde_json::to_vec(&event).map(|v| v.len()).unwrap_or(0);
                if let Err(why) =
                    self.take_chat_quota(chat, bytes, now_ms(), std::time::Instant::now())
                {
                    self.counters.refused_events.fetch_add(1, Ordering::Relaxed);
                    return error(why);
                }
            }
            Who::Daemon => {
                // Approval records are the daemon's own (`approve`).
                if event.source == Source::Approval {
                    self.counters.refused_events.fetch_add(1, Ordering::Relaxed);
                    return error("approval events are written by the daemon");
                }
                // So are wave 5's tap and derm records (the wave 5 base,
                // `contracts/events.md` section 5): the tap runs in the
                // daemon, and the join and the derived records are its own.
                if matches!(event.source, Source::Tap | Source::Derm) {
                    self.counters.refused_events.fetch_add(1, Ordering::Relaxed);
                    return error("tap and derm events are written by the daemon");
                }
                if event.source == Source::Run && event.kind == "run.start" {
                    self.set_chat_from_run(&event);
                    if let (Some(pid), Ok(mut runs)) = (event.pid, self.runs.lock()) {
                        if runs.len() < 2_048 || runs.contains_key(&event.chat_id) {
                            runs.insert(event.chat_id.clone(), RunPid::of(pid));
                            if let Ok(mut info) = self.run_info.lock() {
                                let run = run_info_of(&event, now_ms());
                                if approver::person::runs_as_person(&run) {
                                    self.ran_as_you.store(true, Ordering::SeqCst);
                                }
                                info.insert(event.chat_id.clone(), run);
                            }
                        }
                    }
                    self.save_state();
                }
                // The run is over: its chat tokens open nothing from now on
                // (integration w1, lane D's request 2). A connection already
                // greeted keeps its scope until it closes.
                if event.source == Source::Run && event.kind == "run.stop" {
                    self.receiver.revoke_chat(&event.chat_id);
                    if let Some(tap) = &self.tap {
                        tap.forget_chat(&event.chat_id);
                    }
                    if let Ok(mut runs) = self.runs.lock() {
                        runs.remove(&event.chat_id);
                    }
                    if let Ok(mut info) = self.run_info.lock() {
                        info.remove(&event.chat_id);
                    }
                    self.save_state();
                }
            }
        }
        if store::bound_event(event.clone()).id.is_empty() {
            return error("event id is empty");
        }
        if let Some(held) = matches!(who, Who::Chat { .. })
            .then(|| self.held_gate_decision(&event))
            .flatten()
        {
            // The hook and the agent share the chat token (case 66), and the
            // agent can post first (integration w2 review, W2-S3), so a second
            // copy is never dropped: it is kept under its own id, and the
            // daemon records the conflict, which only it can write.
            return self.keep_conflict(event, held);
        }
        if let Some(code) = matches!(who, Who::Chat { .. })
            .then(|| self.held_code_call(&event))
            .flatten()
        {
            // Fix pass 6 (FP5R-3, FP5R-4): no harness's gate posts for a
            // code tool call (Codex sends no hook for Code Mode's `exec` or
            // `wait`), so a chat's record naming one is the agent's. It is
            // kept as a conflict copy and flagged; the join takes a code
            // call's times from the tap alone.
            return self.keep_conflict(event, code);
        }
        let id = self.ingest(event);
        Reply {
            id: Some(id),
            ..ok()
        }
    }

    /// A chat-scope post of a gate decision already held (`held`, by its id
    /// or its call): stored as `<id>-conflict-<uuid>` with
    /// `detail.conflictsWith` naming the held one, and a daemon-written
    /// `gate.conflict` (source `approval`) naming both.
    fn keep_conflict(&self, mut event: Event, held: String) -> Reply {
        let original = store::bound_event(event.clone()).id;
        // The copy's id must survive `bound_event`'s cut to `MAX_ID`, or a long
        // original would come back as itself (re-review W2-R2): the original
        // part is cut so the suffix always fits.
        let suffix = format!("-conflict-{}", uuid::Uuid::new_v4().simple());
        let keep = store::MAX_ID.saturating_sub(suffix.len());
        let head: String = original.chars().take(keep).collect();
        let copy = format!("{head}{suffix}");
        event.id = copy.clone();
        match &mut event.detail {
            Value::Object(map) => {
                map.insert("conflictsWith".into(), Value::String(held.clone()));
            }
            other => *other = json!({"value": other.clone(), "conflictsWith": held}),
        }
        let (chat, harness, kind, source) = (
            event.chat_id.clone(),
            event.harness.clone(),
            event.kind.clone(),
            event.source,
        );
        let kept = self.ingest(event);
        self.ingest(Event {
            id: format!("gate-conflict-{}", uuid::Uuid::new_v4().simple()),
            at: 0,
            chat_id: chat,
            harness,
            source: Source::Approval,
            kind: "gate.conflict".into(),
            summary: clip(
                &format!("two records for the gate decision {held}"),
                200,
            ),
            detail: json!({"id": held, "copy": kept, "posted": original, "kind": kind, "source": source}),
            pid: None,
            approval_id: None,
        });
        Reply {
            id: Some(kept),
            ..ok()
        }
    }

    /// The id of a gate decision the ring holds under this event's chat and
    /// id (S9), or for its call. Readers keep the first copy whatever is written later
    /// (`store::may_replace`); this refusal only tells the poster, for a
    /// decision still in the last `RING_CAPACITY` events.
    ///
    /// Since gate decision ids end in random bits (box test w2, BW2), the
    /// agent's forgery is a decision under an id of its own for the same
    /// call: a second adapter decision in the chat naming the same
    /// `detail.toolUseId` counts as the same decision too (fix pass 1's
    /// review, FP1-S4). OTel records keep their attributes elsewhere, so only
    /// adapter records are joined this way.
    ///
    /// An earlier record whose `detail.decision` is `deferred` decides
    /// nothing: Cursor's dialect writes one from preToolUse for an MCP call
    /// and the decision from beforeMCPExecution, under the same call (Mac
    /// test w4, MW4-10). So the join by call skips it. The join by id does
    /// not, and a `deferred` posted after a decision is still a conflict.
    fn held_gate_decision(&self, event: &Event) -> Option<String> {
        let new = store::bound_event(event.clone());
        let call = adapter_call(&new);
        let ring = self.order.lock().ok()?;
        ring.iter()
            .rev()
            .find(|old| {
                old.chat_id == event.chat_id
                    && store::is_gate_decision(old)
                    && (old.id == new.id
                        || (call.is_some()
                            && adapter_call(old) == call
                            && !cursor_deferral_then_decision(old, &new)))
            })
            .map(|old| old.id.clone())
    }

    /// The tap's record of a code tool call (`derm_core::policy::CODE_TOOLS`)
    /// in this event's chat that an adapter `approval` or `tool.call` names
    /// by `detail.toolUseId`, for a record still in the ring (fix pass 6).
    fn held_code_call(&self, event: &Event) -> Option<String> {
        if event.source != Source::Adapter
            || !matches!(event.kind.as_str(), "approval" | "tool.call")
        {
            return None;
        }
        let call = event
            .detail
            .get("toolUseId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())?;
        let ring = self.order.lock().ok()?;
        ring.iter()
            .rev()
            .find(|old| {
                old.chat_id == event.chat_id
                    && old.source == Source::Tap
                    && old.kind == "tap.call"
                    && old.detail.get("callId").and_then(Value::as_str) == Some(call)
                    && old
                        .detail
                        .get("toolNormalized")
                        .and_then(Value::as_str)
                        .is_some_and(|t| derm_core::policy::code_tool(&old.harness, t))
            })
            .map(|old| old.id.clone())
    }

    /// A daemon-scope `run.start` may name the chat's folders
    /// (`detail.folders`, or `detail.cwd`), which the check needs for
    /// `writeOutsideFolders`. Only the daemon scope may: a chat could
    /// otherwise widen its own folders.
    fn set_chat_from_run(&self, event: &Event) {
        let mut folders: Vec<String> = event
            .detail
            .get("folders")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if let Some(cwd) = event.detail.get("cwd").and_then(Value::as_str) {
            folders.insert(0, cwd.to_string());
        }
        let Some(context) = clean_context(ChatContext {
            chat_id: event.chat_id.clone(),
            harness: event.harness.clone(),
            folders,
        }) else {
            return;
        };
        if let Ok(mut chats) = self.chats.lock() {
            if chats.len() >= 2_048 && !chats.contains_key(&context.chat_id) {
                return;
            }
            chats.insert(context.chat_id.clone(), context);
        }
    }

    fn op_tail(
        self: &Arc<Self>,
        who: &Who,
        since: Option<i64>,
        chat: Option<String>,
        out: &Outbox,
    ) {
        let chat = match (who, chat) {
            (Who::Daemon, chat) => chat,
            (Who::Chat { chat: own, .. }, Some(c)) if *own == c => Some(c),
            (Who::Chat { .. }, Some(_)) => {
                out.send(&error("a chat token tails only its own chat"));
                return;
            }
            (Who::Chat { .. }, None) => {
                out.send(&error("tail needs daemon scope or a chat filter"));
                return;
            }
        };
        // The log on disk first, outside the lock; then, under it, the ring
        // (which holds anything not yet on disk), the subscription, and only
        // then the `ok`. `ingest` broadcasts under the same lock, so nothing
        // a client does after it reads `ok` can be ingested before the
        // subscription exists (lane K's request 5: the old order sent `ok`
        // first, and an event ingested in between was never pushed).
        let (mut backlog, mut cut): (Vec<Event>, bool) = match since {
            Some(since) => {
                let r = store::read(&self.log_dir, since, i64::MAX, chat.as_deref(), MAX_BACKLOG);
                (r.events, r.truncated)
            }
            None => (Vec::new(), false),
        };
        let Ok(ring) = self.order.lock() else {
            out.send(&error("busy"));
            return;
        };
        if let Some(since) = since {
            let merged = merge_backlog(backlog, ring.iter(), since, chat.as_deref());
            cut |= merged.1;
            backlog = merged.0;
        }
        let Ok(mut tails) = self.tails.lock() else {
            out.send(&error("busy"));
            return;
        };
        // A backlog cut to the newest records says so (box test w5, BW5-12:
        // a busy chat's tail stopped at 5,000 with no notice).
        let mut reply = ok();
        if cut {
            reply.report = Some(
                json!({"backlogCut": true, "backlogSent": backlog.len(), "backlogMax": MAX_BACKLOG}),
            );
        }
        out.send(&reply);
        for event in backlog {
            out.send(&Push::Event(event));
        }
        tails.push(TailSub {
            chat,
            out: out.clone(),
        });
        drop(tails);
        drop(ring);
        #[cfg(test)]
        tests::after_tail_ok();
    }

    /// The `report` object (contract, section 5: lane B defines it, lane J
    /// renders it): counts over the window, and the check's flags.
    fn op_report(&self, who: &Who, chat: Option<String>, since: i64, until: i64) -> Reply {
        if *who != Who::Daemon {
            return error("report needs daemon scope");
        }
        if until < since {
            return error("until is before since");
        }
        let mut report = self.report(chat.as_deref(), since, until);
        if let Value::Object(m) = &mut report {
            let running: Vec<Value> = self
                .running()
                .into_iter()
                .filter(|r| chat.as_deref().is_none_or(|c| r["chat"] == c))
                .collect();
            m.insert("running".into(), Value::Array(running));
        }
        fit_report_with(&mut report, REPORT_BUDGET, Some(self.data_dir.as_str()));
        Reply {
            report: Some(report),
            ..ok()
        }
    }

    pub fn report(&self, chat: Option<&str>, since: i64, until: i64) -> Value {
        let _guard = self.log.read_lock.lock();
        let back = store::read(&self.log_dir, since, until, chat, REPORT_READ_LIMIT);
        let mut by_source: Map<String, Value> = Map::new();
        let mut by_kind: Map<String, Value> = Map::new();
        let mut approvals: Map<String, Value> = Map::new();
        for e in &back.events {
            bump(
                &mut by_source,
                &serde_json::to_value(e.source).unwrap_or_default(),
            );
            bump(&mut by_kind, &Value::String(e.kind.clone()));
            if e.source == Source::Approval {
                if let Some(by) = e.detail.get("by").and_then(Value::as_str) {
                    let answer = e.detail.get("answer").and_then(Value::as_str).unwrap_or("");
                    bump(&mut approvals, &Value::String(format!("{answer}:{by}")));
                }
            }
        }
        let chats = self.chats.lock().map(|c| c.clone()).unwrap_or_default();
        let collector = collector_events(since, until, chat);
        let mut check = flags_report(
            &self.log_dir,
            Some(&self.data_dir),
            chat,
            since,
            until,
            &chats,
            collector,
            now_ms(),
        );
        check.dropped = self.log.dropped();
        let status = collector_status();
        // A chat's run, from its own run records (MW5-23), read over the
        // whole log so a window that misses its start still finds it
        // (FP4-S5): its last start up to `until`, and the first stop after.
        // The window's own run records when it holds the start; the whole
        // log only when it does not (the re-review's R5: that read's cost
        // grows with the log).
        let is_run = |e: &crate::activity::types::ActivityEvent| {
            e.source == Source::Run && (e.kind == "run.start" || e.kind == "run.stop")
        };
        let in_window = back
            .events
            .iter()
            .any(|e| e.source == Source::Run && e.kind == "run.start");
        let run = chat.and_then(|c| {
            let whole;
            let runs: Vec<&crate::activity::types::ActivityEvent> = if in_window {
                back.events.iter().filter(|e| is_run(e)).collect()
            } else {
                whole = store::read_runs(&self.log_dir, c, until, 256);
                whole.events.iter().collect()
            };
            let mut runs = runs;
            runs.sort_by_key(|e| e.at);
            let start = runs.iter().rposition(|e| e.kind == "run.start")?;
            let stop = runs[start..]
                .iter()
                .find(|e| e.kind == "run.stop")
                .map(|e| e.at);
            Some((runs[start].at, stop))
        });
        let (kernel_total, kernel_inside, kernel_during) =
            kernel_drops_for(status.as_ref(), since, until, run);
        // A bound when a gap in the window is merged or reaches past either
        // edge (R5, the second re-review's R2-5).
        let window_up_to = kernel_inside.as_array().map(|gaps| {
            gaps.iter().any(|g| {
                let merged = g.get("merged").and_then(Value::as_u64).unwrap_or(1) > 1;
                let from = g.get("fromMs").and_then(Value::as_i64);
                let to = g.get("toMs").and_then(Value::as_i64);
                merged || from.is_none_or(|t| t < since) || to.is_none_or(|t| t > until)
            })
        });
        json!({
            "since": since,
            "until": until,
            "chat": chat,
            "events": back.events.len(),
            "flags": check.flags.len(),
            "bySource": by_source,
            "byKind": by_kind,
            "approvals": approvals,
            "chainOk": back.chain_ok && check.chain_ok,
            "truncated": back.truncated || check.truncated,
            "dropped": check.dropped,
            "check": check,
            // MW5-18: whether new chats still reach the collector, and how
            // many tails the daemon dropped for falling behind.
            "osRegistration": self.registration_state(),
            // MW5-19: eslogger lines the Mac collector dropped because it
            // read them slower than they came (its own count, since it
            // started); null where there is no collector.
            "collectorDropped": status.as_ref().and_then(|s| s.get("dropped")).and_then(Value::as_u64),
            // MW5-23: what the kernel dropped for the collector's eslogger
            // (its total, the gaps in this window, and for a chat, how many
            // fell during its run, which the OS layer then did not see).
            "osKernelDropped": kernel_total,
            "osKernelDrops": kernel_inside,
            "chatOsMissed": kernel_during,
            // FP4-S5: the count is a bound, not exact, when a gap it takes
            // stands for merged gaps or reaches outside the run.
            "chatOsMissedUpTo": run.map(|r| kernel_drops_up_to(status.as_ref(), r)),
            // R5: the window's count is a bound when a gap in it is merged.
            "osKernelDropsUpTo": window_up_to,
            "tailsDropped": self.counters.tails_dropped.load(Ordering::Relaxed),
        })
    }

    fn op_approve(&self, who: &Who, request: ApprovalRequest) -> Reply {
        self.op_approve_until(who, request, &|| false)
    }

    /// As `op_approve`, and stops waiting with `no`, by no one, once `gone`
    /// says the client hung up (an HTTP ask, W5C-S3).
    fn op_approve_until(
        &self,
        who: &Who,
        mut request: ApprovalRequest,
        gone: &dyn Fn() -> bool,
    ) -> Reply {
        if let Who::Chat { chat, harness } = who {
            request.chat = chat.clone();
            request.harness = harness.clone();
        }
        request.id = clip(&request.id, 128);
        request.tool = clip(&request.tool, 200);
        request.summary = clip(&request.summary, 500);
        request.timeout_seconds = request
            .timeout_seconds
            .clamp(MIN_APPROVE_SECONDS, MAX_APPROVE_SECONDS);
        if request.id.is_empty() {
            return error("approval id is empty");
        }
        self.counters.approvals.fetch_add(1, Ordering::Relaxed);
        let record_id = format!("approval-{}", uuid::Uuid::new_v4().simple());
        self.approval_event(&record_id, &request, None, None, Value::Null);
        let (answer, by, approver) = self.wait_for_answer(&request, gone);
        self.approval_event(&record_id, &request, Some(answer), Some(by), approver);
        self.record_approval(ApprovalRecord {
            id: record_id,
            chat_id: request.chat.clone(),
            harness: request.harness.clone(),
            subject: ApprovalSubject::Tool,
            target: request.tool.clone(),
            scope: ApprovalScope::Once,
            granted: answer == Answer::Yes,
            granted_at: now_ms(),
            ended_at: None,
        });
        Reply {
            id: Some(request.id),
            answer: Some(answer),
            by: Some(by),
            ..ok()
        }
    }

    /// Writes the approval's event; the outcome replaces the request under
    /// the same id (case 35: last copy per id).
    fn approval_event(
        &self,
        record_id: &str,
        request: &ApprovalRequest,
        answer: Option<Answer>,
        by: Option<AnsweredBy>,
        approver: Value,
    ) {
        let word = |v: Option<Value>| v.and_then(|v| v.as_str().map(str::to_string));
        let answer_text = word(answer.and_then(|a| serde_json::to_value(a).ok()));
        let by_text = word(by.and_then(|b| serde_json::to_value(b).ok()));
        let summary = match (&answer_text, &by_text) {
            (Some(a), Some(b)) => format!("{}: {a} ({b})", request.tool),
            _ => format!("{}: asked", request.tool),
        };
        let mut detail = json!({
            "requestId": request.id,
            "tool": request.tool,
            "request": request.summary,
            "timeoutSeconds": request.timeout_seconds,
        });
        if let (Some(a), Some(b), Value::Object(map)) = (answer_text, by_text, &mut detail) {
            map.insert("answer".into(), Value::String(a));
            map.insert("by".into(), Value::String(b));
            if !approver.is_null() {
                map.insert("approver".into(), approver);
            }
        }
        self.ingest(Event {
            id: record_id.to_string(),
            at: 0,
            chat_id: request.chat.clone(),
            harness: request.harness.clone(),
            source: Source::Approval,
            kind: "approval".into(),
            summary,
            detail,
            pid: None,
            approval_id: Some(request.id.clone()),
        });
    }

    fn op_mint(&self, who: &Who, chat: &str, harness: &str) -> Reply {
        if *who != Who::Daemon {
            return error("token.mint needs daemon scope");
        }
        if !crate::activity::registry::valid_chat_id(chat) {
            return error("chat id: 1 to 128 of [A-Za-z0-9_.:-]");
        }
        let Some(harness) = harness_env::harness_id(harness) else {
            return error("unknown harness");
        };
        match self.receiver.mint(chat, harness) {
            Some(token) => {
                if let Ok(mut m) = self.minted_at.lock() {
                    let live: HashSet<String> = self
                        .receiver
                        .holders_snapshot()
                        .iter()
                        .map(|(h, _, _)| hex(h))
                        .collect();
                    m.retain(|sha, _| live.contains(sha));
                    m.insert(hex(&Receiver::token_hash(&token)), now_ms());
                }
                self.save_state();
                Reply {
                    token: Some(token),
                    ..ok()
                }
            }
            None => error("could not mint a token"),
        }
    }

    /// Drops a connection's approver and tail registrations when it closes.
    pub fn forget(&self, conn: u64) {
        if let Ok(mut a) = self.approvers.lock() {
            a.retain(|o| o.conn != conn);
        }
        if let Ok(mut t) = self.tails.lock() {
            t.retain(|s| s.out.conn != conn);
        }
    }

    /// Runs retention now: logs past 7 days, screenshots past 3, the 1 GiB
    /// cap (`activity/retention.rs`). The writer also runs it on its first
    /// write each day; this covers a day with no writes.
    pub fn retention_pass(&self, now: i64) -> usize {
        let _guard = self.log.read_lock.lock();
        retention_pass(&self.log_dir, now)
    }
}

/// `cu` (lane K's request 3): computer use's controls, daemon scope only.
/// A chat token may not stop, read or revoke computer use: it is the
/// agent's (case 66). Where computer use does not run (not macOS, or the
/// feature off) the answer says so.
fn op_cu(who: &Who, action: CuAction, chat: Option<&str>, app: Option<&str>) -> Reply {
    if *who != Who::Daemon {
        return error("cu needs daemon scope");
    }
    let need = |v: Option<&str>, what: &str| -> Result<String, String> {
        v.filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("cu {what} is missing"))
    };
    #[cfg(feature = "computer-use")]
    {
        let Some(service) = crate::computer_use::service::running() else {
            return error("computer use is not running here (macOS only, started by the daemon)");
        };
        let report = match action {
            CuAction::Status => serde_json::to_value(service.status()).ok(),
            CuAction::Stop => match need(chat, "chat") {
                Ok(c) => serde_json::to_value(service.stop(&c)).ok(),
                Err(e) => return error(e),
            },
            CuAction::StopAll => {
                service.stop_all();
                Some(json!({"stopped": "all"}))
            }
            CuAction::Revoke => match (need(chat, "chat"), need(app, "app")) {
                (Ok(c), Ok(a)) => Some(json!({"revoked": service.revoke(&c, &a)})),
                (Err(e), _) | (_, Err(e)) => return error(e),
            },
        };
        Reply { report, ..ok() }
    }
    #[cfg(not(feature = "computer-use"))]
    {
        let _ = (action, need(chat, "chat"), app);
        error("computer use is not built into this daemon (feature computer-use off)")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_sha256(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The state file when it is safe to read: a regular file (no link) owned
/// by this user, no group or other bits, at most 1 MiB, JSON with
/// `version: 1`. Anything else is ignored, and the daemon starts empty.
#[cfg(unix)]
fn read_state(path: &Path) -> Option<Value> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // Opened without following a link and checked on the handle (review
    // W2-S9: no gap between the check and the read).
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    let me = derm_core::platform::effective_user();
    if !meta.file_type().is_file()
        || meta.uid() != me
        || meta.mode() & 0o077 != 0
        || meta.len() > STATE_FILE_MAX
    {
        return None;
    }
    let mut text = String::new();
    file.by_ref()
        .take(STATE_FILE_MAX + 1)
        .read_to_string(&mut text)
        .ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    (value.get("version").and_then(Value::as_u64) == Some(1)).then_some(value)
}

/// Windows (lane Z): the file itself, never a reparse point's target,
/// checked on the open handle as on Unix (`open_private_file`).
#[cfg(windows)]
fn read_state(path: &Path) -> Option<Value> {
    use std::io::Read;
    let mut file = derm_core::platform::windows::open_private_file(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file() || meta.len() > STATE_FILE_MAX {
        return None;
    }
    let mut text = String::new();
    file.by_ref()
        .take(STATE_FILE_MAX + 1)
        .read_to_string(&mut text)
        .ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    (value.get("version").and_then(Value::as_u64) == Some(1)).then_some(value)
}

/// The disk's records and the ring's, as one backlog: one record per chat
/// and id, the last copy where it may replace the first (case 35, the
/// store's `may_replace`), oldest first, at most `MAX_BACKLOG`.
/// What a `run.start` says that `derm status` shows, each string cut: the
/// record is the daemon's own (daemon scope), but its words are `derm run`'s.
/// An exec record's argv as its shape, and a summary built from it.
fn shape_exec(event: &mut Event) {
    let Some(argv) = event.detail.get("argv").and_then(Value::as_array) else {
        // No argv, but the summary may still hold the words.
        if event.summary.starts_with("exec ") || event.summary.starts_with("ran ") {
            event.summary = "exec".into();
        }
        return;
    };
    let words: Vec<String> = argv
        .iter()
        .map(|w| w.as_str().unwrap_or("").to_string())
        .collect();
    let shaped = derm_core::argv::shape(&words);
    event.summary = format!("exec {}", shaped.join(" "))
        .chars()
        .take(200)
        .collect();
    if let Value::Object(m) = &mut event.detail {
        m.insert("argv".into(), json!(shaped));
        m.insert("argvShaped".into(), Value::Bool(true));
    }
}

fn run_info_of(event: &Event, received: i64) -> Value {
    let cut = |v: Option<&Value>, max: usize| -> Value {
        v.and_then(Value::as_str)
            .map(|s| Value::String(s.chars().take(max).collect()))
            .unwrap_or(Value::Null)
    };
    let flags: Vec<Value> = event
        .detail
        .get("dangerousFlags")
        .and_then(Value::as_array)
        .map(|a| a.iter().take(16).map(|f| cut(Some(f), 64)).collect())
        .unwrap_or_default();
    let mut out = json!({
        "harness": Value::String(event.harness.chars().take(64).collect()),
        "boundary": cut(event.detail.get("boundary"), 16),
        "since": received,
        "fullAccessFlags": flags,
        // The agents' user the chat runs as (lane V), its name only.
        "agentUser": cut(event.detail.get("agentUser").and_then(|u| u.get("user")), 32),
    });
    if let Value::Object(m) = &mut out {
        m.extend(wave5_marks(&event.detail));
    }
    out
}

/// The wave 5 marks of a `run.start` (`contracts/events.md` section 5) as the
/// running list keeps them: the boundary choice without its reasons, the
/// io_uring mark, whether the tap is on and why not, and content capture.
/// Each value cut to a fixed size and shape (review W2-S9: `chats.json` is
/// read, not trusted). Integration w5's close (T-7, V-4, request S-7).
fn wave5_marks(d: &Value) -> serde_json::Map<String, Value> {
    let s = |v: Option<&Value>, max: usize| -> Value {
        v.and_then(Value::as_str)
            .map(|x| Value::String(x.chars().take(max).collect()))
            .unwrap_or(Value::Null)
    };
    let b = |v: Option<&Value>| v.and_then(Value::as_bool).map_or(Value::Null, Value::Bool);
    let mut m = serde_json::Map::new();
    if let Some(c) = d.get("boundaryChoice").filter(|v| v.is_object()) {
        m.insert(
            "boundaryChoice".into(),
            json!({
                "chosen": s(c.get("chosen"), 8),
                "named": b(c.get("named")),
                "answeredBy": s(c.get("answeredBy"), 16),
            }),
        );
    }
    if let Some(k) = d.get("sbxKit").filter(|v| v.is_object()) {
        m.insert("sbxKit".into(), json!({"added": b(k.get("added"))}));
    }
    if d.get("ioUring").is_some() {
        m.insert("ioUring".into(), s(d.get("ioUring"), 16));
    }
    if let Some(t) = d.get("tap").filter(|v| v.is_object()) {
        let mut tap = serde_json::Map::new();
        tap.insert("on".into(), b(t.get("on")));
        if t.get("reason").is_some() {
            tap.insert("reason".into(), s(t.get("reason"), 32));
        }
        m.insert("tap".into(), Value::Object(tap));
    }
    if let Some(c) = d.get("content").filter(|v| v.is_object()) {
        let days = c
            .get("retentionDays")
            .and_then(Value::as_u64)
            .filter(|n| (1..=7).contains(n))
            .map_or(Value::Null, Value::from);
        m.insert(
            "content".into(),
            json!({"on": b(c.get("on")), "retentionDays": days}),
        );
    }
    m
}

/// A run's info as `chats.json` held it: the same fields, re-cut, nothing
/// else kept (review W2-S9: the file is read, not trusted).
fn run_info_restored(v: &Value) -> Value {
    let cut = |k: &str, max: usize| -> Value {
        v.get(k)
            .and_then(Value::as_str)
            .map(|s| Value::String(s.chars().take(max).collect()))
            .unwrap_or(Value::Null)
    };
    let flags: Vec<Value> = v
        .get("fullAccessFlags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .take(16)
                .filter_map(Value::as_str)
                .map(|s| Value::String(s.chars().take(64).collect()))
                .collect()
        })
        .unwrap_or_default();
    let mut out = json!({
        "harness": cut("harness", 64),
        "boundary": cut("boundary", 16),
        "since": v.get("since").and_then(Value::as_i64),
        "fullAccessFlags": flags,
        "agentUser": cut("agentUser", 32),
    });
    if let Value::Object(m) = &mut out {
        m.extend(wave5_marks(v));
    }
    out
}

/// The backlog, oldest first, at most `MAX_BACKLOG`, and whether older
/// records were left out.
pub fn merge_backlog<'a>(
    disk: Vec<Event>,
    ring: impl Iterator<Item = &'a Event>,
    since: i64,
    chat: Option<&str>,
) -> (Vec<Event>, bool) {
    let mut out: Vec<Event> = Vec::new();
    let mut slot: HashMap<(String, String), usize> = HashMap::new();
    let ring = ring.filter(|e| e.at >= since && chat.is_none_or(|c| c == e.chat_id));
    for e in disk.into_iter().chain(ring.cloned()) {
        let key = (e.chat_id.clone(), e.id.clone());
        match slot.get(&key) {
            Some(&i) => {
                if out[i].at <= e.at && store::may_replace(&out[i], &e) {
                    out[i] = e;
                }
            }
            None => {
                slot.insert(key, out.len());
                out.push(e);
            }
        }
    }
    out.sort_by_key(|e| e.at);
    let cut = out.len() > MAX_BACKLOG;
    if cut {
        out.drain(..out.len() - MAX_BACKLOG);
    }
    (out, cut)
}

fn bump(map: &mut Map<String, Value>, key: &Value) {
    let Some(key) = key.as_str() else { return };
    let n = map.get(key).and_then(Value::as_u64).unwrap_or(0);
    map.insert(key.to_string(), json!(n + 1));
}

/// One retention pass over a log folder. Returns the items deleted.
pub fn retention_pass(dir: &Path, now: i64) -> usize {
    use crate::activity::retention;
    let items = retention::scan(dir);
    retention::apply(&retention::plan(
        &items,
        retention::day_of_ms(now),
        retention::CAP_BYTES,
    ))
}

/// The Mac collector's own count of eslogger lines it dropped (its status
/// line's `dropped`), on macOS; `None` elsewhere or when it does not answer.
/// The Mac collector's status line, as data; `None` off macOS.
fn collector_status() -> Option<Value> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    crate::activity::collector::fetch_status_detail()
}

/// What the kernel dropped for the collector's eslogger (MW5-23; Apple,
/// `es_message_t.global_seq_num`): its total since the collector started,
/// the gaps that fall inside `[since, until]` (by the event times around
/// each), and, for a chat whose run is known, how many of those dropped
/// events fell during its run, kept `join::STOPPED_KEEP_MS` past its stop as
/// the join keeps it. Nulls when the collector says nothing (off macOS, or a
/// collector built before the count).
pub fn kernel_drops_for(
    status: Option<&Value>,
    since: i64,
    until: i64,
    run: Option<(i64, Option<i64>)>,
) -> (Value, Value, Value) {
    let Some(total) = status
        .and_then(|s| s.get("kernelDropped"))
        .and_then(Value::as_u64)
    else {
        return (Value::Null, Value::Null, Value::Null);
    };
    let gaps: Vec<&Value> = status
        .and_then(|s| s.get("kernelDrops"))
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let span = |g: &Value| {
        let to = g.get("toMs").and_then(Value::as_i64);
        let from = g.get("fromMs").and_then(Value::as_i64).or(to);
        (from, to.or(from))
    };
    let overlaps = |g: &Value, a: i64, b: i64| match span(g) {
        (Some(f), Some(t)) => f <= b && t >= a,
        _ => false,
    };
    let inside: Vec<Value> = gaps
        .iter()
        .filter(|g| overlaps(g, since, until))
        .map(|g| (*g).clone())
        .collect();
    let during = run.map(|(start, stop)| {
        let end = stop.map_or(i64::MAX, |s| s.saturating_add(crate::join::STOPPED_KEEP_MS));
        gaps.iter()
            .filter(|g| overlaps(g, start, end))
            .filter_map(|g| g.get("count").and_then(Value::as_u64))
            .sum::<u64>()
    });
    (json!(total), Value::Array(inside), json!(during))
}

/// Whether `kernel_drops_for`'s count for a run is a bound rather than
/// exact: a gap it takes stands for merged gaps, or begins before the run
/// or ends after it, so some of its events may have fallen outside (FP4-S5).
pub fn kernel_drops_up_to(status: Option<&Value>, run: (i64, Option<i64>)) -> bool {
    let (start, stop) = run;
    let end = stop.map_or(i64::MAX, |s| s.saturating_add(crate::join::STOPPED_KEEP_MS));
    status
        .and_then(|s| s.get("kernelDrops"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|g| {
            let to = g.get("toMs").and_then(Value::as_i64);
            let from = g.get("fromMs").and_then(Value::as_i64).or(to);
            let to = to.or(from);
            let (Some(f), Some(t)) = (from, to) else {
                return false;
            };
            let merged = g.get("merged").and_then(Value::as_u64).unwrap_or(1) > 1;
            f <= end && t >= start && (merged || f < start || t > end)
        })
}

/// The Mac collector's events for a report, as the fork's panel read them;
/// `None` off macOS. Lane K registers the collector with the daemon in
/// wave 2.
fn collector_events(
    since: i64,
    until: i64,
    chat: Option<&str>,
) -> Option<crate::activity::collector::EventsReply> {
    use crate::activity::collector;
    if !cfg!(target_os = "macos") {
        return None;
    }
    let mut reply = collector::fetch_events(since, until, chat, collector::MAX_EVENTS);
    if reply.complete || !reply.events.is_empty() {
        if let Some(problem) = collector::fetch_status_detail()
            .as_ref()
            .and_then(collector::eslogger_problem)
        {
            reply.problem.get_or_insert(problem);
        }
    }
    Some(reply)
}

/// The call an adapter's gate decision names (`detail.toolUseId`), for an
/// adapter record of kind `approval` only.
/// An adapter record that defers its call to a later hook (`detail.decision`
/// `deferred`, Cursor's preToolUse for an MCP call): no decision.
fn deferred(event: &crate::activity::types::ActivityEvent) -> bool {
    event.detail.get("decision").and_then(Value::as_str) == Some("deferred")
}

/// Cursor's honest pair for one MCP call (Mac test w4, MW4-10): its
/// preToolUse sees `MCP:<tool>` with no server and posts `deferred` for
/// `<tool>`, and beforeMCPExecution posts the decision for
/// `<server>/<tool>`, both naming the call. Only that pair is no conflict
/// (fix pass 1's review, FP4-S4): both in a chat whose token is Cursor's
/// (the daemon stamps every record with its token's harness), the earlier
/// one `deferred`, the later one a decision for `<server>/<that tool>`. A
/// second `deferred`, a decision for another tool, or the pair in another
/// agent's chat is still a conflict.
fn cursor_deferral_then_decision(
    old: &crate::activity::types::ActivityEvent,
    new: &crate::activity::types::ActivityEvent,
) -> bool {
    let tool = |e: &crate::activity::types::ActivityEvent| {
        e.detail
            .get("tool")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    old.harness == "cursor"
        && new.harness == "cursor"
        && deferred(old)
        && !deferred(new)
        && match (tool(old), tool(new)) {
            (Some(o), Some(n)) => {
                !o.is_empty()
                    && !o.contains('/')
                    && n.split_once('/')
                        .is_some_and(|(server, t)| !server.is_empty() && t == o)
            }
            _ => false,
        }
}

fn adapter_call(event: &crate::activity::types::ActivityEvent) -> Option<String> {
    use crate::activity::types::ActivitySource::Adapter;
    if event.kind != "approval" || !matches!(event.source, Adapter) {
        return None;
    }
    event
        .detail
        .get("toolUseId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MW5-23: the collector's kernel drops reach the report, in the window
    /// and during a chat's run, and nothing is claimed where the collector
    /// says nothing.
    #[test]
    fn kernel_drops_are_placed_in_the_window_and_the_chats_run() {
        let status = json!({"dropped": 0, "kernelDropped": 150, "kernelDrops": [
            {"fromMs": 1_000, "toMs": 2_000, "count": 100},
            {"fromMs": 50_000, "toMs": 51_000, "count": 40},
            {"toMs": 90_000, "count": 10}
        ]});
        let (total, inside, during) =
            kernel_drops_for(Some(&status), 0, 60_000, Some((1_500, Some(15_000))));
        assert_eq!(total, 150);
        assert_eq!(inside.as_array().unwrap().len(), 2);
        assert_eq!(during, 100, "the first gap overlaps the run");
        // Kept 30 s past the stop, as the join keeps a chat.
        let (_, _, during) =
            kernel_drops_for(Some(&status), 0, i64::MAX, Some((30_000, Some(25_000))));
        assert_eq!(during, 40);
        // A run still going takes every later gap.
        let (_, _, during) = kernel_drops_for(Some(&status), 0, i64::MAX, Some((60_000, None)));
        assert_eq!(during, 10);
        // No chat: no per-chat count. No count from the collector: nulls.
        assert_eq!(kernel_drops_for(Some(&status), 0, 1, None).2, Value::Null);
        assert_eq!(
            kernel_drops_for(Some(&json!({"dropped": 3})), 0, 1, None),
            (Value::Null, Value::Null, Value::Null)
        );
        assert_eq!(
            kernel_drops_for(None, 0, 1, Some((0, None))),
            (Value::Null, Value::Null, Value::Null)
        );
    }

    /// FP4-S5: a count that takes a merged gap, or one reaching outside the
    /// run, is a bound and says so.
    #[test]
    fn a_chats_missed_count_says_when_it_is_a_bound() {
        let inside = json!({"kernelDropped": 5, "kernelDrops": [
            {"fromMs": 2_000, "toMs": 3_000, "count": 5}
        ]});
        assert!(!kernel_drops_up_to(Some(&inside), (1_000, Some(10_000))));
        let merged = json!({"kernelDropped": 5, "kernelDrops": [
            {"fromMs": 2_000, "toMs": 3_000, "count": 5, "merged": 3}
        ]});
        assert!(kernel_drops_up_to(Some(&merged), (1_000, Some(10_000))));
        let reaching = json!({"kernelDropped": 5, "kernelDrops": [
            {"fromMs": 500, "toMs": 3_000, "count": 5}
        ]});
        assert!(kernel_drops_up_to(Some(&reaching), (1_000, Some(10_000))));
        // A gap that does not touch the run says nothing about it.
        let apart = json!({"kernelDropped": 5, "kernelDrops": [
            {"fromMs": 500_000, "toMs": 600_000, "count": 5, "merged": 9}
        ]});
        assert!(!kernel_drops_up_to(Some(&apart), (1_000, Some(10_000))));
    }
    use crate::activity::types::ActivitySource;
    use std::sync::mpsc::RecvTimeoutError;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    type Hook = Box<dyn Fn() + Send>;
    static AFTER_OK: Mutex<Option<Hook>> = Mutex::new(None);

    /// Runs where a tail's client first holds its `ok` and can act on it.
    pub(super) fn after_tail_ok() {
        if let Ok(hook) = AFTER_OK.lock() {
            if let Some(hook) = hook.as_ref() {
                hook();
            }
        }
    }

    fn daemon() -> (Arc<Daemon>, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "tkd-unit-{}-{}",
            std::process::id(),
            &derm_core::token::mint().unwrap()[..12]
        ));
        let data = root.join("data");
        let log: &'static ActivityLog =
            Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
        (Daemon::new(TOKEN, log, &data, false).unwrap(), root)
    }

    fn event(id: &str) -> Event {
        Event {
            id: id.into(),
            at: 0,
            chat_id: "chat-a".into(),
            harness: "pi".into(),
            source: ActivitySource::Adapter,
            kind: "tool.call".into(),
            summary: id.into(),
            detail: json!({}),
            pid: None,
            approval_id: None,
        }
    }

    /// BX8's state file is taken only when it is this user's own private
    /// regular file: one others can read or write, or a link, is ignored.
    #[cfg(unix)]
    #[test]
    fn a_state_file_that_is_not_private_is_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "tkd-state-{}-{}",
            std::process::id(),
            &derm_core::token::mint().unwrap()[..12]
        ));
        std::fs::create_dir_all(&root).unwrap();
        let token = derm_core::token::mint().unwrap();
        let state = root.join("chats.json");
        let text = json!({
            "version": 1,
            "tokens": [{
                "sha256": hex(&Receiver::token_hash(&token)),
                "chat": "chat-x", "harness": "pi", "mintedAt": now_ms()
            }],
            "runs": []
        })
        .to_string();
        let start = |path: PathBuf| {
            let log: &'static ActivityLog = Box::leak(Box::new(ActivityLog::start(
                root.join(format!("data-{}", uuid::Uuid::new_v4().simple())),
            )));
            Daemon::new_with_state(TOKEN, log, &root, false, Some(path)).unwrap()
        };
        std::fs::write(&state, &text).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(start(state.clone()).hello(&token), None, "0644");
        let link = root.join("link.json");
        std::fs::write(&state, &text).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&state, &link).unwrap();
        assert_eq!(start(link).hello(&token), None, "a link");
        std::fs::write(&state, &text).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        let chat = Some(Who::Chat {
            chat: "chat-x".into(),
            harness: "pi".into(),
        });
        assert_eq!(start(state.clone()).hello(&token), chat, "0600, its own");
        // Review W2-S9: a planted run that names no start time, or pid 1,
        // keeps a started chat's token alive for good; neither counts.
        for run in [
            json!({"chat": "chat-x", "pid": std::process::id(), "startTime": null}),
            json!({"chat": "chat-x", "pid": 1, "startTime": derm_core::platform::peer::start_time(1)}),
        ] {
            let planted = json!({
                "version": 1,
                "tokens": [{
                    "sha256": hex(&Receiver::token_hash(&token)),
                    "chat": "chat-x", "harness": "pi", "mintedAt": 0
                }],
                "runs": [run]
            })
            .to_string();
            std::fs::write(&state, &planted).unwrap();
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(start(state.clone()).hello(&token), None, "{run}");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// Lane K's request 5 (the CI flake `ids_the_daemon_makes_never_repeat`):
    /// a client that acts on `tail`'s `ok` at once must see what it caused.
    /// On the old order (`ok` before the subscription) an event ingested at
    /// that moment was never pushed.
    #[test]
    fn an_event_right_after_the_tail_ok_reaches_the_tail() {
        let (d, root) = daemon();
        let hooked = d.clone();
        *AFTER_OK.lock().unwrap() = Some(Box::new(move || {
            hooked.ingest(event("right-after-ok"));
        }));
        let (out, rx, _) = Outbox::new(d.next_conn());
        d.op_tail(&Who::Daemon, None, None, &out);
        *AFTER_OK.lock().unwrap() = None;
        let first: Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        assert_eq!(first["ok"], true, "{first}");
        let pushed = match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => panic!("the event after ok was never pushed"),
            Err(e) => panic!("{e}"),
        };
        assert!(pushed.contains("right-after-ok"), "{pushed}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Integration w2 review W2-S5: a process inside a chat forks a child
    /// that connects and exits; without a pidfd the dead pid has no
    /// ancestors to walk, so the daemon must refuse a peer whose pid no
    /// longer resolves to the process read at accept.
    #[test]
    fn an_approver_whose_process_is_gone_or_reused_is_refused() {
        let (d, root) = daemon();
        let me = derm_core::platform::peer::Peer {
            pid: None,
            uid: derm_core::platform::effective_user(),
        };
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let started = derm_core::platform::peer::start_time(pid);
        assert!(started.is_some());
        child.kill().unwrap();
        child.wait().unwrap();
        let gone = ConnPeer {
            cred: Some(derm_core::platform::peer::Peer {
                pid: Some(pid),
                ..me.clone()
            }),
            pidfd: None,
            program: None,
            start_time: started,
        };
        let why = d.approver_refusal(&gone).expect("a reaped peer is refused");
        assert!(why.contains("gone"), "{why}");
        let own = std::process::id();
        let reused = ConnPeer {
            cred: Some(derm_core::platform::peer::Peer {
                pid: Some(own),
                ..me.clone()
            }),
            pidfd: None,
            program: None,
            start_time: derm_core::platform::peer::start_time(own).map(|t| t + 1),
        };
        let why = d
            .approver_refusal(&reused)
            .expect("another process under the pid is refused");
        assert!(why.contains("not the process"), "{why}");
        let unread = ConnPeer {
            cred: Some(derm_core::platform::peer::Peer {
                pid: Some(own),
                ..me
            }),
            pidfd: None,
            program: None,
            start_time: None,
        };
        assert!(d.approver_refusal(&unread).is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    fn ev_of(chat: &str, source: Source, kind: &str, pid: Option<u32>, detail: Value) -> Event {
        Event {
            id: format!("{kind}-{}", uuid::Uuid::new_v4().simple()),
            at: 0,
            chat_id: chat.into(),
            harness: "claude-code".into(),
            source,
            kind: kind.into(),
            summary: String::new(),
            detail,
            pid,
            approval_id: None,
        }
    }

    /// Lane S's request 1 (integration w5, phase 2): a tap route resolves to
    /// the running chat whose token makes it, read from the receiver's own
    /// table; the chat's `run.stop` kills the route with the token; a route
    /// no chat holds, or one not well formed, resolves to nothing.
    #[test]
    fn a_tap_route_is_its_chats_until_the_chat_stops() {
        let (d, root) = daemon();
        assert!(d.tap_endpoint().is_some(), "the tap started");
        let reply = d.op_mint(&Who::Daemon, "chat-r", "claude-code");
        let token = reply.token.expect("minted");
        let route = derm_tap::route::of_token(&token);
        assert_eq!(
            chat_for_route(&d.receiver, &route),
            Some(derm_tap::Chat {
                id: "chat-r".into(),
                harness: "claude-code".into()
            })
        );
        assert_eq!(chat_for_route(&d.receiver, &"0".repeat(32)), None);
        assert_eq!(chat_for_route(&d.receiver, &route.to_uppercase()), None);
        assert_eq!(chat_for_route(&d.receiver, "../x"), None);
        let stop = ev_of("chat-r", Source::Run, "run.stop", None, json!({}));
        assert!(d.op_event(&Who::Daemon, stop).ok);
        assert_eq!(
            chat_for_route(&d.receiver, &route),
            None,
            "gone with the token"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A restarted daemon takes back a running chat's token (BX8), so its
    /// route resolves again and the tap binds its old port (case 86).
    #[test]
    fn a_restart_brings_back_a_running_chats_route_and_the_taps_port() {
        let root = std::env::temp_dir().join(format!(
            "tkd-tapstate-{}-{}",
            std::process::id(),
            &derm_core::token::mint().unwrap()[..12]
        ));
        std::fs::create_dir_all(&root).unwrap();
        let state = root.join("chats.json");
        let start = || {
            let log: &'static ActivityLog = Box::leak(Box::new(ActivityLog::start(
                root.join(format!("data-{}", uuid::Uuid::new_v4().simple())),
            )));
            Daemon::new_with_state(TOKEN, log, &root, false, Some(state.clone())).unwrap()
        };
        let first = start();
        let port = first.tap.as_ref().map(derm_tap::Tap::port).unwrap();
        let token = first
            .op_mint(&Who::Daemon, "chat-k", "claude-code")
            .token
            .unwrap();
        let mut harness = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let begin = ev_of(
            "chat-k",
            Source::Run,
            "run.start",
            Some(harness.id()),
            json!({"cwd": "/tmp", "boundary": "srt"}),
        );
        assert!(first.op_event(&Who::Daemon, begin).ok);
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(saved["tapPort"], port, "{saved}");
        drop(first);
        let second = start();
        assert_eq!(
            second.tap.as_ref().map(derm_tap::Tap::port),
            Some(port),
            "the old port, free again, is taken back"
        );
        let route = derm_tap::route::of_token(&token);
        assert_eq!(
            chat_for_route(&second.receiver, &route).map(|c| c.id),
            Some("chat-k".to_string())
        );
        let _ = harness.kill();
        let _ = harness.wait();
        let _ = std::fs::remove_dir_all(root);
    }

    /// The join runs on what the daemon ingests: a tap call naming a path,
    /// then the OS feed's write to it, makes one `join.candidates` record
    /// (source `derm`) with that call chosen, and nothing loops.
    #[test]
    fn the_join_reads_what_the_daemon_ingests() {
        let (d, root) = daemon();
        d.ingest(ev_of(
            "chat-j",
            Source::Run,
            "run.start",
            Some(4242),
            json!({"cwd": "/w"}),
        ));
        let mut call = ev_of(
            "chat-j",
            Source::Tap,
            "tap.call",
            None,
            json!({"callId": "toolu_A", "toolNormalized": "write", "paths": ["/w/x"], "resultSha256": null}),
        );
        call.id = "tap-chat-j-toolu_A".into();
        d.ingest(call);
        d.ingest(ev_of(
            "chat-j",
            Source::Adapter,
            "approval",
            None,
            json!({"toolUseId": "toolu_A", "decision": "allow"}),
        ));
        d.ingest(ev_of(
            "chat-j",
            Source::Auditd,
            "write",
            Some(4300),
            json!({"ppid": 4242, "auditAt": now_ms(), "path": "/w/x"}),
        ));
        let ring: Vec<Event> = d.order.lock().unwrap().iter().cloned().collect();
        let joins: Vec<&Event> = ring
            .iter()
            .filter(|e| e.kind == "join.candidates")
            .collect();
        assert_eq!(joins.len(), 1, "{ring:?}");
        assert_eq!(joins[0].source, Source::Derm);
        assert_eq!(joins[0].detail["chosen"], "tap-chat-j-toolu_A");
        assert_eq!(ring.len(), 5, "four events and one join record");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Fix pass 6 (FP5R-3, FP5R-4): no gate posts for a code tool call, so a
    /// chat's `approval` or `tool.call` naming the tap's Code Mode call is
    /// kept as a conflict copy and flagged; one naming another call is not.
    #[test]
    fn fp6_a_chat_record_naming_a_tap_code_call_is_flagged() {
        let (d, root) = daemon();
        let mut call = ev_of(
            "chat-c",
            Source::Tap,
            "tap.call",
            None,
            json!({"callId": "call_E9", "toolNormalized": "exec", "paths": [], "resultSha256": null}),
        );
        call.id = "tap-chat-c-call_E9".into();
        call.harness = "codex".into();
        d.ingest(call);
        let who = Who::Chat {
            chat: "chat-c".into(),
            harness: "codex".into(),
        };
        for (kind, detail) in [
            (
                "approval",
                json!({"toolUseId": "call_E9", "decision": "allow", "tool": "exec"}),
            ),
            ("tool.call", json!({"toolUseId": "call_E9"})),
        ] {
            let mut e = ev_of("chat-c", Source::Adapter, kind, None, detail);
            e.harness = "codex".into();
            let r = d.op_event(&who, e);
            assert!(r.ok, "{kind}");
            assert!(
                r.id.as_deref().is_some_and(|i| i.contains("-conflict-")),
                "{kind}: {:?}",
                r.id
            );
        }
        // A record for a call the tap did not mark as code is ingested as is.
        let mut other = ev_of(
            "chat-c",
            Source::Adapter,
            "approval",
            None,
            json!({"toolUseId": "call_N1", "decision": "allow", "tool": "bash"}),
        );
        other.harness = "codex".into();
        let r = d.op_event(&who, other);
        assert!(
            r.id.as_deref().is_some_and(|i| !i.contains("-conflict-")),
            "{:?}",
            r.id
        );
        let ring: Vec<Event> = d.order.lock().unwrap().iter().cloned().collect();
        let flags: Vec<&Event> = ring.iter().filter(|e| e.kind == "gate.conflict").collect();
        assert_eq!(flags.len(), 2, "{ring:?}");
        assert!(
            flags.iter().all(|f| f.detail["id"] == "tap-chat-c-call_E9"),
            "{flags:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn package_lock(dir: &std::path::Path, deps: &[(&str, &str)]) {
        let mut packages = serde_json::Map::new();
        packages.insert("".into(), json!({"name": "p", "version": "1.0.0"}));
        for (n, v) in deps {
            packages.insert(
                format!("node_modules/{n}"),
                json!({"version": v, "resolved": format!("https://registry.npmjs.org/{n}/-/{n}-{v}.tgz")}),
            );
        }
        std::fs::write(
            dir.join("package-lock.json"),
            json!({"name": "p", "lockfileVersion": 3, "packages": packages}).to_string(),
        )
        .unwrap();
    }

    /// Re-review W5R-3: a chat token had no rate or byte limit on the
    /// socket. Its posts are bounded per chat, and another chat is not.
    #[test]
    fn a_chat_tokens_posts_are_bounded_per_chat() {
        let (d, root) = daemon();
        let a = Who::Chat {
            chat: "chat-qa".into(),
            harness: "claude-code".into(),
        };
        let b = Who::Chat {
            chat: "chat-qb".into(),
            harness: "claude-code".into(),
        };
        let mut refused = 0;
        for i in 0..(SOCKET_BURST_PER_CHAT as usize + 200) {
            let mut e = ev_of("", Source::Adapter, "tool.call", None, json!({"n": i}));
            e.id = format!("q{i}");
            if !d.op_event(&a, e).ok {
                refused += 1;
            }
        }
        assert!(refused > 0, "chat a was never limited");
        let e = ev_of("", Source::Adapter, "tool.call", None, json!({}));
        assert!(d.op_event(&b, e).ok, "chat a spent chat b's share");
        // The day's bytes: one more record past the allowance is refused.
        let now = std::time::Instant::now();
        assert!(d
            .take_chat_quota("chat-qc", SOCKET_BYTES_PER_CHAT_DAY - 10, 0, now)
            .is_ok());
        assert!(d.take_chat_quota("chat-qc", 100, 1, now).is_err());
        // The next day starts again.
        assert!(d.take_chat_quota("chat-qc", 100, 86_400_000, now).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Box test w5, BW5-12: a tail's backlog past MAX_BACKLOG was cut with
    /// no word; merge_backlog now says it cut.
    #[test]
    fn a_backlog_past_its_cap_says_it_was_cut() {
        let events: Vec<Event> = (0..MAX_BACKLOG as i64 + 1)
            .map(|i| {
                let mut e = ev_of("c", Source::Adapter, "tool.call", None, json!({}));
                e.id = format!("e{i}");
                e.at = i + 1;
                e
            })
            .collect();
        let (out, cut) = merge_backlog(events.clone(), std::iter::empty(), 0, None);
        assert!(cut);
        assert_eq!(out.len(), MAX_BACKLOG);
        assert_eq!(out[0].id, "e1", "the oldest is the one left out");
        let (out, cut) = merge_backlog(events[1..].to_vec(), std::iter::empty(), 0, None);
        assert!(!cut);
        assert_eq!(out.len(), MAX_BACKLOG);
    }

    /// Box test w5, BW5-12: an OS feed's exec record kept the harness's
    /// prompt (`claude -p "MARKERZEBRA42 ..."`) in the log with content off
    /// and on. The record keeps the argv's shape only, in the detail and the
    /// summary, from auditd and eslogger alike.
    #[test]
    fn os_feed_exec_records_keep_only_the_argvs_shape() {
        let (d, root) = daemon();
        for (source, summary) in [
            (Source::Auditd, "exec claude -p MARKERZEBRA42 x"),
            (Source::Eslogger, "ran claude"),
        ] {
            let mut e = ev_of(
                "chat-a",
                source,
                "exec",
                Some(77),
                json!({"argv": ["/usr/bin/claude", "-p", "MARKERZEBRA42 do it", "--model=haiku"]}),
            );
            e.summary = summary.into();
            assert!(d.op_event(&Who::Daemon, e).ok);
        }
        let ring: Vec<Event> = d.order.lock().unwrap().iter().cloned().collect();
        let execs: Vec<&Event> = ring.iter().filter(|e| e.kind == "exec").collect();
        assert_eq!(execs.len(), 2, "{ring:?}");
        for e in execs {
            let all = serde_json::to_string(e).unwrap();
            assert!(!all.contains("MARKERZEBRA42"), "{all}");
            assert!(!all.contains("haiku"), "{all}");
            assert_eq!(
                e.detail["argv"],
                json!(["/usr/bin/claude", "-p", "[19 chars]", "--model=[5 chars]"])
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// Lane X's request 4 (integration w5, continue): through the daemon's
    /// own ops, an adapter's install.call and its tool.call give an
    /// install.lockdiff for the chat's folder from its run.start, and an
    /// install script's write to .git/hooks that the join credits to the
    /// call gives install.control (cases 132, 133).
    #[test]
    fn install_records_reach_the_lockfile_diff_and_the_control_flags() {
        let (d, root) = daemon();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        package_lock(&work, &[("left-pad", "1.3.0")]);
        let chat = Who::Chat {
            chat: "chat-x".into(),
            harness: "claude-code".into(),
        };
        let mut start = ev_of(
            "chat-x",
            Source::Run,
            "run.start",
            Some(5151),
            json!({"cwd": work.to_string_lossy()}),
        );
        start.harness = "claude-code".into();
        assert!(d.op_event(&Who::Daemon, start).ok);
        let install = json!({"trust": "client", "toolUseId": "toolu_I", "manager": "npm", "form": "add", "packages": [{"name": "is-number", "version": null, "ecosystem": "npm", "inLockfile": null}], "decision": "allow", "check": null});
        assert!(
            d.op_event(
                &chat,
                ev_of("", Source::Adapter, "install.call", None, install)
            )
            .ok
        );
        assert!(
            d.op_event(
                &chat,
                ev_of(
                    "",
                    Source::Adapter,
                    "approval",
                    None,
                    json!({"toolUseId": "toolu_I", "tool": "bash", "decision": "allow"})
                )
            )
            .ok
        );
        // The harness forks a shell for the Bash call; the shell runs npm,
        // whose install script writes a git hook (the join's tree: box test
        // w5, BW5-11 and BW5-13 credit only what the call started).
        for (kind, pid, detail) in [
            ("fork", 5151, json!({"ppid": 1, "child": 5190})),
            ("exec", 5190, json!({"ppid": 5151, "exe": "/usr/bin/bash"})),
            ("fork", 5190, json!({"ppid": 5151, "child": 5200})),
        ] {
            let mut d2 = detail;
            d2["auditAt"] = json!(now_ms());
            assert!(
                d.op_event(
                    &Who::Daemon,
                    ev_of("chat-x", Source::Auditd, kind, Some(pid), d2)
                )
                .ok
            );
        }
        // The install script writes a git hook, a child of the harness.
        assert!(d
            .op_event(
                &Who::Daemon,
                ev_of(
                    "chat-x",
                    Source::Auditd,
                    "write",
                    Some(5200),
                    json!({"ppid": 5151, "auditAt": now_ms(), "path": format!("{}/.git/hooks/pre-commit", work.to_string_lossy()), "exe": "/usr/bin/node"}),
                )
            )
            .ok);
        package_lock(&work, &[("left-pad", "1.3.0"), ("is-number", "7.0.0")]);
        assert!(
            d.op_event(
                &chat,
                ev_of(
                    "",
                    Source::Adapter,
                    "tool.call",
                    None,
                    json!({"toolUseId": "toolu_I"})
                )
            )
            .ok
        );
        let ring: Vec<Event> = d.order.lock().unwrap().iter().cloned().collect();
        let of = |k: &str| ring.iter().filter(|e| e.kind == k).collect::<Vec<_>>();
        let diffs = of("install.lockdiff");
        assert_eq!(diffs.len(), 1, "{ring:?}");
        assert_eq!(diffs[0].source, Source::Derm);
        assert_eq!(diffs[0].chat_id, "chat-x");
        assert_eq!(diffs[0].detail["added"][0]["name"], "is-number");
        let install_id = of("install.call")[0].id.clone();
        assert_eq!(diffs[0].detail["call"], install_id.as_str());
        let flags = of("install.control");
        assert_eq!(flags.len(), 1, "{ring:?}");
        assert_eq!(flags[0].detail["call"], install_id.as_str());
        assert!(
            flags[0].summary.contains(".git/hooks/"),
            "{}",
            flags[0].summary
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Fix pass 2's review, FP2-S1: the OS feeds' ids are predictable
    /// (`es-<day>-<seq>`, `auditd-<ms>-<serial>`, `sysmon-<record>`), and the
    /// log keeps the first record under an id, so a chat token that posted
    /// under one first hid the real kernel record from the log and the
    /// report. A chat posts under none of them, in any spelling.
    #[test]
    fn a_chat_token_cannot_take_an_os_feeds_id() {
        let (d, root) = daemon();
        let chat = Who::Chat {
            chat: "chat-f".into(),
            harness: "claude-code".into(),
        };
        for id in [
            "es-2026-11-05-5000",
            "ES-2026-11-05-5001",
            " es-2026-11-05-5002",
            "auditd-1793943183583-12",
            "sysmon-4711",
            "Sysmon-abc-write",
        ] {
            let mut e = ev_of("", Source::Adapter, "write", None, json!({"path": "/x"}));
            e.id = id.into();
            assert!(!d.op_event(&chat, e).ok, "{id}");
        }
        // Any other id is the chat's to choose, as before.
        let mut e = ev_of("", Source::Adapter, "tool.call", None, json!({}));
        e.id = "esx-1".into();
        assert!(d.op_event(&chat, e).ok);
        // The daemon scope (derm-audit-feed) still posts the feed's own ids.
        let mut e = ev_of(
            "chat-f",
            Source::Auditd,
            "write",
            Some(9),
            json!({"path": "/x"}),
        );
        e.id = "auditd-1793943183583-13".into();
        assert!(d.op_event(&Who::Daemon, e).ok);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Mac test w5, MW5-14: on macOS the collector's eslogger events were
    /// read only for `report`, so none reached `ingest`: no join, no
    /// control-path flag, no argv shape. Through the pump they do, each
    /// once, with the collector's own time as the effect time.
    #[test]
    fn the_mac_collectors_events_reach_ingest_through_the_pump() {
        use crate::activity::collector::EventsReply;
        use crate::collector::{pump_once, Pump};
        let (d, root) = daemon();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        package_lock(&work, &[("left-pad", "1.3.0")]);
        let chat = Who::Chat {
            chat: "chat-m".into(),
            harness: "claude-code".into(),
        };
        let mut start = ev_of(
            "chat-m",
            Source::Run,
            "run.start",
            Some(6161),
            json!({"cwd": work.to_string_lossy()}),
        );
        start.harness = "claude-code".into();
        assert!(d.op_event(&Who::Daemon, start).ok);
        let install = json!({"trust": "client", "toolUseId": "toolu_M", "manager": "npm", "form": "add", "packages": [{"name": "pkghook", "version": null, "ecosystem": "npm", "inLockfile": null}], "decision": "allow", "check": null});
        assert!(
            d.op_event(
                &chat,
                ev_of("", Source::Adapter, "install.call", None, install)
            )
            .ok
        );
        assert!(
            d.op_event(
                &chat,
                ev_of(
                    "",
                    Source::Adapter,
                    "approval",
                    None,
                    json!({"toolUseId": "toolu_M", "tool": "bash", "decision": "allow"})
                )
            )
            .ok
        );
        // What eslogger saw, as the collector gives it: its own `at`, no
        // auditAt or osAt.
        let t = now_ms();
        let mut seq = 0;
        let mut os = |kind: &str, pid: u32, detail: Value| {
            seq += 1;
            let mut e = ev_of("chat-m", Source::Eslogger, kind, Some(pid), detail);
            e.id = format!("es-{seq}");
            e.at = t + seq;
            e
        };
        let events = vec![
            os("fork", 6161, json!({"ppid": 1, "child": 6190})),
            os(
                "exec",
                6190,
                json!({"ppid": 6161, "exe": "/bin/zsh", "argv": ["/bin/zsh", "-c", "npm install ../pkghook MARKERZEBRA42"]}),
            ),
            os("fork", 6190, json!({"ppid": 6161, "child": 6200})),
            os(
                "write",
                6200,
                json!({"ppid": 6190, "path": format!("{}/.git/hooks/pre-commit", work.to_string_lossy()), "exe": "/usr/local/bin/node"}),
            ),
        ];
        let reply = || EventsReply {
            events: events.clone(),
            complete: true,
            connected: true,
            chain_ok: true,
            ..EventsReply::default()
        };
        let mut pump = Pump::new(t - 1);
        assert_eq!(pump_once(&d, &mut pump, t + 100, |_, _| reply()), 4);
        // The same events again (the overlap): taken once.
        assert_eq!(pump_once(&d, &mut pump, t + 200, |_, _| reply()), 0);
        assert!(pump.since() <= t + 4);
        package_lock(&work, &[("left-pad", "1.3.0"), ("pkghook", "1.0.0")]);
        assert!(
            d.op_event(
                &chat,
                ev_of(
                    "",
                    Source::Adapter,
                    "tool.call",
                    None,
                    json!({"toolUseId": "toolu_M"})
                )
            )
            .ok
        );
        let ring: Vec<Event> = d.order.lock().unwrap().iter().cloned().collect();
        let of = |k: &str| ring.iter().filter(|e| e.kind == k).collect::<Vec<_>>();
        let exec = of("exec");
        assert_eq!(exec.len(), 1, "{ring:?}");
        assert_eq!(exec[0].detail["argvShaped"], json!(true));
        assert!(!serde_json::to_string(exec[0])
            .unwrap()
            .contains("MARKERZEBRA42"));
        assert_eq!(exec[0].detail["osAt"], json!(t + 2));
        assert!(!of("join.candidates").is_empty(), "{ring:?}");
        let flags = of("install.control");
        assert_eq!(flags.len(), 1, "{ring:?}");
        assert_eq!(flags[0].detail["call"], of("install.call")[0].id.as_str());
        assert_eq!(of("install.lockdiff").len(), 1, "{ring:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A chat token cannot point the diff at another folder: the record's
    /// own cwd is never read, and a chat with no daemon-scope run.start has
    /// no folder.
    #[test]
    fn an_install_call_reads_only_the_chats_own_folder() {
        let (d, root) = daemon();
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        package_lock(&elsewhere, &[("left-pad", "1.3.0")]);
        let chat = Who::Chat {
            chat: "chat-y".into(),
            harness: "claude-code".into(),
        };
        let install =
            json!({"toolUseId": "t", "manager": "npm", "cwd": elsewhere.to_string_lossy()});
        assert!(
            d.op_event(
                &chat,
                ev_of("", Source::Adapter, "install.call", None, install)
            )
            .ok
        );
        package_lock(&elsewhere, &[("left-pad", "1.2.0")]);
        assert!(
            d.op_event(
                &chat,
                ev_of(
                    "",
                    Source::Adapter,
                    "tool.call",
                    None,
                    json!({"toolUseId": "t"})
                )
            )
            .ok
        );
        let ring: Vec<Event> = d.order.lock().unwrap().iter().cloned().collect();
        assert!(
            !ring.iter().any(|e| e.kind == "install.lockdiff"),
            "{ring:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
