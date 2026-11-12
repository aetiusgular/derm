//! Lane K's seam in the daemon (wave 2): what runs beside lane B's daemon.
//!
//! `main.rs` calls `start` once the daemon is up and before it serves the
//! socket. It starts two things, each on its own thread, and returns at once:
//!
//! - **The collector registration** (toolkit plan T1.3, Mac half). The
//!   macOS activity collector (`macos/activity-collector/`, a root launchd
//!   daemon around `eslogger`) follows only the processes it is told about.
//!   The fork told it at each harness spawn; in derm, `derm run` posts
//!   `run.start` with the harness's pid, so the daemon tails its own feed
//!   and registers each such pid with the collector for the chat
//!   (`activity::register_process`, lane B's copy of the fork's registry,
//!   which replays the live set whenever the collector comes back). The
//!   read side already runs: `report` asks the collector for its events
//!   (lane B). Only a `run.start` the daemon scope posted counts: a chat
//!   token cannot post one (`Daemon::op_event`). macOS only.
//! - **Computer use** (T1.5), behind the `computer-use` feature, on by
//!   default since lane K: `computer_use::service`. macOS only.
//!
//! Neither makes an outbound connection (rules, section 5, item 8). The
//! collector is reached over its local sockets; its install stays behind
//! your click and your Developer ID (R10).

use std::sync::Arc;

// The collector app's SMAppService calls, compiled here only for tests so
// CI's macOS job builds and runs them (the collector's own workspace is not
// in CI). The collector includes the same file.
#[cfg(test)]
pub mod sm_app_service;

pub mod app;

use derm_core::event::{Event, Source};
use serde_json::Value;

use crate::activity::ProcessKind;
use crate::daemon::{Daemon, Paths};
#[cfg(test)]
use crate::daemon::{Outbox, Who};
#[cfg(test)]
use crate::protocol::Request;

/// What one event asks of the collector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Registration {
    /// Follow `pid` and its descendants for `chat`.
    Follow { pid: u32, chat: String },
    /// The harness exited: stop replaying it to a restarted collector.
    Exited { pid: u32 },
}

/// The registration an event asks for, if any: a daemon-scope `run.start`
/// or `run.stop` with a pid, for a chat id the collector takes.
pub fn registration(event: &Event) -> Option<Registration> {
    if event.source != Source::Run {
        return None;
    }
    let pid = event.pid.filter(|p| *p > 1)?;
    match event.kind.as_str() {
        "run.start" if crate::activity::registry::valid_chat_id(&event.chat_id) => {
            Some(Registration::Follow {
                pid,
                chat: event.chat_id.clone(),
            })
        }
        "run.stop" => Some(Registration::Exited { pid }),
        _ => None,
    }
}

/// Applies one registration through lane B's registry.
fn apply(registration: Registration) {
    match registration {
        Registration::Follow { pid, chat } => {
            crate::activity::register_process(pid, &chat, ProcessKind::Harness)
        }
        Registration::Exited { pid } => crate::activity::process_exited(pid),
    }
}

/// The event inside one `tail` line, if the line is a pushed event.
pub fn pushed_event(line: &str) -> Option<Event> {
    let value: Value = serde_json::from_str(line).ok()?;
    serde_json::from_value(value.get("event")?.clone()).ok()
}

/// Calls `each` for every `derm run` record (`run.start`, `run.stop`) the
/// daemon takes from now on, on the caller's thread, for the daemon's life.
///
/// Mac test w5 retest 2, MW5-18: this was a `tail` of every event. The
/// daemon drops a tail 4,096 lines behind, and this in-process one never
/// counted a line as read (its outbox's pending counter was thrown away), so
/// after 4,096 events of any kind the daemon dropped it, the loop ended, and
/// no later chat was registered with the collector until a restart, while
/// the report still said the collector answered. It now reads the daemon's
/// run records only, through a channel no flood can fill or close.
pub fn follow(daemon: &Arc<Daemon>, mut each: impl FnMut(Event)) {
    let runs = daemon.watch_runs();
    for event in runs {
        each(event);
    }
}

/// The collector's install plan. For `derm Activity.app` (or the collector
/// inside it), the app route (`app.rs`, lane Y): copy it into a root-owned
/// place, check it, register it through SMAppService as you. For a bare
/// binary, a development build (the fork's terminal route,
/// `activity/collector.rs` `terminal_plan`, lane B's copy):
/// the exact commands, the plist and the hashes, for you to read and run
/// yourself in Terminal (rules, section 5, item 2). Nothing here runs them.
///
/// - `binary`: the collector you built (`cargo build --release` in
///   `macos/activity-collector`), absolute, a regular file. Its SHA-256 goes
///   into the root shell that installs it, so a swapped file is refused.
/// - `peer`: the daemon binary the collector will take as its only caller
///   (`--dev-peer-path`, exact path; PROTOCOL.md "Caller check"). Usually
///   the running `derm-daemon`.
///
/// The plist is staged in `<data>/activity/install/` (0600), as the fork
/// staged it in the app's data folder. The names are derm's since the
/// rename (label `io.github.aetiusgular.derm.activity-collector`, sockets in
/// `/var/run/derm-activity`); the collector's own identifiers and socket
/// paths changed with them, in one commit.
pub fn install_plan(
    paths: &Paths,
    binary: &std::path::Path,
    peer: &std::path::Path,
) -> Result<crate::activity::collector::InstallPlan, String> {
    use crate::activity::collector;
    // The signed app bundle (lane Y): `--binary` names the `.app`, or the
    // collector inside it. It is checked by signature, not by a peer path.
    if let Some(app) = app::app_of(binary) {
        let names = collector::Names::current();
        return app::plan(&app, &names, app::Present::now(&names));
    }
    for (what, path) in [("collector binary", binary), ("daemon binary", peer)] {
        if !path.is_absolute() {
            return Err(format!("the {what} needs an absolute path"));
        }
        let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{what}: {e}"))?;
        if !meta.file_type().is_file() {
            return Err(format!("the {what} is not a regular file"));
        }
    }
    let hash = collector::file_sha256(binary).map_err(|e| format!("collector binary: {e}"))?;
    let names = collector::Names::current();
    let stage = paths.data.join("activity").join("install");
    crate::socket::private_dir(&stage).map_err(|e| format!("stage folder: {e}"))?;
    let staged = stage.join(format!("{}.plist", names.label));
    let mut plan = collector::terminal_plan(
        &names,
        &binary.to_string_lossy(),
        &hash,
        &staged.to_string_lossy(),
        &peer.to_string_lossy(),
    )?;
    let peer_hash = collector::file_sha256(peer).map_err(|e| format!("daemon binary: {e}"))?;
    plan.explanation = explanation(
        &binary.to_string_lossy(),
        &hash,
        &peer.to_string_lossy(),
        &peer_hash,
        writable_by_me(peer),
        &staged.to_string_lossy(),
        &names.label,
    );
    crate::service::write_private(&staged, &plan.plist).map_err(|e| format!("plist: {e}"))?;
    Ok(plan)
}

/// The plan's words for derm (Mac test w2, MW5). The fork's text
/// (`activity/collector.rs` `explanation`) spoke for MonoCode's signed app;
/// derm's development install trusts its caller by path, which is weaker, and
/// says what that costs.
fn explanation(
    binary: &str,
    binary_sha: &str,
    peer: &str,
    peer_sha: &str,
    peer_writable: bool,
    staged: &str,
    label: &str,
) -> Vec<String> {
    let mut lines = vec![
        "The collector runs as root, outside any sandbox, and starts /usr/bin/eslogger.".to_string(),
        "It needs Full Disk Access, which you grant it in System Settings, Privacy & Security.".to_string(),
        "It records only: processes `derm run` started for a chat (the daemon names each one) and their children, and apps you granted for computer use while the grant holds.".to_string(),
        "It records what they ran, the files they created, wrote, moved or deleted, and opens of sensitive files such as ~/.ssh. Command lines are kept.".to_string(),
        "It blocks nothing. It sends nothing anywhere. Its log is root-owned, kept 7 days, at most 1 GB.".to_string(),
        format!("It answers one caller: the program at {peer} (SHA-256 {peer_sha} today), matched by its exact path, because this build is unsigned. That is weaker than a signature."),
    ];
    if peer_writable {
        lines.push(format!(
            "You can write {peer} or a folder on the way to it, so any process that runs as you can replace that file, an agent under `derm run --boundary none` included, and the replacement becomes the collector's caller. To close that, copy derm-daemon into a folder only root can write, run the daemon from there, and give that path to collector-plan."
        ));
    } else {
        lines.push(format!(
            "Neither {peer} nor any folder on the way to it is yours or writable by you, so a process running as you cannot replace it (an administrator still can)."
        ));
    }
    lines.push(format!(
        "The commands check the collector binary and the plist against the hashes shown here before anything starts. The binary installed is {binary}, SHA-256 {binary_sha}."
    ));
    lines.push(format!(
        "Its names: the label {label}, its sockets in /var/run/derm-activity and its log in /Library/Application Support/derm/activity."
    ));
    lines.push(format!(
        "This plan ran no command. It wrote one file, the staged plist at {staged} (0600), which the first command copies."
    ));
    lines
}

/// Whether this user could replace `path`: the file, or any folder on the
/// way to it, is this user's or writable by this user, by owner, group, other
/// bits or an ACL, as the kernel decides it (`faccessat` with `AT_EACCESS`).
/// A folder anywhere up the chain decides a rename that swaps the exact path,
/// so every one is checked, for the path as given and for its real path
/// (fix pass 1's review, FP1-S3: the first version looked at the file and
/// its folder, by owner and other-write only). A path it cannot check counts
/// as writable.
fn writable_by_me(path: &std::path::Path) -> bool {
    writable_with(path, can_change)
}

fn writable_with(path: &std::path::Path, can: impl Fn(&std::path::Path) -> bool) -> bool {
    let mut chains = vec![path.to_path_buf()];
    if let Ok(real) = std::fs::canonicalize(path) {
        chains.push(real);
    }
    chains
        .iter()
        .any(|p| p.ancestors().any(|a| !a.as_os_str().is_empty() && can(a)))
}

/// One path: owned by this user (who can always chmod it), or writable by
/// this user's effective ids.
#[cfg(unix)]
fn can_change(p: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let me = derm_core::platform::real_user();
    let Ok(meta) = std::fs::symlink_metadata(p) else {
        return true;
    };
    if meta.uid() == me {
        return true;
    }
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return true;
    };
    // SAFETY: a valid C string; faccessat only reads it. AT_EACCESS checks
    // the effective ids, as a rename would. AT_SYMLINK_NOFOLLOW is not passed:
    // a link's own entry is its folder's, which the chain checks.
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::W_OK, libc::AT_EACCESS) == 0 }
}

/// Windows (lane Z): the collector is the Mac's; every path counts as one
/// this user can change, the answer the Unix code gives when it cannot read.
#[cfg(not(unix))]
fn can_change(_p: &std::path::Path) -> bool {
    true
}

/// How often the pump asks the collector for what it saw.
pub const PUMP_EVERY: std::time::Duration = std::time::Duration::from_secs(2);
/// How far back each ask reaches before the newest event already taken: an
/// event the collector stamps a little before one it already gave.
pub const PUMP_OVERLAP_MS: i64 = 5_000;
/// How many recent ids the pump remembers, to take an event once.
pub const PUMP_SEEN: usize = 50_000;

/// The collector's events into the daemon's own feed (Mac test w5, MW5-14).
/// Until this, the daemon read them only for `report`'s flags, so on macOS
/// no eslogger record reached `Daemon::ingest`: no join candidate set, no
/// install control flag, no argv shaped. The Linux feed has always posted
/// its records through the socket (`derm-audit-feed`); this does the same
/// from inside the daemon. Each event is taken once (by id), keeps the
/// collector's own time as `osAt` (the join's effect time), and keeps its
/// id, so `report` counts it once (`flags_report` skips a collector event
/// the log already holds).
#[derive(Debug)]
pub struct Pump {
    cursor: i64,
    seen: std::collections::HashSet<String>,
    order: std::collections::VecDeque<String>,
}

impl Pump {
    /// A pump that takes events from `since` on (the daemon's start).
    pub fn new(since: i64) -> Self {
        Pump {
            cursor: since,
            seen: Default::default(),
            order: Default::default(),
        }
    }

    /// The window to ask for next.
    pub fn since(&self) -> i64 {
        self.cursor.saturating_sub(PUMP_OVERLAP_MS)
    }

    /// The events of one reply that are new, ready for `ingest`.
    pub fn take(&mut self, reply: crate::activity::collector::EventsReply) -> Vec<Event> {
        let mut out = Vec::new();
        for mut event in reply.events {
            if event.source != Source::Eslogger || event.id.is_empty() {
                continue;
            }
            if !self.seen.insert(event.id.clone()) {
                continue;
            }
            self.order.push_back(event.id.clone());
            while self.order.len() > PUMP_SEEN {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
            self.cursor = self.cursor.max(event.at);
            if let Value::Object(map) = &mut event.detail {
                map.entry("osAt").or_insert(Value::from(event.at));
            }
            out.push(event);
        }
        out
    }
}

/// Pages one round reads past a truncated reply, at most.
pub const PUMP_PAGES: usize = 20;

/// One round: ask, ingest what is new. `fetch` is the collector's events
/// between two times (`activity::collector::fetch_events` on a Mac).
///
/// Mac test w5 retest 2, MW5-19: past its limit the collector keeps the
/// newest events of the window and says `truncated` (`log.rs` `read_events`);
/// the pump then moved its cursor past them, and the older part of a burst
/// was never asked for again. A truncated reply is followed by asks for the
/// window before its oldest event, until one is whole or `PUMP_PAGES` ran.
pub fn pump_once(
    daemon: &Daemon,
    pump: &mut Pump,
    now: i64,
    fetch: impl Fn(i64, i64) -> crate::activity::collector::EventsReply,
) -> usize {
    let since = pump.since();
    let mut until = now;
    let mut n = 0;
    for _ in 0..PUMP_PAGES {
        let reply = fetch(since, until);
        let truncated = reply.truncated;
        let oldest = reply.events.iter().map(|e| e.at).min();
        let events = pump.take(reply);
        n += events.len();
        for event in events {
            daemon.ingest(event);
        }
        // The next page ends at the oldest event this one held (that
        // millisecond again, as the seen ids take each event once).
        match (truncated, oldest) {
            (true, Some(o)) if o > since && o < until => until = o,
            _ => break,
        }
    }
    n
}

/// Starts what lane K adds to a running daemon. Returns at once.
pub fn start(daemon: &Arc<Daemon>, paths: &Paths) {
    if cfg!(target_os = "macos") {
        let follower = daemon.clone();
        let _ = std::thread::Builder::new()
            .name("derm-daemon-collector".into())
            .spawn(move || {
                follower
                    .counters
                    .registration_started
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                follower
                    .counters
                    .registration_running
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                let running = follower.clone();
                // Shown as stopped if the loop ever ends, by a panic too.
                struct Stopped(Arc<Daemon>);
                impl Drop for Stopped {
                    fn drop(&mut self) {
                        self.0
                            .counters
                            .registration_running
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                let _stopped = Stopped(running);
                follow(&follower, |event| {
                    if let Some(r) = registration(&event) {
                        apply(r);
                    }
                })
            });
        let pumped = daemon.clone();
        let _ = std::thread::Builder::new()
            .name("derm-daemon-collector-pump".into())
            .spawn(move || {
                use crate::activity::collector;
                let mut pump = Pump::new(crate::activity::store::now_ms());
                loop {
                    std::thread::sleep(PUMP_EVERY);
                    pump_once(
                        &pumped,
                        &mut pump,
                        crate::activity::store::now_ms(),
                        |since, until| {
                            collector::fetch_events(since, until, None, collector::MAX_EVENTS)
                        },
                    );
                }
            });
    }
    #[cfg(feature = "computer-use")]
    crate::computer_use::service::start(daemon, paths);
    #[cfg(not(feature = "computer-use"))]
    let _ = paths;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run_event(kind: &str, chat: &str, pid: Option<u32>, source: Source) -> Event {
        Event {
            id: format!("{kind}-1"),
            at: 0,
            chat_id: chat.into(),
            harness: "pi".into(),
            source,
            kind: kind.into(),
            summary: String::new(),
            detail: json!({}),
            pid,
            approval_id: None,
        }
    }

    #[test]
    fn a_run_start_with_a_pid_is_followed_for_its_chat() {
        assert_eq!(
            registration(&run_event("run.start", "chat-1", Some(4242), Source::Run)),
            Some(Registration::Follow {
                pid: 4242,
                chat: "chat-1".into()
            })
        );
        assert_eq!(
            registration(&run_event("run.stop", "chat-1", Some(4242), Source::Run)),
            Some(Registration::Exited { pid: 4242 })
        );
    }

    #[test]
    fn nothing_else_registers_a_process() {
        // A chat token posts only adapter and otel records, so a `run.start`
        // of any other source is not one derm run wrote.
        for source in [
            Source::Adapter,
            Source::Otel,
            Source::Eslogger,
            Source::Auditd,
            Source::Cua,
            Source::Approval,
        ] {
            assert_eq!(
                registration(&run_event("run.start", "chat-1", Some(4242), source)),
                None
            );
        }
        // No pid, pid 0 or 1 (init), a chat id the collector refuses.
        assert_eq!(
            registration(&run_event("run.start", "chat-1", None, Source::Run)),
            None
        );
        for pid in [0, 1] {
            assert_eq!(
                registration(&run_event("run.start", "chat-1", Some(pid), Source::Run)),
                None
            );
        }
        assert_eq!(
            registration(&run_event("run.start", "bad id/..", Some(9), Source::Run)),
            None
        );
        assert_eq!(
            registration(&run_event("tool.call", "chat-1", Some(9), Source::Run)),
            None
        );
    }

    #[test]
    fn a_pushed_line_yields_its_event_and_nothing_else_does() {
        let event = run_event("run.start", "chat-1", Some(7), Source::Run);
        let line = serde_json::to_string(&crate::protocol::Push::Event(event.clone())).unwrap();
        assert_eq!(pushed_event(&line), Some(event));
        assert_eq!(pushed_event(r#"{"ok":true}"#), None);
        assert_eq!(pushed_event("not json"), None);
        assert_eq!(
            pushed_event(
                r#"{"approve":{"id":"a","chat":"c","harness":"pi","tool":"t","summary":""}}"#
            ),
            None
        );
    }

    #[test]
    fn follow_sees_what_the_daemon_scope_posts_and_registers_it() {
        use crate::activity::store::ActivityLog;
        use std::sync::mpsc;
        let root =
            std::env::temp_dir().join(format!("derm-collector-{}", uuid::Uuid::new_v4().simple()));
        let data = root.join("data");
        let log: &'static ActivityLog =
            Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
        let daemon = Daemon::new(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            log,
            &data,
            false,
        )
        .unwrap();
        let (tx, rx) = mpsc::channel();
        let following = daemon.clone();
        std::thread::spawn(move || {
            follow(&following, |event| {
                let _ = tx.send(registration(&event));
            })
        });
        // The subscription is made on the follower's thread; post until it
        // hears one, so the test does not race the subscribe.
        let (out, replies, _) = Outbox::new(daemon.next_conn());
        let mut seen = None;
        for n in 0..50 {
            daemon.handle(
                &Who::Daemon,
                Request::Event {
                    event: run_event("run.start", "chat-2", Some(5000 + n), Source::Run),
                },
                &out,
            );
            let _ = replies.recv_timeout(std::time::Duration::from_secs(5));
            if let Ok(r) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
                seen = r;
                break;
            }
        }
        match seen {
            Some(Registration::Follow { chat, .. }) => assert_eq!(chat, "chat-2"),
            other => panic!("no registration: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// Mac test w5 retest 2, MW5-18: the follower's in-process tail never
    /// counted a line as taken (its outbox's pending counter was dropped),
    /// so after 4,096 events in the daemon's life the daemon dropped it as a
    /// slow reader, the thread ended, and no later chat was registered with
    /// the collector until a restart. A flood of OS records must not stop it.
    #[test]
    fn the_follower_keeps_registering_after_a_flood_of_events() {
        use crate::activity::store::ActivityLog;
        use std::sync::mpsc;
        let root =
            std::env::temp_dir().join(format!("derm-collector-{}", uuid::Uuid::new_v4().simple()));
        let data = root.join("data");
        let log: &'static ActivityLog =
            Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
        let daemon = Daemon::new(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            log,
            &data,
            false,
        )
        .unwrap();
        let (tx, rx) = mpsc::channel();
        let following = daemon.clone();
        std::thread::spawn(move || {
            follow(&following, |event| {
                if let Some(r) = registration(&event) {
                    let _ = tx.send(r);
                }
            })
        });
        let (out, replies, _) = Outbox::new(daemon.next_conn());
        let post = |pid: u32, chat: &str| {
            daemon.handle(
                &Who::Daemon,
                Request::Event {
                    event: Event {
                        id: format!("run.start-{pid}"),
                        ..run_event("run.start", chat, Some(pid), Source::Run)
                    },
                },
                &out,
            );
            let _ = replies.recv_timeout(std::time::Duration::from_secs(5));
        };
        // Wait until the follower hears one, so the flood comes after it
        // subscribed.
        let mut heard = false;
        for n in 0..50 {
            post(6000 + n, "chat-before");
            if rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_ok()
            {
                heard = true;
                break;
            }
        }
        assert!(heard, "the follower never subscribed");
        while rx.try_recv().is_ok() {}
        // More OS records than a tail may hold back.
        for n in 0..(crate::daemon::MAX_PENDING_LINES + 500) {
            daemon.ingest(Event {
                id: format!("es-flood-{n}"),
                at: 0,
                chat_id: "chat-before".into(),
                harness: String::new(),
                source: Source::Eslogger,
                kind: "write".into(),
                summary: String::new(),
                detail: json!({"path": format!("/tmp/f{n}")}),
                pid: Some(77),
                approval_id: None,
            });
        }
        post(9001, "chat-after");
        let mut got = None;
        let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < until {
            match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(Registration::Follow { chat, .. }) if chat == "chat-after" => {
                    got = Some(chat);
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(
            got.as_deref(),
            Some("chat-after"),
            "the follower stopped after the flood"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// MW5-19: a burst bigger than one reply. The collector keeps the newest
    /// events of the window past its limit; the pump must ask for the rest.
    #[test]
    fn a_truncated_reply_is_paged_back_to_the_window_start() {
        use crate::activity::collector::EventsReply;
        use crate::activity::store::ActivityLog;
        let root =
            std::env::temp_dir().join(format!("derm-collector-{}", uuid::Uuid::new_v4().simple()));
        let data = root.join("data");
        let log: &'static ActivityLog =
            Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
        let daemon = Daemon::new(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            log,
            &data,
            false,
        )
        .unwrap();
        // 2,500 events, 4 a millisecond, from t = 1,000; the stand-in keeps
        // the newest 1,000 of a window, as `read_events` does.
        let all: Vec<Event> = (0..2_500)
            .map(|i| Event {
                id: format!("es-burst-{i}"),
                at: 1_000 + i / 4,
                chat_id: "chat-b".into(),
                harness: String::new(),
                source: Source::Eslogger,
                kind: "create".into(),
                summary: String::new(),
                detail: json!({"path": format!("/w/f{i}")}),
                pid: Some(9),
                approval_id: None,
            })
            .collect();
        let fetch = |since: i64, until: i64| {
            let mut v: Vec<Event> = all
                .iter()
                .filter(|e| e.at >= since && e.at <= until)
                .cloned()
                .collect();
            let truncated = v.len() > 1_000;
            if truncated {
                v = v.split_off(v.len() - 1_000);
            }
            EventsReply {
                events: v,
                truncated,
                complete: true,
                connected: true,
                chain_ok: true,
                ..EventsReply::default()
            }
        };
        let mut pump = Pump::new(1_000 + PUMP_OVERLAP_MS);
        assert_eq!(pump_once(&daemon, &mut pump, 5_000, fetch), 2_500);
        // Nothing new the next round.
        assert_eq!(pump_once(&daemon, &mut pump, 6_000, fetch), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_report_says_whether_registration_runs() {
        use crate::activity::store::ActivityLog;
        let root =
            std::env::temp_dir().join(format!("derm-collector-{}", uuid::Uuid::new_v4().simple()));
        let data = root.join("data");
        let log: &'static ActivityLog =
            Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
        let daemon = Daemon::new(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            log,
            &data,
            false,
        )
        .unwrap();
        use std::sync::atomic::Ordering;
        let r = daemon.report(None, 0, i64::MAX);
        assert!(r["osRegistration"].is_null(), "{r}");
        assert_eq!(r["tailsDropped"], 0);
        daemon
            .counters
            .registration_started
            .store(true, Ordering::SeqCst);
        daemon
            .counters
            .registration_running
            .store(true, Ordering::SeqCst);
        assert_eq!(
            daemon.report(None, 0, i64::MAX)["osRegistration"],
            "running"
        );
        daemon
            .counters
            .registration_running
            .store(false, Ordering::SeqCst);
        assert_eq!(
            daemon.report(None, 0, i64::MAX)["osRegistration"],
            "stopped"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn the_install_plan_pins_the_binary_and_the_peer_and_stages_the_plist() {
        let root = std::env::temp_dir().join(format!(
            "derm-collector-plan-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let binary = root.join("derm-activity-collector");
        std::fs::write(&binary, b"not really a collector").unwrap();
        let peer = root.join("derm-daemon");
        std::fs::write(&peer, b"daemon").unwrap();
        let paths = Paths {
            socket: root.join("run/derm/daemon.sock"),
            data: root.join("data"),
        };
        let plan = install_plan(&paths, &binary, &peer).unwrap();
        assert_eq!(plan.route, "terminal");
        let hash = crate::activity::collector::file_sha256(&binary).unwrap();
        assert!(
            plan.commands.iter().any(|c| c.contains(&hash)),
            "{:?}",
            plan.commands
        );
        assert!(plan.plist.contains("--dev-peer-path"));
        assert!(plan.plist.contains(&*peer.to_string_lossy()));
        let staged = plan.staged_plist.clone().unwrap();
        assert_eq!(std::fs::read_to_string(&staged).unwrap(), plan.plist);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Every command names its tools by absolute path.
        assert!(plan
            .commands
            .iter()
            .all(|c| c.starts_with("/usr/bin/sudo /")));

        // A relative path, a link and a missing file are refused.
        assert!(install_plan(&paths, std::path::Path::new("rel/bin"), &peer).is_err());
        let link = root.join("link");
        std::os::unix::fs::symlink(&binary, &link).unwrap();
        assert!(install_plan(&paths, &link, &peer).is_err());
        assert!(install_plan(&paths, &root.join("absent"), &peer).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_peer_is_replaceable_when_any_folder_up_its_path_is_ours() {
        // Fix pass 1's review, FP1-S3: the first check looked at the file
        // and its own folder, by owner and other-write. A user-owned /opt/derm
        // above a root-owned /opt/derm/bin/derm-daemon still lets the user rename
        // bin away and put another derm-daemon at the exact path.
        let only = |hit: &'static str| move |p: &std::path::Path| p == std::path::Path::new(hit);
        let peer = std::path::Path::new("/opt/derm/bin/derm-daemon");
        assert!(writable_with(peer, only("/opt/derm")));
        assert!(writable_with(peer, only("/opt")));
        assert!(writable_with(peer, only("/opt/derm/bin/derm-daemon")));
        assert!(!writable_with(peer, only("/elsewhere")));
        // On the real system: /bin/sh is root's all the way up, so only root
        // can replace it (CI's macOS runner and a Linux user both run this
        // as a user).
        let root = derm_core::platform::real_user() == 0;
        assert_eq!(writable_by_me(std::path::Path::new("/bin/sh")), root);
        // A folder of ours anywhere up the given path counts, even when the
        // path is a link to a file we cannot write.
        let dir =
            std::env::temp_dir().join(format!("derm-chain-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let link = dir.join("bin").join("derm-daemon");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        assert!(writable_by_me(&link));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_plan_speaks_for_derm_and_says_what_trusting_the_peer_by_path_costs() {
        // Mac test w2, MW5: the plan said "Only MonoCode may talk to it" and
        // "processes MonoCode started", and did not say that the caller it
        // trusts by path sits in a folder you (and an agent running as you)
        // can write; and it writes a staged plist, which "runs nothing" hid.
        let root = std::env::temp_dir().join(format!(
            "derm-collector-words-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let binary = root.join("derm-activity-collector");
        std::fs::write(&binary, b"not really a collector").unwrap();
        let peer = root.join("derm-daemon");
        std::fs::write(&peer, b"daemon").unwrap();
        let paths = Paths {
            socket: root.join("run/derm/daemon.sock"),
            data: root.join("data"),
        };
        // The plan is a Mac's root shell: off Unix, where no absolute path
        // begins with `/`, it refuses the binary's path rather than build a
        // command it cannot show safely.
        if cfg!(windows) {
            let e = install_plan(&paths, &binary, &peer).unwrap_err();
            assert!(e.contains("cannot show safely"), "{e}");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        let plan = install_plan(&paths, &binary, &peer).unwrap();
        let text = plan.explanation.join("\n");
        assert!(!text.contains("Only MonoCode"), "{text}");
        assert!(!text.contains("processes MonoCode started"), "{text}");
        assert!(text.contains("derm run"), "{text}");
        let peer_hash = crate::activity::collector::file_sha256(&peer).unwrap();
        assert!(
            text.contains(&*peer.to_string_lossy()) && text.contains(&peer_hash),
            "{text}"
        );
        assert!(text.contains("can replace that file"), "{text}");
        assert!(
            text.contains("wrote one file") && text.contains(&plan.staged_plist.clone().unwrap()),
            "{text}"
        );
        assert!(
            text.contains("io.github.aetiusgular.derm.activity-collector"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
