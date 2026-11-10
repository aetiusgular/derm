//! The Linux feed's tail (fix pass 13's review, FP13R-1 and FP13R-11): a
//! restarted daemon's backlog holds the newest records, a backlog longer
//! than the live headroom is not dropped by the first live event, a dropped
//! tail is closed, and `runs` tails `run` records only. The first two were
//! the review's probes and failed on `c6e264b`.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use derm_core::event::{Event, Source};
use derm_daemon::activity::store::{ActivityLog, ChainWriter, Entry};
use derm_daemon::daemon::Daemon;
use serde_json::{json, Value};

const DAEMON_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// FP13R-1: after a daemon restart (the ring is empty), a `since` tail's
/// backlog is the OLDEST 5,000 records of the last 24 h, not the newest:
/// a chat started after them is never in the backlog the feed waits for.
#[test]
fn fp13r_1_a_restarted_daemons_backlog_leaves_out_the_newest_run_start() {
    let root = std::env::temp_dir().join(format!("fp13r1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let data = root.join("data");
    let t0 = now() - 60_000;
    {
        // The log a busy hour left, written as the daemon writes it.
        let mut w = ChainWriter::new(data.join("activity"));
        for i in 0..6_000i64 {
            let e = Event {
                id: format!("busy-{i}"),
                at: t0 + i,
                chat_id: "chat-busy".into(),
                harness: "pi".into(),
                source: Source::Adapter,
                kind: "tool.call".into(),
                summary: String::new(),
                detail: json!({}),
                pid: None,
                approval_id: None,
            };
            w.write(&Entry::Event(e), t0 + i).unwrap();
        }
        let start = Event {
            id: "run-new".into(),
            at: t0 + 10_000,
            chat_id: "chat-new".into(),
            harness: "pi".into(),
            source: Source::Run,
            kind: "run.start".into(),
            summary: String::new(),
            detail: json!({}),
            pid: Some(4242),
            approval_id: None,
        };
        w.write(&Entry::Event(start), t0 + 10_000).unwrap();
    }
    // The daemon restarts: a new process, the ring empty.
    let log: &'static ActivityLog = Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
    let daemon = Daemon::new(DAEMON_TOKEN, log, &data, false).unwrap();
    let socket = root.join("run/derm/daemon.sock");
    let listener = derm_daemon::socket::bind(&socket).unwrap();
    std::thread::spawn(move || derm_daemon::socket::serve(listener, daemon));
    let s = UnixStream::connect(&socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut w = s.try_clone().unwrap();
    let mut r = BufReader::new(s);
    let mut line = String::new();
    writeln!(
        w,
        "{}",
        json!({"op": "hello", "token": DAEMON_TOKEN, "client": "derm-audit-feed tail"})
    )
    .unwrap();
    r.read_line(&mut line).unwrap();
    line.clear();
    writeln!(
        w,
        "{}",
        json!({"op": "tail", "since": now() - 24 * 3600 * 1000})
    )
    .unwrap();
    r.read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    let n = reply["report"]["backlogSent"].as_u64().unwrap() as usize;
    let mut saw_new = false;
    for _ in 0..n {
        line.clear();
        r.read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        if v["event"]["chatId"] == "chat-new" {
            saw_new = true;
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        saw_new,
        "the backlog ({n} events, report {}) left out the newest chat's run.start",
        reply["report"]
    );
}

/// FP13R-11: a `since` tail whose backlog is longer than MAX_PENDING_LINES
/// (4,096) is dropped by the first live event ingested while the backlog is
/// still queued; the feed posts `feed.gap` right after its tail opens
/// (derm-audit-feed.rs:370), so on its gap path it drops its own tail. The
/// connection stays open (read_loop still holds it), so the feed never sees
/// EOF and never learns a live run.start.
#[test]
fn fp13r_11_the_feeds_own_gap_post_does_not_drop_its_tail() {
    let root = std::env::temp_dir().join(format!("fp13r11-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let data = root.join("data");
    let log: &'static ActivityLog = Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
    let daemon = Daemon::new(DAEMON_TOKEN, log, &data, false).unwrap();
    let socket = root.join("run/derm/daemon.sock");
    let listener = derm_daemon::socket::bind(&socket).unwrap();
    let d2 = daemon.clone();
    std::thread::spawn(move || derm_daemon::socket::serve(listener, d2));
    let connect = |client: &str| {
        let s = UnixStream::connect(&socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        let mut line = String::new();
        writeln!(
            w,
            "{}",
            json!({"op": "hello", "token": DAEMON_TOKEN, "client": client})
        )
        .unwrap();
        r.read_line(&mut line).unwrap();
        (w, r)
    };
    let (mut pw, mut pr) = connect("poster");
    let mut ask = |v: Value| {
        writeln!(pw, "{v}").unwrap();
        let mut line = String::new();
        pr.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    };
    // A day's records: more than MAX_PENDING_LINES of them.
    for i in 0..4_600 {
        let r = ask(json!({"op": "event", "event": {
            "id": format!("busy-{i}"), "at": 0, "chatId": "chat-busy", "harness": "pi",
            "source": "adapter", "kind": "tool.call", "summary": "", "detail": {"pad": "x".repeat(2000)}
        }}));
        assert_eq!(r["ok"], true);
    }
    std::thread::sleep(Duration::from_millis(500));
    let (mut tw, mut tr) = connect("derm-audit-feed tail");
    writeln!(tw, "{}", json!({"op": "tail", "since": now() - 3_600_000})).unwrap();
    let mut line = String::new();
    tr.read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    let n = reply["report"]["backlogSent"].as_u64().unwrap();
    // The feed posts its gap at once, as derm-audit-feed.rs:368-373 does.
    let r = ask(json!({"op": "event", "event": {
        "id": "auditd-gap-1", "at": now(), "chatId": "", "harness": "",
        "source": "auditd", "kind": "feed.gap", "summary": "gap",
        "detail": {"fromMs": now() - 60_000, "toMs": now(), "reason": "rotated"}
    }}));
    assert_eq!(r["ok"], true);
    // Then a chat starts.
    let r = ask(json!({"op": "event", "event": {
        "id": "run-live", "at": 0, "chatId": "chat-live", "harness": "pi", "source": "run",
        "kind": "run.start", "summary": "pi", "pid": 4343,
        "detail": {"boundary": "none", "argv": ["pi"], "host": "box", "cwd": "/home/t/proj"}
    }}));
    assert_eq!(r["ok"], true);
    // The feed reads its backlog, then waits for the live run.start.
    let mut got_live = false;
    let mut read = 0u64;
    loop {
        line.clear();
        match tr.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                read += 1;
                if line.contains("\"chat-live\"") {
                    got_live = true;
                    break;
                }
            }
        }
    }
    let rep = ask(json!({"op": "report", "since": 0, "until": i64::MAX}));
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        got_live,
        "backlog {n}, read {read} lines, no live run.start; osFeed {} tailsDropped {}",
        rep["report"]["osFeed"], rep["report"]["tailsDropped"]
    );
}

/// FP13R-1 and FP13R-11: the feed's tail is `run` records only, backlog and
/// live, so a busy log neither pushes its chats out of the backlog nor fills
/// its queue.
#[test]
fn a_runs_tail_sends_run_records_only() {
    let root = std::env::temp_dir().join(format!("fp13r-runs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let data = root.join("data");
    let log: &'static ActivityLog = Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
    let daemon = Daemon::new(DAEMON_TOKEN, log, &data, false).unwrap();
    let socket = root.join("run/derm/daemon.sock");
    let listener = derm_daemon::socket::bind(&socket).unwrap();
    std::thread::spawn(move || derm_daemon::socket::serve(listener, daemon));
    let connect = |client: &str| {
        let s = UnixStream::connect(&socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        let mut line = String::new();
        writeln!(
            w,
            "{}",
            json!({"op": "hello", "token": DAEMON_TOKEN, "client": client})
        )
        .unwrap();
        r.read_line(&mut line).unwrap();
        (w, r)
    };
    let (mut pw, mut pr) = connect("poster");
    let mut ask = |v: Value| {
        writeln!(pw, "{v}").unwrap();
        let mut line = String::new();
        pr.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    };
    let run = |id: &str, chat: &str, kind: &str| {
        json!({"op": "event", "event": {
            "id": id, "at": 0, "chatId": chat, "harness": "pi", "source": "run",
            "kind": kind, "summary": "pi", "pid": 4343,
            "detail": {"boundary": "none", "argv": ["pi"], "host": "box", "cwd": "/home/t/proj"}
        }})
    };
    assert_eq!(ask(run("run-a", "chat-a", "run.start"))["ok"], true);
    for i in 0..50 {
        let r = ask(json!({"op": "event", "event": {
            "id": format!("busy-{i}"), "at": 0, "chatId": "chat-a", "harness": "pi",
            "source": "adapter", "kind": "tool.call", "summary": "", "detail": {}
        }}));
        assert_eq!(r["ok"], true);
    }
    let (mut tw, mut tr) = connect("derm-audit-feed tail");
    writeln!(
        tw,
        "{}",
        json!({"op": "tail", "since": now() - 3_600_000, "runs": true})
    )
    .unwrap();
    let mut line = String::new();
    tr.read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["report"]["backlogSent"], 1, "{reply}");
    line.clear();
    tr.read_line(&mut line).unwrap();
    assert!(line.contains("\"run-a\""), "{line}");
    // Live: an adapter record is not sent, the next run record is.
    assert_eq!(
        ask(json!({"op": "event", "event": {
            "id": "busy-live", "at": 0, "chatId": "chat-a", "harness": "pi",
            "source": "adapter", "kind": "tool.call", "summary": "", "detail": {}
        }}))["ok"],
        true
    );
    assert_eq!(ask(run("run-b", "chat-a", "run.stop"))["ok"], true);
    line.clear();
    tr.read_line(&mut line).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert!(line.contains("\"run-b\""), "{line}");
}

/// FP13R-11: a tail the daemon drops for a full queue is closed, so its
/// client sees the end (a feed under systemd then starts again) instead of
/// a connection held open that never sends another record.
#[test]
fn fp13r_11_a_dropped_tail_is_closed() {
    let root = std::env::temp_dir().join(format!("fp13r-drop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let data = root.join("data");
    let log: &'static ActivityLog = Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
    let daemon = Daemon::new(DAEMON_TOKEN, log, &data, false).unwrap();
    let socket = root.join("run/derm/daemon.sock");
    let listener = derm_daemon::socket::bind(&socket).unwrap();
    std::thread::spawn(move || derm_daemon::socket::serve(listener, daemon));
    let connect = |client: &str| {
        let s = UnixStream::connect(&socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        let mut line = String::new();
        writeln!(
            w,
            "{}",
            json!({"op": "hello", "token": DAEMON_TOKEN, "client": client})
        )
        .unwrap();
        r.read_line(&mut line).unwrap();
        (w, r)
    };
    let (mut tw, mut tr) = connect("a slow tail");
    writeln!(tw, "{}", json!({"op": "tail"})).unwrap();
    let mut line = String::new();
    tr.read_line(&mut line).unwrap();
    // The tail reads nothing while the log fills its queue past its room.
    let (mut pw, mut pr) = connect("poster");
    for i in 0..6_000 {
        writeln!(pw, "{}", json!({"op": "event", "event": {
            "id": format!("busy-{i}"), "at": 0, "chatId": "chat-busy", "harness": "pi",
            "source": "adapter", "kind": "tool.call", "summary": "", "detail": {"pad": "x".repeat(400)}
        }}))
        .unwrap();
        line.clear();
        pr.read_line(&mut line).unwrap();
    }
    // Now it reads: what was queued, then the end.
    let mut lines = 0u64;
    let ended = loop {
        line.clear();
        match tr.read_line(&mut line) {
            Ok(0) => break true,
            Ok(_) => lines += 1,
            Err(_) => break false,
        }
    };
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        ended,
        "no end after {lines} lines: the dropped tail was held open"
    );
    assert!(lines < 6_000);
}
