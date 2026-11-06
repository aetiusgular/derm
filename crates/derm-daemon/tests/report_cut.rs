//! Fix pass 4's review (FP4-S2, FP4-S3): a report cut to fit keeps the
//! rows that matter and never passes the budget. The first two tests are the
//! reviewer's, each failing first. Each runs its own daemon.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use derm_daemon::activity::store::ActivityLog;
use derm_daemon::daemon::Daemon;
use serde_json::{json, Value};

const DAEMON_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    _daemon: Arc<Daemon>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture() -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "tkr-{}-{}",
        std::process::id(),
        &derm_core::token::mint().unwrap()[..12]
    ));
    std::fs::create_dir_all(&root).unwrap();
    let data = root.join("data");
    let log: &'static ActivityLog = Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
    let daemon = Daemon::new(DAEMON_TOKEN, log, &data, false).unwrap();
    let socket = root.join("run/derm/daemon.sock");
    let listener = derm_daemon::socket::bind(&socket).unwrap();
    let serving = daemon.clone();
    std::thread::spawn(move || derm_daemon::socket::serve(listener, serving));
    Fixture {
        root,
        socket,
        _daemon: daemon,
    }
}

struct Client {
    w: UnixStream,
    r: BufReader<UnixStream>,
}

impl Client {
    fn hello(f: &Fixture, token: &str) -> (Client, Value) {
        let s = UnixStream::connect(&f.socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let mut c = Client {
            w: s.try_clone().unwrap(),
            r: BufReader::new(s),
        };
        let reply = c.ask(json!({"op": "hello", "token": token, "client": "test"}));
        (c, reply)
    }

    /// The reply and its line's length.
    fn ask_len(&mut self, v: Value) -> (Value, usize) {
        writeln!(self.w, "{v}").unwrap();
        let mut line = String::new();
        self.r.read_line(&mut line).unwrap();
        (serde_json::from_str(&line).unwrap(), line.len())
    }

    fn ask(&mut self, v: Value) -> Value {
        self.ask_len(v).0
    }
}

fn wait_events(d: &mut Client, chat: Option<&str>, n: usize) -> (Value, usize) {
    let mut out = (Value::Null, 0);
    for _ in 0..200 {
        out = d.ask_len(json!({"op": "report", "chat": chat, "since": 0, "until": i64::MAX}));
        if out.0["report"]["events"].as_u64() == Some(n as u64) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    out
}

/// FP4-S3: a chat token alone can push a report reply past every client's
/// 1 MiB line limit again, so `derm watch report` fails and shows nothing:
/// `fit_report` cuts only the check's rows, and `byKind` grows with every
/// distinct `kind` the chat posts (64 bytes each, `store::MAX_KIND`).
#[test]
fn fp4_s3_a_chat_token_cannot_make_the_report_too_big_to_read() {
    let f = fixture();
    let (mut d, _) = Client::hello(&f, DAEMON_TOKEN);
    // A chat token posts these at 50 a second over the socket
    // (SOCKET_RATE_PER_CHAT_SEC), about 5 minutes, or as `otel.<name>`
    // kinds through OTLP at 2,000 records a post, 10 posts a second. The
    // test posts the same records in daemon scope so it does not wait.
    let mut agent = Client::hello(&f, DAEMON_TOKEN).0;
    let n = 16_000;
    for i in 0..n {
        let kind = format!("k{i:05}{}", "x".repeat(58));
        let r = agent.ask(json!({"op": "event", "event": {
            "id": format!("a-{i}"), "at": 0, "chatId": "chat-x", "harness": "pi",
            "source": "adapter", "kind": kind, "summary": "", "detail": {}
        }}));
        assert_eq!(r["ok"], true, "{r}");
    }
    let (reply, line) = wait_events(&mut d, None, n);
    assert_eq!(
        reply["report"]["events"], n,
        "{}",
        reply["report"]["events"]
    );
    assert!(
        line < derm_daemon::socket::MAX_LINE_BYTES,
        "a chat token made the report line {line} bytes (budget {})",
        derm_daemon::daemon::REPORT_BUDGET
    );
}

/// FP4-S2: the cut keeps the oldest flags, so a chat's own early burst of
/// cheap flags pushes a later real one out of the list, in its own report
/// and in the daemon-wide report for another chat. The writes stand for the
/// agent's own file writes, as the kernel feed records them.
#[test]
fn fp4_s2_a_burst_of_cheap_flags_does_not_push_a_later_real_one_out() {
    let f = fixture();
    let (mut d, _) = Client::hello(&f, DAEMON_TOKEN);
    for chat in ["chat-a", "chat-v"] {
        let r = d.ask(json!({"op": "event", "event": {
            "id": format!("run-{chat}"), "at": 0, "chatId": chat, "harness": "pi", "source": "run",
            "kind": "run.start", "summary": "pi",
            "detail": {"boundary": "none", "argv": ["pi"], "host": "box", "cwd": "/home/t/proj"}
        }}));
        assert_eq!(r["ok"], true);
    }
    let n = 3_000;
    let long = "x".repeat(180);
    for i in 0..n {
        let r = d.ask(json!({"op": "event", "event": {
            "id": format!("w-{i}"), "at": 0, "chatId": "chat-a", "harness": "pi",
            "source": "auditd", "kind": "write", "summary": "",
            "detail": {"path": format!("/home/t/out/{long}-{i}.txt"), "tier": "child"},
            "pid": 77
        }}));
        assert_eq!(r["ok"], true);
    }
    // The real ones, after the burst: the agent's own, and another chat's.
    for (id, chat) in [("real-a", "chat-a"), ("real-v", "chat-v")] {
        let r = d.ask(json!({"op": "event", "event": {
            "id": id, "at": 0, "chatId": chat, "harness": "pi",
            "source": "auditd", "kind": "write", "summary": "",
            "detail": {"path": "/home/t/.ssh/authorized_keys", "tier": "child"},
            "pid": 78
        }}));
        assert_eq!(r["ok"], true);
    }
    let listed = |r: &Value, id: &str| {
        r["report"]["check"]["flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["eventId"] == id)
    };
    let (all, _) = wait_events(&mut d, None, n + 4);
    assert!(all["report"]["check"]["flagsOmitted"].as_u64().unwrap_or(0) > 0);
    let (own, _) = wait_events(&mut d, Some("chat-a"), n + 2);
    let other_listed = listed(&all, "real-v");
    let own_listed = listed(&own, "real-a");
    assert!(
        other_listed && own_listed,
        "another chat's later flag listed: {other_listed}; the chat's own later flag listed: {own_listed}"
    );
}

/// FP4-S3: whatever a report holds, `fit_report` returns it under the
/// budget, cutting in its order and saying so.
#[test]
fn a_report_is_never_returned_over_its_budget() {
    use derm_daemon::daemon::fit_report;
    let budget = 64 * 1024;
    let big = "z".repeat(4_000);
    let kinds: serde_json::Map<String, Value> = (0..2_000)
        .map(|i| (format!("k{i:05}{big}"), json!(1)))
        .collect();
    let flags: Vec<Value> = (0..500)
        .map(|i| {
            json!({"id": format!("f{i}"), "chatId": "c", "at": i, "reason": "writeOutsideFolders",
                   "summary": big, "eventId": format!("e{i}"), "context": []})
        })
        .collect();
    let other: Vec<String> = vec![big.clone(); 30];
    let many: Vec<String> = vec![big.clone(); 40];
    let cases = [
        json!({"events": 1, "flags": 500, "byKind": kinds.clone(),
               "check": {"flags": flags.clone(), "expected": [], "events": []}}),
        json!({"events": 1, "flags": 0, "check": {"flags": [], "expected": [], "events": [],
               "other": other}}),
        json!({"events": 1, "flags": 0, "chat": "c", "running": many.clone(),
               "osKernelDrops": many}),
    ];
    for mut r in cases {
        fit_report(&mut r, budget);
        let n = serde_json::to_vec(&r).unwrap().len();
        assert!(n <= budget, "{n} bytes over {budget}");
        assert_eq!(r["events"], 1, "the totals stay: {r}");
    }
    // The first case keeps its largest counts and says how many keys went.
    let mut r = json!({"events": 1, "flags": 0, "byKind": kinds,
                       "check": {"flags": [], "expected": [], "events": []}});
    fit_report(&mut r, 2 * 1024 * 1024);
    assert_eq!(
        r["byKind"].as_object().unwrap().len(),
        derm_daemon::daemon::REPORT_MAP_KEEP
    );
    assert_eq!(
        r["byKindOmitted"],
        2_000 - derm_daemon::daemon::REPORT_MAP_KEEP
    );
}

/// FP4-S5: a report on one chat whose window misses the chat's `run.start`
/// still finds its run, so the per-chat drop count is never left out for
/// that reason (`chatOsMissedUpTo` is set exactly when a run was found).
#[test]
fn a_chat_report_finds_its_run_outside_the_window() {
    let f = fixture();
    let (mut d, _) = Client::hello(&f, DAEMON_TOKEN);
    let r = d.ask(json!({"op": "event", "event": {
        "id": "run-k", "at": 1_000, "chatId": "chat-k", "harness": "pi", "source": "run",
        "kind": "run.start", "summary": "pi",
        "detail": {"boundary": "none", "argv": ["pi"], "host": "box", "cwd": "/home/t/proj"}
    }}));
    assert_eq!(r["ok"], true);
    // The daemon stamps a record with its own clock: the window starts after
    // the run's start by the wall clock.
    std::thread::sleep(Duration::from_millis(1_100));
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        - 100;
    let r = d.ask(json!({"op": "event", "event": {
        "id": "w-k", "at": 0, "chatId": "chat-k", "harness": "pi", "source": "adapter",
        "kind": "tool.call", "summary": "", "detail": {}
    }}));
    assert_eq!(r["ok"], true);
    let mut reply = Value::Null;
    for _ in 0..100 {
        reply = d.ask(json!({"op": "report", "chat": "chat-k", "since": since, "until": i64::MAX}));
        if reply["report"]["events"] == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        reply["report"]["events"], 1,
        "the window holds only the later event"
    );
    assert_eq!(
        reply["report"]["chatOsMissedUpTo"], false,
        "{}",
        reply["report"]
    );
    let none = d.ask(json!({"op": "report", "chat": "chat-none", "since": 0, "until": i64::MAX}));
    assert!(none["report"]["chatOsMissedUpTo"].is_null());
}

/// R2 (re-review of 1b91bf9): the cut ranks by reason, newest first, within
/// a chat. A chat token alone makes rank-3 `newHost` flags in bulk (an
/// adapter record with `detail.host`, `check.rs` `event_host`: any source
/// but run and approval), posted after the real act, so a write outside the
/// folders (rank 5) is pushed out of its own chat's list. And the agent's own
/// opens of `.env` files anywhere outside its folders are rank-0 flags, so a
/// burst of them after a real sensitive open pushes that one out too.
#[test]
fn r2_flags_a_chat_can_make_in_bulk_do_not_push_out_a_real_one() {
    let f = fixture();
    let (mut d, _) = Client::hello(&f, DAEMON_TOKEN);
    let r = d.ask(json!({"op": "event", "event": {
        "id": "run-a", "at": 0, "chatId": "chat-a", "harness": "pi", "source": "run",
        "kind": "run.start", "summary": "pi",
        "detail": {"boundary": "none", "argv": ["pi"], "host": "box", "cwd": "/home/t/proj"}
    }}));
    assert_eq!(r["ok"], true);
    // The real acts first, as the kernel feed records them.
    for (id, kind, path) in [
        ("real-write", "write", "/home/t/.ssh/authorized_keys"),
        ("real-open", "open", "/home/t/other/.env"),
    ] {
        let r = d.ask(json!({"op": "event", "event": {
            "id": id, "at": 0, "chatId": "chat-a", "harness": "pi",
            "source": "auditd", "kind": kind, "summary": "",
            "detail": {"path": path, "tier": "child"}, "pid": 78
        }}));
        assert_eq!(r["ok"], true, "{r}");
    }
    // Then the chat's own token: adapter records naming new hosts.
    let token = d.ask(json!({"op": "token.mint", "chat": "chat-a", "harness": "pi"}))["token"]
        .as_str()
        .unwrap()
        .to_string();
    let (mut agent, hello) = Client::hello(&f, &token);
    assert_eq!(hello["scope"], "chat", "{hello}");
    let n = 3_000;
    let mut i = 0;
    while i < n {
        let r = agent.ask(json!({"op": "event", "event": {
            "id": format!("h-{i}"), "at": 0, "chatId": "chat-a", "harness": "pi",
            "source": "adapter", "kind": "tool.call", "summary": "",
            "detail": {"host": format!("h{i}.example.net")}
        }}));
        if r["ok"] == true {
            i += 1;
        } else {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    // And the agent's own opens of `.env` files outside its folders.
    for i in 0..n {
        let r = d.ask(json!({"op": "event", "event": {
            "id": format!("o-{i}"), "at": 0, "chatId": "chat-a", "harness": "pi",
            "source": "auditd", "kind": "open", "summary": "",
            "detail": {"path": format!("/tmp/x{i}/.env"), "tier": "child"}, "pid": 79
        }}));
        assert_eq!(r["ok"], true);
    }
    let (rep, _) = wait_events(&mut d, Some("chat-a"), 2 * n + 3);
    let flags = rep["report"]["check"]["flags"].as_array().unwrap();
    assert!(
        rep["report"]["check"]["flagsOmitted"].as_u64().unwrap_or(0) > 0,
        "not cut"
    );
    let listed = |id: &str| flags.iter().any(|f| f["eventId"] == id);
    assert!(
        listed("real-write") && listed("real-open"),
        "real write listed: {}; real sensitive open listed: {}; {} flags kept",
        listed("real-write"),
        listed("real-open"),
        flags.len()
    );
}

/// R2, the chat token's part alone: adapter records naming new hosts, then
/// nothing else; the earlier write outside the folders is pushed out.
#[test]
fn r2b_a_chat_tokens_new_hosts_do_not_push_out_a_real_write() {
    let f = fixture();
    let (mut d, _) = Client::hello(&f, DAEMON_TOKEN);
    let r = d.ask(json!({"op": "event", "event": {
        "id": "real-write", "at": 0, "chatId": "chat-a", "harness": "pi",
        "source": "auditd", "kind": "write", "summary": "",
        "detail": {"path": "/home/t/.ssh/authorized_keys", "tier": "child"}, "pid": 78
    }}));
    assert_eq!(r["ok"], true, "{r}");
    let token = d.ask(json!({"op": "token.mint", "chat": "chat-a", "harness": "pi"}))["token"]
        .as_str()
        .unwrap()
        .to_string();
    let (mut agent, _) = Client::hello(&f, &token);
    let n = 3_000;
    let mut i = 0;
    while i < n {
        let r = agent.ask(json!({"op": "event", "event": {
            "id": format!("h-{i}"), "at": 0, "chatId": "chat-a", "harness": "pi",
            "source": "adapter", "kind": "tool.call", "summary": "",
            "detail": {"host": format!("h{i}.example.net")}
        }}));
        if r["ok"] == true {
            i += 1;
        } else {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    let (rep, _) = wait_events(&mut d, Some("chat-a"), n + 1);
    let check = &rep["report"]["check"];
    let flags = check["flags"].as_array().unwrap();
    let hosts = flags.iter().filter(|f| f["reason"] == "newHost").count();
    assert!(
        flags.iter().any(|f| f["eventId"] == "real-write"),
        "{} flags kept, {hosts} of them newHost from the chat token, {} omitted",
        flags.len(),
        check["flagsOmitted"]
    );
}

/// R2-2's control: the same flood, with a plain write to the guarded path
/// (in `path`) and the move into it (in `dest`): the write is kept, the
/// move is not.
#[test]
fn r2_2_a_move_into_the_guarded_folder_is_kept_like_a_write_there() {
    let f = fixture();
    let (mut d, _) = Client::hello(&f, DAEMON_TOKEN);
    let r = d.ask(json!({"op": "event", "event": {
        "id": "run-a", "at": 0, "chatId": "chat-a", "harness": "pi", "source": "run",
        "kind": "run.start", "summary": "pi",
        "detail": {"boundary": "none", "argv": ["pi"], "host": "box", "cwd": "/home/t/proj"}
    }}));
    assert_eq!(r["ok"], true);
    let mut post = |id: String, kind: &str, detail: Value| {
        let r = d.ask(json!({"op": "event", "event": {
            "id": id, "at": 0, "chatId": "chat-a", "harness": "pi",
            "source": "auditd", "kind": kind, "summary": "", "detail": detail, "pid": 77
        }}));
        assert_eq!(r["ok"], true, "{r}");
    };
    let long = "x".repeat(180);
    let n = 3_000;
    for i in 0..n {
        post(
            format!("w1-{i}"),
            "write",
            json!({"path": format!("/home/t/out/{long}-a{i}.txt"), "tier": "child"}),
        );
    }
    let guarded = f.root.join("data/activity/2026-11-06.jsonl");
    let g = guarded.to_string_lossy().to_string();
    post(
        "real-write".into(),
        "write",
        json!({"path": g, "tier": "child"}),
    );
    post(
        "real-move".into(),
        "rename",
        json!({"path": "/home/t/proj/forged.jsonl", "dest": g, "tier": "child"}),
    );
    for i in 0..n {
        post(
            format!("w2-{i}"),
            "write",
            json!({"path": format!("/home/t/out/{long}-b{i}.txt"), "tier": "child"}),
        );
    }
    let (rep, _) = wait_events(&mut d, Some("chat-a"), 2 * n + 3);
    let check = &rep["report"]["check"];
    let flags = check["flags"].as_array().unwrap();
    let listed = |id: &str| flags.iter().any(|f| f["eventId"] == id);
    let all = d.ask(json!({"op": "report", "chat": "chat-a", "since": 0, "until": 1}));
    let _ = all;
    assert!(
        listed("real-write") && listed("real-move"),
        "write to the guarded path listed: {}; move into it listed: {}; {} kept, {} omitted",
        listed("real-write"),
        listed("real-move"),
        flags.len(),
        check["flagsOmitted"]
    );
}

/// The second re-review's R2-1, the part this pass fixes: in the middle of
/// the agent's own flood of `.env` opens and writes outside its folders, a
/// move into derm's log folder (named in `dest`, R2-2) and a write to
/// `~/.ssh` (an always-listed path) are still listed. A real `.env` open in
/// the middle of the same flood is not promised (R2-1's rest, open).
#[test]
fn a_real_write_to_an_always_listed_path_in_a_flood_is_kept() {
    let f = fixture();
    let (mut d, _) = Client::hello(&f, DAEMON_TOKEN);
    let r = d.ask(json!({"op": "event", "event": {
        "id": "run-a", "at": 0, "chatId": "chat-a", "harness": "pi", "source": "run",
        "kind": "run.start", "summary": "pi",
        "detail": {"boundary": "none", "argv": ["pi"], "host": "box", "cwd": "/home/t/proj"}
    }}));
    assert_eq!(r["ok"], true);
    let mut post = |id: String, kind: &str, detail: Value| {
        let r = d.ask(json!({"op": "event", "event": {
            "id": id, "at": 0, "chatId": "chat-a", "harness": "pi",
            "source": "auditd", "kind": kind, "summary": "", "detail": detail, "pid": 77
        }}));
        assert_eq!(r["ok"], true, "{r}");
    };
    let long = "x".repeat(180);
    let n = 1_500;
    for i in 0..n {
        post(
            format!("o1-{i}"),
            "open",
            json!({"path": format!("/tmp/a{i}/.env"), "tier": "child"}),
        );
        post(
            format!("w1-{i}"),
            "write",
            json!({"path": format!("/home/t/out/{long}-a{i}.txt"), "tier": "child"}),
        );
    }
    let guarded = f.root.join("data/activity/2026-11-06.jsonl");
    post(
        "real-move".into(),
        "rename",
        json!({
            "path": "/home/t/proj/forged.jsonl",
            "dest": guarded.to_string_lossy(),
            "tier": "child"
        }),
    );
    post(
        "real-ssh".into(),
        "write",
        json!({"path": "/home/t/.ssh/authorized_keys", "tier": "child"}),
    );
    for i in 0..n {
        post(
            format!("o2-{i}"),
            "open",
            json!({"path": format!("/tmp/b{i}/.env"), "tier": "child"}),
        );
        post(
            format!("w2-{i}"),
            "write",
            json!({"path": format!("/home/t/out/{long}-b{i}.txt"), "tier": "child"}),
        );
    }
    let (rep, _) = wait_events(&mut d, Some("chat-a"), 4 * n + 3);
    let check = &rep["report"]["check"];
    let flags = check["flags"].as_array().unwrap();
    let listed = |id: &str| flags.iter().any(|f| f["eventId"] == id);
    assert!(check["flagsOmitted"].as_u64().unwrap_or(0) > 0, "not cut");
    assert!(
        listed("real-move"),
        "the move into derm's log folder is listed"
    );
    assert!(listed("real-ssh"), "the write to ~/.ssh is listed");
}
