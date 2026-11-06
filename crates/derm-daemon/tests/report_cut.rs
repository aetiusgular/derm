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
