//! Box test w5 retest 2, BW5R2-5: `derm-audit-feed` stopped with the
//! daemon's unit and did not come back with it, and `derm watch report` said
//! only "os collector: unknown" while a chat's install ran with no OS
//! record. The report now says whether the Linux feed is attached, and
//! when it went. Linux only: elsewhere `osFeed` is null.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use derm_daemon::activity::store::ActivityLog;
use derm_daemon::daemon::{Daemon, AUDIT_FEED_TAIL, MAX_PENDING_LINES};
use serde_json::{json, Value};

const DAEMON_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    daemon: Arc<Daemon>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture() -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "tkf-{}-{}",
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
        daemon,
    }
}

struct Client {
    w: UnixStream,
    r: BufReader<UnixStream>,
}

impl Client {
    fn hello(f: &Fixture, token: &str, client: &str) -> Client {
        let s = UnixStream::connect(&f.socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut c = Client {
            w: s.try_clone().unwrap(),
            r: BufReader::new(s),
        };
        let reply = c.ask(json!({"op": "hello", "token": token, "client": client}));
        assert_eq!(reply["ok"], true, "{reply}");
        c
    }

    fn ask(&mut self, v: Value) -> Value {
        writeln!(self.w, "{v}").unwrap();
        let mut line = String::new();
        self.r.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

fn feed(f: &Fixture) -> Value {
    let mut d = Client::hello(f, DAEMON_TOKEN, "derm watch report");
    d.ask(json!({"op": "report", "since": 0, "until": i64::MAX}))["report"]["osFeed"].clone()
}

/// The state moves only after the daemon has seen the connection close.
fn wait_for(f: &Fixture, state: &str) -> Value {
    let mut last = Value::Null;
    for _ in 0..100 {
        last = feed(f);
        if last["state"] == state {
            return last;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("osFeed never became {state}: {last}");
}

#[test]
fn bw5r2_5_the_report_says_whether_the_linux_feed_is_attached() {
    let f = fixture();
    // None since the daemon started.
    assert_eq!(feed(&f), json!({"state": "none"}));
    // A chat token that names itself the feed does not count.
    let mut d = Client::hello(&f, DAEMON_TOKEN, "test");
    let minted = d.ask(json!({"op": "token.mint", "chat": "c1", "harness": "pi"}));
    let chat_token = minted["token"].as_str().unwrap().to_string();
    let fake = Client::hello(&f, &chat_token, AUDIT_FEED_TAIL);
    assert_eq!(feed(&f), json!({"state": "none"}));
    drop(fake);
    // The feed's own tail, with the daemon's token: attached.
    let mut tail = Client::hello(&f, DAEMON_TOKEN, AUDIT_FEED_TAIL);
    assert_eq!(tail.ask(json!({"op": "tail"}))["ok"], true);
    wait_for(&f, "attached");
    // Its poster, under the feed's other name, changes nothing.
    let poster = Client::hello(&f, DAEMON_TOKEN, "derm-audit-feed");
    drop(poster);
    assert_eq!(feed(&f)["state"], "attached");
    // The feed goes: stopped, with when.
    drop(tail);
    let stopped = wait_for(&f, "stopped");
    assert!(stopped["since"].as_i64().unwrap_or(0) > 0, "{stopped}");
    // And back.
    // And back, once its tail is live again (FP10-S2).
    let mut again = Client::hello(&f, DAEMON_TOKEN, AUDIT_FEED_TAIL);
    assert_eq!(
        feed(&f)["state"],
        "stopped",
        "a hello alone is not attached"
    );
    assert_eq!(again.ask(json!({"op": "tail"}))["ok"], true);
    wait_for(&f, "attached");
}

/// Fix pass 10's review, FP10-S2 (both probes failed on `12ec6eb`): a hello
/// with no tail, and a tail the daemon dropped for falling behind, deliver
/// no `run.start`, so neither is an attached feed.
#[test]
fn fp10_s2_a_hello_without_a_tail_is_not_an_attached_feed() {
    let f = fixture();
    let _idle = Client::hello(&f, DAEMON_TOKEN, AUDIT_FEED_TAIL);
    std::thread::sleep(Duration::from_millis(100));
    assert_ne!(feed(&f)["state"], "attached", "no tail is streaming");
}

#[test]
fn fp10_s2_a_dropped_feed_tail_is_not_attached() {
    let f = fixture();
    let mut tail = Client::hello(&f, DAEMON_TOKEN, AUDIT_FEED_TAIL);
    assert_eq!(tail.ask(json!({"op": "tail"}))["ok"], true);
    wait_for(&f, "attached");
    // The feed's tail is never read, so the daemon drops it.
    let detail = json!({"pad": "x".repeat(8 * 1024)});
    for i in 0..(MAX_PENDING_LINES + 400) {
        f.daemon.ingest(
            serde_json::from_value(json!({
                "id": format!("e{i}"), "at": 0, "chatId": "c", "harness": "pi",
                "source": "adapter", "kind": "tool.call", "summary": "", "detail": detail
            }))
            .unwrap(),
        );
    }
    assert!(
        f.daemon
            .counters
            .tails_dropped
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    let stopped = feed(&f);
    assert_eq!(
        stopped["state"], "stopped",
        "the feed's tail was dropped: {stopped}"
    );
    drop(tail);
}
