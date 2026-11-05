//! The daemon over its socket, as clients use it (`contracts/daemon-protocol.md`).
//! Each test runs its own daemon on a temporary socket and log folder.
// The daemon over a Unix socket; its Windows twin is lane Z's
// `tests/windows/` (the named pipe).
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use derm_daemon::activity::store::ActivityLog;
use derm_daemon::daemon::{Daemon, MAX_PENDING_LINES};
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
        "tkd-{}-{}",
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
    fn connect(f: &Fixture) -> Client {
        let s = UnixStream::connect(&f.socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        Client {
            w: s.try_clone().unwrap(),
            r: BufReader::new(s),
        }
    }

    fn hello(f: &Fixture, token: &str) -> (Client, Value) {
        let mut c = Client::connect(f);
        let reply = c.ask(json!({"op": "hello", "token": token, "client": "test"}));
        (c, reply)
    }

    fn daemon(f: &Fixture) -> Client {
        let (c, reply) = Client::hello(f, DAEMON_TOKEN);
        assert_eq!(reply["scope"], "daemon", "{reply}");
        c
    }

    fn send(&mut self, v: Value) {
        writeln!(self.w, "{v}").unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        self.r.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"))
    }

    fn ask(&mut self, v: Value) -> Value {
        self.send(v);
        self.recv()
    }

    fn closed(&mut self) -> bool {
        let mut buf = [0u8; 1];
        matches!(self.r.read(&mut buf), Ok(0))
    }

    fn try_recv(&mut self, wait: Duration) -> Option<Value> {
        self.r.get_ref().set_read_timeout(Some(wait)).unwrap();
        let mut line = String::new();
        let got = self.r.read_line(&mut line);
        self.r
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        match got {
            Ok(n) if n > 0 => Some(serde_json::from_str(&line).unwrap()),
            _ => None,
        }
    }
}

fn mint(c: &mut Client, chat: &str, harness: &str) -> String {
    let r = c.ask(json!({"op": "token.mint", "chat": chat, "harness": harness}));
    assert_eq!(r["ok"], true, "{r}");
    r["token"].as_str().unwrap().to_string()
}

/// Marks `chat` as started by `derm run` under srt (lane V, S2 part b: a `yes`
/// for a chat with no `run.start`, or one that runs as you, needs the
/// person's password). The harness pid is a child that sleeps, so the test
/// process is not taken for a chat's harness. Kill the child when done.
fn started_under_srt(d: &mut Client, chat: &str) -> std::process::Child {
    let child = std::process::Command::new("sleep")
        .arg("120")
        .spawn()
        .unwrap();
    let r = d.ask(json!({"op": "event", "event": {
        "id": format!("run-start-{chat}"), "at": 0, "chatId": chat, "harness": "claude-code",
        "source": "run", "kind": "run.start", "summary": "",
        "detail": {"boundary": "srt", "cwd": "/tmp"}, "pid": child.id()
    }}));
    assert_eq!(r["ok"], true, "{r}");
    child
}

fn event(id: &str, chat: &str, source: &str, kind: &str, detail: Value) -> Value {
    json!({"op": "event", "event": {
        "id": id, "at": 0, "chatId": chat, "harness": "pi", "source": source,
        "kind": kind, "summary": id, "detail": detail
    }})
}

#[test]
fn a_first_line_that_is_not_hello_or_a_bad_token_closes() {
    let f = fixture();
    let mut c = Client::connect(&f);
    assert_eq!(c.ask(json!({"op": "tail"}))["error"], "hello first");
    assert!(c.closed());
    let mut c = Client::connect(&f);
    c.send(json!("not an object"));
    assert_eq!(c.recv()["error"], "hello first");
    assert!(c.closed());
    // Well formed, but no daemon or chat token.
    let (mut c, r) = Client::hello(&f, &"2".repeat(64));
    assert_eq!(r["error"], "bad token");
    assert!(c.closed());
    let (mut c, r) = Client::hello(&f, "short");
    assert_eq!(r["error"], "bad token");
    assert!(c.closed());
    let (mut c, r) = Client::hello(&f, &DAEMON_TOKEN.to_uppercase());
    assert_eq!(r["error"], "bad token", "tokens are lowercase hex");
    assert!(c.closed());
}

#[test]
fn the_daemon_token_gets_daemon_scope_and_a_minted_one_chat_scope() {
    let f = fixture();
    let (mut d, r) = Client::hello(&f, DAEMON_TOKEN);
    assert_eq!(r["ok"], true);
    assert_eq!(r["daemon"]["protocol"], 1);
    assert_eq!(r["daemon"]["pid"], std::process::id());
    assert_eq!(
        d.ask(json!({"op": "hello", "token": DAEMON_TOKEN, "client": "x"}))["error"],
        "hello once"
    );
    let token = mint(&mut d, "chat-b", "pi");
    assert!(derm_core::token::well_formed(&token));
    assert_ne!(mint(&mut d, "chat-b", "pi"), token, "every mint is fresh");
    let (_c, r) = Client::hello(&f, &token);
    assert_eq!(r, json!({"ok": true, "scope": "chat", "chat": "chat-b"}));
    // Mint refuses what it cannot name.
    let r = d.ask(json!({"op": "token.mint", "chat": "chat b", "harness": "pi"}));
    assert_eq!(r["ok"], false);
    let r = d.ask(json!({"op": "token.mint", "chat": "c", "harness": "Pi"}));
    assert_eq!(r["error"], "unknown harness");
}

#[test]
fn a_chat_token_cannot_mint_report_or_approve_as_the_daemon() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-b", "codex");
    let (mut c, _) = Client::hello(&f, &token);
    assert_eq!(
        c.ask(json!({"op": "token.mint", "chat": "x", "harness": "pi"}))["error"],
        "token.mint needs daemon scope"
    );
    assert_eq!(
        c.ask(json!({"op": "report", "since": 0, "until": 1}))["error"],
        "report needs daemon scope"
    );
    assert_eq!(
        c.ask(json!({"op": "approver"}))["error"],
        "approver needs daemon scope"
    );
    assert_eq!(
        c.ask(json!({"op": "answer", "id": "a", "answer": "yes"}))["error"],
        "not an approver"
    );
    // The connection stays open after each refusal.
    assert_eq!(
        c.ask(json!({"op": "tail"}))["error"],
        "tail needs daemon scope or a chat filter"
    );
}

#[test]
fn bad_lines_are_answered_and_a_long_line_closes() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let r = d.ask(json!({"op": "shutdown"}));
    assert_eq!(r["ok"], false);
    assert!(r["error"].as_str().unwrap().starts_with("bad line"));
    let r = d.ask(json!({"op": "approver", "force": true}));
    assert_eq!(r["ok"], false, "unknown fields are refused, not ignored");
    writeln!(d.w, "{{not json").unwrap();
    assert_eq!(d.recv()["ok"], false);
    // Still serving.
    assert_eq!(d.ask(json!({"op": "approver"}))["ok"], true);
    let mut d = Client::daemon(&f);
    let long = format!(
        "{{\"op\":\"tail\",\"chat\":\"{}\"}}\n",
        "x".repeat(1024 * 1024)
    );
    d.w.write_all(long.as_bytes()).unwrap();
    assert_eq!(d.recv()["error"], "line too long");
    assert!(d.closed());
}

#[test]
fn a_chat_posts_only_into_its_own_chat_and_only_telemetry() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-b", "pi");
    let (mut c, _) = Client::hello(&f, &token);
    let r = c.ask(json!({"op": "event", "event": {
        "id": "pi-7", "at": 42, "chatId": "someone-else", "harness": "claude-code",
        "source": "adapter", "kind": "tool.call", "summary": "exa/search ok",
        "detail": {"trust": "client"}
    }}));
    assert_eq!(r, json!({"ok": true, "id": "pi-7"}));
    for source in ["eslogger", "auditd", "cua", "run", "approval"] {
        let r = c.ask(event("x", "chat-b", source, "exec", json!({})));
        assert_eq!(r["ok"], false, "{source}");
    }
    let r = c.ask(event("", "chat-b", "adapter", "tool.call", json!({})));
    assert_eq!(r["error"], "event id is empty");
    // The daemon scope may post a kernel feed, never an approval record.
    assert_eq!(
        d.ask(event("a1", "chat-b", "auditd", "exec", json!({})))["ok"],
        true
    );
    assert_eq!(
        d.ask(event("a2", "chat-b", "approval", "approval", json!({})))["ok"],
        false
    );
    let (mut t, _) = Client::hello(&f, DAEMON_TOKEN);
    assert_eq!(
        t.ask(json!({"op": "tail", "since": 0, "chat": "chat-b"}))["ok"],
        true
    );
    let first = t.recv();
    let e = &first["event"];
    assert_eq!(e["id"], "pi-7");
    assert_eq!(e["chatId"], "chat-b", "overwritten from the token");
    assert_eq!(e["harness"], "pi", "overwritten from the token");
    assert_eq!(
        e["detail"]["harnessAt"], 42,
        "the client's time is kept apart"
    );
    assert!(
        e["at"].as_i64().unwrap() > 1_700_000_000_000,
        "stamped on receipt"
    );
}

#[test]
fn tail_streams_a_backlog_then_live_events_for_its_filter() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    d.ask(event("old-1", "chat-a", "adapter", "tool.call", json!({})));
    d.ask(event("old-2", "chat-b", "adapter", "tool.call", json!({})));
    let token = mint(&mut d, "chat-a", "pi");
    let (mut c, _) = Client::hello(&f, &token);
    assert_eq!(
        c.ask(json!({"op": "tail", "chat": "chat-b"}))["error"],
        "a chat token tails only its own chat"
    );
    assert_eq!(
        c.ask(json!({"op": "tail", "since": 0, "chat": "chat-a"}))["ok"],
        true
    );
    assert_eq!(c.recv()["event"]["id"], "old-1");
    d.ask(event("live-b", "chat-b", "adapter", "tool.call", json!({})));
    d.ask(event("live-a", "chat-a", "adapter", "tool.call", json!({})));
    assert_eq!(
        c.recv()["event"]["id"],
        "live-a",
        "chat-b's event never reaches chat-a"
    );
    // A daemon tail with no filter and no `since`: live only, every chat.
    let mut all = Client::daemon(&f);
    assert_eq!(all.ask(json!({"op": "tail"}))["ok"], true);
    assert!(
        all.try_recv(Duration::from_millis(200)).is_none(),
        "no backlog"
    );
    d.ask(event("live-c", "chat-c", "adapter", "tool.call", json!({})));
    assert_eq!(all.recv()["event"]["id"], "live-c");
}

#[test]
fn a_tail_backlog_holds_the_last_copy_per_id() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    d.ask(event(
        "call-1",
        "c1",
        "adapter",
        "tool.call",
        json!({"n": 1}),
    ));
    d.ask(event("call-1", "c1", "otel", "tool.call", json!({"n": 2})));
    // Another chat's record under the same id stays its own.
    d.ask(event(
        "call-1",
        "c2",
        "adapter",
        "tool.call",
        json!({"n": 3}),
    ));
    let mut t = Client::daemon(&f);
    t.ask(json!({"op": "tail", "since": 0}));
    let a = t.recv();
    let b = t.recv();
    assert!(t.try_recv(Duration::from_millis(200)).is_none());
    let mut got = vec![
        (
            a["event"]["chatId"].clone(),
            a["event"]["detail"]["n"].clone(),
        ),
        (
            b["event"]["chatId"].clone(),
            b["event"]["detail"]["n"].clone(),
        ),
    ];
    got.sort_by_key(|(c, _)| c.to_string());
    assert_eq!(got, vec![(json!("c1"), json!(2)), (json!("c2"), json!(3))]);
}

#[test]
fn a_chat_token_cannot_replace_a_gate_decision() {
    // Integration w1's security finding S9. The hook posts its decision
    // with the chat token; the agent holds the same token (case 66).
    // Integration w2's review (W2-S3): the agent can also post first, so a
    // second copy is never dropped. It is kept under its own id and the
    // daemon records a `gate.conflict` that names both.
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "c1", "claude-code");
    let (mut first, _) = Client::hello(&f, &token);
    let r = first.ask(event(
        "claude-code-t1-decision",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "allow"}),
    ));
    assert_eq!(r["ok"], true, "{r}");
    let (mut second, _) = Client::hello(&f, &token);
    for (source, kind, decision) in [
        ("adapter", "approval", "deny"),
        ("otel", "approval", "deny"),
        ("otel", "tool.call", "allow"),
    ] {
        let r = second.ask(event(
            "claude-code-t1-decision",
            "c1",
            source,
            kind,
            json!({"decision": decision}),
        ));
        assert_eq!(r["ok"], true, "{source} {kind}: {r}");
        let kept = r["id"].as_str().unwrap().to_string();
        assert!(
            kept.starts_with("claude-code-t1-decision-conflict-"),
            "{kept}"
        );
    }
    let mut t = Client::daemon(&f);
    t.ask(json!({"op": "tail", "since": 0}));
    let mut seen = Vec::new();
    while let Some(line) = t.try_recv(Duration::from_millis(300)) {
        seen.push(line["event"].clone());
    }
    let original: Vec<_> = seen
        .iter()
        .filter(|e| e["id"] == "claude-code-t1-decision")
        .collect();
    assert_eq!(original.len(), 1, "{seen:?}");
    assert_eq!(original[0]["detail"]["decision"], "allow");
    let copies: Vec<_> = seen
        .iter()
        .filter(|e| {
            e["id"]
                .as_str()
                .is_some_and(|i| i.starts_with("claude-code-t1-decision-conflict-"))
        })
        .collect();
    assert_eq!(copies.len(), 3, "{seen:?}");
    for c in &copies {
        assert_eq!(c["chatId"], "c1");
        assert_eq!(c["detail"]["conflictsWith"], "claude-code-t1-decision");
    }
    let flags: Vec<_> = seen
        .iter()
        .filter(|e| e["kind"] == "gate.conflict")
        .collect();
    assert_eq!(flags.len(), 3, "{seen:?}");
    for g in &flags {
        assert_eq!(g["source"], "approval", "the daemon writes it: {g}");
        assert_eq!(g["chatId"], "c1");
        assert_eq!(g["detail"]["id"], "claude-code-t1-decision");
    }
}

#[test]
fn a_second_decision_for_the_same_call_is_a_conflict_whatever_its_id() {
    // Fix pass 1's review, FP1-S4: with random decision ids (BW2) the agent
    // posts its forged decision under an id of its own, naming the call the
    // hook will decide (`detail.toolUseId`). Both are kept; the second is
    // stored as a conflict copy and the daemon flags it. Another call, or
    // another chat, is not a conflict.
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "c1", "opencode");
    let other = mint(&mut d, "c2", "opencode");
    let (mut agent, _) = Client::hello(&f, &token);
    let r = agent.ask(event(
        "forged-by-the-agent",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "allow", "toolUseId": "call_18"}),
    ));
    assert_eq!(r["id"], "forged-by-the-agent", "{r}");
    let (mut hook, _) = Client::hello(&f, &token);
    let real = "opencode-call_18-decision-0123456789abcdef0123456789abcdef";
    let r = hook.ask(event(
        real,
        "c1",
        "adapter",
        "approval",
        json!({"decision": "deny", "toolUseId": "call_18"}),
    ));
    let kept = r["id"].as_str().unwrap().to_string();
    assert!(kept.starts_with(&format!("{real}-conflict-")), "{r}");
    let r = hook.ask(event(
        "opencode-call_19-decision-0123456789abcdef0123456789abcdef",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "deny", "toolUseId": "call_19"}),
    ));
    assert_eq!(
        r["id"], "opencode-call_19-decision-0123456789abcdef0123456789abcdef",
        "{r}"
    );
    let (mut elsewhere, _) = Client::hello(&f, &other);
    let r = elsewhere.ask(event(
        "opencode-call_18-decision-ffffffffffffffffffffffffffffffff",
        "c2",
        "adapter",
        "approval",
        json!({"decision": "deny", "toolUseId": "call_18"}),
    ));
    assert_eq!(
        r["id"], "opencode-call_18-decision-ffffffffffffffffffffffffffffffff",
        "{r}"
    );
    let mut t = Client::daemon(&f);
    t.ask(json!({"op": "tail", "since": 0}));
    let mut seen = Vec::new();
    while let Some(line) = t.try_recv(Duration::from_millis(300)) {
        seen.push(line["event"].clone());
    }
    let flags: Vec<_> = seen
        .iter()
        .filter(|e| e["kind"] == "gate.conflict")
        .collect();
    assert_eq!(flags.len(), 1, "{seen:?}");
    assert_eq!(flags[0]["chatId"], "c1");
    assert_eq!(flags[0]["detail"]["id"], "forged-by-the-agent");
    assert_eq!(flags[0]["detail"]["posted"], real);
    let copy = seen.iter().find(|e| e["id"] == kept.as_str()).unwrap();
    assert_eq!(copy["detail"]["conflictsWith"], "forged-by-the-agent");
    assert!(seen.iter().any(|e| e["id"] == "forged-by-the-agent"));
}

#[test]
fn a_conflict_copy_of_a_long_id_keeps_its_own_id() {
    // Re-review W2-R2: a 128-character id's copy was cut back to the id.
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "c1", "claude-code");
    let (mut c, _) = Client::hello(&f, &token);
    let long = "a".repeat(128);
    let r = c.ask(event(
        &long,
        "c1",
        "adapter",
        "approval",
        json!({"decision": "deny"}),
    ));
    assert_eq!(r["id"], long.as_str(), "{r}");
    let mut ids = Vec::new();
    for _ in 0..2 {
        let r = c.ask(event(
            &long,
            "c1",
            "adapter",
            "approval",
            json!({"decision": "allow"}),
        ));
        let id = r["id"].as_str().unwrap().to_string();
        assert_ne!(id, long, "{r}");
        assert!(id.len() <= 128 && id.contains("-conflict-"), "{id}");
        ids.push(id);
    }
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn a_tail_that_falls_behind_is_dropped_and_ingest_never_waits() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let mut slow = Client::daemon(&f);
    assert_eq!(slow.ask(json!({"op": "tail"}))["ok"], true);
    // Never read `slow` again. Big events fill the socket buffer, then the
    // daemon's queue for it.
    let detail = json!({"pad": "x".repeat(8 * 1024)});
    let started = std::time::Instant::now();
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
        started.elapsed() < Duration::from_secs(20),
        "ingest did not wait on the slow tail"
    );
    assert!(
        f.daemon
            .counters
            .tails_dropped
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    // The daemon still answers.
    assert_eq!(d.ask(json!({"op": "approver"}))["ok"], true);
}

#[test]
fn approve_with_no_approver_is_no_at_once() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-b", "pi");
    let (mut c, _) = Client::hello(&f, &token);
    let started = std::time::Instant::now();
    let r = c.ask(json!({"op": "approve", "request": {
        "id": "ap-1", "chat": "chat-x", "harness": "pi", "tool": "cu/open_app",
        "summary": "Open Safari", "timeoutSeconds": 30
    }}));
    assert_eq!(
        r,
        json!({"ok": true, "id": "ap-1", "answer": "no", "by": "none"})
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn the_first_approver_answer_wins_and_the_outcome_is_recorded() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-b", "claude-code");
    let mut a1 = Client::daemon(&f);
    let mut a2 = Client::daemon(&f);
    assert_eq!(a1.ask(json!({"op": "approver"}))["ok"], true);
    assert_eq!(a2.ask(json!({"op": "approver"}))["ok"], true);
    let mut harness = started_under_srt(&mut d, "chat-b");
    let (mut c, _) = Client::hello(&f, &token);
    let mut t = Client::daemon(&f);
    t.ask(json!({"op": "tail", "chat": "chat-b"}));
    let asker = std::thread::spawn(move || {
        c.ask(json!({"op": "approve", "request": {
            "id": "ap-2", "chat": "ignored", "harness": "ignored",
            "tool": "github/create_issue", "summary": "Create issue", "timeoutSeconds": 30
        }}))
    });
    let p1 = a1.recv();
    let p2 = a2.recv();
    assert_eq!(p1, p2);
    assert_eq!(
        p1["approve"]["chat"], "chat-b",
        "the chat comes from the token"
    );
    assert_eq!(p1["approve"]["harness"], "claude-code");
    assert_eq!(
        a2.ask(json!({"op": "answer", "id": "ap-2", "answer": "yes"}))["ok"],
        true
    );
    let reply = asker.join().unwrap();
    assert_eq!(
        reply,
        json!({"ok": true, "id": "ap-2", "answer": "yes", "by": "approver"})
    );
    // The late answer is told the request is gone.
    assert_eq!(
        a1.ask(json!({"op": "answer", "id": "ap-2", "answer": "no"}))["ok"],
        false
    );
    let asked = t.recv();
    let answered = t.recv();
    assert_eq!(asked["event"]["source"], "approval");
    assert_eq!(
        asked["event"]["id"], answered["event"]["id"],
        "the outcome replaces the request"
    );
    assert_eq!(answered["event"]["detail"]["answer"], "yes");
    assert_eq!(answered["event"]["detail"]["by"], "approver");
    assert_eq!(answered["event"]["approvalId"], "ap-2");
    let _ = harness.kill();
    let _ = harness.wait();
}

#[test]
fn an_unanswered_approve_is_no_at_its_timeout() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let mut a = Client::daemon(&f);
    a.ask(json!({"op": "approver"}));
    let started = std::time::Instant::now();
    let r = d.ask(json!({"op": "approve", "request": {
        "id": "ap-3", "chat": "c", "harness": "pi", "tool": "bash",
        "summary": "rm", "timeoutSeconds": 1
    }}));
    assert_eq!(r["answer"], "no");
    assert_eq!(r["by"], "timeout");
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(a.recv()["approve"]["id"], "ap-3");
    // A timeout of 0 is held to 1 second, never "wait forever".
    let r = d.ask(json!({"op": "approve", "request": {
        "id": "ap-4", "chat": "c", "harness": "pi", "tool": "bash",
        "summary": "rm", "timeoutSeconds": 0
    }}));
    assert_eq!(r["by"], "timeout");
}

#[test]
fn an_approver_that_left_is_not_waited_on() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let mut a = Client::daemon(&f);
    a.ask(json!({"op": "approver"}));
    drop(a);
    std::thread::sleep(Duration::from_millis(200));
    let r = d.ask(json!({"op": "approve", "request": {
        "id": "ap-5", "chat": "c", "harness": "pi", "tool": "bash",
        "summary": "x", "timeoutSeconds": 30
    }}));
    assert_eq!(r["by"], "none");
}

#[test]
fn otlp_from_a_minted_pi_token_reaches_tail_as_a_tool_call() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-p", "pi");
    let mut t = Client::daemon(&f);
    t.ask(json!({"op": "tail", "chat": "chat-p"}));
    let body = json!({"resourceLogs": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "pi"}}]},
        "scopeLogs": [{"logRecords": [{
            "timeUnixNano": "5000000",
            "body": {"stringValue": "pi.tool_result"},
            "attributes": [
                {"key": "tool_name", "value": {"stringValue": "mcp__exa__search"}},
                {"key": "tool_use_id", "value": {"stringValue": "t1"}},
                {"key": "success", "value": {"stringValue": "true"}}
            ]
        }]}]
    }]})
    .to_string();
    let endpoint = f.daemon.endpoint();
    let port = endpoint.rsplit(':').next().unwrap();
    let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    write!(
        s,
        "POST /v1/logs HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nx-derm-token: {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut reply = String::new();
    s.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    let e = &t.recv()["event"];
    assert_eq!(e["source"], "otel");
    assert_eq!(
        e["kind"], "tool.call",
        "`pi.` is stripped like `claude_code.`"
    );
    assert_eq!(e["chatId"], "chat-p");
    assert_eq!(e["harness"], "pi");
    // The old header name is not a token header any more.
    let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    write!(
        s,
        "POST /v1/logs HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nx-monocode-token: {token}\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{{}}"
    )
    .unwrap();
    let mut reply = String::new();
    let _ = s.read_to_string(&mut reply);
    assert!(reply.starts_with("HTTP/1.1 401"), "{reply}");
}

#[test]
fn report_counts_and_flags_a_linux_write_outside_the_chat_folder() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let r = d.ask(json!({"op": "event", "event": {
        "id": "run-1", "at": 0, "chatId": "chat-r", "harness": "pi", "source": "run",
        "kind": "run.start", "summary": "pi",
        "detail": {"boundary": "none", "argv": ["pi"], "host": "box", "cwd": "/home/t/proj"}
    }}));
    assert_eq!(r["ok"], true);
    for (id, path) in [("w-in", "/home/t/proj/a.txt"), ("w-out", "/home/t/.bashrc")] {
        let r = d.ask(json!({"op": "event", "event": {
            "id": id, "at": 0, "chatId": "chat-r", "harness": "pi", "source": "auditd",
            "kind": "write", "summary": "", "detail": {"path": path, "tier": "child"}, "pid": 77
        }}));
        assert_eq!(r["ok"], true);
    }
    // The writer thread is asynchronous: wait for the log to hold all three.
    let mut report = Value::Null;
    for _ in 0..50 {
        report = d.ask(json!({"op": "report", "chat": "chat-r", "since": 0, "until": i64::MAX}))
            ["report"]
            .clone();
        if report["events"] == 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(report["events"], 3, "{report}");
    assert_eq!(report["bySource"], json!({"run": 1, "auditd": 2}));
    assert_eq!(report["flags"], 1, "{report}");
    assert_eq!(report["check"]["flags"][0]["eventId"], "w-out");
    assert_eq!(report["check"]["flags"][0]["reason"], "writeOutsideFolders");
    assert_eq!(report["chainOk"], true);
    assert_eq!(
        d.ask(json!({"op": "report", "since": 5, "until": 1}))["error"],
        "until is before since"
    );
}

#[test]
fn ids_the_daemon_makes_never_repeat_across_daemons() {
    // Case 35: a restarted daemon must not reuse an approval record's id.
    let mut ids = std::collections::HashSet::new();
    for _ in 0..2 {
        let f = fixture();
        let mut d = Client::daemon(&f);
        let mut t = Client::daemon(&f);
        t.ask(json!({"op": "tail"}));
        for n in 0..3 {
            d.ask(json!({"op": "approve", "request": {
                "id": format!("ap-{n}"), "chat": "c", "harness": "pi", "tool": "bash",
                "summary": "", "timeoutSeconds": 1
            }}));
            let id = t.recv()["event"]["id"].as_str().unwrap().to_string();
            t.recv();
            assert!(ids.insert(id), "an id repeated");
        }
    }
    assert_eq!(ids.len(), 6);
}

#[test]
fn retention_removes_logs_past_seven_days() {
    let f = fixture();
    let dir = f.root.join("data/activity");
    std::fs::create_dir_all(&dir).unwrap();
    let now = derm_daemon::activity::store::now_ms();
    let day = |ms: i64| {
        derm_daemon::activity::retention::day_name(derm_daemon::activity::retention::day_of_ms(ms))
    };
    let old = dir.join(format!("app-{}.jsonl", day(now - 9 * 86_400_000)));
    let recent = dir.join(format!("app-{}.jsonl", day(now - 2 * 86_400_000)));
    std::fs::write(&old, "").unwrap();
    std::fs::write(&recent, "").unwrap();
    assert!(f.daemon.retention_pass(now) >= 1);
    assert!(!old.exists());
    assert!(recent.exists());
}

#[test]
fn one_chat_cannot_hold_every_approval_slot_or_reuse_a_waiting_id() {
    use derm_daemon::daemon::MAX_PENDING_PER_CHAT;
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-z", "pi");
    let mut a = Client::daemon(&f);
    a.ask(json!({"op": "approver"}));
    let mut waiting = Vec::new();
    for n in 0..MAX_PENDING_PER_CHAT {
        let (mut c, _) = Client::hello(&f, &token);
        c.send(json!({"op": "approve", "request": {
            "id": format!("z-{n}"), "chat": "", "harness": "pi", "tool": "bash",
            "summary": "", "timeoutSeconds": 30
        }}));
        a.recv();
        waiting.push(c);
    }
    let (mut c, _) = Client::hello(&f, &token);
    let r = c.ask(json!({"op": "approve", "request": {
        "id": "z-extra", "chat": "", "harness": "pi", "tool": "bash",
        "summary": "", "timeoutSeconds": 30
    }}));
    assert_eq!(r["answer"], "no");
    assert_eq!(r["by"], "none", "refused at once, never a hang");
    // The same id while it waits, in the same chat: refused too.
    let (mut c, _) = Client::hello(&f, &token);
    let r = c.ask(json!({"op": "approve", "request": {
        "id": "z-0", "chat": "", "harness": "pi", "tool": "bash",
        "summary": "", "timeoutSeconds": 30
    }}));
    assert_eq!(r["by"], "none");
    // Another chat still gets through.
    let mut harness = started_under_srt(&mut d, "other");
    let asker = std::thread::spawn(move || {
        d.ask(json!({"op": "approve", "request": {
            "id": "o-1", "chat": "other", "harness": "pi", "tool": "bash",
            "summary": "", "timeoutSeconds": 30
        }}))
    });
    assert_eq!(a.recv()["approve"]["id"], "o-1");
    a.ask(json!({"op": "answer", "id": "o-1", "answer": "yes"}));
    assert_eq!(asker.join().unwrap()["answer"], "yes");
    for n in 0..MAX_PENDING_PER_CHAT {
        a.ask(json!({"op": "answer", "id": format!("z-{n}"), "answer": "no"}));
    }
    for mut c in waiting {
        assert_eq!(c.recv()["answer"], "no");
    }
    let _ = harness.kill();
    let _ = harness.wait();
}

/// Integration w1's security finding S8: pending approvals were keyed by the
/// client's id alone, so chat A waiting on an id made chat B's request under
/// the same id fail at once. They are keyed by (chat, id); an answer names
/// the chat when two chats wait on one id.
#[test]
fn two_chats_may_wait_on_the_same_request_id() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let ta = mint(&mut d, "chat-a", "claude-code");
    let tb = mint(&mut d, "chat-b", "claude-code");
    let mut approver = Client::daemon(&f);
    approver.ask(json!({"op": "approver"}));
    let mut harness = started_under_srt(&mut d, "chat-b");
    let ask = |token: String, f: &Fixture| {
        let (mut c, _) = Client::hello(f, &token);
        c.send(json!({"op": "approve", "request": {
            "id": "toolu_1", "chat": "", "harness": "claude-code", "tool": "bash",
            "summary": "", "timeoutSeconds": 30
        }}));
        c
    };
    let mut a = ask(ta, &f);
    let first = approver.recv();
    assert_eq!(first["approve"]["chat"], "chat-a", "{first}");
    let mut b = ask(tb, &f);
    let second = approver.recv();
    assert_eq!(second["approve"]["chat"], "chat-b", "{second}");
    assert_eq!(second["approve"]["id"], "toolu_1");
    // Without the chat the answer is ambiguous and goes nowhere.
    let r = approver.ask(json!({"op": "answer", "id": "toolu_1", "answer": "yes"}));
    assert_eq!(r["ok"], false, "{r}");
    let r =
        approver.ask(json!({"op": "answer", "id": "toolu_1", "chat": "chat-b", "answer": "yes"}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(b.recv()["answer"], "yes");
    assert!(
        a.try_recv(Duration::from_millis(200)).is_none(),
        "chat-a still waits"
    );
    // One left: the id alone is enough again.
    let r = approver.ask(json!({"op": "answer", "id": "toolu_1", "answer": "no"}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(a.recv()["answer"], "no");
    let _ = harness.kill();
    let _ = harness.wait();
}

/// Integration w1's security finding S2, part a (lane J's request 1a): an
/// approver whose process is a running chat's harness, or runs under one,
/// is the agent and is refused. Here the test process itself is named as a
/// chat's harness, so its own approver connection must be refused until the
/// run stops; both outcomes are recorded with the peer, and an answer
/// carries the approver's pid.
#[test]
fn an_approver_inside_a_running_chat_is_refused() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let me = std::process::id();
    let run = |kind: &str| {
        json!({"op": "event", "event": {
            "id": format!("run-{kind}"), "at": 0, "chatId": "chat-s2", "harness": "pi",
            "source": "run", "kind": kind, "summary": kind,
            "detail": {"boundary": "srt", "cwd": "/tmp"}, "pid": me
        }})
    };
    assert_eq!(d.ask(run("run.start"))["ok"], true);
    let mut a = Client::daemon(&f);
    let r = a.ask(json!({"op": "approver"}));
    assert_eq!(r["ok"], false, "{r}");
    let why = r["error"].as_str().unwrap();
    assert!(
        why.starts_with("approver refused: it runs inside chat chat-s2"),
        "{why}"
    );
    // An approve with no approver is no at once: the refused one is not one.
    let r = d.ask(json!({"op": "approve", "request": {
        "id": "s2-1", "chat": "chat-s2", "harness": "pi", "tool": "bash",
        "summary": "", "timeoutSeconds": 5
    }}));
    assert_eq!(
        (r["answer"].as_str(), r["by"].as_str()),
        (Some("no"), Some("none")),
        "{r}"
    );
    assert_eq!(d.ask(run("run.stop"))["ok"], true);
    let mut a = Client::daemon(&f);
    assert_eq!(a.ask(json!({"op": "approver"}))["ok"], true);
    // Started again under srt, after the approver registered, so a yes for
    // it needs no person check (lane V, S2 part b).
    let mut harness = started_under_srt(&mut d, "chat-s2");
    let asker = std::thread::spawn(move || {
        d.ask(json!({"op": "approve", "request": {
            "id": "s2-2", "chat": "chat-s2", "harness": "pi", "tool": "bash",
            "summary": "", "timeoutSeconds": 30
        }}))
    });
    assert_eq!(a.recv()["approve"]["id"], "s2-2");
    a.ask(json!({"op": "answer", "id": "s2-2", "answer": "yes"}));
    assert_eq!(asker.join().unwrap()["answer"], "yes");
    let mut t = Client::daemon(&f);
    t.ask(json!({"op": "tail", "since": 0}));
    let mut approver_events = Vec::new();
    let mut answered = None;
    while let Some(line) = t.try_recv(Duration::from_millis(300)) {
        let e = &line["event"];
        if e["kind"] == "approver" {
            approver_events.push(e.clone());
        }
        if e["kind"] == "approval" && e["detail"]["requestId"] == "s2-2" {
            answered = Some(e.clone());
        }
    }
    let accepted: Vec<bool> = approver_events
        .iter()
        .map(|e| e["detail"]["accepted"].as_bool().unwrap())
        .collect();
    assert_eq!(accepted, vec![false, true], "{approver_events:?}");
    for e in &approver_events {
        assert_eq!(e["detail"]["peer"]["pid"], me);
        assert!(e["detail"]["peer"]["program"].as_str().is_some(), "{e}");
    }
    let answered = answered.expect("the answered request's record");
    assert_eq!(answered["detail"]["approver"]["pid"], me, "{answered}");
    let _ = harness.kill();
    let _ = harness.wait();
}

/// Lane K's request 3 (integration w2): computer use's controls are a
/// daemon-scope op; a chat token, which is the agent's (case 66), may not
/// stop, read or revoke them. In this test no computer use runs, which the
/// daemon says.
#[test]
fn cu_is_daemon_scope_and_says_when_computer_use_is_not_running() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-cu", "claude-code");
    let (mut chat, _) = Client::hello(&f, &token);
    for line in [
        json!({"op": "cu", "action": "status"}),
        json!({"op": "cu", "action": "stop", "chat": "chat-cu"}),
        json!({"op": "cu", "action": "stop-all"}),
        json!({"op": "cu", "action": "revoke", "chat": "chat-cu", "app": "com.apple.calculator"}),
    ] {
        assert_eq!(
            chat.ask(line.clone())["error"],
            "cu needs daemon scope",
            "{line}"
        );
        let r = d.ask(line.clone());
        assert_eq!(r["ok"], false, "{line}: {r}");
        assert!(
            r["error"]
                .as_str()
                .unwrap()
                .starts_with("computer use is not"),
            "{line}: {r}"
        );
    }
    let r = d.ask(json!({"op": "cu", "action": "launch"}));
    assert_eq!(r["ok"], false, "{r}");
}

/// Integration w1, lane D's request 2: a chat token sits in the harness's
/// environment and, under sbx, in the sandbox's saved config. Once its run
/// stops, the token opens nothing: no new hello, no OTLP post. Only the
/// daemon scope (derm run) can stop a run; another chat's tokens stay valid.
#[test]
fn a_chat_token_is_revoked_when_its_run_stops() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let tok = mint(&mut d, "chat-r", "pi");
    let tok2 = mint(&mut d, "chat-r", "pi");
    let other = mint(&mut d, "chat-o", "pi");
    let r = d.ask(event(
        "run-1",
        "chat-r",
        "run",
        "run.start",
        json!({"cwd": "/w"}),
    ));
    assert_eq!(r["ok"], true, "{r}");
    let (mut c, r) = Client::hello(&f, &tok);
    assert_eq!(r["ok"], true, "{r}");
    let r = c.ask(event("run-2", "chat-r", "run", "run.stop", json!({})));
    assert_eq!(r["ok"], false, "a chat cannot stop its own run: {r}");
    assert_eq!(Client::hello(&f, &tok).1["ok"], true);
    let r = d.ask(event(
        "run-2",
        "chat-r",
        "run",
        "run.stop",
        json!({"exitCode": 0}),
    ));
    assert_eq!(r["ok"], true, "{r}");
    for t in [&tok, &tok2] {
        let (_c, r) = Client::hello(&f, t);
        assert_eq!(r["ok"], false, "revoked: {r}");
    }
    assert_eq!(
        Client::hello(&f, &other).1["ok"],
        true,
        "another chat's token stays"
    );
}

#[test]
fn a_deferred_record_before_the_decision_is_no_conflict() {
    // Mac test w4, MW4-10: Cursor's dialect records `deferred` from
    // preToolUse (an MCP call, which beforeMCPExecution decides) and then the
    // decision from beforeMCPExecution, both naming the call. A `deferred`
    // decides nothing, so the decision after it is not a second decision.
    // A decision after a decision is still a conflict, and so is a
    // `deferred` that comes after a decision (the honest order never does
    // that), and one under a decision's own id (S9).
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "c1", "cursor");
    let (mut hook, _) = Client::hello(&f, &token);
    let pre = "cursor-call_7-decision-00000000000000000000000000000001";
    let mcp = "cursor-call_7-decision-00000000000000000000000000000002";
    let r = hook.ask(event(
        pre,
        "c1",
        "adapter",
        "approval",
        json!({"decision": "deferred", "tool": "search", "toolUseId": "call_7"}),
    ));
    assert_eq!(r["id"], pre, "{r}");
    let r = hook.ask(event(
        mcp,
        "c1",
        "adapter",
        "approval",
        json!({"decision": "allow", "tool": "exa/search", "toolUseId": "call_7"}),
    ));
    assert_eq!(
        r["id"], mcp,
        "the decision after a deferred is kept as itself: {r}"
    );
    // A forged allow after the real decision: a conflict, as before.
    let r = hook.ask(event(
        "cursor-call_7-decision-00000000000000000000000000000003",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "allow", "toolUseId": "call_7"}),
    ));
    assert!(r["id"].as_str().unwrap().contains("-conflict-"), "{r}");
    // A deferred after a decision for another call: a conflict too.
    let r = hook.ask(event(
        "cursor-call_8-decision-00000000000000000000000000000001",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "deny", "toolUseId": "call_8"}),
    ));
    assert_eq!(
        r["id"],
        "cursor-call_8-decision-00000000000000000000000000000001"
    );
    let r = hook.ask(event(
        "cursor-call_8-decision-00000000000000000000000000000002",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "deferred", "toolUseId": "call_8"}),
    ));
    assert!(r["id"].as_str().unwrap().contains("-conflict-"), "{r}");
    // A second record under a deferred's own id is a conflict (S9).
    let r = hook.ask(event(
        pre,
        "c1",
        "adapter",
        "approval",
        json!({"decision": "allow", "toolUseId": "call_9"}),
    ));
    assert!(r["id"].as_str().unwrap().contains("-conflict-"), "{r}");
    // Fix pass 1's review, FP4-S4: the exemption is Cursor's honest pair
    // only. A second `deferred` for a call is a conflict; so is a decision
    // after a `deferred` that names another tool than `<server>/<the
    // deferred tool>`; and so is the pair in a chat that is not Cursor's.
    let r = hook.ask(event(
        "cursor-call_10-decision-00000000000000000000000000000001",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "deferred", "tool": "search", "toolUseId": "call_10"}),
    ));
    assert_eq!(
        r["id"],
        "cursor-call_10-decision-00000000000000000000000000000001"
    );
    let r = hook.ask(event(
        "cursor-call_10-decision-00000000000000000000000000000002",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "deferred", "tool": "search", "toolUseId": "call_10"}),
    ));
    assert!(
        r["id"].as_str().unwrap().contains("-conflict-"),
        "a second deferred: {r}"
    );
    let r = hook.ask(event(
        "cursor-call_11-decision-00000000000000000000000000000001",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "deferred", "tool": "search", "toolUseId": "call_11"}),
    ));
    assert_eq!(
        r["id"],
        "cursor-call_11-decision-00000000000000000000000000000001"
    );
    let r = hook.ask(event(
        "cursor-call_11-decision-00000000000000000000000000000002",
        "c1",
        "adapter",
        "approval",
        json!({"decision": "allow", "tool": "bash", "toolUseId": "call_11"}),
    ));
    assert!(
        r["id"].as_str().unwrap().contains("-conflict-"),
        "a decision for another tool: {r}"
    );
    let other = mint(&mut d, "c2", "claude-code");
    let (mut other_hook, _) = Client::hello(&f, &other);
    let r = other_hook.ask(event(
        "claude-code-call_12-decision-00000000000000000000000000000001",
        "c2",
        "adapter",
        "approval",
        json!({"decision": "deferred", "tool": "search", "toolUseId": "call_12"}),
    ));
    assert_eq!(
        r["id"],
        "claude-code-call_12-decision-00000000000000000000000000000001"
    );
    let r = other_hook.ask(event(
        "claude-code-call_12-decision-00000000000000000000000000000002",
        "c2",
        "adapter",
        "approval",
        json!({"decision": "allow", "tool": "exa/search", "toolUseId": "call_12"}),
    ));
    assert!(
        r["id"].as_str().unwrap().contains("-conflict-"),
        "the pair in a chat that is not Cursor's: {r}"
    );
    let mut t = Client::daemon(&f);
    t.ask(json!({"op": "tail", "since": 0}));
    let mut flags = 0;
    while let Some(line) = t.try_recv(Duration::from_millis(300)) {
        if line["event"]["kind"] == "gate.conflict" {
            flags += 1;
        }
    }
    assert_eq!(flags, 6, "six conflicts, none for the honest pair");
}

/// The wave 5 base: `tap` and `derm` records are the daemon's own
/// (`contracts/events.md` section 5). No socket client posts one, with a
/// chat token or the daemon's.
#[test]
fn no_socket_client_posts_a_tap_or_derm_record() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-w5", "pi");
    let (mut c, _) = Client::hello(&f, &token);
    for source in ["tap", "derm"] {
        let r = c.ask(event("w5-c", "chat-w5", source, "tap.call", json!({})));
        assert_eq!(r["ok"], false, "chat scope, {source}: {r}");
        let r = d.ask(event("w5-d", "chat-w5", source, "tap.call", json!({})));
        assert_eq!(r["ok"], false, "daemon scope, {source}: {r}");
        assert_eq!(r["error"], "tap and derm events are written by the daemon");
    }
}

/// Lane U's request R1: a `cu.action` record is the daemon's own
/// (`trust: daemon`, `contracts/wave5-records.schema.json`). No socket
/// client posts one, under any source, with a chat token or the daemon's:
/// a daemon-scope client may post `source: cua` (the collector's path),
/// and an adapter record with that kind would pass a chat's source check.
#[test]
fn no_socket_client_posts_a_cu_action_record() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-cu", "claude-code");
    let (mut c, _) = Client::hello(&f, &token);
    for source in ["cua", "adapter", "otel"] {
        let r = c.ask(event("cu-c", "chat-cu", source, "cu.action", json!({})));
        assert_eq!(r["ok"], false, "chat scope, {source}: {r}");
    }
    for source in ["cua", "adapter", "eslogger"] {
        let r = d.ask(event("cu-d", "chat-cu", source, "cu.action", json!({})));
        assert_eq!(r["ok"], false, "daemon scope, {source}: {r}");
        assert_eq!(r["error"], "cu.action events are written by the daemon");
    }
}

/// S2 part b (wave 5 lane V): a `yes` for a chat that runs as you with no
/// boundary needs your password in `proof`; without one, or with a wrong
/// one, it is refused and the request keeps waiting; a `no` needs nothing.
/// The password is never in a record.
#[test]
fn a_yes_for_a_chat_that_runs_as_you_needs_the_persons_password() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let mut a = Client::daemon(&f);
    assert_eq!(a.ask(json!({"op": "approver"}))["ok"], true);
    let mut sleeper = std::process::Command::new("sleep")
        .arg("120")
        .spawn()
        .unwrap();
    let r = d.ask(json!({"op": "event", "event": {
        "id": "run-start-you", "at": 0, "chatId": "chat-you", "harness": "pi",
        "source": "run", "kind": "run.start", "summary": "",
        "detail": {"boundary": "none", "cwd": "/tmp"}, "pid": sleeper.id()
    }}));
    assert_eq!(r["ok"], true, "{r}");
    let asker = std::thread::spawn(move || {
        d.ask(json!({"op": "approve", "request": {
            "id": "pb-1", "chat": "chat-you", "harness": "pi", "tool": "bash",
            "summary": "", "timeoutSeconds": 30
        }}))
    });
    assert_eq!(a.recv()["approve"]["id"], "pb-1");
    let r = a.ask(json!({"op": "answer", "id": "pb-1", "answer": "yes"}));
    assert_eq!(r["ok"], false, "{r}");
    let why = r["error"].as_str().unwrap_or("");
    assert!(
        why.contains("password is needed") && why.contains("runs as you"),
        "{why}"
    );
    let r = a.ask(json!({"op": "answer", "id": "pb-1", "answer": "yes",
        "proof": {"password": "derm-lane-v-wrong-password"}}));
    assert_eq!(r["ok"], false, "{r}");
    let r = a.ask(json!({"op": "answer", "id": "pb-1", "answer": "no"}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(asker.join().unwrap()["answer"], "no");
    let mut t = Client::daemon(&f);
    t.ask(json!({"op": "tail", "since": 0}));
    let mut lines = Vec::new();
    while let Some(line) = t.try_recv(Duration::from_millis(300)) {
        lines.push(line);
    }
    let all = serde_json::to_string(&lines).unwrap();
    assert!(
        !all.contains("derm-lane-v-wrong-password"),
        "no password in any record"
    );
    let checks = lines
        .iter()
        .filter(|l| l["event"]["kind"] == "person.check")
        .count();
    assert_eq!(checks, 2, "both refused yeses are recorded");
    let _ = sleeper.kill();
    let _ = sleeper.wait();
}

/// One request to the receiver's HTTP port; the status and the body.
fn http(port: &str, path: &str, host: &str, token: Option<&str>, body: &str) -> (u16, String) {
    let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let auth = token.map_or(String::new(), |t| format!("x-derm-token: {t}\r\n"));
    write!(
        s,
        "POST {path} HTTP/1.1\r\nhost: {host}\r\n{auth}content-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut reply = String::new();
    let _ = s.read_to_string(&mut reply);
    let status = reply.get(9..12).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = reply.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

/// Lane T's P4-R1 (integration w5, continue): a chat's `event` over the
/// receiver's HTTP port, for a gate inside an sbx VM, under the socket's
/// chat-scope rules (`daemon-protocol.md`, rule 2).
#[test]
fn a_chat_posts_events_over_http_with_the_sockets_chat_rules() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-h", "claude-code");
    let mut t = Client::daemon(&f);
    t.ask(json!({"op": "tail", "chat": "chat-h"}));
    let endpoint = f.daemon.endpoint();
    let port = endpoint.rsplit(':').next().unwrap().to_string();
    let local = format!("127.0.0.1:{port}");
    let vm = format!("host.docker.internal:{port}");
    let post = |id: &str, source: &str, kind: &str| {
        json!({"event": event(id, "chat-other", source, kind, json!({"toolUseId": "t1"}))["event"]})
            .to_string()
    };
    // An adapter record, from loopback and with sbx's host name: stored in
    // the token's chat and harness, whatever the record says.
    for (id, host) in [("h-1", &local), ("h-2", &vm)] {
        let (status, body) = http(
            &port,
            "/derm/v1/event",
            host,
            Some(&token),
            &post(id, "adapter", "tool.call"),
        );
        assert_eq!(status, 200, "{body}");
        let reply: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(reply["ok"], true, "{body}");
        let e = &t.recv()["event"];
        assert_eq!(e["id"], id);
        assert_eq!(e["chatId"], "chat-h");
        assert_eq!(e["harness"], "claude-code");
    }
    // What a chat token may not post on the socket, it may not post here.
    for (source, kind) in [
        ("run", "run.start"),
        ("approval", "approval"),
        ("auditd", "write"),
        ("derm", "install.lockdiff"),
    ] {
        let (status, body) = http(
            &port,
            "/derm/v1/event",
            &local,
            Some(&token),
            &post("h-x", source, kind),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["ok"],
            false,
            "{source}: {body}"
        );
    }
    // No token, the daemon's own token, a stranger's host, the OTLP route
    // with sbx's host name, a second field, a bad body: refused before the
    // daemon sees anything.
    assert_eq!(
        http(
            &port,
            "/derm/v1/event",
            &local,
            None,
            &post("h-3", "adapter", "tool.call")
        )
        .0,
        401
    );
    assert_eq!(
        http(
            &port,
            "/derm/v1/event",
            &local,
            Some(DAEMON_TOKEN),
            &post("h-3", "adapter", "tool.call")
        )
        .0,
        401
    );
    assert_eq!(
        http(
            &port,
            "/derm/v1/event",
            &format!("evil.example:{port}"),
            Some(&token),
            &post("h-3", "adapter", "tool.call")
        )
        .0,
        403
    );
    assert_eq!(http(&port, "/v1/logs", &vm, Some(&token), "{}").0, 403);
    let two = json!({"event": event("h-3", "c", "adapter", "tool.call", json!({}))["event"], "request": {}}).to_string();
    assert_eq!(
        http(&port, "/derm/v1/event", &local, Some(&token), &two).0,
        400
    );
    assert_eq!(
        http(&port, "/derm/v1/event", &local, Some(&token), "[1]").0,
        400
    );
    assert_eq!(
        http(&port, "/derm/v1/nothing", &local, Some(&token), "{}").0,
        404
    );
    // An event the socket answers one way is answered the same way here.
    let mut extra = event("h-4", "c", "adapter", "tool.call", json!({}));
    extra["event"]["stranger"] = json!(1);
    let (mut c, _) = Client::hello(&f, &token);
    let on_socket = c.ask(extra.clone())["ok"].clone();
    extra["event"]["id"] = json!("h-4b");
    let (_, body) = http(
        &port,
        "/derm/v1/event",
        &local,
        Some(&token),
        &json!({"event": extra["event"]}).to_string(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["ok"],
        on_socket,
        "{body}"
    );
    // After the run stops, the token opens nothing here either.
    assert_eq!(
        d.ask(event("run-stop-h", "chat-h", "run", "run.stop", json!({})))["ok"],
        true
    );
    assert_eq!(
        http(
            &port,
            "/derm/v1/event",
            &local,
            Some(&token),
            &post("h-5", "adapter", "tool.call")
        )
        .0,
        401
    );
}

/// P4-R1's `approve`: the same request path as the socket's, so with no
/// approver it is `no` at once, and an approver's answer comes back in the
/// reply body; the chat and harness come from the token.
#[test]
fn a_chat_asks_over_http_and_gets_the_approvers_answer() {
    let f = fixture();
    let mut d = Client::daemon(&f);
    let token = mint(&mut d, "chat-ha", "claude-code");
    let endpoint = f.daemon.endpoint();
    let port = endpoint.rsplit(':').next().unwrap().to_string();
    let local = format!("127.0.0.1:{port}");
    let request = |id: &str| {
        json!({"request": {"id": id, "chat": "ignored", "harness": "ignored", "tool": "bash", "summary": "npm i x", "timeoutSeconds": 30}}).to_string()
    };
    let (status, body) = http(
        &port,
        "/derm/v1/approve",
        &local,
        Some(&token),
        &request("ap-h1"),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"ok": true, "id": "ap-h1", "answer": "no", "by": "none"})
    );
    let mut a = Client::daemon(&f);
    assert_eq!(a.ask(json!({"op": "approver"}))["ok"], true);
    let mut harness = started_under_srt(&mut d, "chat-ha");
    let (p, t) = (port.clone(), token.clone());
    let asker = std::thread::spawn(move || {
        http(
            &p,
            "/derm/v1/approve",
            &format!("host.docker.internal:{p}"),
            Some(&t),
            &request("ap-h2"),
        )
    });
    let asked = a.recv();
    assert_eq!(asked["approve"]["chat"], "chat-ha");
    assert_eq!(asked["approve"]["harness"], "claude-code");
    assert_eq!(
        a.ask(json!({"op": "answer", "id": "ap-h2", "answer": "no"}))["ok"],
        true
    );
    let (status, body) = asker.join().unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"ok": true, "id": "ap-h2", "answer": "no", "by": "approver"})
    );
    let _ = harness.kill();
    let _ = harness.wait();
}
