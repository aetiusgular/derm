//! Step P's red tests over the daemon's socket (the base, 20 Nov 2026;
//! `plans/parallel_build_accounts.md` section 8.3, item 7;
//! `contracts/daemon-protocol.md` section 6, `contracts/events.md` section 7,
//! `contracts/project-tools.md`). Lane PE's and the base's own record test,
//! and lane PC's `project.control`. No lane edits this file; P integration
//! drops each `ignore` once its lane is green. The guards that already hold
//! run now.
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
const PROJECT_A: &str = "aaaaaaaaaaaaaaaa";
const PROJECT_B: &str = "bbbbbbbbbbbbbbbb";

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
        "tkdp-{}-{}",
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
    fn hello(f: &Fixture, token: &str) -> Client {
        let s = UnixStream::connect(&f.socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut c = Client {
            w: s.try_clone().unwrap(),
            r: BufReader::new(s),
        };
        let r = c.ask(json!({"op": "hello", "token": token, "client": "acctp"}));
        assert_eq!(r["ok"], true, "{r}");
        c
    }

    fn ask(&mut self, v: Value) -> Value {
        writeln!(self.w, "{v}").unwrap();
        self.recv(Duration::from_secs(10)).unwrap_or(Value::Null)
    }

    fn recv(&mut self, wait: Duration) -> Option<Value> {
        self.r.get_ref().set_read_timeout(Some(wait)).unwrap();
        let mut line = String::new();
        match self.r.read_line(&mut line) {
            Ok(n) if n > 0 => serde_json::from_str(&line).ok(),
            _ => None,
        }
    }
}

fn mint(d: &mut Client, chat: &str, project: &str) -> String {
    let r =
        d.ask(json!({"op": "token.mint", "chat": chat, "harness": "codex", "project": project}));
    assert_eq!(r["ok"], true, "{r}");
    r["token"].as_str().unwrap().to_string()
}

fn stored(f: &Fixture, chat: &str, id: &str) -> Value {
    let mut t = Client::hello(f, DAEMON_TOKEN);
    assert_eq!(
        t.ask(json!({"op": "tail", "since": 0, "chat": chat}))["ok"],
        true
    );
    while let Some(line) = t.recv(Duration::from_secs(2)) {
        if line["event"]["id"] == id {
            return line["event"].clone();
        }
    }
    panic!("event {id} not stored for {chat}");
}

/// Guards that hold on the base (contracts/daemon-protocol.md 6.1): a
/// `token.mint` project is 16 lowercase hex or empty, and step P's op lines
/// refuse unknown fields like every op.
#[test]
fn a_mint_project_and_step_ps_op_lines_are_checked_on_the_base() {
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    for bad in ["A", "../x", "AAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaa"] {
        let r =
            d.ask(json!({"op": "token.mint", "chat": "c-x", "harness": "codex", "project": bad}));
        assert_eq!(r["ok"], false, "{bad}: {r}");
    }
    assert_eq!(mint(&mut d, "c-empty", "").len(), 64);
    let token = mint(&mut d, "c-a", PROJECT_A);
    let mut a = Client::hello(&f, &token);
    let r = a.ask(json!({"op": "msg.send", "to": "c-b", "text": "x", "from": "c-z"}));
    assert_eq!(r["ok"], false, "an unknown field is refused: {r}");
    let r = a.ask(
        json!({"op": "screen.put", "chat": "c-a", "rows": 1, "cols": 1,
        "text": "", "scrollbackLines": 0, "at": 0, "extra": 1}),
    );
    assert_eq!(r["ok"], false, "{r}");
}

/// Contracts/events.md 7.1 (Tony's C2 call, 20 Nov 2026): the daemon sets
/// every event's `project` from the chat its token names, over the client's
/// value, and counts each event whose value differed (`report`'s
/// `projectOverwritten`). Red on the base: the daemon keeps no
/// chat-to-project map, so the stored project is `""`, and nothing counts.
#[test]
fn base_a_chats_event_carries_the_daemons_project_not_the_clients() {
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    let token = mint(&mut d, "c-a", PROJECT_A);
    let mut a = Client::hello(&f, &token);
    let r = a.ask(json!({"op": "event", "event": {
        "id": "codex-p1", "at": 1, "chatId": "c-a", "harness": "codex", "source": "adapter",
        "kind": "tool.call", "summary": "x", "detail": {"trust": "client"}, "project": PROJECT_B
    }}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(stored(&f, "c-a", "codex-p1")["project"], PROJECT_A);
    let report = d.ask(json!({"op": "report", "since": 0, "until": i64::MAX}));
    assert_eq!(report["report"]["projectOverwritten"], 1, "{report}");
}

/// P6 and P7 (contracts/project-tools.md sections 1 and 2): a message
/// between two chats of one project is delivered and taken once, marked as
/// from an agent; one to a chat of another project asks the person first.
/// Red on the base: `msg.send` and `msg.take` answer `not built`.
#[test]
fn pe_a_message_reaches_its_own_project_and_asks_across_projects() {
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    let a1 = mint(&mut d, "c-a1", PROJECT_A);
    let a2 = mint(&mut d, "c-a2", PROJECT_A);
    let _b = mint(&mut d, "c-b", PROJECT_B);
    let mut c1 = Client::hello(&f, &a1);
    let mut c2 = Client::hello(&f, &a2);
    let r = c1.ask(json!({"op": "msg.send", "to": "c-a2", "text": "build is green"}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["result"]["delivered"], json!(["c-a2"]), "{r}");
    let t = c2.ask(json!({"op": "msg.take"}));
    let m = &t["result"]["messages"][0];
    assert_eq!(m["from"]["chat"], "c-a1", "{t}");
    assert_eq!(m["from"]["agent"], true, "{t}");
    assert_eq!(m["text"], "build is green", "{t}");
    assert_eq!(
        c2.ask(json!({"op": "msg.take"}))["result"]["messages"],
        json!([])
    );
    // Across projects: an approver sees the ask; a no delivers nothing.
    let mut approver = Client::hello(&f, DAEMON_TOKEN);
    assert_eq!(approver.ask(json!({"op": "approver"}))["ok"], true);
    writeln!(
        c1.w,
        "{}",
        json!({"op": "msg.send", "to": "c-b", "text": "hi"})
    )
    .unwrap();
    let push = approver
        .recv(Duration::from_secs(5))
        .expect("the approver is asked");
    assert_eq!(
        push["approve"]["tool"], "derm_project/derm_message",
        "{push}"
    );
    let id = push["approve"]["id"].clone();
    approver.ask(json!({"op": "answer", "id": id, "answer": "no", "chat": "c-a1"}));
    let r = c1.recv(Duration::from_secs(5)).unwrap();
    assert_eq!(r["result"]["delivered"], json!([]), "{r}");
    assert_eq!(r["result"]["asked"], json!(["c-b"]), "{r}");
}

/// P5's daemon half (contracts/project-tools.md section 3): `derm run`'s
/// `screen.put` is read by a chat of the same project, cleaned again, and
/// refused to a chat token. Red on the base: `screen.put` is not built.
#[test]
fn pe_a_screen_is_read_by_its_own_project_only() {
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    let a1 = mint(&mut d, "c-a1", PROJECT_A);
    let a2 = mint(&mut d, "c-a2", PROJECT_A);
    let r = d.ask(
        json!({"op": "screen.put", "chat": "c-a1", "rows": 2, "cols": 20,
        "text": "$ cargo test\nok\u{202e}", "scrollbackLines": 0, "at": 1}),
    );
    assert_eq!(r["ok"], true, "{r}");
    let mut c1 = Client::hello(&f, &a1);
    let r = c1.ask(
        json!({"op": "screen.put", "chat": "c-a1", "rows": 1, "cols": 1,
        "text": "forged", "scrollbackLines": 0, "at": 2}),
    );
    assert_eq!(r["ok"], false, "a chat token puts no screen: {r}");
    let mut c2 = Client::hello(&f, &a2);
    let r = c2.ask(json!({"op": "screen.read", "chat": "c-a1"}));
    assert_eq!(r["result"]["text"], "$ cargo test\nok", "{r}");
}

/// P4 (contracts/events.md 7.2, note CD section 5 and C4): a write to a
/// run-later path inside a project home is named, including the three paths
/// `control_path` misses; an ordinary file is not. Red on the base:
/// `project_control` names nothing.
#[test]
fn pc_a_write_to_a_project_homes_run_later_files_is_flagged() {
    use derm_daemon::installs::project::project_control;
    let home = "/var/lib/derm/agents/max/projects/aaaaaaaaaaaaaaaa/home";
    for rel in [
        ".claude/settings.json",
        ".claude.json",
        ".codex/config.toml",
        ".pi/agent/settings.json",
        ".agents/skills/x/SKILL.md",
        ".cache/codex-runtimes/codex-primary-runtime/plugins/p/x",
        ".local/bin/claude",
        ".bashrc",
    ] {
        let path = format!("{home}/{rel}");
        assert!(
            project_control(&path, home).is_some(),
            "{rel} is not flagged"
        );
    }
    assert!(project_control(&format!("{home}/notes.txt"), home).is_none());
    assert!(
        project_control("/srv/work/a/.local/bin/x", home).is_none(),
        "outside the home"
    );
}

/// Every client line of `contracts/fixtures/project/exchange.jsonl` parses
/// as the daemon's `Request` (the base's types; holds on the base).
#[test]
fn the_step_p_exchange_parses_as_requests() {
    let text = include_str!("../../../contracts/fixtures/project/exchange.jsonl");
    let mut n = 0;
    for line in text.lines().filter(|l| !l.is_empty()) {
        serde_json::from_str::<derm_daemon::protocol::Request>(line)
            .unwrap_or_else(|e| panic!("{e}: {line}"));
        n += 1;
    }
    assert_eq!(n, 7);
}
