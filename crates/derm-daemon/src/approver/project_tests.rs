//! Step P's daemon half over the real socket, with the real approver and
//! the host attached as request PE-R1 will attach it in `new_with_state`
//! (lane PE). These carry the base's red tests' cases
//! (`tests/contracts_acctp.rs`), which stay `ignore`d until integration
//! adds that line and drops their `ignore`, and add the cases the lane
//! found: an approver's yes, the approval and project records, the map
//! across a restart.

use super::*;
use crate::activity::store::ActivityLog;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

const DAEMON_TOKEN: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const A: &str = "aaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbb";

struct Fixture {
    root: std::path::PathBuf,
    socket: std::path::PathBuf,
    daemon: Arc<Daemon>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture_at(root: &std::path::Path) -> Fixture {
    let data = root.join("data");
    let log: &'static ActivityLog = Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
    let daemon = Daemon::new_with_state(
        DAEMON_TOKEN,
        log,
        &data,
        false,
        Some(root.join("chats.json")),
    )
    .unwrap();
    attach(&daemon);
    // Short: a Unix socket path is at most 104 bytes on macOS (case 111).
    let socket = root.join(format!(
        "r{}/d.sock",
        &uuid::Uuid::new_v4().simple().to_string()[..6]
    ));
    let listener = crate::socket::bind(&socket).unwrap();
    let serving = daemon.clone();
    std::thread::spawn(move || crate::socket::serve(listener, serving));
    Fixture {
        root: root.to_path_buf(),
        socket,
        daemon,
    }
}

fn fixture() -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "dpe-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    std::fs::create_dir_all(&root).unwrap();
    fixture_at(&root)
}

struct Client {
    w: UnixStream,
    r: BufReader<UnixStream>,
}

impl Client {
    fn hello(f: &Fixture, token: &str) -> Client {
        let s = UnixStream::connect(&f.socket).unwrap();
        let mut c = Client {
            w: s.try_clone().unwrap(),
            r: BufReader::new(s),
        };
        let r = c.ask(json!({"op": "hello", "token": token, "client": "pe"}));
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

/// Every stored event of `chat`, from the backlog.
fn stored(f: &Fixture, chat: &str) -> Vec<Value> {
    let mut t = Client::hello(f, DAEMON_TOKEN);
    assert_eq!(
        t.ask(json!({"op": "tail", "since": 0, "chat": chat}))["ok"],
        true
    );
    let mut out = Vec::new();
    while let Some(line) = t.recv(Duration::from_millis(600)) {
        out.push(line["event"].clone());
    }
    out
}

#[test]
fn a_chats_event_carries_the_daemons_project_and_the_overwrite_is_counted() {
    // The base's red test `base_a_chats_event_carries_the_daemons_project_not_the_clients`.
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    let token = mint(&mut d, "c-a", A);
    let mut a = Client::hello(&f, &token);
    let r = a.ask(json!({"op": "event", "event": {
        "id": "codex-p1", "at": 1, "chatId": "c-a", "harness": "codex", "source": "adapter",
        "kind": "tool.call", "summary": "x", "detail": {"trust": "client"}, "project": B
    }}));
    assert_eq!(r["ok"], true, "{r}");
    let e = stored(&f, "c-a")
        .into_iter()
        .find(|e| e["id"] == "codex-p1")
        .unwrap();
    assert_eq!(e["project"], A);
    let report = d.ask(json!({"op": "report", "since": 0, "until": i64::MAX}));
    assert_eq!(report["report"]["projectOverwritten"], 1, "{report}");
}

#[test]
fn a_message_reaches_its_own_project_and_a_no_across_projects_delivers_nothing() {
    // The base's red test `pe_a_message_reaches_its_own_project_and_asks_across_projects`.
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    let a1 = mint(&mut d, "c-a1", A);
    let a2 = mint(&mut d, "c-a2", A);
    let _b = mint(&mut d, "c-b", B);
    let mut c1 = Client::hello(&f, &a1);
    let mut c2 = Client::hello(&f, &a2);
    let r = c1.ask(json!({"op": "msg.send", "to": "c-a2", "text": "build is green"}));
    assert_eq!(r["result"]["delivered"], json!(["c-a2"]), "{r}");
    let t = c2.ask(json!({"op": "msg.take"}));
    let m = &t["result"]["messages"][0];
    assert_eq!(
        (m["from"]["chat"].clone(), m["from"]["agent"].clone()),
        (json!("c-a1"), json!(true)),
        "{t}"
    );
    assert_eq!(m["text"], "build is green", "{t}");
    assert_eq!(
        c2.ask(json!({"op": "msg.take"}))["result"]["messages"],
        json!([])
    );
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
    // The records: one project.message per target, the ask's approval.
    let events = stored(&f, "c-a1");
    let messages: Vec<&Value> = events
        .iter()
        .filter(|e| e["kind"] == "project.message")
        .collect();
    assert_eq!(messages.len(), 2, "{events:?}");
    assert!(messages
        .iter()
        .all(|e| e["source"] == "derm" && e["project"] == A));
    assert!(!serde_json::to_string(&events)
        .unwrap()
        .contains("build is green"));
    let asked = events
        .iter()
        .find(|e| e["source"] == "approval" && e["detail"]["tool"] == "derm_project/derm_message")
        .expect("the ask is recorded as an approval");
    assert_eq!(
        (
            asked["detail"]["answer"].clone(),
            asked["detail"]["by"].clone()
        ),
        (json!("no"), json!("approver"))
    );
}

#[test]
fn an_approvers_yes_delivers_across_projects_and_no_approver_is_a_no() {
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    let a = mint(&mut d, "c-a", A);
    let b = mint(&mut d, "c-b", B);
    // A chat under a boundary, so a yes needs no person check (S2 part b:
    // a chat with no run.start, or one that runs as you, needs one). Its
    // harness is a child of the test, so the approver (this process) is
    // not in its tree.
    let mut harness = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let r = d.ask(json!({"op": "event", "event": {
        "id": "start-c-a", "at": 1, "chatId": "c-a", "harness": "codex", "source": "run",
        "kind": "run.start", "summary": "", "detail": {"boundary": "srt"}, "pid": harness.id()
    }}));
    assert_eq!(r["ok"], true, "{r}");
    let mut ca = Client::hello(&f, &a);
    // Case 63: no approver, no.
    let r = ca.ask(json!({"op": "msg.send", "to": "c-b", "text": "x"}));
    assert_eq!(
        (
            r["result"]["delivered"].clone(),
            r["result"]["asked"].clone()
        ),
        (json!([]), json!(["c-b"])),
        "{r}"
    );
    let mut approver = Client::hello(&f, DAEMON_TOKEN);
    assert_eq!(approver.ask(json!({"op": "approver"}))["ok"], true);
    writeln!(
        ca.w,
        "{}",
        json!({"op": "msg.send", "to": "c-b", "text": "go"})
    )
    .unwrap();
    let push = approver.recv(Duration::from_secs(5)).unwrap();
    assert_eq!(push["approve"]["chat"], "c-a");
    let summary = push["approve"]["summary"].as_str().unwrap();
    assert!(
        summary.contains(A) && summary.contains(B) && !summary.contains("go\""),
        "{summary}"
    );
    approver
        .ask(json!({"op": "answer", "id": push["approve"]["id"], "answer": "yes", "chat": "c-a"}));
    let r = ca.recv(Duration::from_secs(5)).unwrap();
    assert_eq!(r["result"]["delivered"], json!(["c-b"]), "{r}");
    let mut cb = Client::hello(&f, &b);
    let t = cb.ask(json!({"op": "msg.take"}));
    assert_eq!(t["result"]["messages"][0]["text"], "go", "{t}");
    let _ = harness.kill();
    let _ = harness.wait();
}

#[test]
fn a_screen_is_read_by_its_own_project_only_and_cleaned_again() {
    // The base's red test `pe_a_screen_is_read_by_its_own_project_only`.
    // Its last line needs lane PD's `clean`; here the reply is what the
    // core's `clean` makes of the screen, whatever it is today.
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    let a1 = mint(&mut d, "c-a1", A);
    let a2 = mint(&mut d, "c-a2", A);
    let b = mint(&mut d, "c-b", B);
    let text = "$ cargo test\nok\u{202e}";
    let r = d.ask(
        json!({"op": "screen.put", "chat": "c-a1", "rows": 2, "cols": 20,
        "text": text, "scrollbackLines": 0, "at": 1}),
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
    assert_eq!(
        r["result"]["text"],
        derm_core::project::screen::clean(text).text,
        "{r}"
    );
    let l = c2.ask(json!({"op": "screen.list"}));
    assert_eq!(l["result"]["chats"][0]["chat"], "c-a1", "{l}");
    // Another project: no approver, so no; nothing served.
    let mut cb = Client::hello(&f, &b);
    let r = cb.ask(json!({"op": "screen.read", "chat": "c-a1"}));
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(
        cb.ask(json!({"op": "screen.list"}))["result"]["chats"],
        json!([])
    );
    // A daemon-scope connection reads nothing.
    assert_eq!(
        d.ask(json!({"op": "screen.read", "chat": "c-a1"}))["ok"],
        false
    );
    let reads: Vec<Value> = stored(&f, "c-a1")
        .into_iter()
        .filter(|e| e["kind"] == "project.read")
        .collect();
    assert_eq!(reads.len(), 2, "one served, one refused: {reads:?}");
}

#[test]
fn the_map_comes_back_after_a_restart_from_chats_json() {
    let root = std::env::temp_dir().join(format!(
        "dpe-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    std::fs::create_dir_all(&root).unwrap();
    let token = {
        let f = fixture_at(&root);
        let mut d = Client::hello(&f, DAEMON_TOKEN);
        let token = mint(&mut d, "c-a", A);
        let saved: Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("chats.json")).unwrap())
                .unwrap();
        assert_eq!(saved["projects"]["chats"][0]["project"], A, "{saved}");
        assert!(!saved.to_string().contains(&token), "never a token");
        std::mem::forget(f); // the first daemon's socket thread keeps running
        token
    };
    let f = fixture_at(&root);
    assert_eq!(f.daemon.project.project_of("c-a"), A);
    let mut a = Client::hello(&f, &token);
    let r = a.ask(json!({"op": "event", "event": {
        "id": "codex-r1", "at": 1, "chatId": "c-a", "harness": "codex", "source": "adapter",
        "kind": "tool.call", "summary": "x", "detail": {}
    }}));
    assert_eq!(r["ok"], true, "{r}");
    let e = stored(&f, "c-a")
        .into_iter()
        .find(|e| e["id"] == "codex-r1")
        .unwrap();
    assert_eq!(e["project"], A);
}

#[test]
fn a_chat_tokens_step_p_ops_come_out_of_its_socket_share() {
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    let a1 = mint(&mut d, "c-a1", A);
    let _a2 = mint(&mut d, "c-a2", A);
    let mut c1 = Client::hello(&f, &a1);
    let mut refused = 0;
    for _ in 0..700 {
        let r = c1.ask(json!({"op": "msg.send", "to": "c-a2", "text": "x"}));
        if r["ok"] == false && r["error"].as_str().unwrap_or("").contains("too fast") {
            refused += 1;
        }
    }
    assert!(refused > 0, "a burst past the share is refused");
}

/// Request PE-R4 (case 211): with no `chats.json`, a chat's project comes
/// back from the log's `run.start`, and a chat whose `run.stop` is in the
/// log does not come back as running. A chat replayed from the log is not
/// a target until it shows life, as one from `chats.json` (Look out for I).
#[test]
fn pe_r4_the_map_comes_back_from_the_log_when_chats_json_is_gone() {
    let root = std::env::temp_dir().join(format!(
        "dpe-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    std::fs::create_dir_all(&root).unwrap();
    let run = |chat: &str, kind: &str, project: &str| {
        json!({"op": "event", "event": {
            "id": format!("run-{chat}-{kind}"), "at": 1, "chatId": chat, "harness": "codex",
            "source": "run", "kind": kind, "summary": kind,
            "detail": {"project": {"id": project, "folder": "/srv/p"}}
        }})
    };
    {
        let f = fixture_at(&root);
        let mut d = Client::hello(&f, DAEMON_TOKEN);
        mint(&mut d, "c-live", A);
        mint(&mut d, "c-done", B);
        assert_eq!(d.ask(run("c-live", "run.start", A))["ok"], true);
        assert_eq!(d.ask(run("c-done", "run.start", B))["ok"], true);
        assert_eq!(d.ask(run("c-done", "run.stop", B))["ok"], true);
        // Let the log reach the disk before the daemon goes.
        std::thread::sleep(Duration::from_millis(1_500));
        std::mem::forget(f);
    }
    std::fs::remove_file(root.join("chats.json")).unwrap();
    let f = fixture_at(&root);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while f.daemon.project.project_of("c-live").is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(f.daemon.project.project_of("c-live"), A, "from the log");
    let saved = f.daemon.project.saved();
    let chats: Vec<&str> = saved["chats"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["chat"].as_str())
        .collect();
    assert!(chats.contains(&"c-live"), "{saved}");
    assert!(
        !chats.contains(&"c-done"),
        "a stopped chat is not running: {saved}"
    );
    assert!(
        !f.daemon.project.running("c-live"),
        "not live until it shows life"
    );
}

/// Request PE-R2 (contracts/events.md 7.1, "every event it stores"): an
/// event that reaches `ingest` another way than `op_event` (OTel over HTTP,
/// the tap, an OS feed) carries its chat's project too, and a forged one is
/// overwritten.
#[test]
fn pe_r2_an_event_ingested_outside_op_event_carries_its_chats_project() {
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    mint(&mut d, "c-a", A);
    for (id, source, project) in [
        ("otel-pe-r2", derm_core::event::Source::Otel, ""),
        ("auditd-pe-r2", derm_core::event::Source::Auditd, B),
    ] {
        f.daemon.ingest(Event {
            id: id.into(),
            at: 1,
            chat_id: "c-a".into(),
            harness: "codex".into(),
            source,
            kind: "file.write".into(),
            summary: "x".into(),
            detail: json!({}),
            pid: None,
            approval_id: None,
            project: project.into(),
        });
    }
    let got = stored(&f, "c-a");
    for id in ["otel-pe-r2", "auditd-pe-r2"] {
        let e = got
            .iter()
            .find(|e| e["id"] == id)
            .unwrap_or_else(|| panic!("{id}: {got:?}"));
        assert_eq!(e["project"], A, "{e}");
    }
}

/// Request PE-R3 (plan call 20, P-C7): a project ask offers "this once" and
/// "for this session"; a session yes is a grant for the asking chat to the
/// other project, so its next message there is delivered with no card, and
/// a once yes asks again. A gate's own `approve` that names `offers` has
/// them dropped, and a `session` answer to it counts as once.
#[test]
fn pe_r3_a_session_yes_grants_the_chat_and_a_gate_cannot_offer_it() {
    let f = fixture();
    let mut d = Client::hello(&f, DAEMON_TOKEN);
    let a = mint(&mut d, "c-a", A);
    let b = mint(&mut d, "c-b", B);
    let mut harness = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let r = d.ask(json!({"op": "event", "event": {
        "id": "start-c-a", "at": 1, "chatId": "c-a", "harness": "codex", "source": "run",
        "kind": "run.start", "summary": "", "detail": {"boundary": "srt"}, "pid": harness.id()
    }}));
    assert_eq!(r["ok"], true, "{r}");
    let mut ca = Client::hello(&f, &a);
    let mut approver = Client::hello(&f, DAEMON_TOKEN);
    assert_eq!(approver.ask(json!({"op": "approver"}))["ok"], true);
    // A once yes, then the next message asks again.
    for (text, scope) in [("one", "once"), ("two", "session")] {
        writeln!(
            ca.w,
            "{}",
            json!({"op": "msg.send", "to": "c-b", "text": text})
        )
        .unwrap();
        let push = approver.recv(Duration::from_secs(5)).unwrap();
        assert_eq!(
            push["approve"]["offers"],
            json!(["once", "session"]),
            "{push}"
        );
        let r = approver.ask(json!({"op": "answer", "id": push["approve"]["id"],
            "answer": "yes", "chat": "c-a", "scope": scope}));
        assert_eq!(r["ok"], true, "{r}");
        let r = ca.recv(Duration::from_secs(5)).unwrap();
        assert_eq!(r["result"]["delivered"], json!(["c-b"]), "{scope}: {r}");
    }
    // After the session yes, no card.
    let r = ca.ask(json!({"op": "msg.send", "to": "c-b", "text": "three"}));
    assert_eq!(
        (
            r["result"]["delivered"].clone(),
            r["result"]["asked"].clone()
        ),
        (json!(["c-b"]), json!([])),
        "{r}"
    );
    assert!(
        approver.recv(Duration::from_millis(500)).is_none(),
        "no card"
    );
    let mut cb = Client::hello(&f, &b);
    let t = cb.ask(json!({"op": "msg.take"}));
    assert_eq!(
        t["result"]["messages"].as_array().map(Vec::len),
        Some(3),
        "{t}"
    );
    let grants: Vec<Value> = stored(&f, "c-a")
        .into_iter()
        .filter(|e| e["kind"] == "project.grant")
        .collect();
    assert_eq!(grants.len(), 1, "{grants:?}");
    // A gate's ask names `offers`: the push carries none, and a session
    // answer is once.
    writeln!(
        ca.w,
        "{}",
        json!({"op": "approve", "request": {
            "id": "gate-1", "chat": "c-a", "harness": "codex", "tool": "bash",
            "summary": "ls", "timeoutSeconds": 5, "offers": ["once", "session"]
        }})
    )
    .unwrap();
    let push = approver.recv(Duration::from_secs(5)).unwrap();
    assert_eq!(push["approve"]["id"], "gate-1", "{push}");
    assert!(push["approve"].get("offers").is_none(), "{push}");
    approver.ask(
        json!({"op": "answer", "id": "gate-1", "answer": "yes", "chat": "c-a",
        "scope": "session"}),
    );
    let r = ca.recv(Duration::from_secs(5)).unwrap();
    assert_eq!(r["answer"], "yes", "{r}");
    let records: Vec<Value> = stored(&f, "c-a")
        .into_iter()
        .filter(|e| e["source"] == "approval" && e["detail"]["requestId"] == "gate-1")
        .filter(|e| e["detail"]["answer"] == "yes")
        .collect();
    assert_eq!(records.len(), 1, "the gate's yes is recorded");
    // The gate's session answer granted nothing across projects.
    let grants = stored(&f, "c-a")
        .into_iter()
        .filter(|e| e["kind"] == "project.grant")
        .count();
    assert_eq!(grants, 1, "still only the project ask's grant");
    let _ = harness.kill();
    let _ = harness.wait();
}
