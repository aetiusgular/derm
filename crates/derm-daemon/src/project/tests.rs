//! `crate::project::State` with a fake host (lane PE). The daemon-level
//! tests, over the socket with the real approver, are
//! `daemon/approver/project_tests.rs`; the base's red tests
//! `tests/contracts_acctp.rs`.

use super::*;
use crate::protocol::ScreenPut;

const A: &str = "aaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbb";

/// Answers every ask with `answer`, keeps every ask and record.
struct Fake {
    answer: Mutex<Asked>,
    asks: Mutex<Vec<ApprovalRequest>>,
    records: Mutex<Vec<Event>>,
    refuse_quota: Mutex<Option<String>>,
}

impl Fake {
    fn new(answer: Asked) -> Arc<Fake> {
        Arc::new(Fake {
            answer: Mutex::new(answer),
            asks: Mutex::new(Vec::new()),
            records: Mutex::new(Vec::new()),
            refuse_quota: Mutex::new(None),
        })
    }
    fn asks(&self) -> Vec<ApprovalRequest> {
        self.asks.lock().unwrap().clone()
    }
    fn records(&self, kind: &str) -> Vec<Event> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.kind == kind)
            .cloned()
            .collect()
    }
}

impl Host for Fake {
    fn ask(&self, request: ApprovalRequest) -> Asked {
        self.asks.lock().unwrap().push(request);
        *self.answer.lock().unwrap()
    }
    fn record(&self, event: Event) {
        self.records.lock().unwrap().push(event);
    }
    fn quota(&self, _chat: &str, _bytes: usize) -> Result<(), String> {
        match self.refuse_quota.lock().unwrap().clone() {
            Some(why) => Err(why),
            None => Ok(()),
        }
    }
}

fn state(fake: &Arc<Fake>) -> State {
    let s = State::default();
    let host: Arc<dyn Host> = fake.clone();
    // The same allocation as `fake`, which every test keeps.
    s.attach(Arc::downgrade(&host));
    s
}

fn chat<'a>(chat: &'a str) -> Caller<'a> {
    Caller::Chat {
        chat,
        harness: "codex",
    }
}

fn ok(r: &Reply) -> &Value {
    assert!(r.ok, "{:?}", r.error);
    r.result.as_ref().expect("a result")
}

fn err(r: &Reply) -> String {
    assert!(!r.ok, "expected a refusal, got {:?}", r.result);
    r.error.clone().unwrap_or_default()
}

fn event(chat: &str, project: &str) -> Event {
    Event {
        id: "e1".into(),
        at: 1,
        chat_id: chat.into(),
        harness: "codex".into(),
        source: Source::Adapter,
        kind: "tool.call".into(),
        summary: String::new(),
        detail: json!({}),
        pid: None,
        approval_id: None,
        project: project.into(),
    }
}

fn run_start(chat: &str, detail: Value) -> Event {
    Event {
        source: Source::Run,
        kind: "run.start".into(),
        detail,
        ..event(chat, "")
    }
}

fn put(chat: &str, text: &str, scrollback: u32) -> ScreenPut {
    ScreenPut {
        chat: chat.into(),
        rows: 2,
        cols: 40,
        text: text.into(),
        scrollback_lines: scrollback,
        at: 7,
    }
}

#[test]
fn stamp_sets_the_daemons_project_and_counts_only_another_project() {
    let s = State::default();
    s.note_mint("c-a", A);
    let mut e = event("c-a", B);
    s.stamp(&mut e);
    assert_eq!(e.project, A);
    assert_eq!(s.overwritten(), 1);
    // No project from an older client, or the right one: not counted.
    for sent in ["", A] {
        let mut e = event("c-a", sent);
        s.stamp(&mut e);
        assert_eq!(e.project, A);
    }
    assert_eq!(s.overwritten(), 1);
    // A chat the map does not hold has no project, whatever it claims.
    let mut e = event("c-x", A);
    s.stamp(&mut e);
    assert_eq!(e.project, "");
    assert_eq!(s.overwritten(), 2);
}

#[test]
fn a_chats_project_outlives_its_stop_for_the_records_that_follow() {
    let s = State::default();
    s.note_mint("c-a", A);
    s.forget_chat("c-a");
    let mut e = event("c-a", "");
    s.stamp(&mut e);
    assert_eq!(e.project, A, "run.stop and late OS events keep the project");
}

#[test]
fn the_map_comes_back_from_chats_json_and_a_restored_chat_waits_for_a_sign_of_life() {
    let fake = Fake::new(Asked::No);
    let s = state(&fake);
    s.note_mint("c-a1", A);
    s.note_mint("c-a2", A);
    s.note_mint("c-old", A);
    s.forget_chat("c-old");
    s.stamp(&mut run_start(
        "c-a1",
        json!({"runsAs": "derm-max", "project": {"id": A, "folder": "/srv/work/a"}}),
    ));
    let saved = s.saved();
    let chats = saved["chats"].as_array().unwrap();
    assert_eq!(chats.len(), 2, "a stopped chat is not saved: {saved}");
    assert!(!saved.to_string().contains("token"));

    let back = state(&fake);
    back.restore(&saved);
    assert_eq!(back.project_of("c-a1"), A);
    assert_eq!(back.project_of("c-old"), "");
    // Not a target until its token comes back and it acts.
    assert!(err(&back.msg_send(chat("c-a2"), "c-a1", "hi", None)).contains("no running chat"));
    assert_eq!(ok(&back.msg_take(chat("c-a1")))["messages"], json!([]));
    let r = back.msg_send(chat("c-a2"), "c-a1", "hi", None);
    assert_eq!(ok(&r)["delivered"], json!(["c-a1"]));
    let t = back.msg_take(chat("c-a1"));
    assert_eq!(ok(&t)["messages"][0]["from"]["chat"], "c-a2");
    // The folder and the account came back too.
    assert_eq!(back.lock().chats["c-a1"].folder, "/srv/work/a");
    assert_eq!(back.lock().chats["c-a1"].account, "max");
}

#[test]
fn a_restore_of_another_shape_adds_nothing() {
    let s = State::default();
    for bad in [
        Value::Null,
        json!({"version": 2, "chats": [{"chat": "c", "project": A}]}),
        json!({"version": 1, "chats": [{"chat": "../x", "project": A}]}),
        json!({"version": 1, "chats": [{"chat": "c", "project": "AAAA"}]}),
    ] {
        s.restore(&bad);
    }
    assert!(s.lock().chats.is_empty());
}

#[test]
fn run_start_names_the_account_and_folder_and_never_moves_a_minted_project() {
    let s = State::default();
    s.note_mint("c-a", A);
    s.note_run_start(&run_start(
        "c-a",
        json!({"runsAs": "derm-max", "project": {"id": B, "folder": "/srv/b"}}),
    ));
    let c = s.lock().chats["c-a"].clone();
    assert_eq!(c.project, A, "the mint's project holds");
    assert_eq!(c.folder, "", "a folder for another project is not taken");
    assert_eq!(c.account, "max");
    // A chat the map lost (no chats.json) takes run.start's project.
    s.note_run_start(&run_start(
        "c-new",
        json!({"runsAs": "you", "project": {"id": B, "folder": "/srv/b"}}),
    ));
    let c = s.lock().chats["c-new"].clone();
    assert_eq!(
        (c.project.as_str(), c.folder.as_str(), c.account.as_str()),
        (B, "/srv/b", "")
    );
    // A folder that is not a plain absolute path is not kept.
    s.note_run_start(&run_start(
        "c-new",
        json!({"project": {"id": B, "folder": "/srv/b\u{1b}[2J"}}),
    ));
    assert_eq!(s.lock().chats["c-new"].folder, "/srv/b");
}

#[test]
fn a_message_in_one_project_is_delivered_once_marked_from_an_agent_and_recorded_without_its_text() {
    let fake = Fake::new(Asked::No);
    let s = state(&fake);
    s.note_mint("c-a1", A);
    s.note_mint("c-a2", A);
    let r = s.msg_send(chat("c-a1"), "c-a2", "build is green", Some("m-1"));
    let res = ok(&r);
    assert_eq!(res["delivered"], json!(["c-a2"]));
    assert_eq!(res["asked"], json!([]));
    assert!(res["id"].as_str().unwrap().starts_with("m-"));
    let t = s.msg_take(chat("c-a2"));
    let m = &ok(&t)["messages"][0];
    assert_eq!(
        m["from"],
        json!({"chat": "c-a1", "harness": "codex", "account": "", "agent": true})
    );
    assert_eq!(m["text"], "build is green");
    assert_eq!(m["replyTo"], "m-1");
    assert_eq!(ok(&s.msg_take(chat("c-a2")))["messages"], json!([]));
    assert!(fake.asks().is_empty());
    let rec = fake.records(kinds::MESSAGE);
    assert_eq!(rec.len(), 1);
    let r = &rec[0];
    assert_eq!(
        (r.source, r.chat_id.as_str(), r.project.as_str()),
        (Source::Derm, "c-a1", A)
    );
    assert_eq!(r.detail["bytes"], 14);
    assert_eq!(r.detail["asked"], false);
    assert_eq!(r.detail["trust"], "daemon");
    assert_eq!(
        r.detail["sha256"],
        sha256_hex(b"build is green"),
        "the text is named by its hash"
    );
    assert!(!serde_json::to_string(r).unwrap().contains("build is green"));
}

#[test]
fn star_reaches_every_other_running_chat_of_the_project_and_nothing_else() {
    let fake = Fake::new(Asked::Once);
    let s = state(&fake);
    for (c, p) in [
        ("c-a1", A),
        ("c-a2", A),
        ("c-a3", A),
        ("c-b", B),
        ("c-none", ""),
    ] {
        s.note_mint(c, p);
    }
    s.forget_chat("c-a3");
    let r = s.msg_send(chat("c-a1"), "*", "done", None);
    assert_eq!(ok(&r)["delivered"], json!(["c-a2"]));
    assert!(fake.asks().is_empty(), "\"*\" never asks across projects");
    assert_eq!(ok(&s.msg_take(chat("c-b")))["messages"], json!([]));
}

#[test]
fn across_projects_a_message_asks_and_a_no_delivers_nothing() {
    let fake = Fake::new(Asked::No);
    let s = state(&fake);
    s.note_mint("c-a", A);
    s.note_mint("c-b", B);
    s.note_run_start(&run_start(
        "c-a",
        json!({"project": {"id": A, "folder": "/srv/work/a"}}),
    ));
    let r = s.msg_send(chat("c-a"), "c-b", "secret plan", None);
    assert_eq!(ok(&r)["delivered"], json!([]));
    assert_eq!(ok(&r)["asked"], json!(["c-b"]));
    let asks = fake.asks();
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].tool, TOOL_MESSAGE);
    assert_eq!(asks[0].chat, "c-a");
    assert!(
        asks[0].summary.contains("/srv/work/a"),
        "{}",
        asks[0].summary
    );
    assert!(asks[0].summary.contains(B), "{}", asks[0].summary);
    assert!(
        !asks[0].summary.contains("secret plan"),
        "no text on the card or in its record"
    );
    assert_eq!(ok(&s.msg_take(chat("c-b")))["messages"], json!([]));
    let rec = &fake.records(kinds::MESSAGE)[0];
    assert_eq!(
        (rec.detail["asked"].clone(), rec.detail["answer"].clone()),
        (json!(true), json!("no"))
    );
}

#[test]
fn a_yes_this_once_delivers_and_asks_again_next_time() {
    let fake = Fake::new(Asked::Once);
    let s = state(&fake);
    s.note_mint("c-a", A);
    s.note_mint("c-b", B);
    assert_eq!(
        ok(&s.msg_send(chat("c-a"), "c-b", "x", None))["delivered"],
        json!(["c-b"])
    );
    assert_eq!(
        ok(&s.msg_send(chat("c-a"), "c-b", "y", None))["delivered"],
        json!(["c-b"])
    );
    assert_eq!(fake.asks().len(), 2);
    assert!(fake.records(kinds::GRANT).is_empty());
}

#[test]
fn a_session_grant_holds_one_way_for_the_callers_chat_and_ends_with_it() {
    let fake = Fake::new(Asked::Session);
    let s = state(&fake);
    s.note_mint("c-a", A);
    s.note_mint("c-a2", A);
    s.note_mint("c-b", B);
    assert_eq!(
        ok(&s.msg_send(chat("c-a"), "c-b", "x", None))["delivered"],
        json!(["c-b"])
    );
    assert_eq!(fake.asks().len(), 1);
    let grants = fake.records(kinds::GRANT);
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0].detail,
        json!({"from": A, "to": B, "chat": "c-a", "until": "session", "trust": "daemon"})
    );
    // The same chat, either tool, asks no more.
    let r = s.msg_send(chat("c-a"), "c-b", "y", None);
    assert_eq!(ok(&r)["asked"], json!([]));
    s.screen_put(Caller::Daemon, &put("c-b", "$ ls", 0));
    assert_eq!(ok(&s.screen_read(chat("c-a"), "c-b", None))["text"], "$ ls");
    assert_eq!(fake.asks().len(), 1);
    // Another chat of the same project, and the other direction, still ask.
    *fake.answer.lock().unwrap() = Asked::No;
    assert_eq!(
        ok(&s.msg_send(chat("c-a2"), "c-b", "z", None))["asked"],
        json!(["c-b"])
    );
    assert_eq!(
        ok(&s.msg_send(chat("c-b"), "c-a", "z", None))["asked"],
        json!(["c-a"])
    );
    assert_eq!(fake.asks().len(), 3);
    // The grant ends at the caller's run.stop, recorded.
    s.forget_chat("c-a");
    let grants = fake.records(kinds::GRANT);
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[1].detail["ended"], true);
    assert!(s.lock().grants.is_empty());
}

#[test]
fn a_chat_in_no_project_reaches_no_chat_and_none_reaches_it() {
    let fake = Fake::new(Asked::Once);
    let s = state(&fake);
    s.note_mint("c-a", A);
    s.note_mint("c-none", "");
    assert!(err(&s.msg_send(chat("c-none"), "c-a", "x", None)).contains("no project"));
    assert!(err(&s.msg_send(chat("c-a"), "c-none", "x", None)).contains("no project"));
    s.screen_put(Caller::Daemon, &put("c-none", "x", 0));
    assert!(err(&s.screen_read(chat("c-a"), "c-none", None)).contains("no project"));
    assert_eq!(ok(&s.screen_list(chat("c-none")))["chats"], json!([]));
    assert!(fake.asks().is_empty());
}

#[test]
fn sends_that_break_the_contract_are_refused_before_anything_moves() {
    let fake = Fake::new(Asked::Once);
    let s = state(&fake);
    s.note_mint("c-a", A);
    s.note_mint("c-a2", A);
    assert!(err(&s.msg_send(Caller::Daemon, "c-a", "x", None)).contains("chat scope"));
    assert!(err(&s.msg_send(chat("c-a"), "c-a", "x", None)).contains("itself"));
    assert!(err(&s.msg_send(chat("c-a"), "c-zz", "x", None)).contains("no running chat"));
    assert!(err(&s.msg_send(chat("c-a"), "../c", "x", None)).contains("chat id"));
    assert!(err(&s.msg_send(chat("c-a"), "c-a2", "", None)).contains("16 KiB"));
    let big = "x".repeat(MAX_MESSAGE_BYTES + 1);
    assert!(err(&s.msg_send(chat("c-a"), "c-a2", &big, None)).contains("16 KiB"));
    assert!(ok(&s.msg_send(chat("c-a"), "c-a2", &big[1..], None))["delivered"].is_array());
    assert!(err(&s.msg_send(chat("c-a"), "c-a2", "x", Some("a b"))).contains("replyTo"));
    *fake.refuse_quota.lock().unwrap() = Some("this chat posts too fast".into());
    assert!(err(&s.msg_send(chat("c-a"), "c-a2", "x", None)).contains("too fast"));
    assert!(err(&s.msg_take(chat("c-a2"))).contains("too fast"));
    assert!(err(&s.msg_take(Caller::Daemon)).contains("chat scope"));
}

#[test]
fn a_chats_waiting_messages_are_bounded_oldest_out_and_counted() {
    let fake = Fake::new(Asked::Once);
    let s = state(&fake);
    s.note_mint("c-a", A);
    s.note_mint("c-a2", A);
    for i in 0..(MAX_WAITING + 3) {
        s.msg_send(chat("c-a"), "c-a2", &format!("n{i}"), None);
    }
    let t = s.msg_take(chat("c-a2"));
    let list = ok(&t)["messages"].as_array().unwrap().clone();
    assert_eq!(list.len(), MAX_WAITING);
    assert_eq!(list[0]["text"], "n3", "the oldest went first");
    assert_eq!(s.dropped(), 3);
    let big = "y".repeat(MAX_MESSAGE_BYTES);
    for _ in 0..20 {
        s.msg_send(chat("c-a"), "c-a2", &big, None);
    }
    let t = s.msg_take(chat("c-a2"));
    let bytes: usize = ok(&t)["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["text"].as_str().unwrap().len())
        .sum();
    assert!(bytes <= MAX_WAITING_BYTES, "{bytes}");
}

#[test]
fn a_stop_ends_the_chats_screen_and_waiting_messages() {
    let fake = Fake::new(Asked::Once);
    let s = state(&fake);
    s.note_mint("c-a", A);
    s.note_mint("c-a2", A);
    s.msg_send(chat("c-a"), "c-a2", "x", None);
    s.screen_put(Caller::Daemon, &put("c-a2", "x", 0));
    s.forget_chat("c-a2");
    assert!(s.lock().inbox.is_empty() && s.lock().screens.is_empty());
    assert!(err(&s.msg_send(chat("c-a"), "c-a2", "x", None)).contains("no running chat"));
    assert!(err(&s.screen_put(Caller::Daemon, &put("c-a2", "x", 0))).contains("no running chat"));
    // A new mint of the same chat id runs again.
    s.note_mint("c-a2", A);
    assert_eq!(
        ok(&s.msg_send(chat("c-a"), "c-a2", "x", None))["delivered"],
        json!(["c-a2"])
    );
}

#[test]
fn screen_put_is_the_daemon_scopes_and_bounded() {
    let s = State::default();
    s.note_mint("c-a", A);
    assert!(err(&s.screen_put(chat("c-a"), &put("c-a", "forged", 0))).contains("daemon scope"));
    let big = "x".repeat(screen::MAX_TEXT_BYTES + 1);
    assert!(err(&s.screen_put(Caller::Daemon, &put("c-a", &big, 0))).contains("512 KiB"));
    let mut zero = put("c-a", "x", 0);
    zero.rows = 0;
    assert!(err(&s.screen_put(Caller::Daemon, &zero)).contains("at least 1"));
    assert!(err(&s.screen_put(Caller::Daemon, &put("c-x", "x", 0))).contains("no running chat"));
    assert!(s.screen_put(Caller::Daemon, &put("c-a", &big[1..], 0)).ok);
}

#[test]
fn a_read_serves_the_screen_or_the_last_lines_and_records_its_hash_in_the_targets_chat() {
    let fake = Fake::new(Asked::No);
    let s = state(&fake);
    s.note_mint("c-a1", A);
    s.note_mint("c-a2", A);
    assert!(err(&s.screen_read(chat("c-a2"), "c-a1", None)).contains("serves no screen"));
    s.screen_put(
        Caller::Daemon,
        &put("c-a1", "old 1\nold 2\n$ cargo test\nok", 2),
    );
    let r = s.screen_read(chat("c-a2"), "c-a1", None);
    let res = ok(&r);
    assert_eq!(
        res["text"], "$ cargo test\nok",
        "the screen, without its scrollback"
    );
    assert_eq!(
        (res["rows"].clone(), res["cols"].clone(), res["at"].clone()),
        (json!(2), json!(40), json!(7))
    );
    assert_eq!(res["truncated"], false);
    assert_eq!(
        ok(&s.screen_read(chat("c-a2"), "c-a1", Some(3)))["text"],
        "old 2\n$ cargo test\nok"
    );
    assert_eq!(
        ok(&s.screen_read(chat("c-a2"), "c-a1", Some(2000)))["text"],
        "old 1\nold 2\n$ cargo test\nok"
    );
    for bad in [0, 2001] {
        assert!(err(&s.screen_read(chat("c-a2"), "c-a1", Some(bad))).contains("1 to 2000"));
    }
    assert!(err(&s.screen_read(Caller::Daemon, "c-a1", None)).contains("chat scope"));
    let rec = &fake.records(kinds::READ)[0];
    assert_eq!((rec.chat_id.as_str(), rec.project.as_str()), ("c-a1", A));
    assert_eq!(rec.detail["reader"], "c-a2");
    assert_eq!(rec.detail["sha256"], sha256_hex(b"$ cargo test\nok"));
    assert!(!serde_json::to_string(rec).unwrap().contains("cargo"));
    assert!(fake.asks().is_empty());
}

#[test]
fn a_read_across_projects_asks_and_a_no_serves_nothing() {
    let fake = Fake::new(Asked::No);
    let s = state(&fake);
    s.note_mint("c-a", A);
    s.note_mint("c-b", B);
    s.screen_put(Caller::Daemon, &put("c-b", "$ cat .env\nKEY=1", 0));
    let e = err(&s.screen_read(chat("c-a"), "c-b", None));
    assert!(e.contains("did not allow"), "{e}");
    assert_eq!(fake.asks()[0].tool, TOOL_READ);
    let rec = &fake.records(kinds::READ)[0];
    assert_eq!(
        (
            rec.detail["asked"].clone(),
            rec.detail["answer"].clone(),
            rec.detail["bytes"].clone()
        ),
        (json!(true), json!("no"), json!(0))
    );
    *fake.answer.lock().unwrap() = Asked::Once;
    let r = s.screen_read(chat("c-a"), "c-b", None);
    assert_eq!(ok(&r)["text"], "$ cat .env\nKEY=1");
    assert_eq!(fake.records(kinds::READ)[1].detail["answer"], "yes");
}

#[test]
fn list_names_the_projects_screens_but_the_callers_own() {
    let s = State::default();
    for (c, p) in [("c-a1", A), ("c-a2", A), ("c-a3", A), ("c-b", B)] {
        s.note_mint(c, p);
        s.screen_put(Caller::Daemon, &put(c, "x", 0));
    }
    s.note_run_start(&run_start("c-a2", json!({"runsAs": "derm-max"})));
    s.forget_chat("c-a3");
    let l = s.screen_list(chat("c-a1"));
    assert_eq!(
        ok(&l)["chats"],
        json!([{"chat": "c-a2", "harness": "codex", "account": "max", "rows": 2, "cols": 40, "at": 7}])
    );
    assert!(err(&s.screen_list(Caller::Daemon)).contains("chat scope"));
}

#[test]
fn without_a_host_an_ask_is_a_no_and_one_project_still_works() {
    let s = State::default();
    s.note_mint("c-a", A);
    s.note_mint("c-a2", A);
    s.note_mint("c-b", B);
    let r = s.msg_send(chat("c-a"), "c-b", "x", None);
    assert_eq!(
        (ok(&r)["delivered"].clone(), ok(&r)["asked"].clone()),
        (json!([]), json!(["c-b"]))
    );
    assert_eq!(
        ok(&s.msg_send(chat("c-a"), "c-a2", "x", None))["delivered"],
        json!(["c-a2"])
    );
}

#[test]
fn the_map_is_bounded_and_a_stopped_chat_leaves_first() {
    let s = State::default();
    s.note_mint("c-keep", A);
    s.note_mint("c-stopped", A);
    s.forget_chat("c-stopped");
    for i in 0..MAX_CHATS {
        s.note_mint(&format!("c-{i}"), B);
    }
    let g = s.lock();
    assert_eq!(g.chats.len(), MAX_CHATS);
    assert!(!g.chats.contains_key("c-stopped"));
}

#[test]
fn the_last_lines_and_the_screen_are_cut_on_line_boundaries() {
    assert_eq!(select("a\nb\nc", Some(1), 0), "c");
    assert_eq!(select("a\nb\nc", Some(9), 0), "a\nb\nc");
    assert_eq!(select("a\nb\nc", None, 1), "b\nc");
    assert_eq!(select("a\nb\nc", None, 9), "");
    assert_eq!(account_of(&json!({"runsAs": "derm-Max"})), "");
    assert_eq!(
        account_of(&json!({"runsAs": "derm-agent-x-way-too-long-slug"})),
        ""
    );
}
