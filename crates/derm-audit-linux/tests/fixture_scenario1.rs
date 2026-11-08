//! The feed against a log recorded with auditd 3.1.2 on Ubuntu 24.04.5
//! (kernel 6.18.44) in lane D's cloud workspace, 27 Oct 2026, with the rules
//! of `derm-audit-feed rules --uid 1000 --home /home/ubuntu` (less the b32 and
//! sudo lines). The scenario, as user `ubuntu` (uid 1000):
//!
//! ```text
//! setpriv --reuid=1000 ... env -i HOME=/home/ubuntu PATH=... /home/ubuntu/fakeharness.sh   # pid 1031
//!   cd /home/ubuntu/proj; echo hi > inside.txt
//!   echo x > "/home/ubuntu/out side ü.txt"
//!   cat /home/ubuntu/.ssh/id_test > /dev/null
//!   mv inside.txt renamed.txt; rm renamed.txt
//!   python3: connect 127.0.0.1:9, 93.184.215.14:443 (IPv6 is off here)
//!   ( setsid sh -c 'sleep 0.5; echo o > /home/ubuntu/orphan.txt' & )
//!   /bin/true --token ghp_aaaa...
//! setpriv ... sh -c 'echo n > /home/ubuntu/noise.txt'                    # pid 1041, not in the tree
//! ```
//!
//! `scenario1.enriched.audit` is the log as auditd wrote it; `scenario1.raw.audit`
//! is the same with the enriched tail (after 0x1D) cut, as a raw stream.

use derm_audit_linux::feed::Feed;
use derm_audit_linux::parse_for_root;
use derm_audit_linux::tree::Root;
use derm_core::event::{Event, Source};
use serde_json::Value;

const ENRICHED: &str = include_str!("fixtures/scenario1.enriched.audit");
const RAW: &str = include_str!("fixtures/scenario1.raw.audit");
const HOME: &str = "/home/ubuntu";

fn root() -> Root {
    Root {
        chat: "chat-1".into(),
        harness: "pi".into(),
        pid: 1031,
        folders: vec!["/home/ubuntu/proj".into()],
        state: vec!["/home/ubuntu/.pi/agent".into()],
        at: 0,
        stopped: false,
    }
}

fn flags(e: &Event) -> Vec<String> {
    e.detail
        .get("preflags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn path(e: &Event) -> &str {
    e.detail.get("path").and_then(Value::as_str).unwrap_or("")
}

fn find<'a>(events: &'a [Event], kind: &str, p: &str) -> &'a Event {
    events
        .iter()
        .find(|e| e.kind == kind && path(e) == p)
        .unwrap_or_else(|| panic!("no {kind} {p}"))
}

#[test]
fn every_event_is_the_chats_and_from_auditd() {
    let events = parse_for_root(ENRICHED, root(), HOME);
    assert!(events.len() > 20, "{} events", events.len());
    for e in &events {
        assert_eq!(e.chat_id, "chat-1");
        assert_eq!(e.harness, "pi");
        assert_eq!(e.source, Source::Auditd);
        assert!(e.summary.chars().count() <= 200);
        assert!(e.id.starts_with("auditd-"));
    }
    // pid 1041 wrote noise.txt as the same user, outside the tree.
    assert!(events.iter().all(|e| e.pid != Some(1041)));
    assert!(events.iter().all(|e| !path(e).ends_with("noise.txt")));
    // Ids are unique.
    let mut ids: Vec<&str> = events.iter().map(|e| e.id.as_str()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), events.len());
}

#[test]
fn writes_inside_pass_outside_flag_and_the_hex_name_decodes() {
    let events = parse_for_root(ENRICHED, root(), HOME);
    let inside = find(&events, "create", "/home/ubuntu/proj/inside.txt");
    assert!(flags(inside).is_empty());
    assert_eq!(inside.detail["tier"], "root");
    let outside = find(&events, "create", "/home/ubuntu/out side ü.txt");
    assert_eq!(flags(outside), vec!["writeOutside"]);
    let rename = events.iter().find(|e| e.kind == "rename").unwrap();
    assert_eq!(path(rename), "/home/ubuntu/proj/inside.txt");
    assert_eq!(rename.detail["dest"], "/home/ubuntu/proj/renamed.txt");
    assert!(flags(rename).is_empty());
    let unlink = find(&events, "unlink", "/home/ubuntu/proj/renamed.txt");
    assert!(flags(unlink).is_empty());
    assert_eq!(unlink.detail["tier"], "child");
    // /dev/null is noise.
    assert!(flags(find(&events, "write", "/dev/null")).is_empty());
}

#[test]
fn the_secret_read_and_the_new_host_flag() {
    let events = parse_for_root(ENRICHED, root(), HOME);
    let open = find(&events, "open", "/home/ubuntu/.ssh/id_test");
    assert_eq!(flags(open), vec!["sensitive"]);
    let hosts: Vec<(&str, Vec<String>)> = events
        .iter()
        .filter(|e| e.kind == "net.connect")
        .map(|e| (e.detail["host"].as_str().unwrap(), flags(e)))
        .collect();
    assert_eq!(
        hosts,
        vec![
            ("127.0.0.1:9", vec![]),
            ("93.184.215.14:443", vec!["newHost".to_string()])
        ],
        "AF_UNIX connects (nscd) are not kept; loopback is not a new host"
    );
}

#[test]
fn the_orphan_is_followed_and_its_write_flags() {
    let events = parse_for_root(ENRICHED, root(), HOME);
    let orphan = find(&events, "create", "/home/ubuntu/orphan.txt");
    assert_eq!(orphan.pid, Some(1037));
    assert_eq!(
        orphan.detail["ppid"], 1,
        "reparented to init before its own records"
    );
    assert_eq!(flags(orphan), vec!["writeOutside"]);
}

#[test]
fn argv_is_kept_and_the_token_redacted() {
    let events = parse_for_root(ENRICHED, root(), HOME);
    let t = events
        .iter()
        .find(|e| e.kind == "exec" && e.detail["argv"][0] == "/bin/true")
        .unwrap();
    assert_eq!(
        t.detail["argv"],
        serde_json::json!(["/bin/true", "--token", "[redacted]"])
    );
    assert!(!t.summary.contains("ghp_"));
    let whole = serde_json::to_string(&events).unwrap();
    assert!(
        !whole.contains("ghp_aaaa"),
        "the token appears nowhere in the output"
    );
    // The orphan's `sh -c` argument arrived hex-encoded.
    let sh = events
        .iter()
        .find(|e| e.kind == "exec" && e.detail["argv"][0] == "sh")
        .unwrap();
    assert_eq!(
        sh.detail["argv"][2],
        "sleep 0.5; echo o > /home/ubuntu/orphan.txt"
    );
}

#[test]
fn raw_and_enriched_logs_give_the_same_events() {
    assert_eq!(
        parse_for_root(ENRICHED, root(), HOME),
        parse_for_root(RAW, root(), HOME)
    );
}

#[test]
fn records_before_run_start_are_replayed_when_it_arrives() {
    let early = parse_for_root(ENRICHED, root(), HOME);
    let mut f = Feed::new(HOME, None);
    let mut late = Vec::new();
    for line in ENRICHED.split('\n') {
        late.extend(f.push_line(line));
    }
    late.extend(f.flush());
    assert!(
        late.is_empty(),
        "nothing is placed before the root is known"
    );
    let start = Event {
        id: "run-1".into(),
        at: 1,
        chat_id: "chat-1".into(),
        harness: "pi".into(),
        source: Source::Run,
        kind: "run.start".into(),
        summary: "pi under none".into(),
        detail: serde_json::json!({"folders": ["/home/ubuntu/proj"], "stateDirs": ["/home/ubuntu/.pi/agent"]}),
        pid: Some(1031),
        approval_id: None,
    };
    late.extend(f.on_daemon_event(&start, &|_| false));
    assert_eq!(late, early);
}

#[test]
fn a_chat_cannot_stop_its_own_feed_while_its_root_runs() {
    let mut f = Feed::new(HOME, None);
    f.register(root());
    let stop = Event {
        id: "run-2".into(),
        at: 2,
        chat_id: "chat-1".into(),
        harness: "pi".into(),
        source: Source::Run,
        kind: "run.stop".into(),
        summary: "".into(),
        detail: Value::Null,
        pid: None,
        approval_id: None,
    };
    f.on_daemon_event(&stop, &|pid| pid == 1031);
    assert_eq!(f.refused(), 1);
    assert!(f.tracker().root(1031).is_some());
    // Another chat cannot take the root's pid while it runs.
    let mut steal = stop.clone();
    steal.chat_id = "chat-2".into();
    steal.kind = "run.start".into();
    steal.pid = Some(1031);
    f.on_daemon_event(&steal, &|pid| pid == 1031);
    assert_eq!(f.tracker().root(1031).unwrap().chat, "chat-1");
    // Once the root has exited, the stop takes. The chat is kept until the
    // log the feed reads passes the stop (BW5R4-2): nothing is read here.
    f.on_daemon_event(&stop, &|_| false);
    assert!(f.tracker().root(1031).is_some_and(|r| r.stopped));
}

#[test]
fn a_cut_log_never_panics() {
    // Every prefix of the log at a line boundary, and lines cut mid-way.
    let lines: Vec<&str> = ENRICHED.split('\n').collect();
    for n in (0..lines.len()).step_by(17) {
        let mut text = lines[..n].join("\n");
        text.push_str("\ntype=SYSCALL msg=audit(1793114339.775:");
        let _ = parse_for_root(&text, root(), HOME);
    }
}

/// BW5R4-1: a feed that reads the log again from its beginning after a gap
/// skips what an earlier run read (up to the kept place's time), so nothing
/// is posted twice, and posts what came after.
#[test]
fn bw5r4_1_a_reread_skips_what_the_last_run_posted() {
    let all = parse_for_root(ENRICHED, root(), HOME);
    // The last run had read through the first create (stamped ...339775).
    let mut f = Feed::new(HOME, None);
    f.skip_through(1_793_114_339_775);
    let mut out = f.register(root());
    for line in ENRICHED.split('\n') {
        out.extend(f.push_line(line));
    }
    out.extend(f.flush());
    let later: Vec<Event> = all
        .into_iter()
        .filter(|e| e.at > 1_793_114_339_775)
        .collect();
    assert!(!later.is_empty());
    assert_eq!(out, later);
}

/// BW5R4-2 (box test w5, retest 4, on `8caaf00`): with the feed behind (paused
/// 40 s on the box), it read the daemon's `run.start` and `run.stop` before
/// the chat's audit lines, the stop dropped the chat (its processes had
/// exited), and every line after went unplaced: 0 OS records for the chat.
/// The lines stamped before the stop are still the chat's.
#[test]
fn bw5r4_2_lines_read_after_the_chats_stop_are_still_placed() {
    let early = parse_for_root(ENRICHED, root(), HOME);
    let mut f = Feed::new(HOME, None);
    let start = Event {
        id: "run-1".into(),
        at: 1_793_114_339_700,
        chat_id: "chat-1".into(),
        harness: "pi".into(),
        source: Source::Run,
        kind: "run.start".into(),
        summary: "pi under none".into(),
        detail: serde_json::json!({"folders": ["/home/ubuntu/proj"], "stateDirs": ["/home/ubuntu/.pi/agent"]}),
        pid: Some(1031),
        approval_id: None,
    };
    let mut stop = start.clone();
    stop.id = "run-2".into();
    stop.kind = "run.stop".into();
    // The last line of the log is stamped 1793114340.851.
    stop.at = 1_793_114_340_900;
    stop.detail = Value::Null;
    stop.pid = None;
    let mut late = f.on_daemon_event(&start, &|_| false);
    late.extend(f.on_daemon_event(&stop, &|_| false));
    for line in ENRICHED.split('\n') {
        late.extend(f.push_line(line));
    }
    late.extend(f.flush());
    assert_eq!(late, early);
}
