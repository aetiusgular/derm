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
fn a_run_record_is_taken_as_it_comes_since_only_the_daemon_posts_one() {
    // Spec change, fp13's review FP13R-6: until then this test held that a
    // `run.stop` whose root still ran was refused and that another chat could
    // not take a live root's pid, on the reading that a chat token could post
    // `run` records. It cannot: `contracts/daemon-protocol.md` rule 2, and
    // `op_event` refuses them (`derm-daemon/src/daemon.rs`, "a chat token
    // posts only adapter and otel events"). With the pid reused, the refusal
    // kept a stopped chat on a live chat's pid.
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
    // The stop takes even while the pid answers (a reused pid looks alive).
    // The chat is kept until the log the feed reads passes the stop
    // (BW5R4-2): nothing is read here.
    f.on_daemon_event(&stop, &|pid| pid == 1031);
    assert!(f.tracker().root(1031).is_some_and(|r| r.stopped));
    // A later start on the same pid is the next chat's.
    let mut next = stop.clone();
    next.chat_id = "chat-2".into();
    next.kind = "run.start".into();
    next.pid = Some(1031);
    f.on_daemon_event(&next, &|pid| pid == 1031);
    let r = f.tracker().root(1031).unwrap();
    assert_eq!((r.chat.as_str(), r.stopped), ("chat-2", false));
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
    f.skip_before((1_793_114_339_776, 0));
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

// ---- fp13 security review probes ----

fn run_ev(id: &str, kind: &str, chat: &str, pid: Option<u32>, at: i64) -> Event {
    Event {
        id: id.into(),
        at,
        chat_id: chat.into(),
        harness: "pi".into(),
        source: Source::Run,
        kind: kind.into(),
        summary: String::new(),
        detail: serde_json::json!({"folders": ["/home/ubuntu/proj"]}),
        pid,
        approval_id: None,
    }
}

/// FP13R-3 (fp13's review): the binary kept its place whenever no event was
/// open, while the events read before the chat's `run.start` reached the
/// feed waited unposted in the tracker: a restart then never read them. The
/// place now stays at the first line of the oldest unposted event, and
/// moves past them once they are posted.
#[test]
fn fp13r_3_the_place_does_not_pass_events_waiting_for_their_run_start() {
    use derm_audit_linux::resume::Places;
    let mut f = Feed::new(HOME, None);
    let mut places = Places::new();
    let mut out = Vec::new();
    let mut at = 0u64;
    for line in ENRICHED.split('\n') {
        let end = at + line.len() as u64 + 1;
        out.extend(f.push_line(line));
        let key = derm_audit_linux::record::parse_line(line).map(|r| r.event_key());
        places.note(1, 7, at, end, key);
        at = end;
    }
    // Every event is complete, none is posted: the chat's run.start has not
    // reached the feed.
    assert!(out.is_empty());
    assert!(f.tracker().pending_len() > 0);
    let place = places.place(&f.unposted()).unwrap();
    assert!(
        place.offset < at,
        "the place passed {} unposted actions",
        f.tracker().pending_len()
    );
    // The first waiting event's first line is the place.
    let first = ENRICHED
        .split('\n')
        .scan(0u64, |o, l| {
            let s = *o;
            *o += l.len() as u64 + 1;
            Some((s, l))
        })
        .find(|(_, l)| {
            derm_audit_linux::record::parse_line(l)
                .is_some_and(|r| f.unposted().contains(&r.event_key()))
        })
        .map(|(s, _)| s);
    assert_eq!(Some(place.offset), first);
    // Once the chat starts, what waited is posted and the place moves on.
    out.extend(f.register(root()));
    out.extend(f.flush());
    assert!(!out.is_empty());
    let unplaced: std::collections::HashSet<(i64, u64)> = f.unposted();
    let place = places.place(&unplaced).unwrap();
    assert!(place.offset > first.unwrap());
}

/// FP13R-12: a single-record event (no PROCTITLE, no EOE in the ENRICHED
/// log: USER_ACCT, CRED_ACQ, SERVICE_START...) stays open until 16 more
/// events open or the log is quiet half a second, so on a busy log the
/// place is never kept (ausearch(8) 4.1.2 counts a single-record event as
/// complete at once).
#[test]
fn fp13r_12_a_single_record_event_keeps_the_place_from_moving() {
    let mut f = Feed::new(HOME, None);
    f.push_line("type=USER_ACCT msg=audit(1793114339.000:900): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:accounting acct=\"root\" exe=\"/usr/sbin/cron\" hostname=? addr=? terminal=cron res=success'");
    for line in ENRICHED.split('\n') {
        f.push_line(line);
    }
    assert_eq!(
        f.open_events(),
        0,
        "the USER_ACCT event is still open after a whole log of syscall events"
    );
}

/// FP13R-6: a feed restart replays the 24 h backlog. A stopped chat's
/// `run.stop` is refused when its root pid is alive again (reused), so the
/// old chat holds the pid for good, and the live chat that now has that pid
/// is refused at its `run.start`: its processes are credited to the old one.
#[test]
fn fp13r_6_a_replayed_stop_with_a_reused_pid_credits_the_live_chat_to_the_old() {
    let mut f = Feed::new(HOME, None);
    // pid 1031 is alive now: the new chat's root.
    let alive = |pid: u32| pid == 1031;
    f.on_daemon_event(
        &run_ev("r1", "run.start", "chat-old", Some(1031), 1),
        &alive,
    );
    f.on_daemon_event(&run_ev("r2", "run.stop", "chat-old", None, 2), &alive);
    f.on_daemon_event(&run_ev("r3", "run.start", "chat-1", Some(1031), 3), &alive);
    let mut out = Vec::new();
    for line in ENRICHED.split('\n') {
        out.extend(f.push_line(line));
    }
    out.extend(f.flush());
    assert!(!out.is_empty());
    let chats: std::collections::BTreeSet<&str> = out.iter().map(|e| e.chat_id.as_str()).collect();
    assert_eq!(chats.into_iter().collect::<Vec<_>>(), vec!["chat-1"]);
}

/// FP13R-13: a pos file whose inode is not found and whose `logMs` is far
/// ahead (planted, or a clock step: `log_ms` is an unclamped maximum) makes
/// `skip_through` drop every event, for good (now `skip_before`, clamped).
#[test]
fn fp13r_13_a_floor_from_the_pos_file_can_skip_everything() {
    let mut f = Feed::new(HOME, None);
    f.skip_before((i64::MAX / 2, 0));
    let mut out = f.register(root());
    for line in ENRICHED.split('\n') {
        out.extend(f.push_line(line));
    }
    out.extend(f.flush());
    assert!(
        !out.is_empty(),
        "every event skipped by a floor read from the pos file"
    );
}
