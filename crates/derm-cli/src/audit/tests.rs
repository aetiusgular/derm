//! `derm audit` against logs the real writers make: the daemon's
//! `ChainWriter` (v1) and `derm_core::audit_chain::line` (v2), never a
//! hand-written line (rules section 9, item 12). The process-boundary case
//! for chain v2 is the base's red test (`tests/contracts_w6.rs`,
//! `derm_audit_verify_holds_the_fixture_chain`).

use std::fs;
use std::path::{Path, PathBuf};

use derm_core::event::{Event, Source as Src};
use derm_daemon::activity::store::{ChainWriter, Entry};
use serde_json::{json, Value};

use super::anchor::{Place, Record};
use super::chains::{self, Version};
use super::export;
use super::sources::Source;
use super::verify;
use super::why;

const DAY: i64 = 86_400_000;
const T0: i64 = 1_762_934_400_000; // 2025-11-12T08:00:00Z

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("da-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn ev(id: &str, at: i64, source: Src, kind: &str, summary: &str, detail: Value) -> Event {
    Event {
        id: id.into(),
        at,
        chat_id: "s-1".into(),
        harness: "claude-code".into(),
        source,
        kind: kind.into(),
        summary: summary.into(),
        detail,
        pid: None,
        approval_id: None,
    }
}

/// Writes `events` into `<data>/activity` with the daemon's own writer, each
/// on the day of its `at`.
fn write_log(data: &Path, events: &[Event]) {
    let mut w = ChainWriter::new(data.join("activity"));
    for e in events {
        w.write(&Entry::Event(e.clone()), e.at).unwrap();
    }
}

fn day_file(data: &Path, at: i64) -> PathBuf {
    data.join("activity").join(format!(
        "app-{}.jsonl",
        derm_daemon::activity::retention::day_name(at.div_euclid(DAY))
    ))
}

fn plain(n: usize, start: i64) -> Vec<Event> {
    (0..n)
        .map(|i| {
            ev(
                &format!("e{i}"),
                start + i as i64 * 1000,
                Src::Adapter,
                "approval",
                "Bash",
                json!({"toolUseId": format!("t{i}"), "decision": "allow", "durationMs": 1.5}),
            )
        })
        .collect()
}

#[test]
fn the_daemons_log_verifies_across_days_and_an_edit_names_its_file_and_line() {
    let d = scratch("v1days");
    let mut evs = plain(3, T0);
    evs.extend(plain(2, T0 + DAY));
    write_log(&d, &evs);
    let src = Source::Daemon(d.clone());
    let o = verify::check(&src, None, &[]);
    assert!(o.holds(), "{:?}", o.failure);
    assert_eq!(o.report.version, Some(Version::V1));
    assert_eq!(o.report.links.len(), 5);
    assert_eq!(o.report.first().unwrap().seq, 1);
    // An edit on the second day.
    let f2 = day_file(&d, T0 + DAY);
    let text = fs::read_to_string(&f2).unwrap().replace("\"t1\"", "\"t9\"");
    fs::write(&f2, text).unwrap();
    let o = verify::check(&src, None, &[]);
    let (n, why) = o.failure.clone().unwrap();
    assert_eq!(o.place(n), format!("{}:2", f2.display()));
    assert!(why.contains("hash"), "{why}");
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn a_daemon_log_whose_oldest_day_was_removed_holds_and_says_its_head_is_unchecked() {
    let d = scratch("v1ret");
    let mut evs = plain(2, T0);
    evs.extend(plain(2, T0 + DAY));
    write_log(&d, &evs);
    fs::remove_file(day_file(&d, T0)).unwrap();
    let o = verify::check(&Source::Daemon(d.clone()), None, &[]);
    assert!(o.holds(), "{:?}", o.failure);
    assert!(
        o.notes.iter().any(|n| n.contains("begins at seq 3")),
        "{:?}",
        o.notes
    );
    // The same lines named as a file must begin a chain, or be given a start.
    let f = Source::Files(vec![day_file(&d, T0 + DAY)]);
    assert_eq!(verify::check(&f, None, &[]).failure.unwrap().0, 1);
    let start = o.start_used.clone().unwrap();
    assert!(verify::check(&f, Some(start), &[]).holds());
    let _ = fs::remove_dir_all(&d);
}

/// Case 216: an anchor sees a cut at the end and a whole rewrite; lines
/// added after it are no break (OpenMoat ADR-031's prefix rule).
#[test]
fn an_anchor_shows_a_tail_cut_and_a_rewrite_and_lets_the_log_grow() {
    let d = scratch("anchor216");
    write_log(&d, &plain(4, T0));
    let src = Source::Daemon(d.clone());
    let place = Place::File(d.join("anchors.jsonl"));
    assert_eq!(super::anchor_source(&src, &place, T0 + 9_000), 0);
    let anchors = verify::anchors_for(&place, "daemon").unwrap();
    assert_eq!(anchors[0].seq, 4);
    assert_eq!(
        anchors[0].start,
        Some((1, derm_core::audit_chain::GENESIS.into()))
    );
    assert!(verify::check(&src, None, &anchors).holds());
    // The log grows: still holds.
    write_log(&d, &plain(2, T0 + 10_000));
    assert!(verify::check(&src, None, &anchors).holds());
    // A cut at the end, back past the anchored line: the chain still holds
    // on its own, and only the anchor shows it.
    let f = day_file(&d, T0);
    let keep: Vec<String> = fs::read_to_string(&f)
        .unwrap()
        .lines()
        .take(3)
        .map(String::from)
        .collect();
    fs::write(&f, keep.join("\n") + "\n").unwrap();
    assert!(verify::check(&src, None, &[]).holds());
    let o = verify::check(&src, None, &anchors);
    assert!(o.failure.unwrap().1.contains("ends at seq 3"));
    // A whole rewrite with a fresh chain of as many lines.
    fs::remove_dir_all(d.join("activity")).unwrap();
    let mut other = plain(6, T0);
    other[0].summary = "rewritten".into();
    write_log(&d, &other);
    assert!(verify::check(&src, None, &[]).holds());
    let o = verify::check(&src, None, &anchors);
    assert!(o.failure.unwrap().1.contains("another hash"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn an_anchor_refuses_a_broken_chain_and_an_empty_one() {
    let d = scratch("anchorbad");
    let place = Place::File(d.join("a.jsonl"));
    assert_eq!(
        super::anchor_source(&Source::Daemon(d.clone()), &place, 0),
        1
    );
    write_log(&d, &plain(3, T0));
    let f = day_file(&d, T0);
    let t = fs::read_to_string(&f).unwrap().replace("\"t1\"", "\"tx\"");
    fs::write(&f, t).unwrap();
    assert_eq!(
        super::anchor_source(&Source::Daemon(d.clone()), &place, 0),
        1
    );
    assert!(!d.join("a.jsonl").exists());
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn the_anchor_command_refuses_a_chat_and_a_script_before_reading_anything() {
    let args: Vec<String> = ["--file", "/nonexistent/derm-anchor-test"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let chat = |v: &str| (v == "DERM_CHAT_TOKEN").then(|| "tok".into());
    assert_eq!(super::anchor_main(&args, &chat, true), 2);
    assert_eq!(super::anchor_main(&args, &|_| None, false), 2);
    assert!(!Path::new("/nonexistent/derm-anchor-test").exists());
    let rel: Vec<String> = ["--file", "rel/path"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(super::anchor_main(&rel, &|_| None, true), 2);
}

/// An anchor kept for the head also checks the first line while it is kept
/// (AZ-1's fix shape): a head rewritten so the chain still holds from there
/// on is seen.
#[test]
fn an_anchors_start_shows_a_rewritten_head() {
    let d = scratch("anchorhead");
    let mut evs = plain(2, T0);
    evs.extend(plain(2, T0 + DAY));
    write_log(&d, &evs);
    let src = Source::Daemon(d.clone());
    fs::remove_file(day_file(&d, T0)).unwrap();
    let place = Place::File(d.join("a.jsonl"));
    assert_eq!(super::anchor_source(&src, &place, 0), 0);
    let anchors = verify::anchors_for(&place, "daemon").unwrap();
    assert_eq!(anchors[0].start.as_ref().unwrap().0, 3);
    // The kept day rewritten from a made-up start: it holds as given...
    let f = day_file(&d, T0 + DAY);
    let fake_prev = "c".repeat(64);
    let mut prev = fake_prev.clone();
    let mut lines = Vec::new();
    for (i, e) in plain(2, T0 + DAY).iter().enumerate() {
        let (t, h) = derm_daemon::activity::chain::line(
            3 + i as u64,
            &prev,
            "event",
            &serde_json::to_value(e).unwrap(),
        );
        prev = h;
        lines.push(t);
    }
    fs::write(&f, lines.join("\n") + "\n").unwrap();
    assert!(verify::check(&src, None, &[]).holds());
    // ...and the anchor's start shows it (its head's hash too).
    let o = verify::check(&src, None, &anchors);
    assert!(o.failure.is_some());
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn an_anchor_place_with_another_chains_anchors_needs_chain() {
    let d = scratch("anchorlabel");
    let place = Place::File(d.join("a.jsonl"));
    place
        .append(&Record {
            chain: "light:s-1".into(),
            v: 2,
            seq: 0,
            hash: "a".repeat(64),
            start: None,
            anchored_ms: 0,
        })
        .unwrap();
    let e = verify::anchors_for(&place, "daemon").unwrap_err();
    assert!(e.contains("light:s-1") && e.contains("--chain"), "{e}");
    let _ = fs::remove_dir_all(&d);
}

fn export_to_vec(src: &Source, content: bool) -> (Vec<String>, export::Summary) {
    let mut out = Vec::new();
    let s = export::export(src, content, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    (text.lines().map(String::from).collect(), s)
}

/// The export of the daemon's log carries its v1 lines with `"v": 1` and
/// verifies on its own; floats stay (they would not pass chain v2).
#[test]
fn an_export_of_the_daemons_log_verifies_by_itself() {
    let d = scratch("exp1");
    let mut evs = plain(2, T0);
    evs.extend(plain(2, T0 + DAY));
    write_log(&d, &evs);
    let (lines, s) = export_to_vec(&Source::Daemon(d.clone()), false);
    assert_eq!(s.lines, 4);
    assert_eq!(s.start, None);
    assert!(lines
        .iter()
        .all(|l| l.starts_with("{\"v\":1,") || l.contains("\"v\":1")));
    assert!(lines[0].contains("1.5"));
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let r = chains::read(&refs, None);
    assert!(r.holds(), "{:?}", r.broken);
    assert_eq!(s.head.unwrap().1, r.last().unwrap().hash);
    // After retention, the export says where it starts, and verifies from there.
    fs::remove_file(day_file(&d, T0)).unwrap();
    let (lines, s) = export_to_vec(&Source::Daemon(d.clone()), false);
    let (seq, prev) = s.start.clone().unwrap();
    assert_eq!(seq, 3);
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    assert!(chains::read(&refs, Some((seq, &prev))).holds());
    assert!(!chains::read(&refs, None).holds());
    let _ = fs::remove_dir_all(&d);
}

/// Case 221: an export with content off holds no content, and still
/// verifies; an edit, a cut and a reordering of the export break it.
#[test]
fn an_export_with_content_off_holds_none_and_breaks_on_an_edit_a_cut_and_a_reorder() {
    let d = scratch("exp221");
    let mut evs = plain(4, T0);
    // A record from before the content switch, holding a prompt.
    evs[1].detail = json!({"attributes": {"prompt": "my secret plan", "tool_use_id": "t1"}});
    evs[1].source = Src::Otel;
    write_log(&d, &evs);
    let src = Source::Daemon(d.clone());
    let (lines, s) = export_to_vec(&src, false);
    assert_eq!(s.withheld, 1);
    assert!(!lines.join("\n").contains("my secret plan"));
    assert!(lines[1].contains("\"withheld\":\"content\""));
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let r = chains::read(&refs, None);
    assert!(r.holds(), "{:?}", r.broken);
    assert_eq!(r.withheld, 1);
    // Edited.
    let mut e = lines.clone();
    e[2] = e[2].replace("\"t2\"", "\"t7\"");
    assert_eq!(read_break(&e), Some(3));
    // Cut in the middle.
    let mut c = lines.clone();
    c.remove(2);
    assert_eq!(read_break(&c), Some(3));
    // Reordered.
    let mut o = lines.clone();
    o.swap(2, 3);
    assert_eq!(read_break(&o), Some(3));
    // Asked for, the content is kept.
    let (lines, s) = export_to_vec(&src, true);
    assert_eq!((s.withheld, s.with_content), (0, 1));
    assert!(lines.join("\n").contains("my secret plan"));
    let _ = fs::remove_dir_all(&d);
}

fn read_break(lines: &[String]) -> Option<usize> {
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    chains::read(&refs, None).broken.map(|b| b.line)
}

#[test]
fn an_export_stops_at_a_break_and_says_where() {
    let d = scratch("expbreak");
    write_log(&d, &plain(4, T0));
    let f = day_file(&d, T0);
    let t = fs::read_to_string(&f).unwrap().replace("\"t2\"", "\"tx\"");
    fs::write(&f, t).unwrap();
    let (lines, s) = export_to_vec(&Source::Daemon(d.clone()), false);
    assert_eq!(lines.len(), 2);
    assert!(s.broken.unwrap().contains(":3"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn an_export_of_a_v2_log_is_its_lines() {
    let d = scratch("expv2");
    let f = d.join("s-1.jsonl");
    let mut last = None;
    let mut written = Vec::new();
    for i in 0..3 {
        let (t, l) = derm_core::audit_chain::line(
            last.as_ref(),
            "approval",
            &json!({"id": format!("a{i}"), "chatId": "s-1", "detail": {"toolUseId": format!("t{i}")}}),
        )
        .unwrap();
        written.push(t);
        last = Some(l);
    }
    fs::write(&f, written.join("\n") + "\n").unwrap();
    let (lines, s) = export_to_vec(&Source::Files(vec![f]), false);
    assert_eq!(lines, written);
    assert_eq!(s.withheld, 0);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn an_export_never_replaces_a_file() {
    let d = scratch("expout");
    write_log(&d, &plain(1, T0));
    let out = d.join("out.jsonl");
    fs::write(&out, "mine\n").unwrap();
    let args: Vec<String> = [
        "--data-dir",
        d.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(export::main(&args), 2);
    assert_eq!(fs::read_to_string(&out).unwrap(), "mine\n");
    fs::remove_file(&out).unwrap();
    assert_eq!(export::main(&args), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let _ = fs::remove_dir_all(&d);
}

// --- why ----------------------------------------------------------------

fn call_log(d: &Path) {
    let tap = |at, detail: Value| ev("tap-s-1-toolu_W", at, Src::Tap, "tap.call", "Bash", detail);
    let mut evs = vec![
        // The tap's call, then its result under the same id (case 35).
        tap(
            T0,
            json!({"callId": "toolu_W", "tool": "Bash", "model": "m", "argsBytes": 17, "argsSha256": "ab".repeat(32), "paths": ["/w/a.txt"]}),
        ),
        tap(
            T0 + 900,
            json!({"callId": "toolu_W", "tool": "Bash", "model": "m", "argsBytes": 17, "argsSha256": "ab".repeat(32), "paths": ["/w/a.txt"], "resultBytes": 5, "resultSha256": "cd".repeat(32)}),
        ),
        ev(
            "claude-code-toolu_W-decision-1",
            T0 + 100,
            Src::Adapter,
            "approval",
            "Bash",
            json!({"toolUseId": "toolu_W", "decision": "allow", "reason": "rule bash allow"}),
        ),
        // A second decision for the call, as the daemon keeps it (case 98).
        ev(
            "claude-code-toolu_W-decision-1-conflict-9",
            T0 + 150,
            Src::Adapter,
            "approval",
            "Bash",
            json!({"toolUseId": "toolu_W", "decision": "deny", "conflictsWith": "claude-code-toolu_W-decision-1"}),
        ),
        ev(
            "gate-conflict-1",
            T0 + 150,
            Src::Approval,
            "gate.conflict",
            "two records for the gate decision claude-code-toolu_W-decision-1",
            json!({"id": "claude-code-toolu_W-decision-1", "copy": "claude-code-toolu_W-decision-1-conflict-9"}),
        ),
        ev(
            "claude-code-toolu_W",
            T0 + 800,
            Src::Adapter,
            "tool.call",
            "Bash",
            json!({"toolUseId": "toolu_W", "resultSha256": "cd".repeat(32), "size": 5}),
        ),
        // Case 175: the agent posts first under the id of a write it is about
        // to make; the kernel's record under that id is not kept over it.
        ev(
            "auditd-1-2",
            T0 + 300,
            Src::Adapter,
            "tool.call",
            "\u{1b}[31mnothing to see\u{1b}[0m",
            json!({}),
        ),
        ev(
            "auditd-1-1",
            T0 + 200,
            Src::Auditd,
            "exec",
            "bash -c [12 chars]",
            json!({}),
        ),
        ev(
            "auditd-1-2",
            T0 + 300,
            Src::Auditd,
            "write",
            "/w/a.txt",
            json!({}),
        ),
        ev(
            "join-auditd-1-1",
            T0 + 250,
            Src::Derm,
            "join.candidates",
            "exec fits 1 call",
            json!({"trust": "daemon", "effect": "auditd-1-1", "effectKind": "exec", "candidates": [{"call": "tap-s-1-toolu_W", "by": "tree", "why": "the shell call running"}], "chosen": "tap-s-1-toolu_W"}),
        ),
        ev(
            "join-auditd-1-2",
            T0 + 350,
            Src::Derm,
            "join.candidates",
            "write fits 2 calls",
            json!({"trust": "daemon", "effect": "auditd-1-2", "effectKind": "write", "candidates": [{"call": "tap-s-1-toolu_W", "by": "window", "why": "running"}, {"call": "tap-s-1-toolu_X", "by": "window", "why": "running"}], "chosen": null}),
        ),
        // Another call's record, not this one's.
        ev(
            "claude-code-toolu_X-decision-2",
            T0 + 120,
            Src::Adapter,
            "approval",
            "Read",
            json!({"toolUseId": "toolu_X", "decision": "allow"}),
        ),
    ];
    // Many effects, for the screen's cut.
    for i in 0..12 {
        let id = format!("auditd-2-{i}");
        evs.push(ev(
            &id,
            T0 + 400 + i,
            Src::Auditd,
            "write",
            &format!("/w/f{i}"),
            json!({}),
        ));
        evs.push(ev(&format!("join-{id}"), T0 + 401 + i, Src::Derm, "join.candidates", "write", json!({"trust": "daemon", "effect": id, "effectKind": "write", "candidates": [{"call": "tap-s-1-toolu_W", "by": "tree", "why": "tree"}], "chosen": "tap-s-1-toolu_W"})));
    }
    write_log(d, &evs);
}

fn recs(d: &Path) -> Vec<why::Rec> {
    let back =
        derm_daemon::activity::store::read(&d.join("activity"), 0, i64::MAX, Some("s-1"), 10_000);
    assert!(back.chain_ok);
    back.events
        .iter()
        .map(|e| why::Rec {
            id: e.id.clone(),
            at: e.at,
            chat: e.chat_id.clone(),
            harness: e.harness.clone(),
            source: serde_json::to_value(e.source)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
            kind: e.kind.clone(),
            summary: e.summary.clone(),
            detail: e.detail.clone(),
            from: "daemon",
        })
        .collect()
}

#[test]
fn why_shows_intent_decision_and_effects_with_their_candidates() {
    let d = scratch("why");
    call_log(&d);
    let f = why::find("toolu_W", "s-1", &recs(&d));
    // Case 35: the tap's second copy replaced its first.
    assert_eq!(f.intent.len(), 1);
    assert_eq!(f.intent[0].detail["resultBytes"], 5);
    // Case 98: both decisions, the copy marked.
    assert_eq!(f.decisions.len(), 2);
    assert_eq!(f.flags.len(), 1);
    assert_eq!(f.ran.len(), 1);
    assert_eq!(f.effects.len(), 14);
    let exec = f
        .effects
        .iter()
        .find(|e| e.join.id == "join-auditd-1-1")
        .unwrap();
    assert_eq!(exec.chosen, "this");
    assert_eq!(exec.record.as_ref().unwrap().source, "auditd");
    let write = f
        .effects
        .iter()
        .find(|e| e.join.id == "join-auditd-1-2")
        .unwrap();
    assert_eq!((write.chosen, write.candidates), ("none", 2));
    // Case 175: the agent's record under the kernel's id is not shown as the effect.
    let why_missing = write.record.as_ref().unwrap_err();
    assert!(
        why_missing.contains("held by source adapter"),
        "{why_missing}"
    );
    let screen = why::render(&f, false, &[]);
    assert!(!screen.contains("nothing to see"));
    assert!(!screen.contains('\u{1b}'));
    assert!(screen.contains("conflict copy"));
    assert!(screen.contains("one of 2 candidates, none chosen"));
    // One screen: the effects are cut, and the cut says how many it left out.
    assert!(screen.lines().count() <= 24, "{screen}");
    assert!(screen.contains("+6 more"), "{screen}");
    assert!(screen.lines().all(|l| l.chars().count() <= why::WIDTH + 9));
    let all = why::render(&f, true, &[]);
    assert!(all.lines().count() > screen.lines().count());
    assert!(!all.contains("more (derm audit why"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn why_reads_the_log_from_disk_and_answers_one_for_a_call_it_does_not_know() {
    let d = scratch("whymain");
    call_log(&d);
    let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let dd = d.to_str().unwrap();
    assert_eq!(why::main(&a(&["toolu_W", "--data-dir", dd])), 0);
    assert_eq!(
        why::main(&a(&[
            "toolu_W",
            "--data-dir",
            dd,
            "--json",
            "--chat",
            "s-1"
        ])),
        0
    );
    assert_eq!(why::main(&a(&["toolu_NONE", "--data-dir", dd])), 1);
    assert_eq!(why::main(&a(&["toolu_W", "--data-dir", "relative"])), 2);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn why_reads_a_light_tier_log_under_its_chain() {
    let d = scratch("whylight");
    let f = d.join("s-1.jsonl");
    let mut last = None;
    let mut lines = Vec::new();
    for (kind, r) in [
        (
            "approval",
            json!({"id": "claude-code-toolu_L-decision-1", "at": T0, "chatId": "s-1", "harness": "claude-code", "detail": {"toolUseId": "toolu_L", "decision": "ask"}}),
        ),
        (
            "tool.call",
            json!({"id": "claude-code-toolu_L", "at": T0 + 5, "chatId": "s-1", "harness": "claude-code", "detail": {"toolUseId": "toolu_L"}}),
        ),
    ] {
        let (t, l) = derm_core::audit_chain::line(last.as_ref(), kind, &r).unwrap();
        lines.push(t);
        last = Some(l);
    }
    fs::write(&f, lines.join("\n") + "\n").unwrap();
    let (rs, broken) = why::light_records(&f);
    assert!(broken.is_none());
    let found = why::find("toolu_L", "s-1", &rs);
    assert_eq!((found.decisions.len(), found.ran.len()), (1, 1));
    assert!(why::render(&found, false, &[]).contains("light log"));
    // A broken light log is read only up to its break.
    let t = fs::read_to_string(&f)
        .unwrap()
        .replace("\"ask\"", "\"allow\"");
    fs::write(&f, t).unwrap();
    let (rs, broken) = why::light_records(&f);
    assert!(rs.is_empty() && broken.is_some());
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn clean_drops_escapes_and_bidirectional_controls_and_time_is_utc() {
    assert_eq!(why::clean("a\u{1b}[2Jb\u{202e}c\nd", 50), "a [2Jb c d");
    assert_eq!(why::clean("abcdef", 4), "abc…");
    assert_eq!(why::time(T0 + 1_234), "2025-11-12T08:00:01.234Z");
}

#[test]
fn the_dispatch_answers_usage_for_nothing_and_an_unknown_verb() {
    assert_eq!(super::main(&[]), 2);
    assert_eq!(super::main(&["nope".to_string()]), 2);
    assert_eq!(
        super::main(&["export".to_string(), "--ocsf".to_string()]),
        2
    );
}
