//! The feed over the recorded Sysmon events in `tests/windows/fixtures/
//! sysmon/chat.xml` (see that folder's README for what each record is).
//! Runs on every platform: the XML reader and the tree are plain Rust.

use derm_audit_windows::feed::{inside_folders, Feed, Root};
use derm_audit_windows::sysmon::{self, What};
use derm_audit_windows::xml;
use derm_core::event::{Event, Source};

fn fixture() -> Vec<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/windows/fixtures/sysmon/chat.xml"
    );
    std::fs::read_to_string(path)
        .expect("fixture")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn root(started_ms: i64) -> Root {
    Root {
        chat: "c1".into(),
        harness: "codex".into(),
        pid: 4100,
        started_ms,
        folders: vec![r"C:\work\proj".into()],
    }
}

/// 2026-11-05 09:30:00.100 UTC, the harness's creation (record 101).
const HARNESS_AT: i64 = 1_793_871_000_100;

fn run(feed: &mut Feed, lines: &[String]) -> Vec<Event> {
    lines.iter().flat_map(|l| feed.push_xml(l)).collect()
}

fn ids(events: &[Event]) -> Vec<&str> {
    events.iter().map(|e| e.id.as_str()).collect()
}

#[test]
fn every_fixture_line_parses_and_sysmon_reads_its_own() {
    let lines = fixture();
    assert_eq!(lines.len(), 13);
    let mut read = 0;
    for l in &lines {
        let e = xml::parse(l).expect("parses");
        if sysmon::read(&e).is_some() {
            read += 1;
        }
    }
    // 106 (inbound) and 113 (another provider) are not read.
    assert_eq!(read, 11);
}

#[test]
fn a_chat_registered_after_its_harness_started_gets_its_tree() {
    let lines = fixture();
    let mut feed = Feed::new(Source::Derm);
    // Sysmon logs the creation before derm run posts run.start.
    assert!(run(&mut feed, &lines[..1]).is_empty(), "no chat yet");
    feed.register(root(HARNESS_AT + 400));
    let out = run(&mut feed, &lines[1..]);
    assert_eq!(
        ids(&out),
        vec![
            "sysmon-102",
            "sysmon-103",
            "sysmon-104",
            "sysmon-105",
            "sysmon-107",
            "sysmon-109",
            "sysmon-112"
        ]
    );
    for e in &out {
        assert_eq!(e.chat_id, "c1");
        assert_eq!(e.harness, "codex");
        assert_eq!(e.source, Source::Derm);
    }
    let by = |id: &str| out.iter().find(|e| e.id == id).unwrap();
    let exec = by("sysmon-102");
    assert_eq!(exec.kind, "exec");
    assert_eq!(exec.pid, Some(4200));
    assert_eq!(
        exec.detail["parentGuid"],
        "{a1a1a1a1-0000-0000-0000-000000004100}"
    );
    // The command line's length only, never its words (case 85).
    let text = serde_json::to_string(exec).unwrap();
    assert!(!text.contains("SECRET"), "{text}");
    assert_eq!(
        exec.detail["commandLineBytes"],
        "cmd /c echo sk-SECRET-not-kept & dir".len()
    );

    assert_eq!(by("sysmon-103").kind, "create");
    assert!(by("sysmon-103").detail.get("writeOutside").is_none());
    assert_eq!(by("sysmon-104").detail["writeOutside"], true);
    let net = by("sysmon-105");
    assert_eq!(net.kind, "net.connect");
    assert_eq!(net.detail["host"], "github.com:443");
    assert_eq!(net.detail["addr"], "140.82.112.3");
    assert_eq!(by("sysmon-107").kind, "dns");
    assert_eq!(by("sysmon-107").detail["query"], "api.openai.com");
    assert_eq!(by("sysmon-109").kind, "exit");
    // Another spelling of the chat's folder is still inside it.
    let del = by("sysmon-112");
    assert_eq!(del.kind, "unlink");
    assert!(del.detail.get("writeOutside").is_none());
}

#[test]
fn a_reused_pid_is_not_the_chat() {
    let lines = fixture();
    let mut feed = Feed::new(Source::Derm);
    feed.register(root(HARNESS_AT - 200));
    let out = run(&mut feed, &lines);
    // 110 and 111 are another process with the shell's old pid 4200.
    assert!(!ids(&out).contains(&"sysmon-110"));
    assert!(!ids(&out).contains(&"sysmon-111"));
    assert_eq!(feed.chat_of("{c3c3c3c3-0000-0000-0000-000000004200}"), None);
    // The shell left at its exit; the harness stays.
    assert_eq!(feed.chat_of("{b2b2b2b2-0000-0000-0000-000000004200}"), None);
    assert_eq!(
        feed.chat_of("{a1a1a1a1-0000-0000-0000-000000004100}"),
        Some("c1")
    );
}

#[test]
fn a_chat_whose_creation_was_not_seen_adopts_the_next_event_of_its_pid() {
    let lines = fixture();
    let mut feed = Feed::new(Source::Derm);
    // A start an hour later than the creation: outside the window, so the
    // chat waits for the next event from pid 4100.
    feed.register(root(HARNESS_AT + 3_600_000));
    assert_eq!(feed.chat_of("{a1a1a1a1-0000-0000-0000-000000004100}"), None);
    let out = run(&mut feed, &lines);
    assert_eq!(ids(&out)[0], "sysmon-101");
    assert_eq!(
        feed.chat_of("{a1a1a1a1-0000-0000-0000-000000004100}"),
        Some("c1")
    );
}

#[test]
fn an_unregistered_chat_reports_nothing_more() {
    let lines = fixture();
    let mut feed = Feed::new(Source::Derm);
    feed.register(root(HARNESS_AT));
    let first = run(&mut feed, &lines[..3]);
    assert_eq!(ids(&first), vec!["sysmon-101", "sysmon-102", "sysmon-103"]);
    feed.unregister("c1");
    assert!(run(&mut feed, &lines[3..]).is_empty());
}

#[test]
fn an_unrelated_process_is_never_reported() {
    let lines = fixture();
    let mut feed = Feed::new(Source::Derm);
    let out = run(&mut feed, &lines);
    assert!(out.is_empty(), "no chat registered: {:?}", ids(&out));
    let e = xml::parse(&lines[7]).unwrap();
    let a = sysmon::read(&e).unwrap();
    assert!(matches!(a.what, What::Exec { .. }));
    assert_eq!(a.image, r"C:\Windows\explorer.exe");
}

#[test]
fn folders_compare_as_windows_does() {
    let f = vec![r"C:\Work\Proj\".to_string()];
    assert!(inside_folders(r"c:\work\proj\a.txt", &f));
    assert!(inside_folders("C:/work/proj/sub/b", &f));
    assert!(inside_folders(r"\\?\C:\work\proj\x", &f));
    assert!(inside_folders(r"C:\work\proj", &f));
    assert!(
        !inside_folders(r"C:\work\project2\a", &f),
        "a prefix is not a parent"
    );
    assert!(!inside_folders(r"D:\work\proj\a", &f));
    assert!(
        !inside_folders(r"C:\a", &[String::new()]),
        "an empty folder holds nothing"
    );
}
