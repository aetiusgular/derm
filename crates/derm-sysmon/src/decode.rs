//! `derm-sysmon decode` (`contracts/sysmon-service.md` section 4): Sysmon
//! event XML on stdin, one event a line, out as the records the daemon would
//! ingest, `{"recordId","event"}`, one a line. It opens no pipe and needs no
//! rights.
//!
//! Each event goes through the same code the daemon's feed runs (lane Z's
//! `Feed` and this crate's argv split), for a stand-in chat that owns every
//! process: decode knows no chat and no folder, so it registers each
//! process as its own root and leaves out the folder check's `writeOutside`.
//! An exec's argv is shaped as the daemon's ingest shapes it (case 168):
//! nothing printed holds a command line's words. A line that is not a
//! Sysmon event the feed reads prints nothing.

use std::io::{self, BufRead, Write};

use derm_audit_windows::feed::{Feed, Root};
use derm_audit_windows::sysmon;
use derm_audit_windows::xml;
use derm_core::event::Event;
use serde_json::{json, Value};

use crate::cmdline;
use crate::ingest::SOURCE;

/// The stand-in chat decode attributes everything to.
pub const CHAT: &str = "decode";

/// The records for the events in `lines`.
pub fn records<'a>(lines: impl IntoIterator<Item = &'a str>) -> Vec<(u64, Event)> {
    let mut feed = Feed::new(SOURCE);
    let mut out = Vec::new();
    for line in lines {
        let Some(e) = xml::parse(line) else { continue };
        let Some(record) = e.record_id else { continue };
        let Some(a) = sysmon::read(&e) else { continue };
        if feed.chat_of(&a.guid).is_none() {
            // A start no creation is near, so the feed takes this event's
            // own guid for the pid, never an older process's that had it.
            feed.unregister(CHAT);
            feed.register(Root {
                chat: CHAT.into(),
                harness: String::new(),
                pid: a.pid,
                started_ms: i64::MIN / 4,
                folders: Vec::new(),
            });
        }
        for mut ev in feed.push(&a, Some(record)) {
            if let Value::Object(d) = &mut ev.detail {
                d.remove("writeOutside");
            }
            if ev.kind == "exec" {
                shape_exec(&mut ev, e.data.get("CommandLine").map(String::as_str));
            }
            out.push((record, ev));
        }
    }
    out
}

/// The daemon's `shape_exec` for one exec: the argv's shape in `detail` and
/// in the summary.
fn shape_exec(ev: &mut Event, line: Option<&str>) {
    let Some(line) = line else {
        ev.summary = "exec".into();
        return;
    };
    let shaped = derm_core::argv::shape(&cmdline::split(line));
    ev.summary = format!("exec {}", shaped.join(" "))
        .chars()
        .take(200)
        .collect();
    if let Value::Object(d) = &mut ev.detail {
        d.insert("argv".into(), json!(shaped));
        d.insert("argvShaped".into(), Value::Bool(true));
    }
}

/// Reads stdin, writes stdout. An unreadable input is an error.
pub fn run(input: impl BufRead, mut out: impl Write) -> io::Result<()> {
    let mut lines = Vec::new();
    for line in input.lines() {
        let line = line?;
        if line.len() > xml::MAX_EVENT {
            continue;
        }
        lines.push(line);
    }
    for (record, ev) in records(lines.iter().map(String::as_str)) {
        writeln!(out, "{}", json!({"recordId": record, "event": ev}))?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/windows/fixtures/sysmon/chat.xml"
        ))
        .unwrap()
    }

    #[test]
    fn handwritten_decode_prints_every_event_the_feed_reads_and_no_argv_word() {
        let text = fixture();
        let recs = records(text.lines());
        // 106 (inbound) and 113 (another provider) are not read.
        assert_eq!(recs.len(), 11);
        assert!(recs.iter().all(|(_, e)| e.chat_id == CHAT));
        assert!(recs
            .iter()
            .all(|(_, e)| e.detail.get("writeOutside").is_none()));
        let exec = &recs[0].1;
        assert_eq!(exec.kind, "exec");
        assert_eq!(exec.detail["argvShaped"], true);
        assert_eq!(exec.detail["argv"], json!(["node", "[46 chars]"]));
        let mut out = Vec::new();
        run(text.as_bytes(), &mut out).unwrap();
        let printed = String::from_utf8(out).unwrap();
        assert!(!printed.contains("codex.js"));
        assert_eq!(printed.lines().count(), 11);
    }
}
