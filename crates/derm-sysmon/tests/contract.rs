//! Lane 5bE's red test (the wave 5b base): `derm-sysmon decode` turns the
//! recorded Sysmon events (`tests/windows/fixtures/sysmon/chat.xml`) into
//! the records the daemon ingests (`contracts/sysmon-service.md` section
//! 4), on every OS. Built with `--features w5b-red`.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn decode_turns_the_recorded_events_into_records() {
    let xml = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/windows/fixtures/sysmon/chat.xml"
    ))
    .unwrap();
    let events = xml.lines().filter(|l| !l.trim().is_empty()).count();
    let mut child = Command::new(env!("CARGO_BIN_EXE_derm-sysmon"))
        .arg("decode")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(xml.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        !lines.is_empty() && lines.len() <= events,
        "{} of {events}",
        lines.len()
    );
    assert!(lines
        .iter()
        .all(|l| l["recordId"].is_u64() && l["event"]["source"].is_string()));
}
