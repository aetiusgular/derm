//! The Windows OS feed in the daemon (wave 5b, lane 5bE;
//! `contracts/sysmon-service.md` section 3). The daemon cannot read
//! Sysmon's channel itself (Windows test w5, WW5-9: Event Log Readers,
//! administrators and a few system accounts only), so it is a client of the
//! `derm-sysmon` service, which sends it this user's events.
//!
//! All the logic is `derm_sysmon` (`client`, `ingest`), tested there; this
//! module gives it the daemon: `derm run`'s records, the running chats, the
//! ingest, and `report.osFeed`'s state.
//!
//! Integration wires it (lane 5bE's requests): `pub mod sysmon_feed;` in
//! `platform/windows/mod.rs`, [`start`] beside the collector's start in
//! `main.rs`, [`state`] in `Daemon::os_feed_state` on Windows, a `feed.gap`
//! noted in `ingest` as `op_event` notes it, and the chats' folders in
//! `Daemon::running`'s rows.

use std::sync::mpsc::Receiver;
use std::sync::{Arc, OnceLock};

use derm_core::event::{Event, Source};
use derm_sysmon::client::{self, Sink, Status};
use serde_json::{json, Value};

use crate::daemon::Daemon;

static STATUS: OnceLock<Arc<Status>> = OnceLock::new();

struct DaemonSink(Arc<Daemon>);

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// A running chat's row (`Daemon::running`) as the `run.start` the feed
/// registers from. Folders come when the row carries them (a request for
/// integration); without them every create in the chat is marked outside
/// its folders, which says too much, never too little.
fn run_start_of(row: &Value) -> Option<Event> {
    let chat = row.get("chat")?.as_str()?.to_string();
    let pid = u32::try_from(row.get("pid")?.as_u64()?).ok()?;
    if row.get("alive").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    Some(Event {
        id: format!("sysmon-running-{chat}"),
        at: row.get("since").and_then(Value::as_i64).unwrap_or(0),
        chat_id: chat,
        harness: row
            .get("harness")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        source: Source::Run,
        kind: "run.start".into(),
        summary: String::new(),
        detail: json!({"folders": row.get("folders").cloned().unwrap_or(json!([]))}),
        pid: Some(pid),
        approval_id: None,
    })
}

impl Sink for DaemonSink {
    fn runs(&self) -> Receiver<Event> {
        self.0.watch_runs()
    }

    fn running(&self) -> Vec<Event> {
        self.0.running().iter().filter_map(run_start_of).collect()
    }

    fn ingest(&self, e: Event) {
        self.0.ingest(e);
    }

    fn now_ms(&self) -> i64 {
        now_ms()
    }
}

/// Starts the feed for the daemon's life (once).
pub fn start(daemon: &Arc<Daemon>) {
    let status = STATUS.get_or_init(|| Arc::new(Status::default())).clone();
    let sink: Arc<dyn Sink> = Arc::new(DaemonSink(daemon.clone()));
    client::spawn(sink, status);
}

/// The feed's state for `report.osFeed`: `attached`, `stopped` or `none`.
pub fn state() -> Value {
    match STATUS.get() {
        Some(s) => s.state(),
        None => json!({"state": "none", "feed": "sysmon"}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_row_becomes_a_run_start_and_a_dead_one_does_not() {
        let e = run_start_of(&json!({"chat": "c1", "pid": 4100, "alive": true,
            "harness": "codex", "since": 5, "folders": ["C:\\w"]}))
        .unwrap();
        assert_eq!((e.kind.as_str(), e.pid, e.at), ("run.start", Some(4100), 5));
        assert_eq!(e.detail["folders"], json!(["C:\\w"]));
        assert!(run_start_of(&json!({"chat": "c1", "pid": 1, "alive": false})).is_none());
        assert!(run_start_of(&json!({"pid": 1})).is_none());
    }

    #[test]
    fn before_start_the_state_is_none() {
        assert_eq!(state()["state"], "none");
    }
}
