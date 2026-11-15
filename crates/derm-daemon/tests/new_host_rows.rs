//! Fix pass 4's third re-review, R3-2: the reviewer's test, failing first: a
//! record a chat token posts first never takes the kernel's new-host row.

use std::collections::{HashMap, HashSet};

use derm_daemon::activity::check::{run_full, CheckInput};
use derm_daemon::activity::types::{ActivityEvent, ActivitySource};
use serde_json::json;

fn ev(id: &str, at: i64, source: ActivitySource, kind: &str, host: &str) -> ActivityEvent {
    ActivityEvent {
        id: id.into(),
        at,
        chat_id: "chat-a".into(),
        harness: "pi".into(),
        source,
        kind: kind.into(),
        summary: String::new(),
        detail: json!({"host": host}),
        pid: Some(77),
        approval_id: None,
    }
}

/// A new host is flagged once per chat (`flagged_hosts`), on the first
/// record that names it. A chat token names the host first in an adapter
/// record; the kernel feed's own connection to it is then not flagged, and
/// the one row there is is `chatPostable`, ranked with the chat's flood.
#[test]
fn r3_2_a_kernel_connection_to_a_new_host_keeps_an_os_feed_row() {
    let events = vec![
        ev(
            "adapter-1",
            1_000,
            ActivitySource::Adapter,
            "tool.call",
            "exfil.example.net",
        ),
        ev(
            "auditd-real",
            2_000,
            ActivitySource::Auditd,
            "connect",
            "exfil.example.net",
        ),
    ];
    let out = run_full(&CheckInput {
        events: &events,
        approvals: &[],
        chats: &HashMap::new(),
        known_hosts: &HashSet::new(),
        now_ms: 3_000,
        data_dir: None,
    });
    let rows: Vec<(String, bool)> = out
        .flags
        .iter()
        .map(|f| (f.event_id.clone(), f.chat_postable))
        .collect();
    assert!(
        out.flags
            .iter()
            .any(|f| !f.chat_postable && f.summary.contains("exfil")),
        "the only rows for the host: {rows:?}"
    );
}
