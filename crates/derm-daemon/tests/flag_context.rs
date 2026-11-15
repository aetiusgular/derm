//! Fix pass 4's second re-review, R2-3: the reviewer's tests, failing first:
//! a flag's own event is always in its context.

use std::collections::{HashMap, HashSet};

use derm_daemon::activity::check::{run_full, ChatContext, CheckInput};
use derm_daemon::activity::types::{ActivityEvent, ActivitySource};
use serde_json::json;

fn ev(id: &str, source: ActivitySource, kind: &str, detail: serde_json::Value) -> ActivityEvent {
    ActivityEvent {
        id: id.into(),
        at: 1_000,
        chat_id: "chat-a".into(),
        harness: "pi".into(),
        source,
        kind: kind.into(),
        summary: String::new(),
        detail,
        pid: Some(77),
        approval_id: None,
    }
}

/// A flag's context is its 20 nearest events (`check::context_ids`); more
/// than 20 events in the same millisecond, ordered before the flagged one,
/// leave the flagged event out of its own context, so it is not in
/// `check.events`, and `fit_report_with` cannot see its source or its
/// guarded path. One OTLP post's records all take one receive time.
#[test]
fn r2_3_a_flags_own_event_is_always_in_its_context() {
    let mut events: Vec<ActivityEvent> = (0..25)
        .map(|i| {
            ev(
                &format!("otel-{i}"),
                ActivitySource::Otel,
                "otel.x",
                json!({}),
            )
        })
        .collect();
    events.push(ev(
        "auditd-real",
        ActivitySource::Auditd,
        "write",
        json!({"path": "/data/activity/2026-11-06.jsonl", "tier": "child"}),
    ));
    let mut chats = HashMap::new();
    chats.insert(
        "chat-a".to_string(),
        ChatContext {
            chat_id: "chat-a".into(),
            harness: "pi".into(),
            folders: vec!["/home/t/proj".into()],
        },
    );
    let out = run_full(&CheckInput {
        events: &events,
        approvals: &[],
        chats: &chats,
        known_hosts: &HashSet::new(),
        now_ms: 2_000,
        data_dir: Some("/data"),
    });
    let flag = out
        .flags
        .iter()
        .find(|f| f.event_id == "auditd-real")
        .expect("the guarded write is flagged");
    assert!(
        flag.context.contains(&flag.event_id),
        "the flagged event is not in its own context: {:?}",
        flag.context
    );
}

/// R2-3, the chat token's side: its own adapter records naming hosts, more
/// than 20 in one millisecond, give `newHost` flags whose events are not in
/// their own context, so the cut reads them as records a chat token cannot
/// post and puts them in the OS-feed bucket.
#[test]
fn r2_3b_a_chat_tokens_flags_keep_their_own_event() {
    let events: Vec<ActivityEvent> = (0..25)
        .map(|i| {
            ev(
                &format!("a-{i}"),
                ActivitySource::Adapter,
                "tool.call",
                json!({"host": format!("h{i}.example.net")}),
            )
        })
        .collect();
    let out = run_full(&CheckInput {
        events: &events,
        approvals: &[],
        chats: &HashMap::new(),
        known_hosts: &HashSet::new(),
        now_ms: 2_000,
        data_dir: None,
    });
    let lost: Vec<&str> = out
        .flags
        .iter()
        .filter(|f| !f.context.contains(&f.event_id))
        .map(|f| f.event_id.as_str())
        .collect();
    assert_eq!(out.flags.len(), 25);
    assert!(lost.is_empty(), "flags without their own event: {lost:?}");
}
