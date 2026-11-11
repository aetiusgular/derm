//! The daemon's side of the pipe, without the pipe: what the daemon does
//! with each line the service sends and with each `derm run` record
//! (`contracts/sysmon-service.md` section 3). Plain Rust, tested on every
//! OS; `crates/derm-daemon/src/platform/windows/sysmon_feed/` drives it
//! over the pipe.
//!
//! The chat tree is lane Z's [`Feed`] (by `ProcessGuid`, from `run.start`'s
//! pid). This adds:
//! - the argv of an exec, split from Sysmon's `CommandLine` by the C
//!   runtime's rules, which the daemon's ingest shapes before anything is
//!   kept (case 168), as it does auditd's and eslogger's;
//! - a `claim` for each chat's root, so the service also sends the chat's
//!   sandbox-account processes (an srt chat, case 233);
//! - an `ack` after each batch;
//! - a `feed.gap` record for each gap the service names (case 209);
//! - a stopped chat kept until an OS event stamped after its stop arrives,
//!   at most 10 minutes (case 205's rule), since Sysmon's events can come
//!   after `run.stop`.

use std::collections::{HashMap, HashSet, VecDeque};

use derm_audit_windows::feed::{Feed, Root};
use derm_audit_windows::sysmon::{self, What};
use derm_audit_windows::xml;
use derm_core::event::{Event, Source};
use serde_json::{json, Value};

use crate::cmdline;
use crate::wire::{FromDaemon, FromService, Record};

/// The source the Windows feed's records carry. `contracts/events.md` has
/// no `sysmon` source yet (lane Z's request 3); until integration adds it,
/// they carry `auditd`'s, so the daemon's ingest shapes their argv, keeps
/// one copy per id, and the join and the install flags read them as OS
/// records. Their ids (`sysmon-<record id>`) say where they came from.
pub const SOURCE: Source = Source::Auditd;

/// How long a stopped chat is kept for late events, by the daemon's clock.
pub const KEEP_STOPPED_MS: i64 = 10 * 60_000;
/// An OS event this much later than a chat's stop shows the feed has passed
/// it (clocks of two processes on one machine).
pub const PASSED_MS: i64 = 5_000;
/// How many recent process creations are kept to find a root's guid.
const RECENT: usize = 4_096;

/// What the daemon does next.
#[derive(Debug, PartialEq)]
pub enum Out {
    /// Ingest this record.
    Ingest(Event),
    /// Send this line to the service.
    Send(FromDaemon),
}

#[derive(Default)]
pub struct Ingest {
    feed: Feed,
    /// chat -> its root's pid.
    roots: HashMap<String, u32>,
    /// (pid, guid) of recent process creations, newest last.
    execs: VecDeque<(u32, String)>,
    /// Root guids already claimed.
    claimed: HashSet<String>,
    /// Stopped chats waiting for their late events: (chat, stop, daemon
    /// time of the stop).
    stopping: Vec<(String, i64)>,
    /// The Sysmon time of the last event read, for a gap's start.
    last_os_ms: Option<i64>,
}

fn strings(e: &Event, key: &str) -> Vec<String> {
    e.detail
        .get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

impl Ingest {
    pub fn new() -> Ingest {
        Ingest {
            feed: Feed::new(SOURCE),
            ..Ingest::default()
        }
    }

    /// A `derm run` record the daemon took (`run.start`, `run.stop`).
    pub fn on_run(&mut self, e: &Event) -> Vec<Out> {
        if e.source != Source::Run || e.chat_id.is_empty() {
            return Vec::new();
        }
        match e.kind.as_str() {
            "run.start" => {
                let Some(pid) = e.pid else { return Vec::new() };
                // A chat registered again (a reused pid) starts over.
                self.stopping.retain(|(c, _)| *c != e.chat_id);
                self.feed.unregister(&e.chat_id);
                self.feed.register(Root {
                    chat: e.chat_id.clone(),
                    harness: e.harness.clone(),
                    pid,
                    started_ms: e.at,
                    folders: strings(e, "folders"),
                });
                self.roots.insert(e.chat_id.clone(), pid);
                self.claims_for(&e.chat_id)
            }
            "run.stop" => {
                if self.roots.contains_key(&e.chat_id) {
                    self.stopping.retain(|(c, _)| *c != e.chat_id);
                    self.stopping.push((e.chat_id.clone(), e.at));
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// The daemon's clock moved: chats stopped longer than the keep go.
    pub fn tick(&mut self, now_ms: i64) {
        let gone: Vec<String> = self
            .stopping
            .iter()
            .filter(|(_, at)| now_ms - at > KEEP_STOPPED_MS)
            .map(|(c, _)| c.clone())
            .collect();
        for chat in gone {
            self.drop_chat(&chat);
        }
    }

    fn drop_chat(&mut self, chat: &str) {
        self.stopping.retain(|(c, _)| c != chat);
        self.feed.unregister(chat);
        self.roots.remove(chat);
    }

    /// Claims for a chat's root, when its guid is known.
    fn claims_for(&mut self, chat: &str) -> Vec<Out> {
        let Some(pid) = self.roots.get(chat).copied() else {
            return Vec::new();
        };
        let found: Vec<String> = self
            .execs
            .iter()
            .rev()
            .filter(|(p, g)| *p == pid && self.feed.chat_of(g) == Some(chat))
            .map(|(_, g)| g.clone())
            .take(1)
            .collect();
        let mut out = Vec::new();
        for guid in found {
            if self.claimed.insert(guid.clone()) {
                out.push(Out::Send(FromDaemon::Claim {
                    process_guid: guid,
                    chat: chat.to_string(),
                }));
            }
        }
        out
    }

    /// A line the service sent, parsed.
    pub fn on_service(&mut self, line: FromService, now_ms: i64) -> Vec<Out> {
        match line {
            FromService::Events(records) => self.on_records(records),
            FromService::Gap { from, to, reason } => {
                vec![Out::Ingest(self.gap(from, to, &reason, now_ms))]
            }
            FromService::Reply(_) => Vec::new(),
        }
    }

    fn gap(&self, from: u64, to: u64, reason: &str, now_ms: i64) -> Event {
        Event {
            id: format!("sysmon-gap-{from}-{to}"),
            at: 0,
            chat_id: String::new(),
            harness: String::new(),
            source: SOURCE,
            kind: "feed.gap".into(),
            summary: format!("the Windows feed could not read records {from} to {to}"),
            detail: json!({
                "fromRecord": from,
                "toRecord": to,
                // From the last event read before it; none read: any time.
                "fromMs": self.last_os_ms,
                "toMs": now_ms,
                "reason": reason.chars().take(200).collect::<String>(),
                "feed": "sysmon",
            }),
            pid: None,
            approval_id: None,
        }
    }

    fn on_records(&mut self, records: Vec<Record>) -> Vec<Out> {
        let mut out = Vec::new();
        let mut last = None;
        for r in records {
            last = Some(r.record_id);
            let Some(e) = xml::parse(&r.xml) else {
                continue;
            };
            let Some(a) = sysmon::read(&e) else { continue };
            if let Some(at) = a.at_ms {
                self.last_os_ms = Some(self.last_os_ms.map_or(at, |l| l.max(at)));
                self.passed(at);
            }
            if matches!(a.what, What::Exec { .. }) {
                if self.execs.len() == RECENT {
                    self.execs.pop_front();
                }
                self.execs.push_back((a.pid, a.guid.clone()));
            }
            for mut ev in self.feed.push(&a, Some(r.record_id)) {
                if ev.kind == "exec" {
                    if let (Some(line), Value::Object(d)) =
                        (e.data.get("CommandLine"), &mut ev.detail)
                    {
                        d.insert("argv".into(), json!(cmdline::split(line)));
                    }
                }
                out.push(Out::Ingest(ev));
            }
            if matches!(a.what, What::Exec { .. }) {
                if let Some(chat) = self.feed.chat_of(&a.guid).map(str::to_string) {
                    if self.roots.get(&chat) == Some(&a.pid) {
                        out.extend(self.claims_for(&chat));
                    }
                }
            }
        }
        if let Some(id) = last {
            out.push(Out::Send(FromDaemon::Ack { record_id: id }));
        }
        out
    }

    /// An OS event stamped `at` arrived: stopped chats it is well past go.
    fn passed(&mut self, at: i64) {
        let gone: Vec<String> = self
            .stopping
            .iter()
            .filter(|(_, stop)| at > stop + PASSED_MS)
            .map(|(c, _)| c.clone())
            .collect();
        for chat in gone {
            self.drop_chat(&chat);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hand-written fixture (lane Z; its README): not captured.
    fn fixture() -> Vec<Record> {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/windows/fixtures/sysmon/chat.xml"
        ))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| Record {
            record_id: xml::parse(l).and_then(|e| e.record_id).unwrap(),
            xml: l.to_string(),
        })
        .collect()
    }

    /// 2026-11-05 09:30:00.100 UTC, the fixture harness's creation.
    const HARNESS_AT: i64 = 1_793_871_000_100;

    fn run(kind: &str, at: i64) -> Event {
        Event {
            id: format!("run-{kind}"),
            at,
            chat_id: "c1".into(),
            harness: "codex".into(),
            source: Source::Run,
            kind: kind.into(),
            summary: String::new(),
            detail: json!({"folders": [r"C:\work\proj"]}),
            pid: Some(4100),
            approval_id: None,
        }
    }

    fn ingested(out: &[Out]) -> Vec<&Event> {
        out.iter()
            .filter_map(|o| match o {
                Out::Ingest(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn handwritten_a_chats_tree_is_ingested_its_root_claimed_and_the_batch_acked() {
        let mut ing = Ingest::new();
        assert!(ing.on_run(&run("run.start", HARNESS_AT + 500)).is_empty());
        let out = ing.on_service(FromService::Events(fixture()), HARNESS_AT + 9_000);
        let events = ingested(&out);
        assert!(!events.is_empty());
        assert!(events
            .iter()
            .all(|e| e.chat_id == "c1" && e.source == SOURCE));
        assert!(events.iter().all(|e| e.id.starts_with("sysmon-")));
        let claims: Vec<&Out> = out
            .iter()
            .filter(|o| matches!(o, Out::Send(FromDaemon::Claim { .. })))
            .collect();
        assert_eq!(
            claims,
            vec![&Out::Send(FromDaemon::Claim {
                process_guid: "{a1a1a1a1-0000-0000-0000-000000004100}".into(),
                chat: "c1".into()
            })]
        );
        assert_eq!(
            out.last(),
            Some(&Out::Send(FromDaemon::Ack { record_id: 113 }))
        );
        // The harness's exec carries the split argv for the daemon to shape.
        let exec = events.iter().find(|e| e.kind == "exec").unwrap();
        assert_eq!(
            exec.detail["argv"],
            json!(["node", r"C:\npm\node_modules\@openai\codex\bin\codex.js"])
        );
    }

    #[test]
    fn handwritten_a_root_seen_before_run_start_is_claimed_at_the_start() {
        let mut ing = Ingest::new();
        let first: Vec<Record> = fixture().into_iter().take(1).collect();
        let out = ing.on_service(FromService::Events(first), HARNESS_AT);
        assert!(!out
            .iter()
            .any(|o| matches!(o, Out::Send(FromDaemon::Claim { .. }))));
        let out = ing.on_run(&run("run.start", HARNESS_AT + 500));
        assert_eq!(out.len(), 1);
        // Never twice.
        assert!(ing.claims_for("c1").is_empty());
    }

    #[test]
    fn handwritten_a_stopped_chat_keeps_its_late_events_until_the_feed_passes_its_stop() {
        let mut ing = Ingest::new();
        ing.on_run(&run("run.start", HARNESS_AT + 500));
        let all = fixture();
        ing.on_service(FromService::Events(all[..2].to_vec()), HARNESS_AT);
        // The stop comes before the shell's later events are read.
        ing.on_run(&run("run.stop", HARNESS_AT + 1_500));
        let out = ing.on_service(FromService::Events(all[2..3].to_vec()), HARNESS_AT);
        assert_eq!(ingested(&out).len(), 1, "a late event of the stopped chat");
        // An event well after the stop: the chat is let go.
        let mut late = all[7].clone();
        late.xml = late.xml.replace("2026-11-05 09:30:0", "2026-11-05 09:31:0");
        ing.on_service(FromService::Events(vec![late]), HARNESS_AT);
        let out = ing.on_service(FromService::Events(all[3..4].to_vec()), HARNESS_AT);
        assert!(ingested(&out).is_empty());
    }

    #[test]
    fn a_stopped_chat_with_no_later_event_goes_after_the_keep() {
        let mut ing = Ingest::new();
        ing.on_run(&run("run.start", HARNESS_AT + 500));
        ing.on_run(&run("run.stop", HARNESS_AT + 1_000));
        ing.tick(HARNESS_AT + 1_000 + KEEP_STOPPED_MS - 1);
        assert!(ing.roots.contains_key("c1"));
        ing.tick(HARNESS_AT + 1_000 + KEEP_STOPPED_MS + 1);
        assert!(!ing.roots.contains_key("c1"));
    }

    #[test]
    fn a_gap_becomes_a_feed_gap_record_from_the_last_event_read() {
        let mut ing = Ingest::new();
        let out = ing.on_service(
            FromService::Gap {
                from: 5,
                to: 9,
                reason: "records the channel no longer holds".into(),
            },
            1_000,
        );
        let e = ingested(&out)[0];
        assert_eq!(e.kind, "feed.gap");
        assert_eq!(e.detail["fromMs"], Value::Null);
        assert_eq!(e.detail["toMs"], 1_000);
        ing.on_service(FromService::Events(fixture()), 2_000);
        let out = ing.on_service(
            FromService::Gap {
                from: 120,
                to: 121,
                reason: "x".into(),
            },
            3_000,
        );
        assert!(ingested(&out)[0].detail["fromMs"].as_i64().unwrap() > 0);
    }

    #[test]
    fn a_record_that_is_not_an_event_is_acked_and_dropped() {
        let mut ing = Ingest::new();
        let out = ing.on_service(
            FromService::Events(vec![Record {
                record_id: 7,
                xml: "not xml".into(),
            }]),
            0,
        );
        assert_eq!(out, vec![Out::Send(FromDaemon::Ack { record_id: 7 })]);
    }
}
