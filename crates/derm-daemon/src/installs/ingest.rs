//! The ingest wiring for package installs (lane X's request 4, integration
//! w5, continue): what `Daemon::ingest` hands every event to, beside the join.
//!
//! - [`ControlFlags`](super::control::ControlFlags) reads every event, the
//!   join's own `join.candidates` included, and gives `install.control`;
//! - [`LockDiffs`](super::lockdiff::LockDiffs) keeps a project's lockfile when
//!   an adapter's `install.call` arrives and diffs it when that call's
//!   `tool.call` arrives (same `toolUseId`, or the same `callKey` for agents
//!   that give no call id), giving `install.lockdiff`.
//!
//! The project folder is the chat's working folder from its daemon-scope
//! `run.start`, never a folder the record names: an `install.call` is the
//! agent's to write (case 66), so it may say which manager, not where to
//! read. A chat `derm run` did not start has no folder here and gets no diff.
//!
//! One diff per call and manager: a call that installs twice with one manager
//! (`npm i a && npm i b`) changes one lockfile, so the first record's id
//! carries it.

use std::collections::{HashMap, VecDeque};
use std::path::Path;

use derm_core::event::{Event, Source};
use derm_core::installs::Manager;
use serde_json::Value;

use super::control::ControlFlags;
use super::lockdiff::LockDiffs;

/// Calls with a diff in flight, across chats (the oldest go first).
const MAX_CALLS: usize = 1_024;

const MANAGERS: &[Manager] = &[
    Manager::Npm,
    Manager::Pnpm,
    Manager::Yarn,
    Manager::Bun,
    Manager::Pip,
    Manager::Uv,
    Manager::Poetry,
    Manager::Pdm,
    Manager::Pipx,
    Manager::Cargo,
    Manager::Go,
];

fn manager_named(name: &str) -> Option<Manager> {
    MANAGERS.iter().copied().find(|m| m.as_str() == name)
}

/// The call an adapter record names: `toolUseId`, else `callKey`.
fn call_of(e: &Event) -> Option<&str> {
    ["toolUseId", "callKey"]
        .iter()
        .find_map(|k| e.detail.get(*k).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
}

#[derive(Default)]
pub struct InstallRecords {
    control: ControlFlags,
    diffs: LockDiffs,
    /// (chat, call) to the managers seen and the record ids their diffs run under.
    calls: HashMap<(String, String), Vec<(Manager, String)>>,
    order: VecDeque<(String, String)>,
}

impl InstallRecords {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads one ingested event. `cwd` gives a chat's working folder, from its
    /// daemon-scope `run.start`. Returns the records to ingest.
    pub fn observe(
        &mut self,
        e: &Event,
        cwd: impl Fn(&str) -> Option<String>,
        now: i64,
    ) -> Vec<Event> {
        let mut out = self.control.observe(e);
        if e.chat_id.is_empty() {
            return out;
        }
        if e.kind == "run.stop" && e.source == Source::Run {
            self.diffs.forget_chat(&e.chat_id);
            self.calls.retain(|(chat, _), _| chat != &e.chat_id);
            self.order.retain(|(chat, _)| chat != &e.chat_id);
            return out;
        }
        if e.source != Source::Adapter {
            return out;
        }
        if e.kind == "install.call" {
            let (Some(call), Some(manager)) = (
                call_of(e),
                e.detail
                    .get("manager")
                    .and_then(Value::as_str)
                    .and_then(manager_named),
            ) else {
                return out;
            };
            let Some(folder) = cwd(&e.chat_id) else {
                return out;
            };
            let key = (e.chat_id.clone(), call.to_string());
            if !self.calls.contains_key(&key) {
                if self.calls.len() >= MAX_CALLS {
                    if let Some(old) = self.order.pop_front() {
                        self.calls.remove(&old);
                    }
                }
                self.order.push_back(key.clone());
            }
            let seen = self.calls.entry(key).or_default();
            if seen.iter().any(|(m, _)| *m == manager) {
                return out;
            }
            seen.push((manager, e.id.clone()));
            self.diffs.start(
                &e.id,
                &e.chat_id,
                &e.harness,
                manager,
                Path::new(&folder),
                now,
            );
            return out;
        }
        if e.kind == "tool.call" {
            if let Some(call) = call_of(e) {
                let key = (e.chat_id.clone(), call.to_string());
                if let Some(seen) = self.calls.remove(&key) {
                    self.order.retain(|k| k != &key);
                    for (_, id) in seen {
                        out.extend(self.diffs.finish(&id, now));
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(id: &str, source: Source, kind: &str, detail: Value) -> Event {
        Event {
            id: id.into(),
            at: 0,
            chat_id: "c1".into(),
            harness: "claude-code".into(),
            source,
            kind: kind.into(),
            summary: String::new(),
            detail,
            pid: None,
            approval_id: None,
        }
    }

    struct Dir(std::path::PathBuf);
    impl Dir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> Dir {
        let p = std::env::temp_dir().join(format!(
            "derm-installs-ingest-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }

    fn lockfile(dir: &Path, deps: &[(&str, &str)]) {
        let mut packages = serde_json::Map::new();
        packages.insert("".into(), json!({"name": "p", "version": "1.0.0"}));
        for (n, v) in deps {
            packages.insert(format!("node_modules/{n}"), json!({"version": v, "resolved": format!("https://registry.npmjs.org/{n}/-/{n}-{v}.tgz")}));
        }
        std::fs::write(
            dir.join("package-lock.json"),
            serde_json::to_string(
                &json!({"name": "p", "lockfileVersion": 3, "packages": packages}),
            )
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn an_install_call_and_its_tool_call_give_one_lockdiff() {
        let dir = tempdir();
        lockfile(dir.path(), &[("left-pad", "1.3.0")]);
        let folder = dir.path().to_string_lossy().to_string();
        let cwd = |c: &str| (c == "c1").then(|| folder.clone());
        let mut r = InstallRecords::new();
        let call = json!({"toolUseId": "t1", "manager": "npm", "form": "add", "packages": [], "decision": "allow"});
        assert!(r
            .observe(
                &ev("i1", Source::Adapter, "install.call", call.clone()),
                cwd,
                1
            )
            .is_empty());
        // A second npm install in the same call shares the one diff.
        assert!(r
            .observe(&ev("i2", Source::Adapter, "install.call", call), cwd, 2)
            .is_empty());
        lockfile(dir.path(), &[("left-pad", "1.2.0"), ("is-number", "7.0.0")]);
        let out = r.observe(
            &ev(
                "d1",
                Source::Adapter,
                "tool.call",
                json!({"toolUseId": "t1"}),
            ),
            cwd,
            3,
        );
        assert_eq!(out.len(), 1, "{out:?}");
        let d = &out[0];
        assert_eq!(d.kind, "install.lockdiff");
        assert_eq!(d.source, Source::Derm);
        assert_eq!(d.chat_id, "c1");
        assert_eq!(d.detail["call"], "i1");
        assert_eq!(d.detail["added"][0]["name"], "is-number");
        assert_eq!(d.detail["changed"][0]["name"], "left-pad");
        // The call is done: a later tool.call under its id gives nothing.
        assert!(r
            .observe(
                &ev(
                    "d2",
                    Source::Adapter,
                    "tool.call",
                    json!({"toolUseId": "t1"})
                ),
                cwd,
                4
            )
            .is_empty());
    }

    #[test]
    fn a_call_key_joins_the_records_of_an_agent_with_no_call_id() {
        let dir = tempdir();
        let folder = dir.path().to_string_lossy().to_string();
        let cwd = |_: &str| Some(folder.clone());
        let mut r = InstallRecords::new();
        r.observe(
            &ev(
                "i1",
                Source::Adapter,
                "install.call",
                json!({"toolUseId": "k1", "manager": "npm"}),
            ),
            cwd,
            1,
        );
        lockfile(dir.path(), &[("left-pad", "1.3.0")]);
        let out = r.observe(
            &ev("d1", Source::Adapter, "tool.call", json!({"callKey": "k1"})),
            cwd,
            2,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].detail["added"][0]["name"], "left-pad");
    }

    #[test]
    fn no_folder_no_record_and_no_reading_where_the_record_points() {
        let dir = tempdir();
        lockfile(dir.path(), &[("left-pad", "1.3.0")]);
        let mut r = InstallRecords::new();
        // A chat with no run.start folder: the record's own "cwd" is never read.
        let detail =
            json!({"toolUseId": "t1", "manager": "npm", "cwd": dir.path().to_string_lossy()});
        r.observe(
            &ev("i1", Source::Adapter, "install.call", detail),
            |_| None,
            1,
        );
        lockfile(dir.path(), &[("left-pad", "1.2.0")]);
        assert!(r
            .observe(
                &ev(
                    "d1",
                    Source::Adapter,
                    "tool.call",
                    json!({"toolUseId": "t1"})
                ),
                |_| None,
                2
            )
            .is_empty());
    }

    #[test]
    fn only_adapter_records_start_or_end_a_diff_and_run_stop_forgets() {
        let dir = tempdir();
        lockfile(dir.path(), &[("left-pad", "1.3.0")]);
        let folder = dir.path().to_string_lossy().to_string();
        let cwd = |_: &str| Some(folder.clone());
        let mut r = InstallRecords::new();
        // An install.call the daemon wrote, or an unknown manager: nothing.
        r.observe(
            &ev(
                "i0",
                Source::Derm,
                "install.call",
                json!({"toolUseId": "t0", "manager": "npm"}),
            ),
            cwd,
            1,
        );
        r.observe(
            &ev(
                "i9",
                Source::Adapter,
                "install.call",
                json!({"toolUseId": "t9", "manager": "brew"}),
            ),
            cwd,
            1,
        );
        r.observe(
            &ev(
                "i1",
                Source::Adapter,
                "install.call",
                json!({"toolUseId": "t1", "manager": "npm"}),
            ),
            cwd,
            1,
        );
        lockfile(dir.path(), &[("left-pad", "1.2.0")]);
        for t in ["t0", "t9"] {
            assert!(r
                .observe(
                    &ev("d", Source::Adapter, "tool.call", json!({"toolUseId": t})),
                    cwd,
                    2
                )
                .is_empty());
        }
        // An OTel record under the call's id does not end it.
        assert!(r
            .observe(
                &ev("o", Source::Otel, "tool.call", json!({"toolUseId": "t1"})),
                cwd,
                2
            )
            .is_empty());
        r.observe(&ev("s", Source::Run, "run.stop", json!({})), cwd, 3);
        assert!(r
            .observe(
                &ev(
                    "d1",
                    Source::Adapter,
                    "tool.call",
                    json!({"toolUseId": "t1"})
                ),
                cwd,
                4
            )
            .is_empty());
    }

    #[test]
    fn control_flags_still_see_every_event() {
        // The fixture's record pair, as control.rs's own test feeds it, through
        // this wiring: an install call, the gate's record for the call, a
        // write to .git/hooks, and the join's candidate set.
        let mut r = InstallRecords::new();
        let none = |_: &str| None;
        r.observe(
            &ev(
                "ic",
                Source::Adapter,
                "install.call",
                json!({"toolUseId": "t1", "manager": "npm"}),
            ),
            none,
            1,
        );
        r.observe(
            &ev(
                "g1",
                Source::Adapter,
                "approval",
                json!({"toolUseId": "t1"}),
            ),
            none,
            1,
        );
        let mut w = ev(
            "w1",
            Source::Auditd,
            "write",
            json!({"path": "/p/.git/hooks/pre-commit", "exe": "/usr/bin/node"}),
        );
        w.pid = Some(42);
        r.observe(&w, none, 2);
        let out = r.observe(
            &ev(
                "j1",
                Source::Derm,
                "join.candidates",
                json!({"effect": "w1", "candidates": [{"call": "g1"}], "chosen": "g1"}),
            ),
            none,
            3,
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].kind, "install.control");
    }
}
