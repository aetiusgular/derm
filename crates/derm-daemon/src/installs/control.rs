//! Control-path writes by an install (wave 5 lane X; rules case 133;
//! universal plan lane X item 4). A `postinstall` script or a build backend
//! is a stranger's code running with the agent's rights, outside the gate.
//! When the join (lane S, `join/`) credits a write to an install call, and
//! the path is one that names a program something runs later (git's hooks
//! and config, CI workflows, husky, a harness's folders, shell start files,
//! login agents), this records `install.control` crediting the install call
//! (`contracts/events.md` section 5).
//!
//! It reads what the daemon ingests, in order: `install.call` (which calls
//! are installs, by `toolUseId`); the gate's and the tap's records (which
//! event id is which `toolUseId`); the OS feed's writes (their paths); and
//! the join's `join.candidates` (which call a write fits). Memory is bounded
//! per chat and in chats; a chat is kept as long as the join keeps it after
//! its `run.stop` (MW5-17), and a path is flagged once per install (MW5-21).
//!
//! A path under a package store (`node_modules/`, `site-packages/`, a
//! manager's cache) is the package's own files being unpacked, not a
//! control path: a dependency that ships `.github/workflows/` is not flagged.

use std::collections::{HashMap, VecDeque};

use derm_core::event::{Event, Source};
use serde_json::{json, Value};

pub const MAX_CHATS: usize = 512;
const MAX_IDS: usize = 8_192;
const MAX_EFFECTS: usize = 4_096;

/// Effect kinds that put a file in place.
const WRITES: &[&str] = &["create", "write", "truncate", "rename", "link"];

/// Paths that name a program something runs later, lowercased: a folder ends
/// in `/`. Harness folders come from the matcher's control list
/// (`derm_core::policy::CONTROL_PATHS`, its path entries).
const INSTALL_CONTROL: &[&str] = &[
    ".git/hooks/",
    ".git/config",
    ".github/workflows/",
    ".github/actions/",
    ".gitlab-ci.yml",
    ".husky/",
    ".gitmodules",
    ".gitconfig",
    ".config/git/",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".kshrc",
    ".cshrc",
    ".tcshrc",
    ".config/fish/",
    "library/launchagents/",
    "library/launchdaemons/",
    ".config/autostart/",
    ".config/systemd/user/",
    ".config/environment.d/",
    ".ssh/authorized_keys",
    ".ssh/config",
    ".npmrc",
    ".pypirc",
    ".cargo/config.toml",
    ".cargo/config",
];

/// Folders whose files are a package's own (a write there is unpacking).
const STORES: &[&str] = &[
    "/node_modules/",
    "/site-packages/",
    "/dist-packages/",
    "/.cargo/registry/",
    "/.cargo/git/",
    "/pkg/mod/",
    "/.pnpm-store/",
    "/.yarn/cache/",
    "/.yarn/berry/",
    "/.bun/install/",
    "/.npm/_cacache/",
    "/.npm/_npx/",
    "/.cache/uv/",
    "/.cache/pip/",
    "/.cache/pnpm/",
    "/.cache/yarn/",
    "/library/caches/",
];

/// The control marker a path names, or `None`.
pub fn control_path(path: &str) -> Option<String> {
    let p = path.to_lowercase();
    let markers = INSTALL_CONTROL.iter().copied().chain(
        derm_core::policy::CONTROL_PATHS
            .iter()
            .copied()
            .filter(|m| (m.starts_with('.') || m.contains('/')) && !m.starts_with("derm/")),
    );
    let mut best: Option<(usize, &str)> = None;
    for m in markers {
        let m_folder = m.ends_with('/');
        let mut from = 0;
        while let Some(i) = p[from..].find(m) {
            let at = from + i;
            from = at + 1;
            // The marker starts a path part.
            if at > 0 && p.as_bytes()[at - 1] != b'/' {
                continue;
            }
            let end = at + m.len();
            // A file marker ends the path or a part (`.npmrc` not `.npmrc.bak`).
            if !m_folder && end < p.len() && p.as_bytes()[end] != b'/' {
                continue;
            }
            if best.is_none_or(|(b, _)| at < b) {
                best = Some((at, m));
            }
            break;
        }
    }
    let (at, m) = best?;
    // Under a package store, before the marker: the package's own files.
    // A relative path reads as if under `/`, so `node_modules/x/...` counts.
    let before = format!("/{}", &p[..at]);
    if STORES.iter().any(|s| before.contains(s)) {
        return None;
    }
    Some(m.to_string())
}

#[derive(Default)]
struct Chat {
    /// toolUseId to the `install.call` record's id.
    installs: HashMap<String, String>,
    /// Those toolUseIds, oldest first: a flood evicts the oldest, never every
    /// entry (review W5C-S8).
    install_order: VecDeque<String>,
    /// An event id (gate or tap record) to its toolUseId.
    calls: HashMap<String, String>,
    order: VecDeque<String>,
    /// An effect's id to its paths, executable and pid.
    effects: HashMap<String, (Vec<String>, String, Option<u32>)>,
    effect_order: VecDeque<String>,
    /// The (install record, path) pairs already flagged: one write's create
    /// and write effects flag it once (Mac test w5 retest 2, MW5-21).
    flagged: std::collections::HashSet<(String, String)>,
    flagged_order: VecDeque<(String, String)>,
    /// When its `run.stop` came (daemon time); kept a while after it for the
    /// join records of effects that arrive late (MW5-17).
    stopped_at: Option<i64>,
}

#[derive(Default)]
pub struct ControlFlags {
    chats: HashMap<String, Chat>,
    chat_order: VecDeque<String>,
}

fn str_at<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

impl ControlFlags {
    pub fn new() -> Self {
        Self::default()
    }

    fn chat(&mut self, id: &str) -> &mut Chat {
        if !self.chats.contains_key(id) {
            if self.chats.len() >= MAX_CHATS {
                if let Some(old) = self.chat_order.pop_front() {
                    self.chats.remove(&old);
                }
            }
            self.chat_order.push_back(id.to_string());
        }
        self.chats.entry(id.to_string()).or_default()
    }

    pub fn forget(&mut self, chat: &str) {
        self.chats.remove(chat);
        self.chat_order.retain(|c| c != chat);
    }

    /// Reads one ingested event; returns the `install.control` records it
    /// gives (none for most).
    pub fn observe(&mut self, e: &Event) -> Vec<Event> {
        if e.chat_id.is_empty() {
            return Vec::new();
        }
        // Chats stopped longer ago than the join keeps them go (MW5-17).
        let now = e.at;
        let gone: Vec<String> = self
            .chats
            .iter()
            .filter(|(_, c)| {
                c.stopped_at
                    .is_some_and(|s| now - s > crate::join::STOPPED_KEEP_MS)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in gone {
            self.forget(&k);
        }
        if e.kind == "run.stop" {
            if let Some(c) = self.chats.get_mut(&e.chat_id) {
                c.stopped_at.get_or_insert(e.at);
            }
            return Vec::new();
        }
        if e.kind == "install.call" && e.source != Source::Derm {
            if let Some(t) =
                str_at(&e.detail, "toolUseId").filter(|t| t.len() <= super::ingest::MAX_CALL_ID)
            {
                let c = self.chat(&e.chat_id);
                if c.installs.insert(t.to_string(), e.id.clone()).is_none() {
                    c.install_order.push_back(t.to_string());
                }
                while c.install_order.len() > MAX_IDS {
                    if let Some(old) = c.install_order.pop_front() {
                        c.installs.remove(&old);
                    }
                }
            }
            return Vec::new();
        }
        let call_key = if e.kind == "tap.call" {
            str_at(&e.detail, "callId")
        } else {
            str_at(&e.detail, "toolUseId")
        };
        if let Some(t) = call_key.filter(|t| t.len() <= super::ingest::MAX_CALL_ID) {
            if e.source != Source::Derm {
                let c = self.chat(&e.chat_id);
                c.calls.insert(e.id.clone(), t.to_string());
                c.order.push_back(e.id.clone());
                while c.order.len() > MAX_IDS {
                    if let Some(old) = c.order.pop_front() {
                        c.calls.remove(&old);
                    }
                }
            }
        }
        if WRITES.contains(&e.kind.as_str()) && e.source != Source::Derm {
            let paths: Vec<String> = ["path", "dest"]
                .iter()
                .filter_map(|k| str_at(&e.detail, k))
                .map(str::to_string)
                .collect();
            if paths.iter().any(|p| control_path(p).is_some()) {
                let exe = str_at(&e.detail, "exe")
                    .or_else(|| str_at(&e.detail, "comm"))
                    .unwrap_or("")
                    .to_string();
                let c = self.chat(&e.chat_id);
                c.effects.insert(e.id.clone(), (paths, exe, e.pid));
                c.effect_order.push_back(e.id.clone());
                while c.effect_order.len() > MAX_EFFECTS {
                    if let Some(old) = c.effect_order.pop_front() {
                        c.effects.remove(&old);
                    }
                }
            }
            return Vec::new();
        }
        if e.kind != "join.candidates" || e.source != Source::Derm {
            return Vec::new();
        }
        let Some(effect) = str_at(&e.detail, "effect") else {
            return Vec::new();
        };
        let Some(chat) = self.chats.get(&e.chat_id) else {
            return Vec::new();
        };
        let Some((paths, exe, pid)) = chat.effects.get(effect) else {
            return Vec::new();
        };
        let install_of = |call: &str| -> Option<String> {
            let tool_use = chat.calls.get(call)?;
            chat.installs.get(tool_use).cloned()
        };
        // Only a call the join chose (its tree, or the one call naming the
        // path): a call merely running at the time, or one asked about and
        // then refused (which the daemon never learns), is not credited
        // (box test w5, BW5-13: 658 flags, mostly the harness's own writes).
        // A shell the join placed among several shell calls (by tree, none
        // chosen) flags the install among them as one of several (fix pass
        // 1's review, F1); a window candidate never does.
        let tree: Vec<&str> = e
            .detail
            .get("candidates")
            .and_then(Value::as_array)
            .map(|cs| {
                cs.iter()
                    .filter(|c| str_at(c, "by") == Some("tree"))
                    .filter_map(|c| str_at(c, "call"))
                    .collect()
            })
            .unwrap_or_default();
        let (call, one_of) = match str_at(&e.detail, "chosen") {
            Some(chosen) => match install_of(chosen) {
                Some(call) => (call, String::new()),
                None => return Vec::new(),
            },
            None => match tree.iter().find_map(|c| install_of(c)) {
                Some(call) if tree.len() > 1 => {
                    (call, format!(" (one of {} calls running)", tree.len()))
                }
                _ => return Vec::new(),
            },
        };
        let mut out = Vec::new();
        let paths = paths.clone();
        let exe = exe.clone();
        let pid = *pid;
        let chat = self.chats.get_mut(&e.chat_id).expect("read above");
        for (k, path) in paths.iter().enumerate() {
            let Some(marker) = control_path(path) else {
                continue;
            };
            let key = (call.clone(), path.clone());
            if !chat.flagged.insert(key.clone()) {
                continue;
            }
            chat.flagged_order.push_back(key);
            while chat.flagged_order.len() > MAX_EFFECTS {
                if let Some(old) = chat.flagged_order.pop_front() {
                    chat.flagged.remove(&old);
                }
            }
            out.push(Event {
                id: format!("install-control-{effect}-{k}"),
                at: e.at,
                chat_id: e.chat_id.clone(),
                harness: e.harness.clone(),
                source: Source::Derm,
                kind: "install.control".into(),
                summary: format!("install wrote {marker}{one_of}"),
                detail: json!({
                    "trust": "daemon",
                    "call": call,
                    "path": path.chars().take(4096).collect::<String>(),
                    "exe": exe.chars().take(4096).collect::<String>(),
                    "effect": effect,
                }),
                pid,
                approval_id: None,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, kind: &str, source: Source, detail: Value) -> Event {
        Event {
            id: id.into(),
            at: 1_793_000_009_400,
            chat_id: "chat-fixture".into(),
            harness: "claude-code".into(),
            source,
            kind: kind.into(),
            summary: String::new(),
            detail,
            pid: Some(5555),
            approval_id: None,
        }
    }

    #[test]
    fn control_paths_and_package_stores() {
        for (p, m) in [
            ("/home/u/project/.git/hooks/pre-commit", ".git/hooks/"),
            (
                "/home/u/project/.github/workflows/ci.yml",
                ".github/workflows/",
            ),
            ("/home/u/.bashrc", ".bashrc"),
            (
                "/Users/u/Library/LaunchAgents/com.x.plist",
                "library/launchagents/",
            ),
            ("/home/u/project/.claude/settings.json", ".claude/"),
            ("/home/u/project/.husky/pre-commit", ".husky/"),
            (".git/config", ".git/config"),
            ("/home/u/.npmrc", ".npmrc"),
        ] {
            assert_eq!(control_path(p).as_deref(), Some(m), "{p}");
        }
        for p in [
            "/home/u/project/node_modules/pkg/.github/workflows/ci.yml",
            "/home/u/.venv/lib/python3.13/site-packages/x/.git/hooks/h",
            "/home/u/project/src/index.ts",
            "/home/u/project/.npmrc.bak",
            "/home/u/project/my.bashrc",
            "/home/u/.cargo/registry/src/x/.github/workflows/a.yml",
            "node_modules/x/.husky/pre-commit",
        ] {
            assert_eq!(control_path(p), None, "{p}");
        }
    }

    /// The fixture's own record (`contracts/fixtures/installs/records.json`,
    /// `install-control-1`) from the records that lead to it.
    #[test]
    fn a_write_the_join_credits_to_an_install_is_flagged_case_133() {
        let mut f = ControlFlags::new();
        assert!(f
            .observe(&ev(
                "claude-code-toolu_INSTALL1-install",
                "install.call",
                Source::Adapter,
                json!({"toolUseId": "toolu_INSTALL1"})
            ))
            .is_empty());
        assert!(f
            .observe(&ev(
                "gate-1",
                "approval",
                Source::Adapter,
                json!({"toolUseId": "toolu_INSTALL1"})
            ))
            .is_empty());
        assert!(f
            .observe(&ev(
                "auditd-1793000009400-7",
                "write",
                Source::Auditd,
                json!({"path": "/home/u/project/.git/hooks/pre-commit", "exe": "/usr/bin/node"})
            ))
            .is_empty());
        let out = f.observe(&ev(
            "join-auditd-1793000009400-7",
            "join.candidates",
            Source::Derm,
            json!({"trust": "daemon", "effect": "auditd-1793000009400-7", "effectKind": "write", "candidates": [{"call": "gate-1", "by": "tree", "why": "a process this call started"}], "chosen": "gate-1"}),
        ));
        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!(r.kind, "install.control");
        assert_eq!(r.summary, "install wrote .git/hooks/");
        assert_eq!(
            r.detail,
            json!({"trust": "daemon", "call": "claude-code-toolu_INSTALL1-install", "path": "/home/u/project/.git/hooks/pre-commit", "exe": "/usr/bin/node", "effect": "auditd-1793000009400-7"})
        );
        assert_eq!(r.pid, Some(5555));
    }

    /// Mac test w5 retest 2, MW5-21: a postinstall's one write of
    /// `.git/hooks/pre-commit` gave two flags, one for its create effect and
    /// one for its write. A path is flagged once per install call.
    #[test]
    fn one_install_flags_a_path_once_whatever_its_effects() {
        let mut f = ControlFlags::new();
        f.observe(&ev(
            "inst",
            "install.call",
            Source::Adapter,
            json!({"toolUseId": "toolu_I"}),
        ));
        f.observe(&ev(
            "gate",
            "approval",
            Source::Adapter,
            json!({"toolUseId": "toolu_I"}),
        ));
        let mut flags = 0;
        for (id, kind) in [("es-1", "create"), ("es-2", "write"), ("es-3", "write")] {
            f.observe(&ev(
                id,
                kind,
                Source::Eslogger,
                json!({"path": "/p/.git/hooks/pre-commit", "exe": "/usr/bin/node"}),
            ));
            flags += f
                .observe(&ev(
                    &format!("join-{id}"),
                    "join.candidates",
                    Source::Derm,
                    json!({"effect": id, "candidates": [{"call": "gate", "by": "tree"}], "chosen": "gate"}),
                ))
                .len();
        }
        assert_eq!(flags, 1);
        // Another path of the same install, or the same path by another
        // install, is flagged.
        f.observe(&ev(
            "es-4",
            "create",
            Source::Eslogger,
            json!({"path": "/p/.git/hooks/post-checkout"}),
        ));
        assert_eq!(
            f.observe(&ev(
                "join-es-4",
                "join.candidates",
                Source::Derm,
                json!({"effect": "es-4", "candidates": [{"call": "gate", "by": "tree"}], "chosen": "gate"}),
            ))
            .len(),
            1
        );
    }

    /// A stopped chat's late join record still flags its install (MW5-17).
    #[test]
    fn a_join_record_after_the_stop_still_flags_the_install() {
        let mut f = ControlFlags::new();
        f.observe(&ev(
            "inst",
            "install.call",
            Source::Adapter,
            json!({"toolUseId": "toolu_I"}),
        ));
        f.observe(&ev(
            "gate",
            "approval",
            Source::Adapter,
            json!({"toolUseId": "toolu_I"}),
        ));
        f.observe(&ev("stop", "run.stop", Source::Run, json!({})));
        let mut w = ev(
            "es-9",
            "write",
            Source::Eslogger,
            json!({"path": "/p/.github/workflows/x.yml"}),
        );
        w.at += 6_000;
        f.observe(&w);
        let mut j = ev(
            "join-es-9",
            "join.candidates",
            Source::Derm,
            json!({"effect": "es-9", "candidates": [{"call": "gate", "by": "tree"}], "chosen": "gate"}),
        );
        j.at += 6_000;
        assert_eq!(f.observe(&j).len(), 1);
    }

    /// Box test w5, BW5-13: a control-path write the join could only place
    /// by time window (the harness's own, or by a call asked about and then
    /// refused) is credited to no install; this test said the opposite
    /// before the fix pass.
    #[test]
    fn a_window_candidate_install_is_not_flagged() {
        let mut f = ControlFlags::new();
        f.observe(&ev(
            "i1",
            "install.call",
            Source::Adapter,
            json!({"toolUseId": "t1"}),
        ));
        f.observe(&ev(
            "tap-1",
            "tap.call",
            Source::Tap,
            json!({"callId": "t1"}),
        ));
        f.observe(&ev(
            "g2",
            "approval",
            Source::Adapter,
            json!({"toolUseId": "t2"}),
        ));
        f.observe(&ev(
            "w1",
            "rename",
            Source::Auditd,
            json!({"path": "/p/tmp.x", "dest": "/p/.github/workflows/x.yml"}),
        ));
        let out = f.observe(&ev("j1", "join.candidates", Source::Derm, json!({"effect": "w1", "candidates": [{"call": "g2", "by": "window"}, {"call": "tap-1", "by": "window"}], "chosen": null})));
        assert!(out.is_empty(), "{out:?}");
        // The same write chosen by the install's tree is flagged.
        let out = f.observe(&ev("j2", "join.candidates", Source::Derm, json!({"effect": "w1", "candidates": [{"call": "tap-1", "by": "tree"}], "chosen": "tap-1"})));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].detail["call"], "i1");
        assert_eq!(out[0].detail["path"], "/p/.github/workflows/x.yml");
        assert_eq!(out[0].summary, "install wrote .github/workflows/");
    }

    /// Fix pass 1's review, F1: a shell the join places among several
    /// shell calls (by tree, none chosen) still flags the install among
    /// them, as one of several; a window candidate still does not.
    #[test]
    fn an_install_among_tree_candidates_is_flagged_as_one_of_several() {
        let mut f = ControlFlags::new();
        f.observe(&ev(
            "i1",
            "install.call",
            Source::Adapter,
            json!({"toolUseId": "t1"}),
        ));
        f.observe(&ev(
            "tap-1",
            "tap.call",
            Source::Tap,
            json!({"callId": "t1"}),
        ));
        f.observe(&ev(
            "w1",
            "write",
            Source::Auditd,
            json!({"path": "/p/.git/hooks/pre-commit"}),
        ));
        let out = f.observe(&ev("j1", "join.candidates", Source::Derm, json!({"effect": "w1", "candidates": [{"call": "g2", "by": "tree"}, {"call": "tap-1", "by": "tree"}], "chosen": null})));
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].detail["call"], "i1");
        assert_eq!(
            out[0].summary,
            "install wrote .git/hooks/ (one of 2 calls running)"
        );
    }

    #[test]
    fn nothing_for_a_non_install_call_an_ordinary_path_or_a_forged_join() {
        let mut f = ControlFlags::new();
        f.observe(&ev(
            "g1",
            "approval",
            Source::Adapter,
            json!({"toolUseId": "t1"}),
        ));
        f.observe(&ev(
            "w1",
            "write",
            Source::Auditd,
            json!({"path": "/p/.git/hooks/pre-push"}),
        ));
        assert!(f
            .observe(&ev(
                "j1",
                "join.candidates",
                Source::Derm,
                json!({"effect": "w1", "candidates": [{"call": "g1"}], "chosen": "g1"})
            ))
            .is_empty());
        f.observe(&ev(
            "i2",
            "install.call",
            Source::Adapter,
            json!({"toolUseId": "t2"}),
        ));
        f.observe(&ev(
            "g2",
            "approval",
            Source::Adapter,
            json!({"toolUseId": "t2"}),
        ));
        f.observe(&ev(
            "w2",
            "write",
            Source::Auditd,
            json!({"path": "/p/src/a.ts"}),
        ));
        assert!(f
            .observe(&ev(
                "j2",
                "join.candidates",
                Source::Derm,
                json!({"effect": "w2", "candidates": [{"call": "g2"}], "chosen": "g2"})
            ))
            .is_empty());
        // A join record from a chat token is not the join's (the daemon refuses
        // `derm` from a socket client; this reads `adapter` as not the join).
        f.observe(&ev(
            "w3",
            "write",
            Source::Auditd,
            json!({"path": "/p/.git/hooks/x"}),
        ));
        assert!(f
            .observe(&ev(
                "j3",
                "join.candidates",
                Source::Adapter,
                json!({"effect": "w3", "candidates": [{"call": "g2"}], "chosen": "g2"})
            ))
            .is_empty());
        // An install.call the daemon wrote itself is not a gate's.
        f.observe(&ev(
            "i9",
            "install.call",
            Source::Derm,
            json!({"toolUseId": "t9"}),
        ));
        f.observe(&ev(
            "g9",
            "approval",
            Source::Adapter,
            json!({"toolUseId": "t9"}),
        ));
        f.observe(&ev(
            "w9",
            "write",
            Source::Auditd,
            json!({"path": "/p/.git/hooks/x"}),
        ));
        assert!(f
            .observe(&ev(
                "j9",
                "join.candidates",
                Source::Derm,
                json!({"effect": "w9", "candidates": [{"call": "g9"}], "chosen": "g9"})
            ))
            .is_empty());
    }

    #[test]
    fn run_stop_forgets_the_chat_and_memory_stays_bounded() {
        let mut f = ControlFlags::new();
        f.observe(&ev(
            "i1",
            "install.call",
            Source::Adapter,
            json!({"toolUseId": "t1"}),
        ));
        assert!(f.chats.contains_key("chat-fixture"));
        // Kept after the stop for late join records (MW5-17), gone past the
        // join's keep (before, gone at the stop itself).
        f.observe(&ev("s", "run.stop", Source::Derm, json!({})));
        assert!(f.chats.contains_key("chat-fixture"));
        let mut later = ev("x", "tool.call", Source::Adapter, json!({}));
        later.chat_id = "other".into();
        later.at += crate::join::STOPPED_KEEP_MS + 1;
        f.observe(&later);
        assert!(!f.chats.contains_key("chat-fixture"));
        for i in 0..(MAX_EFFECTS + 50) {
            f.observe(&ev(
                &format!("w{i}"),
                "write",
                Source::Auditd,
                json!({"path": "/p/.git/hooks/x"}),
            ));
        }
        assert_eq!(f.chats["chat-fixture"].effects.len(), MAX_EFFECTS);
    }

    /// W5C-S8: a flood of install calls evicts the oldest, never every one.
    #[test]
    fn a_flood_of_install_calls_keeps_the_newest() {
        let mut f = ControlFlags::new();
        for i in 0..(MAX_IDS + 5) {
            f.observe(&ev(
                &format!("i{i}"),
                "install.call",
                Source::Adapter,
                json!({"toolUseId": format!("t{i}")}),
            ));
        }
        let c = &f.chats["chat-fixture"];
        assert_eq!(c.installs.len(), MAX_IDS);
        assert!(!c.installs.contains_key("t0"));
        assert!(c.installs.contains_key(&format!("t{}", MAX_IDS + 4)));
    }

    /// Re-review W5R-10: an id longer than the hook's 128 bytes is not kept.
    #[test]
    fn an_install_call_id_past_the_hooks_cap_is_not_kept() {
        let mut f = ControlFlags::new();
        f.observe(&ev(
            "i1",
            "install.call",
            Source::Adapter,
            json!({"toolUseId": "x".repeat(super::super::ingest::MAX_CALL_ID + 1)}),
        ));
        assert!(f
            .chats
            .get("chat-fixture")
            .is_none_or(|c| c.installs.is_empty()));
        // Re-review W5R2-2: nor on any other record that names a call.
        f.observe(&ev(
            "g1",
            "tool.call",
            Source::Adapter,
            json!({"toolUseId": "x".repeat(super::super::ingest::MAX_CALL_ID + 1)}),
        ));
        assert!(f
            .chats
            .get("chat-fixture")
            .is_none_or(|c| c.calls.is_empty()));
    }
}
