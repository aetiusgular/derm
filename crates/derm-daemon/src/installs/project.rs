//! Step P's flags on an agent account's chat (lane PC; `contracts/events.md`
//! section 7.2; plan steps P4 and P8's first part). Three kinds, source
//! `derm`, written only here:
//!
//! - `project.control`: a write, by any process the OS feed places in an
//!   account's chat, to a path inside that chat's project home that a
//!   harness or a shell runs later. Every such write, not only under an
//!   install. The paths are `control::control_path`'s (which already matches
//!   the whole of `.claude/`, `.codex/` and `.pi/`, `policy.rs:876-878`)
//!   plus [`ADDED`] (note CD section 5, C4).
//! - `signin.read`: an open of a file under the account's `signin/` store
//!   by a process that is not the chat's harness (`run.start`'s
//!   `harnessExe` or `harnessChildExe`, case 177). The open reaches the
//!   daemon only when the account's own audit rules file is loaded
//!   (`derm-audit-feed rules --account`, its `-F dir=<home>/signin` line).
//! - `net.unix`: a `connect` by an account's process to a Unix socket, from
//!   the Linux feed's `unix.connect` ([`UNIX_CONNECT`]), with `outside` true
//!   when the socket is outside the chat's project folders and its bridge.
//!
//! What a chat is comes from its daemon-scope `run.start` only (source
//! `run`, which no chat token may post): `agentUser.account` names the
//! account (its home is `/var/lib/derm/agents/<slug>`, `contracts/
//! agents.md` via `run/user/accounts.rs`), the project id is the event's
//! `project` or `detail.project.id`, and the folders are `cwd`, `folders`
//! and `project.folder`. A chat that runs as the person, or a record from a
//! chat token, gives nothing here: the paths are read from the OS feed's
//! records only (source `auditd`), which only the daemon scope posts.
//!
//! One record per chat, kind and path (and process, for `signin.read`) in a
//! minute: a harness rewrites `.claude.json` at every start and a resolver
//! is asked again and again; a later write of the same path a minute on is
//! recorded again, so a harness's own write never hides the agent's. At
//! most [`MAX_PER_MINUTE`] records a chat in a minute; past that the next
//! record says how many were not written (`notRecorded`). Memory is bounded
//! in chats and in paths per chat; a stopped chat is kept as the join keeps
//! it (MW5-17, MW5-34).

use std::collections::{HashMap, VecDeque};

use derm_core::event::{Event, Source};
use derm_core::project::{kinds, layout, ProjectId};
use serde_json::{json, Map, Value};

use super::control::control_path;

/// Run-later paths in a project home that `control_path` does not match:
/// Codex's user skills (`$HOME/.agents/skills`, Codex 0.167.2
/// `ext/skills/src/host_roots.rs:27-28, 144`), Codex's plugin marketplace
/// under the cache folder (`core-plugins/src/marketplace_policy.rs:556-583`,
/// `dirs::cache_dir()` is `$XDG_CACHE_HOME` else `~/.cache`), and the
/// account's own programs folder (plan P4). Both Codex reads are unchanged
/// at `rust-v0.171.0` (lane PC, read).
pub const ADDED: &[&str] = &[".agents/skills/", ".cache/codex-runtimes/", ".local/bin/"];

/// The Linux feed's kind for a connect to a Unix socket
/// (`derm_audit_linux::map::UNIX_CONNECT`; that crate's test holds the two
/// equal, since the daemon does not depend on it).
pub const UNIX_CONNECT: &str = "unix.connect";

/// Where every agent account's home is (`/etc/derm/agents.json`'s `home`,
/// which its one reader refuses unless it is this folder and the slug,
/// `crates/derm-cli/src/run/user/accounts.rs`).
pub const AGENTS_ROOT: &str = "/var/lib/derm/agents";

/// The root of the chats' bridge folders (`crates/derm-cli/src/run/user/
/// bridge.rs`, `BASE_ROOT`): `<root>/<person uid>/<chat part>-<32 hex>`.
pub const BRIDGE_ROOT: &str = "/run/derm-agent";

/// The links P3 makes in a project home to the account's sign-in store
/// (`contracts/projects.md` 2.3). A read through one carries the link's
/// name, not the store's: run in lane PC's workspace (Linux 6.18.44, 21 Nov
/// 2026), a `-F dir=<store>` open rule fired for `cat <home>/.codex/
/// auth.json` and its PATH record named the link (same inode as the store's
/// file).
pub const SIGNIN_LINKS: &[&str] = &[
    ".codex/auth.json",
    ".codex/auth.lock",
    ".pi/agent/auth.json",
];

/// The system files and folders the account's rules file also watches for
/// reads (`derm_audit_linux::sensitive::SYSTEM_FILES` and `SYSTEM_DIRS`; that
/// crate's test holds them equal). A read of one is no sign-in read.
pub const SYSTEM_SENSITIVE: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
];

/// Records one chat may get in a minute, of the three kinds together.
pub const MAX_PER_MINUTE: u32 = 120;
/// How long a (kind, path) stays recorded before a repeat is recorded again.
pub const REPEAT_MS: i64 = 60_000;
const MAX_CHATS: usize = 512;
const MAX_SEEN: usize = 4_096;
/// The longest path a record keeps (the feed's own field cap).
const MAX_PATH: usize = 4_096;

/// The marker `path` names when it lies inside `project_home` and a
/// harness or a shell runs it later, else `None`.
///
/// `path` is as the audit record gives it, which keeps a name as the
/// process wrote it (`.` and `..` parts included, `control.rs`'s
/// `harness_snapshot`): it counts as inside when either the path as given
/// or the path with its `.` and `..` parts taken away starts with the home
/// by whole parts. Read on what lies after the home, so a marker in the
/// home's own folders (`/var/lib/...`) never counts, and as `control_path`
/// reads (lower case, a marker starts a part, a file marker ends one).
pub fn project_control(path: &str, project_home: &str) -> Option<String> {
    let home = project_home.trim_end_matches('/');
    if home.is_empty() || !home.starts_with('/') {
        return None;
    }
    let mut best: Option<String> = None;
    for p in [path.to_string(), normal(path)] {
        let Some(rest) = p.strip_prefix(home).and_then(|r| r.strip_prefix('/')) else {
            continue;
        };
        if rest.is_empty() {
            continue;
        }
        if let Some(m) = control_path(rest).or_else(|| added(rest)) {
            best = Some(m);
            break;
        }
    }
    best
}

/// An [`ADDED`] marker in `rest` (a path inside a home, with no leading
/// `/`), lower case as `control_path` reads. `.cache/codex-runtimes/` and
/// `.local/bin/` are the home's own (`$XDG_CACHE_HOME` or `~/.cache`,
/// `~/.local/bin`), so only at its start; `.agents/skills/` at the start of
/// any part, since Codex also reads it in each folder it walks
/// (`host_roots.rs:225`), with something after the folder in each case.
fn added(rest: &str) -> Option<String> {
    let r = rest.to_lowercase();
    for m in ADDED {
        let at_root = r.starts_with(m) && r.len() > m.len();
        let anywhere = *m == ".agents/skills/"
            && r.match_indices(m)
                .any(|(i, _)| (i == 0 || r.as_bytes()[i - 1] == b'/') && r.len() > i + m.len());
        if at_root || anywhere {
            return Some((*m).to_string());
        }
    }
    None
}

/// `path` with `.` and empty parts dropped and each `..` taking the part
/// before it; an absolute path only (a relative one is returned as is).
/// Lexical: a link is not followed, so this is one more reading, never the
/// only one.
fn normal(path: &str) -> String {
    if !path.starts_with('/') {
        return path.to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Whether `path` lies in `folder`, by whole parts, as given or lexically
/// normalized.
fn inside(path: &str, folder: &str) -> bool {
    let f = folder.trim_end_matches('/');
    if f.is_empty() || !f.starts_with('/') {
        return false;
    }
    [path.to_string(), normal(path)]
        .iter()
        .any(|p| p == f || p.strip_prefix(f).is_some_and(|rest| rest.starts_with('/')))
}

/// Whether an open of `p` is one of the account's sign-in files: a path in
/// its store, a link P3 makes in one of its project homes, or, for a read
/// (kind `open`, which only a `derm_sens` rule gives) by the account's own
/// uid, any path that is not one of the system files its rules also watch:
/// there the only other watch is the store, so a read the kernel matched to
/// it came through a link the agent may have made anywhere (the record
/// names the link, as run).
fn signin_path(chat: &Chat, e: &Event, p: &str) -> bool {
    let store = format!("{}/{}", chat.account_home, layout::SIGNIN);
    if inside(p, &store) {
        return true;
    }
    let n = normal(p);
    let projects = format!("{}/{}/", chat.account_home, layout::PROJECTS);
    if let Some(rest) = n.strip_prefix(&projects) {
        if let Some((id, tail)) = rest.split_once('/') {
            if derm_core::project::valid_id(id) {
                if let Some(link) = tail.strip_prefix(&format!("{}/", layout::HOME)) {
                    if SIGNIN_LINKS.contains(&link) {
                        return true;
                    }
                }
            }
        }
    }
    e.kind == "open"
        && chat.uid.is_some()
        && e.detail.get("uid").and_then(Value::as_u64) == chat.uid
        && !SYSTEM_SENSITIVE.iter().any(|s| inside(p, s))
}

/// An account slug as `/etc/derm/agents.json` takes it: `[a-z0-9-]{1,15}`
/// (`plans/parallel_build_accounts.md` section 2). Anything else names no
/// account here.
fn valid_slug(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The bridge folder's name part for a chat, as `bridge.rs`'s `chat_part`
/// makes it (`crates/derm-cli/src/run/user/bridge.rs:203-216`): lower case
/// letters, digits, `_` and `-` kept, capitals lowered, anything else `-`,
/// at most 24, and a `_` in front unless it starts with a letter or `_`.
fn bridge_part(chat: &str) -> String {
    let mut s: String = chat
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '_' | '-' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => '-',
        })
        .take(24)
        .collect();
    if !s.starts_with(|c: char| c.is_ascii_lowercase() || c == '_') {
        s.insert(0, '_');
    }
    s
}

/// Whether `path` is inside this chat's bridge folder:
/// `/run/derm-agent/<digits>/<chat part>-<32 lowercase hex>/...`.
fn in_bridge(path: &str, chat: &str) -> bool {
    let p = normal(path);
    let Some(rest) = p
        .strip_prefix(BRIDGE_ROOT)
        .and_then(|r| r.strip_prefix('/'))
    else {
        return false;
    };
    let mut parts = rest.split('/');
    let (Some(uid), Some(dir)) = (parts.next(), parts.next()) else {
        return false;
    };
    if uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(random) = dir.strip_prefix(&format!("{}-", bridge_part(chat))) else {
        return false;
    };
    random.len() == 32
        && random
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Default)]
struct Chat {
    account: String,
    account_home: String,
    project: Option<ProjectId>,
    /// `<account home>/projects/<id>`, when the project is known.
    project_dir: Option<String>,
    /// The account's uid (`agentUser.uid`).
    uid: Option<u64>,
    /// The harness's executables by real path (`harnessExe`, `harnessChildExe`).
    harness: Vec<String>,
    /// The chat's own folders (`cwd`, `folders`, `project.folder`).
    folders: Vec<String>,
    /// Whether the chat's Landlock domain scopes abstract sockets
    /// (`agentUser.landlock.scoped`), so a connect that went through reached
    /// a socket of its own domain (Linux v7.0 `include/uapi/linux/
    /// landlock.h:373-375`).
    scoped: bool,
    /// (kind, path, exe) to when it was last recorded.
    seen: HashMap<(String, String, String), i64>,
    seen_order: VecDeque<(String, String, String)>,
    /// The minute's start, records written in it, and those not written.
    minute: (i64, u32, u64),
    stopped_at: Option<i64>,
}

/// The step P flags (`project.control`, `signin.read`, `net.unix`).
#[derive(Default)]
pub struct ProjectFlags {
    chats: HashMap<String, Chat>,
    order: VecDeque<String>,
    os_seen: i64,
}

fn str_at<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

fn cut(s: &str) -> String {
    let mut end = s.len().min(MAX_PATH);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

impl ProjectFlags {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this chat is an agent account's, as its `run.start` said.
    pub fn is_account_chat(&self, chat: &str) -> bool {
        self.chats.contains_key(chat)
    }

    /// Reads one ingested event; returns the records it gives.
    pub fn observe(&mut self, e: &Event) -> Vec<Event> {
        if let Some(t) = crate::join::feed_progress(e) {
            self.os_seen = self.os_seen.max(t);
        }
        if e.chat_id.is_empty() {
            return Vec::new();
        }
        let (now, os_seen) = (e.at, self.os_seen);
        let gone: Vec<String> = self
            .chats
            .iter()
            .filter(|(_, c)| {
                c.stopped_at
                    .is_some_and(|s| !crate::join::keep_stopped(s, now, os_seen))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in gone {
            self.chats.remove(&k);
            self.order.retain(|c| *c != k);
        }
        if e.source == Source::Run {
            match e.kind.as_str() {
                "run.start" => self.start(e),
                "run.stop" => {
                    if let Some(c) = self.chats.get_mut(&e.chat_id) {
                        c.stopped_at.get_or_insert(e.at);
                    }
                }
                _ => {}
            }
            return Vec::new();
        }
        // Only the OS feed's own records name paths here (a chat token
        // posts adapter and OTel records only, `op_event`).
        if e.source != Source::Auditd {
            return Vec::new();
        }
        let Some(chat) = self.chats.get(&e.chat_id) else {
            return Vec::new();
        };
        let exe = str_at(&e.detail, "exe").unwrap_or("").to_string();
        let mut found: Vec<(&'static str, String, Value, String)> = Vec::new();
        match e.kind.as_str() {
            "truncate" | "rename" | "link" => {
                if let Some(dir) = &chat.project_dir {
                    let home = format!("{dir}/{}", layout::HOME);
                    // A rename's or a link's new name first: that is the
                    // file put in place.
                    for key in ["dest", "path"] {
                        let Some(p) = str_at(&e.detail, key) else {
                            continue;
                        };
                        if key == "path" && matches!(e.kind.as_str(), "rename" | "link") {
                            continue;
                        }
                        if let Some(marker) = project_control(p, &home) {
                            found.push((
                                kinds::CONTROL,
                                p.to_string(),
                                json!({"marker": marker}),
                                format!("wrote {marker} in its project home"),
                            ));
                            break;
                        }
                    }
                }
            }
            "open" | "create" | "write" => {
                // Every open of a sign-in file: the rules key a read as
                // `derm_sens` (kind `open`) and an open for writing, which
                // reads as well when it is `O_RDWR`, as `derm_write` (kinds
                // `create` and `write`; `rules.rs`).
                let path_only = e.detail.get("pathOnly") == Some(&Value::Bool(true));
                if let Some(p) = str_at(&e.detail, "path") {
                    if !path_only && signin_path(chat, e, p) && !chat.harness.contains(&exe) {
                        found.push((
                            kinds::SIGNIN_READ,
                            p.to_string(),
                            if e.kind == "open" {
                                json!({})
                            } else {
                                json!({"forWrite": true})
                            },
                            "a process that is not the harness opened a sign-in file".into(),
                        ));
                    }
                }
                if e.kind != "open" {
                    if let Some(marker) = chat.project_dir.as_ref().and_then(|dir| {
                        str_at(&e.detail, "path")
                            .and_then(|p| project_control(p, &format!("{dir}/{}", layout::HOME)))
                    }) {
                        let p = str_at(&e.detail, "path").unwrap_or_default().to_string();
                        found.push((
                            kinds::CONTROL,
                            p,
                            json!({"marker": marker}),
                            format!("wrote {marker} in its project home"),
                        ));
                    }
                }
            }
            k if k == UNIX_CONNECT => {
                if let Some(p) = str_at(&e.detail, "path") {
                    let abstract_ = p.starts_with('@');
                    let outside = if abstract_ {
                        !chat.scoped
                    } else {
                        !(chat.project_dir.as_deref().is_some_and(|d| inside(p, d))
                            || chat.folders.iter().any(|f| inside(p, f))
                            || in_bridge(p, &e.chat_id))
                    };
                    let what = if outside {
                        if abstract_ {
                            "connected to an abstract Unix socket its domain does not scope"
                        } else {
                            "connected to a Unix socket outside its project"
                        }
                    } else {
                        "connected to a Unix socket of its own"
                    };
                    found.push((
                        kinds::NET_UNIX,
                        p.to_string(),
                        json!({"abstract": abstract_, "outside": outside}),
                        what.into(),
                    ));
                }
            }
            _ => {}
        }
        let mut out = Vec::new();
        for (k, (kind, path, extra, what)) in found.into_iter().enumerate() {
            let key_exe = if kind == kinds::SIGNIN_READ {
                exe.clone()
            } else {
                String::new()
            };
            let chat = self.chats.get_mut(&e.chat_id).expect("read above");
            let key = (kind.to_string(), path.clone(), key_exe);
            if chat.seen.get(&key).is_some_and(|t| e.at - *t < REPEAT_MS) {
                continue;
            }
            if e.at - chat.minute.0 >= 60_000 {
                chat.minute = (e.at, 0, chat.minute.2);
            }
            if chat.minute.1 >= MAX_PER_MINUTE {
                chat.minute.2 += 1;
                continue;
            }
            chat.minute.1 += 1;
            let not_recorded = std::mem::take(&mut chat.minute.2);
            if chat.seen.insert(key.clone(), e.at).is_none() {
                chat.seen_order.push_back(key);
                while chat.seen_order.len() > MAX_SEEN {
                    if let Some(old) = chat.seen_order.pop_front() {
                        chat.seen.remove(&old);
                    }
                }
            }
            let mut d = Map::new();
            d.insert("trust".into(), json!("daemon"));
            d.insert("path".into(), json!(cut(&path)));
            d.insert("process".into(), json!({"pid": e.pid, "exe": cut(&exe)}));
            d.insert("account".into(), json!(chat.account));
            d.insert("effect".into(), json!(e.id));
            if let Value::Object(x) = extra {
                d.extend(x);
            }
            if e.detail.get("denied") == Some(&Value::Bool(true)) {
                d.insert("denied".into(), json!(true));
            }
            if not_recorded > 0 {
                d.insert("notRecorded".into(), json!(not_recorded));
            }
            let id_kind = kind.replace('.', "-");
            let summary: String = format!("{what}: {}", cut(&path))
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .take(200)
                .collect();
            out.push(Event {
                project: chat
                    .project
                    .as_ref()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default(),
                id: format!("{id_kind}-{}-{k}", e.id),
                at: e.at,
                chat_id: e.chat_id.clone(),
                harness: e.harness.clone(),
                source: Source::Derm,
                kind: kind.to_string(),
                summary,
                detail: Value::Object(d),
                pid: e.pid,
                approval_id: None,
            });
        }
        out
    }

    /// A daemon-scope `run.start`: an account chat is kept, any other chat
    /// (a run as the person) is let go, and an id run again starts afresh.
    fn start(&mut self, e: &Event) {
        self.chats.remove(&e.chat_id);
        self.order.retain(|c| *c != e.chat_id);
        let d = &e.detail;
        let Some(user) = d.get("agentUser") else {
            return;
        };
        let Some(slug) = str_at(user, "account").filter(|s| valid_slug(s)) else {
            return;
        };
        let account_home = format!("{AGENTS_ROOT}/{slug}");
        let project = ProjectId::parse(&e.project).or_else(|| {
            d.get("project")
                .and_then(|p| str_at(p, "id"))
                .and_then(ProjectId::parse)
        });
        let project_dir = project
            .as_ref()
            .map(|id| layout::project_dir(&account_home, id));
        let mut folders: Vec<String> = Vec::new();
        if let Some(c) = str_at(d, "cwd") {
            folders.push(c.to_string());
        }
        if let Some(list) = d.get("folders").and_then(Value::as_array) {
            folders.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
        }
        if let Some(f) = d.get("project").and_then(|p| str_at(p, "folder")) {
            folders.push(f.to_string());
        }
        folders.retain(|f| f.starts_with('/') && normal(f) != "/");
        folders.truncate(64);
        let harness = ["harnessExe", "harnessChildExe"]
            .iter()
            .filter_map(|k| str_at(d, k))
            .filter(|x| x.starts_with('/'))
            .map(str::to_string)
            .collect();
        let uid = user.get("uid").and_then(Value::as_u64).filter(|u| *u != 0);
        let scoped = user
            .get("landlock")
            .and_then(|l| l.get("scoped"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if self.chats.len() >= MAX_CHATS {
            if let Some(old) = self.order.pop_front() {
                self.chats.remove(&old);
            }
        }
        self.order.push_back(e.chat_id.clone());
        self.chats.insert(
            e.chat_id.clone(),
            Chat {
                account: slug.to_string(),
                account_home,
                project,
                project_dir,
                uid,
                harness,
                folders,
                scoped,
                ..Chat::default()
            },
        );
    }
}

#[cfg(test)]
mod tests;
