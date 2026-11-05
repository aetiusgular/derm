//! A chat's processes from Sysmon's events, as daemon events (the Windows
//! counterpart of `derm-audit-linux`'s `Feed`; note AU section 6).
//!
//! The tree is keyed on `ProcessGuid`, never on a pid: a guid names one
//! process even after Windows reuses its pid (Sysmon page). A chat's root is
//! the harness `derm run` started; `run.start` names its pid, and the root's
//! guid is the process-creation event for that pid closest before the start
//! (Sysmon logs the creation before `derm run` posts `run.start`), or, when
//! none was seen, the next event from that pid. A process joins the chat
//! when its `ParentProcessGuid` is a member's. A member leaves at its exit
//! (event 5); what it started stays (case 68).
//!
//! What it does not see: a process an agent starts with another process as
//! its parent (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) carries that parent's
//! guid (I, not tested; note AU 2.3, proposed case AU-5), so it is outside
//! the chat here; writes into an existing file (FileCreate logs a create or
//! an overwrite only); connections unless the Sysmon config turns event 3
//! on. `derm status` must say so on Windows (a request for integration).

use std::collections::{HashMap, VecDeque};

use derm_core::event::{Event, Source};
use serde_json::{json, Map, Value};

use crate::sysmon::{self, Action, What};
use crate::xml;

/// How many recent process creations are kept to find a root's guid.
const RECENT: usize = 4096;
/// A root's creation may be logged this long before `run.start`.
const ROOT_BEFORE_MS: i64 = 60_000;
/// ... or this long after it (clocks of two processes).
const ROOT_AFTER_MS: i64 = 5_000;
/// A field kept in a record is cut to this many bytes.
const MAX_FIELD: usize = 4096;

/// A chat the daemon said started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    pub chat: String,
    pub harness: String,
    pub pid: u32,
    /// `run.start`'s time, milliseconds since the epoch.
    pub started_ms: i64,
    /// The chat's folders: a create or delete outside them is flagged.
    pub folders: Vec<String>,
}

#[derive(Default)]
pub struct Feed {
    source: Option<Source>,
    roots: HashMap<String, Root>,
    /// guid -> chat.
    members: HashMap<String, String>,
    /// Chats whose root's guid is not known yet, by root pid.
    waiting: HashMap<u32, String>,
    /// (pid, guid, at) of recent process creations.
    recent: VecDeque<(u32, String, i64)>,
}

impl Feed {
    /// A feed whose events carry `source`. The daemon's contract has no
    /// Windows source yet (lane Z's request for `Source::Sysmon`); the caller
    /// names it.
    pub fn new(source: Source) -> Feed {
        Feed {
            source: Some(source),
            ..Feed::default()
        }
    }

    /// A chat started. Its root's guid is the creation of `pid` closest
    /// before the start, if one was seen; else the next event from `pid`.
    pub fn register(&mut self, root: Root) {
        let found = self
            .recent
            .iter()
            .filter(|(pid, _, at)| {
                *pid == root.pid
                    && *at >= root.started_ms - ROOT_BEFORE_MS
                    && *at <= root.started_ms + ROOT_AFTER_MS
            })
            .max_by_key(|(_, _, at)| *at)
            .map(|(_, guid, _)| guid.clone());
        match found {
            Some(guid) => {
                self.members.insert(guid, root.chat.clone());
            }
            None => {
                self.waiting.insert(root.pid, root.chat.clone());
            }
        }
        self.roots.insert(root.chat.clone(), root);
    }

    /// A chat stopped: its root and members are dropped.
    pub fn unregister(&mut self, chat: &str) {
        self.roots.remove(chat);
        self.members.retain(|_, c| c != chat);
        self.waiting.retain(|_, c| c != chat);
    }

    /// The chat a process belongs to.
    pub fn chat_of(&self, guid: &str) -> Option<&str> {
        self.members.get(guid).map(String::as_str)
    }

    /// One event's XML; the daemon events it makes (none, or one).
    pub fn push_xml(&mut self, text: &str) -> Vec<Event> {
        match xml::parse(text) {
            Some(e) => {
                let record = e.record_id;
                match sysmon::read(&e) {
                    Some(a) => self.push(&a, record),
                    None => Vec::new(),
                }
            }
            None => Vec::new(),
        }
    }

    pub fn push(&mut self, a: &Action, record: Option<u64>) -> Vec<Event> {
        if let What::Exec { parent_guid, .. } = &a.what {
            if self.recent.len() == RECENT {
                self.recent.pop_front();
            }
            self.recent
                .push_back((a.pid, a.guid.clone(), a.at_ms.unwrap_or(0)));
            if let Some(chat) = self.members.get(parent_guid).cloned() {
                self.members.insert(a.guid.clone(), chat);
            }
        }
        if let Some(chat) = self.waiting.get(&a.pid).cloned() {
            if !self.members.contains_key(&a.guid) {
                self.waiting.remove(&a.pid);
                self.members.insert(a.guid.clone(), chat);
            }
        }
        let Some(chat) = self.members.get(&a.guid).cloned() else {
            return Vec::new();
        };
        if matches!(a.what, What::Exit) {
            self.members.remove(&a.guid);
        }
        let Some(root) = self.roots.get(&chat) else {
            return Vec::new();
        };
        vec![to_event(
            a,
            root,
            self.source.unwrap_or(Source::Derm),
            record,
        )]
    }
}

fn cut(s: &str) -> String {
    if s.len() <= MAX_FIELD {
        return s.to_string();
    }
    let mut end = MAX_FIELD;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Whether `path` lies inside one of `folders`, as Windows compares paths:
/// without regard to case or separator.
pub fn inside_folders(path: &str, folders: &[String]) -> bool {
    let norm = |p: &str| {
        let p = p.replace('/', "\\").to_lowercase();
        let p = p.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(p);
        p.trim_end_matches('\\').to_string()
    };
    let p = norm(path);
    folders.iter().any(|f| {
        let f = norm(f);
        !f.is_empty() && (p == f || p.starts_with(&format!("{f}\\")))
    })
}

fn to_event(a: &Action, root: &Root, source: Source, record: Option<u64>) -> Event {
    let mut d = Map::new();
    d.insert("guid".into(), json!(a.guid));
    d.insert("image".into(), json!(cut(&a.image)));
    if let Some(at) = a.at_ms {
        d.insert("osAt".into(), json!(at));
    }
    let (kind, summary) = match &a.what {
        What::Exec {
            parent_guid,
            command_line_bytes,
            ..
        } => {
            d.insert("parentGuid".into(), json!(parent_guid));
            d.insert("commandLineBytes".into(), json!(command_line_bytes));
            ("exec", format!("exec {}", cut(&a.image)))
        }
        What::Exit => ("exit", format!("exit {}", cut(&a.image))),
        What::Create { path } => {
            d.insert("path".into(), json!(cut(path)));
            if !inside_folders(path, &root.folders) {
                d.insert("writeOutside".into(), json!(true));
            }
            ("create", format!("create {}", cut(path)))
        }
        What::Delete { path } => {
            d.insert("path".into(), json!(cut(path)));
            if !inside_folders(path, &root.folders) {
                d.insert("writeOutside".into(), json!(true));
            }
            ("unlink", format!("unlink {}", cut(path)))
        }
        What::Connect { addr, port, host } => {
            let shown = if host.is_empty() {
                addr.as_str()
            } else {
                host.as_str()
            };
            let key = if addr.contains(':') {
                format!("[{shown}]:{port}")
            } else {
                format!("{shown}:{port}")
            };
            d.insert("host".into(), json!(cut(&key)));
            d.insert("addr".into(), json!(addr));
            d.insert("port".into(), json!(port));
            ("net.connect", format!("connect {key}"))
        }
        What::Dns { query } => {
            d.insert("query".into(), json!(cut(query)));
            ("dns", format!("dns {}", cut(query)))
        }
    };
    Event {
        id: match record {
            Some(r) => format!("sysmon-{r}"),
            None => format!("sysmon-{}-{}", a.guid, kind),
        },
        at: 0,
        chat_id: root.chat.clone(),
        harness: root.harness.clone(),
        source,
        kind: kind.into(),
        summary: cut(&summary),
        detail: Value::Object(d),
        pid: Some(a.pid),
        approval_id: None,
    }
}
