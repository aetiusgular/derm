//! Taint in the daemon (wave 6, lane 6D; `plans/toolkit_wave6_plan.md`
//! section 2.2; `contracts/policy.md` section 9; `contracts/events.md`
//! section 6.2).
//!
//! Under `derm run` the gate keeps a chat's taint here instead of in the
//! light tier's file (`derm-cli`'s `gate/taint/state.rs`), for two reasons:
//! under srt `~/.derm` is denied to the harness's hooks (note AZ B8), and the
//! chat's verdict is the person's (`derm run --taint`, `run.start`'s
//! `detail.taint`), which only the daemon's record of the start can say: a
//! hook's environment is the project's to set (case 227).
//!
//! What it keeps, per chat, in memory only: the state the gate adds (the
//! shared type `derm_tap::results::state::State`: mark ids and reasons, the
//! files the chat wrote by path, the hosts it reached as fingerprints), and
//! the verdict `run.start` named. The hosts untrusted results named are the
//! tap's (`derm_tap::results::named`), in the same process.
//!
//! The op (`{"op": "taint", "chat", "hosts", "add"?}`, a proposal for
//! `contracts/daemon-protocol.md` section 2, routed by integration):
//! [`Taints::handle`]. A chat token names only its own chat (case 66), and
//! what it adds only grows the state: a chat token is the agent's, so the
//! agent can add taint and never remove it, and it cannot name a verdict.
//! The reply: `verdict` and `from` (`flag`, `setting`, `default`), the
//! chat's `state`, and `named`, which of the `hosts` asked about an
//! untrusted result in the chat named.
//!
//! What feeds it, besides the op: [`Taints::on_event`] for every event the
//! daemon ingests, of which it reads two: `run.start` from `derm run`
//! (source `run`, which no chat token may post) for the verdict, and
//! `run.stop` to drop the chat.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use derm_core::event::{Event, Source};
use derm_tap::results::state::{State, MAX_HOSTS, MAX_MARKS, MAX_WRITTEN};
use derm_tap::results::verdict::{From, Verdict};
use derm_tap::results::{self, hosts};
use serde_json::{json, Value};

/// Chats kept; past it a stopped chat goes first, then the least recently
/// used.
pub const MAX_CHATS: usize = 256;
/// Hosts one request may ask about.
pub const MAX_ASKED: usize = 256;

#[derive(Default)]
struct Chat {
    id: String,
    flag: Option<Verdict>,
    stopped: bool,
    state: State,
}

/// Every chat's taint the daemon holds.
pub struct Taints {
    chats: Mutex<VecDeque<Chat>>,
    /// The home whose `~/.derm/settings.json` names the default verdict.
    home: Option<PathBuf>,
}

impl Taints {
    pub fn new(home: Option<PathBuf>) -> Taints {
        Taints {
            chats: Mutex::new(VecDeque::new()),
            home,
        }
    }

    fn with_chat<R>(&self, chat: &str, f: impl FnOnce(&mut Chat) -> R) -> Option<R> {
        let mut chats = self.chats.lock().ok()?;
        let pos = chats.iter().position(|c| c.id == chat);
        let mut c = match pos {
            Some(i) => chats.remove(i)?,
            None => Chat {
                id: chat.to_string(),
                ..Chat::default()
            },
        };
        let r = f(&mut c);
        chats.push_back(c);
        while chats.len() > MAX_CHATS {
            match chats.iter().position(|c| c.stopped) {
                Some(i) => {
                    chats.remove(i);
                }
                None => {
                    chats.pop_front();
                }
            }
        }
        Some(r)
    }

    /// Reads one ingested event: `run.start`'s verdict, `run.stop`.
    pub fn on_event(&self, e: &Event) {
        if e.source != Source::Run || e.chat_id.is_empty() {
            return;
        }
        match e.kind.as_str() {
            "run.start" => {
                let flag = e
                    .detail
                    .get("taint")
                    .filter(|t| t.get("from").and_then(Value::as_str) == Some("flag"))
                    .and_then(|t| t.get("verdict"))
                    .and_then(Value::as_str)
                    .and_then(Verdict::parse);
                self.with_chat(&e.chat_id, |c| {
                    c.flag = flag;
                    c.stopped = false;
                });
            }
            "run.stop" => {
                if let Ok(mut chats) = self.chats.lock() {
                    if let Some(c) = chats.iter_mut().find(|c| c.id == e.chat_id) {
                        c.stopped = true;
                    }
                }
                results::forget(&e.chat_id);
            }
            _ => {}
        }
    }

    /// The chat's verdict and where it came from.
    pub fn verdict(&self, chat: &str) -> (Verdict, From) {
        let flag = self
            .chats
            .lock()
            .ok()
            .and_then(|c| c.iter().find(|c| c.id == chat).and_then(|c| c.flag));
        if let Some(v) = flag {
            return (v, From::Flag);
        }
        let setting = self.home.as_ref().and_then(|h| {
            results::verdict::from_settings(&h.join(".derm").join("settings.json")).0
        });
        match setting {
            Some(v) => (v, From::Setting),
            None => (Verdict::Ask, From::Default),
        }
    }

    /// Whether the daemon knows `chat` as tainted.
    pub fn is_tainted(&self, chat: &str) -> bool {
        self.chats
            .lock()
            .ok()
            .and_then(|c| c.iter().find(|c| c.id == chat).map(|c| c.state.tainted()))
            .unwrap_or(false)
    }

    /// Answers one `taint` request. `scope_chat` is the chat of the token
    /// that sent it, `None` for the daemon's scope.
    pub fn handle(&self, scope_chat: Option<&str>, req: &Value) -> Value {
        match self.answer(scope_chat, req) {
            Ok(v) => v,
            Err(why) => json!({"ok": false, "error": why}),
        }
    }

    fn answer(&self, scope_chat: Option<&str>, req: &Value) -> Result<Value, String> {
        let o = req.as_object().ok_or("a taint request is an object")?;
        for k in o.keys() {
            if !matches!(k.as_str(), "op" | "chat" | "hosts" | "add") {
                return Err(format!("unknown field {k}"));
            }
        }
        if o.get("op").and_then(Value::as_str) != Some("taint") {
            return Err("not a taint request".into());
        }
        let chat = o
            .get("chat")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty() && c.len() <= 128)
            .ok_or("chat is a name of 1 to 128 characters")?;
        if let Some(own) = scope_chat {
            if own != chat {
                return Err("a chat token names only its own chat".into());
            }
        }
        let asked: Vec<String> = match o.get("hosts") {
            None => Vec::new(),
            Some(Value::Array(a)) if a.len() <= MAX_ASKED => a
                .iter()
                .map(|h| {
                    h.as_str()
                        .and_then(hosts::canonical)
                        .ok_or("a host is a name")
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(format!("hosts is a list of at most {MAX_ASKED} names")),
        };
        let add: Option<State> = match o.get("add") {
            None => None,
            Some(v) => {
                let s: State =
                    serde_json::from_value(v.clone()).map_err(|e| format!("add: {e}"))?;
                if s.marks.len() > MAX_MARKS
                    || s.written.len() > MAX_WRITTEN
                    || s.hosts.len() > MAX_HOSTS
                    || s.marks
                        .iter()
                        .any(|m| m.id.len() > 160 || m.tool.len() > 160)
                    || s.written.iter().any(|w| w.len() > 4096)
                    || s.hosts.iter().any(|h| h.len() != 64)
                {
                    return Err("add is larger than a state holds".into());
                }
                Some(s)
            }
        };
        let state = self
            .with_chat(chat, |c| {
                if let Some(a) = &add {
                    c.state.merge(a);
                }
                c.state.clone()
            })
            .ok_or("busy")?;
        let (verdict, from) = self.verdict(chat);
        let named = results::named(chat, &asked);
        Ok(json!({
            "ok": true,
            "verdict": verdict.as_str(),
            "from": from.as_str(),
            "state": state,
            "named": named,
        }))
    }
}

/// The daemon's one store (integration routes the op and the ingest to it).
pub fn global() -> &'static Taints {
    static T: OnceLock<Taints> = OnceLock::new();
    T.get_or_init(|| Taints::new(derm_core::runtime::home_dir()))
}

/// Whether a chat is tainted, as the daemon knows it.
pub fn is_tainted(chat: &str) -> bool {
    global().is_tainted(chat)
}

#[cfg(test)]
mod tests;
