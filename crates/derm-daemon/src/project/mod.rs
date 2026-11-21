//! The daemon's half of step P (lane PE's; `contracts/daemon-protocol.md`
//! section 6, `contracts/project-tools.md`, `contracts/events.md` section 7).
//!
//! The base (20 Nov 2026) declares what `daemon.rs` calls, so lane PE never
//! edits `daemon.rs`: the chat-to-project map from `token.mint`, the stamp
//! on every stored event, and the five chat-scope and daemon-scope ops.
//! Until the lane builds them:
//!
//! - `note_mint` keeps nothing, so `project_of` is `""` for every chat;
//! - `stamp` sets every event's `project` to `project_of` its chat, over any
//!   client value (the safe half of Tony's C2 call; the count is the lane's);
//! - every op answers `not built`.
//!
//! The red tests are `crates/derm-daemon/tests/contracts_acctp.rs`.

use derm_core::event::Event;

use crate::daemon::error;
use crate::protocol::Reply;

/// Who sent an op line, as `daemon.rs` resolved the connection's token.
#[derive(Clone, Copy, Debug)]
pub enum Caller<'a> {
    Daemon,
    Chat { chat: &'a str, harness: &'a str },
}

/// The project layer's state, held by the daemon.
#[derive(Default)]
pub struct State {}

impl State {
    /// `token.mint`'s `project` (an id or `""`; checked by the caller), kept
    /// beside the token and in `chats.json` (contracts/daemon-protocol.md
    /// section 6.1). Not built.
    pub fn note_mint(&self, _chat: &str, _project: &str) {}

    /// The project the daemon holds for `chat`, `""` when none. Not built:
    /// always `""`.
    pub fn project_of(&self, _chat: &str) -> String {
        String::new()
    }

    /// Sets `event.project` to the project of its chat, whatever the client
    /// sent, and counts an event whose client value differed
    /// (contracts/events.md 7.1). Built here only as the overwrite; the count
    /// is lane PE's.
    pub fn stamp(&self, event: &mut Event) {
        event.project = self.project_of(&event.chat_id);
    }

    /// How many events arrived with a `project` other than the daemon's.
    /// Not built: 0.
    pub fn overwritten(&self) -> u64 {
        0
    }

    /// `msg.send {to, text, replyTo?}`, chat scope (project-tools.md 1).
    pub fn msg_send(
        &self,
        _caller: Caller<'_>,
        _to: &str,
        _text: &str,
        _reply_to: Option<&str>,
    ) -> Reply {
        error("msg.send: not built (lane PE)")
    }

    /// `msg.take {}`, chat scope.
    pub fn msg_take(&self, _caller: Caller<'_>) -> Reply {
        error("msg.take: not built (lane PE)")
    }

    /// `screen.read {chat, lines?}`, chat scope.
    pub fn screen_read(&self, _caller: Caller<'_>, _chat: &str, _lines: Option<u32>) -> Reply {
        error("screen.read: not built (lane PE)")
    }

    /// `screen.list {}`, chat scope.
    pub fn screen_list(&self, _caller: Caller<'_>) -> Reply {
        error("screen.list: not built (lane PE)")
    }

    /// `screen.put {...}`, daemon scope only (`derm run`, lane PD's client).
    pub fn screen_put(&self, _caller: Caller<'_>, _put: &crate::protocol::ScreenPut) -> Reply {
        error("screen.put: not built (lane PE)")
    }

    /// What `chats.json` keeps of the map (`daemon.rs` `save_state`). Not
    /// built: `null`.
    pub fn saved(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    /// The map back from `chats.json`'s `projects` after a restart, for the
    /// chats whose tokens came back (case 211). Not built.
    pub fn restore(&self, _saved: &serde_json::Value) {}

    /// A chat's `run.stop`: its screen, its waiting messages and the session
    /// grants it holds end (P-C7). Not built.
    pub fn forget_chat(&self, _chat: &str) {}
}
