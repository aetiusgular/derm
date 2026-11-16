//! A chat's taint state as the gate and the daemon both hold it
//! (`contracts/events.md` section 6.2): marks, the files the chat wrote, the
//! hosts it reached. One type, one merge rule, so the light tier's file
//! (`derm-cli`'s `gate/taint/state.rs`) and the daemon's memory
//! (`derm-daemon`'s `taint/`) agree. Nothing is ever removed by a merge: a
//! writer, an agent included, can add taint and never take it away.

use serde::{Deserialize, Serialize};

/// Marks, written files and hosts kept; past either the state says so and
/// counts every later one as known (written) or new (hosts).
pub const MAX_MARKS: usize = 256;
pub const MAX_WRITTEN: usize = 4096;
pub const MAX_HOSTS: usize = 4096;

/// What made a chat tainted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mark {
    /// The `taint.mark` record's id.
    pub id: String,
    /// `untrusted-content` or `secret-read`.
    pub reason: String,
    /// `web`, `mcp`, `unknown-tool` or `secret`.
    pub kind: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub v: u32,
    #[serde(default)]
    pub marks: Vec<Mark>,
    /// Keys of files the chat wrote (`paths::key`).
    #[serde(default)]
    pub written: Vec<String>,
    #[serde(default)]
    pub written_full: bool,
    /// Fingerprints of hosts the chat reached (`derm_tap::results::fingerprint`).
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub hosts_full: bool,
    /// The state could not be read: tainted, and every run is of the
    /// chat's own code.
    #[serde(default)]
    pub unreadable: bool,
}

impl State {
    pub fn tainted(&self) -> bool {
        !self.marks.is_empty() || self.unreadable
    }

    /// The state after `other`'s additions; nothing is ever removed.
    pub fn merge(&mut self, other: &State) {
        for m in &other.marks {
            if self.marks.len() >= MAX_MARKS {
                break;
            }
            if !self.marks.iter().any(|x| x.id == m.id) {
                self.marks.push(m.clone());
            }
        }
        for w in &other.written {
            if !self.written.contains(w) {
                if self.written.len() >= MAX_WRITTEN {
                    self.written_full = true;
                    break;
                }
                self.written.push(w.clone());
            }
        }
        for h in &other.hosts {
            if !self.hosts.contains(h) {
                if self.hosts.len() >= MAX_HOSTS {
                    self.hosts_full = true;
                    break;
                }
                self.hosts.push(h.clone());
            }
        }
        self.written_full |= other.written_full;
        self.hosts_full |= other.hosts_full;
        self.unreadable |= other.unreadable;
        self.v = 1;
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
            && self.written.is_empty()
            && self.hosts.is_empty()
            && !self.written_full
            && !self.hosts_full
            && !self.unreadable
    }

    /// A state that could not be read: tainted, and every run is of the
    /// chat's own code.
    pub fn unreadable() -> State {
        State {
            v: 1,
            unreadable: true,
            ..State::default()
        }
    }
}
