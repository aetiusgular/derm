//! The light tier's per-chat log (wave 6, lane 6B; `plans/toolkit_wave6_plan.md`
//! section 2.1; `contracts/events.md` section 6.4). Every adapter record goes
//! through [`daemon::post_event`], which calls [`after_post`] with whether
//! the daemon took it. A record the daemon did not take (no `derm run`, so
//! no chat token; no daemon; a daemon that refused it) is appended to
//! `~/.derm/local/<chat>.jsonl` as one chain v2 line (`derm_core::audit_chain`),
//! so post records are no longer lost (note AZ, AZ-2).
//!
//! How a line is written (note AZ rows B3 to B5, AZ-8, all run on Linux,
//! APFS and NTFS by the wave 6 base):
//! - the file is opened for read and append (an append-only handle cannot be
//!   locked on Windows, error 5) and locked with `File::try_lock`, retried
//!   until [`DEADLINE`]: several hooks of one chat run at once (a Claude Code
//!   subagent's calls carry the parent's `session_id` and run in the
//!   background, B3), and without the lock 3 of 3 runs tore lines (B5);
//! - the last line is read back under the lock and the new line chains from
//!   it; a file whose last line is torn or not chain v2 is left as it is and
//!   the append fails (the break stays visible to `derm audit verify`);
//! - the line and its newline go out in one `write` (`writeln!` on an
//!   unbuffered file makes several and tore lines under contention, B5);
//! - on Windows a sharing violation (error 32: another process holds the
//!   file without write sharing, an editor or an indexer) is retried until
//!   the deadline (AZ-8).
//!
//! What a failed append means is the caller's: [`denies`] says when a pre
//! event must become a deny (the light tier, a hook with no chat token);
//! wiring it into the dialects is integration's (`gate/` outside this folder
//! and `hook/` are no lane's; `plans/parallel/tk_lane_6B.md`, requests).
//!
//! Not covered (note AZ, S1): calls decided outside `crates/derm-cli/src/gate/`
//! never reach this seam: Amp's plugin, the sbx kit's embedded Claude Code
//! hook, and gates registered from the compat and native packages' own
//! template files. `derm init` names them per agent.
//!
//! What the file proves (case 216): the agent can write it, so an edited,
//! dropped, reordered or relabelled line shows, and a cut anywhere but the
//! end; a cut at the end or a whole rewrite shows only against an anchor
//! (`derm audit anchor`, lane 6E).
//!
//! [`daemon::post_event`]: super::daemon::post_event

mod file;
mod name;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::daemon::{AdapterEvent, Env};

pub use name::file_name;

/// How long an append waits for the lock, or for a sharing violation to
/// clear on Windows. Below every hook timeout derm registers: 30 s for the
/// post hooks of Claude Code's and Codex's plugins, 120 s for every other
/// hook (`connect/gates.json`, the plugins' `hooks/hooks.json`, read 12 Nov);
/// with `post_event`'s own worst case (0.8 s connect, 2 s hello, 1.5 s
/// reply) it stays under 6 s. A locked append took 0.8 ms on APFS and
/// 10.9 ms on NTFS on average under 8-way contention, at worst 17 ms and
/// 24 ms (note AZ B4). Fixed: a variable a project's settings can set must
/// not lengthen it past an agent's timeout (case 70: some agents let a call
/// through when a hook times out) or shorten it to deny every call.
pub const DEADLINE: Duration = Duration::from_millis(1000);

/// What the light tier did with one record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to do: the daemon took the record.
    Skipped,
    /// Appended to the chat's file, as line `seq`.
    Appended { seq: u64 },
    /// The append failed, and why. A pre event in the light tier is a deny
    /// ([`denies`]).
    Failed(String),
}

/// The seam `post_event` calls after the daemon answered (`posted`).
pub fn after_post(event: &AdapterEvent, env: &Env, cwd: &Path, posted: bool) -> Outcome {
    after_post_with(event, env, cwd, posted, &System::real())
}

/// What the light tier reads of the system before it writes (case 270).
pub struct System {
    /// `/proc/self/net/dev`, on Linux.
    pub netdev: Option<String>,
    /// `/proc/self/mountinfo`, on Linux.
    pub mountinfo: Option<String>,
}

impl System {
    pub fn real() -> System {
        let linux = cfg!(target_os = "linux");
        let read = |p: &str| linux.then(|| std::fs::read_to_string(p).ok()).flatten();
        System {
            netdev: read("/proc/self/net/dev"),
            mountinfo: read("/proc/self/mountinfo"),
        }
    }
}

/// Why a file written in `home`'s `.derm` would not reach the disk the
/// person reads it from, or `None` (re-review W6C-R7, case 270; Tony's R7
/// call, option 1): a hook in a network with only `lo` (srt's on Linux,
/// which a project's settings cannot make for derm's hook), or a mount at or
/// under `~/.derm` (srt's `denyRead` of `~/.derm` is a tmpfs there, which
/// goes with the sandbox: run under srt 0.0.82 as a user, the append
/// succeeded and the host's folder stayed empty).
pub fn kept_away(home: &Path, sys: &System) -> Option<String> {
    if sys
        .netdev
        .as_deref()
        .is_some_and(super::daemon::only_loopback_netns)
    {
        return Some(
            "this hook runs in a sandbox's own network (only loopback, as srt's on Linux), where a file it writes in ~/.derm may never reach your disk"
                .into(),
        );
    }
    let derm = home.join(".derm");
    let derm = derm.to_string_lossy();
    for line in sys.mountinfo.as_deref().unwrap_or("").lines() {
        let Some(at) = line.split(' ').nth(4).map(unescape_mount) else {
            continue;
        };
        if at == derm || at.starts_with(&format!("{derm}/")) {
            return Some(format!(
                "{at} is a mount here (srt's tmpfs over ~/.derm), so a file written there goes with the sandbox"
            ));
        }
    }
    None
}

/// `/proc/self/mountinfo` writes a space, a tab, a newline and `\` in a
/// mount point as `\040`, `\011`, `\012` and `\134` (proc(5)).
fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = b.get(i + 1..i + 4).filter(|t| {
            b[i] == b'\\' && t.iter().all(|c| (b'0'..=b'7').contains(c))
        });
        let n = octal.and_then(|t| {
            let v = u16::from(t[0] - b'0') * 64 + u16::from(t[1] - b'0') * 8 + u16::from(t[2] - b'0');
            u8::try_from(v).ok()
        });
        if let Some(n) = n {
            out.push(n);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// [`after_post`] with the system's facts given.
pub fn after_post_with(
    event: &AdapterEvent,
    env: &Env,
    _cwd: &Path,
    posted: bool,
    sys: &System,
) -> Outcome {
    if posted {
        return Outcome::Skipped;
    }
    let Some(home) = home(env) else {
        return Outcome::Failed(
            "derm's light-tier log: no home folder (HOME is not an absolute path)".into(),
        );
    };
    if let Some(why) = kept_away(&home, sys) {
        return Outcome::Failed(format!(
            "derm's light-tier log: {why}; under derm run the gate's records go to the daemon, and one it could not post is not kept here"
        ));
    }
    match append(&home, event, now_ms(), DEADLINE) {
        Ok(seq) => Outcome::Appended { seq },
        Err(why) => Outcome::Failed(format!("derm's light-tier log: {why}")),
    }
}

/// The reason a pre event must be denied after `outcome`, or `None`. Only in
/// the light tier: a hook that is not part of a `derm run` chat
/// (`daemon::derm_run_chat`: a chat token and a real `derm run` above it).
/// A `derm run` chat's record is the daemon's: under srt `~/.derm` is denied
/// to its hooks (note AZ B8), and a daemon restart kills the chat's token
/// (case 86). A token with no `derm run` above it is the light tier's, since
/// a project can set the variable (integration w6's review, W6C-S4).
pub fn denies(outcome: &Outcome, env: &Env, cwd: &Path) -> Option<String> {
    match outcome {
        Outcome::Failed(why) if !super::daemon::derm_run_chat(env, cwd) => Some(format!(
            "{why}; with no daemon a call is not run unrecorded (derm's light tier fails closed)"
        )),
        _ => None,
    }
}

/// The folder the light tier writes in, under `home`.
pub fn folder(home: &Path) -> PathBuf {
    home.join(".derm").join("local")
}

/// The chat's log under `home`.
#[allow(dead_code)] // for `derm audit` (lane 6E) and `derm status` to find a chat's file
pub fn log_path(home: &Path, chat: &str) -> PathBuf {
    folder(home).join(file_name(chat))
}

/// The hook's home: `HOME` on Unix, `USERPROFILE` on Windows, from the
/// hook's own environment (as `derm_core::runtime::home_dir` reads the
/// process's), and only an absolute path.
fn home(env: &Env) -> Option<PathBuf> {
    #[cfg(windows)]
    let key = "USERPROFILE";
    #[cfg(not(windows))]
    let key = "HOME";
    env.get(key).map(PathBuf::from).filter(|p| p.is_absolute())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The record a line holds: the event object `post_event` sends the daemon
/// (`contracts/events.md` section 4), with `at` stamped here, since no
/// daemon stamps it. A float anywhere is written as its decimal text: chain
/// v2 holds none (other JSON writers print floats differently, note AZ E2),
/// and refusing the line would deny the call.
pub fn record(event: &AdapterEvent, at: u64) -> Value {
    let mut detail = Map::new();
    detail.insert("trust".into(), json!("client"));
    for (k, v) in &event.detail {
        detail.insert(k.clone(), no_floats(v.clone()));
    }
    // `post_event` cuts the summary at 200 UTF-16 units and drops a lone
    // surrogate half; the same here, so both copies agree.
    let units: Vec<u16> = event.summary.encode_utf16().take(200).collect();
    let summary: String = char::decode_utf16(units).filter_map(Result::ok).collect();
    json!({
        "id": event.id,
        "chatId": event.chat_id,
        "harness": event.harness,
        "kind": event.kind,
        "summary": summary,
        "detail": detail,
        "at": at,
        "source": "adapter",
    })
}

fn no_floats(v: Value) -> Value {
    match v {
        Value::Number(n) if !(n.is_i64() || n.is_u64()) => Value::String(n.to_string()),
        Value::Array(a) => Value::Array(a.into_iter().map(no_floats).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, no_floats(v))).collect()),
        other => other,
    }
}

/// Appends `event` to its chat's file under `home`, waiting at most
/// `deadline` for the lock. The new line's `seq`, or why nothing was
/// appended.
pub fn append(
    home: &Path,
    event: &AdapterEvent,
    at: u64,
    deadline: Duration,
) -> Result<u64, String> {
    let rec = record(event, at);
    file::append_line(
        &folder(home),
        &file_name(&event.chat_id),
        &event.kind,
        &rec,
        deadline,
    )
}
