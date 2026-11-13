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
pub fn after_post(event: &AdapterEvent, env: &Env, _cwd: &Path, posted: bool) -> Outcome {
    if posted {
        return Outcome::Skipped;
    }
    let Some(home) = home(env) else {
        return Outcome::Failed(
            "derm's light-tier log: no home folder (HOME is not an absolute path)".into(),
        );
    };
    match append(&home, event, now_ms(), DEADLINE) {
        Ok(seq) => Outcome::Appended { seq },
        Err(why) => Outcome::Failed(format!("derm's light-tier log: {why}")),
    }
}

/// The reason a pre event must be denied after `outcome`, or `None`. Only in
/// the light tier proper: a hook with no chat token, so no `derm run` and no
/// daemon will hold the record. A `derm run` chat's record is the daemon's:
/// under srt `~/.derm` is denied to its hooks (note AZ B8), and a daemon
/// restart kills the chat's token (case 86), so failing closed there would
/// deny every call of a chat whose daemon restarted.
#[allow(dead_code)] // integration wires it into the dialects' pre events (request)
pub fn denies(outcome: &Outcome, env: &Env, cwd: &Path) -> Option<String> {
    match outcome {
        Outcome::Failed(why) if super::daemon::chat_token(env, cwd).is_none() => Some(format!(
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
