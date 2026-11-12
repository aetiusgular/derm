//! Whose files the gate trusts, ported by the wave 5b base from the hook
//! core's `packages/derm-claude-plugin/src/core/owner.ts` at `e29ce27` (wave 5
//! lane V, S2 part c; rules cases 53 and 125).
//!
//! A gate trusts its policy, the daemon's socket and its chat token only
//! when they are owned by the right user. Run as the person, that is the
//! person's own uid. Run as an agents' user (`derm run` starts the harness as
//! a second local user, `packaging/linux/agent-user/`), it is the person that
//! user works for, and never the agents' user itself: anything the agent
//! owns, the agent could have written. Which uid is an agents' user, and for
//! whom, comes from `/etc/derm/agent-users.json`, trusted only when root owns
//! every part of its path and no one else can write it (the rule
//! `crates/derm-cli/src/run/user/anchor.rs` applies). A file there that
//! cannot be trusted or read makes the gate trust no one, so every call
//! asks: a broken root file is never read as "no agents' user".
//!
//! Windows has no uid; there [`trusted_owners`] is `None` and every owner
//! check is made by the file's access list instead (`platform::windows`).

use serde_json::Value;

/// The anchor file (`ANCHOR` in `owner.ts`).
pub const ANCHOR: &str = "/etc/derm/agent-users.json";
const MAX_BYTES: u64 = 64 * 1024;

/// Whose files this process trusts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owners {
    /// The uids whose files this gate trusts; empty trusts no one.
    pub uids: Vec<u32>,
    /// True when this process is an agents' user.
    pub agent: bool,
    pub problem: Option<String>,
}

fn none(agent: bool, problem: String) -> Owners {
    Owners {
        uids: Vec::new(),
        agent,
        problem: Some(problem),
    }
}

/// What an anchor's text says about `uid` (`ownersFor`). `text` `None`: no
/// file.
pub fn owners_for(uid: u32, text: Option<&str>) -> Owners {
    let Some(text) = text else {
        return Owners {
            uids: vec![uid],
            agent: false,
            problem: None,
        };
    };
    let Ok(parsed) = serde_json::from_str::<Value>(text) else {
        return none(false, format!("{ANCHOR} is not JSON"));
    };
    let agents = match (&parsed, parsed.get("version"), parsed.get("agents")) {
        (Value::Object(_), Some(v), Some(Value::Array(a))) if v.as_f64() == Some(1.0) => a,
        _ => return none(false, format!("{ANCHOR} is not version 1")),
    };
    // JavaScript's Number.isInteger: an integer value, written as a JSON
    // number (1.0 counts, "1" does not).
    let int = |v: Option<&Value>| -> Option<i64> {
        let f = v?.as_f64()?;
        (f.fract() == 0.0 && f.is_finite()).then_some(f as i64)
    };
    let mut mine = Vec::new();
    for e in agents {
        if !e.is_object() {
            return none(false, format!("{ANCHOR} has an entry without numeric uids"));
        }
        let (Some(a), Some(o)) = (int(e.get("uid")), int(e.get("ownerUid"))) else {
            return none(false, format!("{ANCHOR} has an entry without numeric uids"));
        };
        if a == i64::from(uid) {
            mine.push(o);
        }
    }
    match mine.as_slice() {
        [] => Owners {
            uids: vec![uid],
            agent: false,
            problem: None,
        },
        [owner] => {
            if *owner == i64::from(uid) || *owner == 0 || u32::try_from(*owner).is_err() {
                none(
                    true,
                    format!("{ANCHOR} names an owner that separates nothing"),
                )
            } else {
                Owners {
                    uids: vec![*owner as u32],
                    agent: true,
                    problem: None,
                }
            }
        }
        _ => none(
            true,
            format!("{ANCHOR} names uid {uid} for more than one owner"),
        ),
    }
}

/// What reading the anchor gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// No file: no agents' user on this machine.
    Absent,
    Text(String),
    /// The file is there and cannot be trusted or read.
    Problem(String),
}

/// The anchor's text, `Absent`, or why it cannot be trusted (`readAnchor`).
/// `from` and `trusted` are for tests: outside them every part of the path
/// from `/` must be root's.
#[cfg(unix)]
pub fn read_anchor(file: &std::path::Path, from: &std::path::Path, trusted: u32) -> Anchor {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let shown = file.display();
    match std::fs::symlink_metadata(file) {
        Ok(_) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            return Anchor::Absent
        }
        Err(_) => return Anchor::Problem(format!("{shown} cannot be read")),
    }
    let Ok(rel) = file.strip_prefix(from) else {
        return Anchor::Problem(format!("{shown} is not under {}", from.display()));
    };
    let mut parts = vec![from.to_path_buf()];
    let mut at = from.to_path_buf();
    for c in rel.components() {
        at.push(c);
        parts.push(at.clone());
    }
    for p in &parts {
        let Ok(m) = std::fs::symlink_metadata(p) else {
            return Anchor::Problem(format!("{} cannot be read", p.display()));
        };
        if m.file_type().is_symlink() {
            return Anchor::Problem(format!("{} is a link", p.display()));
        }
        if m.uid() != trusted {
            return Anchor::Problem(format!("{} is not owned by uid {trusted}", p.display()));
        }
        if m.mode() & 0o022 != 0 {
            return Anchor::Problem(format!("{} can be written by group or others", p.display()));
        }
    }
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(file);
    let Ok(f) = opened else {
        return Anchor::Problem(format!("{shown} cannot be read"));
    };
    let Ok(m) = f.metadata() else {
        return Anchor::Problem(format!("{shown} cannot be read"));
    };
    if !m.is_file() || m.len() > MAX_BYTES {
        return Anchor::Problem(format!("{shown} is not a small regular file"));
    }
    let mut buf = Vec::new();
    if (&f).take(MAX_BYTES).read_to_end(&mut buf).is_err() {
        return Anchor::Problem(format!("{shown} cannot be read"));
    }
    Anchor::Text(String::from_utf8_lossy(&buf).into_owned())
}

/// Held by every test that calls [`set_owners_for_test`].
#[doc(hidden)]
pub static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(unix)]
static OWNERS: std::sync::Mutex<Option<Owners>> = std::sync::Mutex::new(None);

/// This process's trusted owners, read once (`trustedOwners`). `None` where
/// the system keeps no uids (Windows).
#[cfg(unix)]
pub fn trusted_owners() -> Option<Owners> {
    let mut cached = OWNERS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(o) = cached.as_ref() {
        return Some(o.clone());
    }
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let o = match read_anchor(std::path::Path::new(ANCHOR), std::path::Path::new("/"), 0) {
        Anchor::Absent => owners_for(uid, None),
        Anchor::Text(t) => owners_for(uid, Some(&t)),
        Anchor::Problem(p) => none(false, p),
    };
    *cached = Some(o.clone());
    Some(o)
}

#[cfg(not(unix))]
pub fn trusted_owners() -> Option<Owners> {
    None
}

/// For tests only: what [`trusted_owners`] returns (`None`: read again).
/// Tests that set it hold [`TEST_LOCK`] for their whole run, since the
/// answer is process-wide.
#[doc(hidden)]
#[cfg(unix)]
pub fn set_owners_for_test(o: Option<Owners>) {
    *OWNERS.lock().unwrap_or_else(|e| e.into_inner()) = o;
}

/// Whether a file owned by `uid` is trusted (true where uids are not kept).
pub fn owned_by_trusted(uid: u32) -> bool {
    match trusted_owners() {
        None => true,
        Some(o) => o.uids.contains(&uid),
    }
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;
