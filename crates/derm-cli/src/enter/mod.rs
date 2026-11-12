//! `derm enter <handoff>`: the command srt runs inside its sandbox account
//! on Windows (`contracts/srt-windows.md`; wave 5b lane 5bD). It reads the
//! chat's handoff file once, by handle, deletes it, sets the chat's
//! variables and starts the harness by its absolute path. It never runs a
//! shell (case 138).
//!
//! `derm enter --check <handoff>` reads and judges a handoff and prints one
//! JSON line saying what a start would do; it starts nothing, deletes
//! nothing and prints no token. It runs on every OS; the checks only
//! Windows can make are named in `skipped` elsewhere.
//!
//! What `derm run` leaves beside the handoff, in the same folder (the
//! chat's, user-only but for the sandbox account's read grant on these
//! three; `run/boundary/windows_srt/`):
//! - `token`: the chat token, for `DERM_CHAT_TOKEN_FILE` (case 76);
//! - `chat.json`: the policy `derm run` judged on the host and the daemon's
//!   route, for `DERM_CHAT_FILE`, so the gate inside takes neither from a
//!   variable a project can set (lane 5bD's reading of contract section 2,
//!   item 4; a request for integration).

pub(crate) mod handoff;
#[cfg(windows)]
mod win;

use std::path::{Path, PathBuf};

use serde_json::json;

pub(crate) const TOKEN_FILE: &str = "token";
pub(crate) const CHAT_FILE: &str = "chat.json";

const USAGE: &str = "usage: derm enter <handoff> | derm enter --check <handoff>";

pub fn main(args: &[String]) -> u8 {
    match args {
        [flag, file] if flag == "--check" => check(Path::new(file)),
        [file] if !file.starts_with('-') => start(Path::new(file)),
        _ => {
            eprintln!("{USAGE}");
            2
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The two files `derm run` writes beside a handoff.
pub(crate) fn siblings(handoff: &Path) -> (PathBuf, PathBuf) {
    let dir = handoff.parent().unwrap_or(Path::new(""));
    (dir.join(TOKEN_FILE), dir.join(CHAT_FILE))
}

/// The names `derm enter` sets in the harness's environment: the handoff's
/// variables and its own three.
pub(crate) fn variable_names(h: &handoff::Handoff) -> Vec<String> {
    let mut names: Vec<String> = h.variables.keys().cloned().collect();
    names.extend(["DERM_CHAT_TOKEN", "DERM_CHAT_TOKEN_FILE", "DERM_CHAT_FILE"].map(str::to_string));
    names.sort();
    names
}

/// The file's bytes, read the safe way this OS allows: never through a
/// link, only a regular file, at most the handoff's size.
fn read_plain(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        win::read_plain(path).map(|(bytes, _)| bytes)
    }
    #[cfg(not(windows))]
    {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let meta = f.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() {
            return Err(format!("{}: not a regular file", path.display()));
        }
        if meta.len() > handoff::MAX_BYTES {
            return Err(format!("handoff: over {} bytes", handoff::MAX_BYTES));
        }
        let mut out = Vec::new();
        f.take(handoff::MAX_BYTES + 1)
            .read_to_end(&mut out)
            .map_err(|e| e.to_string())?;
        Ok(out)
    }
}

fn check(path: &Path) -> u8 {
    let bytes = match read_plain(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("derm enter: {e}");
            return 2;
        }
    };
    let h = match handoff::parse(&bytes, now_ms()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("derm enter: {e}");
            return 2;
        }
    };
    let (token_file, chat_file) = siblings(path);
    let mut out = json!({
        "ok": true,
        "chat": h.chat,
        "harness": h.harness,
        "program": h.argv[0],
        "args": h.argv.len() - 1,
        "cwd": h.cwd,
        "variables": variable_names(&h),
        "tokenFile": token_file.to_string_lossy(),
        "chatFile": chat_file.to_string_lossy(),
        "daemon": h.daemon_http,
        "policyProblem": h.policy_problem,
        "expires": h.expires,
    });
    #[cfg(windows)]
    {
        out["writableHere"] = json!(win::writable_here(path));
        out["skipped"] = json!([]);
    }
    #[cfg(not(windows))]
    {
        // The sandbox account's grant, the reparse-point check by handle and
        // the start itself are Windows' (contract section 2, item 6).
        out["skipped"] = json!(["acl", "reparse", "start"]);
    }
    println!("{out}");
    0
}

fn start(path: &Path) -> u8 {
    #[cfg(windows)]
    {
        win::start(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        eprintln!(
            "derm enter: runs only inside srt's sandbox on Windows (derm run --boundary srt starts it); nothing is started"
        );
        2
    }
}

#[cfg(test)]
mod tests;
