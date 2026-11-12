//! `derm enter` on Windows: the handle checks and the start
//! (`contracts/srt-windows.md` sections 2 and 4).
//!
//! It runs as srt's sandbox account under a write-restricted token whose
//! only privilege is `SeChangeNotifyPrivilege` (srt 0.0.82
//! `vendor/srt-win-src/src/token.rs:21-34, 249`), so it reaches the chat's
//! folder by its full path without rights on the folders above it, and
//! reads the three files there by the read grant `derm run` gave the
//! account on each (`run/boundary/windows_srt/`).
//!
//! Every file is opened with `FILE_FLAG_OPEN_REPARSE_POINT`, refused when it
//! is a reparse point or not a regular file, and judged on that handle. A
//! file this account can open for writing, or whose access list it can
//! change, is refused: one the agent could have made or rewritten.

use std::io::Read;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;

use super::handoff::{self, Handoff};

/// `FILE_FLAG_OPEN_REPARSE_POINT` (winbase.h).
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_ATTRIBUTE_REPARSE_POINT` (winnt.h).
const ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
/// `GENERIC_READ`, `DELETE` and `WRITE_DAC` (winnt.h).
const GENERIC_READ: u32 = 0x8000_0000;
const WRITE_DAC: u32 = 0x0004_0000;

/// Reads a regular file that is not a reparse point, at most the handoff's
/// size, judged on the handle it was read from. Also says whether this
/// account could have written it.
pub(super) fn read_plain(path: &Path) -> Result<(Vec<u8>, bool), String> {
    let f = std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    if meta.file_attributes() & ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("{}: a link or junction; refused", path.display()));
    }
    if !meta.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if meta.len() > handoff::MAX_BYTES {
        return Err(format!(
            "{}: over {} bytes",
            path.display(),
            handoff::MAX_BYTES
        ));
    }
    let mut out = Vec::new();
    (&f).take(handoff::MAX_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    Ok((out, writable_here(path)))
}

/// Whether this account can open `path` for writing or change its access
/// list: the system's own access check, restricting SIDs included. Only
/// "access denied" counts as no: any other failure (a sharing violation from
/// a handle someone holds open, say) is taken as yes, so it refuses.
pub(super) fn writable_here(path: &Path) -> bool {
    /// `ERROR_ACCESS_DENIED` (winerror.h).
    const ACCESS_DENIED: i32 = 5;
    let open = |access: u32| match std::fs::OpenOptions::new()
        .access_mode(access)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(_) => true,
        Err(e) => e.raw_os_error() != Some(ACCESS_DENIED),
    };
    // `GENERIC_WRITE` (winnt.h) and `WRITE_DAC`.
    open(0x4000_0000) || open(WRITE_DAC)
}

fn refuse(why: String) -> u8 {
    eprintln!("derm enter: {why}; nothing is started");
    2
}

/// A file beside the handoff: read-only to this account, plain, small.
fn read_sibling(path: &Path) -> Result<Vec<u8>, String> {
    let (bytes, writable) = read_plain(path)?;
    if writable {
        return Err(format!(
            "{} can be written by this account, so the agent could have made it",
            path.display()
        ));
    }
    Ok(bytes)
}

pub(super) fn start(path: &Path) -> u8 {
    let (bytes, writable) = match read_plain(path) {
        Ok(r) => r,
        Err(e) => return refuse(e),
    };
    if writable {
        return refuse(format!(
            "{} can be written by this account, so the agent could have made it",
            path.display()
        ));
    }
    let h = match handoff::parse(&bytes, super::now_ms()) {
        Ok(h) => h,
        Err(e) => return refuse(e),
    };
    // Read once: the handoff goes now, so nothing else in the sandbox reads
    // it (case 231). `derm run` gave this account delete on it alone; where
    // that does not hold, `derm run` removes it when the chat stops.
    if let Err(e) = std::fs::remove_file(path) {
        eprintln!(
            "derm enter: could not delete the handoff ({e}); derm run removes it when the chat stops"
        );
    }
    let (token_file, chat_file) = super::siblings(path);
    match read_sibling(&token_file) {
        Ok(t) if String::from_utf8_lossy(&t).trim() == h.token => {}
        Ok(_) => return refuse("the token file does not hold the handoff's token".into()),
        Err(e) => return refuse(e),
    }
    match read_sibling(&chat_file)
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).map_err(|e| e.to_string()))
    {
        Ok(v) if v == handoff::chat_file_json(&h) => {}
        Ok(_) => return refuse("chat.json does not match the handoff".into()),
        Err(e) => return refuse(format!("{}: {e}", chat_file.display())),
    }
    run(&h, &token_file, &chat_file)
}

/// Starts the harness as the handoff names it, with the chat's variables,
/// and returns its exit code.
fn run(h: &Handoff, token_file: &Path, chat_file: &Path) -> u8 {
    let mut cmd = Command::new(&h.argv[0]);
    cmd.args(&h.argv[1..]).current_dir(&h.cwd);
    for name in crate::run::plan::OWNED_VARS {
        cmd.env_remove(name);
    }
    for (k, v) in &h.variables {
        cmd.env(k, v);
    }
    cmd.env("DERM_CHAT_TOKEN", &h.token)
        .env("DERM_CHAT_TOKEN_FILE", token_file)
        .env("DERM_CHAT_FILE", chat_file);
    ctrl::stay_for_the_harness();
    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => return refuse(format!("{}: {e}", h.argv[0])),
    };
    match status.code() {
        Some(c) if (0..=255).contains(&c) => c as u8,
        _ => 1,
    }
}

mod ctrl {
    use windows_sys::core::BOOL;
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT,
    };

    /// Ctrl-C and Ctrl-Break reach every process on the console, the
    /// harness too ("cannot be limited to a specific process group",
    /// `GenerateConsoleCtrlEvent`), so `derm enter` takes them as handled and
    /// waits for the harness to answer them itself: one stop, as `derm run`
    /// does (case 142). A handler routine, not `SetConsoleCtrlHandler(NULL,
    /// TRUE)`, whose ignore flag the harness would inherit (`SetConsoleCtrlHandler`
    /// page). A console close still ends this process.
    unsafe extern "system" fn handler(kind: u32) -> BOOL {
        BOOL::from(kind == CTRL_C_EVENT || kind == CTRL_BREAK_EVENT)
    }

    pub(super) fn stay_for_the_harness() {
        // SAFETY: `handler` is a plain function that lives for the process.
        unsafe {
            SetConsoleCtrlHandler(Some(handler), 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("derm-enter-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_file_of_ours_is_writable_here_and_its_bytes_read() {
        let d = scratch("mine");
        let f = d.join("h.json");
        std::fs::write(&f, b"{}").unwrap();
        let (bytes, writable) = read_plain(&f).unwrap();
        assert_eq!(bytes, b"{}");
        assert!(writable);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_file_we_may_only_read_is_not_writable_here() {
        let d = scratch("ro");
        let f = d.join("h.json");
        std::fs::write(&f, b"{}").unwrap();
        // Read and execute for us alone, as `derm run` grants the sandbox
        // account: no write, no WRITE_DAC. The owner keeps READ_CONTROL and
        // WRITE_DAC by ownership unless an OWNER RIGHTS entry says otherwise
        // (Microsoft Learn, "SID strings": OW), so one is added.
        let me = derm_core::platform::windows::effective_user();
        let sddl = format!("D:P(A;;FR;;;{me})(A;;FR;;;OW)");
        derm_core::platform::windows::set_dacl_sddl(&f, &sddl).unwrap();
        let (_, writable) = read_plain(&f).unwrap();
        assert!(!writable);
        assert!(read_sibling(&f).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_file_held_open_with_no_write_sharing_counts_as_writable() {
        let d = scratch("held");
        let f = d.join("h.json");
        std::fs::write(&f, b"{}").unwrap();
        let me = derm_core::platform::windows::effective_user();
        let sddl = format!("D:P(A;;FR;;;{me})(A;;FR;;;OW)");
        // Held open for reading with no write sharing: a write open fails
        // with a sharing violation, not "access denied".
        let _held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1) // FILE_SHARE_READ
            .open(&f)
            .unwrap();
        assert!(writable_here(&f));
        drop(_held);
        derm_core::platform::windows::set_dacl_sddl(&f, &sddl).unwrap();
        assert!(!writable_here(&f));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_folder_or_a_link_is_refused() {
        let d = scratch("kinds");
        assert!(read_plain(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
