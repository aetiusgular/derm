//! The chat's files on Windows and their lifetime: written as the user
//! before srt starts, removed as the chat ends ([`Session`]'s drop).
//!
//! `%USERPROFILE%\.derm-srt` is the user's alone (a protected DACL with one
//! entry, `derm_core`'s `private_dir`, which also refuses a link or a junction
//! on the path, case 137). Under it:
//! - `chats\<chat>\`: user-only and protected, holding `handoff.json`
//!   (the sandbox account may read and delete it), `token` and `chat.json`
//!   (it may read them); each file's own DACL is protected, so nothing
//!   inherited reaches it;
//! - `state\<harness>\`: the harness's state copy, which srt gives the
//!   sandbox account to write (`allowWrite`; srt keeps that grant between
//!   sessions, README "The child token and kept write grants"), emptied at
//!   the start and at the end, never removed, so srt's kept grant stays on
//!   the one folder instead of one per chat.

use std::path::Path;

use super::{rewrite, Ctx, Prepared};
use crate::run::harness::Harness;
use crate::run::plan::Plan;

/// The chat's files and the machine's lock, until dropped.
pub(crate) struct Session {
    #[cfg(windows)]
    _lock: super::lock::Lock,
    chat_dir: String,
    state_dir: String,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.chat_dir);
        empty_folder(Path::new(&self.state_dir));
    }
}

/// Removes what a folder holds and keeps the folder.
fn empty_folder(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            // Never through a link: a link the sandbox made is removed as a
            // link (`symlink_metadata`), not followed.
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => {
                    let _ = std::fs::remove_dir_all(&p);
                }
                Ok(_) => {
                    let _ = std::fs::remove_file(&p).or_else(|_| std::fs::remove_dir(&p));
                }
                Err(_) => {}
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn wire(
    p: &mut Plan,
    chat: &str,
    harness: &'static Harness,
    cwd: &str,
    home: &str,
    token: Option<&str>,
    policy: &derm_core::policy::PolicyFile,
    policy_problem: Option<&str>,
    dry_run: bool,
) -> Result<Option<Session>, (u8, String)> {
    #[cfg(windows)]
    {
        let account = sandbox_account();
        let derm_exe = std::env::current_exe()
            .map_err(|e| (1, format!("derm's own path: {e}")))?
            .to_string_lossy()
            .into_owned();
        let path_var = std::env::var("PATH").ok();
        let launch = |cmd: &str| -> Result<(String, Vec<String>), String> {
            let l = crate::platform::windows::shim::launch_for(
                cmd,
                path_var.as_deref(),
                &|p| p.is_file(),
                &|p| {
                    use std::io::Read;
                    let mut s = String::new();
                    std::fs::File::open(p)
                        .ok()?
                        .take(64 * 1024)
                        .read_to_string(&mut s)
                        .ok()?;
                    Some(s)
                },
            )?;
            Ok((l.program.to_string_lossy().into_owned(), l.leading))
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let ctx = Ctx {
            chat,
            harness,
            cwd,
            home,
            derm_exe: &derm_exe,
            token,
            policy,
            policy_problem,
            sandbox_user: account.as_ref().ok().map(|(u, _)| u.as_str()),
            now_ms,
            launch: &launch,
            exists: &|s: &str| std::fs::symlink_metadata(s).is_ok(),
        };
        let prepared = rewrite(p, &ctx).map_err(|e| (2, e))?;
        if dry_run {
            if let Err(e) = &account {
                p.notes.push(format!("derm run: {e}"));
            }
            return Ok(None);
        }
        let (_, sid) = account.map_err(|e| (1, e))?;
        materialize(&prepared, home, &sid)
            .map(Some)
            .map_err(|e| (1, e))
    }
    #[cfg(not(windows))]
    {
        let _ = (
            p,
            chat,
            harness,
            cwd,
            home,
            token,
            policy,
            policy_problem,
            dry_run,
            rewrite as fn(&mut Plan, &Ctx) -> Result<Prepared, String>,
        );
        Err((2, "internal: srt's Windows form off Windows".into()))
    }
}

/// srt's sandbox account, from its install record in
/// `HKLM\SOFTWARE\sandbox-runtime` (`SandboxUser`, `SandboxUserSid`, and
/// `MarkerVersion`, written last as the record's commit point; srt 0.0.82
/// `vendor/srt-win-src/src/reg.rs:15-24`, `install.rs:336-361`). Only
/// administrators can write that key (`install.rs:336-340`), so its values
/// are taken as read.
#[cfg(windows)]
fn sandbox_account() -> Result<(String, derm_core::platform::windows::UserId), String> {
    let missing = "srt's sandbox account is not installed on this machine (no committed record in HKLM\\SOFTWARE\\sandbox-runtime): run `npx @anthropic-ai/sandbox-runtime windows-install` once, as srt's README says";
    if reg::dword("MarkerVersion").is_none() {
        return Err(missing.into());
    }
    let user = reg::sz("SandboxUser").ok_or(missing)?;
    let sid = reg::sz("SandboxUserSid")
        .and_then(|s| derm_core::platform::windows::UserId::parse(&s))
        .ok_or("srt's install record holds no valid SandboxUserSid")?;
    Ok((user, sid))
}

#[cfg(windows)]
mod reg {
    //! Two reads of `HKLM\SOFTWARE\sandbox-runtime` with `RegGetValueW`
    //! (advapi32), in the 64-bit view as srt writes it (`KEY_WOW64_64KEY`,
    //! `reg.rs:17-18`). Declared here: derm-cli's `windows-sys` features do
    //! not include the registry, and its feature list is lane Z's.

    use std::ffi::c_void;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            hkey: *mut c_void,
            subkey: *const u16,
            value: *const u16,
            flags: u32,
            kind: *mut u32,
            data: *mut c_void,
            size: *mut u32,
        ) -> u32;
    }

    /// `HKEY_LOCAL_MACHINE`, `(HKEY)(ULONG_PTR)(LONG)0x80000002` (winreg.h).
    fn hklm() -> *mut c_void {
        0x8000_0002u32 as i32 as isize as *mut c_void
    }
    const RRF_RT_REG_SZ: u32 = 0x0000_0002;
    const RRF_RT_REG_DWORD: u32 = 0x0000_0010;
    const RRF_SUBKEY_WOW6464KEY: u32 = 0x0001_0000;
    const KEY: &str = "SOFTWARE\\sandbox-runtime";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    pub(super) fn sz(name: &str) -> Option<String> {
        let (key, value) = (wide(KEY), wide(name));
        let mut buf = vec![0u16; 512];
        let mut size = (buf.len() * 2) as u32;
        // SAFETY: the buffers are ours and `size` is their length in bytes.
        let err = unsafe {
            RegGetValueW(
                hklm(),
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if err != 0 {
            return None;
        }
        let n = (size as usize / 2).min(buf.len());
        let s = String::from_utf16(&buf[..n]).ok()?;
        let s = s.trim_end_matches('\0').to_string();
        (!s.is_empty()).then_some(s)
    }

    pub(super) fn dword(name: &str) -> Option<u32> {
        let (key, value) = (wide(KEY), wide(name));
        let mut out = 0u32;
        let mut size = 4u32;
        // SAFETY: `out` is four bytes, as `size` says.
        let err = unsafe {
            RegGetValueW(
                hklm(),
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
                std::ptr::null_mut(),
                (&mut out as *mut u32).cast(),
                &mut size,
            )
        };
        (err == 0).then_some(out)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn a_value_that_is_not_there_reads_as_none() {
            assert_eq!(super::sz("derm-test-no-such-value"), None);
            assert_eq!(super::dword("derm-test-no-such-value"), None);
        }
    }
}

/// The access list of a file in the chat's folder: the user, and the
/// sandbox account with the rights given (`FR` read, `SD` delete; SDDL,
/// Microsoft Learn "Access mask strings"). Protected, so nothing inherited
/// reaches it.
pub(super) fn file_sddl(user: &str, sandbox: &str, rights: &str) -> String {
    format!("D:P(A;;FA;;;{user})(A;;{rights};;;{sandbox})")
}

#[cfg(windows)]
fn materialize(
    p: &Prepared,
    home: &str,
    sandbox: &derm_core::platform::windows::UserId,
) -> Result<Session, String> {
    use derm_core::platform::windows as w;
    let lock = super::lock::take()?;
    let home = super::plain_win(home);
    let root = super::join(&home, ".derm-srt");
    let err = |what: &str, e: std::io::Error| format!("{what}: {e}");
    w::private_dir(Path::new(&root)).map_err(|e| err(&root, e))?;
    w::private_dir(Path::new(&p.chat_dir)).map_err(|e| err(&p.chat_dir, e))?;
    // A folder whose access list is the root's, so srt's grant on it is the
    // only way in for the sandbox account.
    std::fs::create_dir_all(&p.state_dir).map_err(|e| err(&p.state_dir, e))?;
    if !w::owned_plain_dir(Path::new(&p.state_dir)) {
        return Err(format!(
            "{} is not a plain folder of yours; refused",
            p.state_dir
        ));
    }
    // From here on a failure removes what was written.
    let session = Session {
        _lock: lock,
        chat_dir: p.chat_dir.clone(),
        state_dir: p.state_dir.clone(),
    };
    empty_folder(Path::new(&p.state_dir));
    let me = w::effective_user();
    let write = |path: &str, bytes: &[u8], rights: &str| -> Result<(), String> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| err(path, e))?;
        f.write_all(bytes).map_err(|e| err(path, e))?;
        drop(f);
        w::set_dacl_sddl(
            Path::new(path),
            &file_sddl(me.as_str(), sandbox.as_str(), rights),
        )
        .map_err(|e| err(path, e))
    };
    let (token_file, chat_file) = crate::enter::siblings(Path::new(&p.handoff_path));
    write(
        &token_file.to_string_lossy(),
        format!("{}\n", p.handoff.token).as_bytes(),
        "FR",
    )?;
    write(
        &chat_file.to_string_lossy(),
        crate::enter::handoff::chat_file_json(&p.handoff)
            .to_string()
            .as_bytes(),
        "FR",
    )?;
    // The handoff last: `derm enter` deletes it once read (case 231).
    write(
        &p.handoff_path,
        crate::enter::handoff::to_json(&p.handoff)
            .to_string()
            .as_bytes(),
        "FRSD",
    )?;
    let harness_dir = p
        .copies
        .first()
        .and_then(|(_, to)| Path::new(to).parent().map(Path::to_path_buf));
    if let Some(d) = &harness_dir {
        std::fs::create_dir_all(d).map_err(|e| err(&d.to_string_lossy(), e))?;
    }
    for (from, to) in &p.copies {
        // The user's own file, never through a link; a file that is not
        // there is not copied (the harness then signs in or starts fresh).
        match std::fs::symlink_metadata(from) {
            Ok(m) if m.is_file() => {
                std::fs::copy(from, to).map_err(|e| err(from, e))?;
            }
            Ok(_) => return Err(format!("{from} is not a plain file; refused")),
            Err(_) => {}
        }
    }
    Ok(session)
}
