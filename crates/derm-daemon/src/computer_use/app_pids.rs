#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
//! The running processes of an approved macOS app (BW5-19's Mac half,
//! integration w5's fix pass 11).
//!
//! The helper's embedded Cua Driver reads a `list_windows` or `list_apps`
//! with no `pid` and no `window_id` as a whole-display observation, which
//! derm's manifest refuses (Mac test w5, retest 4: "desktop display
//! observation is outside the capability manifest"; the same rule on Linux,
//! box test w5 BW5-19, `direct.rs`). The daemon therefore asks per process
//! of an app the chat holds. A process is the app's when its executable is
//! inside the app bundle the person approved on the card
//! (`<app>.app/Contents/MacOS/`), it runs as this user, and the driver's own
//! check of the pid's bundle still applies after this one.
use std::path::{Path, PathBuf};

/// Whether `exe` is the main program folder's of the bundle at `app`. Both
/// are real paths. Helpers in `Contents/XPCServices` or `Contents/Helpers`
/// are not the app's windows and do not count.
pub fn exe_in_app(app: &Path, exe: &Path) -> bool {
    let main = app.join("Contents").join("MacOS");
    exe.parent() == Some(main.as_path())
}

/// This user's processes whose program is in the app at `app`, by pid. None
/// where derm cannot list processes this way (every system but macOS).
pub fn pids_in_app(app: &Path) -> Option<Vec<u64>> {
    #[cfg(target_os = "macos")]
    {
        let app: PathBuf = std::fs::canonicalize(app).ok()?;
        let uid = unsafe { libc::getuid() };
        Some(
            macos::all_pids()
                .into_iter()
                .filter(|pid| macos::uid_of(*pid) == Some(uid))
                .filter(|pid| macos::program(*pid).is_some_and(|exe| exe_in_app(&app, &exe)))
                .map(|pid| pid as u64)
                .collect(),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _: Option<PathBuf> = None;
        let _ = app;
        None
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::path::PathBuf;

    /// Every pid the kernel lists (libproc's `proc_listallpids`), with the
    /// buffer grown until the list fits.
    pub fn all_pids() -> Vec<i32> {
        let mut cap = 4096usize;
        loop {
            let mut buf = vec![0i32; cap];
            let bytes = (cap * std::mem::size_of::<i32>()) as libc::c_int;
            // SAFETY: the buffer holds `bytes` bytes of pids.
            let n = unsafe { libc::proc_listallpids(buf.as_mut_ptr().cast(), bytes) };
            if n <= 0 {
                return Vec::new();
            }
            let n = n as usize;
            if n < cap || cap >= 1 << 20 {
                buf.truncate(n.min(cap));
                buf.retain(|p| *p > 0);
                return buf;
            }
            cap *= 2;
        }
    }

    pub fn uid_of(pid: i32) -> Option<u32> {
        // SAFETY: a zeroed proc_bsdinfo is valid; proc_pidinfo writes at most
        // `size` bytes.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        (n == size).then_some(info.pbi_uid)
    }

    pub fn program(pid: i32) -> Option<PathBuf> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer is PROC_PIDPATHINFO_MAXSIZE bytes, as
        // proc_pidpath requires.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(PathBuf::from(String::from_utf8_lossy(&buf).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_bundles_main_program_folder_counts() {
        let app = Path::new("/System/Applications/Calculator.app");
        assert!(exe_in_app(
            app,
            Path::new("/System/Applications/Calculator.app/Contents/MacOS/Calculator")
        ));
        for not in [
            "/System/Applications/Calculator.app/Contents/XPCServices/x.xpc/Contents/MacOS/x",
            "/System/Applications/Calculator.app/Contents/MacOS/sub/tool",
            "/System/Applications/Calculator.app.evil/Contents/MacOS/Calculator",
            "/Applications/Other.app/Contents/MacOS/Calculator",
            "/System/Applications/Calculator.app/Contents/MacOS",
        ] {
            assert!(!exe_in_app(app, Path::new(not)), "{not}");
        }
    }

    /// On macOS the listing finds this test's own process only when asked
    /// for the folder its program is in, and never for another app.
    #[cfg(target_os = "macos")]
    #[test]
    fn this_users_processes_are_found_by_their_bundle() {
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        // A test binary is not in an app bundle; a made-up bundle whose
        // main folder is the binary's folder stands in for one.
        let folder = exe.parent().unwrap();
        if folder.ends_with("Contents/MacOS") {
            return;
        }
        let none = pids_in_app(Path::new("/System/Applications/Calculator.app")).unwrap();
        assert!(!none.contains(&(std::process::id() as u64)));
    }
}
