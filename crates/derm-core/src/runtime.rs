//! Where the daemon's socket folder lives on Linux (release check RC6).
//!
//! `$XDG_RUNTIME_DIR` when it is an absolute path. When it is unset (an SSH
//! route that skips PAM, such as Tailscale SSH, gives none, while the systemd
//! user unit has it), `/run/user/<uid>`, the folder `pam_systemd` would have
//! named, when it is a real folder (not a link) owned by that uid with no
//! group or other bits: the XDG Base Directory spec's "owned by the user",
//! mode 0700. Else `None`, and callers keep `~/.derm/run`. Nothing here
//! creates a folder.
//!
//! One function for the daemon's bind path and every Rust client, so a
//! daemon started from one shell and a CLI run from another agree (podman's
//! `GetRuntimeDir` does the same on both sides, with a looser mode check).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The parent of `/run/user/<uid>` on Linux.
pub const RUN_USER: &str = "/run/user";

/// The daemon's socket per OS (`contracts/daemon-protocol.md` section 1):
/// macOS `~/Library/Application Support/derm/daemon.sock`; elsewhere
/// `<runtime_dir>/derm/daemon.sock`, else `~/.derm/run/derm/daemon.sock`.
/// Computes the path only.
pub fn socket_path() -> Option<PathBuf> {
    let home = home_dir();
    socket_path_with(home.as_deref(), runtime_dir(), cfg!(target_os = "macos"))
}

/// The user's home folder: `HOME` on Unix; `USERPROFILE` on Windows, which
/// sets no `HOME` (lane Z's request; the daemon's
/// `socket_path_ends_with_derm_daemon_sock` failed on the Windows runner).
/// On Windows the socket path is `%USERPROFILE%\.derm\run\derm\daemon.sock`,
/// the pointer file to the daemon's pipe.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let key = "USERPROFILE";
    #[cfg(not(windows))]
    let key = "HOME";
    std::env::var_os(key).map(PathBuf::from)
}

/// `socket_path` from its inputs.
pub fn socket_path_with(
    home: Option<&Path>,
    runtime: Option<PathBuf>,
    macos: bool,
) -> Option<PathBuf> {
    if macos {
        return Some(home?.join("Library/Application Support/derm/daemon.sock"));
    }
    let dir = match runtime {
        Some(r) => r,
        None => home?.join(".derm/run"),
    };
    Some(dir.join("derm/daemon.sock"))
}

/// The runtime folder from this process's environment and uid.
pub fn runtime_dir() -> Option<PathBuf> {
    runtime_dir_with(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        current_uid(),
        Path::new(RUN_USER),
    )
}

/// The runtime folder for `uid`, given the variable's value and the parent
/// of the per-user folders (`/run/user`; a temp folder in tests).
pub fn runtime_dir_with(xdg: Option<&OsStr>, uid: u32, run_user: &Path) -> Option<PathBuf> {
    if let Some(dir) = xdg.map(Path::new).filter(|p| p.is_absolute()) {
        return Some(dir.to_path_buf());
    }
    let dir = run_user.join(uid.to_string());
    owned_private_dir(&dir, uid).then_some(dir)
}

/// Whether `dir` is a folder, not a link, owned by `uid`, with no group or
/// other bits (the platform seam's `owned_private_dir`).
#[cfg(unix)]
pub fn owned_private_dir(dir: &Path, uid: u32) -> bool {
    crate::platform::owned_private_dir(dir, &uid)
}

#[cfg(not(unix))]
pub fn owned_private_dir(_dir: &Path, _uid: u32) -> bool {
    false
}

#[cfg(unix)]
pub fn current_uid() -> u32 {
    crate::platform::real_user()
}

#[cfg(not(unix))]
pub fn current_uid() -> u32 {
    u32::MAX
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("derm-rt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_socket_follows_the_contract() {
        let h = Path::new("/home/u");
        assert_eq!(
            socket_path_with(Some(h), None, true),
            Some(h.join("Library/Application Support/derm/daemon.sock"))
        );
        assert_eq!(
            socket_path_with(Some(h), Some(PathBuf::from("/run/user/1")), false),
            Some(PathBuf::from("/run/user/1/derm/daemon.sock"))
        );
        assert_eq!(
            socket_path_with(Some(h), None, false),
            Some(h.join(".derm/run/derm/daemon.sock"))
        );
        assert_eq!(socket_path_with(None, None, false), None);
    }

    #[test]
    fn the_variable_wins_when_it_is_absolute() {
        let root = temp("var");
        let uid = current_uid();
        assert_eq!(
            runtime_dir_with(Some(OsStr::new("/run/user/7")), uid, &root),
            Some(PathBuf::from("/run/user/7"))
        );
    }

    #[test]
    fn an_unset_variable_takes_the_users_own_run_folder() {
        let root = temp("unset");
        let uid = current_uid();
        let mine = root.join(uid.to_string());
        std::fs::create_dir(&mine).unwrap();
        std::fs::set_permissions(&mine, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(runtime_dir_with(None, uid, &root), Some(mine.clone()));
        // An empty or relative value counts as unset: `derm/daemon.sock`
        // relative to wherever the shell stands is no one's folder.
        assert_eq!(
            runtime_dir_with(Some(OsStr::new("")), uid, &root),
            Some(mine.clone())
        );
        assert_eq!(
            runtime_dir_with(Some(OsStr::new("run")), uid, &root),
            Some(mine)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_run_folder_that_is_not_private_and_ours_is_refused() {
        let uid = current_uid();
        // Absent.
        let root = temp("absent");
        assert_eq!(runtime_dir_with(None, uid, &root), None);
        // Group or other bits.
        for mode in [0o750, 0o705, 0o777, 0o711] {
            let root = temp(&format!("mode{mode:o}"));
            let dir = root.join(uid.to_string());
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(runtime_dir_with(None, uid, &root), None, "mode {mode:o}");
            let _ = std::fs::remove_dir_all(&root);
        }
        // A link to a private folder of ours.
        let root = temp("link");
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, root.join(uid.to_string())).unwrap();
        assert_eq!(runtime_dir_with(None, uid, &root), None);
        // A file.
        let root2 = temp("file");
        std::fs::write(root2.join(uid.to_string()), b"x").unwrap();
        assert_eq!(runtime_dir_with(None, uid, &root2), None);
        // Another uid's folder: ours is private but under another uid's name.
        let other = uid.wrapping_add(1);
        let root3 = temp("other");
        let dir = root3.join(other.to_string());
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(runtime_dir_with(None, other, &root3), None);
        for r in [root, root2, root3] {
            let _ = std::fs::remove_dir_all(&r);
        }
    }
}
