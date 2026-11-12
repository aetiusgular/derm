//! Where the hook finds its chat token when the agent strips it from the
//! hook's environment (case 76), ported from
//! `packages/derm-hooks-claude-compat/src/env.ts` at `e29ce27`.
//!
//! Command Code drops every variable whose name matches `/TOKEN/i` (and 14
//! more patterns) before it runs a hook (`contracts/hook-dialects.md`
//! section 2a; npm:command-code `dist/cli.mjs`, the hook env filter), so
//! neither `DERM_CHAT_TOKEN` nor `DERM_CHAT_TOKEN_FILE` reaches it;
//! `DERM_CHAT_ID` and `DERM_DAEMON_SOCKET` do. `derm run --boundary none`
//! writes the token file at `<the daemon socket's folder>/chats/<chat
//! id>.token`, so with both token variables gone the hook works the path out
//! from those two.
//!
//! Nothing new is trusted: `gate::daemon::chat_token` still refuses the file
//! unless it is absolute, a regular file, a trusted user's, private, small,
//! outside the chat's folder and not `daemon.token`, and the daemon still
//! refuses a token that is not a chat token. The socket must be derm's own
//! (L-S6): the path is derived only when the socket's folder is one `derm
//! run` uses, worked out from this process's uid and its passwd home, never
//! from `HOME` or `XDG_RUNTIME_DIR`, which whatever set `DERM_DAEMON_SOCKET`
//! could set as well.

use std::path::{Component, Path, PathBuf};

use crate::gate::daemon::Env;

/// The folders `derm run`'s socket can be in for this user
/// (`defaultSocketDirs`).
///
/// On Windows none: `derm run` names its daemon there by a pointer file, and
/// Command Code's stripped token is not derived, so its ask is a deny.
pub fn default_socket_dirs() -> Vec<PathBuf> {
    if cfg!(windows) {
        return Vec::new();
    }
    let home = passwd_home();
    let mut dirs = Vec::new();
    if cfg!(target_os = "macos") {
        if let Some(h) = home {
            dirs.push(h.join("Library").join("Application Support").join("derm"));
        }
        return dirs;
    }
    #[cfg(unix)]
    dirs.push(
        Path::new("/run/user")
            .join(derm_core::runtime::current_uid().to_string())
            .join("derm"),
    );
    if let Some(h) = home.filter(|h| h.is_absolute()) {
        dirs.push(h.join(".derm").join("run").join("derm"));
    }
    dirs
}

/// This process's home in the password database (`os.userInfo().homedir`).
#[cfg(unix)]
pub fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: an all-zero passwd is a valid value for getpwuid_r to fill.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: the buffer and the struct outlive the call; `out` is null or
    // points at `pw`.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir is a NUL-terminated string inside `buf`.
    let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

#[cfg(not(unix))]
pub fn passwd_home() -> Option<PathBuf> {
    None
}

/// A chat id as `derm run` mints it (`derm-` and 12 hex) or as a test names
/// it: no separators, no dot at the start (`CHAT_ID`).
fn chat_id_ok(chat: &str) -> bool {
    let mut cs = chat.chars();
    cs.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chat.len() <= 64
        && cs.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// A path in its normal form (`path.normalize(p) === p`): no `.` or `..`
/// part, no doubled or trailing separator.
fn normal(p: &str) -> bool {
    !p.contains("//")
        && (p == "/" || !p.ends_with('/'))
        && Path::new(p)
            .components()
            .all(|c| !matches!(c, Component::CurDir | Component::ParentDir))
        && !p.split('/').any(|s| s == "." || s == "..")
}

/// The token file `derm run` wrote for this chat, from `DERM_CHAT_ID` and
/// `DERM_DAEMON_SOCKET` (`derivedTokenFile`), when the socket is
/// `daemon.sock` in one of `socket_dirs`.
pub fn derived_token_file(env: &Env, socket_dirs: &[PathBuf]) -> Option<PathBuf> {
    let chat = env.get("DERM_CHAT_ID")?;
    let sock = env.get("DERM_DAEMON_SOCKET")?;
    if !chat_id_ok(chat) || !Path::new(sock).is_absolute() || !normal(sock) {
        return None;
    }
    let sock = Path::new(sock);
    if sock.file_name().and_then(|n| n.to_str()) != Some("daemon.sock") {
        return None;
    }
    let dir = sock.parent()?;
    if !socket_dirs.iter().any(|d| d == dir) {
        return None;
    }
    Some(dir.join("chats").join(format!("{chat}.token")))
}

/// The hook's environment with `DERM_CHAT_TOKEN_FILE` filled in when both
/// token variables are absent (`hookEnv`).
pub fn hook_env(env: &Env, socket_dirs: &[PathBuf]) -> Env {
    if env.get("DERM_CHAT_TOKEN").is_some() || env.get("DERM_CHAT_TOKEN_FILE").is_some() {
        return env.clone();
    }
    match derived_token_file(env, socket_dirs) {
        Some(p) => env.with("DERM_CHAT_TOKEN_FILE", &p.to_string_lossy()),
        None => env.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from packages/derm-hooks-claude-compat/src/security.test.ts,
    // "L-S6: the derived token file stays in derm's own socket folder", and
    // hook.test.ts, "the chat token when the agent strips it (case 76)".

    #[test]
    fn a_socket_outside_derms_default_folders_derives_nothing() {
        let env = Env::of(&[
            ("DERM_CHAT_ID", "derm-abc123def456"),
            ("DERM_DAEMON_SOCKET", "/tmp/evil/daemon.sock"),
        ]);
        assert_eq!(derived_token_file(&env, &default_socket_dirs()), None);
        assert!(hook_env(&env, &default_socket_dirs())
            .raw("DERM_CHAT_TOKEN_FILE")
            .is_none());
    }

    // Unix paths: on Windows `/srv/d` is rooted but not absolute (case 224),
    // and derm's folders there are none, so nothing is derived.
    #[cfg(unix)]
    #[test]
    fn a_socket_in_one_of_the_folders_given_derives_the_chats_token_file() {
        let env = Env::of(&[
            ("DERM_CHAT_ID", "derm-abc123def456"),
            ("DERM_DAEMON_SOCKET", "/srv/d/daemon.sock"),
        ]);
        let dirs = [PathBuf::from("/srv/d")];
        assert_eq!(
            derived_token_file(&env, &dirs),
            Some(PathBuf::from("/srv/d/chats/derm-abc123def456.token"))
        );
        // A socket named otherwise, or not in normal form, derives nothing.
        for sock in [
            "/srv/d/other.sock",
            "/srv/d/./daemon.sock",
            "/srv//d/daemon.sock",
            "srv/d/daemon.sock",
        ] {
            let env = env.with("DERM_DAEMON_SOCKET", sock);
            assert_eq!(derived_token_file(&env, &dirs), None, "{sock}");
        }
    }

    #[test]
    fn home_and_xdg_runtime_dir_in_the_hooks_environment_do_not_move_derms_folders() {
        // derm's folders come from the uid and the password database
        // (`default_socket_dirs` reads no variable), so a HOME the hook's
        // environment names is not one of them.
        let env = Env::of(&[
            ("HOME", "/tmp/h"),
            ("DERM_CHAT_ID", "c1"),
            ("DERM_DAEMON_SOCKET", "/tmp/h/.derm/run/derm/daemon.sock"),
        ]);
        assert_eq!(derived_token_file(&env, &default_socket_dirs()), None);
    }

    #[test]
    fn a_chat_id_with_a_separator_or_a_dot_is_not_used_to_find_a_file() {
        let dirs = [PathBuf::from("/srv/d")];
        for chat in ["../x", "a/b", ".hidden", "a.b", "", "x\\y"] {
            let env = Env::of(&[
                ("DERM_CHAT_ID", chat),
                ("DERM_DAEMON_SOCKET", "/srv/d/daemon.sock"),
            ]);
            assert_eq!(derived_token_file(&env, &dirs), None, "{chat:?}");
        }
    }

    #[test]
    fn a_token_variable_that_reached_the_hook_wins() {
        let dirs = [PathBuf::from("/srv/d")];
        let env = Env::of(&[
            ("DERM_CHAT_ID", "c1"),
            ("DERM_DAEMON_SOCKET", "/srv/d/daemon.sock"),
            ("DERM_CHAT_TOKEN_FILE", "/own/file"),
        ]);
        assert_eq!(
            hook_env(&env, &dirs).raw("DERM_CHAT_TOKEN_FILE"),
            Some("/own/file")
        );
    }
}
