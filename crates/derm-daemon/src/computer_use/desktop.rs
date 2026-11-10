//! Whether cua-driver can see windows on this Linux desktop, asked before
//! any card (box test w5 retest, BW5R-1).
//!
//! On GNOME Shell under Wayland a normal client cannot list windows, read
//! their screen geometry or capture them; cua-driver does that through its
//! own GNOME Shell extension, `winrects@cua`, and "without the helper,
//! window geometry, capture, activation, and the agent cursor are
//! unavailable" (cua-driver-rs 0.38.0, `libs/cua-driver/wayland-helper/
//! README.md`, "GNOME Shell compatibility"). Its `metadata.json` lists
//! `"shell-version": ["45", "46", "47", "48", "49"]`, and its `enable()`
//! throws on GNOME Shell 50 or newer "for session safety"
//! (`winrects@cua/extension.js:689-690`). On the box (GNOME Shell 50.1) every
//! capture came back `no_window` after the person had approved both cards.
//!
//! So on a GNOME Wayland session derm reads the Shell's version
//! (`/usr/bin/gnome-shell --version` prints `GNOME Shell <version>` and
//! exits while it parses its options, gnome-shell `src/main.c` `print_version`)
//! and the helper's `metadata.json` where GNOME Shell loads user and system
//! extensions from; when no helper is installed, or none lists the running
//! Shell's major version, computer use says why and opens no card. The
//! answer follows the helper's own list, so a later cua-driver whose helper
//! lists GNOME 50 works once it is installed. X11 sessions, wlroots
//! compositors and KDE are not judged here (cua-driver has other routes
//! there; its own refusals still apply).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The extension's UUID (`winrects@cua/metadata.json`).
pub const HELPER_UUID: &str = "winrects@cua";
/// GNOME Shell, named by absolute path (rules case 37).
pub const GNOME_SHELL: &str = "/usr/bin/gnome-shell";
const PROBE_LIMIT: Duration = Duration::from_secs(3);
/// The largest `metadata.json` read.
const MAX_METADATA: u64 = 64 * 1024;

fn var<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

/// A GNOME session on Wayland, by the variables the daemon passes the
/// driver (`direct::DISPLAY_VARS`): `XDG_CURRENT_DESKTOP` names GNOME (it is
/// `ubuntu:GNOME` on Ubuntu) and the session is Wayland.
pub fn gnome_wayland(env: &[(String, String)]) -> bool {
    let gnome = var(env, "XDG_CURRENT_DESKTOP").is_some_and(|d| {
        d.split(':')
            .any(|part| part.trim().eq_ignore_ascii_case("gnome"))
    });
    let wayland = match var(env, "XDG_SESSION_TYPE") {
        Some(t) => t.eq_ignore_ascii_case("wayland"),
        None => var(env, "WAYLAND_DISPLAY").is_some(),
    };
    gnome && wayland
}

/// The major version in `GNOME Shell 50.1` (or `50.rc`), if the line is one.
pub fn shell_major(line: &str) -> Option<u32> {
    let v = line.trim().strip_prefix("GNOME Shell ")?;
    let major = v.split(|c: char| !c.is_ascii_digit()).next()?;
    major.parse().ok()
}

/// The `shell-version` list of a `metadata.json`, as GNOME reads it: each
/// entry's major version ("45", "46.2" both give 45).
pub fn helper_majors(metadata: &str) -> Option<Vec<u32>> {
    let v: Value = serde_json::from_str(metadata).ok()?;
    if v.get("uuid").and_then(Value::as_str) != Some(HELPER_UUID) {
        return None;
    }
    Some(
        v.get("shell-version")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|s| s.split('.').next()?.parse().ok())
            .collect(),
    )
}

/// The reason computer use cannot work here, or `None`. `shell` is
/// `gnome-shell --version`'s line (None when it could not run); `helpers`
/// the `metadata.json` text of each installed copy of the helper.
pub fn verdict(
    env: &[(String, String)],
    shell: Option<&str>,
    helpers: &[String],
) -> Option<String> {
    if !gnome_wayland(env) {
        return None;
    }
    let major = shell.and_then(shell_major);
    let listed: Vec<Vec<u32>> = helpers.iter().filter_map(|m| helper_majors(m)).collect();
    if listed.is_empty() {
        return Some(format!(
            "Computer use cannot see windows here: on GNOME under Wayland cua-driver lists, measures and captures windows only through its GNOME Shell helper ({HELPER_UUID}), which is not installed. Install it with cua-driver's wayland-helper/install.sh and log out and in once; no card is shown until then."
        ));
    }
    match major {
        Some(m) if listed.iter().any(|l| l.contains(&m)) => None,
        Some(m) => Some(format!(
            "Computer use cannot see windows here: this is GNOME Shell {m}, and the installed cua-driver GNOME Shell helper ({HELPER_UUID}) supports GNOME Shell {} only (cua-driver 0.38.0 refuses GNOME 50 and newer for now), so window lists, capture and clicks fail. No card is shown; use an X11 session, or a cua-driver whose helper lists GNOME Shell {m}.",
            supported(&listed)
        )),
        None => Some(format!(
            "Computer use cannot see windows here: this is a GNOME Wayland session, and derm could not read GNOME Shell's version ({GNOME_SHELL} --version) to check cua-driver's GNOME Shell helper ({HELPER_UUID}) against it. No card is shown."
        )),
    }
}

fn supported(listed: &[Vec<u32>]) -> String {
    let mut all: Vec<u32> = listed.iter().flatten().copied().collect();
    all.sort_unstable();
    all.dedup();
    match (all.first(), all.last()) {
        (Some(a), Some(b)) if a != b => format!("{a} to {b}"),
        (Some(a), _) => a.to_string(),
        _ => "none".into(),
    }
}

/// Where GNOME Shell loads the helper from: the user's extensions
/// (`$XDG_DATA_HOME`, else `~/.local/share`) and the system's.
pub fn helper_paths(env: &[(String, String)], home: &Path) -> Vec<PathBuf> {
    let user = var(env, "XDG_DATA_HOME")
        .filter(|d| d.starts_with('/'))
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    [
        user,
        PathBuf::from("/usr/local/share"),
        PathBuf::from("/usr/share"),
    ]
    .into_iter()
    .map(|d| {
        d.join("gnome-shell/extensions")
            .join(HELPER_UUID)
            .join("metadata.json")
    })
    .collect()
}

/// A small regular file's text. Opened without blocking, then checked by
/// the open handle: a FIFO at the path would hold `open(2)` with no limit
/// (review FP9-S6).
fn read_small(path: &Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_METADATA).read_to_string(&mut text).ok()?;
    Some(text)
}

/// `gnome-shell --version`'s first line, from a cleared environment, within
/// a few seconds; None when it is not there or does not answer.
fn shell_version(program: &Path) -> Option<String> {
    let mut child = Command::new(program)
        .arg("--version")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < PROBE_LIMIT => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    std::io::Read::read_to_string(
        &mut std::io::Read::take(child.stdout.take()?, 4096),
        &mut out,
    )
    .ok()?;
    out.lines().next().map(str::to_string)
}

/// `verdict` for this machine: runs `gnome-shell --version` (the program
/// `gnome_shell` names) only on a GNOME Wayland session.
pub fn probe_with(env: &[(String, String)], home: &Path, gnome_shell: &Path) -> Option<String> {
    if !gnome_wayland(env) {
        return None;
    }
    let helpers: Vec<String> = helper_paths(env, home)
        .iter()
        .filter_map(|p| read_small(p))
        .collect();
    let shell = shell_version(gnome_shell);
    verdict(env, shell.as_deref(), &helpers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// cua-driver-rs 0.38.0's own `winrects@cua/metadata.json`.
    const HELPER_038: &str = r#"{
  "uuid": "winrects@cua",
  "name": "WinRects",
  "description": "Expose window geometry, capture, cursor, and verified activation for cua-driver on Wayland.",
  "shell-version": ["45", "46", "47", "48", "49"],
  "version": 10
}"#;

    fn ubuntu_wayland() -> Vec<(String, String)> {
        env(&[
            ("XDG_CURRENT_DESKTOP", "ubuntu:GNOME"),
            ("XDG_SESSION_TYPE", "wayland"),
            ("WAYLAND_DISPLAY", "wayland-0"),
        ])
    }

    #[test]
    fn bw5r_1_gnome_50_with_cua_drivers_helper_is_refused_before_any_card() {
        let why = verdict(
            &ubuntu_wayland(),
            Some("GNOME Shell 50.1"),
            &[HELPER_038.into()],
        )
        .expect("GNOME 50 must be refused");
        assert!(why.contains("GNOME Shell 50"), "{why}");
        assert!(why.contains("45 to 49"), "{why}");
        assert!(why.contains("No card"), "{why}");
    }

    #[test]
    fn a_shell_the_helper_lists_is_fine_and_a_missing_helper_is_not() {
        assert_eq!(
            verdict(
                &ubuntu_wayland(),
                Some("GNOME Shell 49.2"),
                &[HELPER_038.into()]
            ),
            None
        );
        let why = verdict(&ubuntu_wayland(), Some("GNOME Shell 49.2"), &[]).unwrap();
        assert!(why.contains("not installed"), "{why}");
        // A later helper that lists 50 lifts it.
        let later = HELPER_038.replace("\"49\"]", "\"49\", \"50\"]");
        assert_eq!(
            verdict(&ubuntu_wayland(), Some("GNOME Shell 50.1"), &[later]),
            None
        );
        // An unknown Shell version on GNOME Wayland is refused, saying why.
        let why = verdict(&ubuntu_wayland(), None, &[HELPER_038.into()]).unwrap();
        assert!(why.contains("--version"), "{why}");
        // Another UUID is not the helper.
        let other = HELPER_038.replace("winrects@cua", "other@x");
        assert!(verdict(&ubuntu_wayland(), Some("GNOME Shell 49.0"), &[other]).is_some());
    }

    #[test]
    fn x11_kde_and_wlroots_sessions_are_not_judged() {
        for e in [
            env(&[
                ("XDG_CURRENT_DESKTOP", "ubuntu:GNOME"),
                ("XDG_SESSION_TYPE", "x11"),
            ]),
            env(&[
                ("XDG_CURRENT_DESKTOP", "KDE"),
                ("XDG_SESSION_TYPE", "wayland"),
            ]),
            env(&[
                ("XDG_CURRENT_DESKTOP", "sway"),
                ("WAYLAND_DISPLAY", "wayland-1"),
            ]),
            env(&[]),
        ] {
            assert_eq!(verdict(&e, Some("GNOME Shell 50.1"), &[]), None, "{e:?}");
        }
        // No session type: WAYLAND_DISPLAY decides.
        assert!(gnome_wayland(&env(&[
            ("XDG_CURRENT_DESKTOP", "GNOME"),
            ("WAYLAND_DISPLAY", "wayland-0")
        ])));
    }

    #[test]
    fn the_version_line_and_the_list_are_read_as_gnome_reads_them() {
        assert_eq!(shell_major("GNOME Shell 50.1\n"), Some(50));
        assert_eq!(shell_major("GNOME Shell 47.rc"), Some(47));
        assert_eq!(shell_major("gnome-shell 50"), None);
        assert_eq!(helper_majors(HELPER_038).unwrap(), vec![45, 46, 47, 48, 49]);
        assert_eq!(helper_majors("not json"), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_probe_reads_the_users_helper_and_runs_the_shell_by_path() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "derm-desktop-{}-{}",
            std::process::id(),
            &derm_core::token::mint().unwrap()[..8]
        ));
        let ext = root.join("data/gnome-shell/extensions/winrects@cua");
        std::fs::create_dir_all(&ext).unwrap();
        std::fs::write(ext.join("metadata.json"), HELPER_038).unwrap();
        // A stand-in for gnome-shell, written from a child process (case 154).
        let shell = root.join("gnome-shell");
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "printf '#!/bin/sh\\necho \"GNOME Shell 50.1\"\\n' > '{}'",
                shell.display()
            ))
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut e = ubuntu_wayland();
        e.push((
            "XDG_DATA_HOME".into(),
            root.join("data").to_string_lossy().into_owned(),
        ));
        let why = probe_with(&e, &root, &shell).expect("refused");
        assert!(why.contains("GNOME Shell 50"), "{why}");
        // Not a GNOME Wayland session: the shell is never run.
        assert_eq!(
            probe_with(&env(&[]), &root, Path::new("/nonexistent")),
            None
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Review FP9-S6 (its probe, which blocked on `c491b97`, inverted): a
    /// FIFO at the helper's `metadata.json` held `read_small` in open(2).
    #[test]
    fn fp9_s6_a_fifo_metadata_does_not_block() {
        let root = std::env::temp_dir().join(format!("derm-fp9-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fifo = root.join("metadata.json");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let (tx, rx) = std::sync::mpsc::channel();
        let p = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_small(&p));
        });
        let got = rx.recv_timeout(Duration::from_secs(2));
        // Unblock a reader still waiting before cleaning up.
        if got.is_err() {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
        }
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(got, Ok(None), "read_small blocked on a FIFO, or read it");
    }
}
