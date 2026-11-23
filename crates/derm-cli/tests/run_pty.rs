//! `derm run` holds the chat's terminal on its own pty when it has one
//! (step P5, lane PD; request PD-2, P integration): the harness's
//! terminal is derm's pty, not the person's, its output still reaches the
//! person, and derm's own lines end in `\r\n` while the person's terminal
//! is raw (lane PD's Look out for 3). Without a terminal, today's path.
#![cfg(target_os = "linux")]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fake_pi(dir: &Path) {
    let p = dir.join("pi");
    std::fs::write(
        &p,
        "#!/bin/sh\necho \"tty=$(tty)\" >> \"$OUT\"\nprintf 'from the harness\\n'\nexit 3\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A pty of the test's own: (master, slave path).
fn pty() -> (OwnedFd, String) {
    // SAFETY: plain libc calls on a new fd; the name is copied at once.
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0);
        assert_eq!(libc::grantpt(m), 0);
        assert_eq!(libc::unlockpt(m), 0);
        let mut buf = [0 as libc::c_char; 128];
        assert_eq!(libc::ptsname_r(m, buf.as_mut_ptr(), buf.len()), 0);
        let name = std::ffi::CStr::from_ptr(buf.as_ptr())
            .to_string_lossy()
            .into_owned();
        (OwnedFd::from_raw_fd(m), name)
    }
}

#[test]
fn pd_2_on_a_terminal_the_harness_runs_on_derms_own_pty() {
    let dir = std::env::temp_dir().join(format!("derm-pty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    fake_pi(&dir);
    let out = dir.join("seen");
    let (master, slave_name) = pty();
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&slave_name)
        .unwrap();
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_derm"));
    cmd.args(["run", "pi", "--boundary", "none", "--no-daemon", "--cwd"])
        .arg(&dir)
        .env("PATH", path)
        .env("OUT", &out)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    // SAFETY: setsid and TIOCSCTTY in the child before exec, so derm is in
    // its terminal's foreground, as from a shell.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut derm = cmd.spawn().unwrap();
    drop(slave);
    // Read the person's side until derm exits.
    let fd = master.as_raw_fd();
    let mut seen = Vec::new();
    let t = Instant::now();
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd, a short timeout.
        let n = unsafe { libc::poll(&mut pfd, 1, 100) };
        if n > 0 {
            let mut buf = [0u8; 4096];
            // SAFETY: a valid buffer for its length.
            let r = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if r <= 0 {
                break;
            }
            seen.extend_from_slice(&buf[..r as usize]);
        }
        if let Ok(Some(_)) = derm.try_wait() {
            if n <= 0 {
                break;
            }
        }
        if t.elapsed() > Duration::from_secs(20) {
            let _ = derm.kill();
            break;
        }
    }
    let status = derm.wait().unwrap();
    let text = String::from_utf8_lossy(&seen).into_owned();
    let recorded = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(status.code(), Some(3), "{text}");
    assert!(text.contains("from the harness"), "{text}");
    let tty = recorded
        .lines()
        .find_map(|l| l.strip_prefix("tty="))
        .unwrap_or("");
    assert!(tty.starts_with("/dev/pts/"), "{recorded:?}");
    assert_ne!(
        tty, slave_name,
        "the harness's terminal is derm's pty, not the person's"
    );
    // No line of derm's says it had no screen.
    assert!(!text.contains("no screen for this chat"), "{text}");
    // derm's own line printed while it holds the terminal (raw, OPOST off)
    // ends in \r\n (lane PD's Look out for 3): on Linux with no boundary
    // derm says io_uring is not audited (case 128).
    assert!(text.contains("case 128)\r\n"), "{text:?}");
}

#[test]
fn pd_2_without_a_terminal_derm_says_there_is_no_screen() {
    let dir = std::env::temp_dir().join(format!("derm-nopty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    fake_pi(&dir);
    let out = dir.join("seen");
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let o = Command::new(env!("CARGO_BIN_EXE_derm"))
        .args(["run", "pi", "--boundary", "none", "--no-daemon", "--cwd"])
        .arg(&dir)
        .env("PATH", path)
        .env("OUT", &out)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(o.status.code(), Some(3));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("no screen for this chat (stdin or stdout is not a terminal)"),
        "{err}"
    );
    assert!(String::from_utf8_lossy(&o.stdout).contains("from the harness"));
}
