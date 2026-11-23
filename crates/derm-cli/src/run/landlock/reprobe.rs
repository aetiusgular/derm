//! The account's firewall table, checked again while the chat runs (step
//! P10's I-1, lane PA; note CC section 6, option (a)).
//!
//! The helper checks the table once before the chat (`netcheck.rs`). A table
//! flushed later (by hand, or a reload's `flush ruleset`) went unseen until
//! the next start, and the chat reached the network directly meanwhile. The
//! helper now leaves a watchdog behind that runs the same four probes every
//! few seconds, as the account, and stops the chat when one fails.
//!
//! Where it runs: the helper forks it twice before the chat's domain, so it
//! is outside the domain and no longer the harness's child. A process in a
//! domain with the signal scope cannot signal one outside it, and Landlock
//! lets a domain trace only processes in its own or a nested domain (run on
//! Linux 6.18, ABI 7, `/home/claude/probe/llpts.c`: a domain's `kill` to a
//! process outside got EPERM; kernel docs, "the tracee must be in a
//! sub-domain of the tracer"), so the chat cannot stop it. It calls
//! `setsid`, so the terminal's signals and job control never reach it, and
//! the harness has no unknown child (a shell harness's bare `wait` would
//! otherwise wait for it).
//!
//! How it knows the chat ended: a pidfd of the helper's own process, opened
//! before the fork. The helper execs the harness, so the pid is the
//! harness's; a pidfd turns readable when its process exits (pidfd_open(2),
//! Linux 5.3; Landlock needs 5.13), and it is close-on-exec, so the harness
//! never holds it.
//!
//! On a failed probe it says why on the chat's terminal, closes it, sends
//! SIGTERM to the harness (by pidfd, so no reused pid is hit), its process
//! group and every process below it, SIGKILL to the same 2 s later, and,
//! one interval later, SIGKILL to every other process of the account
//! (`kill(-1)`): every chat of the account would fail the same probe, and a
//! process that left the harness's tree must not keep the open network.
//! Never as root. Below ABI 6 (no scopes, on the person's yes) the chat can
//! signal the watchdog; the start line says so.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

/// How often the probes run while a chat runs. Each run makes two TCP
/// connects the Linux feed records for the account (loopback and
/// TEST-NET-1): 1,440 records an hour per chat at 5 s.
pub(crate) const INTERVAL_SECS: u64 = 5;
/// From SIGTERM to SIGKILL.
const GRACE: Duration = Duration::from_secs(2);

/// Forks the watchdog for this process (the helper, about to exec the
/// harness). Returns once the intermediate child has exited.
pub(crate) fn start(interval: Duration) -> Result<(), String> {
    // SAFETY: getpid and getpgrp take no arguments.
    let (me, pgid) = unsafe { (libc::getpid(), libc::getpgrp()) };
    let pidfd = pidfd_open(me)?;
    // SAFETY: the helper is single-threaded here (it has run only the
    // checks); the child uses async-signal-safe calls and this crate's code
    // that allocates, which is sound without other threads.
    match unsafe { libc::fork() } {
        -1 => Err(format!(
            "the network watchdog did not start: {}",
            std::io::Error::last_os_error()
        )),
        0 => {
            // SAFETY: as above.
            match unsafe { libc::fork() } {
                0 => {
                    watchdog(pidfd, me, pgid, interval);
                    // SAFETY: never return into the helper's code.
                    unsafe { libc::_exit(0) }
                }
                -1 => unsafe { libc::_exit(1) },
                _ => unsafe { libc::_exit(0) },
            }
        }
        child => {
            let mut status = 0;
            // SAFETY: `child` is ours.
            unsafe { libc::waitpid(child, &mut status, 0) };
            drop(pidfd);
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                Ok(())
            } else {
                Err("the network watchdog did not start".into())
            }
        }
    }
}

fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd, String> {
    // SAFETY: an integer syscall.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(format!(
            "pidfd_open: {} (Linux 5.3 and later)",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// The watchdog's own process: leaves the session, keeps only stderr and
/// the pidfd, then loops.
fn watchdog(pidfd: OwnedFd, harness: libc::pid_t, pgid: libc::pid_t, interval: Duration) {
    // SAFETY: plain libc calls in the forked child.
    unsafe {
        libc::setsid();
        for s in [
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGHUP,
            libc::SIGTSTP,
            libc::SIGTTOU,
            libc::SIGTTIN,
            libc::SIGPIPE,
        ] {
            libc::signal(s, libc::SIG_IGN);
        }
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if null >= 0 {
            libc::dup2(null, 0);
            libc::dup2(null, 1);
        }
        let keep = pidfd.as_raw_fd();
        for fd in 3..1024 {
            if fd != keep {
                libc::close(fd);
            }
        }
    }
    let out = watch(&pidfd, interval, &mut super::netcheck::check);
    if let Watch::Failed(why) = out {
        let line = format!(
            "\nderm landlock: {why}\nderm landlock: the chat is stopped: the account's firewall table no longer refuses the network\n"
        );
        // SAFETY: fd 2 is the chat's terminal or log; written once, then closed
        // so nothing waits on it.
        unsafe {
            libc::write(2, line.as_ptr().cast(), line.len());
            libc::close(2);
        }
        stop(
            &Target {
                pidfd: &pidfd,
                pid: harness,
                pgid,
            },
            sweep_allowed(),
            interval,
        );
    }
}

/// How a watch ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Watch {
    /// The chat's process exited.
    Ended,
    /// A probe failed.
    Failed(String),
}

/// Runs `check` every `interval` until the pidfd's process exits or a check
/// fails.
pub(crate) fn watch(
    pidfd: &OwnedFd,
    interval: Duration,
    check: &mut dyn FnMut() -> Result<(), String>,
) -> Watch {
    let ms = interval.as_millis().min(i32::MAX as u128) as i32;
    loop {
        let mut p = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd that lives across the call.
        let r = unsafe { libc::poll(&mut p, 1, ms) };
        if r > 0 {
            return Watch::Ended;
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Watch::Ended;
        }
        if r == 0 {
            if let Err(why) = check() {
                return Watch::Failed(why);
            }
        }
    }
}

/// What a failed check stops.
pub(crate) struct Target<'a> {
    pub pidfd: &'a OwnedFd,
    pub pid: libc::pid_t,
    pub pgid: libc::pid_t,
}

/// `kill(-1)` only for an account, never for root (an account is never uid
/// 0: `accounts.rs`).
fn sweep_allowed() -> bool {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() != 0 }
}

/// SIGTERM, then SIGKILL after [`GRACE`], to the harness, its group and
/// every process below it; with `sweep`, one interval later SIGKILL to
/// every other process of this uid.
pub(crate) fn stop(t: &Target, sweep: bool, interval: Duration) {
    for sig in [libc::SIGTERM, libc::SIGKILL] {
        let below = descendants(t.pid);
        // SAFETY: integer syscalls; a pidfd names one process, never a
        // reused pid.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                t.pidfd.as_raw_fd(),
                sig,
                0usize,
                0u32,
            );
            if t.pgid > 1 {
                libc::killpg(t.pgid, sig);
            }
            for p in below {
                libc::kill(p, sig);
            }
        }
        if sig == libc::SIGTERM {
            std::thread::sleep(GRACE);
        }
    }
    if sweep {
        std::thread::sleep(interval + Duration::from_secs(1));
        // SAFETY: as the account: every process of its uid but this one.
        unsafe { libc::kill(-1, libc::SIGKILL) };
    }
}

/// Every process whose ancestors include `pid`, from `/proc`.
fn descendants(pid: libc::pid_t) -> Vec<libc::pid_t> {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let target = pid as u32;
    rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|p| *p != target && derm_core::peer::ancestors(*p).contains(&target))
        .map(|p| p as libc::pid_t)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn sleeper() -> std::process::Child {
        Command::new("/bin/sh")
            .args(["-c", "sleep 30 & sleep 30; wait"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn a_failed_probe_stops_the_chat_and_what_runs_below_it() {
        let mut child = sleeper();
        let pid = child.id() as libc::pid_t;
        std::thread::sleep(Duration::from_millis(200));
        let below = descendants(pid);
        assert!(!below.is_empty(), "the shell's sleeps are found below it");
        let fd = pidfd_open(pid).unwrap();
        let mut n = 0;
        let mut check = || {
            n += 1;
            if n < 2 {
                Ok(())
            } else {
                Err("outbound TCP was not refused".to_string())
            }
        };
        let w = watch(&fd, Duration::from_millis(50), &mut check);
        assert_eq!(w, Watch::Failed("outbound TCP was not refused".into()));
        stop(
            &Target {
                pidfd: &fd,
                pid,
                pgid: 0,
            },
            false,
            Duration::from_millis(10),
        );
        let st = child.wait().unwrap();
        assert!(!st.success(), "{st:?}");
        std::thread::sleep(Duration::from_millis(200));
        for p in below {
            // SAFETY: signal 0 only asks whether the pid is there.
            let alive = unsafe { libc::kill(p, 0) } == 0
                && std::fs::read_to_string(format!("/proc/{p}/stat"))
                    .is_ok_and(|s| !s.contains(") Z "));
            assert!(!alive, "{p} below the chat still runs");
        }
    }

    #[test]
    fn the_watch_ends_when_the_chat_does_and_checks_meanwhile() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 0.4"])
            .spawn()
            .unwrap();
        let fd = pidfd_open(child.id() as libc::pid_t).unwrap();
        let mut n = 0;
        let mut check = || {
            n += 1;
            Ok(())
        };
        let w = watch(&fd, Duration::from_millis(50), &mut check);
        assert_eq!(w, Watch::Ended);
        assert!(n >= 2, "checked {n} times while the chat ran");
        child.wait().unwrap();
    }

    #[test]
    fn root_never_sweeps() {
        // SAFETY: geteuid cannot fail.
        let root = unsafe { libc::geteuid() } == 0;
        assert_eq!(sweep_allowed(), !root);
    }
}
