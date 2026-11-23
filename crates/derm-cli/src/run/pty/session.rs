//! The harness on derm's own pty (Unix): `derm run` sits between the
//! person's terminal and the harness, as util-linux's `script` does
//! (`lib/pty-session.c` at v2.41: the person's termios copied to the new
//! pty, the person's terminal in raw mode, `setsid` and `TIOCSCTTY` in the
//! child, a non-blocking master, `TCSADRAIN` on the way out).
//!
//! What passes, and how (rules cases 87 and 142, plan P5):
//!
//! - **Raw mode.** The person's terminal is put in raw mode (`cfmakeraw`),
//!   so every key reaches the harness's pty as bytes and the line
//!   discipline that acts on them is the harness's own: a harness that sets
//!   raw mode on its terminal gets it, and one that does not gets the
//!   person's own settings, copied at the start.
//! - **Ctrl-C and the other keys that signal.** With the person's terminal
//!   raw, Ctrl-C is the byte 0x03 on the harness's pty, whose line
//!   discipline signals the harness's foreground group once. derm itself
//!   never receives it (no `ISIG` on the person's side), so nothing sends it
//!   twice (case 87); and the harness is in its own session, outside the
//!   person's job, so a signal to the person's foreground group never
//!   reaches it directly either.
//! - **A signal to `derm run` alone.** SIGINT, SIGTERM and SIGHUP a process
//!   sends to `derm run` go on to the harness, as `exec::wait` does today
//!   (case 87). With the person's terminal raw every SIGINT derm receives
//!   came from a process.
//! - **Resize.** SIGWINCH reads the person's terminal size and sets it on
//!   the harness's pty, whose kernel then signals the harness's foreground
//!   group (Linux v7.0 `drivers/tty/tty_io.c` `tty_do_resize`); the reader
//!   is resized with it.
//! - **Suspend.** SIGTSTP sent to `derm run` gives the person's terminal its
//!   settings back and stops derm; SIGCONT puts raw mode back and reads the
//!   size again. The harness, in its own session, keeps running.
//!
//! Windows (case 142) is not built here: `derm run` there keeps today's
//! console path, and [`usable`] does not exist off Unix.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use super::put::Publisher;
use super::Reader;
use crate::run::plan::Plan;

/// At most one `screen.put` this often while the output changes
/// (`contracts/project-tools.md` 3.2).
pub(crate) const PUT_EVERY: Duration = Duration::from_millis(250);
/// After the harness exits, read what it left on the pty until this much
/// time passes with no output...
pub(crate) const DRAIN_IDLE: Duration = Duration::from_millis(100);
/// ...or this much in all (a process the harness left holding its terminal
/// can keep writing; it gets a hangup when derm closes the pty).
pub(crate) const DRAIN_MAX: Duration = Duration::from_secs(2);
const POLL_MS: libc::c_int = 50;
/// Keystrokes waiting for the harness to read them; past this the person's
/// terminal is not read until the harness catches up.
const INPUT_CAP: usize = 1024 * 1024;

const SIG_INT: u32 = 1;
const SIG_TERM: u32 = 2;
const SIG_HUP: u32 = 4;
const SIG_WINCH: u32 = 8;
const SIG_TSTP: u32 = 16;
const SIG_CONT: u32 = 32;

static PENDING: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    // One atomic fetch_or: async-signal-safe.
    let bit = match sig {
        libc::SIGINT => SIG_INT,
        libc::SIGTERM => SIG_TERM,
        libc::SIGHUP => SIG_HUP,
        libc::SIGWINCH => SIG_WINCH,
        libc::SIGTSTP => SIG_TSTP,
        libc::SIGCONT => SIG_CONT,
        _ => 0,
    };
    PENDING.fetch_or(bit, Ordering::SeqCst);
}

const CAUGHT: [libc::c_int; 6] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGWINCH,
    libc::SIGTSTP,
    libc::SIGCONT,
];

fn set_handler(sig: libc::c_int, handler: usize) -> libc::sigaction {
    // SAFETY: a zeroed sigaction with a handler that only does an atomic
    // fetch_or (or SIG_DFL) is a valid argument; `old` receives the previous
    // action.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler;
        libc::sigemptyset(&mut act.sa_mask);
        act.sa_flags = libc::SA_RESTART;
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, &act, &mut old);
        old
    }
}

fn install_handlers() -> Vec<(libc::c_int, libc::sigaction)> {
    PENDING.store(0, Ordering::SeqCst);
    CAUGHT
        .iter()
        .map(|&s| (s, set_handler(s, on_signal as *const () as usize)))
        .collect()
}

fn restore_handlers(old: &[(libc::c_int, libc::sigaction)]) {
    for (sig, act) in old {
        // SAFETY: an action sigaction(2) returned for this signal.
        unsafe {
            libc::sigaction(*sig, act, std::ptr::null_mut());
        }
    }
}

/// The person's side: where keys come from and where the harness's output
/// goes. `derm run` uses fds 0 and 1; tests use the slave of a pty of their
/// own.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Terminal {
    pub(crate) input: RawFd,
    pub(crate) output: RawFd,
}

impl Terminal {
    pub(crate) fn person() -> Terminal {
        Terminal {
            input: libc::STDIN_FILENO,
            output: libc::STDOUT_FILENO,
        }
    }
}

/// Whether `derm run` can hold this chat's terminal: not for `derm acp`'s
/// pipes, not without a terminal on stdin and stdout, not from a background
/// job (setting raw mode there would stop derm with SIGTTOU). The reason is
/// for the start line.
pub(crate) fn usable(piped: bool) -> Result<(), &'static str> {
    if piped {
        return Err("the harness speaks ACP on pipes");
    }
    // SAFETY: plain calls on fds 0 and 1 and this process.
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) != 1 || libc::isatty(libc::STDOUT_FILENO) != 1 {
            return Err("stdin or stdout is not a terminal");
        }
        let fg = libc::tcgetpgrp(libc::STDIN_FILENO);
        if fg == -1 || fg != libc::getpgrp() {
            return Err("derm run is not in its terminal's foreground");
        }
    }
    Ok(())
}

/// Whether derm may set modes on or read from `fd` now: always when `fd` is
/// not derm's controlling terminal (no SIGTTOU or SIGTTIN can come of it),
/// else only from the foreground group.
fn may_touch(fd: RawFd) -> bool {
    // SAFETY: tcgetpgrp and getpgrp on a descriptor and this process.
    unsafe {
        let fg = libc::tcgetpgrp(fd);
        fg == -1 || fg == libc::getpgrp()
    }
}

fn termios(fd: RawFd) -> Option<libc::termios> {
    // SAFETY: tcgetattr writes a termios for a valid descriptor or fails.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        (libc::tcgetattr(fd, &mut t) == 0).then_some(t)
    }
}

fn winsize(fd: RawFd) -> Option<libc::winsize> {
    // SAFETY: TIOCGWINSZ writes a winsize for a terminal or fails.
    unsafe {
        let mut w: libc::winsize = std::mem::zeroed();
        (libc::ioctl(fd, libc::TIOCGWINSZ, &mut w) == 0).then_some(w)
    }
}

fn set_winsize(fd: RawFd, w: &libc::winsize) {
    // SAFETY: TIOCSWINSZ reads a winsize; failure leaves the old size.
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, w);
    }
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn set_flags(fd: RawFd, cloexec: bool, nonblock: bool) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor this module owns.
    unsafe {
        if cloexec {
            let f = cvt(libc::fcntl(fd, libc::F_GETFD))?;
            cvt(libc::fcntl(fd, libc::F_SETFD, f | libc::FD_CLOEXEC))?;
        }
        if nonblock {
            let f = cvt(libc::fcntl(fd, libc::F_GETFL))?;
            cvt(libc::fcntl(fd, libc::F_SETFL, f | libc::O_NONBLOCK))?;
        }
    }
    Ok(())
}

/// A new pty: its master and slave, both close-on-exec. POSIX's
/// `posix_openpt`, `grantpt` and `unlockpt` (libc 0.2.189
/// `src/unix/mod.rs:2112-2118`, every Unix) rather than `openpty`, which
/// the libc crate declares with no library to link (`unix/linux_like/
/// mod.rs:2184`), so where it lives in libutil the link would fail.
pub(super) fn open_pty() -> io::Result<(OwnedFd, OwnedFd)> {
    #[cfg(target_os = "linux")]
    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::O_RDWR | libc::O_NOCTTY;
    // SAFETY: posix_openpt returns a new descriptor or -1.
    let m = cvt(unsafe { libc::posix_openpt(flags) })?;
    // SAFETY: `m` is a descriptor we just opened and own.
    let master = unsafe { OwnedFd::from_raw_fd(m) };
    set_flags(m, true, false)?;
    // SAFETY: plain calls on our own master.
    unsafe {
        cvt(libc::grantpt(m))?;
        cvt(libc::unlockpt(m))?;
    }
    let slave = open_slave(&master)?;
    set_flags(slave.as_raw_fd(), true, false)?;
    Ok((master, slave))
}

/// Linux: the slave by `TIOCGPTPEER`, which needs no path
/// under `/dev/pts` (v7.0 `drivers/tty/pty.c` `ptm_open_peer`: "a race free
/// way for userspace to open the slave end of a pty"); by its name
/// (`ptsname_r`) when the kernel refuses the ioctl.
#[cfg(target_os = "linux")]
fn open_slave(master: &OwnedFd) -> io::Result<OwnedFd> {
    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: TIOCGPTPEER returns a new descriptor or -1.
    let fd = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPTPEER, flags) };
    if fd >= 0 {
        // SAFETY: a descriptor the kernel just gave us.
        return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    let mut name = [0 as libc::c_char; 128];
    // SAFETY: ptsname_r writes at most `name.len()` bytes, NUL included.
    let r = unsafe { libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r));
    }
    // SAFETY: open of a NUL-terminated path.
    let fd = cvt(unsafe { libc::open(name.as_ptr(), flags) })?;
    // SAFETY: a descriptor we just opened.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// macOS and the BSDs: by name. `ptsname` keeps its answer in a static, so
/// one caller at a time.
#[cfg(not(target_os = "linux"))]
fn open_slave(master: &OwnedFd) -> io::Result<OwnedFd> {
    static NAME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = NAME.lock().unwrap_or_else(|p| p.into_inner());
    // SAFETY: ptsname returns a NUL-terminated name or null.
    let name = unsafe { libc::ptsname(master.as_raw_fd()) };
    if name.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open of the NUL-terminated name ptsname gave.
    let fd = cvt(unsafe { libc::open(name, libc::O_RDWR | libc::O_NOCTTY) })?;
    // SAFETY: a descriptor we just opened.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
const TIOCSCTTY: libc::Ioctl = libc::TIOCSCTTY;
#[cfg(not(target_os = "linux"))]
const TIOCSCTTY: libc::c_ulong = libc::TIOCSCTTY as libc::c_ulong;

/// The harness on its own pty, and the person's terminal while it runs.
pub(crate) struct Session {
    pub(crate) child: Child,
    master: OwnedFd,
    term: Terminal,
    /// The person's terminal as it was, put back at the end.
    saved: Option<libc::termios>,
    raw: Option<libc::termios>,
    reader: Reader,
    handlers: Vec<(libc::c_int, libc::sigaction)>,
    restored: bool,
    output_open: bool,
}

/// Starts `plan` on a new pty sized and set as the person's terminal,
/// then puts the person's terminal in raw mode. The environment is the
/// plan's, as `exec::spawn` sets it; `TERM` stays the person's.
pub(crate) fn spawn(plan: &Plan, cwd: &str, term: Terminal) -> io::Result<Session> {
    let saved = termios(term.input);
    let size = winsize(term.input).or_else(|| winsize(term.output));
    let (master, slave) = open_pty()?;
    if let Some(t) = &saved {
        // SAFETY: tcsetattr with a termios tcgetattr gave.
        unsafe {
            libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, t);
        }
    }
    if let Some(w) = &size {
        set_winsize(master.as_raw_fd(), w);
    }
    set_flags(master.as_raw_fd(), false, true)?;

    let mut cmd = Command::new(&plan.program);
    cmd.args(&plan.args).current_dir(cwd);
    for name in &plan.env_remove {
        cmd.env_remove(name);
    }
    for (k, v) in &plan.env_set {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?));
    // SAFETY: setsid and ioctl are async-signal-safe, and the closure runs
    // after std has put the slave on fds 0 to 2 (Rust 1.97.0
    // `library/std/src/sys/process/unix/unix.rs` `do_exec`: the dup2s, then
    // the closures, then execvp). TIOCSCTTY's 0: never steal a terminal
    // another session holds (v7.0 `tty_jobctrl.c` `tiocsctty`).
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let handlers = install_handlers();
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            restore_handlers(&handlers);
            return Err(e);
        }
    };
    // The slave's copies in this process go, so the master reads end of
    // file once the harness and what it started have closed theirs.
    drop(cmd);
    drop(slave);

    let (rows, cols) = size.map(|w| (w.ws_row, w.ws_col)).unwrap_or((0, 0));
    let raw = saved.map(|t| {
        let mut r = t;
        // SAFETY: cfmakeraw edits the termios in place.
        unsafe {
            libc::cfmakeraw(&mut r);
        }
        r
    });
    let s = Session {
        child,
        master,
        term,
        saved,
        raw,
        reader: Reader::new(rows, cols),
        handlers,
        restored: false,
        output_open: true,
    };
    s.raw_mode();
    Ok(s)
}

impl Session {
    /// The chat's screen, as rendered so far (the tests' window on it;
    /// `derm run` sends it with `put`).
    #[cfg(test)]
    pub(crate) fn reader(&mut self) -> &mut Reader {
        &mut self.reader
    }

    fn raw_mode(&self) {
        if let Some(r) = &self.raw {
            if may_touch(self.term.input) {
                // SAFETY: tcsetattr with a termios derived from tcgetattr's.
                unsafe {
                    libc::tcsetattr(self.term.input, libc::TCSANOW, r);
                }
            }
        }
    }

    fn cooked(&self) {
        if let Some(t) = &self.saved {
            if may_touch(self.term.input) {
                // SAFETY: the termios tcgetattr gave at the start.
                unsafe {
                    libc::tcsetattr(self.term.input, libc::TCSADRAIN, t);
                }
            }
        }
    }

    /// The person's terminal size, onto the harness's pty and the reader.
    fn resize(&mut self) {
        if let Some(w) = winsize(self.term.input).or_else(|| winsize(self.term.output)) {
            set_winsize(self.master.as_raw_fd(), &w);
            self.reader.resize(w.ws_row, w.ws_col);
        }
    }

    /// SIGTSTP to derm: the person's settings back, stop, and on SIGCONT
    /// raw mode again (as `less` and `vim` do).
    fn suspend(&mut self) {
        self.cooked();
        set_handler(libc::SIGTSTP, libc::SIG_DFL);
        // SAFETY: a signal to this process; with SIGTSTP at its default
        // action and unblocked, the process stops before kill returns.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGTSTP);
        }
        set_handler(libc::SIGTSTP, on_signal as *const () as usize);
        self.raw_mode();
        self.resize();
    }

    /// Handles the signals that came since the last call. True when the
    /// screen changed size.
    fn signals(&mut self, running: bool) -> bool {
        let bits = PENDING.swap(0, Ordering::SeqCst);
        if running {
            for (bit, sig) in [
                (SIG_INT, libc::SIGINT),
                (SIG_TERM, libc::SIGTERM),
                (SIG_HUP, libc::SIGHUP),
            ] {
                if bits & bit != 0 {
                    // SAFETY: kill with the child's pid, which stays ours
                    // until we reap it, and a valid signal.
                    unsafe {
                        libc::kill(self.child.id() as libc::pid_t, sig);
                    }
                }
            }
        }
        let mut resized = false;
        if bits & SIG_TSTP != 0 {
            self.suspend();
            resized = true;
        }
        if bits & SIG_CONT != 0 {
            self.raw_mode();
            resized = true;
        }
        if resized || bits & SIG_WINCH != 0 {
            self.resize();
            return true;
        }
        false
    }

    fn write_out(&mut self, mut bytes: &[u8]) {
        while self.output_open && !bytes.is_empty() {
            // SAFETY: write from a live buffer to the person's terminal.
            let n = unsafe { libc::write(self.term.output, bytes.as_ptr().cast(), bytes.len()) };
            if n > 0 {
                bytes = &bytes[n as usize..];
                continue;
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EAGAIN) => {
                    let mut p = libc::pollfd {
                        fd: self.term.output,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: poll on one pollfd.
                    unsafe {
                        libc::poll(&mut p, 1, 100);
                    }
                }
                // The terminal is gone (EIO, EPIPE): the reader still gets
                // the output.
                _ => self.output_open = false,
            }
        }
    }

    /// Pumps the person's keys to the harness and its output to the
    /// person's terminal and the reader until the harness exits and its
    /// pty is drained; sends the screen at most every `PUT_EVERY` and once
    /// at the end; then gives the person's terminal and the signal handlers
    /// back. The harness's exit status, as `exec::wait` returns it.
    pub(crate) fn wait(&mut self, publisher: Option<&Publisher>) -> io::Result<ExitStatus> {
        let master = self.master.as_raw_fd();
        let mut status: Option<ExitStatus> = None;
        let mut exited_at: Option<Instant> = None;
        let mut last_data = Instant::now();
        let mut master_open = true;
        let mut input_open = true;
        let mut pending: Vec<u8> = Vec::new();
        let mut dirty = false;
        let mut last_put: Option<Instant> = None;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if self.signals(status.is_none()) {
                dirty = true;
            }
            if status.is_none() {
                if let Some(s) = self.child.try_wait()? {
                    status = Some(s);
                    exited_at = Some(Instant::now());
                    pending.clear();
                }
            }
            if let Some(t) = exited_at {
                if !master_open
                    || t.elapsed() >= DRAIN_MAX
                    || (t.elapsed() >= DRAIN_IDLE && last_data.elapsed() >= DRAIN_IDLE)
                {
                    break;
                }
            }
            let read_input = input_open
                && status.is_none()
                && pending.len() < INPUT_CAP
                && may_touch(self.term.input);
            let mut fds = Vec::with_capacity(2);
            if master_open {
                let mut ev = libc::POLLIN;
                if !pending.is_empty() {
                    ev |= libc::POLLOUT;
                }
                fds.push(libc::pollfd {
                    fd: master,
                    events: ev,
                    revents: 0,
                });
            }
            let input_at = fds.len();
            if read_input {
                fds.push(libc::pollfd {
                    fd: self.term.input,
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            // SAFETY: poll on a live array of `fds.len()` pollfds (none is
            // a plain sleep).
            let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, POLL_MS) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            if master_open {
                let rev = fds[0].revents;
                if rev & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                    // Read what is there, up to 1 MiB a turn so keys and
                    // signals are not starved.
                    for _ in 0..16 {
                        // SAFETY: read into a live buffer from our master.
                        let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
                        if n > 0 {
                            let got = &buf[..n as usize];
                            self.write_out(got);
                            self.reader.feed(got);
                            dirty = true;
                            last_data = Instant::now();
                            continue;
                        }
                        if n == 0 {
                            master_open = false;
                            break;
                        }
                        match io::Error::last_os_error().raw_os_error() {
                            Some(libc::EAGAIN) => break,
                            Some(libc::EINTR) => continue,
                            // EIO: every slave copy is closed (v7.0
                            // `n_tty.c` `n_tty_wait_for_input`).
                            _ => {
                                master_open = false;
                                break;
                            }
                        }
                    }
                }
                if master_open && rev & libc::POLLOUT != 0 && !pending.is_empty() {
                    // SAFETY: write from a live buffer to our master.
                    let n = unsafe { libc::write(master, pending.as_ptr().cast(), pending.len()) };
                    if n > 0 {
                        pending.drain(..n as usize);
                    } else if n < 0
                        && !matches!(
                            io::Error::last_os_error().raw_os_error(),
                            Some(libc::EAGAIN) | Some(libc::EINTR)
                        )
                    {
                        pending.clear();
                    }
                }
            }
            if read_input
                && fds[input_at].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            {
                let room = (INPUT_CAP - pending.len()).min(16 * 1024);
                let mut keys = vec![0u8; room];
                // SAFETY: read into a live buffer from the person's terminal.
                let n = unsafe { libc::read(self.term.input, keys.as_mut_ptr().cast(), room) };
                if n > 0 {
                    pending.extend_from_slice(&keys[..n as usize]);
                } else if n == 0
                    || !matches!(
                        io::Error::last_os_error().raw_os_error(),
                        Some(libc::EAGAIN) | Some(libc::EINTR)
                    )
                {
                    input_open = false;
                }
            }
            if let Some(p) = publisher {
                if dirty && last_put.is_none_or(|t| t.elapsed() >= PUT_EVERY) {
                    p.offer(self.reader.render());
                    dirty = false;
                    last_put = Some(Instant::now());
                }
            }
        }
        if let Some(p) = publisher {
            p.offer(self.reader.render());
        }
        self.restore();
        Ok(status.expect("the loop ends only after the harness exited"))
    }

    /// The person's terminal and derm's signal handlers as they were.
    /// Idempotent; also run on drop, so a panic leaves no raw terminal.
    fn restore(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        self.cooked();
        restore_handlers(&self.handlers);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.restore();
    }
}
