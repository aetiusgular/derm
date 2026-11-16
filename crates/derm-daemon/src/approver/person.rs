//! S2 part b: a person check before a `yes` that an agent could forge
//! (wave 5 lane V; lane J's request 1b, `plans/parallel/tk_lane_J.md`).
//!
//! Who can forge one: any process that runs as the daemon's own user outside
//! a boundary can read `daemon.token`, register as an approver from outside a
//! chat's process tree (a double fork, `setsid`, tmux, `systemd-run --user`:
//! box test w2, step 2.2) and answer `yes` to its own ask. Part a refuses an
//! approver inside a chat's tree; it cannot see one that left it. A chat that
//! runs as the person with no boundary is such a process; so is anything it
//! left running (case 68).
//!
//! What the check is: the person's login password, verified by the system
//! itself: on macOS by its PAM service `checkpw` (`MacPam`, fix pass 12
//! (Mac)), and on Linux by the system's
//! own helper for it, Linux-PAM's `unix_chkpwd` (setgid `shadow`; it checks
//! only the password of the user that runs it, `modules/pam_unix/
//! unix_chkpwd.c`), with a back-off after each wrong one. An agent that runs
//! as the person does not know the password. What it does not stop, and the
//! status line says so: an agent that runs as the person can replace the
//! program the person types the password into, or read it from a shell rc
//! file it planted, and then answer with it. Only a boundary or the agents'
//! user (part c) keeps the agent from the person's account; this check
//! raises the cost from "any script" to "a planted program and a person who
//! types into it".
//!
//! When it applies (`needed`): a `yes` for a chat that runs as the person,
//! for a chat with no `run.start` (started outside `derm run`), or for any
//! chat while one that runs as the person is running or has run since the
//! daemon started (its leftovers can read `daemon.token`). A `no` never
//! needs it: refusing is always safe.
//!
//! The wiring (the `proof` field on `answer`, the call from `op_answer`, and
//! `derm watch --approve` asking for the password) is integration's: lane
//! V's request V-2, with its patch in `tests/integration/w5/V/requests/`.

// The helper below is Unix's; on Windows (lane Z) these stay unused.
#[cfg_attr(not(unix), allow(unused_imports))]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg_attr(not(unix), allow(unused_imports))]
use std::path::{Path, PathBuf};
#[cfg_attr(not(unix), allow(unused_imports))]
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

/// The password is no longer than this (Linux-PAM's `MAXPASS` is 512,
/// `modules/pam_unix/support.h`); a longer one is refused unread.
pub const MAX_PASSWORD: usize = 512;
/// How long the helper may take.
#[cfg_attr(not(unix), allow(dead_code))]
const HELPER_DEADLINE: Duration = Duration::from_secs(10);
/// The back-off after the n-th wrong password in a row: 1, 2, 4 ... seconds,
/// capped here. It is the daemon's, not a connection's: a new connection
/// waits as long.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// What a check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The password is the person's.
    #[cfg_attr(not(unix), allow(dead_code))]
    Person,
    /// It is not, or none was given.
    Wrong(String),
    /// The daemon cannot check here; a `yes` that needs a check is refused.
    Unavailable(String),
}

/// Checks a password for the daemon's own user.
pub trait Checker: Send + Sync {
    fn check(&self, user: &str, password: &[u8]) -> Verdict;
    /// Why no password can be checked here at all, before one is asked for
    /// (Mac test w5, MW5-4): `None` where a check can run.
    fn unavailable(&self) -> Option<String> {
        None
    }
}

/// Whether a `yes` for `chat` needs a person check, and why. `run_info` is
/// the daemon's running chats (`run_info_of`); `ran_as_you` is whether a
/// chat that runs as the person has started since the daemon did.
pub fn needed(
    run_info: &std::collections::HashMap<String, Value>,
    chat: &str,
    ran_as_you: bool,
) -> Option<String> {
    match run_info.get(chat) {
        None => return Some(format!("chat {} was not started by derm run", clip(chat))),
        Some(info) if runs_as_person(info) => {
            return Some(format!("chat {} runs as you with no boundary", clip(chat)))
        }
        Some(_) => {}
    }
    if let Some((other, _)) = run_info.iter().find(|(_, i)| runs_as_person(i)) {
        return Some(format!(
            "chat {} runs as you with no boundary and can answer for others",
            clip(other)
        ));
    }
    ran_as_you.then(|| {
        "a chat ran as you with no boundary since the daemon started; what it left running can read daemon.token".to_string()
    })
}

/// A chat runs as the person when it has no boundary (`none`, or none named)
/// and no agents' user. `run_info` holds `agentUser` only once integration
/// keeps it (request V-2); until then every `none` chat counts, which is the
/// safe reading.
pub fn runs_as_person(info: &Value) -> bool {
    let boundary = info.get("boundary").and_then(Value::as_str).unwrap_or("");
    let agent_user = info
        .get("agentUser")
        .and_then(Value::as_str)
        .is_some_and(|u| !u.is_empty());
    !agent_user && !matches!(boundary, "srt" | "sbx")
}

fn clip(s: &str) -> String {
    s.chars().take(128).collect()
}

/// The back-off: how many wrong passwords in a row, and until when the next
/// try is refused.
#[derive(Default)]
pub struct Backoff {
    state: Mutex<(u32, Option<Instant>)>,
}

impl Backoff {
    /// `Some(wait)` while a try must wait.
    pub fn waiting(&self, now: Instant) -> Option<Duration> {
        let s = self.state.lock().ok()?;
        s.1.and_then(|until| until.checked_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    pub fn failed(&self, now: Instant) {
        if let Ok(mut s) = self.state.lock() {
            s.0 = s.0.saturating_add(1);
            let secs = 1u64 << (s.0 - 1).min(6);
            s.1 = Some(now + Duration::from_secs(secs).min(MAX_BACKOFF));
        }
    }

    pub fn passed(&self) {
        if let Ok(mut s) = self.state.lock() {
            *s = (0, None);
        }
    }
}

/// One check, with the back-off around it. `password` is wiped before this
/// returns, whatever the outcome.
pub fn verify(
    checker: &dyn Checker,
    backoff: &Backoff,
    user: &str,
    password: Option<&mut Vec<u8>>,
    now: Instant,
) -> Verdict {
    // Where no check can run, say so before a password is asked for: a
    // password typed for nothing is a secret sent for nothing (MW5-4).
    if let Some(why) = checker.unavailable() {
        if let Some(p) = password {
            wipe(p);
        }
        return Verdict::Unavailable(why);
    }
    let Some(password) = password else {
        return Verdict::Wrong("no password given".into());
    };
    let verdict = if let Some(wait) = backoff.waiting(now) {
        Verdict::Wrong(format!(
            "a wrong password was given; try again in {} s",
            wait.as_secs().max(1)
        ))
    } else if password.is_empty() {
        Verdict::Wrong("no password given".into())
    } else if password.len() > MAX_PASSWORD || password.contains(&0) {
        Verdict::Wrong("not a password".into())
    } else {
        let v = checker.check(user, password);
        match &v {
            Verdict::Person => backoff.passed(),
            Verdict::Wrong(_) => backoff.failed(now),
            Verdict::Unavailable(_) => {}
        }
        v
    };
    wipe(password);
    verdict
}

/// Overwrites the password in place, in a way the compiler keeps.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Linux-PAM's helper, found at an absolute path, root's, not writable by
/// group or others, set-group-id (to read `/etc/shadow`) or set-user-id.
#[cfg(unix)]
pub struct UnixChkpwd {
    path: PathBuf,
}

/// Where Debian, Ubuntu and Fedora put the helper.
#[cfg_attr(not(unix), allow(dead_code))]
const HELPER_PATHS: &[&str] = &["/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd"];

#[cfg(unix)]
impl UnixChkpwd {
    /// The helper, or why there is none to trust.
    pub fn find() -> Result<Self, String> {
        Self::find_in(HELPER_PATHS, 0)
    }

    fn find_in(paths: &[&str], trusted: u32) -> Result<Self, String> {
        let mut seen = Vec::new();
        for p in paths {
            let path = Path::new(p);
            let Ok(m) = std::fs::metadata(path) else {
                continue;
            };
            let ok = m.is_file()
                && m.uid() == trusted
                && m.mode() & 0o022 == 0
                && m.mode() & 0o6000 != 0;
            if ok {
                // Its folder must be root's too (a link above it, such as
                // `/sbin` to `/usr/sbin`, resolves to one).
                let real = std::fs::canonicalize(path).map_err(|e| format!("{p}: {e}"))?;
                if parents_trusted(&real, trusted) {
                    return Ok(UnixChkpwd { path: real });
                }
            }
            seen.push(*p);
        }
        Err(if seen.is_empty() {
            "unix_chkpwd is not installed (Linux-PAM's pam_unix)".into()
        } else {
            format!(
                "{} is not root's and set-id, or sits in a folder others can write",
                seen.join(", ")
            )
        })
    }
}

#[cfg(unix)]
fn parents_trusted(real: &Path, trusted: u32) -> bool {
    real.ancestors().skip(1).all(|p| {
        std::fs::symlink_metadata(p)
            .map(|m| m.is_dir() && m.uid() == trusted && m.mode() & 0o022 == 0)
            .unwrap_or(false)
    })
}

#[cfg(unix)]
impl Checker for UnixChkpwd {
    /// `unix_chkpwd <user> nonull`, the password and a NUL on a pipe (the
    /// helper refuses a terminal on stdin), exit 0 for the person's password.
    /// `nonull`: an empty password is no proof. Only its exit 7
    /// (`PAM_AUTH_ERR`) is a wrong password; any other failure, such as 9
    /// (`PAM_AUTHINFO_UNAVAIL`: it could not read the shadow entry, as under
    /// no_new_privs), is no verdict on the password (box test w5, BW5-17;
    /// Linux-PAM 1.7.1 `modules/pam_unix/unix_chkpwd.c:160-176`,
    /// `libpam/include/security/_pam_types.h:37, 40`).
    fn check(&self, user: &str, password: &[u8]) -> Verdict {
        let child = Command::new(&self.path)
            .args([user, "nonull"])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => return Verdict::Unavailable(format!("unix_chkpwd did not start: {e}")),
        };
        if let Some(mut stdin) = child.stdin.take() {
            let mut buf = Vec::with_capacity(password.len() + 1);
            buf.extend_from_slice(password);
            buf.push(0);
            let _ = stdin.write_all(&buf);
            wipe(&mut buf);
        }
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Verdict::Person,
                Ok(Some(status)) if status.code() == Some(PAM_AUTH_ERR) => {
                    return Verdict::Wrong("wrong password".into())
                }
                Ok(Some(status)) => {
                    return Verdict::Unavailable(format!(
                        "unix_chkpwd could not check the password ({}): {}",
                        status
                            .code()
                            .map_or_else(|| "killed".to_string(), |c| format!("exit {c}")),
                        if no_new_privs() {
                            NNP_WHY
                        } else {
                            "it may not read /etc/shadow here"
                        }
                    ))
                }
                Ok(None) if start.elapsed() < HELPER_DEADLINE => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Verdict::Unavailable("unix_chkpwd did not answer".into());
                }
            }
        }
    }
}

/// macOS: the person's login password, checked by the system's own PAM
/// service for exactly that, `checkpw` (`/etc/pam.d/checkpw`: `auth required
/// pam_opendirectory.so use_first_pass nullok`; read on macOS 26.5.1). Its
/// one auth module verifies the password with `ODRecordVerifyPassword`
/// (Apple pam_modules-217.0.1, `modules/pam_opendirectory/
/// pam_opendirectory.m:262-304`), which needs no privilege for the caller's
/// own account: run on the Mac as the person, a wrong password came back
/// `PAM_AUTH_ERR` in 2 s with no conversation call. No helper program and no
/// set-id bit are involved, so nothing here depends on no_new_privs.
///
/// The password reaches the module as `PAM_AUTHTOK` (`use_first_pass`;
/// OpenPAM `pam_set_item.c:67-82` takes it from the application), never
/// through a conversation, which only refuses. An empty password is refused
/// before this (`verify`) and by `PAM_DISALLOW_NULL_AUTHTOK`.
///
/// What it costs: a wrong password counts as a failed login for the
/// account. Where an account policy locks after N failures
/// (`pwpolicy -getaccountpolicies`, `policyAttributeMaximumFailedAuthentications`),
/// forged answers could lock the account; the daemon's back-off (one try a
/// minute after six) bounds the rate, and a locked account reads as "cannot
/// check", never as a wrong password.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct MacPam;

#[cfg(target_os = "macos")]
mod mac_pam {
    use std::ffi::{c_char, c_int, c_void};

    pub const SERVICE: &str = "checkpw";
    pub const SERVICE_FILE: &str = "/etc/pam.d/checkpw";
    // OpenPAM `security/pam_constants.h` (macOS SDK, read).
    pub const PAM_SUCCESS: c_int = 0;
    pub const PAM_CONV_ERR: c_int = 6;
    pub const PAM_AUTHTOK: c_int = 6;
    pub const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x1;

    #[repr(C)]
    pub struct PamConv {
        pub conv: extern "C" fn(c_int, *mut c_void, *mut c_void, *mut c_void) -> c_int,
        pub appdata: *mut c_void,
    }

    /// The conversation never answers: the password is `PAM_AUTHTOK`, and a
    /// module that asks for anything else gets an error.
    pub extern "C" fn refuse(_: c_int, _: *mut c_void, _: *mut c_void, _: *mut c_void) -> c_int {
        PAM_CONV_ERR
    }

    #[link(name = "pam")]
    extern "C" {
        pub fn pam_start(
            service: *const c_char,
            user: *const c_char,
            conv: *const PamConv,
            handle: *mut *mut c_void,
        ) -> c_int;
        pub fn pam_set_item(handle: *mut c_void, item: c_int, value: *const c_void) -> c_int;
        pub fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
        pub fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    }
}

/// What `pam_authenticate`'s code means for the password (macOS). Only
/// `PAM_AUTH_ERR` is a wrong password; a locked or disabled account, or any
/// other code, is no verdict on it.
/// OpenPAM's codes (`security/pam_constants.h`, macOS SDK): 0 `PAM_SUCCESS`,
/// 7 `PAM_PERM_DENIED`, 9 `PAM_AUTH_ERR`, 1024 `PAM_APPLE_ACCT_TEMP_LOCK`,
/// 1025 `PAM_APPLE_ACCT_LOCKED`, as `pam_opendirectory.m:266-300` returns
/// them. Numbers, not the macOS constants, so the mapping is tested on
/// every system.
#[cfg(any(target_os = "macos", test))]
fn mac_verdict(code: i32) -> Verdict {
    match code {
        0 => Verdict::Person,
        9 => Verdict::Wrong("wrong password".into()),
        1024 | 1025 => Verdict::Unavailable(
            "macOS says the account is locked after wrong passwords; unlock it by logging in"
                .into(),
        ),
        // Also what a lockout policy answers for the right password while
        // the account is locked (run on the Mac with a test account locked
        // after 3 failures: 7, never 1024; a wrong password there still
        // answers 9).
        7 => Verdict::Unavailable(
            "macOS says the account is disabled, inactive, or locked by its password policy after wrong passwords; wait for the lock to end or log in to clear it"
                .into(),
        ),
        n => Verdict::Unavailable(format!(
            "macOS's password check (PAM service checkpw) answered {n}"
        )),
    }
}

#[cfg(target_os = "macos")]
impl MacPam {
    /// The checker, or why there is none to trust: the service's file must
    /// be there (without it OpenPAM uses `other`, which denies everything,
    /// and every password would read as wrong), root's, and not writable by
    /// group or others.
    pub fn find() -> Result<Self, String> {
        Self::find_at(Path::new(mac_pam::SERVICE_FILE), 0)
    }

    fn find_at(file: &Path, trusted: u32) -> Result<Self, String> {
        let m = std::fs::metadata(file).map_err(|_| {
            format!(
                "{} is missing, so macOS has no PAM service to check a password with",
                file.display()
            )
        })?;
        if !(m.is_file() && m.uid() == trusted && m.mode() & 0o022 == 0) {
            return Err(format!(
                "{} is not root's, or others can write it",
                file.display()
            ));
        }
        Ok(MacPam)
    }

    /// One `pam_authenticate`, on this thread.
    fn authenticate(user: &str, password: &[u8]) -> Result<i32, String> {
        use std::ffi::CString;
        let service = CString::new(mac_pam::SERVICE).map_err(|e| e.to_string())?;
        let user = CString::new(user).map_err(|_| "the user name holds a NUL".to_string())?;
        let mut tok = Vec::with_capacity(password.len() + 1);
        tok.extend_from_slice(password);
        tok.push(0);
        let conv = mac_pam::PamConv {
            conv: mac_pam::refuse,
            appdata: std::ptr::null_mut(),
        };
        let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: every pointer outlives the calls; `handle` is written by
        // pam_start and ended once; `tok` is NUL-terminated and PAM copies
        // it (OpenPAM `pam_set_item.c`), so it is wiped here after.
        let code = unsafe {
            let rc = mac_pam::pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle);
            if rc != mac_pam::PAM_SUCCESS || handle.is_null() {
                wipe(&mut tok);
                return Err(format!("pam_start answered {rc}"));
            }
            let rc = mac_pam::pam_set_item(handle, mac_pam::PAM_AUTHTOK, tok.as_ptr().cast());
            let code = if rc == mac_pam::PAM_SUCCESS {
                mac_pam::pam_authenticate(handle, mac_pam::PAM_DISALLOW_NULL_AUTHTOK)
            } else {
                wipe(&mut tok);
                mac_pam::pam_end(handle, rc);
                return Err(format!("pam_set_item answered {rc}"));
            };
            mac_pam::pam_end(handle, code);
            code
        };
        wipe(&mut tok);
        Ok(code)
    }
}

#[cfg(target_os = "macos")]
impl Checker for MacPam {
    /// The check runs on its own thread with the helper's deadline: the
    /// module waits about 2 s after a wrong password, and OpenDirectory can
    /// take longer; a check that does not answer is no verdict.
    fn check(&self, user: &str, password: &[u8]) -> Verdict {
        let (tx, rx) = std::sync::mpsc::channel();
        let user = user.to_string();
        let mut copy = password.to_vec();
        let started = std::thread::Builder::new()
            .name("person-check".into())
            .spawn(move || {
                let r = MacPam::authenticate(&user, &copy);
                wipe(&mut copy);
                let _ = tx.send(r);
            });
        if let Err(e) = started {
            return Verdict::Unavailable(format!("the password check did not start: {e}"));
        }
        match rx.recv_timeout(HELPER_DEADLINE) {
            Ok(Ok(code)) => mac_verdict(code),
            Ok(Err(why)) => Verdict::Unavailable(format!("macOS's password check failed: {why}")),
            Err(_) => Verdict::Unavailable("macOS's password check did not answer".into()),
        }
    }
}

/// Where the platform has no check built (Windows is lane Z's), or the
/// platform's own cannot run: every `yes` that needs one is refused, and
/// says why.
pub struct NoChecker(pub &'static str);

impl Checker for NoChecker {
    fn check(&self, _user: &str, _password: &[u8]) -> Verdict {
        Verdict::Unavailable(self.0.to_string())
    }
    fn unavailable(&self) -> Option<String> {
        Some(self.0.to_string())
    }
}

/// Linux-PAM's code for a failed authentication, the one exit of
/// `unix_chkpwd` that means a wrong password.
#[cfg(unix)]
const PAM_AUTH_ERR: i32 = 7;

/// Why a set-id helper cannot check a password in a process with
/// no_new_privs set.
const NNP_WHY: &str = "the daemon runs with no_new_privs set (systemd's NoNewPrivileges=, \
or a setting that implies it), so the set-group-id bit unix_chkpwd needs to read \
/etc/shadow is ignored; start derm-daemon from a unit without it";

/// Whether `/proc/self/status` says no_new_privs is set for this process
/// (the kernel's `NoNewPrivs:` line; once set it is inherited and never
/// unset: https://docs.kernel.org/userspace-api/no_new_privs.html).
pub fn no_new_privs() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| no_new_privs_in(&s))
        .unwrap_or(false)
}

fn no_new_privs_in(status: &str) -> bool {
    status.lines().any(|l| {
        l.strip_prefix("NoNewPrivs:")
            .is_some_and(|v| v.trim() == "1")
    })
}

/// The platform's checker.
pub fn platform() -> Box<dyn Checker> {
    // `cfg!` and not `#[cfg]` for Linux, so macOS still compiles the helper
    // (as before lane Z's patch); Windows has no helper to compile.
    #[cfg(unix)]
    if cfg!(target_os = "linux") {
        // Under no_new_privs the helper's set-group-id bit is ignored, and
        // every password, the right one too, would fail (BW5-17).
        if no_new_privs() {
            return Box::new(NoChecker(NNP_WHY));
        }
        return match UnixChkpwd::find() {
            Ok(c) => Box::new(c),
            Err(why) => Box::new(NoChecker(Box::leak(why.into_boxed_str()))),
        };
    }
    // macOS (fix pass 12 (Mac)): the system's own PAM service.
    #[cfg(target_os = "macos")]
    let checker: Box<dyn Checker> = match MacPam::find() {
        Ok(c) => Box::new(c),
        Err(why) => Box::new(NoChecker(Box::leak(why.into_boxed_str()))),
    };
    #[cfg(not(target_os = "macos"))]
    let checker: Box<dyn Checker> = Box::new(NoChecker(
        "no person check is built for this system yet: run the chat under a boundary (srt or sbx)",
    ));
    checker
}

/// The daemon's user name, for the helper (it compares it with the name of
/// the user that runs it).
#[cfg(unix)]
pub fn own_user() -> Option<String> {
    let uid = derm_core::platform::effective_user();
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: a zeroed passwd is a valid out-parameter; buf outlives the
    // pointers stored in it and we copy the name out before it drops.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc =
        unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so pw_name points into buf.
    Some(
        unsafe { std::ffi::CStr::from_ptr(pw.pw_name) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Windows (lane Z): the daemon's SID. No checker is built for Windows yet
/// (`platform()` answers `NoChecker`), so a `yes` that needs a check is
/// refused, as on macOS (lane V's V-6; note AU section 3.1).
#[cfg(windows)]
pub fn own_user() -> Option<String> {
    let me = derm_core::platform::effective_user();
    me.is_known().then(|| me.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fake {
        right: &'static [u8],
        calls: AtomicUsize,
    }
    impl Checker for Fake {
        fn check(&self, _user: &str, password: &[u8]) -> Verdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if password == self.right {
                Verdict::Person
            } else {
                Verdict::Wrong("wrong password".into())
            }
        }
    }

    fn info(boundary: &str, agent_user: Option<&str>) -> Value {
        let mut v = json!({"harness": "pi", "boundary": boundary});
        if let Some(u) = agent_user {
            v["agentUser"] = json!(u);
        }
        v
    }

    #[test]
    fn who_needs_a_person_check() {
        let mut runs = HashMap::new();
        runs.insert("srt-chat".to_string(), info("srt", None));
        runs.insert("sbx-chat".to_string(), info("sbx", None));
        runs.insert("agent-chat".to_string(), info("none", Some("derm-agent")));
        assert_eq!(needed(&runs, "srt-chat", false), None);
        assert_eq!(needed(&runs, "sbx-chat", false), None);
        assert_eq!(needed(&runs, "agent-chat", false), None);
        assert!(needed(&runs, "unknown", false)
            .unwrap()
            .contains("not started by derm run"));
        assert!(needed(&runs, "srt-chat", true)
            .unwrap()
            .contains("since the daemon started"));

        runs.insert("you-chat".to_string(), info("none", None));
        assert!(needed(&runs, "you-chat", false)
            .unwrap()
            .contains("runs as you"));
        // While a chat runs as you, it can answer an srt chat's ask too.
        let why = needed(&runs, "srt-chat", false).unwrap();
        assert!(
            why.contains("you-chat") && why.contains("for others"),
            "{why}"
        );
    }

    #[test]
    fn a_boundary_name_the_daemon_does_not_know_counts_as_none() {
        for b in ["", "none", "SRT", "srt ", "other"] {
            assert!(runs_as_person(&info(b, None)), "{b:?}");
        }
        assert!(runs_as_person(
            &json!({"boundary": "none", "agentUser": ""})
        ));
        assert!(!runs_as_person(&info("srt", None)));
    }

    #[test]
    fn the_right_password_passes_and_is_wiped() {
        let fake = Fake {
            right: b"hunter2",
            calls: AtomicUsize::new(0),
        };
        let backoff = Backoff::default();
        let mut pw = b"hunter2".to_vec();
        assert_eq!(
            verify(&fake, &backoff, "tony", Some(&mut pw), Instant::now()),
            Verdict::Person
        );
        assert!(pw.iter().all(|b| *b == 0), "wiped");
    }

    #[test]
    fn a_wrong_password_backs_off_doubling_and_the_wait_holds_the_right_one_too() {
        let fake = Fake {
            right: b"hunter2",
            calls: AtomicUsize::new(0),
        };
        let backoff = Backoff::default();
        let t0 = Instant::now();
        let v = verify(&fake, &backoff, "tony", Some(&mut b"guess".to_vec()), t0);
        assert_eq!(v, Verdict::Wrong("wrong password".into()));
        // Within the back-off even the right password is refused unchecked.
        let v = verify(&fake, &backoff, "tony", Some(&mut b"hunter2".to_vec()), t0);
        assert!(
            matches!(v, Verdict::Wrong(ref w) if w.contains("try again")),
            "{v:?}"
        );
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            1,
            "the helper was not run during the wait"
        );
        let t1 = t0 + Duration::from_secs(1);
        let _ = verify(&fake, &backoff, "tony", Some(&mut b"guess2".to_vec()), t1);
        assert_eq!(backoff.waiting(t1).unwrap(), Duration::from_secs(2));
        for i in 0..10 {
            let at = t1 + Duration::from_secs(100 * (i + 1));
            let _ = verify(&fake, &backoff, "tony", Some(&mut b"x".to_vec()), at);
            assert!(backoff.waiting(at).unwrap() <= MAX_BACKOFF);
        }
        let later = t1 + Duration::from_secs(5000);
        assert_eq!(
            verify(
                &fake,
                &backoff,
                "tony",
                Some(&mut b"hunter2".to_vec()),
                later
            ),
            Verdict::Person
        );
        assert_eq!(backoff.waiting(later), None, "a pass clears the back-off");
    }

    #[test]
    fn no_password_an_empty_one_or_one_with_a_nul_is_refused_without_the_helper() {
        let fake = Fake {
            right: b"",
            calls: AtomicUsize::new(0),
        };
        let backoff = Backoff::default();
        let now = Instant::now();
        assert!(matches!(
            verify(&fake, &backoff, "tony", None, now),
            Verdict::Wrong(_)
        ));
        assert!(matches!(
            verify(&fake, &backoff, "tony", Some(&mut Vec::new()), now),
            Verdict::Wrong(_)
        ));
        assert!(matches!(
            verify(&fake, &backoff, "tony", Some(&mut b"a\0b".to_vec()), now),
            Verdict::Wrong(_)
        ));
        let mut long = vec![b'a'; MAX_PASSWORD + 1];
        assert!(matches!(
            verify(&fake, &backoff, "tony", Some(&mut long), now),
            Verdict::Wrong(_)
        ));
        assert!(long.iter().all(|b| *b == 0));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }

    /// Box test w5, BW5-17: under the shipped unit's no_new_privs, Linux-PAM's
    /// helper exits 9 for the right password and the wrong one alike (run in
    /// the cloud with the real helper, `setpriv --no-new-privs`); only its
    /// exit 7 is a wrong password, and only a wrong password counts against
    /// the backoff.
    #[cfg(unix)]
    #[test]
    fn only_the_helpers_auth_error_is_a_wrong_password() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("derm-chkpwd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (code, want) in [
            (0, "person"),
            (7, "wrong"),
            (9, "unavailable"),
            (1, "unavailable"),
        ] {
            // Written from a child process, then exec'd (case 154).
            let path = dir.join(format!("chk{code}"));
            let ok = Command::new("sh")
                .arg("-c")
                .arg("printf '#!/bin/sh\\ncat >/dev/null\\nexit %s\\n' \"$2\" > \"$1\" && chmod 755 \"$1\"")
                .arg("sh")
                .arg(&path)
                .arg(code.to_string())
                .status()
                .unwrap();
            assert!(ok.success());
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o755
            );
            let c = UnixChkpwd { path };
            let backoff = Backoff::default();
            let v = verify(
                &c,
                &backoff,
                "tony",
                Some(&mut b"pw".to_vec()),
                Instant::now(),
            );
            let got = match &v {
                Verdict::Person => "person",
                Verdict::Wrong(_) => "wrong",
                Verdict::Unavailable(_) => "unavailable",
            };
            assert_eq!(got, want, "exit {code}: {v:?}");
            assert_eq!(
                backoff.waiting(Instant::now()).is_some(),
                code == 7,
                "exit {code}: only a wrong password waits"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_new_privs_is_read_from_the_status_line() {
        assert!(no_new_privs_in("Name:\tx\nNoNewPrivs:\t1\nSeccomp:\t0\n"));
        assert!(!no_new_privs_in("Name:\tx\nNoNewPrivs:\t0\n"));
        assert!(!no_new_privs_in("Name:\tx\n"));
    }

    /// BW5-17: the shipped user unit must leave set-id helpers working, so
    /// it sets neither NoNewPrivileges=yes nor a setting systemd says
    /// implies it (systemd.exec(5), NoNewPrivileges=; read in Fedora 39's
    /// man page, v254).
    #[test]
    fn the_shipped_unit_keeps_the_person_checks_helper_working() {
        let unit = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/deb/derm-daemon.service"),
        )
        .unwrap();
        let implying = [
            "NoNewPrivileges=",
            "DynamicUser=",
            "LockPersonality=",
            "MemoryDenyWriteExecute=",
            "PrivateDevices=",
            "ProtectClock=",
            "ProtectHostname=",
            "ProtectKernelLogs=",
            "ProtectKernelModules=",
            "ProtectKernelTunables=",
            "RestrictAddressFamilies=",
            "RestrictNamespaces=",
            "RestrictRealtime=",
            "RestrictSUIDSGID=",
            "SystemCallArchitectures=",
            "SystemCallFilter=",
            "SystemCallLog=",
        ];
        for line in unit.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
            for k in implying {
                assert!(
                    !line.starts_with(k) || line == "NoNewPrivileges=no",
                    "the unit sets {line}, which turns no_new_privs on"
                );
            }
        }
    }

    /// MW5-4: where no check can run (macOS today), the daemon says so before
    /// a password is asked for, and the reply does not read as a request
    /// for one.
    #[test]
    fn a_platform_with_no_check_says_so_before_any_password() {
        let none = NoChecker("no person check is built for this system yet");
        let v = verify(&none, &Backoff::default(), "tony", None, Instant::now());
        assert_eq!(
            v,
            Verdict::Unavailable("no person check is built for this system yet".into())
        );
    }

    #[test]
    fn a_platform_with_no_check_refuses_rather_than_passes() {
        let none = NoChecker("no check here");
        let backoff = Backoff::default();
        let v = verify(
            &none,
            &backoff,
            "tony",
            Some(&mut b"pw".to_vec()),
            Instant::now(),
        );
        assert_eq!(v, Verdict::Unavailable("no check here".into()));
        assert_eq!(
            backoff.waiting(Instant::now()),
            None,
            "unavailable is not a wrong try"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_that_is_not_roots_and_set_id_is_not_trusted() {
        // A plain file of the test's: not set-id, and (as a non-root test) not
        // root's; trusted as the test's own uid it still lacks the set-id bit.
        let dir =
            std::env::temp_dir().join(format!("derm-chkpwd-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("unix_chkpwd");
        std::fs::write(&fake, b"#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let me = derm_core::platform::effective_user();
        let err = UnixChkpwd::find_in(&[fake.to_str().unwrap()], me)
            .err()
            .unwrap();
        assert!(err.contains("set-id"), "{err}");
        assert!(UnixChkpwd::find_in(&["/nonexistent/unix_chkpwd"], 0)
            .err()
            .unwrap()
            .contains("not installed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The real helper, where the system has one: a wrong password for the
    /// user running the test is refused (the right one is not known here).
    #[cfg(target_os = "linux")]
    #[test]
    fn the_system_helper_refuses_a_wrong_password() {
        let Ok(helper) = UnixChkpwd::find() else {
            eprintln!("no trusted unix_chkpwd here; skipped");
            return;
        };
        let user = own_user().expect("this user's name");
        let v = helper.check(&user, b"derm-lane-v-not-the-password");
        assert!(matches!(v, Verdict::Wrong(_)), "{v:?}");
    }
    /// Fix pass 12 (Mac): `pam_authenticate`'s codes on macOS. Only 9
    /// (`PAM_AUTH_ERR`) is a wrong password, which the back-off counts; a
    /// locked or disabled account, or a code this does not know, is no
    /// verdict on the password.
    #[test]
    fn mac_only_pams_auth_error_is_a_wrong_password() {
        assert_eq!(mac_verdict(0), Verdict::Person);
        assert!(matches!(mac_verdict(9), Verdict::Wrong(_)));
        assert!(
            matches!(mac_verdict(7), Verdict::Unavailable(w) if w.contains("locked by its password policy"))
        );
        for code in [7, 1024, 1025, 3, 4, 6, 12, 13, -1] {
            assert!(
                matches!(mac_verdict(code), Verdict::Unavailable(_)),
                "{code}"
            );
        }
    }

    /// The PAM service's file must be there and root's, or no check runs:
    /// without the file OpenPAM uses `other`, which denies every password.
    #[cfg(target_os = "macos")]
    #[test]
    fn mac_a_service_file_that_is_missing_or_not_roots_is_not_trusted() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("derm-macpam-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("checkpw");
        assert!(MacPam::find_at(&f, 0).unwrap_err().contains("missing"));
        std::fs::write(&f, "auth required pam_permit.so\n").unwrap();
        // This user's file is not root's.
        assert!(MacPam::find_at(&f, 0).is_err());
        let me = derm_core::platform::effective_user();
        assert!(MacPam::find_at(&f, me).is_ok());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(MacPam::find_at(&f, me).is_err());
        let _ = std::fs::remove_dir_all(&d);
        // The system's own is trusted.
        assert!(MacPam::find().is_ok());
    }

    /// The real service: a wrong password for the user running the test is
    /// refused, with no conversation (the right one is not known here). A
    /// wrong password counts as a failed login for the account, so this
    /// runs only in CI or with `DERM_TEST_PAM=1`.
    #[cfg(target_os = "macos")]
    #[test]
    fn mac_the_systems_pam_service_refuses_a_wrong_password() {
        if std::env::var_os("CI").is_none() && std::env::var_os("DERM_TEST_PAM").is_none() {
            eprintln!("a failed login for this account; set DERM_TEST_PAM=1 to run");
            return;
        }
        let user = own_user().expect("this user's name");
        let v = MacPam.check(&user, b"derm-fp12-not-the-password");
        assert!(matches!(v, Verdict::Wrong(_)), "{v:?}");
    }
}
