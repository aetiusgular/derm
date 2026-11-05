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
//! What the check is: the person's login password, verified by the system's
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

use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

/// The password is no longer than this (Linux-PAM's `MAXPASS` is 512,
/// `modules/pam_unix/support.h`); a longer one is refused unread.
pub const MAX_PASSWORD: usize = 512;
/// How long the helper may take.
const HELPER_DEADLINE: Duration = Duration::from_secs(10);
/// The back-off after the n-th wrong password in a row: 1, 2, 4 ... seconds,
/// capped here. It is the daemon's, not a connection's: a new connection
/// waits as long.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// What a check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The password is the person's.
    Person,
    /// It is not, or none was given.
    Wrong(String),
    /// The daemon cannot check here; a `yes` that needs a check is refused.
    Unavailable(String),
}

/// Checks a password for the daemon's own user.
pub trait Checker: Send + Sync {
    fn check(&self, user: &str, password: &[u8]) -> Verdict;
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
pub struct UnixChkpwd {
    path: PathBuf,
}

/// Where Debian, Ubuntu and Fedora put the helper.
const HELPER_PATHS: &[&str] = &["/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd"];

impl UnixChkpwd {
    /// The helper, or why there is none to trust.
    pub fn find() -> Result<Self, String> {
        Self::find_in(HELPER_PATHS, 0)
    }

    fn find_in(paths: &[&str], trusted: u32) -> Result<Self, String> {
        let mut seen = Vec::new();
        for p in paths {
            let path = Path::new(p);
            let Ok(m) = std::fs::metadata(path) else { continue };
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
            format!("{} is not root's and set-id, or sits in a folder others can write", seen.join(", "))
        })
    }
}

fn parents_trusted(real: &Path, trusted: u32) -> bool {
    real.ancestors().skip(1).all(|p| {
        std::fs::symlink_metadata(p)
            .map(|m| m.is_dir() && m.uid() == trusted && m.mode() & 0o022 == 0)
            .unwrap_or(false)
    })
}

impl Checker for UnixChkpwd {
    /// `unix_chkpwd <user> nonull`, the password and a NUL on a pipe (the
    /// helper refuses a terminal on stdin), exit 0 for the person's password.
    /// `nonull`: an empty password is no proof.
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
                Ok(Some(_)) => return Verdict::Wrong("wrong password".into()),
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

/// Where the platform has no check built (macOS, until a PAM or
/// OpenDirectory route is built; Windows is lane Z's): every `yes` that
/// needs one is refused, and says why.
pub struct NoChecker(pub &'static str);

impl Checker for NoChecker {
    fn check(&self, _user: &str, _password: &[u8]) -> Verdict {
        Verdict::Unavailable(self.0.to_string())
    }
}

/// The platform's checker.
pub fn platform() -> Box<dyn Checker> {
    if cfg!(target_os = "linux") {
        match UnixChkpwd::find() {
            Ok(c) => Box::new(c),
            Err(why) => Box::new(NoChecker(Box::leak(why.into_boxed_str()))),
        }
    } else {
        Box::new(NoChecker(
            "no person check is built for this system yet: run the chat under a boundary (srt or sbx)",
        ))
    }
}

/// The daemon's user name, for the helper (it compares it with the name of
/// the user that runs it).
pub fn own_user() -> Option<String> {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: a zeroed passwd is a valid out-parameter; buf outlives the
    // pointers stored in it and we copy the name out before it drops.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
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
        assert!(needed(&runs, "unknown", false).unwrap().contains("not started by derm run"));
        assert!(needed(&runs, "srt-chat", true).unwrap().contains("since the daemon started"));

        runs.insert("you-chat".to_string(), info("none", None));
        assert!(needed(&runs, "you-chat", false).unwrap().contains("runs as you"));
        // While a chat runs as you, it can answer an srt chat's ask too.
        let why = needed(&runs, "srt-chat", false).unwrap();
        assert!(why.contains("you-chat") && why.contains("for others"), "{why}");
    }

    #[test]
    fn a_boundary_name_the_daemon_does_not_know_counts_as_none() {
        for b in ["", "none", "SRT", "srt ", "other"] {
            assert!(runs_as_person(&info(b, None)), "{b:?}");
        }
        assert!(runs_as_person(&json!({"boundary": "none", "agentUser": ""})));
        assert!(!runs_as_person(&info("srt", None)));
    }

    #[test]
    fn the_right_password_passes_and_is_wiped() {
        let fake = Fake { right: b"hunter2", calls: AtomicUsize::new(0) };
        let backoff = Backoff::default();
        let mut pw = b"hunter2".to_vec();
        assert_eq!(verify(&fake, &backoff, "tony", Some(&mut pw), Instant::now()), Verdict::Person);
        assert!(pw.iter().all(|b| *b == 0), "wiped");
    }

    #[test]
    fn a_wrong_password_backs_off_doubling_and_the_wait_holds_the_right_one_too() {
        let fake = Fake { right: b"hunter2", calls: AtomicUsize::new(0) };
        let backoff = Backoff::default();
        let t0 = Instant::now();
        let v = verify(&fake, &backoff, "tony", Some(&mut b"guess".to_vec()), t0);
        assert_eq!(v, Verdict::Wrong("wrong password".into()));
        // Within the back-off even the right password is refused unchecked.
        let v = verify(&fake, &backoff, "tony", Some(&mut b"hunter2".to_vec()), t0);
        assert!(matches!(v, Verdict::Wrong(ref w) if w.contains("try again")), "{v:?}");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1, "the helper was not run during the wait");
        let t1 = t0 + Duration::from_secs(1);
        let _ = verify(&fake, &backoff, "tony", Some(&mut b"guess2".to_vec()), t1);
        assert_eq!(backoff.waiting(t1).unwrap(), Duration::from_secs(2));
        for i in 0..10 {
            let at = t1 + Duration::from_secs(100 * (i + 1));
            let _ = verify(&fake, &backoff, "tony", Some(&mut b"x".to_vec()), at);
            assert!(backoff.waiting(at).unwrap() <= MAX_BACKOFF);
        }
        let later = t1 + Duration::from_secs(5000);
        assert_eq!(verify(&fake, &backoff, "tony", Some(&mut b"hunter2".to_vec()), later), Verdict::Person);
        assert_eq!(backoff.waiting(later), None, "a pass clears the back-off");
    }

    #[test]
    fn no_password_an_empty_one_or_one_with_a_nul_is_refused_without_the_helper() {
        let fake = Fake { right: b"", calls: AtomicUsize::new(0) };
        let backoff = Backoff::default();
        let now = Instant::now();
        assert!(matches!(verify(&fake, &backoff, "tony", None, now), Verdict::Wrong(_)));
        assert!(matches!(verify(&fake, &backoff, "tony", Some(&mut Vec::new()), now), Verdict::Wrong(_)));
        assert!(matches!(verify(&fake, &backoff, "tony", Some(&mut b"a\0b".to_vec()), now), Verdict::Wrong(_)));
        let mut long = vec![b'a'; MAX_PASSWORD + 1];
        assert!(matches!(verify(&fake, &backoff, "tony", Some(&mut long), now), Verdict::Wrong(_)));
        assert!(long.iter().all(|b| *b == 0));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_platform_with_no_check_refuses_rather_than_passes() {
        let none = NoChecker("no check here");
        let backoff = Backoff::default();
        let v = verify(&none, &backoff, "tony", Some(&mut b"pw".to_vec()), Instant::now());
        assert_eq!(v, Verdict::Unavailable("no check here".into()));
        assert_eq!(backoff.waiting(Instant::now()), None, "unavailable is not a wrong try");
    }

    #[test]
    fn a_helper_that_is_not_roots_and_set_id_is_not_trusted() {
        // A plain file of the test's: not set-id, and (as a non-root test) not
        // root's; trusted as the test's own uid it still lacks the set-id bit.
        let dir = std::env::temp_dir().join(format!("derm-chkpwd-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("unix_chkpwd");
        std::fs::write(&fake, b"#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        let err = UnixChkpwd::find_in(&[fake.to_str().unwrap()], me).err().unwrap();
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
}
