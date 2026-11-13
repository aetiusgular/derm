//! A chat's taint state, and where it is kept.
//!
//! - **The light tier** (a hook with no chat token: no `derm run`): the file
//!   `~/.derm/local/<chat>.taint.json` beside lane 6B's log
//!   (`contracts/events.md` section 6.4), its name from
//!   `gate::locallog::file_name`. Opened read and write, never through a
//!   link, a plain file of this user's with one name, 0600, in folders of
//!   this user's no one else can write (the same checks lane 6B's log takes,
//!   `gate/locallog/file.rs`); locked with `File::try_lock` until
//!   [`DEADLINE`], since a Claude Code subagent's calls run beside the main
//!   agent's under one `session_id` (note AZ B3); read and rewritten in one
//!   write under the lock.
//! - **Under `derm run`** (a chat token): the daemon's op `taint`
//!   ([`daemon_get`], [`daemon_add`]; `crates/derm-daemon/src/taint/`, routed
//!   since integration w6's phase 2 merge). When the daemon refuses it (an
//!   older daemon's "unknown op", a chat id the token does not hold, the
//!   sbx VM's HTTP route, which carries no `taint`) the gate falls back to
//!   the file.
//!
//! What it holds: hashes, paths and ids, never a result (`contracts/events.md`
//! section 6). Every list only grows ([`State::merge`]): a writer that lost
//! a race, or an agent that rewrites the file, can add taint and never
//! remove it through derm. A file that does not parse is a tainted chat whose
//! every run is of its own code ([`State::unreadable`]). An agent that
//! deletes the file clears its taint; a write under `~/.derm` is a control
//! path the policy asks about (step 7a), and the light tier's log keeps the
//! marks that were posted.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::super::daemon::{self, Env, Opts};
use derm_tap::results::verdict::{From, Verdict};

/// How long a hook waits for the state's lock: lane 6B's log deadline.
pub const DEADLINE: Duration = super::super::locallog::DEADLINE;
pub use derm_tap::results::state::{Mark, State};
const MAX_FILE: u64 = 1 << 20;

/// The hook's home folder (lane 6B's rule: `HOME`, `USERPROFILE` on
/// Windows, absolute only).
pub fn home(env: &Env) -> Option<PathBuf> {
    #[cfg(windows)]
    let k = "USERPROFILE";
    #[cfg(not(windows))]
    let k = "HOME";
    env.get(k).map(PathBuf::from).filter(|p| p.is_absolute())
}

/// `~/.derm/local/<chat>.taint.json`.
pub fn file_path(home: &Path, chat: &str) -> PathBuf {
    let log = super::super::locallog::file_name(chat);
    let stem = log.strip_suffix(".jsonl").unwrap_or(&log);
    super::super::locallog::folder(home).join(format!("{stem}.taint.json"))
}

/// The chat's state from its file; an absent file is an empty state.
pub fn load(path: &Path) -> Result<State, String> {
    let start = Instant::now();
    own_folders(path.parent().ok_or("no folder")?)?;
    let mut f = open_locked(path, start)?;
    let s = read_state(&mut f, path);
    let _ = f.unlock();
    Ok(s)
}

/// Adds `add` to the chat's file, under its lock.
pub fn save(path: &Path, add: &State) -> Result<(), String> {
    let start = Instant::now();
    own_folders(path.parent().ok_or("no folder")?)?;
    let mut f = open_locked(path, start)?;
    let done = (|| {
        let mut s = read_state(&mut f, path);
        let before = s.clone();
        s.merge(add);
        if s == before && f.metadata().map(|m| m.len() > 0).unwrap_or(false) {
            return Ok(());
        }
        let mut text = serde_json::to_vec(&s).map_err(|e| e.to_string())?;
        text.push(b'\n');
        // Written over the old state from the start, then cut to length:
        // never truncated first, so a crash leaves either the whole new
        // state, or bytes that do not parse, which read as tainted
        // (`State::unreadable`), never an empty, clean file. One write for
        // the whole state, so a reader under the lock never sees half.
        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let n = f
            .write(&text)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if n != text.len() {
            return Err(format!("{}: a short write", path.display()));
        }
        f.set_len(text.len() as u64)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(())
    })();
    let _ = f.unlock();
    done
}

fn read_state(f: &mut File, path: &Path) -> State {
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len == 0 {
        return State {
            v: 1,
            ..State::default()
        };
    }
    if len > MAX_FILE {
        return State::unreadable();
    }
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(0)).is_err() || f.read_to_end(&mut buf).is_err() {
        let _ = path;
        return State::unreadable();
    }
    serde_json::from_slice::<State>(&buf).unwrap_or_else(|_| State::unreadable())
}

fn open_locked(path: &Path, start: Instant) -> Result<File, String> {
    let mut step = Duration::from_millis(1);
    let wait = |step: &mut Duration, why: String| -> Result<(), String> {
        let spent = start.elapsed();
        if spent >= DEADLINE {
            return Err(why);
        }
        std::thread::sleep((*step).min(DEADLINE - spent));
        *step = (*step * 2).min(Duration::from_millis(25));
        Ok(())
    };
    let file = loop {
        match open(path) {
            Ok(f) => break f,
            Err((busy, why)) if busy => wait(&mut step, why)?,
            Err((_, why)) => return Err(why),
        }
    };
    check_file(&file, path)?;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => wait(
                &mut step,
                format!(
                    "{}: another hook held its lock for over {} ms",
                    path.display(),
                    DEADLINE.as_millis()
                ),
            )?,
            Err(TryLockError::Error(e)) => {
                return Err(format!("{}: the lock failed ({e})", path.display()))
            }
        }
    }
}

#[cfg(unix)]
fn open(path: &Path) -> Result<File, (bool, String)> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            (
                false,
                format!("{}: {e} (a link is refused)", path.display()),
            )
        })
}

#[cfg(windows)]
fn open(path: &Path) -> Result<File, (bool, String)> {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| {
            (
                e.raw_os_error() == Some(ERROR_SHARING_VIOLATION),
                format!("{}: {e}", path.display()),
            )
        })
}

#[cfg(not(any(unix, windows)))]
fn open(path: &Path) -> Result<File, (bool, String)> {
    Err((false, format!("{}: Unix and Windows only", path.display())))
}

#[cfg(unix)]
fn check_file(file: &File, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() {
        return Err(format!("{} is not a plain file", path.display()));
    }
    if m.uid() != derm_core::platform::effective_user() {
        return Err(format!("{} belongs to another user", path.display()));
    }
    if m.nlink() != 1 {
        return Err(format!(
            "{} has {} names (a hard link); derm writes only a file with one",
            path.display(),
            m.nlink()
        ));
    }
    if m.mode() & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(windows)]
fn check_file(file: &File, path: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let m = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("{} is not a plain file", path.display()));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn check_file(_file: &File, _path: &Path) -> Result<(), String> {
    Ok(())
}

/// `~/.derm` and `~/.derm/local`, as lane 6B's log requires them: this
/// user's, no one else can write, `local` made 0700; the home folder is
/// never made.
fn own_folders(local: &Path) -> Result<(), String> {
    let derm = local.parent().ok_or("no folder above the state's")?;
    let home = derm.parent().ok_or("no home folder")?;
    if !std::fs::metadata(home).map(|m| m.is_dir()).unwrap_or(false) {
        return Err(format!("{} is not a folder", home.display()));
    }
    own_folder(derm, false)?;
    own_folder(local, true)
}

#[cfg(unix)]
fn own_folder(dir: &Path, tighten: bool) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let made = match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !m.file_type().is_dir() {
        return Err(format!(
            "{} is not a folder (a link is refused)",
            dir.display()
        ));
    }
    if m.uid() != derm_core::platform::effective_user() {
        return Err(format!("{} belongs to another user", dir.display()));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!("{} can be written by others", dir.display()));
    }
    if (made || tighten) && m.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

#[cfg(windows)]
fn own_folder(dir: &Path, _tighten: bool) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "{} is not a folder (a link or a junction is refused)",
            dir.display()
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn own_folder(dir: &Path, _tighten: bool) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// What the daemon said about a chat (`op: "taint"`).
#[derive(Clone, Debug, PartialEq)]
pub struct FromDaemon {
    pub verdict: Verdict,
    pub from: From,
    pub state: State,
    /// Which of the hosts asked about an untrusted result in the chat named
    /// (the tap's view, `derm_tap::results::named`).
    pub named: Vec<String>,
}

fn opts<'a>(env: &'a Env, cwd: &'a Path) -> Opts<'a> {
    Opts {
        env,
        client: "derm hook (taint)".into(),
        reply_timeout: Duration::from_millis(1500),
        cwd,
    }
}

/// The chat's state, verdict and named hosts from the daemon, or why not.
pub fn daemon_get(
    env: &Env,
    cwd: &Path,
    chat: &str,
    hosts: &[String],
) -> Result<FromDaemon, String> {
    let req = json!({"op": "taint", "chat": chat, "hosts": hosts});
    let reply = daemon::exchange(&[req], &opts(env, cwd))?
        .into_iter()
        .next()
        .ok_or("no reply")?;
    parse_reply(&reply)
}

/// Adds to the chat's state in the daemon.
pub fn daemon_add(env: &Env, cwd: &Path, chat: &str, add: &State) -> Result<(), String> {
    let req = json!({"op": "taint", "chat": chat, "hosts": [], "add": add});
    let reply = daemon::exchange(&[req], &opts(env, cwd))?
        .into_iter()
        .next()
        .ok_or("no reply")?;
    parse_reply(&reply).map(|_| ())
}

pub fn parse_reply(reply: &Value) -> Result<FromDaemon, String> {
    if reply.get("ok") != Some(&Value::Bool(true)) {
        return Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("refused")
            .to_string());
    }
    let verdict = reply
        .get("verdict")
        .and_then(Value::as_str)
        .and_then(Verdict::parse)
        .ok_or("the reply names no verdict")?;
    let from = match reply.get("from").and_then(Value::as_str) {
        Some("flag") => From::Flag,
        Some("setting") => From::Setting,
        _ => From::Default,
    };
    let state: State = reply
        .get("state")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("the reply's state: {e}"))?
        .unwrap_or_default();
    let named = reply
        .get("named")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|h| h.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(FromDaemon {
        verdict,
        from,
        state,
        named,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use derm_tap::results::state::{MAX_HOSTS, MAX_WRITTEN};

    #[cfg(unix)]
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dtaint-s-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        d
    }

    #[test]
    fn a_state_only_grows() {
        let mut a = State::default();
        a.merge(&State {
            marks: vec![Mark {
                id: "m1".into(),
                ..Mark::default()
            }],
            written: vec!["/w/a".into()],
            ..State::default()
        });
        a.merge(&State::default());
        a.merge(&State {
            marks: vec![Mark {
                id: "m1".into(),
                ..Mark::default()
            }],
            written: vec!["/w/b".into()],
            ..State::default()
        });
        assert_eq!(a.marks.len(), 1);
        assert_eq!(a.written, vec!["/w/a", "/w/b"]);
        assert!(a.tainted());
    }

    #[test]
    fn past_its_bound_a_state_says_so() {
        let mut a = State::default();
        let many = State {
            written: (0..MAX_WRITTEN + 3).map(|i| format!("/w/{i}")).collect(),
            hosts: (0..MAX_HOSTS + 1).map(|i| format!("{i:064}")).collect(),
            ..State::default()
        };
        a.merge(&many);
        assert!(a.written_full && a.hosts_full);
        assert_eq!(a.written.len(), MAX_WRITTEN);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_round_trips_and_a_file_that_does_not_parse_is_tainted() {
        let home = tmp("file");
        let p = file_path(&home, "s-1");
        assert!(p.ends_with(".derm/local/s-1.taint.json"));
        assert_eq!(
            load(&p).unwrap(),
            State {
                v: 1,
                ..State::default()
            }
        );
        let add = State {
            written: vec!["/w/run.sh".into()],
            ..State::default()
        };
        save(&p, &add).unwrap();
        let got = load(&p).unwrap();
        assert_eq!(got.written, vec!["/w/run.sh"]);
        assert!(!got.tainted());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::write(&p, "{not json").unwrap();
        let bad = load(&p).unwrap();
        assert!(bad.tainted() && bad.unreadable);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_or_a_second_name_is_refused() {
        let home = tmp("link");
        let p = file_path(&home, "s-2");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(home.join("elsewhere"), &p).unwrap();
        assert!(load(&p).unwrap_err().contains("link"));
        std::fs::remove_file(&p).unwrap();
        std::fs::write(home.join("other"), "").unwrap();
        std::fs::hard_link(home.join("other"), &p).unwrap();
        assert!(load(&p).unwrap_err().contains("names"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_daemon_reply_is_read_and_a_refusal_is_an_error() {
        let r = serde_json::json!({
            "ok": true, "verdict": "deny", "from": "flag",
            "state": {"v": 1, "marks": [{"id": "m", "reason": "untrusted-content", "kind": "web", "tool": "webfetch"}]},
            "named": ["evil.test"]
        });
        let got = parse_reply(&r).unwrap();
        assert_eq!(got.verdict, Verdict::Deny);
        assert_eq!(got.from, From::Flag);
        assert!(got.state.tainted());
        assert_eq!(got.named, vec!["evil.test"]);
        let no = serde_json::json!({"ok": false, "error": "unknown op taint"});
        assert_eq!(parse_reply(&no).unwrap_err(), "unknown op taint");
        assert!(parse_reply(&serde_json::json!({"ok": true})).is_err());
    }
}
