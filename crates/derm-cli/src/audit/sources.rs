//! Where the logs `derm audit` reads live, and reading their lines.
//!
//! - The daemon's activity log: `<data>/activity/app-YYYY-MM-DD.jsonl`, one
//!   chain v1 across the days (`derm-daemon/src/activity/store.rs`), `<data>`
//!   the daemon's data folder (`derm_daemon::daemon::default_data_dir`) or
//!   `--data-dir`. Retention removes the oldest days, so the oldest file kept
//!   begins inside the chain.
//! - The light tier's per-chat log: `~/.derm/local/<chat>.jsonl`, chain v2
//!   (`contracts/events.md` section 6.4; lane 6B writes it).
//! - A file the person names (an export, a copy).

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read as _};
use std::path::{Path, PathBuf};

use derm_daemon::activity::retention;

/// A file over this is refused rather than read whole into memory.
pub const MAX_FILE_BYTES: u64 = 1 << 30;

/// Which log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// The daemon's activity log under this data folder.
    Daemon(PathBuf),
    /// The light tier's log of one chat (its file).
    Light { chat: String, file: PathBuf },
    /// Files the person named, read in order as one chain.
    Files(Vec<PathBuf>),
}

impl Source {
    /// The label an anchor records, so `verify --anchors` checks a chain
    /// against its own anchors only.
    pub fn label(&self) -> String {
        match self {
            Source::Daemon(_) => "daemon".into(),
            Source::Light { chat, .. } => format!("light:{chat}"),
            Source::Files(f) => match f.as_slice() {
                // By its real path, so `derm audit verify` named another way
                // finds the same anchors.
                [one] => format!(
                    "file:{}",
                    fs::canonicalize(one)
                        .unwrap_or_else(|_| one.clone())
                        .display()
                ),
                _ => "files".into(),
            },
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Source::Daemon(d) => format!("the daemon's log in {}", d.join("activity").display()),
            Source::Light { chat, file } => {
                format!("chat {chat}'s light-tier log {}", file.display())
            }
            Source::Files(f) => f
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}

/// The daemon's data folder: `--data-dir`, else the daemon's own default.
pub fn data_dir(given: Option<&str>) -> Result<PathBuf, String> {
    match given {
        Some(d) => {
            let p = PathBuf::from(d);
            if !p.is_absolute() {
                return Err(format!("--data-dir {d:?}: give an absolute path"));
            }
            Ok(p)
        }
        None => derm_daemon::daemon::default_data_dir()
            .ok_or_else(|| "no home folder: give --data-dir".to_string()),
    }
}

/// The light tier's folder, `~/.derm/local`.
pub fn light_dir() -> Option<PathBuf> {
    derm_core::runtime::home_dir().map(|h| h.join(".derm").join("local"))
}

/// A chat id as a file name, as `contracts/events.md` section 6.4 says lane
/// 6B names it: ASCII letters, digits, `_ . : -`, others `_`, at most 128,
/// and `_` in front of a cleaned id that is empty or starts with `.`. On
/// Windows also as lane 6B's `gate/locallog/name.rs` (on `wip/6B-light`,
/// read 12 Nov): `:` becomes `_` and a device name (CON, PRN, AUX, NUL,
/// COM0-9, LPT0-9) gets `_` in front. The rule is the writer's
/// (`gate::locallog::file_name`, lane 6B), called here so the two cannot
/// drift (lane 6E's request 2, wave 6 phase 1 merge).
pub fn light_name(chat: &str) -> String {
    let file = crate::gate::locallog::file_name(chat);
    file.strip_suffix(".jsonl").unwrap_or(&file).to_string()
}

/// The light-tier file of `chat`.
pub fn light_file(chat: &str) -> Option<PathBuf> {
    light_dir().map(|d| d.join(format!("{}.jsonl", light_name(chat))))
}

/// Every light-tier log there is, by chat file stem, sorted.
pub fn light_files() -> Vec<(String, PathBuf)> {
    let Some(dir) = light_dir() else {
        return Vec::new();
    };
    let mut out: Vec<(String, PathBuf)> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let stem = name.strip_suffix(".jsonl")?;
            if stem.ends_with(".taint") {
                return None;
            }
            Some((stem.to_string(), e.path()))
        })
        .collect();
    out.sort();
    out
}

/// The daemon's day files, oldest first.
pub fn day_files(data: &Path) -> Vec<PathBuf> {
    let mut days: Vec<(i64, PathBuf)> = retention::scan(&data.join("activity"))
        .into_iter()
        .filter(|i| i.kind == retention::ItemKind::Log)
        .map(|i| (i.day, i.path))
        .collect();
    days.sort();
    days.into_iter().map(|(_, p)| p).collect()
}

/// The files a source reads, in order.
pub fn files_of(src: &Source) -> Vec<PathBuf> {
    match src {
        Source::Daemon(d) => day_files(d),
        Source::Light { file, .. } => vec![file.clone()],
        Source::Files(f) => f.clone(),
    }
}

/// One line and where it came from.
#[derive(Clone, Debug)]
pub struct Line {
    pub file: usize,
    pub number: usize,
    pub text: String,
}

/// Reads the lines of `files` in order; empty lines are skipped, as the
/// daemon's reader skips them. A file that is not a plain file (a link, a
/// FIFO, a device) is refused, so `derm audit` never blocks on one or reads
/// through a link someone left (rules section 5, item 3).
pub fn lines_of(files: &[PathBuf]) -> Result<Vec<Line>, String> {
    let mut out = Vec::new();
    for (fi, path) in files.iter().enumerate() {
        let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.file_type().is_file() {
            return Err(format!("{}: not a plain file", path.display()));
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err(format!("{}: over 1 GiB, not read", path.display()));
        }
        let file = open_plain(path)?;
        // Review FP1-R8: under the lock only the bytes are copied, so a
        // hook waits for a read, never for the parse.
        shared_lock(&file, path)?;
        let mut bytes = Vec::new();
        let read = (&file).take(MAX_FILE_BYTES).read_to_end(&mut bytes);
        let _ = file.unlock();
        read.map_err(|e| format!("{}: {e}", path.display()))?;
        let mut reader = BufReader::new(bytes.as_slice());
        let mut buf = Vec::new();
        let mut number = 0;
        loop {
            buf.clear();
            let n = reader
                .read_until(b'\n', &mut buf)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            if n == 0 {
                break;
            }
            number += 1;
            let text = String::from_utf8_lossy(&buf);
            let text = text.trim_end_matches(['\n', '\r']);
            if text.trim().is_empty() {
                continue;
            }
            out.push(Line {
                file: fi,
                number,
                text: text.to_string(),
            });
        }
    }
    Ok(out)
}

/// How long a reader waits for a writer's lock: as a hook waits for
/// another's (`gate/locallog/file.rs`, 1 s; a hook holds it for
/// milliseconds, note AZ B4).
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(1000);

/// A shared lock on the file for the read (Windows test w6, WW6-3): a light
/// log's hooks append under an exclusive lock, which on Windows is
/// mandatory, so a read without one met error 33 mid-append; with one the
/// reader waits and reads whole lines on every system. The daemon's log
/// takes no file lock, so its reads never wait.
fn shared_lock(file: &File, path: &Path) -> Result<(), String> {
    let start = std::time::Instant::now();
    loop {
        match file.try_lock_shared() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(format!(
                    "{}: a writer held its lock for over {} ms; not read",
                    path.display(),
                    LOCK_WAIT.as_millis()
                ))
            }
            Err(fs::TryLockError::Error(e)) => {
                return Err(format!("{}: the lock failed ({e})", path.display()))
            }
        }
    }
}

fn open_plain(path: &Path) -> Result<File, String> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = o
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // Checked again on the handle: the path may have changed since.
    let m = f
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() {
        return Err(format!("{}: not a plain file", path.display()));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chat_id_never_names_a_hidden_file_or_a_parent() {
        assert_eq!(light_name("s-1"), "s-1");
        assert_eq!(light_name(".."), "_..");
        assert_eq!(light_name(""), "_");
        assert_eq!(light_name("a/b"), "a_b");
        assert_eq!(light_name("../x"), "_.._x");
        assert_eq!(light_name(&"x".repeat(300)).len(), 128);
        assert_eq!(light_name("a:b"), if cfg!(windows) { "a_b" } else { "a:b" });
        assert_eq!(
            light_name("nul.x"),
            if cfg!(windows) { "_nul.x" } else { "nul.x" }
        );
    }

    /// Windows test w6, WW6-3: a hook holds the light log's lock while it
    /// appends, and on Windows that lock is mandatory: a plain read meets
    /// error 33 (`gate/locallog/tests.rs`,
    /// `a_plain_reader_meets_error_33_while_a_hook_holds_the_lock`), and 1
    /// of 277 `verify --light` runs said BROKEN. The reader takes a shared
    /// lock, waiting as a hook does (1 s), so it reads whole lines on every
    /// system.
    #[test]
    fn ww6_3_a_reader_waits_for_a_hooks_lock_then_reads() {
        let d = std::env::temp_dir().join(format!("da-src-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let f = d.join("a.jsonl");
        fs::write(&f, "one\n").unwrap();
        let holder = fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&f)
            .unwrap();
        holder.lock().unwrap();
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            use std::io::Write as _;
            (&holder).write_all(b"two\n").unwrap();
            holder.unlock().unwrap();
        });
        let start = std::time::Instant::now();
        let l = lines_of(std::slice::from_ref(&f)).unwrap();
        t.join().unwrap();
        assert!(start.elapsed() >= std::time::Duration::from_millis(150));
        let texts: Vec<&str> = l.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, vec!["one", "two"]);
        // Held past the deadline: said so, and nothing is read as broken.
        let holder = fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&f)
            .unwrap();
        holder.lock().unwrap();
        let e = lines_of(std::slice::from_ref(&f)).unwrap_err();
        assert!(e.contains("held its lock"), "{e}");
        holder.unlock().unwrap();
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn lines_skip_blanks_and_refuse_links_and_fifos() {
        let d = std::env::temp_dir().join(format!("da-src-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let f = d.join("a.jsonl");
        fs::write(&f, "one\n\n two \r\nthree").unwrap();
        let l = lines_of(std::slice::from_ref(&f)).unwrap();
        let t: Vec<&str> = l.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(t, vec!["one", " two ", "three"]);
        assert_eq!(l[1].number, 3);
        #[cfg(unix)]
        {
            let link = d.join("link.jsonl");
            std::os::unix::fs::symlink(&f, &link).unwrap();
            assert!(lines_of(&[link]).unwrap_err().contains("not a plain file"));
            let fifo = d.join("fifo");
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: mkfifo on a path we own.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            assert!(lines_of(&[fifo]).unwrap_err().contains("not a plain file"));
        }
        let _ = fs::remove_dir_all(&d);
    }
}
