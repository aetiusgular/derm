//! Content capture and its retention (wave 5, lane S; rules cases 114, 126,
//! and 85 as changed on 4 Nov): with the switch on, a chat's prompts,
//! arguments, results and the model's text are kept locally, 0600, for the 1
//! to 7 days the user chose, then deleted; the hashed records stay
//! (`contracts/events.md` section 5, `contracts/settings.schema.json`).
//!
//! The tap writes the files (`derm_tap::content`, which holds the layout);
//! this module deletes them. Each file carries the retention in force when
//! it was written, so turning content off, or shortening it, deletes nothing
//! early (case 126).
//!
//! A file's age is the larger of two clocks:
//! - the wall clock since the time in its name, which counts the hours the
//!   daemon was not running;
//! - the time this daemon has seen pass while it ran, kept per file in
//!   `content/.ages.json` across restarts, which a wall clock set back
//!   cannot shrink.
//!
//! So a clock moved forward deletes early (never late), and a clock moved
//! back still deletes on time while the daemon runs. What it cannot see: a
//! clock moved back while the daemon was stopped (named in the status doc).

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use derm_core::event::{Event, Source};
use derm_tap::content::{chat_dir_ok, parse_name, DIR};
use serde_json::{json, Value};

const DAY_MS: i64 = 86_400_000;
const AGES: &str = ".ages.json";
const MAX_AGES_FILE: u64 = 8 * 1024 * 1024;

/// The purge's state between passes.
pub struct Purger {
    root: PathBuf,
    last: Option<Instant>,
    /// `<chat>/<file name>` to milliseconds seen passing.
    ages: HashMap<String, i64>,
}

/// What one pass removed, per chat and retention.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Removed {
    pub files: u64,
    pub bytes: u64,
}

impl Purger {
    /// `data` is the daemon's data folder; content sits in `<data>/content/`.
    pub fn new(data: &Path) -> Self {
        let root = data.join(DIR);
        let ages = read_ages(&root.join(AGES)).unwrap_or_default();
        Purger {
            root,
            last: None,
            ages,
        }
    }

    /// One pass at wall time `now_ms`; returns the `content.purge` records.
    pub fn pass(&mut self, now_ms: i64) -> Vec<Event> {
        let seen = self.last.map_or(0, |t| t.elapsed().as_millis() as i64);
        self.last = Some(Instant::now());
        self.pass_with(now_ms, seen)
    }

    /// As `pass`, with the time seen passing since the last pass given (the
    /// tests' clock).
    pub fn pass_with(&mut self, now_ms: i64, seen_ms: i64) -> Vec<Event> {
        let mut removed: BTreeMap<(String, u8), Removed> = BTreeMap::new();
        let mut kept: HashMap<String, i64> = HashMap::new();
        if !private_dir(&self.root) {
            return Vec::new();
        }
        let Ok(chats) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        for chat in chats.flatten() {
            let name = chat.file_name().to_string_lossy().into_owned();
            if !chat_dir_ok(&name) || !private_dir(&chat.path()) {
                continue;
            }
            let Ok(files) = std::fs::read_dir(chat.path()) else {
                continue;
            };
            let mut left = 0;
            for f in files.flatten() {
                let fname = f.file_name().to_string_lossy().into_owned();
                let Some((at, days)) = parse_name(&fname) else {
                    left += 1;
                    continue;
                };
                let Ok(meta) = std::fs::symlink_metadata(f.path()) else {
                    continue;
                };
                if !meta.file_type().is_file() {
                    left += 1;
                    continue;
                }
                let key = format!("{name}/{fname}");
                let lived = self.ages.get(&key).copied().unwrap_or(0) + seen_ms.max(0);
                let age = (now_ms - at).max(lived);
                if age >= i64::from(days) * DAY_MS {
                    if std::fs::remove_file(f.path()).is_ok() {
                        let r = removed.entry((name.clone(), days)).or_default();
                        r.files += 1;
                        r.bytes += meta.len();
                    } else {
                        left += 1;
                        kept.insert(key, lived);
                    }
                } else {
                    left += 1;
                    kept.insert(key, lived);
                }
            }
            if left == 0 {
                let _ = std::fs::remove_dir(chat.path());
            }
        }
        self.ages = kept;
        let _ = write_ages(&self.root.join(AGES), &self.ages);
        removed
            .into_iter()
            .map(|((chat, days), r)| Event {
                id: format!("content-purge-{chat}-{now_ms}-{days}"),
                at: now_ms,
                chat_id: chat,
                harness: String::new(),
                source: Source::Derm,
                kind: "content.purge".into(),
                summary: format!(
                    "content past {days} day{} removed",
                    if days == 1 { "" } else { "s" }
                ),
                detail: json!({
                    "trust": "daemon",
                    "files": r.files,
                    "bytes": r.bytes,
                    "retentionDays": days,
                    "reason": "retention",
                }),
                pid: None,
                approval_id: None,
            })
            .collect()
    }
}

/// What is kept now, for `derm status` and for the notice when content is
/// turned off (case 126: "deletes nothing already kept until its retention
/// ends, and says so"): files, bytes, and the latest wall time a file's
/// retention ends.
pub fn kept(data: &Path) -> (u64, u64, Option<i64>) {
    let root = data.join(DIR);
    let (mut files, mut bytes, mut until) = (0u64, 0u64, None::<i64>);
    let Ok(chats) = std::fs::read_dir(&root) else {
        return (0, 0, None);
    };
    for chat in chats.flatten() {
        let Ok(list) = std::fs::read_dir(chat.path()) else {
            continue;
        };
        for f in list.flatten() {
            if let Some((at, days)) = parse_name(&f.file_name().to_string_lossy()) {
                files += 1;
                bytes += f.metadata().map(|m| m.len()).unwrap_or(0);
                let end = at + i64::from(days) * DAY_MS;
                until = Some(until.map_or(end, |u: i64| u.max(end)));
            }
        }
    }
    (files, bytes, until)
}

fn private_dir(dir: &Path) -> bool {
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    std::fs::symlink_metadata(dir)
        .is_ok_and(|m| m.file_type().is_dir() && m.uid() == uid && m.mode() & 0o077 == 0)
}

fn read_ages(path: &Path) -> Option<HashMap<String, i64>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    if !meta.file_type().is_file()
        || meta.uid() != uid
        || meta.mode() & 0o077 != 0
        || meta.len() > MAX_AGES_FILE
    {
        return None;
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    Some(
        v.as_object()?
            .iter()
            .filter_map(|(k, v)| v.as_i64().filter(|n| *n >= 0).map(|n| (k.clone(), n)))
            .collect(),
    )
}

fn write_ages(path: &Path, ages: &HashMap<String, i64>) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let map: BTreeMap<&String, &i64> = ages.iter().collect();
    f.write_all(
        serde_json::to_string(&map)
            .unwrap_or_else(|_| "{}".into())
            .as_bytes(),
    )?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests;
