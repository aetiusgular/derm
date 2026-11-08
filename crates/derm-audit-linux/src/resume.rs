//! Where `derm-audit-feed run` starts reading the audit log (BW5R4-1, box
//! test w5 retest 4). Until `8caaf00` the feed began at the log's end on
//! every start, so the lines auditd wrote while it was down (stopped, or
//! restarted with the daemon through `PartOf=`) were never read: 31 events
//! of a chat on the box, 0 in derm's log, and nothing said so.
//!
//! The feed now keeps its place, the log's inode and the byte offset after
//! the last line whose events it posted, in `audit-feed.pos` in the daemon's
//! data folder, and starts there. The same idea as audit's own
//! `ausearch --checkpoint` (ausearch(8), audit 4.1.2: "only events not
//! previously output will print in subsequent invocations") and a log
//! shipper's registry of inode and offset. auditd rotates by renaming the
//! log to `<log>.1` ("logs with higher numbers are older than logs with
//! lower numbers", auditd.conf(5), `max_log_file_action` rotate), so a place
//! in a file that was rotated once is read on from `<log>.1`. A place that
//! cannot be found (the log rotated past it, or was cut) is a gap, which the
//! feed posts to the daemon (`feed.gap`) so a chat's report can say its OS
//! records may be missing.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The pos file's name in the daemon's data folder.
pub const POS_FILE: &str = "audit-feed.pos";
/// A pos file is a few dozen bytes; anything larger is not ours.
const POS_MAX_BYTES: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pos {
    /// The log's path as the feed was told it.
    pub log: String,
    pub inode: u64,
    /// The byte after the last line whose events were posted.
    pub offset: u64,
    /// The newest audit time read by then (ms), for a gap's start.
    pub log_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    /// The log's end: no place was kept (the feed's first start).
    End,
    Beginning,
    At(u64),
    /// The place is in the rotated file: read it on from `offset`, then the
    /// log from its beginning.
    Rotated {
        prev: PathBuf,
        offset: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gap {
    /// The newest audit time read before the gap, when known.
    pub from_ms: Option<i64>,
    pub reason: &'static str,
}

/// Where to start, from the kept place and the files as they are now:
/// `cur` and `rotated` are `(inode, length)` of the log and of `<log>.1`.
pub fn decide(
    saved: Option<&Pos>,
    log: &Path,
    cur: (u64, u64),
    rotated: Option<(u64, u64)>,
    from_start: bool,
) -> (Start, Option<Gap>) {
    if from_start {
        return (Start::Beginning, None);
    }
    let Some(p) = saved.filter(|p| Path::new(&p.log) == log) else {
        return (Start::End, None);
    };
    if p.inode == cur.0 {
        if p.offset <= cur.1 {
            return (Start::At(p.offset), None);
        }
        return (
            Start::Beginning,
            Some(Gap {
                from_ms: Some(p.log_ms),
                reason: "the audit log was cut shorter than the feed's place",
            }),
        );
    }
    if let Some((ino, len)) = rotated {
        if ino == p.inode && p.offset <= len {
            return (
                Start::Rotated {
                    prev: rotated_path(log),
                    offset: p.offset,
                },
                None,
            );
        }
    }
    (
        Start::Beginning,
        Some(Gap {
            from_ms: Some(p.log_ms),
            reason: "the audit log rotated past the feed's place while it was down",
        }),
    )
}

/// `<log>.1`, the newest rotated log.
pub fn rotated_path(log: &Path) -> PathBuf {
    let mut s = log.as_os_str().to_os_string();
    s.push(".1");
    PathBuf::from(s)
}

/// Reads a kept place: a regular file of this user's, private, small, never
/// through a link. Anything else is no place.
pub fn load(path: &Path) -> Option<Pos> {
    let mut o = OpenOptions::new();
    o.read(true);
    derm_core::platform::private_no_follow(&mut o);
    let f = o.open(path).ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file()
        || meta.len() > POS_MAX_BYTES
        || derm_core::platform::owner(&meta) != derm_core::platform::effective_user()
        || !derm_core::platform::is_private(&meta)
    {
        return None;
    }
    let mut text = String::new();
    f.take(POS_MAX_BYTES).read_to_string(&mut text).ok()?;
    serde_json::from_str(&text).ok()
}

/// Keeps a place: written beside, then renamed over the old one, 0600.
pub fn save(path: &Path, pos: &Pos) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        derm_core::platform::private_dir(dir)?;
    }
    let tmp = path.with_extension("pos.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    derm_core::platform::private_no_follow(&mut o);
    let mut f: File = o.open(&tmp)?;
    f.write_all(serde_json::to_string(pos)?.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(inode: u64, offset: u64) -> Pos {
        Pos {
            log: "/var/log/audit/audit.log".into(),
            inode,
            offset,
            log_ms: 1_000,
        }
    }

    const LOG: &str = "/var/log/audit/audit.log";

    #[test]
    fn bw5r4_1_a_restart_reads_on_from_the_kept_place() {
        let (s, g) = decide(Some(&pos(7, 500)), Path::new(LOG), (7, 900), None, false);
        assert_eq!(s, Start::At(500));
        assert!(g.is_none());
    }

    #[test]
    fn bw5r4_1_a_place_in_the_rotated_log_is_read_on_there_first() {
        let (s, g) = decide(
            Some(&pos(7, 500)),
            Path::new(LOG),
            (8, 40),
            Some((7, 600)),
            false,
        );
        assert_eq!(
            s,
            Start::Rotated {
                prev: PathBuf::from("/var/log/audit/audit.log.1"),
                offset: 500
            }
        );
        assert!(g.is_none());
    }

    #[test]
    fn bw5r4_1_a_place_that_cannot_be_found_is_a_gap() {
        // Rotated twice: neither file is the kept one.
        let (s, g) = decide(
            Some(&pos(7, 500)),
            Path::new(LOG),
            (9, 40),
            Some((8, 600)),
            false,
        );
        assert_eq!(s, Start::Beginning);
        assert_eq!(g.unwrap().from_ms, Some(1_000));
        // Cut shorter than the place.
        let (s, g) = decide(Some(&pos(7, 500)), Path::new(LOG), (7, 100), None, false);
        assert_eq!(s, Start::Beginning);
        assert!(g.is_some());
    }

    #[test]
    fn with_no_place_or_another_log_it_starts_at_the_end_and_from_start_wins() {
        assert_eq!(
            decide(None, Path::new(LOG), (7, 900), None, false),
            (Start::End, None)
        );
        assert_eq!(
            decide(
                Some(&pos(7, 500)),
                Path::new("/tmp/other.log"),
                (7, 900),
                None,
                false
            ),
            (Start::End, None)
        );
        assert_eq!(
            decide(Some(&pos(7, 500)), Path::new(LOG), (7, 900), None, true),
            (Start::Beginning, None)
        );
    }

    #[test]
    fn a_place_is_kept_private_and_read_back() {
        let dir = std::env::temp_dir().join(format!("derm-pos-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join(POS_FILE);
        save(&path, &pos(7, 500)).unwrap();
        assert_eq!(load(&path), Some(pos(7, 500)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            // A place someone else can write is no place.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o622)).unwrap();
            assert_eq!(load(&path), None);
            // Nor one through a link.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = dir.join("link.pos");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert_eq!(load(&link), None);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
