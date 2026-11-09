//! Where `derm-audit-feed run` starts reading the audit log (BW5R4-1, box
//! test w5 retest 4), and the place it keeps for its next start.
//!
//! Until `8caaf00` the feed began at the log's end on every start, so the
//! lines auditd wrote while it was down were never read. Fix pass 13 kept the
//! log's inode and a byte offset; fp13's review showed that was not enough
//! (FP13R-3, FP13R-4, FP13R-7, FP13R-9, FP13R-13, FP13R-17), and this module
//! now follows the prior art fp13 cited, ausearch's checkpoint (audit 4.1.2,
//! `docs/ausearch.8:34-49`; `src/ausearch.c:439-478`): it keeps the device
//! and the inode of the file and the identity of an event at the place, and
//! a place whose file or event cannot be found again is a gap.
//!
//! - The place is the first line of the oldest event read and not posted
//!   (open in the assembler, or waiting for its chat's `run.start`), or the
//!   end of what was read when everything read was posted (`Places`). A
//!   restart reads on from there; what it posts twice has the same id, which
//!   the daemon's log keeps once per chat and source (`store::may_replace`),
//!   and which the daemon passes to the join and the install flags once
//!   (the re-review's FP13RR-7: they counted it twice).
//! - `check` is one whole line at the place, with its `(time, serial)`. On
//!   start the line is read again at `check.start`; a different line means
//!   the file is not the kept one (ext4 hands a freed inode to the next file,
//!   FP13R-4) or was rewritten, which is a gap.
//! - auditd rotates by renaming the log to `<log>.1` and older files up
//!   (`src/auditd-event.c:1259-1290`, `rotate_logs`; "logs with higher
//!   numbers are older", `docs/auditd.conf.5:127-128`), so the kept file is
//!   looked for in the log and in `<log>.1`. `max_log_file_action = exec`
//!   leaves naming to a script and is not followed.
//! - On a gap the feed reads what is still there, `<log>.1` and the log
//!   from their beginnings, and posts `feed.gap`. It skips nothing by time
//!   or serial: the kernel stamps the time at a syscall's entry and takes
//!   the serial when it writes the record (`kernel/auditsc.c:2021, 2498`), so
//!   a call that blocked is written after events stamped later, and an
//!   order-based floor dropped it (the re-review's FP13RR-2; ausearch skips
//!   by position, `src/ausearch.c:439-452`). What is posted twice is
//!   deduplicated by id.
//! - The feed's own records (its place saves are audited too) never move
//!   the place (FP13RR-1). Whether an earlier run posted anything is a
//!   marker beside the place (`STARTED_FILE`), not a report (FP13RR-4).

use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The pos file's name in the daemon's data folder.
pub const POS_FILE: &str = "audit-feed.pos";
/// Made once, on the feed's first start: a missing place after it is a gap.
pub const STARTED_FILE: &str = "audit-feed.started";
/// A pos file is a few dozen bytes; anything larger is not ours.
const POS_MAX_BYTES: u64 = 4096;
/// At most this many event starts are held for the place (`Places`).
pub const MARKS_MAX: usize = 500_000;

/// One whole line of the log and the audit event it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub start: u64,
    pub end: u64,
    pub ts_ms: i64,
    pub serial: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pos {
    /// The log's path as the feed was told it.
    pub log: String,
    pub dev: u64,
    pub inode: u64,
    /// Where the next run starts reading.
    pub offset: u64,
    /// A line at the place: starting at `offset` (an event not yet
    /// posted), or the last line read before it (everything read posted).
    pub check: Option<Check>,
    /// The newest audit time read by then (ms), for a gap's start.
    pub log_ms: i64,
}

/// What `load` found at the pos file's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loaded {
    Missing,
    /// Something is there and is not a place this feed can trust.
    Refused(&'static str),
    Kept(Pos),
}

/// A log file as found when the feed starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub dev: u64,
    pub inode: u64,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Log,
    Rotated,
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
        offset: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gap {
    /// The newest audit time read before the gap, when known.
    pub from_ms: Option<i64>,
    pub reason: String,
}

/// Where to start. `rotated` is `<log>.1` when there is one; `line_at`
/// reads the whole line starting at an offset of one of the two files and
/// returns where it ends and its event's `(time, serial)`. `ran_before`
/// says an earlier run of the feed started here (`STARTED_FILE`): a missing
/// place is then a gap, not a first start (FP13R-17, FP13RR-4).
pub fn decide(
    loaded: &Loaded,
    log: &Path,
    cur: Found,
    rotated: Option<Found>,
    from_start: bool,
    ran_before: bool,
    line_at: &dyn Fn(Which, u64) -> Option<(u64, (i64, u64))>,
) -> (Start, Option<Gap>) {
    if from_start {
        return (Start::Beginning, None);
    }
    let rest = || {
        if rotated.is_some() {
            Start::Rotated { offset: 0 }
        } else {
            Start::Beginning
        }
    };
    let p = match loaded {
        Loaded::Missing if !ran_before => return (Start::End, None),
        Loaded::Missing => {
            return (
                rest(),
                Some(Gap {
                    from_ms: None,
                    reason: "the feed's kept place is missing (removed, or never written)".into(),
                }),
            )
        }
        Loaded::Refused(why) => {
            return (
                rest(),
                Some(Gap {
                    from_ms: None,
                    reason: format!("the feed's kept place was refused: {why}"),
                }),
            )
        }
        Loaded::Kept(p) => p,
    };
    if Path::new(&p.log) != log {
        return (Start::End, None);
    }
    let holds = |f: Found, which: Which| {
        (f.dev, f.inode) == (p.dev, p.inode)
            && p.offset <= f.len
            && match p.check {
                Some(c) => {
                    (c.start == p.offset || c.end <= p.offset)
                        && line_at(which, c.start) == Some((c.end, (c.ts_ms, c.serial)))
                }
                None => p.offset == 0,
            }
    };
    if holds(cur, Which::Log) {
        return (Start::At(p.offset), None);
    }
    if let Some(r) = rotated {
        if holds(r, Which::Rotated) {
            return (Start::Rotated { offset: p.offset }, None);
        }
    }
    let same_file = (cur.dev, cur.inode) == (p.dev, p.inode);
    let reason = if same_file && p.offset > cur.len {
        "the audit log was cut shorter than the feed's place"
    } else if same_file || rotated.is_some_and(|r| (r.dev, r.inode) == (p.dev, p.inode)) {
        "the line at the feed's place is not the one it kept (the file was rewritten, or its inode reused)"
    } else {
        "the audit log rotated past the feed's place while it was down"
    };
    (
        rest(),
        Some(Gap {
            from_ms: Some(p.log_ms),
            reason: reason.into(),
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
/// through a link, and never blocking on a FIFO or device (opened
/// non-blocking, checked by its handle; fp13's review, FP13R-7, as
/// `derm-core`'s lockfile reader opens).
pub fn load(path: &Path) -> Loaded {
    let mut o = OpenOptions::new();
    o.read(true);
    derm_core::platform::private_no_follow(&mut o);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = match o.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Missing,
        Err(_) => return Loaded::Refused("it could not be opened (a link?)"),
    };
    let Ok(meta) = f.metadata() else {
        return Loaded::Refused("it could not be read");
    };
    if !meta.is_file() {
        return Loaded::Refused("it is not a regular file");
    }
    if meta.len() > POS_MAX_BYTES {
        return Loaded::Refused("it is too large");
    }
    if derm_core::platform::owner(&meta) != derm_core::platform::effective_user()
        || !derm_core::platform::is_private(&meta)
    {
        return Loaded::Refused("it is not this user's private file");
    }
    let mut text = String::new();
    if f.take(POS_MAX_BYTES).read_to_string(&mut text).is_err() {
        return Loaded::Refused("it could not be read");
    }
    match serde_json::from_str(&text) {
        Ok(p) => Loaded::Kept(p),
        Err(_) => Loaded::Refused("it does not hold a place this version reads"),
    }
}

/// Whether an earlier run of the feed started with this data folder: the
/// marker `STARTED_FILE` is there (whatever it holds; a marker that is not a
/// private regular file of this user's counts as there, failing safe).
/// Made, exclusive and 0600, when missing. FP13RR-4: a report of the
/// daemon's log stood in for this and read false on a timeout, a cut window
/// or a run that posted nothing.
pub fn started_before(dir: &Path) -> bool {
    let path = dir.join(STARTED_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = derm_core::platform::private_dir(dir);
            let mut o = OpenOptions::new();
            o.write(true).create_new(true);
            derm_core::platform::private_no_follow(&mut o);
            let _ = o.open(&path);
            false
        }
        Err(_) => true,
    }
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

/// Where one audit event's first line is in the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mark {
    dev: u64,
    inode: u64,
    start: u64,
    end: u64,
    key: (i64, u64),
}

/// The place a restart can start from (fp13's review, FP13R-3): the first
/// line of the oldest event read and not yet posted, else the end of what
/// was read. The feed notes every line it reads; `place` is asked with the
/// events still unposted (`Feed::unposted`).
#[derive(Default)]
pub struct Places {
    firsts: VecDeque<Mark>,
    held: HashSet<(i64, u64)>,
    last_keyed: Option<Mark>,
    last_end: Option<(u64, u64, u64)>,
    /// Event starts let go because more than `MARKS_MAX` were held.
    pub dropped: u64,
}

/// A place: the file, the offset, the check line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub dev: u64,
    pub inode: u64,
    pub offset: u64,
    pub check: Option<Check>,
}

impl Places {
    pub fn new() -> Places {
        Places::default()
    }

    /// One line read: `[start, end)` of file `(dev, inode)`, and its
    /// event's key when it is an audit record.
    /// A line of the feed's own (`own`) moves nothing: the place stays where
    /// it was, so the feed's own save does not make it save again
    /// (FP13RR-1). A restart has a new pid, so the last run's save lines
    /// are a stranger's there: they wait, are never posted (the feed is in
    /// no chat's tree), and age out after `PENDING_MS` of log time (fp13's
    /// second re-review, FP13RR2-6).
    pub fn note(
        &mut self,
        dev: u64,
        inode: u64,
        start: u64,
        end: u64,
        key: Option<(i64, u64)>,
        own: bool,
    ) {
        if own {
            return;
        }
        self.last_end = Some((dev, inode, end));
        let Some(key) = key else { return };
        let m = Mark {
            dev,
            inode,
            start,
            end,
            key,
        };
        self.last_keyed = Some(m);
        if self.held.insert(key) {
            self.firsts.push_back(m);
            while self.firsts.len() > MARKS_MAX {
                if let Some(old) = self.firsts.pop_front() {
                    self.held.remove(&old.key);
                    self.dropped += 1;
                }
            }
        }
    }

    /// The place, given the events still unposted.
    pub fn place(&mut self, unposted: &HashSet<(i64, u64)>) -> Option<Place> {
        while let Some(m) = self.firsts.front() {
            if unposted.contains(&m.key) {
                return Some(Place {
                    dev: m.dev,
                    inode: m.inode,
                    offset: m.start,
                    check: Some(Check {
                        start: m.start,
                        end: m.end,
                        ts_ms: m.key.0,
                        serial: m.key.1,
                    }),
                });
            }
            self.held.remove(&m.key);
            self.firsts.pop_front();
        }
        let (dev, inode, end) = self.last_end?;
        let check = self
            .last_keyed
            .filter(|m| (m.dev, m.inode) == (dev, inode) && m.end <= end)
            .map(|m| Check {
                start: m.start,
                end: m.end,
                ts_ms: m.key.0,
                serial: m.key.1,
            });
        Some(Place {
            dev,
            inode,
            offset: end,
            check,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "/var/log/audit/audit.log";
    const K: (i64, u64) = (1_000, 7);

    fn pos(inode: u64, offset: u64) -> Pos {
        Pos {
            log: LOG.into(),
            dev: 1,
            inode,
            offset,
            check: Some(Check {
                start: offset,
                end: offset + 40,
                ts_ms: K.0,
                serial: K.1,
            }),
            log_ms: 1_000,
        }
    }

    fn found(inode: u64, len: u64) -> Found {
        Found { dev: 1, inode, len }
    }

    /// A file whose line at every offset is the kept one.
    fn same(_: Which, start: u64) -> Option<(u64, (i64, u64))> {
        Some((start + 40, K))
    }

    fn other(_: Which, start: u64) -> Option<(u64, (i64, u64))> {
        Some((start + 40, (9_999, 1)))
    }

    #[test]
    fn bw5r4_1_a_restart_reads_on_from_the_kept_place() {
        let (s, g) = decide(
            &Loaded::Kept(pos(7, 500)),
            Path::new(LOG),
            found(7, 900),
            None,
            false,
            true,
            &same,
        );
        assert_eq!(s, Start::At(500));
        assert!(g.is_none());
    }

    #[test]
    fn bw5r4_1_a_place_in_the_rotated_log_is_read_on_there_first() {
        let only_rotated = |w: Which, start: u64| (w == Which::Rotated).then_some((start + 40, K));
        let (s, g) = decide(
            &Loaded::Kept(pos(7, 500)),
            Path::new(LOG),
            found(8, 40),
            Some(found(7, 600)),
            false,
            true,
            &only_rotated,
        );
        assert_eq!(s, Start::Rotated { offset: 500 });
        assert!(g.is_none());
    }

    #[test]
    fn bw5r4_1_a_place_that_cannot_be_found_is_a_gap() {
        // Rotated twice: neither file is the kept one. What is still there
        // is read from its beginning, `.1` first.
        let (s, g) = decide(
            &Loaded::Kept(pos(7, 500)),
            Path::new(LOG),
            found(9, 40),
            Some(found(8, 600)),
            false,
            true,
            &same,
        );
        assert_eq!(s, Start::Rotated { offset: 0 });
        let g = g.unwrap();
        assert_eq!(g.from_ms, Some(1_000));
        // Cut shorter than the place.
        let (s, g) = decide(
            &Loaded::Kept(pos(7, 500)),
            Path::new(LOG),
            found(7, 100),
            None,
            false,
            true,
            &same,
        );
        assert_eq!(s, Start::Beginning);
        assert!(g.unwrap().reason.contains("cut shorter"));
    }

    #[test]
    fn with_no_place_or_another_log_it_starts_at_the_end_and_from_start_wins() {
        let at = |l: &Loaded, log: &str, from_start: bool| {
            decide(
                l,
                Path::new(log),
                found(7, 900),
                None,
                from_start,
                false,
                &same,
            )
        };
        assert_eq!(at(&Loaded::Missing, LOG, false), (Start::End, None));
        assert_eq!(
            at(&Loaded::Kept(pos(7, 500)), "/tmp/other.log", false),
            (Start::End, None)
        );
        assert_eq!(
            at(&Loaded::Kept(pos(7, 500)), LOG, true),
            (Start::Beginning, None)
        );
    }

    /// FP13R-17 (fp13's review): a missing place after an earlier run, or a
    /// place that is there and refused, was a silent start at the log's end.
    #[test]
    fn fp13r_17_a_missing_or_refused_place_after_a_run_is_a_gap() {
        let (s, g) = decide(
            &Loaded::Missing,
            Path::new(LOG),
            found(7, 900),
            None,
            false,
            true,
            &same,
        );
        assert_eq!(s, Start::Beginning);
        assert!(g.unwrap().reason.contains("missing"));
        let (s, g) = decide(
            &Loaded::Refused("it is not a regular file"),
            Path::new(LOG),
            found(7, 900),
            Some(found(6, 10)),
            false,
            false,
            &same,
        );
        assert_eq!(s, Start::Rotated { offset: 0 });
        assert!(g.unwrap().reason.contains("not a regular file"));
    }

    /// FP13R-4 (fp13's review): the inode alone matched a new file that
    /// reused it. The kept line is read again; another line is a gap.
    #[test]
    fn fp13r_4_a_kept_inode_with_another_line_at_the_place_is_a_gap() {
        let (s, g) = decide(
            &Loaded::Kept(pos(7, 500)),
            Path::new(LOG),
            found(7, 800),
            Some(found(8, 700)),
            false,
            true,
            &other,
        );
        assert_eq!(s, Start::Rotated { offset: 0 });
        assert!(g.unwrap().reason.contains("inode reused"));
        // Another device with the same inode number is not the file either.
        let mut p = pos(7, 500);
        p.dev = 2;
        let (s, g) = decide(
            &Loaded::Kept(p),
            Path::new(LOG),
            found(7, 800),
            None,
            false,
            true,
            &same,
        );
        assert_eq!(s, Start::Beginning);
        assert!(g.is_some());
    }

    #[test]
    fn a_place_is_kept_private_and_read_back() {
        let dir = std::env::temp_dir().join(format!("derm-pos-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join(POS_FILE);
        save(&path, &pos(7, 500)).unwrap();
        assert_eq!(load(&path), Loaded::Kept(pos(7, 500)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            // A place someone else can write is no place.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o622)).unwrap();
            assert!(matches!(load(&path), Loaded::Refused(_)));
            // Nor one through a link.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = dir.join("link.pos");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(matches!(load(&link), Loaded::Refused(_)));
            // Fix pass 13's own place file (no device, no check) is refused,
            // so the first start after the upgrade names a gap.
            std::fs::write(
                &path,
                r#"{"log":"/var/log/audit/audit.log","inode":7,"offset":5,"logMs":1}"#,
            )
            .unwrap();
            assert!(matches!(load(&path), Loaded::Refused(_)));
        }
        assert_eq!(load(&dir.join("none.pos")), Loaded::Missing);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FP13RR-4: whether the feed ran before is its own marker, not a
    /// report: the first start makes it, every later one sees it.
    #[test]
    fn fp13rr_4_the_first_start_is_known_by_a_marker() {
        let dir = std::env::temp_dir().join(format!("derm-started-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!started_before(&dir));
        assert!(started_before(&dir));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir.join(STARTED_FILE)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FP13RR-1: the feed's own lines move no place.
    #[test]
    fn fp13rr_1_the_feeds_own_lines_do_not_move_the_place() {
        let mut p = Places::new();
        p.note(1, 7, 0, 10, Some((1, 1)), false);
        let before = p.place(&HashSet::new());
        p.note(1, 7, 10, 20, Some((2, 2)), true);
        p.note(1, 7, 20, 30, Some((2, 2)), true);
        assert_eq!(p.place(&HashSet::new()), before);
        assert_eq!(before.unwrap().offset, 10);
    }

    /// FP13R-7 (fp13 review): a FIFO planted at the pos file's name. `load`
    /// opened it O_RDONLY with no O_NONBLOCK, which blocks until a writer
    /// opens it (fifo(7)); the feed's main thread never started while its
    /// tail stayed attached.
    #[cfg(unix)]
    #[test]
    fn fp13r_7_a_fifo_at_the_pos_files_name_does_not_hang_the_feed() {
        let dir = std::env::temp_dir().join(format!("derm-fp13r7-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(POS_FILE);
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: a valid C string; mkfifo has no other precondition.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let p2 = path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(load(&p2));
        });
        let r = rx.recv_timeout(std::time::Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(r, Ok(Loaded::Refused(_))),
            "load blocked on a FIFO for 3 s, or took it: {r:?}"
        );
    }

    /// FP13R-3 (fp13's review): the place passed events still waiting for
    /// their chat's `run.start`. It stays at the first line of the oldest
    /// unposted event, and moves to the end once nothing waits.
    #[test]
    fn fp13r_3_the_place_stays_at_the_oldest_unposted_events_first_line() {
        let mut p = Places::new();
        p.note(1, 7, 0, 10, Some((1, 1)), false);
        p.note(1, 7, 10, 20, Some((2, 2)), false);
        p.note(1, 7, 20, 30, Some((1, 1)), false); // a second record of event 1
        p.note(1, 7, 30, 40, Some((3, 3)), false);
        let waiting: HashSet<(i64, u64)> = [(2, 2), (3, 3)].into_iter().collect();
        let at = p.place(&waiting).unwrap();
        assert_eq!(at.offset, 10);
        assert_eq!(
            at.check.map(|c| (c.start, c.end, c.serial)),
            Some((10, 20, 2))
        );
        let at = p.place(&HashSet::new()).unwrap();
        assert_eq!(at.offset, 40);
        assert_eq!(at.check.map(|c| (c.start, c.serial)), Some((30, 3)));
    }
}
