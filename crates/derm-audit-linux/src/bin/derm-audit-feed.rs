//! `derm-audit-feed`: the Linux OS feed's process.
//!
//! - `derm-audit-feed rules [--uid N] [--home PATH]` prints the audit rules
//!   file for the user (default: this user). It installs nothing.
//! - `derm-audit-feed run [--log PATH] [--from-start]` tails the audit log
//!   (default `/var/log/audit/audit.log`, readable by the `adm` group on
//!   Ubuntu), learns chats from the daemon's `run.start` and `run.stop`
//!   records, and posts the chats' events to the daemon. It runs as the
//!   user, never as root; the user needs read access to the log.
//! - `derm-audit-feed parse FILE --root PID --chat ID [--folder DIR]...`
//!   prints, one JSON line each, the events one recorded log gives for one
//!   root. Offline; for the box test and for reading a fixture.
// The audit log is Linux's (lane Z): elsewhere the binary only says so, and
// the readers below are not built.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use derm_audit_linux::client::{self, Client};
use derm_audit_linux::feed::Feed;
use derm_audit_linux::resume::{self, Gap, Pos, Start};
use derm_audit_linux::rules::{plain_path, render, RulesInput};
use derm_audit_linux::tree::Root;
use derm_core::event::{Event, Source};

const DEFAULT_LOG: &str = "/var/log/audit/audit.log";
/// Records already in the daemon's log are read again from this far back,
/// so chats started before the feed are known.
const TAIL_BACKLOG_MS: i64 = 24 * 60 * 60 * 1000;

#[cfg(not(unix))]
fn main() -> ExitCode {
    // `--version` answers everywhere (its test runs on Windows CI too).
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("derm-audit-feed {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    eprintln!(
        "derm-audit-feed reads Linux's audit log; this system has none (on Windows the OS feed is derm-audit-windows)"
    );
    ExitCode::from(2)
}

#[cfg(unix)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("rules") => cmd_rules(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        Some("parse") => cmd_parse(&args[1..]),
        Some("--version") => {
            println!("derm-audit-feed {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            eprintln!("usage: derm-audit-feed <rules|run|parse|--version> ...");
            2
        }
    };
    ExitCode::from(code)
}

fn value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, String> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn home() -> Option<String> {
    std::env::var("HOME").ok().filter(|h| h.starts_with('/'))
}

/// The runtime folder for `uid` as a string, the way `socket_path` finds
/// the daemon's (`derm_core::runtime`).
fn runtime_dir_for(uid: u32) -> Option<String> {
    runtime_dir_for_with(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        uid,
        derm_core::runtime::current_uid(),
        Path::new(derm_core::runtime::RUN_USER),
    )
}

fn runtime_dir_for_with(
    xdg: Option<&std::ffi::OsStr>,
    uid: u32,
    caller: u32,
    run_user: &Path,
) -> Option<String> {
    // The caller's variable names the caller's folder; for another uid only
    // that uid's own private `/run/user/<uid>` counts (fix pass review F2).
    let xdg = if uid == caller { xdg } else { None };
    derm_core::runtime::runtime_dir_with(xdg, uid, run_user)
        .and_then(|p| p.to_str().map(str::to_string))
}

#[cfg(unix)]
fn cmd_rules(args: &[String]) -> u8 {
    // SAFETY: getuid has no preconditions and cannot fail.
    let mut uid = unsafe { libc::getuid() };
    let mut home = home();
    let mut i = 0;
    while i < args.len() {
        let r = match args[i].as_str() {
            "--uid" => value(args, &mut i, "--uid")
                .and_then(|v| v.parse().map_err(|_| "--uid needs a number".into()))
                .map(|v| uid = v),
            "--home" => value(args, &mut i, "--home").map(|v| home = Some(v.to_string())),
            other => Err(format!("unknown argument {other}")),
        };
        if let Err(e) = r {
            eprintln!("derm-audit-feed rules: {e}");
            return 2;
        }
        i += 1;
    }
    let Some(home) = home else {
        eprintln!("derm-audit-feed rules: no home folder (set HOME or pass --home)");
        return 2;
    };
    if !plain_path(&home) {
        eprintln!(
            "derm-audit-feed rules: the home folder {home:?} cannot go into a rules file unquoted"
        );
        return 2;
    }
    if uid == 0 {
        eprintln!("derm-audit-feed rules: refusing uid 0; pass the uid the harnesses run as");
        return 2;
    }
    let exists = |p: &str| Path::new(p).exists();
    // The daemon's folder for that uid: `$XDG_RUNTIME_DIR`, else its own
    // private `/run/user/<uid>` (release check RC6).
    let runtime_dir = runtime_dir_for(uid);
    let (text, skipped) = render(&RulesInput {
        uid,
        home: &home,
        runtime_dir: runtime_dir.as_deref(),
        exists: &exists,
    });
    print!("{text}");
    for s in skipped {
        eprintln!("derm-audit-feed rules: no rule for {s} (it does not exist; reading it later is not recorded)");
    }
    0
}

fn cmd_parse(args: &[String]) -> u8 {
    let mut file = None;
    let mut pid = None;
    let mut chat = None;
    let mut folders = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let r: Result<(), String> = match args[i].as_str() {
            "--root" => value(args, &mut i, "--root")
                .and_then(|v| v.parse().map_err(|_| "--root needs a pid".into()))
                .map(|v| pid = Some(v)),
            "--chat" => value(args, &mut i, "--chat").map(|v| chat = Some(v.to_string())),
            "--folder" => value(args, &mut i, "--folder").map(|v| folders.push(v.to_string())),
            f if !f.starts_with('-') && file.is_none() => {
                file = Some(f.to_string());
                Ok(())
            }
            other => Err(format!("unknown argument {other}")),
        };
        if let Err(e) = r {
            eprintln!("derm-audit-feed parse: {e}");
            return 2;
        }
        i += 1;
    }
    let (Some(file), Some(pid), Some(chat)) = (file, pid, chat) else {
        eprintln!("usage: derm-audit-feed parse FILE --root PID --chat ID [--folder DIR]...");
        return 2;
    };
    let text = match std::fs::read(&file) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => {
            eprintln!("derm-audit-feed parse: {file}: {e}");
            return 1;
        }
    };
    let root = Root {
        chat,
        harness: String::new(),
        pid,
        folders,
        state: vec![],
        at: 0,
        stopped: false,
    };
    for e in derm_audit_linux::parse_for_root(&text, root, &home().unwrap_or_default()) {
        println!("{}", serde_json::to_string(&e).unwrap_or_default());
    }
    0
}

enum Msg {
    /// A line, its file's inode and the offset after it.
    Line(String, u64, u64),
    /// The daemon's backlog is in: every chat it knows is registered, so the
    /// log can be read (BW5R4-1).
    Caught,
    Idle,
    Daemon(Event),
    Gone(String),
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The daemon's data folder, as `derm-daemon` finds it on Linux
/// (`daemon::default_data_dir`): `$XDG_DATA_HOME/derm`, else
/// `~/.local/share/derm`.
fn data_dir(home: &str) -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| Some(Path::new(home).join(".local/share")))
        .map(|d| d.join("derm"))
}

/// A stretch of the audit log the feed could not read (BW5R4-1): the
/// daemon names it in the report of every chat whose run it overlaps.
fn gap_event(gap: &Gap, now: i64) -> Event {
    Event {
        id: format!("auditd-gap-{now}"),
        at: now,
        chat_id: String::new(),
        harness: String::new(),
        source: Source::Auditd,
        kind: "feed.gap".into(),
        summary: format!(
            "derm-audit-feed could not read the audit log: {}",
            gap.reason
        ),
        detail: serde_json::json!({"fromMs": gap.from_ms, "toMs": now, "reason": gap.reason}),
        pid: None,
        approval_id: None,
    }
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(unix)]
fn cmd_run(args: &[String]) -> u8 {
    let mut log = PathBuf::from(DEFAULT_LOG);
    let mut from_start = false;
    let mut i = 0;
    while i < args.len() {
        let r: Result<(), String> = match args[i].as_str() {
            "--log" => value(args, &mut i, "--log").map(|v| log = PathBuf::from(v)),
            "--from-start" => {
                from_start = true;
                Ok(())
            }
            other => Err(format!("unknown argument {other}")),
        };
        if let Err(e) = r {
            eprintln!("derm-audit-feed run: {e}");
            return 2;
        }
        i += 1;
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!(
            "derm-audit-feed run: refusing to run as root; run it as the user whose daemon it feeds"
        );
        return 2;
    }
    let Some(home) = home() else {
        eprintln!("derm-audit-feed run: HOME is not set");
        return 2;
    };
    let Some(socket) = client::socket_path() else {
        eprintln!("derm-audit-feed run: no socket path (HOME and XDG_RUNTIME_DIR are unset)");
        return 2;
    };
    let dir = socket.parent().map(Path::to_path_buf).unwrap_or_default();
    let token = match client::read_daemon_token(&dir) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("derm-audit-feed run: {e}");
            return 1;
        }
    };
    let (tx, rx) = mpsc::channel::<Msg>();
    let tail = match Client::connect(&socket, &token, "derm-audit-feed tail")
        .and_then(|(c, _)| c.tail(Some(now_ms() - TAIL_BACKLOG_MS)))
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("derm-audit-feed run: {e}");
            return 1;
        }
    };
    let (mut poster, _) = match Client::connect(&socket, &token, "derm-audit-feed") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("derm-audit-feed run: {e}");
            return 1;
        }
    };
    {
        let tx = tx.clone();
        let mut tail = tail;
        // BW5R4-1: the log is read only once the backlog's `run` records are
        // in. Read together, a resumed log's lines came before the backlog's
        // `run.start`, waited, and aged out of the pending buffer (by their
        // own time, 15 s) while the backlog streamed: 0 records on the box.
        let mut left = tail.backlog().unwrap_or(0);
        if left == 0 {
            let _ = tx.send(Msg::Caught);
        }
        std::thread::spawn(move || loop {
            match tail.next_event() {
                Ok(e) => {
                    if tx.send(Msg::Daemon(e)).is_err() {
                        return;
                    }
                    if left > 0 {
                        left -= 1;
                        if left == 0 && tx.send(Msg::Caught).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Msg::Gone(format!("daemon tail: {e}")));
                    return;
                }
            }
        });
    }
    // BW5R4-1: start where the last run stopped reading, not at the end.
    let pos_path = data_dir(&home).map(|d| d.join(resume::POS_FILE));
    let saved = pos_path.as_deref().and_then(resume::load);
    let stat = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.ino(), m.len()));
    let Some(cur) = stat(&log) else {
        eprintln!("derm-audit-feed run: cannot read {}", log.display());
        return 1;
    };
    let (start, gap) = resume::decide(
        saved.as_ref(),
        &log,
        cur,
        stat(&resume::rotated_path(&log)),
        from_start,
    );
    eprintln!("derm-audit-feed: starting at {start:?}");
    let floor = gap.as_ref().and_then(|g| g.from_ms);
    if let Some(gap) = gap {
        eprintln!("derm-audit-feed: {}", gap.reason);
        if let Err(e) = poster.post(&gap_event(&gap, now_ms())) {
            eprintln!("derm-audit-feed: could not post the gap: {e}");
        }
    }
    // The log's reader starts on `Caught`.
    let mut follower = Some((tx, log.clone(), start));
    // SAFETY: getuid has no preconditions and cannot fail.
    let runtime_dir = runtime_dir_for(unsafe { libc::getuid() });
    let mut feed = Feed::new(&home, runtime_dir.as_deref());
    if let Some(ms) = floor {
        // Read again from the log's beginning: what the last run read is
        // not posted twice.
        feed.skip_through(ms);
    }
    let mut last_prune = Instant::now();
    let mut failed_posts: u64 = 0;
    // The place after the last line whose events are all posted, and when
    // it was last kept.
    let mut place: Option<(u64, u64)> = None;
    let mut kept: Option<(u64, u64)> = None;
    let mut last_read: Option<(u64, u64)> = None;
    let mut last_keep = Instant::now();
    eprintln!(
        "derm-audit-feed: reading {} for {}",
        log.display(),
        socket.display()
    );
    for msg in rx {
        let mut at = None;
        let idle = matches!(msg, Msg::Idle);
        let events = match msg {
            Msg::Line(l, ino, end) => {
                at = Some((ino, end));
                last_read = at;
                feed.push_line(&l)
            }
            Msg::Idle => {
                // A quiet log: let go of stopped chats it has passed
                // (BW5R4-2), not only once a minute.
                let out = feed.flush();
                feed.prune(&alive);
                out
            }
            Msg::Daemon(e) => feed.on_daemon_event(&e, &alive),
            Msg::Caught => {
                if let Some((tx, log, start)) = follower.take() {
                    std::thread::spawn(move || {
                        if let Err(e) = follow(&log, start, &tx) {
                            let _ = tx.send(Msg::Gone(format!("{}: {e}", log.display())));
                        }
                    });
                }
                Vec::new()
            }
            Msg::Gone(why) => {
                eprintln!("derm-audit-feed: stopping: {why}");
                return 1;
            }
        };
        for e in events {
            if let Err(err) = poster.post(&e) {
                failed_posts += 1;
                eprintln!("derm-audit-feed: post failed ({failed_posts} so far): {err}");
                match Client::connect(&socket, &token, "derm-audit-feed") {
                    Ok((c, _)) => poster = c,
                    Err(e) => {
                        eprintln!("derm-audit-feed: stopping: {e}");
                        return 1;
                    }
                }
            }
        }
        // With no event open, every line read so far has been posted: that
        // is a place to start from again (BW5R4-1). Kept at most once a
        // second, and whenever the log goes quiet.
        if let Some(a) = at {
            if feed.open_events() == 0 {
                place = Some(a);
            }
        } else if idle {
            // `Idle` flushed every open event: all that was read is posted.
            place = last_read;
        }
        if place != kept && (idle || last_keep.elapsed() > Duration::from_secs(1)) {
            if let (Some(path), Some((inode, offset))) = (pos_path.as_deref(), place) {
                let p = Pos {
                    log: log.to_string_lossy().into_owned(),
                    inode,
                    offset,
                    log_ms: feed.log_ms(),
                };
                match resume::save(path, &p) {
                    Ok(()) => kept = place,
                    Err(e) => eprintln!("derm-audit-feed: could not keep its place: {e}"),
                }
            }
            last_keep = Instant::now();
        }
        if last_prune.elapsed() > Duration::from_secs(60) {
            feed.prune(&alive);
            last_prune = Instant::now();
        }
    }
    0
}

/// Follows the log like `tail -F`, from where `start` says (BW5R4-1:
/// `resume::decide`), across rotation (a new inode or a file that shrank).
/// Each line goes with its file's inode and the offset after it, so the
/// loop can keep its place. Sends `Idle` after a quiet half second so open
/// events are flushed. At a rotation the old file is read to its end
/// before the new one, so lines auditd wrote just before it are not lost.
#[cfg(unix)]
fn follow(path: &Path, start: Start, tx: &mpsc::Sender<Msg>) -> std::io::Result<()> {
    if let Start::Rotated { prev, offset } = &start {
        // The place is in the rotated file: read it on to its end first.
        let mut f = File::open(prev)?;
        let ino = f.metadata()?.ino();
        f.seek(SeekFrom::Start(*offset))?;
        let mut r = BufReader::new(f);
        if !drain(&mut r, ino, *offset, tx)? {
            return Ok(());
        }
    }
    let mut file = File::open(path)?;
    let mut inode = file.metadata()?.ino();
    match start {
        Start::End => {
            file.seek(SeekFrom::End(0))?;
        }
        Start::At(offset) => {
            file.seek(SeekFrom::Start(offset))?;
        }
        Start::Beginning | Start::Rotated { .. } => {}
    }
    let mut reader = BufReader::new(file);
    let mut pos = reader.stream_position()?;
    let mut quiet = Instant::now();
    let mut idle_sent = true;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = (&mut reader).take(64 * 1024).read_until(b'\n', &mut line)?;
        if n > 0 && line.ends_with(b"\n") {
            pos += n as u64;
            if tx
                .send(Msg::Line(
                    String::from_utf8_lossy(&line).into_owned(),
                    inode,
                    pos,
                ))
                .is_err()
            {
                return Ok(());
            }
            quiet = Instant::now();
            idle_sent = false;
            continue;
        }
        if n > 0 {
            // A partial line: wait for the rest.
            reader.seek(SeekFrom::Start(pos))?;
        }
        if !idle_sent && quiet.elapsed() > Duration::from_millis(500) {
            if tx.send(Msg::Idle).is_err() {
                return Ok(());
            }
            idle_sent = true;
        }
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.ino() != inode || meta.len() < pos {
                if meta.ino() != inode {
                    // Rotated: what auditd wrote to the old file since the
                    // last read is still in it (the open file survives the
                    // rename).
                    reader.seek(SeekFrom::Start(pos))?;
                    if !drain(&mut reader, inode, pos, tx)? {
                        return Ok(());
                    }
                }
                let f = File::open(path)?;
                inode = f.metadata()?.ino();
                reader = BufReader::new(f);
                pos = 0;
            }
        }
    }
}

/// Sends every whole line left in `reader` (at `pos` in file `inode`).
/// False when the loop has gone.
#[cfg(unix)]
fn drain(
    reader: &mut BufReader<File>,
    inode: u64,
    mut pos: u64,
    tx: &mpsc::Sender<Msg>,
) -> std::io::Result<bool> {
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader.take(64 * 1024).read_until(b'\n', &mut line)?;
        if n == 0 || !line.ends_with(b"\n") {
            return Ok(true);
        }
        pos += n as u64;
        if tx
            .send(Msg::Line(
                String::from_utf8_lossy(&line).into_owned(),
                inode,
                pos,
            ))
            .is_err()
        {
            return Ok(false);
        }
    }
}

use std::io::Read as _;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn next_line(rx: &mpsc::Receiver<Msg>) -> (String, u64, u64) {
        loop {
            match rx.recv_timeout(Duration::from_secs(5)).expect("a line") {
                Msg::Line(l, ino, end) => return (l, ino, end),
                Msg::Idle => continue,
                _ => panic!("not a line"),
            }
        }
    }

    /// BW5R4-1: the feed reads on from its kept place, not the log's end,
    /// and at a rotation reads the old file to its end before the new one.
    #[test]
    fn bw5r4_1_follow_reads_on_from_its_place_and_across_a_rotation() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("derm-follow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        std::fs::write(&log, "one\ntwo\nthree\n").unwrap();
        let (tx, rx) = mpsc::channel::<Msg>();
        let path = log.clone();
        std::thread::spawn(move || follow(&path, Start::At(4), &tx));
        let (l, ino, end) = next_line(&rx);
        assert_eq!((l.as_str(), end), ("two\n", 8));
        assert_eq!(next_line(&rx).0, "three\n");
        // auditd writes once more, then rotates: the old file's last line
        // comes before the new file's first.
        let mut old = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        std::fs::rename(&log, dir.join("audit.log.1")).unwrap();
        old.write_all(b"four\n").unwrap();
        drop(old);
        std::fs::write(&log, "five\n").unwrap();
        let (l, ino4, _) = next_line(&rx);
        assert_eq!((l.as_str(), ino4), ("four\n", ino));
        let (l, ino5, end) = next_line(&rx);
        assert_eq!((l.as_str(), end), ("five\n", 5));
        assert_ne!(ino5, ino);
        drop(rx);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A place in the rotated file: read on there, then the new log.
    #[test]
    fn bw5r4_1_follow_reads_on_in_the_rotated_file_first() {
        let dir = std::env::temp_dir().join(format!("derm-follow-r-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        std::fs::write(dir.join("audit.log.1"), "a\nb\n").unwrap();
        std::fs::write(&log, "c\n").unwrap();
        let (tx, rx) = mpsc::channel::<Msg>();
        let path = log.clone();
        let start = Start::Rotated {
            prev: dir.join("audit.log.1"),
            offset: 2,
        };
        std::thread::spawn(move || follow(&path, start, &tx));
        assert_eq!(next_line(&rx).0, "b\n");
        assert_eq!(next_line(&rx).0, "c\n");
        drop(rx);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fix pass review F2: `rules --uid N` run by root (or by `sudo -E`)
    /// carries the caller's `XDG_RUNTIME_DIR`, which is not N's folder; the
    /// rule would watch the wrong user's token. Only N's own private
    /// `/run/user/N` counts then.
    #[test]
    fn another_uids_rules_ignore_the_callers_variable() {
        let root = std::env::temp_dir().join(format!("derm-feed-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let me = derm_core::runtime::current_uid();
        let xdg = Some(std::ffi::OsStr::new("/run/user/0"));
        // Our own rules: the variable wins, as everywhere.
        assert_eq!(
            runtime_dir_for_with(xdg, me, me, &root).as_deref(),
            Some("/run/user/0")
        );
        // Another uid's: not the caller's variable; that uid's folder is not
        // ours here (owned by the caller), so none.
        let other = me.wrapping_add(1);
        let dir = root.join(other.to_string());
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(runtime_dir_for_with(xdg, other, me, &root), None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
