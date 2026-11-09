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
use derm_audit_linux::resume::{self, Pos};
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
    /// A line: its file's device and inode, and where it starts and ends.
    Line(String, u64, u64, u64, u64),
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
/// daemon names it in the report of every chat whose run it overlaps. `to`
/// is where reading starts again: the first record of what is still there.
/// It carries no `auditAt`, and the daemon's join does not take it for OS
/// progress (fp13's review, FP13R-5).
fn gap_event(from_ms: Option<i64>, to_ms: i64, reason: &str, now: i64) -> Event {
    Event {
        id: format!("auditd-gap-{now}"),
        at: now,
        chat_id: String::new(),
        harness: String::new(),
        source: Source::Auditd,
        kind: "feed.gap".into(),
        summary: format!("derm-audit-feed could not read the audit log: {reason}"),
        detail: serde_json::json!({"fromMs": from_ms, "toMs": to_ms, "reason": reason}),
        pid: None,
        approval_id: None,
    }
}

/// One whole line of an open file at `start`: where it ends, and its audit
/// event's key. Read with `pread`, so the file's own offset is untouched.
#[cfg(unix)]
fn line_at(f: &File, start: u64) -> Option<(u64, (i64, u64))> {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0u8; 16 * 1024];
    let n = f.read_at(&mut buf, start).ok()?;
    let nl = buf[..n].iter().position(|b| *b == b'\n')?;
    let line = String::from_utf8_lossy(&buf[..nl]);
    let key = derm_audit_linux::record::parse_line(&line)?.event_key();
    Some((start + nl as u64 + 1, key))
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
    let since = now_ms() - TAIL_BACKLOG_MS;
    // A tail of `run` records only (fp13's review, FP13R-1, FP13R-11); a
    // daemon older than that refuses the field, and gets the plain tail.
    let tail = match Client::connect(&socket, &token, "derm-audit-feed tail")
        .and_then(|(c, _)| c.tail_runs(Some(since)))
    {
        Ok(t) => Ok(t),
        Err(client::ClientError::Refused(_)) => {
            Client::connect(&socket, &token, "derm-audit-feed tail")
                .and_then(|(c, _)| c.tail(Some(since)))
        }
        Err(e) => Err(e),
    };
    let tail = match tail {
        Ok(t) => t,
        Err(e) => {
            eprintln!("derm-audit-feed run: {e}");
            return 1;
        }
    };
    let backlog_cut = tail.cut();
    let (mut poster, _) = match Client::connect(&socket, &token, "derm-audit-feed") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("derm-audit-feed run: {e}");
            return 1;
        }
    };
    // The oldest backlog record's time, for a cut backlog's gap.
    let oldest_backlog = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(i64::MAX));
    {
        let tx = tx.clone();
        let mut tail = tail;
        let oldest = oldest_backlog.clone();
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
                    if left > 0 {
                        oldest.fetch_min(e.at, std::sync::atomic::Ordering::Relaxed);
                    }
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
    // BW5R4-1: start where the last run stopped reading, not at the end. The
    // files are opened now and held, so a rotation before `Caught` is read
    // through, not past (fp13's review, FP13R-9).
    let pos_path = data_dir(&home).map(|d| d.join(resume::POS_FILE));
    let loaded = pos_path
        .as_deref()
        .map_or(resume::Loaded::Missing, resume::load);
    let open = |p: &Path| -> Option<(File, resume::Found)> {
        let f = File::open(p).ok()?;
        let m = f.metadata().ok()?;
        m.is_file().then_some((
            f,
            resume::Found {
                dev: m.dev(),
                inode: m.ino(),
                len: m.len(),
            },
        ))
    };
    let Some((log_file, cur)) = open(&log) else {
        eprintln!("derm-audit-feed run: cannot read {}", log.display());
        return 1;
    };
    let rotated = open(&resume::rotated_path(&log));
    // FP13RR-4: whether an earlier run started here is the feed's own
    // marker; made now if this is the first start.
    let ran = data_dir(&home).is_some_and(|d| resume::started_before(&d));
    let (start, gap) = resume::decide(
        &loaded,
        &log,
        cur,
        rotated.as_ref().map(|r| r.1),
        from_start,
        ran,
        &|which, at| match which {
            resume::Which::Log => line_at(&log_file, at),
            resume::Which::Rotated => rotated.as_ref().and_then(|r| line_at(&r.0, at)),
        },
    );
    eprintln!("derm-audit-feed: starting at {start:?}");
    // Where reading starts in each file.
    let (prev, log_at) = match start {
        resume::Start::End => (None, cur.len),
        resume::Start::Beginning => (None, 0),
        resume::Start::At(o) => (None, o),
        resume::Start::Rotated { offset } => (rotated.map(|r| (r.0, offset)), 0),
    };
    // A gap's end: the first record of what is read again.
    let gap = gap.map(|g| {
        let first = prev
            .as_ref()
            .and_then(|(f, at)| line_at(f, *at))
            .or_else(|| line_at(&log_file, log_at))
            .map(|(_, k)| k.0);
        (g, first)
    });
    if let Some((g, _)) = &gap {
        eprintln!("derm-audit-feed: {}", g.reason);
    }
    // The log's reader starts on `Caught`.
    let mut follower = Some((tx, log.clone(), log_file, log_at, prev));
    // SAFETY: getuid has no preconditions and cannot fail.
    let runtime_dir = runtime_dir_for(unsafe { libc::getuid() });
    let mut feed = Feed::new(&home, runtime_dir.as_deref());
    // FP13RR-1: the feed's own records (its place saves are audited too).
    feed.set_own_pid(std::process::id());
    let mut gap = gap;
    let mut last_prune = Instant::now();
    let mut places = resume::Places::new();
    let mut kept: Option<resume::Place> = None;
    let mut last_keep = Instant::now();
    eprintln!(
        "derm-audit-feed: reading {} for {}",
        log.display(),
        socket.display()
    );
    for msg in rx {
        let idle = matches!(msg, Msg::Idle);
        let events = match msg {
            Msg::Line(l, dev, ino, start, end) => {
                let events = feed.push_line(&l);
                let key = derm_audit_linux::record::parse_line(&l).map(|r| r.event_key());
                places.note(dev, ino, start, end, key, feed.last_line_own());
                events
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
                // Posted now, not before the backlog: a live event while the
                // backlog is queued could drop this tail (FP13R-11).
                let now = now_ms();
                if let Some((g, first)) = gap.take() {
                    let from = g.from_ms.map(|f| f.min(now));
                    if !post_or_stop(
                        &mut poster,
                        &socket,
                        &token,
                        &gap_event(from, first.unwrap_or(now), &g.reason, now),
                    ) {
                        // FP13RR-6: no place is kept past an unposted gap;
                        // the next start finds the same place and posts it.
                        return 1;
                    }
                }
                if backlog_cut {
                    // FP13R-1: chats whose `run.start` is older than the
                    // newest backlog records are not known.
                    let oldest = oldest_backlog.load(std::sync::atomic::Ordering::Relaxed);
                    let reason = "the daemon's backlog of run records was cut, so chats started before it are not known";
                    eprintln!("derm-audit-feed: {reason}");
                    if !post_or_stop(
                        &mut poster,
                        &socket,
                        &token,
                        &gap_event(Some(since), oldest.min(now), reason, now + 1),
                    ) {
                        return 1;
                    }
                }
                if let Some((tx, log, file, at, prev)) = follower.take() {
                    std::thread::spawn(move || {
                        if let Err(e) = follow(&log, file, at, prev, &tx) {
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
            if !post_or_stop(&mut poster, &socket, &token, &e) {
                // FP13R-14: the place is not kept past an event that was not
                // posted; the restart reads it again.
                return 1;
            }
        }
        // The place: the first line of the oldest event not yet posted, or
        // the end of what was read (fp13's review, FP13R-3). Kept at most
        // once a second, and whenever the log goes quiet.
        if idle || last_keep.elapsed() > Duration::from_secs(1) {
            let place = places.place(&feed.unposted());
            if place != kept {
                if let (Some(path), Some(p)) = (pos_path.as_deref(), place) {
                    let pos = Pos {
                        log: log.to_string_lossy().into_owned(),
                        dev: p.dev,
                        inode: p.inode,
                        offset: p.offset,
                        check: p.check,
                        log_ms: feed.log_ms(),
                    };
                    match resume::save(path, &pos) {
                        Ok(()) => kept = place,
                        Err(e) => eprintln!("derm-audit-feed: could not keep its place: {e}"),
                    }
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

/// Posts one event; on a failure, once more on a new connection. False when
/// that fails too: the caller stops without keeping its place, so the next
/// run reads the event again (fp13's review, FP13R-14).
fn post_or_stop(poster: &mut Client, socket: &Path, token: &str, e: &Event) -> bool {
    let Err(err) = poster.post(e) else {
        return true;
    };
    eprintln!("derm-audit-feed: post failed ({err}); trying again on a new connection");
    match Client::connect(socket, token, "derm-audit-feed") {
        Ok((c, _)) => *poster = c,
        Err(e) => {
            eprintln!("derm-audit-feed: stopping: {e}");
            return false;
        }
    }
    match poster.post(e) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("derm-audit-feed: stopping: the post failed again: {e}");
            false
        }
    }
}

/// Follows the log like `tail -F`: `prev` (the rotated file, from an
/// offset) first, then the log from `at`, both already open (fp13's review,
/// FP13R-9: opened by path only on `Caught`, a rotation in between was read
/// past), and on across rotation (a new inode or a file that shrank). Each
/// line goes with its file's device and inode and its start and end, so the
/// loop can keep its place. Sends `Idle` after a quiet half second so open
/// events are flushed. At a rotation the old file is read to its end before
/// the new one, so lines auditd wrote just before it are not lost.
#[cfg(unix)]
fn follow(
    path: &Path,
    file: File,
    at: u64,
    prev: Option<(File, u64)>,
    tx: &mpsc::Sender<Msg>,
) -> std::io::Result<()> {
    if let Some((mut f, offset)) = prev {
        let meta = f.metadata()?;
        f.seek(SeekFrom::Start(offset))?;
        let mut r = BufReader::new(f);
        if !drain(&mut r, meta.dev(), meta.ino(), offset, tx)? {
            return Ok(());
        }
    }
    let mut file = file;
    let meta = file.metadata()?;
    let (mut dev, mut inode) = (meta.dev(), meta.ino());
    file.seek(SeekFrom::Start(at))?;
    let mut reader = BufReader::new(file);
    let mut pos = at;
    let mut quiet = Instant::now();
    let mut idle_sent = true;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = (&mut reader).take(64 * 1024).read_until(b'\n', &mut line)?;
        if n > 0 && line.ends_with(b"\n") {
            let start = pos;
            pos += n as u64;
            if tx
                .send(Msg::Line(
                    String::from_utf8_lossy(&line).into_owned(),
                    dev,
                    inode,
                    start,
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
            if meta.ino() != inode || meta.dev() != dev || meta.len() < pos {
                if meta.ino() != inode || meta.dev() != dev {
                    // Rotated: what auditd wrote to the old file since the
                    // last read is still in it (the open file survives the
                    // rename).
                    reader.seek(SeekFrom::Start(pos))?;
                    if !drain(&mut reader, dev, inode, pos, tx)? {
                        return Ok(());
                    }
                }
                let f = File::open(path)?;
                let m = f.metadata()?;
                (dev, inode) = (m.dev(), m.ino());
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
    dev: u64,
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
        let start = pos;
        pos += n as u64;
        if tx
            .send(Msg::Line(
                String::from_utf8_lossy(&line).into_owned(),
                dev,
                inode,
                start,
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
                Msg::Line(l, _dev, ino, _start, end) => return (l, ino, end),
                Msg::Idle => continue,
                _ => panic!("not a line"),
            }
        }
    }

    fn opened(p: &Path) -> File {
        File::open(p).unwrap()
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
        let f = opened(&log);
        std::thread::spawn(move || follow(&path, f, 4, None, &tx));
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
        let prev = Some((opened(&dir.join("audit.log.1")), 2));
        let f = opened(&log);
        std::thread::spawn(move || follow(&path, f, 0, prev, &tx));
        assert_eq!(next_line(&rx).0, "b\n");
        assert_eq!(next_line(&rx).0, "c\n");
        drop(rx);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FP13R-9 (fp13's review): the place was decided on a `stat` taken when
    /// the feed started, and the log opened by path only on `Caught`, after
    /// the backlog streamed; a rotation in between made it seek the kept
    /// offset in the new file. The file is now opened at the decision and
    /// held, so the rotation is read through.
    #[test]
    fn fp13r_9_a_rotation_before_caught_is_not_read_past() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("derm-fp13r9-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        std::fs::write(&log, "kept-1\nkept-2\n").unwrap();
        // The decision: read on at byte 7, on the file as opened now.
        let held = opened(&log);
        // While the backlog streams: auditd writes, then rotates.
        let mut old = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        old.write_all(b"unread-3\n").unwrap();
        drop(old);
        std::fs::rename(&log, dir.join("audit.log.1")).unwrap();
        std::fs::write(&log, "new-1\nnew-2\n").unwrap();
        let (tx, rx) = mpsc::channel::<Msg>();
        let path = log.clone();
        std::thread::spawn(move || follow(&path, held, 7, None, &tx));
        let got: Vec<String> = (0..4).map(|_| next_line(&rx).0).collect();
        drop(rx);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got, ["kept-2\n", "unread-3\n", "new-1\n", "new-2\n"]);
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
