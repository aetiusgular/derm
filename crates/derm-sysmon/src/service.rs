//! The service (`contracts/sysmon-service.md` section 2). Windows starts
//! `derm-sysmon.exe service` as `NT SERVICE\derm-sysmon`, a virtual account
//! in Event Log Readers (note BC section 11: such an account reads the
//! channel, run on the box), installed by an administrator
//! (`packaging/windows/sysmon-service/`).
//!
//! Its folder, `%ProgramData%\derm-sysmon\`, writable by administrators,
//! SYSTEM and the service only, holds:
//! - `config.json` (the installer's): `{"daemon": "<the absolute path of
//!   derm-daemon.exe in a folder only administrators write>",
//!   "sandboxAccounts": ["srt-sandbox"]}`;
//! - `pipe`: the pipe's name, drawn at random each start, written after the
//!   pipe's first instance exists (case 136's rule);
//! - `cursors.json`: each user's last record (by SID);
//! - `last-error.txt`: why the service stopped, when it did.
//!
//! The service dispatcher is windows-sys's own calls, as windows-service
//! 0.8.1 makes them (`service_dispatcher.rs:108`,
//! `service_control_handler.rs:26, 119`): no new crate.

use std::collections::{HashMap, HashSet};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use derm_audit_windows::xml;
use serde_json::{json, Value};
use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtGetLogInfo, EvtLogNumberOfLogRecords, EvtLogOldestRecordNumber,
    EvtOpenChannelPath, EvtOpenLog, EvtVarTypeUInt64, EVT_VARIANT,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::acl::{self, who_else_can};
use crate::route::{Accounts, Registry, Router};
use crate::stream::Stream;
use crate::win::{self, Got, Pipe};
use crate::wire::{self, FromDaemon, FromService, Record, Reply};

/// The service's name, and its account's (`NT SERVICE\<NAME>`).
pub const NAME: &str = "derm-sysmon";
/// The prefix of the pipe's drawn name.
pub const PIPE_PREFIX: &str = r"\\.\pipe\derm-sysmon-";
/// At most this many daemons at once.
const MAX_CLIENTS: u64 = 64;
/// How long a client has to say hello.
const HELLO_WAIT: Duration = Duration::from_secs(10);
/// How long the client loop waits for a line before it reads the channel.
const POLL: Duration = Duration::from_millis(250);
const WRITE_WAIT: Duration = Duration::from_secs(10);
/// Records read from the channel per pass.
const READ_MAX: usize = 512;

static STOP: AtomicBool = AtomicBool::new(false);
static STATUS: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

/// The service's folder.
pub fn folder() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join(NAME)
}

fn set_status(state: u32, exit: u32) {
    let h = STATUS.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE;
    if h.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: exit,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: if state == SERVICE_RUNNING || state == SERVICE_STOPPED {
            0
        } else {
            10_000
        },
    };
    // SAFETY: the handle RegisterServiceCtrlHandlerExW gave; a plain struct.
    unsafe { SetServiceStatus(h, &status) };
}

unsafe extern "system" fn handler(
    control: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _ctx: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::SeqCst);
            set_status(SERVICE_STOP_PENDING, NO_ERROR);
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = win::wide_str(NAME);
    // SAFETY: a static handler; the name is copied by the call.
    let h =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null()) };
    if h.is_null() {
        return;
    }
    STATUS.store(h, Ordering::SeqCst);
    set_status(SERVICE_START_PENDING, NO_ERROR);
    let result = serve_until_stopped(|| set_status(SERVICE_RUNNING, NO_ERROR));
    match result {
        Ok(()) => set_status(SERVICE_STOPPED, NO_ERROR),
        Err(why) => {
            let _ = std::fs::write(folder().join("last-error.txt"), &why);
            set_status(
                SERVICE_STOPPED,
                windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR,
            );
        }
    }
}

/// Hands this thread to the service control manager until the service
/// stops. Run by hand (not by Windows) it fails at once.
pub fn run() -> Result<(), String> {
    let mut name = win::wide_str(NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: a null-terminated table whose strings outlive the call.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(format!(
            "not started by the service control manager ({}); install it with packaging/windows/sysmon-service",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// What the installer configured, checked.
struct Config {
    /// derm-daemon.exe's NT path, for comparing with a client's image.
    daemon_nt: String,
    sandbox: HashSet<String>,
}

/// Every folder from `path`'s parent up to its root.
fn ancestors(path: &Path) -> Vec<PathBuf> {
    path.ancestors().skip(1).map(Path::to_path_buf).collect()
}

/// That only `trusted` can write `path` and, for a file, the folder that
/// holds it, and that only they can replace any folder above.
pub fn admin_only(path: &Path, trusted: &[&str], file: bool) -> Result<(), String> {
    let check = |p: &Path, rights: u32| -> Result<(), String> {
        let s = win::security_of_path(p).map_err(|e| format!("{}: {e}", p.display()))?;
        match who_else_can(&s, trusted, rights) {
            Some(why) => Err(format!("{}: {why}", p.display())),
            None => Ok(()),
        }
    };
    check(path, acl::ANY_WRITE)?;
    for (i, dir) in ancestors(path).iter().enumerate() {
        let rights = if file && i == 0 {
            acl::ANY_WRITE
        } else {
            acl::REPLACE
        };
        check(dir, rights)?;
    }
    Ok(())
}

fn load_config(me: &str) -> Result<Config, String> {
    let dir = folder();
    let trusted = [acl::SYSTEM, acl::ADMINISTRATORS, acl::TRUSTED_INSTALLER, me];
    let path = dir.join("config.json");
    admin_only(&path, &trusted, true)?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if text.len() > 64 * 1024 {
        return Err("config.json is too large".into());
    }
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("config.json: {e}"))?;
    let daemon = v
        .get("daemon")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or("config.json names no absolute daemon path")?;
    // The daemon program: administrators' alone, the service not included.
    admin_only(
        &daemon,
        &[acl::SYSTEM, acl::ADMINISTRATORS, acl::TRUSTED_INSTALLER],
        true,
    )?;
    let daemon_nt = win::nt_path(&daemon).ok_or("the daemon program's NT path")?;
    let mut sandbox = HashSet::new();
    for name in v
        .get("sandboxAccounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(16)
    {
        // An account not made yet (srt not installed) maps to nothing.
        if let Some(sid) = win::sid_of_account(name) {
            sandbox.insert(sid);
        }
    }
    Ok(Config { daemon_nt, sandbox })
}

/// The channel's oldest and newest record ids.
fn channel_bounds() -> (Option<u64>, Option<u64>) {
    let path = win::wide_str(derm_audit_windows::sysmon::CHANNEL);
    // SAFETY: NUL-terminated channel path; local machine.
    let h = unsafe { EvtOpenLog(0, path.as_ptr(), EvtOpenChannelPath) };
    if h == 0 {
        return (None, None);
    }
    let get = |id| -> Option<u64> {
        // SAFETY: zeroed EVT_VARIANT is plain data.
        let mut v: EVT_VARIANT = unsafe { std::mem::zeroed() };
        let mut used = 0u32;
        // SAFETY: one EVT_VARIANT's room.
        let ok = unsafe {
            EvtGetLogInfo(
                h,
                id,
                std::mem::size_of::<EVT_VARIANT>() as u32,
                &mut v,
                &mut used,
            )
        };
        // SAFETY: the union's u64 is read only when the type says so.
        (ok != 0 && v.Type == EvtVarTypeUInt64 as u32).then(|| unsafe { v.Anonymous.UInt64Val })
    };
    let oldest = get(EvtLogOldestRecordNumber);
    let count = get(EvtLogNumberOfLogRecords);
    // SAFETY: the handle EvtOpenLog gave; closed once.
    unsafe { EvtClose(h) };
    let newest = match (oldest, count) {
        (Some(o), Some(c)) if c > 0 => Some(o + c - 1),
        (Some(o), Some(_)) => Some(o.saturating_sub(1)),
        _ => None,
    };
    (oldest, newest)
}

/// Account names to SIDs, cached.
struct Names(HashMap<String, Option<String>>);

impl Accounts for Names {
    fn sid_of(&mut self, account: &str) -> Option<String> {
        let key = account.to_lowercase();
        if let Some(v) = self.0.get(&key) {
            return v.clone();
        }
        if self.0.len() > 4096 {
            self.0.clear();
        }
        let v = win::sid_of_account(account);
        self.0.insert(key, v.clone());
        v
    }
}

/// Each user's cursor, kept in `cursors.json`.
struct Cursors {
    path: PathBuf,
    map: Mutex<HashMap<String, u64>>,
}

impl Cursors {
    fn load(path: PathBuf) -> Cursors {
        let map = std::fs::read_to_string(&path)
            .ok()
            .filter(|t| t.len() < 1 << 20)
            .and_then(|t| serde_json::from_str::<HashMap<String, u64>>(&t).ok())
            .unwrap_or_default();
        Cursors {
            path,
            map: Mutex::new(map),
        }
    }

    fn get(&self, sid: &str) -> Option<u64> {
        self.map.lock().ok()?.get(sid).copied()
    }

    fn set(&self, sid: &str, at: u64) {
        let Ok(mut m) = self.map.lock() else { return };
        if m.get(sid) == Some(&at) {
            return;
        }
        m.insert(sid.to_string(), at);
        let _ = write_replace(&self.path, json!(*m).to_string().as_bytes());
    }
}

/// Writes a file in the service's folder by a write and a rename, so a
/// reader never sees half of it. The file takes the folder's access list.
fn write_replace(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", win::random_hex(8)?));
    std::fs::write(&tmp, data)?;
    let (a, b) = (win::wide(tmp.as_os_str()), win::wide(path.as_os_str()));
    // SAFETY: two NUL-terminated paths.
    if unsafe {
        MoveFileExW(
            a.as_ptr(),
            b.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        let e = io::Error::last_os_error();
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// One pipe instance, made with the service's access list: SYSTEM and the
/// service everything; any signed-in user may read and write data, not
/// make an instance (`0x12008b`: FILE_GENERIC_READ and FILE_WRITE_DATA, as
/// Win32-OpenSSH's agent grants `0x12019b` at 0172cc6 `agent.c:111`).
fn instance(name: &[u16], first: bool, sddl: &str) -> io::Result<Pipe> {
    let sd = win::Descriptor::from_sddl(sddl)?;
    let sa = sd.attributes();
    let flags = PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    // SAFETY: NUL-terminated name; `sa` borrows `sd`, alive here.
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            flags,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            MAX_CLIENTS as u32,
            64 * 1024,
            64 * 1024,
            0,
            &sa,
        )
    };
    Pipe::new(win::owned(h)?)
}

struct Shared {
    config: Config,
    cursors: Cursors,
    registry: Mutex<Registry>,
    clients: AtomicU64,
    next: AtomicU64,
}

fn serve_until_stopped(running: impl FnOnce()) -> Result<(), String> {
    let me = win::own_sid().ok_or("the service's own account could not be read")?;
    let dir = folder();
    admin_only(
        &dir,
        &[
            acl::SYSTEM,
            acl::ADMINISTRATORS,
            acl::TRUSTED_INSTALLER,
            &me,
        ],
        false,
    )
    .map_err(|e| format!("the service's folder: {e}"))?;
    let config = load_config(&me)?;
    let shared = Arc::new(Shared {
        config,
        cursors: Cursors::load(dir.join("cursors.json")),
        registry: Mutex::new(Registry::default()),
        clients: AtomicU64::new(0),
        next: AtomicU64::new(1),
    });
    let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;{me})(A;;0x12008b;;;AU)");
    let name = format!(
        "{PIPE_PREFIX}{}",
        win::random_hex(16).map_err(|e| e.to_string())?
    );
    let wide_name = win::wide_str(&name);
    let mut next = Some(instance(&wide_name, true, &sddl).map_err(|e| format!("the pipe: {e}"))?);
    write_replace(&dir.join("pipe"), format!("{name}\n").as_bytes())
        .map_err(|e| format!("the pipe's pointer file: {e}"))?;
    running();
    while !STOP.load(Ordering::SeqCst) {
        let pipe = match next.take() {
            Some(p) => p,
            None => match instance(&wide_name, false, &sddl) {
                Ok(p) => p,
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            },
        };
        match pipe.accept(Some(Duration::from_millis(500))) {
            Ok(true) => {
                if shared.clients.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
                    shared.clients.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let shared = shared.clone();
                std::thread::spawn(move || {
                    let id = shared.next.fetch_add(1, Ordering::SeqCst);
                    let _ = serve_client(&pipe, &shared, id);
                    if let Ok(mut r) = shared.registry.lock() {
                        r.release(id);
                    }
                    shared.clients.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Ok(false) => next = Some(pipe),
            // A client came and went: the instance is dropped.
            Err(_) => {}
        }
    }
    let _ = std::fs::remove_file(dir.join("pipe"));
    Ok(())
}

/// Reads lines from a pipe, keeping what is past the last line end.
struct Lines {
    buf: Vec<u8>,
}

impl Lines {
    /// The next whole line, reading at most `wait` for it.
    fn next(&mut self, pipe: &Pipe, wait: Duration) -> io::Result<Option<String>> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=i).collect();
                let mut r = BufReader::new(&line[..]);
                return wire::read_line(&mut r, wire::MAX_LINE);
            }
            if self.buf.len() > wire::MAX_LINE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a line over the limit",
                ));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            let mut chunk = [0u8; 16 * 1024];
            match pipe.read(&mut chunk, Some(left))? {
                Got::Bytes(n) => self.buf.extend_from_slice(&chunk[..n]),
                Got::TimedOut => return Ok(None),
                Got::Closed => return Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
    }
}

fn send(pipe: &Pipe, line: &FromService) -> io::Result<()> {
    let mut text = line.to_line();
    text.push('\n');
    pipe.write_all(text.as_bytes(), WRITE_WAIT)
}

fn refuse(pipe: &Pipe, why: &str) -> io::Result<()> {
    send(
        pipe,
        &FromService::Reply(Reply {
            ok: false,
            error: Some(why.into()),
            ..Reply::default()
        }),
    )
}

/// Whether a SID is a real user's (a local or domain account, RID 1000 up).
fn is_real_user(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-")
        && sid
            .rsplit('-')
            .next()
            .and_then(|r| r.parse::<u32>().ok())
            .is_some_and(|rid| rid >= 1000)
}

fn serve_client(pipe: &Pipe, shared: &Shared, id: u64) -> io::Result<()> {
    let mut lines = Lines { buf: Vec::new() };
    let Some(first) = lines.next(pipe, HELLO_WAIT)? else {
        return Ok(());
    };
    let protocol = match FromDaemon::parse(&first) {
        Ok(FromDaemon::Hello { protocol }) => protocol,
        _ => return refuse(pipe, "the first line must be hello"),
    };
    if protocol != wire::PROTOCOL {
        return refuse(pipe, "protocol 1 only");
    }
    // The program: class 88 names the client's image without opening it
    // (OpenProcess fails 5 from a virtual account: note BC section 11).
    let image = win::client_pid(pipe.handle()).and_then(win::image_of_pid);
    if !image.is_some_and(|i| i.eq_ignore_ascii_case(&shared.config.daemon_nt)) {
        return refuse(
            pipe,
            "only derm's daemon program, from its administrators' folder, is served",
        );
    }
    // The user: from the client's token, after the first read.
    let Some(sid) = win::client_sid(pipe.handle()) else {
        return refuse(pipe, "the client's account could not be read");
    };
    if !is_real_user(&sid) || shared.config.sandbox.contains(&sid) {
        return refuse(pipe, "only a signed-in user's daemon is served");
    }
    let cursor = shared.cursors.get(&sid);
    send(
        pipe,
        &FromService::Reply(Reply {
            ok: true,
            protocol: Some(wire::PROTOCOL),
            user: Some(sid.clone()),
            cursor: Some(cursor),
            error: None,
        }),
    )?;
    let (_, newest) = channel_bounds();
    let mut stream = Stream::new(cursor, newest);
    let mut router = Router::new(id, &sid, shared.config.sandbox.clone());
    let mut names = Names(HashMap::new());
    let mut saved = Instant::now();
    while !STOP.load(Ordering::SeqCst) {
        while let Some(line) = lines.next(pipe, POLL)? {
            match FromDaemon::parse(&line) {
                Ok(FromDaemon::Claim { process_guid, chat }) => {
                    let result = match shared.registry.lock() {
                        Ok(mut reg) => router.claim(&process_guid, &chat, &mut reg),
                        Err(_) => Err("the service's claims are unreadable".into()),
                    };
                    let reply = match result {
                        Ok(()) => Reply {
                            ok: true,
                            ..Reply::default()
                        },
                        Err(e) => Reply {
                            ok: false,
                            error: Some(e),
                            ..Reply::default()
                        },
                    };
                    send(pipe, &FromService::Reply(reply))?;
                }
                Ok(FromDaemon::Ack { record_id }) => {
                    let _ = stream.ack(record_id);
                }
                // A second hello, an unknown or a malformed line: the
                // connection ends.
                _ => return refuse(pipe, "an unexpected line"),
            }
            if STOP.load(Ordering::SeqCst) {
                break;
            }
        }
        if saved.elapsed() > Duration::from_secs(2) {
            shared.cursors.set(&sid, stream.cursor());
            saved = Instant::now();
        }
        if !stream.ready() {
            continue;
        }
        let (oldest, newest) = channel_bounds();
        for g in stream.check(oldest, newest) {
            send(
                pipe,
                &FromService::Gap {
                    from: g.from,
                    to: g.to,
                    reason: g.reason,
                },
            )?;
        }
        let texts = match derm_audit_windows::reader::read_after(stream.pos(), READ_MAX) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let records: Vec<Record> = texts
            .into_iter()
            .filter_map(|x| {
                let id = xml::parse(&x)?.record_id?;
                Some(Record {
                    record_id: id,
                    xml: x,
                })
            })
            .collect();
        let step = stream.read(records, |r| {
            xml::parse(&r.xml).is_some_and(|e| router.route(&e, &mut names))
        });
        for g in step.gaps {
            send(
                pipe,
                &FromService::Gap {
                    from: g.from,
                    to: g.to,
                    reason: g.reason,
                },
            )?;
        }
        let (batches, too_big) = wire::batches(step.send);
        for id in too_big {
            stream.unsend(id);
            send(
                pipe,
                &FromService::Gap {
                    from: id,
                    to: id,
                    reason: "an event too large to send".into(),
                },
            )?;
        }
        for b in batches {
            send(pipe, &FromService::Events(b))?;
        }
    }
    shared.cursors.set(&sid, stream.cursor());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_user_is_an_account_sid_with_a_rid_from_1000() {
        assert!(is_real_user("S-1-5-21-1-2-3-1001"));
        assert!(!is_real_user("S-1-5-21-1-2-3-500"));
        assert!(!is_real_user("S-1-5-18"));
        assert!(!is_real_user("S-1-5-80-1-2-3-4-5"));
        assert!(!is_real_user("S-1-5-21-1-2-3-x"));
    }

    #[test]
    fn run_by_hand_the_service_says_it_was_not_started_by_windows() {
        assert!(run().is_err());
    }

    #[test]
    fn this_process_reads_its_own_account_and_resolves_a_well_known_name() {
        let me = win::own_sid().unwrap();
        assert!(me.starts_with("S-1-"));
        assert_eq!(
            win::sid_of_account(r"NT AUTHORITY\SYSTEM").as_deref(),
            Some(acl::SYSTEM)
        );
        assert_eq!(win::sid_of_account("no such account derm 5bE"), None);
    }

    #[test]
    fn this_programs_own_image_reads_as_its_nt_path() {
        let exe = std::env::current_exe().unwrap();
        let mine = win::image_of_pid(std::process::id()).unwrap();
        assert_eq!(
            Some(mine.to_lowercase()),
            win::nt_path(&exe).map(|p| p.to_lowercase())
        );
        assert!(mine.starts_with(r"\Device\"));
    }
}
