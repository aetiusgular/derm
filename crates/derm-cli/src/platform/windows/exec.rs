//! `derm run`'s process control on Windows (the seam's primitive 5): the
//! functions `run/exec.rs` gives on Unix, with the same signatures (note AU
//! section 4).
//!
//! The tree. Each harness and each companion starts suspended, joins a Job
//! Object of its own, then resumes, so nothing it starts can run before it
//! is in the job ("By default, processes created by a process in a job are
//! associated with the job"; Job Objects page). std 1.97 keeps both a
//! child's main thread handle and `PROC_THREAD_ATTRIBUTE_JOB_LIST` unstable
//! (`std/src/os/windows/process.rs`), so the main thread is found by a
//! thread snapshot and resumed.
//!
//! The job ends its processes when its last handle closes
//! (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), so a `derm run` that dies (a
//! closed console, a task manager kill) takes its harness's tree with it.
//! When the harness exits on its own, the limit is cleared before the job
//! is closed, so what the harness left running survives it, as on Unix
//! (case 68). A companion's job is ended with it. An exit caused by a closing
//! console is not "on its own", and conhost may tell `derm run` of the close
//! long after the harness has gone: it hands the event to one process at a
//! time, newest first, waiting on each handler, and a Node companion's
//! handler (libuv) blocks for its full time (WW5-7; review FPW-S1). So the
//! limit is not cleared when the harness exits: its job is kept, the limit
//! still set (`LEFT`), until `derm` itself returns from `main`
//! (`release_left`), and a close, logoff or shutdown that reaches `derm`
//! before then ends what the harness left, however late it comes.
//!
//! Stops (case 87, proposed case AU-7). A terminal's Ctrl-C and Ctrl-Break
//! reach every process on the console, the harness included
//! (`GenerateConsoleCtrlEvent`: `CTRL_C_EVENT` "cannot be limited to a
//! specific process group"), so `derm run` handles them and sends nothing:
//! one stop, not two. Windows has no SIGTERM or SIGHUP; a console that
//! closes sends `CTRL_CLOSE_EVENT`, after which "the system terminates the
//! process" when the handler returns, within 5,000 ms (HandlerRoutine
//! page). The handler holds its thread for up to 4.5 s while `wait` gives
//! the harness 3 s to end, then ends its job, so `run.stop` is recorded.
//!
//! The program. `derm run codex` finds `codex.cmd` (npm's shim), reads it
//! and starts `node.exe <script>` itself; any other batch file is refused,
//! never run through `cmd.exe` (`shim.rs`).

use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    GenerateConsoleCtrlEvent, GetConsoleProcessList, SetConsoleCtrlHandler, CTRL_BREAK_EVENT,
    CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
};

use super::shim;
use crate::run::plan::Plan;

/// No console event yet.
const NONE: u32 = u32::MAX;
/// The last console event the handler saw.
static PENDING: AtomicU32 = AtomicU32::new(NONE);

/// How long the handler holds its thread after a close, logoff or shutdown
/// (the system allows 5,000 ms for a close).
const CLOSE_HOLD: Duration = Duration::from_millis(4500);
/// How long the harness is given to end after a close before its job ends.
const CLOSE_GRACE: Duration = Duration::from_secs(3);

/// The jobs of harnesses that exited with no close seen, kill-on-close still
/// set (WW5-7, FPW-S1). conhost hands a closing console's `CTRL_CLOSE_EVENT`
/// to one process at a time, newest first, waiting on each handler (seen on
/// the box, Windows 11 26200.9711, 8 Nov), and libuv's handler in a Node
/// process with a SIGHUP listener sleeps until it is ended (libuv v1.52.1
/// `src/win/signal.c:124-131`), so `derm run`, attached before its companion
/// and its harness, can hear of the close seconds after both have gone.
/// These jobs end when a close reaches `derm`, or when `derm` ends without
/// returning from `main`; `release_left` keeps their processes alive when
/// it returns.
static LEFT: Mutex<Vec<Job>> = Mutex::new(Vec::new());

fn is_close(event: u32) -> bool {
    matches!(
        event,
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT
    )
}

/// Ends every job `wait` kept (a close came after the harness exited).
fn end_left() {
    let jobs = LEFT.lock().unwrap_or_else(|e| e.into_inner());
    for j in jobs.iter() {
        j.terminate(1);
    }
}

/// How long `release_left` waits for a close still on its way, when a
/// kept job still has processes and a console is attached (review FPWR-1).
/// With nothing between `derm` and its harness on the console, `derm`'s
/// turn came about 15 ms after the harness exited (the box, 8 Nov), and
/// `derm` can reach the end of `main` sooner than that.
const CLOSE_LATE: Duration = Duration::from_millis(500);

/// Called as `derm` returns from `main`, or unwinds out of it (review
/// FPWR-3): what each exited harness left running outlives it, as on Unix
/// (case 68), unless a close reaches `derm` first.
pub fn release_left() {
    let live = LEFT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|j| j.active() != Some(0));
    if live && attached_to_console() {
        // Unlocked while it waits: the handler ends the jobs itself.
        let start = Instant::now();
        while start.elapsed() < CLOSE_LATE && !is_close(PENDING.load(Ordering::SeqCst)) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let mut jobs = LEFT.lock().unwrap_or_else(|e| e.into_inner());
    if is_close(PENDING.load(Ordering::SeqCst)) {
        for j in jobs.iter() {
            j.terminate(1);
        }
        jobs.clear();
        return;
    }
    for j in jobs.drain(..) {
        let _ = j.set_kill_on_close(false);
    }
}

/// Whether this process has a console (`GetConsoleProcessList` counts the
/// processes on it, and gives 0 when there is none).
fn attached_to_console() -> bool {
    let mut one = [0u32; 1];
    // SAFETY: a buffer of one entry, its length passed.
    unsafe { GetConsoleProcessList(one.as_mut_ptr(), 1) > 0 }
}

unsafe extern "system" fn on_console(event: u32) -> BOOL {
    PENDING.store(event, Ordering::SeqCst);
    if is_close(event) {
        end_left();
        // The process ends when this returns: hold it while `wait` stops the
        // harness and the caller records the stop. A normal exit of the main
        // thread ends this thread first.
        std::thread::sleep(CLOSE_HOLD);
    }
    1
}

/// Handles Ctrl-C, Ctrl-Break and the close events so `derm run` outlives
/// them long enough to record the harness's end.
pub fn install_handlers() {
    // SAFETY: registers a handler that only stores a number and sleeps.
    unsafe { SetConsoleCtrlHandler(Some(on_console), 1) };
}

/// Whether to pass a SIGINT on (Unix's rule; the same function here so the
/// callers and the tests agree). Windows never calls it with a signal: a
/// console's Ctrl-C reaches the harness itself.
#[allow(
    dead_code,
    reason = "one of the eight names run/ takes from exec; only Unix's wait calls it"
)]
pub fn forward_sigint(from_process: i32, foreground: bool) -> bool {
    match from_process {
        1 => true,
        0 => false,
        _ => !foreground,
    }
}

/// A Job Object that ends its processes when its last handle closes.
struct Job(OwnedHandle);

impl Job {
    fn new() -> std::io::Result<Job> {
        // SAFETY: an unnamed job with default security.
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        let job = Job(owned(h)?);
        job.set_kill_on_close(true)?;
        Ok(job)
    }

    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle() as HANDLE
    }

    fn set_kill_on_close(&self, on: bool) -> std::io::Result<()> {
        // SAFETY: plain data; zero is "no limits".
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        if on {
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        // SAFETY: the job is ours; the struct is the class's.
        let ok = unsafe {
            SetInformationJobObject(
                self.raw(),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// The processes still in the job, or `None` when it cannot be read.
    fn active(&self) -> Option<u32> {
        // SAFETY: plain data, filled by the call.
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: our job handle; `info` is sized as passed.
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(info.ActiveProcesses)
    }

    fn terminate(&self, code: u32) {
        // SAFETY: the job is ours.
        unsafe { TerminateJobObject(self.raw(), code) };
    }
}

fn owned(h: HANDLE) -> std::io::Result<OwnedHandle> {
    use std::os::windows::io::{FromRawHandle, RawHandle};
    if h.is_null() || h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a handle a call just handed over.
    Ok(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) })
}

/// The jobs of the children this process started, by pid.
static JOBS: Mutex<Vec<(u32, Job)>> = Mutex::new(Vec::new());

fn take_job(pid: u32) -> Option<Job> {
    let mut jobs = JOBS.lock().unwrap_or_else(|e| e.into_inner());
    let i = jobs.iter().position(|(p, _)| *p == pid)?;
    Some(jobs.remove(i).1)
}

fn with_job(pid: u32, f: impl FnOnce(&Job)) {
    let jobs = JOBS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, j)) = jobs.iter().find(|(p, _)| *p == pid) {
        f(j);
    }
}

/// Resumes every thread of a process started suspended (one, its main
/// thread). Returns how many were resumed.
fn resume_threads(pid: u32) -> std::io::Result<usize> {
    // SAFETY: a snapshot handle we then own.
    let snap = owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })?;
    // SAFETY: plain data, sized as the API asks.
    let mut e: THREADENTRY32 = unsafe { std::mem::zeroed() };
    e.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut resumed = 0;
    // SAFETY: the snapshot is ours; `e` is sized.
    let mut ok = unsafe { Thread32First(snap.as_raw_handle() as HANDLE, &mut e) };
    while ok != 0 {
        if e.th32OwnerProcessID == pid {
            // SAFETY: a thread of our own suspended child.
            if let Ok(t) = owned(unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, e.th32ThreadID) }) {
                // SAFETY: the thread handle is ours.
                if unsafe { ResumeThread(t.as_raw_handle() as HANDLE) } != u32::MAX {
                    resumed += 1;
                }
            }
        }
        // SAFETY: as above.
        ok = unsafe { Thread32Next(snap.as_raw_handle() as HANDLE, &mut e) };
    }
    Ok(resumed)
}

/// Starts `cmd` suspended, puts it in a new job, then resumes it. A child
/// that cannot be put in its job is ended, never left running outside it.
fn spawn_in_job(cmd: &mut Command, flags: u32) -> std::io::Result<Child> {
    let job = Job::new()?;
    cmd.creation_flags(CREATE_SUSPENDED | flags);
    let mut child = cmd.spawn()?;
    let fail = |child: &mut Child, e: std::io::Error| {
        let _ = child.kill();
        let _ = child.wait();
        e
    };
    // SAFETY: the job and the child's process handle are ours.
    if unsafe { AssignProcessToJobObject(job.raw(), child.as_raw_handle() as HANDLE) } == 0 {
        let e = std::io::Error::last_os_error();
        return Err(fail(
            &mut child,
            std::io::Error::other(format!("could not put the harness in its job: {e}")),
        ));
    }
    match resume_threads(child.id()) {
        Ok(n) if n > 0 => {}
        Ok(_) => {
            return Err(fail(
                &mut child,
                std::io::Error::other("the harness's thread was not found to resume"),
            ))
        }
        Err(e) => return Err(fail(&mut child, e)),
    }
    JOBS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((child.id(), job));
    Ok(child)
}

/// The PATH the child will see: the plan's, else ours.
fn child_path(plan: &Plan) -> Option<String> {
    plan.env_set
        .iter()
        .rev()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var("PATH").ok())
}

fn launch(program: &str, path_var: Option<&str>) -> std::io::Result<shim::Launch> {
    shim::launch_for(program, path_var, &|p| p.is_file(), &|p| {
        use std::io::Read;
        let mut s = String::new();
        std::fs::File::open(p)
            .ok()?
            .take(64 * 1024)
            .read_to_string(&mut s)
            .ok()?;
        Some(s)
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))
}

fn command(l: &shim::Launch, args: &[String], cwd: &str, plan: &Plan) -> Command {
    let mut cmd = Command::new(&l.program);
    cmd.args(&l.leading).args(args).current_dir(cwd);
    for name in &plan.env_remove {
        cmd.env_remove(name);
    }
    for (k, v) in &plan.env_set {
        cmd.env(k, v);
    }
    cmd
}

pub fn spawn(plan: &Plan, cwd: &str, piped: bool) -> std::io::Result<Child> {
    let l = launch(&plan.program, child_path(plan).as_deref())?;
    let mut cmd = command(&l, &plan.args, cwd, plan);
    let io = |p: bool| if p { Stdio::piped() } else { Stdio::inherit() };
    cmd.stdin(io(piped))
        .stdout(io(piped))
        .stderr(Stdio::inherit());
    // Same console and process group as `derm run`: the terminal's Ctrl-C
    // reaches the harness directly (CREATE_NEW_PROCESS_GROUP would turn
    // Ctrl-C off in it; CreateProcess flags page).
    spawn_in_job(&mut cmd, 0)
}

pub fn spawn_companion(
    program: &str,
    args: &[String],
    plan: &Plan,
    cwd: &str,
    path: &str,
) -> std::io::Result<Child> {
    let l = launch(program, Some(path))?;
    let mut cmd = command(&l, args, cwd, plan);
    cmd.env("PATH", path);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    // Its own group, so `stop_companion` can send it Ctrl-Break alone.
    spawn_in_job(&mut cmd, CREATE_NEW_PROCESS_GROUP)
}

/// Asks a companion to stop (Ctrl-Break to its group), waits `grace`, then
/// ends its whole job.
pub fn stop_companion(child: &mut Child, grace: Duration) {
    let pid = child.id();
    if !matches!(child.try_wait(), Ok(Some(_))) {
        // SAFETY: the companion's group id is its pid (it was started with
        // CREATE_NEW_PROCESS_GROUP); this console's other processes are not
        // in that group.
        unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) };
        let start = Instant::now();
        while start.elapsed() < grace {
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    if let Some(job) = take_job(pid) {
        job.terminate(1);
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub fn wait(child: &mut Child) -> std::io::Result<ExitStatus> {
    let pid = child.id();
    let mut closing: Option<Instant> = None;
    loop {
        if let Some(status) = child.try_wait()? {
            // `LEFT` is held from the read to the push (review FPWR-2): the
            // handler stores the event before it takes `LEFT`, so a close
            // is either read here or ends the job once it is kept.
            let mut left = LEFT.lock().unwrap_or_else(|e| e.into_inner());
            // A close stored and not yet read (the exit is checked first).
            let closed = closing.is_some() || is_close(PENDING.swap(NONE, Ordering::SeqCst));
            if let Some(job) = take_job(pid) {
                if closed {
                    // Dropped with kill-on-close set: what the harness left
                    // in it ends now.
                    drop(job);
                } else {
                    // Kept until `derm` returns, or a late close ends it.
                    left.push(job);
                }
            }
            return Ok(status);
        }
        match PENDING.swap(NONE, Ordering::SeqCst) {
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT if closing.is_none() => {
                closing = Some(Instant::now());
            }
            // Ctrl-C and Ctrl-Break reached the harness too: nothing to send.
            CTRL_C_EVENT | CTRL_BREAK_EVENT | NONE => {}
            _ => {}
        }
        if closing.is_some_and(|t| t.elapsed() >= CLOSE_GRACE) {
            with_job(pid, |j| j.terminate(1));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// STATUS_CONTROL_C_EXIT: how a console program ends after Ctrl-C.
const STATUS_CONTROL_C_EXIT: u32 = 0xC000_013A;

/// The exit code for `run.stop` and `derm run`'s own exit. Windows codes are
/// 32 bits; one outside 0 to 255 becomes 1, so a failure never reads as
/// success by truncation (256 is not 0). Ctrl-C's status reads as 130, the
/// code a shell gives SIGINT; Windows has no signal, so the second field is
/// always `None`.
pub fn code(status: &ExitStatus) -> (u8, Option<i32>) {
    match status.code() {
        Some(c) if c as u32 == STATUS_CONTROL_C_EXIT => (130, None),
        Some(c) => (u8::try_from(c).unwrap_or(1), None),
        None => (1, None),
    }
}

pub fn output_with_timeout(program: &str, args: &[String], limit: Duration) -> Option<String> {
    let l = launch(program, std::env::var("PATH").ok().as_deref()).ok()?;
    let mut cmd = Command::new(&l.program);
    cmd.args(&l.leading)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = spawn_in_job(&mut cmd, 0).ok()?;
    let pid = child.id();
    let mut out = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = (&mut out).take(4 * 1024 * 1024).read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success().then_some(()),
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    // A probe's own leftovers end with it, so a grandchild holding the
    // output pipe cannot keep the reader waiting (case 102).
    if let Some(job) = take_job(pid) {
        job.terminate(1);
    }
    let buf = reader.join().ok()?;
    result.map(|()| String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(program: &str, args: &[&str]) -> Plan {
        Plan {
            program: program.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env_set: vec![("DERM_CHAT_ID".into(), "c1".into())],
            env_remove: vec!["DERM_CHAT_TOKEN".into()],
            kit: None,
            sandbox_name: None,
            srt_settings: None,
            folders: vec![],
            state_dirs: vec![],
            notes: vec![],
            full_access: vec![],
            companion: None,
            scratch_dir: None,
        }
    }

    fn cwd() -> String {
        std::env::temp_dir().to_string_lossy().into_owned()
    }

    #[test]
    fn sigint_rule_is_unix_s() {
        assert!(forward_sigint(1, true));
        assert!(!forward_sigint(0, true));
        assert!(forward_sigint(-1, false));
        assert!(!forward_sigint(-1, true));
    }

    /// `PENDING` is one per process, and every `wait` reads it: tests that
    /// drive `wait` or set `PENDING` take turns.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The pids of running `name` processes whose parent is `parent`.
    fn children_named(parent: u32, name: &str) -> Vec<u32> {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        // SAFETY: a snapshot handle we then own.
        let snap = owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }).unwrap();
        // SAFETY: plain data, sized as the API asks.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut out = Vec::new();
        // SAFETY: the snapshot is ours; `e` is sized.
        let mut ok = unsafe { Process32FirstW(snap.as_raw_handle() as HANDLE, &mut e) };
        while ok != 0 {
            let len = e
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(e.szExeFile.len());
            let exe = String::from_utf16_lossy(&e.szExeFile[..len]);
            if e.th32ParentProcessID == parent && exe.eq_ignore_ascii_case(name) {
                out.push(e.th32ProcessID);
            }
            // SAFETY: as above.
            ok = unsafe { Process32NextW(snap.as_raw_handle() as HANDLE, &mut e) };
        }
        out
    }

    /// A harness (`cmd /C start /B ping ...`) that exits at once and leaves a
    /// `ping` running in its job; returns the child and the harness's pid
    /// once the ping exists and the harness has exited.
    fn harness_that_leaves_a_ping() -> (Child, u32) {
        let mut c = spawn(
            &plan(
                "cmd",
                &["/C", "start", "", "/B", "ping", "-n", "60", "127.0.0.1"],
            ),
            &cwd(),
            true,
        )
        .unwrap();
        let harness = c.id();
        let start = Instant::now();
        while (children_named(harness, "PING.EXE").is_empty() || c.try_wait().unwrap().is_none())
            && start.elapsed() < Duration::from_secs(10)
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !children_named(harness, "PING.EXE").is_empty(),
            "no ping started"
        );
        assert!(c.try_wait().unwrap().is_some(), "the harness did not exit");
        (c, harness)
    }

    /// The pings still running under `harness`, ended before they are
    /// returned so no test leaves one behind.
    fn pings_left(harness: u32) -> Vec<u32> {
        let left = children_named(harness, "PING.EXE");
        for p in &left {
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &p.to_string()])
                .output();
        }
        left
    }

    /// WW5-7 (Windows test w5, 3.3): a console closed during `derm run` left
    /// the harness's detached child running. Here the close is stored, unread,
    /// after the harness has exited and before `wait` runs, so the exit branch
    /// is what decides (review FPW-S8b). Fails on `2ce607d`: the `ping` the
    /// harness left in its job is still running.
    #[test]
    fn ww5_7_a_close_that_comes_as_the_harness_exits_ends_what_it_left() {
        let _turn = serial();
        let (mut c, harness) = harness_that_leaves_a_ping();
        PENDING.store(CTRL_CLOSE_EVENT, Ordering::SeqCst);
        wait(&mut c).unwrap();
        PENDING.store(NONE, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(300));
        let left = pings_left(harness);
        assert!(
            left.is_empty(),
            "the harness's child outlived a closed console: {left:?}"
        );
    }

    /// FPW-S1 (the fix pass's review): the close reaches `derm` only after
    /// `wait` has returned, as it does behind a Node companion whose handler
    /// sleeps. The handler itself is called, as conhost would call it. Fails
    /// on `2ce607d`: `wait` had cleared kill-on-close, and the ping survives.
    #[test]
    fn ww5_7_a_close_that_comes_after_wait_returned_ends_what_the_harness_left() {
        let _turn = serial();
        PENDING.store(NONE, Ordering::SeqCst);
        let (mut c, harness) = harness_that_leaves_a_ping();
        wait(&mut c).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            children_named(harness, "PING.EXE").len(),
            1,
            "the ping must outlive the exit"
        );
        // SAFETY: the handler only stores a number, ends jobs and sleeps.
        let handler = std::thread::spawn(|| unsafe { on_console(CTRL_CLOSE_EVENT) });
        let start = Instant::now();
        while !children_named(harness, "PING.EXE").is_empty()
            && start.elapsed() < Duration::from_secs(2)
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let left = pings_left(harness);
        // The handler has stored its event and ended the jobs; it now only
        // holds its thread (review FPWR-12).
        PENDING.store(NONE, Ordering::SeqCst);
        handler.join().unwrap();
        PENDING.store(NONE, Ordering::SeqCst);
        assert!(
            left.is_empty(),
            "a late close left the harness's child running: {left:?}"
        );
    }

    /// FPWR-1 (the re-review): `derm` reached the end of `main` before the
    /// close reached it, so the kept job was released first. `release_left`
    /// waits for a late close while the harness's leftovers live and a
    /// console is attached; GitHub's runner has none, so there the test
    /// checks only that the release happened.
    #[test]
    fn fpwr_1_a_close_while_derm_returns_still_ends_what_the_harness_left() {
        let _turn = serial();
        PENDING.store(NONE, Ordering::SeqCst);
        let (mut c, harness) = harness_that_leaves_a_ping();
        wait(&mut c).unwrap();
        let late = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(100));
            // SAFETY: the handler only stores a number, ends jobs and sleeps.
            unsafe { on_console(CTRL_CLOSE_EVENT) }
        });
        release_left();
        std::thread::sleep(Duration::from_millis(300));
        let left = pings_left(harness);
        PENDING.store(NONE, Ordering::SeqCst);
        late.join().unwrap();
        PENDING.store(NONE, Ordering::SeqCst);
        assert!(LEFT.lock().unwrap().is_empty());
        if attached_to_console() {
            assert!(
                left.is_empty(),
                "a close while derm returned left the child running: {left:?}"
            );
        }
    }

    /// The other side of WW5-7: an exit with no close leaves what the harness
    /// started running once `derm` returns (case 68, lane Z's choice).
    #[test]
    fn ww5_7_an_exit_with_no_close_leaves_what_the_harness_started() {
        let _turn = serial();
        PENDING.store(NONE, Ordering::SeqCst);
        let (mut c, harness) = harness_that_leaves_a_ping();
        wait(&mut c).unwrap();
        release_left();
        assert!(LEFT.lock().unwrap().is_empty());
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(pings_left(harness).len(), 1);
    }

    #[test]
    fn exit_codes_pass_through_and_never_truncate_to_success() {
        let _turn = serial();
        for (exit, want) in [("exit 7", 7u8), ("exit 256", 1), ("exit -1073741510", 130)] {
            let mut c = spawn(&plan("cmd", &["/C", exit]), &cwd(), false).unwrap();
            assert_eq!(code(&wait(&mut c).unwrap()), (want, None), "{exit}");
        }
    }

    #[test]
    fn the_environment_is_set_and_inherited_tokens_cleared() {
        let _turn = serial();
        use std::io::Read;
        std::env::set_var("DERM_CHAT_TOKEN", "left-over");
        let mut c = spawn(&plan("cmd", &["/C", "set DERM_"]), &cwd(), true).unwrap();
        drop(c.stdin.take());
        let mut out = String::new();
        c.stdout.take().unwrap().read_to_string(&mut out).unwrap();
        wait(&mut c).unwrap();
        std::env::remove_var("DERM_CHAT_TOKEN");
        assert!(out.lines().any(|l| l.trim() == "DERM_CHAT_ID=c1"), "{out}");
        assert!(!out.contains("DERM_CHAT_TOKEN"), "{out}");
    }

    #[test]
    fn a_batch_file_is_never_started_through_cmd() {
        let dir = std::env::temp_dir().join(format!("derm-exec-bat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bat = dir.join("evil.bat");
        std::fs::write(&bat, "@echo off\r\necho ran > \"%~dp0ran.txt\"\r\n").unwrap();
        let e = spawn(&plan(&bat.to_string_lossy(), &["&", "calc"]), &cwd(), false).unwrap_err();
        assert!(e.to_string().contains("refusing to start"), "{e}");
        assert!(!dir.join("ran.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_harness_runs_in_a_job_that_its_children_join() {
        let _turn = serial();
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        // `cmd /Q` waits on its stdin.
        let mut c = spawn(&plan("cmd", &["/Q"]), &cwd(), true).unwrap();
        let mut in_job = 0;
        with_job(c.id(), |j| {
            // SAFETY: both handles are ours.
            unsafe { IsProcessInJob(c.as_raw_handle() as HANDLE, j.raw(), &mut in_job) };
        });
        assert_ne!(in_job, 0);
        drop(c.stdin.take());
        assert_eq!(code(&wait(&mut c).unwrap()).0, 0);
        // The job is closed once the harness has exited.
        assert!(JOBS.lock().unwrap().iter().all(|(p, _)| *p != c.id()));
    }

    #[test]
    fn a_companion_is_stopped_with_its_tree() {
        let mut c = spawn_companion(
            "cmd",
            &["/Q".into()],
            &plan("x", &[]),
            &cwd(),
            &std::env::var("PATH").unwrap_or_default(),
        )
        .unwrap();
        let start = Instant::now();
        stop_companion(&mut c, Duration::from_millis(300));
        assert!(matches!(c.try_wait(), Ok(Some(_))));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_probe_returns_its_output_or_none_on_time() {
        let out = output_with_timeout(
            "cmd",
            &["/C".into(), "echo hello".into()],
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(out.trim(), "hello");
        assert_eq!(
            output_with_timeout(
                "cmd",
                &["/C".into(), "exit 1".into()],
                Duration::from_secs(10)
            ),
            None
        );
        let start = Instant::now();
        let slow = ["-n".to_string(), "30".into(), "127.0.0.1".into()];
        assert_eq!(
            output_with_timeout("ping", &slow, Duration::from_millis(500)),
            None
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(
            output_with_timeout("no-such-program-derm", &[], Duration::from_secs(1)),
            None
        );
    }
}
