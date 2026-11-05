//! Who is on the other end of the daemon's pipe, and our ancestry, on
//! Windows (the seam's primitive 2; note AU section 2.3). The same functions
//! as `crate::peer` on Unix.
//!
//! The user: the client's token, through `ImpersonateNamedPipeClient`, then
//! `RevertToSelf` at once. Impersonation takes "the security context of the
//! last message read from the pipe" (the function's page), so before the
//! first read it may fail (I); then the user is read from the client
//! process's token instead. Either way the pipe's DACL admits no other user
//! (pipe.rs), so the user read here is a record, not the guard.
//!
//! The pid: `GetNamedPipeClientProcessId`, which can be spoofed (Project
//! Zero, Sept 2019), as macOS's `LOCAL_PEERPID` names the last user rather
//! than the connector. The handle `pidfd_of` returns is opened at accept and
//! names that process for as long as it is held, the role a pidfd plays on
//! Linux: a reused pid is another process (`pidfd_alive` asks the handle,
//! not the pid).
//!
//! Ancestry: the parent pid from a process snapshot (`th32ParentProcessID`).
//! Windows keeps a dead parent's pid in its children, and pids are reused,
//! so a parent counts only when it started before its child (I, the
//! standard check; Process Explorer's documentation describes the same
//! reuse). A same-user process can also name any parent it can open
//! (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), so ancestry guards against a
//! mistake, not an agent (case 97's open part; proposed case AU-5).

use std::os::windows::io::OwnedHandle;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{FILETIME, HANDLE, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{RevertToSelf, TOKEN_QUERY};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, GetProcessTimes, OpenProcess, OpenThreadToken, QueryFullProcessImageNameW,
    WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};

use super::ident::{self, UserId};
use super::pipe::Stream;
use super::sys;

/// A process handle that names one process for as long as it is held.
pub type Pidfd = OwnedHandle;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub pid: Option<u32>,
    /// The client's user (a SID; named `uid` as on Unix, for the callers).
    pub uid: UserId,
}

/// The client of a server end, or `None` when neither its token nor its
/// process could be read. On a client end, the server.
pub fn of(stream: &Stream) -> Option<Peer> {
    let h = stream.handle();
    let pid = if stream.is_server() {
        let mut pid = 0u32;
        // SAFETY: a pipe handle we hold.
        (unsafe { GetNamedPipeClientProcessId(h, &mut pid) } != 0).then_some(pid)
    } else {
        let mut pid = 0u32;
        // SAFETY: as above.
        (unsafe { windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(h, &mut pid) }
            != 0)
            .then_some(pid)
    };
    let uid = if stream.is_server() {
        impersonated_user(h)
    } else {
        None
    }
    .or_else(|| pid.and_then(ident::user_of_process))?;
    Some(Peer { pid, uid })
}

/// The client's user through impersonation, reverted at once. A failed
/// revert would leave this thread acting as the client, so it ends the
/// process (the function's page: on failure "no client requests should be
/// executed").
fn impersonated_user(h: HANDLE) -> Option<UserId> {
    // SAFETY: a server pipe handle we hold.
    if unsafe { ImpersonateNamedPipeClient(h) } == 0 {
        return None;
    }
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: OpenAsSelf TRUE: the token is opened with the process's own
    // rights, not the client's.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    // SAFETY: ends the impersonation this thread started above.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    if opened == 0 {
        return None;
    }
    let token = sys::owned(token).ok()?;
    ident::token_user(sys::raw(&token))
}

/// A handle on the connecting process, opened now.
pub fn pidfd_of(stream: &Stream) -> Option<Pidfd> {
    let pid = of_pid(stream)?;
    // SAFETY: OpenProcess returns a handle we then own, or null.
    sys::owned(unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    })
    .ok()
}

fn of_pid(stream: &Stream) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: a pipe handle we hold.
    let ok = if stream.is_server() {
        unsafe { GetNamedPipeClientProcessId(stream.handle(), &mut pid) }
    } else {
        unsafe {
            windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(
                stream.handle(),
                &mut pid,
            )
        }
    };
    (ok != 0).then_some(pid)
}

/// Whether the process a handle names still runs.
pub fn pidfd_alive(fd: &Pidfd) -> bool {
    // SAFETY: a process handle with SYNCHRONIZE; zero wait.
    unsafe { WaitForSingleObject(sys::raw(fd), 0) == WAIT_TIMEOUT }
}

fn open_query(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: OpenProcess returns a handle we then own, or null.
    sys::owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) }).ok()
}

/// When a process started: its creation time in 100-nanosecond intervals
/// since 1601 (`GetProcessTimes`). With the pid, it names one process.
pub fn start_time(pid: u32) -> Option<u64> {
    let h = open_query(pid)?;
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: a process handle with query rights; out pointers are ours.
    let ok = unsafe {
        GetProcessTimes(
            sys::raw(&h),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return None;
    }
    let t = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    // A process that has exited but whose object lives on (someone holds a
    // handle) has an exit time: it no longer runs.
    let ended = (u64::from(exited.dwHighDateTime) << 32) | u64::from(exited.dwLowDateTime);
    (t != 0 && ended == 0).then_some(t)
}

/// This process's user.
pub fn me() -> UserId {
    ident::effective_user()
}

/// The program a process runs (`QueryFullProcessImageNameW`).
pub fn program(pid: u32) -> Option<PathBuf> {
    let h = open_query(pid)?;
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: the buffer is valid for `len` characters.
    let ok = unsafe {
        QueryFullProcessImageNameW(sys::raw(&h), PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
    };
    if ok == 0 {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}

/// Every process's parent pid, from one snapshot.
fn parents() -> Vec<(u32, u32)> {
    // SAFETY: a snapshot handle we then own.
    let Ok(snap) = sys::owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // SAFETY: PROCESSENTRY32W is plain data; dwSize set as the API asks.
    let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: the snapshot is ours; `e` is sized.
    let mut ok = unsafe { Process32FirstW(sys::raw(&snap), &mut e) };
    while ok != 0 {
        out.push((e.th32ProcessID, e.th32ParentProcessID));
        // SAFETY: as above.
        ok = unsafe { Process32NextW(sys::raw(&snap), &mut e) };
    }
    out
}

/// A process's parent, when it still runs and started before its child.
pub fn parent(pid: u32) -> Option<u32> {
    let ppid = parents()
        .into_iter()
        .find(|(p, _)| *p == pid)
        .map(|(_, pp)| pp)?;
    if ppid == 0 || ppid == pid {
        return None;
    }
    match (start_time(ppid), start_time(pid)) {
        (Some(parent_started), Some(child_started)) if parent_started <= child_started => {
            Some(ppid)
        }
        _ => None,
    }
}

/// Ancestors of `pid`, nearest first, without `pid` itself, up to 256.
pub fn ancestors(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut cur = pid;
    while out.len() < 256 {
        match parent(cur) {
            Some(p) if p != 0 && p != cur && !out.contains(&p) => {
                out.push(p);
                cur = p;
            }
            _ => break,
        }
    }
    out
}

/// The nearest ancestor of `pid` whose program is `derm.exe` (or `tk.exe`,
/// the old name, as on Unix).
pub fn derm_run_ancestor(pid: u32) -> Option<u32> {
    ancestors(pid).into_iter().find(|p| {
        program(*p)
            .and_then(|path| {
                path.file_stem().map(|n| {
                    matches!(
                        n.to_string_lossy().to_ascii_lowercase().as_str(),
                        "derm" | "tk"
                    )
                })
            })
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn this_process_reads_itself() {
        let me_pid = std::process::id();
        let t = start_time(me_pid).expect("our own start time");
        assert_eq!(start_time(me_pid), Some(t));
        let exe = program(me_pid).unwrap();
        assert_eq!(
            exe.file_name(),
            std::env::current_exe().unwrap().file_name()
        );
        assert_eq!(me(), ident::effective_user());
        assert!(!ancestors(me_pid).contains(&me_pid));
    }

    #[test]
    fn a_child_names_us_as_its_parent() {
        // `cmd /Q` reads commands from its stdin, so it waits until we close
        // it.
        let mut child = std::process::Command::new("cmd")
            .arg("/Q")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let me_pid = std::process::id();
        assert_eq!(parent(child.id()), Some(me_pid));
        assert_eq!(ancestors(child.id()).first(), Some(&me_pid));
        assert!(start_time(me_pid).unwrap() <= start_time(child.id()).unwrap());
        drop(child.stdin.take());
        child.wait().unwrap();
    }

    #[test]
    fn the_peer_is_this_user_and_its_handle_outlives_its_pid() {
        let path = std::path::PathBuf::from(format!(
            r"\\.\pipe\derm-test-peer-{}-{}",
            std::process::id(),
            sys::hex(&sys::random_bytes(4).unwrap())
        ));
        let l = super::super::pipe::bind(&path).unwrap();
        let p2 = path.clone();
        let c = std::thread::spawn(move || {
            let mut c = super::super::pipe::connect(&p2).unwrap();
            // The server peer: this process too.
            let server = of(&c).unwrap();
            assert_eq!(server.pid, Some(std::process::id()));
            c.write_all(b"x").unwrap();
            let mut b = [0u8; 1];
            let _ = c.read(&mut b);
        });
        let (mut s, _) = l.accept().unwrap();
        let p = of(&s).unwrap();
        assert_eq!(p.pid, Some(std::process::id()));
        assert_eq!(p.uid, ident::effective_user());
        let fd = pidfd_of(&s).unwrap();
        assert!(pidfd_alive(&fd));
        let mut b = [0u8; 1];
        s.read_exact(&mut b).unwrap();
        // After a message, impersonation reads the same user.
        assert_eq!(impersonated_user(s.handle()), Some(ident::effective_user()));
        s.write_all(b"y").unwrap();
        c.join().unwrap();
    }

    #[test]
    fn a_child_that_exits_is_not_alive_and_has_no_start_time() {
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit", "0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        // SAFETY: as in `pidfd_of`.
        let fd = sys::owned(unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        })
        .unwrap();
        child.wait().unwrap();
        assert!(!pidfd_alive(&fd));
        assert_eq!(start_time(pid), None);
    }
}
