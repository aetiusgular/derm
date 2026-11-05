//! The daemon's endpoint on Windows: a named pipe (the seam's primitive 1;
//! note AU sections 2.1 and 2.2).
//!
//! Why a pipe: every derm hook is Node, and Node's `net` reaches a local
//! endpoint on Windows only as a pipe under `\\.\pipe\` (Node v26.13.0,
//! `net.html`); Rust's Windows AF_UNIX listener is unstable (issue 150487).
//!
//! The name. Callers pass the path the Unix code binds a socket at
//! (`<runtime>\derm\daemon.sock`). On Windows that path holds a small
//! **pointer file**: the pipe's name, `\\.\pipe\derm-<32 hex>`, drawn at
//! random each time the daemon binds. The pointer file sits in the daemon's
//! private folder (protected, user-only DACL), so only the user reads it;
//! another user cannot learn the name before the daemon starts and so cannot
//! create the pipe first. A path that already is a pipe name is used as it
//! is (tests, or a caller that names one).
//!
//! The pipe: `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance, so a
//! name another process took first fails the bind instead of sharing it
//! (`ERROR_ACCESS_DENIED`; CreateNamedPipe's page); `PIPE_REJECT_REMOTE_CLIENTS`;
//! byte mode; overlapped, so reads and writes take timeouts and a shutdown
//! cancels a blocked read. Its DACL is protected and names the user alone,
//! with `GRGW`. Generic write includes `FILE_CREATE_PIPE_INSTANCE` (named
//! pipe security page), which the daemon needs for its next instance and
//! which lets another process of the same user add an instance; a process
//! of the same user can already replace the pointer file, as one can unlink
//! a Unix socket, so this is the same trust as on Unix (I).
//!
//! The client checks the server before it sends anything: the pipe's owner
//! is one of this process's acceptable owners, and the server process
//! (`GetNamedPipeServerProcessId`) belongs to this user. A squatted name is
//! refused (proposed case AU-1).
//!
//! What a Unix socket does that a pipe does not: `shutdown(Write)` sends no
//! end of file here (the peer sees one when every handle of this end is
//! closed). `shutdown(Read | Both)` cancels this end's blocked reads, which
//! then return 0. No caller on Windows needs a half-close: the only users
//! are the agents' user bridge (`run/user/`, Unix by nature) and TCP.

use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING,
    ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerProcessId, WaitNamedPipeW,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use super::{acl, ident, sys};

/// The prefix of every pipe the daemon draws.
pub const PREFIX: &str = r"\\.\pipe\derm-";
/// A pointer file is read up to this size.
const POINTER_MAX: u64 = 256;
/// How long a client waits for a free instance, in all.
const BUSY_WAIT: Duration = Duration::from_secs(5);
const BUFFER: u32 = 64 * 1024;

/// Whether `path` names a pipe rather than a file.
pub fn is_pipe_name(path: &Path) -> bool {
    let s = path.to_string_lossy();
    let lower = s.to_ascii_lowercase();
    lower.starts_with(r"\\.\pipe\") || lower.starts_with(r"\\?\pipe\")
}

/// Whether `s` is a name the daemon draws: the prefix and 32 lower-case hex
/// digits, nothing else.
pub fn is_drawn_name(s: &str) -> bool {
    s.strip_prefix(PREFIX).is_some_and(|h| {
        h.len() == 32
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// A fresh name: the prefix and 128 random bits.
pub fn draw_name() -> io::Result<String> {
    Ok(format!("{PREFIX}{}", sys::hex(&sys::random_bytes(16)?)))
}

/// What a pointer file must hold: one drawn name, with an optional line end.
pub fn parse_pointer(text: &str) -> Option<&str> {
    let name = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    is_drawn_name(name).then_some(name)
}

/// The protected DACL every instance carries: the user alone, read and
/// write.
fn pipe_sddl() -> io::Result<String> {
    let me = ident::effective_user();
    if !me.is_known() {
        return Err(io::Error::other(
            "cannot make the daemon's pipe: this process's user could not be read",
        ));
    }
    Ok(format!("D:P(A;;GRGW;;;{me})"))
}

fn create_instance(name: &[u16], first: bool, sddl: &str) -> io::Result<OwnedHandle> {
    let sd = acl::Descriptor::from_sddl(sddl)?;
    let sa = sd.attributes();
    let open = PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    // SAFETY: `name` is NUL-terminated; `sa` borrows `sd`, alive here.
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER,
            BUFFER,
            0,
            &sa,
        )
    };
    sys::owned(h).map_err(|e| {
        if first && e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                "the daemon's pipe name is taken by another process (another daemon, or a squatter); refusing to share it",
            )
        } else {
            e
        }
    })
}

/// A listening pipe: one instance waits for the next client at a time.
pub struct Listener {
    name: Vec<u16>,
    shown: String,
    sddl: String,
    pending: Mutex<Option<OwnedHandle>>,
    nonblocking: AtomicBool,
}

/// What `accept` returns beside the stream, as `UnixListener::accept` does.
/// A pipe client has no address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipeAddr;

/// Binds the daemon's endpoint (the seam's `bind`).
pub fn bind(path: &Path) -> io::Result<Listener> {
    let name = if is_pipe_name(path) {
        path.to_string_lossy().into_owned()
    } else {
        if let Some(parent) = path.parent() {
            acl::private_dir(parent)?;
        }
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
            return Err(io::Error::other("socket path is a folder"));
        }
        draw_name()?
    };
    let wide = sys::wide(std::ffi::OsStr::new(&name))?;
    let sddl = pipe_sddl()?;
    let first = create_instance(&wide, true, &sddl)?;
    if !is_pipe_name(path) {
        write_pointer(path, &name)?;
    }
    Ok(Listener {
        name: wide,
        shown: name,
        sddl,
        pending: Mutex::new(Some(first)),
        nonblocking: AtomicBool::new(false),
    })
}

/// Writes the pointer file: a stale one (or a link left in its place) is
/// removed first, then the file is made new, never through a reparse point,
/// and set private.
fn write_pointer(path: &Path, name: &str) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => return Err(io::Error::other("socket path is a folder")),
        Ok(_) => std::fs::remove_file(path)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    super::private_no_follow(&mut options);
    let mut f = options.open(path)?;
    f.write_all(format!("{name}\n").as_bytes())?;
    drop(f);
    acl::set_private(path, false)
}

/// Reads a pointer file: a plain private file of ours holding one drawn name.
pub fn read_pointer(path: &Path) -> io::Result<String> {
    if !acl::is_private_path(path) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is not a private file of this user; not trusting the pipe name it holds",
                path.display()
            ),
        ));
    }
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(POINTER_MAX)
        .read_to_string(&mut text)?;
    parse_pointer(&text)
        .map(str::to_string)
        .ok_or_else(|| io::Error::other(format!("{} does not hold a pipe name", path.display())))
}

impl Listener {
    /// The pipe's name.
    pub fn name(&self) -> &str {
        &self.shown
    }

    /// Waits for the next client (or, when non-blocking, returns
    /// `WouldBlock` when none is waiting).
    pub fn accept(&self) -> io::Result<(Stream, PipeAddr)> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let h = match pending.take() {
            Some(h) => h,
            None => create_instance(&self.name, false, &self.sddl)?,
        };
        let wait = if self.nonblocking.load(Ordering::SeqCst) {
            Some(Duration::ZERO)
        } else {
            None
        };
        // SAFETY: the pipe handle is ours; `run` keeps the OVERLAPPED alive
        // until the operation is over.
        let done = run(sys::raw(&h), wait, |ov, _| unsafe {
            ConnectNamedPipe(sys::raw(&h), ov)
        })?;
        match done {
            Io::Done(_) => {}
            Io::Failed(e) if e == ERROR_PIPE_CONNECTED => {}
            Io::TimedOut => {
                *pending = Some(h);
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Io::Failed(e) => {
                // This instance may be spoiled (a client came and went);
                // the next accept makes a new one.
                return Err(io::Error::from_raw_os_error(e as i32));
            }
        }
        // The next instance now, so a client that comes while this one is
        // served finds one waiting; when it fails, the next accept retries.
        *pending = create_instance(&self.name, false, &self.sddl).ok();
        Ok((Stream::new(h, true), PipeAddr))
    }

    /// An endless iterator of `accept`, as `UnixListener::incoming`.
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.nonblocking.store(on, Ordering::SeqCst);
        Ok(())
    }
}

pub struct Incoming<'a> {
    listener: &'a Listener,
}

impl Iterator for Incoming<'_> {
    type Item = io::Result<Stream>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept().map(|(s, _)| s))
    }
}

/// Connects to the daemon's endpoint (the seam's `connect`): reads the
/// pointer file, opens the pipe for identification only, and refuses a
/// server that is not this user's.
pub fn connect(path: &Path) -> io::Result<Stream> {
    let name = if is_pipe_name(path) {
        path.to_string_lossy().into_owned()
    } else {
        read_pointer(path)?
    };
    let wide = sys::wide(std::ffi::OsStr::new(&name))?;
    let start = std::time::Instant::now();
    let h = loop {
        // SAFETY: `wide` is NUL-terminated. SECURITY_IDENTIFICATION: the
        // server may read who we are, never act as us.
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        match sys::owned(h) {
            Ok(h) => break h,
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && start.elapsed() < BUSY_WAIT =>
            {
                // SAFETY: as above.
                unsafe { WaitNamedPipeW(wide.as_ptr(), 100) };
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no daemon serves {name}"),
                ));
            }
            Err(e) => return Err(e),
        }
    };
    check_server(sys::raw(&h))?;
    Ok(Stream::new(h, false))
}

/// The client's check of the server: the pipe's owner and the serving
/// process's user are ours.
fn check_server(h: HANDLE) -> io::Result<()> {
    let refuse = |why: String| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the daemon's pipe is not this user's ({why}); nothing was sent"),
        )
    };
    let owners = ident::acceptable_owners();
    let s =
        acl::kernel_security(h).map_err(|e| refuse(format!("its owner could not be read: {e}")))?;
    match &s.owner {
        Some(o) if owners.contains(o) => {}
        Some(o) => return Err(refuse(format!("owned by {o}"))),
        None => return Err(refuse("no owner".into())),
    }
    let mut pid = 0u32;
    // SAFETY: a pipe handle we hold; `pid` receives the server's id.
    if unsafe { GetNamedPipeServerProcessId(h, &mut pid) } == 0 {
        return Err(refuse(format!(
            "its server could not be read: {}",
            io::Error::last_os_error()
        )));
    }
    match ident::user_of_process(pid) {
        Some(u) if u == ident::effective_user() => Ok(()),
        Some(u) => Err(refuse(format!("served by {u}"))),
        None => Err(refuse(format!("its server, pid {pid}, could not be read"))),
    }
}

struct Shared {
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    read_shut: AtomicBool,
    write_shut: AtomicBool,
}

/// One connection to or from the daemon's pipe.
pub struct Stream {
    h: OwnedHandle,
    shared: Arc<Shared>,
    server: bool,
}

impl Stream {
    fn new(h: OwnedHandle, server: bool) -> Stream {
        Stream {
            h,
            shared: Arc::new(Shared {
                read_timeout: Mutex::new(None),
                write_timeout: Mutex::new(None),
                read_shut: AtomicBool::new(false),
                write_shut: AtomicBool::new(false),
            }),
            server,
        }
    }

    /// Whether this is the daemon's end.
    pub fn is_server(&self) -> bool {
        self.server
    }

    /// The pipe handle, for the peer reads.
    pub fn handle(&self) -> HANDLE {
        sys::raw(&self.h)
    }

    /// A second handle on the same connection; timeouts and shutdown are
    /// shared, as a socket's are.
    pub fn try_clone(&self) -> io::Result<Stream> {
        Ok(Stream {
            h: self.h.try_clone()?,
            shared: self.shared.clone(),
            server: self.server,
        })
    }

    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        check_timeout(t)?;
        *self
            .shared
            .read_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = t;
        Ok(())
    }

    pub fn set_write_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        check_timeout(t)?;
        *self
            .shared
            .write_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = t;
        Ok(())
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(*self
            .shared
            .read_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner()))
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(*self
            .shared
            .write_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner()))
    }

    /// Ends reading, writing or both on this end. Reads blocked in another
    /// clone return 0. No end of file reaches the peer until every handle
    /// of this end is closed (module comment).
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        use std::net::Shutdown;
        if matches!(how, Shutdown::Write | Shutdown::Both) {
            self.shared.write_shut.store(true, Ordering::SeqCst);
        }
        if matches!(how, Shutdown::Read | Shutdown::Both) {
            self.shared.read_shut.store(true, Ordering::SeqCst);
            // SAFETY: cancels this file object's pending operations; each
            // waiter keeps its OVERLAPPED until it sees the cancel.
            unsafe { CancelIoEx(self.handle(), std::ptr::null()) };
        }
        Ok(())
    }

    fn read_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.shared.read_shut.load(Ordering::SeqCst) || buf.is_empty() {
            return Ok(0);
        }
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let t = *self
            .shared
            .read_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let h = self.handle();
        // SAFETY: the buffer outlives the operation (`run` waits for it).
        let r = run(h, t, |ov, _| unsafe {
            ReadFile(h, buf.as_mut_ptr(), len, std::ptr::null_mut(), ov)
        })?;
        match r {
            Io::Done(n) => Ok(n as usize),
            Io::Failed(e) if e == ERROR_MORE_DATA => Ok(buf.len()),
            Io::Failed(e)
                if e == ERROR_BROKEN_PIPE
                    || e == ERROR_PIPE_NOT_CONNECTED
                    || e == ERROR_NO_DATA =>
            {
                Ok(0)
            }
            Io::Failed(e) if e == ERROR_OPERATION_ABORTED => {
                if self.shared.read_shut.load(Ordering::SeqCst) {
                    Ok(0)
                } else {
                    Err(io::ErrorKind::Interrupted.into())
                }
            }
            Io::Failed(e) => Err(io::Error::from_raw_os_error(e as i32)),
            Io::TimedOut => Err(io::Error::new(io::ErrorKind::TimedOut, "read timed out")),
        }
    }

    fn write_impl(&self, buf: &[u8]) -> io::Result<usize> {
        if self.shared.write_shut.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let t = *self
            .shared
            .write_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let h = self.handle();
        // SAFETY: the buffer outlives the operation (`run` waits for it).
        let r = run(h, t, |ov, _| unsafe {
            WriteFile(h, buf.as_ptr(), len, std::ptr::null_mut(), ov)
        })?;
        match r {
            Io::Done(n) => Ok(n as usize),
            Io::Failed(e)
                if e == ERROR_BROKEN_PIPE
                    || e == ERROR_PIPE_NOT_CONNECTED
                    || e == ERROR_NO_DATA =>
            {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            Io::Failed(e) if e == ERROR_OPERATION_ABORTED => Err(io::ErrorKind::BrokenPipe.into()),
            Io::Failed(e) => Err(io::Error::from_raw_os_error(e as i32)),
            Io::TimedOut => Err(io::Error::new(io::ErrorKind::TimedOut, "write timed out")),
        }
    }
}

fn check_timeout(t: Option<Duration>) -> io::Result<()> {
    if t == Some(Duration::ZERO) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot set a 0 duration timeout",
        ));
    }
    Ok(())
}

impl AsRawHandle for Stream {
    fn as_raw_handle(&self) -> RawHandle {
        self.h.as_raw_handle()
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_impl(buf)
    }
}

impl Read for &Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_impl(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_impl(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_impl(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// How an overlapped operation ended.
enum Io {
    Done(u32),
    Failed(u32),
    TimedOut,
}

/// A manual-reset event for one operation.
struct Event(OwnedHandle);

impl Event {
    fn new() -> io::Result<Event> {
        // SAFETY: an unnamed event with default security.
        let h = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        sys::owned(h).map(Event)
    }
}

/// Starts one overlapped operation with `start` and waits for it, at most
/// `timeout`. On a timeout the operation is cancelled and waited for, so the
/// OVERLAPPED and the caller's buffer are never left in use.
fn run(
    h: HANDLE,
    timeout: Option<Duration>,
    start: impl FnOnce(*mut OVERLAPPED, &mut u32) -> windows_sys::core::BOOL,
) -> io::Result<Io> {
    let ev = Event::new()?;
    // SAFETY: OVERLAPPED is plain data; zero is its documented start state.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = sys::raw(&ev.0);
    let mut n = 0u32;
    let ok = start(&mut ov, &mut n);
    if ok == 0 {
        // SAFETY: reads this thread's last error.
        let e = unsafe { GetLastError() };
        if e != ERROR_IO_PENDING {
            return Ok(Io::Failed(e));
        }
    }
    let ms = match timeout {
        None => INFINITE,
        Some(t) => u32::try_from(t.as_millis().max(1))
            .unwrap_or(INFINITE - 1)
            .min(INFINITE - 1),
    };
    // SAFETY: the event is ours and alive.
    let w = unsafe { WaitForSingleObject(sys::raw(&ev.0), ms) };
    if w != WAIT_OBJECT_0 {
        // Timed out, or the wait failed: cancel this operation and wait for
        // it to end before `ov` goes out of scope.
        // SAFETY: `ov` is the operation's own OVERLAPPED.
        unsafe { CancelIoEx(h, &ov) };
        // SAFETY: bWait TRUE: returns once the operation is over.
        if unsafe { GetOverlappedResult(h, &ov, &mut n, 1) } != 0 {
            return Ok(Io::Done(n));
        }
        // SAFETY: as above.
        let e = unsafe { GetLastError() };
        if w == WAIT_TIMEOUT && e == ERROR_OPERATION_ABORTED {
            return Ok(Io::TimedOut);
        }
        return Ok(Io::Failed(e));
    }
    // SAFETY: the operation is over (its event is set).
    if unsafe { GetOverlappedResult(h, &ov, &mut n, 1) } != 0 {
        Ok(Io::Done(n))
    } else {
        // SAFETY: as above.
        Ok(Io::Failed(unsafe { GetLastError() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn pipe_path(tag: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!(
            r"\\.\pipe\derm-test-{tag}-{}-{}",
            std::process::id(),
            sys::hex(&sys::random_bytes(4).unwrap())
        ))
    }

    #[test]
    fn drawn_names_and_pointer_files_are_strict() {
        let n = draw_name().unwrap();
        assert!(is_drawn_name(&n), "{n}");
        assert_ne!(n, draw_name().unwrap());
        assert_eq!(parse_pointer(&format!("{n}\n")), Some(n.as_str()));
        assert_eq!(parse_pointer(&format!("{n}\r\n")), Some(n.as_str()));
        for bad in [
            String::new(),
            format!("{n}\n\n"),
            format!(" {n}"),
            n.to_uppercase(),
            format!("{n}0"),
            r"\\.\pipe\other".to_string(),
            r"\\server\pipe\derm-00000000000000000000000000000000".to_string(),
        ] {
            assert_eq!(parse_pointer(&bad), None, "{bad:?}");
        }
        assert!(is_pipe_name(Path::new(r"\\.\pipe\x")));
        assert!(is_pipe_name(Path::new(r"\\?\PIPE\x")));
        assert!(!is_pipe_name(Path::new(
            r"C:\Users\me\.derm\run\derm\daemon.sock"
        )));
    }

    #[test]
    fn a_line_goes_both_ways_and_eof_follows_the_servers_close() {
        let path = pipe_path("rw");
        let l = bind(&path).unwrap();
        let p2 = path.clone();
        let client = std::thread::spawn(move || {
            let mut c = connect(&p2).unwrap();
            c.write_all(b"hello\n").unwrap();
            let mut r = BufReader::new(c.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let mut rest = String::new();
            r.read_to_string(&mut rest).unwrap();
            (line, rest)
        });
        let (s, _) = l.accept().unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert_eq!(line, "hello\n");
        (&s).write_all(b"world\nlast\n").unwrap();
        s.shutdown(std::net::Shutdown::Both).unwrap();
        drop(r);
        drop(s);
        let (got, rest) = client.join().unwrap();
        assert_eq!(got, "world\n");
        assert_eq!(
            rest, "last\n",
            "data written before the close is still read"
        );
    }

    #[test]
    fn a_read_times_out_and_a_shutdown_unblocks_a_reader() {
        let path = pipe_path("to");
        let l = bind(&path).unwrap();
        let p2 = path.clone();
        let hold = std::thread::spawn(move || {
            let c = connect(&p2).unwrap();
            std::thread::sleep(Duration::from_millis(1500));
            drop(c);
        });
        let (s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut b = [0u8; 4];
        let e = (&s).read(&mut b).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(s.set_read_timeout(Some(Duration::ZERO)).is_err());
        s.set_read_timeout(None).unwrap();
        let reader = s.try_clone().unwrap();
        let t = std::thread::spawn(move || {
            let mut b = [0u8; 4];
            (&reader).read(&mut b)
        });
        std::thread::sleep(Duration::from_millis(200));
        s.shutdown(std::net::Shutdown::Read).unwrap();
        assert_eq!(t.join().unwrap().unwrap(), 0);
        hold.join().unwrap();
    }

    #[test]
    fn a_name_taken_first_fails_the_bind() {
        // AU-1: the first instance carries FILE_FLAG_FIRST_PIPE_INSTANCE.
        let path = pipe_path("squat");
        let _first = bind(&path).unwrap();
        let e = bind(&path)
            .err()
            .expect("a second first instance must fail");
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse, "{e}");
    }

    #[test]
    fn many_clients_in_turn_and_a_nonblocking_accept() {
        let path = pipe_path("many");
        let l = bind(&path).unwrap();
        l.set_nonblocking(true).unwrap();
        assert_eq!(
            l.accept().err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        l.set_nonblocking(false).unwrap();
        for i in 0..5u8 {
            let p2 = path.clone();
            let c = std::thread::spawn(move || {
                let mut c = connect(&p2).unwrap();
                c.write_all(&[i]).unwrap();
            });
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 1];
            s.read_exact(&mut b).unwrap();
            assert_eq!(b[0], i);
            c.join().unwrap();
        }
    }

    #[test]
    fn a_missing_daemon_is_not_found() {
        let e = connect(&pipe_path("none")).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }
}
