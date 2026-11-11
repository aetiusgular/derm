//! The Windows calls the service and the daemon's client make (windows-sys
//! 0.61.2). Each says what it rests on; the lane's research is
//! `tests/windows/5bE/RESEARCH.md`.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::Duration;

use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING,
    ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetTokenInformation, LookupAccountNameW,
    RevertToSelf, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFinalPathNameByHandleW, ReadFile, WriteFile, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_NT,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    WaitForSingleObject,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use crate::acl::{Ace, Security};

/// `SystemProcessIdInformation` (phnt `ntexapi.h` at 53fbbdc, line 2361:
/// the 88th class; windows-sys 0.61.2 names no constant for it).
const SYSTEM_PROCESS_ID_INFORMATION: i32 = 88;

/// phnt `ntexapi.h` lines 3892-3896.
#[repr(C)]
struct ProcessIdInformation {
    process_id: HANDLE,
    image_name: UNICODE_STRING,
}

pub fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

pub fn wide_str(s: &str) -> Vec<u16> {
    wide(OsStr::new(s))
}

pub fn owned(h: HANDLE) -> io::Result<OwnedHandle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle a Win32 call just returned to us, owned from here.
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

fn raw(h: &OwnedHandle) -> HANDLE {
    h.as_raw_handle() as HANDLE
}

/// A SID as its string (`S-1-...`).
fn sid_string(sid: PSID) -> Option<String> {
    let mut out: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid SID from the caller; `out` is LocalAlloc'd for us.
    if unsafe { ConvertSidToStringSidW(sid, &mut out) } == 0 || out.is_null() {
        return None;
    }
    let mut n = 0;
    // SAFETY: a NUL-terminated string from ConvertSidToStringSidW.
    while unsafe { *out.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `n` characters were just read.
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, n) });
    // SAFETY: freed once, as the function's page asks.
    unsafe { LocalFree(out.cast()) };
    Some(s)
}

/// The SID of an account name (`DOMAIN\name`, `name`, `NT SERVICE\x`).
pub fn sid_of_account(name: &str) -> Option<String> {
    if name.is_empty() || name.len() > 512 {
        return None;
    }
    let w = wide_str(name);
    let mut sid = vec![0u8; 256];
    let mut sid_len = sid.len() as u32;
    let mut dom = vec![0u16; 512];
    let mut dom_len = dom.len() as u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: buffers sized as passed; a null system name is this machine.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            w.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return None;
    }
    sid_string(sid.as_mut_ptr().cast())
}

/// The user SID of a token.
fn token_user(token: HANDLE) -> Option<String> {
    let mut len = 0u32;
    // SAFETY: a size query.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    // SAFETY: reads this thread's last error.
    if len == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: the buffer holds `len` bytes, 8-aligned.
    if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0
    {
        return None;
    }
    // SAFETY: GetTokenInformation wrote a TOKEN_USER at the buffer's start.
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    sid_string(user.User.Sid)
}

/// This process's user SID (the service's account).
pub fn own_sid() -> Option<String> {
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: our own process; the token is closed by `owned`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) } == 0 {
        return None;
    }
    let t = owned(t).ok()?;
    token_user(raw(&t))
}

/// The pipe client's user SID, through impersonation, reverted at once.
/// Only after the server has read from the pipe (1368 before: note BC
/// section 11, run). A failed revert ends the process: the thread would
/// otherwise act as the client (ImpersonateNamedPipeClient's page).
pub fn client_sid(pipe: HANDLE) -> Option<String> {
    // SAFETY: a server pipe handle the caller holds.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return None;
    }
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: OpenAsSelf: the token is opened with the service's rights.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut t) };
    // SAFETY: ends the impersonation started above.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    if opened == 0 {
        return None;
    }
    let t = owned(t).ok()?;
    token_user(raw(&t))
}

pub fn client_pid(pipe: HANDLE) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: a pipe handle the caller holds.
    (unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } != 0).then_some(pid)
}

pub fn server_pid(pipe: HANDLE) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: a pipe handle the caller holds.
    (unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) } != 0).then_some(pid)
}

/// A process's image as an NT path (`\Device\HarddiskVolume3\...`), without
/// opening the process: `NtQuerySystemInformation` class 88, as System
/// Informer's `PhGetProcessImageFileNameById` calls it (nativeprocess.c at
/// 09d3b9a): on a length mismatch the needed size is in `MaximumLength`.
pub fn image_of_pid(pid: u32) -> Option<String> {
    let mut size: u16 = 0x200;
    for _ in 0..2 {
        let mut buf = vec![0u16; usize::from(size).div_ceil(2)];
        let mut info = ProcessIdInformation {
            process_id: pid as usize as HANDLE,
            image_name: UNICODE_STRING {
                Length: 0,
                MaximumLength: size,
                Buffer: buf.as_mut_ptr(),
            },
        };
        // SAFETY: the struct and its buffer live across the call.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_ID_INFORMATION,
                (&mut info as *mut ProcessIdInformation).cast(),
                std::mem::size_of::<ProcessIdInformation>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            size = info.image_name.MaximumLength;
            continue;
        }
        if status < 0 {
            return None;
        }
        let n = usize::from(info.image_name.Length) / 2;
        return Some(String::from_utf16_lossy(&buf[..n.min(buf.len())]));
    }
    None
}

/// A file's or folder's path as an NT path (`GetFinalPathNameByHandleW`,
/// `VOLUME_NAME_NT`), links followed, for comparing with [`image_of_pid`].
pub fn nt_path(path: &Path) -> Option<String> {
    let w = wide(path.as_os_str());
    // SAFETY: NUL-terminated; attributes only; a folder needs backup
    // semantics to open.
    let h = owned(unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    })
    .ok()?;
    let mut buf = vec![0u16; 32 * 1024];
    // SAFETY: the buffer's length in characters.
    let n = unsafe {
        GetFinalPathNameByHandleW(raw(&h), buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_NT)
    } as usize;
    (n > 0 && n < buf.len()).then(|| String::from_utf16_lossy(&buf[..n]))
}

/// Reads the owner and the DACL a security descriptor holds, then frees it.
fn read_descriptor(owner: PSID, dacl: *mut ACL, sd: PSECURITY_DESCRIPTOR) -> Security {
    let owner_s = (!owner.is_null()).then(|| sid_string(owner)).flatten();
    let aces = if dacl.is_null() {
        None
    } else {
        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: a DACL inside `sd`, alive until LocalFree below.
        let ok = unsafe {
            GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        let mut out = Vec::new();
        if ok == 0 {
            // An unreadable list is read as one entry this does not read.
            out.push(Ace {
                kind: u8::MAX,
                flags: 0,
                mask: 0,
                sid: None,
            });
        }
        let count = if ok != 0 { info.AceCount } else { 0 };
        for i in 0..count {
            let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: an index below AceCount.
            if unsafe { GetAce(dacl, i, &mut p) } == 0 || p.is_null() {
                out.push(Ace {
                    kind: u8::MAX,
                    flags: 0,
                    mask: 0,
                    sid: None,
                });
                continue;
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let h = unsafe { &*(p as *const ACE_HEADER) };
            let (mask, sid) = if h.AceType == crate::acl::ALLOWED || h.AceType == crate::acl::DENIED
            {
                // SAFETY: allowed and denied ACEs share ACCESS_ALLOWED_ACE's
                // layout; the SID starts at SidStart.
                let a = unsafe { &*(p as *const ACCESS_ALLOWED_ACE) };
                let sid_ptr = (&a.SidStart as *const u32) as PSID;
                (a.Mask, sid_string(sid_ptr))
            } else {
                (0, None)
            };
            out.push(Ace {
                kind: h.AceType,
                flags: h.AceFlags,
                mask,
                sid,
            });
        }
        Some(out)
    };
    if !sd.is_null() {
        // SAFETY: the descriptor the Get*SecurityInfo call allocated.
        unsafe { LocalFree(sd.cast()) };
    }
    Security {
        owner: owner_s,
        dacl: aces,
    }
}

/// A file's or folder's owner and DACL, by path.
pub fn security_of_path(path: &Path) -> io::Result<Security> {
    let w = wide(path.as_os_str());
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: out pointers into `sd`, freed by read_descriptor.
    let e = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if e != 0 {
        return Err(io::Error::from_raw_os_error(e as i32));
    }
    Ok(read_descriptor(owner, dacl, sd))
}

/// A kernel object's owner and DACL, by handle (the pipe).
pub fn security_of_handle(h: HANDLE) -> io::Result<Security> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: as above.
    let e = unsafe {
        GetSecurityInfo(
            h,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if e != 0 {
        return Err(io::Error::from_raw_os_error(e as i32));
    }
    Ok(read_descriptor(owner, dacl, sd))
}

/// A security descriptor made from SDDL, freed on drop.
pub struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Descriptor> {
        let w = wide_str(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: NUL-terminated; `sd` is LocalAlloc'd for us.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(sd))
    }

    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: freed once.
        unsafe { LocalFree(self.0.cast()) };
    }
}

/// An overlapped pipe handle with one read and one write in flight at
/// most, each with a timeout.
pub struct Pipe {
    h: OwnedHandle,
    read_ev: OwnedHandle,
    write_ev: OwnedHandle,
}

/// What a timed read gives.
pub enum Got {
    Bytes(usize),
    TimedOut,
    Closed,
}

fn event() -> io::Result<OwnedHandle> {
    // SAFETY: an unnamed manual-reset event.
    owned(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })
}

impl Pipe {
    pub fn new(h: OwnedHandle) -> io::Result<Pipe> {
        Ok(Pipe {
            h,
            read_ev: event()?,
            write_ev: event()?,
        })
    }

    pub fn handle(&self) -> HANDLE {
        raw(&self.h)
    }

    /// Waits for an overlapped operation; on a timeout it is cancelled and
    /// waited for, so `ov` and the buffer are free when this returns.
    fn finish(&self, ov: &mut OVERLAPPED, started: i32, wait: Option<Duration>) -> io::Result<Got> {
        let h = raw(&self.h);
        if started == 0 {
            // SAFETY: reads this thread's last error.
            let e = unsafe { GetLastError() };
            if e == ERROR_BROKEN_PIPE || e == ERROR_NO_DATA {
                return Ok(Got::Closed);
            }
            if e != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(e as i32));
            }
            let ms = wait.map_or(u32::MAX, |d| {
                d.as_millis().min(u128::from(u32::MAX - 1)) as u32
            });
            // SAFETY: the event this operation signals.
            let w = unsafe { WaitForSingleObject(ov.hEvent, ms) };
            if w == WAIT_TIMEOUT {
                // SAFETY: cancels only this operation, then waits it out.
                unsafe { CancelIoEx(h, ov) };
            } else if w != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut n = 0u32;
        // SAFETY: waits for the operation (done or cancelled) to finish.
        if unsafe { GetOverlappedResult(h, ov, &mut n, 1) } == 0 {
            // SAFETY: as above.
            let e = unsafe { GetLastError() };
            return match e {
                ERROR_OPERATION_ABORTED => Ok(Got::TimedOut),
                ERROR_BROKEN_PIPE | ERROR_NO_DATA => Ok(Got::Closed),
                _ => Err(io::Error::from_raw_os_error(e as i32)),
            };
        }
        Ok(Got::Bytes(n as usize))
    }

    /// Reads what is there, waiting at most `wait`.
    pub fn read(&self, buf: &mut [u8], wait: Option<Duration>) -> io::Result<Got> {
        // SAFETY: zeroed OVERLAPPED is its documented start state.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = raw(&self.read_ev);
        let len = buf.len().min(u32::MAX as usize) as u32;
        // SAFETY: `buf` and `ov` outlive the operation (`finish` waits).
        let started = unsafe {
            ReadFile(
                raw(&self.h),
                buf.as_mut_ptr(),
                len,
                std::ptr::null_mut(),
                &mut ov,
            )
        };
        match self.finish(&mut ov, started, wait)? {
            Got::Bytes(0) => Ok(Got::Closed),
            g => Ok(g),
        }
    }

    /// Writes all of `data`, each piece waiting at most `wait`.
    pub fn write_all(&self, mut data: &[u8], wait: Duration) -> io::Result<()> {
        while !data.is_empty() {
            // SAFETY: as in `read`.
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            ov.hEvent = raw(&self.write_ev);
            let len = data.len().min(1 << 20) as u32;
            // SAFETY: `data` and `ov` outlive the operation.
            let started = unsafe {
                WriteFile(
                    raw(&self.h),
                    data.as_ptr(),
                    len,
                    std::ptr::null_mut(),
                    &mut ov,
                )
            };
            match self.finish(&mut ov, started, Some(wait))? {
                Got::Bytes(n) if n > 0 => data = &data[n..],
                Got::Bytes(_) | Got::TimedOut => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the pipe took no data",
                    ))
                }
                Got::Closed => return Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
        Ok(())
    }

    /// Waits for a client on a server instance (overlapped
    /// `ConnectNamedPipe`), at most `wait`: `true` connected, `false` no one
    /// came (the instance can wait again, as derm-core's `pipe::accept`
    /// keeps it). `ERROR_PIPE_CONNECTED`: a client came before the call. A
    /// client that came and went spoils the instance: an error.
    pub fn accept(&self, wait: Option<Duration>) -> io::Result<bool> {
        // SAFETY: as in `read`.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = raw(&self.read_ev);
        // SAFETY: `ov` outlives the operation.
        let started =
            unsafe { windows_sys::Win32::System::Pipes::ConnectNamedPipe(raw(&self.h), &mut ov) };
        if started == 0 {
            // SAFETY: reads this thread's last error.
            if unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                return Ok(true);
            }
        }
        match self.finish(&mut ov, started, wait)? {
            Got::Bytes(_) => Ok(true),
            Got::TimedOut => Ok(false),
            Got::Closed => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

/// Opens a pipe by name as a client: read, and write data only (no
/// `FILE_APPEND_DATA`, which is `FILE_CREATE_PIPE_INSTANCE` on a pipe;
/// "Named Pipe Security and Access Rights"), for identification only.
pub fn open_pipe(name: &str) -> io::Result<OwnedHandle> {
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_WRITE_DATA, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    let w = wide_str(name);
    // SAFETY: NUL-terminated name.
    owned(unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ | FILE_WRITE_DATA | READ_CONTROL,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        )
    })
}

/// Random bytes from the system (BCryptGenRandom, through derm-core).
pub fn random_hex(n: usize) -> io::Result<String> {
    let b = derm_core::platform::windows::random_bytes(n)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}
