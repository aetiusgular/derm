//! derm-core on Windows (wave 5, lane Z): the platform seam's Windows side,
//! to the names in `platform/mod.rs`. The research is note AU
//! (`research-notes/AU_windows_platform.md`); each module names the section
//! it follows.
//!
//! - `ident`: who we are, as a SID (primitive 3).
//! - `acl`: files and folders only we may use, as protected user-only DACLs,
//!   and "not a link" as "no reparse point on the path" (primitive 4).
//! - `pipe`: the daemon's endpoint, a named pipe (primitive 1).
//! - `peer`: who is on the other end, and our ancestry (primitive 2).
//! - here: one daemon per user (6) and the host's name (7).
//!
//! Two seam functions take a `std::fs::Metadata`, which on Windows holds no
//! owner and no DACL: `owner` answers a marker that equals no user, and
//! `is_private` answers `false`, so a caller that checks with them refuses
//! (the safe side). `owner_of_path` and `is_private_path` read the real
//! answer from a path; integration's request Z-1 asks the seam for those.

mod acl;
mod ident;
pub mod peer;
mod pipe;
mod sys;

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    LockFileEx, FILE_FLAG_OPEN_REPARSE_POINT, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
};
use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
use windows_sys::Win32::System::IO::OVERLAPPED;

pub use acl::{
    check_light_file, check_light_folder, comparable, is_private_path, only_owner_writes,
    only_owner_writes_file, open_private_file, owned_plain_dir, owner_of_file, owner_of_path,
    set_dacl_sddl,
};
pub use ident::{
    acceptable_owners, effective_user, is_superuser, real_user, trusted_owner, UserId,
};
pub use pipe::{
    bind, connect, draw_name, is_drawn_name, is_pipe_name, parse_pointer, read_pointer, Incoming,
    Listener, PipeAddr, Stream,
};

/// `n` random bytes from the system (the Windows form of reading
/// `/dev/urandom`; request Z-1 asks `token.rs` to use it).
pub fn random_bytes(n: usize) -> io::Result<Vec<u8>> {
    sys::random_bytes(n)
}

/// Case 114 on Windows: Windows Error Reporting, which writes crash dumps,
/// is not invoked for this process or its children (`SetErrorMode` page:
/// `SEM_NOGPFAULTERRORBOX`, "The system does not invoke Windows Error
/// Reporting"; "A child process inherits the error mode of its parent
/// process"). The Windows form of `RLIMIT_CORE` 0.
pub fn no_crash_dumps() {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    };
    // SAFETY: sets this process's error mode; reads and writes no memory.
    unsafe {
        let was = SetErrorMode(0);
        SetErrorMode(was | SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    }
}

/// `platform::no_core_dumps` on Windows (integration, P2-4).
pub fn no_core_dumps() {
    no_crash_dumps()
}

/// Windows' `Metadata` holds no owner: a marker that equals no user.
pub fn owner(_meta: &Metadata) -> UserId {
    UserId::unknown("owner not in metadata")
}

/// Windows' `Metadata` holds no DACL: never private by this test.
pub fn is_private(_meta: &Metadata) -> bool {
    false
}

pub fn owned_private_dir(dir: &Path, user: &UserId) -> bool {
    acl::owned_private_dir(dir, user)
}

pub fn private_dir(dir: &Path) -> io::Result<()> {
    acl::private_dir(dir)
}

pub fn set_private_dir(path: &Path) -> io::Result<()> {
    acl::set_private(path, true)
}

pub fn set_private_file(path: &Path) -> io::Result<()> {
    acl::set_private(path, false)
}

/// Never through a reparse point: the last part of the path is opened
/// itself (`FILE_FLAG_OPEN_REPARSE_POINT`), so a link left there is what is
/// opened, never what it names. A new file takes its folder's inheritable
/// DACL; derm's private folders hold one entry, for the user (`private_dir`).
/// std 1.97 has no stable way to pass a descriptor to `OpenOptions` on
/// Windows (`std/src/os/windows/fs.rs`: `access_mode`, `share_mode`,
/// `custom_flags`, `attributes`, `security_qos_flags`).
pub fn private_no_follow(options: &mut OpenOptions) -> &mut OpenOptions {
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
}

/// One byte at the top of the 64-bit range: `LockFileEx` locks are
/// mandatory, so a lock over the file's content would stop `derm status`
/// reading the pid file. A lock past the end of the file stops no read
/// (SQLite takes its locks the same way, past the data).
const LOCK_AT: u64 = u64::MAX - 1;

pub fn try_lock_exclusive(file: &File) -> bool {
    // SAFETY: OVERLAPPED is plain data; only its offset is used.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.Anonymous.Anonymous.Offset = LOCK_AT as u32;
    ov.Anonymous.Anonymous.OffsetHigh = (LOCK_AT >> 32) as u32;
    // SAFETY: a file handle the caller owns; one byte; fails at once when
    // another handle holds it.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut ov,
        )
    };
    ok != 0
}

pub fn host_name() -> String {
    let mut len = 0u32;
    // SAFETY: a size query; `len` receives the size with its NUL.
    unsafe { GetComputerNameExW(ComputerNameDnsHostname, std::ptr::null_mut(), &mut len) };
    if len == 0 || len > 1024 {
        return String::new();
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: the buffer holds `len` characters.
    let ok = unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return String::new();
    }
    sys::from_wide(&buf[..len as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_is_held_once_and_stops_no_read() {
        let path = std::env::temp_dir().join(format!("derm-wlk-{}", std::process::id()));
        std::fs::write(&path, b"1234\n").unwrap();
        let a = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let b = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(try_lock_exclusive(&a));
        assert!(!try_lock_exclusive(&b));
        // The pid file stays readable while the daemon holds the lock.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "1234\n");
        drop(a);
        assert!(try_lock_exclusive(&b));
        drop(b);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_host_has_a_name_and_metadata_answers_safe() {
        assert!(!host_name().is_empty());
        let m = std::fs::metadata(std::env::temp_dir()).unwrap();
        assert!(!is_private(&m));
        assert_ne!(owner(&m), effective_user());
        assert!(!owner(&m).is_known());
        assert_eq!(random_bytes(16).unwrap().len(), 16);
        assert_ne!(random_bytes(16).unwrap(), random_bytes(16).unwrap());
    }

    #[test]
    fn the_seam_binds_through_a_pointer_file_in_a_private_folder() {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let base = std::path::PathBuf::from(
            base.to_string_lossy()
                .strip_prefix(r"\\?\")
                .unwrap_or(&base.to_string_lossy())
                .to_string(),
        );
        let root = base.join(format!("derm-wsk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("derm").join("daemon.sock");
        let first = bind(&path).unwrap();
        let name = read_pointer(&path).unwrap();
        assert!(is_drawn_name(&name));
        assert_eq!(first.name(), name);
        assert!(owned_private_dir(path.parent().unwrap(), &effective_user()));
        assert!(is_private_path(&path));
        // A second daemon on the same path draws a new name and replaces the
        // pointer; the first one's pipe is no longer reached through it.
        let second = bind(&path).unwrap();
        assert_ne!(second.name(), name);
        let p2 = path.clone();
        let c = std::thread::spawn(move || connect(&p2).map(|_| ()));
        let (_s, _) = second.accept().unwrap();
        c.join().unwrap().unwrap();
        drop(first);
        // A folder in the endpoint's place is refused.
        std::fs::create_dir_all(root.join("dir.sock")).unwrap();
        assert!(bind(&root.join("dir.sock")).is_err());
        // A pointer file with something else in it is not trusted.
        let bad = root.join("derm").join("bad.sock");
        std::fs::write(&bad, b"\\\\.\\pipe\\elsewhere\n").unwrap();
        set_private_file(&bad).unwrap();
        assert!(connect(&bad).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
