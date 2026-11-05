//! Small helpers over `windows-sys` shared by the Windows platform modules:
//! wide strings, owned handles, the last error, and random bytes.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

/// `s` as a NUL-terminated UTF-16 string. Refuses an interior NUL, which
/// would cut the name short at the system call.
pub fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    if v.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a name holds a NUL character",
        ));
    }
    v.push(0);
    Ok(v)
}

/// A UTF-16 buffer up to its first NUL, as a `String` (lossy).
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Takes ownership of a handle a call returned, or the last error when it
/// returned none (null or `INVALID_HANDLE_VALUE`).
pub fn owned(h: HANDLE) -> io::Result<OwnedHandle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle was just returned to us by a call that hands over
    // ownership, and is neither null nor the invalid value.
    Ok(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) })
}

/// The raw handle of an owned one, for a system call.
pub fn raw(h: &OwnedHandle) -> HANDLE {
    use std::os::windows::io::AsRawHandle;
    h.as_raw_handle() as HANDLE
}

/// `n` bytes from the system's preferred random generator
/// (`BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`).
pub fn random_bytes(n: usize) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut buf = vec![0u8; n];
    let len = u32::try_from(n).map_err(|_| io::Error::other("too many random bytes"))?;
    // SAFETY: the buffer is valid for `len` bytes; a null algorithm handle is
    // allowed with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(io::Error::other(format!(
            "BCryptGenRandom failed (NTSTATUS {status:#x})"
        )));
    }
    Ok(buf)
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
