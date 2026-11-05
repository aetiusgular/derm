//! Who we are on Windows (the seam's primitive 3): a user is a SID, read
//! from a token as its canonical string (`ConvertSidToStringSidW`), so two
//! readings of one SID compare equal.
//!
//! The process token's user is both "real" and "effective": Windows has no
//! set-uid, and a thread's impersonation token is never derm's identity
//! (note AU section 2.3). Files a process creates are owned by its token's
//! default owner, which for an administrator's elevated token is the
//! Administrators group, not the user; `acceptable_owners` holds both.

use std::fmt;
use std::os::windows::io::OwnedHandle;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, IsValidSid, TokenElevation, TokenOwner, TokenUser, PSID, TOKEN_ELEVATION,
    TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::sys;

/// A Windows security identifier in its canonical string form
/// (`S-1-5-21-...`), or a marker for a SID that could not be read. A marker
/// starts with `unknown:` and never equals a SID, so a failed read never
/// matches anyone.
///
/// `Copy`, as Unix's `u32` uid is, so callers pass it by value on both
/// systems. The longest SID string is "S-1-" and a 48-bit authority (15
/// digits) then 15 sub-authorities of up to 10 digits each with their
/// dashes: 184 characters (`SID_MAX_SUB_AUTHORITIES` is 15, winnt.h). A
/// longer string is not a SID and is not stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId {
    len: u8,
    bytes: [u8; MAX],
}

const MAX: usize = 190;

impl UserId {
    fn from_ascii(s: &str) -> Option<UserId> {
        if !s.is_ascii() || s.len() > MAX {
            return None;
        }
        let mut bytes = [0u8; MAX];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        Some(UserId {
            len: s.len() as u8,
            bytes,
        })
    }

    /// A SID from its string form. `None` unless it is shaped like one
    /// (`S-` then digits and dashes); used for well-known SIDs and tests.
    pub fn parse(s: &str) -> Option<UserId> {
        let rest = s.strip_prefix("S-")?;
        let ok = !rest.is_empty()
            && rest
                .split('-')
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
        if ok {
            UserId::from_ascii(s)
        } else {
            None
        }
    }

    /// The marker for a SID that could not be read: it equals no SID.
    pub fn unknown(what: &str) -> UserId {
        let what: String = what.chars().filter(char::is_ascii).take(MAX - 8).collect();
        UserId::from_ascii(&format!("unknown:{what}")).unwrap_or(UserId {
            len: 0,
            bytes: [0u8; MAX],
        })
    }

    /// Whether this is a SID read from the system (not a marker).
    pub fn is_known(&self) -> bool {
        self.as_str().starts_with("S-")
    }

    pub fn as_str(&self) -> &str {
        // Only ASCII is ever stored (`from_ascii`).
        std::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserId({:?})", self.as_str())
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for UserId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// LocalSystem.
pub const SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";

/// The string form of a SID the system handed us.
///
/// # Safety
/// `sid` must point to a SID that stays valid for the call.
pub unsafe fn sid_string(sid: PSID) -> Option<UserId> {
    if sid.is_null() || IsValidSid(sid) == 0 {
        return None;
    }
    let mut out: *mut u16 = std::ptr::null_mut();
    if ConvertSidToStringSidW(sid, &mut out) == 0 || out.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *out.add(len) != 0 {
        len += 1;
    }
    let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
    LocalFree(out.cast());
    UserId::parse(&s)
}

/// A token information class, read whole into an 8-byte aligned buffer.
fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: a size query with no buffer; `needed` receives the size.
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 || needed > 64 * 1024 {
        return None;
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let mut got = 0u32;
    // SAFETY: the buffer holds at least `needed` bytes and is 8-aligned.
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut got,
        )
    };
    (ok != 0).then_some(buf)
}

/// The user a token belongs to.
pub fn token_user(token: HANDLE) -> Option<UserId> {
    let buf = token_info(token, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER whose SID points inside it.
    unsafe {
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_string(tu.User.Sid)
    }
}

/// The default owner of objects a token creates.
pub fn token_owner(token: HANDLE) -> Option<UserId> {
    let buf = token_info(token, TokenOwner)?;
    // SAFETY: the buffer holds a TOKEN_OWNER whose SID points inside it.
    unsafe {
        let to = &*(buf.as_ptr() as *const TOKEN_OWNER);
        sid_string(to.Owner)
    }
}

/// Whether a token is elevated (UAC's full administrator token).
pub fn token_elevated(token: HANDLE) -> bool {
    match token_info(token, TokenElevation) {
        // SAFETY: the buffer holds a TOKEN_ELEVATION.
        Some(buf) => unsafe { (*(buf.as_ptr() as *const TOKEN_ELEVATION)).TokenIsElevated != 0 },
        None => false,
    }
}

/// The token of a process handle, for queries.
pub fn process_token(process: HANDLE) -> Option<OwnedHandle> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` receives a handle we then own.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return None;
    }
    sys::owned(token).ok()
}

/// This process's token.
fn own_token() -> Option<OwnedHandle> {
    // SAFETY: the pseudo-handle of the current process needs no closing.
    process_token(unsafe { GetCurrentProcess() })
}

/// The user a running process belongs to, read from its token. `None` when
/// the process is gone or we may not query it.
pub fn user_of_process(pid: u32) -> Option<UserId> {
    // SAFETY: OpenProcess returns a handle we then own, or null.
    let h = sys::owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) }).ok()?;
    let token = process_token(sys::raw(&h))?;
    token_user(sys::raw(&token))
}

fn me() -> &'static UserId {
    static ME: OnceLock<UserId> = OnceLock::new();
    ME.get_or_init(|| {
        own_token()
            .and_then(|t| token_user(sys::raw(&t)))
            .unwrap_or_else(|| UserId::unknown("self"))
    })
}

pub fn real_user() -> UserId {
    *me()
}

pub fn effective_user() -> UserId {
    *me()
}

/// Elevated, or LocalSystem: the Windows forms of running as root.
pub fn is_superuser() -> bool {
    if me().as_str() == SYSTEM {
        return true;
    }
    own_token().is_some_and(|t| token_elevated(sys::raw(&t)))
}

/// The owners a file this process made may carry: its user, and its token's
/// default owner when that differs (an elevated administrator's files are
/// owned by Administrators).
pub fn acceptable_owners() -> Vec<UserId> {
    let mut out = vec![effective_user()];
    if let Some(owner) = own_token().and_then(|t| token_owner(sys::raw(&t))) {
        if !out.contains(&owner) {
            out.push(owner);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sid_string_parses_and_markers_match_nothing() {
        assert!(UserId::parse("S-1-5-21-1-2-3-1001").is_some());
        assert!(UserId::parse("S-1-5-18").is_some());
        for bad in [
            "",
            "S-",
            "S-1--5",
            "s-1-5-18",
            "S-1-5-18 ",
            "S-1-x",
            "unknown:self",
        ] {
            assert!(UserId::parse(bad).is_none(), "{bad:?}");
        }
        let a = UserId::unknown("a");
        assert!(!a.is_known());
        assert_ne!(a, UserId::parse("S-1-5-18").unwrap());
        assert_ne!(UserId::unknown("self"), UserId::unknown("owner"));
        // The longest SID: a 48-bit authority and 15 ten-digit parts.
        let long = format!("S-1-281474976710655{}", "-4294967295".repeat(15));
        assert_eq!(long.len(), 184);
        assert_eq!(
            UserId::parse(&long).map(|u| u.to_string()),
            Some(long.clone())
        );
        assert!(UserId::parse(&format!("{long}-1-2")).is_none());
    }

    #[test]
    fn this_process_has_a_user() {
        let me = effective_user();
        assert!(me.is_known(), "{me}");
        assert_eq!(real_user(), me);
        assert_eq!(user_of_process(std::process::id()), Some(me));
        assert!(acceptable_owners().contains(&me));
        assert_eq!(serde_json::to_string(&me).unwrap(), format!("\"{me}\""));
    }

    #[test]
    fn a_gone_process_has_no_user() {
        // Pid 0 is the idle process, which a user may not open.
        assert_eq!(user_of_process(0), None);
    }
}
