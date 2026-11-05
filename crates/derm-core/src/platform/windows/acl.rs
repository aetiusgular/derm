//! Files and folders only we may use, on Windows (the seam's primitive 4;
//! note AU section 5).
//!
//! Unix holds a private file at 0600 and a folder at 0700. Here the same is
//! a **protected** DACL with one entry, for the user: protected so no
//! permission inherited from a parent (srt's install grants its sandbox
//! account read on the whole profile, note AU section 3.2) reaches it, and
//! on a folder inheritable, so files made inside take the same one entry.
//!
//! The check (`is_private_handle`) reads the object's owner and DACL and
//! accepts it when the DACL is present, holds only allow and deny entries of
//! the plain kinds (inherited or not: an srt profile grant inherited into a
//! file is refused by its entry, not by the missing protection), and every allow entry names the user, the
//! object's owner, LocalSystem or Administrators. The last two can read any
//! file anyway (as root can on Unix); every other principal is refused,
//! whatever the right, read included (Win32-OpenSSH's
//! `check_secure_file_permission` refuses only write rights; a token file
//! must not be read either).
//!
//! "Not a link" becomes "no reparse point": the object is opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT` and refused when it is one, and the whole
//! path is compared with the final path the system resolves for the handle,
//! so a junction or symbolic link anywhere on the path, or an 8.3 short
//! name, refuses (proposed case AU-2; refusing an 8.3 name is the safe side).

use std::io;
use std::os::windows::io::OwnedHandle;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileBasicInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};

use super::ident::{self, UserId};
use super::sys;

/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_DENIED_ACE_TYPE` (winnt.h); every
/// other kind (object, callback, compound) is refused by the check.
const ACCESS_ALLOWED: u8 = 0;
const ACCESS_DENIED: u8 = 1;

/// A security descriptor the system built from SDDL, freed on drop.
pub struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Descriptor> {
        let w = sys::wide(std::ffi::OsStr::new(sddl))?;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated; `sd` receives a LocalAlloc'd
        // descriptor we free on drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(sd))
    }

    /// The descriptor as `SECURITY_ATTRIBUTES` for a create call; borrows
    /// `self`, which must outlive the call.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: the descriptor is valid; the out pointers are ours.
        let ok =
            unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) };
        if ok == 0 || present == 0 || dacl.is_null() {
            return Err(io::Error::other("the descriptor has no DACL"));
        }
        Ok(dacl)
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the system with LocalAlloc; freed once.
        unsafe { LocalFree(self.0.cast()) };
    }
}

/// The SDDL of a protected DACL that lets `user` alone have full access. On
/// a folder the entry is inherited by files and folders made inside it
/// (`OICI`). Refuses a marker in place of a SID.
pub fn user_only_sddl(user: &UserId, folder: bool) -> io::Result<String> {
    if !user.is_known() {
        return Err(io::Error::other(
            "cannot make a private file: this process's user could not be read",
        ));
    }
    let flags = if folder { "OICI" } else { "" };
    Ok(format!("D:P(A;{flags};FA;;;{user})"))
}

/// One entry of a DACL, as the check reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: u8,
    pub mask: u32,
    pub who: Option<UserId>,
}

/// An object's owner and DACL, as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Security {
    pub owner: Option<UserId>,
    /// `None` when the object has no DACL at all (everyone has every right).
    pub dacl: Option<Vec<Entry>>,
    pub protected: bool,
}

/// Whether `s` keeps everyone out but `user` (and the object's owner,
/// LocalSystem and Administrators), by the entries the object has now.
/// Inherited entries count as any other: a file made inside a private folder
/// is private by the folder's one entry, as a Unix file is by its mode bits
/// at the time of the check. Whether the DACL is protected does not change
/// the answer: only the owner (or an administrator) can widen the folder it
/// inherits from, and the owner can widen the file itself anyway. derm's own
/// `set_private` still protects what it writes (Windows CI, 5 Nov: a file
/// made in a private folder is not protected, so the strict reading refused
/// every such file).
pub fn is_private_security(s: &Security, user: &UserId) -> bool {
    let Some(dacl) = &s.dacl else {
        return false;
    };
    let allowed = |who: &UserId| {
        who == user
            || s.owner.as_ref() == Some(who)
            || who.as_str() == ident::SYSTEM
            || who.as_str() == ident::ADMINISTRATORS
    };
    dacl.iter().all(|e| match e.kind {
        ACCESS_DENIED => true,
        ACCESS_ALLOWED => e.who.as_ref().is_some_and(allowed),
        _ => false,
    })
}

/// The rights that change a file or folder or what it holds (Win32-OpenSSH's
/// `check_secure_file_permission` list, with the generic forms and
/// `FILE_DELETE_CHILD` added for folders).
pub const WRITE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA
    | 0x0000_0004 // FILE_APPEND_DATA
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Whether no one but `user` (and the owner, LocalSystem, Administrators)
/// may change the object: the Windows form of Unix's "no group or other
/// write bit". Others may read. Inherited entries count as any other.
pub fn only_owner_writes_security(s: &Security, user: &UserId) -> bool {
    let Some(dacl) = &s.dacl else {
        return false;
    };
    let trusted = |who: &UserId| {
        who == user
            || s.owner.as_ref() == Some(who)
            || who.as_str() == ident::SYSTEM
            || who.as_str() == ident::ADMINISTRATORS
    };
    dacl.iter().all(|e| match e.kind {
        ACCESS_DENIED => true,
        ACCESS_ALLOWED => match &e.who {
            Some(who) => trusted(who) || e.mask & WRITE_RIGHTS == 0,
            None => false,
        },
        _ => false,
    })
}

/// Reads the owner and DACL of an open object.
pub fn read_security(h: HANDLE, kind: SE_OBJECT_TYPE) -> io::Result<Security> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the out pointers point into `sd`, which we free below.
    let err = unsafe {
        GetSecurityInfo(
            h,
            kind,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let out = (|| {
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: `sd` is the descriptor GetSecurityInfo returned.
        unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) };
        // SAFETY: `owner` points into `sd`.
        let owner = unsafe { ident::sid_string(owner) };
        let entries = if dacl.is_null() {
            None
        } else {
            // SAFETY: `dacl` points into `sd`.
            Some(unsafe { entries(dacl) }?)
        };
        Ok(Security {
            owner,
            dacl: entries,
            protected: control & SE_DACL_PROTECTED != 0,
        })
    })();
    // SAFETY: allocated by GetSecurityInfo with LocalAlloc; freed once.
    unsafe { LocalFree(sd.cast()) };
    out
}

/// The entries of a DACL.
///
/// # Safety
/// `dacl` must point to a valid ACL.
unsafe fn entries(dacl: *const ACL) -> io::Result<Vec<Entry>> {
    let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    if GetAclInformation(
        dacl,
        (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    ) == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::with_capacity(info.AceCount as usize);
    for i in 0..info.AceCount {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        if GetAce(dacl, i, &mut ace) == 0 || ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        let header = &*(ace as *const ACE_HEADER);
        let (mask, who) = if header.AceType == ACCESS_ALLOWED || header.AceType == ACCESS_DENIED {
            // Allowed and denied entries share the layout: header, mask, SID.
            let a = &*(ace as *const ACCESS_ALLOWED_ACE);
            let sid = std::ptr::addr_of!(a.SidStart) as PSID;
            (a.Mask, ident::sid_string(sid))
        } else {
            (0, None)
        };
        out.push(Entry {
            kind: header.AceType,
            mask,
            who,
        });
    }
    Ok(out)
}

/// Opens `path` itself (never what a reparse point names) for `access`, and
/// refuses it when it is a reparse point or not of the kind asked.
pub fn open_plain(path: &Path, access: u32, folder: bool) -> io::Result<OwnedHandle> {
    let w = sys::wide(path.as_os_str())?;
    // SAFETY: `w` is NUL-terminated; the handle returned is ours.
    let h = sys::owned(unsafe {
        CreateFileW(
            w.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    })?;
    let attrs = attributes(sys::raw(&h))?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(format!(
            "{} is a link or junction",
            path.display()
        )));
    }
    let is_folder = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_folder != folder {
        return Err(io::Error::other(format!(
            "{} is not a {}",
            path.display(),
            if folder { "folder" } else { "file" }
        )));
    }
    Ok(h)
}

fn attributes(h: HANDLE) -> io::Result<u32> {
    let mut info: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is the size the class asks for.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h,
            FileBasicInfo,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.FileAttributes)
}

/// The path the system resolves for an open handle (`\\?\C:\...`).
pub fn final_path(h: HANDLE) -> io::Result<String> {
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: the buffer is valid for its length. Flags 0: normalized
        // name, with a drive letter.
        let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, 0) };
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if (n as usize) < buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..n as usize]));
        }
        if n as usize > 32 * 1024 {
            return Err(io::Error::other("a path longer than 32,768 characters"));
        }
        buf.resize(n as usize + 1, 0);
    }
}

/// A path in one comparable form: no `\\?\` or `\\?\UNC\` prefix, `\`
/// separators, no trailing separator, lower case. Windows compares names
/// without case; `to_lowercase` folds more than NTFS's table does, so two
/// names may compare equal here that NTFS keeps apart, never the reverse
/// for ASCII (I; the check refuses on a mismatch only, so the error is on
/// the safe side for every name a mismatch catches).
pub fn comparable(p: &str) -> String {
    let p = p.replace('/', "\\");
    let p = if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = p.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        p
    };
    p.trim_end_matches('\\').to_lowercase()
}

/// Whether the handle's final path is the path we asked for: no link,
/// junction or other reparse point anywhere on it. The asked path is first
/// given its long names (`GetLongPathNameW`), since an 8.3 short name is an
/// alias of the same entry, not a redirect (GitHub's Windows runners keep
/// `%TEMP%` under one, `RUNNER~1`); a reparse point keeps its own name there
/// and the system's final path names its target, so it still differs (I;
/// the function's page is silent on reparse points). A substituted drive
/// differs too, and is refused (the safe side).
pub fn path_is_plain(h: HANDLE, asked: &Path) -> io::Result<bool> {
    let asked: PathBuf = std::path::absolute(asked)?;
    let long = long_name(&asked).unwrap_or_else(|| asked.to_string_lossy().into_owned());
    let resolved = final_path(h)?;
    Ok(comparable(&resolved) == comparable(&long))
}

/// The path with its long names, or `None` when the system cannot say.
fn long_name(path: &Path) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;
    let w = sys::wide(path.as_os_str()).ok()?;
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `w` is NUL-terminated; the buffer is valid for its length.
        let n = unsafe { GetLongPathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            return None;
        }
        if (n as usize) < buf.len() {
            return Some(String::from_utf16_lossy(&buf[..n as usize]));
        }
        if n as usize > 32 * 1024 {
            return None;
        }
        buf.resize(n as usize + 1, 0);
    }
}

/// Sets a protected, user-only DACL on an open object, then reads it back
/// and refuses when the object is still not private (a file system that
/// keeps no DACL, or one the set did not reach, fails here, not later).
pub fn set_user_only(h: HANDLE, kind: SE_OBJECT_TYPE, folder: bool) -> io::Result<()> {
    let me = ident::effective_user();
    let sd = Descriptor::from_sddl(&user_only_sddl(&me, folder)?)?;
    let dacl = sd.dacl()?;
    // SAFETY: the handle was opened with WRITE_DAC; `dacl` lives in `sd`.
    let err = unsafe {
        SetSecurityInfo(
            h,
            kind,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if err != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let after = read_security(h, kind)?;
    if !after.protected || !is_private_security(&after, &me) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the private permissions did not take (the file system kept another DACL)",
        ));
    }
    Ok(())
}

/// The seam's `owned_private_dir`: a folder, no reparse point on its path,
/// owned by `user` (or by this process's default owner when `user` is us),
/// private.
pub fn owned_private_dir(dir: &Path, user: &UserId) -> bool {
    let Ok(h) = open_plain(dir, READ_CONTROL, true) else {
        return false;
    };
    if !path_is_plain(sys::raw(&h), dir).unwrap_or(false) {
        return false;
    }
    let Ok(s) = read_security(sys::raw(&h), SE_FILE_OBJECT) else {
        return false;
    };
    let owners = if *user == ident::effective_user() {
        ident::acceptable_owners()
    } else {
        vec![*user]
    };
    s.owner.as_ref().is_some_and(|o| owners.contains(o)) && is_private_security(&s, user)
}

/// Whether the file or folder at `path` is a plain object of ours that only
/// we may use. The path form of the seam's `is_private` (std's `Metadata`
/// holds no owner or DACL on Windows).
pub fn is_private_path(path: &Path) -> bool {
    let me = ident::effective_user();
    let folder = std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir());
    let Ok(h) = open_plain(path, READ_CONTROL, folder) else {
        return false;
    };
    if !path_is_plain(sys::raw(&h), path).unwrap_or(false) {
        return false;
    }
    let Ok(s) = read_security(sys::raw(&h), SE_FILE_OBJECT) else {
        return false;
    };
    s.owner
        .as_ref()
        .is_some_and(|o| ident::acceptable_owners().contains(o))
        && is_private_security(&s, &me)
}

/// Whether `path` is a file (one link) or folder of ours, no reparse point
/// on its path, that no one else may change: the Windows form of the Unix
/// checks "owned by me, no group or other write bit" (`nlink == 1` for a
/// file), as `derm-tap/src/settings.rs` and the computer-use relay make them.
pub fn only_owner_writes(path: &Path) -> bool {
    let folder = std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir());
    let Ok(h) = open_plain(path, READ_CONTROL, folder) else {
        return false;
    };
    if !path_is_plain(sys::raw(&h), path).unwrap_or(false) {
        return false;
    }
    if !folder && links(sys::raw(&h)) != Some(1) {
        return false;
    }
    let Ok(s) = read_security(sys::raw(&h), SE_FILE_OBJECT) else {
        return false;
    };
    s.owner
        .as_ref()
        .is_some_and(|o| ident::acceptable_owners().contains(o))
        && only_owner_writes_security(&s, &ident::effective_user())
}

/// Whether `path` is a folder (not a reparse point) that this user owns: the
/// Windows form of "a real folder, `uid` mine" (`derm run`'s
/// `no_link_above`). Checked on the folder itself, opened without following.
pub fn owned_plain_dir(path: &Path) -> bool {
    let Ok(h) = open_plain(path, READ_CONTROL, true) else {
        return false;
    };
    read_security(sys::raw(&h), SE_FILE_OBJECT)
        .ok()
        .and_then(|s| s.owner)
        .is_some_and(|o| ident::acceptable_owners().contains(&o))
}

/// Opens a regular file of ours that no one else may use, for reading: the
/// file itself (never what a reparse point names), checked on the open
/// handle, so nothing can change between the check and the read (the Unix
/// code's `O_NOFOLLOW` open and `fstat`, review W2-S9).
pub fn open_private_file(path: &Path) -> io::Result<std::fs::File> {
    use windows_sys::Win32::Foundation::GENERIC_READ;
    let h = open_plain(path, GENERIC_READ | READ_CONTROL, false)?;
    let refuse = |why: &str| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} {why}", path.display()),
        )
    };
    if !path_is_plain(sys::raw(&h), path)? {
        return Err(refuse("has a link, junction or short name on its path"));
    }
    let s = read_security(sys::raw(&h), SE_FILE_OBJECT)?;
    if !s
        .owner
        .as_ref()
        .is_some_and(|o| ident::acceptable_owners().contains(o))
    {
        return Err(refuse("is not this user's"));
    }
    if !is_private_security(&s, &ident::effective_user()) {
        return Err(refuse("may be used by another user"));
    }
    Ok(std::fs::File::from(h))
}

fn links(h: HANDLE) -> Option<u32> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: plain data, filled by the call.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a file handle we hold.
    (unsafe { GetFileInformationByHandle(h, &mut info) } != 0).then_some(info.nNumberOfLinks)
}

/// The owner of the file or folder at `path`, read without following a
/// reparse point. The path form of the seam's `owner`.
pub fn owner_of_path(path: &Path) -> io::Result<UserId> {
    let folder = std::fs::symlink_metadata(path)?.is_dir();
    let h = open_plain(path, READ_CONTROL, folder)?;
    read_security(sys::raw(&h), SE_FILE_OBJECT)?
        .owner
        .ok_or_else(|| io::Error::other("the owner could not be read"))
}

/// The seam's `private_dir`: makes `dir` and its parents, then refuses it
/// when it is not a plain folder of ours, and sets it private.
pub fn private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let h = open_plain(dir, READ_CONTROL | WRITE_DAC, true)?;
    if !path_is_plain(sys::raw(&h), dir)? {
        return Err(io::Error::other(format!(
            "{} has a link, junction or short name on its path",
            dir.display()
        )));
    }
    let s = read_security(sys::raw(&h), SE_FILE_OBJECT)?;
    if !s
        .owner
        .as_ref()
        .is_some_and(|o| ident::acceptable_owners().contains(o))
    {
        return Err(io::Error::other(format!(
            "{} belongs to another user",
            dir.display()
        )));
    }
    set_user_only(sys::raw(&h), SE_FILE_OBJECT, true)
}

/// The seam's `set_private_dir` and `set_private_file`.
pub fn set_private(path: &Path, folder: bool) -> io::Result<()> {
    let h = open_plain(path, READ_CONTROL | WRITE_DAC, folder)?;
    set_user_only(sys::raw(&h), SE_FILE_OBJECT, folder)
}

/// Sets the DACL written in `sddl` on a file or folder, as given (tests use
/// it to make a file another user may write; nothing in derm calls it).
pub fn set_dacl_sddl(path: &Path, sddl: &str) -> io::Result<()> {
    let folder = std::fs::symlink_metadata(path)?.is_dir();
    let h = open_plain(path, READ_CONTROL | WRITE_DAC, folder)?;
    let sd = Descriptor::from_sddl(sddl)?;
    let dacl = sd.dacl()?;
    // SAFETY: the handle was opened with WRITE_DAC; `dacl` lives in `sd`.
    let err = unsafe {
        SetSecurityInfo(
            sys::raw(&h),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if err != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    Ok(())
}

/// Reads a kernel object's owner and DACL (a named pipe's, for the client's
/// check of the server).
pub fn kernel_security(h: HANDLE) -> io::Result<Security> {
    read_security(h, SE_KERNEL_OBJECT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(s: &str) -> UserId {
        UserId::parse(s).unwrap()
    }

    fn allow(who: &str) -> Entry {
        Entry {
            kind: ACCESS_ALLOWED,
            mask: 0x1F01FF,
            who: Some(sid(who)),
        }
    }

    const ME: &str = "S-1-5-21-10-20-30-1001";
    const OTHER: &str = "S-1-5-21-10-20-30-1002";
    const SANDBOX: &str = "S-1-5-21-10-20-30-1003";

    fn sec(owner: &str, protected: bool, dacl: Option<Vec<Entry>>) -> Security {
        Security {
            owner: Some(sid(owner)),
            dacl,
            protected,
        }
    }

    #[test]
    fn the_check_keeps_out_everyone_but_the_user() {
        let me = sid(ME);
        assert!(is_private_security(
            &sec(ME, true, Some(vec![allow(ME)])),
            &me
        ));
        assert!(is_private_security(
            &sec(
                ME,
                true,
                Some(vec![
                    allow(ME),
                    allow(ident::SYSTEM),
                    allow(ident::ADMINISTRATORS)
                ])
            ),
            &me
        ));
        // An elevated administrator's file: owned by Administrators.
        assert!(is_private_security(
            &sec(ident::ADMINISTRATORS, true, Some(vec![allow(ME)])),
            &me
        ));
        // Another user, a sandbox account, Everyone, Users: refused, read
        // included (case AU-8: srt's profile read grant).
        for who in [OTHER, SANDBOX, "S-1-1-0", "S-1-5-32-545", "S-1-5-11"] {
            let mut e = allow(who);
            e.mask = 0x120089; // FILE_GENERIC_READ
            assert!(
                !is_private_security(&sec(ME, true, Some(vec![allow(ME), e])), &me),
                "{who}"
            );
        }
    }

    #[test]
    fn a_missing_dacl_an_odd_entry_or_an_inherited_stranger_is_not_private() {
        let me = sid(ME);
        // Inheriting only the user's entry (a file in a private folder).
        assert!(is_private_security(
            &sec(ME, false, Some(vec![allow(ME)])),
            &me
        ));
        // Inheriting Users' read (a file under C:\ProgramData): refused.
        let mut users = allow("S-1-5-32-545");
        users.mask = 0x120089;
        assert!(!is_private_security(
            &sec(ME, false, Some(vec![allow(ME), users])),
            &me
        ));
        assert!(!is_private_security(&sec(ME, true, None), &me));
        let odd = Entry {
            kind: 9, // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            mask: 0x1F01FF,
            who: None,
        };
        assert!(!is_private_security(
            &sec(ME, true, Some(vec![allow(ME), odd])),
            &me
        ));
        let unreadable = Entry {
            kind: ACCESS_ALLOWED,
            mask: 0x1F01FF,
            who: None,
        };
        assert!(!is_private_security(
            &sec(ME, true, Some(vec![unreadable])),
            &me
        ));
        // A deny entry only narrows.
        let deny = Entry {
            kind: ACCESS_DENIED,
            mask: 0x1F01FF,
            who: Some(sid(OTHER)),
        };
        assert!(is_private_security(
            &sec(ME, true, Some(vec![deny, allow(ME)])),
            &me
        ));
    }

    #[test]
    fn others_may_read_but_not_write_a_settings_file() {
        let me = sid(ME);
        let read = |who: &str| Entry {
            kind: ACCESS_ALLOWED,
            mask: 0x120089, // FILE_GENERIC_READ
            who: Some(sid(who)),
        };
        // The profile's usual inherited entries, and srt's read grant.
        let s = sec(
            ME,
            false,
            Some(vec![
                allow(ident::SYSTEM),
                allow(ident::ADMINISTRATORS),
                allow(ME),
                read(SANDBOX),
            ]),
        );
        assert!(only_owner_writes_security(&s, &me));
        for mask in [
            0x2,
            0x4,
            0x10,
            0x40,
            0x100,
            0x1_0000,
            0x4_0000,
            0x8_0000,
            0x1000_0000,
            0x4000_0000,
        ] {
            let w = Entry {
                kind: ACCESS_ALLOWED,
                mask: 0x120089 | mask,
                who: Some(sid(OTHER)),
            };
            assert!(
                !only_owner_writes_security(&sec(ME, true, Some(vec![allow(ME), w])), &me),
                "{mask:#x}"
            );
        }
        assert!(!only_owner_writes_security(&sec(ME, true, None), &me));
    }

    #[test]
    fn the_sddl_names_one_user_and_refuses_a_marker() {
        assert_eq!(
            user_only_sddl(&sid(ME), false).unwrap(),
            format!("D:P(A;;FA;;;{ME})")
        );
        assert_eq!(
            user_only_sddl(&sid(ME), true).unwrap(),
            format!("D:P(A;OICI;FA;;;{ME})")
        );
        assert!(user_only_sddl(&UserId::unknown("self"), true).is_err());
    }

    #[test]
    fn a_short_name_is_the_same_folder_and_a_junction_is_not() {
        // The 8.3 alias of a folder (when the volume makes them) passes; a
        // junction to the same folder does not.
        let d = temp("short").join("a long folder name");
        std::fs::create_dir_all(&d).unwrap();
        if let Some(short) = short_name(&d) {
            let h = open_plain(Path::new(&short), READ_CONTROL, true).unwrap();
            assert!(
                path_is_plain(sys::raw(&h), Path::new(&short)).unwrap(),
                "{short}"
            );
        }
        let j = d.parent().unwrap().join("junction");
        let ok = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&j)
            .arg(&d)
            .status()
            .unwrap();
        assert!(ok.success());
        let inside = j.join("x");
        std::fs::create_dir_all(&inside).unwrap();
        let h = open_plain(&inside, READ_CONTROL, true).unwrap();
        assert!(!path_is_plain(sys::raw(&h), &inside).unwrap());
        assert!(
            open_plain(&j, READ_CONTROL, true).is_err(),
            "the junction itself"
        );
        assert!(!owned_private_dir(&inside, &ident::effective_user()));
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }

    fn short_name(p: &Path) -> Option<String> {
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
        let w = sys::wide(p.as_os_str()).ok()?;
        let mut buf = vec![0u16; 1024];
        // SAFETY: as in `long_name`.
        let n = unsafe { GetShortPathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        let s = (n > 0 && (n as usize) < buf.len())
            .then(|| String::from_utf16_lossy(&buf[..n as usize]))?;
        (comparable(&s) != comparable(&p.to_string_lossy())).then_some(s)
    }

    #[test]
    fn paths_compare_without_prefix_case_or_trailing_separator() {
        assert_eq!(
            comparable(r"\\?\C:\Users\Me\.derm\"),
            comparable(r"c:/users/me/.derm")
        );
        assert_eq!(
            comparable(r"\\?\UNC\srv\share\x"),
            comparable(r"\\srv\share\x")
        );
        assert_ne!(
            comparable(r"C:\Users\ME~1\.derm"),
            comparable(r"C:\Users\Me\.derm")
        );
    }

    fn temp(name: &str) -> PathBuf {
        // Canonical, so no 8.3 name from %TEMP% (GitHub's runners have one)
        // makes the plain-path check refuse.
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let base = PathBuf::from(comparable_keep_case(&base.to_string_lossy()));
        let d = base.join(format!("derm-acl-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn comparable_keep_case(p: &str) -> String {
        p.strip_prefix(r"\\?\").unwrap_or(p).to_string()
    }

    #[test]
    fn a_private_dir_is_made_and_read_back_private() {
        let d = temp("dir").join("a").join("b");
        private_dir(&d).unwrap();
        assert!(owned_private_dir(&d, &ident::effective_user()));
        let s = read_security(
            sys::raw(&open_plain(&d, READ_CONTROL, true).unwrap()),
            SE_FILE_OBJECT,
        )
        .unwrap();
        assert!(s.protected);
        assert_eq!(
            s.dacl
                .unwrap()
                .iter()
                .filter(|e| e.kind == ACCESS_ALLOWED)
                .count(),
            1
        );
        // A file made inside takes the folder's one entry.
        let f = d.join("token");
        std::fs::write(&f, b"x").unwrap();
        assert!(is_private_path(&f));
        assert!(private_dir(&f).is_err(), "a file is not a folder");
        let _ = std::fs::remove_dir_all(d.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn set_private_tightens_an_inheriting_file() {
        let d = temp("file");
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("t");
        std::fs::write(&f, b"x").unwrap();
        // Everyone may read it. (What the temp folder alone gives depends on
        // the machine: on GitHub's runner only the user, SYSTEM and
        // Administrators, which is private.)
        let me = ident::effective_user();
        set_dacl_sddl(&f, &format!("D:(A;;FA;;;{me})(A;;FR;;;WD)")).unwrap();
        assert!(open_private_file(&f).is_err(), "Everyone may read it");
        assert!(!is_private_path(&f));
        set_private(&f, false).unwrap();
        assert!(is_private_path(&f));
        let mut text = String::new();
        std::io::Read::read_to_string(&mut open_private_file(&f).unwrap(), &mut text).unwrap();
        assert_eq!(text, "x");
        assert!(only_owner_writes(&f));
        assert!(only_owner_writes(&d));
        assert_eq!(
            owner_of_path(&f)
                .ok()
                .map(|o| ident::acceptable_owners().contains(&o)),
            Some(true)
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
