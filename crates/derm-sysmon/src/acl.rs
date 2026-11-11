//! "Only administrators can write this" (cases 232, 37), read from an
//! object's owner and DACL. Plain Rust: the Windows side
//! (`win::security_of`) reads the owner and the ACEs, this decides.
//!
//! What counts (the access masks of `winnt.h`, as derm-core's
//! `platform/windows/acl.rs` `WRITE_RIGHTS` uses them):
//! - on the program and on the folder that holds it, any write: a file
//!   added beside a program can be loaded by it (a DLL);
//! - on every folder above, only what can replace what is below:
//!   `DELETE`, `WRITE_DAC`, `WRITE_OWNER` and `GENERIC_ALL` on the folder,
//!   `FILE_DELETE_CHILD` on its parent's entries. Creating a new entry
//!   (`C:\` lets every user make folders) replaces nothing.
//!
//! An owner may change the DACL, so the owner must be trusted too. An ACE
//! that applies only to children (`INHERIT_ONLY_ACE`) grants nothing on the
//! object. A deny ACE only takes away. An allow ACE of a kind this does not
//! read (object or callback ACEs) is refused, never guessed.

/// SYSTEM.
pub const SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// NT SERVICE\TrustedInstaller, which owns Windows' own folders.
pub const TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;

/// Any write, on the program or its own folder.
pub const ANY_WRITE: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_ALL
    | GENERIC_WRITE;
/// What lets a folder above be replaced or its entries removed.
pub const REPLACE: u32 = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_DENIED_ACE_TYPE` (winnt.h).
pub const ALLOWED: u8 = 0;
pub const DENIED: u8 = 1;
/// `INHERIT_ONLY_ACE`.
pub const INHERIT_ONLY: u8 = 0x08;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ace {
    pub kind: u8,
    pub flags: u8,
    pub mask: u32,
    /// The SID, or `None` when the ACE is not one this reads.
    pub sid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Security {
    pub owner: Option<String>,
    /// `None`: a null DACL, which grants everyone everything.
    pub dacl: Option<Vec<Ace>>,
}

/// Why `s` lets someone outside `trusted` do any of `rights`, or `None`.
pub fn who_else_can(s: &Security, trusted: &[&str], rights: u32) -> Option<String> {
    match &s.owner {
        Some(o) if trusted.contains(&o.as_str()) => {}
        Some(o) => return Some(format!("its owner {o} can change who may write")),
        None => return Some("its owner could not be read".into()),
    }
    let Some(dacl) = &s.dacl else {
        return Some("it has no access list: everyone may write".into());
    };
    for ace in dacl {
        if ace.flags & INHERIT_ONLY != 0 || ace.kind == DENIED {
            continue;
        }
        if ace.kind != ALLOWED {
            return Some(format!(
                "an access entry of kind {} this does not read",
                ace.kind
            ));
        }
        let Some(sid) = &ace.sid else {
            return Some("an access entry with no SID".into());
        };
        if ace.mask & rights != 0 && !trusted.contains(&sid.as_str()) {
            return Some(format!("{sid} may write (mask {:#x})", ace.mask));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = "S-1-5-32-545";
    const AUTH: &str = "S-1-5-11";
    const CREATOR_OWNER: &str = "S-1-3-0";
    const ADMINS: &[&str] = &[SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER];

    fn ace(kind: u8, flags: u8, mask: u32, sid: &str) -> Ace {
        Ace {
            kind,
            flags,
            mask,
            sid: Some(sid.into()),
        }
    }

    /// `C:\Program Files` as Windows 11 ships it (read from `icacls` output
    /// as Microsoft documents the defaults; hand-written, I).
    fn program_files() -> Security {
        Security {
            owner: Some(TRUSTED_INSTALLER.into()),
            dacl: Some(vec![
                ace(ALLOWED, 0, 0x1F01FF, TRUSTED_INSTALLER),
                ace(ALLOWED, 0, 0x1301BF, SYSTEM),
                ace(ALLOWED, 0, 0x1301BF, ADMINISTRATORS),
                ace(ALLOWED, 0, 0x1200A9, USERS),
                ace(ALLOWED, 0x0B, GENERIC_ALL, CREATOR_OWNER),
            ]),
        }
    }

    #[test]
    fn handwritten_program_files_is_admin_only_and_a_user_entry_is_not() {
        assert_eq!(who_else_can(&program_files(), ADMINS, ANY_WRITE), None);
        let mut s = program_files();
        s.dacl
            .as_mut()
            .unwrap()
            .push(ace(ALLOWED, 0, FILE_WRITE_DATA, AUTH));
        assert!(who_else_can(&s, ADMINS, ANY_WRITE).unwrap().contains(AUTH));
    }

    #[test]
    fn handwritten_the_drive_root_lets_users_add_folders_but_not_replace_them() {
        // `C:\`: Authenticated Users may add folders (AD) and modify what
        // they make (inherit only).
        let root = Security {
            owner: Some(SYSTEM.into()),
            dacl: Some(vec![
                ace(ALLOWED, 0, 0x1F01FF, ADMINISTRATORS),
                ace(ALLOWED, 0, 0x1F01FF, SYSTEM),
                ace(ALLOWED, 0, 0x1200A9, USERS),
                ace(ALLOWED, 0x0B, 0x1301BF, AUTH),
                ace(ALLOWED, 0, FILE_APPEND_DATA, AUTH),
            ]),
        };
        assert_eq!(who_else_can(&root, ADMINS, REPLACE), None);
        assert!(who_else_can(&root, ADMINS, ANY_WRITE).is_some());
    }

    #[test]
    fn an_untrusted_owner_a_null_dacl_and_an_unread_ace_are_refused() {
        let mut s = program_files();
        s.owner = Some("S-1-5-21-1-2-3-1001".into());
        assert!(who_else_can(&s, ADMINS, ANY_WRITE)
            .unwrap()
            .contains("owner"));
        let s = Security {
            owner: Some(SYSTEM.into()),
            dacl: None,
        };
        assert!(who_else_can(&s, ADMINS, ANY_WRITE).is_some());
        let mut s = program_files();
        s.dacl.as_mut().unwrap().push(Ace {
            kind: 5,
            flags: 0,
            mask: 0x1,
            sid: None,
        });
        assert!(who_else_can(&s, ADMINS, ANY_WRITE).is_some());
        let mut s = program_files();
        s.owner = None;
        assert!(who_else_can(&s, ADMINS, ANY_WRITE).is_some());
    }

    #[test]
    fn a_deny_entry_only_takes_away() {
        let mut s = program_files();
        s.dacl
            .as_mut()
            .unwrap()
            .insert(0, ace(DENIED, 0, ANY_WRITE, AUTH));
        assert_eq!(who_else_can(&s, ADMINS, ANY_WRITE), None);
    }
}
