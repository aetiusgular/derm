//! The three Landlock syscalls, through libc's numbers (libc 0.2.189 has
//! `SYS_landlock_*` for every Linux target derm builds). Values from the
//! kernel's uapi header at v6.18 (`include/uapi/linux/landlock.h`).

pub(super) const CREATE_RULESET_VERSION: u32 = 1 << 0;
pub(super) const RULE_PATH_BENEATH: u32 = 1;

pub(super) const FS_EXECUTE: u64 = 1 << 0;
pub(super) const FS_WRITE_FILE: u64 = 1 << 1;
pub(super) const FS_READ_FILE: u64 = 1 << 2;
pub(super) const FS_READ_DIR: u64 = 1 << 3;
/// ABI 1: bits 0 to 12 (EXECUTE to MAKE_SYM).
pub(super) const FS_ABI1: u64 = (1 << 13) - 1;
pub(super) const FS_REFER: u64 = 1 << 13; // ABI 2
pub(super) const FS_TRUNCATE: u64 = 1 << 14; // ABI 3
pub(super) const FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5
/// The rights that make sense on a file, not a folder (the kernel refuses a
/// rule on a file that names any other).
pub(super) const FS_FILE: u64 =
    FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV;

pub(super) const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0; // ABI 6
pub(super) const SCOPE_SIGNAL: u64 = 1 << 1; // ABI 6

#[repr(C)]
pub(super) struct RulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

#[repr(C, packed)]
pub(super) struct PathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

/// The ABI, or 0 when the kernel has no usable Landlock.
pub(super) fn abi() -> i64 {
    // SAFETY: a null attribute with size 0 and the VERSION flag only asks
    // for the ABI number (landlock(7)).
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if r < 0 {
        0
    } else {
        r
    }
}

/// The filesystem rights the kernel at `abi` knows.
pub(super) fn fs_rights(abi: i64) -> u64 {
    let mut fs = FS_ABI1;
    if abi >= 2 {
        fs |= FS_REFER;
    }
    if abi >= 3 {
        fs |= FS_TRUNCATE;
    }
    if abi >= 5 {
        fs |= FS_IOCTL_DEV;
    }
    fs
}

/// The size of the attribute the kernel at `abi` reads: `scoped` from ABI 6,
/// `handled_access_net` from ABI 4.
pub(super) fn attr_size(abi: i64) -> usize {
    if abi >= 6 {
        24
    } else if abi >= 4 {
        16
    } else {
        8
    }
}
