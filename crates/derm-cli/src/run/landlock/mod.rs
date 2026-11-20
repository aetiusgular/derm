//! One Landlock domain per chat (accounts build, lane L1; note CB sections
//! 5 and 6; rules case 156).
//!
//! Many chats run as one agent account (one account per subscription), so
//! the uid no longer keeps one chat from another. Landlock does: a process
//! in a domain may ptrace, read `/proc/<pid>/environ` of, signal, or reach
//! the abstract Unix sockets of, only processes in its own domain or a
//! sub-domain of it (kernel docs, "the tracee must be in a sub-domain of the
//! tracer"; scopes since ABI 6). Two chats in sibling domains reach none of
//! that in each other (note CB section 6, run on Linux 6.18, ABI 7).
//!
//! Landlock needs no_new_privs or `CAP_SYS_ADMIN` before
//! `landlock_restrict_self` (kernel docs), and no_new_privs stops `sudo`'s
//! set-user-id bit (rules case 162). So the domain cannot be made by
//! `derm run` before `sudo`: `sudo` starts this module's [`enter_main`] as
//! the account, which restricts itself and then execs the harness. A domain
//! restricts "the thread enforcing it, and its future children" (kernel
//! docs), and survives `execve`.
//!
//! The spec travels in the environment (`DERM_LANDLOCK_SPEC`), never on
//! argv: `/proc/<pid>/cmdline` stays readable across domains (note CB
//! section 6, reading 3). It holds paths only, and is removed before the
//! harness starts.

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
mod sys;

#[cfg(all(test, target_os = "linux"))]
mod tests;

/// The variable that carries a [`Spec`] from `derm run` to [`enter_main`].
pub(crate) const SPEC_VAR: &str = "DERM_LANDLOCK_SPEC";
/// The subcommand `sudo` runs as the account (`derm landlock -- <argv>`).
pub(crate) const SUBCOMMAND: &str = "landlock";
/// The first ABI with the signal and abstract-socket scopes.
pub(crate) const SCOPES_ABI: i64 = 6;

/// What a chat's domain allows. Every path not under one of these is
/// refused every handled right.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Spec {
    pub version: u32,
    /// Read files and list folders.
    pub read: Vec<String>,
    /// Read, list and execute.
    pub exec: Vec<String>,
    /// Every filesystem right.
    pub write: Vec<String>,
    /// Refuse to start when the kernel has no Landlock at all.
    pub require_landlock: bool,
    /// Refuse to start when the kernel has no signal and abstract-socket
    /// scopes (ABI 6). `derm run` clears it only on the person's yes.
    pub require_scopes: bool,
}

/// What [`apply`] put in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Applied {
    /// The kernel's ABI; 0 when it has no Landlock.
    pub abi: i64,
    /// The filesystem rights the domain handles.
    pub fs: u64,
    /// The signal and abstract-socket scopes are on.
    pub scoped: bool,
}

/// What a chat's domain is built from (`derm run`, as the person).
pub(crate) struct ChatPaths<'a> {
    /// The chat's folders: its working folder and every `--folder`.
    pub folders: &'a [String],
    /// The agent account's home: its logins, settings and installs.
    pub account_home: &'a str,
    /// The chat's own bridge folder (`user/bridge.rs`), read-only.
    pub bridge: Option<&'a str>,
    /// The account's `PATH`: each folder is readable and executable, so the
    /// harness runs wherever the account installed it.
    pub path: &'a str,
    pub require_scopes: bool,
}

/// The system's own programs and libraries: read and execute.
const SYSTEM_EXEC: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/snap",
];
/// Read only: configuration, the process and system views, the resolver's
/// stub file (`/etc/resolv.conf` links there on systemd hosts, and Landlock
/// checks the link's target).
const SYSTEM_READ: &[&str] = &["/etc", "/proc", "/sys", "/run/systemd/resolve"];
/// Every right: temporary folders and the devices a terminal program opens.
/// `/tmp`, `/var/tmp`, `/dev/shm` and `/dev/pts` are shared by every chat of
/// the account (one uid): the status doc names it.
const SYSTEM_WRITE: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
    "/dev/pts",
];

/// The spec for one chat: the system read-only, its own folders, the account
/// home and the temporary folders writable, its own bridge read-only, and
/// nothing else: not the person's home, not another chat's folders or
/// bridge.
pub(crate) fn chat_spec(p: &ChatPaths) -> Spec {
    let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut exec = owned(SYSTEM_EXEC);
    exec.extend(
        p.path
            .split(':')
            .filter(|d| d.starts_with('/'))
            .map(str::to_string),
    );
    let mut read = owned(SYSTEM_READ);
    read.extend(p.bridge.map(str::to_string));
    let mut write = owned(SYSTEM_WRITE);
    write.push(p.account_home.to_string());
    write.extend(p.folders.iter().cloned());
    for v in [&mut exec, &mut read, &mut write] {
        v.sort();
        v.dedup();
    }
    Spec {
        version: 1,
        read,
        exec,
        write,
        require_landlock: true,
        require_scopes: p.require_scopes,
    }
}

/// The kernel's Landlock ABI, or 0 when it has none (not built, not in the
/// LSM list, or not Linux).
pub(crate) fn abi() -> i64 {
    #[cfg(target_os = "linux")]
    {
        sys::abi()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Puts this thread (and every process it later starts) in a new domain
/// built from `spec`, with no_new_privs set. Best effort per ABI, as the
/// kernel docs' compatibility example does, except where the spec requires
/// what the kernel lacks: then it refuses and changes nothing.
#[cfg(target_os = "linux")]
pub(crate) fn apply(spec: &Spec) -> Result<Applied, String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt;

    let abi = abi();
    if abi < 1 {
        if spec.require_landlock {
            return Err("this kernel has no Landlock (not built, or not in the lsm= list)".into());
        }
        set_no_new_privs()?;
        return Ok(Applied {
            abi,
            fs: 0,
            scoped: false,
        });
    }
    let scoped = abi >= SCOPES_ABI;
    if spec.require_scopes && !scoped {
        return Err(format!(
            "Landlock ABI {abi} has no signal or abstract-socket scope (ABI {SCOPES_ABI}, Linux 6.12)"
        ));
    }
    let fs = sys::fs_rights(abi);
    let attr = sys::RulesetAttr {
        handled_access_fs: fs,
        handled_access_net: 0,
        scoped: if scoped {
            sys::SCOPE_ABSTRACT_UNIX_SOCKET | sys::SCOPE_SIGNAL
        } else {
            0
        },
    };
    // SAFETY: `attr` lives across the call; the size is the part of it the
    // kernel at this ABI reads.
    let rs = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const sys::RulesetAttr,
            sys::attr_size(abi),
            0u32,
        )
    };
    if rs < 0 {
        return Err(format!(
            "landlock_create_ruleset: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the kernel returned a new descriptor that nothing else owns.
    let ruleset = unsafe { OwnedFd::from_raw_fd(rs as i32) };
    let read = sys::FS_READ_FILE | sys::FS_READ_DIR;
    let groups: [(&[String], u64); 3] = [
        (&spec.read, read),
        (&spec.exec, read | sys::FS_EXECUTE),
        (&spec.write, fs),
    ];
    for (paths, rights) in groups {
        for p in paths {
            if !p.starts_with('/') {
                return Err(format!("{p:?} is not an absolute path"));
            }
            // A path that is not there gets no rule, so it stays refused.
            let Ok(f) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                .open(p)
            else {
                continue;
            };
            let is_dir = f.metadata().map(|m| m.is_dir()).unwrap_or(false);
            let allowed = rights & fs & if is_dir { u64::MAX } else { sys::FS_FILE };
            if allowed == 0 {
                continue;
            }
            let rule = sys::PathBeneathAttr {
                allowed_access: allowed,
                parent_fd: f.as_raw_fd(),
            };
            // SAFETY: `rule` and both descriptors live across the call.
            let r = unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset.as_raw_fd(),
                    sys::RULE_PATH_BENEATH,
                    &rule as *const sys::PathBeneathAttr,
                    0u32,
                )
            };
            if r != 0 {
                return Err(format!(
                    "landlock_add_rule {p}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    set_no_new_privs()?;
    // SAFETY: a ruleset descriptor and no flags.
    let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) };
    if r != 0 {
        return Err(format!(
            "landlock_restrict_self: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Applied { abi, fs, scoped })
}

#[cfg(target_os = "linux")]
fn set_no_new_privs() -> Result<(), String> {
    // SAFETY: prctl with integer arguments.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `derm landlock -- <program> <args>`: run as the account by `sudo`;
/// reads the spec, restricts itself, execs the program with the spec
/// variable removed. Exit codes: 126 when the domain cannot be made, 127
/// when the program cannot be started, 2 for a usage error.
pub(crate) fn enter_main(args: &[String]) -> u8 {
    let argv = match args.first().map(String::as_str) {
        Some("--") if args.len() > 1 => &args[1..],
        _ => {
            eprintln!("usage: derm {SUBCOMMAND} -- <program> <args>  (started by derm run as an agent account)");
            return 2;
        }
    };
    let spec = match std::env::var(SPEC_VAR) {
        Ok(text) => match serde_json::from_str::<Spec>(&text) {
            Ok(s) if s.version == 1 => s,
            _ => {
                eprintln!(
                    "derm {SUBCOMMAND}: {SPEC_VAR} is not a version 1 spec; not starting {}",
                    argv[0]
                );
                return 126;
            }
        },
        Err(_) => {
            eprintln!("derm {SUBCOMMAND}: no {SPEC_VAR}; not starting {}", argv[0]);
            return 126;
        }
    };
    enter(&spec, argv)
}

#[cfg(target_os = "linux")]
fn enter(spec: &Spec, argv: &[String]) -> u8 {
    use std::os::unix::process::CommandExt;
    if let Err(why) = apply(spec) {
        eprintln!("derm {SUBCOMMAND}: {why}; not starting {}", argv[0]);
        return 126;
    }
    let err = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .env_remove(SPEC_VAR)
        .exec();
    eprintln!("derm {SUBCOMMAND}: {}: {err}", argv[0]);
    127
}

#[cfg(not(target_os = "linux"))]
fn enter(_spec: &Spec, argv: &[String]) -> u8 {
    eprintln!(
        "derm {SUBCOMMAND}: Landlock is Linux only; not starting {}",
        argv[0]
    );
    126
}
