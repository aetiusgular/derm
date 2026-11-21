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
//!
//! Linux only: `run/user/mod.rs` declares this module for Linux, where
//! agent accounts exist.

use serde::{Deserialize, Serialize};

pub(crate) mod netcheck;
pub(crate) mod reprobe;
pub(crate) mod setup;
mod sys;

#[cfg(test)]
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
    /// Check, as the account and before the domain, that lane L2's table
    /// still refuses the account's own network (`netcheck.rs`; L2's request
    /// to L1, applied by integration). Every chat's spec sets it.
    #[serde(default)]
    pub check_network: bool,
    /// Step P (lane PA): the project folders, sign-in links and gateway
    /// entries the helper makes as the account before the domain
    /// (`setup.rs`; contracts/projects.md section 2.2).
    #[serde(default)]
    pub setup: Option<setup::Setup>,
    /// Step P10's I-1 (lane PA): the network check again every this many
    /// seconds while the chat runs, from a process outside the chat's
    /// domain; 0 checks only at the start (`reprobe.rs`).
    #[serde(default)]
    pub reprobe_secs: u64,
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
/// the account (one uid): the status doc names it. A project chat keeps
/// `/dev/pts` only when its harness makes terminals ([`makes_ptys`]).
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

/// The pty devices' folder. Out of a domain, a new pty's slave cannot be
/// opened, by path or by `TIOCGPTPEER` (run on Linux 6.18, ABI 7: both
/// EACCES), while a terminal the chat was handed as an open descriptor keeps
/// working (P5's stopgap, plan 4a; note CC section 4).
pub(crate) const PTS: &str = "/dev/pts";

/// Whether `harness` makes terminals for its tools, so its chat keeps
/// `/dev/pts` (P5's stopgap). Read at the pins: Pi 1.4.0's and 1.6.0's bash
/// tool spawns with pipes (`dist/core/tools/bash.js:63-68`) and the package
/// carries no pty library; Claude Code 2.1.322's Bash tool runs with pipes
/// (`-p`, run, note CD premise 25) and only its background sessions make a
/// pty (`new Bun.Terminal`, binary read), which outlive the chat outside
/// `derm run` and so are refused in an account chat (the lane's reading);
/// Codex 0.167.2 opens a pty for a command that asks for one
/// (`utils/pty` with `portable-pty`, `unified_exec/mod.rs:187`). Every
/// harness not read keeps it.
pub(crate) fn makes_ptys(harness: &str) -> bool {
    !matches!(harness, "pi" | "claude-code")
}

/// What a project chat's domain is built from (lane PA; contracts/
/// projects.md section 2.2's "Domain right" column).
pub(crate) struct ProjectPaths<'a> {
    /// The chat's folders: its working folder and every `--folder`.
    pub folders: &'a [String],
    /// The project's home, temp and runtime folders, and the chat's own
    /// harness's sign-in store folder.
    pub writable: &'a [String],
    pub bridge: Option<&'a str>,
    /// The chat's `PATH` (no home entry).
    pub path: &'a str,
    /// Keep `/dev/pts` in the domain.
    pub pts: bool,
    pub require_scopes: bool,
}

/// The spec for one project chat: the system read-only, its own folders,
/// its project's folders and the temporary folders writable, `/dev/pts`
/// only when its harness makes terminals, its own bridge read-only. Not the
/// account home, so no chat writes what another project's chat runs (AI-1
/// across projects).
pub(crate) fn project_spec(p: &ProjectPaths) -> Spec {
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
    let mut write: Vec<String> = SYSTEM_WRITE
        .iter()
        .filter(|w| p.pts || **w != PTS)
        .map(|s| s.to_string())
        .collect();
    write.extend(p.writable.iter().cloned());
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
        check_network: true,
        setup: None,
        reprobe_secs: 0,
    }
}

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
        check_network: true,
        setup: None,
        reprobe_secs: 0,
    }
}

/// The kernel's Landlock ABI, or 0 when it has none (not built, not in the
/// LSM list, or not Linux).
pub(crate) fn abi() -> i64 {
    sys::abi()
}

/// Puts this thread (and every process it later starts) in a new domain
/// built from `spec`, with no_new_privs set. Best effort per ABI, as the
/// kernel docs' compatibility example does, except where the spec requires
/// what the kernel lacks: then it refuses and changes nothing.
pub(crate) fn apply(spec: &Spec) -> Result<Applied, String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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
            let Some(f) = rule_fd(p)? else {
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

/// The descriptor a rule for `p` is made from, or `None` when `p` is not
/// there (no rule, so it stays refused).
///
/// Review AI-2 (accounts integration, reproduced by the reviewer): a rule
/// opened with links followed covers the link's target, so a chat that
/// replaces a folder of the account's (`~/.local/bin`, a chat folder) with a
/// link to `/run/derm-agent/<uid>` widened the next chat's domain to every
/// chat's bridge and `chat.token`. Every part of `p` that is a link must be
/// root's (merged /usr's `/bin -> usr/bin`; a chat cannot make one), and the
/// real path is then opened with `openat2(RESOLVE_NO_SYMLINKS)`, so a link
/// put there after the check fails the open instead of being followed
/// (openat2(2): Linux 5.6, before Landlock's 5.13; libc 0.2.189's
/// `SYS_openat2`, 437 on x86_64 and aarch64, and `RESOLVE_NO_SYMLINKS`
/// 0x04, read).
pub(crate) fn rule_fd(p: &str) -> Result<Option<std::fs::File>, String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    let path = Path::new(p);
    let mut at = PathBuf::new();
    for c in path.components() {
        at.push(c);
        match std::fs::symlink_metadata(&at) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", at.display())),
            Ok(m) if m.file_type().is_symlink() && m.uid() != 0 => {
                return Err(format!(
                    "{} is a link that root does not own (uid {}); a chat may have put it there, so its target gets no rule. Remove it, or give the real path",
                    at.display(),
                    m.uid()
                ));
            }
            Ok(_) => {}
        }
    }
    let real = match std::fs::canonicalize(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{p}: {e}")),
    };
    let c = std::ffi::CString::new(real.as_os_str().as_encoded_bytes())
        .map_err(|_| format!("{p}: a NUL in the path"))?;
    // SAFETY: `open_how` is plain integers (libc marks it non-exhaustive),
    // and zero is the kernel's "nothing asked" for each field.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: `c` and `how` live across the call; the size is `how`'s.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!(
            "{} (for {p}): {e}; a link may have been put there since it was checked",
            real.display()
        ));
    }
    // SAFETY: the kernel returned a new descriptor that nothing else owns.
    Ok(Some(unsafe { std::fs::File::from_raw_fd(fd as i32) }))
}

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

pub(crate) fn enter(spec: &Spec, argv: &[String]) -> u8 {
    use std::os::unix::process::CommandExt;
    if spec.check_network {
        if let Err(why) = netcheck::check() {
            eprintln!("derm {SUBCOMMAND}: {why}; not starting {}", argv[0]);
            return 126;
        }
    }
    // As the account, before the domain: the project's folders, the
    // sign-in links and the gateway entries (lane PA, step P2).
    let mut extra: Vec<(String, String)> = Vec::new();
    if let Some(s) = &spec.setup {
        match setup::make(s) {
            Ok(env) => extra = env,
            Err(why) => {
                eprintln!("derm {SUBCOMMAND}: {why}; not starting {}", argv[0]);
                return 126;
            }
        }
    }
    // The watchdog forks before the domain, so it stays outside it: the
    // chat can neither signal nor trace it (scopes, ABI 6).
    if spec.check_network && spec.reprobe_secs > 0 {
        if let Err(why) = reprobe::start(std::time::Duration::from_secs(spec.reprobe_secs)) {
            eprintln!("derm {SUBCOMMAND}: {why}; not starting {}", argv[0]);
            return 126;
        }
    }
    if let Err(why) = apply(spec) {
        eprintln!("derm {SUBCOMMAND}: {why}; not starting {}", argv[0]);
        return 126;
    }
    let err = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .envs(extra)
        .env_remove(SPEC_VAR)
        .exec();
    eprintln!("derm {SUBCOMMAND}: {}: {err}", argv[0]);
    127
}
