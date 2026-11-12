//! The checked policy load, moved here unchanged from `run/mod.rs` by the
//! wave 5b base (plans/toolkit_wave5b_plan.md section 2.0, part 3), so
//! `derm run`, `derm acp`, `derm hook` and `derm gate serve` load the policy
//! by one set of rules (case 226, FPW-S2). `run` re-exports it.

use std::path::{Path, PathBuf};

/// The policy `derm acp` and goose's ask mode decide with (integration w5's
/// Windows fix pass, reviews FPW-S2, FPWR-4, FPWR-5), loaded by the hook
/// core's rules (`loadPolicyFrom`, `loadPolicy` in
/// `packages/derm-claude-plugin/src/core/policy.ts`): a `DERM_POLICY` inside
/// the folder the chat starts in is refused (a project can set it there);
/// the file is opened once, links followed as the hook's `openSync` follows
/// them (the folder checks below follow them too, review FPWR2-3), never
/// blocking on a FIFO (FPWR2-2), and that handle is judged and read, so the
/// file checked is the file applied; on Unix it is the user's own
/// with no group or other write bit (stricter than the hook's trusted owners,
/// which can include the agents' user), on Windows no one but its owner may
/// write it (lane Z's rule, judged by the handle); and its folder, as written
/// and as its target's, may be written by no one else either, since a folder
/// others can write (such as `/tmp`, which srt lets a chat write) lets them
/// swap the file. Anything else gives the empty policy, so every call asks,
/// and the problem says why. `derm_core::policy::load` checks none of this.
pub(crate) fn load_policy_checked(
    path: &str,
    from_env: bool,
    cwd: &str,
) -> (derm_core::policy::PolicyFile, Option<String>) {
    #[cfg(unix)]
    let mine = |uid: u32| uid == derm_core::platform::real_user();
    #[cfg(not(unix))]
    let mine = |_uid: u32| true;
    load_checked_by(path, from_env, cwd, &mine)
}

/// [`load_policy_checked`] with the file owner's rule passed in (the wave 5b
/// base: [`load_for_hook`] passes the trusted owners). Unix only: on Windows
/// the access list decides and `owner_ok` is not read.
pub(crate) fn load_checked_by(
    path: &str,
    from_env: bool,
    cwd: &str,
    owner_ok: &dyn Fn(u32) -> bool,
) -> (derm_core::policy::PolicyFile, Option<String>) {
    use std::io::Read;
    let empty = |why: String| (derm_core::policy::PolicyFile::default(), Some(why));
    let p = Path::new(path);
    if from_env {
        // By its real path, through the deepest part that exists: on macOS
        // `/var` is a link to `/private/var`, so a path not there yet would
        // compare as written and escape the check (case 111; CI's
        // `rust-macos` on `f1d3a6f`).
        let real = real_through_existing(p);
        let folder = std::fs::canonicalize(cwd).unwrap_or_else(|_| PathBuf::from(cwd));
        if real.starts_with(&folder) {
            return empty(
                "DERM_POLICY is inside the chat's folder, which a project can set; not used, so every call asks".into(),
            );
        }
    }
    let file = match open_policy(p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return empty(derm_core::policy::LoadProblem::Missing.to_string())
        }
        Err(e) => return empty(format!("policy file unreadable: {}", e.kind())),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return empty(format!("policy file unreadable: {}", e.kind())),
    };
    if !meta.is_file() {
        return empty("policy file is not a regular file; every call asks".into());
    }
    if !policy_file_private(&file, &meta, owner_ok) {
        return empty(
            "someone other than you may write this policy file; not used, so every call asks"
                .into(),
        );
    }
    let real_parent = std::fs::canonicalize(p)
        .ok()
        .and_then(|r| r.parent().map(Path::to_path_buf));
    for folder in [p.parent().map(Path::to_path_buf), real_parent]
        .into_iter()
        .flatten()
    {
        if !policy_folder_private(&folder) {
            return empty(format!(
                "someone other than you may write {}, the policy file's folder, and swap the file; not used, so every call asks",
                folder.display()
            ));
        }
    }
    if meta.len() > derm_core::policy::MAX_POLICY_BYTES {
        return empty("policy file is over 1 MiB; every call asks".into());
    }
    let mut text = String::new();
    if let Err(e) = (&file)
        .take(derm_core::policy::MAX_POLICY_BYTES + 1)
        .read_to_string(&mut text)
    {
        return empty(format!("policy file unreadable: {}", e.kind()));
    }
    // A file that grew after the size was read (review FPWR2-7).
    if text.len() as u64 > derm_core::policy::MAX_POLICY_BYTES {
        return empty("policy file is over 1 MiB; every call asks".into());
    }
    match derm_core::policy::parse(&text) {
        Ok(policy) => (policy, None),
        Err(problem) => empty(problem.to_string()),
    }
}

/// Opens the policy for reading without blocking on what is not a file
/// (review FPWR2-2): on Unix `O_NONBLOCK`, so a FIFO planted at the path
/// returns at once and the `is_file` check after refuses it, as derm-pi's
/// memory record does (`memory.ts`); on Windows only a path that is a
/// regular file now is opened (a pipe name opens a pipe client).
fn open_policy(p: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(p)
    }
    #[cfg(windows)]
    {
        if !std::fs::metadata(p)?.is_file() {
            return Err(std::io::Error::other("not a regular file"));
        }
        std::fs::File::open(p)
    }
}

/// `p` with its deepest existing ancestor replaced by that ancestor's real
/// path, the rest kept as written; `p` itself when no part resolves.
fn real_through_existing(p: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut at = p;
    loop {
        if let Ok(real) = std::fs::canonicalize(at) {
            return rest.iter().rev().fold(real, |acc, part| acc.join(part));
        }
        match (at.parent(), at.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                at = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

#[cfg(unix)]
fn policy_file_private(
    _file: &std::fs::File,
    meta: &std::fs::Metadata,
    owner_ok: &dyn Fn(u32) -> bool,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    owner_ok(meta.uid()) && meta.mode() & 0o022 == 0
}

#[cfg(windows)]
fn policy_file_private(
    file: &std::fs::File,
    _meta: &std::fs::Metadata,
    _owner_ok: &dyn Fn(u32) -> bool,
) -> bool {
    derm_core::platform::windows::only_owner_writes_file(file)
}

/// The hook core's folder rule: no group or other write bit (links
/// followed, as its `statSync`); on Windows lane Z's `only_owner_writes`.
#[cfg(unix)]
fn policy_folder_private(folder: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(folder).is_ok_and(|m| m.is_dir() && m.mode() & 0o022 == 0)
}

#[cfg(windows)]
fn policy_folder_private(folder: &Path) -> bool {
    std::fs::canonicalize(folder)
        .is_ok_and(|real| derm_core::platform::windows::only_owner_writes(&real))
}

/// The policy a gate reads (`loadPolicyFrom` in the hook core): `DERM_POLICY`
/// when set, else `~/.derm/policy.json`, by [`load_policy_checked`]'s rules,
/// with a relative `DERM_POLICY` refused (FPWR2-5). On Unix the file's owner
/// is judged by the trusted owners (`derm_core::owner`; under an agents' user,
/// the person it works for, note BB BBR-4) and not by the real uid alone; on
/// Windows by its access list, as [`load_policy_checked`] does.
pub(crate) fn load_for_hook(
    env: &crate::gate::daemon::Env,
    cwd: &Path,
) -> (derm_core::policy::PolicyFile, Option<String>) {
    let set = env.raw("DERM_POLICY").filter(|p| !p.trim().is_empty());
    if let Some(p) = set {
        if !Path::new(p).is_absolute() {
            return (
                derm_core::policy::PolicyFile::default(),
                Some("DERM_POLICY is not an absolute path; not used, so every call asks".into()),
            );
        }
    }
    let path = match set {
        Some(p) => PathBuf::from(p),
        None => {
            let home = env
                .get(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .map(PathBuf::from)
                .or_else(derm_core::runtime::home_dir)
                .unwrap_or_default();
            home.join(".derm").join("policy.json")
        }
    };
    load_checked_by(
        &path.to_string_lossy(),
        set.is_some(),
        &cwd.to_string_lossy(),
        &|uid| derm_core::owner::owned_by_trusted(uid),
    )
}
