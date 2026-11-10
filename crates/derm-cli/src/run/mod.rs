//! `derm run` (lane D, T1.4): start a harness inside a boundary, with the
//! chat's token and endpoints in its environment, and record the run in the
//! daemon.
//!
//! ```text
//! derm run pi --boundary sbx            # Docker Sandboxes, the pi kit
//! derm run pi --boundary srt --model-url http://127.0.0.1:8080/v1
//! derm run claude-code --boundary none -- --continue
//! ```
//!
//! Order: read the daemon's token, mint a chat token (`token.mint`), build
//! the plan (`plan.rs`, pure), write srt's settings (0600), start the child,
//! post `run.start` with its pid (the Linux feed places the process tree
//! from it), poll `sbx policy log` under sbx, wait, post `run.stop`, exit
//! with the child's code. The daemon not running is an error unless
//! `--no-daemon` says to run with no feed (fail closed, rules case 9).
//!
//! Contract: `contracts/daemon-protocol.md` sections 2 and 3. Sources: the
//! lane D status doc, Research.

pub(crate) mod args;
// The harness's process tree (the platform seam's primitive 5, lane Z's
// request 1): `exec.rs` on Unix; on Windows the same functions from lane Z's
// `platform/windows/exec.rs` (`install_handlers`, `forward_sigint`, `spawn`,
// `spawn_companion`, `stop_companion`, `wait`, `code`,
// `output_with_timeout`).
#[cfg(unix)]
mod exec;
#[cfg(windows)]
use crate::platform::windows::exec;
mod codex_store;
pub(crate) mod harness;
pub(crate) mod plan;
mod policy_log;
mod preflight;
// Wave 5's seams (the wave 5 base, `plans/parallel_build_tk.md` section 7c):
// each folder is one lane's, and each stub changes nothing. The rest of
// `run/` is integration's in wave 5.
pub(crate) mod boundary; // lane T (pub(crate) for lane W's `derm setup sandbox`, request T-8)
mod tap; // lane S
mod user; // lane V

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use derm_audit_linux::client::{self, Client};
use derm_core::event::{Event, Source};
use serde_json::json;

use args::Boundary;

const POLL: Duration = Duration::from_secs(2);
/// Lane P's Cline approval responder, found on PATH (`packages/derm-cline`;
/// the name and its `--dir <folder>` argument are lane R's request to lane
/// P, recorded in `plans/parallel/tk_lane_R.md`).
pub const CLINE_RESPONDER: &str = "derm-cline-responder";
const POLICY_LOG_TIMEOUT: Duration = Duration::from_secs(10);

/// What `derm run` reads from its own environment, gathered in one place so
/// the tests can give a fake daemon and fake programs.
/// A path with every link in it followed, as the kernel would on an open,
/// and a missing tail kept as written (`realpath -m`): a link whose target
/// does not exist yet resolves to that target, since a write through it
/// creates the target (fix pass 6, FP5R-6). `None` for a relative path or a
/// chain of more than 40 links.
fn real_path_lenient(path: &Path) -> Option<PathBuf> {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::Component;
    if !path.is_absolute() {
        return None;
    }
    let parts = |p: &Path| -> Vec<OsString> {
        p.components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_os_string()),
                Component::ParentDir => Some(OsString::from("..")),
                _ => None,
            })
            .collect()
    };
    let mut todo: VecDeque<OsString> = parts(path).into();
    let mut out = PathBuf::from("/");
    let mut hops = 0;
    while let Some(c) = todo.pop_front() {
        if c == ".." {
            out.pop();
            continue;
        }
        let next = out.join(&c);
        match std::fs::symlink_metadata(&next) {
            Ok(m) if m.file_type().is_symlink() => {
                hops += 1;
                if hops > 40 {
                    return None;
                }
                let target = std::fs::read_link(&next).ok()?;
                if target.is_absolute() {
                    out = PathBuf::from("/");
                }
                for x in parts(&target).into_iter().rev() {
                    todo.push_front(x);
                }
            }
            _ => out = next,
        }
    }
    Some(out)
}

struct RunEnv {
    socket: Option<PathBuf>,
    home: Option<String>,
    gateway: Option<String>,
    /// Program name to path, for tests only (`main` passes none).
    programs: Vec<(String, String)>,
    /// `DERM_POLICY`, the policy file the harness's gate will read.
    policy: Option<String>,
    /// `PATH`, searched for srt's own dependencies (BX4).
    path: String,
    /// `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` (BX3), when
    /// it exists.
    userns: Option<String>,
    /// Ubuntu's AppArmor profile for bubblewrap is installed (BW5R-4).
    bwrap_profile: bool,
    /// `GOOSE_MODE` as inherited, when set and not empty (T2.9).
    goose_mode: Option<String>,
    /// Lane P's Cline approval responder, by absolute path, when one is on
    /// PATH (T2.9).
    cline_responder: Option<String>,
}

impl RunEnv {
    fn real() -> RunEnv {
        RunEnv {
            socket: client::socket_path(),
            home: derm_core::runtime::home_dir()
                .and_then(|h| h.into_os_string().into_string().ok()),
            gateway: std::env::var("DERM_GATEWAY_URL").ok(),
            programs: Vec::new(),
            policy: std::env::var("DERM_POLICY").ok(),
            path: std::env::var("PATH").unwrap_or_default(),
            userns: std::fs::read_to_string(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            )
            .ok(),
            bwrap_profile: std::path::Path::new(boundary::probe::UBUNTU_BWRAP_PROFILE).exists(),
            goose_mode: std::env::var("GOOSE_MODE").ok().filter(|v| !v.is_empty()),
            cline_responder: crate::watch::status::find_on_path(
                CLINE_RESPONDER,
                &std::env::var("PATH").unwrap_or_default(),
            )
            .map(|p| p.to_string_lossy().into_owned()),
        }
    }

    fn program<'a>(&'a self, name: &'a str) -> &'a str {
        self.programs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p.as_str())
            .unwrap_or(name)
    }
}

/// What `derm acp` is handed once the harness has started with piped stdin
/// and stdout: the pipes, and what it needs to answer and record.
pub(crate) struct Pipes {
    pub stdin: std::process::ChildStdin,
    pub stdout: std::process::ChildStdout,
    pub chat: String,
    pub harness: String,
    /// The chat token `derm run` minted, for the adapter records.
    pub token: Option<String>,
    pub socket: Option<PathBuf>,
    /// The policy file the gate reads.
    pub policy: String,
    /// That file as `derm run` loaded and checked it, once (FPW-S2, FPWR-5):
    /// the empty policy when it is missing, refused or invalid, so every
    /// call asks, and why in `policy_problem`.
    pub policy_file: derm_core::policy::PolicyFile,
    pub policy_problem: Option<String>,
    /// Case 83: the run is in full access, so an `ask` becomes a deny.
    pub full_access: bool,
    /// The boundary is srt or sbx (security review L2).
    pub confined: bool,
}

/// `derm acp`'s part: given the pipes, it starts its threads and returns
/// them; `derm run` joins them after the harness exits.
pub(crate) type StdioFilter<'a> = &'a dyn Fn(Pipes) -> Vec<std::thread::JoinHandle<()>>;

pub fn main(argv: &[String]) -> u8 {
    match run(argv, &RunEnv::real()) {
        Ok(code) => code,
        Err((code, msg)) => {
            eprintln!("derm run: {msg}");
            code
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn hostname() -> String {
    derm_core::platform::host_name()
}

fn new_chat_id() -> String {
    format!("derm-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
}

fn event(
    chat: &str,
    harness: &str,
    kind: &str,
    summary: String,
    detail: serde_json::Value,
    pid: Option<u32>,
) -> Event {
    Event {
        id: format!("run-{chat}-{}", uuid::Uuid::new_v4().simple()),
        at: now_ms(),
        chat_id: chat.to_string(),
        harness: harness.to_string(),
        source: Source::Run,
        kind: kind.to_string(),
        summary: summary.chars().take(200).collect(),
        detail,
        pid,
        approval_id: None,
    }
}

/// Writes srt's settings as a new 0600 file in a 0700 folder, refusing a
/// symlink at the file's place.
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        derm_core::platform::set_private_dir(dir)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => {
            return Err(std::io::Error::other(format!(
                "{} is not a regular file",
                path.display()
            )))
        }
        Ok(_) => std::fs::remove_file(path)?,
        Err(_) => {}
    }
    let mut f = derm_core::platform::private_no_follow(
        std::fs::OpenOptions::new().write(true).create_new(true),
    )
    .open(path)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()
}

struct Daemon {
    socket: PathBuf,
    token: String,
}

impl Daemon {
    fn post(&self, e: &Event) -> Result<(), String> {
        let (mut c, _) =
            Client::connect(&self.socket, &self.token, "derm run").map_err(|e| e.to_string())?;
        c.post(e).map(|_| ()).map_err(|e| e.to_string())
    }

    /// One post with the token file read again, for a daemon that restarted
    /// since `derm run` started. The new token must still give daemon scope,
    /// as at the start.
    fn post_after_restart(&self, e: &Event) -> Result<(), String> {
        let dir = self.socket.parent().ok_or("the socket has no folder")?;
        let token = client::read_daemon_token(dir).map_err(|e| e.to_string())?;
        if token == self.token {
            return Err("the token file has not changed".into());
        }
        let (mut c, hello) =
            Client::connect(&self.socket, &token, "derm run").map_err(|e| e.to_string())?;
        if hello.scope != "daemon" {
            return Err("the daemon's token file gave chat scope, not daemon scope".into());
        }
        c.post(e).map(|_| ()).map_err(|e| e.to_string())
    }
}

/// `lstat`, not `stat`: a regular file (no link followed), owned by this
/// user, one hard link, no group or other write bit (fix pass review R1).
#[cfg(unix)]
fn regular_private_file(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| {
        let uid = derm_core::platform::real_user();
        m.file_type().is_file() && m.uid() == uid && m.nlink() == 1 && m.mode() & 0o022 == 0
    })
}

/// The daemon's `cu.endpoint` (MW5-22): a regular private file of yours in
/// its folder, a loopback address and port and nothing else; `None` while
/// computer use is off (the daemon removes the file then, MW5-2).
fn read_cu_endpoint(dir: &Path) -> Option<String> {
    use std::io::Read;
    let file = dir.join("cu.endpoint");
    if !regular_private_file(&file) {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(&file)
        .ok()?
        .take(256)
        .read_to_string(&mut text)
        .ok()?;
    let text = text.trim();
    plan::cu_endpoint_ok(text).then(|| text.to_string())
}

/// The git files in the chat's folder srt's own denies leave out (FP8-S2,
/// re-review FP8R-5): each submodule's `config` and `hooks`, every
/// `config.worktree` git reads with `extensions.worktreeConfig` (the folder's
/// own, a submodule's, and each `.git/worktrees/<name>/`'s), by absolute path.
fn git_controls(cwd: &Path) -> Vec<String> {
    let git = cwd.join(".git");
    let mut out = Vec::new();
    let is_dir = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    if !is_dir(&git) {
        return out;
    }
    let mut push = |p: PathBuf| {
        if let Some(s) = p.to_str() {
            out.push(s.to_string());
        }
    };
    push(git.join("config.worktree"));
    for m in git_module_dirs(cwd) {
        let m = PathBuf::from(m);
        push(m.join("config"));
        push(m.join("config.worktree"));
        push(m.join("hooks"));
    }
    if let Ok(rd) = std::fs::read_dir(git.join("worktrees")) {
        for e in rd.flatten().take(256) {
            if is_dir(&e.path()) {
                push(e.path().join("config.worktree"));
            }
        }
    }
    out.sort();
    out
}

/// Each submodule's git folder under the chat's `.git/modules` (FP8-S2),
/// nested ones too (`modules/a/modules/b`), by absolute path: a folder there
/// holding a `config` or a `HEAD` is one. No link is followed, at most 8
/// levels and 256 folders; a `.git` that is a file (a worktree) has none here.
fn git_module_dirs(cwd: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut todo = vec![(cwd.join(".git").join("modules"), 0usize)];
    let is_dir = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    while let Some((dir, depth)) = todo.pop() {
        if depth > 8 || out.len() >= 256 || !is_dir(&dir) {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let d = e.path();
            if out.len() >= 256 || !is_dir(&d) {
                continue;
            }
            let module = ["config", "HEAD"]
                .iter()
                .any(|f| std::fs::symlink_metadata(d.join(f)).is_ok());
            if module {
                if let Some(s) = d.to_str() {
                    out.push(s.to_string());
                }
                todo.push((d.join("modules"), depth + 1));
            } else {
                // A submodule named `a/b` sits at `modules/a/b`.
                todo.push((d, depth + 1));
            }
        }
    }
    out.sort();
    out
}

/// MW5-32's Linux half (fix pass 8): Codex 0.163.0 reads its config at start
/// and treats any error but "not found" as fatal
/// (`config/src/loader/mod.rs:560-575`), and srt 0.0.81 holds a missing
/// `denyWrite` file by binding `/dev/null` over it, which reads as
/// "Permission denied" inside srt (run in the cloud: Codex stopped with
/// "Failed to read config file ~/.codex/config.toml: Permission denied"). So
/// before a Codex chat under srt on Linux, derm makes what is missing: the
/// folder `~/.codex` (0700, which Codex makes on its first run anyway) and an
/// empty `~/.codex/config.toml` (0600: an empty file is read as no settings,
/// the same as none). Nothing that exists is touched, a link included.
/// Returns what was made, for the start line.
#[cfg(unix)]
fn codex_home_for_srt(home: &Path) -> Result<Vec<String>, String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let mut made = Vec::new();
    let dir = home.join(".codex");
    match std::fs::symlink_metadata(&dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            made.push(dir.display().to_string());
        }
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_dir()) {
        return Ok(made);
    }
    let config = dir.join("config.toml");
    match std::fs::symlink_metadata(&config) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&config)
                .map_err(|e| format!("{}: {e}", config.display()))?;
            made.push(config.display().to_string());
        }
        Err(e) => return Err(format!("{}: {e}", config.display())),
    }
    Ok(made)
}

/// The policy `derm acp` and goose's ask mode decide with (integration w5's
/// Windows fix pass, reviews FPW-S2, FPWR-4, FPWR-5), loaded by the hook
/// core's rules (`loadPolicyFrom`, `loadPolicy` in
/// `packages/derm-claude-plugin/src/core/policy.ts`): a `DERM_POLICY` inside
/// the folder the chat starts in is refused (a project can set it there);
/// the file is opened once (links followed on Unix, as the hook's `openSync`;
/// on Windows a folder with a link or junction on its path is refused by
/// lane Z's check), and that handle is judged and read, so the file checked
/// is the file applied (review FPWR-6); on Unix it is the user's own
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
    let file = match std::fs::File::open(p) {
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
    if !policy_file_private(&file, &meta) {
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
    match derm_core::policy::parse(&text) {
        Ok(policy) => (policy, None),
        Err(problem) => empty(problem.to_string()),
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
fn policy_file_private(_file: &std::fs::File, meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.uid() == derm_core::platform::real_user() && meta.mode() & 0o022 == 0
}

#[cfg(windows)]
fn policy_file_private(file: &std::fs::File, _meta: &std::fs::Metadata) -> bool {
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

/// Windows (lane Z): a regular file of this user's, one link, that no one
/// else may write.
#[cfg(windows)]
fn regular_private_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
        && derm_core::platform::windows::only_owner_writes(path)
}

/// The argv a run record keeps. derm's own part (the wrapper and its flags,
/// the harness program) is kept; the harness's own arguments, which every
/// plan appends last, keep their flag names and lose every other word to its
/// length, unless `content` (Mac test w1, finding M8: a `-p "<prompt>"` sat
/// in the activity log). Both go through the secret redactor (S13).
///
/// `export` is where the OTel export's words sit in `args`: derm's, but its
/// `--settings` value copies the user's own `--settings`, so the record keeps
/// only its length, whatever `content` says (security review L5).
/// The daemon's data folder for `home`, by the daemon's own rule
/// (`derm_daemon::daemon::default_data_dir`), so a content file `derm run`
/// writes is where the daemon's purge looks. A daemon started with
/// `--data-dir` (tests) does not purge it.
/// Makes `path` 0700 if it is missing, its parents as `create_dir_all`
/// makes them (only the last part is private, as the daemon's own folder).
#[cfg(all(unix, not(target_os = "macos")))]
fn make_private_folder(path: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::DirBuilder::new().mode(0o700).create(path);
}

pub(crate) fn content_root(home: &str) -> PathBuf {
    if cfg!(target_os = "macos") {
        return Path::new(home).join("Library/Application Support/derm");
    }
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| Path::new(home).join(".local/share"))
        .join("derm")
}

/// With the content switch on, `run.start`'s argument words, unmasked but
/// through the secret redactor (`recorded_argv`), go to a content file
/// (`<data>/content/<chat>/<ms>-r<days>-run_<id>.argv`, 0600 in a 0700
/// folder) for the retention chosen; the record keeps the masked form and
/// the file's name. Returns the name, or why it was not written.
fn keep_argv(home: &str, chat: &str, days: u8, words: &[String]) -> Option<Result<String, String>> {
    let target = derm_tap::content::Target {
        root: content_root(home),
        retention_days: days,
    };
    // The daemon makes its data folder at its first start; a chat may come
    // first. Made private, as the daemon's own folders are.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&target.root)
        {
            return Some(Err(e.to_string()));
        }
    }
    #[cfg(not(unix))]
    if let Err(e) = std::fs::create_dir_all(&target.root) {
        return Some(Err(e.to_string()));
    }
    let id = format!("run_{}", uuid::Uuid::new_v4().simple());
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    Some(
        derm_tap::content::open(&target, chat, at, &id, "argv")
            .map_err(|e| e.to_string())
            .and_then(|mut f| {
                f.append(json!(words).to_string().as_bytes());
                if f.failed {
                    return Err("the write failed".into());
                }
                f.path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .ok_or_else(|| "no file name".into())
            }),
    )
}

/// Where the harness's own words (`rest`, from after `--`) start in `args`.
/// `plan.rs` appends them last; the tap may then splice its block inside
/// them, after a session subcommand (Codex's `exec`, `app-server`), so they
/// are a prefix of `rest`, one block of derm's words, then the rest of
/// `rest` (Mac test w5, MW5-6). `None` when `args` holds no such split.
fn words_at(args: &[String], rest: &[String]) -> Option<usize> {
    if args.ends_with(rest) {
        return Some(args.len() - rest.len());
    }
    // A prefix of `rest` (at least its first word), a block, then the
    // remaining words at the end. The latest start that fits wins: derm's
    // own words (srt's settings, `--`, the command) come before the user's.
    for k in (1..=rest.len()).rev() {
        let (head, tail) = rest.split_at(k);
        if !args.ends_with(tail) {
            continue;
        }
        let tail_at = args.len() - tail.len();
        if let Some(i) = (0..=tail_at.saturating_sub(k))
            .rev()
            .find(|&i| i + k < tail_at && args[i..i + k] == *head)
        {
            return Some(i);
        }
    }
    None
}

/// What the OS feeds will name as the harness's executable, by its real
/// path: the program as given or the first match on PATH, with every link
/// resolved, or, for a script, the interpreter its `#!` line names (through
/// `env`, looked up on PATH), since the kernel records the interpreter, not
/// the script (re-review R1: Codex, Gemini CLI and Pi from npm are
/// `#!/usr/bin/env node` scripts). None when it cannot be found.
fn harness_exe(program: &str, path: Option<&str>) -> Option<String> {
    harness_exe_with(program, path, pi_agent_dir().as_deref())
}

/// Pi's agent folder as Pi finds it: `PI_CODING_AGENT_DIR` (a leading `~`
/// read as the home), else `~/.pi/agent` (Pi 1.4.0 `packages/coding-agent/
/// src/config.ts:584-611`, `getAgentDir`).
fn pi_agent_dir() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    match std::env::var("PI_CODING_AGENT_DIR") {
        Ok(d) if !d.is_empty() => {
            if d == "~" {
                home
            } else if let Some(rest) = d.strip_prefix("~/") {
                home.map(|h| h.join(rest))
            } else {
                Some(std::path::PathBuf::from(d))
            }
        }
        _ => home.map(|h| h.join(".pi").join("agent")),
    }
}

fn harness_exe_with(
    program: &str,
    path: Option<&str>,
    pi_agent: Option<&std::path::Path>,
) -> Option<String> {
    fn resolve(program: &str, path: Option<&str>) -> Option<std::path::PathBuf> {
        let found = if program.contains('/') {
            std::path::PathBuf::from(program)
        } else {
            crate::watch::status::find_on_path(program, path?)?
        };
        let real = std::fs::canonicalize(found).ok()?;
        real.is_absolute().then_some(real)
    }
    let mut real = resolve(program, path)?;
    // Pi's own installer puts a `/bin/sh` launcher in front of the release
    // it execs (box test w5 retest, BW5R-5): name what that release runs.
    // Only Pi's own launcher, in Pi's own agent folder (review FP9-S5: a
    // `bin/pi` elsewhere with an `install` folder an agent made beside it
    // could name any program as the harness).
    let own = pi_agent
        .and_then(|a| std::fs::canonicalize(a.join("bin").join("pi")).ok())
        .is_some_and(|l| l == real);
    if let Some(release) = own.then(|| pi_managed_release(&real)).flatten() {
        real = release;
    }
    // At most two `#!` hops (a script run by another script), as the
    // kernel's own limit is a few; each line read capped at 256 bytes.
    for _ in 0..2 {
        let mut head = [0u8; 256];
        let n = std::fs::File::open(&real)
            .and_then(|mut f| std::io::Read::read(&mut f, &mut head))
            .unwrap_or(0);
        let Some(line) = head[..n].strip_prefix(b"#!") else {
            break;
        };
        let line =
            String::from_utf8_lossy(line.split(|b| *b == b'\n').next().unwrap_or(&[])).into_owned();
        let mut words = line.split_whitespace();
        let interp = words.next()?;
        let interp = if std::path::Path::new(interp)
            .file_name()
            .is_some_and(|n| n == "env")
        {
            // `env [-S] name ...`: the first word that is not an option.
            words
                .find(|w| !w.starts_with('-') && !w.contains('='))?
                .to_string()
        } else {
            interp.to_string()
        };
        real = resolve(&interp, path)?;
    }
    Some(real.to_string_lossy().into_owned())
}

/// The release a Pi managed-install launcher execs, by its real path (box
/// test w5 retest, BW5R-5). Pi's installer writes the launcher at
/// `<agent dir>/bin/pi` and the managed root at `<agent dir>/install`, whose
/// `managed-install.json` says `{"kind": "pi-managed-install",
/// "schemaVersion": 1, "layout": "releases-v1"}`, whose `current-version`
/// names the active release, and whose `releases/<version>/node_modules/
/// .bin/pi` is that release's program (Pi 1.4.0 `packages/coding-agent/src/
/// package-manager-cli.ts:50-80, 123-133, 192-220`; the launcher's place and
/// its exec, the PiDeck project's install notes and puppyone's Pi locator,
/// which find `bin` beside the managed root). The launcher's own text is not
/// read: derm takes the release only when the launcher is a `#!` shell
/// script named `pi` in a folder `bin`, the marker is Pi's, the version is
/// a plain version, and the program's real path stays under the root's
/// `releases`. Whether the launcher puts a Node of its own first on `PATH`
/// was not found; derm resolves the release's `#!/usr/bin/env node` on the
/// `PATH` it runs with, as for an npm install (inferred).
fn pi_managed_release(launcher: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::io::Read;
    if launcher.file_name()? != "pi" {
        return None;
    }
    let bin = launcher.parent()?;
    if bin.file_name()? != "bin" {
        return None;
    }
    let mut head = [0u8; 64];
    let n = std::fs::File::open(launcher)
        .and_then(|mut f| f.read(&mut head))
        .ok()?;
    let line = head[..n].strip_prefix(b"#!")?;
    let interp = String::from_utf8_lossy(line.split(|b| *b == b'\n').next()?).into_owned();
    let mut words = interp.split_whitespace();
    let first = words.next()?;
    let shell = match std::path::Path::new(first).file_name()?.to_str()? {
        "env" => words.next().unwrap_or(""),
        other => other,
    }
    .to_string();
    if !matches!(shell.as_str(), "sh" | "bash" | "dash") {
        return None;
    }
    let root = bin.parent()?.join("install");
    let small = |name: &str| -> Option<String> {
        let mut text = String::new();
        std::fs::File::open(root.join(name))
            .ok()?
            .take(4096)
            .read_to_string(&mut text)
            .ok()?;
        Some(text)
    };
    let marker: serde_json::Value = serde_json::from_str(&small("managed-install.json")?).ok()?;
    if marker.get("kind").and_then(serde_json::Value::as_str) != Some("pi-managed-install")
        || marker
            .get("schemaVersion")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        || marker.get("layout").and_then(serde_json::Value::as_str) != Some("releases-v1")
    {
        return None;
    }
    let version = small("current-version")?.trim().to_string();
    // Pi's own check (`MANAGED_RELEASE_VERSION_RE`): digits and dots, then
    // an optional `-` or `+` tag of letters, digits, dots and dashes.
    let core: Vec<&str> = version.split(['-', '+']).next()?.split('.').collect();
    let plain = core.len() == 3
        && core
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'));
    if !plain {
        return None;
    }
    let releases = std::fs::canonicalize(root.join("releases")).ok()?;
    let program = std::fs::canonicalize(
        releases
            .join(&version)
            .join("node_modules")
            .join(".bin")
            .join("pi"),
    )
    .ok()?;
    program.starts_with(&releases).then_some(program)
}

/// Codex's target triple and platform package name for this machine, as its
/// npm launcher maps Node's `process.platform` and `process.arch`
/// (`@openai/codex` `bin/codex.js:16-68` at 0.163.0 and 0.167.0). Read from
/// derm's own build, which matches Node's on the machines derm ships for
/// (an x64 Node under Rosetta on an arm64 Mac would not: not handled).
fn codex_platform() -> Option<(&'static str, &'static str)> {
    Some(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux" | "android", "x86_64") => ("x86_64-unknown-linux-musl", "codex-linux-x64"),
        ("linux" | "android", "aarch64") => ("aarch64-unknown-linux-musl", "codex-linux-arm64"),
        ("macos", "x86_64") => ("x86_64-apple-darwin", "codex-darwin-x64"),
        ("macos", "aarch64") => ("aarch64-apple-darwin", "codex-darwin-arm64"),
        ("windows", "x86_64") => ("x86_64-pc-windows-msvc", "codex-win32-x64"),
        ("windows", "aarch64") => ("aarch64-pc-windows-msvc", "codex-win32-arm64"),
        _ => return None,
    })
}

/// The binary a launcher script starts as the harness, by its real path
/// (Mac test w5 retest 6, MW5-28; `harnessChildExe` in `run.start`). Known
/// for one launcher: Codex's npm package, whose `bin/codex.js` spawns its
/// native binary as a child at 0.163.0 (`bin/codex.js:241`) and replaces
/// itself with it where Node has `process.execve` at 0.167.0
/// (`bin/codex.js:236-243`). Found as the launcher finds it
/// (`findCodexExecutable`, `bin/codex.js:79-110`): `require.resolve` of the
/// platform package from the script's folder (Node's `node_modules` walk up
/// the real path, skipping a folder itself named `node_modules`), else the
/// package's own `vendor` folder. None for any other program, and when that
/// binary is not there (the launcher then starts nothing). `NODE_PATH` and
/// Node's global folders are not read.
fn harness_child_exe(program: &str, path: Option<&str>) -> Option<String> {
    let found = if program.contains('/') {
        std::path::PathBuf::from(program)
    } else {
        crate::watch::status::find_on_path(program, path?)?
    };
    let script = std::fs::canonicalize(found).ok()?;
    if script.file_name()? != "codex.js" {
        return None;
    }
    let bin = script.parent()?;
    if bin.file_name()? != "bin" {
        return None;
    }
    let root = bin.parent()?;
    // The package's own manifest names it, read whole up to 1 MiB.
    let file = std::fs::File::open(root.join("package.json")).ok()?;
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::Read::take(file, 1 << 20), &mut text).ok()?;
    let manifest = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    if manifest.get("name").and_then(serde_json::Value::as_str) != Some("@openai/codex") {
        return None;
    }
    let (triple, plat) = codex_platform()?;
    let vendor = bin
        .ancestors()
        .filter(|d| d.file_name().is_none_or(|n| n != "node_modules"))
        .map(|d| d.join("node_modules").join("@openai").join(plat))
        .find(|p| p.join("package.json").is_file())
        .unwrap_or_else(|| root.to_path_buf())
        .join("vendor");
    let exe =
        vendor
            .join(triple)
            .join("bin")
            .join(if cfg!(windows) { "codex.exe" } else { "codex" });
    let real = std::fs::canonicalize(exe).ok()?;
    real.is_file().then(|| real.to_string_lossy().into_owned())
}

/// `range` (words in `before`) as it sits in `after`, where words were
/// put in right after `before`'s first `--` (`srt_loopback_through_proxy`);
/// a range after that point moves by as many words (FP4-S8).
fn shift_after_wrap(
    range: Option<std::ops::Range<usize>>,
    before: &[String],
    after: &[String],
) -> Option<std::ops::Range<usize>> {
    let range = range?;
    let grown = after.len().saturating_sub(before.len());
    match before.iter().position(|w| w == "--") {
        Some(dd) if grown > 0 && range.start > dd => Some(range.start + grown..range.end + grown),
        _ => Some(range),
    }
}

fn recorded_argv(
    program: &str,
    args: &[String],
    rest: &[String],
    content: bool,
    export: Option<std::ops::Range<usize>>,
) -> Vec<String> {
    let mask = |w: &String| -> String {
        if content {
            return w.clone();
        }
        let n = |v: &str| format!("[{} chars]", v.chars().count());
        // A flag is `-x` or `--name`, letters, digits and `-` after the first
        // letter, at most 40 (review R6: `-pPROMPT`, or a prompt that starts
        // with `-`, was kept whole).
        let flag = |f: &str| {
            let name = f
                .strip_prefix("--")
                .or_else(|| f.strip_prefix('-'))
                .unwrap_or("");
            let short = !f.starts_with("--");
            name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && if short {
                    name.len() == 1
                } else {
                    name.len() <= 41
                }
        };
        if w == "--" {
            return w.clone();
        }
        match w.split_once('=') {
            Some((f, value)) if flag(f) => format!("{f}={}", n(value)),
            None if flag(w) => w.clone(),
            _ => n(w),
        }
    };
    // Where the user's words start; with none found, mask everything.
    let split = words_at(args, rest).unwrap_or(0);
    let mut out = vec![program.to_string()];
    for (i, w) in args.iter().enumerate() {
        let exported = export.as_ref().is_some_and(|r| r.contains(&i));
        // derm's own words: everything before the user's, and the export,
        // which for Codex follows a session subcommand (MW5-15).
        if i < split || exported {
            let settings = i > 0 && args[i - 1] == "--settings";
            if exported && settings {
                out.push(format!("[derm otel settings, {} chars]", w.chars().count()));
            } else {
                out.push(w.clone());
            }
        } else {
            out.push(mask(w));
        }
    }
    derm_audit_linux::redact::argv(&out)
}

/// `derm acp`'s entry: `derm run` with the harness's stdin and stdout
/// handed to `filter` (T2.9).
pub(crate) fn main_with(argv: &[String], filter: StdioFilter) -> u8 {
    match run_io(argv, &RunEnv::real(), Some(filter)) {
        Ok(code) => code,
        Err((code, msg)) => {
            eprintln!("derm acp: {msg}");
            code
        }
    }
}

fn run(argv: &[String], env: &RunEnv) -> Result<u8, (u8, String)> {
    run_io(argv, env, None)
}

/// A folder this user owns (Unix: its uid).
#[cfg(unix)]
fn folder_of_mine(_at: &Path, m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    m.uid() == derm_core::platform::real_user()
}

/// Windows (lane Z): owned by this user, and no reparse point.
#[cfg(windows)]
fn folder_of_mine(at: &Path, _m: &std::fs::Metadata) -> bool {
    derm_core::platform::windows::owned_plain_dir(at)
}

/// A folder of the chat's alone: made 0700 with no link at its place, its
/// parents made 0700 when new. Removed after the run.
/// Every folder between `home` (left out) and `path` (left out) that exists
/// is a real folder of this user's: no link, so nothing derm does to `path`
/// lands in another folder (security review L11). A path outside `home` has
/// its parent checked alone.
fn no_link_above(path: &Path, home: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let (mut at, rest) = match parent.strip_prefix(home) {
        Ok(rel) => (home.to_path_buf(), rel.to_path_buf()),
        Err(_) => (PathBuf::new(), parent.to_path_buf()),
    };
    let parts: Vec<_> = rest.components().collect();
    let skip = if at.as_os_str().is_empty() {
        parts.len().saturating_sub(1)
    } else {
        0
    };
    for (n, c) in parts.iter().enumerate() {
        at.push(c);
        if n < skip {
            continue;
        }
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() || !folder_of_mine(&at, &m) => {
                return Err(std::io::Error::other(format!(
                    "{} is a link, not a folder, or not yours; derm will not make the chat's folder under it",
                    at.display()
                )))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Removes the chat's folder made by `make_private_dir`, unless a link has
/// appeared above it or at its place since. `true` when it was removed.
fn remove_private_dir(path: &Path, home: &Path) -> bool {
    if no_link_above(path, home).is_err() {
        return false;
    }
    match std::fs::symlink_metadata(path) {
        // `remove_dir_all` removes a link put inside, never its target.
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => std::fs::remove_dir_all(path).is_ok(),
        _ => false,
    }
}

/// A folder of the chat's alone: made 0700 with no link at its place or
/// above it, its parents made 0700 when new. Removed after the run.
fn make_private_dir(path: &Path, home: &Path) -> std::io::Result<()> {
    no_link_above(path, home)?;
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            derm_core::platform::set_private_dir(parent)?;
        }
    }
    no_link_above(path, home)?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            return Err(std::io::Error::other(format!(
                "{} is in the way (not a folder)",
                path.display()
            )))
        }
        Ok(_) => {}
        Err(_) => std::fs::create_dir(path)?,
    }
    derm_core::platform::set_private_dir(path)
}

/// What a run leaves to undo, on every way out of `run_io` (security review
/// L12): the companion and its group stopped, the files and folders made
/// for the chat removed.
#[derive(Default)]
struct Cleanup {
    companion: Option<std::process::Child>,
    files: Vec<PathBuf>,
    /// Folders `make_private_dir` made, with the HOME they are checked from.
    private_dirs: Vec<(PathBuf, PathBuf)>,
    dirs: Vec<PathBuf>,
    /// The OTel export wrote a helper script (it prints the chat token):
    /// `remove_helpers` removes it and the receiver's memory of it.
    otel_helpers: bool,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(c) = self.companion.as_mut() {
            exec::stop_companion(c, Duration::from_secs(2));
        }
        for f in &self.files {
            let _ = std::fs::remove_file(f);
        }
        for (d, home) in &self.private_dirs {
            remove_private_dir(d, home);
        }
        for d in &self.dirs {
            let _ = std::fs::remove_dir_all(d);
        }
        if self.otel_helpers {
            derm_daemon::otel_receiver::remove_helpers();
        }
    }
}

/// Points Claude Code or Codex at the daemon's OTLP receiver for this chat
/// (`derm_daemon::otel_receiver::apply_export`, which lane B built and lane D
/// deferred; integration w1's request for lane R). The export's arguments go
/// right after the harness's command, before the user's own; its variables
/// join the plan's. Nothing changes when the user already exports OTel, the
/// endpoint is not loopback (sbx), or the harness has no export. Returns
/// what was done, for the run record.
fn wire_export(
    p: &mut plan::Plan,
    rest: &[String],
    harness: &str,
    otlp: Option<&str>,
    token: Option<&str>,
    helper_dir: Option<&Path>,
    log_prompts: bool,
) -> (serde_json::Value, Option<std::ops::Range<usize>>) {
    use derm_daemon::otel_receiver::{apply_export, Applied, Export};
    let (Some(endpoint), Some(token)) = (otlp, token) else {
        return (json!("no endpoint or no token"), None);
    };
    // The endpoint as the plan gives it to the harness (sbx rewrites it).
    let endpoint = p
        .env_set
        .iter()
        .find(|(k, _)| k == "DERM_OTLP_ENDPOINT")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| endpoint.to_string());
    let mut cmd = std::process::Command::new("harness");
    for name in &p.env_remove {
        cmd.env_remove(name);
    }
    for (k, v) in &p.env_set {
        cmd.env(k, v);
    }
    let applied = apply_export(
        &Export {
            harness,
            endpoint: &endpoint,
            token,
            log_prompts,
            helper_dir,
        },
        rest,
        &mut cmd,
    );
    if let Applied::StoodDown(why) = applied {
        return (json!(format!("stood down: {why}")), None);
    }
    let added: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // Before the user's first word, wherever the tap spliced its own block
    // (MW5-6). For Codex, every `-c` sits on one side of a session
    // subcommand: its `-c` is a clap global argument, and clap 4.5.58 keeps
    // the subcommand's occurrences and drops the root's when both are given
    // (`clap_builder` `parser/arg_matcher.rs:53-78`; run against Codex
    // 0.163.0, retest 4's MW5-15). The tap's pairs follow a session
    // subcommand, so the export follows it too.
    let mut at = words_at(&p.args, rest).unwrap_or(p.args.len().saturating_sub(rest.len()));
    if matches!(applied, Applied::Codex)
        && p.args
            .get(at)
            .is_some_and(|w| tap::CODEX_SESSION_SUBCOMMANDS.contains(&w.as_str()))
    {
        at += 1;
    }
    let range = at..at + added.len();
    p.args.splice(at..at, added);
    for (k, v) in cmd.get_envs() {
        let k = k.to_string_lossy().into_owned();
        let already = p.env_set.iter().any(|(n, _)| *n == k);
        match v {
            Some(v) if !already => p.env_set.push((k, v.to_string_lossy().into_owned())),
            None if !p.env_remove.contains(&k) => p.env_remove.push(k),
            _ => {}
        }
    }
    let what = json!(match applied {
        Applied::Claude { helper: Some(_) } => "claude-code, token through otelHeadersHelper",
        Applied::Claude { helper: None } => "claude-code, token in OTEL_EXPORTER_OTLP_HEADERS",
        Applied::Codex => "codex",
        Applied::StoodDown(_) => "stood down",
    });
    (what, Some(range))
}

/// `--help` (usage on stdout, exit 0) or an argument error (exit 2),
/// checked with a stand-in boundary when none is named, so nothing is probed
/// for either (MW5-1). `None` when the arguments read.
fn before_the_probes(argv: &[String]) -> Option<Result<u8, (u8, String)>> {
    let own = argv.iter().take_while(|a| *a != "--");
    if own.clone().any(|a| a == "--help" || a == "-h") {
        println!("{}", args::USAGE);
        return Some(Ok(0));
    }
    let mut trial = argv.to_vec();
    if !own
        .clone()
        .any(|a| a == "--boundary" || a.starts_with("--boundary="))
    {
        let at = trial.iter().position(|a| a == "--").unwrap_or(trial.len());
        trial.splice(at..at, ["--boundary".to_string(), "none".to_string()]);
    }
    match args::parse(&trial) {
        Ok(_) => None,
        Err(e) => Some(Err((2, e))),
    }
}

fn run_io(argv: &[String], env: &RunEnv, filter: Option<StdioFilter>) -> Result<u8, (u8, String)> {
    // Help and argument errors before any probe (Mac test w5, MW5-1: `derm
    // run --help` ran `sbx version` and `sbx ls`, which can start sbx's
    // daemon, and then said no boundary was available).
    if let Some(early) = before_the_probes(argv) {
        return early;
    }
    // The boundary choice reads the raw argv first (lane T's seam).
    let choice = boundary::choose(argv)?;
    let a = args::parse(&choice.argv).map_err(|e| (2, e))?;
    let cwd_raw = match &a.cwd {
        Some(c) => PathBuf::from(c),
        None => std::env::current_dir().map_err(|e| (1, format!("current folder: {e}")))?,
    };
    let cwd = std::fs::canonicalize(&cwd_raw)
        .map_err(|e| (2, format!("--cwd {}: {e}", cwd_raw.display())))?;
    if !cwd.is_dir() {
        return Err((2, format!("{} is not a folder", cwd.display())));
    }
    let cwd = cwd
        .to_str()
        .ok_or((2, "the working folder's path is not UTF-8".to_string()))?
        .to_string();
    let home = env.home.clone().filter(|h| args::absolute(h)).ok_or((
        2,
        format!(
            "{} is not set to an absolute path",
            if cfg!(windows) { "USERPROFILE" } else { "HOME" }
        ),
    ))?;
    let chat = a.chat.clone().unwrap_or_else(new_chat_id);

    // The daemon, unless the user said to run without it.
    let socket = env.socket.clone();
    let dir = socket
        .as_ref()
        .and_then(|s| s.parent().map(Path::to_path_buf));
    let mut daemon = None;
    let mut token = None;
    let mut otlp = None;
    if !a.no_daemon {
        let (Some(socket), Some(dir)) = (socket.clone(), dir.clone()) else {
            return Err((
                1,
                "no daemon socket path (HOME and XDG_RUNTIME_DIR are unset)".into(),
            ));
        };
        otlp = client::read_otlp_endpoint(&dir);
        if !a.dry_run {
            let hint = "start derm-daemon, or pass --no-daemon to run with no token and no feed";
            let dtoken =
                client::read_daemon_token(&dir).map_err(|e| (1, format!("{e}; {hint}")))?;
            let (mut c, hello) = Client::connect(&socket, &dtoken, "derm run")
                .map_err(|e| (1, format!("{e}; {hint}")))?;
            if hello.scope != "daemon" {
                return Err((
                    1,
                    "the daemon's token file gave chat scope, not daemon scope".into(),
                ));
            }
            token = Some(
                c.mint(&chat, a.harness.id)
                    .map_err(|e| (1, e.to_string()))?,
            );
            daemon = Some(Daemon {
                socket,
                token: dtoken,
            });
        }
        if otlp.is_none() {
            eprintln!("derm run: the daemon published no loopback OTLP endpoint; the harness's emitter stays off");
        }
    } else {
        eprintln!("derm run: --no-daemon: no chat token, no feed, nothing recorded");
    }
    let gateway = a
        .gateway_url
        .clone()
        .or_else(|| env.gateway.clone().filter(|v| !v.is_empty()));
    let state_root = dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(&home).join(".derm/run/derm"));
    let settings_path = state_root.join("srt").join(format!("{chat}.json"));
    let token_path = state_root.join("chats").join(format!("{chat}.token"));
    // The policy the gate will read, loaded only to know whether it can ask
    // (goose's mode, T2.9). A missing or bad file asks for everything.
    let policy_path = env
        .policy
        .clone()
        .filter(|p| args::absolute(p))
        .unwrap_or_else(|| format!("{}/.derm/policy.json", home.trim_end_matches('/')));
    // Loaded once, by the hook core's rules, for goose's ask mode here and
    // for `derm acp`'s answers (FPW-S2, FPWR-4, FPWR-5).
    let (policy_file, policy_problem) = load_policy_checked(
        &policy_path,
        env.policy.as_deref().is_some_and(args::absolute),
        &cwd,
    );
    let missing = derm_core::policy::LoadProblem::Missing.to_string();
    if let Some(why) = policy_problem.as_ref().filter(|w| **w != missing) {
        eprintln!("derm run: {policy_path}: {why}");
    }
    let policy_asks = plan::policy_asks(policy_problem.is_none().then_some(&policy_file));
    // Cline's approval folder sits in its own state, which it can write
    // under srt as under none (T2.9).
    let cline_dir = format!("{}/.cline/derm-approval/{chat}", home.trim_end_matches('/'));
    let inputs = plan::Inputs {
        args: &a,
        chat: chat.clone(),
        cwd: cwd.clone(),
        home: home.clone(),
        token: token.clone(),
        otlp,
        gateway,
        daemon_dir: dir.as_ref().and_then(|d| d.to_str()).map(str::to_string),
        daemon_socket: daemon
            .as_ref()
            .and_then(|d| d.socket.to_str())
            .map(str::to_string),
        settings_path: settings_path.to_string_lossy().into_owned(),
        token_file: token_path.to_string_lossy().into_owned(),
        policy: policy_path.clone(),
        policy_regular: false,
        policy_asks,
        goose_mode: env.goose_mode.clone(),
        cline_dir,
        cline_responder: env.cline_responder.clone(),
        // Re-review FP5-R2: what derm's registered Cursor gate runs stays
        // read-only under srt.
        gate_paths: if a.harness.id == "cursor" && a.boundary == Boundary::Srt {
            crate::watch::register::derm_cursor_gate_paths(Path::new(&home))
        } else {
            Vec::new()
        },
        // FP8-S2, FP8R-5: the git files srt's own denies leave out.
        git_controls: if a.boundary == Boundary::Srt {
            git_controls(Path::new(&cwd))
        } else {
            Vec::new()
        },
        // MW5-22: the computer-use bridge's address, when the daemon
        // publishes one (computer use on), for srt's settings.
        cu_endpoint: dir.as_deref().and_then(read_cu_endpoint),
        macos: cfg!(target_os = "macos"),
        terminal: std::io::IsTerminal::is_terminal(&std::io::stdin()),
        // FP5R-5: read only for Codex under srt, where it decides.
        codex_store: if a.harness.id == "codex" && a.boundary == Boundary::Srt {
            codex_store::read(
                &home,
                &cwd,
                std::env::var("CODEX_HOME").ok().as_deref(),
                &codex_store::Roots::real(cfg!(target_os = "macos")),
            )
        } else {
            plan::CodexStoreFiles::default()
        },
    };
    let inputs = plan::Inputs {
        policy_regular: regular_private_file(Path::new(&inputs.policy)),
        ..inputs
    };
    let mut p = plan::build(&inputs).map_err(|e| (2, e))?;
    // The re-review's FP13RR-5: srt 0.0.81 holds a missing `denyWrite` path by
    // mounting over its first missing part on the host for the chat's life
    // (`linux-sandbox-utils.js:178-190, 2314-2331`), which would leave an
    // empty file where the daemon's data folder belongs. The folder is made
    // first, private, as the daemon makes it.
    // A dry run writes nothing and says what a run would make (fp13's second
    // re-review, FP13RR2-5); a run makes the folder 0700 and its missing
    // parents as `create_dir_all` makes them. The deny names the folder
    // `derm run` finds, which is the daemon's only when both read the same
    // `XDG_DATA_HOME` (FP13RR2-4, open).
    #[cfg(all(unix, not(target_os = "macos")))]
    if p.program == "srt" {
        let root = content_root(&inputs.home);
        if a.dry_run {
            if !root.exists() {
                p.notes.push(format!(
                    "derm run: before srt starts, derm makes {} (0700), since srt on Linux would hold a missing denied folder with an empty one",
                    root.display()
                ));
            }
        } else {
            make_private_folder(&root);
        }
    }
    // MW5-32's Linux half: a missing control folder is held as an empty one,
    // not a device (srt mounts over a missing denied path).
    plan::keep_absent_control_folders(&mut p, a.harness.id, inputs.macos, &|s: &str| {
        std::fs::symlink_metadata(s).is_ok()
    });
    // And Codex's config file, which it reads at start, is made empty if it
    // is missing (a missing one would be held by `/dev/null`).
    #[cfg(unix)]
    if a.harness.id == "codex" && a.boundary == Boundary::Srt && !inputs.macos {
        if a.dry_run {
            if !Path::new(&home).join(".codex/config.toml").exists() {
                p.notes.push("derm run: before Codex starts under srt on Linux, derm makes an empty ~/.codex/config.toml (0600) where none is, since srt would hold a missing one with /dev/null, which Codex cannot read".into());
            }
        } else {
            let made = codex_home_for_srt(Path::new(&home)).map_err(|e| (1, e))?;
            if !made.is_empty() {
                p.notes.push(format!(
                    "derm run: made {} (empty; Codex reads it at start, and srt on Linux would hold a missing one with /dev/null, which Codex cannot read)",
                    made.join(" and ")
                ));
            }
        }
    }
    // FP5R-6: srt's denies by their real paths too, where a link leads.
    plan::deny_real_paths(&mut p, &|s: &str| {
        real_path_lenient(Path::new(s)).and_then(|r| r.to_str().map(str::to_string))
    });
    // The model tap's launch environment (lane S's seam), unless `--no-tap`
    // (lane S's request 2, case 127): then the chat says it runs untapped.
    let tap_record = if a.no_tap {
        eprintln!(
            "derm run: --no-tap: this chat runs untapped; its gate and the OS feed still record it"
        );
        Some(json!({"on": false, "via": "none", "reason": "no-tap-flag"}))
    } else {
        tap::environment(a.harness.id, &mut p)?
    };
    // Content capture's switch as the chat starts (lane S's request 3). It
    // replaced DERM_LOG_CONTENT (request 3's rest, integration w5): with it
    // on, the harness's own argument words and its OTel prompts go to
    // content files, never to a record.
    let content_record = Some(tap::content_record(Some(&home)));
    let content_days = content_record
        .as_ref()
        .and_then(|c| c.get("retentionDays"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|d| u8::try_from(d).ok());
    // Claude Code's and Codex's own OTel into the daemon (T2.9). The helper
    // script sits in the daemon's folder under `none`; srt hides that folder,
    // so there the token goes in the header variable, as the chat token
    // already sits in the harness's environment (case 66).
    let helper_dir = state_root.join("otel-helper").join(&chat);
    let mut cleanup = Cleanup::default();
    if !a.dry_run {
        // The helper script prints the chat token: it goes on every way out.
        cleanup.dirs.push(helper_dir.clone());
    }
    let (export, export_at) = if a.dry_run {
        (json!("dry run"), None)
    } else {
        wire_export(
            &mut p,
            &a.rest,
            a.harness.id,
            inputs.otlp.as_deref(),
            token.as_deref(),
            (a.boundary == Boundary::None).then_some(helper_dir.as_path()),
            content_days.is_some(),
        )
    };
    // Only a run that wrote a helper clears the receiver's helpers: one
    // `derm run` is one chat, so they are this run's.
    cleanup.otel_helpers = export == json!("claude-code, token through otelHeadersHelper");
    plan::no_token_in_args(&p, token.as_deref()).map_err(|e| (1, e))?;
    // Under srt, derm's loopback ports through srt's proxy (MW5-5). Last of
    // the argv edits: the tap and the export read the command's position.
    let before = p.args.clone();
    plan::srt_loopback_through_proxy(&mut p);
    // The wrap goes in after srt's `--`, before the export: the export's
    // range moves with it (fix pass 4's review, FP4-S8).
    let export_at = shift_after_wrap(export_at, &before, &p.args);
    // And Claude Code's OTel export, which takes no proxy for a loopback
    // name (MW5-15).
    plan::srt_otlp_through_proxy(&mut p);
    // srt's dependencies and the userns sysctl, before srt fails on them with
    // its own errors (box test w1, BX3 and BX4); the copies srt would run
    // outside the sandbox, never from a folder the sandbox can write, and
    // handed to srt by absolute path (fix pass review R3).
    if a.boundary == Boundary::Srt {
        let mut writable: Vec<String> = p.folders.clone();
        writable.extend(p.state_dirs.iter().cloned());
        writable.push(plan::srt_temp_root(cfg!(target_os = "macos")).into());
        match preflight::srt_with(
            &env.path,
            cfg!(target_os = "linux"),
            env.userns.as_deref(),
            env.bwrap_profile,
            &writable,
            &cwd,
        ) {
            Ok((notes, tools)) => {
                notes.iter().for_each(|n| eprintln!("{n}"));
                if let (Some(t), Some(text)) = (tools, p.srt_settings.as_deref()) {
                    let mut v: serde_json::Value =
                        serde_json::from_str(text).map_err(|e| (1, e.to_string()))?;
                    v["bwrapPath"] = json!(t.bwrap);
                    v["socatPath"] = json!(t.socat);
                    v["ripgrep"] = json!({ "command": t.rg });
                    p.srt_settings =
                        Some(serde_json::to_string_pretty(&v).map_err(|e| (1, e.to_string()))?);
                }
            }
            Err(e) if a.dry_run => eprintln!("derm run: {e}"),
            Err(e) => return Err((1, e)),
        }
    }
    if a.dry_run {
        print!("{}", plan::describe(&p));
        // BW5-5's rest: under sbx the plan's one-step argv is not what runs.
        if a.boundary == Boundary::Sbx {
            if let Some(steps) = boundary::sbx::describe_steps(&p.args, &p.env_set) {
                print!("{steps}");
            }
        }
        if !a.no_daemon {
            println!("(dry run: no token minted, nothing started, nothing recorded)");
        }
        return Ok(0);
    }
    for n in &p.notes {
        eprintln!("{n}");
    }
    if let Some(text) = &p.srt_settings {
        write_private(&settings_path, text)
            .map_err(|e| (1, format!("{}: {e}", settings_path.display())))?;
        cleanup.files.push(settings_path.clone());
    }
    let token_file_named = p.env_set.iter().any(|(k, _)| k == "DERM_CHAT_TOKEN_FILE");
    if let (true, Some(t)) = (token_file_named, &token) {
        write_private(&token_path, &format!("{t}\n"))
            .map_err(|e| (1, format!("{}: {e}", token_path.display())))?;
        cleanup.files.push(token_path.clone());
    }
    if let Some(dir) = &p.scratch_dir {
        make_private_dir(Path::new(dir), Path::new(&home))
            .map_err(|e| (1, format!("{dir}: {e}")))?;
        cleanup
            .private_dirs
            .push((PathBuf::from(dir), PathBuf::from(&home)));
    }
    // The companion runs as the user, outside any sandbox, with the chat
    // token: never one the sandbox could have put on PATH (security review
    // L8), and named before it starts.
    let companion_path = match &p.companion {
        Some((prog, _)) => {
            let mut writable: Vec<String> = Vec::new();
            if a.boundary != Boundary::None {
                writable.extend(p.folders.iter().cloned());
            }
            if a.boundary == Boundary::Srt {
                writable.extend(p.state_dirs.iter().cloned());
                writable.push(plan::srt_temp_root(cfg!(target_os = "macos")).into());
            }
            let argv = preflight::companion(env.program(prog), &env.path, &writable, &cwd)
                .map_err(|e| (1, e))?;
            let path = preflight::companion_path(&env.path, &writable);
            eprintln!(
                "derm run: starting {} beside {} (outside any sandbox, with the chat token)",
                argv.join(" "),
                a.harness.id
            );
            Some((argv, path))
        }
        None => None,
    };

    // sbx: what the log holds before the start is not this run's.
    let mut differ = policy_log::Differ::default();
    let log_args = p.sandbox_name.as_ref().map(|n| {
        vec![
            "policy".to_string(),
            "log".into(),
            n.clone(),
            "--json".into(),
        ]
    });
    if let Some(la) = &log_args {
        if let Some(out) = exec::output_with_timeout(env.program("sbx"), la, POLICY_LOG_TIMEOUT) {
            differ.baseline(&policy_log::parse(&out));
        }
    }

    exec::install_handlers();
    let started = Instant::now();
    let mut launch = p.clone_for_start();
    launch.program = env.program(&p.program).to_string();
    // The companion first, so it is there when the harness writes its first
    // request (lane P's responder).
    if let (Some((prog, cargs)), Some((argv, path))) = (&p.companion, &companion_path) {
        let args: Vec<String> = argv[1..].iter().chain(cargs.iter()).cloned().collect();
        match exec::spawn_companion(&argv[0], &args, &launch, &cwd, path) {
            Ok(c) => cleanup.companion = Some(c),
            Err(e) => {
                eprintln!("derm run: {prog} did not start ({e}); the harness's gated calls will wait and be denied");
            }
        }
    }
    // sbx (lane T's request T-2): create the sandbox, let it reach derm's
    // ports on the host with a rule for it alone (case 117), then attach;
    // it is removed when the harness ends, or on any way out from here (SB3).
    let mut sandbox = if p.sandbox_name.is_some() {
        match boundary::sbx::start(
            env.program("sbx"),
            &mut launch,
            filter.is_none() && boundary::sbx::interactive(),
        ) {
            Ok(s) => Some(s),
            Err((code, why)) => {
                // An attempt the feed can see (box test w5, BW5-7): the
                // chat's start and stop, marked as never started, with the
                // reason, so `derm watch` and the daemon's running list
                // close it at once.
                if let Some(d) = &daemon {
                    let detail = json!({
                        "boundary": a.boundary.name(),
                        "cwd": cwd,
                        "sandboxName": p.sandbox_name,
                        "notStarted": true,
                        "reason": why,
                    });
                    for (kind, summary) in [
                        (
                            "run.start",
                            format!("{} under sbx: not started", a.harness.id),
                        ),
                        (
                            "run.stop",
                            format!("{} under sbx: not started", a.harness.id),
                        ),
                    ] {
                        if let Err(e) = d.post(&event(
                            &chat,
                            a.harness.id,
                            kind,
                            summary,
                            detail.clone(),
                            None,
                        )) {
                            eprintln!("derm run: {kind} was not recorded: {e}");
                        }
                    }
                }
                return Err((code, why));
            }
        }
    } else {
        None
    };
    // The agents' user (lane V's seam), after the companion, which runs as
    // you whatever the harness runs as.
    let daemon_dir_text = dir.as_ref().map(|d| d.to_string_lossy().into_owned());
    let daemon_socket_text = daemon
        .as_ref()
        .map(|d| d.socket.to_string_lossy().into_owned());
    let agent_user = user::wrap_with(
        &mut launch,
        &user::Context {
            boundary: a.boundary.name(),
            chat: &chat,
            cwd: &cwd,
            folders: &p.folders,
            home: &home,
            daemon_dir: daemon_dir_text.as_deref(),
            daemon_socket: daemon_socket_text.as_deref(),
            token: token.as_deref(),
            policy: &policy_path,
        },
    )?;
    // Who it runs as, once lane V's seam has decided (box test w5, BW5-16:
    // the lines before said "as you" for a chat that then ran as the
    // agents' user).
    if agent_user.is_none() && a.boundary == Boundary::None {
        eprintln!("derm run: {} runs as you", a.harness.id);
    }
    let mut child = exec::spawn(&launch, &cwd, filter.is_some())
        .map_err(|e| (127, format!("{}: {e}", p.program)))?;
    let pid = child.id();
    // The filter starts after `run.start` is posted (below), so no record
    // of the chat reaches the daemon before the run's own start; what the
    // agent writes meanwhile waits in its pipe.
    let pipes = (child.stdin.take(), child.stdout.take());
    // The record keeps the shape of the command, not a key passed on it
    // (integration w1, security finding S13; the audit feed's own redactor),
    // and never the harness's own words (finding M8): with the content
    // switch on they go to a content file (case 85 as changed).
    let full_argv = recorded_argv(&p.program, &p.args, &a.rest, false, export_at.clone());
    let argv_file = match (content_days, a.dry_run) {
        (Some(days), false) => keep_argv(
            &home,
            &chat,
            days,
            &recorded_argv(&p.program, &p.args, &a.rest, true, export_at),
        ),
        _ => None,
    };
    // `dangerousFlags` is the name the daemon's `report.running` reads
    // (`run_info_of`): the words that put the agent in full access (case 83).
    let dangerous = &p.full_access;
    let mut base = json!({
        "boundary": a.boundary.name(),
        "argv": full_argv,
        "kit": p.kit,
        "host": hostname(),
        "cwd": cwd,
        "folders": p.folders,
        "stateDirs": p.state_dirs,
        "sandboxName": p.sandbox_name,
        // The agents' user when lane V's seam started the harness as one.
        "runsAs": match (&agent_user, a.boundary == Boundary::None) {
            (Some(u), _) => u.get("user").and_then(|v| v.as_str()).map(str::to_string),
            (None, true) => Some("you".to_string()),
            (None, false) => None,
        },
        "dangerousFlags": dangerous,
        "fullAccess": !dangerous.is_empty(),
        "outsideShapeOnly": a.harness.id == "other",
        // The harness's executable by its real path, so the daemon's join
        // can find the harness under a boundary's wrappers by what it execs
        // (MW5-16, review FP3-S2); null when it cannot be resolved here.
        "harnessExe": harness_exe(
            a.program.as_deref().unwrap_or(a.harness.command),
            std::env::var("PATH").ok().as_deref(),
        ),
        // The binary a launcher starts as the harness (Codex's npm package),
        // so the join finds the harness under the launcher (MW5-28).
        "harnessChildExe": harness_child_exe(
            a.program.as_deref().unwrap_or(a.harness.command),
            std::env::var("PATH").ok().as_deref(),
        ),
        "otelExport": export,
        "acp": filter.is_some(),
        "trust": "client",
    });
    match argv_file {
        Some(Ok(name)) => {
            base["contentKept"] = json!(true);
            base["contentFiles"] = json!([name]);
        }
        Some(Err(e)) => {
            eprintln!("derm run: the argument words were not kept as content ({e})");
            base["contentFailed"] = json!(true);
        }
        None => {}
    }
    // Where the audit feed cannot see io_uring operations (lane T's request
    // T-3, case 128): no boundary on Linux; srt blocks them where its
    // seccomp helper runs; sbx runs the agent on the VM's own kernel.
    let io_uring = boundary::io_uring_mark(
        a.boundary.name(),
        p.srt_settings.as_deref(),
        cfg!(target_os = "linux"),
        std::env::consts::ARCH,
    );
    if io_uring == Some("not-audited") {
        eprintln!("derm run: io_uring operations in this chat are not audited (the audit feed reads syscalls only, case 128)");
    }
    let io_uring = io_uring.map(|m| json!(m));
    // Lane T's P4-R3: whether derm's kit went on the sbx create, and why
    // not, so the record and `derm status` say whether the gate is in the VM.
    let sbx_kit = sandbox.as_ref().map(|s| s.kit_record());
    // Wave 5's records, only where a seam made one (`contracts/events.md`
    // section 5); the base's stubs make none.
    for (key, record) in [
        ("boundaryChoice", &choice.record),
        ("ioUring", &io_uring),
        ("tap", &tap_record),
        ("content", &content_record),
        ("agentUser", &agent_user),
        ("sbxKit", &sbx_kit),
    ] {
        if let Some(v) = record {
            base[key] = v.clone();
        }
    }
    if let Some(d) = &daemon {
        let summary = format!("{} under {}", a.harness.id, a.boundary.name());
        if let Err(e) = d.post(&event(
            &chat,
            a.harness.id,
            "run.start",
            summary,
            base.clone(),
            Some(pid),
        )) {
            eprintln!("derm run: run.start was not recorded: {e}");
        }
    }

    let filter_threads = match (filter, pipes.0, pipes.1) {
        (Some(f), Some(stdin), Some(stdout)) => f(Pipes {
            stdin,
            stdout,
            chat: chat.clone(),
            harness: a.harness.id.to_string(),
            token: token.clone(),
            socket: daemon.as_ref().map(|d| d.socket.clone()),
            policy: policy_path.clone(),
            policy_file: policy_file.clone(),
            policy_problem: policy_problem.clone(),
            full_access: !p.full_access.is_empty(),
            confined: a.boundary != Boundary::None,
        }),
        _ => Vec::new(),
    };

    // sbx: poll the policy log while the harness runs.
    let stop = Arc::new(AtomicBool::new(false));
    let poller = match (&daemon, &log_args) {
        (Some(d), Some(la)) => {
            let sbx_path = env.program("sbx").to_string();
            let (socket, dtoken, la, chat, harness, stop) = (
                d.socket.clone(),
                d.token.clone(),
                la.clone(),
                chat.clone(),
                a.harness.id.to_string(),
                stop.clone(),
            );
            Some(std::thread::spawn(move || {
                let d = Daemon {
                    socket,
                    token: dtoken,
                };
                let mut last = false;
                loop {
                    if let Some(out) = exec::output_with_timeout(&sbx_path, &la, POLICY_LOG_TIMEOUT)
                    {
                        for e in differ.new_entries(&policy_log::parse(&out)) {
                            let _ = d.post(&policy_log::to_event(&e, &chat, &harness, now_ms()));
                        }
                    }
                    if last {
                        return;
                    }
                    let t = Instant::now();
                    while t.elapsed() < POLL && !stop.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    // One more poll after the stop, for what the last
                    // seconds blocked.
                    last = stop.load(Ordering::SeqCst);
                }
            }))
        }
        _ => None,
    };

    let status =
        exec::wait(&mut child).map_err(|e| (1, format!("waiting for {}: {e}", p.program)))?;
    let (code, signal) = exec::code(&status);
    // The agents' user's bridge (lane V) ends with the harness.
    user::finish();
    // The sandbox goes before `run.stop`, so no VM writes into the project
    // after its chat has stopped (SB3).
    let sandbox_removed = sandbox.take().map(|s| match s.remove() {
        Ok(()) => true,
        Err(e) => {
            eprintln!("derm run: {e}");
            false
        }
    });
    if let Some(c) = cleanup.companion.as_mut() {
        exec::stop_companion(c, Duration::from_secs(2));
    }
    // The filter's threads end when the harness's stdout closes; the one
    // reading derm's own stdin may wait for the client, so it is not joined
    // past a short grace.
    let grace = Instant::now() + Duration::from_millis(500);
    for t in filter_threads {
        while !t.is_finished() && Instant::now() < grace {
            std::thread::sleep(Duration::from_millis(10));
        }
        if t.is_finished() {
            let _ = t.join();
        }
    }
    stop.store(true, Ordering::SeqCst);
    if let Some(t) = poller {
        let _ = t.join();
    }
    if let Some(d) = &daemon {
        let mut detail = base;
        detail["exitCode"] = json!(status.code());
        detail["signal"] = json!(signal);
        detail["durationMs"] = json!(started.elapsed().as_millis() as u64);
        if let Some(removed) = sandbox_removed {
            detail["sandboxRemoved"] = json!(removed);
        }
        let summary = format!(
            "{} under {} ended, code {code}",
            a.harness.id,
            a.boundary.name()
        );
        let stop_event = event(&chat, a.harness.id, "run.stop", summary, detail, Some(pid));
        let posted = match d.post(&stop_event) {
            // The daemon restarted during the run and its token rotated
            // (box test w1, BX8): read the token file again, and post once
            // more under daemon scope, marked so the log says why.
            Err(e) if e.contains("bad token") => {
                let mut again = stop_event.clone();
                again.detail["daemonRestarted"] = json!(true);
                d.post_after_restart(&again)
                    .map_err(|e2| format!("{e}; after reading the token again: {e2}"))
            }
            other => other,
        };
        if let Err(e) = posted {
            eprintln!("derm run: run.stop was not recorded: {e}");
        }
    }
    drop(cleanup);
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// MW5-32's Linux half: a missing `~/.codex` and `config.toml` are made
    /// (0700 and 0600, empty); nothing that exists is changed, a link to a
    /// file elsewhere included.
    #[cfg(unix)]
    #[test]
    fn mw5_32_codexs_missing_config_is_made_empty_before_srt() {
        use std::os::unix::fs::symlink;
        let d = std::env::temp_dir().join(format!("derm-mw532-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let made = codex_home_for_srt(&d).unwrap();
        assert_eq!(made.len(), 2, "{made:?}");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&d.join(".codex")), 0o700);
        assert_eq!(mode(&d.join(".codex/config.toml")), 0o600);
        assert_eq!(
            std::fs::read(d.join(".codex/config.toml")).unwrap().len(),
            0
        );
        // Again: nothing more to make, and a config with content is kept.
        std::fs::write(d.join(".codex/config.toml"), "model = \"x\"\n").unwrap();
        assert!(codex_home_for_srt(&d).unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(d.join(".codex/config.toml")).unwrap(),
            "model = \"x\"\n"
        );
        // A link in its place, even a dangling one, is left alone.
        std::fs::remove_file(d.join(".codex/config.toml")).unwrap();
        symlink(d.join("elsewhere.toml"), d.join(".codex/config.toml")).unwrap();
        assert!(codex_home_for_srt(&d).unwrap().is_empty());
        assert!(!d.join("elsewhere.toml").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// FP8-S2: each submodule's git folder is found, nested and with a
    /// slashed name, never through a link.
    #[cfg(unix)]
    #[test]
    fn fp8_s2_submodule_git_folders_are_found() {
        let d = std::env::temp_dir().join(format!("derm-fp8-mods-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let m = d.join(".git/modules");
        for (dir, file) in [
            ("sub", "config"),
            ("sub/modules/inner", "HEAD"),
            ("a/b", "config"),
        ] {
            std::fs::create_dir_all(m.join(dir)).unwrap();
            std::fs::write(m.join(dir).join(file), "").unwrap();
        }
        let elsewhere = d.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("config"), "").unwrap();
        std::os::unix::fs::symlink(&elsewhere, m.join("linked")).unwrap();
        let got = git_module_dirs(&d);
        let want: Vec<String> = ["a/b", "sub", "sub/modules/inner"]
            .iter()
            .map(|x| m.join(x).to_string_lossy().into_owned())
            .collect();
        assert_eq!(got, want);
        assert!(git_module_dirs(&elsewhere).is_empty());
        // FP8R-5: the worktree configs too, and each module's three files.
        std::fs::create_dir_all(d.join(".git/worktrees/w1")).unwrap();
        let c = git_controls(&d);
        for want in [
            d.join(".git/config.worktree"),
            d.join(".git/worktrees/w1/config.worktree"),
            m.join("sub/config"),
            m.join("sub/hooks"),
            m.join("sub/config.worktree"),
            m.join("a/b/hooks"),
        ] {
            assert!(
                c.contains(&want.to_string_lossy().into_owned()),
                "{want:?} {c:?}"
            );
        }
        assert!(git_controls(&elsewhere).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// FP5R-6: the resolver follows a linked folder, a link at the leaf
    /// whose target does not exist yet, `..` after a link, and stops on a
    /// loop.
    #[cfg(unix)]
    #[test]
    fn fp5r_6_a_path_is_resolved_through_every_link() {
        use std::os::unix::fs::symlink;
        let d = std::env::temp_dir().join(format!("derm-fp6-real-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("real/claude")).unwrap();
        std::fs::create_dir_all(d.join("home")).unwrap();
        let d = std::fs::canonicalize(&d).unwrap();
        symlink(d.join("real/claude"), d.join("home/.claude")).unwrap();
        // A file not there yet, under a linked folder.
        assert_eq!(
            real_path_lenient(&d.join("home/.claude/.credentials.json")),
            Some(d.join("real/claude/.credentials.json"))
        );
        // A dangling link at the leaf: a write through it makes its target.
        symlink("../elsewhere/creds", d.join("real/claude/creds")).unwrap();
        assert_eq!(
            real_path_lenient(&d.join("home/.claude/creds")),
            Some(d.join("real/elsewhere/creds"))
        );
        // `..` after a link climbs from where the link led.
        assert_eq!(
            real_path_lenient(&d.join("home/.claude/../x")),
            Some(d.join("real/x"))
        );
        // No link: itself.
        assert_eq!(
            real_path_lenient(&d.join("home/plain")),
            Some(d.join("home/plain"))
        );
        // A loop, and a relative path.
        symlink(d.join("loop"), d.join("loop")).unwrap();
        assert_eq!(real_path_lenient(&d.join("loop/x")), None);
        assert_eq!(real_path_lenient(Path::new("rel/x")), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn chat_ids_are_valid_and_distinct() {
        let a = new_chat_id();
        assert!(args::valid_chat(&a), "{a}");
        assert_ne!(a, new_chat_id());
    }

    #[cfg(unix)]
    #[test]
    fn the_settings_file_is_private_and_never_follows_a_link() {
        let dir = std::env::temp_dir().join(format!("derm-run-w-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let f = dir.join("srt/c.json");
        write_private(&f, "{}").unwrap();
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(f.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        write_private(&f, "{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "{\"a\":1}");
        // A link planted at the file's place is refused, its target untouched.
        let target = dir.join("target");
        std::fs::write(&target, "keep").unwrap();
        std::fs::remove_file(&f).unwrap();
        std::os::unix::fs::symlink(&target, &f).unwrap();
        assert!(write_private(&f, "x").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn usage_errors_exit_2() {
        assert_eq!(main(&[]), 2);
        // Since case 129, `derm run pi` with no `--boundary` depends on the
        // machine (lane T's request T-4); a flag with no value is a usage
        // error everywhere. The no-boundary paths are tested with a fake
        // machine in `boundary/tests.rs`.
        assert_eq!(main(&["pi".into(), "--boundary".into()]), 2);
        assert_eq!(
            main(&[
                "pi".into(),
                "--boundary".into(),
                "none".into(),
                "--cwd".into(),
                "/nonexistent/x".into()
            ]),
            2
        );
    }
}

/// `derm run` end to end against the scripted fake daemon
/// (`derm_audit_linux::client::fake`) and fake `pi` and `srt` scripts.
#[cfg(test)]
mod end_to_end {
    use super::*;
    #[cfg(unix)]
    use derm_audit_linux::client::fake;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// Writes an executable script from a child process, so this test
    /// process never holds the file open for write. A thread of another test
    /// that forks keeps a copy of every open descriptor until it execs, and
    /// exec of a file open for write fails with ETXTBSY ("Text file busy",
    /// os error 26): the flake lane Z saw in `boundary/probe.rs` on `f90d0ab`, reproduced outside
    /// derm (3 of 3,000 execs with a direct write, 0 of 3,000 written from a
    /// child). The same cause as W-F1's lock test.
    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> String {
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let p = bin.join(name);
        let mut w = std::process::Command::new("/bin/sh")
            .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
            .arg(&p)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(
            &mut w.stdin.take().unwrap(),
            format!("#!/bin/sh\n{body}\n").as_bytes(),
        )
        .unwrap();
        assert!(w.wait().unwrap().success());
        p.to_string_lossy().into_owned()
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[cfg(unix)]
    struct Setup {
        fake: fake::Fake,
        work: PathBuf,
        env: RunEnv,
    }

    #[cfg(unix)]
    fn setup(name: &str) -> Setup {
        let fake = fake::start(&format!("run-{name}"), fake::Mode::Normal);
        let work = fake.dir.join("work dir");
        std::fs::create_dir_all(&work).unwrap();
        let out = fake.dir.join("seen");
        // The fake pi writes what it was given and exits 3.
        let pi = script(
            &fake.dir,
            "pi",
            &format!(
                "{{ echo \"token=$DERM_CHAT_TOKEN\"; echo \"chat=$DERM_CHAT_ID\"; echo \"otlp=$DERM_OTLP_ENDPOINT\"; \
                 echo \"boundary=$DERM_BOUNDARY\"; echo \"proxy=$NODE_USE_ENV_PROXY\"; echo \"pwd=$(pwd)\"; \
                 for a in \"$@\"; do echo \"arg=$a\"; done; }} > '{}'; exit 3",
                out.display()
            ),
        );
        // The fake srt checks its settings file is private, keeps a copy,
        // and runs what follows `--` with `pi` pointed at the fake.
        let srt = script(
            &fake.dir,
            "srt",
            &format!(
                "[ \"$1\" = --settings ] || exit 90; f=\"$2\"; [ \"$3\" = -- ] || exit 91; \
                 m=$(stat -c %a \"$f\" 2>/dev/null || stat -f %Lp \"$f\"); [ \"$m\" = 600 ] || exit 92; cp \"$f\" '{}/settings.copy'; \
                 shift 4; exec '{pi}' \"$@\"",
                fake.dir.display()
            ),
        );
        // srt's own dependencies, for the preflight (BX4), outside /tmp:
        // srt can write /tmp, so a copy there is refused (review R3).
        let deps = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/derm-test-deps")
            .join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir_all(&deps).unwrap();
        for b in ["bwrap", "socat", "rg"] {
            script(&deps, b, "exit 0");
        }
        let env = RunEnv {
            socket: Some(fake.socket.clone()),
            home: Some(fake.dir.to_string_lossy().into_owned()),
            gateway: None,
            programs: vec![("pi".into(), pi), ("srt".into(), srt)],
            policy: None,
            path: deps.join("bin").to_string_lossy().into_owned(),
            userns: None,
            bwrap_profile: false,
            goose_mode: None,
            cline_responder: None,
        };
        Setup { fake, work, env }
    }

    #[cfg(unix)]
    fn seen(st: &Setup) -> String {
        std::fs::read_to_string(st.fake.dir.join("seen")).unwrap_or_default()
    }

    #[cfg(unix)]
    fn events(st: &Setup) -> Vec<serde_json::Value> {
        st.fake
            .lines()
            .into_iter()
            .filter(|l| l["op"] == "event")
            .map(|l| l["event"].clone())
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn run_records_never_hold_a_secret_from_the_harness_argv() {
        // Integration w1, security finding S13: a key passed to the harness
        // on its command line would sit in the activity log for 7 days.
        // Its own fake folder: `setup` names the folder after this label and
        // the process id, so two tests sharing a label race.
        let st = setup("none-redact");
        let cwd = st.work.to_string_lossy().into_owned();
        let secret = format!("sk-ant-{}", "x".repeat(24));
        run(
            &s(&[
                "pi",
                "--boundary",
                "none",
                "--chat",
                "chat-r",
                "--cwd",
                &cwd,
                "--",
                "--api-key",
                &secret,
                "--model=sk-ant-inline-secret-value-0001",
            ]),
            &st.env,
        )
        .unwrap();
        let ev = events(&st);
        assert_eq!(ev[0]["kind"], "run.start");
        let all = serde_json::to_string(&ev).unwrap();
        assert!(!all.contains(&secret), "{all}");
        assert!(!all.contains("sk-ant-inline"), "{all}");
        assert!(all.contains("--api-key"), "{all}");
    }

    #[cfg(unix)]
    #[test]
    fn the_harness_exe_is_the_programs_real_path() {
        let dir = std::env::temp_dir().join(format!("derm-hexe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("versions")).unwrap();
        let real = dir.join("versions/claude-9.9.9");
        std::fs::write(&real, [0x7f, b'E', b'L', b'F']).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&real, dir.join("bin/claude")).unwrap();
        let path = format!("relative:{}", dir.join("bin").display());
        let want = std::fs::canonicalize(&real)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(harness_exe("claude", Some(&path)), Some(want.clone()));
        let linked = dir.join("bin/claude").to_string_lossy().into_owned();
        assert_eq!(harness_exe(&linked, None), Some(want));
        assert_eq!(harness_exe("claude", None), None);
        assert_eq!(harness_exe("not-there-derm", Some(&path)), None);
        // A `#!/usr/bin/env node` script is named by the interpreter the
        // kernel runs, as the OS feeds record it.
        let node = dir.join("bin/node-9");
        std::fs::write(&node, [0x7f, b'E', b'L', b'F']).unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = dir.join("versions/cli.js");
        std::fs::write(
            &script,
            "#!/usr/bin/env -S node-9 --no-warnings\nconsole.log(1)\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&script, dir.join("bin/codex")).unwrap();
        let want_node = std::fs::canonicalize(&node)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(harness_exe("codex", Some(&path)), Some(want_node.clone()));
        let direct = dir.join("versions/direct.sh");
        std::fs::write(&direct, format!("#!{}\n", node.display())).unwrap();
        assert_eq!(
            harness_exe(&direct.to_string_lossy(), Some(&path)),
            Some(want_node)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Box test w5 retest, BW5R-5: Pi from its own installer runs as a
    /// `/bin/sh` launcher, `<agent dir>/bin/pi`, which reads
    /// `<agent dir>/install/current-version` and execs that release's
    /// `node_modules/.bin/pi`, a `#!/usr/bin/env node` script (Pi 1.4.0
    /// `package-manager-cli.ts:50-80, 123-133, 192-220`: the managed root's
    /// `managed-install.json`, `current-version` and `releases/<version>`;
    /// the launcher's path and its exec, PiDeck's notes). `harnessExe` was
    /// `/usr/bin/dash`, a shell, so under a boundary the join never found Pi.
    #[cfg(unix)]
    #[test]
    fn bw5r_5_pis_managed_launcher_is_named_by_the_node_it_runs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("derm-pilaunch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let agent = dir.join(".pi/agent");
        let rel = agent.join("install/releases/1.4.0/node_modules");
        let cli = rel.join("@earendil-works/pi-coding-agent/dist/cli.js");
        std::fs::create_dir_all(cli.parent().unwrap()).unwrap();
        std::fs::create_dir_all(rel.join(".bin")).unwrap();
        std::fs::create_dir_all(agent.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("sys")).unwrap();
        let node = dir.join("sys/node");
        std::fs::write(&node, [0x7f, b'E', b'L', b'F']).unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&cli, "#!/usr/bin/env node\n").unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(
            "../@earendil-works/pi-coding-agent/dist/cli.js",
            rel.join(".bin/pi"),
        )
        .unwrap();
        let launcher = agent.join("bin/pi");
        std::fs::write(
            &launcher,
            "#!/bin/sh\nexec \"$root/releases/$v/node_modules/.bin/pi\" \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            agent.join("install/managed-install.json"),
            r#"{"kind": "pi-managed-install", "schemaVersion": 1, "layout": "releases-v1"}"#,
        )
        .unwrap();
        std::fs::write(agent.join("install/current-version"), "1.4.0\n").unwrap();
        let path = format!(
            "{}:{}",
            agent.join("bin").display(),
            dir.join("sys").display()
        );
        let want = std::fs::canonicalize(&node)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let exe = |p: &str| harness_exe_with("pi", Some(p), Some(&agent));
        assert_eq!(exe(&path), Some(want.clone()));
        // Review FP9-S5: the same layout outside Pi's agent folder (a
        // `~/.local/bin/pi` with an `install` beside it) names no release.
        assert_ne!(
            harness_exe_with("pi", Some(&path), Some(&dir.join("elsewhere"))),
            Some(want.clone())
        );
        assert_ne!(
            harness_exe_with("pi", Some(&path), None),
            Some(want.clone())
        );
        // No marker, or a version that is not one: the launcher's own shell,
        // as before (which the join takes as naming no harness).
        std::fs::write(agent.join("install/current-version"), "../../x\n").unwrap();
        assert_ne!(exe(&path), Some(want.clone()));
        std::fs::write(agent.join("install/current-version"), "1.4.0\n").unwrap();
        std::fs::write(agent.join("install/managed-install.json"), "{}").unwrap();
        assert_ne!(exe(&path), Some(want));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mac test w5 retest 6, MW5-28: Codex's npm launcher starts its native
    /// binary as a child (0.163.0) or in its own place (0.167.0); `derm run`
    /// names that binary as the launcher finds it (`bin/codex.js:79-110` at
    /// 0.163.0 and 0.167.0): the platform package by Node's resolution from
    /// the script's folder up, nested or hoisted, else the package's own
    /// `vendor` folder.
    #[cfg(unix)]
    #[test]
    fn mw5_28_the_native_binary_codexs_npm_launcher_starts_is_named() {
        use std::os::unix::fs::PermissionsExt;
        let (triple, plat) = codex_platform().expect("a platform Codex ships for");
        let dir = std::env::temp_dir().join(format!("derm-cxlaunch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pkg = dir.join("lib/node_modules/@openai/codex");
        std::fs::create_dir_all(pkg.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let node = dir.join("bin/node");
        std::fs::write(&node, [0x7f, b'E', b'L', b'F']).unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = pkg.join("bin/codex.js");
        std::fs::write(&script, "#!/usr/bin/env node\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{"name": "@openai/codex", "version": "0.163.0", "bin": {"codex": "bin/codex.js"}}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../lib/node_modules/@openai/codex/bin/codex.js",
            dir.join("bin/codex"),
        )
        .unwrap();
        let path = dir.join("bin").to_string_lossy().into_owned();
        let native_in = |vendor: &std::path::Path| {
            let exe = vendor.join(triple).join("bin").join("codex");
            std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
            std::fs::write(&exe, [0x7f, b'E', b'L', b'F']).unwrap();
            std::fs::canonicalize(&exe)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        };
        // No native binary anywhere: nothing named.
        assert_eq!(harness_child_exe("codex", Some(&path)), None);
        // The package's own vendor folder (the launcher's fallback).
        let own = native_in(&pkg.join("vendor"));
        assert_eq!(harness_child_exe("codex", Some(&path)), Some(own.clone()));
        // Hoisted beside it: Node's resolution finds it first from `bin`'s
        // ancestors, so it wins over the fallback.
        let hoisted = dir.join("lib/node_modules/@openai").join(plat);
        std::fs::create_dir_all(&hoisted).unwrap();
        std::fs::write(hoisted.join("package.json"), "{}").unwrap();
        let hoisted_exe = native_in(&hoisted.join("vendor"));
        assert_eq!(harness_child_exe("codex", Some(&path)), Some(hoisted_exe));
        // Nested in the package (npm's global layout): nearer, so it wins.
        let nested = pkg.join("node_modules/@openai").join(plat);
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("package.json"), "{}").unwrap();
        // The platform package found but its binary missing: the launcher
        // throws and starts nothing, so nothing is named.
        assert_eq!(harness_child_exe("codex", Some(&path)), None);
        let nested_exe = native_in(&nested.join("vendor"));
        assert_eq!(harness_child_exe("codex", Some(&path)), Some(nested_exe));
        // Another package's `bin/codex.js` is not Codex's launcher.
        std::fs::write(pkg.join("package.json"), r#"{"name": "codex-lookalike"}"#).unwrap();
        assert_eq!(harness_child_exe("codex", Some(&path)), None);
        // A native install (no script) names no child: the harness is it.
        std::fs::write(pkg.join("package.json"), r#"{"name": "@openai/codex"}"#).unwrap();
        assert_eq!(harness_child_exe(&own, Some(&path)), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_export_range_moves_with_srts_wrap() {
        // srt, Codex with a session subcommand: derm's export sits after
        // `exec`; srt's wrap then goes in right after `--` (FP4-S8).
        let rest = s(&["exec", "do the thing"]);
        let before = s(&[
            "--settings",
            "/x/s.json",
            "--",
            "codex",
            "exec",
            "-c",
            "otel.a=1",
            "do the thing",
        ]);
        let mut after = before.clone();
        after.splice(3..3, s(&["/usr/bin/env", "NO_PROXY=x", "no_proxy=x"]));
        let range = shift_after_wrap(Some(5..7), &before, &after).unwrap();
        assert_eq!(&after[range.clone()], &s(&["-c", "otel.a=1"])[..]);
        let rec = recorded_argv("srt", &after, &rest, false, Some(range));
        assert!(
            rec.contains(&"otel.a=1".to_string()),
            "derm's export kept: {rec:?}"
        );
        assert!(
            rec.contains(&"[12 chars]".to_string()),
            "the prompt masked: {rec:?}"
        );
        assert!(!rec.contains(&"do the thing".to_string()), "{rec:?}");
        // Nothing added, or a range before `--`: unchanged.
        assert_eq!(shift_after_wrap(Some(5..7), &before, &before), Some(5..7));
        assert_eq!(shift_after_wrap(Some(0..2), &before, &after), Some(0..2));
        assert_eq!(shift_after_wrap(None, &before, &after), None);
    }

    #[test]
    fn recorded_argv_keeps_derm_s_part_and_the_words_with_content_on() {
        let args = s(&["--settings", "/x/s.json", "--", "pi", "-p", "hello there"]);
        let rest = s(&["-p", "hello there"]);
        assert_eq!(
            recorded_argv("srt", &args, &rest, false, None),
            s(&[
                "srt",
                "--settings",
                "/x/s.json",
                "--",
                "pi",
                "-p",
                "[11 chars]"
            ])
        );
        assert_eq!(
            recorded_argv("srt", &args, &rest, true, None),
            s(&[
                "srt",
                "--settings",
                "/x/s.json",
                "--",
                "pi",
                "-p",
                "hello there"
            ])
        );
        // A run-together short flag or a word that only starts with `-` is
        // not a flag (review R6).
        let rest = s(&["-pSUMMARISE", "-- my plan", "--", "-v", "--model=x"]);
        assert_eq!(
            recorded_argv("pi", &rest, &rest, false, None),
            s(&[
                "pi",
                "[11 chars]",
                "[10 chars]",
                "--",
                "-v",
                "--model=[1 chars]"
            ])
        );
        // With content on, a key is still redacted.
        let rest = s(&["--api-key", "sk-ant-aaaaaaaaaaaaaaaaaaaaaaaa"]);
        assert_eq!(
            recorded_argv("pi", &rest, &rest, true, None),
            s(&["pi", "--api-key", "[redacted]"])
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_records_hold_no_prompt_text_from_the_harness_argv() {
        // Mac test w1, finding M8: `claude -p "<prompt>"` put the prompt in
        // the activity log. A record never keeps the harness's own words
        // (since integration w5's continue, content on or off): flags stay,
        // other words become lengths.
        let st = setup("none-prompt");
        let cwd = st.work.to_string_lossy().into_owned();
        run(
            &s(&[
                "pi",
                "--boundary",
                "none",
                "--chat",
                "chat-p",
                "--cwd",
                &cwd,
                "--",
                "--model=qwen27b",
                "-p",
                "summarise my private plan",
            ]),
            &st.env,
        )
        .unwrap();
        let ev = events(&st);
        let argv = ev[0]["detail"]["argv"].clone();
        let all = serde_json::to_string(&ev).unwrap();
        assert!(!all.contains("private plan"), "{all}");
        assert!(!all.contains("qwen27b"), "{all}");
        assert_eq!(
            argv,
            serde_json::json!(["pi", "--model=[7 chars]", "-p", "[25 chars]"]),
            "{argv}"
        );
        // The harness itself still got them.
        assert!(seen(&st).contains("arg=summarise my private plan"));
    }

    /// Lane S's request 3's rest (integration w5, continue): the content
    /// switch replaces `DERM_LOG_CONTENT`. With it on, the record still
    /// keeps the masked argv and says `contentKept`, and the words go to a
    /// 0600 content file under the daemon's data folder for the chat, with
    /// the retention chosen (case 85 as changed).
    #[cfg(unix)]
    #[test]
    fn the_content_switch_keeps_argv_words_in_a_file_never_the_record() {
        use std::os::unix::fs::PermissionsExt;
        let st = setup("content-argv");
        let home = st.env.home.clone().unwrap();
        let cwd = st.work.to_string_lossy().into_owned();
        let argv = |chat: &str| {
            s(&[
                "pi",
                "--boundary",
                "none",
                "--chat",
                chat,
                "--cwd",
                &cwd,
                "--",
                "-p",
                "summarise my private plan",
            ])
        };
        let dir = |chat: &str| content_root(&home).join("content").join(chat);
        // Off (no settings file). `DERM_LOG_CONTENT` is read nowhere now; it
        // is not set here, since setting a variable races other test threads.
        run(&argv("chat-c0"), &st.env).unwrap();
        assert!(!dir("chat-c0").exists());
        let all = serde_json::to_string(&events(&st)).unwrap();
        assert!(!all.contains("private plan"), "{all}");
        // On, two days.
        let settings = Path::new(&home).join(".derm/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(
            &settings,
            r#"{"version":1,"content":{"on":true,"retentionDays":2}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o600)).unwrap();
        run(&argv("chat-c1"), &st.env).unwrap();
        let ev = events(&st);
        let start = ev
            .iter()
            .find(|e| e["kind"] == "run.start" && e["chatId"] == "chat-c1")
            .unwrap();
        let all = serde_json::to_string(&ev).unwrap();
        assert!(!all.contains("private plan"), "{all}");
        assert_eq!(start["detail"]["contentKept"], true);
        assert_eq!(start["detail"]["content"]["on"], true);
        let name = start["detail"]["contentFiles"][0]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            name.contains("-r2-run_") && name.ends_with(".argv"),
            "{name}"
        );
        let file = dir("chat-c1").join(&name);
        assert!(std::fs::read_to_string(&file)
            .unwrap()
            .contains("summarise my private plan"));
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(dir("chat-c1"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn none_mints_a_token_records_start_and_stop_and_returns_the_code() {
        let st = setup("none");
        let cwd = st.work.to_string_lossy().into_owned();
        // `derm run` records the folder canonicalized (macOS: /var is a link to
        // /private/var), so the expected values are too (Mac test M2).
        let real = std::fs::canonicalize(&st.work)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let code = run(
            &s(&[
                "pi",
                "--boundary",
                "none",
                "--chat",
                "chat-e",
                "--cwd",
                &cwd,
                "--",
                "-c",
                "a b",
            ]),
            &st.env,
        )
        .unwrap();
        assert_eq!(code, 3);
        let out = seen(&st);
        assert!(
            out.contains(&format!("token={}", fake::CHAT_TOKEN)),
            "{out}"
        );
        assert!(out.contains("chat=chat-e"));
        assert!(out.contains("otlp=http://127.0.0.1:4318"));
        assert!(out.contains("boundary=none"));
        assert!(out.contains(&format!("pwd={real}")), "{out}");
        assert!(out.contains("arg=-c\narg=a b\n"));
        let ops: Vec<String> = st
            .fake
            .lines()
            .iter()
            .map(|l| l["op"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            ops,
            vec!["hello", "token.mint", "hello", "event", "hello", "event"]
        );
        let ev = events(&st);
        assert_eq!(ev[0]["kind"], "run.start");
        assert_eq!(ev[0]["source"], "run");
        assert_eq!(ev[0]["detail"]["runsAs"], "you");
        assert_eq!(ev[0]["detail"]["folders"], serde_json::json!([real]));
        assert!(ev[0]["pid"].as_u64().unwrap() > 0);
        assert_eq!(ev[1]["kind"], "run.stop");
        assert_eq!(ev[1]["detail"]["exitCode"], 3);
        assert_eq!(ev[0]["pid"], ev[1]["pid"]);
        // Lane T: the boundary as the command line named it, and where the
        // audit feed cannot see io_uring (case 128).
        assert_eq!(
            ev[0]["detail"]["boundaryChoice"],
            serde_json::json!({"chosen": "none", "named": true, "reasons": [], "answeredBy": "flag", "preAnswer": null})
        );
        assert_eq!(
            ev[0]["detail"]["ioUring"],
            if cfg!(target_os = "linux") {
                serde_json::json!("not-audited")
            } else {
                serde_json::Value::Null
            }
        );
        // The token is in no line the daemon got but the mint reply's.
        for l in st.fake.lines() {
            assert!(!l.to_string().contains(fake::CHAT_TOKEN), "{l}");
        }
    }

    #[cfg(unix)]
    /// Lane S's requests 2 and 3 (integration w5, phase 2): `--no-tap` makes
    /// the chat say it runs untapped and why (case 127), and every
    /// `run.start` carries content capture's switch as the chat starts.
    #[test]
    fn no_tap_and_content_are_recorded_in_run_start() {
        // Each setup name is this test's own: the fake daemon's folder is
        // named after it, and a second test using a name wipes the first's.
        for (flag, reason, name) in [
            (true, "no-tap-flag", "notap-flag"),
            (false, "no-base-url", "notap-none"),
        ] {
            let st = setup(name);
            let cwd = st.work.to_string_lossy().into_owned();
            let mut argv = vec![
                "pi",
                "--boundary",
                "none",
                "--chat",
                "chat-t",
                "--cwd",
                &cwd,
            ];
            if flag {
                argv.push("--no-tap");
            }
            argv.extend(["--", "-c", "true"]);
            run(&s(&argv), &st.env).unwrap();
            let ev = events(&st);
            assert_eq!(ev[0]["kind"], "run.start");
            assert_eq!(
                ev[0]["detail"]["tap"],
                serde_json::json!({"on": false, "via": "none", "reason": reason}),
                "--no-tap {flag}"
            );
            assert_eq!(
                ev[0]["detail"]["content"],
                serde_json::json!({"on": false, "retentionDays": null})
            );
        }
        let a = args::parse(&s(&["pi", "--boundary", "none", "--no-tap"])).unwrap();
        assert!(a.no_tap);
        assert!(
            !args::parse(&s(&["pi", "--boundary", "none"]))
                .unwrap()
                .no_tap
        );
    }

    #[cfg(unix)]
    #[test]
    fn srt_writes_private_settings_and_removes_them_after() {
        let st = setup("srt");
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run(
            &s(&[
                "pi",
                "--boundary",
                "srt",
                "--chat",
                "chat-s",
                "--cwd",
                &cwd,
                "--model-url",
                "http://127.0.0.1:8080",
                "--",
                "-p",
                "x",
            ]),
            &st.env,
        )
        .unwrap();
        assert_eq!(code, 3, "{}", seen(&st));
        let out = seen(&st);
        assert!(out.contains("proxy=1"));
        assert!(out.contains("arg=-p\narg=x\n"));
        let copy: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(st.fake.dir.join("settings.copy")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            copy["network"]["allowedDomains"],
            serde_json::json!(["127.0.0.1:4318", "127.0.0.1:8080"])
        );
        assert!(copy["filesystem"]["denyRead"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d == &serde_json::json!(st.fake.dir.to_string_lossy())));
        // srt gets the copies derm checked, by absolute path (review R3). The
        // three settings are Linux only (srt 0.0.81 sandbox-config.js).
        if cfg!(target_os = "linux") {
            let deps = std::fs::canonicalize(Path::new(&st.env.path)).unwrap();
            assert_eq!(
                copy["ripgrep"]["command"],
                serde_json::json!(deps.join("rg"))
            );
            assert_eq!(copy["bwrapPath"], serde_json::json!(deps.join("bwrap")));
            assert_eq!(copy["socatPath"], serde_json::json!(deps.join("socat")));
        } else {
            assert!(copy.get("ripgrep").is_none());
        }
        assert!(
            !st.fake.dir.join("srt/chat-s.json").exists(),
            "removed after the run"
        );
        // Lane T's request T-3: srt's seccomp helper refuses io_uring on
        // x86_64 and aarch64 Linux (case 128).
        let ev = events(&st);
        let want = match (cfg!(target_os = "linux"), std::env::consts::ARCH) {
            (true, "x86_64" | "aarch64") => serde_json::json!("blocked"),
            (true, _) => serde_json::json!("not-audited"),
            _ => serde_json::Value::Null,
        };
        assert_eq!(ev[0]["detail"]["ioUring"], want);
    }

    #[cfg(unix)]
    #[test]
    fn run_stop_is_recorded_after_the_daemon_restarted() {
        // Box test w1, BX8: `systemctl --user restart derm-daemon` during a
        // chat rotated the daemon's token, and the chat's `run.stop` was
        // refused ("bad token"), leaving an unpaired `run.start`. derm run
        // reads the token file again and posts once more.
        let mut st = setup("restart");
        let pi = script(
            &st.fake.dir,
            "pi-restart",
            &format!(
                // After derm run has posted run.start (it posts after the start).
                "sleep 1; printf '%s\\n' {new} > '{dir}/daemon.token'; : > '{dir}/restarted'; exit 4",
                new = fake::RESTARTED_TOKEN,
                dir = st.fake.dir.display()
            ),
        );
        st.env.programs.retain(|(n, _)| n != "pi");
        st.env.programs.push(("pi".into(), pi));
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run(
            &s(&[
                "pi",
                "--boundary",
                "none",
                "--chat",
                "chat-r2",
                "--cwd",
                &cwd,
            ]),
            &st.env,
        )
        .unwrap();
        assert_eq!(code, 4);
        let ev = events(&st);
        let kinds: Vec<&str> = ev.iter().map(|e| e["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, vec!["run.start", "run.stop"], "{ev:?}");
        assert_eq!(ev[1]["detail"]["daemonRestarted"], true);
        let hellos: Vec<String> = st
            .fake
            .lines()
            .iter()
            .filter(|l| l["op"] == "hello")
            .map(|l| l["token"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(
            hellos.last().map(String::as_str),
            Some(fake::RESTARTED_TOKEN)
        );
    }

    #[cfg(unix)]
    #[test]
    fn srt_re_opens_the_policy_only_when_it_is_a_plain_file() {
        // Fix pass review R1: a link at ~/.derm/policy.json to ~/.derm/backups
        // was bound read-only into the sandbox, backups and all.
        let st = setup("srt-link");
        let derm = st.fake.dir.join(".derm");
        std::fs::create_dir_all(derm.join("backups")).unwrap();
        let cwd = st.work.to_string_lossy().into_owned();
        let allow = |chat: &str| -> serde_json::Value {
            run(
                &s(&[
                    "pi",
                    "--boundary",
                    "srt",
                    "--chat",
                    chat,
                    "--cwd",
                    &cwd,
                    "--model-url",
                    "http://127.0.0.1:8080",
                ]),
                &st.env,
            )
            .unwrap();
            let c: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(st.fake.dir.join("settings.copy")).unwrap(),
            )
            .unwrap();
            // The policy's entry only: on macOS the daemon socket is
            // re-opened beside it (MW5-5's gate half), whatever the policy.
            let read: Vec<serde_json::Value> = c["filesystem"]["allowRead"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| !e["path"].as_str().unwrap_or("").ends_with("/daemon.sock"))
                .cloned()
                .collect();
            serde_json::Value::Array(read)
        };
        std::os::unix::fs::symlink(derm.join("backups"), derm.join("policy.json")).unwrap();
        assert_eq!(allow("chat-l1"), serde_json::json!([]), "a link");
        std::fs::remove_file(derm.join("policy.json")).unwrap();
        std::fs::write(derm.join("backups/a.json"), "{}").unwrap();
        std::fs::hard_link(derm.join("backups/a.json"), derm.join("policy.json")).unwrap();
        assert_eq!(
            allow("chat-l2"),
            serde_json::json!([]),
            "a second hard link"
        );
        std::fs::remove_file(derm.join("policy.json")).unwrap();
        std::fs::write(derm.join("policy.json"), "{}").unwrap();
        std::fs::set_permissions(
            derm.join("policy.json"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert_eq!(
            allow("chat-l3"),
            serde_json::json!([]),
            "writable by others"
        );
        std::fs::set_permissions(
            derm.join("policy.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let path = derm.join("policy.json").to_string_lossy().into_owned();
        // Fix pass 6 (FP5R-6): where the folder sits under a link (macOS's
        // temp folder under `/var`, a link to `/private/var`), the entry is
        // written again by its real path, since Seatbelt matches that one.
        let real = std::fs::canonicalize(derm.join("policy.json"))
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut want = vec![serde_json::json!({"path": path, "literal": true})];
        if real != path {
            want.push(serde_json::json!({"path": real, "literal": true}));
        }
        assert_eq!(
            allow("chat-l4"),
            serde_json::Value::Array(want),
            "a plain private file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn srt_without_its_dependencies_starts_nothing() {
        // Box test w1, BX4: srt's own "ripgrep (rg) not found" came after
        // the token was minted; now derm refuses first and starts nothing.
        let mut st = setup("srt-deps");
        st.env.path = String::new();
        let cwd = st.work.to_string_lossy().into_owned();
        let err = run(
            &s(&["pi", "--boundary", "srt", "--chat", "chat-d", "--cwd", &cwd]),
            &st.env,
        )
        .unwrap_err();
        assert_eq!(err.0, 1);
        // Linux needs bubblewrap, socat and ripgrep; macOS ripgrep only.
        let first = if cfg!(target_os = "linux") {
            "bwrap (package bubblewrap)"
        } else {
            "rg (package ripgrep)"
        };
        assert!(err.1.contains(first), "{}", err.1);
        assert!(seen(&st).is_empty(), "the harness never started");
        assert!(!st.fake.dir.join("srt/chat-d.json").exists());
        assert!(events(&st).is_empty(), "nothing recorded");
    }

    /// fp13's second re-review, FP13RR2-5: a dry run under srt on Linux made
    /// the daemon's data folder. It writes nothing and says what a run makes.
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn fp13rr2_5_a_dry_run_under_srt_makes_no_data_folder() {
        let st = setup("srt-dry");
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run(
            &s(&["pi", "--boundary", "srt", "--dry-run", "--cwd", &cwd]),
            &st.env,
        );
        assert!(code.is_ok(), "{code:?}");
        if std::env::var_os("XDG_DATA_HOME").is_none() {
            assert!(
                !st.fake.dir.join(".local/share/derm").exists(),
                "a dry run made the data folder"
            );
        }
        assert!(seen(&st).is_empty(), "the harness never started");
    }

    /// Mac test w5, MW5-1: help and argument errors are answered before
    /// any boundary is probed.
    #[test]
    fn help_and_argument_errors_come_before_the_probes() {
        assert!(matches!(before_the_probes(&s(&["--help"])), Some(Ok(0))));
        assert!(matches!(before_the_probes(&s(&["pi", "-h"])), Some(Ok(0))));
        assert!(matches!(
            before_the_probes(&s(&["--bogus"])),
            Some(Err((2, _)))
        ));
        assert!(matches!(
            before_the_probes(&s(&["pi", "--bogus"])),
            Some(Err((2, _)))
        ));
        // A harness's own -h after `--` is the harness's.
        assert!(before_the_probes(&s(&["pi", "--", "-h"])).is_none());
        assert!(before_the_probes(&s(&["pi"])).is_none());
        assert!(before_the_probes(&s(&["pi", "--boundary", "srt"])).is_none());
    }

    /// Box test w5, BW5-7: a chat whose `sbx create` fails (there, sbx
    /// 0.51.0 refusing derm's v2 kit beside its v3 claude, BW5-6) left no
    /// record at all. Its start and stop are posted, marked not started,
    /// with the reason, and the error still stops `derm run`.
    #[cfg(unix)]
    #[test]
    fn a_failed_sbx_create_is_recorded_as_a_chat_that_did_not_start() {
        let st = setup("sbx-create-fails");
        let sbx = script(
            &st.fake.dir,
            "sbx",
            "if [ \"$1 $2\" = 'policy log' ]; then echo 'no such sandbox' >&2; exit 1; fi; \
             if [ \"$1\" = create ]; then echo 'error: resolve kits: cannot mix v3 kits with v1/v2 kits in one sandbox' >&2; exit 1; fi; \
             exit 80",
        );
        let mut env = clone_env(&st.env);
        env.programs.push(("sbx".into(), sbx));
        let cwd = st.work.to_string_lossy().into_owned();
        let err = run(
            &s(&[
                "pi",
                "--boundary",
                "sbx",
                "--chat",
                "chat-nf",
                "--cwd",
                &cwd,
            ]),
            &env,
        )
        .unwrap_err();
        assert_eq!(err.0, 1, "{err:?}");
        assert!(
            err.1.contains("did not make the sandbox derm-chat-nf"),
            "{err:?}"
        );
        let ev = events(&st);
        let kinds: Vec<&str> = ev.iter().map(|e| e["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, vec!["run.start", "run.stop"], "{ev:?}");
        for e in &ev {
            assert_eq!(e["chatId"], "chat-nf");
            assert_eq!(e["detail"]["notStarted"], true, "{e}");
            assert!(
                e["detail"]["reason"]
                    .as_str()
                    .unwrap_or("")
                    .contains("did not make the sandbox"),
                "{e}"
            );
        }
        assert!(seen(&st).is_empty(), "the harness never started");
    }

    #[cfg(unix)]
    #[test]
    fn sbx_names_the_variables_and_posts_the_blocks_its_log_shows() {
        let st = setup("sbx");
        let n = st.fake.dir.join("polls");
        let calls = st.fake.dir.join("sbx-calls");
        // `policy log`: nothing before the start (no sandbox yet), then one
        // block. `create` (lane T's request T-2): the token by name only,
        // its value in the environment. `policy allow`: the rule for this
        // sandbox. `run` (the attach): checks it got the token by name only,
        // waits for a poll. `rm`: the sandbox goes at the end (SB3).
        let sbx = script(
            &st.fake.dir,
            "sbx",
            &format!(
                "echo \"$*\" >> '{calls}'; \
                 if [ \"$1 $2\" = 'policy log' ]; then echo x >> '{n}'; \
                 if [ \"$(wc -l < '{n}')\" -le 1 ]; then echo 'no such sandbox' >&2; exit 1; fi; \
                 echo '{{\"blocked\":[{{\"Sandbox\":\"derm-chat-x\",\"Host\":\"evil.example:443\",\"Rule\":\"<default policy>\",\"Count\":1}}]}}'; exit 0; fi; \
                 if [ \"$1 $2\" = 'policy allow' ]; then exit 0; fi; \
                 if [ \"$1\" = rm ]; then exit 0; fi; \
                 if [ \"$1\" = create ]; then \
                   case \"$*\" in *\"{tok}\"*) exit 85;; esac; \
                   [ \"$DERM_CHAT_TOKEN\" = {tok} ] || exit 86; exit 0; fi; \
                 [ \"$1\" = run ] || exit 80; \
                 case \"$*\" in *\"{tok}\"*) exit 81;; esac; \
                 case \"$*\" in *\"-e DERM_CHAT_TOKEN\"*) ;; *) exit 82;; esac; \
                 [ \"$DERM_CHAT_TOKEN\" = {tok} ] || exit 83; \
                 [ \"$DERM_OTLP_ENDPOINT\" = http://host.docker.internal:4318 ] || exit 84; \
                 sleep 3; exit 0",
                calls = calls.display(),
                n = n.display(),
                tok = fake::CHAT_TOKEN
            ),
        );
        let mut env = RunEnv {
            socket: st.env.socket.clone(),
            home: st.env.home.clone(),
            gateway: None,
            programs: st.env.programs.clone(),
            policy: None,
            path: String::new(),
            userns: None,
            bwrap_profile: false,
            goose_mode: None,
            cline_responder: None,
        };
        env.programs.push(("sbx".into(), sbx));
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run(
            &s(&["pi", "--boundary", "sbx", "--chat", "chat-x", "--cwd", &cwd]),
            &env,
        )
        .unwrap();
        assert_eq!(code, 0);
        let ev = events(&st);
        let kinds: Vec<&str> = ev.iter().map(|e| e["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds.first(), Some(&"run.start"));
        assert_eq!(kinds.last(), Some(&"run.stop"));
        let block = ev
            .iter()
            .find(|e| e["kind"] == "net.connect")
            .expect("the block was posted");
        assert_eq!(block["detail"]["host"], "evil.example:443");
        assert_eq!(block["detail"]["blocked"], true);
        assert_eq!(block["chatId"], "chat-x");
        assert_eq!(
            ev.iter().filter(|e| e["kind"] == "net.connect").count(),
            1,
            "posted once"
        );
        assert_eq!(ev[0]["detail"]["kit"], "docker.io/sbx/pi-kit:latest");
        assert_eq!(ev[0]["detail"]["sandboxName"], "derm-chat-x");
        // Lane T's request T-2: create with the kit as the workload (SB1),
        // a rule for this sandbox alone to the daemon's port (case 117),
        // the attach, and the removal before `run.stop` (SB3).
        let calls = std::fs::read_to_string(&calls).unwrap();
        let steps: Vec<&str> = calls
            .lines()
            .filter(|l| !l.starts_with("policy log"))
            .collect();
        assert_eq!(steps.len(), 4, "{calls}");
        assert!(
            steps[0].starts_with("create --name derm-chat-x -e "),
            "{}",
            steps[0]
        );
        // `derm run` mounts the folder canonicalized (macOS: /var is a link
        // to /private/var, case 111; CI's rust-macos job, P3-1).
        let real = std::fs::canonicalize(&cwd)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            steps[0].ends_with(&format!(" docker.io/sbx/pi-kit:latest {real}")),
            "{}",
            steps[0]
        );
        assert!(!steps[0].contains("--kit"), "{}", steps[0]);
        assert_eq!(
            steps[1],
            "policy allow network --sandbox derm-chat-x localhost:4318"
        );
        assert!(
            steps[2].starts_with("run --name derm-chat-x -e "),
            "{}",
            steps[2]
        );
        assert!(!steps[2].contains("pi-kit"), "{}", steps[2]);
        assert_eq!(steps[3], "rm --force derm-chat-x");
        let stop = ev.last().unwrap();
        assert_eq!(stop["detail"]["sandboxRemoved"], true);
    }

    #[cfg(unix)]
    /// Lane R: Claude Code's own OTel goes to the daemon under `derm run`
    /// (integration w1's request; `apply_export`), its arguments before the
    /// user's, its token never in an argument, the helper removed after.
    #[test]
    fn claude_codes_own_otel_is_pointed_at_the_daemon() {
        let _one = OTEL_HELPERS.lock().unwrap_or_else(|p| p.into_inner());
        let st = setup("export-claude");
        let out = st.fake.dir.join("claude-seen");
        let claude = script(
            &st.fake.dir,
            "claude",
            &format!(
                "{{ for a in \"$@\"; do echo \"arg=$a\"; done; env | grep -E '^(OTEL_|CLAUDE_CODE_ENABLE_TELEMETRY)' | sort; \
                 h=$(printf '%s' \"$2\" | sed -n 's/.*\"otelHeadersHelper\":\"\\([^\"]*\\)\".*/\\1/p'); \
                 echo \"helper=$h\"; [ -n \"$h\" ] && [ -x \"$h\" ] && echo helper-runs; }} > '{}'; exit 0",
                out.display()
            ),
        );
        let mut env = RunEnv {
            programs: st.env.programs.clone(),
            ..clone_env(&st.env)
        };
        env.programs.push(("claude".into(), claude));
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run(
            &s(&[
                "claude-code",
                "--boundary",
                "none",
                "--chat",
                "chat-o",
                "--cwd",
                &cwd,
                "--",
                "-p",
                "hello",
            ]),
            &env,
        )
        .unwrap();
        assert_eq!(code, 0);
        let seen = std::fs::read_to_string(&out).unwrap();
        // `--settings <json>` first, the user's words last.
        let args: Vec<&str> = seen
            .lines()
            .filter_map(|l| l.strip_prefix("arg="))
            .collect();
        assert_eq!(args[0], "--settings", "{seen}");
        assert_eq!(&args[args.len() - 2..], ["-p", "hello"], "{seen}");
        assert!(seen.contains("CLAUDE_CODE_ENABLE_TELEMETRY=1"), "{seen}");
        assert!(
            seen.contains("OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318"),
            "{seen}"
        );
        assert!(seen.contains("helper-runs"), "{seen}");
        // The token never rides in an argument, and the record says what
        // was wired.
        assert!(!args.iter().any(|a| a.contains(fake::CHAT_TOKEN)), "{seen}");
        let ev = events(&st);
        assert_eq!(
            ev[0]["detail"]["otelExport"],
            "claude-code, token through otelHeadersHelper"
        );
        // The helper went with the run.
        let helper = seen
            .lines()
            .find_map(|l| l.strip_prefix("helper="))
            .unwrap()
            .to_string();
        assert!(!Path::new(&helper).exists(), "{helper} was left behind");
        // Pi exports through its own emitter: nothing is added for it.
        let r = run(
            &s(&[
                "pi",
                "--boundary",
                "none",
                "--chat",
                "chat-p",
                "--cwd",
                &cwd,
            ]),
            &st.env,
        )
        .unwrap();
        assert_eq!(r, 3);
        let ev = events(&st);
        let pi_start = ev
            .iter()
            .find(|e| e["kind"] == "run.start" && e["chatId"] == "chat-p")
            .unwrap();
        assert_eq!(
            pi_start["detail"]["otelExport"],
            "stood down: no OTel export for this harness"
        );
    }

    #[cfg(unix)]
    /// Lane R: Cline gets its approval folder (0700, removed after) and lane
    /// P's responder runs beside it with `--dir` and the chat's variables.
    #[test]
    fn cline_runs_with_its_responder_and_a_private_approval_folder() {
        let st = setup("cline");
        let out = st.fake.dir.join("cline-seen");
        let resp_out = st.fake.dir.join("responder-seen");
        let cline = script(
            &st.fake.dir,
            "cline",
            &format!(
                "{{ echo \"mode=$CLINE_TOOL_APPROVAL_MODE\"; echo \"dir=$CLINE_TOOL_APPROVAL_DIR\"; \
                 m=$(stat -c %a \"$CLINE_TOOL_APPROVAL_DIR\" 2>/dev/null || stat -f %Lp \"$CLINE_TOOL_APPROVAL_DIR\"); echo \"perm=$m\"; \
                 for a in \"$@\"; do echo \"arg=$a\"; done; }} > '{}'; sleep 1; exit 0",
                out.display()
            ),
        );
        let responder = script(
            &st.fake.dir,
            "derm-cline-responder",
            &format!(
                "{{ echo \"args=$*\"; echo \"chat=$DERM_CHAT_ID\"; [ -n \"$DERM_CHAT_TOKEN\" ] && echo has-token; }} > '{}'; \
                 trap 'echo stopped >> \"{}\"; exit 0' TERM; while :; do sleep 0.1; done",
                resp_out.display(),
                resp_out.display()
            ),
        );
        let mut env = clone_env(&st.env);
        env.programs.push(("cline".into(), cline));
        env.cline_responder = Some(responder);
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run(
            &s(&[
                "cline",
                "--boundary",
                "none",
                "--chat",
                "chat-c",
                "--cwd",
                &cwd,
                "--",
                "fix it",
            ]),
            &env,
        )
        .unwrap();
        assert_eq!(code, 0);
        let seen = std::fs::read_to_string(&out).unwrap();
        let dir = format!("{}/.cline/derm-approval/chat-c", st.fake.dir.display());
        assert!(seen.contains("mode=desktop"), "{seen}");
        assert!(seen.contains(&format!("dir={dir}")), "{seen}");
        assert!(seen.contains("perm=700"), "{seen}");
        assert!(
            seen.contains("arg=--auto-approve\narg=false\narg=fix it"),
            "{seen}"
        );
        let r = std::fs::read_to_string(&resp_out).unwrap();
        assert!(r.contains(&format!("args=--dir {dir}")), "{r}");
        assert!(r.contains("chat=chat-c") && r.contains("has-token"), "{r}");
        assert!(r.contains("stopped"), "the responder was stopped: {r}");
        assert!(!Path::new(&dir).exists(), "the approval folder was removed");
    }

    #[cfg(unix)]
    /// Case 80: a program derm has no preset for runs with the outside
    /// shape, recorded as such.
    #[test]
    fn a_program_with_no_preset_runs_and_is_recorded_as_outside_shape_only() {
        let st = setup("other");
        let out = st.fake.dir.join("other-seen");
        let agent = script(
            &st.fake.dir,
            "my-agent",
            &format!(
                "{{ echo \"harness=$DERM_HARNESS\"; echo \"chat=$DERM_CHAT_ID\"; for a in \"$@\"; do echo \"arg=$a\"; done; }} > '{}'; exit 4",
                out.display()
            ),
        );
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run(
            &s(&[
                "--boundary",
                "none",
                "--chat",
                "chat-u",
                "--cwd",
                &cwd,
                "--",
                &agent,
                "--go",
            ]),
            &st.env,
        )
        .unwrap();
        assert_eq!(code, 4);
        let seen = std::fs::read_to_string(&out).unwrap();
        assert!(
            seen.contains("harness=other") && seen.contains("arg=--go"),
            "{seen}"
        );
        let ev = events(&st);
        assert_eq!(ev[0]["harness"], "other");
        assert_eq!(ev[0]["detail"]["outsideShapeOnly"], true);
        assert_eq!(ev.last().unwrap()["kind"], "run.stop");
    }

    #[cfg(unix)]
    /// Case 83: a full-access flag reaches the gate as a hint and the run
    /// record keeps it for `derm status`.
    #[test]
    fn full_access_reaches_the_gate_and_the_record() {
        let st = setup("full");
        let cwd = st.work.to_string_lossy().into_owned();
        run(
            &s(&[
                "pi",
                "--boundary",
                "none",
                "--chat",
                "chat-f",
                "--cwd",
                &cwd,
                "--",
                "--yolo",
            ]),
            &st.env,
        )
        .unwrap();
        let ev = events(&st);
        assert_eq!(
            ev[0]["detail"]["dangerousFlags"],
            serde_json::json!(["--yolo"])
        );
        assert_eq!(ev[0]["detail"]["fullAccess"], true);
    }

    #[cfg(unix)]
    /// `derm acp` end to end: a scripted ACP agent asks about a call the
    /// policy denies; derm answers it, the client never sees the request,
    /// and the decision is posted on the chat token beside the run's records.
    #[test]
    fn acp_answers_a_permission_request_between_the_client_and_a_real_agent() {
        let st = setup("acp");
        let seen = st.fake.dir.join("acp-seen");
        let tool_call = r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"tool_call","toolCallId":"t1","title":"x","kind":"execute","name":"bash","rawInput":{"command":"rm -rf build"}}}}"#;
        let ask = r#"{"jsonrpc":"2.0","id":9,"method":"session/request_permission","params":{"sessionId":"s","toolCall":{"toolCallId":"t1"},"options":[{"optionId":"ok","name":"OK","kind":"allow_once"},{"optionId":"no","name":"No","kind":"reject_once"}]}}"#;
        let agent = script(
            &st.fake.dir,
            "acp-agent",
            &format!(
                "printf '%s\\n' '{tool_call}'; printf '%s\\n' '{ask}'; read line; echo \"$line\" > '{}'; \
                 printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{}}}}'; exit 0",
                seen.display()
            ),
        );
        let policy = st.fake.dir.join("policy.json");
        std::fs::write(
            &policy,
            r#"{"version":1,"rules":[{"tool":"bash","action":"deny"}]}"#,
        )
        .unwrap();
        let mut env = clone_env(&st.env);
        env.policy = Some(policy.to_string_lossy().into_owned());
        // The client's ends: nothing to say, everything the proxy passes on
        // is kept.
        let (client_r, client_w) = std::io::pipe().unwrap();
        let (out_r, out_w) = std::io::pipe().unwrap();
        let ends = std::sync::Mutex::new(Some((client_r, out_w)));
        let filter = |p: Pipes| {
            let (cr, ow) = ends.lock().unwrap().take().unwrap();
            let (tx, log) = crate::acp::proxy::log_channel(p.socket.clone(), p.token.clone());
            let st = Arc::new(crate::acp::proxy::State::new(crate::acp::ctx_from(&p), tx));
            crate::acp::proxy::start(st, Box::new(p.stdin), p.stdout, cr, ow, log)
        };
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run_io(
            &s(&[
                "--boundary",
                "none",
                "--chat",
                "chat-a",
                "--cwd",
                &cwd,
                "--",
                &agent,
            ]),
            &env,
            Some(&filter),
        )
        .unwrap();
        assert_eq!(code, 0);
        drop(client_w);
        // The agent got derm's reject.
        let got: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&seen).unwrap().trim()).unwrap();
        assert_eq!(got["id"], 9);
        assert_eq!(got["result"]["outcome"]["optionId"], "no");
        // The client got the update and the agent's last line, not the request.
        let mut passed = String::new();
        std::io::Read::read_to_string(&mut { out_r }, &mut passed).unwrap();
        assert!(passed.contains("\"tool_call\""), "{passed}");
        assert!(!passed.contains("request_permission"), "{passed}");
        // The records: the run, the call and the decision.
        let deadline = Instant::now() + Duration::from_secs(5);
        let decision = loop {
            let ev = events(&st);
            if let Some(d) = ev.iter().find(|e| e["kind"] == "approval").cloned() {
                break d;
            }
            assert!(Instant::now() < deadline, "no decision record: {ev:?}");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(decision["source"], "adapter");
        assert_eq!(decision["detail"]["decision"], "deny");
        assert_eq!(decision["detail"]["via"], "acp");
        let ev = events(&st);
        assert_eq!(ev[0]["kind"], "run.start");
        assert_eq!(ev[0]["detail"]["acp"], true);
        // The adapter records went on the chat token, not the daemon's.
        let lines = st.fake.lines();
        assert!(lines
            .iter()
            .any(|l| l["op"] == "hello" && l["token"] == fake::CHAT_TOKEN));
    }

    #[cfg(unix)]
    /// FPW-S2 end to end: the same scripted agent, the same deny rule, but in
    /// a policy file others may write. `derm run` refuses the file, so `derm
    /// acp` answers from the empty policy: the ask goes to the client, whose
    /// answer reaches the agent. On `2ce607d` derm applied the file and the
    /// agent got derm's own reject.
    #[test]
    fn fpw_s2_acp_does_not_apply_a_policy_others_may_write() {
        use std::io::{BufRead, Write};
        use std::os::unix::fs::PermissionsExt;
        let st = setup("acp-s2");
        let seen = st.fake.dir.join("acp-seen");
        let tool_call = r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"tool_call","toolCallId":"t1","title":"x","kind":"execute","name":"bash","rawInput":{"command":"rm -rf build"}}}}"#;
        let ask = r#"{"jsonrpc":"2.0","id":9,"method":"session/request_permission","params":{"sessionId":"s","toolCall":{"toolCallId":"t1"},"options":[{"optionId":"ok","name":"OK","kind":"allow_once"},{"optionId":"no","name":"No","kind":"reject_once"}]}}"#;
        let agent = script(
            &st.fake.dir,
            "acp-agent",
            &format!(
                "printf '%s\\n' '{tool_call}'; printf '%s\\n' '{ask}'; read line; echo \"$line\" > '{}'; exit 0",
                seen.display()
            ),
        );
        let policy = st.fake.dir.join("policy.json");
        std::fs::write(
            &policy,
            r#"{"version":1,"rules":[{"tool":"bash","action":"deny"}]}"#,
        )
        .unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o666)).unwrap();
        let mut env = clone_env(&st.env);
        env.policy = Some(policy.to_string_lossy().into_owned());
        let (client_r, mut client_w) = std::io::pipe().unwrap();
        let (out_r, out_w) = std::io::pipe().unwrap();
        // The client: answers "ok" to a permission request it is shown.
        let client = std::thread::spawn(move || {
            let mut asked = false;
            for line in std::io::BufReader::new(out_r).lines().map_while(Result::ok) {
                let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
                if v["method"] == "session/request_permission" {
                    asked = true;
                    let reply = serde_json::json!({"jsonrpc":"2.0","id":v["id"].clone(),"result":{"outcome":{"outcome":"selected","optionId":"ok"}}});
                    writeln!(client_w, "{reply}").unwrap();
                }
            }
            asked
        });
        let ends = std::sync::Mutex::new(Some((client_r, out_w)));
        let filter = |p: Pipes| {
            let (cr, ow) = ends.lock().unwrap().take().unwrap();
            let (tx, log) = crate::acp::proxy::log_channel(p.socket.clone(), p.token.clone());
            let st = Arc::new(crate::acp::proxy::State::new(crate::acp::ctx_from(&p), tx));
            crate::acp::proxy::start(st, Box::new(p.stdin), p.stdout, cr, ow, log)
        };
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run_io(
            &s(&[
                "--boundary",
                "none",
                "--chat",
                "chat-s2",
                "--cwd",
                &cwd,
                "--",
                &agent,
            ]),
            &env,
            Some(&filter),
        )
        .unwrap();
        assert_eq!(code, 0);
        let got: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&seen).unwrap().trim()).unwrap();
        assert_eq!(
            got["result"]["outcome"]["optionId"], "ok",
            "derm applied the policy: {got}"
        );
        assert!(client.join().unwrap(), "the client was never asked");
    }

    #[cfg(unix)]
    /// The OTel receiver keeps one helper folder per process
    /// (`otel_receiver::helper_in`), and the tests share one fake chat token:
    /// two Claude Code runs at once in this test process would clear each
    /// other's helper. One `derm run` is one process, so this is the tests'
    /// alone.
    static OTEL_HELPERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    fn clone_env(e: &RunEnv) -> RunEnv {
        RunEnv {
            socket: e.socket.clone(),
            home: e.home.clone(),
            gateway: e.gateway.clone(),
            programs: e.programs.clone(),
            policy: e.policy.clone(),
            path: e.path.clone(),
            userns: e.userns.clone(),
            bwrap_profile: false,
            goose_mode: e.goose_mode.clone(),
            cline_responder: e.cline_responder.clone(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn no_daemon_is_an_error_and_starts_nothing() {
        let st = setup("down");
        let env = RunEnv {
            socket: Some(st.fake.dir.join("absent/daemon.sock")),
            home: st.env.home.clone(),
            gateway: None,
            programs: st.env.programs.clone(),
            policy: None,
            path: String::new(),
            userns: None,
            bwrap_profile: false,
            goose_mode: None,
            cline_responder: None,
        };
        let cwd = st.work.to_string_lossy().into_owned();
        let err = run(&s(&["pi", "--boundary", "none", "--cwd", &cwd]), &env).unwrap_err();
        assert_eq!(err.0, 1);
        assert!(err.1.contains("--no-daemon"), "{}", err.1);
        assert!(seen(&st).is_empty(), "the harness never started");
    }

    #[cfg(unix)]
    #[test]
    fn no_daemon_flag_runs_without_token_or_records() {
        let st = setup("nod");
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run(
            &s(&["pi", "--boundary", "none", "--no-daemon", "--cwd", &cwd]),
            &st.env,
        )
        .unwrap();
        assert_eq!(code, 3);
        assert!(seen(&st).contains("token=\n"));
        assert!(st.fake.lines().is_empty(), "the daemon heard nothing");
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_contacts_nobody_and_starts_nothing() {
        let st = setup("dry");
        let cwd = st.work.to_string_lossy().into_owned();
        assert_eq!(
            run(
                &s(&["pi", "--boundary", "sbx", "--dry-run", "--cwd", &cwd]),
                &st.env
            )
            .unwrap(),
            0
        );
        assert!(st.fake.lines().is_empty());
        assert!(seen(&st).is_empty());
    }

    #[cfg(unix)]
    /// Security review L5: the copy of the user's `--settings` the export
    /// adds is derm's argument, but its content is the user's: the record
    /// does not keep it.
    #[test]
    fn the_exports_copy_of_the_users_settings_is_not_recorded() {
        let _one = OTEL_HELPERS.lock().unwrap_or_else(|p| p.into_inner());
        let st = setup("export-mask");
        let claude = script(&st.fake.dir, "claude", "exit 0");
        let mut env = clone_env(&st.env);
        env.programs.push(("claude".into(), claude));
        let cwd = st.work.to_string_lossy().into_owned();
        let code = run(
            &s(&[
                "claude-code",
                "--boundary",
                "none",
                "--chat",
                "chat-m",
                "--cwd",
                &cwd,
                "--",
                "--settings",
                r#"{"env":{"MY_NOTE":"private plan text"}}"#,
            ]),
            &env,
        )
        .unwrap();
        assert_eq!(code, 0);
        let ev = events(&st);
        let argv = ev[0]["detail"]["argv"].to_string();
        assert_eq!(
            ev[0]["detail"]["otelExport"],
            "claude-code, token through otelHeadersHelper"
        );
        assert!(!argv.contains("private plan text"), "{argv}");
        assert!(argv.contains("[derm otel settings"), "{argv}");
    }

    /// Security review L12: when the harness does not start, the companion
    /// (and what it started) is stopped, and nothing derm made for the run is
    /// left behind.
    /// The live processes whose argument line holds `marker`, as
    /// `"<pid>: <args>"`. Linux reads `/proc`; elsewhere `ps` (Mac test w4,
    /// MW4-2: this test read `/proc` alone and failed on macOS).
    fn running_with(marker: &str) -> Vec<String> {
        if std::path::Path::new("/proc/self/stat").exists() {
            proc_running_with(marker)
        } else {
            ps_running_with(marker)
        }
    }

    fn proc_running_with(marker: &str) -> Vec<String> {
        let mut out = Vec::new();
        for e in std::fs::read_dir("/proc").unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let zombie = std::fs::read_to_string(e.path().join("stat"))
                .map(|s| {
                    s.rsplit(')')
                        .next()
                        .unwrap_or("")
                        .trim_start()
                        .starts_with('Z')
                })
                .unwrap_or(true);
            let cmd = std::fs::read(e.path().join("cmdline")).unwrap_or_default();
            if !zombie && String::from_utf8_lossy(&cmd).contains(marker) {
                out.push(format!(
                    "{name}: {}",
                    String::from_utf8_lossy(&cmd).replace('\0', " ")
                ));
            }
        }
        out
    }

    /// `ps -axww -o pid=,stat=,args=`: every process, its state, its whole
    /// argument line (procps-ng and BSD ps). `ps` itself is left out.
    fn ps_running_with(marker: &str) -> Vec<String> {
        let out = std::process::Command::new("ps")
            .args(["-axww", "-o", "pid=,stat=,args="])
            .output()
            .expect("ps runs");
        let me = std::process::id().to_string();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let pid = it.next()?;
                let stat = it.next()?;
                let args = it.collect::<Vec<_>>().join(" ");
                (!stat.starts_with('Z')
                    && args.contains(marker)
                    && !args.starts_with("ps ")
                    && pid != me)
                    .then(|| format!("{pid}: {args}"))
            })
            .collect()
    }

    /// Both readers see a live process by its marker and stop seeing it once
    /// it is gone, so the check below means the same on Linux and macOS.
    #[test]
    fn both_process_readers_find_a_marked_process_and_lose_it_when_it_ends() {
        let marker = format!("derm-mark-{}", uuid::Uuid::new_v4().simple());
        let mut child = std::process::Command::new("sh")
            // `; :` keeps the shell itself running: macOS's sh execs a
            // lone last command in place, which drops the marker (CI's
            // rust-macos job on abe7e46).
            .args(["-c", "sleep 30; :", &marker])
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while ps_running_with(&marker).is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            ps_running_with(&marker).len(),
            1,
            "{:?}",
            ps_running_with(&marker)
        );
        if std::path::Path::new("/proc/self/stat").exists() {
            assert_eq!(proc_running_with(&marker).len(), 1);
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(running_with(&marker).is_empty());
        assert!(ps_running_with(&marker).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_harness_that_does_not_start_leaves_nothing_running_or_behind() {
        let _one = OTEL_HELPERS.lock().unwrap_or_else(|p| p.into_inner());
        let st = setup("nostart");
        // Every process the responder starts names the test's folder, so
        // /proc shows whether any is left, whenever the stop came.
        let marker = st.fake.dir.to_string_lossy().into_owned();
        let responder = script(
            &st.fake.dir,
            "derm-cline-responder",
            &format!(
                "sh -c 'while :; do sleep 0.1; done' '{marker}' & while :; do sleep 0.1; done"
            ),
        );
        let mut env = clone_env(&st.env);
        env.programs.push((
            "cline".into(),
            st.fake
                .dir
                .join("no-such-cline")
                .to_string_lossy()
                .into_owned(),
        ));
        env.cline_responder = Some(responder);
        let cwd = st.work.to_string_lossy().into_owned();
        let err = run(
            &s(&[
                "cline",
                "--boundary",
                "none",
                "--chat",
                "chat-n",
                "--cwd",
                &cwd,
            ]),
            &env,
        )
        .unwrap_err();
        assert_eq!(err.0, 127, "{err:?}");
        let left = || running_with(&marker);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !left().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(left().is_empty(), "still running: {:?}", left());
        let dir = format!("{}/.cline/derm-approval/chat-n", st.fake.dir.display());
        assert!(!Path::new(&dir).exists(), "{dir} was left behind");
        // Claude Code's helper script, which prints the chat token, too.
        let mut env = clone_env(&st.env);
        env.programs.push((
            "claude".into(),
            st.fake
                .dir
                .join("no-such-claude")
                .to_string_lossy()
                .into_owned(),
        ));
        let err = run(
            &s(&[
                "claude-code",
                "--boundary",
                "none",
                "--chat",
                "chat-h",
                "--cwd",
                &cwd,
            ]),
            &env,
        )
        .unwrap_err();
        assert_eq!(err.0, 127, "{err:?}");
        let helper = st
            .env
            .socket
            .as_ref()
            .unwrap()
            .parent()
            .unwrap()
            .join("otel-helper/chat-h");
        assert!(!helper.exists(), "{} was left behind", helper.display());
    }

    #[cfg(unix)]
    /// Security review L11: a link anywhere between HOME and the chat's
    /// folder is refused, so derm never chmods or removes another folder.
    #[test]
    fn a_private_folder_under_a_link_is_refused() {
        let root = std::env::temp_dir().join(format!(
            "derm-priv-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let home = root.join("home");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(elsewhere.join("derm-approval/chat-l")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(".cline")).unwrap();
        let path = home.join(".cline/derm-approval/chat-l");
        assert!(make_private_dir(&path, &home).is_err());
        assert!(!remove_private_dir(&path, &home));
        assert!(elsewhere.join("derm-approval/chat-l").exists());
        // A real folder is made and removed.
        let real = root.join("home2");
        std::fs::create_dir_all(&real).unwrap();
        let path = real.join(".cline/derm-approval/chat-l");
        make_private_dir(&path, &real).unwrap();
        assert!(remove_private_dir(&path, &real));
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod policy_load_tests {
    use super::load_policy_checked;

    const RULES: &str = r#"{"version":1,"rules":[{"tool":"bash","action":"deny"}]}"#;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("derm-fpw-s2-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("chat")).unwrap();
        std::fs::create_dir_all(d.join("home")).unwrap();
        d
    }

    fn s(p: &std::path::Path) -> String {
        p.to_str().unwrap().to_string()
    }

    /// The problem, or "applied" when the policy's one rule came through.
    fn verdict(path: &std::path::Path, from_env: bool, chat: &std::path::Path) -> String {
        match load_policy_checked(&s(path), from_env, &s(chat)) {
            (p, None) => {
                assert_eq!(p.rules.len(), 1);
                "applied".into()
            }
            (p, Some(why)) => {
                assert!(p.rules.is_empty(), "a refused policy kept its rules: {why}");
                why
            }
        }
    }

    /// FPW-S2, FPWR-4 (the fix pass's reviews): `derm acp` applied a policy
    /// file anyone could write, a `DERM_POLICY` inside the chat's folder, and
    /// a private file in a folder others can write (`/tmp`, which srt lets a
    /// chat write). The same rules as the hook core's `loadPolicy`.
    #[cfg(unix)]
    #[test]
    fn fpw_s2_a_policy_others_may_write_or_swap_or_the_chat_set_is_not_applied() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let d = scratch("unix");
        let (chat, home) = (d.join("chat"), d.join("home"));
        mode(&home, 0o755);
        let file = home.join("policy.json");
        std::fs::write(&file, RULES).unwrap();
        mode(&file, 0o600);
        assert_eq!(verdict(&file, false, &chat), "applied");
        assert_eq!(verdict(&file, true, &chat), "applied");
        // A link to a private file of yours is judged by its target, as the hook core does.
        let link = home.join("link.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(verdict(&link, false, &chat), "applied");
        for m in [0o620, 0o602, 0o666] {
            mode(&file, m);
            assert!(
                verdict(&file, false, &chat).contains("may write this policy file"),
                "{m:o}"
            );
        }
        mode(&file, 0o600);
        // FPWR-4: a private file in a folder others can write, sticky or
        // not, and a private link to a file in one.
        let open = d.join("open");
        std::fs::create_dir_all(&open).unwrap();
        let planted = open.join("p.json");
        std::fs::write(&planted, RULES).unwrap();
        mode(&planted, 0o600);
        for m in [0o777, 0o1777, 0o775] {
            mode(&open, m);
            assert!(
                verdict(&planted, true, &chat).contains("the policy file's folder"),
                "{m:o}"
            );
        }
        let to_open = home.join("to-open.json");
        std::os::unix::fs::symlink(&planted, &to_open).unwrap();
        assert!(verdict(&to_open, false, &chat).contains("the policy file's folder"));
        mode(&open, 0o755);
        // DERM_POLICY inside the chat's folder, even private, even not there
        // yet, also through a link to the chat's folder (macOS's `/var`).
        let inside = chat.join(".derm-policy.json");
        std::fs::write(&inside, RULES).unwrap();
        mode(&inside, 0o600);
        let alias = d.join("alias");
        std::os::unix::fs::symlink(&chat, &alias).unwrap();
        for p in [
            inside.clone(),
            chat.join("sub").join("missing.json"),
            alias.join("sub").join("deeper").join("missing.json"),
        ] {
            assert!(
                verdict(&p, true, &chat).contains("inside the chat's folder"),
                "{}",
                p.display()
            );
        }
        // The default path is never refused for being in the folder (a chat may start in HOME).
        mode(&chat, 0o755);
        assert_eq!(verdict(&inside, false, &chat), "applied");
        // Missing, or not JSON: the empty policy, the problem named.
        assert!(verdict(&home.join("none.json"), false, &chat).contains("no policy file"));
        std::fs::write(&file, "not json").unwrap();
        assert_ne!(verdict(&file, false, &chat), "applied");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// FPW-S2 and FPWR-4 on Windows: a policy file, or its folder, that
    /// Everyone may write is not applied.
    #[cfg(windows)]
    #[test]
    fn fpw_s2_a_policy_everyone_may_write_or_swap_is_not_applied_on_windows() {
        let d = scratch("win");
        let (chat, home) = (d.join("chat"), d.join("home"));
        let file = home.join("policy.json");
        std::fs::write(&file, RULES).unwrap();
        assert_eq!(verdict(&file, false, &chat), "applied");
        let grant = |p: &std::path::Path, what: &str| {
            assert!(std::process::Command::new("icacls")
                .arg(p)
                .args(["/grant", what])
                .output()
                .unwrap()
                .status
                .success());
        };
        grant(&file, "*S-1-1-0:(W)");
        assert!(verdict(&file, false, &chat).contains("may write this policy file"));
        let open = d.join("open");
        std::fs::create_dir_all(&open).unwrap();
        let planted = open.join("p.json");
        std::fs::write(&planted, RULES).unwrap();
        assert_eq!(verdict(&planted, true, &chat), "applied");
        grant(&open, "*S-1-1-0:(OI)(CI)(M)");
        // The file now inherits Everyone's write too; both say no.
        assert_ne!(verdict(&planted, true, &chat), "applied");
        let inside = chat.join("p.json");
        std::fs::write(&inside, RULES).unwrap();
        assert!(verdict(&inside, true, &chat).contains("inside the chat's folder"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
