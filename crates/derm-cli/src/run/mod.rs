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
mod exec;
pub(crate) mod harness;
pub(crate) mod plan;
mod policy_log;
mod preflight;

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
struct RunEnv {
    socket: Option<PathBuf>,
    home: Option<String>,
    gateway: Option<String>,
    /// Program name to path, for tests only (`main` passes none).
    programs: Vec<(String, String)>,
    /// `DERM_LOG_CONTENT=1`: run records keep the harness's own arguments
    /// (still through the secret redactor). Off by default (finding M8).
    log_content: bool,
    /// `DERM_POLICY`, the policy file the harness's gate will read.
    policy: Option<String>,
    /// `PATH`, searched for srt's own dependencies (BX4).
    path: String,
    /// `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` (BX3), when
    /// it exists.
    userns: Option<String>,
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
            home: std::env::var("HOME").ok(),
            gateway: std::env::var("DERM_GATEWAY_URL").ok(),
            programs: Vec::new(),
            log_content: std::env::var("DERM_LOG_CONTENT").is_ok_and(|v| v == "1"),
            policy: std::env::var("DERM_POLICY").ok(),
            path: std::env::var("PATH").unwrap_or_default(),
            userns: std::fs::read_to_string(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            )
            .ok(),
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
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname writes at
    // most that many bytes.
    let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if r != 0 {
        return String::new();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
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
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
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
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
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
fn regular_private_file(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| {
        // SAFETY: getuid takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        m.file_type().is_file() && m.uid() == uid && m.nlink() == 1 && m.mode() & 0o022 == 0
    })
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
    let split = if args.ends_with(rest) {
        args.len() - rest.len()
    } else {
        // Not expected (plan.rs appends `rest` last); mask everything.
        0
    };
    let mut out = vec![program.to_string()];
    for (i, w) in args[..split].iter().enumerate() {
        let settings = i > 0 && args[i - 1] == "--settings";
        match &export {
            Some(r) if r.contains(&i) && settings => {
                out.push(format!("[derm otel settings, {} chars]", w.chars().count()))
            }
            _ => out.push(w.clone()),
        }
    }
    out.extend(args[split..].iter().map(mask));
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

/// A folder of the chat's alone: made 0700 with no link at its place, its
/// parents made 0700 when new. Removed after the run.
/// Every folder between `home` (left out) and `path` (left out) that exists
/// is a real folder of this user's: no link, so nothing derm does to `path`
/// lands in another folder (security review L11). A path outside `home` has
/// its parent checked alone.
fn no_link_above(path: &Path, home: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
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
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() || m.uid() != uid => {
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
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
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
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
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
    let at = p.args.len().saturating_sub(rest.len());
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

fn run_io(argv: &[String], env: &RunEnv, filter: Option<StdioFilter>) -> Result<u8, (u8, String)> {
    let a = args::parse(argv).map_err(|e| (2, e))?;
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
    let home = env
        .home
        .clone()
        .filter(|h| h.starts_with('/'))
        .ok_or((2, "HOME is not set to an absolute path".to_string()))?;
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
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| format!("{}/.derm/policy.json", home.trim_end_matches('/')));
    let policy_asks = {
        let (policy, problem) = derm_core::policy::load(Path::new(&policy_path));
        plan::policy_asks(problem.is_none().then_some(&policy))
    };
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
    };
    let inputs = plan::Inputs {
        policy_regular: regular_private_file(Path::new(&inputs.policy)),
        ..inputs
    };
    let mut p = plan::build(&inputs).map_err(|e| (2, e))?;
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
            env.log_content,
        )
    };
    // Only a run that wrote a helper clears the receiver's helpers: one
    // `derm run` is one chat, so they are this run's.
    cleanup.otel_helpers = export == json!("claude-code, token through otelHeadersHelper");
    plan::no_token_in_args(&p, token.as_deref()).map_err(|e| (1, e))?;
    // srt's dependencies and the userns sysctl, before srt fails on them with
    // its own errors (box test w1, BX3 and BX4); the copies srt would run
    // outside the sandbox, never from a folder the sandbox can write, and
    // handed to srt by absolute path (fix pass review R3).
    if a.boundary == Boundary::Srt {
        let mut writable: Vec<String> = p.folders.clone();
        writable.extend(p.state_dirs.iter().cloned());
        writable.push("/tmp".into());
        match preflight::srt(
            &env.path,
            cfg!(target_os = "linux"),
            env.userns.as_deref(),
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
                writable.push("/tmp".into());
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
    let mut child = exec::spawn(&launch, &cwd, filter.is_some())
        .map_err(|e| (127, format!("{}: {e}", p.program)))?;
    let pid = child.id();
    // The filter starts after `run.start` is posted (below), so no record
    // of the chat reaches the daemon before the run's own start; what the
    // agent writes meanwhile waits in its pipe.
    let pipes = (child.stdin.take(), child.stdout.take());
    // The record keeps the shape of the command, not a key passed on it
    // (integration w1, security finding S13; the audit feed's own redactor),
    // and not the harness's own words unless DERM_LOG_CONTENT=1 (finding M8).
    let full_argv = recorded_argv(&p.program, &p.args, &a.rest, env.log_content, export_at);
    // `dangerousFlags` is the name the daemon's `report.running` reads
    // (`run_info_of`): the words that put the agent in full access (case 83).
    let dangerous = &p.full_access;
    let base = json!({
        "boundary": a.boundary.name(),
        "argv": full_argv,
        "kit": p.kit,
        "host": hostname(),
        "cwd": cwd,
        "folders": p.folders,
        "stateDirs": p.state_dirs,
        "sandboxName": p.sandbox_name,
        "runsAs": if a.boundary == Boundary::None { Some("you") } else { None },
        "dangerousFlags": dangerous,
        "fullAccess": !dangerous.is_empty(),
        "outsideShapeOnly": a.harness.id == "other",
        "otelExport": export,
        "acp": filter.is_some(),
        "trust": "client",
    });
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

    #[test]
    fn chat_ids_are_valid_and_distinct() {
        let a = new_chat_id();
        assert!(args::valid_chat(&a), "{a}");
        assert_ne!(a, new_chat_id());
    }

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
        assert_eq!(main(&["pi".into()]), 2);
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
    use derm_audit_linux::client::fake;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str) -> String {
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let p = bin.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    struct Setup {
        fake: fake::Fake,
        work: PathBuf,
        env: RunEnv,
    }

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
            log_content: false,
            policy: None,
            path: deps.join("bin").to_string_lossy().into_owned(),
            userns: None,
            goose_mode: None,
            cline_responder: None,
        };
        Setup { fake, work, env }
    }

    fn seen(st: &Setup) -> String {
        std::fs::read_to_string(st.fake.dir.join("seen")).unwrap_or_default()
    }

    fn events(st: &Setup) -> Vec<serde_json::Value> {
        st.fake
            .lines()
            .into_iter()
            .filter(|l| l["op"] == "event")
            .map(|l| l["event"].clone())
            .collect()
    }

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

    #[test]
    fn run_records_hold_no_prompt_text_from_the_harness_argv() {
        // Mac test w1, finding M8: `claude -p "<prompt>"` put the prompt in
        // the activity log. Content is off unless DERM_LOG_CONTENT=1, as in the
        // emitter and the receiver: flags stay, other words become lengths.
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
        // The token is in no line the daemon got but the mint reply's.
        for l in st.fake.lines() {
            assert!(!l.to_string().contains(fake::CHAT_TOKEN), "{l}");
        }
    }

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
    }

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
            c["filesystem"]["allowRead"].clone()
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
        assert_eq!(
            allow("chat-l4"),
            serde_json::json!([{"path": path, "literal": true}]),
            "a plain private file"
        );
    }

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

    #[test]
    fn sbx_names_the_variables_and_posts_the_blocks_its_log_shows() {
        let st = setup("sbx");
        let n = st.fake.dir.join("polls");
        // `policy log`: nothing before the start (no sandbox yet), then one
        // block. `run`: checks it got the token by name only, waits for a poll.
        let sbx = script(
            &st.fake.dir,
            "sbx",
            &format!(
                "if [ \"$1\" = policy ]; then echo x >> '{n}'; \
                 if [ \"$(wc -l < '{n}')\" -le 1 ]; then echo 'no such sandbox' >&2; exit 1; fi; \
                 echo '{{\"blocked\":[{{\"Sandbox\":\"derm-chat-x\",\"Host\":\"evil.example:443\",\"Rule\":\"<default policy>\",\"Count\":1}}]}}'; exit 0; fi; \
                 [ \"$1\" = run ] || exit 80; \
                 case \"$*\" in *\"{tok}\"*) exit 81;; esac; \
                 case \"$*\" in *\"-e DERM_CHAT_TOKEN\"*) ;; *) exit 82;; esac; \
                 [ \"$DERM_CHAT_TOKEN\" = {tok} ] || exit 83; \
                 [ \"$DERM_OTLP_ENDPOINT\" = http://host.docker.internal:4318 ] || exit 84; \
                 sleep 3; exit 0",
                n = n.display(),
                tok = fake::CHAT_TOKEN
            ),
        );
        let mut env = RunEnv {
            socket: st.env.socket.clone(),
            home: st.env.home.clone(),
            gateway: None,
            programs: st.env.programs.clone(),
            log_content: false,
            policy: None,
            path: String::new(),
            userns: None,
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
    }

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
            let (policy, _) = derm_core::policy::load(Path::new(&p.policy));
            let (tx, log) = crate::acp::proxy::log_channel(p.socket.clone(), p.token.clone());
            let st = Arc::new(crate::acp::proxy::State::new(
                crate::acp::decide::Ctx {
                    policy,
                    harness: p.harness.clone(),
                    chat: p.chat.clone(),
                    full_access: p.full_access,
                    confined: p.confined,
                },
                tx,
            ));
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

    /// The OTel receiver keeps one helper folder per process
    /// (`otel_receiver::helper_in`), and the tests share one fake chat token:
    /// two Claude Code runs at once in this test process would clear each
    /// other's helper. One `derm run` is one process, so this is the tests'
    /// alone.
    static OTEL_HELPERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clone_env(e: &RunEnv) -> RunEnv {
        RunEnv {
            socket: e.socket.clone(),
            home: e.home.clone(),
            gateway: e.gateway.clone(),
            programs: e.programs.clone(),
            log_content: e.log_content,
            policy: e.policy.clone(),
            path: e.path.clone(),
            userns: e.userns.clone(),
            goose_mode: e.goose_mode.clone(),
            cline_responder: e.cline_responder.clone(),
        }
    }

    #[test]
    fn no_daemon_is_an_error_and_starts_nothing() {
        let st = setup("down");
        let env = RunEnv {
            socket: Some(st.fake.dir.join("absent/daemon.sock")),
            home: st.env.home.clone(),
            gateway: None,
            programs: st.env.programs.clone(),
            log_content: false,
            policy: None,
            path: String::new(),
            userns: None,
            goose_mode: None,
            cline_responder: None,
        };
        let cwd = st.work.to_string_lossy().into_owned();
        let err = run(&s(&["pi", "--boundary", "none", "--cwd", &cwd]), &env).unwrap_err();
        assert_eq!(err.0, 1);
        assert!(err.1.contains("--no-daemon"), "{}", err.1);
        assert!(seen(&st).is_empty(), "the harness never started");
    }

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
        let left = || -> Vec<String> {
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
                if !zombie && String::from_utf8_lossy(&cmd).contains(&marker) {
                    out.push(format!(
                        "{name}: {}",
                        String::from_utf8_lossy(&cmd).replace('\0', " ")
                    ));
                }
            }
            out
        };
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
