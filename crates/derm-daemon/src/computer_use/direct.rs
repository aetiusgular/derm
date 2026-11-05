//! Computer use on Linux (wave 5 lane U): the helper's line protocol served
//! inside the daemon, with one `cua-driver mcp --direct` child per runtime.
//!
//! On macOS the grants belong to a separate, signed helper app, so the
//! daemon talks to it over a socket (`mod.rs`, `macos/computer-use-helper/`).
//! On Linux there is no such grant: cua-driver 0.38.0's bare `mcp` owns a
//! direct runtime on Windows and Linux and shuts it down on stdin EOF
//! (`crates/cua-driver/src/cli.rs:17-27, 654-660` at `cua-driver-rs-v0.38.0`,
//! read; note AR section 3.2). So the "helper" here is a thread in the
//! daemon that speaks the same protocol `core.rs` speaks to the Mac helper
//! (`hello`, `resolve`, `start`, `tools`, `call`, `stop`) over a socket
//! pair, and `Core` runs unchanged on top.
//!
//! - **Outside the chat.** The driver is the daemon's child, never a child of
//!   `derm-daemon cu-mcp`, which runs in the harness's tree, boundary and
//!   user (lane V). It runs as you, with the display variables the daemon
//!   has, outside every sandbox (rules section 5, item 2), and only while a
//!   chat holds an app.
//! - **Bounded, always.** `CUA_DRIVER_PERMISSION_MODE=bounded` with the
//!   chat's manifest through the environment (`mcp` refuses every
//!   authorization flag, `cli.rs:799-805`); nothing lifts it (case 83). The
//!   environment is cleared first, so a bypass variable in the daemon's own
//!   environment never reaches the driver.
//! - **Apps by executable.** A v3 manifest names an app by `bundle_id` or a
//!   canonical absolute `executable` (`session_manifest.rs:586-596,
//!   1098-1120`). `Core` grants and writes ids; this side resolves a name to
//!   a running program's executable (`/proc/<pid>/exe`) or one on `PATH`,
//!   names it `exe.<file name>` (a dot, so `parse_bundle_id` keeps it), and
//!   rewrites each id to its path when it starts the runtime. An id it did
//!   not resolve itself is refused.
//! - **Never granted:** derm's own programs, cua-driver, screen lockers and
//!   password stores (`apps.rs`, `LINUX_NEVER`).
//! - **The driver itself** is found at a fixed path, owned by root or you
//!   and writable by no one else (`find_driver`). The installer's default
//!   is `$HOME/.local/bin`, which any process of yours can replace: an
//!   unbounded agent could swap it (open item, in the lane's status doc).
//!   Under srt, sbx or lane V's agents' user it cannot.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::apps::is_never_program;
use super::core::HelperLauncher;
use super::helper_client::{EventSink, HelperClient};

/// The largest line taken from the driver: a window screenshot, base64.
const MAX_LINE: usize = 64 * 1024 * 1024;
const PROTOCOL_VERSION: &str = "2025-06-18";
const INIT_TIMEOUT: Duration = Duration::from_secs(20);
/// Longer than `core.rs`'s call timeout, so `Core` times out first and
/// reports the outcome as unknown (case 120).
const CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest manifest written.
const MAX_MANIFEST: usize = 64 * 1024;
/// Variables the driver needs to reach your session's display, passed from
/// the daemon's own environment when set. Nothing else crosses.
const DISPLAY_VARS: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "DBUS_SESSION_BUS_ADDRESS",
];

/// Where cua-driver is looked for, in order. A debug build also takes
/// `DERM_CUA_DRIVER`, for tests and a driver built beside the repository.
pub fn driver_candidates(home: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("DERM_CUA_DRIVER") {
        out.push(PathBuf::from(path));
    }
    out.push(PathBuf::from("/usr/local/bin/cua-driver"));
    out.push(PathBuf::from("/usr/bin/cua-driver"));
    if let Some(home) = home {
        out.push(home.join(".local/bin/cua-driver"));
    }
    out
}

/// The first candidate that is a regular file, after links, owned by root
/// or `uid`, writable by no one else, in folders writable by no one else.
pub fn find_driver(candidates: &[PathBuf], uid: u32) -> Option<PathBuf> {
    candidates
        .iter()
        .filter_map(|c| fs::canonicalize(c).ok())
        .find(|path| trusted_file(path, uid))
}

fn trusted_owner(meta: &fs::Metadata, uid: u32) -> bool {
    (meta.uid() == 0 || meta.uid() == uid) && meta.mode() & 0o022 == 0
}

fn trusted_file(path: &Path, uid: u32) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.mode() & 0o111 == 0 || !trusted_owner(&meta, uid) {
        return false;
    }
    path.ancestors()
        .skip(1)
        .all(|dir| fs::metadata(dir).is_ok_and(|m| trusted_owner(&m, uid)))
}

/// The launcher `mod.rs` uses on Linux.
pub struct DirectLauncher {
    pub driver: Option<PathBuf>,
    /// The daemon's private folder for manifests (0700).
    pub data: Option<PathBuf>,
    /// The daemon's own environment, read once.
    pub env: Vec<(String, String)>,
    pub home: PathBuf,
    /// Where `/proc` is (a fixture in tests).
    pub proc_root: PathBuf,
}

impl HelperLauncher for DirectLauncher {
    fn launch(&self, events: EventSink) -> Result<HelperClient, String> {
        let driver = self
            .driver
            .clone()
            .ok_or("cua-driver is not installed where derm looks (/usr/local/bin, /usr/bin or ~/.local/bin), or it can be changed by someone else.")?;
        let data = self
            .data
            .as_ref()
            .ok_or("No daemon data folder.")?
            .join("computer-use");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&data)
            .map_err(|e| e.to_string())?;
        let (ours, theirs) = UnixStream::pair().map_err(|e| e.to_string())?;
        let server = Arc::new(Server {
            driver,
            private: data,
            env: launch_env(&self.env, &self.home),
            proc_root: self.proc_root.clone(),
            uid: current_uid(),
            own_exe: std::env::current_exe()
                .ok()
                .and_then(|p| fs::canonicalize(p).ok()),
            ids: Mutex::new(HashMap::new()),
            runtimes: Mutex::new(HashMap::new()),
            writer: Mutex::new(Box::new(theirs.try_clone().map_err(|e| e.to_string())?)),
        });
        let reader = theirs;
        thread::Builder::new()
            .name("derm-daemon-cu-direct".into())
            .spawn(move || server.serve(reader))
            .map_err(|e| e.to_string())?;
        Ok(HelperClient::new(
            ours.try_clone().map_err(|e| e.to_string())?,
            ours,
            events,
        ))
    }

    fn location(&self) -> Option<String> {
        self.driver
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn installed(&self) -> bool {
        self.driver.is_some()
    }
}

fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// The driver's environment: a fixed base (telemetry and updates off, as the
/// Mac helper sets them, `driver.rs`), the display variables, nothing else.
pub fn launch_env(daemon_env: &[(String, String)], home: &Path) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = vec![
        ("HOME".into(), home.to_string_lossy().into_owned()),
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("CUA_DRIVER_RS_TELEMETRY_ENABLED".into(), "false".into()),
        ("CUA_DRIVER_RS_UPDATE_CHECK".into(), "false".into()),
        ("DO_NOT_TRACK".into(), "1".into()),
        ("CUA_TELEMETRY".into(), "0".into()),
        ("CUA_DRIVER_DISABLE_RUN_SCRIPT".into(), "1".into()),
        ("CUA_DRIVER_DISABLE_UNRESTRICTED".into(), "1".into()),
        ("CUA_DRIVER_PERMISSION_MODE".into(), "bounded".into()),
    ];
    for (key, value) in daemon_env {
        if DISPLAY_VARS.contains(&key.as_str()) && !value.is_empty() && value.len() < 4096 {
            env.push((key.clone(), value.clone()));
        }
    }
    env
}

struct Runtime {
    child: Mutex<Child>,
    client: Mutex<Client>,
    /// Set by a stop: a call waiting on the driver returns at once.
    cancel: Arc<AtomicBool>,
}

struct Server {
    driver: PathBuf,
    private: PathBuf,
    env: Vec<(String, String)>,
    proc_root: PathBuf,
    uid: u32,
    own_exe: Option<PathBuf>,
    /// derm's ids (`exe.<name>`) for the programs it resolved, to their
    /// canonical paths.
    ids: Mutex<HashMap<String, PathBuf>>,
    runtimes: Mutex<HashMap<String, Arc<Runtime>>>,
    writer: Mutex<Box<dyn Write + Send>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Server {
    fn serve(self: Arc<Self>, stream: UnixStream) {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let Ok(request) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let me = self.clone();
            // Each request on its own thread: a long call never holds up a
            // stop.
            thread::spawn(move || {
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                let mut reply = match me.handle(&request) {
                    Ok(body) => body,
                    Err(error) => json!({"ok": false, "error": error}),
                };
                if let Some(map) = reply.as_object_mut() {
                    map.insert("id".into(), id);
                    map.entry("ok").or_insert(json!(true));
                }
                let mut text = reply.to_string();
                text.push('\n');
                let _ = lock(&me.writer).write_all(text.as_bytes());
            });
        }
        // The daemon closed its side: every runtime ends.
        let all: Vec<_> = lock(&self.runtimes).drain().map(|(_, r)| r).collect();
        for runtime in all {
            finish(&runtime);
        }
    }

    fn handle(&self, request: &Value) -> Result<Value, String> {
        let op = request.get("op").and_then(Value::as_str).unwrap_or("");
        let runtime_id = || {
            request
                .get("runtime")
                .and_then(Value::as_str)
                .filter(|id| {
                    !id.is_empty()
                        && id.len() <= 64
                        && id
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                })
                .map(str::to_string)
                .ok_or_else(|| "Bad runtime id".to_string())
        };
        match op {
            "hello" => Ok(json!({})),
            "resolve" => {
                let query = request.get("query").and_then(Value::as_str).unwrap_or("");
                Ok(json!({"app": self.resolve(query)}))
            }
            "start" => {
                let id = runtime_id()?;
                let manifest = request
                    .get("manifest")
                    .and_then(Value::as_str)
                    .ok_or("No manifest")?;
                let pid = self.start(&id, manifest)?;
                Ok(json!({"pid": pid}))
            }
            "tools" => {
                let runtime = self.runtime(&runtime_id()?)?;
                let result =
                    lock(&runtime.client).request("tools/list", json!({}), INIT_TIMEOUT)?;
                Ok(json!({"tools": result.get("tools").cloned().unwrap_or(json!([]))}))
            }
            "call" => {
                let runtime = self.runtime(&runtime_id()?)?;
                let name = request.get("name").and_then(Value::as_str).unwrap_or("");
                if !super::manifest::tool_allowed(name) {
                    return Err("That tool is not allowed.".into());
                }
                let arguments = request.get("arguments").cloned().unwrap_or(json!({}));
                let result = lock(&runtime.client).request(
                    "tools/call",
                    json!({"name": name, "arguments": arguments}),
                    CALL_TIMEOUT,
                )?;
                Ok(json!({"result": result}))
            }
            "stop" => {
                let id = request.get("runtime").and_then(Value::as_str).unwrap_or("");
                let gone = lock(&self.runtimes).remove(id);
                let ended = gone.is_some();
                if let Some(runtime) = gone {
                    finish(&runtime);
                }
                Ok(json!({"ended": ended, "releasedButtons": []}))
            }
            _ => Err("Unknown op".into()),
        }
    }

    fn runtime(&self, id: &str) -> Result<Arc<Runtime>, String> {
        lock(&self.runtimes)
            .get(id)
            .cloned()
            .ok_or_else(|| "Not running".to_string())
    }

    /// A name or path to a program the person can grant, and derm's id for
    /// it. Running programs of this user first, then `PATH`.
    fn resolve(&self, query: &str) -> Option<Value> {
        let query = query.trim();
        if query.is_empty() || query.len() > 255 || query.contains('\0') {
            return None;
        }
        let path = if query.starts_with('/') {
            fs::canonicalize(query).ok()
        } else if let Some(known) = lock(&self.ids).get(&query.to_ascii_lowercase()) {
            Some(known.clone())
        } else {
            running_program(&self.proc_root, self.uid, query).or_else(|| on_path(query))
        }?;
        if !fs::metadata(&path).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0) {
            return None;
        }
        let name = path.file_name()?.to_string_lossy().into_owned();
        if is_never_program(&name) || Some(&path) == self.own_exe.as_ref() || path == self.driver {
            return None;
        }
        let id = self.id_for(&name, &path)?;
        Some(json!({"bundleId": id, "name": name, "path": path.to_string_lossy()}))
    }

    /// `exe.<name>`, or `exe.<name>.<8 hex>` when another path holds it.
    fn id_for(&self, name: &str, path: &Path) -> Option<String> {
        let clean: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .take(100)
            .collect();
        if clean.trim_matches('-').is_empty() {
            return None;
        }
        let mut ids = lock(&self.ids);
        let plain = format!("exe.{}", clean.to_ascii_lowercase());
        let id = match ids.get(&plain) {
            Some(held) if held != path => {
                let hash = Sha256::digest(path.as_os_str().as_encoded_bytes());
                format!(
                    "{plain}.{:02x}{:02x}{:02x}{:02x}",
                    hash[0], hash[1], hash[2], hash[3]
                )
            }
            _ => plain,
        };
        if ids.len() < 4096 || ids.contains_key(&id) {
            ids.insert(id.clone(), path.to_path_buf());
            Some(id)
        } else {
            None
        }
    }

    /// Core's manifest with each app's id replaced by its executable.
    pub fn rewrite(&self, manifest: &str) -> Result<String, String> {
        if manifest.len() > MAX_MANIFEST || !manifest.is_ascii() {
            return Err("Bad manifest".into());
        }
        let ids = lock(&self.ids);
        let mut out = String::new();
        let mut apps = 0;
        for line in manifest.lines() {
            if let Some(rest) = line.strip_prefix("    - bundle_id: ") {
                let id: String = serde_json::from_str(rest).map_err(|_| "Bad manifest")?;
                let path = ids
                    .get(&id.to_ascii_lowercase())
                    .ok_or_else(|| format!("derm did not resolve {id} on this machine."))?;
                let text = path.to_str().ok_or("A path that is not text")?;
                out.push_str(&format!(
                    "    - executable: {}\n",
                    serde_json::to_string(text).map_err(|e| e.to_string())?
                ));
                apps += 1;
            } else if line.contains("bundle_id") || line.contains("executable") {
                return Err("Bad manifest".into());
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        if apps == 0 {
            return Err("No app in the manifest".into());
        }
        Ok(out)
    }

    fn start(&self, id: &str, manifest: &str) -> Result<u32, String> {
        let manifest = self.rewrite(manifest)?;
        let folder = self
            .private
            .join(format!("m-{}", uuid::Uuid::new_v4().simple()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&folder)
            .map_err(|e| e.to_string())?;
        let path = folder.join("manifest.yaml");
        let result = (|| {
            write_new_private(&path, manifest.as_bytes())?;
            let mut env = self.env.clone();
            env.push((
                "CUA_DRIVER_CAPABILITY_MANIFEST_FILE".into(),
                path.to_string_lossy().into_owned(),
            ));
            env.push(("CUA_DRIVER_CAPABILITY_MANIFEST_APPROVED".into(), "1".into()));
            let mut command = Command::new(&self.driver);
            command.args(["mcp", "--direct"]).env_clear();
            for (key, value) in &env {
                command.env(key, value);
            }
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("cua-driver did not start: {e}"))?;
            let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                let _ = child.kill();
                let _ = child.wait();
                return Err("cua-driver has no pipes.".to_string());
            };
            let mut client = Client::new(stdout, stdin);
            let cancel = client.cancel.clone();
            let initialized = client.initialize(INIT_TIMEOUT);
            let pid = child.id();
            let runtime = Arc::new(Runtime {
                child: Mutex::new(child),
                client: Mutex::new(client),
                cancel,
            });
            if let Err(error) = initialized {
                finish(&runtime);
                return Err(format!("cua-driver did not start: {error}"));
            }
            let old = lock(&self.runtimes).insert(id.to_string(), runtime);
            if let Some(old) = old {
                finish(&old);
            }
            Ok(pid)
        })();
        // The driver reads the manifest once, before stdin (`proxy.rs`), so
        // it is gone once the driver answered initialize.
        let _ = fs::remove_dir_all(&folder);
        result
    }
}

/// Ends a runtime: stdin closed (the driver's own shutdown), then a kill
/// after a short grace, and the child reaped.
fn finish(runtime: &Runtime) {
    // A call in flight sees the flag within 25 ms and lets go of the client.
    runtime.cancel.store(true, Ordering::SeqCst);
    lock(&runtime.client).close();
    let mut child = lock(&runtime.child);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            _ => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())
}

/// A running program of `uid` whose executable's file name or `comm` is
/// `query` (any case): its canonical executable.
pub fn running_program(proc_root: &Path, uid: u32, query: &str) -> Option<PathBuf> {
    let want = query.to_ascii_lowercase();
    let entries = fs::read_dir(proc_root).ok()?;
    let mut found: Vec<(u64, PathBuf)> = Vec::new();
    for entry in entries.flatten().take(65_536) {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u64>().ok()) else {
            continue;
        };
        let dir = entry.path();
        if fs::metadata(&dir).map(|m| m.uid()).ok() != Some(uid) {
            continue;
        }
        let Ok(exe) = fs::read_link(dir.join("exe")) else {
            continue;
        };
        let file = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_ascii_lowercase());
        let comm = fs::read_to_string(dir.join("comm"))
            .ok()
            .map(|c| c.trim().to_ascii_lowercase());
        if file.as_deref() == Some(want.as_str()) || comm.as_deref() == Some(want.as_str()) {
            found.push((pid, exe));
        }
    }
    found.sort();
    found
        .into_iter()
        .map(|(_, exe)| exe)
        .find(|exe| exe.is_absolute() && !exe.to_string_lossy().ends_with(" (deleted)"))
}

/// A program on a fixed `PATH` (not the daemon's: a project can change it).
fn on_path(query: &str) -> Option<PathBuf> {
    if query.contains('/') {
        return None;
    }
    ["/usr/local/bin", "/usr/bin", "/bin", "/snap/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(query))
        .find_map(|p| fs::canonicalize(p).ok())
}

/// A small MCP client over the driver's stdio (the Mac helper's
/// `mcp_client.rs`, the same rules).
struct Client {
    writer: Box<dyn Write + Send>,
    incoming: Receiver<Value>,
    next_id: u64,
    cancel: Arc<AtomicBool>,
}

impl Client {
    fn new(reader: impl Read + Send + 'static, writer: impl Write + Send + 'static) -> Self {
        let (tx, incoming) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut line = Vec::new();
            loop {
                line.clear();
                match (&mut reader)
                    .take(MAX_LINE as u64 + 1)
                    .read_until(b'\n', &mut line)
                {
                    Ok(0) | Err(_) => break,
                    Ok(n) if n > MAX_LINE => {
                        // A line too long: skip the rest of it.
                        let mut rest = Vec::new();
                        if reader.read_until(b'\n', &mut rest).is_err() {
                            break;
                        }
                        continue;
                    }
                    Ok(_) => {}
                }
                if let Ok(value) = serde_json::from_slice::<Value>(&line) {
                    if tx.send(value).is_err() {
                        break;
                    }
                }
            }
        });
        Client {
            writer: Box::new(writer),
            incoming,
            next_id: 1,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    fn send(&mut self, message: &Value) -> Result<(), String> {
        let mut line = serde_json::to_vec(message).map_err(|e| e.to_string())?;
        line.push(b'\n');
        self.writer
            .write_all(&line)
            .and_then(|_| self.writer.flush())
            .map_err(|e| format!("The computer-use runtime closed: {e}"))
    }

    fn close(&mut self) {
        self.writer = Box::new(std::io::sink());
    }

    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err("The computer-use runtime was stopped.".into());
        }
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let deadline = Instant::now() + timeout;
        loop {
            if self.cancel.load(Ordering::SeqCst) {
                return Err("The computer-use runtime was stopped.".into());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            let step = Duration::from_millis(25);
            let message = match self.incoming.recv_timeout(left.min(step)) {
                Ok(m) => m,
                Err(RecvTimeoutError::Timeout) if left > step => continue,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "The computer-use runtime did not answer {method} in time."
                    ))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("The computer-use runtime ended.".into())
                }
            };
            match (message.get("id"), message.get("method").is_some()) {
                (Some(their), true) => {
                    let their = their.clone();
                    self.send(&json!({"jsonrpc":"2.0","id":their,"error":{"code":-32601,"message":"Not supported"}}))?;
                }
                (Some(their), false) if their.as_u64() == Some(id) => {
                    if let Some(error) = message.get("error") {
                        let text = error
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("error");
                        return Err(format!(
                            "The runtime refused {method}: {}",
                            text.chars().take(300).collect::<String>()
                        ));
                    }
                    return Ok(message.get("result").cloned().unwrap_or(Value::Null));
                }
                _ => {}
            }
        }
    }

    fn initialize(&mut self, timeout: Duration) -> Result<Value, String> {
        let result = self.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "derm-daemon", "version": env!("CARGO_PKG_VERSION")}
            }),
            timeout,
        )?;
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}))?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "direct_tests.rs"]
mod tests;
