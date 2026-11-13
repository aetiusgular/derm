//! A client for the daemon's socket (`contracts/daemon-protocol.md`) as a
//! gate uses it, ported by the wave 5b base from the hook core's
//! `packages/derm-claude-plugin/src/core/daemon.ts` at `e29ce27`: `approve`
//! (a policy `ask` on an agent with no ask of its own, or before Claude
//! Code's own prompt) and `event` (the adapter record). Every call is bounded
//! in time; a daemon that is down never blocks a call longer than the
//! connect timeout. `derm hook` and `derm gate serve` use it; it is
//! integration's after the base.
//!
//! Where it differs from the TypeScript, on purpose:
//! - The socket path when neither `DERM_DAEMON_SOCKET` nor
//!   `XDG_RUNTIME_DIR` is set follows `derm_core::runtime` (case 105:
//!   `/run/user/<uid>` when it is the user's own), as every Rust client does.
//!   A set variable is used as the TypeScript uses it, so a relative one is
//!   refused, not skipped.
//! - On Windows the TypeScript refused the daemon outright (no server check
//!   in Node). Here the connect itself checks the pipe's server
//!   (`derm_core::platform::connect`, case 136), so the endpoint is used. A
//!   chat token file is still refused there (no owner to check with a
//!   `stat`; WW5-3), so a hook needs `DERM_CHAT_TOKEN`.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};

/// How long a connect may take (`CONNECT_TIMEOUT_MS`).
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(800);
/// How long `hello` may take to be answered.
pub const HELLO_TIMEOUT: Duration = Duration::from_millis(2000);
const MAX_LINE_BYTES: usize = 1024 * 1024;

/// The host name sbx's VM reaches the host by (Docker's "Develop and test
/// locally" page).
pub const SBX_HOST: &str = "host.docker.internal";

/// The file derm's sbx kit writes in the VM, as root
/// (`packaging/sbx-kit/claude/install.sh`).
pub const VM_MARKER: &str = "/opt/derm-kit/sbx-vm";

/// The environment a gate reads: the process's own, or a test's.
#[derive(Clone, Debug, Default)]
pub struct Env(pub BTreeMap<String, String>);

impl Env {
    pub fn process() -> Env {
        Env(std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect())
    }
    #[cfg(test)]
    pub fn of(pairs: &[(&str, &str)]) -> Env {
        Env(pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect())
    }
    /// The variable as set (empty included).
    pub fn raw(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(String::as_str)
    }
    /// The variable trimmed, `None` when unset or blank.
    pub fn get(&self, k: &str) -> Option<&str> {
        self.raw(k).map(str::trim).filter(|v| !v.is_empty())
    }
    pub fn with(&self, k: &str, v: &str) -> Env {
        let mut e = self.clone();
        e.0.insert(k.into(), v.into());
        e
    }
}

/// The real path of `p`, following links on every part that exists; a
/// missing tail appended as written (`realish` in `policy.ts`).
pub fn realish(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let abs = lexical(&abs);
    let mut head = abs.clone();
    let mut tail = Vec::new();
    loop {
        if let Ok(real) = std::fs::canonicalize(&head) {
            return tail
                .iter()
                .rev()
                .fold(real, |acc: PathBuf, part| acc.join(part));
        }
        match (head.parent(), head.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_os_string());
                head = parent.to_path_buf();
            }
            _ => return abs,
        }
    }
}

/// `path.resolve`'s `.` and `..` handling, without touching the disk.
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// True when `file` is `folder` or lies under it, after links are followed
/// (`insideFolder`).
pub fn inside_folder(file: &Path, folder: &Path) -> bool {
    realish(file).starts_with(realish(folder))
}

/// `contracts/daemon-protocol.md` section 1, with `DERM_DAEMON_SOCKET` as an
/// override for tests and `derm run` (`socketPath`).
pub fn socket_path(env: &Env) -> PathBuf {
    if let Some(s) = env.get("DERM_DAEMON_SOCKET") {
        return PathBuf::from(env.raw("DERM_DAEMON_SOCKET").unwrap_or(s));
    }
    let home = env
        .get(home_key())
        .map(PathBuf::from)
        .or_else(derm_core::runtime::home_dir)
        .unwrap_or_default();
    if cfg!(target_os = "macos") {
        return home
            .join("Library")
            .join("Application Support")
            .join("derm")
            .join("daemon.sock");
    }
    if let Some(rt) = env.raw("XDG_RUNTIME_DIR").filter(|r| !r.trim().is_empty()) {
        return Path::new(rt).join("derm").join("daemon.sock");
    }
    // Case 105: the folder pam_systemd would have named, when it is ours.
    #[cfg(target_os = "linux")]
    {
        let uid = derm_core::runtime::current_uid();
        if let Some(rt) =
            derm_core::runtime::runtime_dir_with(None, uid, Path::new(derm_core::runtime::RUN_USER))
        {
            return rt.join("derm").join("daemon.sock");
        }
    }
    home.join(".derm")
        .join("run")
        .join("derm")
        .join("daemon.sock")
}

fn home_key() -> &'static str {
    if cfg!(windows) {
        "USERPROFILE"
    } else {
        "HOME"
    }
}

/// Why the socket cannot be trusted, or `None` when it can
/// (`socketLooksOwned`): a socket owned by a trusted user in a folder owned
/// by one that no one else can write. On Windows the connect checks the
/// pipe's server instead (the module's note).
pub fn socket_looks_owned(sock: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let Ok(s) = std::fs::symlink_metadata(sock) else {
            return Some("no daemon socket".into());
        };
        if !s.file_type().is_socket() {
            return Some("not a socket".into());
        }
        if !derm_core::owner::owned_by_trusted(s.uid()) {
            return Some("socket owned by another user".into());
        }
        let Some(Ok(d)) = sock.parent().map(std::fs::symlink_metadata) else {
            return Some("no daemon socket".into());
        };
        if !d.is_dir() {
            return Some("socket folder is not a folder".into());
        }
        if !derm_core::owner::owned_by_trusted(d.uid()) {
            return Some("socket folder owned by another user".into());
        }
        if d.mode() & 0o022 != 0 {
            return Some("socket folder writable by others".into());
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = sock;
        None
    }
}

fn hex64(t: &str) -> bool {
    t.len() == 64
        && t.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The chat token this gate presents (`chatToken`): `DERM_CHAT_TOKEN`, else
/// the file `DERM_CHAT_TOKEN_FILE` names (`derm run` writes it, case 76).
/// Never `daemon.token`: a gate is not the daemon. The file must be
/// absolute, a regular file (not a link), a trusted user's, readable by that
/// user alone (under an agents' user, writable by no one else), small,
/// outside the chat's folder, and not named `daemon.token` (finding S3).
pub fn chat_token(env: &Env, cwd: &Path) -> Option<String> {
    if let Some(t) = env.get("DERM_CHAT_TOKEN").filter(|t| hex64(t)) {
        return Some(t.to_string());
    }
    let file = Path::new(env.get("DERM_CHAT_TOKEN_FILE")?);
    if !file.is_absolute() || inside_folder(file, cwd) {
        return None;
    }
    if file.file_name().and_then(|n| n.to_str()) == Some("daemon.token") {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let st = std::fs::symlink_metadata(file).ok()?;
        if !st.is_file() || st.len() > 256 || !derm_core::owner::owned_by_trusted(st.uid()) {
            return None;
        }
        let agent = derm_core::owner::trusted_owners().is_some_and(|o| o.agent);
        let loose = if agent {
            st.mode() & 0o022 != 0
        } else {
            st.mode() & 0o077 != 0
        };
        if loose {
            return None;
        }
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(file)
            .ok()?;
        let mut s = String::new();
        (&mut f).take(257).read_to_string(&mut s).ok()?;
        let t = s.trim();
        hex64(t).then(|| t.to_string())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// What a `stat` of the marker gives (for [`vm_marker`]'s tests).
pub struct MarkerStat {
    pub uid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub file: bool,
    pub dir: bool,
}

/// Why the VM marker does not hold, or `None` when it does (`vmMarker`): a
/// regular file with one link, root's and writable by no one else, in a
/// folder root's and writable by no one else, on Linux.
pub fn vm_marker(
    file: &Path,
    linux: bool,
    stat: &dyn Fn(&Path) -> Option<MarkerStat>,
) -> Option<String> {
    if !linux {
        return Some("the VM route is only for derm's sbx VM, which is Linux".into());
    }
    let Some(f) = stat(file) else {
        return Some("no VM marker (derm's sbx kit was not installed here)".into());
    };
    if !f.file || f.nlink != 1 {
        return Some("the VM marker is not a plain file".into());
    }
    if f.uid != 0 || f.mode & 0o022 != 0 {
        return Some("the VM marker is not root's alone".into());
    }
    let Some(d) = file.parent().and_then(stat) else {
        return Some("no VM marker (derm's sbx kit was not installed here)".into());
    };
    if !d.dir || d.uid != 0 || d.mode & 0o022 != 0 {
        return Some("the VM marker's folder is not root's alone".into());
    }
    None
}

/// The real `lstat` for [`vm_marker`].
pub fn lstat(p: &Path) -> Option<MarkerStat> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(p).ok()?;
        Some(MarkerStat {
            uid: m.uid(),
            mode: m.mode(),
            nlink: m.nlink(),
            file: m.file_type().is_file(),
            dir: m.file_type().is_dir(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        None
    }
}

/// Where a daemon socket would be on this machine whatever
/// `DERM_DAEMON_SOCKET` says (`socketCandidates`).
pub fn socket_candidates(env: &Env) -> Vec<PathBuf> {
    let mut out = vec![
        socket_path(env),
        socket_path(&env.with("DERM_DAEMON_SOCKET", "")),
    ];
    out.push(socket_path(
        &env.with("DERM_DAEMON_SOCKET", "")
            .with("XDG_RUNTIME_DIR", ""),
    ));
    // HOME can be moved by a project's env; the password database's home
    // cannot (re-review W5R-7).
    #[cfg(unix)]
    if let Some(home) = passwd_home() {
        out.push(
            home.join(".derm")
                .join("run")
                .join("derm")
                .join("daemon.sock"),
        );
    }
    #[cfg(unix)]
    out.push(
        Path::new("/run/user")
            .join(derm_core::runtime::current_uid().to_string())
            .join("derm")
            .join("daemon.sock"),
    );
    out.dedup();
    out
}

#[cfg(unix)]
fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; 16 * 1024];
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: the buffer and the struct outlive the call; `out` is null or
    // points at `pw`.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir is a NUL-terminated string inside `buf`.
    let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

/// A `http://host.docker.internal:<port>` endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmUrl {
    pub host: String,
    pub port: u16,
}

/// Reads `DERM_OTLP_ENDPOINT` as WHATWG's URL parser does for the cases the
/// route checks: scheme and host compared lowercase, the scheme's default
/// port read as no port, no user, password, query or fragment, and a path of
/// `/` or nothing.
fn parse_vm_url(raw: &str) -> Option<VmUrl> {
    let lower = raw.to_ascii_lowercase();
    let rest = lower.strip_prefix("http://")?;
    if rest.contains(['?', '#', '@']) {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if !(path.is_empty() || path == "/") {
        return None;
    }
    let (host, port) = authority.rsplit_once(':')?;
    if host != SBX_HOST || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    // WHATWG drops a scheme's default port: `url.port` is then "".
    if port == 80 {
        return None;
    }
    Some(VmUrl {
        host: SBX_HOST.into(),
        port,
    })
}

/// The route from inside derm's sbx VM to the host's daemon port, or `None`
/// (`vmEndpoint`): `DERM_BOUNDARY=sbx`, a plain
/// `http://host.docker.internal:<port>` in `DERM_OTLP_ENDPOINT`, the
/// root-owned marker derm's kit wrote, not root, and no file where a daemon
/// socket would be. A project can set every variable; it cannot make the
/// marker (W5C-S2).
pub fn vm_endpoint(
    env: &Env,
    marker: &dyn Fn() -> Option<String>,
    uid: Option<u32>,
    candidates: &dyn Fn() -> Vec<PathBuf>,
) -> Option<VmUrl> {
    if env.get("DERM_BOUNDARY") != Some("sbx") {
        return None;
    }
    if uid == Some(0) {
        return None;
    }
    let url = parse_vm_url(env.get("DERM_OTLP_ENDPOINT")?)?;
    if marker().is_some() {
        return None;
    }
    for sock in candidates() {
        match std::fs::symlink_metadata(&sock) {
            Ok(_) => return None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    Some(url)
}

/// One HTTP request to the daemon's derm route (`postVm`); its reply, or
/// why not.
pub fn post_vm(
    url: &VmUrl,
    token: &str,
    request: &Value,
    reply_timeout: Duration,
) -> Result<Value, String> {
    let op = request.get("op").and_then(Value::as_str).unwrap_or("");
    let (path, field) = match op {
        "event" => ("/derm/v1/event", "event"),
        "approve" => ("/derm/v1/approve", "request"),
        other => {
            let shown = request.get("op").map_or("undefined".to_string(), |v| {
                v.as_str().map_or(v.to_string(), str::to_string)
            });
            let _ = other;
            return Err(format!("no route for {shown} from a VM"));
        }
    };
    let body = json!({ field: request.get(field).cloned().unwrap_or(Value::Null) }).to_string();
    let addrs: Vec<std::net::SocketAddr> =
        std::net::ToSocketAddrs::to_socket_addrs(&(url.host.as_str(), url.port))
            .map_err(|e| format!("daemon unreachable ({})", io_code(&e)))?
            .collect();
    let mut last = String::from("daemon unreachable (error)");
    for addr in addrs {
        let mut s = match std::net::TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                last = "daemon connect timed out".into();
                continue;
            }
            Err(e) => {
                last = format!("daemon unreachable ({})", io_code(&e));
                continue;
            }
        };
        let _ = s.set_read_timeout(Some(reply_timeout));
        let _ = s.set_write_timeout(Some(reply_timeout));
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-derm-token: {token}\r\nConnection: close\r\n\r\n",
            url.host,
            url.port,
            body.len()
        );
        // One write: a server that answers before reading the body (an
        // error status) must not turn the reply into a failed write.
        let request_bytes = format!("{head}{body}");
        if s.write_all(request_bytes.as_bytes()).is_err() {
            return Err("daemon reply failed".into());
        }
        let mut raw = Vec::new();
        match (&mut s)
            .take(MAX_LINE_BYTES as u64 + 16 * 1024)
            .read_to_end(&mut raw)
        {
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err("daemon reply timed out".into())
            }
            Err(_) => return Err("daemon reply failed".into()),
        }
        return read_http_reply(&raw);
    }
    Err(last)
}

fn read_http_reply(raw: &[u8]) -> Result<Value, String> {
    let text = String::from_utf8_lossy(raw);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return Err("daemon reply failed".into());
    };
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("");
    let chunked = head.lines().any(|l| {
        l.to_ascii_lowercase().starts_with("transfer-encoding:")
            && l.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked {
        dechunk(body)
    } else {
        body.to_string()
    };
    if body.len() > MAX_LINE_BYTES {
        return Err("daemon reply too long".into());
    }
    if status != "200" {
        return Err(format!("daemon answered HTTP {status}"));
    }
    match serde_json::from_str::<Value>(&body) {
        Ok(v @ Value::Object(_)) => Ok(v),
        Ok(_) => Err("daemon sent a bad reply".into()),
        Err(_) => Err("daemon sent a reply that is not JSON".into()),
    }
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size, after)) = rest.split_once("\r\n") {
        let Ok(n) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if n == 0 || after.len() < n {
            break;
        }
        out.push_str(&after[..n]);
        rest = after[n..].trim_start_matches("\r\n");
    }
    out
}

fn io_code(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => "ECONNREFUSED".into(),
        std::io::ErrorKind::NotFound => "ENOENT".into(),
        std::io::ErrorKind::PermissionDenied => "EACCES".into(),
        std::io::ErrorKind::ConnectionReset => "ECONNRESET".into(),
        _ => "error".into(),
    }
}

/// How an exchange is made.
pub struct Opts<'a> {
    pub env: &'a Env,
    pub client: String,
    pub reply_timeout: Duration,
    pub cwd: &'a Path,
}

/// One connection: hello, then each request in order, one reply line each
/// (`exchange`). The replies, or the reason none came.
pub fn exchange(requests: &[Value], o: &Opts) -> Result<Vec<Value>, String> {
    let env = o.env;
    let sock = socket_path(env);
    if env.get("DERM_DAEMON_SOCKET").is_some() && inside_folder(&sock, o.cwd) {
        return Err(
            "DERM_DAEMON_SOCKET is inside the session folder, which a project can set; not used"
                .into(),
        );
    }
    if !sock.is_absolute() {
        return Err("the daemon socket is not an absolute path; not used".into());
    }
    if inside_folder(&sock, o.cwd) {
        return Err(
            "the daemon socket is inside the session folder, which a project can set; not used"
                .into(),
        );
    }
    let Some(token) = chat_token(env, o.cwd) else {
        return Err("no chat token (start the harness with derm run)".into());
    };
    #[cfg(unix)]
    let uid = Some(derm_core::runtime::current_uid());
    #[cfg(not(unix))]
    let uid = None;
    let linux = cfg!(target_os = "linux");
    if let Some(vm) = vm_endpoint(
        env,
        &|| vm_marker(Path::new(VM_MARKER), linux, &lstat),
        uid,
        &|| socket_candidates(env),
    ) {
        let mut replies = Vec::new();
        for r in requests {
            replies.push(post_vm(&vm, &token, r, o.reply_timeout)?);
        }
        return Ok(replies);
    }
    if let Some(why) = socket_looks_owned(&sock) {
        return Err(why);
    }
    over_socket(&sock, &token, &o.client, requests, o.reply_timeout)
}

fn over_socket(
    sock: &Path,
    token: &str,
    client: &str,
    requests: &[Value],
    reply_timeout: Duration,
) -> Result<Vec<Value>, String> {
    let stream = connect_bounded(sock)?;
    let reader_half = stream
        .try_clone()
        .map_err(|e| format!("daemon unreachable ({})", io_code(&e)))?;
    let mut writer = stream;
    let mut reader = BufReader::new(reader_half);
    let mut lines = vec![json!({"op": "hello", "token": token, "client": client})];
    lines.extend(requests.iter().cloned());
    let mut replies = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let timeout = if i == 0 { HELLO_TIMEOUT } else { reply_timeout };
        let _ = writer.set_read_timeout(Some(timeout));
        let _ = writer.set_write_timeout(Some(timeout));
        let mut text = line.to_string();
        text.push('\n');
        if writer.write_all(text.as_bytes()).is_err() {
            return Err("daemon closed the connection".into());
        }
        let label = if i == 0 {
            "daemon hello timed out"
        } else {
            "daemon reply timed out"
        };
        let reply = read_reply(&mut reader, label)?;
        if i == 0 {
            if reply.get("ok") != Some(&Value::Bool(true)) {
                let why = reply.get("error").map_or("no reason".to_string(), |e| {
                    e.as_str().map_or(e.to_string(), str::to_string)
                });
                return Err(format!("daemon refused hello: {why}"));
            }
            // A gate is never the daemon (finding S3).
            if reply.get("scope").and_then(Value::as_str) != Some("chat") {
                return Err("the token has daemon scope; a hook presents only a chat token".into());
            }
            continue;
        }
        replies.push(reply);
    }
    Ok(replies)
}

fn read_reply(
    reader: &mut BufReader<derm_core::platform::Stream>,
    timeout_label: &str,
) -> Result<Value, String> {
    loop {
        let mut buf = Vec::new();
        match reader
            .by_ref()
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)
        {
            Ok(0) => return Err("daemon closed the connection".into()),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(timeout_label.into())
            }
            Err(_) => return Err("daemon closed the connection".into()),
        }
        if buf.len() > MAX_LINE_BYTES {
            return Err("daemon line too long".into());
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        return match serde_json::from_str::<Value>(line) {
            Ok(v @ Value::Object(_)) => Ok(v),
            Ok(_) => Err("daemon sent a bad line".into()),
            Err(_) => Err("daemon sent a line that is not JSON".into()),
        };
    }
}

/// Connects within [`CONNECT_TIMEOUT`]: a socket connect does not block on a
/// listener that is not accepting, so the time bound is on what follows.
fn connect_bounded(sock: &Path) -> Result<derm_core::platform::Stream, String> {
    derm_core::platform::connect(sock).map_err(|e| format!("daemon unreachable ({})", io_code(&e)))
}

/// An `approve` request (contract section 2).
#[derive(Clone, Debug, PartialEq)]
pub struct ApproveRequest {
    pub id: String,
    pub chat: String,
    pub harness: String,
    pub tool: String,
    pub summary: String,
    pub timeout_seconds: u64,
}

impl ApproveRequest {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "chat": self.chat,
            "harness": self.harness,
            "tool": self.tool,
            "summary": self.summary,
            "timeoutSeconds": self.timeout_seconds,
        })
    }
}

/// Who answered an `approve`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum By {
    Approver,
    Timeout,
    None,
}

/// What `approve` gave (`ApproveOutcome`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApproveOutcome {
    Answer { yes: bool, by: By },
    Unreachable(String),
}

/// Sends `approve` and waits for the answer (contract section 2, rule 3).
/// Only an explicit yes from an approver counts as yes.
pub fn approve(request: &ApproveRequest, env: &Env, cwd: &Path) -> ApproveOutcome {
    let o = Opts {
        env,
        client: format!("derm hook ({})", request.harness),
        reply_timeout: Duration::from_secs(request.timeout_seconds + 5),
        cwd,
    };
    let replies = match exchange(
        &[json!({"op": "approve", "request": request.to_json()})],
        &o,
    ) {
        Ok(r) => r,
        Err(e) => return ApproveOutcome::Unreachable(e),
    };
    let Some(reply) = replies
        .first()
        .filter(|r| r.get("ok") == Some(&Value::Bool(true)))
    else {
        let why = replies
            .first()
            .and_then(|r| r.get("error"))
            .map_or("no reply".to_string(), |e| {
                e.as_str().map_or(e.to_string(), str::to_string)
            });
        return ApproveOutcome::Unreachable(format!("daemon refused approve: {why}"));
    };
    let yes = reply.get("answer").and_then(Value::as_str) == Some("yes");
    let by = match reply.get("by").and_then(Value::as_str) {
        Some("timeout") => By::Timeout,
        Some("none") => By::None,
        _ => By::Approver,
    };
    ApproveOutcome::Answer {
        yes: yes && by == By::Approver,
        by,
    }
}

/// The id of a gate decision record (`decisionId`):
/// `<harness>-<call id>-decision-<128 random bits>`, the call id cleaned to
/// the daemon's `clean_id` characters and cut so the whole id fits 128.
pub fn decision_id(harness: &str, call_id: Option<&str>) -> String {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let call: String = call_id
        .unwrap_or("unknown")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let call = if call.is_empty() {
        "unknown".to_string()
    } else {
        call
    };
    let room = 128usize
        .saturating_sub(harness.chars().count() + "--decision-".len() + nonce.len())
        .max(1);
    let cut: String = call.chars().take(room).collect();
    format!("{harness}-{cut}-decision-{nonce}")
}

/// An adapter record (contracts/events.md section 4).
#[derive(Clone, Debug, PartialEq)]
pub struct AdapterEvent {
    pub id: String,
    pub chat_id: String,
    pub harness: String,
    /// `tool.call`, `approval` or `install.call`.
    pub kind: String,
    pub summary: String,
    pub detail: Map<String, Value>,
}

/// What became of one adapter record: the daemon took it, the light tier's
/// per-chat log kept it (`gate/locallog/`), or neither did, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Posted {
    Daemon,
    Light,
    Lost(String),
}

impl Posted {
    /// Whether the daemon took the record (what [`post_event`] returns).
    pub fn by_daemon(&self) -> bool {
        matches!(self, Posted::Daemon)
    }
}

/// Is this hook part of a `derm run` chat, whose records are the daemon's?
/// Only when its chat token is the one a `derm run` of this same program
/// gave the chain the hook runs in: a project's settings can set
/// `DERM_CHAT_TOKEN` in a hook's environment (case 227), never the start
/// environment of the process `derm run` started, so neither a token alone
/// (integration w6's review, W6C-S4) nor a token under a `derm run` that gave
/// none (`--no-daemon`) or gave another (re-review W6C-R6) turns the light
/// tier's fail-closed rules off. Where the hook cannot see that `derm run`
/// (srt's PID namespace on Linux; srt's Seatbelt profile on macOS, read and
/// not run, W6C-R8) or cannot read another process's start environment
/// (Windows), the answer is no, and a record nothing kept denies the call.
/// Under srt on Linux that is not what holds today: srt refuses a Unix
/// socket, so no hook reaches the daemon, and srt's `denyRead` of `~/.derm`
/// is a writable tmpfs, so the light log's append succeeds into a folder
/// that goes with the sandbox and nothing denies (re-review W6C-R7, run;
/// open).
pub fn derm_run_chat(env: &Env, cwd: &Path) -> bool {
    chat_token(env, cwd).is_some_and(|t| run_gave(&t))
}

/// Whether a process running this same program (by its real path) is one of
/// this process's ancestors, and the process it started on the way down to
/// this one (itself an ancestor) was started with `DERM_CHAT_TOKEN` equal to
/// `token`.
pub fn run_gave(token: &str) -> bool {
    #[cfg(test)]
    if let Some(v) = UNDER_DERM_RUN.with(std::cell::Cell::get) {
        return v;
    }
    use derm_core::platform::peer;
    let Some(me) = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
    else {
        return false;
    };
    // The hook itself never counts as the process `derm run` started: a
    // shell that execs the hook hands it whatever start environment its
    // line set, a project's token included. A harness starts its hooks as
    // children, so the process below `derm run` is an ancestor.
    let chain = peer::ancestors(std::process::id());
    chain.windows(2).any(|w| {
        let (below, p) = (w[0], w[1]);
        peer::program(p)
            .and_then(|x| std::fs::canonicalize(x).ok())
            .is_some_and(|x| x == me)
            && peer::environ_var(below, "DERM_CHAT_TOKEN").as_deref() == Some(token)
    })
}

#[cfg(test)]
thread_local! {
    /// A unit test's stand-in for a `derm run` above it that gave the hook's
    /// token (a test runs under cargo, never under `derm run`); `None` reads
    /// the real ancestry.
    pub static UNDER_DERM_RUN: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// The reason a pre event's decision becomes a deny after its record was
/// `posted`, or `None`: only a record neither the daemon nor the light tier
/// kept, in a hook that is not part of a `derm run` chat
/// (`locallog::denies`; lane 6B's request 1, wired at the wave 6 phase 1
/// merge). In a `derm run` chat ([`derm_run_chat`]) the record is the
/// daemon's, and a daemon restart (case 86) must not deny every call.
pub fn lost_deny(posted: &Posted, env: &Env, cwd: &Path) -> Option<String> {
    match posted {
        Posted::Lost(why) => {
            super::locallog::denies(&super::locallog::Outcome::Failed(why.clone()), env, cwd)
        }
        _ => None,
    }
}

/// Posts one adapter record (`postEvent`). Best effort; never panics. True
/// when the daemon took it; a record it did not take goes to the light tier
/// ([`post_event_kept`] says which).
pub fn post_event(event: &AdapterEvent, env: &Env, cwd: &Path) -> bool {
    post_event_kept(event, env, cwd).by_daemon()
}

/// [`post_event`], saying where the record went.
pub fn post_event_kept(event: &AdapterEvent, env: &Env, cwd: &Path) -> Posted {
    let mut detail = Map::new();
    detail.insert("trust".into(), json!("client"));
    for (k, v) in &event.detail {
        detail.insert(k.clone(), v.clone());
    }
    let summary: String = event
        .summary
        .encode_utf16()
        .take(200)
        .collect::<Vec<u16>>()
        .pipe_utf16();
    let line = json!({
        "op": "event",
        "event": {
            "id": event.id,
            "chatId": event.chat_id,
            "harness": event.harness,
            "kind": event.kind,
            "summary": summary,
            "detail": detail,
            "at": 0,
            "source": "adapter",
        }
    });
    let o = Opts {
        env,
        client: format!("derm hook ({})", event.harness),
        reply_timeout: Duration::from_millis(1500),
        cwd,
    };
    let posted = matches!(exchange(&[line], &o), Ok(r) if r.first().and_then(|r| r.get("ok")) == Some(&Value::Bool(true)));
    // Wave 6's seam (lane 6B, `gate/locallog/`): the light tier's per-chat
    // log keeps what the daemon did not take.
    match super::locallog::after_post(event, env, cwd, posted) {
        _ if posted => Posted::Daemon,
        super::locallog::Outcome::Appended { .. } => Posted::Light,
        super::locallog::Outcome::Failed(why) => Posted::Lost(why),
        super::locallog::Outcome::Skipped => Posted::Lost("not recorded".into()),
    }
}

/// JavaScript's `slice(0, 200)` cuts by UTF-16 code units; a cut through a
/// surrogate pair leaves a lone half, which `JSON.stringify` escapes. Here a
/// lone half is dropped instead (a summary is display text).
trait PipeUtf16 {
    fn pipe_utf16(self) -> String;
}
impl PipeUtf16 for Vec<u16> {
    fn pipe_utf16(self) -> String {
        char::decode_utf16(self).filter_map(Result::ok).collect()
    }
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod tests;
