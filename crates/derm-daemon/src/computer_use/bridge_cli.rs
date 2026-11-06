//! `derm-daemon cu-mcp`: the stdio MCP server a harness starts for a chat
//! with computer use. It holds no chat state: it connects to the daemon's
//! loopback bridge with the chat's token and relays lines both ways.
//!
//! The endpoint comes from the daemon's `cu.endpoint` file and the token from
//! what `derm run` gave the harness (`relay.rs`, lane K), never from arguments,
//! so no command line or MCP config file names them. The fork read both from
//! `MONOCODE_CU_ENDPOINT` and `MONOCODE_CU_TOKEN`, which derm does not set.
//!
//! It lives as long as the harness keeps its stdin open. Claude Code does not
//! restart a stdio MCP server that exits ("Stdio servers are local processes,
//! and Claude Code doesn't reconnect them automatically",
//! https://code.claude.com/docs/en/mcp), so a relay that quit on a refused
//! token or a dropped connection took computer use from the chat for good
//! (Mac test findings 4.7 and 4.12). While it has no connection it answers
//! as an empty server itself, and it dials again on a later request.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// The longest line relayed either way: a screenshot result.
const MAX_LINE: usize = 64 * 1024 * 1024;
/// How often a relay with no connection dials again, at most.
const RETRY: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// A daemon that stops reading cannot hold the harness forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
pub const OFF_TEXT: &str =
    "Computer use is off for this chat. Start the harness with derm run on the Mac, with the daemon running.";
pub const STOPPED_TEXT: &str =
    "Computer use stopped for this chat. Ask the user before trying again.";
/// The id prefix of the `initialize` the relay replays after a reconnect.
/// Its reply is the relay's, not the harness's.
const REPLAY_ID: &str = "derm-relay-init-";

/// Where to connect, from the variable's value. Loopback only.
pub fn endpoint(raw: Option<&str>) -> Result<SocketAddr, String> {
    let raw = raw.ok_or(
        "Computer use is not on for this chat. Start the harness with derm run on the Mac, with the daemon running.",
    )?;
    let address: SocketAddr = raw
        .parse()
        .map_err(|_| "Bad computer-use endpoint".to_string())?;
    if !address.ip().is_loopback() {
        return Err("The computer-use endpoint must be on this machine.".into());
    }
    Ok(address)
}

/// Serves on this process's stdin and stdout with `endpoint` and `token`
/// as `relay.rs` found them; `None` answers as an empty server.
pub fn run_with(endpoint: Option<&str>, token: Option<&str>) -> i32 {
    serve_stdio(endpoint, token, RETRY, io::stdin(), io::stdout())
}

type Out = Arc<Mutex<Box<dyn Write + Send>>>;

struct Link {
    stream: TcpStream,
    /// Which connection this is, so a late reader of an old one changes nothing.
    serial: u64,
}

#[derive(Default)]
struct State {
    link: Option<Link>,
    serial: u64,
    /// The harness's own `initialize`, replayed on each reconnect.
    initialize: Option<Value>,
    /// Requests sent to MonoCode and not yet answered: id key, (id, method).
    pending: HashMap<String, (Value, String)>,
    last_dial: Option<Instant>,
}

struct Relay {
    target: Option<(SocketAddr, String)>,
    retry: Duration,
    state: Mutex<State>,
    out: Out,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Serves MCP on `input` and `output` until `input` closes. Returns the exit
/// code: 0 when the harness closed stdin, 1 when the harness went away.
pub fn serve_stdio(
    endpoint_raw: Option<&str>,
    token: Option<&str>,
    retry: Duration,
    input: impl Read + Send + 'static,
    output: impl Write + Send + 'static,
) -> i32 {
    let target = match (endpoint(endpoint_raw), token) {
        (Ok(address), Some(token)) if !token.is_empty() => Some((address, token.to_string())),
        _ => None,
    };
    let relay = Arc::new(Relay {
        target,
        retry,
        state: Mutex::new(State::default()),
        out: Arc::new(Mutex::new(Box::new(output))),
    });
    // Now, so a chat switched on before the harness started is ready at once.
    {
        let mut state = lock(&relay.state);
        relay.dial(&mut state);
    }
    let mut reader = BufReader::new(input);
    loop {
        let line = match read_capped(&mut reader, MAX_LINE) {
            Ok(Some(Ok(line))) => line,
            Ok(Some(Err(TooLong))) => {
                let reply = rpc_error(Value::Null, -32600, "Request too large");
                if !relay.emit(&reply) {
                    return 1;
                }
                continue;
            }
            Ok(None) | Err(_) => break,
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if !relay.from_harness(&line) {
            return 1;
        }
    }
    let state = lock(&relay.state);
    if let Some(link) = &state.link {
        let _ = link.stream.shutdown(std::net::Shutdown::Both);
    }
    0
}

struct TooLong;

/// One line without its newline, or None at the end. A line over `max` is
/// read to its end and reported as too long.
fn read_capped(
    reader: &mut impl BufRead,
    max: usize,
) -> io::Result<Option<Result<Vec<u8>, TooLong>>> {
    let mut line = Vec::new();
    let read = reader
        .by_ref()
        .take(max as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(Some(Ok(line)));
    }
    if line.len() <= max {
        // The last line, with no newline.
        return Ok(Some(Ok(line)));
    }
    // Drop the rest of the line.
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        match buffer.iter().position(|b| *b == b'\n') {
            Some(at) => {
                reader.consume(at + 1);
                break;
            }
            None => {
                let len = buffer.len();
                reader.consume(len);
            }
        }
    }
    Ok(Some(Err(TooLong)))
}

impl Relay {
    /// Writes one line toward the harness. False when the harness is gone.
    fn emit(&self, value: &Value) -> bool {
        let mut line = value.to_string();
        line.push('\n');
        let mut out = lock(&self.out);
        out.write_all(line.as_bytes())
            .and_then(|_| out.flush())
            .is_ok()
    }

    fn from_harness(self: &Arc<Self>, line: &[u8]) -> bool {
        let Ok(message) = serde_json::from_slice::<Value>(line) else {
            let mut state = lock(&self.state);
            if let Some(link) = state.link.as_mut() {
                if write_raw(&mut link.stream, line) {
                    return true;
                }
                self.lost(&mut state);
            }
            return self.emit(&rpc_error(Value::Null, -32700, "Parse error"));
        };
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_string);
        let id = message.get("id").filter(|id| !id.is_null()).cloned();
        let mut state = lock(&self.state);
        if method.is_some() && id.is_some() && state.link.is_none() {
            self.dial(&mut state);
        }
        if method.as_deref() == Some("initialize") && id.is_some() {
            state.initialize = Some(message.clone());
        }
        if state.link.is_some() {
            if let (Some(method), Some(id)) = (&method, &id) {
                state
                    .pending
                    .insert(id.to_string(), (id.clone(), method.clone()));
            }
            if let Some(link) = state.link.as_mut() {
                if write_raw(&mut link.stream, line) {
                    return true;
                }
            }
            // The write failed: this request is pending, and `lost` answers it.
            self.lost(&mut state);
            return true;
        }
        drop(state);
        match (method, id) {
            (Some(method), Some(id)) => self.emit(&local_answer(&method, id, &message, OFF_TEXT)),
            // Notifications and stray responses have nowhere to go.
            _ => true,
        }
    }

    /// Dials MonoCode when there is a target and the last try was long
    /// enough ago. On success, replays the harness's `initialize`.
    fn dial(self: &Arc<Self>, state: &mut State) {
        let Some((address, token)) = &self.target else {
            return;
        };
        if state.last_dial.is_some_and(|at| at.elapsed() < self.retry) {
            return;
        }
        state.last_dial = Some(Instant::now());
        let Some((mut stream, reader)) = connect(*address, token) else {
            return;
        };
        state.serial += 1;
        let serial = state.serial;
        let replayed = match &state.initialize {
            Some(initialize) => {
                let mut replay = initialize.clone();
                replay["id"] = Value::String(format!("{REPLAY_ID}{serial}"));
                let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
                if !(write_value(&mut stream, &replay) && write_value(&mut stream, &initialized)) {
                    return;
                }
                true
            }
            None => false,
        };
        state.link = Some(Link { stream, serial });
        let relay = self.clone();
        thread::spawn(move || relay.from_monocode(reader, serial));
        if replayed {
            // The harness lists again and now sees the chat's tools.
            self.emit(&list_changed());
        }
    }

    /// MonoCode to the harness, a line at a time, until the connection ends.
    fn from_monocode(self: Arc<Self>, mut reader: BufReader<TcpStream>, serial: u64) {
        // A reply too large to pass on ends the connection.
        while let Ok(Some(Ok(line))) = read_capped(&mut reader, MAX_LINE) {
            let message = serde_json::from_slice::<Value>(&line).ok();
            let id = message
                .as_ref()
                .filter(|m| m.get("method").is_none())
                .and_then(|m| m.get("id"))
                .cloned();
            if let Some(id) = &id {
                if id.as_str().is_some_and(|id| id.starts_with(REPLAY_ID)) {
                    continue;
                }
                lock(&self.state).pending.remove(&id.to_string());
            }
            let mut out = lock(&self.out);
            let ok = out
                .write_all(&line)
                .and_then(|_| out.write_all(b"\n"))
                .and_then(|_| out.flush())
                .is_ok();
            if !ok {
                return;
            }
        }
        let mut state = lock(&self.state);
        if state
            .link
            .as_ref()
            .is_some_and(|link| link.serial == serial)
        {
            self.lost(&mut state);
        }
    }

    /// The connection ended: every request in flight gets an answer, and the
    /// harness hears that the tool list changed.
    fn lost(&self, state: &mut State) {
        if let Some(link) = state.link.take() {
            let _ = link.stream.shutdown(std::net::Shutdown::Both);
        }
        let mut pending: Vec<(Value, String)> = state.pending.drain().map(|(_, v)| v).collect();
        pending.sort_by_key(|(id, _)| id.to_string());
        for (id, method) in pending {
            self.emit(&local_answer(&method, id, &Value::Null, STOPPED_TEXT));
        }
        if state.initialize.is_some() {
            self.emit(&list_changed());
        }
    }
}

/// A loopback HTTP proxy from the environment: the one a sandbox gives its
/// child (srt sets `HTTPS_PROXY` and kin to `http://<user>:<token>@localhost:
/// <port>`, `dist/sandbox/sandbox-utils.js:667-760` at 0.0.81).
#[derive(Debug, PartialEq, Eq)]
pub struct Proxy {
    pub addrs: Vec<SocketAddr>,
    /// `user:password`, decoded, for `Proxy-Authorization: Basic`.
    pub auth: Option<String>,
}

/// The first of `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`,
/// `ALL_PROXY`, `all_proxy` that is set, if it is a plain `http://` URL on
/// loopback; anything else is not used (a remote proxy would carry the chat
/// token off the machine).
pub fn loopback_proxy(env: &dyn Fn(&str) -> Option<String>) -> Option<Proxy> {
    let raw = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .find_map(|n| env(n).filter(|v| !v.trim().is_empty()))?;
    let rest = raw.trim().strip_prefix("http://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return None;
    }
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(percent_decode(a)?), h),
        None => (None, rest),
    };
    let (host, port) = if let Some(p) = hostport.strip_prefix("[::1]:") {
        ("[::1]", p)
    } else {
        hostport.rsplit_once(':')?
    };
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    let v4 = SocketAddr::from(([127, 0, 0, 1], port));
    let v6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
    let addrs = match host {
        "localhost" => vec![v4, v6],
        "127.0.0.1" => vec![v4],
        "[::1]" => vec![v6],
        _ => return None,
    };
    Some(Proxy { addrs, auth })
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Opens a tunnel to `target` through `proxy` with HTTP CONNECT and returns
/// the stream once the proxy answered 200. The response head is read a byte
/// at a time, so nothing of the tunnel is read past it.
pub fn through_proxy(proxy: &Proxy, target: SocketAddr) -> std::io::Result<TcpStream> {
    use base64::Engine as _;
    let mut last = std::io::Error::other("no proxy address");
    for addr in &proxy.addrs {
        let mut stream = match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(s) => s,
            Err(e) => {
                last = e;
                continue;
            }
        };
        stream.set_read_timeout(Some(HELLO_TIMEOUT))?;
        stream.set_write_timeout(Some(HELLO_TIMEOUT))?;
        let authority = target.to_string();
        let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(a) = &proxy.auth {
            let b64 = base64::engine::general_purpose::STANDARD.encode(a.as_bytes());
            head.push_str(&format!("Proxy-Authorization: Basic {b64}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
        // One byte at a time, so nothing of the tunnel is read past the
        // answer, within one deadline for the whole head: a proxy that
        // drips a byte a second cannot hold the relay (review FP3-S1).
        let deadline = std::time::Instant::now() + HELLO_TIMEOUT;
        let mut got = Vec::new();
        let mut byte = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(std::io::Error::other("the proxy did not answer in time"));
            }
            stream.set_read_timeout(Some(left))?;
            if got.len() >= 8 * 1024 || stream.read(&mut byte)? == 0 {
                return Err(std::io::Error::other("the proxy did not answer"));
            }
            got.push(byte[0]);
        }
        stream.set_read_timeout(Some(HELLO_TIMEOUT))?;
        let status = String::from_utf8_lossy(&got);
        let first = status.lines().next().unwrap_or("");
        let mut parts = first.split_whitespace();
        let ok =
            parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) && parts.next() == Some("200");
        if !ok {
            let shown: String = first
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .take(80)
                .collect();
            return Err(std::io::Error::other(format!(
                "the proxy refused the tunnel: {shown}"
            )));
        }
        return Ok(stream);
    }
    Err(last)
}

/// The bridge's address, dialled directly, or, when the sandbox itself
/// refused that, through a loopback proxy the environment names (Mac test
/// w5 retest 3, MW5-22): inside srt a direct loopback connect fails
/// (macOS: Seatbelt admits only the proxy's ports; Linux: the sandbox's own
/// network), and srt's proxy admits the bridge's port, which `derm run`
/// lists for it. A dial that failed for any other reason (the daemon gone
/// or restarting, a stale `cu.endpoint`, a slow host) never tries a proxy:
/// a project's settings can name one, and the chat token goes first on the
/// connection (review FP3-S1).
fn dial(address: SocketAddr) -> Option<TcpStream> {
    let refused = match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
        Ok(s) => return Some(s),
        Err(e) => e,
    };
    if !sandbox_refused(&refused, &|p| std::fs::read_to_string(p).ok()) {
        return None;
    }
    let proxy = loopback_proxy(&|n| std::env::var(n).ok())?;
    match through_proxy(&proxy, address) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("derm-daemon cu-mcp: {e}");
            None
        }
    }
}

/// Whether a failed loopback dial was the sandbox's doing, by what the
/// sandbox makes true and an environment variable cannot: on macOS Seatbelt
/// answers a denied connect with EPERM, where a closed port answers
/// ECONNREFUSED; on Linux srt runs the chat in its own network namespace,
/// whose only interface is `lo` (run under srt 0.0.81 with bubblewrap: the
/// host lists its others).
fn sandbox_refused(err: &std::io::Error, read: &dyn Fn(&str) -> Option<String>) -> bool {
    if cfg!(target_os = "macos") {
        err.kind() == std::io::ErrorKind::PermissionDenied
    } else if cfg!(target_os = "linux") {
        read("/proc/self/net/dev").is_some_and(|d| only_loopback(&d))
    } else {
        false
    }
}

/// `/proc/net/dev`'s interfaces are `lo` alone.
fn only_loopback(dev: &str) -> bool {
    let names: Vec<&str> = dev
        .lines()
        .skip(2)
        .filter_map(|l| l.split_once(':').map(|(n, _)| n.trim()))
        .collect();
    !names.is_empty() && names.iter().all(|n| *n == "lo")
}

/// Connects, sends the token and reads MonoCode's answer.
fn connect(address: SocketAddr, token: &str) -> Option<(TcpStream, BufReader<TcpStream>)> {
    let mut stream = dial(address)?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    if !write_value(&mut stream, &json!({"token": token})) {
        return None;
    }
    stream.set_read_timeout(Some(HELLO_TIMEOUT)).ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut first = String::new();
    reader.by_ref().take(4096).read_line(&mut first).ok()?;
    let answer: Value = serde_json::from_str(&first).ok()?;
    if answer.get("monocode").and_then(Value::as_str) != Some("ok") {
        return None;
    }
    stream.set_read_timeout(None).ok()?;
    Some((stream, reader))
}

fn write_raw(stream: &mut TcpStream, line: &[u8]) -> bool {
    stream
        .write_all(line)
        .and_then(|_| stream.write_all(b"\n"))
        .and_then(|_| stream.flush())
        .is_ok()
}

fn write_value(stream: &mut TcpStream, value: &Value) -> bool {
    write_raw(stream, value.to_string().as_bytes())
}

fn list_changed() -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// The relay's own answer while it has no connection to MonoCode.
fn local_answer(method: &str, id: Value, request: &Value, text: &str) -> Value {
    let result = match method {
        "initialize" => {
            let version = request
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .filter(|v| v.len() <= 32)
                .unwrap_or("2025-06-18");
            json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": true } },
                "serverInfo": { "name": "derm-computer-use", "version": env!("CARGO_PKG_VERSION") }
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({ "tools": [] }),
        "tools/call" => json!({"content": [{"type": "text", "text": text}], "isError": true}),
        _ => return rpc_error(id, -32601, "Method not found"),
    };
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review FP3-S1: outside a sandbox, when the bridge's port does not
    /// answer (a stale `cu.endpoint`, the daemon restarting), the relay must
    /// not hand its chat token to a loopback proxy the environment names,
    /// which a project's settings can set.
    #[test]
    fn a_refused_dial_outside_a_sandbox_sends_nothing_to_an_env_proxy() {
        use std::net::TcpListener;
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = closed.local_addr().unwrap();
        drop(closed);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{port}"));
        let token = "ab".repeat(32);
        let got = connect(target, &token);
        std::env::remove_var("HTTPS_PROXY");
        assert!(got.is_none());
        assert!(
            listener.accept().is_err(),
            "the relay connected to the env proxy outside a sandbox"
        );
    }

    #[test]
    fn only_a_sandboxs_own_refusal_lets_the_relay_try_a_proxy() {
        let dev_host = "Inter-|   Receive\n face |bytes\n    lo: 0 0\n  eth0: 1 2\n";
        let dev_srt = "Inter-|   Receive\n face |bytes\n    lo: 0 0\n";
        assert!(!only_loopback(dev_host));
        assert!(only_loopback(dev_srt));
        assert!(!only_loopback(""));
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let host = |_: &str| Some(dev_host.to_string());
        let srt = |_: &str| Some(dev_srt.to_string());
        if cfg!(target_os = "linux") {
            assert!(!sandbox_refused(&refused, &host));
            assert!(sandbox_refused(&refused, &srt));
            assert!(!sandbox_refused(&refused, &|_| None));
        }
        if cfg!(target_os = "macos") {
            assert!(!sandbox_refused(&refused, &srt));
            assert!(sandbox_refused(&denied, &host));
        }
    }

    /// Review FP3-S1: the answer's head has one deadline, not one a byte.
    #[test]
    fn a_proxy_that_drips_its_answer_is_given_up_on_in_time() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            for b in b"HTTP/1.1 200 Connection established" {
                if s.write_all(&[*b]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
        let proxy = Proxy {
            addrs: vec![addr],
            auth: None,
        };
        let t0 = std::time::Instant::now();
        let r = through_proxy(&proxy, "127.0.0.1:9".parse().unwrap());
        assert!(r.is_err());
        assert!(
            t0.elapsed() < HELLO_TIMEOUT + Duration::from_secs(2),
            "{:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn only_a_plain_loopback_http_proxy_is_used() {
        let env = |v: &'static str| move |n: &str| (n == "HTTPS_PROXY").then(|| v.to_string());
        let p = loopback_proxy(&env("http://srt%2Bx:abc@localhost:41234")).unwrap();
        assert_eq!(p.auth.as_deref(), Some("srt+x:abc"));
        assert_eq!(p.addrs.len(), 2);
        assert_eq!(p.addrs[0], "127.0.0.1:41234".parse().unwrap());
        assert_eq!(
            loopback_proxy(&env("http://127.0.0.1:9/")).unwrap().addrs,
            vec!["127.0.0.1:9".parse().unwrap()]
        );
        assert_eq!(
            loopback_proxy(&env("http://[::1]:9")).unwrap().addrs,
            vec!["[::1]:9".parse().unwrap()]
        );
        for bad in [
            "https://localhost:9",
            "http://proxy.example.com:3128",
            "http://10.0.0.1:3128",
            "socks5h://localhost:9",
            "http://localhost",
            "http://localhost:0",
            "http://localhost:9/path",
            "http://localhost:99999",
            "http://localhost.evil:9",
        ] {
            assert_eq!(loopback_proxy(&env(bad)), None, "{bad}");
        }
        assert_eq!(loopback_proxy(&|_: &str| None), None);
    }

    #[test]
    fn the_relay_tunnels_to_the_bridge_through_a_proxy_that_answers_200() {
        use std::net::TcpListener;
        // A stand-in proxy: reads the CONNECT head, checks it, answers, then
        // acts as the bridge on the tunnel.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut b).unwrap();
                head.push(b[0]);
            }
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut first = String::new();
            r.read_line(&mut first).unwrap();
            s.write_all(b"{\"monocode\":\"ok\"}\n").unwrap();
            (String::from_utf8(head).unwrap(), first)
        });
        let proxy = Proxy {
            addrs: vec![SocketAddr::from(([127, 0, 0, 1], port))],
            auth: Some("u:t0k".into()),
        };
        let target: SocketAddr = "127.0.0.1:53276".parse().unwrap();
        let mut stream = through_proxy(&proxy, target).unwrap();
        assert!(write_value(&mut stream, &json!({"token": "x"})));
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut answer = String::new();
        reader.read_line(&mut answer).unwrap();
        assert!(answer.contains("monocode"), "{answer}");
        let (head, first) = seen.join().unwrap();
        assert!(
            head.starts_with("CONNECT 127.0.0.1:53276 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains("Host: 127.0.0.1:53276\r\n"), "{head}");
        // base64("u:t0k")
        assert!(
            head.contains("Proxy-Authorization: Basic dTp0MGs=\r\n"),
            "{head}"
        );
        assert_eq!(first.trim(), r#"{"token":"x"}"#);
    }

    #[test]
    fn a_proxy_that_refuses_the_tunnel_gives_no_stream() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read(&mut b).unwrap_or(0) == 0 {
                    return;
                }
                head.push(b[0]);
            }
            let _ = s.write_all(
                b"HTTP/1.1 403 Forbidden\r\nX-Proxy-Error: blocked-by-allowlist\r\n\r\n",
            );
        });
        let proxy = Proxy {
            addrs: vec![SocketAddr::from(([127, 0, 0, 1], port))],
            auth: None,
        };
        let err = through_proxy(&proxy, "127.0.0.1:9".parse().unwrap()).unwrap_err();
        assert!(err.to_string().contains("403"), "{err}");
    }

    #[test]
    fn takes_only_a_loopback_endpoint() {
        assert!(endpoint(Some("127.0.0.1:4000")).is_ok());
        assert!(endpoint(Some("[::1]:4000")).is_ok());
        assert!(endpoint(None).unwrap_err().contains("not on for this chat"));
        assert!(endpoint(Some("10.0.0.2:4000")).is_err());
        assert!(endpoint(Some("localhost:4000")).is_err(), "no name lookup");
        assert!(endpoint(Some("")).is_err());
    }

    use serde_json::{json, Value};
    use std::net::{Shutdown, TcpListener};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Mutex};

    /// The relay on two pipes: what the harness writes, and its lines back.
    struct Harness {
        stdin: Option<io::PipeWriter>,
        lines: Receiver<Value>,
        done: thread::JoinHandle<i32>,
    }

    impl Harness {
        fn start(endpoint: Option<String>, token: Option<&str>) -> Self {
            let (stdin_read, stdin) = io::pipe().unwrap();
            let (stdout_read, stdout) = io::pipe().unwrap();
            let token = token.map(str::to_string);
            let done = thread::spawn(move || {
                serve_stdio(
                    endpoint.as_deref(),
                    token.as_deref(),
                    Duration::from_millis(50),
                    stdin_read,
                    stdout,
                )
            });
            let (tx, lines) = mpsc::channel();
            thread::spawn(move || {
                for line in BufReader::new(stdout_read).lines() {
                    let Ok(line) = line else { break };
                    let _ = tx.send(serde_json::from_str(&line).unwrap());
                }
            });
            Self {
                stdin: Some(stdin),
                lines,
                done,
            }
        }
        fn send(&mut self, message: Value) {
            writeln!(self.stdin.as_mut().unwrap(), "{message}").unwrap();
        }
        fn next(&self) -> Value {
            self.lines
                .recv_timeout(Duration::from_secs(10))
                .expect("a line from the relay")
        }
        fn close(mut self) -> i32 {
            self.stdin.take();
            self.done.join().unwrap()
        }
    }

    fn initialize(id: i64) -> Value {
        json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}})
    }

    /// A MonoCode stand-in: refuses or takes the token as `accept` says,
    /// logs each line, answers every request but a call to `hang`.
    struct FakeMonoCode {
        address: String,
        accept: Arc<AtomicBool>,
        log: Arc<Mutex<Vec<Value>>>,
        live: Arc<Mutex<Vec<TcpStream>>>,
    }

    impl FakeMonoCode {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let accept = Arc::new(AtomicBool::new(false));
            let log: Arc<Mutex<Vec<Value>>> = Arc::default();
            let live: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
            let (a, l, v) = (accept.clone(), log.clone(), live.clone());
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut hello = String::new();
                    if reader.read_line(&mut hello).is_err() {
                        continue;
                    }
                    if !a.load(Ordering::SeqCst) {
                        let _ =
                            writeln!(stream, "{}", json!({"monocode":"refused","message":"no"}));
                        continue;
                    }
                    let _ = writeln!(stream, "{}", json!({"monocode":"ok"}));
                    v.lock().unwrap().push(stream.try_clone().unwrap());
                    let l = l.clone();
                    thread::spawn(move || {
                        for line in reader.lines() {
                            let Ok(line) = line else { break };
                            let message: Value = serde_json::from_str(&line).unwrap();
                            l.lock().unwrap().push(message.clone());
                            let (Some(id), Some(method)) =
                                (message.get("id"), message["method"].as_str())
                            else {
                                continue;
                            };
                            if message["params"]["name"] == "hang" {
                                continue;
                            }
                            let reply = json!({"jsonrpc":"2.0","id":id,"result":{"echo":method}});
                            if writeln!(stream, "{reply}").is_err() {
                                break;
                            }
                        }
                    });
                }
            });
            Self {
                address,
                accept,
                log,
                live,
            }
        }
        fn logged(&self) -> Vec<Value> {
            self.log.lock().unwrap().clone()
        }
        fn drop_connections(&self) {
            for stream in self.live.lock().unwrap().drain(..) {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }

    fn wait_for(what: impl Fn() -> bool) {
        for _ in 0..500 {
            if what() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out");
    }

    #[test]
    fn without_an_endpoint_the_relay_answers_as_an_empty_server_until_stdin_closes() {
        // 4.12: Claude Code does not restart a stdio server that exits.
        let mut harness = Harness::start(None, None);
        harness.send(initialize(1));
        let reply = harness.next();
        assert_eq!(reply["id"], 1);
        assert_eq!(reply["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(
            reply["result"]["capabilities"]["tools"]["listChanged"],
            true
        );
        assert!(reply["result"]["serverInfo"]["name"].is_string());
        harness.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        harness.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
        let reply = harness.next();
        assert_eq!(reply["id"], 2, "the notification got no answer");
        assert_eq!(reply["result"]["tools"], json!([]));
        harness.send(json!({"jsonrpc":"2.0","id":"c","method":"tools/call","params":{"name":"click","arguments":{}}}));
        let reply = harness.next();
        assert_eq!(reply["id"], "c");
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(reply["result"]["content"][0]["text"], OFF_TEXT);
        harness.send(json!({"jsonrpc":"2.0","id":4,"method":"resources/templates/list"}));
        assert_eq!(harness.next()["error"]["code"], -32601);
        assert_eq!(harness.close(), 0);
    }

    #[test]
    fn a_far_endpoint_is_never_dialled_and_the_relay_stays_up() {
        let mut harness = Harness::start(Some("10.0.0.2:4000".into()), Some("t"));
        harness.send(initialize(1));
        assert!(harness.next()["result"]["serverInfo"].is_object());
        assert_eq!(harness.close(), 0);
    }

    #[test]
    fn a_refused_relay_reconnects_replays_initialize_and_answers_calls_lost_in_a_drop() {
        // 4.7: after a Stop, or MonoCode refusing once, the chat keeps its server.
        let monocode = FakeMonoCode::start();
        let mut harness = Harness::start(Some(monocode.address.clone()), Some("tok"));
        harness.send(initialize(1));
        assert_eq!(
            harness.next()["result"]["capabilities"]["tools"]["listChanged"],
            true
        );
        harness
            .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"click"}}));
        assert_eq!(harness.next()["result"]["isError"], true);

        monocode.accept.store(true, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(120));
        harness.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}));
        assert_eq!(harness.next()["method"], "notifications/tools/list_changed");
        let reply = harness.next();
        assert_eq!(
            reply["id"], 3,
            "the relay's own initialize reply is not passed on"
        );
        assert_eq!(reply["result"]["echo"], "tools/list");
        let logged = monocode.logged();
        assert_eq!(logged[0]["method"], "initialize");
        assert_ne!(logged[0]["id"], 1, "replayed with the relay's own id");
        assert_eq!(logged[0]["params"]["protocolVersion"], "2025-06-18");
        assert_eq!(logged[1]["method"], "notifications/initialized");
        assert_eq!(logged[2]["id"], 3);

        harness
            .send(json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"hang"}}));
        wait_for(|| monocode.logged().len() == 4);
        monocode.drop_connections();
        let reply = harness.next();
        assert_eq!(
            reply["id"], 5,
            "a call in flight is answered, not left hanging"
        );
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(reply["result"]["content"][0]["text"], STOPPED_TEXT);
        assert_eq!(harness.next()["method"], "notifications/tools/list_changed");

        // And it comes back on the next request.
        thread::sleep(Duration::from_millis(120));
        harness.send(json!({"jsonrpc":"2.0","id":6,"method":"tools/list"}));
        assert_eq!(harness.next()["method"], "notifications/tools/list_changed");
        assert_eq!(harness.next()["id"], 6);
        assert_eq!(harness.close(), 0);
    }
}
