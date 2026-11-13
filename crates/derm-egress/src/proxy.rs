//! The proxy, one per brokered chat (`contracts/policy.md` section 8.3;
//! `contracts/events.md` section 6.3). It listens on loopback and takes:
//! - `CONNECT host:port`, the form every HTTPS client sends through a proxy:
//!   the tunnel must carry TLS; derm-egress reads the ClientHello first
//!   (rustls's `Acceptor`, so the server name is known before any
//!   certificate is chosen), refuses an SNI that is not the CONNECT host,
//!   then completes the handshake with a leaf its CA signs for the CONNECT
//!   host, and decides each HTTP/1.1 request in the tunnel with [`decide_with`]
//!   before it opens its own TLS connection upstream (the OS trust store, as
//!   derm-tap's client), ALPN `http/1.1` on both legs;
//! - an absolute-form `http://` request (plain HTTP through a proxy): decided
//!   with every secret treated as bound elsewhere, since a credential is never
//!   swapped in over plain text (srt's rule, `credential-sentinel.js`'s
//!   \"TLS-terminated path unless allowPlaintextInject\").
//!
//! A tunnel that does not start with a TLS handshake is refused (it could
//! carry anything), as is a request asking to upgrade the connection (its
//! frames could not be read). A destination that resolves to a loopback,
//! private, link-local or other non-public address is refused unless its host
//! and port were admitted (AZ-4: the tap's and the OTLP receiver's ports), and
//! the address checked is the address dialled.
//!
//! Each connection gives one `egress.connect` record; each swap one
//! `secret.inject`; each block of a placeholder or value one `secret.block`.
//! No record holds a header, a body or a value.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use derm_core::event::{Event, Source};
use rustls::pki_types::ServerName;
use serde_json::{json, Map, Value};

use crate::ca::Ca;
use crate::http::{self, Bad, Framing, Head};
use crate::{decide_with, normal_host, Blocked, Outbound, Policy, Secret, Verdict};

/// Where records go: the daemon's `ingest`, as the tap's sink.
pub type Sink = Arc<dyn Fn(Vec<Event>) + Send + Sync>;
/// How a host is resolved (the OS's resolver by default; tests point names at
/// a local server).
pub type Resolve = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// Connections open at once; more are closed at accept.
pub const MAX_CONNECTIONS: usize = 256;
const CLIENT_IDLE: Duration = Duration::from_secs(120);
const UPSTREAM_CONNECT: Duration = Duration::from_secs(10);
/// Model replies stream for minutes; a quiet upstream is cut after this.
const UPSTREAM_IDLE: Duration = Duration::from_secs(600);
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "upgrade",
    "expect",
    "transfer-encoding",
];

/// One chat's proxy.
pub struct Config {
    pub chat: String,
    pub harness: String,
    pub secrets: Vec<Secret>,
    pub policy: Policy,
    pub ca: Arc<Ca>,
    pub sink: Sink,
    /// Non-public destinations admitted, by host and port (AZ-4).
    pub allow_local: Vec<(String, u16)>,
    /// The upstream leg's TLS (the OS trust store by default).
    pub upstream_tls: Arc<rustls::ClientConfig>,
    pub resolve: Resolve,
    /// Where to listen (`127.0.0.1:0` by default).
    pub bind: SocketAddr,
}

impl Config {
    /// A chat's proxy with the OS trust store upstream and the OS resolver.
    pub fn new(
        chat: &str,
        harness: &str,
        secrets: Vec<Secret>,
        ca: Arc<Ca>,
        sink: Sink,
    ) -> Result<Config, String> {
        use rustls_platform_verifier::BuilderVerifierExt;
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_platform_verifier()
        .map_err(|e| format!("the OS trust store: {e}"))?
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Config {
            chat: chat.to_string(),
            harness: harness.to_string(),
            secrets,
            policy: Policy::default(),
            ca,
            sink,
            allow_local: Vec::new(),
            upstream_tls: Arc::new(tls),
            resolve: Arc::new(|h, p| (h, p).to_socket_addrs().map(Iterator::collect)),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        })
    }
}

/// A running proxy. Dropping it stops it.
pub struct Egress {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Egress {
    pub fn start(config: Config) -> Result<Egress, String> {
        let listener = TcpListener::bind(config.bind).map_err(|e| format!("egress listen: {e}"))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            config,
            open: AtomicUsize::new(0),
            servers: Mutex::new(HashMap::new()),
        });
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("derm-egress".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    if flag.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(conn) = conn else { continue };
                    if shared.open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                        shared.open.fetch_sub(1, Ordering::SeqCst);
                        let _ = conn.shutdown(Shutdown::Both);
                        continue;
                    }
                    let s = shared.clone();
                    let spawned = std::thread::Builder::new()
                        .name("derm-egress-conn".into())
                        .spawn(move || {
                            s.serve(conn);
                            s.open.fetch_sub(1, Ordering::SeqCst);
                        });
                    if spawned.is_err() {
                        shared.open.fetch_sub(1, Ordering::SeqCst);
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Egress {
            addr,
            stop,
            thread: Some(thread),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The proxy URL a client is given (`HTTPS_PROXY`, srt's `parentProxy`).
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Egress {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.halt();
        }
    }
}

struct Shared {
    config: Config,
    open: AtomicUsize,
    servers: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

/// What one connection did, for its `egress.connect`.
#[derive(Default)]
struct Tally {
    host: String,
    port: u16,
    sni: Option<String>,
    tls: bool,
    requests: u64,
    up: u64,
    down: u64,
    blocked: Option<String>,
    placeholder_to_model: bool,
}

/// A client side that reads through its buffer and writes to the socket.
struct Duplex {
    r: BufReader<TcpStream>,
    w: TcpStream,
}

impl Read for Duplex {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.r.read(b)
    }
}

impl Write for Duplex {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.w.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// Counts what passes through a writer.
struct Counted<'a, W: Write> {
    w: &'a mut W,
    n: u64,
}

impl<W: Write> Write for Counted<'_, W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let k = self.w.write(b)?;
        self.n += k as u64;
        Ok(k)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn event_id() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("egress-{hex}")
}

/// Whether an address is not on the public internet (loopback, private,
/// shared, link-local, unspecified, multicast, broadcast, documentation).
pub fn non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return non_public(IpAddr::V4(m));
            }
            let s = v.segments();
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x64 && s[1] == 0xff9b)
        }
    }
}

/// `host:port` or `[v6]:port`, the port required (CONNECT's authority-form).
fn split_authority(a: &str) -> Option<(String, u16)> {
    let (h, p) = if let Some(rest) = a.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        (h, tail.strip_prefix(':')?)
    } else {
        let (h, p) = a.rsplit_once(':')?;
        if h.contains(':') {
            return None;
        }
        (h, p)
    };
    let port: u16 = p.parse().ok().filter(|p| *p != 0)?;
    (!h.is_empty()).then(|| (normal_host(h), port))
}

impl Shared {
    fn emit(&self, kind: &str, summary: String, detail: Value) {
        let c = &self.config;
        (c.sink)(vec![Event {
            id: event_id(),
            at: now_ms(),
            chat_id: c.chat.clone(),
            harness: c.harness.clone(),
            source: Source::Derm,
            kind: kind.into(),
            summary,
            detail,
            pid: None,
            approval_id: None,
        }]);
    }

    fn connect_record(&self, t: &Tally) {
        let mut d = Map::new();
        d.insert("connectHost".into(), json!(t.host));
        d.insert("port".into(), json!(t.port));
        d.insert("sni".into(), json!(t.sni));
        d.insert(
            "sniMatched".into(),
            json!(t.sni.as_ref().map(|s| normal_host(s) == t.host)),
        );
        d.insert("tls".into(), json!(t.tls));
        d.insert("requests".into(), json!(t.requests));
        d.insert("bytesUp".into(), json!(t.up));
        d.insert("bytesDown".into(), json!(t.down));
        let verdict = if t.blocked.is_some() {
            "blocked"
        } else {
            "forwarded"
        };
        d.insert("verdict".into(), json!(verdict));
        if let Some(r) = &t.blocked {
            d.insert("reason".into(), json!(r));
        }
        if t.placeholder_to_model {
            d.insert("placeholderToModel".into(), json!(true));
        }
        self.emit(
            "egress.connect",
            format!("{} {}:{}", verdict, t.host, t.port),
            Value::Object(d),
        );
    }

    fn block_records(&self, t: &mut Tally, why: &Blocked) {
        t.blocked = Some(why.reason());
        if let Blocked::Secret { id, place, value } = why {
            self.emit(
                "secret.block",
                format!("{id} toward {}", t.host),
                json!({"id": id, "host": t.host, "place": place.as_str(), "form": if *value { "value" } else { "placeholder" }}),
            );
        }
    }

    fn serve(&self, conn: TcpStream) {
        let _ = conn.set_read_timeout(Some(CLIENT_IDLE));
        let _ = conn.set_write_timeout(Some(CLIENT_IDLE));
        let Ok(w) = conn.try_clone() else { return };
        let mut r = BufReader::new(conn);
        let head = match http::read_head(&mut r) {
            Ok(Some(h)) => h,
            Ok(None) => return,
            Err(Bad::Refuse(code, why)) => {
                let _ = (&w).write_all(&http::status_page(code, "Bad Request", why));
                return;
            }
            Err(Bad::Io(_)) => return,
        };
        let mut t = Tally::default();
        if head.line[0].eq_ignore_ascii_case("CONNECT") {
            match split_authority(&head.line[1]) {
                Some((h, p)) => {
                    t.host = h;
                    t.port = p;
                }
                None => {
                    let _ = (&w).write_all(&http::status_page(
                        400,
                        "Bad Request",
                        "CONNECT needs host:port",
                    ));
                    return;
                }
            }
            self.tunnel(Duplex { r, w }, &mut t);
        } else {
            self.plain(r, w, head, &mut t);
        }
        if !t.host.is_empty() {
            self.connect_record(&t);
        }
    }

    /// Host-level checks before any byte goes upstream: SNI, the host name
    /// itself, the allow list.
    fn host_check(&self, t: &Tally, secrets: &[Secret]) -> Option<Blocked> {
        decide_with(
            &Outbound {
                connect_host: &t.host,
                sni: t.sni.as_deref(),
                target: "",
                headers: &[],
                body: b"",
            },
            secrets,
            &self.config.policy,
        )
        .blocked
    }

    fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, String> {
        if let Some(c) = self.servers.lock().map_err(|_| "lock")?.get(host) {
            return Ok(c.clone());
        }
        let key = self.config.ca.leaf(host)?;
        let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(key)));
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        let c = Arc::new(c);
        let mut m = self.servers.lock().map_err(|_| "lock")?;
        if m.len() > 1024 {
            m.clear();
        }
        m.insert(host.to_string(), c.clone());
        Ok(c)
    }

    fn tunnel(&self, mut client: Duplex, t: &mut Tally) {
        if client
            .w
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
        // The first byte of a TLS record is 0x16 (a handshake).
        match client.r.fill_buf() {
            Ok(b) if b.first() == Some(&0x16) => {}
            Ok([]) => return,
            _ => {
                t.blocked = Some("the tunnel does not carry TLS".into());
                return;
            }
        }
        t.tls = true;
        let mut acceptor = rustls::server::Acceptor::default();
        let accepted = loop {
            match acceptor.read_tls(&mut client) {
                Ok(0) => return,
                Ok(_) => {}
                Err(_) => return,
            }
            match acceptor.accept() {
                Ok(Some(a)) => break a,
                Ok(None) => continue,
                Err((_, mut alert)) => {
                    let _ = alert.write_all(&mut client);
                    t.blocked = Some("the tunnel does not start with a TLS ClientHello".into());
                    return;
                }
            }
        };
        t.sni = accepted.client_hello().server_name().map(str::to_string);
        if let Some(b) = self.host_check(t, &self.config.secrets) {
            self.block_records(t, &b);
            return;
        }
        let server = match self.server_config(&t.host) {
            Ok(s) => s,
            Err(e) => {
                t.blocked = Some(format!("no leaf for the host: {e}"));
                return;
            }
        };
        let conn = match accepted.into_connection(server) {
            Ok(c) => c,
            Err((_, mut alert)) => {
                let _ = alert.write_all(&mut client);
                return;
            }
        };
        let mut tls = BufReader::new(rustls::StreamOwned::new(conn, client));
        loop {
            let head = match http::read_head(&mut tls) {
                Ok(Some(h)) => h,
                Ok(None) | Err(Bad::Io(_)) => return,
                Err(Bad::Refuse(code, why)) => {
                    let _ = tls
                        .get_mut()
                        .write_all(&http::status_page(code, "Bad Request", why));
                    t.blocked = Some(why.into());
                    return;
                }
            };
            t.requests += 1;
            let keep = self.request(&mut tls, head, t, true);
            if !keep {
                let _ = tls.get_mut().flush();
                tls.get_mut().conn.send_close_notify();
                let _ = tls.get_mut().flush();
                return;
            }
        }
    }

    fn plain(&self, r: BufReader<TcpStream>, w: TcpStream, head: Head, t: &mut Tally) {
        let Some(h) = crate::target_host(&head.line[1]) else {
            let _ = (&w).write_all(&http::status_page(
                400,
                "Bad Request",
                "a proxy request needs an http:// URL",
            ));
            return;
        };
        if !head.line[1].to_ascii_lowercase().starts_with("http://") {
            let _ = (&w).write_all(&http::status_page(
                400,
                "Bad Request",
                "only http:// is proxied in the clear",
            ));
            return;
        }
        t.host = h;
        let rest = &head.line[1][7..];
        let auth = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
        t.port = split_authority(auth).map_or(80, |(_, p)| p);
        t.requests = 1;
        let mut client = BufReader::new(Duplex { r, w });
        self.request(&mut client, head, t, false);
    }

    /// One request: read its body, decide, forward, relay the response.
    /// Returns whether the client connection stays open for another.
    fn request<S: Read + Write>(
        &self,
        client: &mut BufReader<S>,
        mut head: Head,
        t: &mut Tally,
        tls: bool,
    ) -> bool {
        let method = head.line[0].clone();
        let refuse = |client: &mut BufReader<S>, t: &mut Tally, code: u16, why: &str| {
            let _ = client
                .get_mut()
                .write_all(&http::status_page(code, "Forbidden", why));
            t.blocked = Some(why.to_string());
            false
        };
        if method.eq_ignore_ascii_case("CONNECT") {
            return refuse(client, t, 405, "CONNECT inside a tunnel");
        }
        let upgrade = head.get("upgrade").is_some()
            || head.all("connection").any(|v| {
                v.split(',')
                    .any(|x| x.trim().eq_ignore_ascii_case("upgrade"))
            });
        if upgrade {
            return refuse(client, t, 501, "an upgraded connection cannot be inspected");
        }
        let framing = match http::request_framing(&head) {
            Ok(f) => f,
            Err(Bad::Refuse(code, why)) => return refuse(client, t, code, why),
            Err(Bad::Io(_)) => return false,
        };
        if head
            .all("expect")
            .any(|v| v.eq_ignore_ascii_case("100-continue"))
            && framing != Framing::None
        {
            let _ = client.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            let _ = client.get_mut().flush();
        }
        let body = match http::read_body(client, framing) {
            Ok(b) => b,
            Err(Bad::Refuse(code, why)) => return refuse(client, t, code, why),
            Err(Bad::Io(_)) => return false,
        };
        let close_asked = head
            .all("connection")
            .any(|v| v.split(',').any(|x| x.trim().eq_ignore_ascii_case("close")));
        // Over plain HTTP no secret is swapped in: every secret counts as
        // bound elsewhere, so its placeholder or value there blocks.
        let plain_secrets: Vec<Secret>;
        let secrets: &[Secret] = if tls {
            &self.config.secrets
        } else {
            plain_secrets = self
                .config
                .secrets
                .iter()
                .map(|s| Secret {
                    hosts: Vec::new(),
                    ..s.clone()
                })
                .collect();
            &plain_secrets
        };
        let d = decide_with(
            &Outbound {
                connect_host: &t.host,
                sni: t.sni.as_deref(),
                target: &head.line[1],
                headers: &head.headers,
                body: &body,
            },
            secrets,
            &self.config.policy,
        );
        t.placeholder_to_model |= d.placeholder_to_model;
        let (headers, body) = match d.verdict {
            Verdict::Block { reason } => {
                if let Some(b) = &d.blocked {
                    self.block_records(t, b);
                }
                let _ = client
                    .get_mut()
                    .write_all(&http::status_page(403, "Forbidden", &reason));
                return false;
            }
            Verdict::Forward { headers, body } => (headers, body),
        };
        for id in &d.injected {
            self.emit(
                "secret.inject",
                format!("{id} into {}", t.host),
                json!({"id": id, "host": t.host}),
            );
        }
        head.headers = headers;
        for h in HOP_BY_HOP {
            head.remove(h);
        }
        if framing != Framing::None || !body.is_empty() {
            head.set("content-length", &body.len().to_string());
        } else {
            head.remove("content-length");
        }
        head.set("connection", "close");
        if !tls {
            // Origin-form upstream (RFC 9112 section 3.2.1).
            let rest = &head.line[1][7..];
            let path = rest.find(['/', '?']).map_or("/", |i| &rest[i..]);
            head.line[1] = if path.starts_with('?') {
                format!("/{path}")
            } else {
                path.to_string()
            };
        }
        head.line[2] = "HTTP/1.1".into();
        match self.forward(client, &head, &body, t, tls, &method) {
            Ok(framed) => framed && !close_asked,
            Err(e) => {
                if t.down == 0 {
                    let _ = client
                        .get_mut()
                        .write_all(&http::status_page(502, "Bad Gateway", &e));
                }
                false
            }
        }
    }

    fn dial(&self, t: &Tally) -> Result<TcpStream, String> {
        let addrs = (self.config.resolve)(&t.host, t.port)
            .map_err(|e| format!("cannot resolve {}: {e}", t.host))?;
        let admitted = self
            .config
            .allow_local
            .iter()
            .any(|(h, p)| normal_host(h) == t.host && *p == t.port);
        let mut last = format!("{} has no address", t.host);
        for a in addrs {
            if non_public(a.ip()) && !admitted {
                last = format!("{} resolves to a non-public address", t.host);
                continue;
            }
            match TcpStream::connect_timeout(&a, UPSTREAM_CONNECT) {
                Ok(s) => {
                    let _ = s.set_read_timeout(Some(UPSTREAM_IDLE));
                    let _ = s.set_write_timeout(Some(UPSTREAM_IDLE));
                    return Ok(s);
                }
                Err(e) => last = format!("{a}: {e}"),
            }
        }
        Err(last)
    }

    /// Send one request upstream and relay its response. Returns whether the
    /// response's end was found by its framing (so the client may send
    /// another).
    fn forward<S: Read + Write>(
        &self,
        client: &mut BufReader<S>,
        head: &Head,
        body: &[u8],
        t: &mut Tally,
        tls: bool,
        method: &str,
    ) -> Result<bool, String> {
        let tcp = self.dial(t).inspect_err(|e| t.blocked = Some(e.clone()))?;
        if tls {
            let name = ServerName::try_from(t.host.clone()).map_err(|e| e.to_string())?;
            let conn = rustls::ClientConnection::new(self.config.upstream_tls.clone(), name)
                .map_err(|e| e.to_string())?;
            let mut up = BufReader::new(rustls::StreamOwned::new(conn, tcp));
            self.exchange(client, &mut up, head, body, t, method)
        } else {
            let mut up = BufReader::new(tcp);
            self.exchange(client, &mut up, head, body, t, method)
        }
    }

    fn exchange<S: Read + Write, U: Read + Write>(
        &self,
        client: &mut BufReader<S>,
        up: &mut BufReader<U>,
        head: &Head,
        body: &[u8],
        t: &mut Tally,
        method: &str,
    ) -> Result<bool, String> {
        let mut out = head.to_bytes();
        out.extend_from_slice(body);
        up.get_mut()
            .write_all(&out)
            .map_err(|e| format!("upstream: {e}"))?;
        up.get_mut().flush().map_err(|e| format!("upstream: {e}"))?;
        t.up += out.len() as u64;
        loop {
            let mut resp = match http::read_head(up) {
                Ok(Some(h)) => h,
                Ok(None) => return Err("upstream closed before a response".into()),
                Err(Bad::Refuse(_, why)) => return Err(format!("upstream: {why}")),
                Err(Bad::Io(e)) => return Err(format!("upstream: {e}")),
            };
            let status: u16 = resp.line[1].parse().unwrap_or(0);
            if status == 101 {
                return Err("upstream switched protocols".into());
            }
            let framing = http::response_framing(method, &resp)
                .map_err(|_| "upstream: bad framing".to_string())?;
            let interim = (100..200).contains(&status);
            if !interim {
                resp.remove("connection");
                resp.remove("keep-alive");
                resp.remove("proxy-connection");
                if framing == Framing::Close {
                    resp.set("connection", "close");
                }
            }
            let mut w = Counted {
                w: client.get_mut(),
                n: 0,
            };
            w.write_all(&resp.to_bytes()).map_err(|e| e.to_string())?;
            if interim {
                t.down += w.n;
                continue;
            }
            let r = http::relay_body(up, &mut w, framing);
            let _ = w.flush();
            t.down += w.n;
            r.map_err(|e| format!("upstream: {e}"))?;
            return Ok(framing != Framing::Close);
        }
    }
}

/// Serves one certified key whatever the ClientHello asks.
#[derive(Debug)]
struct Fixed(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_public_addresses_are_named() {
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(non_public(a.parse().unwrap()), "{a}");
        }
        for a in ["140.82.112.6", "2606:4700::1111", "::ffff:1.1.1.1"] {
            assert!(!non_public(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn connect_authorities_need_a_port() {
        assert_eq!(
            split_authority("API.github.com:443"),
            Some(("api.github.com".into(), 443))
        );
        assert_eq!(split_authority("[::1]:8080"), Some(("::1".into(), 8080)));
        assert_eq!(split_authority("api.github.com"), None);
        assert_eq!(split_authority("a:0"), None);
        assert_eq!(split_authority("::1:443"), None);
    }
}
