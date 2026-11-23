//! The login's way out. An agent account's group has no network but
//! loopback (lane L2's nftables table, plans/parallel_build_accounts.md
//! section 3), so a harness's own sign-in run as the account would fail. For
//! the sign-in only, derm opens a CONNECT tunnel on loopback that admits the
//! harness's sign-in hosts on 443 (`harness.rs`) and nothing else, and passes
//! the bytes through unread: it never terminates TLS, so the sign-in's codes
//! and tokens stay inside the harness's own TLS to the vendor (note CB 4.1:
//! derm may not collect, store or intermediate Claude.ai credentials; the
//! sign-in completes through Anthropic's own flow). derm-egress is not used
//! here because it terminates TLS to swap secrets (`derm-egress/src/proxy.rs`
//! module text).
//!
//! The harness takes the tunnel through `HTTPS_PROXY`: Claude Code 2.1.322
//! sent `CONNECT platform.claude.com:443` to it, and Codex 0.167.2 `CONNECT
//! auth.openai.com:443` (run, `plans/parallel/acct_L4.md`, Research).
//!
//! Where the person's own `https_proxy` (else `HTTPS_PROXY`) names an
//! `http://` proxy, the tunnel goes on through it with a CONNECT of its own,
//! as the harness would have run as the person; `no_proxy` (else `NO_PROXY`)
//! matches as curl matches it: a name is the host itself or a domain that
//! contains it, and `*` is every host
//! (https://curl.se/libcurl/c/CURLOPT_NOPROXY.html). A proxy URL with a user
//! name or password is refused: derm carries no credential of the person's.
//!
//! The tunnel takes only the sign-in it was opened for (plan step P10's I-3;
//! `research-notes/CC_project_scoped_agents.md` section 6): a credential is
//! minted per sign-in (`derm_egress::auth`), handed to the harness in its
//! proxy URL's user part through the environment only, and a client whose
//! CONNECT carries no `Proxy-Authorization` with it gets 407, before the
//! target is read. Another account, a chat, or the person's own programs on
//! loopback can no longer use the tunnel while it is open. Claude Code
//! 2.1.322 and Codex 0.167.2 send it unasked on CONNECT (the sources in
//! `derm-egress/src/auth.rs`); the header never goes on, since the tunnel
//! writes its own CONNECT upstream and passes only what follows the head.

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use derm_egress::auth::{self, ProxyCredential};

const HEAD_MAX: usize = 8 * 1024;

pub struct Tunnel {
    pub port: u16,
    /// This sign-in's proxy credential (I-3).
    credential: ProxyCredential,
    /// Hosts asked for and refused, `host:port`, once each.
    refused: Arc<Mutex<Vec<String>>>,
    /// Admitted hosts the tunnel could not reach, with why, once each.
    failed: Arc<Mutex<Vec<String>>>,
}

/// The person's own HTTP proxy, and the hosts that skip it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    /// `host:port`.
    pub addr: String,
    pub no_proxy: Vec<String>,
}

impl Upstream {
    /// Whether `host` goes direct (curl's rule, module text).
    pub fn skips(&self, host: &str) -> bool {
        self.no_proxy.iter().any(|e| {
            let e = e.trim_start_matches('.');
            e == "*" || host == e || host.ends_with(&format!(".{e}"))
        })
    }
}

/// The upstream from the person's environment, or none, or why the proxy
/// it names is not used.
pub fn upstream_from(env: &dyn Fn(&str) -> Option<String>) -> Result<Option<Upstream>, String> {
    let Some(url) = ["https_proxy", "HTTPS_PROXY"]
        .iter()
        .find_map(|k| env(k).filter(|v| !v.is_empty()))
    else {
        return Ok(None);
    };
    let rest = url.strip_prefix("http://").unwrap_or(&url);
    if rest.contains("://") {
        return Err(format!(
            "the proxy {url} is not an http:// proxy; the tunnel goes direct"
        ));
    }
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains('@') {
        return Err("the proxy in https_proxy names a user or password, which derm does not carry; the tunnel goes direct".into());
    }
    let addr = if authority
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
    {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    if addr.starts_with(':') {
        return Err(format!(
            "the proxy {url} names no host; the tunnel goes direct"
        ));
    }
    let no_proxy = ["no_proxy", "NO_PROXY"]
        .iter()
        .find_map(|k| env(k))
        .unwrap_or_default()
        .split(',')
        .map(|e| {
            let e = e.trim().to_ascii_lowercase();
            match e.rsplit_once(':') {
                Some((h, p)) if p.parse::<u16>().is_ok() && !h.contains(':') => h.to_string(),
                _ => e,
            }
        })
        .filter(|e| !e.is_empty())
        .collect();
    Ok(Some(Upstream { addr, no_proxy }))
}

impl Tunnel {
    /// Listens on `127.0.0.1:0` and serves until the process ends.
    pub fn start(allow: &[&str], upstream: Option<Upstream>) -> std::io::Result<Tunnel> {
        let credential = ProxyCredential::mint().map_err(std::io::Error::other)?;
        let l = TcpListener::bind(("127.0.0.1", 0))?;
        let port = l.local_addr()?.port();
        let allow: Arc<Vec<String>> = Arc::new(allow.iter().map(|h| format!("{h}:443")).collect());
        let refused = Arc::new(Mutex::new(Vec::new()));
        let failed = Arc::new(Mutex::new(Vec::new()));
        let (r, f) = (refused.clone(), failed.clone());
        let up = Arc::new(upstream);
        let cred = credential.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let (allow, r, f, up) = (allow.clone(), r.clone(), f.clone(), up.clone());
                let cred = cred.clone();
                std::thread::spawn(move || {
                    let dial = |t: &str| {
                        let host = t.rsplit_once(':').map_or(t, |(h, _)| h);
                        let got = match up.as_ref() {
                            Some(u) if !u.skips(host) => dial_via(&u.addr, t),
                            _ => dial_public(t),
                        };
                        if let Err(why) = &got {
                            note(&f, why.clone());
                        }
                        got
                    };
                    serve(c, &allow, &r, Some(&cred), &dial)
                });
            }
        });
        Ok(Tunnel {
            port,
            credential,
            refused,
            failed,
        })
    }

    pub fn failed(&self) -> Vec<String> {
        self.failed.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// The proxy URL the sign-in is given, with its credential: a secret,
    /// for the sign-in's environment only (case 85). Shown as
    /// [`Tunnel::shown_url`].
    pub fn url(&self) -> String {
        self.credential
            .url(std::net::SocketAddr::from(([127, 0, 0, 1], self.port)))
    }

    pub fn shown_url(&self) -> String {
        auth::shown(&self.url())
    }

    /// The `Proxy-Authorization` value the sign-in sends (tests).
    #[cfg(test)]
    pub(crate) fn authorization(&self) -> String {
        self.credential.header_value()
    }

    pub fn refused(&self) -> Vec<String> {
        self.refused.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

/// The CONNECT target, lowercased, when the head is exactly one CONNECT.
pub fn target(head: &str) -> Option<String> {
    let line = head.split("\r\n").next()?;
    let mut w = line.split(' ');
    let (m, t, v) = (w.next()?, w.next()?, w.next()?);
    if m != "CONNECT" || !v.starts_with("HTTP/1.") || w.next().is_some() {
        return None;
    }
    let (host, port) = t.rsplit_once(':')?;
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || port.parse::<u16>().is_err()
    {
        return None;
    }
    Some(format!("{}:{port}", host.to_ascii_lowercase()))
}

/// An address the tunnel never dials: loopback, private, link-local,
/// unspecified, multicast, CGNAT, documentation and ULA ranges, and an
/// IPv4-mapped IPv6 address of any of them (a name the person's resolver
/// maps there is refused, not followed).
pub fn non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || o[0] >= 240
        }
        IpAddr::V6(a) => {
            if let Some(m) = a.to_ipv4_mapped() {
                return non_public(IpAddr::V4(m));
            }
            let s = a.segments();
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || s[0] == 0x2001 && s[1] == 0x0db8
        }
    }
}

fn note(list: &Mutex<Vec<String>>, what: String) {
    if let Ok(mut v) = list.lock() {
        if !v.contains(&what) && v.len() < 64 {
            v.push(what);
        }
    }
}

/// Through the person's proxy: one CONNECT, and only a 200 with nothing
/// after its head opens the stream. The proxy is the person's own choice, so
/// a loopback proxy is dialed; the target's own address is the proxy's to
/// resolve.
pub fn dial_via(proxy: &str, target: &str) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = proxy
        .to_socket_addrs()
        .map_err(|e| format!("{target}: the proxy {proxy}: {e}"))?
        .collect();
    let mut s = addrs
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, Duration::from_secs(10)).ok())
        .ok_or_else(|| format!("{target}: the proxy {proxy} did not answer"))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .map_err(|e| format!("{target}: the proxy {proxy}: {e}"))?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= HEAD_MAX {
            return Err(format!(
                "{target}: the proxy {proxy} sent no end to its answer"
            ));
        }
        match s.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => {
                return Err(format!(
                    "{target}: the proxy {proxy} closed before answering"
                ))
            }
        }
    }
    let line = String::from_utf8_lossy(&head);
    let line = line.split("\r\n").next().unwrap_or("");
    let code = line.split(' ').nth(1).unwrap_or("");
    if !(line.starts_with("HTTP/1.") && code == "200") {
        return Err(format!("{target}: the proxy {proxy} answered \"{line}\""));
    }
    let _ = s.set_read_timeout(None);
    Ok(s)
}

fn dial_public(target: &str) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = target
        .to_socket_addrs()
        .map_err(|e| format!("{target}: {e}"))?
        .collect();
    if addrs.is_empty() || addrs.iter().any(|a| non_public(a.ip())) {
        return Err(format!(
            "{target} resolves to an address that is not public"
        ));
    }
    let mut last = String::new();
    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_secs(10)) {
            Ok(s) => return Ok(s),
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("{target}: {last}"))
}

/// What the refusal list says of a client without the sign-in's credential.
pub const NO_CREDENTIAL: &str = "a client without this sign-in's proxy credential";

/// One client: read the head, check the credential (when there is one),
/// admit or refuse, then copy both ways.
pub fn serve(
    mut c: TcpStream,
    allow: &[String],
    refused: &Mutex<Vec<String>>,
    credential: Option<&ProxyCredential>,
    dial: &dyn Fn(&str) -> Result<TcpStream, String>,
) {
    let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() >= HEAD_MAX {
            return;
        }
        match c.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    if let Some(cred) = credential {
        if !cred.admits_head(&head) {
            note(refused, NO_CREDENTIAL.into());
            let _ = c.write_all(auth::REFUSAL);
            return;
        }
    }
    let Some(t) = target(&head).filter(|t| allow.iter().any(|a| a == t)) else {
        let asked = target(&head).unwrap_or_else(|| "a request that is not CONNECT".into());
        note(refused, asked);
        let _ = c
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    };
    let mut up = match dial(&t) {
        Ok(u) => u,
        Err(_) => {
            let _ = c.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return;
        }
    };
    if c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .is_err()
        || up.write_all(&buf[end..]).is_err()
    {
        return;
    }
    let _ = c.set_read_timeout(None);
    let (Ok(mut c2), Ok(mut up2)) = (c.try_clone(), up.try_clone()) else {
        return;
    };
    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut up2);
        let _ = up2.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut up, &mut c);
    let _ = c.shutdown(Shutdown::Write);
    let _ = t1.join();
}
