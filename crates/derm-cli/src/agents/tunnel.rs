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

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const HEAD_MAX: usize = 8 * 1024;

pub struct Tunnel {
    pub port: u16,
    /// Hosts asked for and refused, `host:port`, once each.
    refused: Arc<Mutex<Vec<String>>>,
}

impl Tunnel {
    /// Listens on `127.0.0.1:0` and serves until the process ends.
    pub fn start(allow: &[&str]) -> std::io::Result<Tunnel> {
        let l = TcpListener::bind(("127.0.0.1", 0))?;
        let port = l.local_addr()?.port();
        let allow: Arc<Vec<String>> = Arc::new(allow.iter().map(|h| format!("{h}:443")).collect());
        let refused = Arc::new(Mutex::new(Vec::new()));
        let r = refused.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let (allow, r) = (allow.clone(), r.clone());
                std::thread::spawn(move || serve(c, &allow, &r, &dial_public));
            }
        });
        Ok(Tunnel { port, refused })
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
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

/// One client: read the head, admit or refuse, then copy both ways.
pub fn serve(
    mut c: TcpStream,
    allow: &[String],
    refused: &Mutex<Vec<String>>,
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
    let Some(t) = target(&head).filter(|t| allow.iter().any(|a| a == t)) else {
        let asked = target(&head).unwrap_or_else(|| "a request that is not CONNECT".into());
        if let Ok(mut r) = refused.lock() {
            if !r.contains(&asked) && r.len() < 64 {
                r.push(asked);
            }
        }
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
