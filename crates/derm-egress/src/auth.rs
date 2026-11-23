//! A proxy credential for one chat or one sign-in (plan step P10's I-3 and
//! I-4; `research-notes/CC_project_scoped_agents.md` section 6;
//! `research-notes/CD_project_layer_base.md` section 0, item 5;
//! `contracts/projects.md` section 2.3).
//!
//! A loopback proxy takes connections from any local process: another agent
//! account, a chat of another project, the person's own programs. With a
//! credential only the client that was handed it gets through: derm puts it
//! in the proxy URL's user part (`http://derm:<32 hex>@127.0.0.1:<port>`),
//! in the client's environment only, never on argv (case 85), and the proxy
//! answers anything without it with 407.
//!
//! Every client derm hands such a URL builds `Proxy-Authorization: Basic`
//! from the URL's user part and sends it on the first CONNECT, unasked (V,
//! read at the version in use unless marked run):
//!
//! - Claude Code 2.1.322: its parent-proxy code builds `Basic` from the
//!   URL's `username:password` and writes `Proxy-Authorization` on CONNECT
//!   (binary read: `function Vks(e){if(!e.username&&!e.password)return;...
//!   return\`Basic ${Buffer.from(t).toString("base64")}\``, `authHeader:Vks(e)`),
//!   reading `HTTPS_PROXY` before `https_proxy`; 2.1.330 sent it on every
//!   CONNECT to `api.anthropic.com` and `platform.claude.com` (run, note CD
//!   section 2.1).
//! - Codex 0.167.2: reqwest 0.12.28 over hyper-util 0.1.20, whose
//!   `parse_env_uri` turns `user:pass@` into `Auth::Basic`
//!   (`src/client/proxy/matcher.rs:362-375`) and whose tunnel sends it as
//!   `proxy-authorization` (`src/client/legacy/connect/proxy/tunnel.rs:76-77`).
//! - Pi 1.6.0: undici 8.12.4's `ProxyAgent` (`lib/dispatcher/proxy-agent.js:
//!   141-142`), reading `https_proxy` before `HTTPS_PROXY`
//!   (`env-http-proxy-agent.js:33`).
//! - srt 0.0.82 toward its parent: `proxyAuthHeader` (`dist/sandbox/
//!   parent-proxy.js:270-283`), on CONNECT (`:203-208, 255`) and on plain
//!   HTTP (`http-proxy.js:802`).
//! - What a chat's commands run: curl (Basic is `CURLOPT_PROXYAUTH`'s
//!   default, `docs/libcurl/opts/CURLOPT_PROXYAUTH.3` at `curl-8_5_0`), Go's
//!   `net/http` (`connectMethod.proxyAuth`, `transport.go:984-1000, 1820,
//!   1841` at go1.25.0, which `gh` uses), Python requests 2.32.5
//!   (`adapters.py:583-586`).
//!
//! The user name is fixed (`derm`); the password is 128 bits from the OS's
//! random source, per proxy, so a credential is never reused across chats or
//! sign-ins. Comparison is constant time over the decoded bytes.

use std::net::SocketAddr;

use base64::Engine;

/// The user part's name. The password is what holds.
pub const USER: &str = "derm";

/// What a proxy answers a client without the credential: 407 with a Basic
/// challenge (RFC 9110 section 11.7.1), so a client that sends credentials
/// only when asked can try again.
pub const REFUSAL: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"derm\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// One proxy's credential. `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyCredential {
    password: String,
}

impl std::fmt::Debug for ProxyCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyCredential(<not shown>)")
    }
}

/// `n` bytes from the OS's random source, as lowercase hex.
pub fn random_hex(n: usize) -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut b = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "no random source".to_string())?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

impl ProxyCredential {
    /// A fresh credential: 16 random bytes as 32 hex characters, which need
    /// no percent-encoding in a URL's user part.
    pub fn mint() -> Result<ProxyCredential, String> {
        Ok(ProxyCredential {
            password: random_hex(16)?,
        })
    }

    /// The proxy URL a client is given: `http://derm:<password>@<addr>`. A
    /// secret: it goes in the client's environment, never on argv, in a
    /// record or on a start line (use [`shown`] there).
    pub fn url(&self, addr: SocketAddr) -> String {
        format!("http://{USER}:{}@{addr}", self.password)
    }

    /// The header value such a client sends.
    pub fn header_value(&self) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(self.expected())
        )
    }

    fn expected(&self) -> Vec<u8> {
        format!("{USER}:{}", self.password).into_bytes()
    }

    /// Whether one `Proxy-Authorization` value carries this credential:
    /// scheme `Basic` in any letter case, then the base64 of
    /// `derm:<password>`, compared in constant time.
    pub fn admits_value(&self, value: &str) -> bool {
        let v = value.trim_matches([' ', '\t']);
        let Some((scheme, token)) = v.split_once([' ', '\t']) else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(got) =
            base64::engine::general_purpose::STANDARD.decode(token.trim_matches([' ', '\t']))
        else {
            return false;
        };
        same(&got, &self.expected())
    }

    /// Whether a request's headers carry this credential: exactly one
    /// `Proxy-Authorization` header, and it admits (two are refused, so no
    /// reader in between can take the other one).
    pub fn admits(&self, headers: &[(String, String)]) -> bool {
        let mut found = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"));
        match (found.next(), found.next()) {
            (Some((_, v)), None) => self.admits_value(v),
            _ => false,
        }
    }

    /// [`admits`](Self::admits) over a raw request head (the request line,
    /// then `name: value` lines, `\r\n` each), for a proxy that reads the
    /// head as text.
    pub fn admits_head(&self, head: &str) -> bool {
        let headers: Vec<(String, String)> = head
            .split("\r\n")
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self.admits(&headers)
    }
}

fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A proxy URL as it may be shown: the user part replaced, the rest kept.
pub fn shown(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let marked = if authority.contains('@') {
        format!("<credential>@{host}")
    } else {
        host.to_string()
    };
    if scheme.is_empty() {
        format!("{marked}{tail}")
    } else {
        format!("{scheme}://{marked}{tail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_admits_its_own_basic_header_and_nothing_else() {
        let c = ProxyCredential::mint().unwrap();
        let other = ProxyCredential::mint().unwrap();
        assert_ne!(c, other, "a fresh password each time");
        let h = c.header_value();
        assert!(c.admits_value(&h));
        assert!(c.admits_value(&h.replacen("Basic", "basic", 1)));
        assert!(c.admits_value(&format!("  {h} ")));
        assert!(!other.admits_value(&h));
        for bad in [
            "",
            "Basic",
            "Bearer abc",
            "Basic !!!",
            "Basic ZGVybTo=",
            &h[..h.len() - 2],
        ] {
            assert!(!c.admits_value(bad), "{bad:?}");
        }
        // The URL's user part is what a client turns into that header.
        let url = c.url("127.0.0.1:9".parse().unwrap());
        let pw = url
            .strip_prefix("http://derm:")
            .and_then(|r| r.strip_suffix("@127.0.0.1:9"))
            .unwrap();
        assert_eq!(pw.len(), 32);
        assert!(pw.bytes().all(|b| b.is_ascii_hexdigit()));
        let made = base64::engine::general_purpose::STANDARD.encode(format!("derm:{pw}"));
        assert!(c.admits_value(&format!("Basic {made}")));
        assert!(!format!("{c:?}").contains(pw));
    }

    #[test]
    fn exactly_one_proxy_authorization_header_is_read() {
        let c = ProxyCredential::mint().unwrap();
        let ok = ("Proxy-Authorization".to_string(), c.header_value());
        assert!(c.admits(std::slice::from_ref(&ok)));
        assert!(!c.admits(&[]));
        assert!(!c.admits(&[ok.clone(), ok.clone()]));
        assert!(!c.admits(&[("Authorization".into(), c.header_value())]));
        let head = format!(
            "CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\nproxy-authorization: {}\r\n\r\n",
            c.header_value()
        );
        assert!(c.admits_head(&head));
        assert!(!c.admits_head("CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n"));
        // The request line is never read as a header.
        assert!(!c.admits_head(&format!(
            "proxy-authorization: {}\r\n\r\n",
            c.header_value()
        )));
    }

    #[test]
    fn a_shown_url_carries_no_credential() {
        let c = ProxyCredential::mint().unwrap();
        let url = c.url("127.0.0.1:4242".parse().unwrap());
        assert_eq!(shown(&url), "http://<credential>@127.0.0.1:4242");
        assert_eq!(shown("http://127.0.0.1:1"), "http://127.0.0.1:1");
        assert_eq!(shown("http://a:b@h:1/p?q"), "http://<credential>@h:1/p?q");
        assert_eq!(shown("a:b@c@h:1"), "<credential>@h:1");
    }
}
