//! A standalone derm-egress for the contract checks (`tests/cli-contract/
//! checks/6C/`), never shipped: `cargo build -p derm-egress --example
//! egress_dev`. One secret (`github`, host `api.github.com`, value from
//! `DEV_SECRET_VALUE`), a fresh CA in memory, and a TLS echo server with its
//! own CA that every name resolves to. The echo answers what reached it as
//! JSON (whether the `authorization` header or the body held the value or the
//! placeholder), never a value. Records go to `<dir>/records.jsonl`.
//!
//! `egress_dev <dir>` prints one JSON line (`proxy`, `ca`, `bundle`,
//! `placeholder`, `records`) and serves until stdin closes.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use derm_egress::ca::Ca;
use derm_egress::{http, Config, Egress, Secret};

#[derive(Debug)]
struct One(Arc<rustls::sign::CertifiedKey>);
impl rustls::server::ResolvesServerCert for One {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("egress_dev <dir>"));
    std::fs::create_dir_all(&dir).unwrap();
    let value = std::env::var("DEV_SECRET_VALUE").expect("DEV_SECRET_VALUE");
    let placeholder = derm_egress::secrets::mint_placeholder("github").unwrap();

    // The echo upstream.
    let up_ca = Arc::new(Ca::generate().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_addr = listener.local_addr().unwrap();
    {
        let (up_ca, value, ph) = (up_ca.clone(), value.clone(), placeholder.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut tcp) = conn else { continue };
                let (ca, value, ph) = (up_ca.clone(), value.clone(), ph.clone());
                std::thread::spawn(move || {
                    let mut acc = rustls::server::Acceptor::default();
                    let a = loop {
                        if acc.read_tls(&mut tcp).unwrap_or(0) == 0 {
                            return;
                        }
                        if let Ok(Some(a)) = acc.accept() {
                            break a;
                        }
                    };
                    let name = a.client_hello().server_name().unwrap_or("none").to_string();
                    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                        .with_safe_default_protocol_versions()
                        .unwrap()
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(One(ca.leaf(&name).unwrap())));
                    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
                    let Ok(c) = a.into_connection(Arc::new(cfg)) else { return };
                    let mut s = BufReader::new(rustls::StreamOwned::new(c, tcp));
                    let Ok(Some(h)) = http::read_head(&mut s) else { return };
                    let body = http::request_framing(&h).ok().and_then(|f| http::read_body(&mut s, f).ok()).unwrap_or_default();
                    let auth = h.get("authorization").unwrap_or("");
                    let b = String::from_utf8_lossy(&body);
                    let reply = serde_json::json!({
                        "host": name,
                        "authHasValue": auth.contains(&value),
                        "authHasPlaceholder": auth.contains(&ph),
                        "bodyHasValue": b.contains(&value),
                        "bodyHasPlaceholder": b.contains(&ph),
                    })
                    .to_string();
                    let _ = write!(
                        s.get_mut(),
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                        reply.len()
                    );
                    let _ = s.get_mut().flush();
                    s.get_mut().conn.send_close_notify();
                    let _ = s.get_mut().flush();
                });
            }
        });
    }

    let ca = Arc::new(Ca::generate().unwrap());
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, ca.cert_pem()).unwrap();
    let mut bundle = String::new();
    for p in ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"] {
        if let Ok(r) = std::fs::read_to_string(p) {
            bundle = r;
            break;
        }
    }
    bundle.push_str(&ca.cert_pem());
    let bundle_path = dir.join("bundle.pem");
    std::fs::write(&bundle_path, bundle).unwrap();
    let records = dir.join("records.jsonl");
    let file = Arc::new(Mutex::new(std::fs::File::create(&records).unwrap()));
    let sink: derm_egress::Sink = Arc::new(move |evs| {
        let mut f = file.lock().unwrap();
        for e in evs {
            let _ = writeln!(f, "{}", serde_json::to_string(&e).unwrap());
        }
        let _ = f.flush();
    });
    let secrets = vec![Secret {
        id: "github".into(),
        value,
        hosts: vec!["api.github.com".into()],
        placeholder: placeholder.clone(),
    }];
    let mut cfg = Config::new("dev-chat", "dev", secrets, ca, sink).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(up_ca.cert_der().clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg.upstream_tls = Arc::new(tls);
    cfg.resolve = Arc::new(move |_, _| Ok(vec![up_addr]));
    cfg.allow_local = vec![("api.github.com".into(), 443), ("evil.test".into(), 443)];
    let egress = Egress::start(cfg).unwrap();
    println!(
        "{}",
        serde_json::json!({
            "proxy": egress.url(),
            "ca": ca_path,
            "bundle": bundle_path,
            "placeholder": placeholder,
            "records": records,
        })
    );
    let _ = std::io::stdout().flush();
    let mut sink = Vec::new();
    let _ = std::io::stdin().lock().read_to_end(&mut sink);
    let _ = std::io::stdin().lock().fill_buf();
    drop(egress);
}
