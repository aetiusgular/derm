//! The first flight of a tunnel that is relayed unread (review R3, P fix 2;
//! rules case RV-2): the ClientHello's server name, read without terminating
//! TLS, so a relay that admits by its CONNECT name also checks what the TLS
//! inside asks for.
//!
//! Before this, derm-egress's pass-through and the chat's sign-in tunnel
//! checked only the CONNECT host and port, then copied bytes: a ClientHello
//! for any other server name, or bytes that were not TLS at all, reached the
//! sign-in host's address and were recorded as `forwarded` (P review, probes
//! R-1 and R-2, run). derm's terminated path already refused both
//! (`lib.rs`, the SNI check; `proxy.rs` `tunnel`, the first byte).
//!
//! The hello is parsed by rustls' own server-side `Acceptor` (rustls 0.23.46,
//! `server::Acceptor::read_tls` and `accept`), the parser the terminated
//! path uses, fed through a reader that keeps every byte it hands over; the
//! `Accepted` is dropped, so no TLS state is kept, and the kept bytes go
//! upstream as they came. A hello split over several records is read whole,
//! since the acceptor reassembles it.

use std::io::{self, Read};

/// The most a relay reads before the hello is whole. A TLS record is at most
/// 2^14 bytes of plaintext plus its header (RFC 8446 section 5.1), and a
/// ClientHello with post-quantum key shares is about 1.8 KB; this leaves room
/// for a hello split over a few records and refuses a client that never
/// finishes one.
pub const MAX_HELLO_BYTES: usize = 64 * 1024;

/// Why a tunnel's first flight is not a TLS ClientHello with a server name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotHello {
    /// The first byte is not a TLS handshake record's (0x16).
    NotTls,
    /// A handshake record, but not a ClientHello rustls takes.
    Malformed,
    /// A ClientHello with no server name (an address, or none at all).
    NoServerName,
    /// More than [`MAX_HELLO_BYTES`] before the hello ended.
    TooLong,
    /// The client closed, went quiet past its read timeout, or failed.
    Closed,
}

impl NotHello {
    /// The record's reason.
    pub fn reason(&self) -> &'static str {
        match self {
            NotHello::NotTls => "the tunnel does not carry TLS",
            NotHello::Malformed => "the tunnel does not start with a TLS ClientHello",
            NotHello::NoServerName => "the TLS ClientHello names no server",
            NotHello::TooLong => "the TLS ClientHello did not end",
            NotHello::Closed => "the client closed before its TLS ClientHello",
        }
    }
}

/// What was read: every byte taken from `r` (to send on unchanged), and the
/// hello's server name, lowercased, or why there is none.
pub struct Read1 {
    pub bytes: Vec<u8>,
    pub server_name: Result<String, NotHello>,
}

struct Keep<'a> {
    inner: &'a mut dyn Read,
    kept: Vec<u8>,
}

impl Read for Keep<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let room = MAX_HELLO_BYTES.saturating_sub(self.kept.len());
        if room == 0 {
            return Err(io::Error::other("hello too long"));
        }
        let n = room.min(b.len());
        let got = self.inner.read(&mut b[..n])?;
        self.kept.extend_from_slice(&b[..got]);
        Ok(got)
    }
}

/// Reads the client's first flight from `r` until rustls has a whole
/// ClientHello, and returns its server name with the bytes read.
pub fn read_client_hello(r: &mut dyn Read) -> Read1 {
    let mut first = [0u8; 1];
    let n: usize = r.read(&mut first).unwrap_or_default();
    if n == 0 {
        return Read1 {
            bytes: Vec::new(),
            server_name: Err(NotHello::Closed),
        };
    }
    if first[0] != 0x16 {
        return Read1 {
            bytes: first.to_vec(),
            server_name: Err(NotHello::NotTls),
        };
    }
    let mut chained = io::Cursor::new(first).chain(r);
    let mut keep = Keep {
        inner: &mut chained,
        kept: Vec::new(),
    };
    let mut acceptor = rustls::server::Acceptor::default();
    let name = loop {
        match acceptor.read_tls(&mut keep) {
            Ok(0) => break Err(NotHello::Closed),
            Ok(_) => {}
            Err(_) if keep.kept.len() >= MAX_HELLO_BYTES => break Err(NotHello::TooLong),
            Err(_) => break Err(NotHello::Closed),
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                break accepted
                    .client_hello()
                    .server_name()
                    .map(str::to_ascii_lowercase)
                    .ok_or(NotHello::NoServerName)
            }
            Ok(None) => continue,
            Err(_) => break Err(NotHello::Malformed),
        }
    };
    Read1 {
        bytes: keep.kept,
        server_name: name,
    }
}

/// A real ClientHello for `name` (no server name with `None`), from rustls'
/// own client, for tests in this crate and others that need the first flight
/// a harness sends (rules 9.12: the stand-in is the real thing).
#[doc(hidden)]
pub fn client_hello_for(name: Option<&str>) -> Vec<u8> {
    use std::sync::Arc;
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring's protocol versions")
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    cfg.enable_sni = name.is_some();
    let server =
        rustls::pki_types::ServerName::try_from(name.unwrap_or("example.test").to_string())
            .expect("a DNS name");
    let mut c = rustls::ClientConnection::new(Arc::new(cfg), server).expect("a client");
    let mut out = Vec::new();
    c.write_tls(&mut out).expect("a first flight");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_for(name: Option<&str>) -> Vec<u8> {
        super::client_hello_for(name)
    }

    #[test]
    fn a_hello_gives_its_server_name_and_every_byte_read() {
        let h = hello_for(Some("Platform.Claude.com"));
        let mut after = h.clone();
        after.extend_from_slice(b"rest");
        let mut r = io::Cursor::new(after);
        let got = read_client_hello(&mut r);
        assert_eq!(got.server_name, Ok("platform.claude.com".into()));
        // `read_tls` takes what is there, so the kept bytes may run past the
        // hello; the relay sends every kept byte on, so nothing is lost or
        // changed: kept, then the rest, is the stream as sent.
        assert!(got.bytes.starts_with(&h));
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        let mut whole = got.bytes.clone();
        whole.extend(rest);
        let mut sent = h;
        sent.extend_from_slice(b"rest");
        assert_eq!(whole, sent, "byte for byte");
    }

    #[test]
    fn plain_bytes_a_hello_with_no_name_and_a_close_are_refused_by_name() {
        let got = read_client_hello(&mut io::Cursor::new(b"GET / HTTP/1.1\r\n\r\n".to_vec()));
        assert_eq!(got.server_name, Err(NotHello::NotTls));
        let got = read_client_hello(&mut io::Cursor::new(hello_for(None)));
        assert_eq!(got.server_name, Err(NotHello::NoServerName));
        let got = read_client_hello(&mut io::Cursor::new(Vec::new()));
        assert_eq!(got.server_name, Err(NotHello::Closed));
        let mut cut = hello_for(Some("a.test"));
        cut.truncate(20);
        let got = read_client_hello(&mut io::Cursor::new(cut));
        assert_eq!(got.server_name, Err(NotHello::Closed));
        // A handshake record that is not a ClientHello.
        let got = read_client_hello(&mut io::Cursor::new(vec![0x16, 3, 1, 0, 4, 2, 0, 0, 0]));
        assert_eq!(got.server_name, Err(NotHello::Malformed));
    }

    #[test]
    fn a_hello_that_never_ends_stops_at_the_cap() {
        // A record header that promises the most a record may hold, then
        // the same again, forever: the acceptor never has a whole hello.
        struct Endless;
        impl Read for Endless {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                for (i, x) in b.iter_mut().enumerate() {
                    *x = if i % 2 == 0 { 0x16 } else { 0x03 };
                }
                Ok(b.len())
            }
        }
        let got = read_client_hello(&mut Endless);
        assert!(got.server_name.is_err());
        assert!(got.bytes.len() <= MAX_HELLO_BYTES);
    }
}
