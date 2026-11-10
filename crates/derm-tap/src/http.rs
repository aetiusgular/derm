//! Just enough HTTP/1.1 for a loopback client: one request at a time on a
//! kept-alive connection, bounded, strict about framing.
//!
//! Refused with 400: a header block over `MAX_HEAD`, a body over `MAX_BODY`,
//! `Content-Length` with `Transfer-Encoding`, two different lengths, a
//! transfer coding other than `chunked`, a bad chunk size, obsolete line
//! folding, a header name with a byte outside `token`. A request with
//! `Expect: 100-continue` gets its `100 Continue` before the body is read.

use std::io::{self, BufRead, Write};

pub const MAX_HEAD: usize = 64 * 1024;
pub const MAX_BODY: usize = 32 * 1024 * 1024;
const MAX_HEADERS: usize = 200;

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    /// `HTTP/1.0` closes after one exchange.
    pub http10: bool,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn wants_close(&self) -> bool {
        let conn = self.header("connection").unwrap_or("");
        let has = |t: &str| conn.split(',').any(|p| p.trim().eq_ignore_ascii_case(t));
        has("close") || (self.http10 && !has("keep-alive"))
    }
}

/// Why a request could not be read.
#[derive(Debug)]
pub enum ReadError {
    /// The client closed before a request began: not an error.
    Closed,
    /// The bytes do not frame a request; answer 400 and close.
    Bad(&'static str),
    Io(io::Error),
}

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Reads one line ending in `\n` (with an optional `\r`), counting toward
/// `budget`.
fn read_line(r: &mut impl BufRead, budget: &mut usize) -> Result<Option<String>, ReadError> {
    let mut buf = Vec::new();
    loop {
        let avail = match r.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadError::Io(e)),
        };
        if avail.is_empty() {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(ReadError::Bad("truncated head"))
            };
        }
        let (take, done) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (avail.len(), false),
        };
        if take > *budget {
            return Err(ReadError::Bad("head too large"));
        }
        *budget -= take;
        buf.extend_from_slice(&avail[..take]);
        r.consume(take);
        if done {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return String::from_utf8(buf)
                .map(Some)
                .map_err(|_| ReadError::Bad("head not UTF-8"));
        }
    }
}

/// Reads one request. `on_continue` is called when the client waits for
/// `100 Continue`.
pub fn read_request(
    r: &mut impl BufRead,
    mut on_continue: impl FnMut() -> io::Result<()>,
) -> Result<Request, ReadError> {
    let mut budget = MAX_HEAD;
    let line = loop {
        match read_line(r, &mut budget)? {
            None => return Err(ReadError::Closed),
            // Leading blank lines are allowed before a request (RFC 9112 2.2).
            Some(l) if l.is_empty() => continue,
            Some(l) => break l,
        }
    };
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ReadError::Bad("bad request line"));
    };
    if method.is_empty() || !method.bytes().all(is_token) || target.is_empty() {
        return Err(ReadError::Bad("bad request line"));
    }
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return Err(ReadError::Bad("unsupported version")),
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let Some(l) = read_line(r, &mut budget)? else {
            return Err(ReadError::Bad("truncated head"));
        };
        if l.is_empty() {
            break;
        }
        if l.starts_with(' ') || l.starts_with('\t') {
            return Err(ReadError::Bad("obsolete line folding"));
        }
        let Some((name, value)) = l.split_once(':') else {
            return Err(ReadError::Bad("header without a colon"));
        };
        if name.is_empty() || !name.bytes().all(is_token) {
            return Err(ReadError::Bad("bad header name"));
        }
        if value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(ReadError::Bad("bad header value"));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(ReadError::Bad("too many headers"));
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }
    let mut req = Request {
        method: method.to_string(),
        target: target.to_string(),
        http10,
        headers,
        body: Vec::new(),
    };
    let lengths: Vec<&str> = req
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .flat_map(|(_, v)| v.split(','))
        .map(str::trim)
        .collect();
    let te: Vec<String> = req
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|(_, v)| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if !te.is_empty() && !lengths.is_empty() {
        return Err(ReadError::Bad("both Content-Length and Transfer-Encoding"));
    }
    let waits = req
        .header("expect")
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
    if !te.is_empty() {
        if te != ["chunked"] {
            return Err(ReadError::Bad("unsupported transfer coding"));
        }
        if waits {
            on_continue().map_err(ReadError::Io)?;
        }
        req.body = read_chunked(r)?;
    } else if let Some(first) = lengths.first() {
        if lengths.iter().any(|l| l != first) {
            return Err(ReadError::Bad("conflicting Content-Length"));
        }
        if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) || first.len() > 12 {
            return Err(ReadError::Bad("bad Content-Length"));
        }
        let n: usize = first
            .parse()
            .map_err(|_| ReadError::Bad("bad Content-Length"))?;
        if n > MAX_BODY {
            return Err(ReadError::Bad("body too large"));
        }
        if waits && n > 0 {
            on_continue().map_err(ReadError::Io)?;
        }
        let mut body = vec![0; n];
        r.read_exact(&mut body).map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => ReadError::Bad("truncated body"),
            _ => ReadError::Io(e),
        })?;
        req.body = body;
    }
    Ok(req)
}

fn read_chunked(r: &mut impl BufRead) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::new();
    let mut budget = MAX_HEAD;
    loop {
        let Some(line) = read_line(r, &mut budget)? else {
            return Err(ReadError::Bad("truncated chunk"));
        };
        let size = line.split(';').next().unwrap_or("").trim();
        if size.is_empty() || size.len() > 8 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ReadError::Bad("bad chunk size"));
        }
        let n = usize::from_str_radix(size, 16).map_err(|_| ReadError::Bad("bad chunk size"))?;
        if n == 0 {
            // Trailers, then the blank line.
            loop {
                match read_line(r, &mut budget)? {
                    Some(l) if l.is_empty() => return Ok(body),
                    Some(_) => {}
                    None => return Err(ReadError::Bad("truncated trailers")),
                }
            }
        }
        if body.len() + n > MAX_BODY {
            return Err(ReadError::Bad("body too large"));
        }
        let start = body.len();
        body.resize(start + n, 0);
        r.read_exact(&mut body[start..])
            .map_err(|_| ReadError::Bad("truncated chunk"))?;
        match read_line(r, &mut budget)? {
            Some(l) if l.is_empty() => {}
            _ => return Err(ReadError::Bad("chunk not followed by CRLF")),
        }
    }
}

/// The reason phrase for a status (any phrase is valid; these are the usual).
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// Writes a status line and headers. The body follows as chunks
/// (`chunked: true`) or not at all.
pub fn write_head(
    w: &mut impl Write,
    status: u16,
    headers: &[(String, String)],
    chunked: bool,
    close: bool,
) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (n, v) in headers {
        head.push_str(n);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    if chunked {
        head.push_str("transfer-encoding: chunked\r\n");
    }
    if close {
        head.push_str("connection: close\r\n");
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes())
}

pub fn write_chunk(w: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    w.write_all(format!("{:x}\r\n", bytes.len()).as_bytes())?;
    w.write_all(bytes)?;
    w.write_all(b"\r\n")?;
    w.flush()
}

pub fn end_chunks(w: &mut impl Write) -> io::Result<()> {
    w.write_all(b"0\r\n\r\n")?;
    w.flush()
}

/// A whole small response with a JSON body.
pub fn write_json(w: &mut impl Write, status: u16, body: &str, close: bool) -> io::Result<()> {
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), body.len().to_string()),
    ];
    write_head(w, status, &headers, false, close)?;
    w.write_all(body.as_bytes())?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn read(bytes: &[u8]) -> Result<Request, ReadError> {
        read_request(&mut BufReader::with_capacity(7, bytes), || Ok(()))
    }

    #[test]
    fn a_kept_alive_connection_reads_requests_one_after_another() {
        let two = b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n1;ext=1\r\n!\r\n0\r\nT: 1\r\n\r\n";
        let mut r = BufReader::with_capacity(5, &two[..]);
        let a = read_request(&mut r, || Ok(())).unwrap();
        assert_eq!(
            (a.method.as_str(), a.target.as_str(), a.body.as_slice()),
            ("POST", "/a", &b"abc"[..])
        );
        let b = read_request(&mut r, || Ok(())).unwrap();
        assert_eq!((b.target.as_str(), b.body.as_slice()), ("/b", &b"hi!"[..]));
        assert!(matches!(
            read_request(&mut r, || Ok(())),
            Err(ReadError::Closed)
        ));
    }

    #[test]
    fn framing_that_could_smuggle_a_request_is_refused() {
        for bad in [
            &b"POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
            b"POST / HTTP/1.1\r\nContent-Length: 3, 4\r\n\r\nabcd",
            b"POST / HTTP/1.1\r\nContent-Length: +3\r\n\r\nabc",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nX: a\r\n b\r\n\r\n",
            b"POST / HTTP/1.1\r\nBad Name: a\r\n\r\n",
            b"POST /  HTTP/1.1\r\n\r\n",
            b"POST / HTTP/2\r\n\r\n",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc",
        ] {
            assert!(
                matches!(read(bad), Err(ReadError::Bad(_))),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn heads_and_bodies_are_bounded() {
        let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        big.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(read(&big), Err(ReadError::Bad("head too large"))));
        let huge = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(matches!(
            read(huge.as_bytes()),
            Err(ReadError::Bad("body too large"))
        ));
    }

    #[test]
    fn expect_continue_is_answered_before_the_body() {
        let mut asked = 0;
        let req = b"POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok";
        let r = read_request(&mut BufReader::new(&req[..]), || {
            asked += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!((asked, r.body.as_slice()), (1, &b"ok"[..]));
    }

    #[test]
    fn close_follows_the_version_and_the_header() {
        let r = read(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert!(r.wants_close());
        let r = read(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").unwrap();
        assert!(!r.wants_close());
        let r = read(b"GET / HTTP/1.1\r\nConnection: Upgrade, close\r\n\r\n").unwrap();
        assert!(r.wants_close());
    }
}
