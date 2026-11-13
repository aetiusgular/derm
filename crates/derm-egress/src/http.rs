//! The HTTP/1.1 derm-egress reads and writes (RFC 9112). Strict where a
//! lenient reading would let one request be read two ways (request
//! smuggling): both `Content-Length` and `Transfer-Encoding`, two different
//! lengths, a transfer coding other than `chunked`, a folded header line, a
//! bare CR, or a trailer section are refused. A request body is read whole,
//! up to [`MAX_BODY`], because the broker must see all of it before anything
//! is sent; a response is relayed as it arrives, its end found by its framing.

use std::io::{self, BufRead, Read, Write};

/// The most a request head may take.
pub const MAX_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
/// The most of a request body the proxy reads before it decides. Over it the
/// request is refused (fail safe): it cannot be inspected whole.
pub const MAX_BODY: usize = 32 * 1024 * 1024;

/// A request or response head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    /// Request: method, target, version. Response: version, status, reason.
    pub line: [String; 3],
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn remove(&mut self, name: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    pub fn set(&mut self, name: &str, value: &str) {
        self.remove(name);
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// The head as bytes, CRLF line ends.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            format!("{} {} {}\r\n", self.line[0], self.line[1], self.line[2]).into_bytes();
        for (k, v) in &self.headers {
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

/// Why a request cannot be read.
#[derive(Debug)]
pub enum Bad {
    Io(io::Error),
    /// The status to answer with and why.
    Refuse(u16, &'static str),
}

impl From<io::Error> for Bad {
    fn from(e: io::Error) -> Self {
        Bad::Io(e)
    }
}

fn token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// Read one line ending in LF (CRLF or LF), without its end. `None` at a
/// clean end of stream before any byte.
fn read_line(r: &mut impl BufRead, budget: &mut usize) -> Result<Option<Vec<u8>>, Bad> {
    let mut line = Vec::new();
    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(Bad::Refuse(400, "the head ended mid-line"))
            };
        }
        let (take, done) = match memchr::memchr(b'\n', buf) {
            Some(i) => (i + 1, true),
            None => (buf.len(), false),
        };
        if take > *budget {
            return Err(Bad::Refuse(431, "the head is too large"));
        }
        *budget -= take;
        line.extend_from_slice(&buf[..take]);
        r.consume(take);
        if done {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.contains(&b'\r') {
                return Err(Bad::Refuse(400, "a bare CR in the head"));
            }
            return Ok(Some(line));
        }
    }
}

/// Read a head. `None` when the stream ends before one starts (a client that
/// closed a kept-alive connection).
pub fn read_head(r: &mut impl BufRead) -> Result<Option<Head>, Bad> {
    let mut budget = MAX_HEAD;
    let first = loop {
        match read_line(r, &mut budget)? {
            None => return Ok(None),
            // RFC 9112 section 2.2: a server SHOULD ignore an empty line
            // before the request line.
            Some(l) if l.is_empty() => continue,
            Some(l) => break l,
        }
    };
    let first =
        String::from_utf8(first).map_err(|_| Bad::Refuse(400, "a head that is not UTF-8"))?;
    let mut parts = first.splitn(3, ' ');
    let line = [
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    ];
    if line.iter().take(2).any(String::is_empty) {
        return Err(Bad::Refuse(400, "a malformed start line"));
    }
    let mut headers = Vec::new();
    loop {
        let l = read_line(r, &mut budget)?.ok_or(Bad::Refuse(400, "the head ended early"))?;
        if l.is_empty() {
            break;
        }
        if l[0] == b' ' || l[0] == b'\t' {
            return Err(Bad::Refuse(400, "a folded header line"));
        }
        let colon =
            memchr::memchr(b':', &l).ok_or(Bad::Refuse(400, "a header line with no colon"))?;
        let (k, v) = (&l[..colon], &l[colon + 1..]);
        if k.is_empty() || !k.iter().all(|c| token_char(*c)) {
            return Err(Bad::Refuse(400, "a header name that is not a token"));
        }
        let v = String::from_utf8(v.to_vec())
            .map_err(|_| Bad::Refuse(400, "a header value that is not UTF-8"))?;
        headers.push((
            String::from_utf8(k.to_vec()).unwrap_or_default(),
            v.trim_matches(|c| c == ' ' || c == '\t').to_string(),
        ));
        if headers.len() > MAX_HEADERS {
            return Err(Bad::Refuse(431, "too many header fields"));
        }
    }
    Ok(Some(Head { line, headers }))
}

/// How a message's body is framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked,
    /// A response with neither header: its body runs to the end of the stream.
    Close,
}

/// A request's framing (RFC 9112 section 6.3), refusing every shape two
/// readers could disagree on.
pub fn request_framing(h: &Head) -> Result<Framing, Bad> {
    let te: Vec<&str> = h.all("transfer-encoding").collect();
    let cl: Vec<&str> = h.all("content-length").collect();
    if !te.is_empty() && !cl.is_empty() {
        return Err(Bad::Refuse(
            400,
            "both Content-Length and Transfer-Encoding",
        ));
    }
    if !te.is_empty() {
        let codings: Vec<String> = te
            .iter()
            .flat_map(|v| v.split(','))
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect();
        return if codings == ["chunked"] {
            Ok(Framing::Chunked)
        } else {
            Err(Bad::Refuse(501, "a transfer coding other than chunked"))
        };
    }
    length(&cl).map(|l| l.map_or(Framing::None, Framing::Length))
}

fn length(values: &[&str]) -> Result<Option<u64>, Bad> {
    let mut seen: Option<u64> = None;
    for v in values.iter().flat_map(|v| v.split(',')) {
        let v = v.trim();
        if v.is_empty() || !v.bytes().all(|c| c.is_ascii_digit()) || v.len() > 15 {
            return Err(Bad::Refuse(400, "a Content-Length that is not a number"));
        }
        let n: u64 = v
            .parse()
            .map_err(|_| Bad::Refuse(400, "a Content-Length that is not a number"))?;
        if seen.is_some_and(|s| s != n) {
            return Err(Bad::Refuse(400, "two different Content-Length values"));
        }
        seen = Some(n);
    }
    Ok(seen)
}

/// Read a request body whole, up to [`MAX_BODY`].
pub fn read_body(r: &mut impl BufRead, framing: Framing) -> Result<Vec<u8>, Bad> {
    match framing {
        Framing::None | Framing::Close => Ok(Vec::new()),
        Framing::Length(n) => {
            if n > MAX_BODY as u64 {
                return Err(Bad::Refuse(413, "a body over the inspection limit"));
            }
            let mut b = vec![0u8; n as usize];
            r.read_exact(&mut b)?;
            Ok(b)
        }
        Framing::Chunked => {
            let mut body = Vec::new();
            let mut budget = MAX_HEAD;
            loop {
                let line = read_line(r, &mut budget)?
                    .ok_or(Bad::Refuse(400, "a chunked body cut short"))?;
                let size = line.split(|c| *c == b';').next().unwrap_or_default();
                let size = std::str::from_utf8(size)
                    .ok()
                    .map(str::trim)
                    .filter(|s| {
                        !s.is_empty() && s.len() <= 15 && s.bytes().all(|c| c.is_ascii_hexdigit())
                    })
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .ok_or(Bad::Refuse(400, "a chunk size that is not hex"))?;
                if size == 0 {
                    break;
                }
                if body.len() as u64 + size > MAX_BODY as u64 {
                    return Err(Bad::Refuse(413, "a body over the inspection limit"));
                }
                let start = body.len();
                body.resize(start + size as usize, 0);
                r.read_exact(&mut body[start..])?;
                let mut crlf = [0u8; 2];
                r.read_exact(&mut crlf)?;
                if &crlf != b"\r\n" {
                    return Err(Bad::Refuse(400, "a chunk not ended by CRLF"));
                }
            }
            // The trailer section: refused when it holds any field, since the
            // proxy re-frames the body and would drop it.
            let last =
                read_line(r, &mut budget)?.ok_or(Bad::Refuse(400, "a chunked body cut short"))?;
            if !last.is_empty() {
                return Err(Bad::Refuse(400, "a trailer section"));
            }
            Ok(body)
        }
    }
}

/// A response's framing (RFC 9112 section 6.3) for a request with `method`.
pub fn response_framing(method: &str, h: &Head) -> Result<Framing, Bad> {
    let status: u16 = h.line[1]
        .parse()
        .map_err(|_| Bad::Refuse(502, "an upstream status that is not a number"))?;
    if method.eq_ignore_ascii_case("HEAD")
        || status == 204
        || status == 304
        || (100..200).contains(&status)
    {
        return Ok(Framing::None);
    }
    let te: Vec<&str> = h.all("transfer-encoding").collect();
    if !te.is_empty() {
        let last = te
            .iter()
            .flat_map(|v| v.split(','))
            .map(|c| c.trim().to_ascii_lowercase())
            .rfind(|c| !c.is_empty());
        return Ok(if last.as_deref() == Some("chunked") {
            Framing::Chunked
        } else {
            Framing::Close
        });
    }
    let cl: Vec<&str> = h.all("content-length").collect();
    match length(&cl)
        .map_err(|_| Bad::Refuse(502, "an upstream Content-Length that is not a number"))?
    {
        Some(n) => Ok(Framing::Length(n)),
        None => Ok(Framing::Close),
    }
}

/// Copy a response body from `r` to `w` as it arrives, byte for byte, ending
/// where its framing ends. Returns the bytes copied.
pub fn relay_body(r: &mut impl BufRead, w: &mut impl Write, framing: Framing) -> io::Result<u64> {
    match framing {
        Framing::None => Ok(0),
        Framing::Length(n) => {
            let copied = io::copy(&mut r.take(n), w)?;
            if copied < n {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream body cut short",
                ));
            }
            Ok(copied)
        }
        Framing::Close => io::copy(r, w),
        Framing::Chunked => {
            let mut total = 0u64;
            loop {
                let mut line = Vec::new();
                r.take(4096).read_until(b'\n', &mut line)?;
                if !line.ends_with(b"\n") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a bad chunk line from upstream",
                    ));
                }
                w.write_all(&line)?;
                total += line.len() as u64;
                let size = std::str::from_utf8(&line)
                    .ok()
                    .and_then(|l| l.split(';').next())
                    .map(str::trim)
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "a bad chunk size from upstream")
                    })?;
                if size == 0 {
                    // Trailer lines, then the empty line.
                    loop {
                        let mut t = Vec::new();
                        r.take(8192).read_until(b'\n', &mut t)?;
                        if !t.ends_with(b"\n") {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "a bad trailer from upstream",
                            ));
                        }
                        w.write_all(&t)?;
                        total += t.len() as u64;
                        if t == b"\r\n" || t == b"\n" {
                            w.flush()?;
                            return Ok(total);
                        }
                    }
                }
                let n = io::copy(&mut r.take(size + 2), w)?;
                total += n;
                if n < size + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upstream chunk cut short",
                    ));
                }
                w.flush()?;
            }
        }
    }
}

/// A short response the proxy writes itself.
pub fn status_page(code: u16, reason: &str, text: &str) -> Vec<u8> {
    let body = format!("derm-egress: {text}\n");
    format!(
        "HTTP/1.1 {code} {reason}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\nx-derm-egress: blocked\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn head(s: &str) -> Result<Option<Head>, Bad> {
        read_head(&mut BufReader::new(s.as_bytes()))
    }

    fn refused(r: Result<Framing, Bad>) -> u16 {
        match r {
            Err(Bad::Refuse(c, _)) => c,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_plain_request_reads_with_its_headers_in_order() {
        let h = head("\r\nPOST /x HTTP/1.1\r\nHost: a.test\r\nX-A:  1 \r\nx-a: 2\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(h.line, ["POST".to_string(), "/x".into(), "HTTP/1.1".into()]);
        assert_eq!(h.all("x-a").collect::<Vec<_>>(), ["1", "2"]);
        assert_eq!(h.get("HOST"), Some("a.test"));
        assert!(head("").unwrap().is_none());
    }

    #[test]
    fn smuggling_shapes_are_refused() {
        for (s, code) in [
            ("GET / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
            ("GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", 400),
            ("GET / HTTP/1.1\r\nContent-Length: 1, 2\r\n\r\n", 400),
            ("GET / HTTP/1.1\r\nContent-Length: +1\r\n\r\n", 400),
            ("GET / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501),
            ("GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", 501),
            ("GET / HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n", 501),
        ] {
            assert_eq!(refused(request_framing(&head(s).unwrap().unwrap())), code, "{s:?}");
        }
        for s in [
            "GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n",
            "GET / HTTP/1.1\r\nX\r\n\r\n",
            "GET / HTTP/1.1\r\nX Y: a\r\n\r\n",
            "GET / HTTP/1.1\r\nX: a\rb\r\n\r\n",
        ] {
            assert!(matches!(head(s), Err(Bad::Refuse(400, _))), "{s:?}");
        }
        // Repeated equal lengths are one length.
        let h = head("GET / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(request_framing(&h).unwrap(), Framing::Length(3));
    }

    #[test]
    fn a_chunked_body_is_read_whole_and_a_trailer_is_refused() {
        let mut r = BufReader::new(&b"4;ext=1\r\nabcd\r\n2\r\nef\r\n0\r\n\r\nNEXT"[..]);
        assert_eq!(read_body(&mut r, Framing::Chunked).unwrap(), b"abcdef");
        let mut rest = String::new();
        r.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "NEXT");
        let mut t = BufReader::new(&b"1\r\na\r\n0\r\nX-Sum: 1\r\n\r\n"[..]);
        assert!(matches!(
            read_body(&mut t, Framing::Chunked),
            Err(Bad::Refuse(400, _))
        ));
        let mut bad = BufReader::new(&b"1\r\nab\r\n"[..]);
        assert!(read_body(&mut bad, Framing::Chunked).is_err());
    }

    #[test]
    fn a_body_over_the_limit_is_refused_before_it_is_read() {
        let mut r = BufReader::new(&b""[..]);
        assert!(matches!(
            read_body(&mut r, Framing::Length(MAX_BODY as u64 + 1)),
            Err(Bad::Refuse(413, _))
        ));
    }

    #[test]
    fn a_response_is_relayed_to_its_framings_end_and_no_further() {
        let mut out = Vec::new();
        let mut r = BufReader::new(&b"5\r\nhello\r\n0\r\n\r\nLEFT"[..]);
        relay_body(&mut r, &mut out, Framing::Chunked).unwrap();
        assert_eq!(out, b"5\r\nhello\r\n0\r\n\r\n");
        let mut out = Vec::new();
        let mut r = BufReader::new(&b"abcLEFT"[..]);
        relay_body(&mut r, &mut out, Framing::Length(3)).unwrap();
        assert_eq!(out, b"abc");
        let h = head("HTTP/1.1 204 No Content\r\ncontent-length: 9\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(response_framing("GET", &h).unwrap(), Framing::None);
        let h = head("HTTP/1.1 200 OK\r\n\r\n").unwrap().unwrap();
        assert_eq!(response_framing("GET", &h).unwrap(), Framing::Close);
        assert_eq!(response_framing("HEAD", &h).unwrap(), Framing::None);
    }

    #[test]
    fn a_head_over_its_size_is_refused() {
        let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert!(matches!(head(&big), Err(Bad::Refuse(431, _))));
    }
}
