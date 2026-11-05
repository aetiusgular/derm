//! An incremental Server-Sent Events reader: bytes in as they arrive, whole
//! events out. Lines end in `\n`, `\r\n` or `\r` (the SSE spec); a blank
//! line ends an event; `:` lines are comments (`ping` keep-alives arrive as
//! events, not comments, and pass through untouched either way: this only
//! reads a copy).

/// One event: its `event:` name (empty when none) and its `data:` lines
/// joined with `\n`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseEvent {
    pub event: String,
    pub data: String,
}

/// The reader. An event whose data grows past `max_event` is dropped and the
/// reader stops (`overflowed`), so a hostile stream cannot grow memory.
#[derive(Debug)]
pub struct SseReader {
    line: Vec<u8>,
    event: String,
    data: String,
    has_data: bool,
    last_cr: bool,
    max_event: usize,
    pub overflowed: bool,
}

impl SseReader {
    pub fn new(max_event: usize) -> Self {
        SseReader {
            line: Vec::new(),
            event: String::new(),
            data: String::new(),
            has_data: false,
            last_cr: false,
            max_event,
            overflowed: false,
        }
    }

    /// Feeds bytes; returns the events they completed.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        let mut out = Vec::new();
        if self.overflowed {
            return out;
        }
        for &b in bytes {
            if self.last_cr {
                self.last_cr = false;
                if b == b'\n' {
                    continue;
                }
            }
            match b {
                b'\n' | b'\r' => {
                    self.last_cr = b == b'\r';
                    let line = std::mem::take(&mut self.line);
                    if let Some(e) = self.take_line(&line) {
                        out.push(e);
                    }
                    if self.overflowed {
                        return out;
                    }
                }
                _ => {
                    if self.line.len() + self.data.len() >= self.max_event {
                        self.overflowed = true;
                        self.line.clear();
                        self.data.clear();
                        return out;
                    }
                    self.line.push(b);
                }
            }
        }
        out
    }

    fn take_line(&mut self, line: &[u8]) -> Option<SseEvent> {
        if line.is_empty() {
            if !self.has_data && self.event.is_empty() {
                return None;
            }
            let e = SseEvent {
                event: std::mem::take(&mut self.event),
                data: std::mem::take(&mut self.data),
            };
            self.has_data = false;
            return Some(e);
        }
        if line[0] == b':' {
            return None;
        }
        let text = String::from_utf8_lossy(line);
        let (field, value) = match text.find(':') {
            Some(i) => {
                let v = &text[i + 1..];
                (&text[..i], v.strip_prefix(' ').unwrap_or(v))
            }
            None => (&text[..], ""),
        };
        match field {
            "event" => self.event = value.to_string(),
            "data" => {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
                if self.data.len() > self.max_event {
                    self.overflowed = true;
                    self.data.clear();
                }
            }
            _ => {}
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_split_anywhere_and_any_line_ending() {
        let stream = b"event: a\ndata: {\"x\":1}\n\n: ping\r\nevent: b\r\ndata: one\r\ndata: two\r\n\r\ndata: 3\r\r";
        for cut in 0..stream.len() {
            let mut r = SseReader::new(1 << 20);
            let mut got = r.feed(&stream[..cut]);
            got.extend(r.feed(&stream[cut..]));
            assert_eq!(
                got,
                vec![
                    SseEvent { event: "a".into(), data: "{\"x\":1}".into() },
                    SseEvent { event: "b".into(), data: "one\ntwo".into() },
                    SseEvent { event: "".into(), data: "3".into() },
                ],
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn a_huge_event_stops_the_reader_without_growing() {
        let mut r = SseReader::new(64);
        let mut got = r.feed(b"data: ");
        got.extend(r.feed(&[b'x'; 200]));
        got.extend(r.feed(b"\n\ndata: later\n\n"));
        assert!(got.is_empty());
        assert!(r.overflowed);
    }
}
