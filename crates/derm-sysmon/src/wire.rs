//! The pipe's wire (`contracts/sysmon-service.md` section 3): JSON lines
//! both ways, at most 1 MiB a line, the daemon first.
//!
//! The service answers a daemon line with a reply (`{"ok":...}`, no `op`)
//! and pushes its own lines with an `op` (`events`, `gap`). A line is read
//! with a bound, so a peer that never sends a line end cannot grow the
//! reader's buffer past the limit.

use std::io::{self, BufRead};

use serde_json::{json, Value};

/// The protocol both sides speak.
pub const PROTOCOL: u64 = 1;
/// The longest line either side reads, the line end included.
pub const MAX_LINE: usize = 1 << 20;
/// The most records one `events` line carries.
pub const MAX_BATCH: usize = 256;
/// The escaped XML bytes one `events` line carries, measured as JSON
/// writes them, with room under `MAX_LINE` for the rest of the line.
pub const MAX_BATCH_BYTES: usize = MAX_LINE / 2;

/// A line the daemon sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FromDaemon {
    Hello { protocol: u64 },
    Claim { process_guid: String, chat: String },
    Ack { record_id: u64 },
}

/// A line the service sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FromService {
    /// An answer to `hello` or `claim`.
    Reply(Reply),
    Events(Vec<Record>),
    Gap {
        from: u64,
        to: u64,
        reason: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    pub ok: bool,
    pub protocol: Option<u64>,
    /// The client's SID, as the service read it from the client's token.
    pub user: Option<String>,
    /// The last record id this user acknowledged, when `hello` was answered
    /// (`Some(None)`: none yet).
    pub cursor: Option<Option<u64>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub record_id: u64,
    pub xml: String,
}

fn str_of(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

impl FromDaemon {
    pub fn to_line(&self) -> String {
        match self {
            FromDaemon::Hello { protocol } => json!({"op": "hello", "protocol": protocol}),
            FromDaemon::Claim { process_guid, chat } => {
                json!({"op": "claim", "processGuid": process_guid, "chat": chat})
            }
            FromDaemon::Ack { record_id } => json!({"op": "ack", "recordId": record_id}),
        }
        .to_string()
    }

    /// A daemon line, or why it is not one. Unknown fields are ignored; an
    /// unknown `op` is an error.
    pub fn parse(line: &str) -> Result<FromDaemon, String> {
        let v: Value = serde_json::from_str(line).map_err(|_| "not a JSON line".to_string())?;
        match v.get("op").and_then(Value::as_str) {
            Some("hello") => Ok(FromDaemon::Hello {
                protocol: v
                    .get("protocol")
                    .and_then(Value::as_u64)
                    .ok_or("hello without a protocol")?,
            }),
            Some("claim") => Ok(FromDaemon::Claim {
                process_guid: str_of(&v, "processGuid").ok_or("claim without a processGuid")?,
                chat: str_of(&v, "chat").ok_or("claim without a chat")?,
            }),
            Some("ack") => Ok(FromDaemon::Ack {
                record_id: v
                    .get("recordId")
                    .and_then(Value::as_u64)
                    .ok_or("ack without a recordId")?,
            }),
            Some(other) => Err(format!(
                "unknown op {:?}",
                other.chars().take(32).collect::<String>()
            )),
            None => Err("a line without an op".into()),
        }
    }
}

impl FromService {
    pub fn to_line(&self) -> String {
        match self {
            FromService::Reply(r) => {
                let mut m = serde_json::Map::new();
                m.insert("ok".into(), Value::Bool(r.ok));
                if let Some(p) = r.protocol {
                    m.insert("protocol".into(), json!(p));
                }
                if let Some(u) = &r.user {
                    m.insert("user".into(), json!(u));
                }
                if let Some(c) = r.cursor {
                    m.insert("cursor".into(), json!(c));
                }
                if let Some(e) = &r.error {
                    m.insert("error".into(), json!(e));
                }
                Value::Object(m)
            }
            FromService::Events(records) => json!({
                "op": "events",
                "records": records
                    .iter()
                    .map(|r| json!({"recordId": r.record_id, "xml": r.xml}))
                    .collect::<Vec<_>>(),
            }),
            FromService::Gap { from, to, reason } => {
                json!({"op": "gap", "from": from, "to": to, "reason": reason})
            }
        }
        .to_string()
    }

    pub fn parse(line: &str) -> Result<FromService, String> {
        let v: Value = serde_json::from_str(line).map_err(|_| "not a JSON line".to_string())?;
        match v.get("op").and_then(Value::as_str) {
            None => Ok(FromService::Reply(Reply {
                ok: v
                    .get("ok")
                    .and_then(Value::as_bool)
                    .ok_or("a reply without ok")?,
                protocol: v.get("protocol").and_then(Value::as_u64),
                user: str_of(&v, "user"),
                cursor: v.get("cursor").map(Value::as_u64),
                error: str_of(&v, "error"),
            })),
            Some("events") => {
                let records = v
                    .get("records")
                    .and_then(Value::as_array)
                    .ok_or("events without records")?
                    .iter()
                    .map(|r| {
                        Ok(Record {
                            record_id: r
                                .get("recordId")
                                .and_then(Value::as_u64)
                                .ok_or("a record without a recordId")?,
                            xml: str_of(r, "xml").ok_or("a record without xml")?,
                        })
                    })
                    .collect::<Result<Vec<_>, &str>>()?;
                Ok(FromService::Events(records))
            }
            Some("gap") => Ok(FromService::Gap {
                from: v
                    .get("from")
                    .and_then(Value::as_u64)
                    .ok_or("gap without from")?,
                to: v
                    .get("to")
                    .and_then(Value::as_u64)
                    .ok_or("gap without to")?,
                reason: str_of(&v, "reason")
                    .unwrap_or_default()
                    .chars()
                    .take(200)
                    .collect(),
            }),
            Some(other) => Err(format!(
                "unknown op {:?}",
                other.chars().take(32).collect::<String>()
            )),
        }
    }
}

/// Reads one line, without its line end, of at most `max` bytes with it.
/// `Ok(None)` at the end of the stream; an error for a longer line, a line
/// that is not UTF-8, or a stream that ends inside a line.
pub fn read_line(r: &mut impl BufRead, max: usize) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the stream ended inside a line",
                ))
            };
        }
        let (take, done) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if buf.len() + take > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a line longer than {max} bytes"),
            ));
        }
        buf.extend_from_slice(&chunk[..take]);
        r.consume(take);
        if done {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return String::from_utf8(buf).map(Some).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "a line that is not UTF-8")
            });
        }
    }
}

/// How many bytes `xml` takes inside a JSON string.
fn escaped_len(xml: &str) -> usize {
    serde_json::to_string(xml).map_or(usize::MAX, |s| s.len())
}

/// Cuts records into `events` lines that each stay under the line limit.
/// A record that alone would not fit is not sent: its id is returned
/// beside the batches, for a `gap` line (it is never cut short).
pub fn batches(records: Vec<Record>) -> (Vec<Vec<Record>>, Vec<u64>) {
    let mut out: Vec<Vec<Record>> = Vec::new();
    let mut too_big = Vec::new();
    let mut cur: Vec<Record> = Vec::new();
    let mut bytes = 0usize;
    for r in records {
        let n = escaped_len(&r.xml);
        if n > MAX_BATCH_BYTES {
            too_big.push(r.record_id);
            continue;
        }
        if !cur.is_empty() && (cur.len() >= MAX_BATCH || bytes + n > MAX_BATCH_BYTES) {
            out.push(std::mem::take(&mut cur));
            bytes = 0;
        }
        bytes += n;
        cur.push(r);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    (out, too_big)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange() -> Vec<(String, Value)> {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/fixtures/sysmon-service/exchange.jsonl"
        ))
        .unwrap();
        text.lines()
            .map(|l| {
                let v: Value = serde_json::from_str(l).unwrap();
                (v["from"].as_str().unwrap().to_string(), v["line"].clone())
            })
            .collect()
    }

    #[test]
    fn the_contracts_exchange_reads_and_writes_back_the_same() {
        let lines = exchange();
        assert_eq!(lines.len(), 7);
        for (from, line) in lines {
            let text = line.to_string();
            let again: Value = if from == "daemon" {
                serde_json::from_str(&FromDaemon::parse(&text).unwrap().to_line()).unwrap()
            } else {
                serde_json::from_str(&FromService::parse(&text).unwrap().to_line()).unwrap()
            };
            assert_eq!(again, line, "{from}: {text}");
        }
    }

    #[test]
    fn a_hello_reply_with_no_cursor_keeps_its_null() {
        let r = FromService::parse(
            r#"{"ok":true,"protocol":1,"user":"S-1-5-21-1-2-3-1001","cursor":null}"#,
        )
        .unwrap();
        let FromService::Reply(r) = r else { panic!() };
        assert_eq!(r.cursor, Some(None));
        let r = FromService::parse(r#"{"ok":true}"#).unwrap();
        let FromService::Reply(r) = r else { panic!() };
        assert_eq!(r.cursor, None);
    }

    #[test]
    fn a_daemon_line_with_an_unknown_op_or_no_op_is_refused() {
        assert!(FromDaemon::parse(r#"{"op":"events","records":[]}"#).is_err());
        assert!(FromDaemon::parse(r#"{"ok":true}"#).is_err());
        assert!(FromDaemon::parse("hello").is_err());
        assert!(FromDaemon::parse(r#"{"op":"ack","recordId":-1}"#).is_err());
    }

    #[test]
    fn a_line_over_the_limit_is_an_error_not_a_bigger_buffer() {
        let long = [b'a'; 100];
        let mut r = io::BufReader::with_capacity(8, &long[..]);
        assert_eq!(
            read_line(&mut r, 50).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut r = io::BufReader::with_capacity(8, &b"abc\r\ndef\n"[..]);
        assert_eq!(read_line(&mut r, 50).unwrap().as_deref(), Some("abc"));
        assert_eq!(read_line(&mut r, 50).unwrap().as_deref(), Some("def"));
        assert_eq!(read_line(&mut r, 50).unwrap(), None);
        let mut r = io::BufReader::new(&b"half"[..]);
        assert_eq!(
            read_line(&mut r, 50).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn batches_stay_under_the_line_limit_even_after_escaping() {
        let big = "\"".repeat(200 * 1024);
        let mut records: Vec<Record> = (0..20)
            .map(|i| Record {
                record_id: i,
                xml: big.clone(),
            })
            .collect();
        // Control characters escape to six bytes each.
        records.push(Record {
            record_id: 99,
            xml: "\u{1}".repeat(100 * 1024),
        });
        let (lines, too_big) = batches(records);
        assert_eq!(too_big, vec![99]);
        assert_eq!(lines.iter().map(Vec::len).sum::<usize>(), 20);
        for b in lines {
            let line = FromService::Events(b).to_line();
            assert!(line.len() < MAX_LINE, "{}", line.len());
        }
        let many: Vec<Record> = (0..1000)
            .map(|i| Record {
                record_id: i,
                xml: "x".into(),
            })
            .collect();
        let (b, _) = batches(many);
        assert_eq!(b.len(), 4);
        assert_eq!(b.iter().map(Vec::len).sum::<usize>(), 1000);
    }
}
