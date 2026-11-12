//! The chain v2 line format (wave 6; `contracts/events.md` section 6.4),
//! written by the wave 6 base as the contract's reference so lanes 6B (the
//! light tier's writer) and 6E (`derm audit verify`, export and anchor)
//! build against one format. Lanes change it only through a request.
//!
//! Why a second format (note AZ, B6 and AZ-1): the daemon's v1 chain
//! (`derm-daemon/src/activity/chain.rs`) hashes `prev` and the record only,
//! so a relabelled key or a whole-file consistent renumber still verifies,
//! and `verify` takes no expected end, so a cut at the tail verifies too.
//! v2 hashes the format tag, `seq`, `prev`, the kind and the record, and
//! [`verify`] takes the start and the end an anchor recorded.
//!
//! A line is one JSON object on one line:
//! `{"v":2,"seq":<n>,"prev":"<hex64>","kind":"<kind>","hash":"<hex64>","record":<object>}`,
//! and `hash` is SHA-256 over
//! `derm-chain-v2\n<seq in decimal>\n<prev>\n<kind>\n<record as serde_json::to_string>`.
//! serde_json here keeps keys sorted (no `preserve_order`; note AZ, E2), so
//! the record is hashed in its canonical form whatever order a writer used.
//! A record holds no floating-point number: other JSON writers print floats
//! differently (`1.5e-7` against `1.5e-07`, note AZ E2), so [`line`] refuses
//! one. The first line of a chain has `prev` [`GENESIS`] and `seq` 0.
//!
//! What the chain proves and what it does not (case 216): a file the agent
//! can write shows an edited, dropped, reordered or relabelled line, and a
//! cut anywhere but the end; a cut at the end, or a whole rewrite with a
//! fresh chain, shows only against an anchor (the head's `seq` and `hash`
//! kept where the agent cannot write, lane 6E).

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The format tag, the `v` of every line.
pub const VERSION: u64 = 2;

/// The `prev` of a chain's first line.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A line's kind: lowercase ASCII words joined by `.` (`approval`,
/// `tool.call`, `install.call`, `taint.mark`), at most 64 bytes.
pub fn kind_ok(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= 64
        && kind
            .split('.')
            .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
}

fn has_float(v: &Value) -> bool {
    match v {
        Value::Number(n) => !(n.is_i64() || n.is_u64()),
        Value::Array(a) => a.iter().any(has_float),
        Value::Object(o) => o.values().any(has_float),
        _ => false,
    }
}

/// The hash of one line.
pub fn hash(seq: u64, prev: &str, kind: &str, record: &Value) -> String {
    let body = serde_json::to_string(record).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(b"derm-chain-v2\n");
    h.update(seq.to_string().as_bytes());
    h.update(b"\n");
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(kind.as_bytes());
    h.update(b"\n");
    h.update(body.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0xf) as usize] as char);
    }
    out
}

fn is_hash(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One line read back.
#[derive(Clone, Debug, PartialEq)]
pub struct Link {
    pub seq: u64,
    pub prev: String,
    pub kind: String,
    pub hash: String,
    pub record: Value,
}

/// The line after `last` (or the first, with `None`), without its newline,
/// and its link. Refuses a bad kind, a record that is not an object, and a
/// record that holds a float.
pub fn line(last: Option<&Link>, kind: &str, record: &Value) -> Result<(String, Link), String> {
    if !kind_ok(kind) {
        return Err(format!("chain v2: bad kind {kind:?}"));
    }
    if !record.is_object() {
        return Err("chain v2: a record is a JSON object".into());
    }
    if has_float(record) {
        return Err("chain v2: a record holds no floating-point number".into());
    }
    let (seq, prev) = match last {
        Some(l) => (l.seq + 1, l.hash.clone()),
        None => (0, GENESIS.to_string()),
    };
    let h = hash(seq, &prev, kind, record);
    let mut o = Map::new();
    o.insert("v".into(), Value::from(VERSION));
    o.insert("seq".into(), Value::from(seq));
    o.insert("prev".into(), Value::from(prev.clone()));
    o.insert("kind".into(), Value::from(kind));
    o.insert("hash".into(), Value::from(h.clone()));
    o.insert("record".into(), record.clone());
    let link = Link {
        seq,
        prev,
        kind: kind.into(),
        hash: h,
        record: record.clone(),
    };
    Ok((Value::Object(o).to_string(), link))
}

/// Reads one line. Every field is required and nothing else is allowed.
pub fn parse(text: &str) -> Result<Link, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let o = v.as_object().ok_or("not an object")?;
    if o.len() != 6 {
        return Err("a line has exactly v, seq, prev, kind, hash and record".into());
    }
    if o.get("v").and_then(Value::as_u64) != Some(VERSION) {
        return Err("not a chain v2 line".into());
    }
    let seq = o.get("seq").and_then(Value::as_u64).ok_or("no seq")?;
    let prev = o.get("prev").and_then(Value::as_str).ok_or("no prev")?;
    let kind = o.get("kind").and_then(Value::as_str).ok_or("no kind")?;
    let h = o.get("hash").and_then(Value::as_str).ok_or("no hash")?;
    let record = o
        .get("record")
        .filter(|r| r.is_object())
        .ok_or("no record")?;
    if !is_hash(prev) || !is_hash(h) || !kind_ok(kind) {
        return Err("bad prev, hash or kind".into());
    }
    Ok(Link {
        seq,
        prev: prev.into(),
        kind: kind.into(),
        hash: h.into(),
        record: record.clone(),
    })
}

/// Where a chain broke, by line number from 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Break {
    pub line: usize,
    pub why: String,
}

/// What an anchor recorded: a link's `seq` and `hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mark {
    pub seq: u64,
    pub hash: String,
}

/// Verifies `lines` (without newlines; empty lines are an error). `start`:
/// the `seq` and `prev` the first line must have (a day file's first `prev`
/// from an anchor; `None` means a chain from [`GENESIS`] at `seq` 0).
/// `end`: the last line must be this mark (an anchored head), else a cut at
/// the end is not seen. Returns the last link.
pub fn verify(
    lines: &[&str],
    start: Option<(u64, &str)>,
    end: Option<&Mark>,
) -> Result<Option<Link>, Break> {
    let (mut want_seq, mut want_prev) = match start {
        Some((s, p)) => (s, p.to_string()),
        None => (0, GENESIS.to_string()),
    };
    let mut last: Option<Link> = None;
    for (i, text) in lines.iter().enumerate() {
        let n = i + 1;
        let l = parse(text).map_err(|why| Break { line: n, why })?;
        if l.seq != want_seq {
            return Err(Break {
                line: n,
                why: format!("seq {} where {} was due", l.seq, want_seq),
            });
        }
        if l.prev != want_prev {
            return Err(Break {
                line: n,
                why: "prev is not the hash of the line before".into(),
            });
        }
        if hash(l.seq, &l.prev, &l.kind, &l.record) != l.hash {
            return Err(Break {
                line: n,
                why: "hash does not match the line".into(),
            });
        }
        want_seq = l.seq + 1;
        want_prev = l.hash.clone();
        last = Some(l);
    }
    if let Some(m) = end {
        let ok = last
            .as_ref()
            .is_some_and(|l| l.seq == m.seq && l.hash == m.hash);
        if !ok {
            return Err(Break {
                line: lines.len(),
                why: format!("the chain does not end at the anchored seq {}", m.seq),
            });
        }
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chain(n: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut last: Option<Link> = None;
        for i in 0..n {
            let (text, link) = line(
                last.as_ref(),
                if i % 2 == 0 { "approval" } else { "tool.call" },
                &json!({"tool": "bash", "i": i, "decision": "allow"}),
            )
            .unwrap();
            out.push(text);
            last = Some(link);
        }
        out
    }

    fn refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn a_chain_verifies_and_its_head_is_its_last_line() {
        let c = chain(5);
        let last = verify(&refs(&c), None, None).unwrap().unwrap();
        assert_eq!(last.seq, 4);
        let m = Mark {
            seq: 4,
            hash: last.hash.clone(),
        };
        assert!(verify(&refs(&c), None, Some(&m)).is_ok());
    }

    #[test]
    fn the_hash_covers_seq_kind_and_record_and_keys_are_canonical() {
        let r1 = json!({"b": 1, "a": "x"});
        let r2: Value = serde_json::from_str(r#"{"a":"x","b":1}"#).unwrap();
        assert_eq!(
            hash(0, GENESIS, "approval", &r1),
            hash(0, GENESIS, "approval", &r2)
        );
        assert_ne!(
            hash(0, GENESIS, "approval", &r1),
            hash(1, GENESIS, "approval", &r1)
        );
        assert_ne!(
            hash(0, GENESIS, "approval", &r1),
            hash(0, GENESIS, "event", &r1)
        );
    }

    #[test]
    fn edits_cuts_reorders_relabels_and_renumbers_break_it() {
        let c = chain(5);
        // An edited record.
        let mut e = c.clone();
        e[2] = e[2].replace("\"i\":2", "\"i\":9");
        assert_eq!(verify(&refs(&e), None, None).unwrap_err().line, 3);
        // A dropped line in the middle.
        let mut d = c.clone();
        d.remove(2);
        assert_eq!(verify(&refs(&d), None, None).unwrap_err().line, 3);
        // Two lines swapped.
        let mut s = c.clone();
        s.swap(1, 2);
        assert_eq!(verify(&refs(&s), None, None).unwrap_err().line, 2);
        // A relabelled kind (v1 let this through, note AZ B6).
        let mut k = c.clone();
        k[1] = k[1].replace("\"kind\":\"tool.call\"", "\"kind\":\"approval\"");
        assert_eq!(verify(&refs(&k), None, None).unwrap_err().line, 2);
        // A head cut needs the start: without it the rest is a new chain only
        // if its first seq is 0, which it is not.
        assert_eq!(verify(&refs(&c[2..]), None, None).unwrap_err().line, 1);
        let p = parse(&c[1]).unwrap();
        assert!(verify(&refs(&c[2..]), Some((2, p.hash.as_str())), None).is_ok());
    }

    #[test]
    fn a_tail_cut_shows_only_against_an_anchor() {
        let c = chain(5);
        let head = parse(&c[4]).unwrap();
        let m = Mark {
            seq: head.seq,
            hash: head.hash,
        };
        assert!(verify(&refs(&c[..3]), None, None).is_ok());
        assert!(verify(&refs(&c[..3]), None, Some(&m)).is_err());
    }

    #[test]
    fn line_refuses_floats_bad_kinds_and_non_objects() {
        assert!(line(None, "approval", &json!({"x": 1.5})).is_err());
        assert!(line(None, "Approval", &json!({})).is_err());
        assert!(line(None, "a..b", &json!({})).is_err());
        assert!(line(None, "approval", &json!([1])).is_err());
        assert!(line(None, "taint.mark", &json!({"x": -3})).is_ok());
    }

    #[test]
    fn parse_refuses_extra_or_missing_fields() {
        let c = chain(1);
        let mut v: Value = serde_json::from_str(&c[0]).unwrap();
        v["extra"] = json!(1);
        assert!(parse(&v.to_string()).is_err());
        v.as_object_mut().unwrap().remove("extra");
        v.as_object_mut().unwrap().remove("kind");
        assert!(parse(&v.to_string()).is_err());
    }

    /// `contracts/fixtures/audit/chain-v2.jsonl` is this module's output, and
    /// each tampered copy beside it breaks where its file says.
    #[test]
    fn the_contract_fixtures_are_this_modules_output() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/fixtures/audit");
        let good = std::fs::read_to_string(dir.join("chain-v2.jsonl")).unwrap();
        let lines: Vec<&str> = good.lines().collect();
        let last = verify(&lines, None, None).unwrap().unwrap();
        let cases: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("tampered.json")).unwrap())
                .unwrap();
        let m = Mark {
            seq: last.seq,
            hash: last.hash,
        };
        for c in cases["cases"].as_array().unwrap() {
            let text: Vec<&str> = c["lines"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_str().unwrap())
                .collect();
            let r = verify(&text, None, Some(&m));
            assert_eq!(
                r.err().map(|b| b.line as u64),
                c["breaksAt"].as_u64(),
                "{}",
                c["name"]
            );
        }
    }
}
