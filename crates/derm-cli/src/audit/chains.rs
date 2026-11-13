//! Reading a chain line by line under the rule its lines carry: chain v2
//! (`derm_core::audit_chain`, the light tier's log and what a v2 export
//! holds) or v1 (the daemon's activity log, `derm_daemon::activity::chain`).
//! Each line is checked by the reference function of its version, one line
//! at a time with the `seq` and `prev` the line before it left, so the two
//! rules stay the references' own and a withheld line (below) can sit in a
//! chain without its record.
//!
//! A **withheld** line is how `derm audit export` leaves out a record that
//! holds content when the person did not ask for it (`contracts/events.md`
//! section 6.5, E1, case 221): `{"v":<1|2>,"seq":..,"prev":..,"hash":..,
//! "withheld":"content"}`. Its hash cannot be checked without its record, so
//! it is taken as claimed and counted; the line after it must still follow
//! it, so an edit anywhere else still shows.

use std::collections::BTreeMap;

use derm_core::audit_chain;
use derm_daemon::activity::chain as v1;
use serde_json::{Map, Value};

/// The keys of a v1 line's record (`derm-daemon/src/activity/store.rs`).
pub const V1_KEYS: &[&str] = &["event", "approval"];

/// The `withheld` value of a line export left out for its content.
pub const WITHHELD: &str = "content";

/// Which rule a line is read under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

impl Version {
    pub fn number(self) -> u64 {
        match self {
            Version::V1 => 1,
            Version::V2 => 2,
        }
    }

    /// The `seq` a chain begins at: the daemon's writer starts at 1
    /// (`store.rs`, `ChainWriter::write`), chain v2 at 0.
    pub fn first_seq(self) -> u64 {
        match self {
            Version::V1 => 1,
            Version::V2 => 0,
        }
    }
}

/// One line read and checked.
#[derive(Clone, Debug, PartialEq)]
pub struct Read {
    pub seq: u64,
    pub prev: String,
    pub hash: String,
    /// The v2 kind, or the v1 key (`event`, `approval`).
    pub kind: String,
    /// `None` for a withheld line.
    pub record: Option<Value>,
}

/// Where a chain broke.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Broken {
    /// From 1, over every line given.
    pub line: usize,
    pub why: String,
}

/// A chain read to its end or its first break.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub version: Option<Version>,
    /// Lines read before the break (all of them when it holds).
    pub links: Vec<Read>,
    pub broken: Option<Broken>,
    pub withheld: usize,
}

impl Report {
    #[cfg(test)]
    pub fn holds(&self) -> bool {
        self.broken.is_none()
    }
    pub fn first(&self) -> Option<&Read> {
        self.links.first()
    }
    pub fn last(&self) -> Option<&Read> {
        self.links.last()
    }
    /// The link at `seq`, if the chain read reached it.
    pub fn at(&self, seq: u64) -> Option<&Read> {
        let first = self.first()?.seq;
        let i = usize::try_from(seq.checked_sub(first)?).ok()?;
        self.links.get(i).filter(|l| l.seq == seq)
    }
}

/// The rule a line names: `v` 2 is chain v2; `v` 1, or no `v` and a v1 key,
/// is v1.
pub fn version_of(o: &Map<String, Value>) -> Option<Version> {
    match o.get("v") {
        Some(v) if v.as_u64() == Some(2) => Some(Version::V2),
        Some(v) if v.as_u64() == Some(1) => Some(Version::V1),
        Some(_) => None,
        None if V1_KEYS.iter().any(|k| o.contains_key(*k)) => Some(Version::V1),
        None if o.get("withheld").is_some() => Some(Version::V1),
        None => None,
    }
}

fn is_hash(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Reads `lines` as one chain. `start`: the `seq` and `prev` the first line
/// must have; `None` means a chain from the genesis `prev` at the version's
/// first `seq`.
pub fn read(lines: &[&str], start: Option<(u64, &str)>) -> Report {
    let mut r = Report::default();
    let mut want: Option<(u64, String)> = start.map(|(s, p)| (s, p.to_string()));
    for (i, text) in lines.iter().enumerate() {
        let n = i + 1;
        let fail = |why: String| Broken { line: n, why };
        let o = match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(o)) => o,
            Ok(_) => {
                r.broken = Some(fail("not a JSON object".into()));
                break;
            }
            Err(_) if n == lines.len() => {
                r.broken = Some(fail(
                    "the last line is cut short (a killed writer leaves this; so does a cut)"
                        .into(),
                ));
                break;
            }
            Err(e) => {
                r.broken = Some(fail(format!("not JSON: {e}")));
                break;
            }
        };
        let Some(version) = version_of(&o) else {
            r.broken = Some(fail("not a chain line (no v1 key and no \"v\": 2)".into()));
            break;
        };
        match r.version {
            None => r.version = Some(version),
            Some(v) if v != version => {
                r.broken = Some(fail(format!(
                    "a v{} line in a v{} chain",
                    version.number(),
                    v.number()
                )));
                break;
            }
            Some(_) => {}
        }
        let (want_seq, want_prev) = want
            .clone()
            .unwrap_or((version.first_seq(), audit_chain::GENESIS.to_string()));
        let link = if o.contains_key("withheld") {
            withheld(&o, version)
        } else {
            match version {
                Version::V2 => {
                    match audit_chain::verify(&[*text], Some((want_seq, &want_prev)), None) {
                        Ok(Some(l)) => Ok(Read {
                            seq: l.seq,
                            prev: l.prev,
                            hash: l.hash,
                            kind: l.kind,
                            record: Some(l.record),
                        }),
                        Ok(None) => Err("empty".to_string()),
                        Err(b) => Err(b.why),
                    }
                }
                Version::V1 => v1_line(text),
            }
        };
        let link = match link {
            Ok(l) => l,
            Err(why) => {
                r.broken = Some(fail(why));
                break;
            }
        };
        if link.seq != want_seq {
            r.broken = Some(fail(format!("seq {} where {} was due", link.seq, want_seq)));
            break;
        }
        if link.prev != want_prev {
            r.broken = Some(fail("prev is not the hash of the line before".into()));
            break;
        }
        if link.record.is_none() {
            r.withheld += 1;
        }
        want = Some((link.seq + 1, link.hash.clone()));
        r.links.push(link);
    }
    r
}

fn v1_line(text: &str) -> Result<Read, String> {
    let l = v1::parse_line(text, V1_KEYS).ok_or("not a v1 chain line")?;
    if v1::link_hash(&l.prev, &l.record) != l.hash {
        return Err("hash does not match the line".into());
    }
    Ok(Read {
        seq: l.seq,
        prev: l.prev,
        hash: l.hash,
        kind: l.key,
        record: Some(l.record),
    })
}

fn withheld(o: &Map<String, Value>, version: Version) -> Result<Read, String> {
    let allowed: &[&str] = &["v", "seq", "prev", "hash", "kind", "withheld"];
    if o.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err("a withheld line holds only v, seq, prev, hash, kind and withheld".into());
    }
    if o.get("withheld").and_then(Value::as_str) != Some(WITHHELD) {
        return Err("a withheld line says \"withheld\": \"content\"".into());
    }
    if version == Version::V2 && o.get("v").and_then(Value::as_u64) != Some(2) {
        return Err("bad withheld line".into());
    }
    let seq = o.get("seq").and_then(Value::as_u64).ok_or("no seq")?;
    let prev = o.get("prev").and_then(Value::as_str).ok_or("no prev")?;
    let hash = o.get("hash").and_then(Value::as_str).ok_or("no hash")?;
    if !is_hash(prev) || !is_hash(hash) {
        return Err("bad prev or hash".into());
    }
    let kind = o
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("withheld")
        .to_string();
    Ok(Read {
        seq,
        prev: prev.into(),
        hash: hash.into(),
        kind,
        record: None,
    })
}

/// Whether a record holds content: an attribute the daemon's receiver counts
/// as prompt, reply or a call's arguments or result
/// (`otel_receiver::normalize::is_prompt_text`), with a value that is not a
/// harness's redaction mark. Today's daemon keeps none in a record (content
/// goes to content files, `contracts/events.md` section 5); a log from before
/// the content switch (`DERM_LOG_CONTENT=1`) can hold them.
pub fn holds_content(record: &Value) -> bool {
    fn walk(v: &Value, depth: usize) -> bool {
        if depth > 16 {
            return true; // unreadable depth: treat as content, the safe side
        }
        match v {
            Value::Object(o) => o.iter().any(|(k, v)| {
                (derm_daemon::otel_receiver::normalize::is_prompt_text(k) && is_text(v))
                    || walk(v, depth + 1)
            }),
            Value::Array(a) => a.iter().any(|v| walk(v, depth + 1)),
            _ => false,
        }
    }
    fn is_text(v: &Value) -> bool {
        match v {
            Value::Null => false,
            Value::String(s) => {
                let t = s.trim();
                !(t.is_empty() || t == "<REDACTED>" || t == "[REDACTED]")
            }
            Value::Bool(_) | Value::Number(_) => false,
            _ => true,
        }
    }
    walk(record, 0)
}

/// The withheld form of a line, as export writes it.
pub fn withheld_line(version: Version, link: &Read) -> String {
    let mut o: BTreeMap<&str, Value> = BTreeMap::new();
    o.insert("v", Value::from(version.number()));
    o.insert("seq", Value::from(link.seq));
    o.insert("prev", Value::from(link.prev.clone()));
    o.insert("hash", Value::from(link.hash.clone()));
    if version == Version::V2 {
        o.insert("kind", Value::from(link.kind.clone()));
    }
    o.insert("withheld", Value::from(WITHHELD));
    serde_json::to_string(&o).unwrap_or_default()
}

/// A v1 line as export writes it: the daemon's line with `"v": 1` added.
/// The v1 hash covers `prev` and the record only, so the added key changes
/// nothing it checks.
pub fn v1_export_line(link: &Read) -> String {
    let mut o = Map::new();
    o.insert("v".into(), Value::from(1));
    o.insert("seq".into(), Value::from(link.seq));
    o.insert("prev".into(), Value::from(link.prev.clone()));
    o.insert("hash".into(), Value::from(link.hash.clone()));
    o.insert(
        link.kind.clone(),
        link.record.clone().unwrap_or(Value::Null),
    );
    Value::Object(o).to_string()
}

/// `<seq>:<hex64>`, as `--start` and `--anchor` take it.
pub fn parse_mark(text: &str) -> Result<(u64, String), String> {
    let (s, h) = text
        .split_once(':')
        .ok_or_else(|| format!("{text:?}: give <seq>:<hash>"))?;
    let seq = s
        .parse::<u64>()
        .map_err(|_| format!("{text:?}: the seq is not a number"))?;
    if !is_hash(h) {
        return Err(format!("{text:?}: the hash is 64 lowercase hex digits"));
    }
    Ok((seq, h.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub fn v2_chain(n: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut last = None;
        for i in 0..n {
            let (t, l) = audit_chain::line(
                last.as_ref(),
                if i % 2 == 0 { "approval" } else { "tool.call" },
                &json!({"i": i, "chatId": "c", "detail": {"toolUseId": format!("t{i}")}}),
            )
            .unwrap();
            out.push(t);
            last = Some(l);
        }
        out
    }

    pub fn v1_chain(records: &[Value]) -> Vec<String> {
        let mut prev = v1::GENESIS.to_string();
        records
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let (t, h) = v1::line(i as u64 + 1, &prev, "event", r);
                prev = h;
                t
            })
            .collect()
    }

    fn refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn a_v2_chain_holds_and_an_edit_breaks_it_where_the_reference_does() {
        let c = v2_chain(4);
        let r = read(&refs(&c), None);
        assert!(r.holds());
        assert_eq!(r.version, Some(Version::V2));
        assert_eq!(r.last().unwrap().seq, 3);
        let mut e = c.clone();
        e[2] = e[2].replace("\"i\":2", "\"i\":7");
        let r = read(&refs(&e), None);
        assert_eq!(r.broken.unwrap().line, 3);
        let reference = audit_chain::verify(&refs(&e), None, None).unwrap_err();
        assert_eq!(reference.line, 3);
    }

    #[test]
    fn a_v1_chain_holds_with_or_without_the_export_mark() {
        let c = v1_chain(&[json!({"id": "a"}), json!({"id": "b"}), json!({"id": "c"})]);
        assert!(read(&refs(&c), None).holds());
        let r = read(&refs(&c), None);
        let marked: Vec<String> = r.links.iter().map(v1_export_line).collect();
        let r2 = read(&refs(&marked), None);
        assert!(r2.holds(), "{:?}", r2.broken);
        assert_eq!(r2.version, Some(Version::V1));
        // An edited record under the mark still breaks.
        let mut e = marked.clone();
        e[1] = e[1].replace("\"b\"", "\"x\"");
        assert_eq!(read(&refs(&e), None).broken.unwrap().line, 2);
    }

    #[test]
    fn a_v1_relabel_that_v1_misses_is_not_claimed_as_caught() {
        // v1 hashes neither seq nor the key (note AZ, B6): an event relabelled
        // as an approval still verifies under the v1 rule. Recorded so the
        // export's v1 lines are never described as stronger than they are.
        let c = v1_chain(&[json!({"id": "a"}), json!({"id": "b"})]);
        let mut e = c.clone();
        e[1] = e[1].replace("\"event\":", "\"approval\":");
        assert!(read(&refs(&e), None).holds());
    }

    #[test]
    fn a_withheld_line_keeps_the_chain_and_an_edit_after_it_still_shows() {
        let c = v2_chain(4);
        let r = read(&refs(&c), None);
        let mut w = c.clone();
        w[1] = withheld_line(Version::V2, &r.links[1]);
        let r2 = read(&refs(&w), None);
        assert!(r2.holds(), "{:?}", r2.broken);
        assert_eq!(r2.withheld, 1);
        assert_eq!(r2.links[1].record, None);
        let mut e = w.clone();
        e[2] = e[2].replace("\"i\":2", "\"i\":5");
        assert_eq!(read(&refs(&e), None).broken.unwrap().line, 3);
        // A withheld line that claims another hash breaks the next line.
        let mut f = w.clone();
        f[1] = f[1].replace(&r.links[1].hash, &"a".repeat(64));
        assert_eq!(read(&refs(&f), None).broken.unwrap().line, 3);
        // A withheld line may carry nothing else.
        let mut g = w.clone();
        g[1] = g[1].replace("\"withheld\"", "\"prompt\":\"x\",\"withheld\"");
        assert_eq!(read(&refs(&g), None).broken.unwrap().line, 2);
    }

    #[test]
    fn versions_do_not_mix_and_a_cut_last_line_is_named() {
        let a = v2_chain(2);
        let b = v1_chain(&[json!({"id": "a"})]);
        let mixed = vec![a[0].clone(), b[0].clone()];
        assert!(read(&refs(&mixed), None)
            .broken
            .unwrap()
            .why
            .contains("v1 line"));
        let mut cut = a.clone();
        cut[1] = cut[1][..20].to_string();
        let r = read(&refs(&cut), None);
        assert!(r.broken.unwrap().why.contains("cut short"));
    }

    #[test]
    fn a_start_is_required_for_a_chain_that_does_not_begin_at_genesis() {
        let c = v2_chain(4);
        assert_eq!(read(&refs(&c[2..]), None).broken.unwrap().line, 1);
        let p = audit_chain::parse(&c[1]).unwrap();
        assert!(read(&refs(&c[2..]), Some((2, &p.hash))).holds());
        let r = read(&refs(&c[2..]), Some((2, &p.hash)));
        assert_eq!(r.at(3).unwrap().seq, 3);
        assert!(r.at(1).is_none());
        assert!(r.at(9).is_none());
    }

    #[test]
    fn content_is_found_where_the_receiver_names_it_and_marks_are_not_content() {
        assert!(holds_content(
            &json!({"detail": {"attributes": {"prompt": "hi"}}})
        ));
        assert!(holds_content(
            &json!({"detail": {"attributes": {"tool_parameters": "{}"}}})
        ));
        assert!(holds_content(
            &json!({"detail": {"x": [{"output": "secret"}]}})
        ));
        assert!(!holds_content(
            &json!({"detail": {"attributes": {"prompt": "<REDACTED>"}}})
        ));
        assert!(!holds_content(
            &json!({"detail": {"attributes": {"response": "[REDACTED]"}}})
        ));
        assert!(!holds_content(
            &json!({"detail": {"promptLength": 12, "resultSha256": "ab"}})
        ));
        let mut deep = json!("x");
        for _ in 0..20 {
            deep = json!({ "a": deep });
        }
        assert!(holds_content(&deep));
    }

    #[test]
    fn marks_parse_strictly() {
        let h = "a".repeat(64);
        assert_eq!(parse_mark(&format!("4:{h}")).unwrap(), (4, h.clone()));
        assert!(parse_mark(&h).is_err());
        assert!(parse_mark(&format!("x:{h}")).is_err());
        assert!(parse_mark("4:ABC").is_err());
        assert!(parse_mark(&format!("4:{}", "A".repeat(64))).is_err());
    }
}
