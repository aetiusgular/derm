//! `derm audit verify`: checks a chain with no daemon (E2). Exit 0 when the
//! chain holds and every anchor given still matches, 1 with the first broken
//! line or the first anchor that no longer matches, 2 on a usage or read
//! error (`contracts/events.md` section 6.5).
//!
//! An anchor is checked as a prefix (OpenMoat 0.19.0, ADR-031,
//! `anchor::check`): the anchored line must still be in the chain with the
//! hash it had. Lines written after it are not a break, so a log that grew
//! since it was anchored still verifies; a cut at or before the anchored
//! line, or a whole rewrite, does not (case 216).

use serde_json::{json, Value};

use super::anchor::{Place, Record};
use super::chains::{self, Report, Version};
use super::sources::{self, Line, Source};

/// What one chain's check found.
#[derive(Debug, Default)]
pub struct Outcome {
    pub label: String,
    pub describe: String,
    pub files: Vec<std::path::PathBuf>,
    pub lines: Vec<Line>,
    pub report: Report,
    /// The first failure: (line index from 1 over `lines`, why). A line 0
    /// means the chain as a whole (an anchor past its end).
    pub failure: Option<(usize, String)>,
    pub notes: Vec<String>,
    pub start_used: Option<(u64, String)>,
}

impl Outcome {
    pub fn holds(&self) -> bool {
        self.failure.is_none()
    }

    /// `<file>:<line>` for a line index from 1.
    pub fn place(&self, n: usize) -> String {
        match self.lines.get(n.wrapping_sub(1)) {
            Some(l) => format!(
                "{}:{}",
                self.files
                    .get(l.file)
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                l.number
            ),
            None => "(end of the chain)".into(),
        }
    }

    pub fn json(&self) -> Value {
        json!({
            "chain": self.label,
            "holds": self.holds(),
            "version": self.report.version.map(Version::number),
            "lines": self.report.links.len(),
            "withheld": self.report.withheld,
            "first": self.report.first().map(|l| json!({"seq": l.seq, "prev": l.prev})),
            "head": self.report.last().map(|l| json!({"seq": l.seq, "hash": l.hash})),
            "broken": self.failure.as_ref().map(|(n, why)| json!({"at": self.place(*n), "why": why})),
            "notes": self.notes,
        })
    }
}

/// Checks `src` from `start` (or genesis) against `anchors`.
pub fn check(src: &Source, start: Option<(u64, String)>, anchors: &[Record]) -> Outcome {
    let files = sources::files_of(src);
    let mut out = Outcome {
        label: src.label(),
        describe: src.describe(),
        files: files.clone(),
        ..Outcome::default()
    };
    let lines = match sources::lines_of(&files) {
        Ok(l) => l,
        Err(e) => {
            out.failure = Some((0, e));
            return out;
        }
    };
    out.lines = lines;
    if out.lines.is_empty() {
        out.notes.push("no lines".into());
        if anchors
            .iter()
            .any(|a| a.chain == out.label || a.chain.is_empty())
        {
            out.failure = Some((
                0,
                "the log is empty but an anchor names a line in it".into(),
            ));
        }
        return out;
    }
    let texts: Vec<&str> = out.lines.iter().map(|l| l.text.as_str()).collect();
    // The daemon's oldest day kept begins inside the chain once retention has
    // removed a day: its first line is taken as given, and said so, unless a
    // start or an anchor's start checks it (AZ-1).
    let mut start = start;
    if start.is_none() {
        if let Source::Daemon(_) = src {
            if let Ok(Value::Object(o)) = serde_json::from_str::<Value>(texts[0]) {
                let seq = o.get("seq").and_then(Value::as_u64);
                let prev = o.get("prev").and_then(Value::as_str);
                if let (Some(s), Some(p)) = (seq, prev) {
                    if !(s == Version::V1.first_seq() && p == derm_core::audit_chain::GENESIS) {
                        out.notes.push(format!(
                            "begins at seq {s}, not at the chain's start (older days removed by retention, or cut): its first line is taken as given; give --start <seq>:<prev> or an anchor to check it"
                        ));
                        start = Some((s, p.to_string()));
                    }
                }
            }
        }
    }
    out.start_used = start.clone();
    out.report = chains::read(&texts, start.as_ref().map(|(s, p)| (*s, p.as_str())));
    if out.report.withheld > 0 {
        out.notes.push(format!(
            "{} line(s) withheld for their content: their hashes are taken as claimed",
            out.report.withheld
        ));
    }
    if out.report.version == Some(Version::V1) {
        out.notes.push(
            "v1 rule (the daemon's log): it shows an edited, dropped, reordered or cut line, not a relabelled key or a whole-file renumber (note AZ, B6)".into(),
        );
    }
    if let Some(b) = &out.report.broken {
        out.failure = Some((b.line, b.why.clone()));
        return out;
    }
    for (i, a) in anchors.iter().enumerate() {
        if let Some(fail) = anchor_fails(&out.report, a, &mut out.notes) {
            out.failure = Some((0, format!("anchor {}: {fail}", i + 1)));
            return out;
        }
    }
    out
}

/// Why anchor `a` no longer matches the chain read, or `None`.
fn anchor_fails(r: &Report, a: &Record, notes: &mut Vec<String>) -> Option<String> {
    if let Some(v) = r.version {
        if a.v != 0 && a.v != v.number() {
            return Some(format!(
                "it anchors a v{} chain and this one is v{}",
                a.v,
                v.number()
            ));
        }
    }
    let first = r.first().map(|l| l.seq).unwrap_or(0);
    let last = r.last().map(|l| l.seq).unwrap_or(0);
    match r.at(a.seq) {
        Some(l) if l.hash != a.hash => {
            return Some(format!(
                "seq {} has another hash now: lines up to it were rewritten",
                a.seq
            ))
        }
        Some(_) => {}
        None if a.seq > last => {
            return Some(format!(
                "the chain ends at seq {last}, before the anchored seq {}: lines were cut or the log rewritten",
                a.seq
            ))
        }
        None => notes.push(format!(
            "anchor at seq {} is before the first line kept (seq {first}): not checked",
            a.seq
        )),
    }
    if let Some((s, p)) = &a.start {
        match r.at(*s) {
            Some(l) if &l.prev != p => {
                return Some(format!(
                    "the line at seq {s} no longer follows the prev it had when anchored: the head was rewritten"
                ))
            }
            Some(_) => {}
            None if *s < first => notes.push(format!(
                "the anchored start (seq {s}) is before the first line kept (seq {first})"
            )),
            None => {}
        }
    }
    None
}

/// The anchors a place keeps for `label` (or every anchor with `--chain`'s
/// label). An error when the place holds none for it.
pub fn anchors_for(place: &Place, label: &str) -> Result<Vec<Record>, String> {
    let all = place.records()?;
    let mine: Vec<Record> = all.iter().filter(|r| r.chain == label).cloned().collect();
    if mine.is_empty() {
        let mut labels: Vec<&str> = all.iter().map(|r| r.chain.as_str()).collect();
        labels.sort();
        labels.dedup();
        return Err(format!(
            "{} holds no anchor for {label:?} (it holds: {}); give --chain <label>",
            place.describe(),
            labels.join(", ")
        ));
    }
    Ok(mine)
}

pub const USAGE: &str = "usage: derm audit verify [<file>... | --light <chat>] [--data-dir <dir>] [--start <seq>:<prev>] [--anchor <seq>:<hash>]... [--anchors <file|git repo> [--chain <label>]] [--json]";

pub fn main(args: &[String]) -> u8 {
    let mut files = Vec::new();
    let mut light: Option<String> = None;
    let mut data: Option<String> = None;
    let mut start: Option<(u64, String)> = None;
    let mut marks: Vec<(u64, String)> = Vec::new();
    let mut place: Option<String> = None;
    let mut chain: Option<String> = None;
    let mut as_json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| match it.next() {
            Some(v) => Ok(v.clone()),
            None => Err(format!("{name} needs a value")),
        };
        let r: Result<(), String> = (|| {
            match a.as_str() {
                "--light" => light = Some(value("--light")?),
                "--data-dir" => data = Some(value("--data-dir")?),
                "--start" => start = Some(chains::parse_mark(&value("--start")?)?),
                "--anchor" => marks.push(chains::parse_mark(&value("--anchor")?)?),
                "--anchors" => place = Some(value("--anchors")?),
                "--chain" => chain = Some(value("--chain")?),
                "--json" => as_json = true,
                "-h" | "--help" => return Err(String::new()),
                s if s.starts_with('-') => return Err(format!("unknown flag {s}")),
                s => files.push(std::path::PathBuf::from(s)),
            }
            Ok(())
        })();
        if let Err(e) = r {
            if !e.is_empty() {
                eprintln!("derm audit verify: {e}");
            }
            eprintln!("{USAGE}");
            return 2;
        }
    }
    if light.is_some() && !files.is_empty() {
        eprintln!("derm audit verify: give files or --light, not both\n{USAGE}");
        return 2;
    }
    let srcs: Vec<Source> = if !files.is_empty() {
        vec![Source::Files(files)]
    } else if let Some(c) = &light {
        match sources::light_file(c) {
            Some(f) => vec![Source::Light {
                chat: c.clone(),
                file: f,
            }],
            None => {
                eprintln!("derm audit verify: no home folder");
                return 2;
            }
        }
    } else {
        let d = match sources::data_dir(data.as_deref()) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("derm audit verify: {e}");
                return 2;
            }
        };
        let mut v = vec![Source::Daemon(d)];
        v.extend(
            sources::light_files()
                .into_iter()
                .map(|(chat, file)| Source::Light { chat, file }),
        );
        v
    };
    if srcs.len() > 1 && (start.is_some() || !marks.is_empty()) {
        eprintln!(
            "derm audit verify: --start and --anchor name one chain: give a file or --light\n{USAGE}"
        );
        return 2;
    }
    let mut code = 0u8;
    let mut reports = Vec::new();
    for src in &srcs {
        let mut anchors: Vec<Record> = marks
            .iter()
            .map(|(seq, hash)| Record {
                chain: src.label(),
                v: 0,
                seq: *seq,
                hash: hash.clone(),
                start: None,
                anchored_ms: 0,
            })
            .collect();
        let mut missing = None;
        if let Some(p) = &place {
            let label = chain.clone().unwrap_or_else(|| src.label());
            let pl = Place::of(std::path::Path::new(p));
            match anchors_for(&pl, &label) {
                Ok(a) => anchors.extend(a),
                // Checking every chain: one with no anchor there is checked
                // without one, and said so.
                Err(e) if srcs.len() > 1 && chain.is_none() => missing = Some(e),
                Err(e) => {
                    eprintln!("derm audit verify: {e}");
                    return 2;
                }
            }
        }
        let mut o = check(src, start.clone(), &anchors);
        o.notes.extend(missing);
        if !o.holds() {
            code = 1;
        }
        if as_json {
            reports.push(o.json());
        } else {
            print_outcome(&o, anchors.len());
        }
    }
    if as_json {
        println!("{}", Value::Array(reports));
    }
    code
}

fn print_outcome(o: &Outcome, anchors: usize) {
    match &o.failure {
        None => {
            let span = match (o.report.first(), o.report.last()) {
                (Some(f), Some(l)) => {
                    format!(", seq {} to {}, head {}:{}", f.seq, l.seq, l.seq, l.hash)
                }
                _ => String::new(),
            };
            println!(
                "{}: holds ({} line(s){span}{})",
                o.describe,
                o.report.links.len(),
                if anchors > 0 {
                    format!(", {anchors} anchor(s) match")
                } else {
                    ", no anchor: a cut at the end or a whole rewrite would not show".into()
                }
            );
        }
        Some((n, why)) => {
            if *n == 0 {
                println!("{}: BROKEN: {why}", o.describe);
            } else {
                println!("{}: BROKEN at {}: {why}", o.describe, o.place(*n));
            }
        }
    }
    for note in &o.notes {
        println!("  note: {note}");
    }
}

/// The head a chain's check ends at and its first line, for `anchor`.
pub fn head_record(o: &Outcome, now_ms: i64) -> Option<Record> {
    let v = o.report.version?;
    let last = o.report.last()?;
    let first = o.report.first()?;
    Some(Record {
        chain: o.label.clone(),
        v: v.number(),
        seq: last.seq,
        hash: last.hash.clone(),
        start: Some((first.seq, first.prev.clone())),
        anchored_ms: now_ms,
    })
}
