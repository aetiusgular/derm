//! `derm audit why <call>`: one call on one screen: what the model asked
//! for (the tap's `tap.call`), what derm decided (the gate's `approval`),
//! that it ran (`tool.call`), and what the OS saw it do (the join's
//! `join.candidates`, with every candidate, and `install.control`)
//! (`plans/toolkit_wave6_plan.md` section 2.1, lane 6E).
//!
//! It reads the daemon's log from disk with the daemon's own reader
//! (`derm_daemon::activity::store::read`), so its rules hold here as they do
//! in the daemon: the last copy per id (case 35), and a gate decision and an
//! OS feed's record keep their first copy (cases 98, 175). Then, because a
//! chat token is the agent's (case 66):
//! - an intent counts only from the tap's own source, an effect only from an
//!   OS feed's own source: a record of another source under an effect's id
//!   leaves the effect shown as missing, never as what that record says
//!   (case 175);
//! - a second decision for the call (a conflict copy, `detail.conflictsWith`)
//!   is shown as one, with the daemon's `gate.conflict` flags (case 98);
//! - every text a record carries is shown with its control characters
//!   removed and cut to the screen's width, and the source of each line is
//!   named, so the agent's own words never pass as derm's.
//! Its output is one screen: each part is cut to a few lines with how many
//! it left out (`--all` lifts the cut; case 185's rule for replies that grow
//! with the data).

use std::collections::BTreeSet;
use std::path::Path;

use derm_daemon::activity::{retention, store};
use serde_json::{json, Value};

use super::chains;
use super::sources;

/// How many records a read takes from the daemon's log.
pub const READ_LIMIT: usize = 500_000;
/// Effects shown before the cut, without `--all`.
pub const EFFECTS_SHOWN: usize = 8;
/// Lines of every other part shown before the cut.
pub const PART_SHOWN: usize = 3;
/// Characters of one line.
pub const WIDTH: usize = 110;

/// One record, from the daemon's log or a light-tier log.
#[derive(Clone, Debug, PartialEq)]
pub struct Rec {
    pub id: String,
    pub at: i64,
    pub chat: String,
    pub harness: String,
    pub source: String,
    pub kind: String,
    pub summary: String,
    pub detail: Value,
    pub from: &'static str,
}

impl Rec {
    fn str_at(&self, path: &[&str]) -> Option<&str> {
        let mut v = &self.detail;
        for p in path {
            v = v.get(*p)?;
        }
        v.as_str()
    }

    fn is(&self, sources: &[&str], kind: &str) -> bool {
        self.kind == kind && sources.contains(&self.source.as_str())
    }

    /// The call id the record names: the gate's `toolUseId`, the tap's
    /// `callId`, or an OTel record's `tool_use_id` attribute.
    fn call_id(&self) -> Option<&str> {
        self.str_at(&["toolUseId"])
            .or_else(|| self.str_at(&["callId"]))
            .or_else(|| self.str_at(&["attributes", "tool_use_id"]))
    }
}

const OS: &[&str] = &["auditd", "eslogger"];
const GATE: &[&str] = &["adapter", "otel"];

fn from_event(e: &derm_core::event::Event) -> Rec {
    Rec {
        id: e.id.clone(),
        at: e.at,
        chat: e.chat_id.clone(),
        harness: e.harness.clone(),
        source: serde_json::to_value(e.source)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        kind: e.kind.clone(),
        summary: e.summary.clone(),
        detail: e.detail.clone(),
        from: "daemon",
    }
}

/// The records of a light-tier log, read under its chain: lines past a
/// break are not read.
pub fn light_records(file: &Path) -> (Vec<Rec>, Option<String>) {
    let lines = match sources::lines_of(&[file.to_path_buf()]) {
        Ok(l) => l,
        Err(e) => return (Vec::new(), Some(e)),
    };
    let texts: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
    let r = chains::read(&texts, None);
    let broken = r
        .broken
        .as_ref()
        .map(|b| format!("{}:{}: {}", file.display(), lines[b.line - 1].number, b.why));
    let recs = r
        .links
        .iter()
        .filter_map(|l| {
            let rec = l.record.as_ref()?;
            let s = |k: &str| rec.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            Some(Rec {
                id: s("id"),
                at: rec.get("at").and_then(Value::as_i64).unwrap_or(0),
                chat: s("chatId"),
                harness: s("harness"),
                source: rec
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("adapter")
                    .to_string(),
                kind: l.kind.clone(),
                summary: s("summary"),
                detail: rec.get("detail").cloned().unwrap_or(Value::Null),
                from: "light",
            })
        })
        .collect();
    (recs, broken)
}

/// What `why` found for one call.
#[derive(Debug, Default)]
pub struct Found {
    pub call: String,
    pub chat: String,
    pub harness: String,
    pub intent: Vec<Rec>,
    pub decisions: Vec<Rec>,
    pub ran: Vec<Rec>,
    pub effects: Vec<Effect>,
    pub other: Vec<Rec>,
    pub flags: Vec<Rec>,
}

/// One effect the join credited (or offered) to the call.
#[derive(Debug, Clone)]
pub struct Effect {
    pub join: Rec,
    /// The OS feed's own record of the effect, or why there is none.
    pub record: Result<Rec, String>,
    /// `this`, `another` or `none`.
    pub chosen: &'static str,
    pub by: String,
    pub candidates: usize,
}

/// Finds call `call`'s records among `recs` (one chat's).
pub fn find(call: &str, chat: &str, recs: &[Rec]) -> Found {
    let mut f = Found {
        call: call.into(),
        chat: chat.into(),
        ..Found::default()
    };
    let in_chat = || recs.iter().filter(|r| r.chat == chat);
    for r in in_chat() {
        if r.call_id() != Some(call) {
            continue;
        }
        if r.is(&["tap"], "tap.call") {
            f.intent.push(r.clone());
        } else if r.is(GATE, "approval") {
            f.decisions.push(r.clone());
        } else if r.is(GATE, "tool.call") {
            f.ran.push(r.clone());
        } else if !OS.contains(&r.source.as_str()) && r.kind != "join.candidates" {
            f.other.push(r.clone());
        }
        if f.harness.is_empty() {
            f.harness = r.harness.clone();
        }
    }
    let ids: BTreeSet<&str> = f
        .intent
        .iter()
        .chain(&f.decisions)
        .chain(&f.ran)
        .map(|r| r.id.as_str())
        .collect();
    for r in in_chat() {
        if r.is(&["approval"], "gate.conflict")
            && (r.str_at(&["id"]).is_some_and(|i| ids.contains(i))
                || r.str_at(&["copy"]).is_some_and(|i| ids.contains(i)))
        {
            f.flags.push(r.clone());
        }
        if r.is(&["derm"], "join.candidates") {
            let cands = r
                .detail
                .get("candidates")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mine = cands.iter().find(|c| {
                c.get("call")
                    .and_then(Value::as_str)
                    .is_some_and(|c| ids.contains(c))
            });
            let Some(mine) = mine else { continue };
            let chosen = match r.detail.get("chosen").and_then(Value::as_str) {
                Some(c) if ids.contains(c) => "this",
                Some(_) => "another",
                None => "none",
            };
            let effect = r.str_at(&["effect"]).unwrap_or("").to_string();
            f.effects.push(Effect {
                record: effect_record(&effect, chat, recs),
                join: r.clone(),
                chosen,
                by: mine
                    .get("by")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                candidates: cands.len(),
            });
        }
        if r.is(&["derm"], "install.control")
            && r.str_at(&["call"]).is_some_and(|c| ids.contains(c))
        {
            f.other.push(r.clone());
        }
    }
    for part in [
        &mut f.intent,
        &mut f.decisions,
        &mut f.ran,
        &mut f.other,
        &mut f.flags,
    ] {
        part.sort_by_key(|r| r.at);
    }
    f.effects.sort_by_key(|e| e.join.at);
    f
}

/// The OS feed's own record of effect `id` (case 175).
fn effect_record(id: &str, chat: &str, recs: &[Rec]) -> Result<Rec, String> {
    let under: Vec<&Rec> = recs
        .iter()
        .filter(|r| r.id == id && r.chat == chat)
        .collect();
    if let Some(r) = under.iter().find(|r| OS.contains(&r.source.as_str())) {
        return Ok((*r).clone());
    }
    match under.first() {
        Some(r) => Err(format!(
            "held by source {}, not the OS feed (case 175)",
            clean(&r.source, 20)
        )),
        None => Err("the OS feed's record is not in the log kept".into()),
    }
}

/// Text from a record, for the screen: control characters (escape
/// sequences included) and bidirectional controls removed, cut to `max`.
pub fn clean(text: &str, max: usize) -> String {
    let flat: String = text
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                ' '
            } else {
                c
            }
        })
        .collect();
    if flat.chars().count() <= max {
        return flat;
    }
    let mut out: String = flat.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn time(ms: i64) -> String {
    let day = retention::day_of_ms(ms);
    let rest = ms.rem_euclid(86_400_000);
    format!(
        "{}T{:02}:{:02}:{:02}.{:03}Z",
        retention::day_name(day),
        rest / 3_600_000,
        rest / 60_000 % 60,
        rest / 1_000 % 60,
        rest % 1_000
    )
}

fn short_hash(v: Option<&str>) -> String {
    v.map(|h| h.chars().take(12).collect::<String>())
        .unwrap_or_else(|| "-".into())
}

fn line_of(r: &Rec) -> String {
    let d = &r.detail;
    let s = |k: &str| d.get(k).and_then(Value::as_str);
    let n = |k: &str| d.get(k).and_then(Value::as_u64);
    let body = match r.kind.as_str() {
        "tap.call" => {
            let paths: Vec<String> = d
                .get("paths")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            format!(
                "{} ({}), arguments {} bytes sha256 {}{}{}",
                s("tool").unwrap_or("?"),
                s("model").unwrap_or("model ?"),
                n("argsBytes").map_or("?".into(), |b| b.to_string()),
                short_hash(s("argsSha256")),
                if paths.is_empty() {
                    String::new()
                } else {
                    format!(", names {}", paths.join(", "))
                },
                if d.get("incomplete").and_then(Value::as_bool) == Some(true) {
                    ", stream cut"
                } else {
                    ""
                }
            )
        }
        "approval" => format!(
            "{}{}{}",
            s("decision").unwrap_or("?"),
            s("reason").map(|x| format!(": {x}")).unwrap_or_default(),
            if d.get("conflictsWith").is_some() {
                " [a conflict copy: a second decision for this call]"
            } else {
                ""
            }
        ),
        "tool.call" => format!(
            "ran{}{}",
            n("resultBytes")
                .or_else(|| n("size"))
                .map(|b| format!(", result {b} bytes"))
                .unwrap_or_default(),
            s("resultSha256")
                .map(|h| format!(" sha256 {}", short_hash(Some(h))))
                .unwrap_or_default()
        ),
        _ => format!("{}: {}", r.kind, r.summary),
    };
    clean(
        &format!(
            "{}  {}  [{}{}]",
            time(r.at),
            body,
            r.source,
            if r.from == "light" { ", light log" } else { "" }
        ),
        WIDTH,
    )
}

fn effect_line(e: &Effect) -> String {
    let what = match &e.record {
        Ok(r) => format!("{} {}", r.kind, r.summary),
        Err(why) => format!(
            "{} {}: {why}",
            e.join.str_at(&["effectKind"]).unwrap_or("effect"),
            e.join.str_at(&["effect"]).unwrap_or("")
        ),
    };
    let chosen = match e.chosen {
        "this" => "credited to this call".to_string(),
        "another" => "credited to another call".to_string(),
        _ => format!("one of {} candidates, none chosen", e.candidates),
    };
    clean(
        &format!(
            "{}  {chosen}, by {}: {what} [{}]",
            time(e.join.at),
            e.by,
            e.record.as_ref().map(|r| r.source.as_str()).unwrap_or("-")
        ),
        WIDTH,
    )
}

/// The screen.
pub fn render(f: &Found, all: bool, notes: &[String]) -> String {
    let mut out = format!(
        "call {} in chat {} ({})\n",
        clean(&f.call, 80),
        clean(&f.chat, 80),
        clean(
            if f.harness.is_empty() {
                "?"
            } else {
                &f.harness
            },
            40
        )
    );
    let mut part = |name: &str, lines: Vec<String>, cap: usize, empty: &str| {
        if lines.is_empty() {
            out.push_str(&format!("{name:<9}{empty}\n"));
            return;
        }
        let shown = if all {
            lines.len()
        } else {
            lines.len().min(cap)
        };
        for (i, l) in lines.iter().take(shown).enumerate() {
            out.push_str(&format!("{:<9}{l}\n", if i == 0 { name } else { "" }));
        }
        if lines.len() > shown {
            out.push_str(&format!(
                "{:<9}+{} more (derm audit why {} --all)\n",
                "",
                lines.len() - shown,
                clean(&f.call, 60)
            ));
        }
    };
    part(
        "intent",
        f.intent.iter().map(line_of).collect(),
        PART_SHOWN,
        "no tap record (an untapped chat, or the tap saw no such call)",
    );
    part(
        "decision",
        f.decisions.iter().map(line_of).collect(),
        PART_SHOWN,
        "no gate decision recorded",
    );
    part(
        "ran",
        f.ran.iter().map(line_of).collect(),
        PART_SHOWN,
        "no record that it ran",
    );
    part(
        "effects",
        f.effects.iter().map(effect_line).collect(),
        EFFECTS_SHOWN,
        "none the OS feed saw and the join credited (or no OS feed for this chat)",
    );
    if !f.other.is_empty() {
        part(
            "other",
            f.other.iter().map(line_of).collect(),
            PART_SHOWN,
            "",
        );
    }
    if !f.flags.is_empty() {
        part(
            "flags",
            f.flags.iter().map(line_of).collect(),
            PART_SHOWN,
            "",
        );
    }
    for n in notes {
        out.push_str(&format!("note     {}\n", clean(n, WIDTH)));
    }
    out
}

fn rec_json(r: &Rec) -> Value {
    json!({"id": r.id, "at": r.at, "source": r.source, "kind": r.kind, "summary": r.summary, "detail": r.detail, "from": r.from})
}

pub fn found_json(f: &Found, notes: &[String]) -> Value {
    json!({
        "call": f.call,
        "chat": f.chat,
        "harness": f.harness,
        "intent": f.intent.iter().map(rec_json).collect::<Vec<_>>(),
        "decisions": f.decisions.iter().map(rec_json).collect::<Vec<_>>(),
        "ran": f.ran.iter().map(rec_json).collect::<Vec<_>>(),
        "effects": f.effects.iter().map(|e| json!({
            "join": rec_json(&e.join),
            "record": e.record.as_ref().map(rec_json).unwrap_or_else(|why| json!({"missing": why})),
            "chosen": e.chosen,
            "by": e.by,
            "candidates": e.candidates,
        })).collect::<Vec<_>>(),
        "other": f.other.iter().map(rec_json).collect::<Vec<_>>(),
        "flags": f.flags.iter().map(rec_json).collect::<Vec<_>>(),
        "notes": notes,
    })
}

pub const USAGE: &str =
    "usage: derm audit why <call id> [--chat <chat>] [--data-dir <dir>] [--all] [--json]";

pub fn main(args: &[String]) -> u8 {
    let mut call: Option<String> = None;
    let mut chat: Option<String> = None;
    let mut data: Option<String> = None;
    let mut all = false;
    let mut as_json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--chat" | "--data-dir" => match it.next() {
                Some(v) if a == "--chat" => chat = Some(v.clone()),
                Some(v) => data = Some(v.clone()),
                None => {
                    eprintln!("derm audit why: {a} needs a value\n{USAGE}");
                    return 2;
                }
            },
            "--all" => all = true,
            "--json" => as_json = true,
            s if s.starts_with('-') => {
                eprintln!("derm audit why: unknown flag {s}\n{USAGE}");
                return 2;
            }
            s if call.is_none() => call = Some(s.to_string()),
            _ => {
                eprintln!("derm audit why: one call at a time\n{USAGE}");
                return 2;
            }
        }
    }
    let Some(call) = call else {
        eprintln!("{USAGE}");
        return 2;
    };
    let dir = match sources::data_dir(data.as_deref()) {
        Ok(d) => d.join("activity"),
        Err(e) => {
            eprintln!("derm audit why: {e}");
            return 2;
        }
    };
    let mut notes = Vec::new();
    let back = store::read(&dir, 0, i64::MAX, chat.as_deref(), READ_LIMIT);
    if !back.chain_ok {
        notes.push("the daemon's log chain does not hold: run derm audit verify".to_string());
    }
    if back.truncated {
        notes.push(format!(
            "the log holds over {READ_LIMIT} records here; only the first were read"
        ));
    }
    let mut recs: Vec<Rec> = back.events.iter().map(from_event).collect();
    // The light-tier logs of the chat named, or of every chat when none is.
    let lights: Vec<std::path::PathBuf> = match &chat {
        Some(c) => sources::light_file(c)
            .into_iter()
            .filter(|f| f.exists())
            .collect(),
        None => sources::light_files().into_iter().map(|(_, f)| f).collect(),
    };
    for f in lights {
        let (r, broken) = light_records(&f);
        if let Some(b) = broken {
            notes.push(format!(
                "a light-tier log breaks at {b}; its records from there are not read"
            ));
        }
        recs.extend(r);
    }
    let chat = match chat {
        Some(c) => c,
        None => {
            let chats: BTreeSet<&str> = recs
                .iter()
                .filter(|r| r.call_id() == Some(call.as_str()))
                .map(|r| r.chat.as_str())
                .collect();
            match chats.len() {
                0 => {
                    eprintln!("derm audit why: no record names call {}", clean(&call, 80));
                    return 1;
                }
                1 => chats.into_iter().next().unwrap_or_default().to_string(),
                _ => {
                    eprintln!(
                        "derm audit why: call {} is named in {} chats ({}): give --chat",
                        clean(&call, 80),
                        chats.len(),
                        chats
                            .iter()
                            .map(|c| clean(c, 60))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    return 2;
                }
            }
        }
    };
    let found = find(&call, &chat, &recs);
    if found.intent.is_empty()
        && found.decisions.is_empty()
        && found.ran.is_empty()
        && found.other.is_empty()
    {
        eprintln!(
            "derm audit why: no record of call {} in chat {}",
            clean(&call, 80),
            clean(&chat, 80)
        );
        return 1;
    }
    if found.decisions.len() > 1 {
        notes.push(format!(
            "{} decisions are recorded for this call: a chat token is the agent's too (case 66), so the copies are kept and flagged (case 98)",
            found.decisions.len()
        ));
    }
    if as_json {
        println!("{}", found_json(&found, &notes));
    } else {
        print!("{}", render(&found, all, &notes));
    }
    0
}
