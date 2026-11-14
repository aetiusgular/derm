//! `derm watch report`: the daemon's `report` over a window, rendered for a
//! terminal (`contracts/daemon-protocol.md`, the report object). The check
//! inside it is the fork's `FlagsReport`: writes outside a chat's folders,
//! sensitive paths, new hosts, apps left running.

use std::io::Write;

use serde_json::{json, Value};

use super::conn::Conn;
use super::text::{clean, clock, count, date_time, now_ms, parse_when, short};
use super::Args;

pub const FLAGS: &[super::Flag] = &[
    ("--since", true),
    ("--until", true),
    ("--chat", true),
    ("--json", false),
    ("--socket", true),
];

pub const USAGE: &str = "usage: derm watch report [--since <1d|2h|ms>] [--until <now|ms>] [--chat <id>] [--json] [--socket <path>]";

/// The window when `--since` is not given.
pub const DEFAULT_SINCE: &str = "1d";

pub fn main(args: &Args) -> u8 {
    let now = now_ms();
    let since_text = args.value("--since").unwrap_or(DEFAULT_SINCE);
    let until_text = args.value("--until").unwrap_or("now");
    let (Some(since), Some(until)) = (parse_when(since_text, now), parse_when(until_text, now))
    else {
        eprintln!("derm watch report: --since and --until take 30s, 10m, 2h, 1d, now or epoch ms");
        return 2;
    };
    if until < since {
        eprintln!("derm watch report: --until is before --since");
        return 2;
    }
    let socket = match args.socket() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("derm watch report: {e}");
            return 2;
        }
    };
    let report = match fetch(&socket, args.value("--chat"), since, until) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("derm watch report: {e}");
            return 1;
        }
    };
    let out = std::io::stdout();
    let mut out = out.lock();
    let text = if args.flag("--json") {
        serde_json::to_string_pretty(&report).unwrap_or_default()
    } else {
        render(&report)
    };
    let _ = writeln!(out, "{text}");
    // A broken chain is the one result a script must not miss.
    if report.get("chainOk").and_then(Value::as_bool) == Some(false) {
        3
    } else {
        0
    }
}

pub fn fetch(
    socket: &std::path::Path,
    chat: Option<&str>,
    since: i64,
    until: i64,
) -> Result<Value, String> {
    let mut conn = Conn::open(socket, "derm watch report")?;
    let mut req = json!({"op": "report", "since": since, "until": until});
    if let Some(c) = chat {
        req["chat"] = json!(c);
    }
    let reply = conn.request(&req)?;
    reply
        .get("report")
        .cloned()
        .ok_or_else(|| "daemon protocol: the report reply has no report".into())
}

pub fn render(r: &Value) -> String {
    let n = |k: &str| r.get(k).and_then(Value::as_u64).unwrap_or(0);
    let mut out = String::new();
    let chat = match r.get("chat").and_then(Value::as_str) {
        Some(c) => format!("chat {}", clean(c, 64)),
        None => "every chat".into(),
    };
    out.push_str(&format!(
        "derm watch report: {} to {}, {chat}\n",
        date_time(r.get("since").and_then(Value::as_i64).unwrap_or(0)),
        date_time(r.get("until").and_then(Value::as_i64).unwrap_or(0)),
    ));
    let chain = match r.get("chainOk").and_then(Value::as_bool) {
        Some(true) => "chain ok",
        Some(false) => "CHAIN BROKEN: the log was changed or a record is missing",
        None => "chain not checked",
    };
    out.push_str(&format!(
        "events {}   flags {}   {chain}\n",
        count(n("events")),
        count(n("flags"))
    ));
    if r.get("truncated").and_then(Value::as_bool) == Some(true) {
        out.push_str("truncated: the window holds more events than one report reads\n");
    }
    if n("dropped") > 0 {
        out.push_str(&format!(
            "dropped: {} records the daemon's queue had no room for\n",
            count(n("dropped"))
        ));
    }
    for (title, key) in [
        ("by source", "bySource"),
        ("by kind", "byKind"),
        ("approvals", "approvals"),
    ] {
        if let Some(line) = tally(r.get(key)) {
            out.push_str(&format!("{title}: {line}\n"));
        }
    }
    // Integration w2 (review W2-S3): the daemon keeps a second record under a
    // gate decision's id and writes `gate.conflict`. The first copy may be
    // the agent's, since it holds the hook's chat token.
    let conflicts = r
        .get("byKind")
        .and_then(|k| k.get("gate.conflict"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if conflicts > 0 {
        out.push_str(&format!(
            "GATE CONFLICT: {} records under a gate decision's id; the first copy may be the agent's (derm watch tail --json shows both)\n",
            count(conflicts)
        ));
    }
    // Mac test w5 retest 2, MW5-21: an install's control-path writes were
    // in the by-kind counts only.
    let control = r
        .get("byKind")
        .and_then(|k| k.get("install.control"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if control > 0 {
        out.push_str(&format!(
            "INSTALL CONTROL WRITES: {} paths a package's install script wrote that a program runs later (derm watch tail --json lists each, kind install.control)\n",
            count(control)
        ));
    }
    let check = r.get("check").cloned().unwrap_or(Value::Null);
    // Box test w5 retest 3, BW5R3-1: the collector is the Mac's; on Linux,
    // where the daemon reports `osFeed`, its "unknown" read as if the OS
    // layer's state were unknown beside the feed's own line.
    let linux_feed = r.get("osFeed").is_some_and(Value::is_object);
    if let Some(reach) = check
        .get("collectorReachable")
        .and_then(Value::as_str)
        .filter(|_| !linux_feed)
    {
        let why = check
            .get("collectorReason")
            .and_then(Value::as_str)
            .map(|w| format!(" ({})", clean(w, 80)))
            .unwrap_or_default();
        out.push_str(&format!("os collector: {}{why}\n", clean(reach, 16)));
    }
    // Mac test w5, MW5-18: the collector can answer while the daemon has
    // stopped telling it about new chats; say so, never "yes" alone.
    if r.get("osRegistration").and_then(Value::as_str) == Some("stopped") {
        out.push_str(
            "OS REGISTRATION STOPPED: chats started from now on are not followed by the OS feed until derm-daemon restarts\n",
        );
    }
    // Box test w5 retest 2, BW5R2-5: on Linux the OS feed is a process of
    // its own, and a stop of the daemon's unit took it down for good while
    // the report said only "os collector: unknown".
    match r.get("osFeed").and_then(|f| f.get("state")).and_then(Value::as_str) {
        Some("stopped") => {
            let since = r["osFeed"]
                .get("since")
                .and_then(Value::as_i64)
                .map(|ms| format!(" at {}", date_time(ms)))
                .unwrap_or_default();
            out.push_str(&format!(
                "OS FEED STOPPED{since}: derm-audit-feed is not attached (its connection closed, or the daemon dropped its tail for falling behind), so chats since then have no OS records (systemctl --user restart derm-audit-feed)\n"
            ));
        }
        Some("none") => out.push_str(
            "os feed: derm-audit-feed has not attached since derm-daemon started; the OS layer records nothing until it does (docs/install/linux.md)\n",
        ),
        _ => {}
    }
    if let Some(n) = r
        .get("collectorDropped")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    {
        out.push_str(&format!(
            "OS EVENTS DROPPED: the collector dropped {} eslogger lines since it started (a burst faster than it reads); flags and joins miss what they held\n",
            count(n)
        ));
    }
    // MW5-23: what the kernel dropped for the collector's eslogger, from the
    // gaps in its `global_seq_num`; for a chat, the part during its run.
    if let Some(n) = r
        .get("osKernelDropped")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    {
        let here: u64 = r
            .get("osKernelDrops")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|g| g.get("count").and_then(Value::as_u64))
                    .sum()
            })
            .unwrap_or(0);
        out.push_str(&format!(
            "OS EVENTS THE KERNEL DROPPED: {} since the collector started, {}{} in this window (eslogger fell behind and Endpoint Security dropped them)\n",
            count(n),
            // R5: a merged gap may reach outside the window.
            if r.get("osKernelDropsUpTo").and_then(Value::as_bool) == Some(true) {
                "up to "
            } else {
                ""
            },
            count(here)
        ));
    }
    if let Some(n) = r
        .get("chatOsMissed")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    {
        // FP4-S5: a count from merged gaps, or gaps reaching outside the
        // run, is a bound.
        let up_to = r.get("chatOsMissedUpTo").and_then(Value::as_bool) == Some(true);
        out.push_str(&format!(
            "CHAT NOT FULLY WATCHED: the kernel dropped {}{} OS events while this chat ran; its OS records, joins and control flags are incomplete\n",
            if up_to { "up to " } else { "" },
            count(n)
        ));
    }
    if let Some(n) = r
        .get("chatOsLate")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    {
        // MW5-34: effects that came after derm stopped waiting for a feed
        // that was behind are in the log, never joined or flagged.
        out.push_str(&format!(
            "CHAT NOT FULLY WATCHED: {} of its OS events reached derm after it had waited 10 min for the OS feed, which was behind; they are in the log with no join records or control flags\n",
            count(n)
        ));
    }
    // BW5R4-1: the Linux feed could not read a stretch of the audit log.
    if let Some(gaps) = r.get("chatOsFeedGaps").and_then(Value::as_array) {
        for g in gaps {
            out.push_str(&format!(
                "CHAT NOT FULLY WATCHED: the OS feed could not read the audit log {} ({}); this chat's OS records, joins and control flags may be missing\n",
                gap_span(g),
                clean(g.get("reason").and_then(Value::as_str).unwrap_or(""), 120)
            ));
        }
    } else if let Some(gaps) = r.get("osFeedGaps").and_then(Value::as_array) {
        for g in gaps {
            out.push_str(&format!(
                "OS FEED GAP: derm-audit-feed could not read the audit log {} ({}); chats that ran then may be missing OS records\n",
                gap_span(g),
                clean(g.get("reason").and_then(Value::as_str).unwrap_or(""), 120)
            ));
        }
    }
    if let Some(n) = r
        .get("chatOsAfter")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    {
        // FP11-S2: the feed had passed the stop, so these were done after
        // the run stopped, by a process it left running.
        out.push_str(&format!(
            "AFTER THE CHAT STOPPED: {} OS events of this chat's processes came after derm stopped keeping it (the OS feed was current); a process it started kept running; they are in the log with no join records or control flags\n",
            count(n)
        ));
    }
    if let Some(n) = r
        .get("tailsDropped")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    {
        out.push_str(&format!(
            "tails dropped for falling behind since the daemon started: {}\n",
            count(n)
        ));
    }
    let flags = check
        .get("flags")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if flags.is_empty() {
        out.push_str("no flags\n");
    } else {
        out.push_str("flags:\n");
        for f in &flags {
            out.push_str(&flag_line(f));
            out.push('\n');
        }
    }
    // MW5-25: a report the daemon cut to fit one line says so.
    let omitted = |k: &str| check.get(k).and_then(Value::as_u64).unwrap_or(0);
    let (flags_out, expected_out) = (omitted("flagsOmitted"), omitted("expectedOmitted"));
    if flags_out > 0 || expected_out > 0 {
        out.push_str(&format!(
            "NOT LISTED: {} more flags and {} hidden rows, to keep the report under 1 MiB; narrow it with --since or --chat\n",
            count(flags_out),
            count(expected_out)
        ));
    }
    // The third re-review's R3-1: always-listed paths whose rows were cut.
    if let Some(paths) = check.get("alwaysListedOmitted").and_then(Value::as_array) {
        let total = check
            .get("alwaysListedOmittedTotal")
            .and_then(Value::as_u64)
            .unwrap_or(paths.len() as u64);
        let names: Vec<&str> = paths.iter().filter_map(Value::as_str).collect();
        out.push_str(&format!(
            "ALWAYS-LISTED PATHS WHOSE ROWS WERE CUT ({}): {}{}\n",
            count(total),
            names.join(", "),
            if total > names.len() as u64 {
                ", ..."
            } else {
                ""
            }
        ));
    }
    // FP4-S3: what else the daemon cut to keep the reply under its budget.
    let top = |k: &str| r.get(k).and_then(Value::as_u64).unwrap_or(0);
    // Each count map's cut, named apart (the re-review's R3).
    for (k, what) in [
        ("byKindOmitted", "kinds"),
        ("bySourceOmitted", "sources"),
        ("approvalsOmitted", "approval answers"),
    ] {
        let n = top(k);
        let key = k.trim_end_matches("Omitted");
        let emptied = r
            .get(key)
            .and_then(Value::as_object)
            .is_some_and(|m| m.is_empty());
        if n > 0 && emptied {
            // The second re-review's R2-4: the map went whole.
            out.push_str(&format!(
                "NOT COUNTED BY {}: all {} {what} left out; the report was cut to its totals\n",
                what.to_ascii_uppercase(),
                count(n)
            ));
        } else if n > 0 {
            out.push_str(&format!(
                "NOT COUNTED BY {}: {} {what} with the fewest events left out of the counts above\n",
                what.to_ascii_uppercase(),
                count(n)
            ));
        }
    }
    let hidden_total = check
        .get("suppressedTotal")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if hidden_total > 0 {
        out.push_str(&format!(
            "expected and hidden: {} (counts only; the report was cut)\n",
            count(hidden_total)
        ));
    }
    let cut = |v: &Value| v.get("reportCut").and_then(Value::as_bool) == Some(true);
    if cut(r) || cut(&check) {
        out.push_str(
            "REPORT CUT TO ITS TOTALS: even no rows fit under 1 MiB; narrow it with --since or --chat\n",
        );
    }
    if let Some(sup) = check.get("suppressed").and_then(Value::as_object) {
        let hidden: u64 = sup.values().filter_map(Value::as_u64).sum();
        if hidden > 0 {
            out.push_str(&format!(
                "expected and hidden: {} (derm watch report --json lists them)\n",
                count(hidden)
            ));
        }
    }
    out.trim_end().to_string()
}

fn flag_line(f: &Value) -> String {
    let s = |k: &str| f.get(k).and_then(Value::as_str).unwrap_or("");
    let times = f.get("count").and_then(Value::as_u64).unwrap_or(1);
    let more = if times > 1 {
        format!(" (x{times})")
    } else {
        String::new()
    };
    format!(
        "  {}  {:<17}  {:<20}  {}{more}",
        clock(f.get("at").and_then(Value::as_i64).unwrap_or(0)),
        short(s("chatId"), 17),
        reason(s("reason")),
        clean(s("summary"), 140)
    )
}

/// The check's reasons in words (`activity/check.rs`, `FlagReason`).
fn reason(r: &str) -> String {
    match r {
        "writeOutsideFolders" => "write outside folders".into(),
        "sensitivePath" => "sensitive path".into(),
        "newHost" => "new host".into(),
        "leftRunning" => "left running".into(),
        "appNotGranted" => "app not granted".into(),
        "recordingOff" => "recording off".into(),
        "noGateRecord" => "no gate record".into(),
        other => clean(other, 20),
    }
}

/// `a 3, b 1` in descending count, at most 8 keys and "N more".
fn tally(v: Option<&Value>) -> Option<String> {
    let m = v?.as_object()?;
    if m.is_empty() {
        return None;
    }
    let mut rows: Vec<(String, u64)> = m
        .iter()
        .map(|(k, v)| (clean(k, 40), v.as_u64().unwrap_or(0)))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let more = rows.len().saturating_sub(8);
    let mut parts: Vec<String> = rows
        .iter()
        .take(8)
        .map(|(k, n)| format!("{k} {}", count(*n)))
        .collect();
    if more > 0 {
        parts.push(format!("{more} more"));
    }
    Some(parts.join(", "))
}

/// `from <time> to <time>` for a `feed.gap` row; a gap with no known start
/// is "up to <time>".
fn gap_span(g: &Value) -> String {
    let t = |k: &str| g.get(k).and_then(Value::as_i64).map(date_time);
    match (t("fromMs"), t("toMs")) {
        (Some(a), Some(b)) => format!("from {a} to {b}"),
        (None, Some(b)) => format!("up to {b}"),
        _ => "for a while".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        json!({
            "since": 1792200000000i64, "until": 1792204985350i64, "chat": null,
            "events": 1204, "flags": 1,
            "bySource": {"adapter": 400, "otel": 700, "run": 4},
            "byKind": {"tool.call": 900},
            "approvals": {"yes:approver": 3, "no:timeout": 1},
            "chainOk": true, "truncated": false, "dropped": 0,
            "check": {
                "flags": [{"id": "w-1", "chatId": "derm-aaaa", "at": 1792204000000i64,
                    "reason": "writeOutsideFolders", "summary": "/etc/hosts", "eventId": "e1",
                    "context": [], "count": 2, "lastAt": 0}],
                "events": [], "chainOk": true, "collectorReachable": "no",
                "collectorReason": "not running", "truncated": false, "dropped": 0,
                "expected": [], "suppressed": {"harnessStartup": 5}
            }
        })
    }

    #[test]
    fn bw5r2_5_a_linux_feed_that_is_not_attached_is_named() {
        // Box test w5 retest 2, BW5R2-5.
        let stopped = render(
            &json!({"events": 1, "osFeed": {"state": "stopped", "since": 1792204000000i64}}),
        );
        assert!(stopped.contains("OS FEED STOPPED at "), "{stopped}");
        assert!(
            stopped.contains("systemctl --user restart derm-audit-feed"),
            "{stopped}"
        );
        let none = render(&json!({"events": 1, "osFeed": {"state": "none"}}));
        assert!(
            none.contains("os feed: derm-audit-feed has not attached"),
            "{none}"
        );
        for quiet in [
            json!({"events": 1, "osFeed": {"state": "attached"}}),
            json!({"events": 1, "osFeed": null}),
            json!({"events": 1}),
        ] {
            let t = render(&quiet);
            assert!(!t.contains("derm-audit-feed"), "{t}");
        }
    }

    #[test]
    fn a_gate_conflict_is_named() {
        let r = json!({"events": 3, "byKind": {"approval": 1, "gate.conflict": 2}});
        assert!(
            render(&r).contains("GATE CONFLICT: 2 records"),
            "{}",
            render(&r)
        );
        let quiet = json!({"events": 1, "byKind": {"approval": 1}});
        assert!(!render(&quiet).contains("GATE CONFLICT"));
    }

    #[test]
    fn the_report_names_counts_flags_and_approvals() {
        let t = render(&sample());
        assert!(t.contains("events 1,204   flags 1   chain ok"), "{t}");
        assert!(t.contains("by source: otel 700, adapter 400, run 4"), "{t}");
        assert!(t.contains("approvals: yes:approver 3, no:timeout 1"), "{t}");
        assert!(t.contains("write outside folders"), "{t}");
        assert!(t.contains("/etc/hosts (x2)"), "{t}");
        assert!(t.contains("os collector: no (not running)"), "{t}");
        assert!(t.contains("expected and hidden: 5"), "{t}");
    }

    #[test]
    fn bw5r3_1_the_macs_collector_line_is_left_out_on_linux() {
        let check = json!({"collectorReachable": "unknown"});
        let linux = json!({"events": 1, "check": check, "osFeed": {"state": "attached"}});
        assert!(
            !render(&linux).contains("os collector"),
            "{}",
            render(&linux)
        );
        let mac = json!({"events": 1, "check": {"collectorReachable": "yes"}, "osFeed": null});
        assert!(render(&mac).contains("os collector: yes"));
    }

    #[test]
    fn mw5_34_a_chats_late_os_events_are_named() {
        let r = json!({"events": 1, "chatOsLate": 3});
        assert!(render(&r).contains(
            "CHAT NOT FULLY WATCHED: 3 of its OS events reached derm after it had waited 10 min for the OS feed"
        ));
        let after = json!({"events": 1, "chatOsAfter": 2});
        assert!(render(&after).contains("AFTER THE CHAT STOPPED: 2 OS events"));
        assert!(!render(&after).contains("NOT FULLY WATCHED"));
        assert!(!render(&json!({"events": 1, "chatOsLate": null})).contains("NOT FULLY WATCHED"));
    }

    #[test]
    fn kernel_drops_and_a_chat_not_fully_watched_are_named() {
        let mut r = sample();
        assert!(!render(&r).contains("KERNEL"));
        r["osKernelDropped"] = json!(2400);
        r["osKernelDrops"] = json!([{"fromMs": 1, "toMs": 2, "count": 900}]);
        r["chatOsMissed"] = json!(0);
        let t = render(&r);
        assert!(
            t.contains("OS EVENTS THE KERNEL DROPPED: 2,400 since the collector started, 900 in this window"),
            "{t}"
        );
        assert!(!t.contains("NOT FULLY WATCHED"), "{t}");
        r["chatOsMissed"] = json!(900);
        assert!(render(&r).contains("CHAT NOT FULLY WATCHED: the kernel dropped 900 OS events"));
        r["osKernelDropsUpTo"] = json!(true);
        assert!(render(&r).contains("up to 900 in this window"));
        r["chatOsMissedUpTo"] = json!(true);
        assert!(
            render(&r).contains("CHAT NOT FULLY WATCHED: the kernel dropped up to 900 OS events")
        );
    }

    #[test]
    fn a_report_the_daemon_cut_says_how_many_rows_it_left_out() {
        let mut r = sample();
        assert!(!render(&r).contains("NOT LISTED"));
        r["check"]["flagsOmitted"] = json!(1500);
        r["check"]["expectedOmitted"] = json!(0);
        let t = render(&r);
        assert!(
            t.contains("NOT LISTED: 1,500 more flags and 0 hidden rows"),
            "{t}"
        );
    }

    #[test]
    fn always_listed_paths_whose_rows_were_cut_are_named() {
        let mut r = sample();
        assert!(!render(&r).contains("ALWAYS-LISTED"));
        r["check"]["alwaysListedOmitted"] = json!(["/home/t/.ssh/authorized_keys"]);
        r["check"]["alwaysListedOmittedTotal"] = json!(1);
        let t = render(&r);
        assert!(
            t.contains("ALWAYS-LISTED PATHS WHOSE ROWS WERE CUT (1): /home/t/.ssh/authorized_keys"),
            "{t}"
        );
    }

    #[test]
    fn a_report_cut_past_its_rows_says_so() {
        let mut r = sample();
        assert!(!render(&r).contains("NOT COUNTED BY"));
        assert!(!render(&r).contains("REPORT CUT"));
        r["byKindOmitted"] = json!(1200);
        r["check"]["reportCut"] = json!(true);
        let t = render(&r);
        assert!(t.contains("NOT COUNTED BY KINDS: 1,200 kinds"), "{t}");
        r["approvalsOmitted"] = json!(3);
        r["check"]["suppressedTotal"] = json!(40);
        let t = render(&r);
        assert!(
            t.contains("NOT COUNTED BY APPROVAL ANSWERS: 3 approval answers"),
            "{t}"
        );
        assert!(t.contains("expected and hidden: 40 (counts only"), "{t}");
        assert!(t.contains("REPORT CUT TO ITS TOTALS"), "{t}");
        let mut empty = r.clone();
        empty["byKind"] = json!({});
        assert!(render(&empty).contains("NOT COUNTED BY KINDS: all 1,200 kinds left out"));
        // A report left with its totals only still renders.
        let t = render(&json!({"events": 5, "flags": 2, "reportCut": true}));
        assert!(t.contains("REPORT CUT TO ITS TOTALS"), "{t}");
    }

    #[test]
    fn install_control_writes_are_named_beside_the_flags() {
        let mut r = sample();
        r["byKind"]["install.control"] = json!(2);
        let t = render(&r);
        assert!(t.contains("INSTALL CONTROL WRITES: 2 paths"), "{t}");
        assert!(!render(&sample()).contains("INSTALL CONTROL"));
    }

    #[test]
    fn a_stopped_os_registration_and_dropped_tails_are_named() {
        // Mac test w5 retest 2, MW5-18: the report said "os collector: yes"
        // while no new chat reached the collector.
        let mut r = sample();
        r["osRegistration"] = json!("stopped");
        r["tailsDropped"] = json!(2);
        let t = render(&r);
        assert!(t.contains("OS REGISTRATION STOPPED"), "{t}");
        assert!(
            t.contains("tails dropped for falling behind since the daemon started: 2"),
            "{t}"
        );
        r["collectorDropped"] = json!(1234);
        let t = render(&r);
        assert!(
            t.contains("the collector dropped 1,234 eslogger lines"),
            "{t}"
        );
        r["osRegistration"] = json!("running");
        r["tailsDropped"] = json!(0);
        r["collectorDropped"] = json!(0);
        let t = render(&r);
        assert!(!t.contains("OS REGISTRATION"), "{t}");
        assert!(!t.contains("tails dropped"), "{t}");
        assert!(!t.contains("OS EVENTS DROPPED"), "{t}");
    }

    #[test]
    fn a_chat_id_as_derm_run_mints_it_is_shown_whole() {
        // `derm run` names a chat `derm-` and 12 hex digits (run/mod.rs), 17
        // characters; the column was 16 wide while the prefix was `tk-`.
        let mut r = sample();
        r["check"]["flags"][0]["chatId"] = json!("derm-3f2a1c9b0d11");
        let t = render(&r);
        assert!(t.contains("derm-3f2a1c9b0d11  "), "{t}");
    }

    #[test]
    fn a_broken_chain_is_said_in_capitals() {
        let mut r = sample();
        r["chainOk"] = json!(false);
        assert!(render(&r).contains("CHAIN BROKEN"));
    }

    #[test]
    fn a_hostile_flag_summary_is_cleaned() {
        let mut r = sample();
        r["check"]["flags"][0]["summary"] = json!("\x1b[2Jfine");
        assert!(!render(&r).contains('\x1b'));
    }

    #[test]
    fn a_long_tally_is_cut() {
        let mut m = serde_json::Map::new();
        for i in 0..12 {
            m.insert(format!("k{i:02}"), json!(i));
        }
        let t = tally(Some(&Value::Object(m))).unwrap();
        assert!(t.ends_with("4 more"), "{t}");
    }

    /// BW5R4-1: a stretch of the audit log the Linux feed could not read is
    /// named for a chat that ran in it, and for the window.
    #[test]
    fn bw5r4_1_a_feed_gap_is_named() {
        let gap = json!({"fromMs": 1792204000000i64, "toMs": 1792204040000i64, "reason": "the audit log rotated past the feed's place while it was down"});
        let chat = render(
            &json!({"events": 1, "chatOsFeedGaps": [gap.clone()], "osFeedGaps": [gap.clone()]}),
        );
        assert!(
            chat.contains("CHAT NOT FULLY WATCHED: the OS feed could not read the audit log from "),
            "{chat}"
        );
        assert!(!chat.contains("OS FEED GAP"), "{chat}");
        let window = render(&json!({"events": 1, "osFeedGaps": [gap]}));
        assert!(
            window.contains("OS FEED GAP: derm-audit-feed could not read"),
            "{window}"
        );
        let quiet = render(&json!({"events": 1, "chatOsFeedGaps": null, "osFeedGaps": null}));
        assert!(
            !quiet.contains("FEED GAP") && !quiet.contains("NOT FULLY"),
            "{quiet}"
        );
    }
}
