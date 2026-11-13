//! `derm audit export --ocsf`: derm's records as OCSF 1.9.0 events (note
//! AZ, E4; `contracts/events.md` section 6.5), one JSON object per line,
//! for a SIEM to ingest.
//!
//! Read in the schema at its tag (`ocsf/ocsf-schema` v1.9.0, commit
//! 856d462; `ocsf-1.9.0-subset.json` beside this file, made by
//! `extract.py`, is what the tests validate every mapped event against):
//!
//! | derm record | OCSF class | activity |
//! |---|---|---|
//! | `exec`, `exit`, `fork` (auditd, eslogger); `run.start`, `run.stop` | 1007 Process Activity | Launch, Terminate, Other "Fork" |
//! | `create`, `write`, `truncate`, `open`, `rename`, `unlink`; `link`, `copyfile`, `clone`, `exchangedata` | 1001 File System Activity | Create, Update, Update, Open, Rename, Delete; Other |
//! | `net.connect` | 4001 Network Activity | Open |
//! | `tap.request`, `tap.call`, `approval` (a gate's decision), `tool.call`, `install.call`, an approval card (v1 `approval` key) | 6003 API Activity | Other, with the label |
//! | `gate.conflict`, `install.control`, `agent.unregistered`, `taint.review`, `taint.mark` | 2004 Detection Finding | Create |
//! | anything else (`join.candidates`, `feed.gap`, `content.purge`, `cu.action`, a harness's own telemetry, a withheld line) | 0 Base Event | Other, with the kind |
//!
//! `class_uid` is the category's uid times 1000 plus the class's, and
//! `type_uid` the class's times 100 plus the activity's (OCSF's rule, held
//! by the tests). The model and the harness of a tap record go in the
//! `ai_operation` profile's `ai_model` and `ai_agent`; a gate's decision in
//! the `security_control` profile's `action_id` (Allowed, Denied, Other for
//! an ask).
//!
//! What the chain proves is carried, not claimed: each event's `raw_data` is
//! the exported chain line itself, `raw_data_hash` its SHA-256, and
//! `unmapped.derm.chain` its `v`, `seq`, `prev` and `hash`. The
//! `record_integrity` profile's attestation is not used: OCSF computes its
//! fingerprint over the OCSF event's own serialization, and derm's hash is
//! over derm's record (`attestation.json`, read at the tag), so naming it an
//! attestation would claim what it is not. `derm audit verify --ocsf` checks
//! the chain through `raw_data` and that every event is what this mapping
//! makes of its `raw_data`, so an edited OCSF field shows.
//!
//! Content stays out as it does in the plain export: a withheld line maps to
//! a Base Event that says so, and nothing of a record's detail is added
//! beyond what its exported line already holds.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::chains::{Read, Version};

/// The OCSF version every event names.
pub const OCSF_VERSION: &str = "1.9.0";

/// What an export knows beside the line: the chain's label and the device.
#[derive(Clone, Debug, PartialEq)]
pub struct Ctx {
    pub log_name: String,
    pub device: Value,
    pub product_version: String,
}

impl Ctx {
    /// The machine the log was read on, for the daemon's and the light
    /// tier's logs (they are this machine's); `unknown` for a file named.
    pub fn new(log_name: &str, local: bool) -> Ctx {
        let host = if local {
            derm_core::platform::host_name()
        } else {
            String::new()
        };
        let device = if host.is_empty() {
            json!({"name": "unknown", "type_id": 0})
        } else {
            json!({"hostname": host, "type_id": 0})
        };
        Ctx {
            log_name: log_name.into(),
            device,
            product_version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

fn sha256_hex(text: &str) -> String {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The fields of a record a mapping reads.
struct R<'a> {
    id: String,
    at: i64,
    chat: String,
    harness: String,
    source: String,
    kind: String,
    summary: String,
    detail: &'a Value,
    pid: Option<u64>,
}

static NULL: Value = Value::Null;

fn fields<'a>(version: Version, link: &Read, record: &'a Value) -> R<'a> {
    let s = |k: &str| {
        record
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let card = version == Version::V1 && link.kind == "approval";
    R {
        id: s("id"),
        at: record
            .get(if card { "grantedAt" } else { "at" })
            .and_then(Value::as_i64)
            .unwrap_or(0),
        chat: s("chatId"),
        harness: s("harness"),
        source: if card { "approval".into() } else { s("source") },
        kind: if card {
            "approval.card".into()
        } else if version == Version::V2 {
            link.kind.clone()
        } else {
            s("kind")
        },
        summary: if card {
            format!(
                "{} {}: {}",
                s("subject"),
                s("target"),
                if record.get("granted").and_then(Value::as_bool) == Some(true) {
                    "granted"
                } else {
                    "refused"
                }
            )
        } else {
            s("summary")
        },
        detail: record.get("detail").unwrap_or(&NULL),
        pid: record.get("pid").and_then(Value::as_u64),
    }
}

/// `(class_uid, activity_id, label)`: the label names an Other activity.
fn class_of(r: &R) -> (u64, u64, Option<&'static str>) {
    let os = matches!(r.source.as_str(), "auditd" | "eslogger");
    match (os, r.kind.as_str()) {
        (true, "exec") => (1007, 1, None),
        (true, "exit") => (1007, 2, None),
        (true, "fork") => (1007, 99, Some("Fork")),
        (_, "run.start") if r.source == "run" => (1007, 1, None),
        (_, "run.stop") if r.source == "run" => (1007, 2, None),
        (true, "create") => (1001, 1, None),
        (true, "write") | (true, "truncate") => (1001, 3, None),
        (true, "open") => (1001, 14, None),
        (true, "rename") => (1001, 5, None),
        (true, "unlink") => (1001, 4, None),
        (true, "link") => (1001, 99, Some("Link")),
        (true, "copyfile") => (1001, 99, Some("Copy")),
        (true, "clone") => (1001, 99, Some("Clone")),
        (true, "exchangedata") => (1001, 99, Some("Exchange Data")),
        (true, "net.connect") => (4001, 1, None),
        (false, "tap.request") => (6003, 99, Some("Model Request")),
        (false, "tap.call") => (6003, 99, Some("Tool Call")),
        (false, "approval") => (6003, 99, Some("Tool Decision")),
        (false, "tool.call") => (6003, 99, Some("Tool Result")),
        (false, "install.call") => (6003, 99, Some("Package Install")),
        (false, "approval.card") => (6003, 99, Some("Approval")),
        (false, "gate.conflict")
        | (false, "install.control")
        | (false, "agent.unregistered")
        | (false, "taint.review")
        | (false, "taint.mark") => (2004, 1, None),
        _ => (0, 99, None),
    }
}

fn captions(class: u64, activity: u64) -> (&'static str, u64, &'static str, &'static str) {
    // (class caption, category uid, category caption, activity caption)
    let (cc, cat, catc) = match class {
        1007 => ("Process Activity", 1, "System Activity"),
        1001 => ("File System Activity", 1, "System Activity"),
        4001 => ("Network Activity", 4, "Network Activity"),
        6003 => ("API Activity", 6, "Application Activity"),
        2004 => ("Detection Finding", 2, "Findings"),
        _ => ("Base Event", 0, "Uncategorized"),
    };
    let act = match (class, activity) {
        (_, 99) => "Other",
        (1007, 1) => "Launch",
        (1007, 2) => "Terminate",
        (1001, 1) | (2004, 1) => "Create",
        (1001, 3) => "Update",
        (1001, 4) => "Delete",
        (1001, 5) => "Rename",
        (1001, 14) => "Open",
        (4001, 1) => "Open",
        _ => "Unknown",
    };
    (cc, cat, catc, act)
}

fn severity(class: u64, r: &R) -> u64 {
    match (class, r.kind.as_str()) {
        (2004, "taint.mark") => 1,
        (2004, "taint.review") => 2,
        (2004, _) => 3,
        _ => 1,
    }
}

fn provider(host: &str) -> &'static str {
    match host {
        "api.anthropic.com" => "Anthropic",
        "api.openai.com" | "chatgpt.com" => "OpenAI",
        "generativelanguage.googleapis.com" => "Google",
        _ => "unknown",
    }
}

fn s_at<'a>(d: &'a Value, k: &str) -> Option<&'a str> {
    d.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn file_of(path: &str) -> Value {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .filter(|n| !n.is_empty())
        .unwrap_or(path);
    json!({"name": name, "path": path, "type_id": 0})
}

fn process_of(r: &R) -> Value {
    let mut p = Map::new();
    match r.pid {
        Some(pid) => {
            p.insert("pid".into(), json!(pid));
        }
        None => {
            p.insert("uid".into(), json!(r.id));
        }
    }
    if let Some(exe) = s_at(r.detail, "exe").or_else(|| s_at(r.detail, "harnessExe")) {
        p.insert("file".into(), file_of(exe));
    }
    Value::Object(p)
}

fn actor_of(r: &R) -> Value {
    let mut a = Map::new();
    a.insert(
        "app_name".into(),
        json!(if r.harness.is_empty() {
            "unknown"
        } else {
            &r.harness
        }),
    );
    if let Some(ppid) = r.detail.get("ppid").and_then(Value::as_u64) {
        a.insert("process".into(), json!({"pid": ppid}));
    }
    Value::Object(a)
}

/// One OCSF event for one exported chain line. `text` is the line as
/// exported; `link` its reading; `version` the chain's.
pub fn map(text: &str, link: &Read, version: Version, ctx: &Ctx) -> Value {
    let mut chain = json!({"v": version.number(), "seq": link.seq, "prev": link.prev, "hash": link.hash, "kind": link.kind});
    let Some(record) = link.record.as_ref() else {
        // A withheld line: nothing but where it sits.
        chain["withheld"] = json!(true);
        return finish(
            json!({"message": "withheld for its content", "time": 0}),
            0,
            99,
            Some("Withheld"),
            1,
            &format!("seq-{}", link.seq),
            link,
            "withheld",
            "",
            json!({"chain": chain}),
            &[],
            text,
            ctx,
        );
    };
    let r = fields(version, link, record);
    let (class, activity, label) = class_of(&r);
    let mut e = Map::new();
    e.insert("time".into(), json!(r.at));
    e.insert("message".into(), json!(r.summary));
    let mut profiles: Vec<&str> = Vec::new();
    match class {
        1007 | 1001 => {
            e.insert("actor".into(), actor_of(&r));
            e.insert("device".into(), ctx.device.clone());
            if class == 1007 {
                e.insert("process".into(), process_of(&r));
            } else {
                let path = s_at(r.detail, "path").unwrap_or("");
                e.insert(
                    "file".into(),
                    file_of(if path.is_empty() { "unknown" } else { path }),
                );
                if let Some(dest) = s_at(r.detail, "dest") {
                    e.insert("file_result".into(), file_of(dest));
                }
            }
        }
        4001 => {
            let mut dst = Map::new();
            match s_at(r.detail, "addr") {
                Some(ip) => dst.insert("ip".into(), json!(ip)),
                None => dst.insert(
                    "name".into(),
                    json!(s_at(r.detail, "host").unwrap_or("unknown")),
                ),
            };
            if let Some(port) = r.detail.get("port").and_then(Value::as_u64) {
                dst.insert("port".into(), json!(port));
            }
            e.insert("dst_endpoint".into(), Value::Object(dst));
            // Network Activity has `actor` and `device` through the `host`
            // profile only (the subset, class 4001).
            profiles.push("host");
            e.insert("actor".into(), actor_of(&r));
            e.insert("device".into(), ctx.device.clone());
        }
        6003 => {
            e.insert("actor".into(), actor_of(&r));
            // The harness spoke to derm on this machine (the tap's and the
            // daemon's ports are loopback only).
            e.insert("src_endpoint".into(), json!({"ip": "127.0.0.1"}));
            let tool = s_at(r.detail, "tool").unwrap_or("");
            let operation = match r.kind.as_str() {
                "tap.request" => s_at(r.detail, "api").unwrap_or("model request").to_string(),
                "approval.card" => "approve".to_string(),
                "install.call" => format!(
                    "{} {}",
                    s_at(r.detail, "manager").unwrap_or("install"),
                    s_at(r.detail, "form").unwrap_or("")
                )
                .trim()
                .to_string(),
                _ if !tool.is_empty() => tool.to_string(),
                _ => r.summary.clone(),
            };
            let mut api = json!({"operation": if operation.is_empty() { "unknown".to_string() } else { operation }});
            if let Some(up) = s_at(r.detail, "upstream") {
                api["service"] = json!({"name": up});
            }
            e.insert("api".into(), api);
            if r.source == "tap" {
                profiles.push("ai_operation");
                let mut agent =
                    json!({"name": if r.harness.is_empty() { "unknown" } else { &r.harness }});
                if let Some(model) = s_at(r.detail, "model") {
                    let up = s_at(r.detail, "upstream").unwrap_or("");
                    let m = json!({"name": model, "ai_provider": provider(up)});
                    agent["ai_model"] = m.clone();
                    e.insert("ai_model".into(), m);
                }
                e.insert("ai_agent".into(), agent);
            }
            if r.kind == "approval" || r.kind == "approval.card" {
                let decision = if r.kind == "approval.card" {
                    if record.get("granted").and_then(Value::as_bool) == Some(true) {
                        "allow"
                    } else {
                        "deny"
                    }
                } else {
                    // The gate's record, else a harness's OTel
                    // `tool_decision` (its attributes, `contracts/events.md`
                    // section 2).
                    s_at(r.detail, "decision")
                        .or_else(|| r.detail.get("attributes").and_then(|a| s_at(a, "decision")))
                        .unwrap_or("")
                };
                let (id, name) = match decision {
                    "allow" | "accept" | "ask_accept" => (1, None),
                    "deny" | "reject" | "ask_reject" | "ask_timeout" => (2, None),
                    "" => (0, None),
                    _ => (99, Some(decision)),
                };
                profiles.push("security_control");
                e.insert("action_id".into(), json!(id));
                if let Some(n) = name {
                    e.insert("action".into(), json!(n));
                }
            }
        }
        2004 => {
            e.insert(
                "finding_info".into(),
                json!({"uid": if r.id.is_empty() { format!("seq-{}", link.seq) } else { r.id.clone() }, "title": r.summary}),
            );
        }
        _ => {}
    }
    let mut derm = Map::new();
    derm.insert("chain".into(), chain);
    derm.insert("source".into(), json!(r.source));
    derm.insert("chatId".into(), json!(r.chat));
    derm.insert("harness".into(), json!(r.harness));
    derm.insert("kind".into(), json!(r.kind));
    derm.insert("detail".into(), r.detail.clone());
    if let Some(pid) = r.pid {
        derm.insert("pid".into(), json!(pid));
    }
    let label = label.or(if class == 0 { Some("") } else { None });
    let other = if class == 0 {
        r.kind.clone()
    } else {
        String::new()
    };
    finish(
        Value::Object(e),
        class,
        activity,
        label,
        severity(class, &r),
        &r.id,
        link,
        &r.kind,
        &other,
        Value::Object(derm),
        &profiles,
        text,
        ctx,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    mut e: Value,
    class: u64,
    activity: u64,
    label: Option<&str>,
    sev: u64,
    uid: &str,
    link: &Read,
    kind: &str,
    other: &str,
    derm: Value,
    profiles: &[&str],
    text: &str,
    ctx: &Ctx,
) -> Value {
    let (cc, cat, catc, act) = captions(class, activity);
    let activity_name = match label {
        Some("") => other.to_string(),
        Some(l) => l.to_string(),
        None => act.to_string(),
    };
    let activity_name = if activity_name.is_empty() {
        "Other".into()
    } else {
        activity_name
    };
    let sev_caption = match sev {
        1 => "Informational",
        2 => "Low",
        3 => "Medium",
        _ => "Unknown",
    };
    let mut meta = json!({
        "version": OCSF_VERSION,
        "product": {"name": "derm", "vendor_name": "derm", "version": ctx.product_version},
        "uid": if uid.is_empty() { format!("seq-{}", link.seq) } else { uid.to_string() },
        "log_name": ctx.log_name,
        "event_code": kind,
        "sequence": link.seq,
    });
    if !profiles.is_empty() {
        meta["profiles"] = json!(profiles);
    }
    let o = e.as_object_mut().expect("an object");
    o.insert("class_uid".into(), json!(class));
    o.insert("class_name".into(), json!(cc));
    o.insert("category_uid".into(), json!(cat));
    o.insert("category_name".into(), json!(catc));
    o.insert("activity_id".into(), json!(activity));
    o.insert("activity_name".into(), json!(activity_name));
    o.insert("type_uid".into(), json!(class * 100 + activity));
    o.insert("type_name".into(), json!(format!("{cc}: {activity_name}")));
    o.insert("severity_id".into(), json!(sev));
    o.insert("severity".into(), json!(sev_caption));
    o.insert("metadata".into(), meta);
    o.insert("raw_data".into(), json!(text));
    o.insert(
        "raw_data_hash".into(),
        json!({"algorithm_id": 3, "algorithm": "SHA-256", "value": sha256_hex(text)}),
    );
    o.insert("unmapped".into(), json!({ "derm": derm }));
    e
}

/// What `verify --ocsf` takes from an event to map its line again: the
/// line, and the context the export had.
pub fn unmap(event: &Value) -> Result<(String, Ctx), String> {
    let raw = event
        .get("raw_data")
        .and_then(Value::as_str)
        .ok_or("no raw_data")?;
    let meta = event.get("metadata").ok_or("no metadata")?;
    let ctx = Ctx {
        log_name: meta
            .get("log_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        device: event
            .get("device")
            .cloned()
            .unwrap_or_else(|| json!({"name": "unknown", "type_id": 0})),
        product_version: meta
            .pointer("/product/version")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    };
    Ok((raw.to_string(), ctx))
}

#[cfg(test)]
mod tests;

/// The schema validator, for the audit module's own tests.
#[cfg(test)]
pub fn validate_for_tests(e: &Value) -> Vec<String> {
    tests::validate(e)
}
