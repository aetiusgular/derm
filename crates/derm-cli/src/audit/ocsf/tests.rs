//! Every event the mapping makes is validated against OCSF 1.9.0 itself:
//! `ocsf-1.9.0-subset.json`, extracted by `extract.py` from the schema
//! repository at v1.9.0 (commit 856d462) with every class, profile and
//! object resolved through `extends` and `$include`. The validator checks
//! what the schema states: required attributes (a profile's only when the
//! event names the profile), no attribute the class or object does not
//! define, types, enums, `at_least_one` constraints, and the captions and
//! uids OCSF derives (`class_uid`, `type_uid`, `type_name`, the names).
//! The records come from derm's own writers, never typed by hand as lines.

use serde_json::{json, Value};

use super::super::chains::{self, Version};
use super::*;

fn schema() -> Value {
    serde_json::from_str(include_str!("ocsf-1.9.0-subset.json")).unwrap()
}

fn profiles_of(e: &Value) -> Vec<String> {
    e.pointer("/metadata/profiles")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn check_value(
    s: &Value,
    ty: &str,
    array: bool,
    v: &Value,
    at: &str,
    prof: &[String],
    errs: &mut Vec<String>,
) {
    if array {
        match v.as_array() {
            Some(a) => {
                for (i, x) in a.iter().enumerate() {
                    check_value(s, ty, false, x, &format!("{at}[{i}]"), prof, errs);
                }
            }
            None => errs.push(format!("{at}: not an array")),
        }
        return;
    }
    let ok = match ty {
        "integer_t" | "long_t" | "port_t" | "timestamp_t" => v.is_i64() || v.is_u64(),
        "float_t" => v.is_number(),
        "boolean_t" => v.is_boolean(),
        "json_t" => true,
        t if t.ends_with("_t") => v.is_string(),
        "object" => v.is_object(),
        obj => {
            match s["objects"].get(obj) {
                Some(def) => check_object(s, def, v, at, prof, errs),
                None => errs.push(format!("{at}: object type {obj} not in the subset")),
            }
            true
        }
    };
    if !ok {
        errs.push(format!("{at}: not a {ty}: {v}"));
    }
}

fn check_attrs(
    s: &Value,
    attrs: &Value,
    v: &Value,
    at: &str,
    prof: &[String],
    errs: &mut Vec<String>,
) {
    let Some(o) = v.as_object() else {
        errs.push(format!("{at}: not an object"));
        return;
    };
    for (k, val) in o {
        let Some(def) = attrs.get(k) else {
            errs.push(format!("{at}.{k}: not defined by OCSF here"));
            continue;
        };
        if let Some(p) = def.get("profile").and_then(Value::as_str) {
            if !prof.iter().any(|x| x == p) {
                errs.push(format!(
                    "{at}.{k}: belongs to profile {p}, not named in metadata.profiles"
                ));
            }
        }
        if let Some(en) = def.get("enum").and_then(Value::as_object) {
            let key = val
                .as_u64()
                .map(|n| n.to_string())
                .or_else(|| val.as_str().map(String::from));
            if !key.as_deref().is_some_and(|k| en.contains_key(k)) {
                errs.push(format!("{at}.{k}: {val} not in its enum"));
            }
        }
        check_value(
            s,
            def["type"].as_str().unwrap_or("object"),
            def["array"].as_bool().unwrap_or(false),
            val,
            &format!("{at}.{k}"),
            prof,
            errs,
        );
    }
    for (k, def) in attrs.as_object().unwrap() {
        let applies = def
            .get("profile")
            .and_then(Value::as_str)
            .is_none_or(|p| prof.iter().any(|x| x == p));
        if def["requirement"] == "required" && applies && !o.contains_key(k) {
            errs.push(format!("{at}.{k}: required"));
        }
    }
}

fn check_object(
    s: &Value,
    def: &Value,
    v: &Value,
    at: &str,
    prof: &[String],
    errs: &mut Vec<String>,
) {
    check_attrs(s, &def["attributes"], v, at, prof, errs);
    if let Some(any) = def
        .pointer("/constraints/at_least_one")
        .and_then(Value::as_array)
    {
        if !any.iter().any(|k| v.get(k.as_str().unwrap()).is_some()) {
            errs.push(format!("{at}: needs at least one of {any:?}"));
        }
    }
}

/// The errors of one event against OCSF 1.9.0.
pub fn validate(e: &Value) -> Vec<String> {
    let s = schema();
    let mut errs = Vec::new();
    let class = e["class_uid"].as_u64().unwrap_or(u64::MAX);
    let Some(c) = s["classes"].get(class.to_string()) else {
        return vec![format!("class_uid {class} not in the subset")];
    };
    let prof = profiles_of(e);
    check_attrs(&s, &c["attributes"], e, "event", &prof, &mut errs);
    let act = e["activity_id"].as_u64().unwrap_or(u64::MAX);
    let sev = e["severity_id"].as_u64().unwrap_or(u64::MAX);
    let cat = c["category_uid"].as_u64().unwrap();
    let want = |k: &str, v: Value| (k.to_string(), v);
    let act_caption = c["attributes"]["activity_id"]["enum"][act.to_string()].clone();
    for (k, v) in [
        want("category_uid", json!(cat)),
        want("class_name", c["caption"].clone()),
        want("category_name", s["categories"][cat.to_string()].clone()),
        want("type_uid", json!(class * 100 + act)),
        want(
            "severity",
            c["attributes"]["severity_id"]["enum"][sev.to_string()].clone(),
        ),
    ] {
        if e[&k] != v {
            errs.push(format!("{k}: {} where OCSF says {v}", e[&k]));
        }
    }
    let name = e["activity_name"].as_str().unwrap_or("");
    if act == 99 {
        if name.is_empty() {
            errs.push("activity_name: an Other activity names itself".into());
        }
    } else if json!(name) != act_caption {
        errs.push(format!(
            "activity_name {name} where OCSF says {act_caption}"
        ));
    }
    if e["type_name"] != json!(format!("{}: {name}", c["caption"].as_str().unwrap())) {
        errs.push(format!("type_name {}", e["type_name"]));
    }
    errs
}

/// v1 lines from the daemon's own writer, one per record.
fn v1_lines(records: &[Value]) -> Vec<String> {
    let mut prev = derm_daemon::activity::chain::GENESIS.to_string();
    records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let key = if r.get("grantedAt").is_some() {
                "approval"
            } else {
                "event"
            };
            let (t, h) = derm_daemon::activity::chain::line(i as u64 + 1, &prev, key, r);
            prev = h;
            t
        })
        .collect()
}

fn ev(source: &str, kind: &str, detail: Value) -> Value {
    json!({"id": format!("{source}-{kind}-1"), "at": 1_762_934_400_000_i64, "chatId": "s-1", "harness": "claude-code", "source": source, "kind": kind, "summary": format!("{kind} summary"), "detail": detail, "pid": 42})
}

/// One record of every row of the mapping table, and some it leaves to the
/// Base Event, as derm's records carry them (`contracts/events.md` sections
/// 4 and 5, `crates/derm-audit-linux/src/map.rs`, the collector's
/// `PROTOCOL.md`, `contracts/fixtures/tap/records.json`).
fn every_kind() -> Vec<Value> {
    let os = |k: &str, d: Value| ev("auditd", k, d);
    vec![
        os(
            "exec",
            json!({"argv": ["bash", "[12 chars]"], "ppid": 7, "exe": "/usr/bin/bash", "comm": "bash"}),
        ),
        ev("eslogger", "exit", json!({"ppid": 7})),
        os("fork", json!({"child": 43, "ppid": 7})),
        os("create", json!({"path": "/w/new.txt", "ppid": 7})),
        os("write", json!({"path": "/w/a.txt"})),
        os("truncate", json!({"path": "/w/a.txt"})),
        os("open", json!({"path": "/home/u/.ssh/id_ed25519"})),
        os("rename", json!({"path": "/w/a", "dest": "/w/b"})),
        os("unlink", json!({"path": "/w/b"})),
        os("link", json!({"path": "/w/c", "dest": "/w/d"})),
        ev(
            "eslogger",
            "copyfile",
            json!({"path": "/w/c", "dest": "/w/e"}),
        ),
        os(
            "net.connect",
            json!({"host": "93.184.215.14:443", "addr": "93.184.215.14", "port": 443}),
        ),
        ev(
            "run",
            "run.start",
            json!({"boundary": "srt", "harnessExe": "/usr/local/bin/claude", "host": "box"}),
        ),
        ev("run", "run.stop", json!({})),
        // derm-egress's records (lane 6C's request R3, integration w6 phase
        // 2), as `derm run` posts them: source `run`, Tony's R2 of 12 Nov,
        // integration w6's close).
        ev(
            "run",
            "egress.connect",
            json!({"connectHost": "api.github.com", "port": 443, "sni": "api.github.com", "sniMatched": true, "tls": true, "requests": 1, "bytesUp": 120, "bytesDown": 900, "verdict": "forwarded"}),
        ),
        ev(
            "run",
            "egress.connect",
            json!({"connectHost": "evil.test", "port": 443, "sni": "evil.test", "sniMatched": true, "tls": true, "requests": 1, "bytesUp": 80, "bytesDown": 0, "verdict": "blocked", "reason": "a secret bound for another host"}),
        ),
        ev(
            "run",
            "secret.block",
            json!({"id": "gh", "host": "evil.test", "place": "header", "form": "placeholder"}),
        ),
        ev(
            "run",
            "secret.inject",
            json!({"id": "gh", "host": "api.github.com"}),
        ),
        ev(
            "tap",
            "tap.request",
            json!({"trust": "daemon", "api": "anthropic-messages", "upstream": "api.anthropic.com", "model": "claude-fixture", "status": 200, "inputTokens": 12}),
        ),
        ev(
            "tap",
            "tap.call",
            json!({"trust": "daemon", "callId": "toolu_1", "tool": "Bash", "model": "m", "argsSha256": "ab", "argsBytes": 3}),
        ),
        ev(
            "adapter",
            "approval",
            json!({"toolUseId": "toolu_1", "decision": "allow", "tool": "bash"}),
        ),
        ev(
            "adapter",
            "approval",
            json!({"toolUseId": "toolu_2", "decision": "deny", "tool": "bash"}),
        ),
        ev(
            "adapter",
            "approval",
            json!({"toolUseId": "toolu_3", "decision": "ask", "tool": "bash"}),
        ),
        ev(
            "otel",
            "approval",
            json!({"attributes": {"decision": "accept"}}),
        ),
        ev(
            "adapter",
            "tool.call",
            json!({"toolUseId": "toolu_1", "resultSha256": "cd", "size": 5}),
        ),
        ev(
            "adapter",
            "install.call",
            json!({"toolUseId": "toolu_4", "manager": "npm", "form": "add", "packages": [], "decision": "ask"}),
        ),
        ev("approval", "gate.conflict", json!({"id": "a", "copy": "b"})),
        ev(
            "derm",
            "install.control",
            json!({"call": "tap-s-1-toolu_4", "path": "/w/.git/hooks/pre-commit", "exe": "/usr/bin/node"}),
        ),
        ev(
            "derm",
            "agent.unregistered",
            json!({"executable": "/u/claude", "preset": "claude-code", "ppid": 1}),
        ),
        ev(
            "adapter",
            "taint.mark",
            json!({"reason": "untrusted-content", "toolUseId": "toolu_5", "via": "hook"}),
        ),
        ev(
            "adapter",
            "taint.review",
            json!({"verdict": "ask", "toolUseId": "toolu_6", "rule": "new-host"}),
        ),
        ev(
            "derm",
            "join.candidates",
            json!({"trust": "daemon", "effect": "auditd-1-1", "effectKind": "write", "candidates": [], "chosen": null}),
        ),
        ev("auditd", "feed.gap", json!({})),
        ev(
            "cua",
            "cu.action",
            json!({"action": "click", "verdict": "ok"}),
        ),
        ev(
            "otel",
            "model.request",
            json!({"attributes": {"model": "m"}}),
        ),
        // A record with no pid and no harness.
        json!({"id": "x", "at": 0, "chatId": "", "harness": "", "source": "auditd", "kind": "exec", "summary": "", "detail": {}}),
        // A person's approval card (the v1 log's `approval` key).
        json!({"id": "card-1", "chatId": "s-1", "harness": "codex", "subject": "app", "target": "com.apple.calculator", "scope": "chat", "granted": true, "grantedAt": 1_762_934_400_001_i64}),
    ]
}

fn mapped(lines: &[String], ctx: &Ctx) -> Vec<Value> {
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let r = chains::read(&refs, None);
    assert!(r.holds(), "{:?}", r.broken);
    let v = r.version.unwrap();
    r.links
        .iter()
        .zip(lines)
        .map(|(l, t)| map(t, l, v, ctx))
        .collect()
}

#[test]
fn every_mapped_event_is_valid_ocsf_1_9_0() {
    let ctx = Ctx::new("daemon", true);
    let lines = v1_lines(&every_kind());
    let events = mapped(&lines, &ctx);
    let mut classes = std::collections::BTreeSet::new();
    for (e, l) in events.iter().zip(&lines) {
        let errs = validate(e);
        assert!(
            errs.is_empty(),
            "{}\n{errs:#?}\n{l}",
            e["metadata"]["event_code"]
        );
        classes.insert(e["class_uid"].as_u64().unwrap());
    }
    // Every class of the table is reached.
    assert_eq!(
        classes.into_iter().collect::<Vec<_>>(),
        vec![0, 1001, 1007, 2004, 4001, 6003]
    );
    // A file named elsewhere has no known device, and is still valid.
    for e in mapped(&lines, &Ctx::new("file:/x", false)) {
        assert!(validate(&e).is_empty());
    }
}

#[test]
fn the_classes_and_activities_are_the_tables() {
    let events = mapped(&v1_lines(&every_kind()), &Ctx::new("daemon", true));
    let by: Vec<(String, u64, String)> = events
        .iter()
        .map(|e| {
            (
                e["metadata"]["event_code"].as_str().unwrap().to_string(),
                e["class_uid"].as_u64().unwrap(),
                e["activity_name"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let has = |k: &str, c: u64, a: &str| {
        assert!(
            by.iter().any(|(kk, cc, aa)| kk == k && *cc == c && aa == a),
            "{k} {c} {a}: {by:?}"
        )
    };
    has("exec", 1007, "Launch");
    has("exit", 1007, "Terminate");
    has("fork", 1007, "Fork");
    has("run.start", 1007, "Launch");
    has("create", 1001, "Create");
    has("write", 1001, "Update");
    has("open", 1001, "Open");
    has("rename", 1001, "Rename");
    has("unlink", 1001, "Delete");
    has("link", 1001, "Link");
    has("net.connect", 4001, "Open");
    has("tap.call", 6003, "Tool Call");
    has("approval", 6003, "Tool Decision");
    has("approval.card", 6003, "Approval");
    has("install.control", 2004, "Create");
    has("join.candidates", 0, "join.candidates");
    has("egress.connect", 4001, "Open");
    has("secret.block", 2004, "Create");
    has("secret.inject", 6003, "Secret Injected");
    // A forwarded connection is Allowed, a blocked one Denied, and the
    // CONNECT host is the destination.
    let egress: Vec<(u64, String)> = events
        .iter()
        .filter(|e| e["metadata"]["event_code"] == "egress.connect")
        .map(|e| {
            (
                e["action_id"].as_u64().unwrap(),
                e["dst_endpoint"]["name"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        egress,
        vec![
            (1, "api.github.com".to_string()),
            (2, "evil.test".to_string())
        ]
    );
    // The same kinds posted by a chat token are not derm-egress's.
    let forged = mapped(
        &v1_lines(&[
            ev(
                "adapter",
                "egress.connect",
                json!({"connectHost": "a.test"}),
            ),
            ev("adapter", "secret.block", json!({"id": "x"})),
            ev("adapter", "secret.inject", json!({"id": "x"})),
            // Nor is the daemon's own source theirs any longer.
            ev("derm", "secret.block", json!({"id": "x"})),
        ]),
        &Ctx::new("daemon", true),
    );
    assert!(forged.iter().all(|e| e["class_uid"] == 0), "{forged:?}");
    // A kind the OS feed did not write is not mapped as the OS's: an
    // agent-posted `exec` stays a Base Event (case 175's spirit).
    let fake = mapped(
        &v1_lines(&[ev("adapter", "exec", json!({}))]),
        &Ctx::new("daemon", true),
    );
    assert_eq!(fake[0]["class_uid"], 0);
    // The gate's decisions carry the security_control action.
    let actions: Vec<u64> = events
        .iter()
        .filter(|e| e["activity_name"] == "Tool Decision")
        .map(|e| e["action_id"].as_u64().unwrap())
        .collect();
    assert_eq!(actions, vec![1, 2, 99, 1]);
}

#[test]
fn raw_data_is_the_exported_line_and_its_hash() {
    let lines = v1_lines(&every_kind()[..3]);
    let ctx = Ctx::new("daemon", true);
    for (e, l) in mapped(&lines, &ctx).iter().zip(&lines) {
        assert_eq!(e["raw_data"], json!(l));
        assert_eq!(e["raw_data_hash"]["value"], json!(sha256_hex(l)));
        let chain = &e["unmapped"]["derm"]["chain"];
        let link = chains::read(&[l.as_str()], None);
        let _ = link;
        assert_eq!(chain["v"], 1);
        assert!(chain["hash"].as_str().unwrap().len() == 64);
    }
}

#[test]
fn a_v2_light_tier_line_and_a_withheld_line_map_too() {
    let mut out = Vec::new();
    let mut last = None;
    for (k, r) in [
        (
            "approval",
            json!({"id": "claude-code-t-decision-1", "chatId": "s-1", "harness": "claude-code", "kind": "approval", "summary": "Bash", "detail": {"toolUseId": "t", "decision": "deny", "trust": "client"}, "at": 5, "source": "adapter"}),
        ),
        (
            "tool.call",
            json!({"id": "claude-code-t", "chatId": "s-1", "harness": "claude-code", "kind": "tool.call", "summary": "Bash", "detail": {"toolUseId": "t"}, "at": 6, "source": "adapter"}),
        ),
    ] {
        let (t, l) = derm_core::audit_chain::line(last.as_ref(), k, &r).unwrap();
        out.push(t);
        last = Some(l);
    }
    let refs: Vec<&str> = out.iter().map(String::as_str).collect();
    let r = chains::read(&refs, None);
    let w = chains::withheld_line(Version::V2, &r.links[1]);
    let lines = vec![out[0].clone(), w];
    let ctx = Ctx::new("light:s-1", true);
    let events = mapped(&lines, &ctx);
    assert_eq!(events[0]["action_id"], 2);
    assert_eq!(events[1]["activity_name"], "Withheld");
    assert!(!events[1].to_string().contains("toolUseId"));
    for e in &events {
        assert!(validate(e).is_empty(), "{:?}", validate(e));
    }
}

#[test]
fn the_validator_catches_what_the_schema_forbids() {
    let ctx = Ctx::new("daemon", true);
    let e = mapped(&v1_lines(&every_kind()[..1]), &ctx).remove(0);
    let broken = |f: &dyn Fn(&mut Value)| {
        let mut x = e.clone();
        f(&mut x);
        !validate(&x).is_empty()
    };
    assert!(broken(&|x| x["type_uid"] = json!(100702)));
    assert!(broken(&|x| x["activity_id"] = json!(7)));
    assert!(broken(&|x| x["process"] = json!({"name": "bash"})));
    assert!(broken(&|x| x["made_up"] = json!(1)));
    assert!(broken(
        &|x| x["ai_model"] = json!({"name": "m", "ai_provider": "p"})
    ));
    assert!(broken(&|x| {
        x.as_object_mut().unwrap().remove("device");
    }));
    assert!(broken(&|x| x["time"] = json!("yesterday")));
    assert!(broken(&|x| x["class_name"] = json!("File System Activity")));
}

#[test]
fn unmap_gives_back_the_line_and_the_context() {
    let ctx = Ctx::new("daemon", true);
    let lines = v1_lines(&every_kind());
    for (e, l) in mapped(&lines, &ctx).iter().zip(&lines) {
        let (raw, c) = unmap(e).unwrap();
        assert_eq!(&raw, l);
        assert_eq!(c.log_name, "daemon");
        let link = &chains::read(
            &[raw.as_str()],
            Some((
                e["unmapped"]["derm"]["chain"]["seq"].as_u64().unwrap(),
                e["unmapped"]["derm"]["chain"]["prev"].as_str().unwrap(),
            )),
        )
        .links[0];
        let mut c2 = c.clone();
        if e.get("device").is_none() {
            c2.device = ctx.device.clone();
        }
        assert_eq!(&map(&raw, link, Version::V1, &c2), e);
    }
}
