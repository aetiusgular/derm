//! The policy presets `derm setup` offers (`setup/presets/*.json`; the
//! universal plan's lane W): read-only, workspace-write (the default, and the
//! policy derm's sbx kit copies into the VM, lane T's P4-D6) and strict. Each
//! file holds the policy derm writes to `~/.derm/policy.json` and what it is:
//! a summary, the boundaries it is for, the CLI versions its command rules
//! were read at (rule 6), and its known gaps.

use serde_json::Value;

/// The presets, in the order `derm setup` offers them after its default.
pub const FILES: &[(&str, &str)] = &[
    (
        "workspace-write",
        include_str!("presets/workspace-write.json"),
    ),
    ("read-only", include_str!("presets/read-only.json")),
    ("strict", include_str!("presets/strict.json")),
];

/// One preset, parsed.
#[derive(Clone, Debug)]
pub struct Preset {
    pub name: String,
    pub default: bool,
    pub summary: String,
    pub policy: Value,
}

/// Every preset, checked; an error names the first problem.
pub fn all() -> Result<Vec<Preset>, String> {
    FILES.iter().map(|(n, t)| parse(n, t)).collect()
}

/// The preset named `name`.
pub fn find(name: &str) -> Option<Preset> {
    all().ok()?.into_iter().find(|p| p.name == name)
}

fn parse(name: &str, text: &str) -> Result<Preset, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("{name}: {e}"))?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    if s("name") != name {
        return Err(format!("{name}: its name is not {name}"));
    }
    let policy = v
        .get("policy")
        .cloned()
        .ok_or(format!("{name}: no policy"))?;
    policy_problem(&policy).map_err(|e| format!("{name}: {e}"))?;
    for k in ["summary", "boundary", "readAt"] {
        if s(k).is_empty() {
            return Err(format!("{name}: no {k}"));
        }
    }
    if v.get("cli")
        .and_then(Value::as_object)
        .is_none_or(|c| c.is_empty())
    {
        return Err(format!("{name}: no cli versions"));
    }
    Ok(Preset {
        name: name.to_string(),
        default: v.get("default").and_then(Value::as_bool).unwrap_or(false),
        summary: s("summary"),
        policy,
    })
}

fn tool_ok(t: &str) -> bool {
    let name = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    t == "*"
        || match t.split_once('/') {
            Some((a, b)) => name(a) && (b == "*" || name(b)),
            None => name(t),
        }
}

fn word_ok(w: &str, first: bool) -> bool {
    let body = |s: &str, max: usize| {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= max
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter().all(|c| {
                c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || matches!(c, b'.' | b'_' | b':' | b'=' | b'+' | b'-')
            })
    };
    if body(w, 64) {
        return true;
    }
    !first
        && (w.strip_prefix("--").is_some_and(|r| body(r, 62))
            || (!w.starts_with("--") && w.strip_prefix('-').is_some_and(|r| body(r, 62))))
}

/// The checks `contracts/policy.schema.json` makes, with section 7's
/// `command` (request W-1), on a policy document. Run before anything is
/// written, so a preset can never be a file every reader refuses.
pub fn policy_problem(p: &Value) -> Result<(), String> {
    let o = p.as_object().ok_or("the policy is not an object")?;
    for k in o.keys() {
        if !matches!(
            k.as_str(),
            "version" | "askTimeoutSeconds" | "servers" | "rules"
        ) {
            return Err(format!("unknown field {k}"));
        }
    }
    if o.get("version").and_then(Value::as_i64) != Some(1) {
        return Err("version is not 1".into());
    }
    if let Some(t) = o.get("askTimeoutSeconds") {
        if !t.as_u64().is_some_and(|t| (1..=3600).contains(&t)) {
            return Err("askTimeoutSeconds outside 1 to 3600".into());
        }
    }
    let rules = o.get("rules").and_then(Value::as_array).ok_or("no rules")?;
    if rules.len() > 1000 {
        return Err("more than 1000 rules".into());
    }
    for (i, r) in rules.iter().enumerate() {
        let r = r.as_object().ok_or(format!("rule {i} is not an object"))?;
        for k in r.keys() {
            if !matches!(
                k.as_str(),
                "tool" | "harness" | "chat" | "action" | "descriptionSha256" | "command"
            ) {
                return Err(format!("rule {i}: unknown field {k}"));
            }
        }
        let tool = r.get("tool").and_then(Value::as_str).unwrap_or("");
        if !tool_ok(tool) {
            return Err(format!("rule {i}: bad tool"));
        }
        if !matches!(
            r.get("action").and_then(Value::as_str),
            Some("allow" | "ask" | "deny")
        ) {
            return Err(format!("rule {i}: bad action"));
        }
        if let Some(c) = r.get("command") {
            let words = c
                .as_array()
                .ok_or(format!("rule {i}: command is not an array"))?;
            if words.is_empty() || words.len() > 8 {
                return Err(format!("rule {i}: command has {} words", words.len()));
            }
            for (j, w) in words.iter().enumerate() {
                if !w.as_str().is_some_and(|w| word_ok(w, j == 0)) {
                    return Err(format!("rule {i}: command word {j}"));
                }
            }
            if tool != "bash" || r.contains_key("descriptionSha256") {
                return Err(format!("rule {i}: a command rule is on bash, with no pin"));
            }
        }
    }
    Ok(())
}

/// The policy text derm writes: the preset's `policy`, pretty, one newline.
pub fn policy_text(p: &Preset) -> String {
    let mut t = serde_json::to_string_pretty(&p.policy).unwrap_or_default();
    t.push('\n');
    t
}

/// Whether this derm's own matcher reads the policy (derm-core's parser). A
/// preset with command rules needs contracts/policy.md section 7 in the
/// matchers (request W-1); without it every reader refuses the file and
/// every call asks, so `derm setup` writes nothing and says why.
pub fn matcher_reads(text: &str) -> Result<(), String> {
    derm_core::policy::parse(text)
        .map(|_| ())
        .map_err(|e| e.to_string())
}
