//! The harness-neutral gate: one tool call in, one decision out. Ported by
//! the wave 5b base from the hook core's
//! `packages/derm-claude-plugin/src/core/gate.ts` at `e29ce27`. Each dialect
//! (`hook/claude_format/`, `hook/native/`, `gate/serve/`) maps an agent's
//! input to a [`GateCall`] and the answer back to that agent's reply. The
//! matcher is `derm_core::policy::evaluate`; the redactor
//! `derm_core::redact::hook`; the daemon client [`super::daemon`].

use derm_core::policy::{self, Action, PolicyFile, SHELL_TOOLS};
use derm_core::redact::hook::{has_token_shape, redact_text, redact_value};
use serde_json::{Map, Value};

use super::daemon::{AdapterEvent, ApproveOutcome, ApproveRequest, By, Env};

/// An ask never waits longer than this inside a hook, whatever the policy
/// says, so the agent's own hook timeout (120 s in derm's hook files) is
/// never reached (`HOOK_ASK_CAP_SECONDS`).
pub const HOOK_ASK_CAP_SECONDS: u32 = 90;

/// Tools that write files: a secret-like value in their input turns `allow`
/// into `ask` instead of being rewritten (`WRITE_TOOLS`).
pub const WRITE_TOOLS: [&str; 6] = [
    "write",
    "edit",
    "multiedit",
    "notebookedit",
    "apply_patch",
    "patch",
];

/// Install records one call posts at most (`MAX_INSTALL_RECORDS`).
pub const MAX_INSTALL_RECORDS: usize = 8;

/// `FULL_ACCESS_NOTE`.
pub const FULL_ACCESS_NOTE: &str =
    "the chat runs in full access (DERM_FULL_ACCESS=1), so derm denies what it would ask";

/// One tool call as a dialect read it (`GateCall`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GateCall {
    pub harness: String,
    /// The tool name as the agent gave it.
    pub tool: String,
    pub tool_input: Value,
    pub chat: Option<String>,
    pub tool_use_id: Option<String>,
    /// The chat runs in full access; `None`: `DERM_FULL_ACCESS=1` in the
    /// environment says so.
    pub full_access: Option<bool>,
}

/// The gate's answer (`GateAnswer`).
#[derive(Clone, Debug, PartialEq)]
pub struct GateAnswer {
    pub action: Action,
    pub normalized_tool: String,
    pub reason: String,
    /// Set when secret-like values were redacted from a tool that sends its
    /// input out (MCP, web).
    pub updated_input: Option<Value>,
    pub redacted: usize,
    pub ask_timeout_seconds: u32,
}

/// A policy as a dialect holds it: the file and why it is empty, if it is.
#[derive(Clone, Debug, Default)]
pub struct LoadedPolicy {
    pub policy: PolicyFile,
    pub problem: Option<String>,
}

pub fn is_shell_tool(normalized: &str) -> bool {
    SHELL_TOOLS.contains(&normalized)
}

fn values_of(v: &Value, out: &mut Vec<String>, depth: usize) -> Result<(), String> {
    if depth > 64 {
        return Err("tool input nested too deep to check".into());
    }
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Number(n) => out.push(js_number(n)),
        Value::Bool(b) => out.push(b.to_string()),
        Value::Array(a) => {
            for x in a {
                values_of(x, out, depth + 1)?;
            }
        }
        Value::Object(o) => {
            for x in o.values() {
                values_of(x, out, depth + 1)?;
            }
        }
        Value::Null => {}
    }
    Ok(())
}

/// `String(n)` for a JSON number.
fn js_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().unwrap_or(0.0);
    if f.fract() == 0.0 && f.abs() < 1e21 {
        format!("{f:.0}")
    } else {
        f.to_string()
    }
}

/// The text the reject list and the shell check run over (`inputTextFor`).
/// For a shell tool: the command, then on their own lines the values of
/// every other field but `description` (S7), each with a `/` also read with
/// a trailing `/`. Otherwise the serialized input and, on their own lines,
/// every string key and value as it is.
pub fn input_text_for(normalized_tool: &str, tool_input: &Value) -> Result<String, String> {
    if is_shell_tool(normalized_tool) {
        if let Value::Object(fields) = tool_input {
            let head = match fields.get("command") {
                Some(Value::String(s)) => Some(s.clone()),
                Some(Value::Array(a)) if a.iter().all(Value::is_string) => Some(
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
                _ => None,
            };
            if let Some(head) = head {
                let mut rest = Vec::new();
                for (k, v) in fields {
                    if k != "command" && k != "description" {
                        values_of(v, &mut rest, 0)?;
                    }
                }
                let extra: Vec<String> = rest
                    .iter()
                    .filter(|v| v.contains('/') && !v.ends_with('/'))
                    .map(|v| format!("{v}/"))
                    .collect();
                rest.extend(extra);
                return Ok(if rest.is_empty() {
                    head
                } else {
                    format!("{head}\n{}", rest.join("\n"))
                });
            }
        }
    }
    if let Value::String(s) = tool_input {
        return Ok(s.clone());
    }
    let serialized = serde_json::to_string(tool_input).unwrap_or_default();
    let mut leaves = Vec::new();
    fn walk(v: &Value, depth: usize, leaves: &mut Vec<String>) {
        if depth > 64 {
            return;
        }
        match v {
            Value::String(s) => leaves.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| walk(x, depth + 1, leaves)),
            Value::Object(o) => {
                for (k, x) in o {
                    leaves.push(k.clone());
                    walk(x, depth + 1, leaves);
                }
            }
            _ => {}
        }
    }
    walk(tool_input, 0, &mut leaves);
    Ok(if leaves.is_empty() {
        serialized
    } else {
        format!("{serialized}\n{}", leaves.join("\n"))
    })
}

fn full_access(call: &GateCall, env: &Env) -> bool {
    call.full_access
        .unwrap_or_else(|| env.raw("DERM_FULL_ACCESS") == Some("1"))
}

/// `decideCall`: the policy's answer for one call, with full access applied.
pub fn decide_call(loaded: &LoadedPolicy, call: &GateCall, env: &Env) -> GateAnswer {
    let answer = decide_call_inner(loaded, call);
    deny_ask_in_full_access(answer, call, env)
}

/// Under full access an ask becomes a deny (case 83;
/// `denyAskInFullAccess`). An adapter that turns an answer into an ask
/// after [`decide_call`] applies it again (review W4-S3).
pub fn deny_ask_in_full_access(mut answer: GateAnswer, call: &GateCall, env: &Env) -> GateAnswer {
    if full_access(call, env) && answer.action == Action::Ask {
        answer.action = Action::Deny;
        answer.reason = format!("{}; {FULL_ACCESS_NOTE}", answer.reason);
        answer.updated_input = None;
    }
    answer
}

fn decide_call_inner(loaded: &LoadedPolicy, call: &GateCall) -> GateAnswer {
    let p = &loaded.policy;
    let normalized_tool = policy::normalize_tool_name_for(&call.tool, &p.servers, &call.harness);
    let ask_timeout_seconds = p.ask_timeout_seconds.min(HOOK_ASK_CAP_SECONDS);
    let input_text = match input_text_for(&normalized_tool, &call.tool_input) {
        Ok(t) => t,
        Err(why) => {
            return GateAnswer {
                action: Action::Ask,
                normalized_tool,
                reason: why,
                updated_input: None,
                redacted: 0,
                ask_timeout_seconds,
            }
        }
    };
    let d = policy::evaluate(
        p,
        &policy::Call {
            tool: call.tool.clone(),
            harness: call.harness.clone(),
            chat: call.chat.clone(),
            description: None,
            input_text,
        },
    );
    let mut answer = GateAnswer {
        action: d.action,
        normalized_tool: d.normalized_tool,
        reason: match &loaded.problem {
            // The TypeScript `evaluate` names the load problem when no rule
            // matched (`no rule (<problem>)`, `policy.ts:835`); derm_core's
            // does not see the problem.
            Some(problem) if d.reason.starts_with("no rule") => {
                format!("no rule ({problem}){}", &d.reason["no rule".len()..])
            }
            _ => d.reason,
        },
        updated_input: None,
        redacted: 0,
        ask_timeout_seconds,
    };
    if answer.action == Action::Deny {
        return answer;
    }
    let (value, count) = redact_value(&call.tool_input);
    if count == 0 {
        return answer;
    }
    answer.redacted = count;
    let writes_or_runs = is_shell_tool(&answer.normalized_tool)
        || WRITE_TOOLS.contains(&answer.normalized_tool.as_str());
    if writes_or_runs {
        if answer.action == Action::Allow {
            answer.action = Action::Ask;
            answer.reason = "secret-like value in input".into();
        }
        return answer;
    }
    answer.updated_input = Some(value);
    answer.reason = format!(
        "{}; {count} secret-like value{} redacted",
        answer.reason,
        if count == 1 { "" } else { "s" }
    );
    answer
}

fn clean_part(s: &str, max: usize) -> String {
    let c: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(max)
        .collect();
    if c.is_empty() {
        "unknown".into()
    } else {
        c
    }
}

/// The `install.call` records for a shell call the gate read as an install
/// (`installEvents`; contracts/events.md section 5): one per install, at
/// most [`MAX_INSTALL_RECORDS`], whatever the policy said. A call whose text
/// holds a token shape keeps no package names (W5R-4, W5R2-1); a package
/// the redactor flags is left out and counted (W5C-S9).
pub fn install_events(
    call: &GateCall,
    answer: &GateAnswer,
    decision: Action,
    chat: &str,
) -> Vec<AdapterEvent> {
    if !is_shell_tool(&answer.normalized_tool) {
        return Vec::new();
    }
    let Ok(raw) = input_text_for(&answer.normalized_tool, &call.tool_input) else {
        return Vec::new();
    };
    let folded = policy::fold_text(&policy::decode_escapes(&raw));
    let installs = derm_core::installs::parse::parse_installs(&folded);
    let unquoted: String = folded.chars().filter(|c| *c != '\'' && *c != '"').collect();
    let token_in_text = [raw.clone(), unquoted.clone(), unquoted.replace('-', "_")]
        .iter()
        .any(|t| has_token_shape(t));
    let take: Vec<_> = installs.into_iter().take(MAX_INSTALL_RECORDS).collect();
    let mut details = derm_core::installs::install_call_details(
        &take,
        decision,
        call.tool_use_id.as_deref(),
        None,
    );
    for d in &mut details {
        let all = d["packages"].as_array().cloned().unwrap_or_default();
        let clean: Vec<Value> = if token_in_text {
            Vec::new()
        } else {
            all.iter()
                .filter(|p| {
                    redact_text(p["name"].as_str().unwrap_or("")).count == 0
                        && p["version"]
                            .as_str()
                            .is_none_or(|v| redact_text(v).count == 0)
                })
                .cloned()
                .collect()
        };
        if clean.len() < all.len() {
            d["redacted"] = Value::from(all.len() - clean.len());
            d["packages"] = Value::Array(clean);
        }
    }
    let call_part = clean_part(call.tool_use_id.as_deref().unwrap_or("unknown"), 48);
    let action = match decision {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    };
    details
        .into_iter()
        .enumerate()
        .map(|(i, detail)| {
            let names: Vec<String> = detail["packages"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|p| p["name"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let shown = names.iter().take(4).cloned().collect::<Vec<_>>().join(" ");
            let more = if names.len() > 4 { " ..." } else { "" };
            let summary = format!(
                "{} {} {shown}{more} {action}",
                detail["manager"].as_str().unwrap_or(""),
                detail["form"].as_str().unwrap_or("")
            );
            AdapterEvent {
                id: format!(
                    "{}-{call_part}-install-{i}-{}",
                    call.harness,
                    uuid::Uuid::new_v4().simple()
                ),
                chat_id: chat.to_string(),
                harness: call.harness.clone(),
                kind: "install.call".into(),
                summary,
                detail: match detail {
                    Value::Object(m) => m,
                    _ => Map::new(),
                },
            }
        })
        .collect()
}

/// What the approver sees: the tool and a redacted preview of the input, at
/// most 160 characters (`approvalSummary`).
pub fn approval_summary(answer: &GateAnswer, tool_input: &Value) -> String {
    let text = input_text_for(&answer.normalized_tool, tool_input).unwrap_or_default();
    let preview = redact_text(&text).text;
    let preview = preview.split_whitespace().collect::<Vec<_>>().join(" ");
    let all = format!("{}: {preview}", answer.normalized_tool);
    let units: Vec<u16> = all.encode_utf16().collect();
    if units.len() > 160 {
        let mut cut: String = char::decode_utf16(units[..159].iter().copied())
            .filter_map(Result::ok)
            .collect();
        cut.push('…');
        cut
    } else {
        all
    }
}

/// How an ask ended (`AskResolution`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskResolution {
    Allow(String),
    Deny(String),
    /// Let the agent show its own prompt.
    Harness(String),
}

/// Resolves a policy `ask` through the daemon's `approve` (`resolveAsk`).
/// `harness_can_ask`: no approver or no daemon falls back to the agent's own
/// prompt; else anything but an approver's yes is a deny
/// (contracts/policy.md section 5).
pub fn resolve_ask(
    answer: &GateAnswer,
    call: &GateCall,
    harness_can_ask: bool,
    env: &Env,
    approve: &dyn Fn(&ApproveRequest) -> ApproveOutcome,
) -> AskResolution {
    if full_access(call, env) {
        return AskResolution::Deny(format!("{}; {FULL_ACCESS_NOTE}", answer.reason));
    }
    let id = match &call.tool_use_id {
        Some(t) => format!("ap-{}-{t}", call.harness),
        None => format!("ap-{}-{}", call.harness, uuid::Uuid::new_v4()),
    };
    let request = ApproveRequest {
        id,
        chat: call.chat.clone().unwrap_or_default(),
        harness: call.harness.clone(),
        tool: answer.normalized_tool.clone(),
        summary: approval_summary(answer, &call.tool_input),
        timeout_seconds: u64::from(answer.ask_timeout_seconds),
    };
    match approve(&request) {
        ApproveOutcome::Unreachable(why) => {
            if harness_can_ask {
                AskResolution::Harness(format!("{} (derm daemon: {why})", answer.reason))
            } else {
                AskResolution::Deny(format!(
                    "{}; ask needs an approver and the derm daemon is not reachable ({why})",
                    answer.reason
                ))
            }
        }
        ApproveOutcome::Answer { yes: true, .. } => {
            AskResolution::Allow(format!("{}; approved in derm", answer.reason))
        }
        ApproveOutcome::Answer { by: By::None, .. } => {
            if harness_can_ask {
                AskResolution::Harness(format!("{} (no derm approver connected)", answer.reason))
            } else {
                AskResolution::Deny(format!(
                    "{}; ask needs an approver and none is connected",
                    answer.reason
                ))
            }
        }
        ApproveOutcome::Answer {
            by: By::Timeout, ..
        } => AskResolution::Deny(format!("{}; ask timed out", answer.reason)),
        ApproveOutcome::Answer { .. } => {
            AskResolution::Deny(format!("{}; declined in derm", answer.reason))
        }
    }
}

#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;
