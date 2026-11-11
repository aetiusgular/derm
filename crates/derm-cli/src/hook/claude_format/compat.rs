//! The eight agents whose PreToolUse is Claude Code's or near it: OpenClaude,
//! Qwen Code, Droid, Command Code, Kimi Code, Auggie, Copilot CLI and Grok
//! Build. One table entry per agent, each its row of
//! `contracts/hook-dialects.md` section 2a; ported from
//! `packages/derm-hooks-claude-compat/src/{hook,agents,dialect}.ts` at
//! `e29ce27`, whose comments name the source of each field (lane L's
//! research at each `verified_at`). Inputs from OpenClaude 0.35.1, Qwen
//! 0.27.1, Droid 1.7.0, Copilot 1.0.108, Grok 1.0.77 and Kimi 2.5.2 were
//! recorded through derm's contract checks by the wave 5b base (note BC
//! section 2, run); Command Code and Auggie stay unverified (accounts).
//!
//! The rules every dialect keeps (section 1): one decision, the core's;
//! allow only where a rule says allow (case 72); an ask goes to the agent's
//! own prompt where it shows one in this mode, else to the derm approver,
//! else it is a deny, never "no decision" (cases 71, 83); a deny blocks one
//! call, never the run (case 79); nothing is printed but the agent's
//! decision, and the tool input is never echoed (case 77).

use derm_core::policy::Action;
use serde_json::{json, Map, Value};

use super::{chat_of, one_line, parse_input, str_of, Decision, Deps};
use crate::gate::core::{
    decide_call, input_text_for, install_events, resolve_ask, AskResolution, GateAnswer, GateCall,
};
use crate::hook::Reply;

/// Shell tools under other names (case 82): mapped to `bash` before the
/// core sees them, so a `bash` rule and case 30's shell checks apply. Each
/// list equals its preset file's `coverage.shellAliases` (test).
pub const SHELL_ALIASES: [(&str, &[&str]); 8] = [
    ("openclaude", &["powershell", "monitor"]),
    ("qwen-code", &["run_shell_command", "monitor"]),
    ("droid", &["execute"]),
    (
        "command-code",
        &["shell_command", "powershell", "monitor_command"],
    ),
    ("kimi", &["powershell"]),
    ("auggie", &["launch-process", "write-process"]),
    (
        "copilot-cli",
        &["powershell", "write_bash", "write_powershell"],
    ),
    ("grok", &["run_terminal_command", "shell"]),
];

/// Modes where the agent may not show the prompt an ask requests, or runs
/// the call anyway: fail safe to the approver or deny (cases 71, 83).
const NO_PROMPT_MODES: [&str; 12] = [
    "bypasspermissions",
    "dontask",
    "yolo",
    "auto",
    "autopilot",
    "full",
    "full-access",
    "fullaccess",
    "allow-all",
    "allowall",
    "off",
    "acceptall",
];

/// The call as the hook read it, before the core sees it (`ReadCall`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReadCall {
    /// The name for the core: a shell alias already `bash`, an MCP name in
    /// a form the core splits.
    pub tool: String,
    /// The name exactly as the agent sent it.
    pub raw_tool: String,
    pub tool_input: Value,
    pub call_id: Option<String>,
    pub session: Option<String>,
    pub mode: Option<String>,
    /// The input is rebuilt for the core (a shell's stdin text as
    /// `command`): a rewrite of it is never sent back.
    pub input_mapped: bool,
    /// Why the call cannot be allowed as it is (an MCP call with no server,
    /// case 73; Grok's cut input, L-S3): caps the answer at ask.
    pub unresolved: Option<String>,
}

/// How a dialect writes its replies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Replies {
    /// Claude Code's shape, allow with `updatedInput`, an ask of its own
    /// (OpenClaude, Qwen Code).
    Claude,
    /// Claude Code's shape with no ask: Droid's ask only logs.
    ClaudeNoAsk,
    /// Command Code: Claude Code's allow without `updatedInput`, no ask.
    CommandCode,
    /// Kimi reads only deny: an allow prints nothing.
    Kimi,
    /// Auggie: Claude Code's allow with `updatedInput`, no ask.
    Auggie,
    Copilot,
    Grok,
}

/// One agent's dialect (`Dialect`).
pub struct Dialect {
    pub id: &'static str,
    pub name: &'static str,
    /// The version the row was read at (preset `coverage.verifiedAt`; the
    /// tests hold the two equal).
    #[cfg_attr(not(test), allow(dead_code))]
    pub verified_at: &'static str,
    /// The event names the agent puts in its input; anything else blocks.
    pub events: &'static [&'static str],
    replies: Replies,
    /// The agent shows its own prompt for an ask in the input's mode.
    mode_decides_ask: bool,
    /// The agent can replace a call's input from the reply.
    pub can_rewrite: bool,
}

pub const DIALECTS: [Dialect; 8] = [
    Dialect {
        id: "openclaude",
        name: "OpenClaude",
        verified_at: "0.34.0",
        events: &["PreToolUse"],
        replies: Replies::Claude,
        mode_decides_ask: true,
        can_rewrite: true,
    },
    Dialect {
        id: "qwen-code",
        name: "Qwen Code",
        verified_at: "0.26.6",
        events: &["PreToolUse"],
        replies: Replies::Claude,
        mode_decides_ask: true,
        can_rewrite: true,
    },
    Dialect {
        id: "droid",
        name: "Droid",
        verified_at: "1.3.0",
        events: &["PreToolUse"],
        replies: Replies::ClaudeNoAsk,
        mode_decides_ask: false,
        can_rewrite: true,
    },
    Dialect {
        id: "command-code",
        name: "Command Code",
        verified_at: "1.88.2",
        events: &["PreToolUse"],
        replies: Replies::CommandCode,
        mode_decides_ask: false,
        can_rewrite: false,
    },
    Dialect {
        id: "kimi",
        name: "Kimi Code",
        verified_at: "2.4.1",
        events: &["PreToolUse"],
        replies: Replies::Kimi,
        mode_decides_ask: false,
        can_rewrite: false,
    },
    Dialect {
        id: "auggie",
        name: "Auggie",
        verified_at: "0.36.0",
        events: &["PreToolUse"],
        replies: Replies::Auggie,
        mode_decides_ask: false,
        can_rewrite: true,
    },
    Dialect {
        id: "copilot-cli",
        name: "Copilot CLI",
        verified_at: "1.0.105",
        events: &["preToolUse", "PreToolUse"],
        replies: Replies::Copilot,
        mode_decides_ask: true,
        can_rewrite: true,
    },
    Dialect {
        id: "grok",
        name: "Grok Build",
        verified_at: "1.0.71",
        events: &["PreToolUse", "pre_tool_use"],
        replies: Replies::Grok,
        mode_decides_ask: true,
        can_rewrite: true,
    },
];

pub fn dialect(id: &str) -> Option<&'static Dialect> {
    DIALECTS.iter().find(|d| d.id == id)
}

pub fn shell_aliases(id: &str) -> &'static [&'static str] {
    SHELL_ALIASES
        .iter()
        .find(|(a, _)| *a == id)
        .map(|(_, l)| *l)
        .unwrap_or(&[])
}

fn reply(json: Option<Value>, stderr: Option<String>, exit: u8) -> Reply {
    Reply {
        stdout: json.map(|j| super::json_line(&j)).unwrap_or_default(),
        stderr: stderr.map(|s| format!("{s}\n")).unwrap_or_default(),
        exit,
    }
}

/// Exit 2 with the reason on stderr, which every one of the eight reads as
/// "this call is denied", and the agent's own deny JSON on stdout where it
/// has one (`exit2`).
fn exit2(reason: &str, json: Option<Value>) -> Reply {
    reply(json, Some(format!("derm: {}", one_line(reason, 2000))), 2)
}

/// Claude Code's PreToolUse reply (`claudeShape`).
fn claude_shape(decision: &str, reason: &str, updated: Option<&Value>) -> Value {
    let mut out = Map::new();
    out.insert("hookEventName".into(), json!("PreToolUse"));
    out.insert("permissionDecision".into(), json!(decision));
    out.insert(
        "permissionDecisionReason".into(),
        json!(format!("derm: {}", one_line(reason, 2000))),
    );
    if let Some(u) = updated {
        out.insert("updatedInput".into(), u.clone());
    }
    json!({"hookSpecificOutput": out})
}

impl Dialect {
    fn has_ask(&self) -> bool {
        matches!(
            self.replies,
            Replies::Claude | Replies::Copilot | Replies::Grok
        )
    }

    /// The agent shows its own prompt for an ask in this call's mode
    /// (`ownAskIn`, `modeShowsPrompt`).
    pub fn own_ask_in(&self, call: &ReadCall) -> bool {
        if !self.mode_decides_ask {
            return false;
        }
        let Some(mode) = &call.mode else {
            return true;
        };
        let m: String = mode
            .trim()
            .to_lowercase()
            .chars()
            .filter(|c| !derm_core::redact::hook::js_space(*c) && *c != '_')
            .collect();
        !NO_PROMPT_MODES.contains(&m.as_str())
    }

    pub fn allow(&self, reason: &str, updated: Option<&Value>) -> Reply {
        match self.replies {
            Replies::Claude | Replies::ClaudeNoAsk | Replies::Auggie => {
                reply(Some(claude_shape("allow", reason, updated)), None, 0)
            }
            Replies::CommandCode => reply(Some(claude_shape("allow", reason, None)), None, 0),
            Replies::Kimi => super::none(),
            Replies::Copilot => {
                let mut o = Map::new();
                o.insert("permissionDecision".into(), json!("allow"));
                o.insert(
                    "permissionDecisionReason".into(),
                    json!(format!("derm: {reason}")),
                );
                if let Some(u) = updated {
                    o.insert("modifiedArgs".into(), u.clone());
                }
                reply(Some(Value::Object(o)), None, 0)
            }
            Replies::Grok => {
                let mut o = Map::new();
                o.insert("decision".into(), json!("allow"));
                o.insert("reason".into(), json!(format!("derm: {reason}")));
                if let Some(u) = updated {
                    o.insert(
                        "hookSpecificOutput".into(),
                        json!({"hookEventName": "PreToolUse", "updatedInput": u}),
                    );
                }
                reply(Some(Value::Object(o)), None, 0)
            }
        }
    }

    /// One call blocked, never the run (case 79).
    pub fn deny(&self, reason: &str) -> Reply {
        match self.replies {
            Replies::Claude | Replies::ClaudeNoAsk | Replies::CommandCode | Replies::Auggie => {
                exit2(reason, Some(claude_shape("deny", reason, None)))
            }
            Replies::Kimi => exit2(
                reason,
                Some(json!({"hookSpecificOutput": {
                    "permissionDecision": "deny",
                    "permissionDecisionReason": format!("derm: {}", one_line(reason, 2000)),
                }})),
            ),
            Replies::Copilot => exit2(
                reason,
                Some(
                    json!({"permissionDecision": "deny", "permissionDecisionReason": format!("derm: {reason}")}),
                ),
            ),
            Replies::Grok => exit2(
                reason,
                Some(json!({"decision": "deny", "reason": format!("derm: {reason}")})),
            ),
        }
    }

    /// The agent's own prompt, where it has one.
    pub fn ask(&self, reason: &str) -> Option<Reply> {
        match self.replies {
            Replies::Claude => Some(reply(Some(claude_shape("ask", reason, None)), None, 0)),
            Replies::Copilot => Some(reply(
                Some(
                    json!({"permissionDecision": "ask", "permissionDecisionReason": format!("derm: {reason}")}),
                ),
                None,
                0,
            )),
            Replies::Grok => Some(reply(
                Some(json!({"decision": "ask", "reason": format!("derm: {reason}")})),
                None,
                0,
            )),
            _ => None,
        }
    }

    /// The agent's input as a call (`read`).
    pub fn read(&self, input: &Map<String, Value>) -> Result<ReadCall, String> {
        match self.id {
            "qwen-code" => read_claude_like(
                self.id,
                input,
                &["tool_use_id", "tool_call_id"],
                &["session_id"],
                &["permission_mode"],
            ),
            "kimi" => read_claude_like(
                self.id,
                input,
                &["tool_call_id", "tool_use_id"],
                &["session_id"],
                &["permission_mode"],
            ),
            "auggie" => read_auggie(input),
            "copilot-cli" => read_copilot(input),
            "grok" => read_grok(input),
            id => read_claude_like(
                id,
                input,
                &["tool_use_id"],
                &["session_id"],
                &["permission_mode"],
            ),
        }
    }
}

/// The text a shell tool under another name writes, when it is not in a
/// `command` field (`SHELL_TEXT`): the text a call writes to a shell
/// another call started (Auggie's write-process `input_text`; Copilot's
/// write_bash and write_powershell `input`), or a program with its
/// arguments apart (Command Code's monitor_command `command` and `args`).
fn shell_text(id: &str, tool: &str, input: &Map<String, Value>) -> Option<Option<String>> {
    let field = |k: &str| input.get(k).and_then(Value::as_str).map(str::to_string);
    match (id, tool) {
        ("auggie", "write-process") => Some(field("input_text")),
        ("copilot-cli", "write_bash" | "write_powershell") => Some(field("input")),
        ("command-code", "monitor_command") => Some({
            let args = input.get("args").cloned().unwrap_or_else(|| json!([]));
            match (
                input.get("command").and_then(Value::as_str),
                args.as_array(),
            ) {
                (Some(c), Some(a)) if a.iter().all(Value::is_string) => {
                    let mut words = vec![c.to_string()];
                    words.extend(a.iter().filter_map(Value::as_str).map(str::to_string));
                    Some(words.join(" "))
                }
                _ => None,
            }
        }),
        _ => None,
    }
}

/// The core's name and input for a call the agent named `raw`
/// (`shellRead`).
fn shell_read(id: &str, raw: &str, tool_input: Value) -> ReadCall {
    let lowered = raw.trim().to_lowercase();
    if !shell_aliases(id).contains(&lowered.as_str()) {
        return ReadCall {
            tool: raw.into(),
            tool_input,
            ..ReadCall::default()
        };
    }
    let empty = Map::new();
    let obj = tool_input.as_object().unwrap_or(&empty);
    match shell_text(id, &lowered, obj) {
        None => ReadCall {
            tool: "bash".into(),
            tool_input,
            ..ReadCall::default()
        },
        Some(Some(text)) if tool_input.is_object() => ReadCall {
            tool: "bash".into(),
            tool_input: json!({"command": text}),
            input_mapped: true,
            ..ReadCall::default()
        },
        Some(_) => ReadCall {
            tool: "bash".into(),
            tool_input,
            unresolved: Some(format!(
                "derm could not read the shell text of {}",
                one_line(raw, 64)
            )),
            ..ReadCall::default()
        },
    }
}

fn join_unresolved(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        (a, b) => a.or(b),
    }
}

/// The common read for agents whose input is Claude Code's
/// (`readClaudeLike`).
fn read_claude_like(
    id: &str,
    input: &Map<String, Value>,
    call_keys: &[&str],
    session_keys: &[&str],
    mode_keys: &[&str],
) -> Result<ReadCall, String> {
    let raw = str_of(input, &["tool_name"]).ok_or("hook input has no tool_name")?;
    let mut r = shell_read(
        id,
        raw,
        input
            .get("tool_input")
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    r.raw_tool = raw.into();
    r.call_id = str_of(input, call_keys).map(str::to_string);
    r.session = str_of(input, session_keys).map(str::to_string);
    r.mode = str_of(input, mode_keys).map(str::to_string);
    Ok(r)
}

/// Auggie names an MCP tool `<tool>_<server>`, which the core cannot split;
/// the server is known only from `mcp_metadata` (augment.mjs 0.36.0).
fn read_auggie(input: &Map<String, Value>) -> Result<ReadCall, String> {
    let mut r = read_claude_like(
        "auggie",
        input,
        &["tool_use_id"],
        &["conversation_id"],
        &["permission_mode"],
    )?;
    if input.get("is_mcp_tool") == Some(&Value::Bool(true)) {
        let meta = input.get("mcp_metadata").and_then(Value::as_object);
        let server = meta.and_then(|m| str_of(m, &["mcpExecutedToolServerName"]));
        let tool = meta.and_then(|m| str_of(m, &["mcpExecutedToolName"]));
        match (server, tool) {
            (Some(s), Some(t)) => r.tool = format!("mcp__{s}__{t}"),
            _ => r.unresolved = Some("Auggie did not name the MCP server".into()),
        }
    }
    Ok(r)
}

/// Copilot's camelCase preToolUse: `toolName`, `toolArgs` (an object or a
/// JSON string), `sessionId`; the PascalCase variant is Claude Code's shape.
fn read_copilot(input: &Map<String, Value>) -> Result<ReadCall, String> {
    let Some(raw) = input.get("toolName").and_then(Value::as_str) else {
        return read_claude_like(
            "copilot-cli",
            input,
            &["tool_use_id"],
            &["session_id"],
            &["permission_mode"],
        );
    };
    let mut args = input.get("toolArgs").cloned().unwrap_or_else(|| json!({}));
    if let Value::String(s) = &args {
        // Kept as the string when it does not parse: the core reads a string
        // input as it is.
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            args = v;
        }
    }
    let mut r = shell_read("copilot-cli", raw, args);
    r.raw_tool = raw.into();
    r.session = str_of(input, &["sessionId"]).map(str::to_string);
    Ok(r)
}

/// Grok sends both spellings. An MCP call comes as the bare
/// `<server>__<tool>` (hooks doc 1.0.71), so it is given the core's `mcp__`
/// prefix (L-S5); and an input whose long strings Grok cut is never allowed
/// as it is (L-S3).
fn read_grok(input: &Map<String, Value>) -> Result<ReadCall, String> {
    let raw = str_of(input, &["toolName", "tool_name"]).ok_or("hook input has no toolName")?;
    // `input.toolInput ?? input.tool_input ?? {}`: null counts as absent.
    let tool_input = ["toolInput", "tool_input"]
        .iter()
        .find_map(|k| input.get(*k).filter(|v| !v.is_null()))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut r = shell_read("grok", raw, tool_input);
    let mcp_prefixed = raw.len() >= 4 && raw[..4].eq_ignore_ascii_case("mcp_");
    if r.tool == raw && raw.contains("__") && !mcp_prefixed {
        r.tool = format!("mcp__{raw}");
    }
    let cut = (input.get("toolInputTruncated") != Some(&Value::Bool(false))).then(|| {
        "Grok cut the input's long strings (toolInputTruncated), so derm saw only their start"
            .to_string()
    });
    r.unresolved = join_unresolved(r.unresolved.take(), cut);
    r.raw_tool = raw.into();
    r.call_id = str_of(input, &["toolUseId", "tool_use_id"]).map(str::to_string);
    r.session = str_of(input, &["sessionId", "session_id"]).map(str::to_string);
    r.mode = str_of(input, &["permissionMode", "permission_mode"]).map(str::to_string);
    Ok(r)
}

/// A key for a call the agent gives no id (Droid, Auggie, Copilot): the
/// agent, the session, the tool and its input (`callKey`). Only joins
/// records; a decision's own id still ends in 128 random bits.
pub fn call_key(d: &Dialect, call: &ReadCall) -> String {
    let args = serde_json::to_string(&call.tool_input).unwrap_or_default();
    let text = format!(
        "{}\n{}\n{}\n{args}",
        d.id,
        call.session.as_deref().unwrap_or(""),
        call.raw_tool
    );
    super::sha256_hex(&text)[..16].to_string()
}

/// The decision for one call, before the reply is written (`Outcome`).
pub struct Outcome {
    pub decision: Action,
    pub reason: String,
    pub answer: GateAnswer,
}

/// `decide`: the core's answer, narrowed (control files, an unresolved
/// name, a rewrite the agent cannot take), then an ask resolved.
pub fn decide(d: &Dialect, call: &ReadCall, deps: &Deps) -> Outcome {
    let chat = chat_of(&deps.env, call.session.as_deref());
    let gate_call = GateCall {
        harness: d.id.into(),
        tool: call.tool.clone(),
        tool_input: call.tool_input.clone(),
        chat,
        tool_use_id: call.call_id.clone(),
        full_access: None,
    };
    let mut answer = decide_call(&deps.policy(), &gate_call, &deps.env);
    // Narrowing only, in this order; each turns an allow into an ask.
    let text = input_text_for(&answer.normalized_tool, &call.tool_input).unwrap_or_default();
    if let (a, Some(control)) =
        super::control::narrow(answer.action, super::control::agent_control_path(&text))
    {
        answer.action = a;
        answer.reason = format!("input names a control file ({control})");
    }
    if let Some(why) = &call.unresolved {
        if answer.action == Action::Allow {
            answer.action = Action::Ask;
            answer.reason = format!("{}; {why}", answer.reason);
        }
    }
    let can_rewrite = d.can_rewrite
        && !call.input_mapped
        && answer.updated_input.as_ref().is_some_and(Value::is_object);
    if answer.updated_input.is_some() && !can_rewrite && answer.action == Action::Allow {
        answer.action = Action::Ask;
        answer.reason = format!(
            "secret-like value in input that derm cannot rewrite on {}",
            d.name
        );
    }
    match answer.action {
        Action::Deny | Action::Allow => {
            return Outcome {
                decision: answer.action,
                reason: answer.reason.clone(),
                answer,
            }
        }
        Action::Ask => {}
    }
    let own = d.has_ask() && d.own_ask_in(call);
    let approve = deps.approver();
    let (decision, reason) = match resolve_ask(&answer, &gate_call, own, &deps.env, &approve) {
        AskResolution::Allow(r) => (Action::Allow, r),
        AskResolution::Deny(r) => (Action::Deny, r),
        AskResolution::Harness(r) => (Action::Ask, r),
    };
    Outcome {
        decision,
        reason,
        answer,
    }
}

/// `handlePre`.
pub fn handle_pre(d: &Dialect, input: &Map<String, Value>, deps: &Deps) -> Reply {
    // A hook registered for one event and run for another decides nothing.
    for key in ["hook_event_name", "hookEventName"] {
        if let Some(v) = input.get(key) {
            if !v.as_str().is_some_and(|s| d.events.contains(&s)) {
                return d.deny(&format!(
                    "unexpected hook event {}",
                    one_line(&super::js_string(v), 64)
                ));
            }
        }
    }
    let read = match d.read(input) {
        Ok(r) => r,
        Err(why) => return d.deny(&why),
    };
    let out = decide(d, &read, deps);
    let chat = chat_of(&deps.env, read.session.as_deref()).unwrap_or_default();
    let key = call_key(d, &read);
    let decision = super::action_str(out.decision);
    deps.post(
        &Decision {
            harness: d.id,
            id_part: Some(read.call_id.as_deref().unwrap_or(&key)),
            chat: &chat,
            tool: &out.answer.normalized_tool,
            decision,
            policy_action: out.answer.action,
            reason: &out.reason,
            redacted: out.answer.redacted,
            join: Some(match &read.call_id {
                Some(id) => ("toolUseId", id.as_str()),
                None => ("callKey", key.as_str()),
            }),
        }
        .event(),
    );
    // With no call id the records join by the call key, so the install
    // record carries it as its toolUseId.
    let install_call = GateCall {
        harness: d.id.into(),
        tool: read.tool.clone(),
        tool_input: read.tool_input.clone(),
        tool_use_id: Some(read.call_id.clone().unwrap_or_else(|| key.clone())),
        ..GateCall::default()
    };
    for e in install_events(&install_call, &out.answer, out.decision, &chat) {
        deps.post(&e);
    }
    match out.decision {
        Action::Deny => d.deny(&out.reason),
        Action::Ask => d
            .ask(&out.reason)
            .unwrap_or_else(|| d.deny(&format!("{}; {} cannot ask", out.reason, d.name))),
        Action::Allow => {
            let updated = out
                .answer
                .updated_input
                .as_ref()
                .filter(|u| d.can_rewrite && !read.input_mapped && u.is_object());
            d.allow(&out.reason, updated)
        }
    }
}

/// One hook call (`runHook`): every failure is the agent's deny.
pub fn run(agent: &str, event: &str, stdin: &[u8], deps: Deps) -> Reply {
    let Some(d) = dialect(agent) else {
        return reply(
            None,
            Some(format!("derm: unknown agent {}", one_line(agent, 64))),
            2,
        );
    };
    if event != "pre" {
        return reply(
            None,
            Some(format!("derm: unknown hook event {}", one_line(event, 64))),
            2,
        );
    }
    let env = super::token::hook_env(&deps.env, &super::token::default_socket_dirs());
    run_with(d, stdin, deps.with_env(env))
}

/// [`run`] once the environment is the hook's.
pub fn run_with(d: &Dialect, stdin: &[u8], deps: Deps) -> Reply {
    match parse_input(stdin) {
        Ok(input) => handle_pre(d, &input, &deps),
        Err(why) => d.deny(why),
    }
}
