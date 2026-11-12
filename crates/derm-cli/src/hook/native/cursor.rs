//! Cursor CLI (`agent`), docs only for this lane (no account, call 8); the
//! wave 5b base recorded seven inputs from Cursor 2026.11.10-731fb78 on the
//! Mac (`tk_w5b_base.md`, part 2: a project `.cursor/hooks.json` ran under
//! `-p --trust` with no further prompt; new fields `cwd` and `sandbox`).
//! - Registered in `~/.cursor/hooks.json`, version 1, on two events with
//!   `failClosed: true`: preToolUse (every tool: Shell, Read, Write, Grep,
//!   Delete, Task and `MCP:<tool>`) and beforeMCPExecution (MCP calls, with
//!   the server).
//! - preToolUse in: `{tool_name, tool_input, tool_use_id, cwd, ...}` plus the
//!   common fields (`conversation_id`, `generation_id`, `cursor_version`,
//!   `hook_event_name`, `workspace_roots`, ...). Out: `{permission: "allow" |
//!   "deny", user_message, agent_message, updated_input}`. "ask" is accepted
//!   by its schema and not enforced there, so derm never sends it on
//!   preToolUse: an ask goes to derm's approver or is denied.
//! - preToolUse names an MCP tool `MCP:<tool>` with no server (case 73), so
//!   it denies what the policy denies outright and leaves the rest to
//!   beforeMCPExecution (the deferral pair, case 110), which carries
//!   `mcp_server_name` and takes allow, deny and ask (Cursor's own prompt).
//! - beforeMCPExecution in: `{tool_name, tool_input (a JSON string),
//!   mcp_server_name, url | command}`. No `updated_input` there. A missing
//!   server name denies, as the docs advise.
//! - Whose input (contracts/hook-dialects.md 9.2, BCR-7): Grok 1.0.77 runs
//!   the hooks in `~/.cursor/hooks.json` after folder trust, by default, so
//!   `derm hook cursor pre` can fire inside Grok. An input with no
//!   `cursor_version`, or with an event Cursor does not send, is not Cursor's:
//!   it is denied with the fix named, never decided in Cursor's dialect.
//!   What Grok's run of a Cursor hook carries is NF, so the deferral case 109
//!   allows (derm's own Grok gate registered and failing closed) is not
//!   built here; the block holds against it.
//!
//! Ported from `packages/derm-hooks-native/src/dialects/cursor.ts` at
//! `e29ce27`.

use serde_json::{json, Value};

use super::shell::{as_core_shell, ShellForm};
use super::{chat_from, derm, input_or_empty, json_line, str_field, Dialect, Input, ReadCall};
use crate::gate::daemon::Env;
use crate::hook::Reply;

pub const CURSOR_SHELL: ShellForm = ShellForm {
    names: &["Shell"],
    command_fields: &["command"],
};

/// What a non-Cursor input is told: the agent that runs Cursor's hooks has
/// an import to turn off.
pub const NOT_CURSORS: &str = "another agent ran Cursor's hooks (Grok imports ~/.cursor/hooks.json by default): turn that import off ([compat.cursor] hooks = false in Grok's config) and register derm's gate for that agent";

fn deny(reason: &str) -> Reply {
    let text = derm(reason);
    json_line(json!({"permission": "deny", "user_message": text, "agent_message": text}))
}

fn allow(_reason: &str, updated: Option<&Value>) -> Reply {
    json_line(match updated {
        None => json!({"permission": "allow"}),
        Some(u) => json!({"permission": "allow", "updated_input": u}),
    })
}

fn ask(reason: &str) -> Reply {
    let text = derm(reason);
    json_line(json!({"permission": "ask", "user_message": text, "agent_message": text}))
}

fn event(input: &Input) -> &str {
    input
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// `cursorRead`, with Cursor's own marks checked (9.2).
pub fn read(input: &Input, env: &Env) -> Result<ReadCall, String> {
    let ev = event(input);
    if ev != "preToolUse" && ev != "beforeMCPExecution" {
        let shown: String = ev.encode_utf16().take(40).collect::<Vec<u16>>().pipe();
        let shown = if shown.is_empty() {
            "(none)".to_string()
        } else {
            shown
        };
        let fix = if ev == "PreToolUse" || ev == "BeforeTool" {
            format!("; {NOT_CURSORS}")
        } else {
            String::new()
        };
        return Err(format!("unexpected hook event {shown}{fix}"));
    }
    if !matches!(input.get("cursor_version"), Some(Value::String(s)) if !s.is_empty()) {
        return Err(format!(
            "the hook input has no cursor_version, so it is not Cursor's; {NOT_CURSORS}"
        ));
    }
    let chat = chat_from(env, input.get("conversation_id"));
    let call_id = str_field(input, "tool_use_id")
        .or_else(|| str_field(input, "generation_id"))
        .map(str::to_string);
    let base = |r: ReadCall| ReadCall {
        chat: chat.clone(),
        call_id: call_id.clone(),
        ..r
    };
    if ev == "beforeMCPExecution" {
        let server = str_field(input, "mcp_server_name").ok_or("Cursor gave no MCP server name")?;
        let tool = str_field(input, "tool_name").ok_or("hook input has no tool_name")?;
        let mut tool_input = input_or_empty(input.get("tool_input"));
        if let Value::String(s) = &tool_input {
            // Not JSON: the gate reads the text as it is.
            if let Ok(v) = serde_json::from_str::<Value>(s) {
                tool_input = v;
            }
        }
        return Ok(base(ReadCall {
            tool: format!("mcp__{server}__{tool}"),
            raw_tool: format!("{server}/{tool}"),
            tool_input,
            ..ReadCall::default()
        }));
    }
    let raw = str_field(input, "tool_name").ok_or("hook input has no tool_name")?;
    if let Some(bare) = raw.strip_prefix("MCP:") {
        if bare.is_empty() {
            return Err("hook input names an MCP tool with no name".into());
        }
        return Ok(base(ReadCall {
            tool: bare.to_string(),
            raw_tool: raw.to_string(),
            tool_input: input_or_empty(input.get("tool_input")),
            defer_unless_deny: Some(
                "MCP call: decided in beforeMCPExecution, which names the server".into(),
            ),
            ..ReadCall::default()
        }));
    }
    let (tool, tool_input) =
        as_core_shell(&CURSOR_SHELL, raw, &input_or_empty(input.get("tool_input")));
    Ok(base(ReadCall {
        tool,
        raw_tool: raw.to_string(),
        tool_input,
        ..ReadCall::default()
    }))
}

trait Pipe {
    fn pipe(self) -> String;
}
impl Pipe for Vec<u16> {
    fn pipe(self) -> String {
        char::decode_utf16(self).filter_map(Result::ok).collect()
    }
}

pub static CURSOR: Dialect = Dialect {
    id: "cursor",
    name: "Cursor",
    read,
    // Only beforeMCPExecution enforces an ask.
    own_ask: |input| event(input) == "beforeMCPExecution",
    allow,
    deny,
    ask,
    // updated_input exists on preToolUse only; MCP calls are decided where it
    // does not, so a redacted MCP input is a deny there.
    can_rewrite: false,
};
