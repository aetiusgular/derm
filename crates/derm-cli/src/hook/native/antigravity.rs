//! Google Antigravity CLI (`agy`), docs only (no seat, call 8): lane N read
//! antigravity.google/docs/hooks on 3 Nov; this lane read it again 10 Nov
//! (no version stamp, Starlight 0.41.5), and the fields below still hold.
//! - Stdin (camelCase): `{toolCall: {name, args}, stepIdx, conversationId,
//!   workspacePaths, transcriptPath, artifactDirectoryPath, modelName,
//!   lastUserInput}`. No call id and no event name.
//! - Stdout: `{"decision", "reason"}`; decision is required: allow
//!   (delegates to the next hook or the default policy), deny, ask (a
//!   remembered "Always Allow" answers it), force_ask (always prompts),
//!   deny_unless_prior_grant, and since this read auto_approve, which derm
//!   never sends. derm's ask is force_ask.
//! - Exit codes are not documented: every reply, deny included, is the JSON
//!   on exit 0.
//! - No input rewrite documented: a redacted input is a deny.
//! - Names: shell `run_command` (`args.CommandLine`), and `manage_task` with
//!   Action `send_input` types into a background task (`args.Input`), so both
//!   are `bash` (case 82). How an MCP tool is named is not on the hooks page
//!   (NF); every MCP call is taken to go through `call_mcp_tool`, read for a
//!   server and a tool, and an allow asks when either is missing.
//!
//! Ported from `packages/derm-hooks-native/src/dialects/antigravity.ts` at
//! `e29ce27`.

use serde_json::{json, Value};

use super::shell::{as_core_shell, ShellForm};
use super::{chat_from, derm, json_line, Dialect, Input, ReadCall};
use crate::gate::daemon::Env;
use crate::hook::Reply;

pub const ANTIGRAVITY_SHELL: ShellForm = ShellForm {
    names: &["run_command", "manage_task"],
    command_fields: &["CommandLine", "Input"],
};

const MCP_DISPATCHER: &str = "call_mcp_tool";

fn out(decision: &str, reason: &str) -> Reply {
    json_line(json!({"decision": decision, "reason": derm(reason)}))
}

fn str_of(o: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| match o.get(*k) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    })
}

/// `antigravityRead`.
pub fn read(input: &Input, env: &Env) -> Result<ReadCall, String> {
    let Some(Value::Object(call)) = input.get("toolCall") else {
        return Err("hook input has no toolCall".into());
    };
    let raw = match call.get("name") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err("hook input has no toolCall.name".into()),
    };
    let args = match call.get("args") {
        None | Some(Value::Null) => json!({}),
        Some(v) => v.clone(),
    };
    let mut read = if raw == "manage_task"
        && !(args.is_object() && args.get("Action") == Some(&json!("send_input")))
    {
        // Listing, killing or reading a task runs nothing new.
        ReadCall {
            tool: raw.clone(),
            raw_tool: raw.clone(),
            tool_input: args,
            ..ReadCall::default()
        }
    } else if raw == MCP_DISPATCHER {
        let a = match &args {
            Value::Object(o) => o.clone(),
            _ => serde_json::Map::new(),
        };
        let server = str_of(
            &a,
            &[
                "ServerName",
                "serverName",
                "server_name",
                "Server",
                "server",
            ],
        );
        let tool = str_of(
            &a,
            &[
                "ToolName",
                "toolName",
                "tool_name",
                "Tool",
                "tool",
                "Name",
                "name",
            ],
        );
        // `a.Arguments ?? a.arguments ?? a.Args ?? a.args ?? a`.
        let inner = ["Arguments", "arguments", "Args", "args"]
            .iter()
            .find_map(|k| a.get(*k).filter(|v| !v.is_null()).cloned())
            .unwrap_or_else(|| Value::Object(a.clone()));
        match (server, tool) {
            (Some(s), Some(t)) => ReadCall {
                tool: format!("mcp__{s}__{t}"),
                raw_tool: raw.clone(),
                tool_input: inner,
                ..ReadCall::default()
            },
            _ => ReadCall {
                tool: raw.clone(),
                raw_tool: raw.clone(),
                tool_input: args,
                ambiguous: Some("Antigravity's MCP call names no server derm can read".into()),
                ..ReadCall::default()
            },
        }
    } else {
        let (tool, tool_input) = as_core_shell(&ANTIGRAVITY_SHELL, &raw, &args);
        ReadCall {
            tool,
            raw_tool: raw.clone(),
            tool_input,
            ..ReadCall::default()
        }
    };
    read.chat = chat_from(env, input.get("conversationId"));
    if let (Some(Value::String(conv)), Some(Value::Number(step))) =
        (input.get("conversationId"), input.get("stepIdx"))
    {
        read.call_id = Some(format!("{conv}-{}", js_number(step)));
    }
    Ok(read)
}

/// `String(n)` for a JSON number in an id.
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

pub static ANTIGRAVITY: Dialect = Dialect {
    id: "antigravity",
    name: "Antigravity",
    read,
    own_ask: |_| true,
    allow: |reason, _| out("allow", reason),
    deny: |reason| out("deny", reason),
    ask: |reason| out("force_ask", reason),
    can_rewrite: false,
};
