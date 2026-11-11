//! Crush (charmbracelet/crush), read and run by lane N at v0.99.0; its
//! contract checks held at v0.100.0, the pin (note BC section 2; no newer tag
//! on 10 Nov).
//! - Registered as a flat entry in `hooks.PreToolUse` of
//!   `~/.config/crush/crush.json` (`{name, matcher, command, timeout}`), with
//!   an absolute command.
//! - Stdin: `{event, hook_event_name, session_id, cwd, tool_name, tool_input,
//!   tool_use_id}`. No server field.
//! - Allow: `{"decision": "allow"}` on exit 0 pre-approves (Crush skips its
//!   own prompt), so derm says it only for a rule's allow (case 72).
//! - Deny: exit 2 with the reason on stderr (stdout is ignored then).
//! - `ask` and anything but allow or deny read as no opinion, and exit 49 or
//!   `halt: true` end the turn (case 79): never used.
//! - Fails open, with no switch (case 70): the gate stays fast.
//! - Input rewrite: `updated_input`, a shallow merge over the input; derm
//!   sends every top-level key, so it replaces the whole input.
//! - Names: shell `bash`; MCP `mcp_<server>_<tool>` with single
//!   underscores, split with the configured server names
//!   ([`super::crush_servers`]).
//!
//! Ported from `packages/derm-hooks-native/src/dialects/crush.ts` at
//! `e29ce27`.

use serde_json::{json, Map, Value};

use super::crush_servers::crush_server_names;
use super::mcp_split::{split_single_underscore, Named, ServerNames};
use super::shell::{as_core_shell, ShellForm};
use super::{
    chat_from, cwd_of, derm, home, input_or_empty, shown, str_field, Dialect, Input, ReadCall,
};
use crate::gate::daemon::Env;
use crate::hook::Reply;

pub const CRUSH_SHELL: ShellForm = ShellForm {
    names: &[],
    command_fields: &["command"],
};

fn deny(reason: &str) -> Reply {
    Reply {
        stdout: String::new(),
        stderr: format!("{}\n", derm(reason)),
        exit: 2,
    }
}

fn allow(reason: &str, updated: Option<&Value>) -> Reply {
    let mut out = Map::new();
    out.insert("version".into(), json!(1));
    out.insert("decision".into(), json!("allow"));
    out.insert("reason".into(), json!(derm(reason)));
    if let Some(u) = updated {
        out.insert("updated_input".into(), u.clone());
    }
    super::json_line(Value::Object(out))
}

/// Crush's `mcp_<server>_<tool>` to the core's form.
pub fn crush_mcp_name(raw: &str, names: &ServerNames) -> Named {
    split_single_underscore(raw, names, "Crush")
}

/// `crushReadWith`: the reader with the server names passed in.
pub fn read_with(
    input: &Input,
    env: &Env,
    server_names: &dyn Fn(&Input, &Env) -> ServerNames,
) -> Result<ReadCall, String> {
    // `input.hook_event_name ?? input.event`: a null event is still an event.
    let ev = input
        .get("hook_event_name")
        .filter(|v| !v.is_null())
        .or_else(|| input.get("event"));
    if let Some(ev) = ev {
        if ev != "PreToolUse" {
            return Err(format!("unexpected hook event {}", shown(ev)));
        }
    }
    let raw = str_field(input, "tool_name").ok_or("hook input has no tool_name")?;
    let named = if raw.starts_with("mcp_") {
        crush_mcp_name(raw, &server_names(input, env))
    } else {
        Named::plain(raw)
    };
    let (tool, tool_input) = as_core_shell(
        &CRUSH_SHELL,
        &named.tool,
        &input_or_empty(input.get("tool_input")),
    );
    Ok(ReadCall {
        tool,
        raw_tool: raw.to_string(),
        tool_input,
        chat: chat_from(env, input.get("session_id")),
        call_id: str_field(input, "tool_use_id").map(str::to_string),
        ambiguous: named.ambiguous,
        defer_unless_deny: None,
    })
}

fn read(input: &Input, env: &Env) -> Result<ReadCall, String> {
    read_with(input, env, &|input, env| {
        crush_server_names(env, cwd_of(input, "cwd"), &home(env))
    })
}

pub static CRUSH: Dialect = Dialect {
    id: "crush",
    name: "Crush",
    read,
    own_ask: |_| false,
    allow,
    deny,
    ask: deny,
    can_rewrite: true,
};
