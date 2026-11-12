//! Mistral Vibe (mistralai/mistral-vibe): lane N read 3.0.3 and 3.0.4; the
//! wave 5b base recorded 3.1.1's pre_tool input (`tk_w5b_base.md`, part 2);
//! this lane diffed 3.1.1 to 3.1.2 on 10 Nov: `vibe/core/hooks/`,
//! `_foreign_hooks.py`, `_hook_matcher.py` and `_mcp_naming.py` are
//! unchanged (3.1.2 adds a session-only `trusting()` to the harness files
//! manager, which widens what BC-2 covers, lane 5bF's).
//! - Registered as `[[hooks]]` in `~/.vibe/hooks.toml`: name, type
//!   "pre_tool", command, timeout, `strict = true` (a failed hook denies).
//! - Stdin: `{session_id, transcript_path, cwd, parent_session_id,
//!   hook_event_name, tool_name, tool_call_id, tool_input}`; `tool_name` is
//!   qualified (`file_system.bash`, `process.start`, `mcp_<server>.<tool>`).
//! - Deny: `{"decision": "deny", "reason"}` on exit 0. Exit 2 is a failure,
//!   not a deny. Allow: nothing printed; Vibe's own permission check follows
//!   (case 72). No ask. Rewrite: `hook_specific_output.tool_input`.
//! - Names: `<group>.<tool>`; an MCP group is `mcp_` plus the server name
//!   folded to identifier characters, so exactly one `.` splits an MCP name
//!   plainly. Built-in tools map to the names Vibe's own matcher gives the
//!   model; the shell tools (`file_system.bash`, `process.start`, and
//!   `process.write`, which types into a running process) become `bash`
//!   (case 82).
//!
//! Ported from `packages/derm-hooks-native/src/dialects/mistralVibe.ts` at
//! `e29ce27`.

use serde_json::{json, Value};

use super::mcp_split::Named;
use super::shell::{as_core_shell, ShellForm};
use super::{
    chat_from, derm, input_or_empty, json_line, none, shown, str_field, Dialect, Input, ReadCall,
};
use crate::gate::daemon::Env;
use crate::hook::Reply;

pub const VIBE_SHELL: ShellForm = ShellForm {
    names: &["file_system.bash", "process.start", "process.write"],
    command_fields: &["command", "text"],
};

/// Vibe's built-in names to the names its own matcher gives the model
/// (`_hook_matcher.py:61-87`).
pub const VIBE_BUILTIN_NAMES: [(&str, &str); 14] = [
    ("self.wait", "wait"),
    ("self.sleep", "sleep"),
    ("file_system.read_file", "read_file"),
    ("file_system.write_file", "write_file"),
    ("file_system.edit", "edit"),
    ("skill.read", "skill"),
    ("process.output", "process_output"),
    ("process.list", "process_list"),
    ("process.stop", "process_stop"),
    ("agents.list_configs", "agents_list_configs"),
    ("agents.list", "agents_list"),
    ("agents.spawn", "agents_spawn"),
    ("agents.send_message", "agents_send_message"),
    ("agents.interrupt", "agents_interrupt"),
];

fn deny(reason: &str) -> Reply {
    json_line(json!({"decision": "deny", "reason": derm(reason)}))
}

fn allow(_reason: &str, updated: Option<&Value>) -> Reply {
    match updated {
        None => none(),
        Some(u) => json_line(json!({"hook_specific_output": {"tool_input": u}})),
    }
}

/// The name the core matches, and whether its server split is in doubt
/// (`vibeName`).
pub fn vibe_name(raw: &str) -> Named {
    if raw.starts_with("mcp_") {
        let dots = raw.matches('.').count();
        let dot = raw.find('.');
        if let Some(dot) = dot.filter(|&d| dots == 1 && d > 4 && d < raw.len() - 1) {
            return Named::plain(format!("mcp__{}__{}", &raw[4..dot], &raw[dot + 1..]));
        }
        return Named {
            tool: raw.replace('.', "_"),
            ambiguous: Some(
                "ambiguous server name: Vibe's MCP name does not split at one dot".into(),
            ),
        };
    }
    Named::plain(
        VIBE_BUILTIN_NAMES
            .iter()
            .find(|(k, _)| *k == raw)
            .map(|(_, v)| *v)
            .unwrap_or(raw),
    )
}

/// `Buffer.from(s, "base64")`: the standard and the URL-safe alphabet,
/// anything else skipped, stopping at `=`.
pub fn base64_lenient(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            _ => continue,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// `process.write` may carry its text base64-encoded; the gate reads the
/// text (`decodeWrite`).
fn decode_write(tool_input: Value) -> Value {
    match &tool_input {
        Value::Object(o) => match (o.get("bytesBase64"), o.get("text")) {
            (Some(Value::String(b)), t) if !matches!(t, Some(Value::String(_))) => {
                let mut o = o.clone();
                let text = String::from_utf8_lossy(&base64_lenient(b)).into_owned();
                o.insert("text".into(), Value::String(text));
                Value::Object(o)
            }
            _ => tool_input,
        },
        _ => tool_input,
    }
}

/// `vibeRead`.
pub fn read(input: &Input, env: &Env) -> Result<ReadCall, String> {
    if let Some(ev) = input.get("hook_event_name") {
        if ev != "pre_tool" {
            return Err(format!("unexpected hook event {}", shown(ev)));
        }
    }
    let raw = str_field(input, "tool_name").ok_or("hook input has no tool_name")?;
    let given = input_or_empty(input.get("tool_input"));
    let raw_input = if raw == "process.write" {
        decode_write(given)
    } else {
        given
    };
    let (shell_tool, tool_input) = as_core_shell(&VIBE_SHELL, raw, &raw_input);
    let named = if shell_tool == "bash" {
        Named::plain("bash")
    } else {
        vibe_name(raw)
    };
    Ok(ReadCall {
        tool: named.tool,
        raw_tool: raw.to_string(),
        tool_input,
        chat: chat_from(env, input.get("session_id")),
        call_id: str_field(input, "tool_call_id").map(str::to_string),
        ambiguous: named.ambiguous,
        defer_unless_deny: None,
    })
}

pub static MISTRAL_VIBE: Dialect = Dialect {
    id: "mistral-vibe",
    name: "Mistral Vibe",
    read,
    own_ask: |_| false,
    allow,
    deny,
    ask: deny,
    can_rewrite: true,
};
