//! Kiro CLI (`kiro-cli`), docs only (headless Kiro needs a paid key, call
//! 8). Lane N read kiro.dev/docs/hooks on 3 Nov; this lane read it again 10
//! Nov: /hooks ("Page updated: October 21, 2026"), /hooks/actions ("October
//! 10, 2026") and /hooks/types ("November 6, 2026").
//! - Registered as a standalone file `~/.kiro/hooks/derm.json` (CLI V3 loads
//!   global hooks from there): `{"version": "v1", "hooks": [{name, trigger:
//!   "PreToolUse", action: {type: "command", command}, timeout}]}`.
//! - Stdin: `{hook_event_name: "PreToolUse", cwd, session_id, tool_name,
//!   tool_input}` (the /types example). No call id.
//! - Exit 0: stdout "is added to the agent's context" (/actions), so derm
//!   prints nothing on allow (case 77). Any other exit: stderr goes to the
//!   agent and, for PreToolUse, "the tool invocation is blocked"; derm denies
//!   with exit 2 and the reason on stderr.
//! - No ask and no input rewrite from a PreToolUse command hook: an ask goes
//!   to derm's approver or is denied.
//! - Names: shell `execute_bash` (`execute_pwsh` on Windows; lane N's read
//!   of /tools, not read again: I); MCP tools use the sanitized internal id
//!   `mcp_<server>_<tool>` (/types), split with the configured server names
//!   ([`super::kiro_servers`]).
//!
//! Ported from `packages/derm-hooks-native/src/dialects/kiro.ts` at
//! `e29ce27`.

use super::kiro_servers::kiro_server_names;
use super::mcp_split::{split_single_underscore, Named, ServerNames};
use super::shell::{as_core_shell, ShellForm};
use super::{
    chat_from, cwd_of, derm, home, input_or_empty, none, shown, str_field, Dialect, Input, ReadCall,
};
use crate::gate::daemon::Env;
use crate::hook::Reply;

pub const KIRO_SHELL: ShellForm = ShellForm {
    names: &["execute_bash", "execute_pwsh"],
    command_fields: &["command"],
};

fn deny(reason: &str) -> Reply {
    Reply {
        stdout: String::new(),
        stderr: format!("{}\n", derm(reason)),
        exit: 2,
    }
}

/// `kiroReadWith`: the reader with the server names passed in.
pub fn read_with(
    input: &Input,
    env: &Env,
    server_names: &dyn Fn(&Input, &Env) -> ServerNames,
) -> Result<ReadCall, String> {
    if let Some(ev) = input.get("hook_event_name") {
        if ev != "PreToolUse" && ev != "preToolUse" {
            return Err(format!("unexpected hook event {}", shown(ev)));
        }
    }
    let raw = str_field(input, "tool_name").ok_or("hook input has no tool_name")?;
    let named = if raw.starts_with("mcp_") {
        split_single_underscore(raw, &server_names(input, env), "Kiro")
    } else {
        Named::plain(raw)
    };
    let (tool, tool_input) = as_core_shell(
        &KIRO_SHELL,
        &named.tool,
        &input_or_empty(input.get("tool_input")),
    );
    Ok(ReadCall {
        tool,
        raw_tool: raw.to_string(),
        tool_input,
        chat: chat_from(env, input.get("session_id")),
        call_id: None,
        ambiguous: named.ambiguous,
        defer_unless_deny: None,
    })
}

fn read(input: &Input, env: &Env) -> Result<ReadCall, String> {
    read_with(input, env, &|input, env| {
        kiro_server_names(cwd_of(input, "cwd"), &home(env))
    })
}

pub static KIRO: Dialect = Dialect {
    id: "kiro",
    name: "Kiro",
    read,
    own_ask: |_| false,
    // Nothing on stdout: on exit 0 it would reach the model (case 77).
    allow: |_, _| none(),
    deny,
    ask: deny,
    can_rewrite: false,
};
