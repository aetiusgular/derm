//! goose (block/goose): lane N read and ran 1.57.0; the wave 5b base
//! recorded 1.58.1's PreToolUse input (`tk_w5b_base.md`, part 2); this lane
//! read 1.59.0 on 10 Nov: `crates/goose/src/hooks/mod.rs` and
//! `plugins/` are unchanged from 1.58.1, and the new
//! `agents/state_machine/pre_tool_hook.rs` still sends PreToolUse through
//! `emit_blocking_with_outcome` and adds an observe-only PreToolUseResult.
//! - Registered as a plugin `~/.agents/plugins/<name in ~/.derm/gate-name>/` (BC-1) with `plugin.json` and
//!   `hooks/hooks.json`: `PreToolUse[{matcher, hooks: [{type: "command",
//!   command, timeout, on_failure: "block"}]}]`; the command runs under
//!   `sh -c`.
//! - Stdin (`HookContext`, `hooks/mod.rs:222-256` at v1.59.0): `{event,
//!   session_id, matcher_context, tool_call_id, tool_name, tool_input,
//!   working_dir}`. No server field.
//! - Deny: exit 2 with the reason on stderr, or `{"decision": "block",
//!   "reason"}` on stdout at any exit (`classify_output`, `:897-940`). This
//!   hook does both. Allow: exit 0 with nothing printed. No ask, no rewrite.
//! - A failed hook allows unless `on_failure` is "block" (`apply_verdict`,
//!   `:853-866`), which derm's registration sets.
//! - Names: built-in tools bare (`shell`, `write`, `edit`), extension tools
//!   `<extension key>__<tool>`; the key keeps `[A-Za-z0-9_-]` lowercased, so
//!   it can hold `__` itself, and a name with two runs of `__` cannot say
//!   where the extension ends: an allow there asks.
//! - BC-1 (high, run by the base): goose loads a project's
//!   `.agents/plugins/<name>/` before user plugins and keeps the first name,
//!   so a repository can replace derm's goose gate. That is registration's
//!   to close (lane 5bF); here the control list keeps `.agents/plugins/`.
//!
//! Ported from `packages/derm-hooks-native/src/dialects/goose.ts` at
//! `e29ce27`.

use serde_json::json;

use super::shell::{as_core_shell, ShellForm};
use super::{chat_from, derm, input_or_empty, none, shown, str_field, Dialect, Input, ReadCall};
use crate::gate::daemon::Env;
use crate::hook::Reply;

pub const GOOSE_SHELL: ShellForm = ShellForm {
    names: &["shell"],
    command_fields: &["command"],
};

fn block(reason: &str) -> Reply {
    let text = derm(reason);
    Reply {
        stdout: format!("{}\n", json!({"decision": "block", "reason": text})),
        stderr: format!("{text}\n"),
        exit: 2,
    }
}

/// How many runs of two or more `_` a name holds.
pub fn underscore_runs(name: &str) -> usize {
    let mut runs = 0;
    let mut len = 0;
    for c in name.chars().chain(std::iter::once('\0')) {
        if c == '_' {
            len += 1;
        } else {
            if len >= 2 {
                runs += 1;
            }
            len = 0;
        }
    }
    runs
}

/// `gooseRead`.
pub fn read(input: &Input, env: &Env) -> Result<ReadCall, String> {
    if let Some(ev) = input.get("event") {
        if ev != "PreToolUse" {
            return Err(format!("unexpected hook event {}", shown(ev)));
        }
    }
    let raw = str_field(input, "tool_name").ok_or("hook input has no tool_name")?;
    let (tool, tool_input) =
        as_core_shell(&GOOSE_SHELL, raw, &input_or_empty(input.get("tool_input")));
    Ok(ReadCall {
        tool,
        raw_tool: raw.to_string(),
        tool_input,
        chat: chat_from(env, input.get("session_id")),
        call_id: str_field(input, "tool_call_id").map(str::to_string),
        ambiguous: (underscore_runs(raw) > 1)
            .then(|| "ambiguous extension name: goose's key can hold __ itself".to_string()),
        defer_unless_deny: None,
    })
}

pub static GOOSE: Dialect = Dialect {
    id: "goose",
    name: "goose",
    read,
    own_ask: |_| false,
    allow: |_, _| none(),
    deny: block,
    // Never reached: goose shows no prompt for a hook (own_ask false).
    ask: block,
    can_rewrite: false,
};
