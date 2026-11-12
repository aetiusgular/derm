//! Codex (`packages/derm-codex-plugin/src/hook.ts` at `e29ce27`, read in
//! Codex's source at rust-v0.163.0; its hook runner re-read at rust-v0.167.1
//! by the wave 5b base, unchanged, `contracts/hook-dialects.md` 9.1):
//! - PreToolUse blocks on exit 2 with a non-empty stderr reason.
//! - `ask` is not supported (Codex marks the run failed and the call goes
//!   on), so a policy ask goes to the derm approver and anything but an
//!   approver's yes is a deny.
//! - Every failed run lets the call through: Codex fails open. So every
//!   path here ends in a decision.
//! - `updatedInput` needs `allow` and replaces an MCP tool's arguments
//!   whole; for Bash and apply_patch it must carry a string `command`, so
//!   only MCP input is rewritten, and a secret in anything else is a deny.
//! - PostToolUse cannot rewrite output; `decision: "block"` replaces the
//!   tool result with the reason.

use derm_core::policy::Action;
use serde_json::{json, Map, Value};

use super::{chat_of, none, parse_input, Decision, Deps};
use crate::gate::core::{decide_call, install_events, resolve_ask, AskResolution, GateCall};
use crate::hook::Reply;

pub const HARNESS: &str = "codex";

/// Codex reads stderr as the block reason; it must not be empty.
pub fn block_pre(reason: &str) -> Reply {
    let text = super::squash(reason);
    let text = if text.is_empty() {
        "blocked".into()
    } else {
        text
    };
    Reply {
        stdout: String::new(),
        stderr: format!("derm: {text}\n"),
        exit: 2,
    }
}

pub fn handle_pre(input: &Map<String, Value>, deps: &Deps) -> Reply {
    let Some(tool) = input
        .get("tool_name")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    else {
        return block_pre("hook input has no tool_name");
    };
    let chat = chat_of(&deps.env, input.get("session_id").and_then(Value::as_str));
    let call = GateCall {
        harness: HARNESS.into(),
        tool: tool.into(),
        tool_input: input
            .get("tool_input")
            .cloned()
            .unwrap_or_else(|| json!({})),
        chat: chat.clone(),
        tool_use_id: input
            .get("tool_use_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        full_access: None,
    };
    let answer = decide_call(&deps.policy(), &call, &deps.env);
    let (mut action, mut reason) = (answer.action, answer.reason.clone());
    if action == Action::Ask {
        let approve = deps.approver();
        match resolve_ask(&answer, &call, false, &deps.env, &approve) {
            AskResolution::Allow(r) => (action, reason) = (Action::Allow, r),
            AskResolution::Deny(r) | AskResolution::Harness(r) => {
                (action, reason) = (Action::Deny, r)
            }
        }
    }
    let is_mcp = tool.starts_with("mcp__");
    if action == Action::Allow && answer.updated_input.is_some() && !is_mcp {
        action = Action::Deny;
        reason = "secret-like value in input of a tool derm cannot rewrite on Codex".into();
    }
    let chat_s = chat.unwrap_or_default();
    deps.post(
        &Decision {
            harness: HARNESS,
            id_part: call.tool_use_id.as_deref(),
            chat: &chat_s,
            tool: &answer.normalized_tool,
            decision: super::action_str(action),
            policy_action: answer.action,
            reason: &reason,
            redacted: answer.redacted,
            join: call.tool_use_id.as_deref().map(|t| ("toolUseId", t)),
        }
        .event(),
    );
    for e in install_events(&call, &answer, action, &chat_s) {
        deps.post(&e);
    }
    if action == Action::Deny {
        return block_pre(&reason);
    }
    if let Some(updated) = &answer.updated_input {
        return Reply {
            stdout: super::json_line(&json!({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": format!("derm: {reason}"),
                "updatedInput": updated,
            }})),
            stderr: String::new(),
            exit: 0,
        };
    }
    // Allow: say nothing, so Codex's own approval flow runs as configured.
    none()
}

pub fn handle_post(input: &Map<String, Value>, deps: &Deps) -> Reply {
    let tool = input.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let tool_use_id = input.get("tool_use_id").and_then(Value::as_str);
    let response = input.get("tool_response");
    let serialized = super::serialized(response, true);
    let (value, count) = match response {
        Some(r) => derm_core::redact::hook::redact_value(r),
        None => (Value::Null, 0),
    };
    let chat =
        chat_of(&deps.env, input.get("session_id").and_then(Value::as_str)).unwrap_or_default();
    let name = super::claude_code::gate_name(HARNESS, tool, deps);
    deps.post(&super::tool_call_event(
        format!("{HARNESS}-{}", tool_use_id.unwrap_or("unknown")),
        HARNESS,
        &chat,
        &name,
        &serialized,
        count,
        tool_use_id.map(|t| ("toolUseId", t)),
    ));
    if count == 0 {
        return none();
    }
    Reply {
        stdout: super::json_line(&json!({
            "decision": "block",
            "reason": format!("derm replaced this output: {} redacted.\n{}", super::values(count), super::reason_text(&value)),
        })),
        stderr: String::new(),
        exit: 0,
    }
}

/// One hook call (`runHook`). `event` is `pre` or `post`.
pub fn run(event: &str, stdin: &[u8], deps: Deps) -> Reply {
    let pre = event == "pre";
    let input = match parse_input(stdin) {
        Ok(i) => i,
        Err(why) => return if pre { block_pre(why) } else { none() },
    };
    if pre {
        if let Some(e) = input.get("hook_event_name") {
            if e != "PreToolUse" {
                return block_pre(&format!("unexpected hook event {}", super::js_string(e)));
            }
        }
        return handle_pre(&input, &deps);
    }
    handle_post(&input, &deps)
}
