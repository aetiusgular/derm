//! Claude Code (`packages/derm-claude-plugin/src/hook.ts` at `e29ce27`,
//! read at Claude Code 2.1.311's hooks docs; inputs recorded from 2.1.322 by
//! the wave 5b base, note BC section 2):
//! - PreToolUse's reply is `hookSpecificOutput.permissionDecision` allow,
//!   deny or ask, with `permissionDecisionReason` and `updatedInput` (which
//!   replaces the whole input). Exit 2 with stderr blocks the call.
//! - PostToolUse's `hookSpecificOutput.updatedToolOutput` replaces what the
//!   model sees, in the tool's own output shape. A post hook never blocks.
//! - In `bypassPermissions` and `dontAsk` Claude Code may not show the prompt
//!   a hook's ask requests, so an unanswered ask is a deny there.

use derm_core::policy::Action;
use serde_json::{json, Map, Value};

use super::{chat_of, none, parse_input, Decision, Deps};
use crate::gate::core::{decide_call, install_events, resolve_ask, AskResolution, GateCall};
use crate::hook::Reply;

pub const HARNESS: &str = "claude-code";

const NO_PROMPT_MODES: [&str; 2] = ["bypassPermissions", "dontAsk"];

/// Exit 2 blocks the call on PreToolUse; stderr is the reason Claude reads.
pub fn block_pre(reason: &str) -> Reply {
    Reply {
        stdout: String::new(),
        stderr: format!("derm: {reason}\n"),
        exit: 2,
    }
}

fn pre_output(decision: &str, reason: &str, updated: Option<Value>) -> Reply {
    let mut out = Map::new();
    out.insert("hookEventName".into(), json!("PreToolUse"));
    out.insert("permissionDecision".into(), json!(decision));
    out.insert(
        "permissionDecisionReason".into(),
        json!(format!("derm: {reason}")),
    );
    if let Some(u) = updated {
        out.insert("updatedInput".into(), u);
    }
    Reply {
        stdout: super::json_line(&json!({"hookSpecificOutput": out})),
        stderr: String::new(),
        exit: 0,
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
    let (decision, reason) = match answer.action {
        Action::Ask => {
            let mode = input
                .get("permission_mode")
                .map(super::js_string)
                .unwrap_or_default();
            let promptless = NO_PROMPT_MODES.contains(&mode.as_str());
            let approve = deps.approver();
            match resolve_ask(&answer, &call, !promptless, &deps.env, &approve) {
                AskResolution::Allow(r) => ("allow", r),
                AskResolution::Deny(r) => ("deny", r),
                AskResolution::Harness(r) => ("ask", r),
            }
        }
        a => (super::action_str(a), answer.reason.clone()),
    };
    let chat_s = chat.unwrap_or_default();
    deps.post(
        &Decision {
            harness: HARNESS,
            id_part: call.tool_use_id.as_deref(),
            chat: &chat_s,
            tool: &answer.normalized_tool,
            decision,
            policy_action: answer.action,
            reason: &reason,
            redacted: answer.redacted,
            join: call.tool_use_id.as_deref().map(|t| ("toolUseId", t)),
        }
        .event(),
    );
    for e in install_events(&call, &answer, parse_action(decision), &chat_s) {
        deps.post(&e);
    }
    let updated = if decision == "deny" {
        None
    } else {
        answer.updated_input.clone()
    };
    pre_output(decision, &reason, updated)
}

pub(super) fn parse_action(s: &str) -> Action {
    match s {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        _ => Action::Ask,
    }
}

/// The name the gate gives a tool, for a post record.
pub(super) fn gate_name(harness: &str, tool: &str, deps: &Deps) -> String {
    let call = GateCall {
        harness: harness.into(),
        tool: tool.into(),
        tool_input: json!({}),
        ..GateCall::default()
    };
    decide_call(&deps.policy(), &call, &deps.env).normalized_tool
}

pub fn handle_post(input: &Map<String, Value>, deps: &Deps) -> Reply {
    let tool = input.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let tool_use_id = input.get("tool_use_id").and_then(Value::as_str);
    let response = input.get("tool_response");
    let serialized = super::serialized(response, false);
    let (value, count) = match response {
        Some(r) => derm_core::redact::hook::redact_value(r),
        None => (Value::Null, 0),
    };
    let chat =
        chat_of(&deps.env, input.get("session_id").and_then(Value::as_str)).unwrap_or_default();
    let name = gate_name(HARNESS, tool, deps);
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
            "hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": value}
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
    if super::marks::run_by_cursor(&input) {
        return super::marks::cursor_run(pre, &deps.env);
    }
    if super::marks::run_by_grok(&input) {
        return super::marks::grok_run(pre, &deps.env);
    }
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
