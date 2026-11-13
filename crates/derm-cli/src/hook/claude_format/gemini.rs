//! Gemini CLI (`packages/derm-gemini-extension/src/hook.ts` at `e29ce27`,
//! read in gemini-cli v0.66.0 and run against 0.66.0 and 0.65.0; the hook
//! runner re-read at v0.68.0 by the wave 5b base, unchanged; inputs recorded
//! from 0.67.0, note BC section 2):
//! - BeforeTool's block is `{"decision":"deny","reason"}` on exit 0, or
//!   exit 2 with the reason on stderr; this hook does both, so a block
//!   survives either reading.
//! - `{"decision":"ask"}` forces Gemini's own confirmation.
//! - An allow cannot approve (Gemini's policy runs after the hook), so an
//!   allow prints nothing; `hookSpecificOutput.tool_input` replaces the
//!   arguments.
//! - Gemini fails open on a crash, a signal, any exit but 0 and 2, and a
//!   timeout, so every path ends in a decision.
//! - AfterTool's `{"decision":"deny","reason"}` replaces the tool's result.
//! - Gemini gives a hook no call id: records join by a key made from the
//!   session, the tool and its arguments.
//! - Gemini strips secret-named variables from a hook's environment when
//!   its redaction is on, so the token file's path is also read from
//!   `GEMINI_CLI_DERM_CHAT_TOKEN_FILE` (`env.ts`).

use derm_core::policy::Action;
use serde_json::{json, Map, Value};

use super::{chat_of, none, parse_input, Decision, Deps};
use crate::gate::core::{
    decide_call, input_text_for, install_events, resolve_ask, AskResolution, GateCall,
};
use crate::gate::daemon::Env;
use crate::hook::Reply;

pub const HARNESS: &str = "gemini";
pub const TOKEN_FILE_ALIAS: &str = "GEMINI_CLI_DERM_CHAT_TOKEN_FILE";

/// The hook's environment with the token file's alias read (`hookEnv`):
/// only the file's path is aliased, never a raw token, and only when
/// `DERM_CHAT_TOKEN_FILE` is absent.
pub fn hook_env(env: &Env) -> Env {
    match (env.get("DERM_CHAT_TOKEN_FILE"), env.get(TOKEN_FILE_ALIAS)) {
        (None, Some(alias)) => env.with("DERM_CHAT_TOKEN_FILE", alias),
        _ => env.clone(),
    }
}

fn one_line(reason: &str) -> String {
    let t = super::squash(reason);
    if t.is_empty() {
        "blocked".into()
    } else {
        t
    }
}

/// A block Gemini reads either way: a deny on stdout, the reason on stderr,
/// exit 2.
pub fn block(reason: &str) -> Reply {
    let text = format!("derm: {}", one_line(reason));
    Reply {
        stdout: super::json_line(&json!({"decision": "deny", "reason": text})),
        stderr: format!("{text}\n"),
        exit: 2,
    }
}

fn ask(reason: &str) -> Reply {
    let r = one_line(reason);
    Reply {
        stdout: super::json_line(&json!({
            "decision": "ask",
            "reason": format!("derm: {r}"),
            "systemMessage": format!("derm asks: {r}"),
        })),
        stderr: String::new(),
        exit: 0,
    }
}

/// The key BeforeTool's and AfterTool's records share (`callKey`): the
/// first 16 hex of the SHA-256 of the session, the tool and its arguments.
pub fn call_key(input: &Map<String, Value>) -> String {
    let args =
        serde_json::to_string(input.get("tool_input").unwrap_or(&json!({}))).unwrap_or_default();
    // `String(input[k] ?? "")`: absent and null are "".
    let field = |k: &str| match input.get(k) {
        None | Some(Value::Null) => String::new(),
        Some(v) => super::js_string(v),
    };
    let text = format!("{}\n{}\n{args}", field("session_id"), field("tool_name"));
    super::sha256_hex(&text)[..16].to_string()
}

/// The post record's id: the call key and Gemini's timestamp, so two
/// identical calls stay two records.
fn record_id(input: &Map<String, Value>) -> String {
    let at = match input.get("timestamp").and_then(Value::as_str) {
        Some(t) => t.chars().filter(char::is_ascii_alphanumeric).collect(),
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_default(),
    };
    format!("{HARNESS}-{}-{at}", call_key(input))
}

/// Gemini CLI 0.68.0's own tools under the names the policy's rules use
/// (integration w6's close, E0's R-E0-4; rules cases 82 and 243):
/// `run_shell_command` is a shell (`coverage.shellAliases`), the rest its
/// file, search and fetch tools (`coverage.toolAliases`). Names from
/// `@google/gemini-cli-core@0.68.0` `dist/src/tools/definitions/
/// base-declarations.js:25-75` (read). Held equal to the preset row by a
/// test. E0 found every call of these asking under the default preset.
pub const TOOL_ALIASES: &[(&str, &str)] = &[
    ("run_shell_command", "bash"),
    ("read_file", "read"),
    ("read_many_files", "read"),
    ("list_directory", "ls"),
    ("grep_search", "grep"),
    ("write_file", "write"),
    ("replace", "edit"),
    ("web_fetch", "webfetch"),
    ("google_web_search", "websearch"),
    ("write_todos", "todowrite"),
];

/// The name the gate matches (`toolForGate`): `mcp__<server>__<tool>` from
/// `mcp_context` when it names both, since `mcp_<server>_<tool>` misreads a
/// server whose name holds `_`; else the policy's name for one of Gemini's
/// own tools (`TOOL_ALIASES`); else the tool's own name.
pub fn tool_for_gate(input: &Map<String, Value>) -> String {
    let name = input
        .get("tool_name")
        .map(super::js_string)
        .unwrap_or_default();
    let ctx = input.get("mcp_context").and_then(Value::as_object);
    let part = |k: &str| {
        ctx.and_then(|c| c.get(k))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    match (part("server_name"), part("tool_name")) {
        (Some(s), Some(t)) => format!("mcp__{s}__{t}"),
        _ => TOOL_ALIASES
            .iter()
            .find(|(raw, _)| *raw == name)
            .map_or(name.clone(), |(_, policy)| (*policy).to_string()),
    }
}

pub fn handle_before(input: &Map<String, Value>, deps: &Deps) -> Reply {
    if !input
        .get("tool_name")
        .and_then(Value::as_str)
        .is_some_and(|t| !t.is_empty())
    {
        return block("hook input has no tool_name");
    }
    let chat = chat_of(&deps.env, input.get("session_id").and_then(Value::as_str));
    let tool_input = input
        .get("tool_input")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let call = GateCall {
        harness: HARNESS.into(),
        tool: tool_for_gate(input),
        tool_input: tool_input.clone(),
        chat: chat.clone(),
        tool_use_id: None,
        full_access: None,
    };
    let mut answer = decide_call(&deps.policy(), &call, &deps.env);
    let text = input_text_for(&answer.normalized_tool, &tool_input).unwrap_or_default();
    if let (a, Some(control)) =
        super::control::narrow(answer.action, super::control::gemini_control_path(&text))
    {
        answer.action = a;
        answer.reason = format!("input names a control file ({control})");
    }
    let (mut action, mut reason, mut gemini_asks) = (answer.action, answer.reason.clone(), false);
    if action == Action::Ask {
        // Gemini shows its own prompt, so with no derm approver the ask
        // goes to Gemini; an approver's no, or a timeout, denies.
        let approve = deps.approver();
        match resolve_ask(&answer, &call, true, &deps.env, &approve) {
            AskResolution::Allow(r) => (action, reason) = (Action::Allow, r),
            AskResolution::Deny(r) => (action, reason) = (Action::Deny, r),
            AskResolution::Harness(r) => (gemini_asks, reason) = (true, r),
        }
    }
    let key = call_key(input);
    let shown = if gemini_asks { Action::Ask } else { action };
    let chat_s = chat.unwrap_or_default();
    let lost = deps.post_decision(
        &Decision {
            harness: HARNESS,
            id_part: Some(&key),
            chat: &chat_s,
            tool: &answer.normalized_tool,
            decision: super::action_str(shown),
            policy_action: answer.action,
            reason: &reason,
            redacted: answer.redacted,
            join: Some(("callKey", &key)),
        }
        .event(),
    );
    // The light tier fails closed: a decision no one recorded is a deny.
    let shown = match lost {
        Some(why) if shown != Action::Deny => {
            (action, gemini_asks, reason) = (Action::Deny, false, why);
            Action::Deny
        }
        _ => shown,
    };
    // Gemini gives no call id: the install record joins by the call key.
    let install_call = GateCall {
        tool_use_id: Some(key.clone()),
        ..call.clone()
    };
    for e in install_events(&install_call, &answer, shown, &chat_s) {
        deps.post(&e);
    }
    if action == Action::Deny {
        return block(&reason);
    }
    if gemini_asks {
        return ask(&reason);
    }
    if let Some(updated) = &answer.updated_input {
        if !updated.is_object() {
            return block("secret-like value in input that derm cannot rewrite on Gemini");
        }
        return Reply {
            stdout: super::json_line(&json!({
                "hookSpecificOutput": {"hookEventName": "BeforeTool", "tool_input": updated},
                "systemMessage": format!("derm: {}", one_line(&reason)),
            })),
            stderr: String::new(),
            exit: 0,
        };
    }
    // Allow: print nothing, so Gemini's own policy decides.
    none()
}

pub fn handle_after(input: &Map<String, Value>, deps: &Deps) -> Reply {
    let chat =
        chat_of(&deps.env, input.get("session_id").and_then(Value::as_str)).unwrap_or_default();
    let response = input.get("tool_response");
    let serialized = super::serialized(response, true);
    // What the model reads is llmContent; returnDisplay is what the
    // terminal shows. `undefined` fields drop out, as JSON.stringify drops
    // them.
    let seen = match response {
        Some(Value::Object(r)) => {
            let mut m = Map::new();
            for k in ["llmContent", "returnDisplay", "error"] {
                if let Some(v) = r.get(k) {
                    m.insert(k.into(), v.clone());
                }
            }
            Some(Value::Object(m))
        }
        other => other.cloned(),
    };
    let (value, count) = match &seen {
        Some(s) => derm_core::redact::hook::redact_value(s),
        None => (Value::Null, 0),
    };
    let tool = if input.get("tool_name").is_some_and(Value::is_string) {
        tool_for_gate(input)
    } else {
        String::new()
    };
    let name = super::claude_code::gate_name(HARNESS, &tool, deps);
    let key = call_key(input);
    deps.post(&super::tool_call_event(
        record_id(input),
        HARNESS,
        &chat,
        &name,
        &serialized,
        count,
        Some(("callKey", &key)),
    ));
    if count == 0 {
        return none();
    }
    let redacted = match &value {
        Value::Object(m) => m.get("llmContent").cloned().unwrap_or(Value::Null),
        other => other.clone(),
    };
    Reply {
        stdout: super::json_line(&json!({
            "decision": "deny",
            "reason": format!("derm replaced this output: {} redacted.\n{}", super::values(count), super::reason_text(&redacted)),
        })),
        stderr: String::new(),
        exit: 0,
    }
}

/// One hook call (`runHook`). `event` is `before` or `after`.
pub fn run(event: &str, stdin: &[u8], deps: Deps) -> Reply {
    let env = hook_env(&deps.env);
    let deps = deps.with_env(env);
    let before = event == "before";
    let input = match parse_input(stdin) {
        Ok(i) => i,
        Err(why) => return if before { block(why) } else { none() },
    };
    if before {
        if let Some(e) = input.get("hook_event_name") {
            if e != "BeforeTool" {
                return block(&format!("unexpected hook event {}", super::js_string(e)));
            }
        }
        return handle_before(&input, &deps);
    }
    handle_after(&input, &deps)
}
