//! Hermes Agent (NousResearch/hermes-agent): `derm hook hermes <pre|post>`,
//! which `packages/derm-hermes-plugin/derm_gate.py` runs once per call by
//! derm's absolute path with the call as JSON on stdin, in place of the Node
//! decider (`bin/derm-decide.mjs`, `src/decide.ts`) it ran before. The JSON
//! in and out is the decider's, so the Python side is unchanged in what it
//! reads:
//!
//! - stdin: `{"event": "pre", "tool_name", "args", "session_id",
//!   "tool_call_id"}` or `{"event": "post", "tool_name", "args", "result",
//!   "session_id", "tool_call_id", "status"}`; the payload's `event` and the
//!   registration's must agree (contracts/hook-dialects.md 9.1);
//! - stdout, one JSON object, exit 0: `{"decision": "allow" | "deny" |
//!   "ask", "reason", "args"?}` for `pre` ("ask": no derm approver answered,
//!   Hermes's own gate may ask, `derm_gate.py` decides), `{"result"?,
//!   "redacted"}` for `post`.
//!
//! Hermes facts (read by lane I at v0.22.5, by the base at `main` `2b7a6ce`
//! (BCR-6), and by this lane at `main` `78abaaf` on 10 Nov: no change under
//! `hermes_cli/` or `tools/approval*` since the pin): the shell tool is
//! `terminal` (field `command`), in the core's shell list; MCP tools are
//! `mcp__<server>__<tool>`; a `pre_tool_call` callback runs under
//! `plugins.hook_callback_timeout`, 30 s by default, and a timeout or a
//! raise blocks (`hermes_cli/plugins_dispatch.py:59-94`), so an ask here
//! waits at most [`ASK_CAP_SECONDS`]; a `modify` directive is merged
//! shallowly over the args.
//!
//! Ported from `packages/derm-hermes-plugin/src/decide.ts` at `e29ce27`.

use derm_core::policy::Action;
use derm_core::redact::hook::redact_text;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{action_word, chat_from, json_line, str_field, Input, Io};
use crate::gate::core::{
    decide_call, input_text_for, install_events, resolve_ask, AskResolution, GateCall,
};
use crate::gate::daemon::{decision_id, AdapterEvent, ApproveRequest};
use crate::hook::Reply;

pub const HARNESS: &str = "hermes";
/// Under Hermes's default 30 s callback timeout, with room for derm's start
/// and the reply (`ASK_CAP_SECONDS`).
pub const ASK_CAP_SECONDS: u32 = 20;
const MAX_RESULT_UNITS: usize = 200_000;

fn deny(reason: &str) -> Reply {
    json_line(json!({"decision": "deny", "reason": reason}))
}

/// `String(v)` as JavaScript writes it, for a tool name or an event.
fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "null".into(),
        Some(Value::Object(_)) => "[object Object]".into(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| match x {
                Value::Null => String::new(),
                other => js_string(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(other) => other.to_string(),
    }
}

/// One call: `event` is the registration's (argv), `text` stdin as read.
pub fn answer(event: &str, text: Result<String, String>, io: &dyn Io) -> Reply {
    let text = match text {
        Ok(t) => t,
        Err(why) => return deny(&why),
    };
    let input: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return deny("hook input is not JSON"),
    };
    let Value::Object(input) = input else {
        return deny("hook input is not an object");
    };
    let said = input.get("event");
    let said_pre = said == Some(&json!("pre"));
    let said_post = said == Some(&json!("post"));
    if !said_pre && !said_post {
        return deny(&format!("unknown event {}", js_string(said)));
    }
    if (said_pre && event != "pre") || (said_post && event != "post") {
        return deny(&format!(
            "the call is a {} call and derm hook hermes was registered for {event}",
            js_string(said)
        ));
    }
    if said_post {
        return match post(&input, io) {
            Ok(r) => r,
            Err(_) => json_line(json!({"redacted": 0})),
        };
    }
    match pre(&input, io) {
        Ok(r) => r,
        Err(why) => deny(&format!("hook error: {why}")),
    }
}

fn pre(input: &Input, io: &dyn Io) -> Result<Reply, String> {
    let Some(tool) = str_field(input, "tool_name") else {
        return Ok(deny("tool call has no tool name"));
    };
    let chat = chat_from(io.env(), input.get("session_id"));
    let id = str_field(input, "tool_call_id").map(str::to_string);
    let call = GateCall {
        harness: HARNESS.into(),
        tool: tool.to_string(),
        tool_input: match input.get("args") {
            None | Some(Value::Null) => json!({}),
            Some(v) => v.clone(),
        },
        chat: chat.clone(),
        tool_use_id: id.clone(),
        full_access: None,
    };
    let mut answer = decide_call(&io.load_policy(), &call, io.env());
    // Hermes's control files are derm-core's (`CONTROL_PATHS`, integration
    // w2), asked in `decide_call`; the copy here went at the wave 5b close.
    input_text_for(&answer.normalized_tool, &call.tool_input)?;
    answer.ask_timeout_seconds = answer.ask_timeout_seconds.min(ASK_CAP_SECONDS);
    let mut decision = answer.action;
    let mut reason = answer.reason.clone();
    if decision == Action::Ask {
        // Hermes has its own human gate, so with no derm approver the ask
        // goes there (`derm_gate.py` refuses that under yolo, where Hermes's
        // gate approves everything); an approver's no or a timeout is a deny.
        let approve = |r: &ApproveRequest| io.approve(r);
        let (d, r) = match resolve_ask(&answer, &call, true, io.env(), &approve) {
            AskResolution::Allow(r) => (Action::Allow, r),
            AskResolution::Deny(r) => (Action::Deny, r),
            AskResolution::Harness(r) => (Action::Ask, r),
        };
        decision = d;
        reason = r;
    }
    if decision == Action::Allow
        && answer
            .updated_input
            .as_ref()
            .is_some_and(|u| !u.is_object())
    {
        decision = Action::Deny;
        reason = "secret-like value in input that derm cannot rewrite on Hermes".into();
    }
    let mut detail = Map::new();
    detail.insert("tool".into(), answer.normalized_tool.clone().into());
    detail.insert("decision".into(), action_word(decision).into());
    detail.insert("policyAction".into(), action_word(answer.action).into());
    detail.insert("reason".into(), reason.clone().into());
    detail.insert("redacted".into(), answer.redacted.into());
    if let Some(id) = &id {
        detail.insert("toolUseId".into(), id.clone().into());
    }
    // A decision is written once per chat and id (the daemon, S9), so one
    // with no call id gets its own id instead of a shared "unknown".
    let lost = io.post_decision(&AdapterEvent {
        id: decision_id(HARNESS, id.as_deref()),
        chat_id: chat.clone().unwrap_or_default(),
        harness: HARNESS.into(),
        kind: "approval".into(),
        summary: format!("{} {}", answer.normalized_tool, action_word(decision)),
        detail,
    });
    // The light tier fails closed: a decision no one recorded is a deny.
    if let Some(why) = lost.filter(|_| decision != Action::Deny) {
        (decision, reason) = (Action::Deny, why);
    }
    for e in install_events(&call, &answer, decision, chat.as_deref().unwrap_or("")) {
        io.post(&e);
    }
    let mut out = Map::new();
    out.insert("decision".into(), action_word(decision).into());
    out.insert("reason".into(), reason.into());
    if decision != Action::Deny {
        if let Some(u) = answer.updated_input {
            out.insert("args".into(), u);
        }
    }
    Ok(json_line(Value::Object(out)))
}

fn post(input: &Input, io: &dyn Io) -> Result<Reply, String> {
    let raw = match input.get("result") {
        Some(Value::String(s)) => s.clone(),
        None | Some(Value::Null) => "null".into(),
        Some(v) => serde_json::to_string(v).unwrap_or_default(),
    };
    let sha = hex(&Sha256::digest(raw.as_bytes()));
    let red = redact_text(&raw);
    let chat = chat_from(io.env(), input.get("session_id"));
    let id = str_field(input, "tool_call_id").map(str::to_string);
    let tool_name = match input.get("tool_name") {
        None | Some(Value::Null) => String::new(),
        v => js_string(v),
    };
    let tool = decide_call(
        &io.load_policy(),
        &GateCall {
            harness: HARNESS.into(),
            tool: tool_name,
            tool_input: json!({}),
            ..GateCall::default()
        },
        io.env(),
    )
    .normalized_tool;
    let mut detail = Map::new();
    detail.insert("tool".into(), tool.clone().into());
    detail.insert("resultSha256".into(), sha.into());
    detail.insert("resultBytes".into(), raw.len().into());
    detail.insert("redacted".into(), red.count.into());
    if let Some(id) = &id {
        detail.insert("toolUseId".into(), id.clone().into());
    }
    io.post(&AdapterEvent {
        id: format!("{HARNESS}-{}", id.as_deref().unwrap_or("unknown")),
        chat_id: chat.unwrap_or_default(),
        harness: HARNESS.into(),
        kind: "tool.call".into(),
        summary: if red.count > 0 {
            format!("{tool} done, {} redacted", red.count)
        } else {
            format!("{tool} done")
        },
        detail,
    });
    if red.count == 0 {
        return Ok(json_line(json!({"redacted": 0})));
    }
    let units: Vec<u16> = red.text.encode_utf16().collect();
    let result = if units.len() > MAX_RESULT_UNITS {
        let cut: String = char::decode_utf16(units[..MAX_RESULT_UNITS].iter().copied())
            .filter_map(Result::ok)
            .collect();
        format!("{cut}\n[derm: output cut at {MAX_RESULT_UNITS} characters]")
    } else {
        red.text
    };
    Ok(json_line(json!({"result": result, "redacted": red.count})))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
