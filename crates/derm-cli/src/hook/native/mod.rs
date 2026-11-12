//! The native dialects (lane 5bB): Cursor (preToolUse and
//! beforeMCPExecution, case 110), Antigravity, goose, Mistral Vibe, Crush,
//! Kiro (stdout is context, case 77) and Hermes, each answering as
//! `packages/derm-hooks-native` and `packages/derm-hermes-plugin` did at
//! `e29ce27`, on the gate in `crate::gate`.
//!
//! This file is the shared runner (`runner.ts`): read the agent's stdin, turn
//! it into the gate's call through the agent's dialect, decide with
//! `gate::core`, narrow for the agent's own control files, resolve an ask,
//! record the decision, and print the agent's own reply. What differs per
//! agent lives in its file: how the call is read (tool name, input, chat,
//! call id), which shell tools become `bash` (case 82), and how allow, ask
//! and deny are written (cases 71, 72, 77, 79). Every failure it can see is
//! the dialect's deny (case 70).

mod antigravity;
mod crush;
pub(crate) mod crush_servers;
mod cursor;
mod goose;
mod hermes;
mod kiro;
mod kiro_servers;
mod mcp_split;
mod shell;
mod vibe;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use derm_core::policy::Action;
use serde_json::{Map, Value};

use super::Reply;
use crate::gate::core::{
    decide_call, input_text_for, install_events, resolve_ask, AskResolution, GateAnswer, GateCall,
    LoadedPolicy,
};
use crate::gate::daemon::{self, AdapterEvent, ApproveOutcome, ApproveRequest, Env};

/// The most stdin a hook reads (`MAX_STDIN_BYTES`, 32 MiB).
pub const MAX_STDIN_BYTES: u64 = 32 * 1024 * 1024;

/// What a dialect reads out of the agent's pre-tool input (`ReadCall`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReadCall {
    /// The tool name the gate matches (shell tools already mapped to `bash`).
    pub tool: String,
    /// The name the agent sent, kept for the record.
    pub raw_tool: String,
    pub tool_input: Value,
    pub chat: Option<String>,
    pub call_id: Option<String>,
    /// Set when the dialect could not settle which server an MCP name belongs
    /// to: an allow then asks.
    pub ambiguous: Option<String>,
    /// Set when another hook event of the same agent decides this call in
    /// full (Cursor's beforeMCPExecution after a preToolUse that names no
    /// server): this event denies only what the core denies outright and
    /// lets the rest on to that event, without asking anyone (case 110).
    pub defer_unless_deny: Option<String>,
}

pub type Input = Map<String, Value>;

/// One agent's dialect (`Dialect`).
pub struct Dialect {
    /// The agent's preset id, which is also the harness id the policy sees.
    pub id: &'static str,
    /// The agent's display name for messages.
    pub name: &'static str,
    /// Reads the call, or returns why it cannot (a block).
    pub read: fn(&Input, &Env) -> Result<ReadCall, String>,
    /// True when the agent shows its own prompt for this call when the hook asks.
    pub own_ask: fn(&Input) -> bool,
    /// The reply for a policy allow; the input set when derm redacted it.
    pub allow: fn(&str, Option<&Value>) -> Reply,
    /// The reply that denies this one call and lets the run go on (case 79).
    pub deny: fn(&str) -> Reply,
    /// The reply that hands the call to the agent's own prompt; only called
    /// when `own_ask` is true.
    pub ask: fn(&str) -> Reply,
    /// Whether the agent takes a rewritten input from a hook.
    pub can_rewrite: bool,
}

/// What the runner reaches outside itself (`Deps`): the environment, the
/// policy, the daemon. Tests pass their own.
pub trait Io {
    fn env(&self) -> &Env;
    fn load_policy(&self) -> LoadedPolicy;
    fn approve(&self, r: &ApproveRequest) -> ApproveOutcome;
    fn post(&self, e: &AdapterEvent);
}

/// The real environment, policy and daemon.
pub struct Real {
    pub env: Env,
    pub cwd: PathBuf,
}

impl Real {
    pub fn process() -> Real {
        Real {
            env: Env::process(),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

impl Io for Real {
    fn env(&self) -> &Env {
        &self.env
    }
    fn load_policy(&self) -> LoadedPolicy {
        let (policy, problem) = crate::gate::policy::load_for_hook(&self.env, &self.cwd);
        LoadedPolicy { policy, problem }
    }
    fn approve(&self, r: &ApproveRequest) -> ApproveOutcome {
        daemon::approve(r, &self.env, &self.cwd)
    }
    fn post(&self, e: &AdapterEvent) {
        let _ = daemon::post_event(e, &self.env, &self.cwd);
    }
}

/// The empty reply: exit 0, nothing printed (`NONE`).
pub fn none() -> Reply {
    Reply {
        stdout: String::new(),
        stderr: String::new(),
        exit: 0,
    }
}

/// One JSON line on stdout, exit 0.
pub fn json_line(v: Value) -> Reply {
    Reply {
        stdout: format!("{v}\n"),
        stderr: String::new(),
        exit: 0,
    }
}

/// One line of text, never empty. A reason is derm's own text plus rule
/// names; never the tool input (`oneLine`).
pub fn one_line(reason: &str) -> String {
    let text = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        "blocked".into()
    } else {
        text
    }
}

/// `derm: <reason>` on one line.
pub fn derm(reason: &str) -> String {
    format!("derm: {}", one_line(reason))
}

/// The chat a record belongs to: `DERM_CHAT_ID` from `derm run`, else the
/// agent's session id (`chatFrom`).
pub fn chat_from(env: &Env, session_id: Option<&Value>) -> Option<String> {
    if let Some(c) = env.get("DERM_CHAT_ID") {
        return Some(c.to_string());
    }
    match session_id {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// A non-empty string field.
pub fn str_field<'a>(input: &'a Input, key: &str) -> Option<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// `String(v).slice(0, 40)` for an event name in a refusal.
pub fn shown(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    };
    let units: Vec<u16> = s.encode_utf16().take(40).collect();
    char::decode_utf16(units).filter_map(Result::ok).collect()
}

/// `toolInput ?? {}`.
pub fn input_or_empty(v: Option<&Value>) -> Value {
    match v {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(v) => v.clone(),
    }
}

fn dialect(agent: &str) -> Option<&'static Dialect> {
    Some(match agent {
        "cursor" => &cursor::CURSOR,
        "antigravity" => &antigravity::ANTIGRAVITY,
        "goose" => &goose::GOOSE,
        "mistral-vibe" => &vibe::MISTRAL_VIBE,
        "crush" => &crush::CRUSH,
        "kiro" => &kiro::KIRO,
        _ => return None,
    })
}

/// Reads stdin up to the cap plus one byte, so an input over the cap is
/// seen as such and the agent never meets a closed pipe before it is read.
pub fn read_stdin(stdin: &mut dyn std::io::Read) -> Result<String, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    stdin
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("hook input could not be read: {e}"))?;
    if buf.len() as u64 > MAX_STDIN_BYTES {
        // Drain the rest so the agent's write does not fail first.
        let _ = std::io::copy(stdin, &mut std::io::sink());
        return Err("hook input too large".into());
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// `derm hook <agent> <event>` for the native agents and Hermes.
pub fn answer(agent: &str, event: &str, stdin: &mut dyn std::io::Read) -> Reply {
    let io = Real::process();
    let text = read_stdin(stdin);
    if agent == "hermes" {
        return hermes::answer(event, text, &io);
    }
    let Some(d) = dialect(agent) else {
        return super::fail_closed(agent, &format!("no native dialect for {agent}"));
    };
    match text {
        Ok(t) => run_pre(d, &t, &io),
        Err(why) => (d.deny)(&why),
    }
}

/// Parses stdin and handles it; every failure it can see is the dialect's
/// deny (`runPre`).
pub fn run_pre(d: &Dialect, stdin_text: &str, io: &dyn Io) -> Reply {
    let input: Value = match serde_json::from_str(stdin_text) {
        Ok(v) => v,
        Err(_) => return (d.deny)("hook input is not JSON"),
    };
    let Value::Object(input) = input else {
        return (d.deny)("hook input is not an object");
    };
    match handle_pre(d, &input, io) {
        Ok(r) => r,
        Err(why) => (d.deny)(&format!("hook error: {why}")),
    }
}

/// The outcome of one call (`Outcome`).
pub struct Outcome {
    pub decision: Action,
    pub reason: String,
    pub answer: GateAnswer,
}

fn gate_call(d: &Dialect, read: &ReadCall, with_chat: bool) -> GateCall {
    GateCall {
        harness: d.id.to_string(),
        tool: read.tool.clone(),
        tool_input: read.tool_input.clone(),
        chat: if with_chat { read.chat.clone() } else { None },
        tool_use_id: read.call_id.clone(),
        full_access: None,
    }
}

/// Decides one read call: the core (the agents' control files included), then the ask
/// (`decide`).
pub fn decide(d: &Dialect, input: &Input, read: &ReadCall, io: &dyn Io) -> Result<Outcome, String> {
    let call = gate_call(d, read, true);
    let mut answer = decide_call(&io.load_policy(), &call, io.env());
    if answer.updated_input.is_some() && !answer.normalized_tool.contains('/') {
        // The core redacts the input of any tool it does not know writes or
        // runs. On these agents that includes built-in tools under their own
        // names (Vibe's `write_file`, goose's `write`): rewriting one changes
        // what it does, so a secret-like value there asks instead, as the
        // core does for its own write tools. MCP tools (`server/tool`) keep
        // the redaction, which keeps the secret from the server.
        answer.updated_input = None;
        if answer.action == Action::Allow {
            answer.action = Action::Ask;
            answer.reason = "secret-like value in input".into();
        }
    }
    if answer.action == Action::Allow {
        if let Some(why) = &read.ambiguous {
            answer.action = Action::Ask;
            answer.reason = why.clone();
        }
    }
    // The agents' own control files are derm-core's (`CONTROL_PATHS`, folded
    // in by integration w4), asked in `decide_call` before any allow stands;
    // lane 5bB's own copy of them was removed at the wave 5b close (its
    // request 3). An input the core cannot read as text still fails here.
    input_text_for(&answer.normalized_tool, &read.tool_input)?;
    let cannot_rewrite = || {
        format!(
            "secret-like value in input that derm cannot rewrite on {}",
            d.name
        )
    };
    if answer.action == Action::Allow && answer.updated_input.is_some() && !d.can_rewrite {
        return Ok(Outcome {
            decision: Action::Deny,
            reason: cannot_rewrite(),
            answer,
        });
    }
    if answer.action != Action::Ask {
        return Ok(Outcome {
            decision: answer.action,
            reason: answer.reason.clone(),
            answer,
        });
    }
    // Case 71: the agent's own prompt where it shows one, else the daemon
    // approver within the hook's time, else deny; never "no decision".
    let approve = |r: &ApproveRequest| io.approve(r);
    let r = resolve_ask(&answer, &call, (d.own_ask)(input), io.env(), &approve);
    Ok(match r {
        AskResolution::Allow(reason) => {
            if answer.updated_input.is_some() && !d.can_rewrite {
                Outcome {
                    decision: Action::Deny,
                    reason: cannot_rewrite(),
                    answer,
                }
            } else {
                Outcome {
                    decision: Action::Allow,
                    reason,
                    answer,
                }
            }
        }
        AskResolution::Deny(reason) => Outcome {
            decision: Action::Deny,
            reason,
            answer,
        },
        AskResolution::Harness(reason) => Outcome {
            decision: Action::Ask,
            reason,
            answer,
        },
    })
}

pub fn action_word(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    }
}

/// Handles one pre-tool input that is already parsed (`handlePre`).
pub fn handle_pre(d: &Dialect, input: &Input, io: &dyn Io) -> Result<Reply, String> {
    let read = match (d.read)(input, io.env()) {
        Ok(r) => r,
        Err(why) => return Ok((d.deny)(&why)),
    };
    let out = match &read.defer_unless_deny {
        Some(defer) => {
            let mut answer = decide_call(&io.load_policy(), &gate_call(d, &read, true), io.env());
            answer.updated_input = None;
            if answer.action == Action::Deny {
                Outcome {
                    decision: Action::Deny,
                    reason: answer.reason.clone(),
                    answer,
                }
            } else {
                Outcome {
                    decision: Action::Allow,
                    reason: defer.clone(),
                    answer,
                }
            }
        }
        None => decide(d, input, &read, io)?,
    };
    let deferred = read.defer_unless_deny.is_some() && out.decision == Action::Allow;
    let mut detail = Map::new();
    detail.insert("tool".into(), out.answer.normalized_tool.clone().into());
    detail.insert(
        "decision".into(),
        (if deferred {
            "deferred"
        } else {
            action_word(out.decision)
        })
        .into(),
    );
    detail.insert("policyAction".into(), action_word(out.answer.action).into());
    detail.insert("reason".into(), out.reason.clone().into());
    detail.insert("redacted".into(), out.answer.redacted.into());
    if let Some(id) = &read.call_id {
        detail.insert("toolUseId".into(), id.clone().into());
    }
    io.post(&AdapterEvent {
        id: daemon::decision_id(d.id, read.call_id.as_deref()),
        chat_id: read.chat.clone().unwrap_or_default(),
        harness: d.id.to_string(),
        kind: "approval".into(),
        summary: format!(
            "{} {}",
            out.answer.normalized_tool,
            action_word(out.decision)
        ),
        detail,
    });
    // A deferral decides nothing (Cursor's preToolUse for an MCP call), so it
    // records no install; the hook that decides does.
    if !deferred {
        let call = gate_call(d, &read, false);
        let chat = read.chat.clone().unwrap_or_default();
        for e in install_events(&call, &out.answer, out.decision, &chat) {
            io.post(&e);
        }
    }
    Ok(match out.decision {
        Action::Deny => (d.deny)(&out.reason),
        Action::Ask => (d.ask)(&out.reason),
        Action::Allow => (d.allow)(&out.reason, out.answer.updated_input.as_ref()),
    })
}

/// A path the hook input names as the agent's working folder.
pub fn cwd_of<'a>(input: &'a Input, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str)
}

/// The home a server-name reader uses.
pub fn home(env: &Env) -> PathBuf {
    crush_servers::home_of(env)
}
