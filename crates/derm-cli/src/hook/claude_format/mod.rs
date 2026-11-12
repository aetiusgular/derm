//! The Claude-format dialects (lane 5bA): Claude Code, Codex, Gemini,
//! OpenClaude, Qwen Code, Droid, Command Code, Kimi Code, Auggie, Copilot
//! CLI and Grok, each as its TypeScript adapter answered at `e29ce27`
//! (`packages/derm-claude-plugin/src/hook.ts`, `derm-codex-plugin/src/
//! hook.ts`, `derm-gemini-extension/src/hook.ts`, `derm-hooks-claude-compat/
//! src/{hook,agents,dialect,control,env}.ts`), on the gate in `crate::gate`.
//!
//! - [`claude_code`]: Claude Code's PreToolUse and PostToolUse, and its hook
//!   run by another agent (case 109, BCR-7).
//! - [`codex`]: Codex's PreToolUse and PostToolUse.
//! - [`gemini`]: Gemini's BeforeTool and AfterTool.
//! - [`compat`]: the eight agents whose PreToolUse is Claude Code's or near
//!   it, one table entry each.
//! - [`control`]: the agents' own control files the core's list does not
//!   name (an allow that names one asks).
//! - [`token`]: where the chat token comes from when an agent strips it
//!   from the hook's environment (case 76).
//!
//! Every path ends in a decision: an input that cannot be read, a gate that
//! fails, anything unexpected on a pre event is that agent's deny. A post
//! event never blocks.

pub mod claude_code;
pub mod codex;
pub mod compat;
pub mod control;
pub mod gemini;
pub mod marks;
pub mod token;

#[cfg(test)]
mod tests;

use std::io::Read;
use std::path::{Path, PathBuf};

use derm_core::policy::Action;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::Reply;
use crate::gate::core::LoadedPolicy;
use crate::gate::daemon::{self, AdapterEvent, ApproveOutcome, ApproveRequest, Env};

/// The most a hook reads from stdin (`MAX_STDIN_BYTES` in every adapter).
pub const MAX_STDIN_BYTES: usize = 32 * 1024 * 1024;

/// How a dialect loads the policy: the environment and the chat's folder in.
pub type LoadPolicy<'a> = Box<dyn Fn(&Env, &Path) -> LoadedPolicy + 'a>;
/// How a dialect asks the daemon's approver.
pub type Approve<'a> = Box<dyn Fn(&ApproveRequest, &Env, &Path) -> ApproveOutcome + 'a>;
/// How a dialect posts a record; true when the daemon took it.
pub type Post<'a> = Box<dyn Fn(&AdapterEvent, &Env, &Path) -> bool + 'a>;

/// What a dialect reaches outside itself: the environment, the policy, the
/// daemon. The real ones in [`Deps::real`]; tests pass their own (the
/// TypeScript tests' `deps`).
pub struct Deps<'a> {
    pub env: Env,
    pub cwd: PathBuf,
    pub load_policy: LoadPolicy<'a>,
    pub approve: Approve<'a>,
    pub post: Post<'a>,
}

impl<'a> Deps<'a> {
    /// The policy by `load_for_hook`'s rules and the daemon by its socket.
    pub fn real(env: Env, cwd: PathBuf) -> Deps<'a> {
        Deps {
            env,
            cwd,
            load_policy: Box::new(|env, cwd| {
                let (policy, problem) = crate::gate::policy::load_for_hook(env, cwd);
                LoadedPolicy { policy, problem }
            }),
            approve: Box::new(daemon::approve),
            post: Box::new(daemon::post_event),
        }
    }

    /// The same dependencies with another environment (Gemini's token-file
    /// alias, the compat dialects' derived token file).
    pub fn with_env(self, env: Env) -> Deps<'a> {
        Deps { env, ..self }
    }

    pub fn policy(&self) -> LoadedPolicy {
        (self.load_policy)(&self.env, &self.cwd)
    }

    pub fn post(&self, e: &AdapterEvent) {
        let _ = (self.post)(e, &self.env, &self.cwd);
    }

    pub fn approver(&self) -> impl Fn(&ApproveRequest) -> ApproveOutcome + '_ {
        move |r| (self.approve)(r, &self.env, &self.cwd)
    }
}

/// The hook's entry from `hook/mod.rs`: reads stdin (at most one byte past
/// the cap, so an input that is too large is seen as such and the agent
/// never meets a closed pipe), then answers with the real dependencies.
pub fn answer(agent: &str, event: &str, stdin: &mut dyn std::io::Read) -> Reply {
    let mut buf = Vec::new();
    let _ = stdin.take(MAX_STDIN_BYTES as u64 + 1).read_to_end(&mut buf);
    // Drain the rest, so the agent's write never fails on a closed pipe.
    let _ = std::io::copy(stdin, &mut std::io::sink());
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    answer_with(agent, event, &buf, Deps::real(Env::process(), cwd))
}

/// One call with the dependencies passed in.
pub fn answer_with(agent: &str, event: &str, stdin: &[u8], deps: Deps) -> Reply {
    match agent {
        "claude-code" => claude_code::run(event, stdin, deps),
        "codex" => codex::run(event, stdin, deps),
        "gemini" => gemini::run(event, stdin, deps),
        _ => compat::run(agent, event, stdin, deps),
    }
}

/// Stdin as an object, or why it is not one (`runHook`'s three checks, in
/// their order). Invalid UTF-8 is read as `Buffer.toString("utf8")` reads it.
pub fn parse_input(stdin: &[u8]) -> Result<Map<String, Value>, &'static str> {
    if stdin.len() > MAX_STDIN_BYTES {
        return Err("hook input too large");
    }
    let text = String::from_utf8_lossy(stdin);
    let v: Value = serde_json::from_str(&text).map_err(|_| "hook input is not JSON")?;
    match v {
        Value::Object(m) => Ok(m),
        _ => Err("hook input is not an object"),
    }
}

/// `String(v)` for a value a reason names.
pub fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => js_number(n),
        Value::Array(a) => a
            .iter()
            .map(|x| match x {
                Value::Null => String::new(),
                other => js_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// `String(n)` for a JSON number.
pub fn js_number(n: &serde_json::Number) -> String {
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

/// A string field, or `None` when it is absent or not a non-empty string
/// (`str` in `dialect.ts`).
pub fn str_of<'v>(o: &'v Map<String, Value>, keys: &[&str]) -> Option<&'v str> {
    keys.iter()
        .find_map(|k| o.get(*k).and_then(Value::as_str).filter(|s| !s.is_empty()))
}

/// The chat a record belongs to (`chatOf`): `DERM_CHAT_ID`, else the
/// agent's session.
pub fn chat_of(env: &Env, session: Option<&str>) -> Option<String> {
    env.get("DERM_CHAT_ID")
        .map(str::to_string)
        .or_else(|| session.filter(|s| !s.is_empty()).map(str::to_string))
}

/// `reason.replace(/\s+/g, " ").trim()`, by JavaScript's whitespace.
pub fn squash(reason: &str) -> String {
    let mut out = String::with_capacity(reason.len());
    let mut space = false;
    for c in reason.chars() {
        if derm_core::redact::hook::js_space(c) {
            space = true;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            out.push(c);
        }
    }
    out
}

/// One line of text, never empty, cut at `max` UTF-16 units with `…`
/// (`oneLine` in `dialect.ts`).
pub fn one_line(reason: &str, max: usize) -> String {
    let t = squash(reason);
    let t = if t.is_empty() {
        "blocked".to_string()
    } else {
        t
    };
    let units: Vec<u16> = t.encode_utf16().collect();
    if units.len() > max {
        let mut cut: String = char::decode_utf16(units[..max - 1].iter().copied())
            .filter_map(Result::ok)
            .collect();
        cut.push('…');
        cut
    } else {
        t
    }
}

/// A result serialized as the TypeScript serialized it for its hash
/// (`JSON.stringify`, or the string itself where the adapter said so).
/// Keys come out sorted, not in the agent's order (no `preserve_order` in
/// the workspace), so the hash of an object differs from the TypeScript's;
/// the daemon reads only whether a hash is there (`join/mod.rs`).
pub fn serialized(v: Option<&Value>, string_as_is: bool) -> String {
    match v {
        None => String::new(),
        Some(Value::String(s)) if string_as_is => s.clone(),
        Some(v) => serde_json::to_string(v).unwrap_or_default(),
    }
}

pub fn sha256_hex(text: &str) -> String {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn action_str(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    }
}

/// A line of JSON on stdout.
pub fn json_line(v: &Value) -> String {
    format!("{v}\n")
}

pub fn none() -> Reply {
    Reply {
        stdout: String::new(),
        stderr: String::new(),
        exit: 0,
    }
}

/// The `approval` record of one decision (every adapter's `postEvent`
/// after the gate).
pub struct Decision<'a> {
    pub harness: &'a str,
    /// The id the record's id is made from: the call's own, or a call key.
    pub id_part: Option<&'a str>,
    pub chat: &'a str,
    pub tool: &'a str,
    pub decision: &'a str,
    pub policy_action: Action,
    pub reason: &'a str,
    pub redacted: usize,
    /// `toolUseId` or `callKey`, with its value.
    pub join: Option<(&'a str, &'a str)>,
}

impl Decision<'_> {
    pub fn event(&self) -> AdapterEvent {
        let mut detail = Map::new();
        detail.insert("tool".into(), Value::from(self.tool));
        detail.insert("decision".into(), Value::from(self.decision));
        detail.insert(
            "policyAction".into(),
            Value::from(action_str(self.policy_action)),
        );
        detail.insert("reason".into(), Value::from(self.reason));
        detail.insert("redacted".into(), Value::from(self.redacted));
        if let Some((k, v)) = self.join {
            detail.insert(k.into(), Value::from(v));
        }
        AdapterEvent {
            id: daemon::decision_id(self.harness, self.id_part),
            chat_id: self.chat.to_string(),
            harness: self.harness.to_string(),
            kind: "approval".into(),
            summary: format!("{} {}", self.tool, self.decision),
            detail,
        }
    }
}

/// The `tool.call` record of a post event (every adapter's `handlePost`).
pub fn tool_call_event(
    id: String,
    harness: &str,
    chat: &str,
    tool: &str,
    serialized: &str,
    redacted: usize,
    join: Option<(&str, &str)>,
) -> AdapterEvent {
    let mut detail = Map::new();
    detail.insert("tool".into(), Value::from(tool));
    detail.insert("resultSha256".into(), Value::from(sha256_hex(serialized)));
    detail.insert("resultBytes".into(), Value::from(serialized.len()));
    detail.insert("redacted".into(), Value::from(redacted));
    if let Some((k, v)) = join {
        detail.insert(k.into(), Value::from(v));
    }
    AdapterEvent {
        id,
        chat_id: chat.to_string(),
        harness: harness.to_string(),
        kind: "tool.call".into(),
        summary: if redacted > 0 {
            format!("{tool} done, {redacted} redacted")
        } else {
            format!("{tool} done")
        },
        detail,
    }
}

/// `${count} secret-like value${count === 1 ? "" : "s"}`.
pub fn values(count: usize) -> String {
    format!(
        "{count} secret-like value{}",
        if count == 1 { "" } else { "s" }
    )
}

/// A redacted result as the text the agent's block reason carries, cut at
/// 20,000 UTF-16 units (`MAX_REASON_CHARS` in Codex's and Gemini's hooks).
pub fn reason_text(v: &Value) -> String {
    const MAX: usize = 20_000;
    let text = match v {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    };
    let units: Vec<u16> = text.encode_utf16().collect();
    if units.len() > MAX {
        let cut: String = char::decode_utf16(units[..MAX].iter().copied())
            .filter_map(Result::ok)
            .collect();
        format!("{cut}\n[derm: output cut at {MAX} characters]")
    } else {
        text
    }
}
