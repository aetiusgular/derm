//! `derm gate serve`: the gate as a co-process that the in-process plugins
//! (Pi and oh-my-pi through derm-pi, OpenCode, Kilo, OpenClaw, Amp, Cline)
//! start once per session (`contracts/gate-serve.md`). Lane 5bC's.
//!
//! JSON lines on stdin and stdout, one request and one reply per line, in
//! order. Every decision goes through `gate::core::decide_call`, the path
//! `derm hook` and `derm acp` use (case 229), with the policy loaded per
//! request by `gate::policy::load_for_hook`, so a policy edited during a
//! session applies to the next call, as it does for a command hook.
//!
//! What it adds to the contract the base wrote (requests for integration in
//! `plans/parallel/tk_lane_5bC.md`):
//! - `decide` and `approve` take `"record": false`, for a plugin whose own
//!   glue can still change the outcome (Cline's rewrite rule, Pi's memory
//!   index): the co-process then posts nothing, and the plugin posts the
//!   final outcome with `record`.
//! - `record`: the approval record and the install records for one call,
//!   with the outcome the plugin settled on.
//! - `redact`: the hook redactor over a value, for a tool result.
//! - `memory.check` also answers `projectKnown`, which derm-pi's card text
//!   needs.
//!
//! Failure is the plugin's to turn into a deny (case 228): a line that is
//! not JSON or is over 1 MiB, a first line that is not a matching `hello`,
//! end of input: the co-process says why on its stdout when it can and
//! exits. It never reads a file a request names (the memory record's path
//! comes from its own environment) and writes nothing but that record.

mod memory;

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

use derm_core::policy::Action;
use derm_core::redact::hook::redact_value;
use serde_json::{json, Map, Value};

use super::core::{self as gate, AskResolution, GateAnswer, GateCall, LoadedPolicy};
use super::daemon::{self, AdapterEvent, ApproveOutcome, ApproveRequest, Env};

/// The protocol version `hello` names.
pub const PROTOCOL: u64 = 1;

/// The longest line read, the newline not counted (contract section 2).
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// The agents that start a co-process: the in-process plugins' harness ids
/// (`crates/derm-cli/src/connect/presets/index.json`).
pub const AGENTS: [&str; 7] = [
    "pi", "oh-my-pi", "opencode", "kilo", "openclaw", "amp", "cline",
];

const USAGE: &str = "usage: derm gate serve --agent <pi|oh-my-pi|opencode|kilo|openclaw|amp|cline>";

/// What one request may name, at most (a plugin's id, a label).
const MAX_ID_CHARS: usize = 128;

pub fn main(args: &[String]) -> u8 {
    let agent = match parse_args(args) {
        Ok(a) => a,
        Err(why) => {
            eprintln!("derm gate serve: {why}\n{USAGE}");
            return 2;
        }
    };
    let env = Env::process();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let post = |e: &AdapterEvent| daemon::post_event_kept(e, &env, &cwd);
    let approve = |r: &ApproveRequest| daemon::approve(r, &env, &cwd);
    // Records a plugin does not wait for (`"wait": false`) go to the daemon
    // from a thread of their own, so a slow daemon never holds the next reply
    // (Cline gives a hook 3 s). Bounded: past it a record is dropped.
    let (tx, rx) = std::sync::mpsc::sync_channel::<AdapterEvent>(LATER_QUEUE);
    let poster = {
        let (env, cwd) = (env.clone(), cwd.clone());
        std::thread::spawn(move || {
            for e in rx {
                daemon::post_event(&e, &env, &cwd);
            }
        })
    };
    let post_later = move |e: AdapterEvent| tx.try_send(e).is_ok();
    let daemon_up = || {
        daemon::exchange(
            &[],
            &daemon::Opts {
                env: &env,
                client: "derm gate serve".into(),
                reply_timeout: std::time::Duration::from_millis(1500),
                cwd: &cwd,
            },
        )
        .is_ok()
    };
    let ctx = Ctx {
        agent,
        memory_state: memory::state_path(&env),
        env: env.clone(),
        cwd: cwd.clone(),
        post: &post,
        post_later: &post_later,
        approve: &approve,
        daemon_up: &daemon_up,
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let code = run(&ctx, &mut stdin.lock(), &mut stdout.lock());
    // The queue is closed when the last sender goes: give it a moment to
    // finish what is queued, never long enough to hold the host's exit.
    drop(ctx);
    drop(post_later);
    let deadline = std::time::Instant::now() + LATER_FLUSH;
    while !poster.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    code
}

/// Records waiting for the poster thread, at most.
const LATER_QUEUE: usize = 256;
/// How long the co-process waits for queued records at its end.
const LATER_FLUSH: std::time::Duration = std::time::Duration::from_secs(2);

fn parse_args(args: &[String]) -> Result<String, String> {
    let mut agent = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--agent" => {
                let v = args.get(i + 1).ok_or("--agent needs a value")?;
                agent = Some(v.clone());
                i += 2;
            }
            a => {
                if let Some(v) = a.strip_prefix("--agent=") {
                    agent = Some(v.to_string());
                    i += 1;
                } else {
                    return Err(format!("unknown argument {a:?}"));
                }
            }
        }
    }
    let agent = agent.ok_or("--agent is required")?;
    if !AGENTS.contains(&agent.as_str()) {
        return Err(format!(
            "{agent:?} is not an agent that starts the co-process"
        ));
    }
    Ok(agent)
}

/// Everything a request is answered with: the agent from argv (never from a
/// request), the session's environment and folder, and the two daemon
/// calls, which tests replace.
pub(crate) struct Ctx<'a> {
    pub agent: String,
    pub env: Env,
    pub cwd: PathBuf,
    pub memory_state: Option<PathBuf>,
    /// Posts a record now: where it went (`daemon::Posted`).
    pub post: &'a dyn Fn(&AdapterEvent) -> daemon::Posted,
    /// Queues a record without waiting for the daemon; false when dropped.
    pub post_later: &'a dyn Fn(AdapterEvent) -> bool,
    pub approve: &'a dyn Fn(&ApproveRequest) -> ApproveOutcome,
    /// Whether a daemon takes this chat now (a hello with its chat token),
    /// for a plugin that keeps its own records ([`keep_light`]).
    pub daemon_up: &'a dyn Fn() -> bool,
}

/// One line of input, as read.
enum Line {
    End,
    TooLong,
    Text(Vec<u8>),
}

fn read_line(input: &mut dyn BufRead) -> std::io::Result<Line> {
    let mut buf = Vec::new();
    let n = input
        .take(MAX_LINE_BYTES as u64 + 2)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(Line::End);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    if buf.len() > MAX_LINE_BYTES {
        return Ok(Line::TooLong);
    }
    Ok(Line::Text(buf))
}

fn send(out: &mut dyn Write, v: &Value) -> bool {
    let mut text = v.to_string();
    text.push('\n');
    out.write_all(text.as_bytes()).is_ok() && out.flush().is_ok()
}

fn refuse(id: &Value, why: &str) -> Value {
    json!({"id": id, "ok": false, "error": why})
}

/// The loop: `hello` first, then one reply per request, in order. Returns
/// the exit code: 0 at the end of input, 2 when the co-process stops on a
/// line it cannot read or a bad `hello`, 1 when stdout is gone.
pub(crate) fn run(ctx: &Ctx, input: &mut dyn BufRead, out: &mut dyn Write) -> u8 {
    let mut greeted = false;
    loop {
        let bytes = match read_line(input) {
            Ok(Line::End) => return 0,
            Ok(Line::TooLong) => {
                send(out, &refuse(&Value::Null, "line over 1 MiB"));
                return 2;
            }
            Ok(Line::Text(b)) => b,
            Err(e) => {
                eprintln!("derm gate serve: stdin: {e}");
                return 2;
            }
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let request: Value = match std::str::from_utf8(&bytes)
            .ok()
            .and_then(|t| serde_json::from_str(t).ok())
        {
            Some(v @ Value::Object(_)) => v,
            _ => {
                send(out, &refuse(&Value::Null, "not a JSON object"));
                return 2;
            }
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        if !matches!(id, Value::String(_) | Value::Number(_)) {
            send(out, &refuse(&Value::Null, "a request needs an id"));
            if !greeted {
                return 2;
            }
            continue;
        }
        let op = request.get("op").and_then(Value::as_str).unwrap_or("");
        if !greeted {
            let reply = hello(ctx, &id, &request);
            let ok = reply["ok"] == json!(true);
            if !send(out, &reply) {
                return 1;
            }
            if !ok {
                return 2;
            }
            greeted = true;
            continue;
        }
        let reply = match op {
            "decide" => op_decide(ctx, &id, &request),
            "approve" => op_approve(ctx, &id, &request),
            "event" => op_event(ctx, &id, &request),
            "record" => op_record(ctx, &id, &request),
            "redact" => op_redact(&id, &request),
            "memory.check" => memory::op_check(ctx, &id, &request),
            "memory.approve" => memory::op_approve(ctx, &id, &request),
            "hello" => refuse(&id, "hello was already said"),
            other => refuse(&id, &format!("unknown op {}", clip(other, 64))),
        };
        if !send(out, &reply) {
            return 1;
        }
    }
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn hello(ctx: &Ctx, id: &Value, r: &Value) -> Value {
    if r.get("op").and_then(Value::as_str) != Some("hello") {
        return refuse(id, "the first request must be hello");
    }
    if r.get("protocol").and_then(Value::as_u64) != Some(PROTOCOL) {
        return refuse(id, "protocol 1 is the only one this derm speaks");
    }
    if r.get("agent").and_then(Value::as_str) != Some(ctx.agent.as_str()) {
        return refuse(
            id,
            &format!("hello names another agent than --agent {}", ctx.agent),
        );
    }
    let (_, problem) = super::policy::load_for_hook(&ctx.env, &ctx.cwd);
    json!({
        "id": id,
        "ok": true,
        "protocol": PROTOCOL,
        "policy": {"loaded": problem.is_none(), "problem": problem},
    })
}

fn opt_str(v: Option<&Value>, field: &str) -> Result<Option<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("{field} must be a string")),
    }
}

/// The call a request names (`gate::core::GateCall`), the harness from argv.
fn call_of(ctx: &Ctx, r: &Value) -> Result<GateCall, String> {
    let c = match r.get("call") {
        Some(c @ Value::Object(_)) => c,
        _ => return Err("call must be an object".into()),
    };
    let tool = match c.get("tool") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err("call.tool must be a tool name".into()),
    };
    let chat = opt_str(c.get("chat"), "call.chat")?
        .filter(|s| !s.is_empty())
        .or_else(|| {
            ctx.env
                .get("DERM_CHAT_ID")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });
    let tool_use_id = opt_str(c.get("toolUseId"), "call.toolUseId")?.filter(|s| !s.is_empty());
    let full_access = match c.get("fullAccess") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err("call.fullAccess must be true, false or null".into()),
    };
    // The core's call has no `description` (request 1): [`op_decide`] holds
    // it apart and applies it to the policy (`with_description`).
    opt_str(c.get("description"), "call.description")?;
    Ok(GateCall {
        harness: ctx.agent.clone(),
        tool,
        tool_input: c.get("input").cloned().unwrap_or_else(|| json!({})),
        chat,
        tool_use_id,
        full_access,
    })
}

fn action_word(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    }
}

fn action_of(v: Option<&Value>) -> Option<Action> {
    match v.and_then(Value::as_str) {
        Some("allow") => Some(Action::Allow),
        Some("ask") => Some(Action::Ask),
        Some("deny") => Some(Action::Deny),
        _ => None,
    }
}

fn answer_json(id: &Value, a: &GateAnswer) -> Value {
    json!({
        "id": id,
        "ok": true,
        "action": action_word(a.action),
        "normalizedTool": a.normalized_tool,
        "reason": a.reason,
        "updatedInput": a.updated_input.clone().unwrap_or(Value::Null),
        "redacted": a.redacted,
        "askTimeoutSeconds": a.ask_timeout_seconds,
    })
}

/// The decide reply a plugin sends back with `approve` or `record`. The
/// tool and reason are the plugin's (its glue may have narrowed the policy's
/// answer, as Pi's memory index does); the ask's timeout is capped as the
/// core caps it.
fn answer_of(r: &Value) -> Result<GateAnswer, String> {
    let a = match r.get("answer") {
        Some(a @ Value::Object(_)) => a,
        _ => return Err("answer must be the decide reply".into()),
    };
    let action = action_of(a.get("action")).ok_or("answer.action must be allow, ask or deny")?;
    let normalized_tool = match a.get("normalizedTool") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err("answer.normalizedTool must be a tool name".into()),
    };
    let reason = opt_str(a.get("reason"), "answer.reason")?.unwrap_or_default();
    let redacted = a.get("redacted").and_then(Value::as_u64).unwrap_or(0) as usize;
    let ask_timeout_seconds = a
        .get("askTimeoutSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(u64::from(gate::HOOK_ASK_CAP_SECONDS))
        .min(u64::from(gate::HOOK_ASK_CAP_SECONDS)) as u32;
    Ok(GateAnswer {
        action,
        normalized_tool,
        reason,
        updated_input: None,
        redacted,
        ask_timeout_seconds,
    })
}

/// `"wait": false`: the record is queued and the reply does not wait for the
/// daemon. By default it waits, so a decision reaches the daemon before the
/// call it decided runs (case 189: every derm gate posts its decision first).
fn waits(r: &Value) -> Result<bool, String> {
    match r.get("wait") {
        None | Some(Value::Null) => Ok(true),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err("wait must be true or false".into()),
    }
}

fn wants_record(r: &Value) -> Result<bool, String> {
    match r.get("record") {
        None | Some(Value::Null) => Ok(true),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err("record must be true or false".into()),
    }
}

fn op_decide(ctx: &Ctx, id: &Value, r: &Value) -> Value {
    let (call, record) = match (call_of(ctx, r), wants_record(r)) {
        (Ok(c), Ok(rec)) => (c, rec),
        (Err(e), _) | (_, Err(e)) => return refuse(id, &e),
    };
    let description = r["call"]
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_string);
    let (policy, problem) = super::policy::load_for_hook(&ctx.env, &ctx.cwd);
    let policy = with_description(policy, description.as_deref());
    let mut call = call;
    if call.harness == "oh-my-pi" {
        call.tool = omp_tool_name(&call.tool, &policy.servers);
    }
    let mut answer = gate::decide_call(&LoadedPolicy { policy, problem }, &call, &ctx.env);
    if answer.action != Action::Ask {
        let lost = if record {
            post_outcome(ctx, &call, &answer, answer.action, None, true, false).1
        } else {
            keep_light(ctx, &call, &answer, answer.action, None)
        };
        // The light tier fails closed: a decision no one recorded is a deny.
        if let Some(why) = lost.filter(|_| answer.action != Action::Deny) {
            (answer.action, answer.reason, answer.updated_input) = (Action::Deny, why, None);
        }
    }
    answer_json(id, &answer)
}

/// oh-my-pi names an MCP tool `mcp__<server>_<tool>`, after lowercasing the
/// server and turning each run of other characters into `_`; the longest
/// known server that is a prefix followed by `_` is the server
/// (`ompToolName`, `packages/derm-pi/src/harness.ts` at `e29ce27`; lane I's
/// run against oh-my-pi 18.13.3). derm-core's normalizer splits that form at
/// the first `_` (request 2), so the co-process gives it the `mcp__<server>
/// __<tool>` form first.
fn omp_tool_name(raw: &str, servers: &[String]) -> String {
    let Some(rest) = raw.strip_prefix("mcp__") else {
        return raw.to_string();
    };
    if rest.contains("__") {
        return raw.to_string();
    }
    let sanitize = |s: &str| {
        let mut out = String::new();
        for c in s.to_lowercase().chars() {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
                out.push(c);
            } else if !out.ends_with('_') {
                out.push('_');
            }
        }
        let mut collapsed = String::new();
        for c in out.chars() {
            if !(c == '_' && collapsed.ends_with('_')) {
                collapsed.push(c);
            }
        }
        collapsed.trim_matches('_').to_string()
    };
    let mut best: Option<String> = None;
    for s in servers {
        let s = sanitize(s);
        if !s.is_empty()
            && rest.len() > s.len() + 1
            && rest.starts_with(&s)
            && rest.as_bytes()[s.len()] == b'_'
            && best.as_ref().is_none_or(|b| s.len() > b.len())
        {
            best = Some(s);
        }
    }
    match best {
        Some(b) => format!("mcp__{b}__{}", &rest[b.len() + 1..]),
        None => raw.to_string(),
    }
}

/// The tool's description as the host shows it (Pi), for the description
/// pin (cases 57, 96). `gate::core::decide_call` evaluates with no
/// description, under which every pinned `allow` asks ("description
/// changed", `derm_core::policy::evaluate`). A pin the description holds is
/// taken off its rule here, so the rule matches as an unpinned one, which is
/// what `evaluate` does with the description given: every tied `allow` must
/// hold its pin, and a held pin changes nothing else. A pin it does not hold
/// stays, and asks. Until the core's call carries the description (request
/// 1), this is how the co-process passes it.
fn with_description(
    mut policy: derm_core::policy::PolicyFile,
    description: Option<&str>,
) -> derm_core::policy::PolicyFile {
    let Some(d) = description else {
        return policy;
    };
    let sha = derm_core::policy::description_sha256(d);
    for rule in &mut policy.rules {
        if rule
            .description_sha256
            .as_deref()
            .is_some_and(|pin| pin.eq_ignore_ascii_case(&sha))
        {
            rule.description_sha256 = None;
        }
    }
    policy
}

/// The approval record of one call's outcome, as every gate writes it.
fn approval_event(
    call: &GateCall,
    answer: &GateAnswer,
    outcome: Action,
    extra: Option<&Extra>,
) -> AdapterEvent {
    let chat = call.chat.clone().unwrap_or_default();
    let mut detail = Map::new();
    detail.insert("tool".into(), json!(answer.normalized_tool));
    let label = extra
        .and_then(|e| e.label.clone())
        .unwrap_or_else(|| action_word(outcome).to_string());
    detail.insert("decision".into(), json!(label));
    detail.insert("policyAction".into(), json!(action_word(answer.action)));
    let reason = extra
        .and_then(|e| e.reason.clone())
        .unwrap_or_else(|| answer.reason.clone());
    detail.insert("reason".into(), json!(reason));
    detail.insert("redacted".into(), json!(answer.redacted));
    if let Some(via) = extra.and_then(|e| e.via.clone()) {
        detail.insert("via".into(), json!(via));
    }
    if let Some(t) = &call.tool_use_id {
        detail.insert("toolUseId".into(), json!(t));
    }
    AdapterEvent {
        id: daemon::decision_id(&call.harness, call.tool_use_id.as_deref()),
        chat_id: chat.clone(),
        harness: call.harness.clone(),
        kind: "approval".into(),
        summary: format!("{} {}", answer.normalized_tool, action_word(outcome)),
        detail,
    }
}

/// For a plugin that keeps its own records (`record: false`: derm-pi, whose
/// records are the decision notices its emitter sends the daemon): with no
/// daemon to take this chat, the co-process keeps the light tier's record of
/// the outcome itself, and the reason to deny when it cannot (case 249; box
/// test w6, BW6-3: Pi's decisions were kept nowhere and nothing failed
/// closed). With a daemon, nothing: the plugin's own record goes there.
fn keep_light(
    ctx: &Ctx,
    call: &GateCall,
    answer: &GateAnswer,
    outcome: Action,
    extra: Option<&Extra>,
) -> Option<String> {
    if (ctx.daemon_up)() {
        return None;
    }
    let e = approval_event(call, answer, outcome, extra);
    let kept = super::locallog::after_post(&e, &ctx.env, &ctx.cwd, false);
    super::locallog::denies(&kept, &ctx.env, &ctx.cwd)
}

/// The approval record for one call's outcome, then, with `installs`, its
/// install records: what the TypeScript adapters posted after `decideCall`
/// (`opencode.ts`, `openclaw.ts`, `cline.ts`). How many the daemon took, and,
/// for an approval record posted now, the light tier's deny reason when no
/// one kept it (`daemon::lost_deny`).
fn post_outcome(
    ctx: &Ctx,
    call: &GateCall,
    answer: &GateAnswer,
    outcome: Action,
    extra: Option<&Extra>,
    installs: bool,
    later: bool,
) -> (usize, Option<String>) {
    let mut lost = None;
    let mut send = |e: &AdapterEvent, approval: bool| {
        if later {
            (ctx.post_later)(e.clone())
        } else {
            let p = (ctx.post)(e);
            if approval {
                lost = daemon::lost_deny(&p, &ctx.env, &ctx.cwd);
            }
            p.by_daemon()
        }
    };
    let chat = call.chat.clone().unwrap_or_default();
    let record = approval_event(call, answer, outcome, extra);
    let mut posted = 0;
    if send(&record, true) {
        posted += 1;
    }
    if installs {
        for e in gate::install_events(call, answer, outcome, &chat) {
            if send(&e, false) {
                posted += 1;
            }
        }
    }
    (posted, lost)
}

/// What a plugin adds to its own record (`record`).
struct Extra {
    label: Option<String>,
    via: Option<String>,
    reason: Option<String>,
}

fn plain_word(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max && s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

fn op_approve(ctx: &Ctx, id: &Value, r: &Value) -> Value {
    let call = match call_of(ctx, r) {
        Ok(c) => c,
        Err(e) => return refuse(id, &e),
    };
    let answer = match answer_of(r) {
        Ok(a) if a.action == Action::Ask => a,
        Ok(_) => return refuse(id, "approve is for an answer that asks"),
        Err(e) => return refuse(id, &e),
    };
    let can_ask = match r.get("canAsk") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return refuse(id, "canAsk must be true or false"),
    };
    let record = match wants_record(r) {
        Ok(b) => b,
        Err(e) => return refuse(id, &e),
    };
    let resolved = gate::resolve_ask(&answer, &call, can_ask, &ctx.env, ctx.approve);
    let (mut kind, mut reason, outcome) = match resolved {
        AskResolution::Allow(why) => ("allow", why, Some(Action::Allow)),
        AskResolution::Deny(why) => ("deny", why, Some(Action::Deny)),
        AskResolution::Harness(why) => ("harness", why, None),
    };
    if !record {
        // The outcome, or the host's own prompt about to ask (an ask, as the
        // Claude-format hooks record one before the agent's prompt).
        let extra = Extra {
            label: None,
            via: None,
            reason: Some(reason.clone()),
        };
        let kept = outcome.unwrap_or(Action::Ask);
        if let Some(why) =
            keep_light(ctx, &call, &answer, kept, Some(&extra)).filter(|_| kept != Action::Deny)
        {
            (kind, reason) = ("deny", why);
        }
    }
    if let (true, Some(outcome)) = (record, outcome) {
        let extra = Extra {
            label: None,
            via: None,
            reason: Some(reason.clone()),
        };
        let (_, lost) = post_outcome(ctx, &call, &answer, outcome, Some(&extra), true, false);
        // The light tier fails closed: an allow no one recorded is a deny.
        if let Some(why) = lost.filter(|_| outcome != Action::Deny) {
            (kind, reason) = ("deny", why);
        }
    }
    json!({"id": id, "ok": true, "kind": kind, "reason": reason})
}

fn op_record(ctx: &Ctx, id: &Value, r: &Value) -> Value {
    let call = match call_of(ctx, r) {
        Ok(c) => c,
        Err(e) => return refuse(id, &e),
    };
    let answer = match answer_of(r) {
        Ok(a) => a,
        Err(e) => return refuse(id, &e),
    };
    let Some(outcome) = action_of(r.get("decision")) else {
        return refuse(id, "decision must be allow, ask or deny");
    };
    let label = match opt_str(r.get("label"), "label") {
        Ok(Some(l)) if plain_word(&l, 64) => Some(l),
        Ok(None) => None,
        Ok(Some(_)) => return refuse(id, "label must be plain text of at most 64 characters"),
        Err(e) => return refuse(id, &e),
    };
    let via = match opt_str(r.get("via"), "via") {
        Ok(Some(v)) if plain_word(&v, 32) => Some(v),
        Ok(None) => None,
        Ok(Some(_)) => return refuse(id, "via must be plain text of at most 32 characters"),
        Err(e) => return refuse(id, &e),
    };
    let reason = match opt_str(r.get("reason"), "reason") {
        Ok(v) => v.map(|s| clip(&s, 1000)),
        Err(e) => return refuse(id, &e),
    };
    // An install is recorded with the plugin's outcome, an ask included (the
    // host's own prompt decides it), unless the plugin leaves that to another
    // record (Cline's approval files).
    let installs = match r.get("installs") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return refuse(id, "installs must be true or false"),
    };
    let later = match waits(r) {
        Ok(w) => !w,
        Err(e) => return refuse(id, &e),
    };
    let (posted, _) = post_outcome(
        ctx,
        &call,
        &answer,
        outcome,
        Some(&Extra { label, via, reason }),
        installs,
        later,
    );
    json!({"id": id, "ok": true, "posted": posted})
}

/// A record only the plugin knows (contract section 2.3): an ask the host's
/// own prompt answered, a tool result. The harness is the co-process's and
/// `detail.trust` is `client` whatever the plugin sent.
fn op_event(ctx: &Ctx, id: &Value, r: &Value) -> Value {
    let e = match r.get("event") {
        Some(Value::Object(e)) => e,
        _ => return refuse(id, "event must be an object"),
    };
    let text = |k: &str| e.get(k).and_then(Value::as_str).map(str::to_string);
    let Some(eid) = text("id").filter(|s| !s.is_empty() && s.chars().count() <= MAX_ID_CHARS)
    else {
        return refuse(id, "event.id must be a string of at most 128 characters");
    };
    let kind = match text("kind").as_deref() {
        Some(k @ ("approval" | "tool.call")) => k.to_string(),
        _ => return refuse(id, "event.kind must be approval or tool.call"),
    };
    let mut detail = match e.get("detail") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(d)) => d.clone(),
        Some(_) => return refuse(id, "event.detail must be an object"),
    };
    detail.remove("trust");
    let chat = text("chatId")
        .filter(|s| !s.is_empty())
        .or_else(|| ctx.env.get("DERM_CHAT_ID").map(str::to_string))
        .unwrap_or_default();
    let event = AdapterEvent {
        id: eid,
        chat_id: chat,
        harness: ctx.agent.clone(),
        kind,
        summary: text("summary").unwrap_or_default(),
        detail,
    };
    let posted = match waits(r) {
        Ok(true) => (ctx.post)(&event).by_daemon(),
        Ok(false) => (ctx.post_later)(event),
        Err(e) => return refuse(id, &e),
    };
    json!({"id": id, "ok": true, "posted": posted})
}

/// The hook redactor over one value (`derm_core::redact::hook`), for a tool
/// result the plugin hands back to its host.
fn op_redact(id: &Value, r: &Value) -> Value {
    let Some(v) = r.get("value") else {
        return refuse(id, "value is required");
    };
    let (value, count) = redact_value(v);
    json!({"id": id, "ok": true, "value": value, "count": count})
}

/// Whether `p` is an absolute path a record may be keyed by.
fn plain_absolute(p: &str) -> bool {
    !p.is_empty() && p.len() <= 4096 && !p.contains('\0') && Path::new(p).is_absolute()
}

#[cfg(test)]
mod tests;
