//! What `derm acp` decides, with no I/O: the policy against an ACP tool
//! call, and against the client-side requests an agent sends (toolkit plan
//! T2.9; note AQ section 7; corner cases 71, 73, 83).
//!
//! ACP v1 (schema 1.29.1, `agentclientprotocol/agent-client-protocol` at
//! `0e486bc`, read 3 Nov 2026):
//! - An agent "MAY request permission from the user before executing a tool
//!   call" (`docs/protocol/v1/tool-calls.mdx:138`), so only the calls it asks
//!   about can be answered; the rest are logged, not gated.
//! - A tool call's `name` is optional, and names "are opaque, informational
//!   metadata and do not advertise a capability or grant authorization"
//!   (`tool-calls.mdx:42-49`); `kind` only helps "choose appropriate icons"
//!   (`schema/v1/schema.json`, `ToolKind`). So a named call is matched by its
//!   name; an unnamed one by its kind and `rawInput`, and it is never allowed
//!   by derm alone: the best it gets is `ask` (case 73).
//! - The answer is one of the options the agent offered
//!   (`allow_once`, `allow_always`, `reject_once`, `reject_always`) or
//!   `cancelled` (`RequestPermissionOutcome`). derm answers an allow only with
//!   `allow_once`: `allow_always` would let the agent stop asking, and derm
//!   would stop seeing those calls.
//! - `fs/read_text_file` (`path`), `fs/write_text_file` (`path`, `content`)
//!   and `terminal/create` (`command`, `args`, `cwd`, `env`) are requests the
//!   agent sends the client (`ReadTextFileRequest`, `WriteTextFileRequest`,
//!   `CreateTerminalRequest`). The client runs them with its own rights,
//!   outside any boundary derm put the agent in.

use derm_core::policy::{evaluate, Action, Call, PolicyFile};
use serde_json::Value;

/// What `derm acp` knows when it answers.
pub struct Ctx {
    pub policy: PolicyFile,
    pub harness: String,
    pub chat: String,
    /// The run is in full access (case 83): an `ask` becomes a deny.
    pub full_access: bool,
    /// The agent runs inside srt or sbx. The client runs `fs/*` and
    /// `terminal/*` itself, outside that boundary, so derm turns them off
    /// (security review L2).
    pub confined: bool,
}

/// One tool call as the agent described it, from its `tool_call` and every
/// `tool_call_update` so far, and the permission request's own `toolCall`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ToolInfo {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub raw_input: Option<Value>,
    /// Free text for the user. Gemini CLI 0.66.0 puts the shell command here
    /// and sends no `rawInput` (run in the cloud, 3 Nov 2026), so it is read
    /// too: more text only ever narrows a decision (the reject list, control
    /// files and the shell checks deny or ask; none of them allows).
    pub title: Option<String>,
}

impl ToolInfo {
    /// Takes the fields a `ToolCall` or `ToolCallUpdate` carries; a field
    /// absent or `null` leaves the earlier value (the schema's rule for
    /// `name`, and the update's "only changed fields").
    pub fn merge(&mut self, v: &Value) {
        if let Some(n) = v.get("name").and_then(Value::as_str) {
            self.name = Some(n.to_string());
        }
        if let Some(k) = v.get("kind").and_then(Value::as_str) {
            self.kind = Some(k.to_string());
        }
        if let Some(r) = v.get("rawInput").filter(|r| !r.is_null()) {
            self.raw_input = Some(r.clone());
        }
        if let Some(t) = v.get("title").and_then(Value::as_str) {
            self.title = Some(t.to_string());
        }
    }
}

/// derm's answer to a permission request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Answer with this option (an `allow_once` or a reject).
    Select { option_id: String, allow: bool },
    /// Answer `cancelled`: the agent offered no reject option.
    Cancelled,
    /// Pass the request on to the client, whose prompt the user sees.
    Forward,
}

/// The decision and why, for the answer and the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub action: Action,
    /// What derm does: `allow`, `deny` or `ask` (the client's prompt).
    pub decision: &'static str,
    pub tool: String,
    pub reason: String,
    pub named: bool,
}

/// The text the reject list and the shell checks run over: a shell call's
/// command line when the input has one, else the input as JSON. A shell
/// call with no readable command line is matched on its JSON, whose
/// brackets the shell check reads as a glob: it asks, the safe side.
pub fn input_text(info: &ToolInfo, shell: bool) -> String {
    let mut text = match &info.raw_input {
        None => String::new(),
        Some(raw) => match raw.get("command").and_then(Value::as_str) {
            Some(cmd) if shell => {
                let mut line = cmd.to_string();
                if let Some(args) = raw.get("args").and_then(Value::as_array) {
                    for a in args {
                        line.push(' ');
                        line.push_str(a.as_str().unwrap_or(""));
                    }
                }
                line
            }
            _ => serde_json::to_string(raw).unwrap_or_default(),
        },
    };
    if let Some(t) = info.title.as_deref().filter(|t| !t.is_empty()) {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(t);
    }
    text
}

/// A kind as a tool name derm's rules can name: `acp_<kind>`, letters and
/// `_` only; `execute` is `bash`, so shell rules and case 30's checks apply.
fn kind_tool(kind: Option<&str>) -> (String, bool) {
    match kind.unwrap_or("other") {
        "execute" => ("bash".to_string(), true),
        k => {
            let clean: String = k
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '_'
                    }
                })
                .take(32)
                .collect();
            (
                format!("acp_{}", if clean.is_empty() { "other" } else { &clean }),
                false,
            )
        }
    }
}

/// The policy against one tool call the agent asks about.
pub fn permission(ctx: &Ctx, info: &ToolInfo) -> Verdict {
    let named = info.name.as_deref().is_some_and(|n| !n.trim().is_empty());
    let (tool, shell) = match &info.name {
        Some(n) if named => {
            let shell = info.kind.as_deref() == Some("execute");
            (n.clone(), shell)
        }
        _ => kind_tool(info.kind.as_deref()),
    };
    let d = evaluate(
        &ctx.policy,
        &Call {
            tool: tool.clone(),
            harness: ctx.harness.clone(),
            chat: Some(ctx.chat.clone()),
            description: None,
            input_text: input_text(info, shell),
        },
    );
    let mut action = d.action;
    let mut reason = d.reason;
    // Case 73: an unnamed call is never allowed by derm alone.
    if !named && action == Action::Allow {
        action = Action::Ask;
        reason = format!("unnamed ACP call ({}), {reason}: ask", d.normalized_tool);
    }
    // Case 83: in full access nobody is asked.
    if ctx.full_access && action == Action::Ask {
        action = Action::Deny;
        reason = format!("{reason}; full access, so an ask is a deny");
    }
    let decision = match action {
        Action::Allow => "allow",
        Action::Deny => "deny",
        Action::Ask => "ask",
    };
    Verdict {
        action,
        decision,
        tool: d.normalized_tool,
        reason,
        named,
    }
}

/// The answer to send for a verdict, from the options the agent offered.
pub fn answer(verdict: &Verdict, options: &[Value]) -> Answer {
    let find = |kind: &str| -> Option<String> {
        options.iter().find_map(|o| {
            (o.get("kind").and_then(Value::as_str) == Some(kind))
                .then(|| {
                    o.get("optionId")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .flatten()
        })
    };
    match verdict.action {
        // Only `allow_once`; with none offered, the user decides.
        Action::Allow => match find("allow_once") {
            Some(id) => Answer::Select {
                option_id: id,
                allow: true,
            },
            None => Answer::Forward,
        },
        Action::Deny => match find("reject_once").or_else(|| find("reject_always")) {
            Some(id) => Answer::Select {
                option_id: id,
                allow: false,
            },
            None => Answer::Cancelled,
        },
        Action::Ask => Answer::Forward,
    }
}

/// `fs/write_text_file`: the policy's `write` rule over the path and the
/// content. `Some(reason)` refuses it; anything else goes to the client,
/// which writes or not.
pub fn client_write(ctx: &Ctx, params: &Value) -> (Option<String>, String) {
    let path = params.get("path").and_then(Value::as_str).unwrap_or("");
    let content = params.get("content").and_then(Value::as_str).unwrap_or("");
    client_request(ctx, "write", format!("{path}\n{content}"))
}

/// `fs/read_text_file`: the policy's `read` rule over the path (security
/// review L2: a read the agent could not make itself is still one).
pub fn client_read(ctx: &Ctx, params: &Value) -> (Option<String>, String) {
    let path = params.get("path").and_then(Value::as_str).unwrap_or("");
    client_request(ctx, "read", path.to_string())
}

/// The text a `terminal/create` runs: `NAME=value` for each variable, the
/// command and its arguments, and the folder it runs in (security review L4:
/// ACP `terminals.mdx:288` has clients check `env` too). `Err` when a field
/// is not the type the schema gives it: derm does not guess what a client
/// would make of it.
pub fn terminal_text(params: &Value) -> Result<String, String> {
    let command = params
        .get("command")
        .and_then(Value::as_str)
        .ok_or("terminal/create with no command string")?;
    let mut line = String::new();
    match params.get("env") {
        None | Some(Value::Null) => {}
        Some(Value::Array(vars)) => {
            for v in vars {
                let name = v.get("name").and_then(Value::as_str);
                let value = v.get("value").and_then(Value::as_str);
                let (Some(name), Some(value)) = (name, value) else {
                    return Err(
                        "terminal/create with a variable that is not a name and a value".into(),
                    );
                };
                line.push_str(&format!("{name}={value} "));
            }
        }
        Some(_) => return Err("terminal/create with env that is not a list".into()),
    }
    line.push_str(command);
    match params.get("args") {
        None | Some(Value::Null) => {}
        Some(Value::Array(args)) => {
            for a in args {
                let a = a
                    .as_str()
                    .ok_or("terminal/create with an argument that is not a string")?;
                line.push(' ');
                line.push_str(a);
            }
        }
        Some(_) => return Err("terminal/create with args that is not a list".into()),
    }
    match params.get("cwd") {
        None | Some(Value::Null) => {}
        Some(Value::String(c)) => {
            line.push('\n');
            line.push_str(c);
        }
        Some(_) => return Err("terminal/create with a cwd that is not a string".into()),
    }
    Ok(line)
}

/// `terminal/create`: the policy's `bash` rule over `terminal_text`.
pub fn client_terminal(ctx: &Ctx, params: &Value) -> (Option<String>, String) {
    match terminal_text(params) {
        Ok(text) => client_request(ctx, "bash", text),
        Err(why) => (Some(why.clone()), why),
    }
}

/// Refused on a deny, and on an ask in full access (case 83; security review
/// L3). Any other ask goes to the client, whose own prompt decides.
fn client_request(ctx: &Ctx, tool: &str, text: String) -> (Option<String>, String) {
    let d = evaluate(
        &ctx.policy,
        &Call {
            tool: tool.to_string(),
            harness: ctx.harness.clone(),
            chat: Some(ctx.chat.clone()),
            description: None,
            input_text: text,
        },
    );
    match d.action {
        Action::Deny => (Some(d.reason.clone()), d.reason),
        Action::Ask if ctx.full_access => {
            let why = format!("{}; full access, so an ask is a deny", d.reason);
            (Some(why.clone()), why)
        }
        _ => (None, d.reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use derm_core::policy::parse;
    use serde_json::json;

    fn ctx(rules: &str) -> Ctx {
        Ctx {
            policy: parse(&format!(r#"{{"version":1,"rules":{rules}}}"#)).unwrap(),
            harness: "gemini".into(),
            chat: "derm-chat1".into(),
            full_access: false,
            confined: false,
        }
    }

    fn info(name: Option<&str>, kind: &str, raw: Value) -> ToolInfo {
        ToolInfo {
            name: name.map(str::to_string),
            kind: Some(kind.into()),
            raw_input: Some(raw),
            title: None,
        }
    }

    fn options() -> Vec<Value> {
        vec![
            json!({"optionId": "a1", "name": "Allow", "kind": "allow_once"}),
            json!({"optionId": "a2", "name": "Always", "kind": "allow_always"}),
            json!({"optionId": "r1", "name": "Reject", "kind": "reject_once"}),
        ]
    }

    #[test]
    fn a_named_call_is_matched_by_its_name() {
        let c = ctx(r#"[{"tool":"read_file","action":"allow"},{"tool":"bash","action":"deny"}]"#);
        let v = permission(&c, &info(Some("read_file"), "read", json!({"path": "/x"})));
        assert_eq!((v.decision, v.named), ("allow", true));
        assert_eq!(
            answer(&v, &options()),
            Answer::Select {
                option_id: "a1".into(),
                allow: true
            }
        );
        // An MCP name in any spelling the matcher knows.
        let c = ctx(r#"[{"tool":"exa/search","action":"deny"}]"#);
        let v = permission(&c, &info(Some("mcp__exa__search"), "fetch", json!({})));
        assert_eq!(v.decision, "deny");
        assert_eq!(
            answer(&v, &options()),
            Answer::Select {
                option_id: "r1".into(),
                allow: false
            }
        );
    }

    #[test]
    fn an_unnamed_call_is_never_allowed_by_derm_alone() {
        // Case 73: `*` allows everything named; an unnamed call still asks.
        let c = ctx(r#"[{"tool":"*","action":"allow"}]"#);
        for kind in ["read", "edit", "execute", "fetch", "other", "made-up kind"] {
            let v = permission(&c, &info(None, kind, json!({"command": "ls"})));
            assert_eq!(v.decision, "ask", "{kind}");
            assert!(!v.named);
            assert_eq!(answer(&v, &options()), Answer::Forward, "{kind}");
        }
        // A deny still holds for it: `execute` is matched as `bash`.
        let c = ctx(r#"[{"tool":"bash","action":"deny"}]"#);
        let v = permission(&c, &info(None, "execute", json!({"command": "ls"})));
        assert_eq!(v.decision, "deny");
        // And the reject list holds whatever the name.
        let c = ctx(r#"[{"tool":"*","action":"allow"}]"#);
        let v = permission(
            &c,
            &info(
                Some("write_file"),
                "edit",
                json!({"path": "/home/u/.claude/settings.local.json", "content": "{}"}),
            ),
        );
        assert_eq!(v.decision, "deny", "{v:?}");
        // A blank name is no name.
        let v = permission(&c, &info(Some("  "), "read", json!({})));
        assert_eq!(v.decision, "ask");
    }

    #[test]
    fn a_shell_call_is_read_as_its_command_line() {
        let c = ctx(r#"[{"tool":"bash","action":"allow"}]"#);
        let v = permission(
            &c,
            &info(Some("bash"), "execute", json!({"command": "ls -la"})),
        );
        assert_eq!(v.decision, "allow", "{v:?}");
        // Case 30: what the shell reads in a way a matcher cannot asks.
        for cmd in ["ls *", "echo $HOME", "cat ~/.ssh/id_rsa", "ls {a,b}"] {
            let v = permission(&c, &info(Some("bash"), "execute", json!({"command": cmd})));
            assert_eq!(v.decision, "ask", "{cmd}");
        }
        // Arguments in their own array are part of the line.
        let v = permission(
            &c,
            &info(
                Some("bash"),
                "execute",
                json!({"command": "ls", "args": ["$HOME"]}),
            ),
        );
        assert_eq!(v.decision, "ask");
        // No readable command line: matched on the JSON, which asks.
        let v = permission(&c, &info(Some("bash"), "execute", json!({"cmd": ["ls"]})));
        assert_eq!(v.decision, "ask");
    }

    #[test]
    fn no_policy_rule_is_the_clients_prompt_and_full_access_denies_it() {
        let c = ctx("[]");
        let v = permission(&c, &info(Some("edit_file"), "edit", json!({})));
        assert_eq!((v.decision, v.reason.as_str()), ("ask", "no rule"));
        assert_eq!(answer(&v, &options()), Answer::Forward);
        let mut c = ctx("[]");
        c.full_access = true;
        let v = permission(&c, &info(Some("edit_file"), "edit", json!({})));
        assert_eq!(v.decision, "deny");
        assert!(v.reason.contains("full access"), "{}", v.reason);
        // Full access never turns a rule's allow into a deny.
        let mut c = ctx(r#"[{"tool":"read_file","action":"allow"}]"#);
        c.full_access = true;
        let v = permission(&c, &info(Some("read_file"), "read", json!({})));
        assert_eq!(v.decision, "allow");
    }

    #[test]
    fn derm_answers_allow_only_once_and_never_for_good() {
        let v = Verdict {
            action: Action::Allow,
            decision: "allow",
            tool: "x".into(),
            reason: String::new(),
            named: true,
        };
        // Only `allow_always` offered: the user decides.
        assert_eq!(
            answer(
                &v,
                &[json!({"optionId": "a2", "name": "Always", "kind": "allow_always"})]
            ),
            Answer::Forward
        );
        let deny = Verdict {
            action: Action::Deny,
            ..v.clone()
        };
        // `reject_always` when no `reject_once` is offered; `cancelled`
        // when no reject is.
        assert_eq!(
            answer(
                &deny,
                &[json!({"optionId": "r2", "name": "Never", "kind": "reject_always"})]
            ),
            Answer::Select {
                option_id: "r2".into(),
                allow: false
            }
        );
        assert_eq!(
            answer(
                &deny,
                &[json!({"optionId": "a1", "name": "Allow", "kind": "allow_once"})]
            ),
            Answer::Cancelled
        );
        // An option with no id is not one.
        assert_eq!(
            answer(&v, &[json!({"kind": "allow_once"})]),
            Answer::Forward
        );
    }

    #[test]
    fn a_title_holding_the_command_is_read_and_only_narrows() {
        // Gemini CLI 0.66.0's request: no name, no rawInput, the command in
        // the title.
        let gemini = |cmd: &str| ToolInfo {
            name: None,
            kind: Some("execute".into()),
            raw_input: None,
            title: Some(cmd.into()),
        };
        let c = ctx(r#"[{"tool":"*","action":"allow"}]"#);
        let v = permission(
            &c,
            &gemini("codex --dangerously-bypass-approvals-and-sandbox"),
        );
        assert_eq!(v.decision, "deny", "{v:?}");
        let v = permission(&c, &gemini("touch a"));
        assert_eq!(v.decision, "ask");
        // A named call's allow survives a plain title, and a title naming a
        // control file asks.
        let c = ctx(r#"[{"tool":"read_file","action":"allow"}]"#);
        let mut i = info(Some("read_file"), "read", json!({"path": "/w/a"}));
        i.title = Some("Reading a".into());
        assert_eq!(permission(&c, &i).decision, "allow");
        i.title = Some("Reading ~/.codex/config.toml".into());
        assert_eq!(permission(&c, &i).decision, "ask");
    }

    #[test]
    fn merging_keeps_what_an_update_leaves_out() {
        let mut i = ToolInfo::default();
        i.merge(&json!({"toolCallId": "t1", "name": "bash", "kind": "execute", "rawInput": {"command": "ls"}}));
        i.merge(
            &json!({"toolCallId": "t1", "status": "in_progress", "name": null, "rawInput": null}),
        );
        assert_eq!(i.name.as_deref(), Some("bash"));
        assert_eq!(i.raw_input, Some(json!({"command": "ls"})));
        i.merge(&json!({"toolCallId": "t1", "rawInput": {"command": "rm -rf /"}}));
        assert_eq!(i.raw_input, Some(json!({"command": "rm -rf /"})));
    }

    #[test]
    fn client_writes_and_terminals_the_policy_denies_are_refused() {
        let c = ctx(r#"[{"tool":"write","action":"deny"},{"tool":"bash","action":"allow"}]"#);
        let (refuse, _) = client_write(
            &c,
            &json!({"sessionId": "s", "path": "/w/a.txt", "content": "x"}),
        );
        assert!(refuse.is_some());
        let (refuse, _) = client_terminal(
            &c,
            &json!({"sessionId": "s", "command": "ls", "args": ["-la"]}),
        );
        assert!(refuse.is_none());
        // An ask is not a refusal: the client decides, as it would without derm.
        let c = ctx("[]");
        assert!(client_write(&c, &json!({"path": "/w/a", "content": ""}))
            .0
            .is_none());
        // The reject list holds for both.
        let c = ctx(r#"[{"tool":"*","action":"allow"}]"#);
        let (refuse, why) = client_write(
            &c,
            &json!({"path": "/p/.claude/settings.local.json", "content": "{}"}),
        );
        assert!(refuse.is_some(), "{why}");
        let (refuse, why) = client_terminal(
            &c,
            &json!({"command": "codex", "args": ["--dangerously-bypass-approvals-and-sandbox"]}),
        );
        assert!(refuse.is_some(), "{why}");
    }
}
