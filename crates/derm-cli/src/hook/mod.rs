//! `derm hook <agent> <event>`: the command-hook gate in Rust (wave 5b,
//! `plans/toolkit_wave5b_plan.md` section 0, item 1; cut by the wave 5b
//! base). The agent's registration runs derm by its absolute path with the
//! agent's id and event (`contracts/hook-dialects.md` section 9); the agent's
//! hook input is on stdin and its reply goes to stdout, stderr and the exit
//! code in that agent's own dialect.
//!
//! This file only dispatches, and it is integration's: `claude_format/` is
//! lane 5bA's (Claude Code, Codex, Gemini, OpenClaude, Qwen Code, Droid,
//! Command Code, Kimi Code, Auggie, Copilot CLI, Grok) and `native/` lane
//! 5bB's (Cursor, Antigravity, goose, Mistral Vibe, Crush, Kiro, and Hermes).
//! The agent comes from argv, never from the input (wave 5b plan section 5,
//! item 3), and a dialect acts only when the input's own marks agree with it
//! (BCR-7, case 109; `contracts/hook-dialects.md` section 9.2).
//!
//! Every failure is the agent's own deny ([`fail_closed`]): an unknown agent
//! or event, an input that cannot be read, a dialect not built yet.

pub mod claude_format;
pub mod native;

use std::io::Write;

/// Which lane's dialect answers an agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// `claude_format/`, lane 5bA.
    ClaudeFormat,
    /// `native/`, lane 5bB.
    Native,
}

/// The agents `derm hook` answers, with their family and the events their
/// registration passes (`contracts/hook-dialects.md` section 9.1).
pub const AGENTS: [(&str, Family, &[&str]); 18] = [
    ("claude-code", Family::ClaudeFormat, &["pre", "post"]),
    ("codex", Family::ClaudeFormat, &["pre", "post"]),
    ("gemini", Family::ClaudeFormat, &["before", "after"]),
    ("openclaude", Family::ClaudeFormat, &["pre"]),
    ("qwen-code", Family::ClaudeFormat, &["pre"]),
    ("droid", Family::ClaudeFormat, &["pre"]),
    ("command-code", Family::ClaudeFormat, &["pre"]),
    ("kimi", Family::ClaudeFormat, &["pre"]),
    ("auggie", Family::ClaudeFormat, &["pre"]),
    ("copilot-cli", Family::ClaudeFormat, &["pre"]),
    ("grok", Family::ClaudeFormat, &["pre"]),
    ("cursor", Family::Native, &["pre"]),
    ("antigravity", Family::Native, &["pre"]),
    ("goose", Family::Native, &["pre"]),
    ("mistral-vibe", Family::Native, &["pre"]),
    ("crush", Family::Native, &["pre"]),
    ("kiro", Family::Native, &["pre"]),
    ("hermes", Family::Native, &["pre", "post"]),
];

/// What a hook writes and how it exits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub stdout: String,
    pub stderr: String,
    pub exit: u8,
}

/// The agent's own deny, with `derm: <reason>` (each dialect's `deny` or
/// `block` in the TypeScript, `bin/fallback.mjs` for the native ones; Hermes's
/// plugin adds the prefix itself). For an
/// agent derm does not know: the reason on stderr and exit 2, the most any
/// hook runner reads as a failure.
pub fn fail_closed(agent: &str, reason: &str) -> Reply {
    let text = format!(
        "derm: {}",
        reason.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    let json = |v: serde_json::Value| format!("{v}\n");
    let exit2 = |stdout: String| Reply {
        stdout,
        stderr: format!("{text}\n"),
        exit: 2,
    };
    match agent {
        "cursor" => Reply {
            stdout: json(
                serde_json::json!({"permission": "deny", "user_message": text, "agent_message": text}),
            ),
            stderr: String::new(),
            exit: 0,
        },
        "antigravity" | "mistral-vibe" => Reply {
            stdout: json(serde_json::json!({"decision": "deny", "reason": text})),
            stderr: String::new(),
            exit: 0,
        },
        "goose" => exit2(json(
            serde_json::json!({"decision": "block", "reason": text}),
        )),
        "gemini" => exit2(json(
            serde_json::json!({"decision": "deny", "reason": text}),
        )),
        // `derm hook hermes` answers in the Node decider's shape, and
        // `derm_gate.py` adds `derm: ` itself (its `_block`), so the reason
        // goes without it, as `hook/native/hermes.rs`'s own deny does.
        "hermes" => Reply {
            stdout: json(serde_json::json!({
                "decision": "deny",
                "reason": text.trim_start_matches("derm: "),
            })),
            stderr: String::new(),
            exit: 0,
        },
        _ => exit2(String::new()),
    }
}

pub const USAGE: &str = "usage: derm hook <agent> <event>

  The gate for an agent's command hook: the agent's hook input on stdin, its
  reply on stdout, stderr and the exit code (contracts/hook-dialects.md).
  The agent's registration names the event (`derm connect <agent> --gate`).";

/// Runs one hook call: reads stdin, answers, writes the reply.
pub fn main(args: &[String]) -> u8 {
    let agent = args.first().map(String::as_str).unwrap_or("");
    let event = args.get(1).map(String::as_str).unwrap_or("");
    let reply = answer(agent, event, &mut std::io::stdin().lock());
    let _ = std::io::stdout().write_all(reply.stdout.as_bytes());
    let _ = std::io::stderr().write_all(reply.stderr.as_bytes());
    reply.exit
}

/// The reply for one call, with stdin passed in (for tests).
pub fn answer(agent: &str, event: &str, stdin: &mut dyn std::io::Read) -> Reply {
    if agent.is_empty() {
        let mut r = fail_closed(agent, "no agent named");
        r.stderr.push_str(USAGE);
        r.stderr.push('\n');
        return r;
    }
    let Some((_, family, events)) = AGENTS.iter().find(|(a, _, _)| *a == agent) else {
        let shown: String = agent.chars().take(40).collect();
        return fail_closed(
            agent,
            &format!(
                "unknown agent {shown:?}: `derm hook` takes {}",
                agent_list()
            ),
        );
    };
    if !events.contains(&event) {
        let shown: String = event.chars().take(40).collect();
        return fail_closed(
            agent,
            &format!(
                "unknown event {shown:?} for {agent}: it takes {}",
                events.join(" or ")
            ),
        );
    }
    match family {
        Family::ClaudeFormat => claude_format::answer(agent, event, stdin),
        Family::Native => native::answer(agent, event, stdin),
    }
}

fn agent_list() -> String {
    AGENTS
        .iter()
        .map(|(a, _, _)| *a)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_agent_or_event_is_a_deny() {
        let r = answer("frob", "pre", &mut std::io::empty());
        assert_eq!(r.exit, 2);
        assert!(r.stderr.starts_with("derm: unknown agent"));
        let r = answer("cursor", "post", &mut std::io::empty());
        assert_eq!(r.exit, 0);
        assert!(r.stdout.contains("\"permission\":\"deny\""));
    }

    #[test]
    fn the_fallback_matches_the_native_packages_table() {
        // packages/derm-hooks-native/bin/fallback.mjs at e29ce27.
        let r = fail_closed("crush", "x");
        assert_eq!(
            (r.stdout.as_str(), r.stderr.as_str(), r.exit),
            ("", "derm: x\n", 2)
        );
        let r = fail_closed("goose", "x");
        assert_eq!(
            r.stdout,
            "{\"decision\":\"block\",\"reason\":\"derm: x\"}\n"
        );
        assert_eq!(r.exit, 2);
    }

    /// Lane 5bB's request 1: Hermes's plugin runs `derm hook hermes`, whose
    /// reply is the old Node decider's (`hook/native/hermes.rs`), and
    /// `derm_gate.py` adds `derm: ` itself (`_block`, lines 52-54, 167-168).
    /// Recorded: `{"decision":"deny","reason":"unknown event other"}`
    /// (`decide.test.ts`, "anything it cannot read is a deny").
    #[test]
    fn hermes_fails_closed_in_the_deciders_own_shape() {
        let r = fail_closed("hermes", "unknown  event other");
        assert_eq!(
            (r.stdout.as_str(), r.stderr.as_str(), r.exit),
            (
                "{\"decision\":\"deny\",\"reason\":\"unknown event other\"}\n",
                "",
                0
            )
        );
    }
}
