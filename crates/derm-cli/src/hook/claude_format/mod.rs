//! The Claude-format dialects (lane 5bA): Claude Code, Codex, Gemini,
//! OpenClaude, Qwen Code, Droid, Command Code, Kimi Code, Auggie, Copilot
//! CLI and Grok, each as its TypeScript adapter answers today
//! (`packages/derm-claude-plugin`, `derm-codex-plugin`,
//! `derm-gemini-extension`, `derm-hooks-claude-compat`), on the gate in
//! `crate::gate`.
//!
//! The base's stub answers every call with the agent's fail-closed deny, so
//! a registration that reaches it before the lane lands blocks every call
//! and lets none through.

pub fn answer(agent: &str, event: &str, stdin: &mut dyn std::io::Read) -> super::Reply {
    let _ = (event, stdin);
    super::fail_closed(
        agent,
        "derm hook: this agent's dialect is not built yet (wave 5b lane 5bA); the call is denied",
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stub_denies() {
        for agent in ["claude-code", "codex", "gemini", "grok"] {
            let r = super::answer(agent, "pre", &mut std::io::empty());
            assert_eq!(r.exit, 2, "{agent}");
        }
    }
}
