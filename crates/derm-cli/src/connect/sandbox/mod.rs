//! The Standard tier's writers (wave 6, lane 6A; `contracts/sandbox.md`):
//! derm's policy as each agent's own sandbox settings, for `derm run` to
//! deliver (`run/standard/`) and for `derm connect` to print or write behind
//! the usual dry run and terminal yes. The wave 6 base's stub: no agent has a
//! writer yet, so [`fragment`] answers none for every agent and nothing calls
//! it but its test.
//!
//! Each row of `presets/wave6/sandbox.json` names how an agent takes its
//! sandbox (note AZ section 5): Claude Code 2.1.322 by its own `--settings`
//! file, since a project file beats the user's settings (A2) and a type
//! error drops a whole file, hooks included (A10); Codex 0.167.2 by `-c`
//! pairs, since a trusted project outranks the user's profile (A4).

use serde_json::Value;

/// The settings fragment for `agent` from derm's policy, or `None` where the
/// agent has no Standard tier (the base's stub: every agent).
pub(crate) fn fragment(_agent: &str, _policy: &Value) -> Option<Value> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_writes_for_no_agent() {
        for agent in ["claude-code", "codex", "cursor", "gemini"] {
            assert_eq!(fragment(agent, &serde_json::json!({"version": 1})), None);
        }
    }
}
