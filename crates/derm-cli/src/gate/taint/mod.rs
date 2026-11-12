//! Taint and injected input at the gate (wave 6, lane 6D;
//! `plans/toolkit_wave6_plan.md` section 2.2; `contracts/policy.md` section
//! 9; `contracts/events.md` section 6.2). The wave 6 base cut this seam:
//! [`decide_call`] passes every answer through [`adjust`] before full access
//! applies. The stub returns the answer unchanged.
//!
//! What lane 6D builds here (note AZ rows D1 to D6; E0's ranked list item 5
//! and request R-E0-6): a chat is tainted after untrusted content or a
//! secret read; after that, egress to a new host, protected writes,
//! installs, pushes and running a file the session wrote get the chat's
//! verdict: `ask`, `deny` or `record`, chosen per chat with `derm run
//! --taint` (Tony's call of 12 Nov), else the setting, else `ask`
//! (`contracts/policy.md` section 9). Taint only raises an answer: an allow
//! can become an ask, never the other way (rules section 5, item 7). The same calls not
//! covered by `locallog/` (note AZ, S1) are not covered here.
//!
//! [`decide_call`]: super::core::decide_call

use super::core::{GateAnswer, GateCall};
use super::daemon::Env;

/// The seam `decide_call` calls with the policy's answer.
pub fn adjust(answer: GateAnswer, _call: &GateCall, _env: &Env) -> GateAnswer {
    answer
}

#[cfg(test)]
mod tests {
    use super::*;
    use derm_core::policy::Action;
    use serde_json::json;

    #[test]
    fn the_stub_returns_the_answer_unchanged() {
        let answer = GateAnswer {
            action: Action::Allow,
            normalized_tool: "bash".into(),
            reason: "rule bash allow".into(),
            updated_input: None,
            redacted: 0,
            ask_timeout_seconds: 60,
        };
        let call = GateCall {
            harness: "claude-code".into(),
            tool: "Bash".into(),
            tool_input: json!({"command": "git push"}),
            chat: Some("s-1".into()),
            tool_use_id: None,
            full_access: None,
        };
        assert_eq!(
            adjust(answer.clone(), &call, &Env(Default::default())),
            answer
        );
    }
}
