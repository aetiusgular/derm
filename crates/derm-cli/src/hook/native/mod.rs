//! The native dialects (lane 5bB): Cursor (preToolUse and
//! beforeMCPExecution, case 110), Antigravity, goose, Mistral Vibe, Crush,
//! Kiro (stdout is context, case 77) and Hermes, each as
//! `packages/derm-hooks-native` and `packages/derm-hermes-plugin` answer
//! today, on the gate in `crate::gate`.
//!
//! The base's stub answers every call with the agent's fail-closed deny.

pub fn answer(agent: &str, event: &str, stdin: &mut dyn std::io::Read) -> super::Reply {
    use std::io::Read;
    let _ = event;
    // Read what the agent sent, so it never meets a closed pipe.
    let _ = std::io::copy(&mut stdin.take(16 << 20), &mut std::io::sink());
    super::fail_closed(
        agent,
        "derm hook: this agent's dialect is not built yet (wave 5b lane 5bB); the call is denied",
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stub_denies() {
        let r = super::answer("cursor", "pre", &mut std::io::empty());
        assert!(r.stdout.contains("\"permission\":\"deny\""));
        let r = super::answer("kiro", "pre", &mut std::io::empty());
        assert_eq!(r.exit, 2);
        assert!(
            r.stdout.is_empty(),
            "Kiro reads stdout as context (case 77)"
        );
    }
}
