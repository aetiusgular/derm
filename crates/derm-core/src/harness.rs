//! The harness ids a chat token can carry: what `derm run` sends with
//! `token.mint` and what the daemon accepts (`contracts/daemon-protocol.md`
//! section 3). Mac test w4, MW4-6: the daemon kept its own list of session
//! 0's 14 ids, so `derm run` could not start 9 of its 21 agents, nor an
//! unknown program (rules case 80). One list now, here.
//!
//! It is every id of the preset table (`crates/derm-cli/src/connect/presets/
//! index.json`, both `harnesses` and `planned`, in its order) and `other`,
//! the id `derm run --boundary <b> -- <program>` uses for a program no row
//! names. `derm-cli`'s tests hold it equal to the table and to `derm run`'s
//! own list; the daemon's tests mint a token for each.

pub const IDS: &[&str] = &[
    "claude-code",
    "codex",
    "pi",
    "opencode",
    "gemini",
    "cursor",
    "hermes",
    "openclaw",
    "goose",
    "qwen-code",
    "copilot-cli",
    "amp",
    "crush",
    "zed",
    "kilo",
    "codebuff",
    "oh-my-pi",
    "continue",
    "grok",
    "antigravity",
    "openclaude",
    "auggie",
    "cline",
    "command-code",
    "droid",
    "kimi",
    "kiro",
    "mistral-vibe",
    "rovo-dev",
    "other",
];

/// The id `name` names, as a `'static` string, or `None`.
pub fn id(name: &str) -> Option<&'static str> {
    IDS.iter().copied().find(|id| *id == name)
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_are_unique_and_plain() {
        let mut seen = std::collections::HashSet::new();
        for id in super::IDS {
            assert!(seen.insert(*id), "{id} twice");
            assert!(
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{id}"
            );
        }
        assert_eq!(super::id("other"), Some("other"));
        assert_eq!(super::id("claude"), None);
    }
}
