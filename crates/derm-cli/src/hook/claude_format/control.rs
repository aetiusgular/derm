//! The agents' own control files that the core's list
//! (`derm_core::policy::CONTROL_PATHS`) does not name. An allowed call whose
//! input names one asks instead, read the way the core reads its own list:
//! folded, escapes decoded, with and without quotes. Ported from
//! `packages/derm-gemini-extension/src/control.ts` and
//! `packages/derm-hooks-claude-compat/src/control.ts` at `e29ce27`; the
//! sources for each path are in their headers (gemini-cli v0.66.0; lane L's
//! research for the eight). Narrows only, never widens.

use derm_core::policy::{decode_escapes, fold_text, unquote, Action};

/// Gemini's (`GEMINI_CONTROL_PATHS`): `.gemini/` (settings with `hooks`,
/// `hooksConfig.enabled` and `.disabled`, extensions, policies), the managed
/// folders on Linux and macOS, and the variable that moves them.
pub const GEMINI_CONTROL_PATHS: [&str; 4] =
    [".gemini/", "gemini-cli/", "geminicli/", "gemini_cli_system"];

/// The eight Claude-format agents' (`AGENT_CONTROL_PATHS`).
pub const AGENT_CONTROL_PATHS: [&str; 18] = [
    ".openclaude/",
    ".openclaude.json",
    "openclaude_config_dir",
    ".qwen/",
    "qwen_home",
    "qwen_code_system_settings",
    ".factory/",
    "factory_home_override",
    ".commandcode/",
    ".kimi-code/",
    "kimi_code_home",
    ".augment/",
    ".copilot/",
    "copilot_home",
    ".grok/",
    "grok_claude_hooks_enabled",
    "grok_cursor_hooks_enabled",
    "grok_home",
];

fn texts(input_text: &str) -> (String, String) {
    let folded = fold_text(&decode_escapes(input_text));
    let unquoted = unquote(&folded);
    (folded, unquoted)
}

/// The first Gemini control path the input names.
pub fn gemini_control_path(input_text: &str) -> Option<&'static str> {
    let (folded, unquoted) = texts(input_text);
    GEMINI_CONTROL_PATHS
        .iter()
        .copied()
        .find(|p| folded.contains(p) || unquoted.contains(p))
}

/// A folder's bare name at `i` in `text`, not run on into a longer name
/// (`(?![a-z0-9_-])` after it): `mv ~/.factory x` and `rm -r .qwen` are
/// caught, `.qwenrc` and `.grok_cache` are not (L-S4).
fn names_bare_folder(text: &str, bare: &str) -> bool {
    let mut from = 0;
    while let Some(i) = text[from..].find(bare) {
        let end = from + i + bare.len();
        let next = text[end..].chars().next();
        if !next
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            return true;
        }
        from = from + i + bare.chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// The first of the eight agents' control paths the input names
/// (`agentControlPath`): the list as written first, then a folder entry by
/// its bare name.
pub fn agent_control_path(input_text: &str) -> Option<&'static str> {
    let (folded, unquoted) = texts(input_text);
    if let Some(p) = AGENT_CONTROL_PATHS
        .iter()
        .copied()
        .find(|p| folded.contains(p) || unquoted.contains(p))
    {
        return Some(p);
    }
    AGENT_CONTROL_PATHS
        .iter()
        .copied()
        .filter(|p| p.ends_with('/'))
        .find(|p| {
            let bare = &p[..p.len() - 1];
            names_bare_folder(&folded, bare) || names_bare_folder(&unquoted, bare)
        })
}

/// An allow becomes an ask when `found` names a control path; anything
/// else is unchanged (`narrowForControl`).
pub fn narrow(action: Action, found: Option<&'static str>) -> (Action, Option<&'static str>) {
    match (action, found) {
        (Action::Allow, Some(c)) => (Action::Ask, Some(c)),
        (a, _) => (a, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_folder_counts_unless_it_runs_on() {
        assert_eq!(agent_control_path("mv ~/.factory x"), Some(".factory/"));
        assert_eq!(agent_control_path("rm -r .qwen"), Some(".qwen/"));
        assert_eq!(agent_control_path("cat .qwenrc"), None);
        assert_eq!(agent_control_path("ls .grok_cache .factory-notes"), None);
        assert_eq!(agent_control_path("cp x .factory.bak"), Some(".factory/"));
    }

    #[test]
    fn narrowing_never_widens() {
        assert_eq!(narrow(Action::Deny, Some(".gemini/")).0, Action::Deny);
        assert_eq!(narrow(Action::Allow, None).0, Action::Allow);
        assert_eq!(narrow(Action::Allow, Some(".gemini/")).0, Action::Ask);
    }

    #[test]
    fn gemini_paths_are_read_folded_and_unquoted() {
        assert_eq!(
            gemini_control_path("cat ~/.GEMINI/settings.json"),
            Some(".gemini/")
        );
        assert_eq!(
            gemini_control_path("echo x > '.gem''ini/x'"),
            Some(".gemini/")
        );
        assert_eq!(gemini_control_path("ls"), None);
    }
}
