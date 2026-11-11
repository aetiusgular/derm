//! The native agents' and Hermes's own control files. derm-core's list
//! (`derm_core::policy`'s control paths) predates these agents and names none
//! of them; an allowed call whose input names one is asked here instead, the
//! same rule the core applies to its own list (narrowing only, never
//! widening). Moving them into derm-core is a request for integration.
//!
//! Ported from `packages/derm-hooks-native/src/control.ts` and
//! `packages/derm-hermes-plugin/src/control.ts` at `e29ce27`; why each entry
//! is on the list is in those files and `plans/parallel/tk_lane_N.md`,
//! `tk_lane_I.md` (Research).

use derm_core::policy::{decode_escapes, fold_text, unquote, Action};

/// Cursor, Antigravity, goose, Mistral Vibe, Crush, Kiro
/// (`NATIVE_CONTROL_PATHS`).
pub const NATIVE_CONTROL_PATHS: [&str; 18] = [
    // Cursor: hooks.json (the gate's registration), cli-config.json (its
    // permission lists), mcp.json; the managed hooks files.
    ".cursor/",
    "cursor/hooks.json",
    // Antigravity: ~/.gemini/config/hooks.json is under ~/.gemini/, already
    // the core's; the workspace's .agents/hooks.json is not.
    ".agents/hooks.json",
    // goose: the plugin folder that holds derm's hooks.json (BC-1: a
    // project's `.agents/plugins/` too), its config and permission files, and
    // the variables that move them or switch its mode.
    ".agents/plugins/",
    ".config/goose/",
    "goose_path_root",
    "goose_mode",
    "goose_disable_keyring",
    // Mistral Vibe: hooks.toml, config.toml, trusted folders, and the
    // variable that moves the folder.
    ".vibe/",
    "vibe_home",
    // Crush: crush.json and crushrc (global and project), its data folder,
    // and the variables that move them.
    ".config/crush/",
    ".local/share/crush/",
    "crushrc",
    "crush.json",
    "crush_global_config",
    "crush_global_data",
    // Kiro: agent configs with their hooks, settings, steering.
    ".kiro/",
    "kiro_home",
];

/// Hermes (`HERMES_CONTROL_PATHS`).
pub const HERMES_CONTROL_PATHS: [&str; 6] = [
    ".hermes/",
    "hermes_home",
    "hermes_safe_mode",
    "hermes_yolo_mode",
    "hermes_enable_project_plugins",
    "hermes_accept_hooks",
];

/// The first entry of `list` the input names, read the way the core reads its
/// own list: escapes decoded, folded, and again with quotes removed.
pub fn control_path<'a>(list: &[&'a str], input_text: &str) -> Option<&'a str> {
    let folded = fold_text(&decode_escapes(input_text));
    let unquoted = unquote(&folded);
    list.iter()
        .copied()
        .find(|p| folded.contains(p) || unquoted.contains(p))
}

/// Narrows an allow to ask when the input names an entry of `list`. Never
/// widens: the control path is returned only when it changed the action.
pub fn narrow<'a>(list: &[&'a str], action: Action, input_text: &str) -> (Action, Option<&'a str>) {
    if action != Action::Allow {
        return (action, None);
    }
    match control_path(list, input_text) {
        Some(c) => (Action::Ask, Some(c)),
        None => (action, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_path_in_any_spelling_narrows_an_allow_only() {
        let (a, c) = narrow(
            &NATIVE_CONTROL_PATHS,
            Action::Allow,
            "cat ~/.ViBe/hooks.toml",
        );
        assert_eq!((a, c), (Action::Ask, Some(".vibe/")));
        let (a, c) = narrow(
            &NATIVE_CONTROL_PATHS,
            Action::Allow,
            "export GOOSE_\"MODE\"=auto",
        );
        assert_eq!((a, c), (Action::Ask, Some("goose_mode")));
        let (a, c) = narrow(&NATIVE_CONTROL_PATHS, Action::Allow, "cat \\u002ekiro/x");
        assert_eq!((a, c), (Action::Ask, Some(".kiro/")));
        assert_eq!(
            narrow(&NATIVE_CONTROL_PATHS, Action::Deny, "cat .vibe/x"),
            (Action::Deny, None)
        );
        assert_eq!(
            narrow(&HERMES_CONTROL_PATHS, Action::Allow, "ls"),
            (Action::Allow, None)
        );
    }
}
