//! Lane W's request W-2: derm setup's policy presets
//! (`crates/derm-cli/src/setup/presets/`) read by derm-core's matcher, with
//! command rules (request W-1, `contracts/policy.md` section 7), against
//! `tests/cli-contract/checks/W/preset-cases.json`.

use derm_core::policy::{evaluate, parse, Action, Call, Permission};
use serde_json::Value;

const PRESETS: &[(&str, &str)] = &[
    (
        "workspace-write",
        include_str!("../../derm-cli/src/setup/presets/workspace-write.json"),
    ),
    (
        "read-only",
        include_str!("../../derm-cli/src/setup/presets/read-only.json"),
    ),
    (
        "strict",
        include_str!("../../derm-cli/src/setup/presets/strict.json"),
    ),
];
const CASES: &str = include_str!("../../../tests/cli-contract/checks/W/preset-cases.json");

#[test]
fn every_preset_parses_and_answers_its_cases() {
    let cases: Value = serde_json::from_str(CASES).unwrap();
    let cases = cases["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 50);
    for (name, text) in PRESETS {
        let doc: Value = serde_json::from_str(text).unwrap();
        let policy = parse(&doc["policy"].to_string()).unwrap_or_else(|e| panic!("{name}: {e}"));
        for c in cases.iter().filter(|c| c["preset"] == *name) {
            let call: Call = serde_json::from_value(c["call"].clone()).unwrap();
            let d = evaluate(&policy, &call);
            let want: Action = serde_json::from_value(c["expect"]["action"].clone()).unwrap();
            let prefix = c["expect"]["reasonPrefix"].as_str().unwrap();
            assert_eq!(d.action, want, "case {} ({name}): {}", c["id"], d.reason);
            // P1: the reason past its permission's name is what the case
            // was written against.
            let rest = match d.permission {
                Some(p) => d.reason.strip_prefix(&p.prefix()).unwrap_or(&d.reason),
                None => &d.reason,
            };
            assert!(
                rest.starts_with(prefix),
                "case {} ({name}): {:?} does not start with {prefix:?}",
                c["id"],
                d.reason
            );
        }
    }
}

/// P1 against the default preset: its `derm` command rules are derm itself,
/// a secret is secrets, an install is running downloaded code, a hook file
/// is a file that runs later, and its other command rules carry none.
#[test]
fn the_default_presets_answers_carry_their_permissions() {
    let cases: Value = serde_json::from_str(CASES).unwrap();
    let doc: Value = serde_json::from_str(PRESETS[0].1).unwrap();
    let policy = parse(&doc["policy"].to_string()).unwrap();
    let want: &[(u64, Option<Permission>, &str)] = &[
        (
            5,
            Some(Permission::DermItself),
            "derm itself, rule bash derm setup",
        ),
        (
            35,
            Some(Permission::Secrets),
            "secrets, input names a secret path",
        ),
        (
            8,
            Some(Permission::RunningDownloadedCode),
            "running downloaded code, package install",
        ),
        (3, None, "rule bash git push"),
        (4, None, "rule bash docker run --privileged"),
        (12, None, "no rule"),
        (37, None, "command changes the filesystem root"),
    ];
    for (id, permission, start) in want {
        let c = cases["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == *id && c["preset"] == "workspace-write")
            .unwrap_or_else(|| panic!("case {id}"));
        let call: Call = serde_json::from_value(c["call"].clone()).unwrap();
        let d = evaluate(&policy, &call);
        assert_eq!(d.permission, *permission, "case {id}: {}", d.reason);
        assert!(d.reason.starts_with(start), "case {id}: {}", d.reason);
    }
}

/// Step P (lane PE's request PE-R8, the base's request): derm's own project
/// tools in each preset, by Claude Code's name (`mcp__derm_project__<tool>`,
/// split at the double underscore). Same-project calls are the daemon's to
/// allow and cross-project ones ask at the daemon as well (P7); the preset
/// says whether the gate asks first. The writing verbs of `derm project`
/// and `derm secret bind` are denied, as `derm setup`'s are (case 147).
#[test]
fn step_p_presets_answer_derms_project_tools_and_deny_its_writing_verbs() {
    let want = [
        ("workspace-write", Action::Allow, Action::Allow),
        ("read-only", Action::Ask, Action::Allow),
        ("strict", Action::Ask, Action::Ask),
    ];
    for (name, text) in PRESETS {
        let doc: Value = serde_json::from_str(text).unwrap();
        let policy = parse(&doc["policy"].to_string()).unwrap();
        let (_, message, read) = want.iter().find(|w| w.0 == *name).unwrap();
        for (tool, action) in [
            ("mcp__derm_project__derm_message", message),
            ("mcp__derm_project__derm_terminal_read", read),
        ] {
            let call = Call {
                tool: tool.into(),
                harness: "claude-code".into(),
                chat: None,
                description: None,
                input_text: "{}".into(),
            };
            let d = evaluate(&policy, &call);
            assert_eq!(d.action, *action, "{name} {tool}: {}", d.reason);
        }
        for cmd in [
            "derm project add /srv/x",
            "derm project remove /srv/x",
            "derm secret bind gh --project /srv/x",
            "derm secret unbind gh",
        ] {
            let call = Call {
                tool: "Bash".into(),
                harness: "claude-code".into(),
                chat: None,
                description: None,
                input_text: cmd.into(),
            };
            assert_eq!(
                evaluate(&policy, &call).action,
                Action::Deny,
                "{name}: {cmd}"
            );
        }
    }
}
