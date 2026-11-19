//! `derm kit register`: what it writes for each agent, and where it refuses.
//! The expected entries are the ones the Node registrars write in the Node
//! kit (`packaging/sbx-kit/register-hooks.mjs`, `register-agent.mjs`), with
//! `derm hook <agent> <event>` where they name Node and the hook file.

use super::*;
use std::collections::HashMap;

const DERM: &str = "/usr/local/bin/derm";
const HOME: &str = "/home/agent";

fn disk(files: &[(&str, &str)]) -> impl Fn(&Path) -> Result<Option<String>, String> {
    let map: HashMap<PathBuf, String> = files
        .iter()
        .map(|(p, t)| (PathBuf::from(p), t.to_string()))
        .collect();
    move |p: &Path| Ok(map.get(p).cloned())
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

fn one(planned: Vec<Planned>, path: &str) -> String {
    assert_eq!(planned.len(), 1, "{planned:?}");
    assert_eq!(planned[0].path, PathBuf::from(path));
    planned[0].text.clone().expect("a new text")
}

#[test]
fn it_runs_only_where_derms_kit_wrote_its_vm_marker() {
    let home = Path::new(HOME);
    // On a host there is no marker: nothing is written, whoever asks.
    for (agent, root, h) in [
        (CLAUDE, true, None),
        ("droid", false, Some(home)),
        ("cursor", true, Some(home)),
    ] {
        let why = refusal(agent, Some("no VM marker"), root, h, true).expect("refused");
        assert!(why.contains("only inside derm's sbx VM"), "{why}");
        assert!(why.contains("derm connect"), "{why}");
    }
    // In the VM: Claude Code's managed settings are root's.
    assert_eq!(refusal(CLAUDE, None, true, None, false), None);
    assert!(refusal(CLAUDE, None, false, None, false)
        .unwrap()
        .contains("root's"));
    assert!(refusal(CLAUDE, None, true, Some(home), true)
        .unwrap()
        .contains("no --home"));
    // The others' config is the agent's own user's.
    for agent in HOME_AGENTS {
        assert_eq!(
            refusal(agent, None, false, Some(home), true),
            None,
            "{agent}"
        );
        assert!(refusal(agent, None, true, Some(home), true)
            .unwrap()
            .contains("not as root"));
        assert!(refusal(agent, None, false, None, true)
            .unwrap()
            .contains("needs --home"));
        assert!(
            refusal(agent, None, false, Some(Path::new("home/agent")), true)
                .unwrap()
                .contains("absolute")
        );
        assert!(refusal(agent, None, false, Some(home), false)
            .unwrap()
            .contains("not this user's own"));
    }
    assert!(refusal("codex", None, false, Some(home), true)
        .unwrap()
        .contains("no registration"));
}

#[test]
fn claude_codes_gate_goes_into_its_managed_settings_in_exec_form() {
    let file = Path::new(MANAGED);
    let p = plan_claude(DERM, file, None).unwrap();
    assert_eq!(p.path, file);
    let got = json(p.text.as_deref().unwrap());
    assert_eq!(
        got,
        serde_json::json!({"hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [{
                "type": "command", "command": DERM,
                "args": ["hook", "claude-code", "pre"],
                "timeout": 120, "onFailure": "block"}]}],
            "PostToolUse": [{"matcher": "*", "hooks": [{
                "type": "command", "command": DERM,
                "args": ["hook", "claude-code", "post"],
                "timeout": 120}]}]
        }})
    );
    // The entries are the ones `derm run claude-code` registers on a host.
    assert_eq!(got["hooks"], crate::run::claude_gate::hooks(DERM, None));
    // A second run changes nothing.
    let again = plan_claude(DERM, file, p.text.as_deref()).unwrap();
    assert_eq!(again.text, None);
}

#[test]
fn claude_codes_other_settings_and_hooks_are_kept() {
    let have = r#"{"env": {"A": "1"}, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/other/check"}]}], "Stop": []}}"#;
    let p = plan_claude(DERM, Path::new(MANAGED), Some(have)).unwrap();
    let got = json(p.text.as_deref().unwrap());
    assert_eq!(got["env"], serde_json::json!({"A": "1"}));
    assert_eq!(got["hooks"]["Stop"], serde_json::json!([]));
    let pre = got["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre.len(), 2);
    assert_eq!(pre[0]["hooks"][0]["command"], "/opt/other/check");
    assert_eq!(pre[1]["hooks"][0]["command"], DERM);
    assert_eq!(got["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
}

#[test]
fn claude_codes_settings_of_another_shape_are_refused_not_replaced() {
    let file = Path::new(MANAGED);
    for (have, want) in [
        ("[1]", "does not hold a JSON object"),
        ("{", "is not JSON"),
        (r#"{"hooks": []}"#, "\"hooks\" in"),
        (
            r#"{"hooks": {"PreToolUse": {}}}"#,
            "\"hooks.PreToolUse\" in",
        ),
    ] {
        let e = plan_claude(DERM, file, Some(have)).unwrap_err();
        assert!(e.contains(want), "{have}: {e}");
    }
    // An empty file is a file with nothing in it yet.
    assert!(plan_claude(DERM, file, Some("  \n"))
        .unwrap()
        .text
        .is_some());
}

#[test]
fn copilot_cli_gets_a_hooks_file_of_derms_own() {
    let text = one(
        plan_agent("copilot-cli", DERM, Path::new(HOME), &disk(&[])).unwrap(),
        "/home/agent/.copilot/hooks/derm.json",
    );
    assert_eq!(
        json(&text),
        serde_json::json!({"version": 1, "hooks": {"preToolUse": [{
            "type": "command", "bash": "/usr/local/bin/derm hook copilot-cli pre", "timeoutSec": 120}]}})
    );
    // A file there that is not derm's is not replaced.
    let e = plan_agent(
        "copilot-cli",
        DERM,
        Path::new(HOME),
        &disk(&[("/home/agent/.copilot/hooks/derm.json", "{\"version\": 1}\n")]),
    )
    .unwrap_err();
    assert!(e.contains("not derm's"), "{e}");
}

#[test]
fn droid_gets_its_entry_beside_its_other_settings_and_never_under_a_file_that_shadows_it() {
    let home = Path::new(HOME);
    let file = "/home/agent/.factory/settings.json";
    let text = one(plan_agent("droid", DERM, home, &disk(&[])).unwrap(), file);
    let entry = serde_json::json!({"matcher": "*", "hooks": [{
        "type": "command", "command": "/usr/local/bin/derm hook droid pre", "timeout": 120}]});
    assert_eq!(
        json(&text),
        serde_json::json!({"hooks": {"PreToolUse": [entry.clone()]}})
    );

    let have = "{\n  \"model\": \"x\",\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\"matcher\": \"Bash\", \"hooks\": []}\n    ]\n  }\n}\n";
    let text = one(
        plan_agent("droid", DERM, home, &disk(&[(file, have)])).unwrap(),
        file,
    );
    let got = json(&text);
    assert_eq!(got["model"], "x");
    assert_eq!(
        got["hooks"]["PreToolUse"],
        serde_json::json!([{"matcher": "Bash", "hooks": []}, entry])
    );

    for shadow in [
        "/home/agent/.factory/hooks.json",
        "/home/agent/.factory/hooks/hooks.json",
    ] {
        let e = plan_agent("droid", DERM, home, &disk(&[(shadow, "{}")])).unwrap_err();
        assert!(e.contains("would shadow derm's gate"), "{e}");
    }
}

#[test]
fn cursor_gets_both_of_its_hooks_fail_closed() {
    let file = "/home/agent/.cursor/hooks.json";
    let text = one(
        plan_agent("cursor", DERM, Path::new(HOME), &disk(&[])).unwrap(),
        file,
    );
    let h = serde_json::json!({"type": "command", "command": "/usr/local/bin/derm hook cursor pre", "timeout": 120, "failClosed": true});
    assert_eq!(
        json(&text),
        serde_json::json!({"version": 1, "hooks": {"preToolUse": [h.clone()], "beforeMCPExecution": [h.clone()]}})
    );
    // Another hook in the file stays where it is.
    let have = "{\n  \"version\": 1,\n  \"hooks\": {\n    \"preToolUse\": [\n      {\"command\": \"./mine.sh\"}\n    ]\n  }\n}\n";
    let got = json(&one(
        plan_agent("cursor", DERM, Path::new(HOME), &disk(&[(file, have)])).unwrap(),
        file,
    ));
    assert_eq!(
        got["hooks"]["preToolUse"],
        serde_json::json!([{"command": "./mine.sh"}, h.clone()])
    );
    assert_eq!(got["hooks"]["beforeMCPExecution"], serde_json::json!([h]));
}

#[test]
fn kiro_gets_a_hooks_file_of_derms_own() {
    let text = one(
        plan_agent("kiro", DERM, Path::new(HOME), &disk(&[])).unwrap(),
        "/home/agent/.kiro/hooks/derm.json",
    );
    assert_eq!(
        json(&text),
        serde_json::json!({"version": "v1", "hooks": [{
            "name": "derm-gate",
            "description": "derm policy gate: exit 2 blocks the call, exit 0 prints nothing",
            "trigger": "PreToolUse",
            "action": {"type": "command", "command": "/usr/local/bin/derm hook kiro pre"},
            "timeout": 120, "enabled": true}]})
    );
}

#[test]
fn every_registration_runs_derm_by_its_absolute_path_and_a_second_run_changes_nothing() {
    for agent in HOME_AGENTS {
        let first = plan_agent(agent, DERM, Path::new(HOME), &disk(&[])).unwrap();
        let mut written: Vec<(String, String)> = Vec::new();
        for p in &first {
            let text = p.text.clone().expect("a new file");
            // The reader `derm connect` and `derm doctor` find derm's line
            // with: one place, named by an absolute path (case 227).
            assert_eq!(
                gate::derm_hook_runs(&text, agent).first(),
                Some(&true),
                "{agent}: {text}"
            );
            assert!(
                !gate::derm_hook_runs(&text, agent).contains(&false),
                "{agent}"
            );
            assert!(text.ends_with('\n'), "{agent}");
            written.push((p.path.to_string_lossy().into_owned(), text));
        }
        let refs: Vec<(&str, &str)> = written
            .iter()
            .map(|(p, t)| (p.as_str(), t.as_str()))
            .collect();
        let again = plan_agent(agent, DERM, Path::new(HOME), &disk(&refs)).unwrap();
        assert!(again.iter().all(|p| p.text.is_none()), "{agent}: {again:?}");
    }
}

#[test]
fn an_agent_with_no_kit_registration_is_refused() {
    for agent in ["codex", "pi", "claude-code", "goose", ""] {
        let e = plan_agent(agent, DERM, Path::new(HOME), &disk(&[])).unwrap_err();
        assert!(e.contains("no registration"), "{agent}: {e}");
    }
}

#[test]
fn the_command_takes_register_an_agent_and_at_most_a_home() {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(main(&s(&[])), 2);
    assert_eq!(main(&s(&["register"])), 2);
    assert_eq!(main(&s(&["install", "droid"])), 2);
    assert_eq!(main(&s(&["register", "droid", "--house", "/x"])), 2);
    // No test machine holds derm's VM marker, so this writes nothing.
    assert_eq!(
        main(&s(&[
            "register",
            "droid",
            "--home",
            "/nonexistent-derm-kit-test"
        ])),
        1
    );
    assert_eq!(main(&s(&["register", "claude-code"])), 1);
}
