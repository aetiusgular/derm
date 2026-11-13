//! `derm setup`'s tests: the presets, the settings file, the questions and
//! their writes in a scratch home, the shims run for real with `/bin/sh`,
//! and every refusal. Nothing here reads the real home, the terminal or the
//! machine's agents.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::ask::{pick, Script};
use super::{files, presets, settings, shims, Ctx};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("derm-setup-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn agent(id: &str, name: &str, built: bool, registered: &str) -> Value {
    json!({
        "id": id, "name": name, "onPath": format!("/usr/bin/{id}"),
        "gate": {"status": if built { "built" } else { "planned" }},
        "registered": registered, "failMode": "blocks",
    })
}

fn rows() -> Vec<Value> {
    vec![
        json!({"id": "claude-code", "executables": ["claude"]}),
        json!({"id": "pi", "executables": ["pi"]}),
        json!({"id": "zed"}),
    ]
}

fn ok_matcher(_: &str) -> Result<(), String> {
    Ok(())
}

fn refusing_matcher(_: &str) -> Result<(), String> {
    Err("policy file invalid: unknown field `command`".into())
}

/// Runs `derm setup` against a scratch home with scripted answers; returns
/// the exit code, what was said, and the `derm connect` calls made.
fn setup(
    home: &Path,
    answers: &[&str],
    matcher: fn(&str) -> Result<(), String>,
    packages: Option<PathBuf>,
    dry: bool,
) -> (u8, Script, Vec<Vec<String>>) {
    let mut script = Script::new(answers);
    let mut calls: Vec<Vec<String>> = Vec::new();
    let mut connect = |a: &[String]| {
        calls.push(a.to_vec());
        0u8
    };
    let code = {
        let mut ctx = Ctx {
            home: home.to_path_buf(),
            ask: &mut script,
            agents: vec![
                agent("claude-code", "Claude Code", true, "yes"),
                agent("pi", "Pi", true, "no"),
                agent("zed", "Zed", false, "n/a"),
            ],
            rows: rows(),
            derm: PathBuf::from("/usr/local/bin/derm"),
            packages,
            matcher,
            connect: &mut connect,
            dry_run: dry,
            changed: Vec::new(),
        };
        super::run(&mut ctx)
    };
    (code, script, calls)
}

#[test]
fn every_preset_parses_and_names_its_cli_versions() {
    let all = presets::all().expect("presets");
    let names: Vec<&str> = all.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["workspace-write", "read-only", "strict"]);
    assert_eq!(
        all.iter()
            .filter(|p| p.default)
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>(),
        ["workspace-write"]
    );
    for (name, text) in presets::FILES {
        let v: Value = serde_json::from_str(text).unwrap();
        for cli in [
            "git",
            "gh",
            "vercel",
            "netlify",
            "fly",
            "aws",
            "gcloud",
            "az",
            "docker",
            "kubectl",
            "terraform",
        ] {
            assert!(
                v["cli"][cli].as_str().is_some_and(|s| !s.is_empty()),
                "{name}: no version for {cli}"
            );
        }
        assert!(
            v["boundary"].as_str().unwrap().contains("sbx"),
            "{name} says which boundary it is for"
        );
    }
}

/// The policy's own words for a few calls, read from the preset's rules as
/// the matcher's section 7 reads them: which action a command rule gives.
fn command_action(policy: &Value, words: &[&str]) -> Option<String> {
    policy["rules"].as_array().unwrap().iter().find_map(|r| {
        let c: Vec<&str> = r["command"]
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        (c == words).then(|| r["action"].as_str().unwrap().to_string())
    })
}

fn tool_action(policy: &Value, tool: &str) -> Option<String> {
    policy["rules"].as_array().unwrap().iter().find_map(|r| {
        (r.get("command").is_none() && r["tool"] == tool)
            .then(|| r["action"].as_str().unwrap().to_string())
    })
}

#[test]
fn workspace_write_is_quiet_inside_and_strict_at_the_edges() {
    let p = presets::find("workspace-write").unwrap().policy;
    // Ordinary work in the project folder runs (under the sbx kit an ask is a deny).
    for t in ["read", "write", "edit", "bash", "grep", "glob", "todowrite"] {
        assert_eq!(tool_action(&p, t).as_deref(), Some("allow"), "{t}");
    }
    // The edges ask: pushes, deploys, clouds, containers, remote shells, history.
    for w in [
        &["git", "push"][..],
        &["gh", "pr", "create"],
        &["vercel"],
        &["aws"],
        &["docker", "run"],
        &["kubectl", "apply"],
        &["terraform", "apply"],
        &["ssh"],
        &["git", "reset", "--hard"],
    ] {
        assert_eq!(command_action(&p, w).as_deref(), Some("ask"), "{w:?}");
    }
    // Host access from a container, and derm's own controls, are denied.
    for w in [
        &["docker", "run", "--privileged"][..],
        &["docker", "run", "-v"],
        &["derm", "setup"],
        &["derm", "watch", "approve"],
    ] {
        assert_eq!(command_action(&p, w).as_deref(), Some("deny"), "{w:?}");
    }
    assert_eq!(tool_action(&p, "webfetch").as_deref(), Some("ask"));
}

/// Case 147: an agent reconfiguring derm. `derm init` (wave 6, lane 6B)
/// registers gates and writes a policy as `derm setup` does, so every preset
/// denies it beside `derm setup` (lane 6B's request 7, wave 6 phase 1 merge).
#[test]
fn every_preset_denies_derm_init_beside_derm_setup() {
    use crate::gate::core::{decide_call, GateCall, LoadedPolicy};
    use derm_core::policy::Action;
    for name in ["workspace-write", "strict", "read-only"] {
        let p = presets::find(name).unwrap().policy;
        for w in [&["derm", "setup"][..], &["derm", "init"]] {
            assert_eq!(
                command_action(&p, w).as_deref(),
                Some("deny"),
                "{name}: {w:?}"
            );
        }
        // Through the gate itself, with a flag after the rule's words.
        let loaded = LoadedPolicy {
            policy: derm_core::policy::parse(&p.to_string()).unwrap(),
            problem: None,
        };
        for cmd in ["derm init", "derm init --dry-run", "derm setup"] {
            let call = GateCall {
                harness: "claude-code".into(),
                tool: "Bash".into(),
                tool_input: serde_json::json!({"command": cmd}),
                ..GateCall::default()
            };
            let a = decide_call(&loaded, &call, &crate::gate::daemon::Env::of(&[]));
            assert_eq!(a.action, Action::Deny, "{name}: {cmd}: {}", a.reason);
        }
    }
}

#[test]
fn strict_denies_where_the_plan_says_strict_and_read_only_asks_for_writes() {
    let s = presets::find("strict").unwrap().policy;
    for w in [
        &["git", "push", "--force"][..],
        &["git", "push", "-f"],
        &["gh", "repo", "delete"],
        &["gh", "auth", "token"],
        &["vercel", "--prod"],
        &["netlify", "deploy", "--prod"],
        &["aws", "iam"],
        &["kubectl", "delete"],
        &["terraform", "destroy"],
    ] {
        assert_eq!(command_action(&s, w).as_deref(), Some("deny"), "{w:?}");
    }
    let r = presets::find("read-only").unwrap().policy;
    for t in ["write", "edit", "bash"] {
        assert_eq!(tool_action(&r, t).as_deref(), Some("ask"), "{t}");
    }
    for w in [&["git", "status"][..], &["gh", "pr", "view"]] {
        assert_eq!(command_action(&r, w).as_deref(), Some("allow"), "{w:?}");
    }
}

#[test]
fn policy_problem_refuses_each_bad_command_shape() {
    for bad in [
        json!({"version": 1, "rules": [{"tool": "read", "command": ["cat"], "action": "allow"}]}),
        json!({"version": 1, "rules": [{"tool": "bash", "command": ["Git"], "action": "ask"}]}),
        json!({"version": 1, "rules": [{"tool": "bash", "command": ["--force"], "action": "ask"}]}),
        json!({"version": 1, "rules": [{"tool": "bash", "command": [], "action": "ask"}]}),
        json!({"version": 1, "rules": [{"tool": "bash", "command": ["git", "$x"], "action": "ask"}]}),
        json!({"version": 1, "rules": [{"tool": "bash", "command": ["git"], "action": "allow", "descriptionSha256": "a"}]}),
        json!({"version": 1, "rules": [{"tool": "bash", "action": "maybe"}]}),
        json!({"version": 2, "rules": []}),
    ] {
        assert!(presets::policy_problem(&bad).is_err(), "{bad}");
    }
    assert!(presets::policy_problem(&json!({"version": 1, "rules": [{"tool": "bash", "command": ["git", "push", "--force"], "action": "deny"}]})).is_ok());
}

#[test]
fn pick_takes_a_word_or_a_unique_first_letter_and_else_the_default() {
    assert_eq!(pick("", &["no", "yes"]), "no");
    assert_eq!(pick("y", &["no", "yes"]), "yes");
    assert_eq!(pick("YES", &["no", "yes"]), "yes");
    assert_eq!(pick("maybe", &["no", "yes"]), "no");
    assert_eq!(pick("3", &["keep", "off", "1", "2", "3"]), "3");
    assert_eq!(pick("s", &["leave", "stop", "run-as-you"]), "stop");
}

#[test]
fn a_full_run_writes_the_policy_and_the_settings_private() {
    let home = scratch("full");
    let pkgs = scratch("pkgs");
    // policy: workspace-write; pre-answer: leave; tap: on; content: 3 days;
    // own server: no; computer use: off; check: on; Pi's gate: yes; shims: no.
    let (code, script, calls) = setup(
        &home,
        &["", "", "", "3", "", "", "on", "yes", ""],
        ok_matcher,
        Some(pkgs.clone()),
        false,
    );
    assert_eq!(code, 0, "{}", script.said);
    let policy = std::fs::read_to_string(home.join(".derm/policy.json")).unwrap();
    assert_eq!(
        policy,
        presets::policy_text(&presets::find("workspace-write").unwrap())
    );
    let settings_text = std::fs::read_to_string(home.join(".derm/settings.json")).unwrap();
    let parsed = derm_tap::settings::parse(&settings_text).expect("the tap's reader takes it");
    assert_eq!(parsed.content_days, Some(3));
    assert!(parsed.tap_on);
    let v: Value = serde_json::from_str(&settings_text).unwrap();
    assert_eq!(v["installs"]["check"], true);
    assert!(v.get("boundary").is_none(), "left alone: {v}");
    for f in ["policy.json", "settings.json"] {
        let m = std::fs::metadata(home.join(".derm").join(f)).unwrap();
        assert_eq!(m.mode() & 0o777, 0o600, "{f}");
    }
    assert_eq!(
        std::fs::metadata(home.join(".derm")).unwrap().mode() & 0o777,
        0o700
    );
    // Pi's gate went through derm connect, with the packages folder; Claude
    // Code's, already registered, was not asked about.
    assert_eq!(
        calls,
        vec![vec![
            "pi".to_string(),
            "--gate".into(),
            "--hook".into(),
            pkgs.join("packages/derm-pi").display().to_string(),
            "--write".into()
        ]]
    );
    assert!(
        !script.asked.iter().any(|q| q.contains("claude-code")),
        "{:?}",
        script.asked
    );
    assert!(script.said.contains("Written:"));
}

#[test]
fn a_second_run_keeps_the_policy_backs_up_what_it_replaces_and_writes_nothing_unasked() {
    let home = scratch("second");
    let (code, _, _) = setup(
        &home,
        &["", "", "", "", "", "", "", "", ""],
        ok_matcher,
        None,
        false,
    );
    assert_eq!(code, 0);
    let first = std::fs::read_to_string(home.join(".derm/policy.json")).unwrap();
    // Keep everything: nothing changes, nothing is backed up.
    let (code, script, _) = setup(
        &home,
        &["", "", "", "", "", "", "", "", ""],
        ok_matcher,
        None,
        false,
    );
    assert_eq!(code, 0);
    assert!(
        script.said.contains("Nothing was written."),
        "{}",
        script.said
    );
    assert!(!home.join(".derm/backups").exists());
    // Replace with strict: the old policy goes to backups first.
    let (code, script, _) = setup(
        &home,
        &["strict", "", "", "", "", "", "", "", ""],
        ok_matcher,
        None,
        false,
    );
    assert_eq!(code, 0, "{}", script.said);
    let kept: Vec<_> = std::fs::read_dir(home.join(".derm/backups"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(std::fs::read_to_string(kept[0].path()).unwrap(), first);
    assert_eq!(
        std::fs::metadata(kept[0].path()).unwrap().mode() & 0o777,
        0o600
    );
}

#[test]
fn a_policy_this_derms_matcher_refuses_is_never_written() {
    let home = scratch("refused");
    let (code, script, _) = setup(
        &home,
        &["", "", "", "", "", "", "", "", ""],
        refusing_matcher,
        None,
        false,
    );
    assert_eq!(code, 1);
    assert!(!home.join(".derm/policy.json").exists());
    assert!(
        script.said.contains("every call would ask"),
        "{}",
        script.said
    );
}

#[test]
fn the_pre_answer_an_upstream_and_computer_use_are_written_as_the_schema_says() {
    let home = scratch("settings");
    // policy none; pre-answer run-as-you; tap off; content off; own server yes
    // (box, http, local); computer use on; check off; Pi's gate no; shims no.
    let (code, script, _) = setup(
        &home,
        &[
            "none",
            "run-as-you",
            "off",
            "off",
            "yes",
            "box",
            "http://192.0.2.7:8080/v1",
            "yes",
            "on",
            "",
            "",
            "",
        ],
        ok_matcher,
        None,
        false,
    );
    assert_eq!(code, 0, "{}", script.said);
    assert!(!home.join(".derm/policy.json").exists());
    let text = std::fs::read_to_string(home.join(".derm/settings.json")).unwrap();
    settings::problem(&text).expect("the whole file follows the schema");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["boundary"]["preAnswer"], "run-as-you");
    assert_eq!(v["tap"]["on"], false);
    assert_eq!(
        v["tap"]["upstreams"]["box"],
        json!({"base": "http://192.0.2.7:8080/v1", "local": true})
    );
    assert_eq!(v["computerUse"]["on"], true);
    assert_eq!(v["content"], json!({"on": false}));
    let s = derm_tap::settings::parse(&text).unwrap();
    assert_eq!(s.upstreams.len(), 1);
    assert!(script.said.contains("daemon restarts"));
}

#[test]
fn an_upstream_the_schema_refuses_is_not_added() {
    assert!(settings::upstream_problem("anthropic", "https://x.example", false).is_some());
    assert!(
        settings::upstream_problem("box", "http://x.example", false).is_some(),
        "plain http not local"
    );
    assert!(settings::upstream_problem("Box", "https://x.example", false).is_some());
    assert!(settings::upstream_problem("box", "https://user@x.example", false).is_some());
    assert!(settings::upstream_problem("box", "https://x.example/v1?a=b", false).is_some());
    assert!(settings::upstream_problem("box", "ftp://x.example", true).is_some());
    assert!(settings::upstream_problem("box", "https://x.example/v1", false).is_none());
    let home = scratch("badup");
    let (code, script, _) = setup(
        &home,
        &[
            "none",
            "",
            "",
            "",
            "yes",
            "openai",
            "https://x.example",
            "no",
            "",
            "",
            "",
            "",
        ],
        ok_matcher,
        None,
        false,
    );
    assert_eq!(code, 0);
    assert!(
        script.said.contains("Not added: openai is a built-in"),
        "{}",
        script.said
    );
    let text = std::fs::read_to_string(home.join(".derm/settings.json")).unwrap_or_default();
    assert!(!text.contains("upstreams"), "{text}");
}

#[test]
fn a_dry_run_asks_nothing_and_writes_nothing() {
    let home = scratch("dry");
    let (code, script, calls) = setup(&home, &[], ok_matcher, None, true);
    assert_eq!(code, 0);
    assert!(script.asked.is_empty(), "{:?}", script.asked);
    assert!(calls.is_empty());
    assert!(!home.join(".derm").exists());
    assert!(script.said.contains("Would ask"));
    assert!(script.said.contains("pi"), "{}", script.said);
}

#[test]
fn a_gate_with_no_packages_folder_says_how_and_runs_nothing() {
    let home = scratch("nogate");
    let (_, script, calls) = setup(
        &home,
        &["none", "", "", "", "", "", "", "yes", ""],
        ok_matcher,
        None,
        false,
    );
    assert!(calls.is_empty());
    assert!(script.said.contains("--packages"), "{}", script.said);
}

#[test]
fn a_settings_file_that_is_not_yours_alone_is_not_read_and_is_kept_aside() {
    let home = scratch("loose");
    std::fs::create_dir_all(home.join(".derm")).unwrap();
    std::fs::set_permissions(home.join(".derm"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let f = home.join(".derm/settings.json");
    std::fs::write(&f, r#"{"version":1,"boundary":{"preAnswer":"run-as-you"}}"#).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(settings::read(&f).is_err());
    // derm setup starts from the defaults; a write replaces it only after
    // keeping a copy, and refuses the copy too while it is open to others.
    let (code, script, _) = setup(
        &home,
        &["none", "stop", "", "", "", "", "", "", ""],
        ok_matcher,
        None,
        false,
    );
    assert!(script.said.contains("ignore it now"), "{}", script.said);
    assert_eq!(
        code, 1,
        "the old file is refused, so nothing is written over it: {}",
        script.said
    );
    assert_eq!(
        std::fs::read_to_string(&f).unwrap(),
        r#"{"version":1,"boundary":{"preAnswer":"run-as-you"}}"#
    );
}

#[test]
fn an_existing_folder_others_can_read_is_made_private() {
    // Box test w5, BW5-2: `~/.derm` from an earlier wave stayed 0755 after
    // setup wrote its private files into it (B-W2 expects 0700).
    let d = scratch("files-0755");
    let dir = d.join(".derm");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    files::write_private(&dir.join("policy.json"), "{}", &dir.join("backups")).unwrap();
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "{mode:o}");
}

#[test]
fn files_refuse_a_link_another_users_folder_and_a_folder_open_to_others() {
    let d = scratch("files");
    let target = d.join("real.json");
    std::fs::write(&target, "{}").unwrap();
    std::os::unix::fs::symlink(&target, d.join("link.json")).unwrap();
    assert!(files::read_private(&d.join("link.json"), 1024).is_err());
    let open = d.join("open");
    std::fs::create_dir_all(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(files::write_private(&open.join("policy.json"), "{}", &d.join("b")).is_err());
    assert!(!open.join("policy.json").exists());
    std::os::unix::fs::symlink(&d, d.join("dirlink")).unwrap();
    assert!(files::own_folder(&d.join("dirlink")).is_err());
}

#[test]
fn a_shim_runs_derm_run_with_its_own_folder_off_path() {
    let home = scratch("shim");
    let dir = shims::folder(&home);
    // A fake derm that prints its argv and PATH.
    let fake = home.join("fake-derm");
    std::fs::write(
        &fake,
        "#!/bin/sh\nprintf '%s|' \"$@\"\nprintf 'PATH=%s\\n' \"$PATH\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
    let text = shims::text("claude", "claude-code", &fake, &dir).unwrap();
    assert!(files::write_shim(&dir.join("claude"), &text, shims::MARKER).unwrap());
    assert_eq!(
        std::fs::metadata(dir.join("claude")).unwrap().mode() & 0o777,
        0o700
    );
    let path = format!("{}:/usr/bin:{}/:/bin", dir.display(), dir.display());
    let out = std::process::Command::new(dir.join("claude"))
        .args(["-p", "hi there", "*"])
        .env("PATH", &path)
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.trim(),
        "run|claude-code|--|-p|hi there|*|PATH=/usr/bin:/bin",
        "{out}"
    );
    // A second write of the same text changes nothing; a file not derm's is left alone.
    assert!(!files::write_shim(&dir.join("claude"), &text, shims::MARKER).unwrap());
    std::fs::write(dir.join("pi"), "#!/bin/sh\necho mine\n").unwrap();
    std::fs::set_permissions(dir.join("pi"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let pi = shims::text("pi", "pi", &fake, &dir).unwrap();
    assert!(files::write_shim(&dir.join("pi"), &pi, shims::MARKER).is_err());
    assert_eq!(
        std::fs::read_to_string(dir.join("pi")).unwrap(),
        "#!/bin/sh\necho mine\n"
    );
}

#[test]
fn a_shim_refuses_a_path_it_cannot_quote_and_a_name_that_is_not_plain() {
    let dir = Path::new("/home/u/.derm/bin");
    assert!(shims::text("claude", "claude-code", Path::new("/opt/it's/derm"), dir).is_err());
    assert!(shims::text("claude", "claude-code", Path::new("derm"), dir).is_err());
    assert!(shims::text("../x", "pi", Path::new("/usr/bin/derm"), dir).is_err());
    assert!(shims::text("-x", "pi", Path::new("/usr/bin/derm"), dir).is_err());
}

#[test]
fn shims_are_planned_only_for_installed_agents_derm_run_knows() {
    let plan = shims::plan(&rows(), &["claude-code".into(), "zed".into()]);
    assert_eq!(
        plan,
        vec![("claude".to_string(), "claude-code".to_string())]
    );
}

#[test]
fn the_shims_question_writes_them_and_prints_the_path_line_and_orcas_override() {
    let home = scratch("shimq");
    let (code, script, _) = setup(
        &home,
        &["none", "", "", "", "", "", "", "", "yes"],
        ok_matcher,
        None,
        false,
    );
    assert_eq!(code, 0, "{}", script.said);
    assert!(home.join(".derm/bin/claude").exists());
    assert!(home.join(".derm/bin/pi").exists());
    assert!(script.said.contains("export PATH=\""), "{}", script.said);
    assert!(
        script.said.contains("claude-code: derm run claude-code --"),
        "{}",
        script.said
    );
}

#[test]
fn derm_setup_refuses_inside_a_chat() {
    let set = |k: &str| (k == "DERM_CHAT_TOKEN_FILE").then(|| std::ffi::OsString::from("/run/x"));
    assert!(super::inside_a_chat(&set)
        .unwrap()
        .contains("DERM_CHAT_TOKEN_FILE"));
    assert!(super::inside_a_chat(&|_| None).is_none());
}

#[test]
fn usage_errors_exit_2_and_a_test_build_never_asks() {
    assert_eq!(super::main(&["--bogus".to_string()]), 2);
    assert_eq!(
        super::main(&["--packages".to_string(), "relative".to_string()]),
        2
    );
    assert_eq!(super::main(&[]), 2, "no terminal in a test build");
    assert_eq!(super::main(&["preset".to_string(), "nope".to_string()]), 2);
    assert_eq!(super::main(&["presets".to_string()]), 0);
}

/// Box test w5, BW5-3; Mac test w5, MW5-9: Claude Code's, Pi's and Codex's
/// gates install through their own commands, which derm connect prints;
/// derm setup says so instead of reporting an exit code.
#[test]
fn print_only_gates_are_named_from_connects_table() {
    for id in ["claude-code", "pi", "codex"] {
        assert!(super::gate_is_print_only(id), "{id}");
    }
    assert!(!super::gate_is_print_only("zed"));
}

/// Lane 5bF's request 3: a command-hook agent's gate is `derm hook`, so
/// derm setup registers it with no package folder.
#[test]
fn a_derm_hook_gate_needs_no_package_folder() {
    for id in ["cursor", "crush", "qwen-code", "grok"] {
        assert!(super::gate_is_derm_hook(id), "{id}");
    }
    for id in ["claude-code", "pi", "opencode", "zed"] {
        assert!(!super::gate_is_derm_hook(id), "{id}");
    }
}

#[test]
fn the_gate_package_comes_from_connects_table() {
    assert_eq!(super::gate_package("pi").as_deref(), Some("derm-pi"));
    assert_eq!(
        super::gate_package("cursor").as_deref(),
        Some("derm-hooks-native")
    );
    assert_eq!(super::gate_package("zed"), None);
}

#[test]
fn every_executable_row_names_an_agent_and_a_plain_program() {
    let t: Value =
        serde_json::from_str(include_str!("../connect/presets/wave5/executables.json")).unwrap();
    let rows = t["rows"].as_object().unwrap();
    assert!(rows.len() >= 20);
    for (id, v) in rows {
        assert!(
            t["sources"][id].as_str().is_some_and(|s| !s.is_empty()),
            "{id} has no source"
        );
        for e in v.as_array().unwrap() {
            let e = e.as_str().unwrap();
            assert!(
                shims::text(e, id, Path::new("/usr/bin/derm"), Path::new("/h/.derm/bin")).is_ok(),
                "{id}: {e}"
            );
        }
    }
    for id in ["command-code", "zed"] {
        assert!(rows.get(id).is_none(), "{id} is left out on purpose");
        assert!(t["leftOut"][id].is_string());
    }
}

/// Box test w5 retest, BW5R-8: a setup run that writes only shims (the
/// policy kept, the settings unchanged) left `~/.derm` at 0755, while one
/// that writes the policy or the settings made it 0700.
#[test]
fn bw5r_8_a_shim_only_setup_keeps_the_derm_folder_private() {
    let home = scratch("shimonly");
    let (code, script, _) = setup(
        &home,
        &["workspace-write", "", "", "", "", "", "", "", "no"],
        ok_matcher,
        None,
        false,
    );
    assert_eq!(code, 0, "{}", script.said);
    assert!(home.join(".derm/settings.json").exists());
    std::fs::set_permissions(home.join(".derm"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let (code, script, _) = setup(
        &home,
        &["keep", "", "", "", "", "", "", "", "yes"],
        ok_matcher,
        None,
        false,
    );
    assert_eq!(code, 0, "{}", script.said);
    assert!(home.join(".derm/bin/claude").exists(), "{}", script.said);
    for d in [".derm", ".derm/bin"] {
        let mode = std::fs::metadata(home.join(d))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "{d} {mode:o}: {}", script.said);
    }
}

/// Review FP9-S7: with `~/.derm` refused (here a link to another folder),
/// setup said "Shims not written" and wrote them anyway, through the link.
#[test]
fn fp9_s7_a_refused_derm_folder_gets_no_shims() {
    let home = scratch("shimlink");
    let elsewhere = home.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, home.join(".derm")).unwrap();
    let (_code, script, _) = setup(
        &home,
        &["workspace-write", "", "", "", "", "", "", "", "yes"],
        ok_matcher,
        None,
        false,
    );
    assert!(script.said.contains("Shims not written"), "{}", script.said);
    assert!(
        !elsewhere.join("bin/claude").exists(),
        "a shim went through the refused link: {}",
        script.said
    );
}
