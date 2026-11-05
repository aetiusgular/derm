use super::*;
use std::os::unix::fs::PermissionsExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn plan(program: &str, args: &[&str], token: bool) -> Plan {
    Plan {
        program: program.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        env_set: if token {
            vec![("DERM_CHAT_TOKEN".into(), TOKEN.into())]
        } else {
            Vec::new()
        },
        env_remove: Vec::new(),
        kit: None,
        sandbox_name: None,
        srt_settings: None,
        folders: Vec::new(),
        state_dirs: Vec::new(),
        notes: Vec::new(),
        full_access: Vec::new(),
        companion: None,
        scratch_dir: None,
    }
}

struct Dirs {
    root: PathBuf,
    daemon: PathBuf,
    home: PathBuf,
    work: PathBuf,
}

fn dirs(name: &str, endpoint: Option<&str>) -> Dirs {
    let root = std::env::temp_dir().join(format!("derm-run-tap-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (daemon, home, work) = (root.join("run"), root.join("home"), root.join("work"));
    for d in [&daemon, &home, &work] {
        std::fs::create_dir_all(d).unwrap();
    }
    if let Some(e) = endpoint {
        std::fs::write(daemon.join("tap.endpoint"), format!("{e}\n")).unwrap();
    }
    Dirs {
        root,
        daemon,
        home,
        work,
    }
}

fn inputs(d: &Dirs) -> Inputs {
    Inputs {
        daemon_dir: Some(d.daemon.clone()),
        home: Some(d.home.to_string_lossy().into_owned()),
        cwd: Some(d.work.to_string_lossy().into_owned()),
        inherited: Vec::new(),
        claude_managed: d.root.join("managed/managed-settings.json"),
    }
}

fn env<'a>(p: &'a Plan, k: &str) -> Option<&'a str> {
    p.env_set
        .iter()
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.as_str())
}

#[test]
fn claude_code_gets_its_base_url_with_the_route_and_a_tapped_record() {
    let d = dirs("claude", Some("http://127.0.0.1:45001"));
    let mut p = plan("claude", &["-p", "hi"], true);
    let rec = environment_with("claude-code", &mut p, &inputs(&d))
        .unwrap()
        .unwrap();
    let route = route::of_token(TOKEN);
    assert_eq!(
        env(&p, "ANTHROPIC_BASE_URL"),
        Some(format!("http://127.0.0.1:45001/r/{route}/anthropic").as_str())
    );
    assert_eq!(
        rec,
        json!({"on": true, "via": "env", "api": "anthropic-messages", "upstream": "api.anthropic.com"})
    );
    assert!(
        !rec.to_string().contains(&route),
        "the record never holds the route"
    );
    assert_eq!(p.args, vec!["-p", "hi"]);
    let _ = std::fs::remove_dir_all(d.root);
}

#[test]
fn codex_gets_its_provider_flags_before_its_own_and_the_route_only_in_its_environment() {
    let d = dirs("codex", Some("http://127.0.0.1:45002"));
    let mut p = plan("codex", &["exec", "do it"], true);
    let rec = environment_with("codex", &mut p, &inputs(&d))
        .unwrap()
        .unwrap();
    assert_eq!(rec["via"], "codex-provider");
    // Codex 0.163.0 ignores a provider set with `-c` before `exec` and
    // honours it after (run 4 Nov 2026, lane S Research), so the flags go
    // right after a session subcommand.
    assert_eq!(
        &p.args[..3],
        &[
            "exec".to_string(),
            "-c".to_string(),
            "model_provider=\"derm-tap\"".to_string()
        ]
    );
    assert_eq!(p.args.last().map(String::as_str), Some("do it"));
    // With no subcommand (the TUI) they go first.
    let mut tui = plan("codex", &["fix the tests"], true);
    environment_with("codex", &mut tui, &inputs(&d)).unwrap();
    assert_eq!(tui.args[0], "-c");
    assert_eq!(tui.args.last().map(String::as_str), Some("fix the tests"));
    for sub in ["e", "review", "resume", "fork", "app-server"] {
        let mut s = plan("codex", &[sub, "--x"], true);
        environment_with("codex", &mut s, &inputs(&d)).unwrap();
        assert_eq!(&s.args[..2], &[sub.to_string(), "-c".to_string()], "{sub}");
    }
    let route = route::of_token(TOKEN);
    assert!(!p.args.iter().any(|a| a.contains(&route)));
    assert_eq!(env(&p, "DERM_TAP_ROUTE"), Some(route.as_str()));

    // Under srt the flags go after `-- <command>`, and srt lets the harness
    // reach the tap's port.
    let srt =
        json!({"network": {"allowedDomains": ["127.0.0.1:4318"], "deniedDomains": []}}).to_string();
    let mut p = plan(
        "srt",
        &["--settings", "/s.json", "--", "/bin/codex", "exec", "x"],
        true,
    );
    p.srt_settings = Some(srt);
    environment_with("codex", &mut p, &inputs(&d)).unwrap();
    assert_eq!(
        &p.args[..6],
        &["--settings", "/s.json", "--", "/bin/codex", "exec", "-c"]
    );
    let s: Value = serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
    assert_eq!(
        s["network"]["allowedDomains"],
        json!(["127.0.0.1:4318", "127.0.0.1:45002"])
    );
    let _ = std::fs::remove_dir_all(d.root);
}

#[test]
fn a_chat_runs_untapped_and_says_why_when_it_cannot_be_tapped() {
    // No endpoint published by the daemon.
    let d = dirs("noendpoint", None);
    let mut p = plan("claude", &[], true);
    assert_eq!(
        environment_with("claude-code", &mut p, &inputs(&d)).unwrap(),
        Some(json!({"on": false, "via": "none", "reason": "no-endpoint"}))
    );
    assert_eq!(env(&p, "ANTHROPIC_BASE_URL"), None);
    // An endpoint that is not loopback http is not used.
    std::fs::write(d.daemon.join("tap.endpoint"), "http://10.0.0.5:4000\n").unwrap();
    assert_eq!(
        environment_with("claude-code", &mut p, &inputs(&d)).unwrap(),
        Some(json!({"on": false, "via": "none", "reason": "no-endpoint"}))
    );
    // An agent with no base URL.
    std::fs::write(d.daemon.join("tap.endpoint"), "http://127.0.0.1:4000\n").unwrap();
    assert_eq!(
        environment_with("cursor", &mut p, &inputs(&d)).unwrap(),
        Some(json!({"on": false, "via": "none", "reason": "no-base-url"}))
    );
    assert_eq!(
        environment_with("pi", &mut p, &inputs(&d))
            .unwrap()
            .unwrap()["reason"],
        "no-base-url"
    );
    // The user's setting.
    let f = d.home.join(".derm/settings.json");
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(&f, r#"{"version":1,"tap":{"on":false}}"#).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        environment_with("claude-code", &mut p, &inputs(&d))
            .unwrap()
            .unwrap()["reason"],
        "setting"
    );
    assert!(p.env_set.iter().all(|(k, _)| k != "ANTHROPIC_BASE_URL"));
    // No token: --no-daemon or a dry run; nothing to record.
    let mut p = plan("claude", &[], false);
    std::fs::remove_file(&f).unwrap();
    assert_eq!(
        environment_with("claude-code", &mut p, &inputs(&d)).unwrap(),
        None
    );
    let _ = std::fs::remove_dir_all(d.root);
}

#[test]
fn case_113_a_base_url_set_elsewhere_refuses_the_start_and_names_where() {
    let d = dirs("c113", Some("http://127.0.0.1:4000"));
    let refuse =
        |harness: &str, p: &mut Plan, i: &Inputs| environment_with(harness, p, i).unwrap_err().1;

    let mut i = inputs(&d);
    i.inherited = vec![("ANTHROPIC_BASE_URL".into(), "http://my-gateway:8080".into())];
    assert!(refuse("claude-code", &mut plan("claude", &[], true), &i)
        .contains("ANTHROPIC_BASE_URL is set in derm run's environment"));

    let i = inputs(&d);
    let user = d.home.join(".claude/settings.json");
    std::fs::create_dir_all(user.parent().unwrap()).unwrap();
    std::fs::write(
        &user,
        r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:9"}}"#,
    )
    .unwrap();
    let why = refuse("claude-code", &mut plan("claude", &[], true), &i);
    assert!(
        why.contains(&user.display().to_string()) && why.contains("tap\": {\"on\": false}"),
        "{why}"
    );
    std::fs::remove_file(&user).unwrap();

    let local = d.work.join(".claude/settings.local.json");
    std::fs::create_dir_all(local.parent().unwrap()).unwrap();
    std::fs::write(&local, r#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"1"}}"#).unwrap();
    assert!(refuse("claude-code", &mut plan("claude", &[], true), &i)
        .contains("settings.local.json sets CLAUDE_CODE_USE_BEDROCK"));
    std::fs::remove_file(&local).unwrap();

    let managed_d = d.root.join("managed/managed-settings.d");
    std::fs::create_dir_all(&managed_d).unwrap();
    std::fs::write(
        managed_d.join("10-gw.json"),
        r#"{"env":{"ANTHROPIC_BASE_URL":"https://gw.corp"}}"#,
    )
    .unwrap();
    assert!(refuse("claude-code", &mut plan("claude", &[], true), &i).contains("10-gw.json"));
    std::fs::remove_dir_all(&managed_d).unwrap();

    let inline = r#"{"env":{"ANTHROPIC_BASE_URL":"http://x"}}"#;
    assert!(refuse(
        "claude-code",
        &mut plan("claude", &["--settings", inline], true),
        &i
    )
    .contains("--settings"));

    for args in [
        &["--oss"][..],
        &["-p", "work"],
        &["-c", "model_provider=\"ollama\""],
        &["--config=openai_base_url=\"http://x\""],
    ] {
        assert!(
            !refuse("codex", &mut plan("codex", args, true), &i).is_empty(),
            "{args:?}"
        );
    }
    let cfg = d.home.join(".codex/config.toml");
    std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    for (text, want) in [
        (
            "model_provider = \"ollama\"\n",
            "model_provider = \"ollama\"",
        ),
        ("openai_base_url = \"http://x\"\n", "openai_base_url"),
        (
            "profile = \"w\"\n[profiles.w]\nmodel_provider = \"lms\"\n",
            "profile \"w\"",
        ),
    ] {
        std::fs::write(&cfg, text).unwrap();
        let why = refuse("codex", &mut plan("codex", &[], true), &i);
        assert!(why.contains(want), "{why}");
    }
    // Codex's own provider named outright is not a different route.
    std::fs::write(&cfg, "model_provider = \"openai\"\nmodel = \"gpt-x\"\n").unwrap();
    assert!(
        environment_with("codex", &mut plan("codex", &[], true), &i)
            .unwrap()
            .unwrap()["on"]
            == true
    );
    let _ = std::fs::remove_dir_all(d.root);
}

#[test]
fn under_sbx_the_tap_is_the_hosts_and_each_variable_is_named_to_sbx() {
    let d = dirs("sbx", Some("http://127.0.0.1:45003"));
    let mut p = plan(
        "sbx",
        &["run", "--name", "derm-c", "-e", "DERM_CHAT_ID", "claude"],
        true,
    );
    p.sandbox_name = Some("derm-c".into());
    let rec = environment_with("claude-code", &mut p, &inputs(&d))
        .unwrap()
        .unwrap();
    assert_eq!(rec["on"], true);
    assert!(env(&p, "ANTHROPIC_BASE_URL")
        .unwrap()
        .starts_with("http://host.docker.internal:45003/r/"));
    assert_eq!(
        &p.args[..5],
        &["run", "--name", "derm-c", "-e", "ANTHROPIC_BASE_URL"]
    );
    assert!(p
        .notes
        .iter()
        .any(|n| n.contains("sbx policy allow network localhost:45003")));
    // Codex's flags under sbx wait for lane T: untapped, said.
    let mut p = plan("sbx", &["run", "--name", "derm-c", "codex"], true);
    p.sandbox_name = Some("derm-c".into());
    assert_eq!(
        environment_with("codex", &mut p, &inputs(&d)).unwrap(),
        Some(json!({"on": false, "via": "none"}))
    );
    assert_eq!(p.args, vec!["run", "--name", "derm-c", "codex"]);
    let _ = std::fs::remove_dir_all(d.root);
}

#[test]
fn the_tap_table_merges_into_the_presets_and_every_row_follows_the_schema() {
    let table: Value = serde_json::from_str(crate::connect::presets::table_json()).unwrap();
    let rows: Vec<&Value> = ["harnesses", "planned"]
        .iter()
        .flat_map(|l| table[*l].as_array().unwrap())
        .filter(|r| !r["tap"].is_null())
        .collect();
    assert_eq!(rows.len(), 11);
    for r in rows {
        let t = &r["tap"];
        let via = t["via"].as_str().unwrap();
        assert!(["env", "codex-provider", "none"].contains(&via));
        assert!(t["verifiedAt"].is_string());
        if via == "env" {
            assert!(t["name"]
                .as_str()
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_'));
        }
    }
}

#[test]
fn the_content_record_follows_the_settings_and_defaults_off() {
    let d = dirs("content", None);
    let home = d.home.to_string_lossy().into_owned();
    assert_eq!(
        content_record(Some(&home)),
        json!({"on": false, "retentionDays": null})
    );
    let f = d.home.join(".derm/settings.json");
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(
        &f,
        r#"{"version":1,"content":{"on":true,"retentionDays":4}}"#,
    )
    .unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        content_record(Some(&home)),
        json!({"on": true, "retentionDays": 4})
    );
    assert_eq!(
        content_record(None),
        json!({"on": false, "retentionDays": null})
    );
    let _ = std::fs::remove_dir_all(d.root);
}
