//! Tests for `derm connect <agent> --rules` (`rules.rs`): the translation of
//! deny rules, the user's own entries kept, derm's record, and the agents
//! with no second layer (case 70).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::json::{self, Value};
use super::presets::Env;
use super::rules::translate;
use super::write::tests::{scratch, Answer};
use super::{run, Ctx};

struct MapEnv(HashMap<String, String>);
impl Env for MapEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

fn go(home: &Path, env: &[(&str, &str)], args: &[&str]) -> (u8, String, String) {
    let env = MapEnv(
        env.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    let mut a = Answer(true, None);
    let mut ctx = Ctx {
        home: home.to_path_buf(),
        cwd: home.join("proj"),
        macos: false,
        env: &env,
        run_user: home.join("no-run-user"),
        confirm: &mut a,
        out: String::new(),
        err: String::new(),
        live: false,
    };
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let code = run(&args, &mut ctx);
    (code, ctx.out, ctx.err)
}

const POLICY: &str = r#"{"version": 1, "servers": ["GitHub.Tools"], "rules": [
  {"tool": "exa/*", "action": "allow"},
  {"tool": "github_tools/delete_repo", "action": "deny"},
  {"tool": "evil/*", "action": "deny"},
  {"tool": "bash", "action": "deny", "harness": "qwen-code"},
  {"tool": "bash", "action": "deny", "harness": "codex"},
  {"tool": "write", "action": "deny"},
  {"tool": "fs/read", "action": "deny", "chat": "c1"},
  {"tool": "fs/*", "action": "ask"}
]}"#;

fn deny(home: &Path, file: &str) -> Vec<String> {
    let v = json::parse(&fs::read_to_string(home.join(file)).unwrap(), false)
        .unwrap()
        .root
        .unwrap()
        .to_value();
    match v.get_path(&["permissions", "deny"]) {
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| match x {
                Value::Str(s) => s.clone(),
                _ => panic!(),
            })
            .collect(),
        _ => panic!("no permissions.deny"),
    }
}

#[test]
fn deny_rules_only_in_the_agents_own_spelling() {
    let p = derm_core::policy::parse(POLICY).unwrap();
    let (q, skipped) = translate(&p, "qwen-code");
    assert_eq!(
        q,
        ["mcp__GitHub_Tools__delete_repo", "mcp__evil__*", "Bash"]
    );
    assert!(
        skipped.iter().any(|s| s.starts_with("write ")),
        "{skipped:?}"
    );
    assert!(
        skipped.iter().any(|s| s.contains("one chat")),
        "{skipped:?}"
    );
    // The shell rule was for Qwen; OpenClaude does not get it.
    let (o, _) = translate(&p, "openclaude");
    assert_eq!(o, ["mcp__GitHub_Tools__delete_repo", "mcp__evil__*"]);
}

#[test]
fn rules_are_written_beside_yours_and_taken_out_again() {
    let home = scratch("rules-qwen");
    fs::create_dir_all(home.join(".derm")).unwrap();
    fs::write(home.join(".derm/policy.json"), POLICY).unwrap();
    fs::create_dir_all(home.join(".qwen")).unwrap();
    fs::write(
        home.join(".qwen/settings.json"),
        "{\n  \"model\": \"q\",\n  \"permissions\": {\n    \"deny\": [\"Bash\", \"Read(./secrets/**)\"]\n  }\n}\n",
    )
    .unwrap();
    let (code, out, err) = go(&home, &[], &["qwen-code", "--rules"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("dry run"), "{out}");
    let (code, out, err) = go(&home, &[], &["qwen-code", "--rules", "--write"]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(
        deny(&home, ".qwen/settings.json"),
        [
            "Bash",
            "Read(./secrets/**)",
            "mcp__GitHub_Tools__delete_repo",
            "mcp__evil__*"
        ]
    );
    // `Bash` was yours before derm: it is not in derm's record.
    let rec = fs::read_to_string(home.join(".derm/rules/qwen-code.json")).unwrap();
    assert!(!rec.contains("\"Bash\""), "{rec}");
    // A second run changes nothing; a narrower policy takes derm's out.
    let (_, out, _) = go(&home, &[], &["qwen-code", "--rules", "--write"]);
    assert!(out.contains("already matches"), "{out}");
    fs::write(
        home.join(".derm/policy.json"),
        r#"{"version": 1, "rules": [{"tool": "evil/*", "action": "deny"}]}"#,
    )
    .unwrap();
    go(&home, &[], &["qwen-code", "--rules", "--write"]);
    assert_eq!(
        deny(&home, ".qwen/settings.json"),
        ["Bash", "Read(./secrets/**)", "mcp__evil__*"]
    );
    let (code, _, _) = go(&home, &[], &["qwen-code", "--rules", "--clear", "--write"]);
    assert_eq!(code, 0);
    assert_eq!(
        deny(&home, ".qwen/settings.json"),
        ["Bash", "Read(./secrets/**)"]
    );
}

#[test]
fn qwen_home_moves_the_file_and_a_bad_policy_writes_nothing() {
    let home = scratch("rules-qhome");
    let q = home.join("q");
    fs::create_dir_all(&q).unwrap();
    fs::create_dir_all(home.join(".qwen")).unwrap();
    fs::write(
        home.join("p.json"),
        r#"{"version": 1, "rules": [{"tool": "x/y", "action": "deny"}]}"#,
    )
    .unwrap();
    let qs = q.display().to_string();
    let ps = home.join("p.json").display().to_string();
    let env = [("QWEN_HOME", qs.as_str()), ("DERM_POLICY", ps.as_str())];
    let (code, out, err) = go(&home, &env, &["qwen-code", "--rules", "--write"]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(deny(&home, "q/settings.json"), ["mcp__x__y"]);
    assert!(!home.join(".qwen/settings.json").exists());
    fs::write(home.join("p.json"), "{not json").unwrap();
    let (code, _, err) = go(&home, &env, &["qwen-code", "--rules", "--write"]);
    assert_eq!(code, 1);
    assert!(err.contains("cannot read"), "{err}");
}

#[test]
fn agents_with_no_second_layer_say_so_and_write_nothing() {
    let home = scratch("rules-none");
    for a in ["crush", "kimi", "continue", "rovo-dev", "droid", "auggie"] {
        let (code, out, _) = go(&home, &[], &[a, "--rules", "--write"]);
        assert_eq!(code, 1, "{a}");
        assert!(out.contains("derm connect --rules:"), "{a}: {out}");
    }
    let (code, _, err) = go(&home, &[], &["openclaude", "--rules", "--gate"]);
    assert_eq!(code, 2, "{err}");
    let (code, _, _) = go(&home, &[], &["openclaude", "--clear"]);
    assert_eq!(code, 2);
    // Not installed: nothing written.
    fs::create_dir_all(home.join(".derm")).unwrap();
    fs::write(home.join(".derm/policy.json"), POLICY).unwrap();
    let (code, out, _) = go(&home, &[], &["openclaude", "--rules", "--write"]);
    assert_eq!(code, 1, "{out}");
    assert!(!home.join(".openclaude").exists());
}

const GEMINI_POLICY: &str = r#"{"version": 1, "servers": ["GitHub.Tools"], "rules": [
  {"tool": "exa/*", "action": "allow"},
  {"tool": "github_tools/delete_repo", "action": "deny"},
  {"tool": "evil/*", "action": "deny"},
  {"tool": "bash", "action": "deny", "harness": "gemini"},
  {"tool": "bash", "action": "deny", "harness": "codex"},
  {"tool": "write", "action": "deny"},
  {"tool": "*", "action": "deny", "chat": "c1"},
  {"tool": "fs/*", "action": "ask"}
]}"#;

/// Gemini CLI 0.66.0: an owned `~/.gemini/policies/derm.toml` of deny rules
/// with lane I's priorities; a stranger's file of that name is refused;
/// `--clear` leaves the header; GEMINI_CLI_HOME moves the folder.
#[test]
fn gemini_gets_its_deny_rules_in_a_file_of_its_own() {
    let home = scratch("rules-gemini");
    fs::create_dir_all(home.join(".gemini")).unwrap();
    fs::create_dir_all(home.join(".derm")).unwrap();
    fs::write(home.join(".derm/policy.json"), GEMINI_POLICY).unwrap();
    let (code, out, err) = go(&home, &[], &["gemini", "--rules", "--write"]);
    assert_eq!(code, 0, "{out}{err}");
    let t = fs::read_to_string(home.join(".gemini/policies/derm.toml")).unwrap();
    assert!(t.starts_with(super::rules::GEMINI_MARKER), "{t}");
    let blocks: Vec<&str> = t.split("[[rule]]\n").skip(1).map(str::trim).collect();
    assert_eq!(
        blocks,
        [
            "mcpName = \"GitHub.Tools\"\ntoolName = \"delete_repo\"\ndecision = \"deny\"\npriority = 221\ndenyMessage = \"derm: rule github_tools/delete_repo\"",
            "mcpName = \"evil\"\ntoolName = \"*\"\ndecision = \"deny\"\npriority = 121\ndenyMessage = \"derm: rule evil/*\"",
            // A bash deny outranks every allow, as in the hook (review W4-S6; 521 before).
            "toolName = \"run_shell_command\"\ndecision = \"deny\"\npriority = 950\ndenyMessage = \"derm: rule bash harness=gemini\"",
        ],
        "{t}"
    );
    assert!(!t.contains("allow") && !t.contains("ask"), "{t}");
    assert!(
        out.contains("skipped: write") && out.contains("skipped: * (for one chat)"),
        "{out}"
    );
    assert!(out.contains("--policy"), "{out}");
    let (code, out, _) = go(&home, &[], &["gemini", "--rules", "--write"]);
    assert_eq!(code, 0);
    assert!(out.contains("already matches"), "{out}");
    let (code, out, err) = go(&home, &[], &["gemini", "--rules", "--clear", "--write"]);
    assert_eq!(code, 0, "{out}{err}");
    let t = fs::read_to_string(home.join(".gemini/policies/derm.toml")).unwrap();
    assert!(
        t.starts_with(super::rules::GEMINI_MARKER) && !t.contains("[[rule]]"),
        "{t}"
    );

    // A stranger's file under derm's name is refused.
    fs::write(
        home.join(".gemini/policies/derm.toml"),
        "[[rule]]\ntoolName = \"*\"\n",
    )
    .unwrap();
    let (code, _, err) = go(&home, &[], &["gemini", "--rules", "--write"]);
    assert_eq!(code, 1);
    assert!(err.contains("not derm's"), "{err}");

    // GEMINI_CLI_HOME replaces the home folder, not `.gemini`.
    let g = home.join("g");
    fs::create_dir_all(g.join(".gemini")).unwrap();
    let gh = g.display().to_string();
    let (code, out, err) = go(
        &home,
        &[("GEMINI_CLI_HOME", &gh)],
        &["gemini", "--rules", "--write"],
    );
    assert_eq!(code, 0, "{out}{err}");
    assert!(g.join(".gemini/policies/derm.toml").exists());
}

const CODEX_TOML: &str = "model = \"o4\"\n\n[mcp_servers.GitHub-Tools]\ncommand = \"gh-mcp\"\ndisabled_tools = [\"mine\"]\n\n# my search server\n[mcp_servers.evil]\nurl = \"https://e.example/mcp\"\n\n[mcp_servers.quiet]\ncommand = \"q\"\nenabled = false\n";

const CODEX_POLICY: &str = r#"{"version": 1, "servers": [], "rules": [
  {"tool": "github_tools/delete_repo", "action": "deny"},
  {"tool": "github_tools/mine", "action": "deny"},
  {"tool": "evil/*", "action": "deny"},
  {"tool": "quiet/*", "action": "deny"},
  {"tool": "absent/x", "action": "deny"},
  {"tool": "bash", "action": "deny"},
  {"tool": "exa/*", "action": "allow"},
  {"tool": "evil/y", "action": "deny", "harness": "gemini"}
]}"#;

/// Codex rust-v0.166.0: `disabled_tools` and `enabled = false` for servers
/// already in config.toml, the user's own entries and comments kept, derm's
/// changes recorded and undone by `--clear`, the shell and absent servers
/// named.
#[test]
fn codex_disables_tools_and_servers_it_finds_and_undoes_its_own() {
    let p = derm_core::policy::parse(CODEX_POLICY).unwrap();
    let (t, rec, notes) =
        super::rules::codex_plan(CODEX_TOML, &p, &super::rules::CodexRecord::default()).unwrap();
    assert!(
        t.contains("disabled_tools = [\"mine\", \"delete_repo\"]"),
        "{t}"
    );
    assert!(t.contains("# my search server\n[mcp_servers.evil]\nurl = \"https://e.example/mcp\"\nenabled = false\n"), "{t}");
    assert!(
        t.contains("[mcp_servers.quiet]\ncommand = \"q\"\nenabled = false\n"),
        "{t}"
    );
    assert!(t.starts_with("model = \"o4\"\n"), "{t}");
    assert_eq!(
        rec,
        super::rules::CodexRecord {
            tools: vec![("GitHub-Tools".into(), vec!["delete_repo".into()], false)],
            servers: vec![("evil".into(), "absent".into())],
        }
    );
    let all = notes.join("\n");
    assert!(all.contains("skipped: absent/x (no server"), "{all}");
    assert!(all.contains("skipped: bash"), "{all}");
    assert!(all.contains("exactly `delete_repo`"), "{all}");
    assert!(!all.contains("evil/y"), "{all}");
    // Undone with an empty policy, back to the user's own text.
    let (back, rec2, _) =
        super::rules::codex_plan(&t, &derm_core::policy::PolicyFile::default(), &rec).unwrap();
    assert_eq!(back, CODEX_TOML);
    assert_eq!(rec2, super::rules::CodexRecord::default());
    // A tools list derm created is removed again.
    let p2 = derm_core::policy::parse(
        r#"{"version": 1, "servers": [], "rules": [{"tool": "evil/z", "action": "deny"}]}"#,
    )
    .unwrap();
    let (t3, rec3, _) =
        super::rules::codex_plan(CODEX_TOML, &p2, &super::rules::CodexRecord::default()).unwrap();
    assert!(
        t3.contains(
            "[mcp_servers.evil]\nurl = \"https://e.example/mcp\"\ndisabled_tools = [\"z\"]\n"
        ),
        "{t3}"
    );
    let (back3, _, _) =
        super::rules::codex_plan(&t3, &derm_core::policy::PolicyFile::default(), &rec3).unwrap();
    assert_eq!(back3, CODEX_TOML);
}

#[test]
fn codex_rules_end_to_end_with_codex_home() {
    let home = scratch("rules-codex");
    let ch = home.join("ch");
    fs::create_dir_all(&ch).unwrap();
    fs::write(ch.join("config.toml"), CODEX_TOML).unwrap();
    fs::create_dir_all(home.join(".derm")).unwrap();
    fs::write(home.join(".derm/policy.json"), CODEX_POLICY).unwrap();
    let chs = ch.display().to_string();
    let (code, out, err) = go(
        &home,
        &[("CODEX_HOME", &chs)],
        &["codex", "--rules", "--write"],
    );
    assert_eq!(code, 0, "{out}{err}");
    let t = fs::read_to_string(ch.join("config.toml")).unwrap();
    assert!(t.contains("\"delete_repo\""), "{t}");
    assert!(home.join(".derm/rules/codex.json").exists());
    let (code, out, _) = go(
        &home,
        &[("CODEX_HOME", &chs)],
        &["codex", "--rules", "--write"],
    );
    assert_eq!(code, 0);
    assert!(out.contains("already matches"), "{out}");
    let (code, out, err) = go(
        &home,
        &[("CODEX_HOME", &chs)],
        &["codex", "--rules", "--clear", "--write"],
    );
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(
        fs::read_to_string(ch.join("config.toml")).unwrap(),
        CODEX_TOML
    );
}

/// Wave 5 lane W (policy.md section 7): a command deny denies one command.
/// Written as an agent's own deny it would take the whole shell away, so
/// every writer leaves it to the gate and says so.
#[test]
fn a_command_rule_never_becomes_a_whole_shell_deny() {
    let p = derm_core::policy::parse(
        r#"{"version": 1, "rules": [
            {"tool": "bash", "action": "allow"},
            {"tool": "bash", "command": ["gh", "repo", "delete"], "action": "deny"}
        ]}"#,
    )
    .unwrap();
    let (q, skipped) = translate(&p, "qwen-code");
    assert!(q.is_empty(), "{q:?}");
    assert!(
        skipped
            .iter()
            .any(|s| s == "bash gh repo delete (a command rule stays with the gate)"),
        "{skipped:?}"
    );
    let (toml, skipped) = super::rules::gemini_toml(&p);
    assert!(!toml.contains("run_shell_command"), "{toml}");
    assert!(
        skipped.iter().any(|s| s.starts_with("bash gh repo delete")),
        "{skipped:?}"
    );
}
