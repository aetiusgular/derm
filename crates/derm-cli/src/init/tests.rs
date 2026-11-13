use std::path::PathBuf;

use serde_json::{json, Value};

use super::*;

struct Script {
    answers: Vec<bool>,
    said: String,
    asked: Vec<String>,
}

impl Io for Script {
    fn say(&mut self, text: &str) {
        self.said.push_str(text);
        self.said.push('\n');
    }
    fn yes(&mut self, q: &str) -> bool {
        self.asked.push(q.to_string());
        if self.answers.is_empty() {
            false
        } else {
            self.answers.remove(0)
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "derm-6b-init-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn agent(id: &str, gate: &str, registered: &str, ask: &str) -> Value {
    json!({
        "id": id, "name": id, "gate": {"status": gate}, "registered": registered,
        "onPath": format!("/usr/bin/{id}"), "ask": ask, "failMode": "closed",
    })
}

struct Run {
    code: u8,
    said: String,
    asked: Vec<String>,
    connected: Vec<Vec<String>>,
}

fn run_with(
    home: &std::path::Path,
    agents: Vec<Value>,
    rows: Vec<Value>,
    answers: &[bool],
    dry: bool,
    packages: Option<PathBuf>,
    stale: &dyn Fn(&str) -> Vec<String>,
) -> Run {
    let mut io = Script {
        answers: answers.to_vec(),
        said: String::new(),
        asked: Vec::new(),
    };
    let mut connected = Vec::new();
    let mut connect = |a: &[String]| {
        connected.push(a.to_vec());
        0u8
    };
    let mut ctx = Ctx {
        home: home.to_path_buf(),
        io: &mut io,
        agents,
        rows,
        packages,
        stale,
        connect: &mut connect,
        dry_run: dry,
    };
    let code = run(&mut ctx);
    Run {
        code,
        said: io.said,
        asked: io.asked,
        connected,
    }
}

fn none(_: &str) -> Vec<String> {
    Vec::new()
}

#[test]
fn a_dry_run_says_the_plan_and_writes_nothing() {
    let home = scratch("dry");
    let r = run_with(
        &home,
        vec![
            agent("claude-code", "built", "no", "own-prompt"),
            agent("codex", "built", "no", "approver-or-deny"),
            agent("crush", "built", "no", "own-prompt"),
        ],
        vec![],
        &[true],
        true,
        None,
        &none,
    );
    assert_eq!(r.code, 0);
    assert!(r.asked.is_empty());
    assert!(r.connected.is_empty());
    assert!(!home.join(".derm").exists());
    assert!(r.said.contains("the workspace-write preset"), "{}", r.said);
    assert!(
        r.said.contains(
            "claude plugin marketplace add aetiusgular/derm && claude plugin install derm@derm"
        ),
        "{}",
        r.said
    );
    assert!(
        r.said
            .contains(&format!("--ref v{}", env!("CARGO_PKG_VERSION"))),
        "{}",
        r.said
    );
    assert!(
        r.said.contains("derm connect crush --gate --write"),
        "{}",
        r.said
    );
    assert!(
        r.said.contains("codex") && r.said.contains("an ask is a deny (no daemon to answer it)"),
        "{}",
        r.said
    );
    assert!(
        r.said.contains("an ask is the agent's own prompt"),
        "{}",
        r.said
    );
    assert!(r.said.contains(".derm/local/<chat>.jsonl"), "{}", r.said);
    assert!(
        r.said.contains("shows only against an anchor"),
        "{}",
        r.said
    );
    assert!(r.said.contains("A dry run"), "{}", r.said);
}

#[test]
fn a_yes_writes_the_default_policy_and_registers_each_gate_through_connect() {
    let home = scratch("yes");
    let r = run_with(
        &home,
        vec![
            agent("crush", "built", "no", "own-prompt"),
            agent("claude-code", "built", "no", "own-prompt"),
            agent("pi", "built", "yes", "own-prompt"),
        ],
        vec![],
        &[true],
        false,
        None,
        &none,
    );
    assert_eq!(r.code, 0, "{}", r.said);
    assert_eq!(r.asked.len(), 1);
    // Claude Code's plugin installs through its own command: shown, not run.
    assert_eq!(
        r.connected,
        vec![vec!["crush".to_string(), "--gate".into(), "--write".into()]]
    );
    let policy = home.join(".derm/policy.json");
    let text = std::fs::read_to_string(&policy).unwrap();
    crate::setup::presets::matcher_reads(&text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&policy).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(home.join(".derm")).unwrap().mode() & 0o777,
            0o700
        );
    }
    assert!(r.said.contains("Written:"), "{}", r.said);
    assert!(
        r.said.contains("pi") && r.said.contains("derm's gate registered"),
        "{}",
        r.said
    );
}

#[test]
fn a_no_writes_nothing_and_connects_nothing() {
    let home = scratch("no");
    let r = run_with(
        &home,
        vec![agent("crush", "built", "no", "own-prompt")],
        vec![],
        &[false],
        false,
        None,
        &none,
    );
    assert_eq!(r.code, 0);
    assert!(r.connected.is_empty());
    assert!(!home.join(".derm").exists());
    assert!(r.said.contains("Nothing was written."));
}

#[test]
fn a_policy_you_have_is_kept() {
    let home = scratch("keep");
    std::fs::create_dir_all(home.join(".derm")).unwrap();
    std::fs::write(home.join(".derm/policy.json"), "{\"version\":1}").unwrap();
    let r = run_with(&home, vec![], vec![], &[true], false, None, &none);
    assert_eq!(r.code, 0);
    assert!(r.said.contains("kept:"), "{}", r.said);
    // Nothing else to do: no question.
    assert!(r.asked.is_empty());
    assert!(r.said.contains("Nothing to write."));
    assert_eq!(
        std::fs::read_to_string(home.join(".derm/policy.json")).unwrap(),
        "{\"version\":1}"
    );
}

#[test]
fn a_policy_that_appears_after_the_plan_is_not_written_over() {
    let home = scratch("race");
    std::fs::create_dir_all(home.join(".derm")).unwrap();
    let p = home.join(".derm/policy.json");
    assert!(write_new_private(&p, "{}").is_ok());
    let e = write_new_private(&p, "{\"x\":1}");
    assert!(e.is_err());
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "{}");
}

#[cfg(unix)]
#[test]
fn a_derm_folder_through_a_link_or_open_to_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let home = scratch("link");
    let other = scratch("other");
    std::os::unix::fs::symlink(&other, home.join(".derm")).unwrap();
    let r = run_with(&home, vec![], vec![], &[true], false, None, &none);
    assert_eq!(r.code, 1);
    assert!(r.said.contains("a link is refused"), "{}", r.said);
    assert_eq!(std::fs::read_dir(&other).unwrap().count(), 0);
    std::fs::remove_file(home.join(".derm")).unwrap();
    std::fs::create_dir(home.join(".derm")).unwrap();
    std::fs::set_permissions(home.join(".derm"), std::fs::Permissions::from_mode(0o777)).unwrap();
    let r = run_with(&home, vec![], vec![], &[true], false, None, &none);
    assert_eq!(r.code, 1);
    assert!(r.said.contains("written by others"), "{}", r.said);
}

#[test]
fn an_agent_not_on_path_is_left_out_and_a_plugin_gate_names_its_folder() {
    let home = scratch("plugin");
    let mut gone = agent("gemini", "built", "no", "own-prompt");
    gone["onPath"] = Value::Null;
    let r = run_with(
        &home,
        vec![gone, agent("opencode", "built", "no", "own-prompt")],
        vec![],
        &[true],
        false,
        None,
        &none,
    );
    assert!(!r.said.contains("gemini"), "{}", r.said);
    assert!(r.said.contains("needs --packages"), "{}", r.said);
    assert!(r.connected.is_empty(), "{:?}", r.connected);
    // With the source folder, connect runs with --hook.
    let home = scratch("plugin2");
    let r = run_with(
        &home,
        vec![agent("opencode", "built", "no", "own-prompt")],
        vec![],
        &[true],
        false,
        Some(PathBuf::from("/src/derm")),
        &none,
    );
    assert_eq!(r.connected.len(), 1, "{}", r.said);
    let a = &r.connected[0];
    assert_eq!(a[0], "opencode");
    assert!(
        a.windows(2)
            .any(|w| w[0] == "--hook" && w[1].ends_with("derm-opencode-plugin")),
        "{a:?}"
    );
    assert_eq!(a.last().unwrap(), "--write");
}

#[test]
fn calls_that_decide_outside_the_rust_gate_are_named_not_covered() {
    let home = scratch("s1");
    let stale = |id: &str| {
        if id == "crush" {
            vec!["runs node found on PATH".to_string()]
        } else {
            Vec::new()
        }
    };
    let r = run_with(
        &home,
        vec![
            agent("amp", "built", "yes", "own-prompt"),
            agent("crush", "built", "yes", "own-prompt"),
            agent("codex", "built", "yes", "approver-or-deny"),
        ],
        vec![],
        &[],
        true,
        None,
        &stale,
    );
    assert!(
        r.said.contains("Not covered by the light tier:"),
        "{}",
        r.said
    );
    assert!(
        r.said.contains("amp: its plugin decides in TypeScript"),
        "{}",
        r.said
    );
    assert!(
        r.said.contains("crush: runs node found on PATH"),
        "{}",
        r.said
    );
    let section = r
        .said
        .split("Not covered by the light tier:")
        .nth(1)
        .unwrap();
    let section = section.split("\n\n").next().unwrap();
    assert!(!section.contains("codex"), "{section}");
}

#[test]
fn the_standard_tier_is_named_as_derm_run_s_never_written() {
    let home = scratch("std");
    let rows = vec![
        json!({"id": "claude-code", "sandbox": {"via": "settings-flag"}}),
        json!({"id": "codex", "sandbox": {"via": "config-override"}}),
        json!({"id": "cursor", "sandbox": {"via": "advisory"}}),
        json!({"id": "gemini", "sandbox": null}),
    ];
    let r = run_with(
        &home,
        vec![
            agent("claude-code", "built", "yes", "own-prompt"),
            agent("codex", "built", "yes", "approver-or-deny"),
            agent("cursor", "built", "yes", "own-prompt"),
            agent("gemini", "built", "yes", "own-prompt"),
        ],
        rows,
        &[true],
        false,
        None,
        &none,
    );
    assert!(
        r.said.contains("derm run claude-code --tier standard"),
        "{}",
        r.said
    );
    assert!(
        r.said.contains("derm run codex --tier standard"),
        "{}",
        r.said
    );
    assert!(
        r.said.contains("cursor: the Standard tier is not held"),
        "{}",
        r.said
    );
    assert!(!r.said.contains("gemini --tier"), "{}", r.said);
    // Nothing of a vendor's settings is written: only derm's own policy.
    let mut names: Vec<String> = walk(&home);
    names.sort();
    assert_eq!(names, [".derm", ".derm/policy.json"]);
}

fn walk(root: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            out.push(
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            if p.is_dir() {
                stack.push(p);
            }
        }
    }
    out
}

#[test]
fn the_base_s_table_has_no_sandbox_row_so_nothing_is_offered() {
    // Lane 6A fills `presets/wave6/sandbox.json`; until then no agent has a
    // Standard tier line.
    for id in ["claude-code", "codex", "cursor"] {
        let rows = table_rows();
        let line = standard_line(id, &rows);
        let has_row = rows
            .iter()
            .find(|r| s(r, "id") == id)
            .and_then(|r| r.get("sandbox"))
            .is_some_and(|v| v.is_object());
        assert_eq!(line.is_some(), has_row, "{id}");
    }
}

#[test]
fn inside_a_chat_the_writes_are_refused() {
    let token = |k: &str| (k == "DERM_CHAT_TOKEN").then(|| std::ffi::OsString::from("x"));
    assert!(inside_a_chat(&token).is_some_and(|w| w.contains("DERM_CHAT_TOKEN")));
    let file = |k: &str| (k == "DERM_CHAT_TOKEN_FILE").then(|| std::ffi::OsString::from("/t"));
    assert!(inside_a_chat(&file).is_some());
    let empty = |k: &str| (k == "DERM_CHAT_TOKEN").then(|| std::ffi::OsString::from(""));
    assert_eq!(inside_a_chat(&empty), None);
}

#[test]
fn the_arguments_are_checked() {
    assert_eq!(main(&["--bogus".into()]), 2);
    assert_eq!(main(&["--packages".into()]), 2);
    assert_eq!(main(&["--packages".into(), "relative".into()]), 2);
    assert_eq!(main(&["--help".into()]), 0);
    // Not a terminal in a test build: the write path stops before reading
    // anything.
    assert_eq!(main(&[]), 2);
}
