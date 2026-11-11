//! Lane 5bB's unit tests: the 17 cases of `fixtures/hook-cases/manual.json`
//! for this lane (the TypeScript tests that make no hook call), ported one
//! for one with the TypeScript test named above each, and the lane's own
//! corner cases (rules section 4; the native agents' cases 70, 72, 77, 79,
//! 82, 109, 227 and BC-1, BC-2). The recorded hook calls are
//! `tests/hook_cases_5bB.rs`.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::crush::crush_mcp_name;
use super::crush_servers::{crush_server_names, crushrc_server_names, json_keys, project_folders};
use super::kiro_servers::kiro_server_names;
use super::mcp_split::{Named, ServerNames};
use super::vibe::vibe_name;
use super::*;
use crate::gate::core::LoadedPolicy;
use crate::gate::daemon::{AdapterEvent, ApproveOutcome, ApproveRequest, By, Env};

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tree(files: &[(&str, &str)]) -> Tmp {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let base = std::env::temp_dir().join(format!(
        "derm-5bb-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    for (rel, text) in files {
        let f = base.join(rel);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, text).unwrap();
    }
    Tmp(base)
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn listed(v: &[&str], complete: bool) -> ServerNames {
    ServerNames {
        names: names(v),
        complete,
        why: None,
    }
}

// --- manual.json, 5bB: mistralVibe.test.ts -------------------------------

/// mistralVibe.test.ts :: Mistral Vibe pre_tool > names: one dot splits an
/// MCP name; more asks; built-ins take the model's names
#[test]
fn vibe_names_one_dot_splits_an_mcp_name_more_asks_built_ins_take_the_models_names() {
    assert_eq!(
        vibe_name("mcp_exa.web_search_exa"),
        Named::plain("mcp__exa__web_search_exa")
    );
    assert!(vibe_name("mcp_exa.evil.t").ambiguous.is_some());
    assert!(vibe_name("mcp_.t").ambiguous.is_some());
    assert_eq!(
        vibe_name("file_system.read_file"),
        Named::plain("read_file")
    );
    assert_eq!(vibe_name("agents.spawn"), Named::plain("agents_spawn"));
}

// --- manual.json, 5bB: kiro.test.ts --------------------------------------

/// kiro.test.ts :: Kiro PreToolUse > a Markdown agent profile or Powers make
/// the server list incomplete
#[test]
fn kiro_a_markdown_agent_profile_or_powers_make_the_server_list_incomplete() {
    let home = tree(&[("w/.kiro/agents/a.md", "---\nmcpServers: {}\n---\n")]);
    let work = home.0.join("w");
    assert!(!kiro_server_names(Some(&work.to_string_lossy()), &home.0).complete);
    let p = tree(&[("w/.keep", ""), (".kiro/powers/x/.keep", "")]);
    let r = kiro_server_names(Some(&p.0.join("w").to_string_lossy()), &p.0);
    assert!(!r.complete);
    assert!(r.why.unwrap().contains("Powers"));
    let ok = tree(&[(
        "w/.kiro/settings/mcp.json",
        r#"{"mcpServers":{"my.server":{}}}"#,
    )]);
    let r = kiro_server_names(Some(&ok.0.join("w").to_string_lossy()), &ok.0);
    assert!(r.complete);
    assert_eq!(sorted(r.names), names(&["my.server", "my_server"]));
}

// --- manual.json, 5bB: crushServers.test.ts ------------------------------

/// crushServers.test.ts :: Crush's configured MCP server names > reads the mcp
/// keys of a JSON config
#[test]
fn crush_reads_the_mcp_keys_of_a_json_config() {
    assert_eq!(
        json_keys(
            &json!({"mcp": {"exa": {}, "exa_evil": {}}}).to_string(),
            "mcp"
        ),
        Some(names(&["exa", "exa_evil"]))
    );
    assert_eq!(json_keys("{}", "mcp"), Some(vec![]));
    assert_eq!(json_keys("{ not json", "mcp"), None);
    assert_eq!(json_keys(&json!({"mcp": ["exa"]}).to_string(), "mcp"), None);
}

/// crushServers.test.ts :: Crush's configured MCP server names > reads mcp add
/// lines from a plain crushrc and refuses anything it cannot read statically
#[test]
fn crush_reads_mcp_add_lines_from_a_plain_crushrc_and_refuses_anything_it_cannot_read_statically() {
    assert_eq!(
        crushrc_server_names("# comment\nmcp add exa --type http --url https://mcp.exa.ai/mcp\nmcp add 'my server' --type stdio --command /bin/x\nprovider add x\n"),
        Some(names(&["exa", "my server"]))
    );
    for bad in [
        "mcp add $NAME --type stdio",
        "mcp add `echo x`",
        "mcp add \"ex$a\"",
        "mcp add exa; mcp add other",
        "if true; then mcp add x; fi",
        "source ~/other",
        ". ~/other",
        "eval mcp add x",
        "mcp add x\\\n --type stdio",
        "mcp add ex* --type stdio",
        "mcp add {a,b}",
        "mcp add x > /tmp/y",
        "f() { mcp add x; }",
        "export X=1",
    ] {
        assert_eq!(crushrc_server_names(bad), None, "{bad}");
    }
    assert_eq!(crushrc_server_names("mcp add"), None);
}

/// crushServers.test.ts :: Crush's configured MCP server names > walks from the
/// working folder to the git root, and only the working folder without one
#[test]
fn crush_walks_from_the_working_folder_to_the_git_root_and_only_the_working_folder_without_one() {
    let base = tree(&[("repo/.git/HEAD", "x"), ("repo/a/b/.keep", "")]);
    let b = base.0.join("repo").join("a").join("b");
    assert_eq!(
        project_folders(&b),
        vec![
            b.clone(),
            base.0.join("repo").join("a"),
            base.0.join("repo")
        ]
    );
    let loose = tree(&[("x/y/.keep", "")]);
    let y = loose.0.join("x").join("y");
    // No .git anywhere up to / in a temp folder: the folder alone.
    assert_eq!(project_folders(&y), vec![y.clone()]);
    // `.` and `..` are read as path.resolve reads them.
    assert_eq!(project_folders(&y.join("..").join("y").join(".")), vec![y]);
}

fn env(pairs: &[(&str, &Path)]) -> Env {
    Env(pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string_lossy().into_owned()))
        .collect())
}

/// crushServers.test.ts :: Crush's configured MCP server names > collects the
/// global, data and project files Crush loads
#[test]
fn crush_collects_the_global_data_and_project_files_crush_loads() {
    let home = tree(&[
        (".config/crush/crush.json", r#"{"mcp":{"exa":{}}}"#),
        (
            ".config/crush/crushrc",
            "mcp add github --type http --url https://x\n",
        ),
        (
            ".local/share/crush/crush.json",
            r#"{"mcp":{"data_one":{}}}"#,
        ),
        ("proj/.git/HEAD", "x"),
        ("proj/.crush.json", r#"{"mcp":{"exa_evil":{}}}"#),
        (
            "proj/sub/crushrc",
            "mcp add sub_server --type stdio --command /bin/true\n",
        ),
    ]);
    let cwd = home.0.join("proj").join("sub");
    let got = crush_server_names(
        &env(&[("HOME", &home.0)]),
        Some(&cwd.to_string_lossy()),
        &home.0,
    );
    assert!(got.complete, "{:?}", got.why);
    assert_eq!(
        sorted(got.names),
        names(&["data_one", "exa", "exa_evil", "github", "sub_server"])
    );
}

/// crushServers.test.ts :: Crush's configured MCP server names > follows
/// CRUSH_GLOBAL_CONFIG, CRUSH_GLOBAL_DATA and XDG folders
#[test]
fn crush_follows_crush_global_config_crush_global_data_and_xdg_folders() {
    let home = tree(&[
        ("elsewhere/crush.json", r#"{"mcp":{"moved":{}}}"#),
        ("data/crush.json", r#"{"mcp":{"moved_data":{}}}"#),
        ("xdg/crush/crush.json", r#"{"mcp":{"xdg_one":{}}}"#),
        ("w/.keep", ""),
    ]);
    let w = home.0.join("w").to_string_lossy().into_owned();
    let e = env(&[
        ("CRUSH_GLOBAL_CONFIG", &home.0.join("elsewhere")),
        ("CRUSH_GLOBAL_DATA", &home.0.join("data")),
    ]);
    assert_eq!(
        sorted(crush_server_names(&e, Some(&w), &home.0).names),
        names(&["moved", "moved_data"])
    );
    let e = env(&[("XDG_CONFIG_HOME", &home.0.join("xdg"))]);
    assert_eq!(
        crush_server_names(&e, Some(&w), &home.0).names,
        names(&["xdg_one"])
    );
}

/// crushServers.test.ts :: Crush's configured MCP server names > is incomplete
/// when a file cannot be read whole, or with no cwd
#[test]
fn crush_is_incomplete_when_a_file_cannot_be_read_whole_or_with_no_cwd() {
    let home = tree(&[(".config/crush/crush.json", "{ broken"), ("w/.keep", "")]);
    let w = home.0.join("w").to_string_lossy().into_owned();
    assert!(!crush_server_names(&Env::default(), Some(&w), &home.0).complete);
    let rc = tree(&[(".config/crush/crushrc", "mcp add $X\n"), ("w/.keep", "")]);
    let w = rc.0.join("w").to_string_lossy().into_owned();
    let r = crush_server_names(&Env::default(), Some(&w), &rc.0);
    assert!(!r.complete);
    assert!(r.why.unwrap().contains("crushrc"));
    assert!(!crush_server_names(&Env::default(), None, &rc.0).complete);
    assert!(!crush_server_names(&Env::default(), Some("relative/dir"), &rc.0).complete);
}

/// crushServers.test.ts :: Crush MCP names to the core's form (W2-R1 for single
/// underscores) > a name that can split one way needs no list
#[test]
fn crush_a_name_that_can_split_one_way_needs_no_list() {
    assert_eq!(
        crush_mcp_name("mcp_exa_search", &listed(&[], false)),
        Named::plain("mcp__exa__search")
    );
    assert_eq!(
        crush_mcp_name("bash", &listed(&[], true)),
        Named::plain("bash")
    );
}

/// crushServers.test.ts :: Crush MCP names to the core's form (W2-R1 for single
/// underscores) > splits at the one configured server that fits
#[test]
fn crush_splits_at_the_one_configured_server_that_fits() {
    assert_eq!(
        crush_mcp_name("mcp_exa_web_search_exa", &listed(&["exa", "github"], true)),
        Named::plain("mcp__exa__web_search_exa")
    );
    assert_eq!(
        crush_mcp_name("mcp_exa_evil_t", &listed(&["exa_evil"], true)),
        Named::plain("mcp__exa_evil__t")
    );
}

/// crushServers.test.ts :: Crush MCP names to the core's form (W2-R1 for single
/// underscores) > asks when two servers fit, when none does, or when the list
/// is incomplete
#[test]
fn crush_asks_when_two_servers_fit_when_none_does_or_when_the_list_is_incomplete() {
    let two = crush_mcp_name("mcp_exa_evil_t", &listed(&["exa", "exa_evil"], true));
    assert_eq!(two.tool, "mcp_exa_evil_t");
    assert!(two.ambiguous.unwrap().contains("more than one"));
    assert!(crush_mcp_name("mcp_exa_evil_t", &listed(&["github"], true))
        .ambiguous
        .unwrap()
        .contains("no configured"));
    let partial = ServerNames {
        names: names(&["exa"]),
        complete: false,
        why: Some("a crushrc derm cannot read statically (crushrc)".into()),
    };
    assert!(crush_mcp_name("mcp_exa_evil_t", &partial)
        .ambiguous
        .unwrap()
        .contains("crushrc"));
}

// --- manual.json, 5bB: presets.test.ts -----------------------------------

fn preset(id: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/connect/presets")
        .join(format!("{id}.json"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// The preset row says what the dialect does (case 82): its shell aliases are
/// the dialect's shell names, and its ask route is the dialect's.
fn preset_agrees(id: &str, shell: &[&str]) {
    let row = preset(id);
    let c = &row["coverage"];
    let aliases: Vec<&str> = c["shellAliases"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(aliases, shell, "{id}");
    let d = dialect(id).unwrap();
    // Cursor shows its own prompt only for MCP calls (beforeMCPExecution);
    // every other tool goes to the approver or is denied, so its row says
    // that route. Antigravity always shows its own (force_ask).
    let own = id == "antigravity";
    assert_eq!(
        c["ask"],
        if own {
            "own-prompt"
        } else {
            "approver-or-deny"
        },
        "{id}"
    );
    assert_eq!(d.id, id);
    assert_eq!(
        crate::hook::AGENTS
            .iter()
            .find(|(a, _, _)| *a == id)
            .map(|(_, f, _)| *f),
        Some(crate::hook::Family::Native)
    );
}

/// presets.test.ts :: preset rows and dialects > cursor: shell aliases, ask
/// route and package agree (case 82)
#[test]
fn preset_cursor_shell_aliases_and_ask_route_agree() {
    preset_agrees("cursor", cursor::CURSOR_SHELL.names);
}

/// presets.test.ts :: preset rows and dialects > antigravity: shell aliases,
/// ask route and package agree (case 82)
#[test]
fn preset_antigravity_shell_aliases_and_ask_route_agree() {
    preset_agrees("antigravity", antigravity::ANTIGRAVITY_SHELL.names);
}

/// presets.test.ts :: preset rows and dialects > goose: shell aliases, ask
/// route and package agree (case 82)
#[test]
fn preset_goose_shell_aliases_and_ask_route_agree() {
    preset_agrees("goose", goose::GOOSE_SHELL.names);
}

/// presets.test.ts :: preset rows and dialects > mistral-vibe: shell aliases,
/// ask route and package agree (case 82)
#[test]
fn preset_mistral_vibe_shell_aliases_and_ask_route_agree() {
    preset_agrees("mistral-vibe", vibe::VIBE_SHELL.names);
}

/// presets.test.ts :: preset rows and dialects > crush: shell aliases, ask
/// route and package agree (case 82)
#[test]
fn preset_crush_shell_aliases_and_ask_route_agree() {
    preset_agrees("crush", crush::CRUSH_SHELL.names);
}

/// presets.test.ts :: preset rows and dialects > kiro: shell aliases, ask
/// route and package agree (case 82)
#[test]
fn preset_kiro_shell_aliases_and_ask_route_agree() {
    preset_agrees("kiro", kiro::KIRO_SHELL.names);
}

// --- the lane's own corner cases -----------------------------------------

/// A fake environment, policy and daemon for the runner.
struct Fake {
    env: Env,
    policy: Value,
    approve: Option<bool>,
    posted: std::cell::RefCell<Vec<AdapterEvent>>,
    asked: std::cell::RefCell<Vec<ApproveRequest>>,
}

impl Fake {
    fn new(policy: Value) -> Fake {
        Fake {
            env: Env::default(),
            policy,
            approve: None,
            posted: Default::default(),
            asked: Default::default(),
        }
    }
}

impl Io for Fake {
    fn env(&self) -> &Env {
        &self.env
    }
    fn load_policy(&self) -> LoadedPolicy {
        LoadedPolicy {
            policy: derm_core::policy::parse(&self.policy.to_string()).unwrap(),
            problem: None,
        }
    }
    fn approve(&self, r: &ApproveRequest) -> ApproveOutcome {
        self.asked.borrow_mut().push(r.clone());
        match self.approve {
            None => ApproveOutcome::Answer {
                yes: false,
                by: By::None,
            },
            Some(yes) => ApproveOutcome::Answer {
                yes,
                by: By::Approver,
            },
        }
    }
    fn post(&self, e: &AdapterEvent) {
        self.posted.borrow_mut().push(e.clone());
    }
}

fn allow_bash() -> Value {
    json!({"version": 1, "askTimeoutSeconds": 1, "rules": [{"tool": "bash", "action": "allow"}]})
}

const CURSOR_COMMON: &str = r#""conversation_id":"c","generation_id":"g","cursor_version":"2026.11.10","hook_event_name":"preToolUse""#;

/// The fail-closed table in `hook/mod.rs` (what an agent reads before a
/// dialect runs) equals each dialect's own deny, as `bin/fallback.mjs` was
/// held to the TypeScript dialects (`src/bin.test.ts`).
#[test]
fn the_fail_closed_table_equals_each_dialects_own_deny() {
    for id in [
        "cursor",
        "antigravity",
        "goose",
        "mistral-vibe",
        "crush",
        "kiro",
    ] {
        let d = dialect(id).unwrap();
        assert_eq!(
            crate::hook::fail_closed(id, "x  y"),
            (d.deny)("x y"),
            "{id}"
        );
    }
}

/// Case 77: Kiro and goose print nothing on allow (stdout reaches the model
/// on Kiro), and no reply echoes the tool input.
#[test]
fn an_allow_prints_nothing_where_stdout_is_context_and_no_reply_echoes_the_input() {
    let f = Fake::new(allow_bash());
    let secret_free = "echo unique-marker-5bb";
    let kiro_in = format!(
        r#"{{"hook_event_name":"PreToolUse","cwd":"/w","tool_name":"execute_bash","tool_input":{{"command":"{secret_free}"}}}}"#
    );
    let r = run_pre(&kiro::KIRO, &kiro_in, &f);
    assert_eq!((r.stdout.as_str(), r.exit), ("", 0));
    let goose_in = format!(
        r#"{{"event":"PreToolUse","tool_name":"shell","tool_input":{{"command":"{secret_free}"}}}}"#
    );
    let r = run_pre(&goose::GOOSE, &goose_in, &f);
    assert_eq!((r.stdout.as_str(), r.exit), ("", 0));
    let deny = Fake::new(json!({"version": 1, "rules": [{"tool": "bash", "action": "deny"}]}));
    for (d, input) in [(&kiro::KIRO, &kiro_in), (&goose::GOOSE, &goose_in)] {
        let r = run_pre(d, input, &deny);
        assert!(!r.stdout.contains("unique-marker") && !r.stderr.contains("unique-marker"));
    }
}

/// Case 109, BCR-7 (contracts/hook-dialects.md 9.2): an input without Cursor's
/// marks, such as Grok running `~/.cursor/hooks.json`, is denied with the fix
/// named, never decided in Cursor's dialect, even where the policy allows.
#[test]
fn an_input_without_cursors_marks_is_denied_with_the_fix_named() {
    let f = Fake::new(allow_bash());
    let grokish =
        r#"{"hook_event_name":"PreToolUse","tool_name":"Shell","tool_input":{"command":"ls"}}"#;
    let r = run_pre(&cursor::CURSOR, grokish, &f);
    assert!(r.stdout.contains("\"permission\":\"deny\""), "{}", r.stdout);
    assert!(r.stdout.contains("compat.cursor"));
    let no_version =
        r#"{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"ls"}}"#;
    let r = run_pre(&cursor::CURSOR, no_version, &f);
    assert!(r.stdout.contains("no cursor_version"), "{}", r.stdout);
    assert!(
        f.posted.borrow().is_empty(),
        "no decision is recorded for another agent's input"
    );
    let real =
        format!(r#"{{{CURSOR_COMMON},"tool_name":"Shell","tool_input":{{"command":"ls"}}}}"#);
    let r = run_pre(&cursor::CURSOR, &real, &f);
    assert_eq!(r.stdout, "{\"permission\":\"allow\"}\n");
}

/// Case 110: Cursor's preToolUse for `MCP:<tool>` defers and records
/// `deferred`, with no install record and no ask.
#[test]
fn cursors_mcp_pre_tool_use_defers_without_an_ask_or_an_install_record() {
    let mut f = Fake::new(json!({"version": 1, "rules": [{"tool": "github/*", "action": "ask"}]}));
    f.approve = Some(true);
    let input = format!(
        r#"{{{CURSOR_COMMON},"tool_name":"MCP:create_issue","tool_input":{{}},"tool_use_id":"t1"}}"#
    );
    let r = run_pre(&cursor::CURSOR, &input, &f);
    assert_eq!(r.stdout, "{\"permission\":\"allow\"}\n");
    assert!(f.asked.borrow().is_empty());
    let posted = f.posted.borrow();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].detail["decision"], "deferred");
    assert_eq!(posted[0].detail["toolUseId"], "t1");
}

/// BC-1 and BC-2 (note BC section 11): an agent's call that would write a
/// project-level goose plugin or a Vibe hooks file (the shadows that replace
/// derm's gate in the next session) asks under an allow-bash policy, and with
/// no approver is denied. What a repository brings with it is lane 5bF's.
#[test]
fn writing_a_goose_plugin_or_a_vibe_hooks_file_into_a_project_asks() {
    let f = Fake::new(allow_bash());
    for cmd in [
        "mkdir -p .agents/plugins/derm/hooks",
        "cp /tmp/h.json ./.AGENTS/plugins/derm/hooks/hooks.json",
    ] {
        let input =
            json!({"event": "PreToolUse", "tool_name": "shell", "tool_input": {"command": cmd}})
                .to_string();
        let r = run_pre(&goose::GOOSE, &input, &f);
        assert_eq!(r.exit, 2, "{cmd}");
        assert!(
            r.stderr.contains("control file (.agents/plugins/)"),
            "{cmd}: {}",
            r.stderr
        );
    }
    for cmd in [
        "printf x > .vibe/hooks.toml",
        "cat x >> /srv/added/.vibe/hooks.toml",
    ] {
        let input = json!({"hook_event_name": "pre_tool", "tool_name": "file_system.bash", "tool_input": {"command": cmd}}).to_string();
        let r = run_pre(&vibe::MISTRAL_VIBE, &input, &f);
        assert!(
            r.stdout.contains("control file (.vibe/)"),
            "{cmd}: {}",
            r.stdout
        );
    }
}

/// Case 79: every deny is the agent's per-call form, never the run-ending
/// one (Crush's exit 49 or `halt`, goose's and Vibe's exit 0 failures).
#[test]
fn every_deny_is_the_per_call_form() {
    let r = (crush::CRUSH.deny)("x");
    assert_eq!((r.exit, r.stdout.as_str()), (2, ""));
    assert!(!r.stderr.contains("halt"));
    let r = (vibe::MISTRAL_VIBE.deny)("x");
    assert_eq!(r.exit, 0, "exit 2 is a failure to Vibe, not a deny");
    let r = (goose::GOOSE.deny)("x");
    assert_eq!(r.exit, 2);
    assert!(r.stdout.contains("\"block\""));
}

/// Case 72: Crush's allow skips its own prompt, so it is said only for a
/// rule's allow; with no rule the call is the approver's or denied.
#[test]
fn crush_says_allow_only_for_a_rules_allow() {
    let f = Fake::new(json!({"version": 1, "rules": []}));
    let input =
        r#"{"hook_event_name":"PreToolUse","tool_name":"view","tool_input":{"file_path":"a"}}"#;
    let r = run_pre(&crush::CRUSH, input, &f);
    assert_eq!(r.exit, 2, "no rule and no approver: denied, {r:?}");
    assert_eq!(f.asked.borrow().len(), 1);
}

/// An input over 32 MiB is the dialect's deny, and the rest of stdin is
/// read, so the agent never meets a closed pipe first.
#[test]
fn an_input_over_the_cap_is_a_deny_and_stdin_is_drained() {
    struct Endless(u64);
    impl std::io::Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Ok(0);
            }
            let n = (buf.len() as u64).min(self.0) as usize;
            buf[..n].fill(b' ');
            self.0 -= n as u64;
            Ok(n)
        }
    }
    let mut big = Endless(MAX_STDIN_BYTES + 4096);
    assert_eq!(
        read_stdin(&mut big),
        Err("hook input too large".to_string())
    );
    assert_eq!(big.0, 0);
    let r = answer("crush", "pre", &mut Endless(MAX_STDIN_BYTES + 1));
    assert_eq!(r.exit, 2);
    assert!(r.stderr.contains("too large"));
}

/// Hermes: the payload's event and the registration's must agree (9.1); an
/// unknown event or bad input is the decider's deny, which `derm_gate.py`
/// turns into a block.
#[test]
fn hermes_refuses_an_event_the_registration_does_not_name() {
    let r = hermes::answer(
        "pre",
        Ok(r#"{"event":"post","tool_name":"terminal","result":"x"}"#.into()),
        &Fake::new(allow_bash()),
    );
    assert!(r.stdout.contains("\"decision\":\"deny\""), "{}", r.stdout);
    let r = hermes::answer(
        "post",
        Ok(r#"{"event":"pre","tool_name":"terminal","args":{}}"#.into()),
        &Fake::new(allow_bash()),
    );
    assert!(r.stdout.contains("\"decision\":\"deny\""));
    let r = hermes::answer(
        "pre",
        Err("hook input too large".into()),
        &Fake::new(allow_bash()),
    );
    assert!(r.stdout.contains("too large"));
}

/// Hermes: an ask waits at most 20 seconds, whatever the policy says.
#[test]
fn hermes_caps_an_ask_at_twenty_seconds() {
    let mut f = Fake::new(
        json!({"version": 1, "askTimeoutSeconds": 600, "rules": [{"tool": "terminal", "action": "ask"}]}),
    );
    f.approve = Some(true);
    let r = hermes::answer(
        "pre",
        Ok(r#"{"event":"pre","tool_name":"terminal","args":{"command":"ls"}}"#.into()),
        &f,
    );
    assert!(r.stdout.contains("\"allow\""), "{}", r.stdout);
    assert_eq!(f.asked.borrow()[0].timeout_seconds, 20);
}

/// Antigravity's call id joins the conversation and the step as JavaScript
/// would print the number.
#[test]
fn antigravity_names_a_call_by_conversation_and_step() {
    let input: Input = serde_json::from_str(
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}},"stepIdx":3,"conversationId":"c-1"}"#,
    )
    .unwrap();
    let read = (antigravity::ANTIGRAVITY.read)(&input, &Env::default()).unwrap();
    assert_eq!(read.call_id.as_deref(), Some("c-1-3"));
    assert_eq!(read.tool, "bash");
}

#[test]
fn goose_counts_runs_of_underscores() {
    assert_eq!(goose::underscore_runs("github__create_issue"), 1);
    assert_eq!(goose::underscore_runs("a__b___c"), 2);
    assert_eq!(goose::underscore_runs("a_b_c"), 0);
}

#[test]
fn vibe_reads_a_base64_write_as_node_does() {
    assert_eq!(vibe::base64_lenient("aGVsbG8="), b"hello");
    assert_eq!(vibe::base64_lenient("aGVs\nbG8"), b"hello");
    assert_eq!(vibe::base64_lenient("-_8"), vec![0xfb, 0xff]);
}

#[test]
fn one_line_is_never_empty() {
    assert_eq!(one_line("  a \n b "), "a b");
    assert_eq!(one_line(" \n"), "blocked");
}

/// A project's config file that is a FIFO neither blocks the hook nor counts
/// as read: the list is incomplete (case 111's class; the TypeScript stat the
/// path and read it after).
#[cfg(unix)]
#[test]
fn a_fifo_config_does_not_block_and_makes_the_list_incomplete() {
    let home = tree(&[("w/.git/HEAD", "x")]);
    let fifo = home.0.join("w").join("crush.json");
    let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
    // SAFETY: a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let t0 = std::time::Instant::now();
    let r = crush_server_names(
        &Env::default(),
        Some(&home.0.join("w").to_string_lossy()),
        &home.0,
    );
    assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    assert!(!r.complete);
    assert_eq!(r.why.as_deref(), Some("crush.json could not be read"));
}
