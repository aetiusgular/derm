//! Lane 5bA's unit tests: the TypeScript cases that make no hook call
//! (`contracts/fixtures/hook-cases/manual.json`, lane 5bA, 16 cases), the
//! one recorded call the replay skips (`manual-calls.json`), and this
//! lane's own cases. The L-S6 cases and the chat-id case are in
//! `token.rs`; the control-path cases in `control.rs`.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::*;
use crate::gate::core::LoadedPolicy;
use crate::gate::daemon::{AdapterEvent, ApproveOutcome, ApproveRequest, By, Env};

fn presets() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/connect/presets")
}

fn policy(v: Value) -> LoadedPolicy {
    LoadedPolicy {
        policy: serde_json::from_value(v).unwrap(),
        problem: None,
    }
}

/// Dependencies with a policy and no daemon (the TypeScript tests'
/// `noDaemon`): an approve is unreachable, a post goes nowhere.
fn no_daemon<'a>(p: LoadedPolicy, env: Env) -> Deps<'a> {
    Deps {
        env,
        cwd: PathBuf::from("/"),
        load_policy: Box::new(move |_, _| p.clone()),
        approve: Box::new(|_, _, _| ApproveOutcome::Unreachable("no daemon (test)".into())),
        post: Box::new(|_, _, _| false),
    }
}

/// manual.json: "<agent> > its shell aliases equal its preset row's
/// coverage.shellAliases", for each of the eight, and the dialect's id is
/// its preset's id.
#[test]
fn each_dialects_shell_aliases_equal_its_preset_rows_coverage_shell_aliases() {
    for d in &compat::DIALECTS {
        let row: Value = serde_json::from_str(
            &std::fs::read_to_string(presets().join(format!("{}.json", d.id))).unwrap(),
        )
        .unwrap();
        let mut want: Vec<String> = row["coverage"]["shellAliases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let mut got: Vec<String> = compat::shell_aliases(d.id)
            .iter()
            .map(|s| s.to_string())
            .collect();
        want.sort();
        got.sort();
        assert_eq!(got, want, "{}", d.id);
        assert_eq!(row["id"].as_str(), Some(d.id), "{}", d.id);
        // The version the dialect was read at is one the preset names.
        let at = row["coverage"]["verifiedAt"].as_str().unwrap_or("");
        assert!(
            at.split([',', ' ']).any(|v| v == d.verified_at),
            "{}: {at}",
            d.id
        );
    }
}

/// manual.json: "plugin files > decide denies anything that is not a tool
/// call" (Codex's `decide`): `{}` and `null` block, under an allow-all
/// policy too.
#[test]
fn codex_denies_anything_that_is_not_a_tool_call() {
    let allow_all = json!({"version": 1, "rules": [{"tool": "*", "action": "allow"}]});
    for input in ["{}", "null", "[]", "\"x\""] {
        let r = codex::run(
            "pre",
            input.as_bytes(),
            no_daemon(policy(allow_all.clone()), Env::default()),
        );
        assert_eq!(r.exit, 2, "{input}");
        assert!(r.stderr.starts_with("derm: "), "{input}: {}", r.stderr);
        assert!(r.stdout.is_empty());
    }
}

/// manual.json: "Gemini BeforeTool > matches an MCP tool by mcp_context, so
/// a server with _ or - splits right".
#[test]
fn gemini_matches_an_mcp_tool_by_mcp_context() {
    let m = |v: Value| v.as_object().unwrap().clone();
    assert_eq!(
        gemini::tool_for_gate(&m(
            json!({"tool_name": "mcp_my_srv_do_it", "mcp_context": {"server_name": "my_srv", "tool_name": "do_it"}})
        )),
        "mcp__my_srv__do_it"
    );
    assert_eq!(
        gemini::tool_for_gate(&m(json!({"tool_name": "mcp_exa_search"}))),
        "mcp_exa_search"
    );
    assert_eq!(
        gemini::tool_for_gate(&m(
            json!({"tool_name": "read_file", "mcp_context": {"server_name": "", "tool_name": "x"}})
        )),
        "read_file"
    );
}

/// manual.json: "the hook's environment > reads the chat token file from
/// GEMINI_CLI_DERM_CHAT_TOKEN_FILE when Gemini dropped
/// DERM_CHAT_TOKEN_FILE"; a raw token under a GEMINI_CLI_ name is never
/// taken.
#[test]
fn gemini_reads_the_token_file_from_its_alias_only() {
    let e = gemini::hook_env(&Env::of(&[(
        gemini::TOKEN_FILE_ALIAS,
        "/run/derm/chats/c.token",
    )]));
    assert_eq!(
        e.raw("DERM_CHAT_TOKEN_FILE"),
        Some("/run/derm/chats/c.token")
    );
    let e = gemini::hook_env(&Env::of(&[
        ("DERM_CHAT_TOKEN_FILE", "/a"),
        (gemini::TOKEN_FILE_ALIAS, "/b"),
    ]));
    assert_eq!(e.raw("DERM_CHAT_TOKEN_FILE"), Some("/a"));
    let e = gemini::hook_env(&Env::of(&[("GEMINI_CLI_DERM_CHAT_TOKEN", &"2".repeat(64))]));
    assert_eq!(e.raw("DERM_CHAT_TOKEN"), None);
}

/// manual.json: "L-S10: Kimi's deny JSON > is one line, the same reason as
/// stderr".
#[test]
fn kimis_deny_json_is_one_line_with_the_reason_stderr_has() {
    let r = compat::dialect("kimi").unwrap().deny("two\nlines");
    let o: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(
        o["hookSpecificOutput"]["permissionDecisionReason"],
        "derm: two lines"
    );
    assert_eq!(r.stderr, "derm: two lines\n");
    assert_eq!(r.stdout.matches('\n').count(), 1);
}

/// manual-calls.json: "the chat token when the agent strips it (case 76) >
/// Command Code: with DERM_CHAT_TOKEN and DERM_CHAT_TOKEN_FILE stripped, the
/// hook finds the token file from DERM_CHAT_ID and DERM_DAEMON_SOCKET". The
/// fake daemon's folder stands in for derm's own socket folder (L-S6); the
/// same socket outside derm's folders derives no token, so the ask is a
/// deny and the approver is not asked.
#[cfg(unix)]
#[test]
fn command_code_finds_its_stripped_token_from_the_chat_id_and_the_socket() {
    use crate::gate::fake_daemon::{Approve, FakeDaemon, CHAT_TOKEN};
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("d5a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let d = FakeDaemon::start(Approve::Yes, Some(&root));
    let chat = "derm-0123456789ab";
    let chats = d.dir.join("chats");
    std::fs::create_dir_all(&chats).unwrap();
    std::fs::set_permissions(&chats, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = chats.join(format!("{chat}.token"));
    std::fs::write(&file, format!("{CHAT_TOKEN}\n")).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ask_all =
        json!({"version": 1, "askTimeoutSeconds": 1, "rules": [{"tool": "*", "action": "ask"}]});
    let sock = d.socket.display().to_string();
    let stripped = Env::of(&[("DERM_DAEMON_SOCKET", &sock), ("DERM_CHAT_ID", chat)]);
    let input = json!({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t1"}).to_string();
    let real = |env: Env| {
        let p = policy(ask_all.clone());
        Deps {
            env,
            // A chat folder apart from the daemon's (a socket inside the
            // chat's folder is refused).
            cwd: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            load_policy: Box::new(move |_, _| p.clone()),
            approve: Box::new(crate::gate::daemon::approve),
            post: Box::new(crate::gate::daemon::post_event),
        }
    };
    let cc = compat::dialect("command-code").unwrap();
    let env = token::hook_env(&stripped, std::slice::from_ref(&d.dir));
    let r = compat::run_with(cc, input.as_bytes(), real(env));
    assert_eq!(r.exit, 0, "{r:?}");
    assert!(
        r.stdout.contains("\"permissionDecision\":\"allow\""),
        "{r:?}"
    );
    let approvals = || {
        d.lines()
            .into_iter()
            .filter(|(_, l)| l["op"] == "approve")
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
    };
    let last = approvals().pop().unwrap();
    assert_eq!(last["request"]["harness"], "command-code");
    assert_eq!(last["request"]["chat"], chat);
    let before = approvals().len();
    let env = token::hook_env(&stripped, &token::default_socket_dirs());
    let planted = compat::run_with(cc, input.as_bytes(), real(env));
    assert_eq!(planted.exit, 2, "{planted:?}");
    assert_eq!(approvals().len(), before);
    drop(d);
    let _ = std::fs::remove_dir_all(&root);
}

/// Every pre path ends in a decision: input the hook cannot read is each
/// agent's deny, and a post event never blocks (contracts/hook-dialects.md
/// section 1; Codex and Gemini fail open on anything else).
#[test]
fn input_that_cannot_be_read_denies_on_pre_and_never_blocks_on_post() {
    let pol = policy(json!({"version": 1, "rules": [{"tool": "*", "action": "allow"}]}));
    let agents: Vec<(&str, &str, &str)> = vec![
        ("claude-code", "pre", "post"),
        ("codex", "pre", "post"),
        ("gemini", "before", "after"),
    ];
    for bad in ["", "not json", "[1]", "{\"tool_name\": \"\"}"] {
        for (agent, pre, post) in &agents {
            let r = answer_with(
                agent,
                pre,
                bad.as_bytes(),
                no_daemon(pol.clone(), Env::default()),
            );
            assert_eq!(r.exit, 2, "{agent} {bad:?}");
            let r = answer_with(
                agent,
                post,
                bad.as_bytes(),
                no_daemon(pol.clone(), Env::default()),
            );
            assert_eq!((r.exit, r.stdout.as_str()), (0, ""), "{agent} post {bad:?}");
        }
        for d in &compat::DIALECTS {
            let r = answer_with(
                d.id,
                "pre",
                bad.as_bytes(),
                no_daemon(pol.clone(), Env::default()),
            );
            assert_eq!(r.exit, 2, "{} {bad:?}", d.id);
            assert!(r.stderr.starts_with("derm: "), "{}", d.id);
        }
    }
    // Over the cap: too large, read as such.
    let big = vec![b' '; MAX_STDIN_BYTES + 1];
    let r = answer_with("claude-code", "pre", &big, no_daemon(pol, Env::default()));
    assert_eq!(r.stderr, "derm: hook input too large\n");
}

/// The tool input is never echoed (case 77): a secret in a denied call's
/// input reaches neither stdout nor stderr, on any of the eleven.
#[test]
fn a_denied_calls_input_is_never_echoed() {
    let pol = policy(json!({"version": 1, "rules": [{"tool": "*", "action": "deny"}]}));
    let secret = "sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
    let input = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": format!("echo {secret}")}, "toolName": "Bash", "toolInput": {"command": format!("echo {secret}")}, "toolInputTruncated": false}).to_string();
    // Claude Code's deny is its JSON on exit 0; every other one exits 2.
    let r = answer_with(
        "claude-code",
        "pre",
        input.as_bytes(),
        no_daemon(pol.clone(), Env::default()),
    );
    assert!(
        r.stdout.contains("\"permissionDecision\":\"deny\""),
        "{r:?}"
    );
    assert!(!r.stdout.contains(secret) && !r.stderr.contains(secret));
    let mut agents = vec!["codex"];
    agents.extend(compat::DIALECTS.iter().map(|d| d.id));
    for a in agents {
        let r = answer_with(
            a,
            "pre",
            input.as_bytes(),
            no_daemon(pol.clone(), Env::default()),
        );
        assert_eq!(r.exit, 2, "{a}");
        assert!(
            !r.stdout.contains(secret) && !r.stderr.contains(secret),
            "{a}"
        );
    }
    let g = json!({"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": {"command": format!("echo {secret}")}}).to_string();
    let r = answer_with(
        "gemini",
        "before",
        g.as_bytes(),
        no_daemon(pol, Env::default()),
    );
    assert_eq!(r.exit, 2);
    assert!(!r.stdout.contains(secret) && !r.stderr.contains(secret));
}

/// Full access (case 83): an ask that a narrowing made, after the core
/// decided allow, is still a deny, never the agent's own prompt (review
/// W4-S3), on every dialect with an ask of its own.
#[test]
fn under_full_access_a_narrowed_ask_is_a_deny() {
    let pol = policy(json!({"version": 1, "rules": [{"tool": "*", "action": "allow"}]}));
    let env = Env::of(&[("DERM_FULL_ACCESS", "1")]);
    for id in ["openclaude", "qwen-code", "copilot-cli", "grok"] {
        let args = json!({"file_path": "/home/u/.grok/config.toml"});
        let input = json!({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": args, "toolName": "Read", "toolInput": args, "toolArgs": args, "toolInputTruncated": false}).to_string();
        let r = answer_with(
            id,
            "pre",
            input.as_bytes(),
            no_daemon(pol.clone(), env.clone()),
        );
        assert_eq!(r.exit, 2, "{id}: {r:?}");
        assert!(r.stderr.contains("full access"), "{id}: {}", r.stderr);
    }
}

/// An approve only an approver's yes counts as yes; a timeout and a no are
/// denies on Codex, which has no ask of its own.
#[test]
fn on_codex_only_an_approvers_yes_allows_an_ask() {
    let pol = policy(json!({"version": 1, "rules": [{"tool": "*", "action": "ask"}]}));
    let input = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}).to_string();
    for (outcome, exit) in [
        (
            ApproveOutcome::Answer {
                yes: true,
                by: By::Approver,
            },
            0,
        ),
        (
            ApproveOutcome::Answer {
                yes: false,
                by: By::Approver,
            },
            2,
        ),
        (
            ApproveOutcome::Answer {
                yes: false,
                by: By::Timeout,
            },
            2,
        ),
        (
            ApproveOutcome::Answer {
                yes: false,
                by: By::None,
            },
            2,
        ),
        (ApproveOutcome::Unreachable("x".into()), 2),
    ] {
        let o = outcome.clone();
        let p = pol.clone();
        let deps = Deps {
            env: Env::default(),
            cwd: PathBuf::from("/"),
            load_policy: Box::new(move |_, _| p.clone()),
            approve: Box::new(move |_: &ApproveRequest, _: &Env, _: &Path| o.clone()),
            post: Box::new(|_: &AdapterEvent, _: &Env, _: &Path| true),
        };
        let r = codex::run("pre", input.as_bytes(), deps);
        assert_eq!(r.exit, exit, "{outcome:?}");
    }
}

/// Grok's input as Grok 1.0.77 sent it to a hook in Claude Code's
/// settings.json (recorded by this lane, 10 Nov; marks.rs), trimmed of its
/// paths.
fn grok_input() -> serde_json::Map<String, Value> {
    json!({
        "hookEventName": "pre_tool_use", "sessionId": "s", "cwd": "/w", "workspaceRoot": "/w",
        "timestamp": "2026-11-11T05:37:14.460773847+00:00", "transcriptPath": "/t",
        "permissionMode": "bypassPermissions", "toolName": "run_terminal_command", "toolUseId": "call_2",
        "toolInput": {"command": "echo hi > ran.txt", "description": "step"}, "toolInputTruncated": false,
        "hook_event_name": "PreToolUse", "session_id": "s", "transcript_path": "/t",
        "permission_mode": "bypassPermissions", "tool_name": "run_terminal_command",
        "tool_input": {"command": "echo hi > ran.txt", "description": "step"}, "tool_use_id": "call_2"
    })
    .as_object()
    .unwrap()
    .clone()
}

/// BCR-7, section 9.2: Grok's input is told apart by both of its marks;
/// Claude Code's own input, and either mark alone, is not Grok's.
#[test]
fn grok_input_is_told_apart_by_both_its_marks() {
    assert!(marks::run_by_grok(&grok_input()));
    let mut one = grok_input();
    one.remove("toolInputTruncated");
    assert!(!marks::run_by_grok(&one));
    let mut other = grok_input();
    other.insert("hookEventName".into(), json!("PreToolUse"));
    assert!(!marks::run_by_grok(&other));
    let claude = json!({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t", "permission_mode": "default"});
    assert!(!marks::run_by_grok(claude.as_object().unwrap()));
    assert!(!marks::run_by_cursor(&grok_input()));
}

/// Claude Code's hook run by Grok never decides as Claude Code: with no
/// derm Grok gate it blocks and names the fix, and posts nothing; with
/// derm's Grok gate registered failing closed it defers with no record.
#[cfg(unix)]
#[test]
fn claude_codes_hook_run_by_grok_blocks_or_defers_and_never_decides() {
    use std::os::unix::fs::PermissionsExt;
    let home = std::env::temp_dir().join(format!("d5g-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".grok/hooks")).unwrap();
    let posted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let deps = |home: &Path| {
        let n = posted.clone();
        let p = policy(json!({"version": 1, "rules": [{"tool": "*", "action": "allow"}]}));
        Deps {
            env: Env::of(&[("HOME", &home.display().to_string())]),
            cwd: PathBuf::from("/"),
            load_policy: Box::new(move |_, _| p.clone()),
            approve: Box::new(|_, _, _| ApproveOutcome::Unreachable("test".into())),
            post: Box::new(move |_, _, _| {
                n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                true
            }),
        }
    };
    let input = Value::Object(grok_input()).to_string();
    let r = claude_code::run("pre", input.as_bytes(), deps(&home));
    assert_eq!(r.exit, 2, "{r:?}");
    assert!(
        r.stderr.contains("Grok ran derm's Claude Code hook"),
        "{}",
        r.stderr
    );
    // derm's Grok gate, in the Rust form, naming this very program.
    let me = std::env::current_exe().unwrap();
    let file = home.join(".grok/hooks/derm.json");
    let write = |fail_closed: bool, prog: &Path| {
        let entry = json!({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": format!("\"{}\" hook grok pre", prog.display()), "timeout": 120, "failClosed": fail_closed}]}]}});
        std::fs::write(&file, entry.to_string()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    write(true, &me);
    let me_closed = std::fs::metadata(&me)
        .map(|m| m.permissions().mode() & 0o022 == 0)
        .unwrap_or(false);
    let r = claude_code::run("pre", input.as_bytes(), deps(&home));
    if me_closed {
        assert_eq!(
            (r.exit, r.stdout.as_str(), r.stderr.as_str()),
            (0, "", ""),
            "{r:?}"
        );
    }
    // An entry that fails open, or names another program, is not derm's
    // gate: the hook blocks again.
    write(false, &me);
    assert_eq!(
        claude_code::run("pre", input.as_bytes(), deps(&home)).exit,
        2
    );
    write(true, Path::new("/bin/true"));
    assert_eq!(
        claude_code::run("pre", input.as_bytes(), deps(&home)).exit,
        2
    );
    // Never a record, in any of these.
    assert_eq!(posted.load(std::sync::atomic::Ordering::SeqCst), 0);
    // The post event never blocks.
    let r = claude_code::run("post", input.as_bytes(), deps(&home));
    assert_eq!((r.exit, r.stdout.as_str()), (0, ""));
    let _ = std::fs::remove_dir_all(&home);
}

/// A Rust registration counts only as `"<this program>" hook <agent>
/// <event>` with an event the agent takes (case 227: never a bare `derm`).
#[test]
fn a_rust_registration_names_this_program_by_its_absolute_path() {
    let me = std::env::current_exe().unwrap();
    let m = me.display().to_string();
    let ok = |c: &str| marks::is_derm_rust_command(c, "grok", Some(&me));
    let closed = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&me)
                .map(|x| x.permissions().mode() & 0o022 == 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    assert_eq!(ok(&format!("\"{m}\" hook grok pre")), closed);
    assert!(!ok("derm hook grok pre"));
    assert!(!ok(&format!("\"{m}\" hook grok post")));
    assert!(!ok(&format!("\"{m}\" hook claude-code pre")));
    assert!(!ok(&format!("\"{m}\" hook grok pre; rm -rf /")));
    assert!(!ok("/bin/true hook grok pre"));
}
