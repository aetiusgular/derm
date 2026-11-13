//! Integration w6, phase 1 merge: lane 6B's request 1 (`plans/parallel/
//! tk_lane_6B.md`). In the light tier (a hook with no chat token, so no
//! `derm run` and no daemon) a decision record neither the daemon nor the
//! per-chat log kept is a deny: a call is not run unrecorded
//! (`gate::locallog::denies`, `gate::daemon::lost_deny`). With a chat token
//! and a real `derm run` above the hook the record is the daemon's, and a
//! lost one denies nothing (case 86; note AZ B8: under srt a chat's hooks
//! cannot write `~/.derm`); a token alone does not count (W6C-S4).
//!
//! Each dialect family is driven through the real binary: Claude Code, Codex
//! and Gemini (the Claude-format dialects), Cursor (the native runner) and
//! Pi through `derm gate serve`. The log is made unwritable by putting a
//! plain file where `~/.derm/local/` goes, which `locallog::file` refuses.

#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

const TOKEN: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const MARK: &str = "derm's light tier fails closed";

/// A home with an allow-everything policy (0600, outside the work folder,
/// case 226) and, when `broken`, a plain file at `~/.derm/local`.
fn home(name: &str, broken: bool) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "dw6fc-{name}-{}-{}",
        if broken { "broken" } else { "fine" },
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("work")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    let policy = p.join("policy.json");
    std::fs::write(
        &policy,
        r#"{"version":1,"askTimeoutSeconds":1,"rules":[{"tool":"*","action":"allow"}]}"#,
    )
    .unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
    if broken {
        std::fs::create_dir_all(p.join(".derm")).unwrap();
        std::fs::set_permissions(p.join(".derm"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(p.join(".derm/local"), "not a folder").unwrap();
    }
    p
}

fn run(dir: &Path, args: &[&str], stdin: &str, token: bool) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_derm"));
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("DERM_POLICY", dir.join("policy.json"))
        .current_dir(dir.join("work"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if token {
        // A chat token with no daemon behind it: what a `derm run` chat's
        // hook sees after its daemon went away (case 86).
        c.env("DERM_CHAT_TOKEN", TOKEN)
            .env("DERM_DAEMON_SOCKET", dir.join("no-daemon.sock"));
    }
    let mut child = c.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn claude_pre(dir: &Path) -> String {
    json!({
        "session_id": "s-fc", "transcript_path": dir.join("t.jsonl"), "cwd": dir.join("work"),
        "permission_mode": "default", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "toolu_fc1",
    })
    .to_string()
}

fn claude_decision(o: &Output) -> String {
    serde_json::from_slice::<Value>(&o.stdout)
        .ok()
        .and_then(|v| {
            v["hookSpecificOutput"]["permissionDecision"]
                .as_str()
                .map(str::to_string)
        })
        .unwrap_or_else(|| "none".into())
}

fn log_lines(dir: &Path, chat: &str) -> usize {
    std::fs::read_to_string(dir.join(".derm/local").join(format!("{chat}.jsonl")))
        .map(|t| t.lines().count())
        .unwrap_or(0)
}

#[test]
fn claude_code_denies_a_call_its_light_tier_log_could_not_keep() {
    let fine = home("cc", false);
    let o = run(
        &fine,
        &["hook", "claude-code", "pre"],
        &claude_pre(&fine),
        false,
    );
    assert_eq!(claude_decision(&o), "allow", "{}", text(&o));
    assert_eq!(
        log_lines(&fine, "s-fc"),
        1,
        "the light tier kept the record"
    );

    let broken = home("cc", true);
    let o = run(
        &broken,
        &["hook", "claude-code", "pre"],
        &claude_pre(&broken),
        false,
    );
    assert_eq!(claude_decision(&o), "deny", "{}", text(&o));
    assert!(text(&o).contains(MARK), "{}", text(&o));
}

#[test]
fn a_chat_token_with_no_derm_run_above_it_is_still_the_light_tier() {
    // Integration w6's review, W6C-S4: a project's settings can set
    // `DERM_CHAT_TOKEN` (case 227), so a token alone does not make a chat
    // `derm run`'s. Before the fix this call was allowed and ran unrecorded.
    let broken = home("cctoken", true);
    let o = run(
        &broken,
        &["hook", "claude-code", "pre"],
        &claude_pre(&broken),
        true,
    );
    assert_eq!(claude_decision(&o), "deny", "{}", text(&o));
    assert!(text(&o).contains(MARK), "{}", text(&o));
}

/// Runs `derm hook claude-code pre` as `sh -c <inner>` under a real
/// `derm run --no-daemon`, its input the Claude Code call.
fn under_derm_run(broken: &Path, inner: &str) -> Output {
    let derm = env!("CARGO_BIN_EXE_derm");
    let mut child = Command::new(derm)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", broken)
        .env("XDG_RUNTIME_DIR", broken)
        .env("DERM_POLICY", broken.join("policy.json"))
        .current_dir(broken.join("work"))
        .args(["run", "--boundary", "none", "--no-daemon", "--no-tap", "--"])
        .args(["sh", "-c", inner])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(claude_pre(broken).as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn a_project_set_token_under_a_derm_run_that_gave_none_is_still_the_light_tier() {
    // Integration w6's re-review, W6C-R6: `derm run --no-daemon` gives no
    // token, so a token set below it (as a project's settings set one, case
    // 227) is not the run's. Before the fix a `derm run` ancestor alone was
    // enough, and this call ran unrecorded.
    let broken = home("ccrun", true);
    let inner = format!(
        "DERM_CHAT_TOKEN={TOKEN} DERM_DAEMON_SOCKET={} exec {} hook claude-code pre",
        broken.join("no-daemon.sock").display(),
        env!("CARGO_BIN_EXE_derm")
    );
    let o = under_derm_run(&broken, &inner);
    assert_eq!(claude_decision(&o), "deny", "{}", text(&o));
    assert!(text(&o).contains(MARK), "{}", text(&o));
}

#[test]
fn a_token_derm_runs_child_was_started_with_keeps_a_lost_record_from_denying() {
    // Case 86: a `derm run` chat whose daemon went away. The process `derm
    // run` started (here `sh`, through `env`, which execs it in its own pid)
    // was started with the token, as a harness is when the daemon gives one,
    // so the record was the daemon's and its loss denies nothing.
    let broken = home("ccgave", true);
    let inner = format!("{} hook claude-code pre", env!("CARGO_BIN_EXE_derm"));
    let o = under_derm_run(
        &broken,
        &format!(
            "exec env DERM_CHAT_TOKEN={TOKEN} DERM_DAEMON_SOCKET={} sh -c '{inner}'",
            broken.join("no-daemon.sock").display()
        ),
    );
    assert_eq!(claude_decision(&o), "allow", "{}", text(&o));
    assert!(!text(&o).contains(MARK), "{}", text(&o));
}

#[test]
fn a_token_other_than_the_one_derm_run_gave_is_still_the_light_tier() {
    // W6C-R6: a project's settings replace the token in a real `derm run`
    // chat (case 227). The hook's token is not the one the run gave.
    let broken = home("ccother", true);
    let other = "3".repeat(64);
    let inner = format!(
        "DERM_CHAT_TOKEN={other} exec {} hook claude-code pre",
        env!("CARGO_BIN_EXE_derm")
    );
    let o = under_derm_run(
        &broken,
        &format!(
            "exec env DERM_CHAT_TOKEN={TOKEN} DERM_DAEMON_SOCKET={} sh -c '{inner}'",
            broken.join("no-daemon.sock").display()
        ),
    );
    assert_eq!(claude_decision(&o), "deny", "{}", text(&o));
    assert!(text(&o).contains(MARK), "{}", text(&o));
}

#[test]
fn codex_denies_a_call_its_light_tier_log_could_not_keep() {
    let input = |d: &Path| {
        json!({
            "session_id": "s-fc", "turn_id": "t-1", "transcript_path": null, "cwd": d.join("work"),
            "hook_event_name": "PreToolUse", "model": "m", "permission_mode": "default",
            "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "call_fc1",
        })
        .to_string()
    };
    let fine = home("codex", false);
    let o = run(&fine, &["hook", "codex", "pre"], &input(&fine), false);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(log_lines(&fine, "s-fc"), 1);

    // Codex's block is exit 2 with the reason on stderr (`codex::block_pre`).
    let broken = home("codex", true);
    let o = run(&broken, &["hook", "codex", "pre"], &input(&broken), false);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains(MARK), "{}", text(&o));
}

#[test]
fn gemini_denies_a_call_its_light_tier_log_could_not_keep() {
    let input = |d: &Path| {
        json!({
            "session_id": "s-fc", "transcript_path": d.join("t.json"), "cwd": d.join("work"),
            "hook_event_name": "BeforeTool", "timestamp": "2026-11-12T12:00:00.000Z",
            "tool_name": "run_shell_command", "tool_input": {"command": "ls"},
        })
        .to_string()
    };
    let fine = home("gemini", false);
    let o = run(&fine, &["hook", "gemini", "before"], &input(&fine), false);
    assert!(!text(&o).contains(MARK), "{}", text(&o));

    let broken = home("gemini", true);
    let o = run(
        &broken,
        &["hook", "gemini", "before"],
        &input(&broken),
        false,
    );
    assert!(text(&o).contains(MARK), "{}", text(&o));
}

#[test]
fn cursor_denies_a_call_its_light_tier_log_could_not_keep() {
    let input = r#"{"conversation_id":"c-fc","generation_id":"g","cursor_version":"2026.11.10","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"ls"}}"#;
    let fine = home("cursor", false);
    let o = run(&fine, &["hook", "cursor", "pre"], input, false);
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "{\"permission\":\"allow\"}\n",
        "{}",
        text(&o)
    );

    let broken = home("cursor", true);
    let o = run(&broken, &["hook", "cursor", "pre"], input, false);
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(out.contains("\"permission\":\"deny\""), "{}", text(&o));
    assert!(text(&o).contains(MARK), "{}", text(&o));
}

#[test]
fn gate_serve_denies_a_decision_its_light_tier_log_could_not_keep() {
    let lines = format!(
        "{}\n{}\n",
        json!({"id": 0, "op": "hello", "agent": "pi", "protocol": 1}),
        json!({"id": 1, "op": "decide", "call": {"tool": "bash", "input": {"command": "ls"}, "chat": "s-fc"}}),
    );
    let action = |o: &Output| -> (String, String) {
        let reply: Value = String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["id"] == 1)
            .unwrap_or(Value::Null);
        (
            reply["action"].as_str().unwrap_or("none").to_string(),
            reply["reason"].as_str().unwrap_or("").to_string(),
        )
    };
    let fine = home("serve", false);
    let o = run(&fine, &["gate", "serve", "--agent", "pi"], &lines, false);
    assert_eq!(action(&o).0, "allow", "{}", text(&o));

    let broken = home("serve", true);
    let o = run(&broken, &["gate", "serve", "--agent", "pi"], &lines, false);
    let (a, why) = action(&o);
    assert_eq!(a, "deny", "{}", text(&o));
    assert!(why.contains(MARK), "{why}");
}
