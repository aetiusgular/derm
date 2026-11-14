//! One red test per wave 6 contract (the wave 6 base, 12 Nov 2026), at the
//! process boundary so they build on the base and fail there:
//! `contracts/sandbox.md` (lane 6A), `contracts/events.md` section 6.4 (6B,
//! the light tier) and 6.5 (6E, `derm audit verify`), `contracts/policy.md`
//! section 9 (6D, taint), `contracts/eval.md` (6F's runner), and E0's ranked
//! list (`plans/parallel/tk_eval_baseline.md`): the gate and preset fixes
//! R-E0-1 to R-E0-5 (integration's: `gate/` and `setup/presets/` are no
//! lane's) and R-E0-6 (6D). Lane 6C's is `crates/derm-egress/tests/contract.rs`.
//!
//! Built only with the feature while they fail on purpose:
//! `cargo test -p derm-cli --features w6-red --test contracts_w6`. Each test
//! names its owner; integration makes the feature default at the close. No
//! lane edits this file; a case a lane finds wrong is a request.
//!
//! Inputs come from the real tools: Claude Code 2.1.322's hook inputs
//! (`contracts/fixtures/hook-w6/claude-code-2.1.322.json`, recorded by the
//! base), MoatBench 0.19.0's scenarios (`contracts/fixtures/eval/
//! moatbench-e0-allowed.json`), and the hook-case recordings' Gemini shape
//! (`contracts/fixtures/hook-cases/5bA.json`).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read_json(rel: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(repo().join(rel)).unwrap()).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = std::env::temp_dir().join(format!("dw6-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("work")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p
}

fn derm() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_derm"));
    c.env_clear();
    c.env("PATH", "/usr/bin:/bin");
    c
}

/// The workspace-write preset's `policy` object alone, as `derm setup`
/// writes it (the preset file's other keys fail the policy schema), 0600,
/// outside the work folder (case 226).
fn preset_policy(dir: &Path, preset: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p: Value = read_json(&format!("crates/derm-cli/src/setup/presets/{preset}.json"));
    let path = dir.join("policy.json");
    std::fs::write(&path, serde_json::to_string(&p["policy"]).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn hook(dir: &Path, policy: &Path, agent: &str, event: &str, input: &Value) -> Output {
    use std::io::Write;
    let mut child = derm()
        .args(["hook", agent, event])
        .env("HOME", dir)
        .env("DERM_POLICY", policy)
        .current_dir(dir.join("work"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Claude Code's decision word, or `none` when the reply holds none.
fn claude_decision(out: &Output) -> String {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<Value>(text.trim())
        .ok()
        .and_then(|v| {
            v["hookSpecificOutput"]["permissionDecision"]
                .as_str()
                .map(str::to_string)
        })
        .unwrap_or_else(|| "none".into())
}

/// A MoatBench step as Claude Code's PreToolUse input, in the shape the real
/// 2.1.322 sends (the recorded fixture's keys).
fn claude_pre(dir: &Path, session: &str, n: usize, step: &Value) -> Value {
    let home = dir.to_str().unwrap();
    let work = dir.join("work");
    let abs = |p: &str| -> String {
        if let Some(rest) = p.strip_prefix("~/") {
            format!("{home}/{rest}")
        } else if p.starts_with('/') {
            p.to_string()
        } else {
            work.join(p).to_string_lossy().into_owned()
        }
    };
    let (tool, input) = if let Some(c) = step.get("shell").and_then(Value::as_str) {
        (
            "Bash".to_string(),
            json!({"command": c, "description": "step"}),
        )
    } else if let Some(p) = step.get("read").and_then(Value::as_str) {
        ("Read".to_string(), json!({"file_path": abs(p)}))
    } else if let Some(p) = step.get("write").and_then(Value::as_str) {
        (
            "Write".to_string(),
            json!({"file_path": abs(p), "content": "x\n"}),
        )
    } else if let Some(p) = step.get("edit").and_then(Value::as_str) {
        (
            "Edit".to_string(),
            json!({"file_path": abs(p), "old_string": "a", "new_string": "b"}),
        )
    } else if let Some(m) = step.get("mcp") {
        (
            format!(
                "mcp__{}__{}",
                m["server"].as_str().unwrap(),
                m["tool"].as_str().unwrap()
            ),
            m["args"].clone(),
        )
    } else {
        panic!("a step kind this test does not map: {step}")
    };
    json!({
        "session_id": session,
        "transcript_path": format!("{home}/t.jsonl"),
        "cwd": work.to_string_lossy(),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
        "tool_use_id": format!("toolu_w6_{n}"),
        "prompt_id": "p-1",
    })
}

/// The same call's PostToolUse, with an empty result in the tool's shape.
fn claude_post(pre: &Value) -> Value {
    let mut post = pre.clone();
    post["hook_event_name"] = json!("PostToolUse");
    post["tool_response"] = json!({"stdout": "", "stderr": "", "interrupted": false});
    post["duration_ms"] = json!(5);
    post
}

fn e0_scenarios(owner: &str) -> Vec<Value> {
    read_json("contracts/fixtures/eval/moatbench-e0-allowed.json")["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["owner"] == owner)
        .cloned()
        .collect()
}

/// Replays a scenario's steps in one chat; returns the e0Allowed steps'
/// decisions.
fn replay(name: &str, s: &Value) -> Vec<(usize, String)> {
    replay_in(&scratch(name), name, s)
}

/// The same, in a home the caller prepared (a `settings.json` in it).
fn replay_in(dir: &Path, name: &str, s: &Value) -> Vec<(usize, String)> {
    let dir = dir.to_path_buf();
    let policy = preset_policy(&dir, "workspace-write");
    let session = format!("e0-{name}");
    let steps = s["steps"].as_array().unwrap();
    let allowed: Vec<usize> = s["e0Allowed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_u64().unwrap() as usize)
        .collect();
    let mut got = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let pre = claude_pre(&dir, &session, i, step);
        let out = hook(&dir, &policy, "claude-code", "pre", &pre);
        if allowed.contains(&i) {
            got.push((i, claude_decision(&out)));
        }
        let _ = hook(&dir, &policy, "claude-code", "post", &claude_post(&pre));
    }
    got
}

// --- E0's requests to the base: gate and presets (R-E0-1, 2, 3, 5) --------

/// Owner: integration (the gate's command reading and the presets; R-E0-1,
/// R-E0-2, R-E0-3, R-E0-5). Each step derm 0.1.3's default allowed in E0 is
/// at least an ask.
#[test]
fn e0_gate_misses_are_no_longer_allowed() {
    let mut misses = Vec::new();
    for s in e0_scenarios("gate") {
        let id = s["id"].as_str().unwrap().to_string();
        for (i, d) in replay(&id, &s) {
            if d == "allow" || d == "none" {
                misses.push(format!("{id} step {i}: {d}"));
            }
        }
    }
    assert!(misses.is_empty(), "still allowed: {misses:#?}");
}

/// Owner: integration (per-agent aliases, R-E0-4). Gemini CLI 0.68.0's
/// `run_shell_command` and `read_file` meet the preset's bash and read
/// rules, so `git status` and a project read are allowed, not asked.
#[test]
fn e0_gemini_tool_names_meet_the_presets_rules() {
    let dir = scratch("gemini");
    let policy = preset_policy(&dir, "workspace-write");
    let work = dir.join("work");
    for (tool, input) in [
        ("run_shell_command", json!({"command": "git status"})),
        (
            "read_file",
            json!({"file_path": work.join("README.md").to_string_lossy()}),
        ),
    ] {
        let call = json!({
            "session_id": "g-1",
            "transcript_path": "/t.json",
            "cwd": work.to_string_lossy(),
            "hook_event_name": "BeforeTool",
            "timestamp": "2026-11-12T12:00:00.000Z",
            "tool_name": tool,
            "tool_input": input,
        });
        let out = hook(&dir, &policy, "gemini", "before", &call);
        let reply: Value =
            serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap_or(json!({}));
        assert!(
            reply.get("decision").is_none() || reply["decision"] == "allow",
            "{tool}: {reply}"
        );
    }
}

// --- Lane 6D: taint and session-written code (R-E0-6) ----------------------

/// Owner: lane 6D (`contracts/policy.md` section 9). The five E0 scenarios
/// whose miss is a session's own taint or its own code, replayed in one chat
/// with no daemon: the light tier's taint file decides.
#[test]
fn e0_taint_misses_are_reviewed() {
    let mut misses = Vec::new();
    for s in e0_scenarios("6D") {
        let id = s["id"].as_str().unwrap().to_string();
        for (i, d) in replay(&id, &s) {
            if d == "allow" || d == "none" {
                misses.push(format!("{id} step {i}: {d}"));
            }
        }
    }
    assert!(misses.is_empty(), "still allowed: {misses:#?}");
}

/// Owner: lane 6D (`contracts/policy.md` section 9: all three verdicts,
/// Tony's call of 12 Nov). With the light tier's setting at `deny`, the
/// agent-written script E0 found allowed is denied; at `record`, it runs and
/// the chat's log holds a `taint.review` that says what it would have been.
#[test]
fn each_taint_verdict_does_what_it_says() {
    use std::os::unix::fs::PermissionsExt;
    let s = e0_scenarios("6D")
        .into_iter()
        .find(|s| s["id"] == "agent-written-shell-script-runs")
        .unwrap();
    for (verdict, want) in [("deny", "deny"), ("record", "allow")] {
        let name = format!("verdict-{verdict}");
        let dir = scratch(&name);
        std::fs::create_dir_all(dir.join(".derm")).unwrap();
        std::fs::set_permissions(dir.join(".derm"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let settings = dir.join(".derm/settings.json");
        std::fs::write(
            &settings,
            format!(r#"{{"version":1,"taint":{{"verdict":"{verdict}"}}}}"#),
        )
        .unwrap();
        std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o600)).unwrap();
        let got = replay_in(&dir, &name, &s);
        assert!(got.iter().all(|(_, d)| d == want), "{verdict}: {got:?}");
        if verdict == "record" {
            let log = std::fs::read_to_string(dir.join(format!(".derm/local/e0-{name}.jsonl")))
                .unwrap_or_default();
            let review = log
                .lines()
                .filter_map(|l| derm_core::audit_chain::parse(l).ok())
                .find(|l| l.kind == "taint.review");
            let r = review.expect("record writes a taint.review");
            assert_eq!(r.record["detail"]["verdict"], "record");
            assert_eq!(r.record["detail"]["wouldBe"], "ask");
        }
    }
}

// --- Lane 6B: the light tier ------------------------------------------------

/// Owner: lane 6B (`contracts/events.md` section 6.4). With no daemon, the
/// real Claude Code 2.1.322 PreToolUse and PostToolUse inputs leave two chain
/// v2 lines in `~/.derm/local/<session>.jsonl`, `approval` then `tool.call`.
#[test]
fn a_hook_with_no_daemon_appends_chain_v2_lines() {
    let dir = scratch("light");
    let policy = preset_policy(&dir, "workspace-write");
    let fx = read_json("contracts/fixtures/hook-w6/claude-code-2.1.322.json");
    let work = dir.join("work");
    let mut session = String::new();
    for input in fx["inputs"].as_array().unwrap() {
        let text = input
            .to_string()
            .replace("{WORK}", work.to_str().unwrap())
            .replace("{CONFIG}", dir.join("cfg").to_str().unwrap())
            .replace("{T}", dir.to_str().unwrap());
        let v: Value = serde_json::from_str(&text).unwrap();
        session = v["session_id"].as_str().unwrap().to_string();
        let event = if v["hook_event_name"] == "PreToolUse" {
            "pre"
        } else {
            "post"
        };
        hook(&dir, &policy, "claude-code", event, &v);
    }
    let log = dir.join(".derm/local").join(format!("{session}.jsonl"));
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{}", log.display());
    derm_core::audit_chain::verify(&lines, None, None).unwrap();
    let kinds: Vec<String> = lines
        .iter()
        .map(|l| derm_core::audit_chain::parse(l).unwrap().kind)
        .collect();
    assert_eq!(kinds, ["approval", "tool.call"]);
}

/// Owner: lane 6B. `derm init --dry-run` exits 0 and writes nothing under
/// the home it was given.
#[test]
fn derm_init_dry_run_writes_nothing() {
    let dir = scratch("init");
    let out = derm()
        .args(["init", "--dry-run"])
        .env("HOME", &dir)
        .current_dir(dir.join("work"))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dir.join(".derm").exists());
}

// --- Lane 6E: `derm audit verify` -------------------------------------------

/// Owner: lane 6E (`contracts/events.md` section 6.5, case 221). The fixture
/// chain verifies against its head; each tampered copy fails.
#[test]
fn derm_audit_verify_holds_the_fixture_chain() {
    let dir = scratch("verify");
    let fx = repo().join("contracts/fixtures/audit");
    let good = std::fs::read_to_string(fx.join("chain-v2.jsonl")).unwrap();
    let head = derm_core::audit_chain::parse(good.lines().last().unwrap()).unwrap();
    let anchor = format!("{}:{}", head.seq, head.hash);
    let cases: Value =
        serde_json::from_str(&std::fs::read_to_string(fx.join("tampered.json")).unwrap()).unwrap();
    for (i, c) in cases["cases"].as_array().unwrap().iter().enumerate() {
        let file = dir.join(format!("case{i}.jsonl"));
        let lines: Vec<&str> = c["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect();
        std::fs::write(&file, lines.join("\n") + "\n").unwrap();
        let out = derm()
            .args(["audit", "verify"])
            .arg(&file)
            .args(["--anchor", &anchor])
            .env("HOME", &dir)
            .output()
            .unwrap();
        let want = if c["breaksAt"].is_null() { 0 } else { 1 };
        assert_eq!(out.status.code(), Some(want), "{}", c["name"]);
    }
}

// --- Lane 6A: the Standard tier ---------------------------------------------

fn dry_run(dir: &Path, args: &[&str]) -> Output {
    derm()
        .arg("run")
        .args(args)
        .env("HOME", dir)
        .env("PATH", "/usr/bin:/bin:/tmp/cli/node_modules/.bin")
        .current_dir(dir.join("work"))
        .output()
        .unwrap()
}

/// Owner: lane 6A (`contracts/sandbox.md` sections 1 and 2). Claude Code's
/// block goes in by `--settings <file>`, and the chat says its tier.
#[test]
fn the_standard_tier_gives_claude_code_its_block_by_settings_flag() {
    let dir = scratch("std-claude");
    let out = dry_run(
        &dir,
        &[
            "claude-code",
            "--boundary",
            "none",
            "--tier",
            "standard",
            "--dry-run",
            "--no-daemon",
            "--",
            "-p",
            "hi",
        ],
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Box test w6, BW6-1: where Ubuntu's AppArmor setting kills every
    // command Claude Code's sandbox runs (CI's Ubuntu runner has
    // `kernel.apparmor_restrict_unprivileged_userns` at 1), the tier is
    // refused before anything starts, naming why.
    if host_kills_claude_codes_commands() {
        assert_eq!(out.status.code(), Some(2), "{all}");
        assert!(all.contains("cannot run a command on this host"), "{all}");
        return;
    }
    assert_eq!(out.status.code(), Some(0), "{all}");
    assert!(all.contains("\"--settings\""), "{all}");
    assert!(all.contains("tier: standard"), "{all}");
}

/// The facts `preflight::apparmor_note_for` reads for BW6-1, as this test
/// can read them: Ubuntu's `bwrap-userns-restrict` with `/usr/bin/bwrap`
/// first on PATH, or the userns sysctl at 1.
fn host_kills_claude_codes_commands() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let sysctl = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .is_ok_and(|v| v.trim() == "1");
    let profile = std::path::Path::new("/etc/apparmor.d/bwrap-userns-restrict").exists();
    let first_bwrap = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .find_map(|d| {
            let p = std::path::Path::new(d).join("bwrap");
            p.exists().then(|| std::fs::canonicalize(&p).unwrap_or(p))
        });
    let ubuntu_bwrap = first_bwrap
        .as_deref()
        .is_none_or(|b| b == std::path::Path::new("/usr/bin/bwrap"));
    (profile && ubuntu_bwrap) || (!profile && sysctl)
}

/// Owner: lane 6A (`contracts/sandbox.md` section 3). Codex's profile goes
/// in by `-c` pairs at derm's own `-c` level: right after a leading session
/// subcommand, beside the tap's and the export's pairs (`run/args.rs`
/// `codex_config_split`), so every flag derm adds sits on one side of it
/// (case 184). Corrected at the wave 6 phase 1 merge (lane 6A's request
/// 6A-3): the base asked for before `exec`, which on Codex 0.163.0 would let
/// clap drop the root's copy when the tap's pairs follow `exec`; Codex
/// 0.167.2 keeps both sides (lane 6A, run).
#[test]
fn the_standard_tier_gives_codex_its_profile_by_config_overrides() {
    let dir = scratch("std-codex");
    let out = dry_run(
        &dir,
        &[
            "codex",
            "--boundary",
            "none",
            "--tier",
            "standard",
            "--dry-run",
            "--no-daemon",
            "--",
            "exec",
            "hi",
        ],
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0), "{all}");
    let argv = all
        .lines()
        .find_map(|l| l.strip_prefix("argv: "))
        .unwrap_or_default();
    let words: Vec<String> = serde_json::from_str(argv).unwrap_or_default();
    let exec = words
        .iter()
        .position(|w| w == "exec")
        .expect("the argv holds exec");
    assert_eq!(
        words.get(exec + 1..exec + 3),
        Some(&["-c".to_string(), "default_permissions=\"derm\"".to_string()][..]),
        "{all}"
    );
    assert!(
        !words[..exec]
            .iter()
            .any(|w| w.contains("default_permissions")),
        "nothing of derm's before exec: {all}"
    );
}

/// Owner: lane 6A (case 214, AZ-7). A project's `excludedCommands` refuses
/// the Standard tier for Claude Code, naming the key.
#[test]
fn a_projects_excluded_commands_refuses_the_standard_tier() {
    let dir = scratch("std-excluded");
    let claude = dir.join("work/.claude");
    std::fs::create_dir_all(&claude).unwrap();
    std::fs::write(
        claude.join("settings.json"),
        r#"{"sandbox":{"excludedCommands":["cat *"]}}"#,
    )
    .unwrap();
    let out = dry_run(
        &dir,
        &[
            "claude-code",
            "--boundary",
            "none",
            "--tier",
            "standard",
            "--dry-run",
            "--no-daemon",
            "--",
            "-p",
            "hi",
        ],
    );
    assert_ne!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("excludedCommands"));
}

/// Owner: lane 6A (case 215, note AZ A8). Under srt the vendor sandbox is
/// off and derm says it runs one tier.
#[test]
fn the_standard_tier_under_srt_runs_one_tier_and_says_which() {
    let dir = scratch("std-srt");
    let out = dry_run(
        &dir,
        &[
            "claude-code",
            "--boundary",
            "srt",
            "--tier",
            "standard",
            "--dry-run",
            "--no-daemon",
            "--",
            "-p",
            "hi",
        ],
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(all.contains("one tier: whole (srt)"), "{all}");
}

// --- Lane 6F: the eval runner -----------------------------------------------

/// Owner: lane 6F (`contracts/eval.md`). The runner lists the MoatBench
/// scenarios E0 found allowed, by id.
#[test]
fn the_eval_runner_lists_the_e0_scenarios() {
    let out = Command::new("node")
        .args(["tests/eval/run.mjs", "--suite", "moatbench", "--list"])
        .current_dir(repo())
        .output();
    let text = out
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    for s in e0_scenarios("gate").iter().chain(e0_scenarios("6D").iter()) {
        let id = s["id"].as_str().unwrap();
        assert!(text.lines().any(|l| l.trim() == id), "{id} not listed");
    }
}
