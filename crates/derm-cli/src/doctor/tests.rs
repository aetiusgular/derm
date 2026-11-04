//! `derm doctor` against fake homes: a fake agent on PATH, the agents' own
//! files, and the real Claude Code and Codex hooks from this repository as
//! the "installed" gate.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::*;

struct Home {
    root: PathBuf,
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn home(name: &str) -> Home {
    let root = std::env::temp_dir().join(format!(
        "derm-doctor-t-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(root.join("home")).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::create_dir_all(root.join("proj")).unwrap();
    Home { root }
}

fn put(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn program(h: &Home, name: &str, body: &str) {
    let p = h.root.join("bin").join(name);
    put(&p, &format!("#!/bin/sh\n{body}\n"));
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn env(h: &Home) -> Env {
    Env {
        home: Some(h.root.join("home")),
        path: h.root.join("bin").to_string_lossy().into_owned(),
        vars: vec![],
        cwd: Some(h.root.join("proj")),
    }
}

fn probes() -> Probes {
    Probes {
        version: probe_version,
        node: find_on_path("node", &std::env::var("PATH").unwrap_or_default()),
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let t = e.file_type().unwrap();
        let dest = to.join(e.file_name());
        if t.is_dir() {
            if e.file_name() != "node_modules" {
                copy_dir(&e.path(), &dest);
            }
        } else if t.is_file() {
            std::fs::copy(e.path(), &dest).unwrap();
        }
    }
}

/// A copy of the plugin where Claude Code 2.1.311 puts it: its versioned
/// cache under `<config>/plugins/cache` (`b(Ne(),"plugins","cache")` in the
/// binary), with the record pointing there.
fn claude_install(h: &Home, src: &Path) -> PathBuf {
    let dest = h.root.join("home/.claude/plugins/cache/derm/derm/0.1.3");
    copy_dir(src, &dest);
    put(
        &h.root.join("home/.claude/plugins/installed_plugins.json"),
        &json!({"version": 2, "plugins": {"derm@derm": [{"scope": "user", "installPath": dest, "version": "0.1.3"}]}}).to_string(),
    );
    dest
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn version_tokens_are_read_from_rows_and_programs() {
    assert_eq!(version_token("2.1.311, run").as_deref(), Some("2.1.311"));
    assert_eq!(
        version_token("2.1.318 (Claude Code)").as_deref(),
        Some("2.1.318")
    );
    assert_eq!(
        version_token("codex-cli 0.166.0").as_deref(),
        Some("0.166.0")
    );
    assert_eq!(version_token("v0.22.5, source").as_deref(), Some("0.22.5"));
    assert_eq!(
        version_token("2026.10.22, docs").as_deref(),
        Some("2026.10.22")
    );
    assert_eq!(version_token("NF"), None);
    assert_eq!(version_token("x86_64 7"), None);
}

#[test]
fn rows_are_found_by_preset_id_or_orcas_id() {
    assert_eq!(find_row("claude-code").unwrap()["id"], "claude-code");
    assert_eq!(find_row("claude").unwrap()["id"], "claude-code");
    assert_eq!(find_row("aug").unwrap()["id"], "auggie");
    assert_eq!(find_row("cline").unwrap()["id"], "cline");
    assert!(find_row("vim").is_none());
}

#[test]
fn a_version_other_than_the_rows_is_unverified() {
    // Case 81.
    let h = home("ver");
    program(&h, "claude", "echo '2.1.318 (Claude Code)'");
    let row = find_row("claude-code").unwrap();
    let r = doctor(&row, &env(&h), &probes(), false, false);
    assert_eq!(r["version"]["state"], "unverified");
    assert_eq!(r["version"]["installed"], "2.1.318");
    assert_eq!(r["version"]["verifiedAt"], "2.1.311");
    assert!(r["problems"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p.as_str().unwrap().contains("unverified at 2.1.318")));
    assert!(render(&r).contains("unverified at 2.1.318"));
    // The same version: nothing to say about it.
    program(&h, "claude", "echo '2.1.311 (Claude Code)'");
    let r = doctor(&row, &env(&h), &probes(), false, false);
    assert_eq!(r["version"]["state"], "matches");
    // Not installed: said, not a problem.
    let h2 = home("ver-none");
    let r = doctor(&row, &env(&h2), &probes(), false, false);
    assert_eq!(r["version"]["state"], "not found");
    // A shim that exits non-zero is not a working install (case 102).
    program(&h2, "claude", "echo 'claude: not found'; exit 127");
    let r = doctor(&row, &env(&h2), &probes(), false, false);
    assert_eq!(r["version"]["state"], "unknown");
}

#[test]
fn switches_that_turn_the_gate_off_are_named() {
    let h = home("shadow");
    let row = find_row("claude-code").unwrap();
    put(
        &h.root.join("proj/.claude/settings.json"),
        r#"{"disableAllHooks": true}"#,
    );
    put(
        &h.root.join("proj/.claude/settings.local.json"),
        r#"{"enabledPlugins": {"derm@derm": false}}"#,
    );
    put(&h.root.join("proj/.mcp.json"), "{}");
    let r = doctor(&row, &env(&h), &probes(), false, false);
    let sh = r["shadows"].as_array().unwrap();
    let whats: Vec<&str> = sh.iter().map(|s| s["what"].as_str().unwrap()).collect();
    assert!(
        whats
            .iter()
            .any(|w| w.contains("disableAllHooks") && w.contains("project")),
        "{whats:?}"
    );
    assert!(
        whats
            .iter()
            .any(|w| w.contains("enabledPlugins") && w.contains("local")),
        "{whats:?}"
    );
    assert!(
        whats.iter().any(|w| w.contains("project-level config")),
        "{whats:?}"
    );
    let problems = r["problems"].as_array().unwrap();
    let off: Vec<_> = problems
        .iter()
        .filter(|p| {
            let p = p.as_str().unwrap();
            p.contains("disableAllHooks") || p.contains("enabledPlugins")
        })
        .collect();
    assert_eq!(off.len(), 2, "{problems:?}");
    // The project-level file is listed, not counted as a switch.
    assert!(!problems
        .iter()
        .any(|p| p.as_str().unwrap().contains("project-level")));
    assert!(problems
        .iter()
        .any(|p| p.as_str().unwrap().contains("not registered")));
    // Droid's hooks.json shadows its settings.json.
    let row = find_row("droid").unwrap();
    put(&h.root.join("home/.factory/hooks.json"), "{}");
    let r = doctor(&row, &env(&h), &probes(), false, false);
    assert_eq!(r["shadows"][0]["turnsOff"], json!(true));
    assert!(r["shadows"][0]["what"]
        .as_str()
        .unwrap()
        .contains("hooks.json"));
}

#[test]
fn the_installed_claude_code_gate_denies_a_denied_call() {
    let h = home("cc-gate");
    claude_install(&h, &repo().join("packages/derm-claude-plugin"));
    let r = run_fixture("claude-code", &env(&h), &probes());
    assert_eq!(r["state"], "pass", "{r}");
    // A hook that lets everything through fails the check.
    let fake = h.root.join("fake-plugin");
    put(
        &fake.join("bin/derm-hook.mjs"),
        "process.stdout.write('{}');",
    );
    claude_install(&h, &fake);
    let r = run_fixture("claude-code", &env(&h), &probes());
    assert_eq!(r["state"], "fail", "{r}");
    // A hook that blocks only because it broke is not a pass.
    put(
        &fake.join("bin/derm-hook.mjs"),
        "process.stderr.write('derm: hook error: boom\\n'); process.exitCode = 2;",
    );
    claude_install(&h, &fake);
    let r = run_fixture("claude-code", &env(&h), &probes());
    assert_eq!(r["state"], "fail-closed", "{r}");
}

#[test]
fn the_installed_codex_gate_denies_a_denied_call() {
    let h = home("cx-gate");
    let cache = h.root.join("home/.codex/plugins/cache/derm/derm");
    copy_dir(
        &repo().join("packages/derm-codex-plugin"),
        &cache.join("0.1.3"),
    );
    let r = run_fixture("codex", &env(&h), &probes());
    assert_eq!(r["state"], "pass", "{r}");
    // Nothing installed: not run, and why.
    let h2 = home("cx-none");
    let r = run_fixture("codex", &env(&h2), &probes());
    assert_eq!(r["state"], "not run");
    // An agent with no runner says so.
    let r = run_fixture("gemini", &env(&h2), &probes());
    assert_eq!(r["state"], "not run");
    assert!(r["why"].as_str().unwrap().contains("no fixture runner"));
}

#[test]
fn a_planned_gate_is_said_and_live_is_not_built() {
    let h = home("planned");
    // Cline's gate is built since wave 4 (lane P, integration w4); Rovo Dev
    // has none after wave 4 and stays the planned example.
    assert_eq!(
        find_row("cline").unwrap()["coverage"]["gate"]["status"],
        "built"
    );
    let row = find_row("rovo-dev").unwrap();
    let r = doctor(&row, &env(&h), &probes(), true, false);
    assert_eq!(r["gate"]["status"], "planned");
    assert_eq!(r["registered"], "n/a");
    assert_eq!(r["gateRun"]["state"], "not run");
    assert!(r["live"].as_str().unwrap().starts_with("not built"));
    let text = render(&r);
    assert!(text.contains("planned, wave 4 lane Q"), "{text}");
    assert!(text.contains("nothing to do"), "{text}");
}

#[test]
fn usage_errors_exit_2() {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(main(&s(&[])), 2);
    assert_eq!(main(&s(&["--bogus"])), 2);
    assert_eq!(main(&s(&["vim"])), 2);
    assert_eq!(main(&s(&["pi", "codex"])), 2);
}

#[test]
fn the_report_is_kept_private_and_a_link_is_never_followed() {
    use std::os::unix::fs::MetadataExt;
    let h = home("save");
    let home_dir = h.root.join("home");
    let r = json!({"agent": "codex", "problems": []});
    save(&home_dir, &r).unwrap();
    let p = report_path(&home_dir, "codex");
    assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(p.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );
    // Saved again over the old one.
    save(&home_dir, &json!({"agent": "codex", "problems": ["x"]})).unwrap();
    let back: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    assert_eq!(back["problems"], json!(["x"]));
    // A folder that is a link is refused.
    let h2 = home("save-link");
    let target = h2.root.join("elsewhere");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(h2.root.join("home/.derm")).unwrap();
    std::os::unix::fs::symlink(&target, h2.root.join("home/.derm/doctor")).unwrap();
    assert!(save(&h2.root.join("home"), &r).is_err());
    assert!(std::fs::read_dir(&target).unwrap().next().is_none());
    // An id that is not one is refused.
    assert!(save(&home_dir, &json!({"agent": "../x"})).is_err());
}

/// Security review L9: `derm doctor` runs the hook as you, outside any
/// sandbox, so it runs only the copy the agent loads from its own plugin
/// cache, owned by you and writable by no one else.
#[test]
fn the_hook_derm_runs_is_the_agents_own_copy_and_no_other() {
    use std::os::unix::fs::PermissionsExt;
    // An installPath outside the plugin cache: not run.
    let h = home("hook-out");
    put(
        &h.root.join("home/.claude/plugins/installed_plugins.json"),
        &json!({"plugins": {"derm@derm": [{"installPath": repo().join("packages/derm-claude-plugin")}]}}).to_string(),
    );
    let r = run_fixture("claude-code", &env(&h), &probes());
    assert_eq!(r["state"], "not run", "{r}");
    assert!(r["why"].as_str().unwrap().contains("outside"), "{r}");
    // A link in the cache to a copy elsewhere: not run either.
    let link = h.root.join("home/.claude/plugins/cache/derm/derm/0.1.3");
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(repo().join("packages/derm-claude-plugin"), &link).unwrap();
    put(
        &h.root.join("home/.claude/plugins/installed_plugins.json"),
        &json!({"plugins": {"derm@derm": [{"installPath": link}]}}).to_string(),
    );
    let r = run_fixture("claude-code", &env(&h), &probes());
    assert_eq!(r["state"], "not run", "{r}");
    // A copy whose folder others can write: not run.
    let h = home("hook-mode");
    let dest = claude_install(&h, &repo().join("packages/derm-claude-plugin"));
    std::fs::set_permissions(dest.join("bin"), std::fs::Permissions::from_mode(0o777)).unwrap();
    let r = run_fixture("claude-code", &env(&h), &probes());
    assert_eq!(r["state"], "not run", "{r}");
    assert!(r["why"].as_str().unwrap().contains("writable"), "{r}");
    // Codex: the highest version, read as a version; a name that is not one
    // is never picked.
    let h = home("hook-semver");
    let cache = h.root.join("home/.codex/plugins/cache/derm/derm");
    for v in ["0.2.0", "zzz"] {
        put(
            &cache.join(v).join("bin/derm-hook.mjs"),
            "process.stdout.write('{}');",
        );
    }
    copy_dir(
        &repo().join("packages/derm-codex-plugin"),
        &cache.join("0.10.0"),
    );
    let r = run_fixture("codex", &env(&h), &probes());
    assert_eq!(r["state"], "pass", "{r}");
    assert!(
        r["hook"]
            .as_str()
            .unwrap()
            .ends_with("0.10.0/bin/derm-hook.mjs"),
        "{r}"
    );
}

/// Security review L9 and L18: the run is asked for, and the report names
/// the file before anything runs it.
#[test]
fn the_gate_runs_only_when_asked_and_the_file_is_named() {
    let h = home("ask-gate");
    let cache = h.root.join("home/.codex/plugins/cache/derm/derm");
    copy_dir(
        &repo().join("packages/derm-codex-plugin"),
        &cache.join("0.1.3"),
    );
    let row = find_row("codex").unwrap();
    let r = doctor(&row, &env(&h), &probes(), false, false);
    assert_eq!(r["gateRun"]["state"], "not run", "{r}");
    let why = r["gateRun"]["why"].as_str().unwrap();
    assert!(why.contains("--run-gate"), "{why}");
    assert!(why.contains("0.1.3/bin/derm-hook.mjs"), "{why}");
    assert!(render(&r).contains("--run-gate"));
    let r = doctor(&row, &env(&h), &probes(), false, true);
    assert_eq!(r["gateRun"]["state"], "pass", "{r}");
    assert!(
        render(&r).contains("0.1.3/bin/derm-hook.mjs"),
        "{}",
        render(&r)
    );
}
