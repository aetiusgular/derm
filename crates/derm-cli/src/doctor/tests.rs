//! `derm doctor` against fake homes: a fake agent on PATH, the agents' own
//! files, and the real Claude Code and Codex hooks from this repository as
//! the "installed" gate.

#[cfg(unix)]
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

#[cfg(unix)]
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

/// A stand-in for derm at `~/.local/bin/derm`, where the plugins' launcher
/// finds it (wave 5b lane 5bF): it answers a shell call as `derm hook
/// <agent> pre` answers one a policy denies, in that agent's own form
/// (Claude Code's deny decision, Codex's exit 2 with the reason on stderr,
/// Gemini's JSON deny), and records its argv. The real derm answers the
/// same call in the contract checks (`tests/cli-contract/checks/5bF/`).
/// Built on every OS, since the tests that call it run on Windows too
/// (they were among the Windows job's failures before wave 5b); the modes
/// are Unix-only.
fn derm_at_home(h: &Home) {
    let bin = h.root.join("home/.local/bin");
    let body = "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$HOME/derm-argv\"\ncat >/dev/null\ncase \"$2\" in\nclaude-code) printf '%s\\n' '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"derm: rule bash deny\"}}' ;;\ncodex) echo 'derm: rule bash deny' >&2; exit 2 ;;\ngemini) printf '%s\\n' '{\"decision\":\"deny\",\"reason\":\"derm: rule bash deny\"}'; exit 2 ;;\nesac\n";
    put(&bin.join("derm"), body);
    #[cfg(unix)]
    for p in [
        h.root.join("home"),
        h.root.join("home/.local"),
        bin.clone(),
        bin.join("derm"),
    ] {
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
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

#[cfg(unix)]
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
    derm_at_home(&h);
    let dest = claude_install(&h, &repo().join("packages/derm-claude-plugin"));
    let r = run_fixture("claude-code", &env(&h), &probes());
    assert_eq!(r["state"], "pass", "{r}");
    std::fs::remove_dir_all(&dest).unwrap();
    // The launcher ran `derm hook claude-code pre` from ~/.local/bin.
    assert!(
        r["hook"].as_str().unwrap().ends_with("hooks/derm-gate.sh"),
        "{r}"
    );
    assert_eq!(
        std::fs::read_to_string(h.root.join("home/derm-argv")).unwrap(),
        "hook claude-code pre\n"
    );
    // A plugin from before wave 5b (only bin/derm-hook.mjs) is still run,
    // with node, as before.
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
    derm_at_home(&h);
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
    let r = run_fixture("crush", &env(&h2), &probes());
    assert_eq!(r["state"], "not run");
    assert!(r["why"].as_str().unwrap().contains("no fixture runner"));
}

/// Wave 5b lane 5bF: Gemini's extension, copied where Gemini installs it,
/// runs the launcher with Gemini's own input, and its JSON deny passes.
#[cfg(unix)]
#[test]
fn the_installed_gemini_gate_denies_a_denied_call() {
    let h = home("gm-gate");
    derm_at_home(&h);
    let r = run_fixture("gemini", &env(&h), &probes());
    assert_eq!(r["state"], "not run", "{r}");
    copy_dir(
        &repo().join("packages/derm-gemini-extension"),
        &h.root.join("home/.gemini/extensions/derm"),
    );
    let r = run_fixture("gemini", &env(&h), &probes());
    assert_eq!(r["state"], "pass", "{r}");
    assert_eq!(
        std::fs::read_to_string(h.root.join("home/derm-argv")).unwrap(),
        "hook gemini before\n"
    );
}

/// Case 227 (wave 5b lane 5bF): a registration that finds derm's gate, or
/// its node, on PATH is a problem with the fix; one naming derm by its
/// absolute path is not.
#[cfg(unix)]
#[test]
fn a_registration_that_finds_the_gate_on_path_is_a_problem() {
    let h = home("on-path");
    let crush = h.root.join("home/.config/crush/crush.json");
    let mut e = env(&h);
    let line = |cmd: &str| {
        format!(
            "{{\"hooks\":{{\"PreToolUse\":[{{\"name\":\"derm-gate\",\"command\":{}}}]}}}}",
            serde_json::to_string(cmd).unwrap()
        )
    };
    for (cmd, want) in [
        (
            "node --no-warnings \"/x/derm-hooks-native/bin/derm-hook.mjs\" crush",
            Some("before wave 5b"),
        ),
        ("derm hook crush pre", Some("found on PATH")),
        ("\"derm\" hook crush pre", Some("found on PATH")),
        ("/usr/local/bin/derm hook crush pre", None),
        ("\"/opt/x/derm\" hook crush pre", None),
    ] {
        put(&crush, &line(cmd));
        let p = stale_registrations("crush", &e);
        match want {
            Some(w) => {
                assert_eq!(p.len(), 1, "{cmd}: {p:?}");
                assert!(
                    p[0].contains(w) && p[0].contains("derm connect crush --gate --write"),
                    "{cmd}: {p:?}"
                );
            }
            None => assert!(p.is_empty(), "{cmd}: {p:?}"),
        }
    }
    // XDG_CONFIG_HOME moves the file, as derm connect reads it.
    let xdg = h.root.join("xdg");
    put(&xdg.join("crush/crush.json"), &line("derm hook crush pre"));
    e.vars
        .push(("XDG_CONFIG_HOME".into(), xdg.display().to_string()));
    put(&crush, &line("/usr/bin/derm hook crush pre"));
    assert_eq!(stale_registrations("crush", &e).len(), 1);
    // A plugin copy from before wave 5b.
    let h2 = home("on-path-plugin");
    let old = h2.root.join("old-plugin");
    put(&old.join("bin/derm-hook.mjs"), "process.exitCode = 2;");
    claude_install(&h2, &old);
    let p = stale_registrations("claude-code", &env(&h2));
    assert!(
        p.iter().any(|x| x.contains("runs `node` found on PATH")),
        "{p:?}"
    );
    claude_install(&h2, &repo().join("packages/derm-claude-plugin"));
    assert!(stale_registrations("claude-code", &env(&h2)).is_empty());
    // And the report lists them as problems.
    let row = find_row("crush").unwrap();
    put(&crush, &line("derm hook crush pre"));
    let r = doctor(&row, &env(&h), &probes(), false, false);
    assert!(r["problems"].to_string().contains("found on PATH"), "{r}");
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

#[cfg(unix)]
#[test]
fn the_report_is_kept_private_and_a_link_is_never_followed() {
    #[cfg(unix)]
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

#[cfg(unix)]
/// Security review L9: `derm doctor` runs the hook as you, outside any
/// sandbox, so it runs only the copy the agent loads from its own plugin
/// cache, owned by you and writable by no one else.
#[test]
fn the_hook_derm_runs_is_the_agents_own_copy_and_no_other() {
    #[cfg(unix)]
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
    std::fs::set_permissions(dest.join("hooks"), std::fs::Permissions::from_mode(0o777)).unwrap();
    let r = run_fixture("claude-code", &env(&h), &probes());
    assert_eq!(r["state"], "not run", "{r}");
    assert!(r["why"].as_str().unwrap().contains("writable"), "{r}");
    // Codex: the highest version, read as a version; a name that is not one
    // is never picked.
    let h = home("hook-semver");
    derm_at_home(&h);
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
            .ends_with("0.10.0/hooks/derm-gate.sh"),
        "{r}"
    );
}

/// Security review L9 and L18: the run is asked for, and the report names
/// the file before anything runs it.
#[test]
fn the_gate_runs_only_when_asked_and_the_file_is_named() {
    let h = home("ask-gate");
    derm_at_home(&h);
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
    assert!(why.contains("0.1.3/hooks/derm-gate.sh"), "{why}");
    assert!(why.contains("/bin/sh, which runs derm hook"), "{why}");
    assert!(render(&r).contains("--run-gate"));
    let r = doctor(&row, &env(&h), &probes(), false, true);
    assert_eq!(r["gateRun"]["state"], "pass", "{r}");
    assert!(
        render(&r).contains("0.1.3/hooks/derm-gate.sh"),
        "{}",
        render(&r)
    );
}

/// Mac test w4, MW4-4: with two `derm@derm` records, a local install for
/// another folder (0.1.0) and a local install for this one (0.1.3),
/// `derm doctor claude-code` named and ran the first record's hook. Claude
/// Code loads a project or local record only in its `projectPath` (case
/// 103), so doctor takes the record that applies here, as `derm status` does.
#[test]
fn the_claude_code_hook_doctor_names_is_the_one_this_folder_loads() {
    let h = home("two-installs");
    let src = repo().join("packages/derm-claude-plugin");
    let plugins = h.root.join("home/.claude/plugins");
    let other = plugins.join("cache/derm/derm/0.1.0");
    let here = plugins.join("cache/derm/derm/0.1.3");
    copy_dir(&src, &other);
    copy_dir(&src, &here);
    let elsewhere = h.root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let proj = h.root.join("proj");
    put(
        &plugins.join("installed_plugins.json"),
        &json!({"version": 2, "plugins": {"derm@derm": [
            {"scope": "local", "projectPath": elsewhere, "installPath": other, "version": "0.1.0"},
            {"scope": "local", "projectPath": proj, "installPath": here, "version": "0.1.3"}
        ]}})
        .to_string(),
    );
    let got = installed_hook("claude-code", &env(&h)).unwrap();
    assert!(
        got.starts_with(here.canonicalize().unwrap()),
        "{}",
        got.display()
    );
    // From a folder no record names, no hook: not another folder's.
    let mut away = env(&h);
    away.cwd = Some(h.root.join("bin"));
    let err = installed_hook("claude-code", &away).unwrap_err();
    assert!(err.contains("this folder"), "{err}");
    // A user record applies anywhere; a local one for here comes first.
    put(
        &plugins.join("installed_plugins.json"),
        &json!({"version": 2, "plugins": {"derm@derm": [
            {"scope": "user", "installPath": other, "version": "0.1.0"},
            {"scope": "local", "projectPath": proj, "installPath": here, "version": "0.1.3"}
        ]}})
        .to_string(),
    );
    let got = installed_hook("claude-code", &env(&h)).unwrap();
    assert!(
        got.starts_with(here.canonicalize().unwrap()),
        "{}",
        got.display()
    );
    let got = installed_hook("claude-code", &away).unwrap();
    assert!(
        got.starts_with(other.canonicalize().unwrap()),
        "{}",
        got.display()
    );
}

/// BW5B-3 (box test w5b, step 3): goose 1.59.0 loads every folder under the
/// session folder's `.agents/plugins/` as a project plugin with no prompt,
/// ranks it before yours, keeps the first plugin of a name, and reads
/// `disabledPlugins` from the session folder's `.config/goose/settings.json`
/// and `settings.local.json` and from your own (`plugins/discovery.rs:52-101,
/// 155-176, 181-250`, `agents/services.rs:383` at 5d03ef6). doctor names
/// each, and says which one switches derm's gate off.
#[test]
fn bw5b_3_goose_project_plugins_and_disabled_plugins_are_named() {
    let h = home("goose-shadows");
    let e = env(&h);
    let row = find_row("goose").unwrap();
    assert!(shadows("goose", &row, &e).is_empty());
    let proj = h.root.join("proj");
    let name = "derm-0123456789abcdef";
    put(&h.root.join("home/.derm/gate-name"), &format!("{name}\n"));
    #[cfg(unix)]
    std::fs::set_permissions(
        h.root.join("home/.derm/gate-name"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    put(&proj.join(".agents/plugins/derm/hooks/hooks.json"), "{}");
    put(&proj.join(".agents/plugins/lint/plugin.json"), "{}");
    put(
        &proj.join(".config/goose/settings.json"),
        "{\"disabledPlugins\": [\"derm\", \"derm-gate\"]}",
    );
    let s = shadows("goose", &row, &e);
    let paths: Vec<String> = s
        .iter()
        .map(|v| v["path"].as_str().unwrap().replace('\\', "/"))
        .collect();
    for want in [
        ".agents/plugins/derm",
        ".agents/plugins/lint",
        ".config/goose/settings.json",
    ] {
        assert!(paths.iter().any(|p| p.ends_with(want)), "{want}: {s:?}");
    }
    // None of these is derm's drawn name: each adds hooks, none turns derm off.
    assert!(s.iter().all(|v| v["turnsOff"] == json!(false)), "{s:?}");
    // A project plugin under derm's drawn name, or a disabledPlugins that
    // names it (project, local or yours), switches derm's gate off.
    put(
        &proj.join(format!(".agents/plugins/{name}/plugin.json")),
        "{}",
    );
    put(
        &proj.join(".config/goose/settings.local.json"),
        &format!("{{\"disabledPlugins\": [\"{name}\"]}}"),
    );
    put(
        &h.root.join("home/.config/goose/settings.json"),
        &format!("{{\"disabledPlugins\": [\"{name}\"]}}"),
    );
    let s = shadows("goose", &row, &e);
    let off: Vec<String> = s
        .iter()
        .filter(|v| v["turnsOff"] == json!(true))
        .map(|v| v["path"].as_str().unwrap().replace('\\', "/"))
        .collect();
    // goose stops at the first scope that lists derm's (local), so your own
    // settings do not decide here (FP1-S11).
    assert_eq!(off.len(), 2, "{s:?}");
    assert!(
        off.iter()
            .any(|p| p.ends_with(&format!(".agents/plugins/{name}"))),
        "{off:?}"
    );
    assert!(
        off.iter()
            .any(|p| p.ends_with("proj/.config/goose/settings.local.json")),
        "{off:?}"
    );
    assert!(
        !off.iter()
            .any(|p| p.ends_with("home/.config/goose/settings.json")),
        "{off:?}"
    );
    // The session folder is your home: goose reads one plugins folder, yours.
    let mut at_home = env(&h);
    at_home.cwd = Some(h.root.join("home"));
    put(
        &h.root
            .join("home/.agents/plugins")
            .join(name)
            .join("plugin.json"),
        "{}",
    );
    let s = shadows("goose", &row, &at_home);
    assert!(
        !s.iter()
            .any(|v| v["path"].as_str().unwrap().contains(".agents/plugins")),
        "{s:?}"
    );
}

/// BW5B-3: a repository decides how many plugin folders doctor reads; it
/// names derm's own always and at most 32 others.
#[test]
fn bw5b_3_a_project_with_many_goose_plugins_is_listed_in_bounds() {
    let h = home("goose-many");
    let e = env(&h);
    let row = find_row("goose").unwrap();
    let name = "derm-fedcba9876543210";
    put(&h.root.join("home/.derm/gate-name"), &format!("{name}\n"));
    #[cfg(unix)]
    std::fs::set_permissions(
        h.root.join("home/.derm/gate-name"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let plugins = h.root.join("proj/.agents/plugins");
    for i in 0..100 {
        std::fs::create_dir_all(plugins.join(format!("p{i:03}"))).unwrap();
    }
    std::fs::create_dir_all(plugins.join(name)).unwrap();
    let s = shadows("goose", &row, &e);
    assert_eq!(s.len(), 34, "{s:?}");
    assert!(s
        .iter()
        .any(|v| v["turnsOff"] == json!(true) && v["path"].as_str().unwrap().ends_with(name)));
    assert!(
        s.iter()
            .any(|v| v["what"].as_str().unwrap().starts_with("68 more")),
        "{s:?}"
    );
}

/// FP1-S11 (the fix pass's review): goose decides a plugin by the first
/// scope that lists it, local, then project, then yours, `enabledPlugins` as
/// well as `disabledPlugins` (`plugins/discovery.rs:155-176` at 5d03ef6);
/// with no drawn name, derm's gate is under the older fixed name `derm`.
#[test]
fn fp1_s11_goose_scopes_decide_in_order_and_the_old_name_counts() {
    let h = home("goose-scopes");
    let e = env(&h);
    let row = find_row("goose").unwrap();
    // No ~/.derm/gate-name: derm's plugin is the one named `derm`.
    put(&h.root.join("proj/.agents/plugins/derm/plugin.json"), "{}");
    put(
        &h.root.join("home/.config/goose/settings.json"),
        "{\"disabledPlugins\": [\"derm\"]}",
    );
    let off = |s: &Vec<serde_json::Value>| {
        s.iter()
            .filter(|v| v["turnsOff"] == json!(true))
            .map(|v| v["path"].as_str().unwrap().replace('\\', "/"))
            .collect::<Vec<_>>()
    };
    let s = shadows("goose", &row, &e);
    let o = off(&s);
    assert!(
        o.iter().any(|p| p.ends_with("proj/.agents/plugins/derm")),
        "{s:?}"
    );
    assert!(
        o.iter()
            .any(|p| p.ends_with("home/.config/goose/settings.json")),
        "{s:?}"
    );
    // The session folder's local settings enable it: your disable no longer counts.
    put(
        &h.root.join("proj/.config/goose/settings.local.json"),
        "{\"enabledPlugins\": [\"derm\"]}",
    );
    let s = shadows("goose", &row, &e);
    assert!(
        !off(&s)
            .iter()
            .any(|p| p.ends_with("home/.config/goose/settings.json")),
        "{s:?}"
    );
}
