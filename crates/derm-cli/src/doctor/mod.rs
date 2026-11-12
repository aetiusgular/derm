//! `derm doctor <agent>` (wave 4 lane R, toolkit plan T2.9 and section 3):
//! a self-test for one agent, printed as a report a user can attach to an
//! issue.
//!
//! - The installed version against the version the agent's preset row was
//!   verified at (rules case 81): "unverified at <installed>" when they
//!   differ. `<agent> --version` is run, as you, argv only, with a clean
//!   environment and a time limit (`derm status --probe`'s probe).
//! - Whether derm's gate is registered in your user-level files, read the
//!   way `derm status` reads them (`watch/register.rs`).
//! - What can shadow it: the agent's project-level and managed files that
//!   exist (case 78), and the switches known to turn a gate off: Claude
//!   Code's `disableAllHooks` and a project's `enabledPlugins["derm@derm"] =
//!   false`, Droid's `~/.factory/hooks.json` (its binary merges it over
//!   `settings.json` per event, so a PreToolUse array there shadows derm's;
//!   `contracts/hook-dialects.md` section 2a).
//! - What the agent does when the gate fails, and where an ask goes, from
//!   the row (cases 70, 71).
//! - With `--run-gate`, the installed gate run once against a fixture: a
//!   shell call under a policy that denies `bash`, for the agents whose
//!   installed hook derm can find (Claude Code, Codex, Gemini). Since wave
//!   5b (lane 5bF) that is the plugin's launcher, `hooks/derm-gate.sh`, run
//!   with /bin/sh as the agent runs it, so the Rust hook (`derm hook`) from
//!   derm's install folders is what answers; a plugin from before wave 5b
//!   is run with node as before, and named as a problem (case 227). The
//!   hook runs as you, outside any sandbox, with no chat token, so it
//!   reaches no daemon. Only the agent's own copy in its plugin cache is
//!   run, owned by you and writable by no one else; without `--run-gate`
//!   the report names the file and nothing runs it (security review L9).
//! - Case 227: a registration in the agent's own files that runs derm's
//!   gate through a program found on PATH (a wave 4 `node ...
//!   derm-hook.mjs` line, or a bare `derm hook`), and a plugin whose hooks
//!   file still runs `node`, are problems with the fix named.
//! - `--live` (one canary call through the agent on your account) is not
//!   built in this version, and says so.
//!
//! Exit 0 when nothing needs doing, 1 when something does, 2 on a usage
//! error. What it writes: the report, 0600, at `~/.derm/doctor/<agent>.json`
//! for `derm status`, and a temporary folder of its own while the gate runs
//! (security review L18).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::watch::register::{self, Registered};
use crate::watch::status::{find_on_path, probe_version, Env};

pub const USAGE: &str = "usage: derm doctor <agent> [--json] [--run-gate] [--live]

  <agent> is a preset id (`derm status` lists them) or Orca's id for it.
  Runs `<agent> --version`. With --run-gate, also runs the installed gate
  once against a fixture, as you and outside any sandbox; without it, the
  report names the file it would run. Keeps the report in
  ~/.derm/doctor/<agent>.json for `derm status`.";

const HOOK_TIMEOUT: Duration = Duration::from_secs(20);

pub fn main(args: &[String]) -> u8 {
    let mut id = None;
    let (mut json_out, mut live, mut run_gate) = (false, false, false);
    for a in args {
        match a.as_str() {
            "--json" => json_out = true,
            "--live" => live = true,
            "--run-gate" => run_gate = true,
            "-h" | "--help" => {
                eprintln!("{USAGE}");
                return 2;
            }
            s if s.starts_with('-') => {
                eprintln!("derm doctor: unknown option {s:?}\n{USAGE}");
                return 2;
            }
            s if id.is_none() => id = Some(s.to_string()),
            s => {
                eprintln!("derm doctor: one agent at a time ({s:?})\n{USAGE}");
                return 2;
            }
        }
    }
    let Some(id) = id else {
        eprintln!("{USAGE}");
        return 2;
    };
    let Some(row) = find_row(&id) else {
        eprintln!("derm doctor: no agent {id:?}; `derm status` lists them");
        return 2;
    };
    let env = Env::real();
    // What will run, said before it runs (security review L18).
    if let Some(cli) = row
        .get("cli")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty() && *c != "TODO" && !c.contains('/'))
    {
        eprintln!("derm doctor: running `{cli} --version` as you, with a clean environment and a time limit");
    }
    let mut report = doctor(&row, &env, &Probes::real(), live, run_gate);
    report["at"] = json!(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0));
    // The last report per agent, for `derm status` (T2.9).
    if let Some(home) = env.home.as_deref() {
        if let Err(e) = save(home, &report) {
            eprintln!("derm doctor: the report was not kept for derm status: {e}");
        }
    }
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("{}", render(&report));
    }
    u8::from(report["problems"].as_array().is_some_and(|p| !p.is_empty()))
}

/// Where `derm doctor` keeps its last report per agent: derm's own folder.
pub fn report_path(home: &Path, agent: &str) -> PathBuf {
    home.join(".derm/doctor").join(format!("{agent}.json"))
}

/// Keeps the report as a new 0600 file renamed into place in a 0700
/// folder; a link in the way is refused, never followed.
pub fn save(home: &Path, report: &Value) -> std::io::Result<()> {
    let agent = report["agent"].as_str().unwrap_or("");
    if agent.is_empty()
        || !agent
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(std::io::Error::other("not an agent id"));
    }
    let path = report_path(home, agent);
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no folder"))?;
    for d in [home.join(".derm"), dir.to_path_buf()] {
        match std::fs::symlink_metadata(&d) {
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                return Err(std::io::Error::other(format!(
                    "{} is not a folder",
                    d.display()
                )))
            }
            Ok(_) => {}
            Err(_) => {
                std::fs::create_dir(&d)?;
                // The seam's `set_private_dir` is `chmod 0700` on Unix.
                derm_core::platform::set_private_dir(&d)?;
            }
        }
    }
    let tmp = dir.join(format!(".{agent}.{}.tmp", uuid::Uuid::new_v4().simple()));
    // The seam's `private_no_follow` is `.mode(0o600).custom_flags(O_NOFOLLOW)`
    // on Unix.
    let mut f = derm_core::platform::private_no_follow(
        std::fs::OpenOptions::new().write(true).create_new(true),
    )
    .open(&tmp)?;
    let text = serde_json::to_string_pretty(report).map_err(std::io::Error::other)?;
    std::io::Write::write_all(&mut f, text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)
}

/// The preset row for a preset id or Orca's id, from either list.
pub fn find_row(id: &str) -> Option<Value> {
    let table: Value = serde_json::from_str(crate::connect::presets::table_json()).ok()?;
    ["harnesses", "planned"]
        .iter()
        .filter_map(|l| table.get(*l).and_then(Value::as_array))
        .flatten()
        .find(|r| {
            r.get("id").and_then(Value::as_str) == Some(id)
                || r.pointer("/coverage/orcaId").and_then(Value::as_str) == Some(id)
        })
        .cloned()
}

/// The first `N.N[.N...]` in a string: `"2.1.311, run"` gives `2.1.311`,
/// `"claude 2.1.318 (Claude Code)"` gives `2.1.318`, `"v0.22.5"` gives
/// `0.22.5`.
pub fn version_token(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit()
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'v')
        {
            let start = i;
            let mut dots = 0;
            while i < b.len()
                && (b[i].is_ascii_digit()
                    || (b[i] == b'.' && i + 1 < b.len() && b[i + 1].is_ascii_digit()))
            {
                if b[i] == b'.' {
                    dots += 1;
                }
                i += 1;
            }
            if dots >= 1 {
                return Some(s[start..i].to_string());
            }
        }
        i += 1;
    }
    None
}

/// What doctor runs, so the tests can give fakes.
pub struct Probes {
    pub version: fn(&Path) -> String,
    pub node: Option<PathBuf>,
}

impl Probes {
    fn real() -> Probes {
        Probes {
            version: probe_version,
            node: find_on_path("node", &std::env::var("PATH").unwrap_or_default()),
        }
    }
}

pub fn doctor(row: &Value, env: &Env, probes: &Probes, live: bool, run_gate: bool) -> Value {
    let s = |v: &Value, p: &str| {
        v.pointer(p)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let id = s(row, "/id");
    let mut problems: Vec<String> = Vec::new();

    // The program and its version (case 81).
    let cli = row
        .get("cli")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty() && *c != "TODO" && !c.contains('/'))
        .map(str::to_string);
    let program = cli.as_deref().and_then(|c| find_on_path(c, &env.path));
    let verified_at = s(row, "/coverage/verifiedAt");
    let installed = program.as_deref().map(probes.version);
    let version = match (&installed, version_token(&verified_at)) {
        (Some(out), Some(want)) => match version_token(out) {
            Some(have) if have == want => {
                json!({"state": "matches", "installed": have, "verifiedAt": want})
            }
            Some(have) => {
                problems.push(format!(
                    "{id} {have} is not the version derm's row was verified at ({want}): unverified at {have}"
                ));
                json!({"state": "unverified", "installed": have, "verifiedAt": want})
            }
            None => json!({"state": "unknown", "probe": out, "verifiedAt": want}),
        },
        (Some(out), None) => json!({"state": "no verified version", "probe": out}),
        (None, _) => json!({"state": "not found", "cli": cli}),
    };

    // Registration, for a built gate.
    let status = s(row, "/coverage/gate/status");
    let registered = if status == "built" {
        register::check(&id, env)
    } else {
        Registered::NotBuilt
    };
    if matches!(registered, Registered::No(_)) {
        problems.push(format!("derm's gate is not registered for {id}"));
    }

    // What can shadow it.
    let shadows = shadows(&id, row, env);
    for sh in &shadows {
        if sh["turnsOff"] == json!(true) {
            problems.push(sh["what"].as_str().unwrap_or("").to_string());
        }
    }

    // The gate against a fixture.
    let gate_run = if status != "built" {
        json!({"state": "not run", "why": "derm's gate for this agent is not built yet"})
    } else if run_gate {
        eprintln!("derm doctor: running the installed gate once against a fixture, as you, outside any sandbox");
        run_fixture(&id, env, probes)
    } else {
        match installed_hook(&id, env) {
            Ok(h) => json!({
                "state": "not run",
                "why": format!(
                    "pass --run-gate to run {} once with {}, as you, outside any sandbox",
                    h.display(),
                    if is_launcher(&h) { "/bin/sh, which runs derm hook from derm's install folders" } else { "node" }
                ),
                "hook": h.display().to_string(),
            }),
            Err(why) => json!({"state": "not run", "why": why}),
        }
    };
    // Case 227: a registration that finds derm's gate, or the node that
    // runs it, on PATH.
    let stale = stale_registrations(&id, env);
    problems.extend(stale.iter().cloned());
    match gate_run["state"].as_str() {
        Some("fail") => problems.push(format!(
            "the installed gate did not deny a denied call: {}",
            gate_run["saw"].as_str().unwrap_or("")
        )),
        Some("fail-closed") => problems.push(format!(
            "the installed gate blocked, but not on the policy's rule (it failed closed, so every call is blocked): {}",
            gate_run["saw"].as_str().unwrap_or("")
        )),
        _ => {}
    }

    json!({
        "agent": id,
        "name": s(row, "/name"),
        "derm": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "program": program.map(|p| p.display().to_string()),
        "version": version,
        "tier": row.pointer("/coverage/tier").cloned().unwrap_or(Value::Null),
        "gate": {
            "status": status,
            "family": s(row, "/coverage/gate/family"),
            "where": s(row, "/coverage/gate/where"),
            "wave": row.pointer("/coverage/gate/wave").cloned().unwrap_or(Value::Null),
            "lane": row.pointer("/coverage/gate/lane").cloned().unwrap_or(Value::Null),
        },
        "registered": registered.word(),
        "registeredDetail": registered.detail(),
        "shadows": shadows,
        "failMode": s(row, "/coverage/failMode"),
        "failSwitch": row.pointer("/coverage/failSwitch").cloned().unwrap_or(Value::Null),
        "ask": s(row, "/coverage/ask"),
        "gateRun": gate_run,
        "onPath": stale,
        "live": if live {
            json!("not built in this version: no canary call was made")
        } else {
            json!("not asked (--live)")
        },
        "problems": problems,
    })
}

fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn expand(p: &str, env: &Env) -> Option<PathBuf> {
    if let Some(rest) = p.strip_prefix("~/") {
        return env.home.as_ref().map(|h| h.join(rest));
    }
    if let Some(rest) = p.strip_prefix("<project>/") {
        return env.cwd.as_ref().map(|c| c.join(rest));
    }
    p.starts_with('/').then(|| PathBuf::from(p))
}

fn read_json_small(path: &Path) -> Option<Value> {
    let m = std::fs::metadata(path).ok()?;
    if !m.is_file() || m.len() > 1024 * 1024 {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&register::strip_jsonc(&text)).ok()
}

/// Files that exist and can override or switch off derm's gate for this
/// agent: the row's project-level and managed files (case 78), and the
/// switches read in each agent's own files.
pub fn shadows(id: &str, row: &Value, env: &Env) -> Vec<Value> {
    let mut out = Vec::new();
    let mut seen = |path: PathBuf, what: String, turns_off: bool| {
        out.push(json!({"path": path.display().to_string(), "what": what, "turnsOff": turns_off}));
    };
    if let Some(p) = row
        .pointer("/configFiles/project")
        .and_then(Value::as_str)
        .and_then(|p| expand(p, env))
    {
        if p.exists() {
            seen(
                p,
                "a project-level config here can add servers or hooks of its own".into(),
                false,
            );
        }
    }
    for m in row
        .pointer(&format!("/managedFiles/{}", platform()))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let p = PathBuf::from(m);
        if p.exists() {
            seen(
                p,
                "a managed file here outranks your own settings".into(),
                false,
            );
        }
    }
    match id {
        "claude-code" => {
            let config = env
                .var("CLAUDE_CONFIG_DIR")
                .map(PathBuf::from)
                .or_else(|| env.home.as_ref().map(|h| h.join(".claude")));
            let managed = if cfg!(target_os = "macos") {
                "/Library/Application Support/ClaudeCode/managed-settings.json"
            } else {
                "/etc/claude-code/managed-settings.json"
            };
            let mut files: Vec<(PathBuf, &str)> = Vec::new();
            if let Some(c) = config {
                files.push((c.join("settings.json"), "user"));
            }
            if let Some(cwd) = &env.cwd {
                files.push((cwd.join(".claude/settings.json"), "project"));
                files.push((cwd.join(".claude/settings.local.json"), "local"));
            }
            files.push((PathBuf::from(managed), "managed"));
            for (path, scope) in files {
                let Some(v) = read_json_small(&path) else {
                    continue;
                };
                if v.get("disableAllHooks") == Some(&json!(true)) {
                    seen(
                        path.clone(),
                        format!("disableAllHooks is true in the {scope} settings: no hook runs, derm's included"),
                        true,
                    );
                }
                if v.pointer("/enabledPlugins/derm@derm") == Some(&json!(false)) {
                    seen(
                        path.clone(),
                        format!("enabledPlugins[\"derm@derm\"] is false in the {scope} settings"),
                        true,
                    );
                }
                if scope == "managed" && v.get("allowManagedHooksOnly") == Some(&json!(true)) {
                    seen(
                        path.clone(),
                        "allowManagedHooksOnly is true: only hooks your managed settings register run".into(),
                        false,
                    );
                }
            }
        }
        "droid" => {
            if let Some(h) = env.home.as_ref().map(|h| h.join(".factory/hooks.json")) {
                if h.exists() {
                    seen(
                        h,
                        "~/.factory/hooks.json exists: Droid merges it over settings.json per event, so its PreToolUse array shadows derm's".into(),
                        true,
                    );
                }
            }
        }
        // BW5B-3, case 78. goose 1.59.0 loads hooks with the session folder
        // as the project (`agents/services.rs:383`): every folder under its
        // `.agents/plugins/` is a plugin, loaded with no prompt and ranked
        // before yours, the first of a name kept (`plugins/discovery.rs:
        // 52-101, 181-201`), unless the session folder is your home, whose
        // folder is the same one; and `disabledPlugins` in the session
        // folder's `.config/goose/settings.local.json` and `settings.json`
        // and in your `~/.config/goose/settings.json` switches a plugin off
        // by name (`discovery.rs:155-176, 203-250`), all at 5d03ef6.
        "goose" => {
            // derm's plugin: the drawn name, or with none drawn the older
            // fixed name the row keeps (`legacyName`; FP1-S11).
            let name = env
                .home
                .as_deref()
                .and_then(|h| crate::connect::gate::read_gate_name(h).ok().flatten())
                .or_else(|| {
                    crate::connect::gate::table()
                        .ok()?
                        .into_iter()
                        .find(|a| a.agent == "goose")?
                        .legacy_name
                });
            let ours = |n: &str| name.as_deref() == Some(n);
            let mut settings: Vec<(PathBuf, &str)> = Vec::new();
            if let Some(cwd) = &env.cwd {
                let project = cwd.join(".agents/plugins");
                let yours = env.home.as_ref().map(|h| h.join(".agents/plugins"));
                let same = yours.as_ref().is_some_and(|y| {
                    y == &project
                        || matches!(
                            (std::fs::canonicalize(y), std::fs::canonicalize(&project)),
                            (Ok(a), Ok(b)) if a == b
                        )
                });
                if !same {
                    // A repository decides how many folders this holds: read
                    // at most 4,096 entries, name derm's own always, and at
                    // most 32 others, then say how many more there are. A
                    // name that is not UTF-8 is skipped, as goose skips it
                    // (`discovery.rs:197`).
                    let mut kids: Vec<(String, PathBuf)> = std::fs::read_dir(&project)
                        .into_iter()
                        .flatten()
                        .take(4096)
                        .flatten()
                        .filter(|e| e.path().is_dir())
                        .filter_map(|e| Some((e.file_name().to_str()?.to_string(), e.path())))
                        .collect();
                    kids.sort();
                    let mut others = 0usize;
                    for (n, p) in kids {
                        if ours(&n) {
                            seen(p, format!("a project plugin named `{n}`, derm's gate's own name, which goose keeps in place of yours: derm's gate does not run here"), true);
                        } else if others < 32 {
                            others += 1;
                            seen(p, format!("a project plugin `{n}` that goose loads with no prompt, before yours: its hooks run the repository's commands before derm's on every call (a deny from either stops the call)"), false);
                        } else {
                            others += 1;
                        }
                    }
                    if others > 32 {
                        seen(
                            project.clone(),
                            format!("{} more project plugins here, not listed", others - 32),
                            false,
                        );
                    }
                }
                settings.push((cwd.join(".config/goose/settings.local.json"), "local"));
                settings.push((cwd.join(".config/goose/settings.json"), "project"));
            }
            if let Some(h) = &env.home {
                settings.push((h.join(".config/goose/settings.json"), "user"));
            }
            // goose takes the first scope that lists a plugin, enabled or
            // disabled, local, then project, then yours (`discovery.rs:
            // 155-176`): only that scope decides derm's.
            let mut done: Vec<PathBuf> = Vec::new();
            let mut decided = false;
            let names = |v: &Value, key: &str| -> Vec<String> {
                v.get(key)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            };
            for (path, scope) in settings {
                if done.contains(&path) {
                    continue;
                }
                done.push(path.clone());
                if !path.exists() {
                    continue;
                }
                let v = read_json_small(&path).unwrap_or(Value::Null);
                let disabled = names(&v, "disabledPlugins");
                let enabled = names(&v, "enabledPlugins");
                if !decided {
                    if let Some(n) = disabled.iter().find(|n| ours(n)) {
                        decided = true;
                        seen(path, format!("disabledPlugins in the {scope} settings names `{n}`, derm's gate: goose does not run it"), true);
                        continue;
                    }
                    if enabled.iter().any(|n| ours(n)) {
                        decided = true;
                    }
                }
                if scope != "user" {
                    seen(path, format!("the {scope} settings can switch plugins on or off by name (disabledPlugins: {})", if disabled.is_empty() { "none now".to_string() } else { disabled.join(", ") }), false);
                }
            }
        }
        _ => {}
    }
    out
}

/// The installed hook script for an agent derm can find it for.
/// `hook` is the agent's own copy, as `derm doctor` may run it: its real
/// path under `root` (the agent's plugin folder), and every part from `root`
/// down to it owned by you and writable by no one else (security review L9).
/// The real path comes back.
fn checked_hook(hook: &Path, root: &Path) -> Result<PathBuf, String> {
    let real = std::fs::canonicalize(hook).map_err(|e| format!("{}: {e}", hook.display()))?;
    let root = std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let rel = real.strip_prefix(&root).map_err(|_| {
        format!(
            "{} is outside {}, the agent's plugin folder; derm runs only the copy the agent installed there",
            real.display(),
            root.display()
        )
    })?;
    let uid = derm_core::platform::real_user();
    let mut at = root.clone();
    let mut parts = vec![at.clone()];
    for c in rel.components() {
        at.push(c);
        parts.push(at.clone());
    }
    for p in &parts {
        let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if !yours_alone(p, &m, uid) {
            return Err(format!(
                "{} is not yours alone (owner or group/other writable); derm will not run a hook someone else could have written",
                p.display()
            ));
        }
    }
    let m = std::fs::symlink_metadata(&real).map_err(|e| e.to_string())?;
    if !m.file_type().is_file() {
        return Err(format!("{} is not a regular file", real.display()));
    }
    Ok(real)
}

/// Owned by `uid`, writable by no one else.
#[cfg(unix)]
fn yours_alone(_p: &Path, m: &std::fs::Metadata, uid: derm_core::platform::UserId) -> bool {
    use std::os::unix::fs::MetadataExt;
    m.uid() == uid && m.mode() & 0o022 == 0
}

/// Windows (lane Z): the same, from the owner and DACL.
#[cfg(windows)]
fn yours_alone(p: &Path, _m: &std::fs::Metadata, uid: derm_core::platform::UserId) -> bool {
    uid == derm_core::platform::effective_user()
        && derm_core::platform::windows::only_owner_writes(p)
}

/// A folder name read as a version (`0.10.0`), else `None`.
fn semver(name: &str) -> Option<(u64, u64, u64)> {
    let mut it = name.split('.').map(|p| {
        (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .then(|| p.parse::<u64>().ok())
            .flatten()
    });
    let v = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(v)
}

/// The hook an installed plugin copy runs: the wave 5b launcher
/// (`hooks/derm-gate.sh`, run with /bin/sh), else a copy from before wave
/// 5b (`bin/derm-hook.mjs`, run with node).
fn plugin_hook(copy: &Path) -> Option<PathBuf> {
    ["hooks/derm-gate.sh", "bin/derm-hook.mjs"]
        .iter()
        .map(|rel| copy.join(rel))
        .find(|p| p.is_file())
}

/// Whether a hook is the wave 5b launcher.
fn is_launcher(hook: &Path) -> bool {
    hook.file_name().is_some_and(|n| n == "derm-gate.sh")
}

fn installed_hook(id: &str, env: &Env) -> Result<PathBuf, String> {
    let home = env.home.as_ref().ok_or("HOME is not set")?;
    match id {
        "claude-code" => {
            let config = env
                .var("CLAUDE_CONFIG_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".claude"));
            let plugins = env
                .var("CLAUDE_CODE_PLUGIN_CACHE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| config.join("plugins"));
            let record = plugins.join("installed_plugins.json");
            let v = read_json_small(&record)
                .ok_or_else(|| format!("{} not found or not JSON", record.display()))?;
            let entries = v
                .pointer("/plugins/derm@derm")
                .and_then(Value::as_array)
                .ok_or("derm@derm is not in installed_plugins.json")?;
            // Claude Code 2.1.311 installs into its versioned cache under
            // `<config>/plugins/cache` (`b(Ne(),"plugins","cache")` in the
            // binary), so the copy it loads is under `plugins`.
            // Only a record Claude Code would load in this folder, best
            // first (Mac test w4, MW4-4: the first record with a hook was
            // taken, another folder's local install included).
            let mut ranked: Vec<(u8, &str)> = entries
                .iter()
                .filter_map(|e| {
                    let rank = crate::watch::register::claude_record_rank(e, env.cwd.as_deref())?;
                    Some((rank, e.get("installPath").and_then(Value::as_str)?))
                })
                .collect();
            ranked.sort_by_key(|(rank, _)| *rank);
            if ranked.is_empty() {
                return Err(format!(
                    "no derm@derm install record applies in this folder ({}): a project or local install loads only in its own folder",
                    env.cwd
                        .as_deref()
                        .map(|c| c.display().to_string())
                        .unwrap_or_else(|| "unknown".into())
                ));
            }
            let mut first_err = None;
            for p in ranked.into_iter().map(|(_, p)| p) {
                let Some(hook) = plugin_hook(&PathBuf::from(p)) else {
                    continue;
                };
                match checked_hook(&hook, &plugins) {
                    Ok(h) => return Ok(h),
                    Err(e) => {
                        first_err.get_or_insert(e);
                    }
                }
            }
            Err(first_err.unwrap_or_else(|| {
                "no installed copy of derm@derm holds hooks/derm-gate.sh or bin/derm-hook.mjs"
                    .into()
            }))
        }
        "codex" => {
            let codex = env
                .var("CODEX_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".codex"));
            let dir = codex.join("plugins/cache/derm/derm");
            // The highest version folder, read as a version; a name that is
            // not one is never picked (security review L9: `zzz` sorted last).
            // Which copy Codex itself loads when several are cached is not
            // verified; the highest is the one it installed last.
            let best = std::fs::read_dir(&dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    semver(&name).map(|v| (v, e.path()))
                })
                .filter_map(|(v, p)| plugin_hook(&p).map(|h| (v, h)))
                .max_by_key(|(v, _)| *v)
                .ok_or_else(|| format!("no installed copy under {}", dir.display()))?;
            checked_hook(&best.1, &dir)
        }
        // Gemini installs an extension by copying it into
        // `~/.gemini/extensions/<name>` (gemini-cli 0.68.0,
        // `EXTENSIONS_DIRECTORY_NAME`, bundle/chunk-ASDLQWJU.js); derm's is
        // named derm (`gemini-extension.json`).
        "gemini" => {
            let dir = home.join(".gemini/extensions");
            let ext = dir.join("derm");
            let hook = plugin_hook(&ext).ok_or_else(|| {
                format!(
                    "no derm extension under {} holds hooks/derm-gate.sh",
                    dir.display()
                )
            })?;
            checked_hook(&hook, &dir)
        }
        other => Err(format!("no fixture runner for {other} in this version")),
    }
}

/// `derm connect`'s view of doctor's environment (`connect::presets::Env`).
struct ConnectEnv<'a>(&'a Env);

impl crate::connect::presets::Env for ConnectEnv<'_> {
    fn var(&self, key: &str) -> Option<String> {
        self.0.var(key).map(str::to_string)
    }
}

/// Case 227 (wave 5b lane 5bF): what in this agent's own files runs derm's
/// gate through a program found on PATH. A plugin copy from before wave 5b
/// runs `node` (note BC, BC-3, run: a project's `env.PATH` chose which
/// node ran it); a registration `derm connect --gate` wrote before wave 5b
/// runs `node ... derm-hook.mjs`; a line naming a bare `derm` runs
/// whichever derm comes first on PATH. Each comes back as a problem that
/// names the fix.
pub fn stale_registrations(id: &str, env: &Env) -> Vec<String> {
    let mut out = Vec::new();
    if matches!(id, "claude-code" | "codex" | "gemini") {
        if let Ok(h) = installed_hook(id, env) {
            if !is_launcher(&h) {
                out.push(format!(
                    "the installed plugin's hook ({}) runs `node` found on PATH (rules case 227): install derm's plugin from this release, whose hooks file runs /bin/sh on hooks/derm-gate.sh",
                    h.display()
                ));
            }
        }
    }
    let Some(home) = env.home.as_deref() else {
        return out;
    };
    let Ok(table) = crate::connect::gate::table() else {
        return out;
    };
    let Some(row) = table.iter().find(|a| a.agent == id) else {
        return out;
    };
    if !row.command.as_deref().is_some_and(|c| c.contains("{derm}")) {
        return out;
    }
    use crate::connect::gate::{resolve, Place, Step};
    let cenv = ConnectEnv(env);
    let mut places: Vec<Place> = Vec::new();
    let mut legacy: Vec<Place> = Vec::new();
    for st in &row.steps {
        let (at, chain): (&Place, &[String]) = match st {
            Step::JsonArrayEntry { at, chain, .. } => (at, chain),
            Step::JsonMember { at, .. }
            | Step::TomlArrayEntry { at, .. }
            | Step::OwnedFile { at, .. } => (at, &[]),
            Step::PluginFolder { at, .. } => {
                // BC-1: the folder takes the name in ~/.derm/gate-name; one
                // still under the fixed name is a problem of its own.
                let name = crate::connect::gate::read_gate_name(home).ok().flatten();
                if let Some(n) = name
                    .as_deref()
                    .or((!at.path.contains("{gatename}")).then_some(""))
                {
                    places.push(Place {
                        path: format!("{}/hooks/hooks.json", at.path.replace("{gatename}", n)),
                        home_env: at.home_env.clone(),
                        xdg_config: at.xdg_config,
                    });
                }
                if let Some(old) = row
                    .legacy_name
                    .as_deref()
                    .filter(|_| at.path.contains("{gatename}"))
                {
                    legacy.push(Place {
                        path: format!("{}/hooks/hooks.json", at.path.replace("{gatename}", old)),
                        home_env: at.home_env.clone(),
                        xdg_config: at.xdg_config,
                    });
                }
                continue;
            }
            _ => continue,
        };
        places.push(at.clone());
        for c in chain {
            places.push(Place {
                path: c.clone(),
                home_env: at.home_env.clone(),
                xdg_config: at.xdg_config,
            });
        }
    }
    let mut seen: Vec<PathBuf> = Vec::new();
    for at in &places {
        let file = resolve(at, home, &cenv);
        if seen.contains(&file) {
            continue;
        }
        seen.push(file.clone());
        let Ok(m) = std::fs::metadata(&file) else {
            continue;
        };
        if !m.is_file() || m.len() > 1024 * 1024 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let fix = format!("run `derm connect {id} --gate --write` again");
        if text.contains("derm-hook.mjs") {
            out.push(format!(
                "{} registers derm's gate with the line from before wave 5b, which runs the `node` found on PATH (rules case 227): {fix}",
                file.display()
            ));
        }
        if bare_derm_hook(&text, id) {
            out.push(format!(
                "{} runs a `derm hook` found on PATH, not derm by its absolute path (rules case 227): {fix}",
                file.display()
            ));
        }
    }
    // BC-1, BC-2: derm's gate under an older derm's fixed name, which a
    // repository's own entry of that name replaces or switches off.
    let fixed = |text: &str| row.markers.iter().any(|m| text.contains(m.as_str()));
    for at in &legacy {
        let file = resolve(at, home, &cenv);
        if std::fs::read_to_string(&file).is_ok_and(|t| fixed(&t)) {
            out.push(format!(
                "{} is derm's gate under the fixed name `{}`, which a repository's own plugin of that name can replace or switch off (note BC, BC-1): run `derm connect {id} --gate --write` again, then remove that folder",
                file.parent().and_then(Path::parent).unwrap_or(&file).display(),
                row.legacy_name.as_deref().unwrap_or("")
            ));
        }
    }
    if let Some(old) = row.legacy_name.as_deref() {
        for st in &row.steps {
            let Step::TomlArrayEntry { at, .. } = st else {
                continue;
            };
            if !st.takes_gate_name() {
                continue;
            }
            let file = resolve(at, home, &cenv);
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
                continue;
            };
            let named_old = doc
                .get("hooks")
                .and_then(|h| h.as_array_of_tables())
                .is_some_and(|aot| {
                    aot.iter().any(|t| {
                        t.get("name").and_then(|v| v.as_str()) == Some(old)
                            && t.get("command").and_then(|v| v.as_str()).is_some_and(fixed)
                    })
                });
            if named_old {
                out.push(format!(
                    "{} names derm's gate `{old}`, a name a project's own hooks.toml can take first (note BC, BC-2): run `derm connect {id} --gate --write` again",
                    file.display()
                ));
            }
        }
    }
    out
}

/// Whether `text` holds `hook <id> ` after a program that is not an
/// absolute path (`derm hook crush pre`, `"derm" hook crush pre`).
fn bare_derm_hook(text: &str, id: &str) -> bool {
    // BW5B-1: the same reader `derm connect` finds its own entry with, so
    // the fix this names (`--gate --write`) replaces what it names.
    crate::connect::gate::derm_hook_runs(text, id).contains(&false)
}

/// What node needs from a cleared environment on Windows besides HOME and
/// PATH. Without `SystemRoot`, node 24 aborts before any script runs, in
/// `InitializeOncePerProcessInternal` (exit 134; CI's Windows job, node
/// 24.22.2), where it checks that OpenSSL's CSPRNG seeds (`src/node.cc`,
/// `CHECK(ncrypto::CSPRNG(nullptr, 0))`); Windows' crypto providers resolve
/// their DLLs through `%SystemRoot%` ("Always, always include SystemRoot
/// when passing a custom environment block to CreateProcess",
/// https://jpassing.com/2009/12/28/the-hidden-danger-of-forgetting-to-specify-systemroot-in-a-custom-environment-block).
/// `USERPROFILE` is Windows' HOME. srt's sandbox keeps the same two from the
/// account's profile (`enter/handoff.rs`, `RESERVED`). From lane/windows-ci.
#[cfg(windows)]
const NODE_WINDOWS_ENV: &[&str] = &["SystemRoot", "USERPROFILE"];
#[cfg(not(windows))]
const NODE_WINDOWS_ENV: &[&str] = &[];

/// Runs the installed hook once on a shell call, under a policy that denies
/// `bash`, from a folder of its own (the hook refuses a `DERM_POLICY` inside
/// the session folder). Pass: the agent's own deny form.
pub fn run_fixture(id: &str, env: &Env, probes: &Probes) -> Value {
    let hook = match installed_hook(id, env) {
        Ok(h) => h,
        Err(why) => return json!({"state": "not run", "why": why}),
    };
    let launcher = is_launcher(&hook);
    let node = probes.node.clone();
    if !launcher && node.is_none() {
        return json!({"state": "not run", "why": "node is not on PATH"});
    }
    let scratch =
        std::env::temp_dir().join(format!("derm-doctor-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| -> Result<Value, String> {
        let work = scratch.join("work");
        let pol = scratch.join("policy");
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&pol).map_err(|e| e.to_string())?;
        for d in [&scratch, &work, &pol] {
            // The seam's `set_private_dir` is `chmod 0700` on Unix.
            derm_core::platform::set_private_dir(d).map_err(|e| e.to_string())?;
        }
        let policy = pol.join("policy.json");
        let mut f = derm_core::platform::private_no_follow(
            std::fs::OpenOptions::new().write(true).create_new(true),
        )
        .open(&policy)
        .map_err(|e| e.to_string())?;
        std::io::Write::write_all(
            &mut f,
            br#"{"version":1,"rules":[{"tool":"bash","action":"deny"}]}"#,
        )
        .map_err(|e| e.to_string())?;
        // The agent's own input for a shell call (contracts/fixtures/
        // hook-dialects; Gemini's tool is `run_shell_command`).
        let input = if id == "gemini" {
            json!({
                "session_id": "derm-doctor",
                "hook_event_name": "BeforeTool",
                "tool_name": "run_shell_command",
                "tool_input": {"command": "rm -rf derm-doctor-canary"},
                "cwd": work,
                "timestamp": "2026-11-11T00:00:00.000Z",
            })
        } else {
            json!({
                "session_id": "derm-doctor",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf derm-doctor-canary"},
                "tool_use_id": "derm-doctor-1",
                "cwd": work,
                "permission_mode": "default",
            })
        };
        let event = if id == "gemini" { "before" } else { "pre" };
        let mut cmd = if launcher {
            // As the agent runs it: /bin/sh by its absolute path on the
            // launcher, which runs `derm hook <agent> <event>` from derm's
            // install folders (never PATH).
            let mut c = Command::new("/bin/sh");
            c.arg(&hook).arg(id).arg(event);
            c
        } else {
            let mut c = Command::new(node.as_ref().expect("checked above"));
            c.arg("--no-warnings").arg(&hook).arg(event);
            c
        };
        cmd.current_dir(&work)
            .env_clear()
            .env("DERM_POLICY", &policy)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // HOME is doctor's own (the launcher finds derm under it); PATH only
        // for node, which the launcher never reads.
        if let Some(h) = &env.home {
            cmd.env("HOME", h);
        }
        if let Some(v) = std::env::var_os("PATH").filter(|_| !launcher) {
            cmd.env("PATH", v);
        }
        // An older plugin's node on Windows needs these too (lane/windows-ci,
        // `NODE_WINDOWS_ENV`); the launcher never runs there.
        if !launcher {
            for k in NODE_WINDOWS_ENV {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("{}: {e}", if launcher { "/bin/sh" } else { "node" }))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = std::io::Write::write_all(&mut stdin, input.to_string().as_bytes());
        }
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if start.elapsed() < HOOK_TIMEOUT => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(
                        json!({"state": "fail", "hook": hook, "saw": format!("no answer in {} s", HOOK_TIMEOUT.as_secs())}),
                    );
                }
            }
        };
        let mut out = String::new();
        let mut err = String::new();
        if let Some(mut o) = child.stdout.take() {
            let _ = std::io::Read::read_to_string(&mut o, &mut out);
        }
        if let Some(mut e) = child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut e, &mut err);
        }
        let code = status.code();
        let denied = match id {
            // Claude Code: a deny decision on exit 0, or exit 2.
            "claude-code" => {
                code == Some(2)
                    || serde_json::from_str::<Value>(out.trim())
                        .ok()
                        .and_then(|v| {
                            v.pointer("/hookSpecificOutput/permissionDecision")
                                .and_then(Value::as_str)
                                .map(|d| d == "deny")
                        })
                        .unwrap_or(false)
            }
            // Gemini: its JSON deny, on exit 0 or 2.
            "gemini" => serde_json::from_str::<Value>(out.trim())
                .ok()
                .is_some_and(|v| v["decision"] == "deny" || v["decision"] == "block"),
            // Codex: exit 2 with a reason on stderr.
            _ => code == Some(2) && err.trim_start().starts_with("derm:"),
        };
        // A hook that fails to load also exits 2 (it fails closed): only a
        // denial that names the policy's rule shows the gate itself ran.
        let on_rule = out.contains("rule bash") || err.contains("rule bash");
        let state = match (denied, on_rule) {
            (true, true) => "pass",
            (true, false) => "fail-closed",
            _ => "fail",
        };
        let saw = format!(
            "exit {}, {}",
            code.map(|c| c.to_string())
                .unwrap_or_else(|| "on a signal".into()),
            crate::watch::text::clean(if out.trim().is_empty() { &err } else { &out }, 160)
        );
        Ok(json!({"state": state, "hook": hook, "saw": saw}))
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    result.unwrap_or_else(|why| json!({"state": "not run", "why": why}))
}

pub fn render(r: &Value) -> String {
    let s = |p: &str| {
        r.pointer(p)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let clean = |t: &str| crate::watch::text::clean(t, 400);
    let mut out = format!(
        "derm doctor {} ({}), derm {}, {} {}\n",
        s("/agent"),
        clean(&s("/name")),
        s("/derm"),
        s("/os"),
        s("/arch")
    );
    let version = match s("/version/state").as_str() {
        "matches" => format!("{}, as verified", s("/version/installed")),
        "unverified" => format!(
            "{}: unverified at {} (derm's row was verified at {})",
            s("/version/installed"),
            s("/version/installed"),
            s("/version/verifiedAt")
        ),
        "not found" => "not found on PATH".into(),
        _ => format!("unknown ({})", clean(&s("/version/probe"))),
    };
    out.push_str(&format!(
        "  program:    {}\n  version:    {version}\n",
        if s("/program").is_empty() {
            "-".into()
        } else {
            clean(&s("/program"))
        }
    ));
    let gate = match s("/gate/status").as_str() {
        "built" => format!(
            "built ({}): {}",
            s("/gate/family"),
            clean(&s("/gate/where"))
        ),
        "planned" => format!(
            "planned, wave {} lane {}",
            r.pointer("/gate/wave").and_then(Value::as_u64).unwrap_or(0),
            s("/gate/lane")
        ),
        other => other.to_string(),
    };
    out.push_str(&format!("  gate:       {gate}\n"));
    out.push_str(&format!("  registered: {}", s("/registered")));
    if let Some(d) = r.get("registeredDetail").and_then(Value::as_str) {
        out.push_str(&format!(" ({})", clean(d)));
    }
    out.push('\n');
    let fail = match s("/failMode").as_str() {
        "blocks" => "blocks".to_string(),
        "blocks-with-switch" => format!(
            "blocks, with {}",
            r.get("failSwitch")
                .and_then(Value::as_str)
                .unwrap_or("its switch")
        ),
        "open" => "FAILS OPEN: a crashed or slow gate lets the call through".into(),
        "open-on-timeout" => "FAILS OPEN on a timeout".into(),
        _ => "unknown".into(),
    };
    out.push_str(&format!("  when the gate fails: {fail}\n"));
    out.push_str(&format!(
        "  ask goes to: {}\n",
        match s("/ask").as_str() {
            "own-prompt" => "its own prompt",
            "approver-or-deny" => "derm's approver, else deny",
            _ => "unknown",
        }
    ));
    let shadows = r
        .get("shadows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if shadows.is_empty() {
        out.push_str("  shadows:    none found\n");
    } else {
        out.push_str("  shadows:\n");
        for sh in shadows {
            out.push_str(&format!(
                "    {}: {}\n",
                clean(sh["path"].as_str().unwrap_or("")),
                clean(sh["what"].as_str().unwrap_or(""))
            ));
        }
    }
    let gr = r.get("gateRun").cloned().unwrap_or(Value::Null);
    out.push_str(&format!(
        "  gate run:   {}\n",
        match gr["state"].as_str().unwrap_or("") {
            "pass" => format!(
                "pass: the installed gate ({}) denied a denied shell call",
                clean(gr["hook"].as_str().unwrap_or(""))
            ),
            "fail" => format!("FAIL: {}", clean(gr["saw"].as_str().unwrap_or(""))),
            "fail-closed" => format!(
                "BLOCKED, not on the rule (the hook failed closed): {}",
                clean(gr["saw"].as_str().unwrap_or(""))
            ),
            _ => format!("not run: {}", clean(gr["why"].as_str().unwrap_or(""))),
        }
    ));
    out.push_str(&format!("  live:       {}\n", s("/live")));
    let problems = r
        .get("problems")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if problems.is_empty() {
        out.push_str("\nnothing to do");
    } else {
        out.push_str("\nto look at:\n");
        for p in problems {
            out.push_str(&format!("  - {}\n", clean(p.as_str().unwrap_or(""))));
        }
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests;
