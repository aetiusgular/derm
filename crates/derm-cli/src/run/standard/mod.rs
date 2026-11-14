//! The Standard tier (wave 6, lane 6A; `plans/toolkit_wave6_plan.md` section
//! 2.1; `contracts/sandbox.md`): the agent's own per-command sandbox, written
//! from derm's paths and handed to it by `derm run`, never by the user's
//! files alone. `run_io` calls [`environment`] once the plan is built, after
//! the tap's, and adds the returned record to `run.start` as `detail.tier`
//! (`contracts/events.md` section 6.1).
//!
//! What it does, from note AZ (rows A1 to A11, AZ-7) and the runs recorded
//! in `plans/parallel/tk_lane_6A.md` (Research):
//!
//! - No `--tier` and a `whole` default (Tony's call of 12 Nov): nothing, no
//!   record; lane T's boundary choice runs unchanged.
//! - `--tier standard` under srt: one tier, srt's (vendor sandboxes do not
//!   start inside it, A8; case 215). Under sbx: the vendor sandbox stays on
//!   inside the VM (A8, run on sbx 0.53.0). Under none: the Standard tier
//!   alone.
//! - Claude Code 2.1.322: derm's block as the last `--settings` of the
//!   command line. Claude Code reads one `--settings`, the last (run: a later
//!   one turned the sandbox off, an earlier one was not read), so the user's
//!   own `--settings` is refused. A user or managed file's sandbox keys merge
//!   with the block (run: `filesystem.allowRead` re-opened a denied read,
//!   `allowWrite` and `permissions.additionalDirectories` widened writes,
//!   `excludedCommands` took a command out of the sandbox, a managed
//!   `enabled: false` turned it off), so any sandbox key outside derm's block
//!   is refused, a project's too (it was dropped at 2.1.322, run; refused so
//!   a later version cannot widen the block unnoticed, contract section 6).
//! - Codex 0.167.2: `default_permissions="derm"` and the profile as `-c`
//!   pairs at derm's own `-c` level (case 184). A config layer that defines
//!   `[permissions.derm]` merges into it (run: an extra write root widened
//!   it), and `-s`, `--sandbox` or a later `-c default_permissions` replace
//!   it (run), so each is refused.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::args::{Boundary, Tier};
use super::plan::Plan;

// The writers live in `connect/sandbox/` (lane 6A's too).
use crate::connect::sandbox as writers;

use writers::Context;

/// What the seam reads beyond the plan. [`environment`] gathers it from the
/// process; the tests give their own.
pub(crate) struct Inputs {
    pub home: Option<String>,
    pub cwd: Option<String>,
    /// `CLAUDE_CONFIG_DIR` when absolute: Claude Code's user settings folder.
    pub claude_config_dir: Option<String>,
    /// `CODEX_HOME` when absolute.
    pub codex_home: Option<String>,
    /// Claude Code's managed settings file (and its `.d` folder beside it).
    pub claude_managed: PathBuf,
    /// Codex's system config (`/etc/codex/config.toml`).
    pub codex_system: PathBuf,
    pub daemon_dir: Option<String>,
    pub data_dir: Option<String>,
    pub windows: bool,
    /// Linux only: what decides whether Claude Code's own sandbox can run a
    /// command here (box test w6, BW6-1): the bubblewrap it will run (the
    /// first `bwrap` on PATH, by its real path), whether Ubuntu's
    /// `bwrap-userns-restrict` profile is installed, and the userns sysctl.
    pub linux_bwrap: Option<LinuxBwrap>,
}

/// The facts `preflight::apparmor_note_for` reads, for the Standard tier.
#[derive(Clone, Debug, Default)]
pub(crate) struct LinuxBwrap {
    pub bwrap: Option<String>,
    pub profile: bool,
    pub userns: Option<String>,
}

impl Inputs {
    fn real(plan: &Plan) -> Self {
        let home =
            derm_core::runtime::home_dir().and_then(|h| h.into_os_string().into_string().ok());
        let abs_var = |k: &str| std::env::var(k).ok().filter(|v| super::args::absolute(v));
        Inputs {
            data_dir: home
                .as_deref()
                .map(|h| super::content_root(h).to_string_lossy().into_owned()),
            home,
            cwd: plan.folders.first().cloned().or_else(|| {
                std::env::current_dir()
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned())
            }),
            claude_config_dir: abs_var("CLAUDE_CONFIG_DIR"),
            codex_home: abs_var("CODEX_HOME"),
            claude_managed: PathBuf::from(if cfg!(target_os = "macos") {
                "/Library/Application Support/ClaudeCode/managed-settings.json"
            } else {
                "/etc/claude-code/managed-settings.json"
            }),
            codex_system: PathBuf::from("/etc/codex/config.toml"),
            daemon_dir: derm_audit_linux::client::socket_path()
                .and_then(|s| s.parent().map(|d| d.to_string_lossy().into_owned())),
            windows: cfg!(windows),
            linux_bwrap: cfg!(target_os = "linux").then(|| {
                let path = std::env::var("PATH").unwrap_or_default();
                let cwd = std::env::current_dir()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                LinuxBwrap {
                    bwrap: super::preflight::first_on_path(&path, "bwrap", &cwd).map(|b| {
                        std::fs::canonicalize(&b)
                            .map(|r| r.to_string_lossy().into_owned())
                            .unwrap_or(b)
                    }),
                    profile: Path::new(super::boundary::probe::UBUNTU_BWRAP_PROFILE).exists(),
                    userns: std::fs::read_to_string(
                        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                    )
                    .ok(),
                }
            }),
        }
    }
}

/// The seam `run_io` calls. `Ok(None)`: no tier record (no `--tier` and a
/// `whole` default). An `Err` stops the run before the harness starts.
pub(crate) fn environment(
    harness: &str,
    boundary: Boundary,
    tier: Option<Tier>,
    plan: &mut Plan,
) -> Result<Option<Value>, (u8, String)> {
    let inputs = Inputs::real(plan);
    environment_with(harness, boundary, tier, plan, &inputs)
}

/// `tier.default` from `~/.derm/settings.json`, read only from a file
/// `derm_tap::settings::load` accepts (a regular file of the user's that no
/// one else may write), and a warning when it is not used.
fn tier_default(home: Option<&str>) -> (Option<Tier>, Option<String>) {
    let Some(home) = home else {
        return (None, None);
    };
    let path = derm_tap::settings::path_for(home);
    if std::fs::symlink_metadata(&path).is_err() {
        return (None, None);
    }
    let (_, warning) = derm_tap::settings::load(&path);
    if let Some(w) = warning {
        return (None, Some(w));
    }
    let Some(v) = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    else {
        return (
            None,
            Some(format!("{} could not be read again", path.display())),
        );
    };
    match v.get("tier") {
        None => (None, None),
        Some(t) => match t.get("default").map(|d| d.as_str()) {
            None if t.is_object() && t.as_object().is_some_and(|o| o.is_empty()) => (None, None),
            Some(Some("standard")) if t.as_object().is_some_and(|o| o.len() == 1) => {
                (Some(Tier::Standard), None)
            }
            Some(Some("whole")) if t.as_object().is_some_and(|o| o.len() == 1) => {
                (Some(Tier::Whole), None)
            }
            _ => (
                None,
                Some(format!(
                    "{} has a tier the schema does not allow (tier.default is \"standard\" or \"whole\"); the default, whole, applies",
                    path.display()
                )),
            ),
        },
    }
}

/// The harness's row in `presets/wave6/sandbox.json`, as merged into the
/// preset table.
fn sandbox_row(harness: &str) -> Option<Value> {
    let table: Value = serde_json::from_str(crate::connect::presets::table_json()).ok()?;
    ["harnesses", "planned"].iter().find_map(|list| {
        table
            .get(*list)?
            .as_array()?
            .iter()
            .find(|r| r.get("id").and_then(Value::as_str) == Some(harness))
            .and_then(|r| r.get("sandbox").cloned())
            .filter(|s| !s.is_null())
    })
}

fn boundary_name(b: Boundary) -> &'static str {
    match b {
        Boundary::Sbx => "sbx",
        Boundary::Srt => "srt",
        Boundary::None => "none",
    }
}

/// Where the harness's own words start in `plan.args`: after sbx's `--`
/// under sbx (made when the plan has none), else at 0.
fn harness_words_start(plan: &mut Plan) -> usize {
    if plan.program != "sbx" {
        return 0;
    }
    match plan.args.iter().position(|a| a == "--") {
        Some(p) => p + 1,
        None => {
            plan.args.push("--".into());
            plan.args.len()
        }
    }
}

pub(crate) fn environment_with(
    harness: &str,
    boundary: Boundary,
    tier: Option<Tier>,
    plan: &mut Plan,
    i: &Inputs,
) -> Result<Option<Value>, (u8, String)> {
    let asked = match tier {
        Some(t) => t,
        None => {
            let (d, warning) = tier_default(i.home.as_deref());
            if let Some(w) = warning {
                plan.notes.push(format!("derm run: {w}"));
            }
            match d {
                Some(Tier::Standard) => Tier::Standard,
                // A `whole` default, said or not: nothing changes.
                _ => return Ok(None),
            }
        }
    };
    if asked == Tier::Whole {
        return Ok(Some(json!({"tier": "whole", "asked": "whole"})));
    }
    let row = sandbox_row(harness);
    let via = row
        .as_ref()
        .and_then(|r| r.get("via"))
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_string();
    let verified = row
        .as_ref()
        .and_then(|r| r.get("verifiedAt"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let whole = |why: &str| json!({"tier": "whole", "asked": "standard", "why": why, "via": via});
    // An agent derm writes no sandbox for, or one whose tier a project can
    // widen (Cursor, contract section 4).
    if via != "settings-flag" && via != "config-override" {
        let what = if via == "advisory" {
            match i.cwd.as_deref().map(|c| writers::cursor_repo_widening(Path::new(c))) {
                Some(Ok(keys)) if !keys.is_empty() => format!(
                    "{harness}'s own sandbox is not held by derm: its CLI merges a repository's .cursor/sandbox.json with yours, and this one sets {} (note AZ A6)",
                    keys.join(", ")
                ),
                Some(Err(e)) => format!(
                    "{harness}'s own sandbox is not held by derm: its CLI merges a repository's .cursor/sandbox.json with yours, and {e} (note AZ A6)"
                ),
                _ => format!(
                    "{harness}'s own sandbox is not held by derm: its CLI merges a repository's .cursor/sandbox.json with yours, which can widen it (note AZ A6)"
                ),
            }
        } else {
            // WW6-10: `other` is a program derm does not know.
            if harness == "other" {
                "derm writes no sandbox for this program".to_string()
            } else {
                format!("derm writes no sandbox of {harness}'s own")
            }
        };
        if boundary == Boundary::None {
            return Err((
                2,
                format!(
                    "--tier standard: {what}, and --boundary none puts nothing around it; run it under srt or sbx (--tier whole), or leave --tier out"
                ),
            ));
        }
        plan.notes.push(format!(
            "derm run: --tier standard: {what}; this chat runs the Whole tier ({})",
            boundary_name(boundary)
        ));
        return Ok(Some(whole(if via == "advisory" {
            "advisory"
        } else {
            "no-sandbox-row"
        })));
    }
    if i.windows {
        return Err((
            2,
            format!(
                "--tier standard: derm writes {harness}'s own sandbox on Linux and macOS only (verified at {verified} there); run --tier whole"
            ),
        ));
    }
    // Box test w6, BW6-1: on Ubuntu 26.04 Claude Code 2.1.322's sandbox
    // started, and every command then died in its own seccomp step
    // (`apply-seccomp: write /proc/self/setgroups (nested userns is
    // capability-restricted; caller must provide CAP_SYS_ADMIN): Permission
    // denied`), with no `failIfUnavailable` refusal: Ubuntu's
    // `bwrap-userns-restrict` runs everything `/usr/bin/bwrap` starts under
    // `unpriv_bwrap`, which denies that capability, as it does for srt (the
    // same `apply-seccomp`; `preflight::apparmor_note_for`). Claude Code
    // takes the first `bwrap` on PATH unless managed settings set
    // `sandbox.bwrapPath` (2.1.322's bundle: `fN("bwrap")`, `ps` lists
    // `bwrapPath` among the managed-only keys). Under sbx the VM's kernel is
    // not this host's, so this is checked with no boundary only.
    if harness == "claude-code" && boundary == Boundary::None {
        if let Some(b) = &i.linux_bwrap {
            let bwrap = b.bwrap.as_deref().unwrap_or(super::preflight::UBUNTU_BWRAP);
            if super::preflight::apparmor_note_for(true, b.profile, b.userns.as_deref(), bwrap)
                .is_some()
            {
                let why = if b.profile {
                    format!(
                        "Ubuntu's AppArmor profile {} runs everything {bwrap} starts under unpriv_bwrap, which denies the CAP_SYS_ADMIN Claude Code's seccomp step needs, so every command it runs fails (apply-seccomp: write /proc/self/setgroups ... Permission denied)",
                        super::boundary::probe::UBUNTU_BWRAP_PROFILE
                    )
                } else {
                    "kernel.apparmor_restrict_unprivileged_userns is 1, which takes the capabilities Claude Code's bubblewrap and seccomp step need, so every command it runs fails".to_string()
                };
                return Err((
                    2,
                    format!(
                        "--tier standard: Claude Code's own sandbox cannot run a command on this host: {why}. Claude Code runs the first bwrap on PATH; with the bubblewrap copy docs/install/linux.md describes for srt first on PATH it starts. Or leave --tier out, or run --tier whole under srt or sbx"
                    ),
                ));
            }
        }
    }
    if boundary == Boundary::Srt {
        plan.notes.push(format!(
            "derm run: one tier: whole (srt): {harness}'s own sandbox does not start inside srt's (note AZ A8), so srt is this chat's only sandbox; for the Standard tier alone, run with --boundary none"
        ));
        return Ok(Some(whole("srt-no-nesting")));
    }
    let home = i.home.clone().filter(|h| h.starts_with('/')).ok_or((
        2,
        "--tier standard: HOME is not an absolute path".to_string(),
    ))?;
    let cwd = i.cwd.clone().unwrap_or_default();
    let mut folders = plan.folders.clone();
    if folders.is_empty() && !cwd.is_empty() {
        folders.push(cwd.clone());
    }
    let start = harness_words_start(plan);
    let words: Vec<String> = plan.args[start..].to_vec();
    let added_dirs = if harness == "claude-code" {
        claude_refusals(&words, i, &cwd)?
    } else {
        codex_refusals(&words, i, &home, &cwd)?;
        Vec::new()
    };
    for d in &added_dirs {
        if !folders.contains(d) {
            folders.push(d.clone());
        }
        if !plan.folders.contains(d) {
            plan.folders.push(d.clone());
        }
    }
    // MW6-4: a brokered chat (this tier with no srt or sbx) admits its
    // secrets' hosts, so their requests reach derm-egress.
    let allowed_domains = if crate::secret::chain::brokered("standard", boundary_name(boundary)) {
        crate::secret::secret_hosts(Path::new(&home))
    } else {
        Vec::new()
    };
    let ctx = Context {
        home,
        folders,
        daemon_dir: i.daemon_dir.clone(),
        data_dir: i.data_dir.clone(),
        allowed_domains,
        tmp_to_chat: tmp_to_chat(harness, boundary),
    };
    let pinned = if harness == "claude-code" {
        let text =
            serde_json::to_string(&writers::claude_block(&ctx)).map_err(|e| (1, e.to_string()))?;
        // Last, so no other `--settings` replaces it: the export's, which
        // `run_io` adds later before the user's words, included (request
        // 6A-2: until it merges into this block, Claude Code does not read
        // its `otelHeadersHelper`).
        plan.args.extend(["--settings".to_string(), text.clone()]);
        plan.notes.push(format!(
            "derm run: tier: standard: Claude Code's own sandbox, from derm's --settings block (the last on its command line, so Claude Code reads no other): its Bash, PowerShell and Monitor commands cannot read your secrets, the agents' sign-ins or derm's folders, write outside this chat's folders, or reach the network unless you allow a host when it asks; its file tools, MCP servers and hooks run outside that sandbox, under derm's gate (note AZ A7){}",
            if boundary == Boundary::Sbx { "; under sbx it runs inside the VM too (note AZ A8)" } else { "" }
        ));
        text
    } else {
        let pairs = writers::codex_pairs(&ctx);
        let mut at = start;
        if plan
            .args
            .get(at)
            .is_some_and(|w| super::tap::CODEX_SESSION_SUBCOMMANDS.contains(&w.as_str()))
        {
            at += 1;
        }
        plan.args.splice(at..at, pairs.iter().cloned());
        plan.notes.push(format!(
            "derm run: tier: standard: Codex's own sandbox, from derm's permission profile \"{}\" given with -c (Codex's session flags outrank every config file): its commands cannot read your secrets, the agents' sign-ins or derm's folders, write outside this chat's folders, or reach the network{}",
            writers::CODEX_PROFILE,
            if boundary == Boundary::Sbx {
                "; under sbx it runs inside the VM too (note AZ A8), where /tmp is the VM's"
            } else {
                "; /tmp is read-only to them, and their temporary files go to a folder of this chat's own (TMPDIR), removed when the chat ends"
            }
        ));
        pairs[3].clone()
    };
    if !verified.is_empty() {
        // Mac test w6, MW6-3: under sbx the VM runs sbx's own image of the
        // agent (Claude Code 2.1.323 there on 13 Nov), not the host's.
        plan.notes.push(if boundary == Boundary::Sbx {
            format!(
                "derm run: {harness}'s Standard tier is verified at {verified}; under sbx the VM runs sbx's own {harness}, at the version sbx's image holds, not the one installed here"
            )
        } else {
            format!(
                "derm run: {harness}'s Standard tier is verified at {verified}; `derm doctor` names an installed version that differs"
            )
        });
    }
    let mut rec = json!({
        "tier": "standard",
        "asked": "standard",
        "via": via,
        "pinSha256": writers::pin(&pinned),
    });
    if boundary == Boundary::Sbx {
        rec["vendorUnderSbx"] = json!("on");
    }
    Ok(Some(rec))
}

/// Box test w6, BW6-2: Codex's `:workspace` writes `/tmp`, which every
/// chat and every user's programs share, so with no boundary derm's profile
/// makes it read-only and `derm run` gives Codex a `TMPDIR` of the chat's
/// own (`chat_tmp_dir`). Under sbx `/tmp` is the VM's, and a host folder
/// named in `TMPDIR` would not be there.
pub fn tmp_to_chat(harness: &str, boundary: Boundary) -> bool {
    harness == "codex" && boundary == Boundary::None
}

/// Whether this chat's record is the Standard tier with Codex's `/tmp`
/// kept to the chat (`tmp_to_chat`): then `derm run` makes the folder.
pub fn wants_chat_tmp(harness: &str, boundary: Boundary, record: Option<&Value>) -> bool {
    tmp_to_chat(harness, boundary)
        && record.and_then(|r| r.get("tier")).and_then(Value::as_str) == Some("standard")
}

/// The chat's own temporary folder for `TMPDIR` (BW6-2): a name no one can
/// make first (a random part, as the trust folder's, review W6C-S9), made
/// with `create_dir` so a folder already there is refused, 0700. A dry run
/// names it and makes nothing.
pub fn chat_tmp_dir(temp: &Path, chat: &str, dry_run: bool) -> Result<PathBuf, String> {
    if dry_run {
        return Ok(temp.join(format!("derm-tmp-{chat}-<random>")));
    }
    let dir = temp.join(format!("derm-tmp-{chat}-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)) {
            let _ = std::fs::remove_dir(&dir);
            return Err(format!("{}: {e}", dir.display()));
        }
    }
    Ok(dir)
}

/// A settings file Claude Code reads, and which layer it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Layer {
    Managed,
    User,
    Project,
}

/// Every settings file Claude Code 2.1.322 may read besides derm's block:
/// the managed file and its `.d` folder, the user's (`CLAUDE_CONFIG_DIR`,
/// else `~/.claude`), and a project's `.claude/settings.json` and
/// `settings.local.json` in the working folder and each folder above it
/// (more than Claude Code reads, on purpose: a refusal is the side that
/// fails safe).
fn claude_files(i: &Inputs, cwd: &str) -> Vec<(PathBuf, Layer)> {
    let mut out = vec![(i.claude_managed.clone(), Layer::Managed)];
    if let Some(dir) = i
        .claude_managed
        .parent()
        .map(|p| p.join("managed-settings.d"))
    {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            let mut more: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect();
            more.sort();
            out.extend(more.into_iter().map(|p| (p, Layer::Managed)));
        }
    }
    let user_dir = i
        .claude_config_dir
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| i.home.as_ref().map(|h| Path::new(h).join(".claude")));
    if let Some(d) = user_dir {
        out.push((d.join("settings.json"), Layer::User));
    }
    let mut dir = Some(Path::new(cwd));
    while let Some(d) = dir.filter(|d| !d.as_os_str().is_empty()) {
        out.push((d.join(".claude/settings.json"), Layer::Project));
        out.push((d.join(".claude/settings.local.json"), Layer::Project));
        dir = d.parent();
    }
    out
}

/// A JSON file's value: `Ok(None)` when absent, `Err` when it is there and
/// cannot be read whole.
fn json_file(path: &Path) -> Result<Option<Value>, String> {
    let meta = match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{} could not be read ({e})", path.display())),
        Ok(m) => m,
    };
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.len() > 1 << 20 {
        return Err(format!(
            "{} is over 1 MiB, so derm did not read it",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{} could not be read ({e})", path.display()))?;
    if text.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|_| format!("{} is not JSON derm can read", path.display()))
}

/// The dotted names of `v`'s keys under `prefix`, one level into objects.
fn key_names(prefix: &str, v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(o) = v.as_object() {
        for (k, x) in o {
            match x.as_object() {
                Some(inner) if !inner.is_empty() => {
                    out.extend(inner.keys().map(|k2| format!("{prefix}.{k}.{k2}")));
                }
                _ => out.push(format!("{prefix}.{k}")),
            }
        }
    }
    out
}

/// Claude Code: refuses what would widen or replace derm's block (case 214
/// and the runs above); returns the folders the user's own `--add-dir`
/// names, which widen the sandbox's writes and become the chat's folders.
fn claude_refusals(words: &[String], i: &Inputs, cwd: &str) -> Result<Vec<String>, (u8, String)> {
    let refuse = |why: String| Err((2, format!("--tier standard: {why}; or run --tier whole")));
    let mut added = Vec::new();
    let mut k = 0;
    while k < words.len() {
        let w = words[k].as_str();
        if w == "--" {
            return refuse(
                "the harness's words hold `--`, after which Claude Code would read derm's --settings as part of the prompt".into(),
            );
        }
        if w == "--settings" || w.starts_with("--settings=") {
            return refuse(
                "the harness's words carry their own --settings, and Claude Code reads only the last --settings (run on 2.1.322: a later one turned derm's sandbox off, an earlier one was not read); put those settings in ~/.claude/settings.json".into(),
            );
        }
        let dir = if w == "--add-dir" {
            k += 1;
            words.get(k).map(String::as_str)
        } else {
            w.strip_prefix("--add-dir=")
        };
        if let Some(d) = dir {
            let p = if d.starts_with('/') {
                d.to_string()
            } else {
                format!("{}/{d}", cwd.trim_end_matches('/'))
            };
            added.push(p);
        }
        k += 1;
    }
    for (file, layer) in claude_files(i, cwd) {
        let v = match json_file(&file) {
            Ok(None) => continue,
            Ok(Some(v)) => v,
            Err(e) => {
                return refuse(format!(
                    "{e}, so derm cannot tell whether it widens Claude Code's sandbox"
                ))
            }
        };
        if v.to_string().contains("dangerouslyDisableSandbox") {
            return refuse(format!(
                "{} names dangerouslyDisableSandbox (case 214)",
                file.display()
            ));
        }
        if let Some(s) = v.get("sandbox") {
            let keys = key_names("sandbox", s);
            let named = if keys.is_empty() {
                "sandbox".to_string()
            } else {
                keys.join(", ")
            };
            let why = if s.get("excludedCommands").is_some() {
                "excludedCommands takes a matching command out of the sandbox (note AZ AZ-7; run on 2.1.322 from a user file and from a --settings block)"
            } else {
                match layer {
                    Layer::User => "Claude Code merges a user file's sandbox keys with derm's block (run on 2.1.322: filesystem.allowRead re-opened a denied read, filesystem.allowWrite widened writes)",
                    Layer::Managed => "managed settings outrank derm's block (run on 2.1.322: a managed sandbox.enabled false turned it off, a managed filesystem.allowRead re-opened a denied read)",
                    Layer::Project => "Claude Code 2.1.322 drops a project's sandbox keys under derm's block (run), and derm refuses them so a later version cannot widen it unnoticed (contracts/sandbox.md section 6)",
                }
            };
            return refuse(format!(
                "{} sets {named} beside derm's sandbox block, and {why}; remove it",
                file.display()
            ));
        }
        if layer != Layer::Project {
            if let Some(d) = v.pointer("/permissions/additionalDirectories") {
                if d.as_array().is_some_and(|a| !a.is_empty()) {
                    return refuse(format!(
                        "{} sets permissions.additionalDirectories, which widens the sandbox's writes to those folders (run on 2.1.322); pass --add-dir on the command line instead, so derm records them as this chat's folders",
                        file.display()
                    ));
                }
            }
        }
    }
    Ok(added)
}

/// The keys of every `-c` pair in Codex's words, in each form clap reads
/// (`-c k=v`, `--config k=v`, `--config=k=v`, `-ck=v`, `-c=k=v`), up to `--`.
fn codex_config_keys(words: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut k = 0;
    while k < words.len() {
        let w = words[k].as_str();
        if w == "--" {
            break;
        }
        let pair = if w == "-c" || w == "--config" {
            k += 1;
            words.get(k).map(String::as_str)
        } else if let Some(p) = w.strip_prefix("--config=") {
            Some(p)
        } else if w.starts_with("-c") && !w.starts_with("--") && w.len() > 2 {
            Some(w[2..].strip_prefix('=').unwrap_or(&w[2..]))
        } else {
            None
        };
        if let Some(p) = pair {
            out.push(p.split('=').next().unwrap_or("").trim().to_string());
        }
        k += 1;
    }
    out
}

/// Every config file Codex 0.167.2 layers (`config/src/loader/mod.rs:124-
/// 136`): the system file, the user's and its profile files, the working
/// folder's `config.toml`, and each folder's `.codex/config.toml` from the
/// working folder to the root (a repository's top included).
fn codex_files(i: &Inputs, home: &str, cwd: &str) -> Vec<PathBuf> {
    let mut out = vec![i.codex_system.clone()];
    let codex_home = i
        .codex_home
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(home).join(".codex"));
    out.push(codex_home.join("config.toml"));
    if let Ok(rd) = std::fs::read_dir(&codex_home) {
        let mut more: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".config.toml"))
            })
            .collect();
        more.sort();
        out.extend(more);
    }
    if !cwd.is_empty() {
        out.push(Path::new(cwd).join("config.toml"));
    }
    let mut dir = Some(Path::new(cwd));
    while let Some(d) = dir.filter(|d| !d.as_os_str().is_empty()) {
        out.push(d.join(".codex/config.toml"));
        dir = d.parent();
    }
    out
}

/// Codex: refuses what would replace or widen derm's profile.
fn codex_refusals(words: &[String], i: &Inputs, home: &str, cwd: &str) -> Result<(), (u8, String)> {
    let refuse = |why: String| Err((2, format!("--tier standard: {why}; or run --tier whole")));
    match super::plan::codex_own_sandbox(words) {
        super::plan::CodexOwnSandbox::Unset => {}
        super::plan::CodexOwnSandbox::Off => {
            return refuse(
                "the harness's words turn Codex's own sandbox off, which is the Standard tier's sandbox".into(),
            )
        }
        super::plan::CodexOwnSandbox::On(w) => {
            return refuse(format!(
                "`{w}` chooses Codex's sandbox on its command line, and it replaces derm's profile (run on 0.167.2: `-s workspace-write` and a later `-c default_permissions` each did)"
            ))
        }
    }
    if words.iter().any(|w| w == "--full-auto") {
        return refuse("--full-auto chooses Codex's legacy sandbox mode, which Codex reads instead of a permission profile".into());
    }
    for key in codex_config_keys(words) {
        if key == "permissions"
            || key.starts_with("permissions.")
            || key == "permission_profile"
            || key.starts_with("permission_profile.")
        {
            return refuse(format!(
                "-c {key} on the command line changes Codex's permission profiles, which derm's Standard profile is"
            ));
        }
    }
    for file in codex_files(i, home, cwd) {
        let text = match std::fs::metadata(&file) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return refuse(format!("{} could not be read ({e})", file.display())),
            Ok(m) if !m.is_file() => continue,
            Ok(m) if m.len() > 1 << 20 => {
                return refuse(format!(
                    "{} is over 1 MiB, so derm did not read it",
                    file.display()
                ))
            }
            Ok(_) => std::fs::read_to_string(&file).map_err(|e| {
                (
                    2,
                    format!(
                        "--tier standard: {} could not be read ({e})",
                        file.display()
                    ),
                )
            })?,
        };
        let doc: toml_edit::DocumentMut = match text.parse() {
            Ok(d) => d,
            Err(_) => {
                return refuse(format!(
                "{} is not TOML derm can read, so derm cannot tell whether it widens its profile",
                file.display()
            ))
            }
        };
        let names = doc
            .get("permissions")
            .and_then(|p| p.as_table_like())
            .is_some_and(|t| t.contains_key(writers::CODEX_PROFILE));
        if names {
            return refuse(format!(
                "{} defines [permissions.{}], which Codex merges into derm's profile of that name (run on 0.167.2: an extra write root there widened it); rename it",
                file.display(),
                writers::CODEX_PROFILE
            ));
        }
    }
    Ok(())
}

// The tier refuses Windows before it reads a path (`Inputs::windows`, which
// the Unix tests set to hold that refusal); the rest read Unix paths.
#[cfg(all(test, unix))]
mod tests;
