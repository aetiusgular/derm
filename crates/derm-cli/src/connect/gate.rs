//! `derm connect <agent> --gate --hook <package folder> [--node <path>]` and
//! `--ungate` (wave 4 lane Q, T2.8): register derm's gate in an agent's own
//! user-level files, or take it out, from the table in `gates.json`.
//!
//! The same rules as every `derm connect` write (lane C): a dry run first;
//! `--write` asks once on the terminal for every file, re-reads every file
//! and refuses if any changed since the diff (case 55) before the first
//! write, backs each file up and replaces it atomically; user-level files
//! under your home only (cases 65, 78); nothing for an agent that is not
//! installed (case 54). Beside an entry Orca or you already have, never in
//! its place (case 75); derm's own entry is found by the row's `marker`, so a
//! second `--gate` replaces it and never adds a second gate. `--ungate`
//! takes derm's entries out of shared files and never deletes a file or a
//! folder: it says which ones to remove. Agents whose gate installs through
//! their own command (Claude Code, Codex, Pi, oh-my-pi, Gemini, Hermes,
//! OpenClaw) get those commands printed, never run.
//!
//! The hook folder is the package that holds the gate (`--hook`): an
//! absolute path, not a link, owned by you or root and closed to others,
//! with a `package.json` naming the package the row expects. The gate then
//! runs every time the agent calls a tool, so a folder an agent or another
//! user can write would be a way around it (rules section 5, item 4).

use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use super::json::{self, Value};
use super::presets::Env;
use super::write::{self, Current};
use super::{diff, log, spec, Ctx};

const TABLE: &str = include_str!("gates.json");

#[derive(Clone, Debug)]
pub struct Agent {
    pub agent: String,
    pub name: String,
    pub package: String,
    pub hook_file: Option<String>,
    pub command: Option<String>,
    pub source: String,
    pub marker: Option<String>,
    pub installed_if: Vec<String>,
    pub cli: Option<String>,
    pub refuse_if_exists: Vec<String>,
    pub steps: Vec<Step>,
    pub notes: Vec<String>,
}

/// Where a file is: a `~/` path, moved by `homeEnv` (the variable replaces
/// the folder right under `~`) or, for `~/.config/...`, by
/// `XDG_CONFIG_HOME` when `xdgConfig`.
#[derive(Clone, Debug)]
pub struct Place {
    pub path: String,
    pub home_env: Option<String>,
    pub xdg_config: bool,
}

#[derive(Clone, Debug)]
pub enum Step {
    JsonArrayEntry {
        at: Place,
        jsonc: bool,
        array: Vec<String>,
        entry: Value,
        create_with: Option<Value>,
        chain: Vec<String>,
    },
    /// OpenCode's and Kilo's `permission` block: each key set to its value
    /// only where that narrows (see `plan_permission`).
    JsonPermission {
        at: Place,
        jsonc: bool,
        chain: Vec<String>,
        keys: Vec<(String, Value)>,
        fragment: String,
    },
    JsonMember {
        at: Place,
        jsonc: bool,
        object: Vec<String>,
        name: String,
        entry: Value,
    },
    TomlArrayEntry {
        at: Place,
        array: String,
        entry: Vec<(String, Value)>,
    },
    TomlSet {
        at: Place,
        table: Vec<String>,
        values: Vec<(String, Value)>,
    },
    OwnedFile {
        at: Place,
        content: Value,
    },
    PluginFolder {
        at: Place,
        files: Vec<(String, Value)>,
    },
    Commands {
        commands: Vec<String>,
        note: String,
        /// With `--hook <folder>`: the marketplace file to find above the
        /// folder, and the lines to print with `{marketplace_dir}` filled
        /// (Mac test w4, MW4-7).
        from_folder: Option<(String, Vec<String>)>,
    },
}

fn s<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    match v.get(key) {
        Some(Value::Str(x)) => Ok(x),
        _ => Err(format!("gates.json: `{key}` missing or not a string")),
    }
}

fn opt_s(v: &Value, key: &str) -> Option<String> {
    match v.get(key) {
        Some(Value::Str(x)) => Some(x.clone()),
        _ => None,
    }
}

fn strs(v: &Value, key: &str) -> Result<Vec<String>, String> {
    match v.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| match i {
                Value::Str(x) => Ok(x.clone()),
                _ => Err(format!("gates.json: `{key}` holds a non-string")),
            })
            .collect(),
        _ => Err(format!("gates.json: `{key}` is not a list")),
    }
}

fn members(v: &Value, key: &str) -> Result<Vec<(String, Value)>, String> {
    match v.get(key) {
        Some(Value::Object(m)) => Ok(m.clone()),
        _ => Err(format!("gates.json: `{key}` is not an object")),
    }
}

fn place(v: &Value) -> Result<Place, String> {
    let path = s(v, "path")?.to_string();
    if !path.starts_with("~/") {
        return Err(format!("gates.json: `{path}` is not under ~/"));
    }
    Ok(Place {
        path,
        home_env: opt_s(v, "homeEnv"),
        xdg_config: matches!(v.get("xdgConfig"), Some(Value::Bool(true))),
    })
}

fn jsonc(v: &Value) -> Result<bool, String> {
    match s(v, "format")? {
        "json" => Ok(false),
        "jsonc" => Ok(true),
        other => Err(format!("gates.json: format `{other}`")),
    }
}

fn step(v: &Value) -> Result<Step, String> {
    Ok(match s(v, "kind")? {
        "json-array-entry" => Step::JsonArrayEntry {
            at: place(v)?,
            jsonc: jsonc(v)?,
            array: strs(v, "array")?,
            entry: v.get("entry").cloned().ok_or("gates.json: no entry")?,
            create_with: v.get("createWith").cloned(),
            chain: strs(v, "mergeChain")?,
        },
        "json-permission" => Step::JsonPermission {
            at: place(v)?,
            jsonc: jsonc(v)?,
            chain: strs(v, "mergeChain")?,
            keys: members(v, "keys")?,
            fragment: s(v, "fragment")?.to_string(),
        },
        "json-member" => Step::JsonMember {
            at: place(v)?,
            jsonc: jsonc(v)?,
            object: strs(v, "object")?,
            name: s(v, "name")?.to_string(),
            entry: v.get("entry").cloned().ok_or("gates.json: no entry")?,
        },
        "toml-array-entry" => Step::TomlArrayEntry {
            at: place(v)?,
            array: s(v, "array")?.to_string(),
            entry: members(v, "entry")?,
        },
        "toml-set" => Step::TomlSet {
            at: place(v)?,
            table: strs(v, "table")?,
            values: members(v, "values")?,
        },
        "owned-file" => Step::OwnedFile {
            at: place(v)?,
            content: v.get("content").cloned().ok_or("gates.json: no content")?,
        },
        "plugin-folder" => Step::PluginFolder {
            at: place(v)?,
            files: members(v, "files")?,
        },
        "commands" => Step::Commands {
            commands: strs(v, "commands")?,
            note: s(v, "note")?.to_string(),
            from_folder: match v.get("fromFolder") {
                None => None,
                Some(f) => Some((s(f, "marketplaceFile")?.to_string(), strs(f, "commands")?)),
            },
        },
        other => return Err(format!("gates.json: unknown step kind `{other}`")),
    })
}

/// The table, read with derm connect's own JSON reader so every entry keeps
/// its key order (serde_json's map is sorted in this build).
pub fn table() -> Result<Vec<Agent>, String> {
    let doc = json::parse(TABLE, false).map_err(|e| format!("gates.json: {e}"))?;
    let root = doc.root.map(|n| n.to_value()).ok_or("gates.json: empty")?;
    let Some(Value::Array(rows)) = root.get("agents") else {
        return Err("gates.json: no agents".into());
    };
    rows.iter()
        .map(|r| {
            let steps = match r.get("steps") {
                Some(Value::Array(st)) => st.iter().map(step).collect::<Result<Vec<_>, _>>()?,
                _ => return Err("gates.json: no steps".into()),
            };
            Ok(Agent {
                agent: s(r, "agent")?.to_string(),
                name: s(r, "name")?.to_string(),
                package: s(r, "package")?.to_string(),
                hook_file: opt_s(r, "hookFile"),
                command: opt_s(r, "command"),
                source: s(r, "source")?.to_string(),
                marker: opt_s(r, "marker"),
                installed_if: strs(r, "installedIf")?,
                cli: opt_s(r, "cli"),
                refuse_if_exists: strs(r, "refuseIfExists")?,
                steps,
                notes: strs(r, "notes")?,
            })
        })
        .collect()
}

/// What fills the placeholders.
#[derive(Clone, Debug, Default)]
pub struct Vars {
    pub command: Option<String>,
    pub hook_dir: Option<String>,
    pub version: String,
}

/// Placeholders a whole string may be.
const WHOLE: &[&str] = &["{command}", "{hook_url}", "{hook_dir}", "{version}"];

/// Fills whole-string placeholders in `v`. Any other `{`...`}` that names a
/// placeholder is refused, so nothing is spliced into the middle of a value.
pub fn fill(v: &Value, vars: &Vars) -> Result<Value, String> {
    Ok(match v {
        Value::Str(x) => {
            let need = |o: &Option<String>, what: &str| {
                o.clone()
                    .ok_or_else(|| format!("{what} is needed for this agent: give --hook"))
            };
            match x.as_str() {
                "{command}" => Value::Str(need(&vars.command, "the gate's command")?),
                "{hook_dir}" => Value::Str(need(&vars.hook_dir, "the hook folder")?),
                "{hook_url}" => Value::Str(format!(
                    "file://{}",
                    need(&vars.hook_dir, "the hook folder")?
                )),
                "{version}" => Value::Str(vars.version.clone()),
                other => {
                    if WHOLE.iter().any(|p| other.contains(p))
                        || ["{node}", "{hook_file}"].iter().any(|p| other.contains(p))
                    {
                        return Err(format!(
                            "gates.json: placeholder inside `{other}`; a placeholder must be the whole string"
                        ));
                    }
                    v.clone()
                }
            }
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|i| fill(i, vars))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, i)| Ok((k.clone(), fill(i, vars)?)))
                .collect::<Result<_, String>>()?,
        ),
        other => other.clone(),
    })
}

/// A path or a program derm writes into a command: letters, digits and
/// `._/@+~ -` only, so a double-quoted word in `sh`, a JSON string and a
/// TOML string all read it as written.
fn plain_path(p: &str) -> bool {
    p.starts_with('/')
        && p.len() <= 1024
        && p.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'_' | b'/' | b'@' | b'+' | b'~' | b' ' | b'-')
        })
        && !Path::new(p)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
}

/// Fills a command template's `{node}`, `{hook_file}`, `{hook_dir}` and
/// `{version}` (the only place text is spliced, from checked paths).
fn fill_text(
    t: &str,
    node: &str,
    hook_file: Option<&str>,
    hook_dir: Option<&str>,
    version: &str,
) -> String {
    let mut out = t.replace("{node}", node).replace("{version}", version);
    out = out.replace("{hook_file}", hook_file.unwrap_or("<the hook file>"));
    out.replace("{hook_dir}", hook_dir.unwrap_or("<the package folder>"))
}

/// Owned by you (or root) and not writable by group or others.
fn closed(meta: &std::fs::Metadata, uid: u32) -> bool {
    (meta.uid() == uid || meta.uid() == 0) && meta.mode() & 0o022 == 0
}

/// Checks the hook folder and returns the hook file's path if the row names
/// one.
pub fn check_hook(dir: &str, agent: &Agent, uid: u32) -> Result<Option<String>, String> {
    if !plain_path(dir) {
        return Err(format!(
            "--hook `{dir}` must be an absolute path of letters, digits and ._/@+~ - (no `..`)"
        ));
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("{dir}: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(format!("{dir}: not a folder (a link is refused)"));
    }
    if !closed(&meta, uid) {
        return Err(format!(
            "{dir}: owned by someone else or writable by others; the gate in it would run on every tool call (chmod go-w)"
        ));
    }
    let pkg = Path::new(dir).join("package.json");
    let text = std::fs::read_to_string(&pkg).map_err(|e| format!("{}: {e}", pkg.display()))?;
    let name = json::parse(&text, false)
        .ok()
        .and_then(|d| d.root.map(|n| n.to_value()))
        .and_then(|v| opt_s(&v, "name"));
    if name.as_deref() != Some(agent.package.as_str()) {
        return Err(format!(
            "{dir} holds {}, not {}: --hook names the package folder of {}'s gate",
            name.as_deref().unwrap_or("no package name"),
            agent.package,
            agent.name
        ));
    }
    let Some(rel) = &agent.hook_file else {
        return Ok(None);
    };
    let file = format!("{}/{rel}", dir.trim_end_matches('/'));
    let m = std::fs::symlink_metadata(&file).map_err(|e| format!("{file}: {e}"))?;
    if m.file_type().is_symlink() || !m.is_file() {
        return Err(format!("{file}: not a regular file (a link is refused)"));
    }
    if !closed(&m, uid) {
        return Err(format!(
            "{file}: owned by someone else or writable by others"
        ));
    }
    Ok(Some(file))
}

/// The nearest folder at or up to three levels above `dir` holding
/// `file` (a plugin marketplace) that lists `dir` as derm's plugin: the
/// marketplace is named `derm` and has a plugin `derm` whose `source` is
/// `dir` by its path from that folder (`"./packages/<name>"` for Claude
/// Code, `{"source":"local","path":"./packages/<name>"}` for Codex). The
/// file, its folder and every folder from the marketplace folder down to
/// `dir` are yours or root's, writable by no one else, and no link (fix pass
/// 1's review, FP4-S5: the text only had to contain the path, so a file you
/// do not own, or one that named the folder for another plugin, was printed
/// as derm's advice). `dir` passed `check_hook`'s plain-path check.
fn marketplace_above(dir: &str, file: &str) -> Option<String> {
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let dir = Path::new(dir);
    let mut at = Some(dir);
    for _ in 0..4 {
        let root = at?;
        if let Ok(rel) = dir.strip_prefix(root) {
            if lists_derm(root, file, &rel.to_string_lossy(), uid)
                && folders_closed(root, dir, file, uid)
            {
                return Some(root.to_string_lossy().into_owned());
            }
        }
        at = root.parent();
    }
    None
}

fn lists_derm(root: &Path, file: &str, rel: &str, uid: u32) -> bool {
    let mf = root.join(file);
    let Ok(m) = std::fs::symlink_metadata(&mf) else {
        return false;
    };
    if !m.is_file() || m.len() > 1024 * 1024 || !closed(&m, uid) {
        return false;
    }
    let Some(v) = std::fs::read_to_string(&mf)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
    else {
        return false;
    };
    let want = |p: &str| {
        let p = p.strip_prefix("./").unwrap_or(p);
        let p = p.trim_end_matches('/');
        if rel.is_empty() {
            p.is_empty() || p == "."
        } else {
            p == rel
        }
    };
    v["name"] == "derm"
        && v["plugins"].as_array().is_some_and(|ps| {
            ps.iter().any(|p| {
                p["name"] == "derm"
                    && match &p["source"] {
                        serde_json::Value::String(s) => want(s),
                        serde_json::Value::Object(o) => {
                            o.get("source").and_then(serde_json::Value::as_str) == Some("local")
                                && o.get("path")
                                    .and_then(serde_json::Value::as_str)
                                    .is_some_and(want)
                        }
                        _ => false,
                    }
            })
        })
}

/// The marketplace file's folders (`.claude-plugin`, `.agents/plugins`) and
/// every folder from `root` down to `dir`: real folders, yours or root's,
/// writable by no one else.
fn folders_closed(root: &Path, dir: &Path, file: &str, uid: u32) -> bool {
    let mut folders: Vec<PathBuf> = Vec::new();
    let mut f = root.join(file);
    while let Some(parent) = f.parent() {
        if parent == root {
            break;
        }
        folders.push(parent.to_path_buf());
        f = parent.to_path_buf();
    }
    let mut d = Some(dir);
    while let Some(x) = d {
        folders.push(x.to_path_buf());
        if x == root {
            break;
        }
        d = x.parent();
    }
    folders
        .iter()
        .all(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && closed(&m, uid)))
}

/// The file a place names on this machine.
pub fn resolve(at: &Place, home: &Path, env: &dyn Env) -> PathBuf {
    let rest = &at.path[2..];
    if let Some(var) = &at.home_env {
        if let Some(dir) = env.var(var).filter(|d| d.starts_with('/')) {
            let tail = rest.split_once('/').map_or("", |(_, t)| t);
            return PathBuf::from(dir).join(tail);
        }
    }
    if at.xdg_config {
        if let (Some(tail), Some(x)) = (
            rest.strip_prefix(".config/"),
            env.var("XDG_CONFIG_HOME").filter(|d| d.starts_with('/')),
        ) {
            return PathBuf::from(x).join(tail);
        }
    }
    home.join(rest)
}

/// OpenCode's `Wildcard.match` (1.19.4 `packages/opencode/src/util/wildcard.ts:3-19`,
/// the same in Kilo 7.8.18): the whole of `s` against `pattern`, where `*` is
/// any run (newlines too), `?` one character, everything else literal and
/// case-sensitive off Windows, backslashes read as `/`, and a pattern ending
/// in ` *` also matches without that tail (`ls *` matches `ls`).
pub fn wildcard(s: &str, pattern: &str) -> bool {
    let s: Vec<char> = s.replace('\\', "/").chars().collect();
    let p: Vec<char> = pattern.replace('\\', "/").chars().collect();
    fn m(s: &[char], p: &[char]) -> bool {
        // Iterative glob with one star backtrack point.
        let (mut i, mut j) = (0usize, 0usize);
        let (mut star, mut mark) = (None::<usize>, 0usize);
        while i < s.len() {
            if j < p.len() && (p[j] == '?' || (p[j] != '*' && p[j] == s[i])) {
                i += 1;
                j += 1;
            } else if j < p.len() && p[j] == '*' {
                star = Some(j);
                mark = i;
                j += 1;
            } else if let Some(st) = star {
                j = st + 1;
                mark += 1;
                i = mark;
            } else {
                return false;
            }
        }
        while j < p.len() && p[j] == '*' {
            j += 1;
        }
        j == p.len()
    }
    if p.len() >= 2 && p[p.len() - 2..] == [' ', '*'] && m(&s, &p[..p.len() - 2]) {
        return true;
    }
    m(&s, &p)
}

fn under_home(p: &Path, home: &Path) -> bool {
    p.starts_with(home) && !p.components().any(|c| matches!(c, Component::ParentDir))
}

fn has_marker(v: &Value, marker: &str) -> bool {
    json::compact(v).contains(marker)
}

/// derm finds its own entry by the row's marker; an entry that does not hold
/// it (a package folder renamed, say) could never be found again, and a
/// second `--gate` would add a second gate.
fn ensure_marker(v: &Value, marker: &str, what: &str) -> Result<(), String> {
    if has_marker(v, marker) {
        Ok(())
    } else {
        Err(format!(
            "{what} would not hold `{marker}`, which is how derm finds its own entry again; use the package folder under its own name"
        ))
    }
}

/// Every step's change to one file's text.
#[derive(Debug)]
pub enum Outcome {
    Changed(String),
    Same,
}

/// Adds `entry` to the array at `array` (or replaces derm's own, found by
/// `marker`), keeping every other element where it is.
pub fn add_to_array(
    text: &str,
    jsonc: bool,
    array: &[String],
    entry: &Value,
    marker: &str,
    create_with: Option<&Value>,
    remove: bool,
) -> Result<Outcome, String> {
    let doc = json::parse(text, jsonc)
        .map_err(|e| format!("{e}; derm will not rewrite a file it cannot parse"))?;
    let (parent, key) = array.split_at(array.len() - 1);
    let parent: Vec<&str> = parent.iter().map(String::as_str).collect();
    let key = key[0].as_str();
    let root = doc.root.as_ref().map(|n| n.to_value());
    let existing = root
        .as_ref()
        .and_then(|r| r.get_path(&parent))
        .and_then(|o| o.get(key));
    let items = match existing {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => {
            return Err(format!(
                "`{}` in the file is not a list; derm will not guess",
                array.join(".")
            ))
        }
    };
    let mut new_items = Vec::new();
    let mut placed = false;
    for it in &items {
        if has_marker(it, marker) {
            if !remove && !placed {
                new_items.push(entry.clone());
                placed = true;
            }
        } else {
            new_items.push(it.clone());
        }
    }
    if !remove && !placed {
        new_items.push(entry.clone());
    }
    if new_items == items {
        return Ok(Outcome::Same);
    }
    if remove && existing.is_none() {
        return Ok(Outcome::Same);
    }
    let new_value = Value::Array(new_items);
    if doc.root.is_none() {
        let mut whole = create_with.cloned().unwrap_or(Value::Object(Vec::new()));
        whole.set_path(&parent, key, new_value)?;
        return Ok(Outcome::Changed(format!(
            "{}\n",
            json::pretty(&whole, "  ", "")
        )));
    }
    if existing.is_some() {
        let mut path_to: Vec<&str> = parent.clone();
        path_to.push(key);
        if let Some((a, b)) = doc.span_at(&path_to) {
            if json::has_comment(&text[a..b]) {
                return Err(format!(
                    "`{}` holds comments, which a rewrite of the list would drop; add the entry by hand",
                    array.join(".")
                ));
            }
        }
    }
    let new = doc
        .set_member(&parent, key, &new_value, true, true)
        .map_err(|e| format!("internal: {e:?}"))?;
    super::verify_json(text, &new, jsonc, &parent, key, Some(&new_value))?;
    Ok(Outcome::Changed(new))
}

/// Sets the member `name` of the object at `object` (Antigravity's named
/// hook), when it is absent or derm's own.
pub fn set_named(
    text: &str,
    jsonc: bool,
    object: &[String],
    name: &str,
    entry: &Value,
    marker: &str,
    remove: bool,
) -> Result<Outcome, String> {
    let doc = json::parse(text, jsonc)
        .map_err(|e| format!("{e}; derm will not rewrite a file it cannot parse"))?;
    let path: Vec<&str> = object.iter().map(String::as_str).collect();
    let current = doc.lookup(&path, name);
    if let Some(c) = &current {
        if !has_marker(c, marker) {
            return Err(format!(
                "`{name}` in the file is not derm's entry; derm will not replace it (rename it, or remove it yourself)"
            ));
        }
    }
    if remove {
        return match current {
            None => Ok(Outcome::Same),
            Some(_) => {
                let new = doc
                    .remove_member(&path, name)
                    .map_err(|e| format!("internal: {e:?}"))?;
                super::verify_json(text, &new, jsonc, &path, name, None)?;
                Ok(Outcome::Changed(new))
            }
        };
    }
    if current.as_ref() == Some(entry) {
        return Ok(Outcome::Same);
    }
    let new = doc
        .set_member(&path, name, entry, true, true)
        .map_err(|e| format!("internal: {e:?}"))?;
    super::verify_json(text, &new, jsonc, &path, name, Some(entry))?;
    Ok(Outcome::Changed(new))
}

fn toml_value(v: &Value) -> Result<toml_edit::Value, String> {
    Ok(match v {
        Value::Str(x) => x.as_str().into(),
        Value::Bool(b) => (*b).into(),
        Value::Number(n) => {
            if n.contains(['.', 'e', 'E']) {
                n.parse::<f64>().map_err(|e| e.to_string())?.into()
            } else {
                n.parse::<i64>().map_err(|e| e.to_string())?.into()
            }
        }
        _ => return Err("gates.json: a TOML value must be a string, number or boolean".into()),
    })
}

fn parse_toml(text: &str) -> Result<toml_edit::DocumentMut, String> {
    text.parse::<toml_edit::DocumentMut>().map_err(|e| {
        format!(
            "not valid TOML ({}); derm will not rewrite a file it cannot parse",
            e.message()
        )
    })
}

/// Appends one `[[<array>]]` table holding exactly `entry`'s keys, or
/// replaces derm's own (found by `marker`).
pub fn toml_array(
    text: &str,
    array: &str,
    entry: &[(String, Value)],
    marker: &str,
    remove: bool,
) -> Result<Outcome, String> {
    let mut doc = parse_toml(text)?;
    let mut table = toml_edit::Table::new();
    for (k, v) in entry {
        table.insert(k, toml_edit::Item::Value(toml_value(v)?));
    }
    let new_text = {
        let item = doc.entry(array).or_insert(toml_edit::Item::ArrayOfTables(
            toml_edit::ArrayOfTables::new(),
        ));
        let Some(aot) = item.as_array_of_tables_mut() else {
            return Err(format!(
                "`{array}` in the file is not a list of tables; derm will not guess"
            ));
        };
        let ours: Vec<usize> = aot
            .iter()
            .enumerate()
            .filter(|(_, t)| t.to_string().contains(marker))
            .map(|(i, _)| i)
            .collect();
        if remove && ours.is_empty() {
            return Ok(Outcome::Same);
        }
        // derm's first table is replaced where it is; any other copy goes.
        let keep_first = !remove && !ours.is_empty();
        for i in ours.iter().skip(usize::from(keep_first)).rev() {
            aot.remove(*i);
        }
        if keep_first {
            if let Some(t) = aot.get_mut(ours[0]) {
                t.clear();
                for (k, v) in table.iter() {
                    t.insert(k, v.clone());
                }
            }
        } else if !remove {
            aot.push(table);
        }
        if aot.is_empty() && remove {
            doc.remove(array);
        }
        doc.to_string()
    };
    if new_text == text {
        return Ok(Outcome::Same);
    }
    Ok(Outcome::Changed(new_text))
}

/// Sets `values` in the table at `table`, creating it.
pub fn toml_set(
    text: &str,
    table: &[String],
    values: &[(String, Value)],
) -> Result<Outcome, String> {
    let mut doc = parse_toml(text)?;
    let mut cur = doc.as_table_mut();
    for (i, seg) in table.iter().enumerate() {
        let item = cur.entry(seg).or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(i + 1 < table.len());
            toml_edit::Item::Table(t)
        });
        cur = item
            .as_table_mut()
            .ok_or_else(|| format!("`{}` in the file is not a table", table[..=i].join(".")))?;
    }
    for (k, v) in values {
        let want = toml_value(v)?;
        if cur
            .get(k)
            .and_then(|i| i.as_value())
            .map(|x| x.to_string().trim().to_string())
            == Some(want.to_string().trim().to_string())
        {
            continue;
        }
        cur.insert(k, toml_edit::Item::Value(want));
    }
    let out = doc.to_string();
    if out == text {
        return Ok(Outcome::Same);
    }
    Ok(Outcome::Changed(out))
}

/// One step's change to a file's text, given the text and whether the file
/// exists.
type Edit = Box<dyn Fn(&str, bool) -> Result<Outcome, String>>;

/// The file an agent that deep-merges several global files reads last, and
/// the others that exist. `chain` lists them in the order the agent merges
/// them (OpenCode 1.19.4 `config.ts:272-274`; Kilo 7.8.18 `config.ts:460-482`):
/// the last one that exists wins key by key, and its arrays replace the
/// others' (remeda 2.26.0 `mergeDeep`), so derm writes there, or at `at`
/// when none exists. With no chain, `at` alone.
pub fn chain_target(
    at: &Place,
    chain: &[String],
    home: &Path,
    env: &dyn Env,
) -> (PathBuf, Vec<PathBuf>) {
    let place = |p: &String| Place {
        path: p.clone(),
        home_env: at.home_env.clone(),
        xdg_config: at.xdg_config,
    };
    let files: Vec<PathBuf> = chain
        .iter()
        .map(|p| resolve(&place(p), home, env))
        .collect();
    let present: Vec<&PathBuf> = files
        .iter()
        .filter(|f| std::fs::symlink_metadata(f).is_ok())
        .collect();
    let target = present
        .last()
        .map_or_else(|| resolve(at, home, env), |f| (*f).clone());
    let others = present
        .into_iter()
        .filter(|f| **f != target)
        .cloned()
        .collect();
    (target, others)
}

/// Each other file's root value, read the way derm reads every file it
/// would edit: a file it cannot parse stops the run.
fn read_others(others: &[PathBuf]) -> Result<Vec<(PathBuf, Value)>, String> {
    others
        .iter()
        .map(|f| {
            let current = write::read_current(f)?;
            let text = current.text()?;
            let doc = json::parse(text, true).map_err(|e| {
                format!(
                    "{}: {e}; derm reads it to know what the agent merges with the file it writes",
                    f.display()
                )
            })?;
            Ok((
                f.clone(),
                doc.root
                    .map(|n| n.to_value())
                    .unwrap_or(Value::Object(Vec::new())),
            ))
        })
        .collect()
}

/// The permission keys a legacy `tools` switch denies: OpenCode turns
/// `tools.<t>: false` into `permission.<t>: "deny"` placed before every
/// `permission` key, `write`, `edit` and `patch` into `edit`
/// (1.19.4 `config.ts:567-578`; Kilo 7.8.18 `config.ts:1024-1034`). A value
/// that is not `true` counts as a deny here, which can only leave a key out.
pub fn tools_denies(roots: &[&Value]) -> Vec<String> {
    let mut out = Vec::new();
    for r in roots {
        if let Some(Value::Object(tools)) = r.get("tools") {
            for (t, v) in tools {
                if *v != Value::Bool(true) {
                    let k = if matches!(t.as_str(), "write" | "edit" | "patch") {
                        "edit"
                    } else {
                        t.as_str()
                    };
                    if !out.iter().any(|o: &String| o == k) {
                        out.push(k.to_string());
                    }
                }
            }
        }
    }
    out
}

/// What derm changes in the `permission` block.
#[derive(Debug, PartialEq)]
pub enum PermEdit {
    None,
    /// The whole value (absent, or `"allow"` turned into an object).
    Whole(Value),
    /// Members set in place or appended, in order.
    Keys(Vec<(String, Value)>),
}

/// OpenCode 1.19.4 reads `permission` as one action for everything or an
/// object whose keys are patterns over the permission name, in the file's
/// order (`core/src/v1/config/permission.ts`), and takes the last rule that
/// matches (`findLast`, `permission/index.ts:28-32`), `ask` when none does.
/// So a key derm adds goes last and wins over every key before it. derm:
/// sets an exact key from `allow` to the wanted value in place; adds a key
/// only when every key that matches it (and every `tools` deny) is the
/// string `allow` or `ask`; leaves a deny, a pattern object and anything
/// else, and says so. A whole-config `"allow"` becomes `{"*": "allow", ...}`;
/// `"ask"` and `"deny"` stay.
pub fn plan_permission(
    cur: Option<&Value>,
    want: &[(String, Value)],
    tools_deny: &[String],
) -> (PermEdit, Vec<String>) {
    let mut notes = Vec::new();
    let narrows = |v: &Value| matches!(v, Value::Str(s) if s == "allow" || s == "ask");
    let addable = |k: &str, existing: &[(String, Value)], notes: &mut Vec<String>| -> bool {
        if let Some(t) = tools_deny.iter().find(|t| wildcard(k, t)) {
            notes.push(format!(
                "permission.{k} not added: a `tools` switch turns `{t}` off, and a `permission` key of that name would override it"
            ));
            return false;
        }
        if let Some((p, _)) = existing.iter().find(|(p, v)| wildcard(k, p) && !narrows(v)) {
            notes.push(format!(
                "permission.{k} not added: `{p}` already matches it with a deny or a pattern list, and a key after it would override that"
            ));
            return false;
        }
        true
    };
    match cur {
        None => {
            let add: Vec<(String, Value)> = want
                .iter()
                .filter(|(k, _)| addable(k, &[], &mut notes))
                .cloned()
                .collect();
            if add.is_empty() {
                (PermEdit::None, notes)
            } else {
                (PermEdit::Whole(Value::Object(add)), notes)
            }
        }
        Some(Value::Str(a)) if a == "allow" => {
            let mut obj = vec![("*".to_string(), Value::str("allow"))];
            for (k, v) in want {
                if addable(k, &obj, &mut notes) {
                    obj.push((k.clone(), v.clone()));
                }
            }
            (PermEdit::Whole(Value::Object(obj)), notes)
        }
        Some(Value::Str(a)) if a == "ask" || a == "deny" => {
            notes.push(format!(
                "permission is \"{a}\" for everything; derm leaves it"
            ));
            (PermEdit::None, notes)
        }
        Some(Value::Object(m)) => {
            let mut set = Vec::new();
            for (k, v) in want {
                match m.iter().find(|(p, _)| p == k) {
                    Some((_, Value::Str(s))) if s == "allow" => set.push((k.clone(), v.clone())),
                    Some((_, cv)) if cv == v => {}
                    Some(_) => notes.push(format!(
                        "permission.{k} left as it is: it is a deny or a pattern list"
                    )),
                    None => {
                        if addable(k, m, &mut notes) {
                            set.push((k.clone(), v.clone()));
                        }
                    }
                }
            }
            if set.is_empty() {
                (PermEdit::None, notes)
            } else {
                (PermEdit::Keys(set), notes)
            }
        }
        Some(_) => {
            notes.push("permission is not an action or an object; derm leaves it".into());
            (PermEdit::None, notes)
        }
    }
}

/// Applies `edit` to `text`, after checking the block is still the one the
/// plan read.
fn apply_permission(
    text: &str,
    jsonc: bool,
    read: Option<&Value>,
    edit: &PermEdit,
) -> Result<Outcome, String> {
    let doc = json::parse(text, jsonc)
        .map_err(|e| format!("{e}; derm will not rewrite a file it cannot parse"))?;
    let now = doc.lookup(&[], "permission");
    if now.as_ref() != read {
        return Err("`permission` changed while derm planned; run the dry run again".into());
    }
    match edit {
        PermEdit::None => Ok(Outcome::Same),
        PermEdit::Whole(v) => {
            let new = doc
                .set_member(&[], "permission", v, true, true)
                .map_err(|e| format!("internal: {e:?}"))?;
            super::verify_json(text, &new, jsonc, &[], "permission", Some(v))?;
            Ok(Outcome::Changed(new))
        }
        PermEdit::Keys(set) => {
            let mut cur = text.to_string();
            for (k, v) in set {
                let doc = json::parse(&cur, jsonc).map_err(|e| format!("internal: {e}"))?;
                let new = doc
                    .set_member(&["permission"], k, v, true, true)
                    .map_err(|e| format!("internal: {e:?}"))?;
                super::verify_json(&cur, &new, jsonc, &["permission"], k, Some(v))?;
                cur = new;
            }
            Ok(Outcome::Changed(cur))
        }
    }
}

/// One file's plan: what it holds now and what it will hold.
#[derive(Debug)]
pub struct FilePlan {
    pub path: PathBuf,
    pub current: Current,
    pub new_text: String,
}

/// A file derm owns alone: written when absent or already derm's.
fn owned(
    text: &str,
    exists: bool,
    content: &Value,
    marker: &str,
    remove: bool,
) -> Result<Option<String>, String> {
    let want = format!("{}\n", json::pretty(content, "  ", ""));
    if remove {
        return Ok(None);
    }
    if exists && !text.contains(marker) {
        return Err("the file exists and is not derm's; derm will not replace it".into());
    }
    if text == want {
        return Ok(None);
    }
    Ok(Some(want))
}

pub struct Opts<'a> {
    pub agent: &'a str,
    pub ungate: bool,
    pub hook: Option<&'a str>,
    pub node: Option<&'a str>,
    pub write: bool,
}

/// `--gate` and `--ungate`.
pub fn run(o: &Opts, ctx: &mut Ctx) -> Result<u8, String> {
    let table = table()?;
    let Some(agent) = table.iter().find(|a| a.agent == o.agent) else {
        let ids: Vec<&str> = table.iter().map(|a| a.agent.as_str()).collect();
        return Err(format!(
            "no gate registration for `{}`; one of: {}",
            o.agent,
            ids.join(", ")
        ));
    };
    let uid = derm_core::runtime::current_uid();
    let hook_file = match o.hook {
        Some(dir) => check_hook(dir, agent, uid)?,
        None => None,
    };
    let hook_dir = o.hook.map(|d| d.trim_end_matches('/').to_string());
    let node = match o.node {
        Some(n) => {
            if !plain_path(n) {
                return Err("--node takes an absolute path of letters, digits and ._/@+~ -".into());
            }
            n.to_string()
        }
        None => "node".to_string(),
    };
    let version = env!("CARGO_PKG_VERSION").to_string();
    let command = agent.command.as_deref().and_then(|t| {
        hook_file
            .as_deref()
            .map(|h| fill_text(t, &node, Some(h), hook_dir.as_deref(), &version))
    });
    let vars = Vars {
        command,
        hook_dir: hook_dir.clone(),
        version: version.clone(),
    };
    let verb = if o.ungate { "--ungate" } else { "--gate" };
    ctx.out.push_str(&format!(
        "derm connect {verb}: {} ({}), gate package {}\nsource: {}\n",
        agent.name, agent.agent, agent.package, agent.source
    ));

    // Agents whose gate installs through their own command: print only.
    let printed: Vec<&Step> = agent
        .steps
        .iter()
        .filter(|s| matches!(s, Step::Commands { .. }))
        .collect();
    if !printed.is_empty() {
        for st in printed {
            if let Step::Commands {
                commands,
                note,
                from_folder,
            } = st
            {
                let local = match (from_folder, hook_dir.as_deref()) {
                    (Some((file, lines)), Some(dir)) => match marketplace_above(dir, file) {
                        Some(root) => Some(
                            lines
                                .iter()
                                .map(|l| l.replace("{marketplace_dir}", &root))
                                .collect::<Vec<_>>(),
                        ),
                        None => {
                            ctx.out.push_str(&format!(
                                "no {file} above {dir} lists that folder; the lines below install the release from GitHub, not the folder\n"
                            ));
                            None
                        }
                    },
                    _ => None,
                };
                let commands = local.as_ref().unwrap_or(commands);
                if o.ungate {
                    ctx.out.push_str(&format!(
                        "print only: remove derm's gate with {}'s own command (its plugin or extension list)\n",
                        agent.name
                    ));
                } else {
                    ctx.out.push_str("print only: run these yourself\n\n");
                    let cmd = vars.command.clone().unwrap_or_else(|| {
                        agent.command.as_deref().map_or(String::new(), |t| {
                            fill_text(t, &node, None, hook_dir.as_deref(), &version)
                        })
                    });
                    for c in commands {
                        let c = c.replace("{command}", &cmd);
                        ctx.out.push_str(&format!(
                            "  {}\n",
                            fill_text(
                                &c,
                                &node,
                                hook_file.as_deref(),
                                hook_dir.as_deref(),
                                &version
                            )
                        ));
                    }
                }
                ctx.out.push_str(&format!("\nnote:   {note}\n"));
            }
        }
        if o.write {
            ctx.err.push_str(&format!(
                "derm connect: {} is print-only for {verb}; nothing written\n",
                agent.name
            ));
            return Ok(1);
        }
        return Ok(0);
    }

    if !o.ungate && hook_dir.is_none() {
        return Err(format!(
            "--gate for {} needs --hook <absolute folder of {}>",
            agent.name, agent.package
        ));
    }
    let marker = agent
        .marker
        .as_deref()
        .ok_or("gates.json: a writing row needs a marker")?;
    for r in &agent.refuse_if_exists {
        let p = resolve(
            &Place {
                path: r.clone(),
                home_env: None,
                xdg_config: true,
            },
            &ctx.home,
            ctx.env,
        );
        if std::fs::symlink_metadata(&p).is_ok() {
            return Err(format!(
                "{} exists, and {} reads it over the file derm would write; register the gate by hand",
                p.display(),
                agent.name
            ));
        }
    }

    // Plan every file before anything is written.
    let mut plans: Vec<FilePlan> = Vec::new();
    let mut leave: Vec<String> = Vec::new();
    for st in &agent.steps {
        let mut targets: Vec<(PathBuf, Edit)> = Vec::new();
        match st {
            Step::JsonArrayEntry {
                at,
                jsonc,
                array,
                entry,
                create_with,
                chain,
            } => {
                let entry =
                    fill(entry, &vars)
                        .or_else(|e| if o.ungate { Ok(Value::Null) } else { Err(e) })?;
                if !o.ungate {
                    ensure_marker(&entry, marker, "the entry")?;
                }
                let (target, others) = chain_target(at, chain, &ctx.home, ctx.env);
                // A list in a file read before the target is replaced by
                // one the target gains (mergeDeep replaces arrays).
                let path: Vec<&str> = array.iter().map(String::as_str).collect();
                let (parent, last) = path.split_at(path.len() - 1);
                let holder = read_others(&others)?
                    .into_iter()
                    .find(|(_, r)| r.get_path(parent).and_then(|o| o.get(last[0])).is_some())
                    .map(|(f, _)| f);
                let (jsonc, array, cw) = (*jsonc, array.clone(), create_with.clone());
                let (m, rm, name) = (marker.to_string(), o.ungate, agent.name.clone());
                targets.push((
                    target,
                    Box::new(move |t, _| {
                        if let (Some(h), false) = (&holder, rm) {
                            let has = json::parse(t, jsonc).ok().and_then(|d| {
                                let p: Vec<&str> = array.iter().map(String::as_str).collect();
                                let (pa, k) = p.split_at(p.len() - 1);
                                d.lookup(pa, k[0])
                            });
                            if has.is_none() {
                                return Err(format!(
                                    "`{}` is set in {}, which {name} reads before this file; a list here would replace that one. Add derm's entry there by hand, or move your list into this file",
                                    array.join("."),
                                    h.display()
                                ));
                            }
                        }
                        add_to_array(t, jsonc, &array, &entry, &m, cw.as_ref(), rm)
                    }),
                ));
            }
            Step::JsonPermission {
                at,
                jsonc,
                chain,
                keys,
                fragment,
            } => {
                let (target, others) = chain_target(at, chain, &ctx.home, ctx.env);
                if o.ungate {
                    if target.exists() {
                        leave.push(format!(
                            "{} keeps its `permission` block; derm only narrowed it and does not widen it back",
                            target.display()
                        ));
                    }
                    continue;
                }
                let others = read_others(&others)?;
                if let Some((f, _)) = others.iter().find(|(_, r)| r.get("permission").is_some()) {
                    leave.push(format!(
                        "`permission` is also set in {}; {} merges the files key by key and derm will not guess the order. Add the keys from {fragment} by hand",
                        f.display(),
                        agent.name
                    ));
                    continue;
                }
                let current = write::read_current(&target)?;
                let text = current.text()?.to_string();
                let doc =
                    json::parse(&text, *jsonc).map_err(|e| format!("{}: {e}", target.display()))?;
                let mine = doc.root.as_ref().map(|n| n.to_value());
                let read = doc.lookup(&[], "permission");
                let mut roots: Vec<&Value> = others.iter().map(|(_, r)| r).collect();
                if let Some(r) = &mine {
                    roots.push(r);
                }
                let denies = tools_denies(&roots);
                let (edit, notes) = plan_permission(read.as_ref(), keys, &denies);
                for n in notes {
                    leave.push(format!("{}: {n}", target.display()));
                }
                let jsonc = *jsonc;
                targets.push((
                    target,
                    Box::new(move |t, _| apply_permission(t, jsonc, read.as_ref(), &edit)),
                ));
            }
            Step::JsonMember {
                at,
                jsonc,
                object,
                name,
                entry,
            } => {
                let entry =
                    fill(entry, &vars)
                        .or_else(|e| if o.ungate { Ok(Value::Null) } else { Err(e) })?;
                if !o.ungate {
                    ensure_marker(&entry, marker, "the entry")?;
                }
                let (jsonc, object, name) = (*jsonc, object.clone(), name.clone());
                let (m, rm) = (marker.to_string(), o.ungate);
                targets.push((
                    resolve(at, &ctx.home, ctx.env),
                    Box::new(move |t, _| set_named(t, jsonc, &object, &name, &entry, &m, rm)),
                ));
            }
            Step::TomlArrayEntry { at, array, entry } => {
                let entry: Vec<(String, Value)> = if o.ungate {
                    Vec::new()
                } else {
                    entry
                        .iter()
                        .map(|(k, v)| Ok((k.clone(), fill(v, &vars)?)))
                        .collect::<Result<_, String>>()?
                };
                if !o.ungate {
                    ensure_marker(&Value::Object(entry.clone()), marker, "the table")?;
                }
                let (array, m, rm) = (array.clone(), marker.to_string(), o.ungate);
                targets.push((
                    resolve(at, &ctx.home, ctx.env),
                    Box::new(move |t, _| toml_array(t, &array, &entry, &m, rm)),
                ));
            }
            Step::TomlSet { at, table, values } => {
                if o.ungate {
                    leave.push(format!(
                        "{} keeps [{}] as derm set it; change it yourself if you want it back",
                        resolve(at, &ctx.home, ctx.env).display(),
                        table.join(".")
                    ));
                    continue;
                }
                let (table, values) = (table.clone(), values.clone());
                targets.push((
                    resolve(at, &ctx.home, ctx.env),
                    Box::new(move |t, _| toml_set(t, &table, &values)),
                ));
            }
            Step::OwnedFile { at, content } => {
                let p = resolve(at, &ctx.home, ctx.env);
                if o.ungate {
                    if p.exists() {
                        leave.push(format!(
                            "remove {} (derm never deletes a file)",
                            p.display()
                        ));
                    }
                    continue;
                }
                let content = fill(content, &vars)?;
                ensure_marker(&content, marker, "the file")?;
                let m = marker.to_string();
                targets.push((
                    p,
                    Box::new(move |t, exists| {
                        Ok(match owned(t, exists, &content, &m, false)? {
                            Some(n) => Outcome::Changed(n),
                            None => Outcome::Same,
                        })
                    }),
                ));
            }
            Step::PluginFolder { at, files } => {
                let dir = resolve(at, &ctx.home, ctx.env);
                if o.ungate {
                    if dir.exists() {
                        leave.push(format!(
                            "remove the folder {} (derm never deletes a folder)",
                            dir.display()
                        ));
                    }
                    continue;
                }
                // A folder already there is derm's only when the file that
                // carries the gate's command says so.
                if std::fs::symlink_metadata(&dir).is_ok() {
                    let ours = files.iter().any(|(rel, content)| {
                        fill(content, &vars).is_ok_and(|c| has_marker(&c, marker))
                            && std::fs::read_to_string(dir.join(rel))
                                .is_ok_and(|t| t.contains(marker))
                    });
                    if !ours {
                        return Err(format!(
                            "{} exists and is not derm's; derm will not write into it",
                            dir.display()
                        ));
                    }
                }
                for (rel, content) in files {
                    if rel.starts_with('/') || rel.split('/').any(|c| c == ".." || c.is_empty()) {
                        return Err(format!("gates.json: bad file name `{rel}`"));
                    }
                    let content = fill(content, &vars)?;
                    let m = marker.to_string();
                    // plugin.json carries no command; it is derm's when the
                    // folder's other file is.
                    let needs_marker = has_marker(&content, marker);
                    targets.push((
                        dir.join(rel),
                        Box::new(move |t, exists| {
                            if exists && !needs_marker {
                                let want = format!("{}\n", json::pretty(&content, "  ", ""));
                                return Ok(if t == want {
                                    Outcome::Same
                                } else {
                                    Outcome::Changed(want)
                                });
                            }
                            Ok(match owned(t, exists, &content, &m, false)? {
                                Some(n) => Outcome::Changed(n),
                                None => Outcome::Same,
                            })
                        }),
                    ));
                }
            }
            Step::Commands { .. } => {}
        }
        for (path, change) in targets {
            if !under_home(&path, &ctx.home) {
                return Err(format!(
                    "{} is outside your home folder; derm writes user-level files under it only",
                    path.display()
                ));
            }
            // Several steps can touch one file: each works on the text the
            // one before it left.
            let idx = match plans.iter().position(|p| p.path == path) {
                Some(i) => i,
                None => {
                    let current = write::read_current(&path)?;
                    let text = current.text()?.to_string();
                    plans.push(FilePlan {
                        path: path.clone(),
                        current,
                        new_text: text,
                    });
                    plans.len() - 1
                }
            };
            let exists = plans[idx].current.bytes.is_some();
            match change(&plans[idx].new_text, exists)
                .map_err(|e| format!("{}: {e}", path.display()))?
            {
                Outcome::Changed(t) => {
                    spec::reject_list(&t).or_else(|e| {
                        // The file's own text may hold what the list names;
                        // only what derm adds is checked.
                        if spec::reject_list(plans[idx].current.text().unwrap_or("")).is_err() {
                            Ok(())
                        } else {
                            Err(e)
                        }
                    })?;
                    plans[idx].new_text = t;
                }
                Outcome::Same => {}
            }
        }
    }
    for n in &agent.notes {
        ctx.out.push_str(&format!("note:   {n}\n"));
    }
    let changed: Vec<&FilePlan> = plans
        .iter()
        .filter(|p| p.current.text().ok() != Some(p.new_text.as_str()))
        .collect();
    for l in &leave {
        ctx.out.push_str(&format!("left:   {l}\n"));
    }
    if changed.is_empty() {
        ctx.out.push_str(if o.ungate {
            "derm's gate is not in these files; nothing to change\n"
        } else {
            "derm's gate is already registered exactly so; nothing to change\n"
        });
        return Ok(0);
    }
    for p in &changed {
        let label = p.path.display().to_string();
        ctx.out.push_str(&format!(
            "\nfile {}: {}\n\n",
            label,
            if p.current.bytes.is_none() {
                "absent (derm would create it)".to_string()
            } else {
                format!("sha256 {}", p.current.sha256)
            }
        ));
        ctx.out.push_str(&diff::unified_redacted(
            p.current.text().unwrap_or(""),
            &p.new_text,
            &label,
            &format!("{label} (after derm connect {verb})"),
        ));
    }
    if !installed(agent, &ctx.home, ctx.env) {
        ctx.out.push_str(&format!(
            "\n{} does not look installed here (no `{}` on PATH, none of {}); derm writes nothing for an agent that is not installed.\n",
            agent.name,
            agent.cli.as_deref().unwrap_or("binary"),
            agent.installed_if.join(", ")
        ));
        if o.write {
            ctx.err.push_str("derm connect: nothing written\n");
            return Ok(1);
        }
        return Ok(0);
    }
    if !o.write {
        ctx.out
            .push_str("\ndry run: nothing written. Add --write to write it.\n");
        return Ok(0);
    }
    ctx.flush();
    let question = format!(
        "Write {} file{} for {}'s gate?",
        changed.len(),
        if changed.len() == 1 { "" } else { "s" },
        agent.name
    );
    if !ctx.confirm.confirm(&question)? {
        return Err("not confirmed; nothing written".into());
    }
    // Case 55, across files: every file is re-read before the first write.
    for p in &changed {
        let now = write::read_current(&p.path)?;
        if now.sha256 != p.current.sha256 {
            return Err(format!(
                "{} changed since the diff was shown; nothing written. Run the dry run again.",
                p.path.display()
            ));
        }
    }
    let backups = ctx.home.join(".derm/backups");
    let socket = super::log_socket(ctx);
    for p in &changed {
        let w = write::commit(
            &p.path,
            &agent.agent,
            &p.current.sha256,
            &p.new_text,
            &backups,
        )?;
        let rec = log::Record {
            harness: agent.agent.clone(),
            path: p.path.display().to_string(),
            server: "derm-gate".into(),
            action: if o.ungate {
                "ungate".into()
            } else {
                "gate".into()
            },
            sha256_before: p.current.sha256.clone(),
            sha256_after: w.sha256_after.clone(),
            backup: w.backup.as_ref().map(|b| b.display().to_string()),
            origin: format!("gate package {}", hook_dir.clone().unwrap_or_default()),
        };
        let logged = log::record(&socket, &ctx.home.join(".derm/connect.log"), &rec)
            .unwrap_or_else(|e| format!("nowhere ({e})"));
        ctx.out.push_str(&format!(
            "written: {} (sha256 {}).{} Logged to {logged}.\n",
            p.path.display(),
            w.sha256_after,
            w.backup
                .map_or(String::new(), |b| format!(" Backup: {}.", b.display()))
        ));
    }
    Ok(0)
}

/// Case 54: one of the row's folders, or its program on PATH.
fn installed(agent: &Agent, home: &Path, env: &dyn Env) -> bool {
    let found = agent.installed_if.iter().any(|p| {
        resolve(
            &Place {
                path: p.clone(),
                home_env: None,
                xdg_config: true,
            },
            home,
            env,
        )
        .exists()
    });
    found
        || agent.cli.as_ref().is_some_and(|cli| {
            env.var("PATH")
                .unwrap_or_default()
                .split(':')
                .filter(|d| d.starts_with('/'))
                .any(|d| Path::new(d).join(cli).is_file())
        })
}
