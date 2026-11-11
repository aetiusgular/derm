//! The MCP server names Crush is configured with, so the Crush dialect can
//! tell `mcp_exa_evil_t` (server `exa_evil`) from `mcp_exa_web_search`
//! (server `exa`): Crush names an MCP tool `mcp_<server>_<tool>` with no
//! escaping (`internal/agent/tools/mcp-tools.go:58-60` at v0.99.0), and a
//! server name may hold `_`. Integration w2's re-review W2-R1 left this class
//! of name to the agent's own server list.
//!
//! Where Crush reads its config, at v0.99.0 (`internal/config/load.go`; the
//! TypeScript's reading, unchanged at 0.100.0 by the base's contract run):
//! `/etc/crush/crush.json`; `$CRUSH_GLOBAL_CONFIG/crush.json`, else the user
//! config folder's `crush/crush.json`, and the `crushrc` beside it;
//! `$CRUSH_GLOBAL_DATA/crush.json`, else `$XDG_DATA_HOME/crush/crush.json`,
//! else `~/.local/share/crush/crush.json`; and from the working folder up to
//! the git work tree's root, or the working folder alone with none:
//! `.crushrc`, `crushrc`, `.crush.json`, `crush.json`. A crushrc is Bash run
//! by Crush's interpreter with an `mcp add <name>` builtin; derm reads one
//! only when every line is blank, a comment, or a plain builtin call with no
//! expansion, quoting trick, redirection or control flow. Anything else, an
//! unreadable or invalid JSON file, or no absolute cwd makes the list
//! incomplete, and then every split that is not forced asks. Every name ever
//! added counts: more names can only make a split ambiguous, never plain.
//!
//! Ported from `packages/derm-hooks-native/src/crushServers.ts` at `e29ce27`.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use super::mcp_split::ServerNames;
use crate::gate::daemon::Env;

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_WALK: usize = 64;

/// JavaScript's `\s` (and what `String.prototype.trim` drops).
pub use derm_core::redact::hook::js_space;

/// `path.resolve` for an absolute path: `.` and `..` removed lexically.
pub fn resolve(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The home folder a reader uses: `HOME` trimmed, else the OS's.
pub fn home_of(env: &Env) -> PathBuf {
    env.get("HOME")
        .map(PathBuf::from)
        .or_else(derm_core::runtime::home_dir)
        .unwrap_or_default()
}

fn config_dir(env: &Env, home: &Path) -> PathBuf {
    if let Some(g) = env.get("CRUSH_GLOBAL_CONFIG") {
        return PathBuf::from(g);
    }
    let base = match env.get("XDG_CONFIG_HOME") {
        Some(x) if Path::new(x).is_absolute() => PathBuf::from(x),
        _ => home.join(".config"),
    };
    base.join("crush")
}

fn data_file(env: &Env, home: &Path) -> PathBuf {
    if let Some(d) = env.get("CRUSH_GLOBAL_DATA") {
        return Path::new(d).join("crush.json");
    }
    if let Some(x) = env.get("XDG_DATA_HOME") {
        return Path::new(x).join("crush").join("crush.json");
    }
    home.join(".local")
        .join("share")
        .join("crush")
        .join("crush.json")
}

/// The folders from `cwd` up to the git work tree's root (a `.git` file or
/// folder), or `cwd` alone (`projectFolders`).
pub fn project_folders(cwd: &Path) -> Vec<PathBuf> {
    let start = resolve(cwd);
    let mut out = Vec::new();
    let mut dir = start.clone();
    for _ in 0..MAX_WALK {
        out.push(dir.clone());
        if dir.join(".git").exists() {
            return out;
        }
        match dir.parent() {
            Some(up) if up != dir => dir = up.to_path_buf(),
            _ => break,
        }
    }
    vec![start]
}

/// What a small config read gives.
pub enum Small {
    /// Not there (`undefined`).
    Missing,
    /// There and not readable whole (`null`).
    Unreadable,
    Text(String),
}

/// Reads a regular file of at most 4 MiB, links followed (`readSmall`). The
/// file is opened without blocking and judged by its handle, so a project
/// that swaps it for a FIFO after a check cannot hold the hook (the
/// TypeScript stat the path and then read it, case 111's class).
pub fn read_small(file: &Path) -> Small {
    use std::io::Read;
    let opened = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(file)
        }
        #[cfg(not(unix))]
        {
            match std::fs::metadata(file) {
                Ok(m) if !m.is_file() => return Small::Unreadable,
                _ => std::fs::File::open(file),
            }
        }
    };
    let f = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Small::Missing,
        Err(_) => return Small::Unreadable,
    };
    match f.metadata() {
        Ok(m) if m.is_file() && m.len() <= MAX_CONFIG_BYTES => {}
        _ => return Small::Unreadable,
    }
    let mut b = Vec::new();
    match f.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut b) {
        Ok(_) if b.len() as u64 <= MAX_CONFIG_BYTES => {
            Small::Text(String::from_utf8_lossy(&b).into_owned())
        }
        _ => Small::Unreadable,
    }
}

/// The keys of `key` in one JSON config; `None` when the file cannot be read
/// whole (`jsonServerNames`, Kiro's `serversIn`).
pub fn json_keys(text: &str, key: &str) -> Option<Vec<String>> {
    let v: Value = serde_json::from_str(text).ok()?;
    let Value::Object(o) = v else { return None };
    match o.get(key) {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Object(m)) => Some(m.keys().cloned().collect()),
        Some(_) => None,
    }
}

fn plain_word(w: &str) -> bool {
    !w.is_empty()
        && w.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-')
        })
}

fn quoted(w: &str) -> bool {
    w.len() >= 2
        && w.starts_with('\'')
        && w.ends_with('\'')
        && !w[1..w.len() - 1].contains(['\'', '\n'])
}

/// `line.match(/'[^']*'|[^\s']+/g)`: a quoted string with its quotes, or a
/// run of characters that are neither space nor quote; an unclosed quote is
/// skipped.
fn words(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            if let Some(j) = chars[i + 1..].iter().position(|&d| d == '\'') {
                out.push(chars[i..=i + 1 + j].iter().collect());
                i += j + 2;
            } else {
                i += 1;
            }
        } else if js_space(c) {
            i += 1;
        } else {
            let start = i;
            while i < chars.len() && chars[i] != '\'' && !js_space(chars[i]) {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        }
    }
    out
}

const CONTROL_WORDS: [&str; 22] = [
    "if", "then", "else", "fi", "for", "while", "case", "function", "source", ".", "eval", "alias",
    "exec", "export", "set", "unset", "cd", "pushd", "trap", "declare", "local", "readonly",
];

/// The names a crushrc's `mcp add` lines give, or `None` when a line is
/// anything but blank, a comment, or a builtin call made of plain words and
/// single-quoted strings (`crushrcServerNames`).
pub fn crushrc_server_names(text: &str) -> Option<Vec<String>> {
    let mut names = Vec::new();
    for raw in text.split('\n') {
        let line = raw.trim_matches(js_space);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let ws = words(line);
        if ws.join(" ").is_empty() {
            continue;
        }
        if ws.iter().any(|w| !plain_word(w) && !quoted(w)) {
            return None;
        }
        let plain: Vec<String> = ws
            .iter()
            .map(|w| {
                if quoted(w) {
                    w[1..w.len() - 1].to_string()
                } else {
                    w.clone()
                }
            })
            .collect();
        if plain.first().map(String::as_str) == Some("mcp")
            && plain.get(1).map(String::as_str) == Some("add")
        {
            names.push(plain.get(2)?.clone());
        }
        if CONTROL_WORDS.contains(&plain.first().map(String::as_str).unwrap_or("")) {
            return None;
        }
    }
    Some(names)
}

/// Collects names, keeping the first failure's reason.
#[derive(Default)]
pub struct Collect {
    names: Vec<String>,
    complete: bool,
    why: Option<String>,
}

impl Collect {
    pub fn new() -> Collect {
        Collect {
            complete: true,
            ..Collect::default()
        }
    }
    pub fn add(&mut self, n: String) {
        if !self.names.contains(&n) {
            self.names.push(n);
        }
    }
    pub fn fail(&mut self, reason: String) {
        self.complete = false;
        if self.why.is_none() {
            self.why = Some(reason);
        }
    }
    pub fn done(self) -> ServerNames {
        ServerNames {
            names: self.names,
            complete: self.complete,
            why: self.why,
        }
    }
}

fn base_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Every MCP server name Crush may have, with whether the list is whole
/// (`crushServerNames`).
pub fn crush_server_names(env: &Env, cwd: Option<&str>, home: &Path) -> ServerNames {
    let mut c = Collect::new();
    let dir = config_dir(env, home);
    let mut json_files = vec![
        PathBuf::from("/etc/crush/crush.json"),
        dir.join("crush.json"),
        data_file(env, home),
    ];
    let mut rc_files = vec![dir.join("crushrc")];
    match cwd.filter(|c| !c.is_empty() && Path::new(c).is_absolute()) {
        None => c.fail("the hook input has no absolute cwd".into()),
        Some(cwd) => {
            for d in project_folders(Path::new(cwd)) {
                rc_files.push(d.join(".crushrc"));
                rc_files.push(d.join("crushrc"));
                json_files.push(d.join(".crush.json"));
                json_files.push(d.join("crush.json"));
            }
        }
    }
    for f in &json_files {
        match read_small(f) {
            Small::Missing => {}
            Small::Text(t) => match json_keys(&t, "mcp") {
                Some(ns) => ns.into_iter().for_each(|n| c.add(n)),
                None => c.fail(format!("{} could not be read", base_name(f))),
            },
            Small::Unreadable => c.fail(format!("{} could not be read", base_name(f))),
        }
    }
    for f in &rc_files {
        let got = match read_small(f) {
            Small::Missing => continue,
            Small::Text(t) => crushrc_server_names(&t),
            Small::Unreadable => None,
        };
        match got {
            Some(ns) => ns.into_iter().for_each(|n| c.add(n)),
            None => c.fail(format!(
                "a crushrc derm cannot read statically ({})",
                base_name(f)
            )),
        }
    }
    c.done()
}
