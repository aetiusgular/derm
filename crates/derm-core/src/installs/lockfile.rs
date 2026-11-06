//! Lockfiles: which packages a project already pins (wave 5 lane X). A port
//! of the hook core's `installs/lockfile.ts`, held equal to it by
//! `contracts/fixtures/installs/lockfiles/`. Used by the gate here (a pinned
//! package keeps an `allow`) and by the daemon's lockfile diff
//! (`crates/derm-daemon/src/installs/`).
//!
//! Line readers for names, versions and whether an entry came from the
//! registry, written against lockfiles the managers wrote on 4 Nov 2026. A
//! line they cannot read is skipped: a missed entry can only make the gate
//! ask.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::parse::Manager;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LockEntry {
    pub name: String,
    pub version: String,
    pub registry: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    PackageLock,
    PnpmLock,
    YarnLock,
    BunLock,
    UvLock,
    PoetryLock,
    PdmLock,
    Pylock,
    CargoLock,
    GoSum,
}

impl LockKind {
    /// The fixture's names (`expected.json`).
    pub fn from_name(s: &str) -> Option<LockKind> {
        Some(match s {
            "package-lock" => LockKind::PackageLock,
            "pnpm-lock" => LockKind::PnpmLock,
            "yarn-lock" => LockKind::YarnLock,
            "bun-lock" => LockKind::BunLock,
            "uv-lock" => LockKind::UvLock,
            "poetry-lock" => LockKind::PoetryLock,
            "pdm-lock" => LockKind::PdmLock,
            "pylock" => LockKind::Pylock,
            "cargo-lock" => LockKind::CargoLock,
            "go-sum" => LockKind::GoSum,
            _ => return None,
        })
    }
}

/// The lockfiles each manager writes, in the order a project would have them.
pub fn lockfiles(manager: Manager) -> &'static [(&'static str, LockKind)] {
    match manager {
        Manager::Npm => &[
            ("package-lock.json", LockKind::PackageLock),
            ("npm-shrinkwrap.json", LockKind::PackageLock),
        ],
        Manager::Pnpm => &[("pnpm-lock.yaml", LockKind::PnpmLock)],
        Manager::Yarn => &[("yarn.lock", LockKind::YarnLock)],
        Manager::Bun => &[("bun.lock", LockKind::BunLock)],
        Manager::Pip => &[("pylock.toml", LockKind::Pylock)],
        Manager::Uv => &[("uv.lock", LockKind::UvLock)],
        Manager::Poetry => &[("poetry.lock", LockKind::PoetryLock)],
        Manager::Pdm => &[("pdm.lock", LockKind::PdmLock)],
        Manager::Pipx => &[],
        Manager::Cargo => &[("Cargo.lock", LockKind::CargoLock)],
        Manager::Go => &[("go.sum", LockKind::GoSum)],
    }
}

pub const MAX_LOCKFILE_BYTES: u64 = 16 * 1024 * 1024;

/// The entries of one lockfile's text.
pub fn parse_lockfile(kind: LockKind, text: &str) -> Vec<LockEntry> {
    match kind {
        LockKind::PackageLock => package_lock(text),
        LockKind::PnpmLock => pnpm_lock(text),
        LockKind::YarnLock => yarn_lock(text),
        LockKind::BunLock => bun_lock(text),
        LockKind::UvLock | LockKind::PoetryLock | LockKind::PdmLock | LockKind::CargoLock => {
            toml_packages(text, "[[package]]", kind)
        }
        LockKind::Pylock => toml_packages(text, "[[packages]]", kind),
        LockKind::GoSum => go_sum(text),
    }
}

/// `name@version`, split past a scope's own `@`.
fn split_at(spec: &str) -> Option<(String, String)> {
    let at = spec.rfind('@')?;
    if at == 0 {
        return None;
    }
    Some((spec[..at].to_string(), spec[at + 1..].to_string()))
}

fn package_lock(text: &str) -> Vec<LockEntry> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(packages) = doc.get("packages").and_then(|p| p.as_object()) {
        for (key, v) in packages {
            let Some(i) = key.rfind("node_modules/") else {
                continue;
            };
            if !v.is_object() {
                continue;
            }
            // A local folder npm links (`npm install ../pkg`): `link: true`
            // and `resolved` naming the folder's own entry, which holds the
            // version (npm 10.9.9, run; box test w5, BW5-14).
            let target = if v.get("link") == Some(&serde_json::Value::Bool(true)) {
                v.get("resolved")
                    .and_then(|r| r.as_str())
                    .and_then(|r| packages.get(r))
                    .filter(|t| t.is_object())
            } else {
                Some(v)
            };
            let Some(target) = target else {
                continue;
            };
            let Some(version) = target.get("version").and_then(|x| x.as_str()) else {
                continue;
            };
            let name = match v.get("name").and_then(|x| x.as_str()) {
                Some(n) => n.to_string(),
                None => key[i + "node_modules/".len()..].to_string(),
            };
            out.push(LockEntry {
                name,
                version: version.to_string(),
                registry: registry_resolved(v.get("resolved")),
            });
        }
        return out;
    }
    fn walk(deps: Option<&serde_json::Value>, depth: usize, out: &mut Vec<LockEntry>) {
        if depth > 64 {
            return;
        }
        let Some(map) = deps.and_then(|d| d.as_object()) else {
            return;
        };
        for (name, v) in map {
            if !v.is_object() {
                continue;
            }
            if let Some(version) = v.get("version").and_then(|x| x.as_str()) {
                if !version.contains(':') {
                    out.push(LockEntry {
                        name: name.clone(),
                        version: version.to_string(),
                        registry: registry_resolved(v.get("resolved")),
                    });
                }
            }
            walk(v.get("dependencies"), depth + 1, out);
        }
    }
    walk(doc.get("dependencies"), 0, &mut out);
    out
}

/// A registry tarball URL (`https://host/.../-/name-1.0.0.tgz`), or none.
fn registry_resolved(resolved: Option<&serde_json::Value>) -> bool {
    match resolved {
        None => true,
        Some(serde_json::Value::String(s)) => {
            let Some(rest) = s.strip_prefix("https://") else {
                return false;
            };
            let Some((host, path)) = rest.split_once('/') else {
                return false;
            };
            if host.is_empty() || host.contains('/') {
                return false;
            }
            match path.rfind("/-/") {
                Some(i) => {
                    let file = &path[i + 3..];
                    !file.is_empty() && !file.contains('/') && file.ends_with(".tgz")
                }
                None => false,
            }
        }
        Some(_) => false,
    }
}

fn unquote_key(k: &str) -> String {
    let t = k.trim();
    if t.len() >= 2
        && ((t.starts_with('\'') && t.ends_with('\'')) || (t.starts_with('"') && t.ends_with('"')))
    {
        return t[1..t.len() - 1].to_string();
    }
    t.to_string()
}

fn pnpm_lock(text: &str) -> Vec<LockEntry> {
    let mut out = Vec::new();
    let mut in_packages = false;
    for line in text.lines() {
        if line.chars().next().is_some_and(|c| !c.is_whitespace()) {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        // Two spaces, a key, a colon, and nothing or `{}` after it.
        let Some(rest) = line.strip_prefix("  ") else {
            continue;
        };
        if rest.starts_with(char::is_whitespace) {
            continue;
        }
        let rest = rest.trim_end();
        let key = if let Some(k) = rest.strip_suffix(": {}") {
            k
        } else if let Some(k) = rest.strip_suffix(':') {
            k
        } else {
            continue;
        };
        let key = key.trim_end();
        if key.is_empty() {
            continue;
        }
        let mut key = unquote_key(key);
        if let Some(p) = key.find('(').filter(|&p| p > 0) {
            key.truncate(p);
        }
        if let Some(k) = key.strip_prefix('/') {
            key = k.to_string();
        }
        let split = split_at(&key).or_else(|| {
            let slash = key.rfind('/')?;
            if slash == 0 {
                return None;
            }
            Some((key[..slash].to_string(), key[slash + 1..].to_string()))
        });
        let Some((name, version)) = split else {
            continue;
        };
        let registry = ![
            "link:",
            "file:",
            "workspace:",
            "git:",
            "github:",
            "http:",
            "https:",
        ]
        .iter()
        .any(|p| version.starts_with(p))
            && !version.contains('/');
        out.push(LockEntry {
            name,
            version,
            registry,
        });
    }
    out
}

fn yarn_lock(text: &str) -> Vec<LockEntry> {
    let mut out = Vec::new();
    let mut header: Option<String> = None;
    let mut version: Option<String> = None;
    let mut resolution: Option<String> = None;
    let flush = |header: &mut Option<String>,
                 version: &mut Option<String>,
                 resolution: &mut Option<String>,
                 out: &mut Vec<LockEntry>| {
        if let (Some(h), Some(v)) = (header.as_ref(), version.as_ref()) {
            if let Some(r) = resolution.as_ref() {
                if let Some((name, proto)) = berry_resolution(r) {
                    if proto != "workspace" {
                        out.push(LockEntry {
                            name,
                            version: v.clone(),
                            registry: proto == "npm",
                        });
                    }
                }
            } else {
                let first = unquote_key(h.split(',').next().unwrap_or("").trim());
                if let Some((name, range)) = split_at(&first) {
                    let registry = !["file:", "link:", "git:", "github:", "http:", "https:"]
                        .iter()
                        .any(|p| range.starts_with(p));
                    out.push(LockEntry {
                        name,
                        version: v.clone(),
                        registry,
                    });
                }
            }
        }
        *header = None;
        *version = None;
        *resolution = None;
    };
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if line.chars().next().is_some_and(|c| !c.is_whitespace()) {
            flush(&mut header, &mut version, &mut resolution, &mut out);
            if line.starts_with("__metadata") {
                continue;
            }
            let h = line.trim_end();
            header = Some(h.strip_suffix(':').unwrap_or(h).to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("  ") {
            if rest.starts_with(char::is_whitespace) {
                continue;
            }
            if let Some(v) = rest
                .strip_prefix("version")
                .map(|r| r.strip_prefix(':').unwrap_or(r))
            {
                if v.starts_with(' ') {
                    let v = v.trim().trim_matches('"');
                    if !v.is_empty() && !v.contains(char::is_whitespace) {
                        version = Some(v.to_string());
                    }
                }
            }
            if let Some(r) = rest.strip_prefix("resolution: ") {
                let r = r.trim().trim_matches('"');
                if !r.is_empty() {
                    resolution = Some(r.to_string());
                }
            }
        }
    }
    flush(&mut header, &mut version, &mut resolution, &mut out);
    out
}

/// Berry's `name@protocol:rest`, the protocol in lowercase letters.
fn berry_resolution(r: &str) -> Option<(String, String)> {
    let start = usize::from(r.starts_with('@'));
    let at = r[start..].find('@')? + start;
    let name = &r[..at];
    if name.is_empty() || name[start..].contains('@') {
        return None;
    }
    let rest = &r[at + 1..];
    let colon = rest.find(':')?;
    let proto = &rest[..colon];
    if proto.is_empty() || !proto.chars().all(|c| c.is_ascii_lowercase()) {
        return None;
    }
    Some((name.to_string(), proto.to_string()))
}

fn bun_lock(text: &str) -> Vec<LockEntry> {
    let cleaned = strip_trailing_commas(text);
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&cleaned) else {
        return Vec::new();
    };
    let Some(packages) = doc.get("packages").and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for v in packages.values() {
        let Some(first) = v
            .as_array()
            .and_then(|a| a.first())
            .and_then(|f| f.as_str())
        else {
            continue;
        };
        let Some((name, version)) = split_at(first) else {
            continue;
        };
        if [
            "workspace:",
            "file:",
            "link:",
            "git:",
            "github:",
            "http:",
            "https:",
            "root:",
        ]
        .iter()
        .any(|p| version.starts_with(p))
        {
            continue;
        }
        out.push(LockEntry {
            name,
            version,
            registry: true,
        });
    }
    out
}

/// `,` before `}` or `]` (past whitespace) removed, as the hook core's
/// `/,(\s*[}\]])/g` does.
fn strip_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == ',' {
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

fn toml_packages(text: &str, header: &str, kind: LockKind) -> Vec<LockEntry> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut source: Option<String> = None;
    let mut flush = |in_block: bool,
                     name: &mut Option<String>,
                     version: &mut Option<String>,
                     source: &mut Option<String>| {
        if in_block {
            if let (Some(n), Some(v)) = (name.as_ref(), version.as_ref()) {
                let has_key = |s: &str, k: &str| {
                    s.match_indices(k).any(|(i, _)| {
                        let before_ok = i == 0
                            || !s.as_bytes()[i - 1].is_ascii_alphanumeric()
                                && s.as_bytes()[i - 1] != b'_';
                        before_ok && s[i + k.len()..].trim_start().starts_with('=')
                    })
                };
                let local = match kind {
                    LockKind::UvLock => source.as_deref().is_some_and(|s| {
                        ["editable", "virtual", "path", "directory"]
                            .iter()
                            .any(|k| has_key(s, k))
                    }),
                    LockKind::CargoLock => source.is_none(),
                    _ => false,
                };
                let registry = match kind {
                    LockKind::CargoLock => source
                        .as_deref()
                        .is_some_and(|s| s.starts_with("\"registry+")),
                    LockKind::UvLock => source.as_deref().is_none_or(|s| has_key(s, "registry")),
                    _ => true,
                };
                if !local {
                    out.push(LockEntry {
                        name: n.clone(),
                        version: v.clone(),
                        registry,
                    });
                }
            }
        }
        *name = None;
        *version = None;
        *source = None;
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            flush(in_block, &mut name, &mut version, &mut source);
            in_block = line == header;
            continue;
        }
        if !in_block {
            continue;
        }
        for key in ["name", "version", "source"] {
            let Some(rest) = line.strip_prefix(key) else {
                continue;
            };
            let rest = rest.trim_start();
            let Some(value) = rest.strip_prefix('=') else {
                continue;
            };
            let value = value.trim_start();
            let quoted = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .filter(|v| !v.contains('"'))
                .map(str::to_string);
            match key {
                "name" => {
                    if quoted.is_some() {
                        name = quoted;
                    }
                }
                "version" => {
                    if quoted.is_some() {
                        version = quoted;
                    }
                }
                _ => source = Some(value.to_string()),
            }
        }
    }
    flush(in_block, &mut name, &mut version, &mut source);
    out
}

fn go_sum(text: &str) -> Vec<LockEntry> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() != 3 || f[1].ends_with("/go.mod") {
                return None;
            }
            Some(LockEntry {
                name: f[0].to_string(),
                version: f[1].to_string(),
                registry: true,
            })
        })
        .collect()
}

// --- Reading from disk ---------------------------------------------------------

/// One lockfile's text, or `None`: not there, not a regular file, a link, or
/// too large. On Unix the file is opened without following a link and
/// without blocking on a FIFO.
pub fn read_lockfile_text(file: &Path) -> Option<String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    {
        if std::fs::symlink_metadata(file)
            .ok()?
            .file_type()
            .is_symlink()
        {
            return None;
        }
    }
    let f = opts.open(file).ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_LOCKFILE_BYTES {
        return None;
    }
    let mut text = String::new();
    f.take(MAX_LOCKFILE_BYTES).read_to_string(&mut text).ok()?;
    Some(text)
}

pub struct FoundLockfile {
    pub file: PathBuf,
    pub kind: LockKind,
    pub entries: Vec<LockEntry>,
}

/// The nearest lockfile of `manager` at or above `cwd`, up to 32 folders.
pub fn find_lockfile(manager: Manager, cwd: &Path) -> Option<FoundLockfile> {
    let names = lockfiles(manager);
    if names.is_empty() || !cwd.is_absolute() {
        return None;
    }
    let mut dir = cwd.to_path_buf();
    for _ in 0..32 {
        for (file, kind) in names {
            let full = dir.join(file);
            if let Some(text) = read_lockfile_text(&full) {
                return Some(FoundLockfile {
                    entries: parse_lockfile(*kind, &text),
                    file: full,
                    kind: *kind,
                });
            }
        }
        if !dir.pop() {
            break;
        }
    }
    None
}
