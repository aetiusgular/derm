//! derm-pi's record of the memory indexes you approved (case 48), judged
//! by handle on every OS (wave 5b plan, call 3; contract section 2.4).
//!
//! The record is the file `packages/derm-pi/extensions/memory.ts` kept
//! (`readState`, `writeState` at `e29ce27`): `{"version":1,"projects":
//! {<project's real path>:{<folder>/INDEX.md:{"sha256","lines"}}}}`, at
//! `DERM_MEMORY_STATE` when that is absolute, else `~/.derm/memory-index.json`.
//! It is used only when it is a regular file of this user's that no one else
//! may write (Unix: owner is the real uid, no group or other write bit,
//! opened without following a link and without blocking; Windows: one link,
//! no reparse point, and only its owner, LocalSystem and Administrators may
//! write it, read from the handle, as `gate::policy` judges the policy). A
//! missing record is trusted and empty. Anything else is not trusted: nothing
//! counts as approved and nothing is written back, so every index asks.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{plain_absolute, refuse, Ctx};
use crate::gate::daemon::Env;

/// The index files a record may hold (`FOLDERS` in `memory.ts`).
pub const INDEXES: [&str; 3] = ["memory/INDEX.md", "research/INDEX.md", "refs/INDEX.md"];
/// The record is read only up to this size (`MAX_STATE_BYTES`).
pub const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
/// Lines kept per approved index (`MAX_KEPT_LINES`).
pub const MAX_KEPT_LINES: usize = 500;

#[derive(Clone, Debug, PartialEq)]
pub struct Approved {
    pub sha256: String,
    pub lines: Vec<String>,
}

pub type Projects = BTreeMap<String, BTreeMap<String, Approved>>;

#[derive(Debug, PartialEq)]
pub struct StateRead {
    pub trusted: bool,
    pub projects: Projects,
}

fn untrusted() -> StateRead {
    StateRead {
        trusted: false,
        projects: Projects::new(),
    }
}

/// Where the record is (`statePathOf`): `DERM_MEMORY_STATE` when it is set
/// and absolute, none when it is set and relative, else under the home.
pub fn state_path(env: &Env) -> Option<PathBuf> {
    match env.raw("DERM_MEMORY_STATE") {
        Some(p) if !p.is_empty() => {
            let p = Path::new(p);
            p.is_absolute().then(|| p.to_path_buf())
        }
        _ => {
            let home = env
                .get(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .map(PathBuf::from)
                .or_else(derm_core::runtime::home_dir)?;
            Some(home.join(".derm").join("memory-index.json"))
        }
    }
}

fn is_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `cleanState`: only the three index names, a lower-case SHA-256, and the
/// string lines, at most [`MAX_KEPT_LINES`].
fn clean(raw: &Value) -> Projects {
    let mut out = Projects::new();
    let Some(projects) = raw.get("projects").and_then(Value::as_object) else {
        return out;
    };
    for (root, files) in projects {
        let Some(files) = files.as_object() else {
            continue;
        };
        let mut kept = BTreeMap::new();
        for (rel, rec) in files {
            if !INDEXES.contains(&rel.as_str()) {
                continue;
            }
            let Some(sha) = rec
                .get("sha256")
                .and_then(Value::as_str)
                .filter(|s| is_sha(s))
            else {
                continue;
            };
            let lines = rec
                .get("lines")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .take(MAX_KEPT_LINES)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            kept.insert(
                rel.clone(),
                Approved {
                    sha256: sha.to_string(),
                    lines,
                },
            );
        }
        out.insert(root.clone(), kept);
    }
    out
}

#[cfg(unix)]
fn open_record(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(windows)]
fn open_record(path: &Path) -> std::io::Result<std::fs::File> {
    // A pipe name opens a pipe client; only what is a file now is opened,
    // and a link is opened as itself, not followed.
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    derm_core::platform::private_no_follow(&mut o).open(path)
}

#[cfg(unix)]
fn record_private(file: &std::fs::File, meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let _ = file;
    // `memory.ts` compares the owner with `process.getuid()`.
    meta.uid() == derm_core::platform::real_user() && meta.mode() & 0o022 == 0
}

#[cfg(windows)]
fn record_private(file: &std::fs::File, meta: &std::fs::Metadata) -> bool {
    !meta.file_type().is_symlink() && derm_core::platform::windows::only_owner_writes_file(file)
}

/// `readState`, judged by the handle it reads.
pub fn read_state(path: Option<&Path>) -> StateRead {
    let Some(path) = path else {
        return untrusted();
    };
    let file = match open_record(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return StateRead {
                trusted: true,
                projects: Projects::new(),
            }
        }
        Err(_) => return untrusted(),
    };
    let Ok(meta) = file.metadata() else {
        return untrusted();
    };
    if !meta.is_file() || meta.len() > MAX_STATE_BYTES || !record_private(&file, &meta) {
        return untrusted();
    }
    let mut text = String::new();
    if (&file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_string(&mut text)
        .is_err()
        || text.len() as u64 > MAX_STATE_BYTES
    {
        return untrusted();
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(v) => StateRead {
            trusted: true,
            projects: clean(&v),
        },
        Err(_) => untrusted(),
    }
}

fn to_json(projects: &Projects) -> Value {
    let p: serde_json::Map<String, Value> = projects
        .iter()
        .map(|(root, files)| {
            let f: serde_json::Map<String, Value> = files
                .iter()
                .map(|(rel, a)| (rel.clone(), json!({"sha256": a.sha256, "lines": a.lines})))
                .collect();
            (root.clone(), Value::Object(f))
        })
        .collect();
    json!({"version": 1, "projects": p})
}

/// `writeState`: a new private file beside the record, then a rename over
/// it, so a reader never sees half of it and a link at the name is replaced,
/// not followed. The folder is made private when missing.
pub fn write_state(path: &Path, projects: &Projects) -> bool {
    let Some(dir) = path.parent() else {
        return false;
    };
    if !dir.exists() && derm_core::platform::private_dir(dir).is_err() {
        return false;
    }
    let tmp = dir.join(format!(
        ".memory-index-{}-{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    let written = derm_core::platform::private_no_follow(&mut o)
        .open(&tmp)
        .and_then(|mut f| {
            // On Windows a new file takes its folder's access list: held
            // private, as the reader requires.
            #[cfg(windows)]
            derm_core::platform::set_private_file(&tmp)?;
            f.write_all(format!("{}\n", to_json(projects)).as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    true
}

/// The project, index and hash a memory request names.
fn target_of(r: &Value) -> Result<(String, String, String), String> {
    let project = r.get("project").and_then(Value::as_str).unwrap_or("");
    if !plain_absolute(project) {
        return Err("project must be an absolute path".into());
    }
    let rel = r.get("rel").and_then(Value::as_str).unwrap_or("");
    if !INDEXES.contains(&rel) {
        return Err(format!("rel must be one of {}", INDEXES.join(", ")));
    }
    let sha = r.get("sha256").and_then(Value::as_str).unwrap_or("");
    if !is_sha(sha) {
        return Err("sha256 must be 64 lower-case hex digits".into());
    }
    Ok((project.into(), rel.into(), sha.into()))
}

pub(super) fn op_check(ctx: &Ctx, id: &Value, r: &Value) -> Value {
    let (project, rel, sha) = match target_of(r) {
        Ok(t) => t,
        Err(e) => return refuse(id, &e),
    };
    let state = read_state(ctx.memory_state.as_deref());
    let known = state
        .trusted
        .then(|| state.projects.get(&project))
        .flatten();
    let (word, lines) = match known.and_then(|k| k.get(&rel)) {
        Some(a) if a.sha256 == sha => ("approved", Vec::new()),
        Some(a) => ("changed", a.lines.clone()),
        None => ("unknown", Vec::new()),
    };
    json!({
        "id": id,
        "ok": true,
        "state": word,
        "trusted": state.trusted,
        "projectKnown": known.is_some(),
        "lines": lines,
    })
}

pub(super) fn op_approve(ctx: &Ctx, id: &Value, r: &Value) -> Value {
    let (project, rel, sha) = match target_of(r) {
        Ok(t) => t,
        Err(e) => return refuse(id, &e),
    };
    let lines: Vec<String> = match r.get("lines") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) if a.iter().all(Value::is_string) => a
            .iter()
            .filter_map(Value::as_str)
            .take(MAX_KEPT_LINES)
            .map(str::to_string)
            .collect(),
        Some(_) => return refuse(id, "lines must be a list of strings"),
    };
    let Some(path) = ctx.memory_state.as_deref() else {
        return json!({"id": id, "ok": true, "written": false});
    };
    let mut state = read_state(Some(path));
    if !state.trusted {
        return json!({"id": id, "ok": true, "written": false});
    }
    state
        .projects
        .entry(project)
        .or_default()
        .insert(rel, Approved { sha256: sha, lines });
    let written = write_state(path, &state.projects);
    json!({"id": id, "ok": true, "written": written})
}
