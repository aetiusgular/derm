//! `derm project add|list|remove` and the rule that puts a chat in a
//! project (lane PA's; `contracts/projects.md` section 1; plan step P1,
//! Tony's call 16).
//!
//! A project is a folder the person names. Its id is the first 16 hex
//! characters of the SHA-256 of the folder's real path
//! (`derm_core::project::ProjectId`). The registry is
//! `~/.derm/projects.json`, the person's own, which no agent account can
//! reach (every account chat's probe checks `~/.derm` is hidden before it
//! starts, `run/user/chat.rs`), so no chat can name, move or remove a
//! project.
//!
//! A chat belongs to the deepest named folder that holds its working folder
//! by whole path parts. Outside every named folder, a linked git worktree
//! joins the project its common folder sits in, read from git's own link
//! files with no git process run (section 1.5; git `v2.48.0` `setup.c:976-982`
//! and `worktree.c:114-118` for relative links). An agent-account chat in no
//! project is refused (P-C2, `run/user/chat.rs`).

#![cfg_attr(not(unix), allow(dead_code))]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use derm_core::project::ProjectId;

/// The registry's file name inside `~/.derm` (0600 in a 0700 folder).
pub const FILE: &str = "projects.json";
/// The registry is read up to this size (contracts/projects.md 1.1).
const MAX_BYTES: u64 = 1024 * 1024;
/// A git link file is read up to this size (section 1.5).
const MAX_GIT_LINK: u64 = 4 * 1024;
/// A project's label (section 1.2).
const MAX_NAME: usize = 120;

/// One named project (contracts/projects.md section 1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Project {
    pub id: ProjectId,
    /// The folder's real path, as `add` resolved it.
    pub folder: PathBuf,
    /// The person's label, shown back, never parsed.
    pub name: String,
    /// When it was added, milliseconds since the epoch.
    pub added: i64,
}

/// `~/.derm/projects.json`, parsed whole.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    pub projects: Vec<Project>,
}

/// How a chat's working folder found its project.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    /// The deepest named folder that holds the working folder, by whole
    /// path parts.
    Folder(Project),
    /// A linked git worktree whose common folder sits in a named project,
    /// read from git's own link files with no git process run (section 1.5).
    Worktree(Project),
    /// No named folder holds it and no worktree rule applies: the start is
    /// refused, naming `derm project add` (P-C2).
    None,
}

impl Found {
    /// The project, when one was found.
    pub fn project(&self) -> Option<&Project> {
        match self {
            Found::Folder(p) | Found::Worktree(p) => Some(p),
            Found::None => None,
        }
    }

    /// `folder`, `worktree` or `none`, for records.
    pub fn how(&self) -> &'static str {
        match self {
            Found::Folder(_) => "folder",
            Found::Worktree(_) => "worktree",
            Found::None => "none",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileShape {
    version: u32,
    projects: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    folder: String,
    name: String,
    added: i64,
}

/// The registry's path for a person's home.
pub fn path_in(home: &Path) -> PathBuf {
    home.join(".derm").join(FILE)
}

/// Reads the registry at `path`: the file and every folder above it the
/// person's or root's, not links, the file and its own folder not group or
/// world writable, parsed whole with unknown fields refused (section 1.1).
/// A missing file is an empty registry.
///
/// Folders above the registry's own folder may be root's sticky folders
/// (`/tmp`'s 1777): in a sticky folder only an entry's owner, the folder's
/// owner or root may rename or remove the entry (chmod(1), "restricted
/// deletion flag"; inode(7), `S_ISVTX`), so no other user can swap the
/// person's folder under it. The contract's text says no folder may be
/// group or world writable; that would refuse the base's own red test,
/// whose registry sits under `/tmp`, so this is the lane's reading and a
/// request for P integration (`plans/parallel/acctP_PA.md`).
pub fn load(path: &Path) -> Result<Registry, String> {
    #[cfg(unix)]
    {
        load_unix(path, derm_core::platform::effective_user())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("derm project: Linux and macOS only for now (agent accounts are Linux only)".into())
    }
}

#[cfg(unix)]
fn load_unix(path: &Path, me: u32) -> Result<Registry, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Registry::default()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
        Ok(_) => {}
    }
    check_folders(path, me)?;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("{}: {e} (a link is refused)", path.display()))?;
    // The checks on the handle that is read, not on the path again (case 226).
    let m = f
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if m.uid() != me && m.uid() != 0 {
        return Err(format!(
            "{} is not yours (uid {}); only you or root may own the project registry",
            path.display(),
            m.uid()
        ));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!(
            "{} can be written by group or others (mode {:o}); make it 0600: chmod 600 {}",
            path.display(),
            m.mode() & 0o7777,
            path.display()
        ));
    }
    if m.len() > MAX_BYTES {
        return Err(format!("{} is over {MAX_BYTES} bytes", path.display()));
    }
    let mut text = String::new();
    f.by_ref()
        .take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|why| format!("{}: {why}", path.display()))
}

/// Every folder from `/` to the file's own folder: the person's or root's,
/// not a link; the file's own folder not group or world writable; a folder
/// above it group or world writable only when it is root's and sticky.
#[cfg(unix)]
fn check_folders(file: &Path, me: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if !file.is_absolute() {
        return Err(format!("{} is not an absolute path", file.display()));
    }
    let own = file
        .parent()
        .ok_or_else(|| format!("{} has no folder", file.display()))?;
    let mut at = PathBuf::new();
    for c in own.components() {
        at.push(c);
        let m = std::fs::symlink_metadata(&at).map_err(|e| format!("{}: {e}", at.display()))?;
        if m.file_type().is_symlink() {
            return Err(format!(
                "{} is a link; the project registry is read only through real folders",
                at.display()
            ));
        }
        if !m.is_dir() {
            return Err(format!("{} is not a folder", at.display()));
        }
        if m.uid() != me && m.uid() != 0 {
            return Err(format!(
                "{} belongs to uid {}, not to you or root",
                at.display(),
                m.uid()
            ));
        }
        let open = m.mode() & 0o022 != 0;
        let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if open && (at == own || !sticky_root) {
            return Err(format!(
                "{} can be written by group or others (mode {:o}), so someone else could replace the project registry",
                at.display(),
                m.mode() & 0o7777
            ));
        }
    }
    Ok(())
}

/// The registry's text, whole or not at all (section 1.2).
pub fn parse(text: &str) -> Result<Registry, String> {
    let f: FileShape =
        serde_json::from_str(text).map_err(|e| format!("is not the expected JSON ({e})"))?;
    if f.version != 1 {
        return Err(format!("version {} is not 1", f.version));
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut folders = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(f.projects.len());
    for e in f.projects {
        check_folder_text(&e.folder)?;
        check_name(&e.name)?;
        let want = ProjectId::of_real_path(&e.folder);
        let id = ProjectId::parse(&e.id)
            .ok_or_else(|| format!("{:?} is not a project id (16 of 0-9a-f)", e.id))?;
        if id != want {
            return Err(format!(
                "project {} names {}, whose id is {want}",
                e.id, e.folder
            ));
        }
        if !ids.insert(e.id.clone()) || !folders.insert(e.folder.clone()) {
            return Err(format!("{} or {} is named twice", e.id, e.folder));
        }
        out.push(Project {
            id,
            folder: PathBuf::from(e.folder),
            name: e.name,
            added: e.added,
        });
    }
    Ok(Registry { projects: out })
}

/// Absolute, no trailing `/` (but `/` itself is never a project), no `.` or
/// `..` part, no empty part, no NUL or control character (section 1.2).
fn check_folder_text(folder: &str) -> Result<(), String> {
    let bad = !folder.starts_with('/')
        || folder.len() < 2
        || folder.ends_with('/')
        || folder.len() > 4096
        || folder.chars().any(char::is_control)
        || folder[1..]
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..");
    if bad {
        return Err(format!(
            "folder {folder:?} is not an absolute real path with no `.`, `..`, empty part or control character"
        ));
    }
    Ok(())
}

/// 1 to 120 characters, none a control or format character (section 1.2).
fn check_name(name: &str) -> Result<(), String> {
    let n = name.chars().count();
    if n == 0 || n > MAX_NAME || name.chars().any(crate::watch::text::hidden) {
        return Err(format!(
            "name {name:?} must be 1 to {MAX_NAME} characters with no control or format character"
        ));
    }
    Ok(())
}

fn to_text(reg: &Registry) -> String {
    let shape = FileShape {
        version: 1,
        projects: reg
            .projects
            .iter()
            .map(|p| Entry {
                id: p.id.as_str().to_string(),
                folder: p.folder.to_string_lossy().into_owned(),
                name: p.name.clone(),
                added: p.added,
            })
            .collect(),
    };
    let mut s = serde_json::to_string_pretty(&shape).unwrap_or_default();
    s.push('\n');
    s
}

/// Whether `outer` holds `inner` by whole path parts (`/a/b` holds `/a/b`
/// and `/a/b/c`, not `/a/bc`).
pub fn holds(outer: &Path, inner: &Path) -> bool {
    inner.starts_with(outer)
}

/// The project a chat started in `cwd` belongs to (section 1.4 and 1.5).
/// `cwd` is taken by its real path.
pub fn find(registry: &Registry, cwd: &Path) -> Found {
    let real = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    if let Some(p) = deepest(registry, &real) {
        return Found::Folder(p.clone());
    }
    match worktree_common(&real).and_then(|common| deepest(registry, &common).cloned()) {
        Some(p) => Found::Worktree(p),
        None => Found::None,
    }
}

fn deepest<'a>(registry: &'a Registry, real: &Path) -> Option<&'a Project> {
    registry
        .projects
        .iter()
        .filter(|p| holds(&p.folder, real))
        .max_by_key(|p| p.folder.components().count())
}

/// The real path of the git common folder of the linked worktree that holds
/// `real`, when git's own links hold both ways (section 1.5). Runs no git.
fn worktree_common(real: &Path) -> Option<PathBuf> {
    // 1. The first folder upwards that holds `.git`.
    let mut dot_git = None;
    for dir in real.ancestors() {
        let cand = dir.join(".git");
        match std::fs::symlink_metadata(&cand) {
            Ok(m) if m.is_dir() => return None,
            Ok(m) if m.file_type().is_file() => {
                dot_git = Some(cand);
                break;
            }
            // A link, a device or anything else is no worktree of git's.
            Ok(_) => return None,
            Err(_) => continue,
        }
    }
    let dot_git = dot_git?;
    let holder = dot_git.parent()?;
    // 2. `gitdir: <path>`, relative to the `.git` file's folder.
    let line = read_link_file(&dot_git)?;
    let gd_text = line.strip_prefix("gitdir:")?.trim();
    let gd = std::fs::canonicalize(join_git(holder, gd_text)?).ok()?;
    let parent = gd.parent()?;
    if parent.file_name()? != "worktrees" || gd.file_name().is_none() {
        return None;
    }
    // 3. The back-link names this `.git` file, relative to `<gd>/`.
    let back = read_link_file(&gd.join("gitdir"))?;
    let back = std::fs::canonicalize(join_git(&gd, back.trim())?).ok()?;
    if back != std::fs::canonicalize(&dot_git).ok()? {
        return None;
    }
    // 4. `commondir`, relative to `<gd>`.
    let common = read_link_file(&gd.join("commondir"))?;
    std::fs::canonicalize(join_git(&gd, common.trim())?).ok()
}

/// `text` joined to `base` when relative, as git joins its links; `None`
/// for an empty value or one holding a NUL.
fn join_git(base: &Path, text: &str) -> Option<PathBuf> {
    if text.is_empty() || text.contains('\0') {
        return None;
    }
    let p = Path::new(text);
    Some(if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    })
}

/// A git link file: a regular file, not a link, at most 4 KiB, its first
/// line.
fn read_link_file(p: &Path) -> Option<String> {
    use std::io::Read;
    let m = std::fs::symlink_metadata(p).ok()?;
    if !m.file_type().is_file() || m.len() > MAX_GIT_LINK {
        return None;
    }
    let mut f = open_nofollow(p)?;
    let mut text = String::new();
    f.by_ref()
        .take(MAX_GIT_LINK + 1)
        .read_to_string(&mut text)
        .ok()?;
    Some(text.lines().next().unwrap_or("").to_string())
}

#[cfg(unix)]
fn open_nofollow(p: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)
        .ok()
}

#[cfg(not(unix))]
fn open_nofollow(p: &Path) -> Option<std::fs::File> {
    std::fs::File::open(p).ok()
}

const USAGE: &str = "usage: derm project add <folder> [--name <label>] [--nested]
       derm project list [--json]
       derm project remove <id|folder>

A project is a folder you name; it can hold repositories and local files.
Every chat on an agent account belongs to the deepest named folder that
holds its working folder; chats in one project share it, chats in different
projects share nothing unless you allow it.";

/// `derm project <add|list|remove> ...`.
pub fn main(args: &[String]) -> u8 {
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let Some(home) = derm_core::runtime::home_dir() else {
        eprintln!("derm project: your home folder could not be found");
        return 1;
    };
    run(args, &home, inside_a_chat(), &mut out, &mut err)
}

/// A chat token in the environment, or a `derm run` among the ancestors
/// (case 147's best effort, as `derm setup` and `derm agents` do).
fn inside_a_chat() -> Option<String> {
    for v in ["DERM_CHAT_TOKEN", "DERM_CHAT_TOKEN_FILE"] {
        if std::env::var_os(v).is_some_and(|x| !x.is_empty()) {
            return Some(format!("{v} is set, so this runs inside a derm run chat"));
        }
    }
    #[cfg(unix)]
    {
        let me = std::process::id();
        if let Some(p) = derm_core::peer::derm_run_ancestor(me) {
            return Some(format!("a derm run (pid {p}) started this"));
        }
    }
    None
}

fn run(
    args: &[String],
    home: &Path,
    in_chat: Option<String>,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    let verb = args.first().map(String::as_str);
    let rest = args.get(1..).unwrap_or(&[]);
    let file = path_in(home);
    match verb {
        Some("list") => list(&file, rest, out, err),
        Some(v @ ("add" | "remove")) => {
            if let Some(why) = in_chat {
                let _ = writeln!(
                    err,
                    "derm project {v}: refused inside a chat ({why}); an agent does not name or remove projects. Run it in your own terminal"
                );
                return 1;
            }
            if v == "add" {
                add(&file, home, rest, out, err)
            } else {
                remove(&file, rest, out, err)
            }
        }
        Some("-h" | "--help" | "help") => {
            let _ = writeln!(out, "{USAGE}");
            0
        }
        _ => {
            let _ = writeln!(err, "{USAGE}");
            2
        }
    }
}

fn list(
    file: &Path,
    rest: &[String],
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    let json = match rest {
        [] => false,
        [f] if f == "--json" => true,
        _ => {
            let _ = writeln!(err, "{USAGE}");
            return 2;
        }
    };
    let reg = match load(file) {
        Ok(r) => r,
        Err(why) => {
            let _ = writeln!(err, "derm project list: {why}");
            return 1;
        }
    };
    if json {
        let v: serde_json::Value =
            serde_json::from_str(&to_text(&reg)).unwrap_or(serde_json::Value::Null);
        let _ = writeln!(out, "{}", v["projects"]);
        return 0;
    }
    if reg.projects.is_empty() {
        let _ = writeln!(out, "no projects; name one with: derm project add <folder>");
    }
    for p in &reg.projects {
        let _ = writeln!(
            out,
            "{}\t{}\t{}",
            p.id,
            p.folder.display(),
            crate::watch::text::clean(&p.name, MAX_NAME)
        );
    }
    0
}

fn add(
    file: &Path,
    home: &Path,
    rest: &[String],
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    let mut folder: Option<&str> = None;
    let mut name: Option<String> = None;
    let mut nested = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--name" if i + 1 < rest.len() => {
                name = Some(rest[i + 1].clone());
                i += 1;
            }
            "--nested" => nested = true,
            a if !a.starts_with('-') && folder.is_none() => folder = Some(a),
            _ => {
                let _ = writeln!(err, "{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let Some(folder) = folder else {
        let _ = writeln!(err, "{USAGE}");
        return 2;
    };
    let fail = |err: &mut dyn std::io::Write, why: String| -> u8 {
        let _ = writeln!(err, "derm project add: {why}");
        1
    };
    let real = match std::fs::canonicalize(folder) {
        Ok(r) => r,
        Err(e) => return fail(err, format!("{folder}: {e}")),
    };
    if !real.is_dir() {
        return fail(err, format!("{} is not a folder", real.display()));
    }
    let real_text = real.to_string_lossy().into_owned();
    if let Err(why) = check_folder_text(&real_text) {
        return fail(err, why);
    }
    let real_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    if real == real_home {
        return fail(
            err,
            "your home folder itself is not a project: name a folder inside it".into(),
        );
    }
    if holds(&real_home.join(".derm"), &real) {
        return fail(err, "a folder inside ~/.derm is not a project".into());
    }
    let name = name.unwrap_or_else(|| {
        real.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| real_text.clone())
    });
    if let Err(why) = check_name(&name) {
        return fail(err, why);
    }
    let mut reg = match load(file) {
        Ok(r) => r,
        Err(why) => return fail(err, why),
    };
    if let Some(p) = reg.projects.iter().find(|p| p.folder == real) {
        return fail(
            err,
            format!("{} is already project {}", real.display(), p.id),
        );
    }
    if !nested {
        if let Some(p) = reg
            .projects
            .iter()
            .find(|p| holds(&p.folder, &real) || holds(&real, &p.folder))
        {
            return fail(
                err,
                format!(
                    "{} is inside or above project {} ({}); chats there would move to the deepest one. Add --nested if that is what you want",
                    real.display(),
                    p.id,
                    p.folder.display()
                ),
            );
        }
    }
    let added = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let id = ProjectId::of_real_path(&real_text);
    reg.projects.push(Project {
        id: id.clone(),
        folder: real.clone(),
        name,
        added,
    });
    if let Err(why) = save(file, &reg) {
        return fail(err, why);
    }
    let _ = writeln!(out, "{id}\t{}", real.display());
    0
}

fn remove(
    file: &Path,
    rest: &[String],
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    let [which] = rest else {
        let _ = writeln!(err, "{USAGE}");
        return 2;
    };
    let mut reg = match load(file) {
        Ok(r) => r,
        Err(why) => {
            let _ = writeln!(err, "derm project remove: {why}");
            return 1;
        }
    };
    let real = std::fs::canonicalize(which).ok();
    let Some(i) = reg.projects.iter().position(|p| {
        p.id.as_str() == which.as_str()
            || p.folder == Path::new(which)
            || real.as_deref() == Some(p.folder.as_path())
    }) else {
        let _ = writeln!(
            err,
            "derm project remove: {which} is no project (derm project list)"
        );
        return 1;
    };
    let p = reg.projects.remove(i);
    if let Err(why) = save(file, &reg) {
        let _ = writeln!(err, "derm project remove: {why}");
        return 1;
    }
    let _ = writeln!(
        out,
        "removed {} ({}); its folders under each agent account (/var/lib/derm/agents/<slug>/projects/{}) stay until derm agents cleans them",
        p.id,
        p.folder.display(),
        p.id
    );
    0
}

/// A new 0600 file beside the registry, renamed over it; `~/.derm` made 0700
/// when it is not there.
fn save(file: &Path, reg: &Registry) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let dir = file
            .parent()
            .ok_or_else(|| format!("{} has no folder", file.display()))?;
        if std::fs::symlink_metadata(dir).is_err() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        check_folders(file, derm_core::platform::effective_user())?;
        let tmp = dir.join(format!(
            ".{FILE}.{}.{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        let done = f
            .write_all(to_text(reg).as_bytes())
            .and_then(|()| f.sync_all())
            .and_then(|()| std::fs::rename(&tmp, file));
        if let Err(e) = done {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{}: {e}", file.display()));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (file, reg);
        Err("derm project: Linux and macOS only for now".into())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp(n: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "dpa-{n}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Tmp(std::fs::canonicalize(&p).unwrap())
    }
    fn mode(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }
    fn cli(home: &Path, args: &[&str], chat: Option<&str>) -> (u8, String, String) {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let code = run(&a, home, chat.map(str::to_string), &mut o, &mut e);
        (
            code,
            String::from_utf8(o).unwrap(),
            String::from_utf8(e).unwrap(),
        )
    }

    #[test]
    fn add_list_remove_round_trip_and_the_file_is_private() {
        let t = tmp("cli");
        let home = t.0.join("home");
        let work = home.join("work");
        std::fs::create_dir_all(work.join("sub")).unwrap();
        mode(&home, 0o700);
        let (c, o, e) = cli(&home, &["add", work.to_str().unwrap()], None);
        assert_eq!(c, 0, "{e}");
        let id = ProjectId::of_real_path(work.to_str().unwrap());
        assert!(o.starts_with(id.as_str()), "{o}");
        let file = path_in(&home);
        let m = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600);
        let dm = std::fs::metadata(home.join(".derm"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dm, 0o700);
        // Twice, a nested one, home, ~/.derm, `/`: refused.
        assert_eq!(cli(&home, &["add", work.to_str().unwrap()], None).0, 1);
        let (c, _, e) = cli(&home, &["add", work.join("sub").to_str().unwrap()], None);
        assert!(c == 1 && e.contains("--nested"), "{e}");
        assert_eq!(
            cli(
                &home,
                &[
                    "add",
                    work.join("sub").to_str().unwrap(),
                    "--nested",
                    "--name",
                    "s"
                ],
                None
            )
            .0,
            0
        );
        assert!(cli(&home, &["add", home.to_str().unwrap()], None)
            .2
            .contains("home folder"));
        assert!(
            cli(&home, &["add", home.join(".derm").to_str().unwrap()], None)
                .2
                .contains("~/.derm")
        );
        assert!(cli(&home, &["add", "/"], None)
            .2
            .contains("not an absolute real path"));
        // A label with a format character is refused.
        let other = home.join("other");
        std::fs::create_dir_all(&other).unwrap();
        assert!(cli(
            &home,
            &["add", other.to_str().unwrap(), "--name", "a\u{202e}b"],
            None
        )
        .2
        .contains("format character"));
        let (c, o, _) = cli(&home, &["list"], None);
        assert_eq!(c, 0);
        assert_eq!(o.lines().count(), 2, "{o}");
        let (_, j, _) = cli(&home, &["list", "--json"], None);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        let (c, o, _) = cli(&home, &["remove", id.as_str()], None);
        assert!(
            c == 0 && o.contains("stay until derm agents cleans them"),
            "{o}"
        );
        assert_eq!(load(&file).unwrap().projects.len(), 1);
        assert_eq!(cli(&home, &["remove", id.as_str()], None).0, 1);
    }

    #[test]
    fn add_and_remove_are_refused_inside_a_chat_and_list_is_not() {
        let t = tmp("chat");
        let w = t.0.join("w");
        std::fs::create_dir_all(&w).unwrap();
        let (c, _, e) = cli(
            &t.0,
            &["add", w.to_str().unwrap()],
            Some("DERM_CHAT_TOKEN is set"),
        );
        assert!(c == 1 && e.contains("inside a chat"), "{e}");
        assert!(!path_in(&t.0).exists());
        assert_eq!(cli(&t.0, &["remove", "x"], Some("x")).0, 1);
        assert_eq!(cli(&t.0, &["list"], Some("x")).0, 0);
    }

    #[test]
    fn the_registry_is_refused_through_a_link_or_an_open_folder_or_a_wrong_id() {
        let t = tmp("reg");
        let dir = t.0.join(".derm");
        std::fs::create_dir_all(&dir).unwrap();
        mode(&dir, 0o700);
        let file = dir.join(FILE);
        let good = r#"{"version":1,"projects":[{"id":"6853732bf2a99f2b","folder":"/home/u/work","name":"work","added":1}]}"#;
        std::fs::write(&file, good).unwrap();
        mode(&file, 0o600);
        assert_eq!(load(&file).unwrap().projects.len(), 1);
        // A link to it.
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(load(&link).is_err());
        // Its own folder open to others, sticky or not.
        for m in [0o777, 0o1777, 0o770] {
            mode(&dir, m);
            assert!(
                load(&file).unwrap_err().contains("group or others"),
                "{m:o}"
            );
        }
        mode(&dir, 0o700);
        // An id that is not its folder's, a folder with `..`, a duplicate,
        // a version 2, a missing file.
        for bad in [
            r#"{"version":1,"projects":[{"id":"0000000000000000","folder":"/home/u/work","name":"w","added":1}]}"#,
            r#"{"version":1,"projects":[{"id":"6853732bf2a99f2b","folder":"/home/u/../work","name":"w","added":1}]}"#,
            r#"{"version":2,"projects":[]}"#,
            r#"{"version":1,"projects":[{"id":"6853732bf2a99f2b","folder":"/home/u/work","name":"w","added":1,"x":1}]}"#,
        ] {
            std::fs::write(&file, bad).unwrap();
            assert!(load(&file).is_err(), "{bad}");
        }
        let two = format!(
            r#"{{"version":1,"projects":[{e},{e}]}}"#,
            e = r#"{"id":"6853732bf2a99f2b","folder":"/home/u/work","name":"w","added":1}"#
        );
        std::fs::write(&file, two).unwrap();
        assert!(load(&file).unwrap_err().contains("twice"));
        std::fs::remove_file(&file).unwrap();
        assert_eq!(load(&file).unwrap(), Registry::default());
    }

    #[test]
    fn whole_parts_only_and_the_deepest_wins() {
        let reg = Registry {
            projects: vec![
                Project {
                    id: ProjectId::of_real_path("/nonexistent-dpa/a"),
                    folder: "/nonexistent-dpa/a".into(),
                    name: "a".into(),
                    added: 0,
                },
                Project {
                    id: ProjectId::of_real_path("/nonexistent-dpa/a/b"),
                    folder: "/nonexistent-dpa/a/b".into(),
                    name: "b".into(),
                    added: 0,
                },
            ],
        };
        let name = |p: &str| find(&reg, Path::new(p)).project().map(|x| x.name.clone());
        assert_eq!(name("/nonexistent-dpa/a/b/c").as_deref(), Some("b"));
        assert_eq!(name("/nonexistent-dpa/a/bc").as_deref(), Some("a"));
        assert_eq!(name("/nonexistent-dpa/a").as_deref(), Some("a"));
        assert_eq!(name("/nonexistent-dpa/ab"), None);
    }

    /// The base's red test (`pa_the_nearest_named_folder_and_a_relative_
    /// worktree_find_their_project`) with the back-link git 2.48 writes:
    /// `write_worktree_linking_files` writes `relative_path(<worktree>,
    /// <gitdir>)` + `/.git` (git `v2.48.0` `worktree.c:1040-1042`), and the
    /// reader strips `/.git` and joins it to `worktrees/<id>/`
    /// (`worktree.c:107-117`). From `work/repo/.git/worktrees/wt` to `wt`
    /// that is five `..`; the base test writes four, which names
    /// `work/wt/.git` (request PA-1).
    #[test]
    fn a_relative_worktree_as_git_2_48_writes_it_joins_its_project() {
        let t = tmp("rwt");
        for d in ["work/repo/.git/worktrees/wt", "wt", "evil"] {
            std::fs::create_dir_all(t.0.join(d)).unwrap();
        }
        std::fs::write(
            t.0.join("wt/.git"),
            "gitdir: ../work/repo/.git/worktrees/wt\n",
        )
        .unwrap();
        let gd = t.0.join("work/repo/.git/worktrees/wt");
        std::fs::write(gd.join("gitdir"), "../../../../../wt/.git\n").unwrap();
        std::fs::write(gd.join("commondir"), "../..\n").unwrap();
        std::fs::write(
            t.0.join("evil/.git"),
            "gitdir: ../work/repo/.git/worktrees/wt\n",
        )
        .unwrap();
        let work = t.0.join("work");
        let reg = Registry {
            projects: vec![Project {
                id: ProjectId::of_real_path(work.to_str().unwrap()),
                folder: work.clone(),
                name: "work".into(),
                added: 0,
            }],
        };
        assert_eq!(find(&reg, &t.0.join("wt")).how(), "worktree");
        assert_eq!(find(&reg, &t.0.join("evil")).how(), "none");
        // The base test's four `..` name `work/wt/.git`: not this worktree.
        std::fs::write(gd.join("gitdir"), "../../../../wt/.git\n").unwrap();
        assert_eq!(find(&reg, &t.0.join("wt")).how(), "none");
    }

    #[test]
    fn an_absolute_worktree_link_as_git_2_43_writes_it_joins_its_project() {
        // git 2.43.0 run here: `.git` holds `gitdir: <abs>/.git/worktrees/<n>`,
        // the back-link is absolute, `commondir` is `../..`.
        let t = tmp("wt");
        let repo = t.0.join("repo");
        let wt = t.0.join("wt");
        let gd = repo.join(".git/worktrees/wt");
        std::fs::create_dir_all(&gd).unwrap();
        std::fs::create_dir_all(wt.join("deep")).unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", gd.display())).unwrap();
        std::fs::write(
            gd.join("gitdir"),
            format!("{}\n", wt.join(".git").display()),
        )
        .unwrap();
        std::fs::write(gd.join("commondir"), "../..\n").unwrap();
        let reg = Registry {
            projects: vec![Project {
                id: ProjectId::of_real_path(repo.to_str().unwrap()),
                folder: repo.clone(),
                name: "repo".into(),
                added: 0,
            }],
        };
        assert_eq!(find(&reg, &wt.join("deep")).how(), "worktree");
        // A `.git` that is a link is not git's worktree file.
        std::fs::remove_file(wt.join(".git")).unwrap();
        std::os::unix::fs::symlink(repo.join("x"), wt.join(".git")).unwrap();
        assert_eq!(find(&reg, &wt).how(), "none");
    }
}
