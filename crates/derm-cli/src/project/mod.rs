//! `derm project add|list|remove` and the rule that puts a chat in a
//! project (lane PA's; `contracts/projects.md` section 1; plan step P1,
//! Tony's call 16).
//!
//! The base (20 Nov 2026) declares the types and the functions other code
//! calls: `derm run` (integration's `run/mod.rs`) asks `find` for the chat's
//! project before it mints the token, and lane PA's own `run/user/` reads
//! the id for the folder names. Until the lane builds them, `load` refuses,
//! `find` finds nothing and `main` says the verbs are not built.

use std::path::{Path, PathBuf};

pub use derm_core::project::ProjectId;

/// The registry's file name inside `~/.derm` (0600 in a 0700 folder).
pub const FILE: &str = "projects.json";

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

/// Reads the registry at `path`: the file and every folder above it the
/// person's, not links, not group or world writable, parsed whole with
/// unknown fields refused (section 1.1). A missing file is an empty
/// registry. Not built (lane PA).
pub fn load(_path: &Path) -> Result<Registry, String> {
    Err("derm project: not built (lane PA)".into())
}

/// The project a chat started in `cwd` belongs to (section 1.4 and 1.5).
/// `cwd` is taken by its real path. Not built (lane PA): finds nothing.
pub fn find(_registry: &Registry, _cwd: &Path) -> Found {
    Found::None
}

/// `derm project <add|list|remove> ...`. Not built (lane PA).
pub fn main(_args: &[String]) -> u8 {
    eprintln!("derm project: not built yet (plans/parallel_build_accounts.md section 8, lane PA)");
    2
}
