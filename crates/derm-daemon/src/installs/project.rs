//! `project.control` (lane PC's; `contracts/events.md` section 7.2; plan
//! step P4): every write, by a process the join places in an account's chat,
//! to a path inside that chat's project home that a harness or a shell runs
//! later. Not only under an install.
//!
//! The paths are `control::control_path`'s (which already matches the whole
//! of `.claude/`, `.codex/` and `.pi/`) plus `ADDED` (note CD section 5, C4).
//!
//! The base declares the function the join's flagger calls. Until lane PC
//! builds it, nothing is flagged, which is what the red test
//! `pc_a_write_to_a_project_homes_run_later_files_is_flagged` shows.

/// Run-later paths in a project home that `control_path` does not match:
/// Codex's user skills (`$HOME/.agents/skills`), Codex's plugin marketplace
/// under the cache folder, and the account's own programs folder.
pub const ADDED: &[&str] = &[".agents/skills/", ".cache/codex-runtimes/", ".local/bin/"];

/// The marker `path` names when it lies inside `project_home` and a
/// harness or a shell runs it later, else `None`. Both are real paths.
/// Not built (lane PC): `None`.
pub fn project_control(_path: &str, _project_home: &str) -> Option<String> {
    None
}
