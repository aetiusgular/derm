//! One sign-in per subscription per device (lane PB's; `contracts/
//! projects.md` section 2.3; plan step P3, Tony's call 17).
//!
//! Each account keeps one sign-in store per harness in
//! `<account home>/signin/<harness>/`, outside every project home. A project
//! home reaches it this way, as note CD sections 2.1 to 2.3 read each
//! harness at the version in use:
//!
//! - Codex 0.167.2: `<home>/.codex/auth.json` and `<home>/.codex/auth.lock`
//!   are links to the store's (Codex renames onto a link's target and takes
//!   its cross-process lock on `<home>/auth.lock`; C6).
//! - Pi 1.6.0 (nothing below 1.5.1): `<home>/.pi/agent/auth.json` is a link
//!   to the store's (Pi locks the resolved file from 1.5.1, #11655; C1).
//! - Claude Code 2.1.322: no link (a renewal renames over it, by read);
//!   `CLAUDE_SECURESTORAGE_CONFIG_DIR` names the store, behind a switch that
//!   stays off until P-B1 passes on the box.
//!
//! The base declares the function lane PA's helper calls when it makes a
//! project home. Until lane PB builds it, nothing is linked, which is what
//! the red tests `pb_*` show failing.

use std::path::{Path, PathBuf};

/// What a project home needs from the account's sign-in store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Linked {
    /// The links made, as paths in the project home.
    pub links: Vec<PathBuf>,
    /// Variables the harness gets (Claude Code's store folder, when its
    /// switch is on).
    pub env: Vec<(String, String)>,
}

/// Makes `project_home`'s links into `<account_home>/signin/<harness>/`
/// for `harness` (`claude-code`, `codex`, `pi`), as the account, before the
/// chat's domain. Never reads, copies or writes a sign-in file's content
/// (note CB 4.1); never follows a link it did not make. Not built (lane PB).
pub fn link_project_home(
    _account_home: &Path,
    _project_home: &Path,
    _harness: &str,
) -> Result<Linked, String> {
    Err("sign-in links: not built (lane PB)".into())
}
