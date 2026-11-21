//! A chat of an agent account inside its project (lane PA's;
//! `contracts/projects.md` section 2; plan step P2).
//!
//! The base declares the two functions the chat route calls once a chat has
//! a project: the folders and variables it gets, and its Landlock spec.
//! Until lane PA builds them they give today's route (the whole account home
//! written, no project variables), which is what the red tests
//! `pa_two_projects_in_one_account_do_not_reach_each_other` and
//! `pa_a_project_chat_gets_its_own_home_tmp_and_runtime_folder` show.

use super::landlock::{chat_spec, ChatPaths, Spec};
use crate::project::ProjectId;

/// What the chat route knows when it builds a project chat.
pub(crate) struct ProjectChat<'a> {
    /// `/var/lib/derm/agents/<slug>`.
    pub account_home: &'a str,
    pub project: &'a ProjectId,
    /// The chat's own folders (its project folder, any `--folder`).
    pub folders: &'a [String],
    /// The harness's id (`claude-code`, `codex`, `pi`, ...), for its sign-in
    /// store folder (section 2.3).
    pub harness: &'a str,
    /// The daemon bridge's folder, when the chat has one.
    pub bridge: Option<&'a str>,
    pub require_scopes: bool,
}

/// The variables the chat's harness gets on `/usr/bin/env`'s argv after the
/// helper (`HOME`, `TMPDIR`, `XDG_RUNTIME_DIR`, `PATH`, and the harness's
/// own from section 2.3), in order. Not built (lane PA): none.
pub(crate) fn project_env(_c: &ProjectChat<'_>) -> Vec<(String, String)> {
    Vec::new()
}

/// The chat's Landlock spec (section 2.2, the "Domain right" column). Not
/// built (lane PA): today's spec, which writes the whole account home.
pub(crate) fn project_chat_spec(c: &ProjectChat<'_>) -> Spec {
    let path = format!(
        "{}/.local/bin:/usr/local/bin:/usr/bin:/bin",
        c.account_home.trim_end_matches('/')
    );
    chat_spec(&ChatPaths {
        folders: c.folders,
        account_home: c.account_home,
        bridge: c.bridge,
        path: &path,
        require_scopes: c.require_scopes,
    })
}
