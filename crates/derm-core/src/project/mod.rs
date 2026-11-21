//! The project layer's shared types (step P's base, 20 Nov 2026;
//! `contracts/projects.md`, `contracts/project-tools.md`,
//! `contracts/events.md` section 7). The project is the trust unit
//! (`plans/toolkit_agent_accounts_plan.md` revision 5, section 3.4).
//!
//! This file is the contract's reference and no lane's
//! (`scripts/lane-ownership.json`); `screen.rs` is lane PD's. Both
//! `derm run` (derm-cli) and the daemon read these, so they live in the
//! core, which every crate already depends on.

use sha2::{Digest, Sha256};

pub mod screen;

/// Hex characters in a project id. Sixteen keeps Claude Code's inbox socket
/// path under its 103-byte limit inside a project's runtime folder (88
/// bytes with a 15-character slug; note CD section 4, V for the limit:
/// Claude Code 2.1.322 `var Q=103`).
pub const ID_LEN: usize = 16;

/// A project's id: the first 16 lowercase hex characters of the SHA-256 of
/// the project folder's real path, as bytes (contracts/projects.md
/// section 1.3). `""` is never an id: an event outside every project
/// carries `""` in its `project` field instead.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProjectId(String);

impl ProjectId {
    /// The id of a folder whose real path is `real_path`. The caller passes
    /// the real path (every link resolved); this function does not touch the
    /// disk.
    pub fn of_real_path(real_path: &str) -> ProjectId {
        let digest = Sha256::digest(real_path.as_bytes());
        let mut hex = String::with_capacity(ID_LEN);
        for b in digest.iter().take(ID_LEN / 2) {
            hex.push_str(&format!("{b:02x}"));
        }
        ProjectId(hex)
    }

    /// An id as a record or an op line carries it: exactly 16 of
    /// `[0-9a-f]`. Anything else is `None`.
    pub fn parse(text: &str) -> Option<ProjectId> {
        valid_id(text).then(|| ProjectId(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 16 lowercase hex characters.
pub fn valid_id(text: &str) -> bool {
    text.len() == ID_LEN && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The value of an event's `project` field or of `token.mint`'s `project`:
/// an id, or `""` for a chat outside accounts (contracts/events.md 7.1).
pub fn valid_field(text: &str) -> bool {
    text.is_empty() || valid_id(text)
}

/// The record kinds step P adds, all source `derm`, written only by the
/// daemon (contracts/events.md section 7.2).
pub mod kinds {
    /// A write to a run-later path inside a chat's project home (lane PC).
    pub const CONTROL: &str = "project.control";
    /// An open of a sign-in store file by a process that is not the chat's
    /// harness (lane PC).
    pub const SIGNIN_READ: &str = "signin.read";
    /// A `connect` by an agent account's process to a Unix socket (lane PC).
    pub const NET_UNIX: &str = "net.unix";
    /// A `derm_message` delivered or asked (lane PE).
    pub const MESSAGE: &str = "project.message";
    /// A `derm_terminal_read` served (lane PE).
    pub const READ: &str = "project.read";
    /// A session grant across projects (lane PE).
    pub const GRANT: &str = "project.grant";
    pub const ALL: &[&str] = &[CONTROL, SIGNIN_READ, NET_UNIX, MESSAGE, READ, GRANT];
}

/// Under each account home (contracts/projects.md section 2).
pub mod layout {
    /// `<account home>/signin`: the account's sign-in store, outside every
    /// project home. Made by the installer (lane PF).
    pub const SIGNIN: &str = "signin";
    /// `<account home>/projects`: the parent of every project's folders.
    /// Made by the installer (lane PF).
    pub const PROJECTS: &str = "projects";
    /// `<account home>/projects/<id>/<part>`: made by the helper, as the
    /// account, before the chat's domain (lane PA).
    pub const HOME: &str = "home";
    pub const TMP: &str = "tmp";
    pub const RUN: &str = "run";
    /// The per-harness store folder names under `signin/`.
    pub const SIGNIN_HARNESSES: &[&str] = &["claude-code", "codex", "pi"];

    /// `<account home>/projects/<id>`.
    pub fn project_dir(account_home: &str, id: &super::ProjectId) -> String {
        format!(
            "{}/{PROJECTS}/{}",
            account_home.trim_end_matches('/'),
            id.as_str()
        )
    }

    /// `<account home>/signin/<harness>`.
    pub fn signin_dir(account_home: &str, harness: &str) -> String {
        format!("{}/{SIGNIN}/{harness}", account_home.trim_end_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_sixteen_hex_of_the_real_paths_sha256() {
        // `printf %s /home/u/work | sha256sum | cut -c1-16`, run.
        let id = ProjectId::of_real_path("/home/u/work");
        assert_eq!(id.as_str(), "6853732bf2a99f2b");
        assert!(valid_id(id.as_str()));
        assert_eq!(ProjectId::parse(id.as_str()), Some(id.clone()));
        assert_ne!(id, ProjectId::of_real_path("/home/u/work/"));
    }

    #[test]
    fn only_sixteen_lowercase_hex_parse() {
        assert!(ProjectId::parse("0123456789abcdef").is_some());
        for bad in [
            "",
            "0123456789ABCDEF",
            "0123456789abcde",
            "0123456789abcdef0",
            "../../etc/passwd",
        ] {
            assert!(ProjectId::parse(bad).is_none(), "{bad}");
        }
        assert!(valid_field(""));
        assert!(!valid_field("x"));
    }

    #[test]
    fn the_runtime_folder_keeps_claude_codes_socket_under_its_limit() {
        // contracts/projects.md section 2.4: the longest slug (15), the id,
        // `/run/cc-socks/`, a 7-digit pid and `.sock` fit in 103 bytes.
        let home = format!("/var/lib/derm/agents/{}", "a".repeat(15));
        let dir = layout::project_dir(&home, &ProjectId::of_real_path("/x"));
        let sock = format!("{dir}/{}/cc-socks/{}.sock", layout::RUN, "9".repeat(7));
        assert_eq!(sock.len(), 88, "{sock}");
        assert!(sock.len() <= 103);
    }
}
