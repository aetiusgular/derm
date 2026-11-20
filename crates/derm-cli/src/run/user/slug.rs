//! The agent account's name, the same on every system
//! (`plans/parallel_build_accounts.md` section 2, as integration narrowed it
//! from acct_W section 7 and Tony's call of 20 Nov, acct_W 12.1). Compiled
//! everywhere: `derm agents add` checks a slug before it knows the system's
//! accounts, and `run/user/accounts.rs` (Linux) reads root's file with it.

/// Where root keeps the accounts (section 2).
pub const AGENTS: &str = "/etc/derm/agents.json";
/// The group every agent account is in, and the only group the outbound
/// block (`skgid`) matches.
pub const GROUP: &str = "derm-agents";

/// An account's name is `PREFIX` and its slug. Read by the Linux reader
/// only until macOS and Windows accounts are built (plan steps B and C).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const PREFIX: &str = "derm-";

/// The longest slug: Windows takes a local account name of at most 20
/// characters (`USER_INFO_1`, https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1),
/// and `derm-` is 5. useradd's own limit is 32 (lane L2, run); macOS's was
/// not a limit in session M's runs.
pub const SLUG_MAX: usize = 15;

/// `[a-z0-9-]{1,15}`, and not one of the reserved slugs: `agent` would name
/// wave 5's agents' user `derm-agent`, `agents` the accounts' group
/// `derm-agents`, and `agent-<x>` wave 5's sudoers file for a person `x`
/// (`/etc/sudoers.d/derm-agent-<x>`, `packaging/linux/agent-user/install.sh`).
pub fn plain_slug(s: &str) -> bool {
    (1..=SLUG_MAX).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !matches!(s, "agent" | "agents")
        && !s.starts_with("agent-")
}
