//! What `derm agents login` and `status` know of each harness's own sign-in,
//! read at the version in use (plans/parallel/acct_L4.md, Research):
//!
//! - **Claude Code 2.1.322.** `claude auth login` is its own sign-in
//!   (`claude auth --help`: "login  Sign in to your Anthropic account";
//!   `--claudeai`, a Claude subscription, is the default). With no browser it
//!   prints the authorize URL and waits for the pasted code (run in the
//!   cloud). It then posts the code to `https://platform.claude.com/v1/oauth/token`
//!   (its bundle; a CONNECT to `platform.claude.com:443` seen through a proxy,
//!   run) and asks `https://api.anthropic.com/api/oauth/claude_cli/roles` (its
//!   bundle, not run). On Linux it keeps the sign-in in
//!   `<config dir>/.credentials.json`, the config dir being
//!   `CLAUDE_SECURESTORAGE_CONFIG_DIR`, else `CLAUDE_CONFIG_DIR`, else
//!   `~/.claude` (its bundle: `storagePath:Oe(e,".credentials.json")`; rules
//!   case 186: on Linux the file is its store). `~/.claude.json` and
//!   `~/.claude/` appear before any sign-in (`claude auth status` makes
//!   them), so only `.credentials.json` says signed in.
//! - **Codex 0.167.2.** `codex login --device-auth` asks
//!   `https://auth.openai.com/api/accounts/deviceauth/usercode`, polls
//!   `.../deviceauth/token` and exchanges the code at the same issuer
//!   (`codex-rs/login/src/device_code_auth.rs:165-227`, `server.rs:78`
//!   `DEFAULT_ISSUER`; a CONNECT to `auth.openai.com:443` seen, run), then
//!   writes `$CODEX_HOME/auth.json` (default `~/.codex`) in its default file
//!   store (rules cases 186, 190). `codex login status` makes `auth.lock` and
//!   `auth.json.lock` with no sign-in (run), so only `auth.json` counts.
//!
//! Pi is not here: its `/login` signs in to several providers, Claude
//! subscriptions among them, which Anthropic's terms keep for its own apps
//! (note CB 4.1); Tony's call.

/// One harness's sign-in.
pub struct SignIn {
    /// derm's id for the harness (`run/harness.rs`).
    pub id: &'static str,
    /// The program and its sign-in words, run as the account.
    pub argv: &'static [&'static str],
    /// The file the sign-in leaves, from the account's home, for a harness
    /// whose sign-in is not in the account's store (`signin.rs`; Codex's and,
    /// with its switch on, Claude Code's are, at `signin/<id>/`). Its
    /// presence is all derm ever learns of it.
    pub file: &'static str,
    /// What the sign-in itself dials, on 443: all the login's tunnel admits.
    pub hosts: &'static [&'static str],
    /// The vendor, for what derm says.
    pub vendor: &'static str,
}

pub const ALL: &[SignIn] = &[
    SignIn {
        id: "claude-code",
        argv: &["claude", "auth", "login"],
        file: ".claude/.credentials.json",
        hosts: &["platform.claude.com", "api.anthropic.com"],
        vendor: "Anthropic",
    },
    SignIn {
        id: "codex",
        argv: &["codex", "login", "--device-auth"],
        file: ".codex/auth.json",
        hosts: &["auth.openai.com"],
        vendor: "OpenAI",
    },
];

pub fn find(id: &str) -> Option<&'static SignIn> {
    ALL.iter().find(|s| s.id == id)
}

/// What `status` says beside a Claude Code sign-in (note CB 4.1, read whole
/// at https://code.claude.com/docs/en/legal-and-compliance).
pub const INDIVIDUAL_USE: &str = "Anthropic's terms: \"Advertised usage limits for Pro and Max plans assume ordinary, individual usage of Claude Code and the Agent SDK\"; many chats on one subscription may not be that (https://code.claude.com/docs/en/legal-and-compliance)";
