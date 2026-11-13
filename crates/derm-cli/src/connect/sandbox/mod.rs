//! The Standard tier's writers (wave 6, lane 6A; `contracts/sandbox.md`):
//! derm's paths as each agent's own sandbox settings, for `derm run` to
//! deliver (`run/standard/`) and for `derm connect` and `derm doctor` to
//! print or check (integration wires those; `tk_lane_6A.md`, requests).
//!
//! Each row of `presets/wave6/sandbox.json` names how an agent takes its
//! sandbox (note AZ section 5): Claude Code 2.1.322 by its own `--settings`
//! file, since a project file beats the user's settings (A2) and a type
//! error drops a whole file, hooks included (A10); Codex 0.167.2 by `-c`
//! pairs, since a trusted project outranks the user's profile (A4). Cursor's
//! is advisory: a repository's `.cursor/sandbox.json` widens the user's
//! (A6, read in its bundle, not run).
//!
//! What the agent's sandbox is given is the same for both writers: reads of
//! the user's secrets, the other agents' and its own sign-in files, derm's
//! folders (`~/.derm`, the daemon's runtime folder, its data folder) denied;
//! writes in the chat's folders only (each agent's own default write root is
//! the working folder); no network, so a host the agent wants is the
//! person's call (Claude Code 2.1.322 answers a host off its list with 403,
//! "deny network-outbound ... (user denied)", run in the cloud on 12 Nov;
//! Codex's `:workspace` has network off, `protocol/src/models.rs:414-417`).
//! The list mirrors what srt hides (`run/plan.rs`, the srt settings).

use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// What the writers need to know about one chat.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// The user's home, absolute.
    pub home: String,
    /// The chat's folders, the working folder first.
    pub folders: Vec<String>,
    /// The daemon's runtime folder, when known.
    pub daemon_dir: Option<String>,
    /// The daemon's data folder (its activity log, content files).
    pub data_dir: Option<String>,
}

/// Under the home, by name: what srt hides from every chat (`run/plan.rs`,
/// srt's `denyRead`), and the sign-in files of every agent derm starts
/// (`run/harness.rs`, `credential`): the agent's own process reads its file
/// outside its sandbox (A7: only commands run inside it), so its commands
/// never need to.
const HIDDEN_UNDER_HOME: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".config/gh",
    ".kube",
    ".password-store",
    ".local/share/keyrings",
    ".docker/config.json",
    ".netrc",
    ".git-credentials",
    ".derm",
    ".tk",
];

/// The absolute paths an agent's sandbox denies to its commands' reads.
pub fn denied_reads(c: &Context) -> Vec<String> {
    let home = c.home.trim_end_matches('/');
    let under = |r: &str| format!("{home}/{r}");
    let mut out: Vec<String> = HIDDEN_UNDER_HOME.iter().map(|r| under(r)).collect();
    for h in crate::run::harness::HARNESSES {
        if let Some(cred) = h.credential {
            out.push(under(cred));
        }
    }
    if let Some(d) = &c.daemon_dir {
        out.push(d.clone());
    }
    if let Some(d) = &c.data_dir {
        out.push(d.clone());
    }
    out.retain(|p| p.starts_with('/'));
    out.sort();
    out.dedup();
    out
}

/// The chat's folders past the working folder, which each agent's sandbox
/// already lets its commands write.
fn extra_write_roots(c: &Context) -> Vec<String> {
    let mut out: Vec<String> = c
        .folders
        .iter()
        .skip(1)
        .filter(|f| f.starts_with('/'))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Claude Code 2.1.322's block (contract section 2; keys V at 2.1.322, note
/// AZ A1). Never `excludedCommands` (AZ-7): it takes a matching command out
/// of the sandbox, inside a `--settings` block too (run in the cloud, 12
/// Nov: `"touch *"` there let `touch <outside>` write the host).
pub fn claude_block(c: &Context) -> Value {
    json!({
        "sandbox": {
            "enabled": true,
            "failIfUnavailable": true,
            "allowUnsandboxedCommands": false,
            "autoAllowBashIfSandboxed": true,
            "filesystem": {
                "denyRead": denied_reads(c),
                "allowWrite": extra_write_roots(c),
            },
            "network": {
                "allowedDomains": [],
            },
        },
        "permissions": {
            "blockReadsOutsideWorkingDirectories": true,
        },
    })
}

/// The profile's name. A config layer that also defines it would be merged
/// into derm's (Codex 0.167.2 merges tables, run: a user's or a trusted
/// project's `[permissions.derm.filesystem]` entry widened the profile), so
/// `run/standard/` refuses a chat whose layers name it.
pub const CODEX_PROFILE: &str = "derm";

/// A TOML basic string.
fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Codex 0.167.2's profile as one inline TOML table, the value of a `-c
/// permissions.derm=...` pair (contract section 3). Codex splits a `-c`
/// key at every `.` (`config/src/overrides.rs:18-22`), so paths go in as
/// the table's quoted keys, never in the `-c` key; the value is parsed as
/// TOML (`utils/cli/src/config_override.rs:95-101`). Run in the cloud on
/// 12 Nov: a deny held, a write outside the folder was refused, one inside
/// went through, and a deny of a path that does not exist started fine.
pub fn codex_profile(c: &Context) -> String {
    let mut entries: Vec<String> = denied_reads(c)
        .iter()
        .map(|p| format!("{}=\"deny\"", toml_string(p)))
        .collect();
    entries.extend(
        extra_write_roots(c)
            .iter()
            .map(|p| format!("{}=\"write\"", toml_string(p))),
    );
    format!(
        "{{description=\"derm Standard tier\",extends=\":workspace\",filesystem={{{}}}}}",
        entries.join(",")
    )
}

/// The `-c` pairs `derm run` gives Codex, in order.
pub fn codex_pairs(c: &Context) -> Vec<String> {
    vec![
        "-c".into(),
        format!("default_permissions=\"{CODEX_PROFILE}\""),
        "-c".into(),
        format!("permissions.{CODEX_PROFILE}={}", codex_profile(c)),
    ]
}

/// The pin (contract section 6, case 213): the sha256 of what derm hands
/// the agent, as it hands it.
pub fn pin(text: &str) -> String {
    let d = Sha256::digest(text.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// The settings for `agent` as `derm connect` would print them, or `None`
/// where derm writes no Standard tier for it.
pub(crate) fn fragment(agent: &str, c: &Context) -> Option<Value> {
    match agent {
        "claude-code" => Some(claude_block(c)),
        "codex" => Some(json!({
            "default_permissions": CODEX_PROFILE,
            "permissions": {CODEX_PROFILE: codex_profile(c)},
        })),
        _ => None,
    }
}

/// Keys of Cursor's `sandbox.json` a repository can widen the user's file
/// with: unions (`additionalReadonlyPaths`, `additionalReadwritePaths`, the
/// network `allow` list) and last-layer values (`readBoundary`,
/// `additionalReadPaths`). Read in Cursor CLI 2026.11.11-b912975's bundle,
/// `connect-pool-worker.js` `Fe`/`Me`/`Oe`/`De`/`Te`/`Be` (note AZ 8.3);
/// not run.
const CURSOR_WIDENING_KEYS: &[&str] = &[
    "additionalReadonlyPaths",
    "additionalReadwritePaths",
    "additionalReadPaths",
    "readBoundary",
];

/// For `derm doctor` and `derm run`: the keys a repository's
/// `.cursor/sandbox.json` sets that widen the user's (contract section 4).
/// `Err` when the file is there and cannot be read whole.
pub fn cursor_repo_widening(workspace: &Path) -> Result<Vec<String>, String> {
    let file = workspace.join(".cursor/sandbox.json");
    let text = match std::fs::symlink_metadata(&file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", file.display())),
        Ok(m) if !m.is_file() => return Err(format!("{} is not a regular file", file.display())),
        Ok(m) if m.len() > 1 << 20 => return Err(format!("{} is over 1 MiB", file.display())),
        Ok(_) => std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?,
    };
    let v: Value =
        serde_json::from_str(&text).map_err(|_| format!("{} is not JSON", file.display()))?;
    let mut out = Vec::new();
    for k in CURSOR_WIDENING_KEYS {
        if v.get(*k).is_some_and(|x| !x.is_null()) {
            out.push((*k).to_string());
        }
    }
    let allow = v
        .pointer("/network/allow")
        .or_else(|| v.pointer("/networkPolicy/allow"));
    if allow.is_some_and(|a| a.as_array().is_some_and(|a| !a.is_empty())) {
        out.push("network.allow".into());
    }
    if v.get("type").and_then(Value::as_str) == Some("insecure_none") {
        // Ignored by Cursor for a repository file (note AZ 8.3), but named.
        out.push("type insecure_none (ignored by Cursor in a repository file)".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            home: "/h/u".into(),
            folders: vec!["/w/p".into(), "/w/extra dir".into()],
            daemon_dir: Some("/run/user/1/derm".into()),
            data_dir: Some("/h/u/.local/share/derm".into()),
        }
    }

    #[test]
    fn the_block_holds_derms_keys_and_never_excluded_commands() {
        let b = claude_block(&ctx());
        let s = &b["sandbox"];
        assert_eq!(s["enabled"], true);
        assert_eq!(s["failIfUnavailable"], true);
        assert_eq!(s["allowUnsandboxedCommands"], false);
        assert_eq!(
            b["permissions"]["blockReadsOutsideWorkingDirectories"],
            true
        );
        assert!(s.get("excludedCommands").is_none());
        assert_eq!(s["network"]["allowedDomains"], json!([]));
        let deny: Vec<&str> = s["filesystem"]["denyRead"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for want in [
            "/h/u/.ssh",
            "/h/u/.derm",
            "/h/u/.claude/.credentials.json",
            "/h/u/.codex/auth.json",
            "/run/user/1/derm",
            "/h/u/.local/share/derm",
        ] {
            assert!(deny.contains(&want), "{want}: {deny:?}");
        }
        // The working folder is the agent's own root; only the extra one.
        assert_eq!(s["filesystem"]["allowWrite"], json!(["/w/extra dir"]));
    }

    #[test]
    fn the_codex_profile_is_one_inline_table_codex_parses() {
        let p = codex_profile(&ctx());
        // Parsed the way Codex parses a `-c` value (`_x_ = <value>`).
        let t: toml_edit::DocumentMut = format!("_x_ = {p}").parse().unwrap();
        let tbl = t["_x_"].as_inline_table().unwrap();
        assert_eq!(tbl.get("extends").unwrap().as_str(), Some(":workspace"));
        let fs = tbl.get("filesystem").unwrap().as_inline_table().unwrap();
        assert_eq!(fs.get("/h/u/.ssh").unwrap().as_str(), Some("deny"));
        assert_eq!(fs.get("/w/extra dir").unwrap().as_str(), Some("write"));
        let pairs = codex_pairs(&ctx());
        assert_eq!(pairs[1], "default_permissions=\"derm\"");
        assert!(pairs[3].starts_with("permissions.derm={"));
    }

    #[test]
    fn a_path_with_quotes_or_controls_stays_one_toml_key() {
        let c = Context {
            home: "/h/a\"b\\c\nd".into(),
            ..Context::default()
        };
        let p = codex_profile(&c);
        let t: toml_edit::DocumentMut = format!("_x_ = {p}").parse().unwrap();
        let fs = t["_x_"]["filesystem"].as_inline_table().unwrap();
        assert!(fs.get("/h/a\"b\\c\nd/.ssh").is_some(), "{p}");
    }

    #[test]
    fn the_pin_is_the_sha256_of_the_text() {
        assert_eq!(
            pin("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fragments_exist_for_the_agents_derm_writes_for() {
        assert!(fragment("claude-code", &ctx()).is_some());
        assert!(fragment("codex", &ctx()).is_some());
        for agent in ["cursor", "gemini", "pi"] {
            assert_eq!(fragment(agent, &ctx()), None);
        }
    }

    #[test]
    fn a_repository_cursor_file_that_widens_is_named() {
        let d = std::env::temp_dir().join(format!("dsb-cursor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".cursor")).unwrap();
        assert_eq!(
            cursor_repo_widening(&d.join("none")).unwrap(),
            Vec::<String>::new()
        );
        std::fs::write(
            d.join(".cursor/sandbox.json"),
            r#"{"type":"workspace_readwrite","additionalReadwritePaths":["/"],"network":{"allow":["*"]}}"#,
        )
        .unwrap();
        assert_eq!(
            cursor_repo_widening(&d).unwrap(),
            vec![
                "additionalReadwritePaths".to_string(),
                "network.allow".to_string()
            ]
        );
        std::fs::write(d.join(".cursor/sandbox.json"), "{").unwrap();
        assert!(cursor_repo_widening(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
