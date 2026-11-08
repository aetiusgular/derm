//! What `derm run` needs to know per harness: the command it starts, how sbx
//! runs it, and the folders it keeps its own state in. Ids and commands are
//! the preset table (`crates/derm-cli/src/connect/presets/`, `id`, `cli`).
//!
//! sbx: each harness's form is the preset table's `kit` field
//! (`connect/presets/wave5/kit.json`, lane T's request T-5): sbx's built-in
//! agents (claude, codex, copilot, cursor, devin, docker-agent, droid,
//! gemini, kiro, opencode, shell; https://docs.docker.com/reference/cli/sbx/run/)
//! and sbx-kits-contrib's kits (Pi's `docker.io/sbx/pi-kit:latest`, Hermes,
//! OpenClaw, Amp, Crush, Grok), with the words each kit adds that turn the
//! agent's approvals off. A harness with no kit there has no sbx form, and
//! `--boundary sbx` refuses it rather than guess.
//!
//! State folders are where a harness writes its sessions and settings, so
//! srt lets it write there and the feed reads those writes as its own. Pi
//! `~/.pi/agent` (Pi's docs; the sbx kit's `credentialFile`), Claude Code
//! `~/.claude` and `~/.claude.json` (box plan 5.4), Codex `~/.codex`
//! (the fork's harness.rs), OpenCode and Gemini from their presets' config
//! paths (I until lane C verifies the presets).

#[derive(Debug)]
pub struct Harness {
    pub id: &'static str,
    /// The command, from the presets' `cli`.
    pub command: &'static str,
    /// Folders and files under the home it writes on its own.
    pub state: &'static [&'static str],
    /// Its own credential file under the home, which srt leaves readable
    /// for it and hides from every other harness.
    pub credential: Option<&'static str>,
    /// Files and folders under the home that hold the agent's gate, hooks,
    /// plugin lists and MCP servers: what an agent must never rewrite for
    /// itself (integration w1, security finding S6). Under srt they are
    /// `denyWrite` entries inside the state folders srt lets it write, each
    /// as a literal path, so one that does not exist yet stays denied (srt
    /// 0.0.81 README lines 537, 584). Sources: the matchers' `CONTROL_PATHS`
    /// (`crates/derm-core/src/policy.rs:524`), `contracts/hook-dialects.md`
    /// section 2 and note AQ section 4 for each agent's registration.
    pub control: &'static [&'static str],
    /// What `derm run` sets for this agent before it starts (T2.9).
    pub launch: Launch,
}

/// How sbx runs a harness, from the preset table's `kit` field
/// (`crates/derm-cli/src/connect/presets/wave5/kit.json`, lane T's request
/// T-5): one table for `derm run`, the default boundary and `derm status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sbx {
    /// The AGENT argument of `sbx run`: sbx's built-in agent, or the
    /// harness's own command when a kit is the workload.
    pub agent: String,
    /// A sandbox kit, when the agent is not built in: the workload, first
    /// positional on `sbx create` (SB1).
    pub kit: Option<String>,
    /// The words the kit adds that turn the agent's approvals off
    /// (`fullAccess`; rules case 83).
    pub full_access: Vec<String>,
}

/// The host each harness renews its own sign-in at, which srt's proxy must
/// admit or a chat fails once its access token expires (Mac test w5 retest
/// 4, MW5-24), read in the harness's code at the version in use:
/// Claude Code 2.1.311 posts to `https://platform.claude.com/v1/oauth/token`
/// (its bundle; Docker's own sbx `claude` kit allows the same host), Codex
/// 0.163.0 to `https://auth.openai.com/oauth/token`
/// (`codex-rs/login/src/auth/manager.rs:212`). Others: not read, none. On
/// macOS a harness in `macos_keychain_fallback` gets none (MW5-26).
pub fn sign_in_hosts(id: &str) -> &'static [&'static str] {
    match id {
        "claude-code" => &["platform.claude.com:443"],
        "codex" => &["auth.openai.com:443"],
        _ => &[],
    }
}

/// A harness whose sign-in lives in the macOS login keychain and falls back
/// to a plaintext file under the home when a keychain write fails, by id,
/// with that file (Mac test w5 retest 5, MW5-26). Claude Code 2.1.318's
/// macOS build stores it as `keychain-with-plaintext-fallback`: a failed
/// `security add-generic-password` that is not a timeout writes
/// `~/.claude/.credentials.json` instead (`plaintext_fallback_used`), and a
/// read takes the keychain's copy first (its bundle, read 6 Nov 2026). Under
/// srt the keychain write fails (seen at retest 5; why is inferred: srt's
/// Seatbelt profile allows writes only under its write roots, and the login
/// keychain's file is not one), so a renewal there would keep the rotated
/// token in that file only while the host's Claude Code reads the keychain's
/// old one. Its Linux build has no keychain: the file is its store. Codex
/// 0.163.0 keeps its sign-in in `auth.json` unless configured otherwise
/// (`config/src/types.rs:136-146`, `AuthCredentialsStoreMode::File`); a Codex
/// configured for a keyring is `plan::codex_store_risk`'s, on every system
/// (fix pass 6, FP5R-5).
pub fn macos_keychain_fallback(id: &str) -> Option<&'static str> {
    match id {
        "claude-code" => Some(".claude/.credentials.json"),
        _ => None,
    }
}

impl Harness {
    /// The sbx form for this harness, or `None` when sbx has no agent and
    /// no kit for it (`--boundary sbx` refuses it rather than guess).
    pub fn sbx(&self) -> Option<Sbx> {
        let (from, name, full) = kit_rows().iter().find(|(id, _)| id == self.id)?.1.clone();
        Some(if from == "sbx" {
            Sbx {
                agent: name,
                kit: None,
                full_access: full,
            }
        } else {
            Sbx {
                agent: self.command.to_string(),
                kit: Some(name),
                full_access: full,
            }
        })
    }
}

/// `(id, (from, name, fullAccess))` for every preset row with a kit.
type KitRow = (String, (String, String, Vec<String>));

fn kit_rows() -> &'static [KitRow] {
    static ROWS: std::sync::OnceLock<Vec<KitRow>> = std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        let table: serde_json::Value =
            serde_json::from_str(crate::connect::presets::table_json()).unwrap_or_default();
        let mut out = Vec::new();
        for list in ["harnesses", "planned"] {
            for row in table
                .get(list)
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                let (Some(id), Some(kit)) = (
                    row.get("id").and_then(serde_json::Value::as_str),
                    row.get("kit").filter(|k| k.is_object()),
                ) else {
                    continue;
                };
                let s = |k: &str| kit.get(k).and_then(serde_json::Value::as_str);
                let (Some(from @ ("sbx" | "sbx-kits-contrib")), Some(name)) =
                    (s("from"), s("name"))
                else {
                    continue;
                };
                let full = kit
                    .get("fullAccess")
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                out.push((id.to_string(), (from.to_string(), name.to_string(), full)));
            }
        }
        out
    })
}

/// Launch settings some gates need (toolkit plan T2.9; `contracts/hook-dialects.md`
/// section 2c for Cline, its section 2b and note AQ section 4c for goose).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Launch {
    None,
    /// Cline's approval files: `CLINE_TOOL_APPROVAL_MODE=desktop`,
    /// `CLINE_TOOL_APPROVAL_DIR=<a private folder>`, `--auto-approve false`,
    /// and lane P's responder started beside it.
    Cline,
    /// `GOOSE_MODE=approve` when the policy has asks: goose's default, Auto,
    /// approves everything before its hook runs and ignores its own rule file.
    Goose,
}

/// The harness `derm run --boundary <b> -- <argv>` starts when the program is
/// not one in this table (rules case 80): nothing about it is known, so it
/// gets the outside shape only. Its command comes from the argv.
pub const OTHER: Harness = Harness {
    id: "other",
    command: "",
    state: &[],
    credential: None,
    control: &[],
    launch: Launch::None,
};

pub const HARNESSES: &[Harness] = &[
    Harness {
        id: "pi",
        command: "pi",
        state: &[".pi/agent"],
        credential: Some(".pi/agent/auth.json"),
        control: &[
            ".pi/agent/settings.json",
            ".pi/agent/extensions",
            ".pi/agent/mcp.json",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "claude-code",
        command: "claude",
        state: &[".claude", ".claude.json"],
        credential: Some(".claude/.credentials.json"),
        // `.claude.json` also holds MCP servers, but Claude Code writes it
        // through every session (its state), so it stays writable; the
        // matchers ask on any input that names it.
        control: &[
            ".claude/settings.json",
            ".claude/settings.local.json",
            ".claude/plugins",
            // Hook scripts the settings name (`$CLAUDE_PROJECT_DIR/.claude/
            // hooks/`, Claude Code's convention, inferred; re-review FP5-R4).
            ".claude/hooks",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "codex",
        command: "codex",
        state: &[".codex"],
        credential: Some(".codex/auth.json"),
        // `rules/` holds execpolicy `.rules` files, which allow commands
        // without asking (security review L14, from the 0.163.0 binary).
        // FP8-S1: `.env` is loaded into Codex's environment at every start
        // (0.163.0 `arg0/src/lib.rs:132, 274-280`, only `CODEX_*` names
        // filtered). FP8-S7: `tmp/` holds each live session's helper links
        // (`codex-linux-sandbox`, `apply_patch`; `arg0/src/lib.rs:339-405`),
        // which another session runs; Codex starts without them when it
        // cannot write there (`:157-165`).
        control: &[
            ".codex/.env",
            ".codex/config.toml",
            ".codex/hooks.json",
            ".codex/plugins",
            ".codex/requirements.toml",
            ".codex/rules",
            ".codex/tmp",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "opencode",
        command: "opencode",
        state: &[".local/share/opencode", ".config/opencode"],
        credential: None,
        control: &[
            ".config/opencode/opencode.json",
            ".config/opencode/opencode.jsonc",
            ".config/opencode/plugin",
            ".config/opencode/plugins",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "gemini",
        command: "gemini",
        state: &[".gemini"],
        credential: Some(".gemini/oauth_creds.json"),
        // `.env` is loaded into the environment when the folder is trusted;
        // `trustedFolders.json` decides whether a project's settings load
        // (security review L14, from the 0.66.0 bundle).
        control: &[
            ".gemini/settings.json",
            ".gemini/extensions",
            ".gemini/policies",
            ".gemini/config/hooks.json",
            ".gemini/.env",
            ".gemini/trustedFolders.json",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "copilot-cli",
        command: "copilot",
        state: &[".copilot"],
        credential: None,
        control: &[".copilot/hooks", ".copilot/mcp-config.json"],
        launch: Launch::None,
    },
    // Hermes: lane C verified the CLI `hermes` and the folder `~/.hermes`
    // (HERMES_HOME; its preset row). Added by integration
    // w1; sbx has no Hermes agent (its form is sbx-kits-contrib's kit), and
    // its credential file is not read (NF).
    Harness {
        id: "hermes",
        command: "hermes",
        state: &[".hermes"],
        credential: None,
        control: &[".hermes/config.yaml", ".hermes/plugins"],
        launch: Launch::None,
    },
    Harness {
        id: "openclaw",
        command: "openclaw",
        state: &[".openclaw"],
        credential: None,
        // OpenClaw's plugin and config files were not read for this (NF);
        // the whole folder is the matchers' control path.
        control: &[],
        launch: Launch::None,
    },
    Harness {
        id: "goose",
        command: "goose",
        state: &[".config/goose", ".local/share/goose"],
        credential: None,
        control: &[".config/goose/config.yaml", ".config/goose/permission.yaml"],
        launch: Launch::Goose,
    },
    Harness {
        id: "qwen-code",
        command: "qwen",
        state: &[".qwen"],
        credential: None,
        control: &[".qwen/settings.json"],
        launch: Launch::None,
    },
    // OpenClaude 0.34.0, a Claude Code fork: `~/.openclaude/settings.json`
    // holds `hooks` and `disableAllHooks`, `~/.openclaude.json` its MCP
    // servers and session state (lane L, `packages/derm-hooks-claude-compat/
    // src/control.ts` and its Research). Added by integration w4 when lane L
    // gave its row a `cli`. As for Claude Code, `.openclaude.json` stays
    // writable (its state) and the matchers ask on input that names it.
    Harness {
        id: "openclaude",
        command: "openclaude",
        state: &[".openclaude", ".openclaude.json"],
        credential: None,
        // As Claude Code's row: `settings.local.json` and `plugins` load
        // hooks and servers in Claude Code; for OpenClaude that is inferred
        // from the fork, not read (review W4-S7). A deny here only narrows.
        control: &[
            ".openclaude/settings.json",
            ".openclaude/settings.local.json",
            ".openclaude/plugins",
            ".openclaude/hooks",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "amp",
        command: "amp",
        state: &[".config/amp", ".local/share/amp"],
        credential: None,
        control: &[".config/amp/settings.json", ".config/amp/plugins"],
        launch: Launch::None,
    },
    Harness {
        id: "crush",
        command: "crush",
        state: &[".config/crush", ".local/share/crush"],
        credential: None,
        control: &[".config/crush/crush.json", ".config/crush/crushrc"],
        launch: Launch::None,
    },
    // Wave 4 (lane R): the agents still in the table's `planned` list whose
    // row names a command, so `derm run` starts them before and after lane Q
    // moves them to `harnesses`. Commands from each row's `cli`; state and
    // control from the MCP file and the gate's registration each row's
    // `mcpFile` and `coverage.gate.where` name (note AQ section 4b,
    // `contracts/hook-dialects.md` section 2). sbx's built-in agents
    // include droid and kiro (https://docs.docker.com/reference/cli/sbx/run/,
    // read 27 Oct 2026 by lane D); the other four have no sbx form here.
    // Cursor's CLI (Mac test w4, MW4-8). Command: `cursor-agent`, the one
    // Cursor's install page names (https://docs.cursor.com/en/cli/installation,
    // read 4 Nov 2026); the installer also links a bare `agent`, which other
    // CLIs use too, so `agent` is not matched (a program of that name under
    // srt would get Cursor's state). sbx: `cursor` is one of `sbx run`'s
    // built-in agents (the list at the top of this file). State: `~/.cursor`,
    // where the CLI writes `cli-config.json` (seen on the Mac and the rig, 4
    // Nov) and reads `mcp.json` (its preset row) and `hooks.json` (derm's
    // gate, lane N). Control: those three, since `cli-config.json` holds the
    // CLI's own approval mode and allowlist (seen, Mac test w4). Fix pass 1's
    // review (FP4-S1): all of `~/.cursor` is writable state under srt, and
    // Cursor runs code from inside it as you, so these are control too:
    // `hooks/` (hook scripts) and `managed/` (team hooks, written to
    // `managed/team_<id>/hooks/`), both read in
    // https://cursor.com/docs/agent/hooks (4 Nov 2026); `cli.json`, a
    // project's permissions, which can allow tools
    // (https://cursor.com/docs/cli/reference/configuration, 4 Nov 2026);
    // `plugins/` (plugin hooks load after user hooks, same page; the folder
    // name is inferred, the page names none); `extensions/` and `argv.json`
    // (the IDE's, by VS Code's layout, inferred); `skills/`, `commands/` and
    // `rules/` (text the agent reads as instructions, inferred). What else
    // the CLI writes there was not read (NF): srt with Cursor is not run, so
    // a CLI feature that writes one of these fails closed under srt.
    Harness {
        id: "cursor",
        command: "cursor-agent",
        state: &[".cursor"],
        credential: None,
        // Re-review FP5-R1: Cursor itself write-protects every
        // `.cursor/**/*.json` and `.cursor/.workspace-trusted`
        // (https://cursor.com/docs/reference/sandbox.md, read 4 Nov 2026),
        // among them `sandbox.json`, which widens Cursor's own sandbox, and
        // `worktrees.json`, whose setup commands Cursor runs
        // (https://cursor.com/docs/configuration/worktrees). srt takes
        // literal paths on Linux, so the whole of `~/.cursor` is read-only:
        // the entries below name what is known to matter.
        control: &[
            ".cursor",
            ".cursor/hooks.json",
            ".cursor/mcp.json",
            ".cursor/cli-config.json",
            ".cursor/cli.json",
            ".cursor/hooks",
            ".cursor/managed",
            ".cursor/plugins",
            ".cursor/extensions",
            ".cursor/argv.json",
            ".cursor/skills",
            ".cursor/commands",
            ".cursor/rules",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "grok",
        command: "grok",
        state: &[".grok"],
        credential: None,
        control: &[".grok/hooks", ".grok/config.toml"],
        launch: Launch::None,
    },
    Harness {
        id: "oh-my-pi",
        command: "omp",
        state: &[".omp/agent"],
        credential: None,
        control: &[
            ".omp/agent/settings.json",
            ".omp/agent/extensions",
            ".omp/agent/mcp.json",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "cline",
        command: "cline",
        state: &[".cline"],
        credential: None,
        // `.cline/plugins`: derm's own gate is installed there (the agents
        // page), and a second plugin there loads beside it (review W4-S1).
        control: &[".cline/data/settings", ".cline/hooks", ".cline/plugins"],
        launch: Launch::Cline,
    },
    Harness {
        id: "command-code",
        command: "cmd",
        state: &[".commandcode"],
        credential: None,
        control: &[".commandcode/settings.json", ".commandcode/mcp.json"],
        launch: Launch::None,
    },
    Harness {
        id: "droid",
        command: "droid",
        state: &[".factory"],
        credential: None,
        // `hooks.json` too: Droid's binary merges it over `settings.json`,
        // so an agent that creates it shadows derm's gate (hook-dialects 2a).
        control: &[
            ".factory/settings.json",
            ".factory/hooks.json",
            ".factory/mcp.json",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "kilo",
        command: "kilo",
        state: &[".config/kilo", ".local/share/kilo"],
        credential: None,
        control: &[".config/kilo/kilo.json", ".config/kilo/plugin"],
        launch: Launch::None,
    },
    Harness {
        id: "kimi",
        command: "kimi",
        state: &[".kimi-code"],
        credential: None,
        control: &[".kimi-code/config.toml", ".kimi-code/mcp.json"],
        launch: Launch::None,
    },
    Harness {
        id: "kiro",
        command: "kiro-cli",
        state: &[".kiro"],
        credential: None,
        control: &[".kiro/hooks", ".kiro/settings", ".kiro/agents"],
        launch: Launch::None,
    },
];

/// Ids in the presets that `derm run` does not start: Zed (its `zed` command
/// opens the editor app, not an agent; lane C's row names it for `derm
/// connect`). Cursor was here until its row named `cursor-agent` (fix pass 1
/// for the Mac test w4, MW4-8). Integration w1 renamed
/// lane D's `NO_CLI` when the verified table gave Zed a `cli`. A row whose
/// `cli` is still `TODO` is not started either, until its lane fills it.
/// Codebuff (`codebuff`) and Continue (`cn`) got a `cli` when integration w4
/// folded lane Q's verified rows in (lane Q's request 9). Neither has a gate
/// (the rows are an MCP file and a print-only rule file), and their state
/// folders were not read, so `derm run` gives them no state, control or
/// credential entries: `derm run --boundary <b> -- codebuff` runs it as an
/// unknown program, with the outside shape only (case 80).
pub const NOT_RUN: &[&str] = &["zed", "codebuff", "continue"];

pub fn find(id: &str) -> Option<&'static Harness> {
    HARNESSES.iter().find(|h| h.id == id)
}

/// The table's harness whose command is `program` (a bare name or the last
/// part of a path): `derm run --boundary b -- claude ...` is Claude Code, so
/// it gets Claude Code's state folders, control files and export, not the
/// outside shape alone.
/// The preset whose command is `program`'s last part, for a note only.
pub fn by_basename(program: &str) -> Option<&'static Harness> {
    let base = program.rsplit('/').next().unwrap_or(program);
    HARNESSES.iter().find(|h| h.command == base)
}

/// The preset whose command is `program`, a bare name. A path is not
/// matched (security review L15): any binary named `claude` would get Claude
/// Code's state folders writable and its credential readable inside srt.
pub fn by_command(program: &str) -> Option<&'static Harness> {
    if program.contains('/') {
        return None;
    }
    HARNESSES.iter().find(|h| h.command == program)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every preset row, in either list, that names a command is here with
    /// that command, or in `NOT_RUN`; a row whose `cli` is `TODO` is not
    /// here. Both lists are read, so lane Q moving a row from `planned` to
    /// `harnesses` changes nothing for `derm run`.
    #[test]
    fn every_preset_with_a_cli_is_here_with_the_same_command() {
        let v: serde_json::Value =
            serde_json::from_str(crate::connect::presets::table_json()).unwrap();
        let mut rows: Vec<serde_json::Value> = v["harnesses"].as_array().unwrap().clone();
        rows.extend(v["planned"].as_array().unwrap().iter().cloned());
        let mut named = 0;
        for row in rows {
            let id = row["id"].as_str().unwrap();
            if NOT_RUN.contains(&id) {
                assert!(find(id).is_none(), "{id}");
                continue;
            }
            match row["cli"].as_str().filter(|c| *c != "TODO") {
                Some(cli) => {
                    named += 1;
                    assert_eq!(find(id).map(|h| h.command), Some(cli), "{id}");
                }
                None => assert!(find(id).is_none(), "{id} has no cli in its row"),
            }
        }
        assert_eq!(named, HARNESSES.len());
    }

    /// Mac test w4, MW4-6: every harness `derm run` starts, and `other`
    /// (case 80), is an id the daemon mints a token for, and the shared list
    /// is exactly the preset table's ids in both lists plus `other`.
    #[test]
    fn every_harness_derm_run_starts_can_get_a_token() {
        let v: serde_json::Value =
            serde_json::from_str(crate::connect::presets::table_json()).unwrap();
        let mut table: Vec<String> = Vec::new();
        for list in ["harnesses", "planned"] {
            for row in v[list].as_array().unwrap() {
                table.push(row["id"].as_str().unwrap().to_string());
            }
        }
        table.push(OTHER.id.to_string());
        let mut shared: Vec<String> = derm_core::harness::IDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        table.sort();
        shared.sort();
        assert_eq!(table, shared);
        for h in HARNESSES.iter().chain(std::iter::once(&OTHER)) {
            assert!(derm_core::harness::id(h.id).is_some(), "{}", h.id);
        }
    }

    /// Mac test w4, MW4-8: Cursor's CLI had no command here, so a Cursor
    /// chat could get no token: no ask reached an approver and no decision
    /// reached the daemon. It runs as `cursor-agent`, the name Cursor's
    /// install page gives, and its gate and permission files stay read-only
    /// under srt.
    #[test]
    fn cursor_runs_as_cursor_agent_with_its_gate_files_read_only() {
        let h = find("cursor").expect("cursor");
        assert_eq!(h.command, "cursor-agent");
        assert!(!NOT_RUN.contains(&"cursor"));
        for c in [
            ".cursor/hooks.json",
            ".cursor/mcp.json",
            ".cursor/cli-config.json",
            // Fix pass 1's review, FP4-S1.
            ".cursor/cli.json",
            ".cursor/hooks",
            ".cursor/managed",
            ".cursor/plugins",
        ] {
            assert!(h.control.contains(&c), "{c}");
        }
        assert_eq!(by_command("agent").map(|h| h.id), None);
    }

    /// Request T-5: the forms come from the kit table, the nine derm ran
    /// before are unchanged, and the kits for harnesses that had none now
    /// give them one.
    #[test]
    fn sbx_forms_come_from_the_kit_table() {
        let f = |id: &str| find(id).unwrap_or_else(|| panic!("{id}")).sbx();
        assert_eq!(
            f("pi"),
            Some(Sbx {
                agent: "pi".into(),
                kit: Some("docker.io/sbx/pi-kit:latest".into()),
                full_access: vec![],
            })
        );
        for (id, agent) in [
            ("claude-code", "claude"),
            ("codex", "codex"),
            ("opencode", "opencode"),
            ("gemini", "gemini"),
            ("copilot-cli", "copilot"),
            ("cursor", "cursor"),
            ("droid", "droid"),
            ("kiro", "kiro"),
        ] {
            let s = f(id).unwrap();
            assert_eq!((s.agent.as_str(), s.kit.as_deref()), (agent, None), "{id}");
        }
        assert_eq!(
            f("claude-code").unwrap().full_access,
            vec!["--dangerously-skip-permissions".to_string()]
        );
        assert_eq!(
            f("kiro").unwrap().full_access,
            vec!["--trust-all-tools".to_string()]
        );
        for id in ["hermes", "openclaw", "amp", "crush", "grok"] {
            let s = f(id).unwrap();
            assert!(s.kit.is_some(), "{id}");
            assert_eq!(s.agent, find(id).unwrap().command, "{id}");
        }
        for id in [
            "goose",
            "qwen-code",
            "openclaude",
            "cline",
            "command-code",
            "oh-my-pi",
        ] {
            assert_eq!(f(id), None, "{id}");
        }
        assert_eq!(OTHER.sbx(), None);
    }

    #[test]
    fn paths_are_relative_and_inside_the_state() {
        for h in HARNESSES {
            for p in h.state.iter().chain(h.credential.iter()).chain(h.control) {
                assert!(!p.starts_with('/') && !p.contains(".."), "{p}");
            }
            // A control file outside the state folders is not writable under
            // srt anyway; one inside them is what the deny is for.
            for c in h.control {
                assert!(
                    h.state
                        .iter()
                        .any(|s| c == s || c.starts_with(&format!("{s}/"))),
                    "{}: {c} is not inside its state",
                    h.id
                );
            }
        }
    }

    /// Every file or folder the agents page tells you to put derm's gate in
    /// (`~/...` in `docs/install/agents.md`) that lies inside an agent's
    /// state is also one of its control paths, so srt keeps it read-only
    /// (integration w4's review, W4-S1: Cline's gate in `~/.cline/plugins/
    /// derm/` sat in writable state).
    #[test]
    fn every_install_path_inside_a_state_folder_is_control() {
        let page = include_str!("../../../../docs/install/agents.md");
        let mut paths: Vec<String> = Vec::new();
        let mut rest = page;
        while let Some(i) = rest.find("~/") {
            rest = &rest[i + 2..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || "._/-".contains(c)))
                .unwrap_or(rest.len());
            let p = rest[..end].trim_end_matches(['/', '.']);
            if !p.is_empty() {
                paths.push(p.to_string());
            }
        }
        assert!(
            paths.iter().any(|p| p == ".cline/plugins/derm"),
            "{paths:?}"
        );
        let under = |p: &str, d: &str| p == d || p.starts_with(&format!("{d}/"));
        let mut missing = Vec::new();
        for h in HARNESSES {
            for p in &paths {
                if h.state.iter().any(|s| under(p, s)) && !h.control.iter().any(|c| under(p, c)) {
                    missing.push(format!("{}: {p}", h.id));
                }
            }
        }
        assert!(missing.is_empty(), "writable under srt: {missing:?}");
    }

    /// OpenClaude is a Claude Code fork: what srt keeps read-only in
    /// `~/.claude` it keeps read-only in `~/.openclaude` (review W4-S7).
    #[test]
    fn openclaude_keeps_claude_codes_control_files() {
        let claude: Vec<String> = find("claude-code")
            .unwrap()
            .control
            .iter()
            .map(|c| c.replacen(".claude/", ".openclaude/", 1))
            .collect();
        let open = find("openclaude").unwrap().control;
        for c in &claude {
            assert!(open.contains(&c.as_str()), "{c}");
        }
    }

    #[test]
    fn launch_settings_belong_to_cline_and_goose_only() {
        for h in HARNESSES {
            let want = match h.id {
                "cline" => Launch::Cline,
                "goose" => Launch::Goose,
                _ => Launch::None,
            };
            assert_eq!(h.launch, want, "{}", h.id);
        }
    }

    #[test]
    fn a_program_is_found_by_its_command() {
        assert_eq!(by_command("claude").map(|h| h.id), Some("claude-code"));
        // Only the bare name (security review L15; this test asserted the
        // opposite before).
        assert!(by_command("/usr/local/bin/codex").is_none());
        assert_eq!(
            by_basename("/usr/local/bin/codex").map(|h| h.id),
            Some("codex")
        );
        assert_eq!(by_command("kiro-cli").map(|h| h.id), Some("kiro"));
        assert!(by_command("vim").is_none());
        assert!(by_command("").is_none());
    }
}
