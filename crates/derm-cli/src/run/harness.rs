//! What `derm run` needs to know per harness: the command it starts, how sbx
//! runs it, and the folders it keeps its own state in. Ids and commands are
//! the preset table (`crates/derm-cli/src/connect/presets/`, `id`, `cli`).
//!
//! sbx: the built-in agents of `sbx run` are claude, codex, copilot, cursor,
//! devin, docker-agent, droid, gemini, kiro, opencode, shell
//! (https://docs.docker.com/reference/cli/sbx/run/, read 27 Oct 2026). Pi
//! runs from the community kit `docker.io/sbx/pi-kit:latest` as Pi 1.4.0's
//! `docs/containerization.md:110` and the kit's README give it:
//! `sbx run --kit "docker.io/sbx/pi-kit:latest" pi`. The other harnesses
//! have no sbx form here; `--boundary sbx` refuses them rather than guess.
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
    pub sbx: Option<Sbx>,
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

#[derive(Clone, Copy, Debug)]
pub struct Sbx {
    /// The AGENT argument of `sbx run`.
    pub agent: &'static str,
    /// A kit passed with `--kit`, when the agent is not built in.
    pub kit: Option<&'static str>,
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

pub const PI_KIT: &str = "docker.io/sbx/pi-kit:latest";

/// The harness `derm run --boundary <b> -- <argv>` starts when the program is
/// not one in this table (rules case 80): nothing about it is known, so it
/// gets the outside shape only. Its command comes from the argv.
pub const OTHER: Harness = Harness {
    id: "other",
    command: "",
    sbx: None,
    state: &[],
    credential: None,
    control: &[],
    launch: Launch::None,
};

pub const HARNESSES: &[Harness] = &[
    Harness {
        id: "pi",
        command: "pi",
        sbx: Some(Sbx {
            agent: "pi",
            kit: Some(PI_KIT),
        }),
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
        sbx: Some(Sbx {
            agent: "claude",
            kit: None,
        }),
        state: &[".claude", ".claude.json"],
        credential: Some(".claude/.credentials.json"),
        // `.claude.json` also holds MCP servers, but Claude Code writes it
        // through every session (its state), so it stays writable; the
        // matchers ask on any input that names it.
        control: &[
            ".claude/settings.json",
            ".claude/settings.local.json",
            ".claude/plugins",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "codex",
        command: "codex",
        sbx: Some(Sbx {
            agent: "codex",
            kit: None,
        }),
        state: &[".codex"],
        credential: Some(".codex/auth.json"),
        // `rules/` holds execpolicy `.rules` files, which allow commands
        // without asking (security review L14, from the 0.163.0 binary).
        control: &[
            ".codex/config.toml",
            ".codex/hooks.json",
            ".codex/plugins",
            ".codex/requirements.toml",
            ".codex/rules",
        ],
        launch: Launch::None,
    },
    Harness {
        id: "opencode",
        command: "opencode",
        sbx: Some(Sbx {
            agent: "opencode",
            kit: None,
        }),
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
        sbx: Some(Sbx {
            agent: "gemini",
            kit: None,
        }),
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
        sbx: Some(Sbx {
            agent: "copilot",
            kit: None,
        }),
        state: &[".copilot"],
        credential: None,
        control: &[".copilot/hooks", ".copilot/mcp-config.json"],
        launch: Launch::None,
    },
    // Hermes: lane C verified the CLI `hermes` and the folder `~/.hermes`
    // (HERMES_HOME; its preset row). Added by integration
    // w1; sbx has no Hermes agent, and its credential file is not read (NF).
    Harness {
        id: "hermes",
        command: "hermes",
        sbx: None,
        state: &[".hermes"],
        credential: None,
        control: &[".hermes/config.yaml", ".hermes/plugins"],
        launch: Launch::None,
    },
    Harness {
        id: "openclaw",
        command: "openclaw",
        sbx: None,
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
        sbx: None,
        state: &[".config/goose", ".local/share/goose"],
        credential: None,
        control: &[".config/goose/config.yaml", ".config/goose/permission.yaml"],
        launch: Launch::Goose,
    },
    Harness {
        id: "qwen-code",
        command: "qwen",
        sbx: None,
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
        sbx: None,
        state: &[".openclaude", ".openclaude.json"],
        credential: None,
        control: &[".openclaude/settings.json"],
        launch: Launch::None,
    },
    Harness {
        id: "amp",
        command: "amp",
        sbx: None,
        state: &[".config/amp", ".local/share/amp"],
        credential: None,
        control: &[".config/amp/settings.json", ".config/amp/plugins"],
        launch: Launch::None,
    },
    Harness {
        id: "crush",
        command: "crush",
        sbx: None,
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
    Harness {
        id: "grok",
        command: "grok",
        sbx: None,
        state: &[".grok"],
        credential: None,
        control: &[".grok/hooks", ".grok/config.toml"],
        launch: Launch::None,
    },
    Harness {
        id: "oh-my-pi",
        command: "omp",
        sbx: None,
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
        sbx: None,
        state: &[".cline"],
        credential: None,
        control: &[".cline/data/settings", ".cline/hooks"],
        launch: Launch::Cline,
    },
    Harness {
        id: "command-code",
        command: "cmd",
        sbx: None,
        state: &[".commandcode"],
        credential: None,
        control: &[".commandcode/settings.json", ".commandcode/mcp.json"],
        launch: Launch::None,
    },
    Harness {
        id: "droid",
        command: "droid",
        sbx: Some(Sbx {
            agent: "droid",
            kit: None,
        }),
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
        sbx: None,
        state: &[".config/kilo", ".local/share/kilo"],
        credential: None,
        control: &[".config/kilo/kilo.json", ".config/kilo/plugin"],
        launch: Launch::None,
    },
    Harness {
        id: "kimi",
        command: "kimi",
        sbx: None,
        state: &[".kimi-code"],
        credential: None,
        control: &[".kimi-code/config.toml", ".kimi-code/mcp.json"],
        launch: Launch::None,
    },
    Harness {
        id: "kiro",
        command: "kiro-cli",
        sbx: Some(Sbx {
            agent: "kiro",
            kit: None,
        }),
        state: &[".kiro"],
        credential: None,
        control: &[".kiro/hooks", ".kiro/settings", ".kiro/agents"],
        launch: Launch::None,
    },
];

/// Ids in the presets that `derm run` does not start: Cursor (no CLI in its
/// preset row) and Zed (its `zed` command opens the editor app, not an
/// agent; lane C's row names it for `derm connect`). Integration w1 renamed
/// lane D's `NO_CLI` when the verified table gave Zed a `cli`. A row whose
/// `cli` is still `TODO` is not started either, until its lane fills it.
/// Codebuff (`codebuff`) and Continue (`cn`) got a `cli` when integration w4
/// folded lane Q's verified rows in (lane Q's request 9). Neither has a gate
/// (the rows are an MCP file and a print-only rule file), and their state
/// folders were not read, so `derm run` gives them no state, control or
/// credential entries: `derm run --boundary <b> -- codebuff` runs it as an
/// unknown program, with the outside shape only (case 80).
pub const NOT_RUN: &[&str] = &["cursor", "zed", "codebuff", "continue"];

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

    #[test]
    fn only_pi_needs_a_kit_and_paths_are_relative_and_inside_the_state() {
        for h in HARNESSES {
            if let Some(s) = h.sbx {
                assert_eq!(s.kit.is_some(), h.id == "pi", "{}", h.id);
            }
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
