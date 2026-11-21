//! A chat of an agent account inside its project (lane PA's;
//! `contracts/projects.md` section 2; plan step P2).
//!
//! Each project gets its own home, temp folder and runtime folder inside
//! every account (`/var/lib/derm/agents/<slug>/projects/<id>/{home,tmp,run}`),
//! and its chats write those and their own folders, not the account home.
//! So nothing a chat of project A writes is read or run by a chat of project
//! B (AI-1 across projects, P-C1), and Claude Code's teams, mailboxes and
//! inbox sockets are per project (N-2; N-1 needs PE's `crossSessionInbound`).
//!
//! The harness is found on `/usr/local/bin:/usr/bin:/bin` only, so it is a
//! root-owned install outside every home (`chat.rs` checks it), and the
//! variables go on `/usr/bin/env`'s argv after the helper, since `sudo`
//! passes none of `HOME`, `PATH` or `XDG_*` (`keep()`; contracts/projects.md
//! section 2.3).

use super::landlock::{makes_ptys, project_spec, setup, ProjectPaths, Spec};
use crate::project::ProjectId;
use derm_core::project::layout;

/// The `PATH` of every project chat: no home entry (section 2.3).
pub(crate) const PATH: &str = "/usr/local/bin:/usr/bin:/bin";
/// derm's gateway entry's server name (contracts/project-tools.md section 1).
pub(crate) const SERVER: &str = "derm_project";
/// The variables `derm-daemon project-mcp` reads (`computer_use/relay.rs`'s
/// rules, `contracts/project-tools.md` section 1): passed by name, never by
/// value, so no token lands in a config file.
const SERVER_VARS: &[&str] = &[
    "DERM_CHAT_TOKEN",
    "DERM_CHAT_TOKEN_FILE",
    "DERM_DAEMON_SOCKET",
];

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

impl ProjectChat<'_> {
    fn dir(&self) -> String {
        layout::project_dir(self.account_home, self.project)
    }
    fn part(&self, part: &str) -> String {
        format!("{}/{part}", self.dir())
    }
}

/// The variables the chat's harness gets on `/usr/bin/env`'s argv after the
/// helper (`HOME`, `TMPDIR`, `XDG_RUNTIME_DIR`, `PATH`, and the harness's
/// own from section 2.3), in order. Paths only: a secret never goes on argv
/// (case 85). `CODEX_HOME` stays unset (it must exist when set, and the
/// home's `.codex` is used); Claude Code's store folder, when lane PB's
/// switch is on, comes from PB's links at the helper.
pub(crate) fn project_env(c: &ProjectChat<'_>) -> Vec<(String, String)> {
    let mut env = vec![
        ("HOME".to_string(), c.part(layout::HOME)),
        ("TMPDIR".to_string(), c.part(layout::TMP)),
        ("XDG_RUNTIME_DIR".to_string(), c.part(layout::RUN)),
        ("PATH".to_string(), PATH.to_string()),
    ];
    if c.harness == "claude-code" {
        // The name is read (binary, 2.1.322); that it stops the native
        // installer writing into the home is I (note CD section 2.1).
        env.push(("DISABLE_AUTOUPDATER".to_string(), "1".to_string()));
    }
    env
}

/// The folders a chat of this project writes besides its own: its project's
/// home, temp and runtime folders, and its harness's sign-in store folder
/// when it has one (section 2.2).
pub(crate) fn project_writable(c: &ProjectChat<'_>) -> Vec<String> {
    let mut w = vec![
        c.part(layout::HOME),
        c.part(layout::TMP),
        c.part(layout::RUN),
    ];
    if layout::SIGNIN_HARNESSES.contains(&c.harness) {
        w.push(layout::signin_dir(c.account_home, c.harness));
    }
    w
}

/// The chat's Landlock spec (section 2.2, the "Domain right" column).
pub(crate) fn project_chat_spec(c: &ProjectChat<'_>) -> Spec {
    let writable = project_writable(c);
    project_spec(&ProjectPaths {
        folders: c.folders,
        writable: &writable,
        bridge: c.bridge,
        path: PATH,
        pts: makes_ptys(c.harness),
        require_scopes: c.require_scopes,
    })
}

/// What the helper makes for this chat before its domain: the project's
/// folders, the sign-in links, and `derm_project` in the harness's own
/// config when the file is not there yet (`entry`).
pub(crate) fn project_setup(c: &ProjectChat<'_>, entry: Option<setup::File>) -> setup::Setup {
    setup::Setup {
        account_home: c.account_home.to_string(),
        project: c.project.as_str().to_string(),
        harness: c.harness.to_string(),
        files: entry.into_iter().collect(),
    }
}

/// derm's gateway entry for `harness`, as the harness's own user config
/// file under the project home would hold it alone. The shapes are the ones
/// `derm connect`'s renderer writes for these three presets
/// (`connect/render.rs`; recorded from each harness's own `mcp add` in
/// `connect/fixtures/recorded/`: `claude-1-after.json`, `codex-1-after.toml`,
/// `pi-1-after.json`). The renderer is private to `connect/`, which is no
/// lane's here; request PA-3 asks integration to open it so this calls it.
/// `daemon` is `derm-daemon`'s absolute path, a root-owned copy (case 227).
/// `None` for any other harness, or a path that is not plain.
pub(crate) fn gateway_entry(harness: &str, daemon: &str) -> Option<setup::File> {
    use serde_json::{json, Map, Value};
    if !daemon.starts_with('/')
        || daemon.contains('$')
        || daemon.contains('"')
        || daemon.contains('\\')
        || daemon.chars().any(char::is_control)
    {
        return None;
    }
    let refs = || {
        let mut m = Map::new();
        for v in SERVER_VARS {
            m.insert(v.to_string(), Value::String(format!("${{{v}}}")));
        }
        Value::Object(m)
    };
    let json_file = |rel: &str, entry: Value, newline: bool| {
        let mut t = serde_json::to_string_pretty(&json!({"mcpServers": {SERVER: entry}})).ok()?;
        if newline {
            t.push('\n');
        }
        Some(setup::File {
            rel: rel.to_string(),
            text: t,
        })
    };
    match harness {
        // presets/claude-code.json: `~/.claude.json`, `mcpServers`, `type`
        // first, `envRef` `${VAR}`, no trailing newline.
        "claude-code" => json_file(
            ".claude.json",
            json!({"type": "stdio", "command": daemon, "args": ["project-mcp"], "env": refs()}),
            false,
        ),
        // presets/codex.json: `~/.codex/config.toml`, `[mcp_servers.<name>]`;
        // variables by name only (`env_vars`), since Codex has no `${VAR}`.
        "codex" => {
            let names: Vec<String> = SERVER_VARS.iter().map(|v| format!("\"{v}\"")).collect();
            Some(setup::File {
                rel: ".codex/config.toml".to_string(),
                text: format!(
                    "[mcp_servers.{SERVER}]\ncommand = \"{daemon}\"\nargs = [\"project-mcp\"]\nenv_vars = [{}]\n",
                    names.join(", ")
                ),
            })
        }
        // presets/pi.json: `~/.pi/agent/mcp.json`, `mcpServers`, `exposure`.
        "pi" => json_file(
            ".pi/agent/mcp.json",
            json!({"command": daemon, "args": ["project-mcp"], "env": refs(), "exposure": "direct"}),
            true,
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "/var/lib/derm/agents/max";

    fn chat<'a>(id: &'a ProjectId, f: &'a [String], h: &'a str) -> ProjectChat<'a> {
        ProjectChat {
            account_home: ACCOUNT,
            project: id,
            folders: f,
            harness: h,
            bridge: Some("/run/derm-agent/1000/c-x"),
            require_scopes: true,
        }
    }

    #[test]
    fn a_project_chat_writes_its_project_and_its_harnesss_store_and_not_the_account_home() {
        let id = ProjectId::of_real_path("/srv/a");
        let f = vec!["/srv/a".to_string()];
        let s = project_chat_spec(&chat(&id, &f, "codex"));
        assert!(!s.write.iter().any(|w| w == ACCOUNT), "{:?}", s.write);
        assert!(s.write.contains(&format!("{ACCOUNT}/signin/codex")));
        assert!(!s.write.iter().any(|w| w.ends_with("/signin/pi")));
        assert!(s.read.contains(&"/run/derm-agent/1000/c-x".to_string()));
        assert!(
            s.exec.iter().all(|e| !e.starts_with(ACCOUNT)),
            "{:?}",
            s.exec
        );
        // Codex makes ptys and keeps /dev/pts; Pi and Claude Code do not.
        assert!(s.write.contains(&"/dev/pts".to_string()));
        for h in ["pi", "claude-code"] {
            let s = project_chat_spec(&chat(&id, &f, h));
            assert!(!s.write.contains(&"/dev/pts".to_string()), "{h}");
            assert!(s.write.contains(&"/dev/ptmx".to_string()), "{h}");
            assert!(s.write.contains(&"/dev/tty".to_string()), "{h}");
        }
        // A harness with no store gets no store folder.
        let s = project_chat_spec(&chat(&id, &f, "gemini"));
        assert!(!s.write.iter().any(|w| w.contains("/signin")));
    }

    #[test]
    fn claude_code_gets_the_autoupdater_off_and_paths_only() {
        let id = ProjectId::of_real_path("/srv/a");
        let env = project_env(&chat(&id, &[], "claude-code"));
        assert!(env.contains(&("DISABLE_AUTOUPDATER".into(), "1".into())));
        assert!(env
            .iter()
            .all(|(k, v)| !k.contains("TOKEN") && !v.contains('\n')));
        assert_eq!(env[0].0, "HOME");
    }

    #[test]
    fn the_gateway_entry_names_the_variables_and_never_their_values() {
        let d = "/usr/local/bin/derm-daemon";
        let cc = gateway_entry("claude-code", d).unwrap();
        assert_eq!(cc.rel, ".claude.json");
        let v: serde_json::Value = serde_json::from_str(&cc.text).unwrap();
        let e = &v["mcpServers"][SERVER];
        assert_eq!(e["command"], d);
        assert_eq!(e["args"][0], "project-mcp");
        assert_eq!(e["env"]["DERM_CHAT_TOKEN"], "${DERM_CHAT_TOKEN}");
        let cx = gateway_entry("codex", d).unwrap();
        assert_eq!(cx.rel, ".codex/config.toml");
        assert!(
            cx.text.starts_with("[mcp_servers.derm_project]\n"),
            "{}",
            cx.text
        );
        assert!(cx.text.contains("env_vars = [\"DERM_CHAT_TOKEN\", \"DERM_CHAT_TOKEN_FILE\", \"DERM_DAEMON_SOCKET\"]"), "{}", cx.text);
        let pi = gateway_entry("pi", d).unwrap();
        assert_eq!(pi.rel, ".pi/agent/mcp.json");
        assert!(serde_json::from_str::<serde_json::Value>(&pi.text).is_ok());
        assert!(
            gateway_entry("codex", "derm-daemon").is_none(),
            "an absolute path only"
        );
        assert!(gateway_entry("codex", "/x/$HOME/d").is_none());
        assert!(gateway_entry("no-such-harness", d).is_none());
        assert!(gateway_entry("codex", "/x/\"y").is_none());
    }
}
