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
        // Box research BR-1: the account's login shell is
        // /usr/sbin/nologin, so a remote login as the account (Tailscale
        // SSH admitted one with no password, 22 Nov) gets no shell, and sudo
        // hands that shell on as SHELL. Claude Code takes SHELL when it is
        // bash or zsh, else it looks for one ("is not a valid bash/zsh path,
        // falling back to detection", 2.1.330 binary); Codex 0.167.2 reads
        // the passwd shell and falls back to bash on Linux
        // (`shell-command/src/shell_detect.rs:363-381`). The chat's own is
        // named here so every harness gets one.
        ("SHELL".to_string(), posix_shell().to_string()),
    ];
    match c.harness {
        // Box research BR-4: the account's Claude Code updated itself into
        // the home it shares and the next chat ran that copy. 2.1.322 turns
        // its background updater off for either name (its bundle's `vb`),
        // and claude.ai's connectors off by `ENABLE_CLAUDEAI_MCP_SERVERS`
        // (Tony, 22 Nov: `mcp-proxy.anthropic.com` stays closed for account
        // chats). The same values go in derm's `--settings` block, whose
        // `env` a project home's settings cannot override
        // (`claude_gate::block_for`).
        "claude-code" => env.extend(
            crate::run::claude_gate::ACCOUNT_ENV
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string())),
        ),
        // Pi 1.6.0's `PI_OFFLINE` skips its startup version check, the
        // package installs and updates its settings name, and the model
        // catalog refresh (`main.js:488-491`; `core/package-manager.js:
        // 53-58, 1129-1131`; `modes/interactive/interactive-mode.js:903`):
        // nothing is installed into the project home at a start. Pi updates
        // itself only by `pi update` (`package-manager-cli.js:248`).
        "pi" => env.push(("PI_OFFLINE".to_string(), "1".to_string())),
        _ => {}
    }
    env
}

/// bash when the machine has it at /bin/bash, else /bin/sh (box research
/// BR-1).
fn posix_shell() -> &'static str {
    if std::path::Path::new("/bin/bash").is_file() {
        "/bin/bash"
    } else {
        "/bin/sh"
    }
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

/// Where an agent account's Pi chat reads derm's Pi package from (request
/// PA-2): a root-owned copy outside every home, which no chat can change.
/// Pi loads a folder named by `-e` as a package, for that run only (Pi 1.6.0
/// `dist/main.js:636`, `core/resource-loader.js:386`,
/// `core/package-manager.js:790-802`), so nothing is written into the
/// project home, where the chat could take it out again.
/// Node's module compile cache off (`NODE_DISABLE_COMPILE_CACHE`, Node 22's
/// `module.enableCompileCache` docs; run on 22.23.5).
const NODE_CACHE_OFF: (&str, &str) = ("NODE_DISABLE_COMPILE_CACHE", "1");
pub(crate) const PI_PACKAGE: &str = "/usr/local/lib/derm/derm-pi";

/// Codex's key for a hook from its session flags (`-c`): the synthetic
/// layer path (Codex 0.167.2 `hooks/src/engine/discovery.rs:472`, resolved
/// against `/` by `utils/absolute-path/src/lib.rs:46-57`) and the event,
/// group and handler (`hooks/src/lib.rs:125-135`).
const CODEX_FLAGS_KEY: &str = "/<session-flags>/config.toml";

/// How derm's gate reaches an agent account's chat (request PA-2): words
/// for the harness's command line, variables for it, and whether the gate
/// is there and blocks a call when it fails (`run.start`'s `gate.expected`,
/// `boundary::probe::gate_holds`'s meaning).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Gate {
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub expected: bool,
    /// For `run.start`: `session-flags`, `cli-package`, `settings` or `none`.
    pub how: &'static str,
    /// The start line.
    pub line: String,
}

/// derm's gate for an agent account's chat of `harness`. The project home
/// is the chat's to write, so a registration there could be taken out by
/// the chat between two starts; derm puts its gate on the harness's own
/// command line instead, which the chat cannot edit. `derm` is the
/// root-owned derm the helper runs (case 227). `pi_package` is a checked
/// root-owned copy of derm's Pi package, when there is one.
pub(crate) fn harness_gate(harness: &str, derm: &str, pi_package: Option<&str>) -> Gate {
    let mut g = harness_gate_only(harness, derm, pi_package);
    if harness == "codex" {
        // Box research BR-4's Codex half: Codex 0.167.2 checks for a new
        // release at start and writes `$CODEX_HOME/version.json`, the
        // project home's (`tui/src/updates.rs:27-48`,
        // `updates_cache.rs:20-22`), then offers to run the update; off by
        // its own key on its command line, beside derm's hooks, so the
        // project home's `config.toml` cannot turn it on
        // (`config_toml.rs:533`, `core/src/config/mod.rs:4316`).
        g.args.extend([
            "-c".to_string(),
            "check_for_update_on_startup=false".to_string(),
        ]);
    }
    g
}

fn harness_gate_only(harness: &str, derm: &str, pi_package: Option<&str>) -> Gate {
    match harness {
        // Claude Code's gate is derm run's own `--settings` registration,
        // whatever HOME is (`run/claude_gate.rs`); `gate.expected` comes
        // from it.
        "claude-code" => Gate {
            how: "settings",
            ..Gate::default()
        },
        "codex" => match codex_gate_args(derm) {
            Some(args) => Gate {
                args,
                env: Vec::new(),
                // Codex lets a call through when its hook fails or times out
                // (case 70; preset `failMode: open`), so the gate is there
                // but is not one that holds.
                expected: false,
                how: "session-flags",
                line: "derm run: derm's gate reaches Codex on its own command line (-c hooks, trusted there), which the chat cannot edit; Codex lets a call through when the hook fails or times out (case 70)".into(),
            },
            None => Gate {
                how: "none",
                line: format!("derm run: no derm gate for this Codex chat: {derm} is not a plain path"),
                ..Gate::default()
            },
        },
        "pi" => match pi_package {
            Some(pkg) => Gate {
                args: vec!["-e".into(), pkg.to_string()],
                // Security review PI-S1: Pi 1.6.0 loads the package's
                // `.ts` through jiti with its file cache on (loader.js:503-
                // 507 names only `moduleCache: false`; jiti 2.7.0 takes
                // `fsCache` from JITI_FS_CACHE, default true), in
                // `os.tmpdir()/jiti`, the chat's own TMPDIR. A cached file is
                // taken when its name and last line match, both computable
                // from the readable source, so one write there would replace
                // the gate for the project's next Pi chat. Off.
                // P box test, Look out for 34: Node's compile cache, which Pi
                // 1.6.0 turns on (`dist/bundle/cli.js:4`) in the same TMPDIR
                // and the next chat reads, off too.
                env: vec![
                    ("DERM_BIN".into(), derm.to_string()),
                    ("JITI_FS_CACHE".into(), "false".into()),
                    (NODE_CACHE_OFF.0.into(), NODE_CACHE_OFF.1.into()),
                ],
                expected: true,
                how: "cli-package",
                line: format!("derm run: derm's gate reaches Pi from {pkg} on its own command line (-e), which the chat cannot edit"),
            },
            None => Gate {
                how: "none",
                env: vec![(NODE_CACHE_OFF.0.into(), NODE_CACHE_OFF.1.into())],
                line: format!("derm run: NO DERM GATE for this Pi chat: Pi reads derm's package from a root-owned copy at {PI_PACKAGE} on an agent account, and there is none (sudo install -d -o root -g root -m 0755 {PI_PACKAGE} && sudo cp -r <derm>/packages/derm-pi/. {PI_PACKAGE}/); its calls run ungated"),
                ..Gate::default()
            },
        },
        _ => Gate {
            how: "none",
            line: format!("derm run: derm writes no gate for {harness} on an agent account; its calls run ungated by derm"),
            ..Gate::default()
        },
    }
}

/// derm's two Codex hooks and their trust, as one `-c hooks=...` pair, and
/// `features.hooks` on (default on in 0.167.2, `features/src/lib.rs:1469-
/// 1473`; a project home's own `config.toml` could turn it off). Codex
/// loads hooks from every config layer, its session flags too
/// (`discovery.rs:156-215`, `load_toml_hooks_from_layer` at 433-451), and
/// reads hook state from the user layer and the session flags, the later
/// winning field by field (`config_rules.rs:15-68`), so `enabled = true` and
/// derm's `trusted_hash` here outrank anything the project home's
/// `config.toml` says for these keys. A `-c` path is split on `.`
/// (`config/src/overrides.rs:22`), so the state goes in as one value. The
/// hash is Codex's own: SHA-256 of the key-sorted JSON of `{event_name,
/// matcher, hooks: [the normalized handler]}` (`discovery.rs:972-990`,
/// `config/src/fingerprint.rs:54-66`; the same formula as derm's Codex
/// plugin contract check, `tests/cli-contract/checks/dermCodex.mjs`, run at
/// 0.163.0). `None` when `derm` is not a plain absolute path.
pub(crate) fn codex_gate_args(derm: &str) -> Option<Vec<String>> {
    if !derm.starts_with('/')
        || derm.chars().any(|c| {
            c.is_control() || matches!(c, '\'' | '"' | '\\' | '$' | '`' | '\u{2018}' | '\u{2019}')
        })
    {
        return None;
    }
    // A derm that does not start would exit 127, which Codex reads as a
    // non-blocking error and lets the call through. Codex blocks on exit 2
    // only with a reason on stderr; exit 2 with an empty stderr is a failed
    // hook and the call runs (`hooks/src/events/pre_tool_use.rs:268-283`,
    // security review PI-S2). So any exit but 0 prints a reason and exits 2.
    // A hook killed with bash itself (SIGINT to the shell) still has no
    // status and fails open, which is why `expected` stays false.
    let pre = format!(
        "'{derm}' hook codex pre || {{ echo 'derm gate: no decision, blocked' >&2; exit 2; }}"
    );
    let post = format!("'{derm}' hook codex post");
    let events = [
        ("PreToolUse", "pre_tool_use", pre, 120u64),
        ("PostToolUse", "post_tool_use", post, 30u64),
    ];
    let mut hooks = toml_edit::InlineTable::new();
    let mut state = toml_edit::InlineTable::new();
    for (event, label, command, timeout) in events.iter() {
        let event: &str = event;
        let mut handler = toml_edit::InlineTable::new();
        handler.insert("type", "command".into());
        handler.insert("command", command.as_str().into());
        handler.insert("timeout", i64::try_from(*timeout).ok()?.into());
        let mut handlers = toml_edit::Array::new();
        handlers.push(handler);
        let mut group = toml_edit::InlineTable::new();
        group.insert("matcher", "*".into());
        group.insert("hooks", toml_edit::Value::Array(handlers));
        let mut groups = toml_edit::Array::new();
        groups.push(group);
        hooks.insert(event, toml_edit::Value::Array(groups));
        let mut st = toml_edit::InlineTable::new();
        st.insert("enabled", true.into());
        st.insert(
            "trusted_hash",
            codex_hook_hash(label, "*", command, *timeout).into(),
        );
        state.insert(
            format!("{CODEX_FLAGS_KEY}:{label}:0:0"),
            toml_edit::Value::InlineTable(st),
        );
    }
    hooks.insert("state", toml_edit::Value::InlineTable(state));
    Some(vec![
        "-c".into(),
        format!(
            "hooks={}",
            toml_edit::Value::InlineTable(hooks).to_string().trim()
        ),
        "-c".into(),
        "features.hooks=true".into(),
    ])
}

/// Codex 0.167.2's trust hash for one command hook (`hook_hash`,
/// `discovery.rs:972-990`): `commandWindows` and `statusMessage` are `None`
/// and left out by TOML, `async` is false, the timeout as normalized.
pub(crate) fn codex_hook_hash(
    event_label: &str,
    matcher: &str,
    command: &str,
    timeout: u64,
) -> String {
    use sha2::{Digest, Sha256};
    // serde_json's map is ordered by key (no `preserve_order` feature), as
    // Codex's `sort_all_objects` makes it.
    let identity = serde_json::json!({
        "event_name": event_label,
        "matcher": matcher,
        "hooks": [{"type": "command", "command": command, "timeout": timeout, "async": false}],
    });
    let bytes = serde_json::to_vec(&identity).unwrap_or_default();
    let hash = Sha256::digest(&bytes);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// `PI_PACKAGE` when it is derm's Pi package and only root can change it:
/// the folder and every folder above it root's and not group- or
/// world-writable, and every entry under it the same, no link among them
/// (at most 2,000 entries, 8 levels), with a `package.json` named
/// `@aetiusgular/derm-pi`.
pub(crate) fn pi_package(dir: &str) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let root = std::path::Path::new(dir);
    let closed = |p: &std::path::Path| -> Result<std::fs::Metadata, String> {
        let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is a link, not root's, or others may write it",
                p.display()
            ));
        }
        Ok(m)
    };
    for p in root.ancestors() {
        closed(p)?;
    }
    let mut seen = 0usize;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((d, depth)) = stack.pop() {
        for e in std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let e = e.map_err(|e| format!("{}: {e}", d.display()))?;
            seen += 1;
            if seen > 2_000 {
                return Err(format!("{dir} holds more than 2,000 entries"));
            }
            let m = closed(&e.path())?;
            if m.is_dir() {
                if depth >= 8 {
                    return Err(format!("{dir} is more than 8 folders deep"));
                }
                stack.push((e.path(), depth + 1));
            } else if !m.is_file() {
                return Err(format!("{} is not a file or a folder", e.path().display()));
            }
        }
    }
    let text = std::fs::read_to_string(root.join("package.json"))
        .map_err(|e| format!("{dir}/package.json: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{dir}/package.json: {e}"))?;
    if v.get("name").and_then(serde_json::Value::as_str) != Some("@aetiusgular/derm-pi") {
        return Err(format!("{dir}/package.json is not derm's Pi package"));
    }
    Ok(dir.to_string())
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

    /// Box research BR-4: the account's Claude Code ran its native updater
    /// into the shared home and the next chat ran that copy. The harness is
    /// named by path (`chat::root_install`); here each harness's own
    /// updater is turned off too, read at the version in use:
    /// Claude Code 2.1.322 (`DISABLE_AUTOUPDATER` or `DISABLE_UPDATES`,
    /// its bundle's `vb`), Codex 0.167.2 (`check_for_update_on_startup`,
    /// `config_toml.rs:533`, `tui/src/updates.rs:27-28`), Pi 1.6.0
    /// (`PI_OFFLINE`, `main.js:488-491`, `core/package-manager.js:53-58`).
    /// Claude Code's claude.ai connectors off too (Tony, 22 Nov: keep
    /// `mcp-proxy.anthropic.com` closed for account chats).
    #[test]
    fn br_4_an_account_chat_turns_each_harnesss_updater_off() {
        let id = ProjectId::of_real_path("/srv/a");
        let f = vec!["/srv/a".to_string()];
        let has =
            |env: &[(String, String)], k: &str, v: &str| env.iter().any(|(a, b)| a == k && b == v);
        let cc = project_env(&chat(&id, &f, "claude-code"));
        for (k, v) in [
            ("DISABLE_AUTOUPDATER", "1"),
            ("DISABLE_UPDATES", "1"),
            ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"),
        ] {
            assert!(has(&cc, k, v), "{k}: {cc:?}");
        }
        let pi = project_env(&chat(&id, &f, "pi"));
        assert!(has(&pi, "PI_OFFLINE", "1"), "{pi:?}");
        assert!(!has(&pi, "DISABLE_UPDATES", "1"));
        for derm in ["/usr/local/bin/derm", "/bad path/derm"] {
            let g = harness_gate("codex", derm, None);
            assert!(
                g.args
                    .windows(2)
                    .any(|w| w[0] == "-c" && w[1] == "check_for_update_on_startup=false"),
                "{derm}: {:?}",
                g.args
            );
        }
        assert!(harness_gate("pi", "/usr/local/bin/derm", None)
            .args
            .is_empty());
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

    /// Request PA-2: Codex's hooks and their trust on its command line, in
    /// the form Codex 0.167.2 reads; the hash formula is Codex's own,
    /// checked against its own fingerprint test (`config/src/
    /// fingerprint_tests.rs:6-26`).
    #[test]
    fn pa_2_codex_gets_derms_hooks_and_their_trust_on_its_command_line() {
        use sha2::{Digest, Sha256};
        // Codex's own fixture, through the same key-sorted JSON.
        let fixture = serde_json::json!({"rows": [{"z": 2, "a": 1}, {"z": 4, "a": 3}],
            "nested": {"z": "text", "a": true}});
        let h = Sha256::digest(serde_json::to_vec(&fixture).unwrap());
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "a5e4c8fbdbc75d185b0f2b5291bfb2de10e8c523d6c89248876fd78a97c83176"
        );
        let args = codex_gate_args("/usr/local/bin/derm").unwrap();
        assert_eq!(args[0], "-c");
        assert_eq!(
            args[2..],
            ["-c".to_string(), "features.hooks=true".to_string()]
        );
        let value = args[1].strip_prefix("hooks=").unwrap();
        let doc: toml_edit::DocumentMut = format!("x = {value}").parse().unwrap();
        let t = doc["x"].as_inline_table().unwrap();
        let pre = &t
            .get("PreToolUse")
            .unwrap()
            .as_array()
            .unwrap()
            .get(0)
            .unwrap();
        let pre = pre.as_inline_table().unwrap();
        assert_eq!(pre.get("matcher").unwrap().as_str(), Some("*"));
        let h0 = pre
            .get("hooks")
            .unwrap()
            .as_array()
            .unwrap()
            .get(0)
            .unwrap()
            .as_inline_table()
            .unwrap();
        let cmd = h0.get("command").unwrap().as_str().unwrap();
        // Security review PI-S2: exit 2 blocks only with a reason on
        // stderr (Codex 0.167.2 `hooks/src/events/pre_tool_use.rs:268-283`).
        assert_eq!(
            cmd,
            "'/usr/local/bin/derm' hook codex pre || { echo 'derm gate: no decision, blocked' >&2; exit 2; }"
        );
        assert_eq!(h0.get("timeout").unwrap().as_integer(), Some(120));
        let state = t.get("state").unwrap().as_inline_table().unwrap();
        let key = "/<session-flags>/config.toml:pre_tool_use:0:0";
        let st = state.get(key).unwrap().as_inline_table().unwrap();
        assert_eq!(st.get("enabled").unwrap().as_bool(), Some(true));
        assert_eq!(
            st.get("trusted_hash").unwrap().as_str().unwrap(),
            codex_hook_hash("pre_tool_use", "*", cmd, 120)
        );
        // The identity Codex hashes, by hand.
        let want = format!(
            "{{\"event_name\":\"pre_tool_use\",\"hooks\":[{{\"async\":false,\"command\":\"{cmd}\",\"timeout\":120,\"type\":\"command\"}}],\"matcher\":\"*\"}}"
        );
        let h = Sha256::digest(want.as_bytes());
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            codex_hook_hash("pre_tool_use", "*", cmd, 120),
            format!("sha256:{hex}")
        );
        assert!(state
            .get("/<session-flags>/config.toml:post_tool_use:0:0")
            .is_some());
        for bad in ["derm", "/x/'y/derm", "/x/$(y)/derm", "/x/\"y", "/x/`y`"] {
            assert!(codex_gate_args(bad).is_none(), "{bad}");
        }
    }

    /// Request PA-2: what each harness gets, and whether the gate is one
    /// that holds (`gate.expected`): Codex's fails open, Pi's blocks, and a
    /// Pi chat with no root-owned package says so and expects none.
    #[test]
    fn pa_2_gate_expected_is_true_only_where_derms_gate_runs_and_blocks() {
        let d = "/usr/local/bin/derm";
        let c = harness_gate("codex", d, None);
        assert_eq!((c.expected, c.how), (false, "session-flags"));
        // The hooks' two `-c` pairs and BR-4's update check off.
        assert_eq!(c.args.len(), 6);
        let p = harness_gate("pi", d, Some(PI_PACKAGE));
        assert_eq!((p.expected, p.how), (true, "cli-package"));
        assert_eq!(p.args, vec!["-e".to_string(), PI_PACKAGE.to_string()]);
        // Security review PI-S1: jiti's transform cache, which Pi 1.6.0
        // leaves on and keeps in the chat's own TMPDIR, is off.
        assert!(
            p.env
                .contains(&("JITI_FS_CACHE".to_string(), "false".to_string())),
            "{:?}",
            p.env
        );
        assert_eq!(
            p.env,
            vec![
                ("DERM_BIN".to_string(), d.to_string()),
                ("JITI_FS_CACHE".to_string(), "false".to_string()),
                ("NODE_DISABLE_COMPILE_CACHE".to_string(), "1".to_string())
            ]
        );
        // P box test, Look out for 34 (red first): Pi 1.6.0 turns Node's
        // compile cache on (`dist/bundle/cli.js:4`, `enableCompileCache()`),
        // in `os.tmpdir()/node-compile-cache`, the chat's own TMPDIR, read by
        // the project's next Pi chat as it loads Pi and derm's package. Off,
        // with or without derm's package (Node 22.23.5, run: status 3,
        // "Disabled by NODE_DISABLE_COMPILE_CACHE").
        let none = harness_gate("pi", d, None);
        assert!(
            none.env
                .contains(&("NODE_DISABLE_COMPILE_CACHE".to_string(), "1".to_string())),
            "{:?}",
            none.env
        );
        assert_eq!((none.expected, none.how), (false, "none"));
        assert!(
            none.args.is_empty() && none.line.contains("NO DERM GATE"),
            "{}",
            none.line
        );
        let other = harness_gate("gemini", d, None);
        assert!(!other.expected && other.args.is_empty());
        assert_eq!(harness_gate("claude-code", d, None).how, "settings");
    }

    #[test]
    fn pa_2_a_pi_package_others_can_write_or_not_root_s_is_refused() {
        // This workspace's temp folder is no root-owned tree with derm's
        // name: refused, and the reason names the path.
        let t = std::env::temp_dir().join(format!("pa2-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        std::fs::write(t.join("package.json"), r#"{"name":"@aetiusgular/derm-pi"}"#).unwrap();
        let r = pi_package(&t.to_string_lossy());
        assert!(r.is_err(), "{r:?}");
        let _ = std::fs::remove_dir_all(&t);
        assert!(pi_package("/no/such/derm-pi").is_err());
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
    fn br_1_every_harness_gets_a_posix_shell_not_the_accounts_no_login_shell() {
        // The account's passwd shell is /usr/sbin/nologin (box research
        // BR-1), and sudo hands it on as SHELL; the chat's is a real shell.
        let id = ProjectId::of_real_path("/srv/a");
        for h in ["claude-code", "codex", "pi", "other"] {
            let env = project_env(&chat(&id, &[], h));
            let shell = env
                .iter()
                .find(|(k, _)| k == "SHELL")
                .map(|(_, v)| v.as_str());
            assert!(
                matches!(shell, Some("/bin/bash") | Some("/bin/sh")),
                "{h}: {shell:?}"
            );
        }
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
