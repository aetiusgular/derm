//! Whose input it is (`contracts/hook-dialects.md` section 9.2; case 109,
//! BCR-7). Cursor's CLI runs Claude Code's hooks as third-party hooks, an
//! enabled plugin's included, with its own camelCase event and its
//! `cursor_version` (https://cursor.com/docs/reference/third-party-hooks;
//! seen by run on Cursor CLI 2026.10.22, Mac test w4, MW4-5; Cursor
//! 2026.11.10-731fb78's inputs recorded by the wave 5b base, part 2). The
//! TypeScript reads those two marks together (`runByCursor` in
//! `packages/derm-claude-plugin/src/hook.ts`, fix pass 1's review FP4-S2);
//! this file is its port.
//!
//! Grok Build 1.0.77 runs the hooks in `~/.claude/settings.json` too, by
//! default (BCR-7, read in its binary by the wave 5b base). Recorded by this
//! lane on 10 Nov (V, run: Grok 1.0.77 `50ca579fa996`, `-p --yolo` against
//! the fake chat server, a recording hook in Grok's own `hooks/own.json` and
//! one in Claude Code's `settings.json`): both hooks got the same input,
//! Grok's own, which carries both spellings, Claude Code's
//! (`hook_event_name: "PreToolUse"`, `tool_name`, `tool_input`, ...) and
//! Grok's (`hookEventName: "pre_tool_use"`, `toolName`, `toolInput`,
//! `toolInputTruncated`, `workspaceRoot`, ...). Grok's marks here are its
//! snake-case event under `hookEventName` and its `toolInputTruncated`, both;
//! Claude Code 2.1.322's input carries neither (note BC section 2, and the
//! 48 recorded Claude Code calls in `contracts/fixtures/hook-cases/5bA.json`).
//!
//! When derm's own gate for the agent that ran the hook is registered and
//! fails closed, this hook defers (no decision, no record), so the gate runs
//! once per call (case 75); otherwise it blocks and names the fix. It never
//! decides in Claude Code's dialect for another agent's input.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::gate::daemon::Env;

/// Input Cursor sends when it runs a Claude Code hook: its camelCase event
/// and its `cursor_version`, both.
pub fn run_by_cursor(input: &Map<String, Value>) -> bool {
    matches!(
        input.get("hook_event_name").and_then(Value::as_str),
        Some("preToolUse" | "postToolUse")
    ) && input.get("cursor_version").is_some_and(Value::is_string)
}

/// Input Grok sends when it runs a Claude Code hook: Grok's snake-case
/// event under `hookEventName` and its `toolInputTruncated`, both.
pub fn run_by_grok(input: &Map<String, Value>) -> bool {
    matches!(
        input.get("hookEventName").and_then(Value::as_str),
        Some("pre_tool_use" | "post_tool_use")
    ) && input
        .get("toolInputTruncated")
        .is_some_and(Value::is_boolean)
}

const MAX_HOOKS_FILE_BYTES: u64 = 1024 * 1024;

#[cfg(unix)]
fn closed(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let uid = derm_core::platform::real_user();
    (meta.uid() == uid || meta.uid() == 0) && meta.mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn closed(_meta: &std::fs::Metadata) -> bool {
    // The TypeScript read no owner on Windows (Node reports uid 0 and a
    // mode from the read-only bit, case 225); here nothing counts there.
    false
}

/// A plain path, as `--hook` and `--node` take them: no `$`, backtick or
/// `\` a shell would expand, and no `.` or `..` part (re-review FP5-R3).
fn plain(p: &str) -> bool {
    !p.is_empty()
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/@+~-".contains(c))
        && !p.split('/').any(|part| part == ".." || part == ".")
}

/// The wave 5b form lane 5bF writes: `"<abs derm>" hook <agent> <event>`,
/// where `<abs derm>` is this very program (same real path) and a file no
/// one else can write. An entry naming another program, or a `derm` found
/// on PATH, is not derm's gate (case 227).
pub fn is_derm_rust_command(command: &str, agent: &str, me: Option<&Path>) -> bool {
    let words: Vec<&str> = command.split_whitespace().collect();
    let [prog, "hook", a, event] = words.as_slice() else {
        return false;
    };
    if *a != agent {
        return false;
    }
    let events = super::super::AGENTS
        .iter()
        .find(|(a, _, _)| *a == agent)
        .map(|(_, _, e)| *e)
        .unwrap_or(&[]);
    if !events.contains(event) {
        return false;
    }
    let prog = prog
        .strip_prefix('"')
        .and_then(|p| p.strip_suffix('"'))
        .unwrap_or(prog);
    if !plain(prog) || !prog.starts_with('/') {
        return false;
    }
    let (Some(me), Ok(real)) = (me, std::fs::canonicalize(prog)) else {
        return false;
    };
    let Ok(me) = std::fs::canonicalize(me) else {
        return false;
    };
    real == me && std::fs::metadata(&real).is_ok_and(|m| m.is_file() && closed(&m))
}

/// A hooks file as JSON, when it is a regular file under 1 MiB.
fn read_json(file: &Path) -> Option<Value> {
    let st = std::fs::metadata(file).ok()?;
    if !st.is_file() || st.len() > MAX_HOOKS_FILE_BYTES {
        return None;
    }
    serde_json::from_str(&std::fs::read_to_string(file).ok()?).ok()
}

/// `<node> --no-warnings "<abs>/bin/derm-hook.mjs" <agent> pre`, the line
/// `derm connect <agent> --gate` writes for the Claude-compat package
/// (`hookCommand` in `registration.ts`), where the node and the hook file
/// pass the checks `watch::register` applies to Cursor's, and the
/// package is derm-hooks-claude-compat.
#[cfg(unix)]
pub fn is_derm_compat_node_command(command: &str, agent: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let c = command.trim_end();
    let Some(rest) = c.strip_suffix(&format!("\" {agent} pre")) else {
        return false;
    };
    let Some((node, file)) = rest.split_once(" --no-warnings \"") else {
        return false;
    };
    if !plain(node)
        || !plain(file)
        || !file.starts_with('/')
        || !file.ends_with("/bin/derm-hook.mjs")
    {
        return false;
    }
    let uid = derm_core::platform::real_user();
    let closed = |m: &std::fs::Metadata| (m.uid() == uid || m.uid() == 0) && m.mode() & 0o022 == 0;
    let check = || -> Option<bool> {
        if node != "node" {
            let name = node.rsplit('/').next().unwrap_or("");
            if !node.starts_with('/') || !name.starts_with("node") {
                return Some(false);
            }
            let m = std::fs::metadata(std::fs::canonicalize(node).ok()?).ok()?;
            if !m.is_file() || !closed(&m) {
                return Some(false);
            }
        }
        let m = std::fs::symlink_metadata(file).ok()?;
        if !m.is_file() || !closed(&m) {
            return Some(false);
        }
        let pkg = Path::new(file).parent()?.parent()?.join("package.json");
        let pm = std::fs::symlink_metadata(&pkg).ok()?;
        if !pm.is_file() || !closed(&pm) || pm.len() > 1024 * 1024 {
            return Some(false);
        }
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&pkg).ok()?).ok()?;
        Some(v["name"] == "@aetiusgular/derm-hooks-claude-compat")
    };
    check().unwrap_or(false)
}

#[cfg(not(unix))]
pub fn is_derm_compat_node_command(_command: &str, _agent: &str) -> bool {
    false
}

/// derm's Grok gate in `~/.grok/hooks/derm.json` (the file `derm connect
/// grok --gate` writes, `registration.ts`): a PreToolUse group with derm's
/// grok command, and every such entry `failClosed` (Grok 1.0.71 and later
/// read it).
pub fn grok_gate_registered(env: &Env) -> bool {
    let Some(home) = env.raw("HOME").filter(|h| Path::new(h).is_absolute()) else {
        return false;
    };
    let Some(v) = read_json(
        &PathBuf::from(home)
            .join(".grok")
            .join("hooks")
            .join("derm.json"),
    ) else {
        return false;
    };
    let me = std::env::current_exe().ok();
    let ours: Vec<&Value> = v
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|g| g.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter(|h| {
            h.get("command").and_then(Value::as_str).is_some_and(|c| {
                is_derm_compat_node_command(c, "grok")
                    || is_derm_rust_command(c, "grok", me.as_deref())
            })
        })
        .collect();
    !ours.is_empty()
        && ours
            .iter()
            .all(|h| h.get("failClosed") == Some(&Value::Bool(true)))
}

/// What Claude Code's hook answers when Grok ran it: no decision when
/// derm's Grok gate decides this call, else a block that names the fix.
pub fn grok_run(pre: bool, env: &Env) -> super::Reply {
    if !pre {
        return super::none();
    }
    if grok_gate_registered(env) {
        return super::none();
    }
    super::claude_code::block_pre(
        "Grok ran derm's Claude Code hook (Grok's Claude Code hook import), and derm's own Grok gate is not registered in ~/.grok/hooks/derm.json; run derm connect grok --gate --write, or set hooks = false under [compat.claude] in ~/.grok/config.toml",
    )
}

/// derm's two Cursor entries (`connect/gates.json`) in
/// `~/.cursor/hooks.json`, each `failClosed` (`cursorGateRegistered`).
/// `HOME` as the hook's environment gives it, absolute only.
pub fn cursor_gate_registered(env: &Env) -> bool {
    let Some(home) = env.raw("HOME").filter(|h| Path::new(h).is_absolute()) else {
        return false;
    };
    let Some(v) = read_json(&PathBuf::from(home).join(".cursor").join("hooks.json")) else {
        return false;
    };
    let me = std::env::current_exe().ok();
    ["preToolUse", "beforeMCPExecution"].iter().all(|event| {
        let Some(list) = v
            .get("hooks")
            .and_then(|h| h.get(*event))
            .and_then(Value::as_array)
        else {
            return false;
        };
        let ours: Vec<&Value> = list
            .iter()
            .filter(|e| {
                // The node form `derm connect cursor --gate` writes today, by
                // the check `derm status` uses (`watch::register`, held equal
                // to the TypeScript's `isDermCursorCommand`), or the wave 5b
                // form lane 5bF will write.
                crate::watch::register::is_derm_cursor_entry(e)
                    || e.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| is_derm_rust_command(c, "cursor", me.as_deref()))
            })
            .collect();
        !ours.is_empty()
            && ours
                .iter()
                .all(|e| e.get("failClosed") == Some(&Value::Bool(true)))
    })
}

/// What Claude Code's hook answers when Cursor ran it (`cursorRun`).
pub fn cursor_run(pre: bool, env: &Env) -> super::Reply {
    if !pre {
        return super::none();
    }
    if cursor_gate_registered(env) {
        return super::Reply {
            stdout: "{}\n".into(),
            stderr: String::new(),
            exit: 0,
        };
    }
    super::claude_code::block_pre(
        "Cursor ran derm's Claude Code hook (Cursor's third-party hooks), and derm's own Cursor gate is not registered in ~/.cursor/hooks.json; run derm connect cursor --gate --hook <derm-hooks-native folder> --write, or turn off Third-Party Imports in Cursor's settings",
    )
}
