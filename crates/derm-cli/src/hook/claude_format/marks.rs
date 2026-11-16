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

/// What follows the single-quoted path in a Windows row's PowerShell line
/// (gates.json's Codex and Cursor Windows rows): the call operator's words,
/// then, when derm.exe did not start (`$LASTEXITCODE` is `$null`, which
/// `exit` would make 0, an allow), a reason and `missing_exit`; else derm's
/// own exit code, which `-Command` would turn into 1 (fix pass 8, run on
/// the box; Codex 0.167.2 and 0.169.0 and Cursor run Windows hooks through
/// PowerShell: `shell_detect.rs:363-365`, cursor.com/docs/hooks).
pub fn ps_tail(agent: &str, event: &str, missing_exit: u8) -> String {
    format!(
        " hook {agent} {event}; if ($null -eq $LASTEXITCODE) {{ [Console]::Error.WriteLine('derm: derm.exe did not start'); exit {missing_exit} }}; exit $LASTEXITCODE"
    )
}

/// derm's PowerShell line for `agent`'s `event`: `& '<abs derm>'` and
/// [`ps_tail`] with exit 2, where the path holds nothing that ends a
/// single-quoted string (`connect::gate::ps_reads`) and is this very program
/// (same real path), a file only its owner may write.
/// Elsewhere a shell runs the line, where `&` at its start is a syntax
/// error, so it is never a gate that can run there (fix pass 9's review,
/// F3); [`ps_command_path`] is the parse, on every system.
pub fn is_derm_ps_command(command: &str, agent: &str, event: &str, me: Option<&Path>) -> bool {
    cfg!(windows) && ps_command_path(command, agent, event).is_some_and(|p| is_me(p, me))
}

/// The path in derm's PowerShell line for `agent`'s `event`, when the line
/// is exactly `& '<path>'` and [`ps_tail`] with exit 2, the path is
/// absolute and holds nothing that ends a single-quoted string.
pub fn ps_command_path<'a>(command: &'a str, agent: &str, event: &str) -> Option<&'a str> {
    let rest = command.strip_prefix("& '")?;
    let (path, tail) = rest.split_once('\'')?;
    (tail == ps_tail(agent, event, 2)
        && crate::connect::gate::ps_reads(path).is_none()
        && (Path::new(path).is_absolute() || path_is_windows_absolute(path)))
    .then_some(path)
}

/// `C:\...` or `\\server\...`, absolute on Windows whatever this system is
/// (so the parse reads the same in a Unix test).
fn path_is_windows_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
        || p.starts_with("\\\\")
}

/// `path` is this very program (same real path), a file only its owner may
/// write.
fn is_me(path: &str, me: Option<&Path>) -> bool {
    let (Some(me), Ok(real)) = (me, std::fs::canonicalize(path)) else {
        return false;
    };
    let Ok(me) = std::fs::canonicalize(me) else {
        return false;
    };
    real == me && owner_alone_writes(&real)
}

#[cfg(unix)]
fn owner_alone_writes(real: &Path) -> bool {
    std::fs::metadata(real).is_ok_and(|m| m.is_file() && closed(&m))
}

#[cfg(windows)]
fn owner_alone_writes(real: &Path) -> bool {
    real.is_file() && derm_core::platform::windows::only_owner_writes(real)
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
    let Some(home) = home_in(env, cfg!(windows)) else {
        return false;
    };
    let Some(v) = read_json(&home.join(".grok").join("hooks").join("derm.json")) else {
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

/// The home folder as the hook's environment gives it, absolute only:
/// `HOME`, and on Windows `USERPROFILE`, where `derm connect` writes
/// (`derm_core::runtime::home_dir`). Until fix pass 9's review (F1) this read
/// `HOME` alone, so on Windows, where it is usually unset, Cursor running
/// derm's Claude Code hook blocked every call with derm's Cursor gate
/// registered (run on the box).
pub fn home_in(env: &Env, windows: bool) -> Option<PathBuf> {
    let key = if windows { "USERPROFILE" } else { "HOME" };
    env.raw(key)
        .filter(|h| Path::new(h).is_absolute())
        .map(PathBuf::from)
}

/// derm's two Cursor entries (`connect/gates.json`) in
/// `~/.cursor/hooks.json`, each `failClosed` (`cursorGateRegistered`).
pub fn cursor_gate_registered(env: &Env) -> bool {
    let Some(home) = home_in(env, cfg!(windows)) else {
        return false;
    };
    let Some(v) = read_json(&home.join(".cursor").join("hooks.json")) else {
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
                    || e.get("command").and_then(Value::as_str).is_some_and(|c| {
                        is_derm_rust_command(c, "cursor", me.as_deref())
                            // Fix pass 9: the Windows row's PowerShell line.
                            || is_derm_ps_command(c, "cursor", "pre", me.as_deref())
                    })
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
        "Cursor ran derm's Claude Code hook (Cursor's third-party hooks), and derm's own Cursor gate is not registered in ~/.cursor/hooks.json; run derm connect cursor --gate --write, or turn off Third-Party Imports in Cursor's settings",
    )
}

#[cfg(test)]
mod fp9_tests {
    use super::*;

    /// Fix pass 9's review, F1: the hook finds the home `derm connect`
    /// writes to, `USERPROFILE` on Windows (where `HOME` is usually unset).
    #[test]
    fn fp9_the_home_is_userprofile_on_windows_and_home_elsewhere() {
        let abs = if cfg!(windows) {
            "C:\\Users\\u"
        } else {
            "/home/u"
        };
        let only_profile = Env::of(&[("USERPROFILE", abs)]);
        let only_home = Env::of(&[("HOME", abs)]);
        assert_eq!(home_in(&only_profile, true), Some(PathBuf::from(abs)));
        assert_eq!(home_in(&only_home, true), None);
        assert_eq!(home_in(&only_home, false), Some(PathBuf::from(abs)));
        assert_eq!(home_in(&only_profile, false), None);
        assert_eq!(home_in(&Env::of(&[("HOME", "rel")]), false), None);
    }

    /// The parse of derm's PowerShell line: exact prefix and tail, an
    /// absolute path PowerShell reads as written.
    #[test]
    fn fp9_the_powershell_line_parses_only_in_derms_exact_form() {
        let tail = ps_tail("cursor", "pre", 2);
        let ok = format!("& 'C:\\Users\\u\\.local\\bin\\derm.exe'{tail}");
        assert_eq!(
            ps_command_path(&ok, "cursor", "pre"),
            Some("C:\\Users\\u\\.local\\bin\\derm.exe")
        );
        for bad in [
            format!("& 'derm.exe'{tail}"),
            format!("& 'C:\\a\u{2019}b\\derm.exe'{tail}"),
            format!("& 'C:\\derm.exe'{tail}; whoami"),
            format!(" & 'C:\\derm.exe'{tail}"),
            format!("& 'C:\\derm.exe'{}", ps_tail("cursor", "pre", 0)),
            format!("& 'C:\\derm.exe'{}", ps_tail("codex", "pre", 2)),
            "& 'C:\\derm.exe' hook cursor pre; exit $LASTEXITCODE".to_string(),
        ] {
            assert_eq!(ps_command_path(&bad, "cursor", "pre"), None, "{bad}");
        }
        // Off Windows it is never derm's gate, whatever it names.
        if !cfg!(windows) {
            let me = std::env::current_exe().unwrap();
            let line = format!("& '{}'{tail}", me.display());
            assert!(!is_derm_ps_command(&line, "cursor", "pre", Some(&me)));
        }
    }
}
