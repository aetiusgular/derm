//! `derm run claude-code` registers derm's own gate (fix pass 6; note BE
//! section 1.5, option (e), Tony's call of 15 Nov 2026).
//!
//! Until now a Claude Code chat under `derm run` was gated by derm's plugin,
//! whose hooks file starts `/bin/sh` on `hooks/derm-gate.sh`. On Windows
//! there is no `/bin/sh`: Claude Code 2.1.322's exec form spawns the command
//! with `child_process.spawn` and no shell, gets ENOENT, and with
//! `onFailure: "block"` blocks every call (note BE section 1.1, run on the
//! box). Now `derm run` puts derm's gate in its own `--settings` block, by
//! the absolute path of the derm that runs the chat, in exec form, with
//! `onFailure: "block"`, and turns derm's plugin off for the chat
//! (`enabledPlugins: {"derm@derm": false}`), on every system:
//!
//! - one gate per call: plugin hooks and settings hooks are two hooks
//!   (Claude Code dedupes on `pluginRoot ?? skillRoot ?? settingsSource +
//!   command`), and with the plugin off a call made one approval record (a
//!   cloud probe against the real 2.1.322, note BE section 1.2);
//! - the gate is the derm that runs the chat, never one found on PATH or a
//!   copy that went stale (note BE section 1.4);
//! - no launcher and no shell.
//!
//! Claude Code reads one `--settings`, the last on its command line (case
//! 246). So the block derm adds last holds everything a chat's `--settings`
//! held before it: the user's own (when it is JSON; a file path is refused,
//! since derm would have to read and merge it), the OTel export's
//! `otelHeadersHelper` and the Standard tier's sandbox block, in their order,
//! then derm's hooks. A user's hooks are kept beside derm's.
//!
//! Not under sbx: the harness runs in the VM, where this host's derm does
//! not exist, and the sbx kit's hook is the gate (wave 5b's 5bF).

use serde_json::{json, Map, Value};

use super::plan::Plan;

/// derm's plugin, as `claude plugin install derm@derm` names it.
pub const PLUGIN: &str = "derm@derm";

/// Where Claude Code's own arguments start in `plan.args`: 0 when the plan
/// starts Claude Code itself, after `-- <command>` under srt.
fn start(plan: &Plan) -> usize {
    if plan.program == "srt" {
        if let Some(p) = plan.args.iter().position(|a| a == "--") {
            return (p + 2).min(plan.args.len());
        }
    }
    0
}

/// Every `--settings` value in `words`, in order.
fn settings_values(words: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        if words[i] == "--settings" {
            if let Some(v) = words.get(i + 1) {
                out.push(v.as_str());
            }
            i += 2;
            continue;
        }
        if let Some(v) = words[i].strip_prefix("--settings=") {
            out.push(v);
        }
        i += 1;
    }
    out
}

/// Refuses, before anything starts, a `--settings` among the user's own
/// words that is not a JSON object: derm adds the last `--settings`, and
/// Claude Code reads only that one, so the user's must be merged into it.
pub fn check_user_settings(rest: &[String]) -> Result<(), String> {
    for v in settings_values(rest) {
        if !matches!(serde_json::from_str::<Value>(v), Ok(Value::Object(_))) {
            return Err(format!(
                "Claude Code reads only the last --settings on its command line, and derm adds its gate there; a --settings that is not JSON ({} characters) cannot be merged into it: pass the settings as JSON, or put them in ~/.claude/settings.json",
                v.chars().count()
            ));
        }
    }
    Ok(())
}

/// derm's hook entries for Claude Code, in exec form: `derm hook claude-code
/// pre` blocks when it fails or times out; `post` records the call and
/// redacts its result (the plugin's `hooks/hooks.json`, with the plugin's
/// launcher replaced by derm's own absolute path).
pub fn hooks(derm: &str) -> Value {
    json!({
        "PreToolUse": [{
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": derm,
                "args": ["hook", "claude-code", "pre"],
                "timeout": 120,
                "onFailure": "block"
            }]
        }],
        "PostToolUse": [{
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": derm,
                "args": ["hook", "claude-code", "post"],
                "timeout": 30
            }]
        }]
    })
}

/// Merges `add` into `into`: `hooks` per event, keeping every entry once;
/// `enabledPlugins` per plugin; any other key replaced, as a later
/// `--settings` would replace it.
fn merge(into: &mut Map<String, Value>, add: &Map<String, Value>) {
    for (k, v) in add {
        match (k.as_str(), into.get_mut(k), v) {
            ("hooks", Some(Value::Object(have)), Value::Object(more)) => {
                for (event, entries) in more {
                    let list = have
                        .entry(event.clone())
                        .or_insert_with(|| Value::Array(Vec::new()));
                    match (list, entries) {
                        (Value::Array(list), Value::Array(entries)) => {
                            for e in entries {
                                if !list.contains(e) {
                                    list.push(e.clone());
                                }
                            }
                        }
                        (slot, other) => *slot = other.clone(),
                    }
                }
            }
            ("enabledPlugins", Some(Value::Object(have)), Value::Object(more)) => {
                for (p, on) in more {
                    have.insert(p.clone(), on.clone());
                }
            }
            _ => {
                into.insert(k.clone(), v.clone());
            }
        }
    }
}

/// The block derm adds last: every `--settings` JSON object Claude Code's
/// arguments hold, in order, then derm's hooks and its plugin off.
pub fn block(words: &[String], derm: &str) -> Value {
    let mut out = Map::new();
    for v in settings_values(words) {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(v) {
            merge(&mut out, &m);
        }
    }
    let mine = json!({
        "hooks": hooks(derm),
        "enabledPlugins": {PLUGIN: false},
    });
    if let Value::Object(m) = mine {
        merge(&mut out, &m);
    }
    Value::Object(out)
}

/// Adds derm's block as the last `--settings` of Claude Code's arguments.
/// Call it after every other edit of Claude Code's `--settings`: the
/// Standard tier's and the OTel export's.
pub fn register(plan: &mut Plan, derm: &str) -> Result<(), String> {
    let at = start(plan);
    let text = serde_json::to_string(&block(&plan.args[at..], derm)).map_err(|e| e.to_string())?;
    plan.args.extend(["--settings".to_string(), text]);
    plan.notes.push(format!(
        "derm run: derm's gate for Claude Code is in derm's --settings block, run by its absolute path ({derm}) with no shell, and derm's plugin is off for this chat (enabledPlugins), so each call is gated once"
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn the_block_holds_derms_gate_and_turns_the_plugin_off() {
        let b = block(&s(&["-p", "go"]), "/opt/derm/bin/derm");
        let pre = &b["hooks"]["PreToolUse"][0]["hooks"][0];
        assert_eq!(pre["command"], "/opt/derm/bin/derm");
        assert_eq!(pre["args"], json!(["hook", "claude-code", "pre"]));
        assert_eq!(pre["onFailure"], "block");
        assert_eq!(b["hooks"]["PreToolUse"][0]["matcher"], "*");
        assert_eq!(
            b["hooks"]["PostToolUse"][0]["hooks"][0]["args"],
            json!(["hook", "claude-code", "post"])
        );
        assert_eq!(b["enabledPlugins"]["derm@derm"], false);
    }

    #[test]
    fn every_earlier_settings_object_is_kept_in_order_and_hooks_once() {
        let user = r#"{"model":"x","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/u/h"}]}]},"enabledPlugins":{"derm@derm":true,"other@m":true}}"#;
        let export = format!(
            "{}",
            serde_json::json!({
                "model": "x",
                "hooks": serde_json::from_str::<Value>(user).unwrap()["hooks"].clone(),
                "otelHeadersHelper": "/h/helper"
            })
        );
        let standard = r#"{"sandbox":{"enabled":true}}"#;
        let words = s(&[
            "--settings",
            &export,
            "-p",
            "go",
            "--settings",
            user,
            "--settings",
            standard,
        ]);
        let b = block(&words, "/d/derm");
        assert_eq!(b["model"], "x");
        assert_eq!(b["otelHeadersHelper"], "/h/helper");
        assert_eq!(b["sandbox"]["enabled"], true);
        let pre = b["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2, "the user's hook once, then derm's: {b}");
        assert_eq!(pre[0]["hooks"][0]["command"], "/u/h");
        assert_eq!(pre[1]["hooks"][0]["command"], "/d/derm");
        assert_eq!(b["enabledPlugins"]["derm@derm"], false);
        assert_eq!(b["enabledPlugins"]["other@m"], true);
    }

    #[test]
    fn a_user_settings_that_is_not_json_is_refused() {
        assert!(check_user_settings(&s(&["--settings", "/home/u/s.json"])).is_err());
        assert!(check_user_settings(&s(&["--settings=[1]"])).is_err());
        assert!(check_user_settings(&s(&["--settings", "{\"a\":1}", "-p", "x"])).is_ok());
        assert!(check_user_settings(&s(&["-p", "x"])).is_ok());
    }

    #[test]
    fn register_adds_the_last_settings_after_srts_command() {
        let mut p = Plan {
            program: "srt".into(),
            args: s(&["--settings", "/srt/s.json", "--", "claude", "-p", "go"]),
            ..Plan::default()
        };
        register(&mut p, "/d/derm").unwrap();
        assert_eq!(p.args[p.args.len() - 2], "--settings");
        let b: Value = serde_json::from_str(p.args.last().unwrap()).unwrap();
        assert_eq!(
            b["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "/d/derm"
        );
        // srt's own --settings is a file of srt's, not Claude Code's.
        assert!(b.get("filesystem").is_none(), "{b}");
        assert!(p.notes.iter().any(|n| n.contains("plugin is off")));
    }
}
