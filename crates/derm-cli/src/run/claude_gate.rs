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
//! - one gate per call: a plugin's hooks and a settings file's are two
//!   hooks (Claude Code's hooks docs: a handler that appears in several
//!   settings files runs once, a plugin's copy stays separate), and with
//!   the plugin off a call made one approval record (a cloud probe against
//!   the real 2.1.322 on Linux, note BE section 1.2);
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

/// Claude Code's own words: up to a user's `--`, after which every word is
/// the prompt (fix pass 6's re-review).
fn options(words: &[String]) -> &[String] {
    let end = words.iter().position(|w| w == "--").unwrap_or(words.len());
    &words[..end]
}

/// Every `--settings` value in `words`, in order, before a `--`.
fn settings_values(words: &[String]) -> Vec<&str> {
    let words = options(words);
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
///
/// Refused too: words that start Claude Code with no hook at all, derm's
/// gate included, so the chat would run ungated while `derm run` says it is
/// gated (fix pass 6's review): `--bare` ("skip hooks (those defined in
/// settings and by installed plugins ...)") and `--safe-mode` ("all
/// customizations (... hooks ...) disabled"), as `claude --help` of 2.1.322
/// says, and a `--settings` that sets `disableAllHooks` true.
pub fn check_user_settings(rest: &[String]) -> Result<(), String> {
    for w in options(rest) {
        let flag = w.split('=').next().unwrap_or(w);
        if flag == "--bare" || flag == "--safe-mode" {
            return Err(format!(
                "{flag} starts Claude Code with no hooks, so derm's gate would not run; derm run does not start a chat it says is gated with no gate"
            ));
        }
    }
    for v in settings_values(rest) {
        let parsed = serde_json::from_str::<Value>(v);
        if !matches!(parsed, Ok(Value::Object(_))) {
            return Err(format!(
                "Claude Code reads only the last --settings on its command line, and derm adds its gate there; a --settings that is not JSON ({} characters) cannot be merged into it: pass the settings as JSON, or put them in ~/.claude/settings.json",
                v.chars().count()
            ));
        }
        if parsed.is_ok_and(|o| o.get("disableAllHooks") == Some(&Value::Bool(true))) {
            return Err(
                "a --settings that sets disableAllHooks turns every hook off, derm's gate included; derm run does not start a chat it says is gated with no gate"
                    .into(),
            );
        }
    }
    Ok(())
}

/// Refuses, before anything starts, a Claude Code settings file that turns
/// every hook off (`disableAllHooks: true`): the managed file and its `.d`
/// folder (fix pass 10, MW6R5-3), the user's (`CLAUDE_CONFIG_DIR`, else
/// `~/.claude`), and the project's shared and local files in the session
/// folder (fix pass 6's review). A file written during the chat is not seen
/// here; derm's block sets the key false, which a managed `true` outranks.
pub fn check_settings_files(
    home: &std::path::Path,
    config_dir: Option<&str>,
    cwd: &std::path::Path,
) -> Result<(), String> {
    check_settings_files_in(
        &crate::connect::gate::managed_settings_dir(),
        home,
        config_dir,
        cwd,
    )
}

/// `check_settings_files` with the managed settings folder given.
///
/// Fix pass 10, MW6R5-3 (Mac retest of fix pass 6's line, run with Tony's
/// file on the Mac): `{"disableAllHooks": true}` in
/// `/Library/Application Support/ClaudeCode/managed-settings.json` outranks
/// derm's `--settings` block (managed settings come first in Claude Code's
/// precedence, code.claude.com/docs/en/settings), and a `derm run
/// claude-code` chat started with no word and ran a Bash call with no
/// approval record. Read in Claude Code's order: `managed-settings.json`,
/// then `managed-settings.d/*.json` by name, skipping dot files.
pub(crate) fn check_settings_files_in(
    managed_dir: &std::path::Path,
    home: &std::path::Path,
    config_dir: Option<&str>,
    cwd: &std::path::Path,
) -> Result<(), String> {
    let user = config_dir
        .filter(|d| std::path::Path::new(d).is_absolute())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| home.join(".claude"));
    let mut managed = vec![managed_dir.join("managed-settings.json")];
    if let Ok(rd) = std::fs::read_dir(managed_dir.join("managed-settings.d")) {
        let mut more: Vec<std::path::PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|x| x == "json")
                    && !p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with('.'))
            })
            .collect();
        more.sort();
        managed.extend(more);
    }
    let lead = managed.len();
    let mut files = managed;
    files.push(user.join("settings.json"));
    // The session folder's, and each folder above it up to the repository's
    // root, whose `.claude/settings.local.json` Claude Code reads from a
    // subfolder too (`watch/register.rs`; fix pass 6's re-review).
    for dir in cwd.ancestors() {
        files.push(dir.join(".claude").join("settings.json"));
        files.push(dir.join(".claude").join("settings.local.json"));
        if dir.join(".git").exists() {
            break;
        }
    }
    let files = if cwd.ancestors().any(|d| d.join(".git").exists()) {
        files
    } else {
        files[..lead + 3].to_vec()
    };
    for (i, f) in files.into_iter().enumerate() {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        // A file derm cannot read as JSON may still be read by Claude Code
        // (a byte-order mark, say): refused rather than taken as harmless.
        let Ok(v) = serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}')) else {
            return Err(format!(
                "{} is not JSON derm can read, so derm cannot tell whether it turns hooks off (disableAllHooks); fix it or move it",
                f.display()
            ));
        };
        if v.get("disableAllHooks") == Some(&Value::Bool(true)) {
            return Err(format!(
                "{} sets disableAllHooks, which turns every hook off, derm's gate included; derm run does not start a chat it says is gated with no gate",
                f.display()
            ));
        }
        // P6 (lane PE): Claude Code 2.1.322 decides `crossSessionInbound`
        // from managed settings first, then the flag (derm's block), then
        // the user's; a project's or local file may only tighten (its `I()`,
        // read; run: `plans/parallel/acctP_PE.md`, Research). So only a
        // managed `accept` outranks derm's `refuse` and lets another
        // session's message in. A managed `hold` parks every message for the
        // person's review and delivers none on its own; it is left as the
        // person's (or their admin's) choice.
        if i < lead && v.get("crossSessionInbound") == Some(&Value::from("accept")) {
            return Err(format!(
                "{} sets crossSessionInbound to accept, which outranks derm's refuse, so another Claude Code session could message this chat; derm's project chats take messages only through derm_message (P6). Set it to refuse or hold, or remove it",
                f.display()
            ));
        }
    }
    Ok(())
}

/// derm's hook entries for Claude Code, in exec form: `derm hook claude-code
/// pre` blocks when it fails or times out; `post` records the call and
/// redacts its result (the plugin's `hooks/hooks.json`, with the plugin's
/// launcher replaced by derm's own absolute path).
///
/// With a daemon, each names the chat (`--run-chat <chat>`, fix pass 6's
/// review; with `--no-daemon` there is no daemon to hold its taint, and the
/// light tier keeps it, as before): the hook
/// then knows `derm run` registered it, from its own arguments, which a
/// project's or the agent's settings `env` cannot change, so a hook whose
/// chat token was unset gets no light-tier file but the fail-closed state
/// (`gate::taint`). The post timeout is the Windows settings row's, so the
/// two registrations read alike.
pub fn hooks(derm: &str, chat: Option<&str>) -> Value {
    let words = |event: &str| -> Vec<String> {
        let mut w = vec![
            "hook".to_string(),
            "claude-code".to_string(),
            event.to_string(),
        ];
        if let Some(c) = chat {
            w.extend(["--run-chat".to_string(), c.to_string()]);
        }
        w
    };
    json!({
        "PreToolUse": [{
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": derm,
                "args": words("pre"),
                "timeout": 120,
                "onFailure": "block"
            }]
        }],
        "PostToolUse": [{
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": derm,
                "args": words("post"),
                "timeout": 120
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
#[cfg(test)]
pub fn block(words: &[String], derm: &str, chat: Option<&str>) -> Value {
    block_for(words, derm, chat, false)
}

/// [`block`], for a chat on an agent account when `account` is true.
pub fn block_for(words: &[String], derm: &str, chat: Option<&str>, account: bool) -> Value {
    let mut out = Map::new();
    for v in settings_values(words) {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(v) {
            merge(&mut out, &m);
        }
    }
    // `disableAllHooks` false: Claude Code 2.1.322 lists the key as
    // restrictive (its settings table, `{path:["disableAllHooks"],
    // restrictive:!0}`), so a true from another file may still win; derm
    // refuses one at the start (`check_settings_files`) and says so here
    // for the rest (fix pass 6's review).
    // `crossSessionInbound` refuse (P6, lane PE): on Linux Claude Code's
    // cross-session inbox takes lines from any process of its user with no
    // auth line (2.1.322 `ZNr()` is true on Windows only, read), and a line
    // from another project reached the model by run; with this key it is
    // refused. derm's block is the flag source, which beats the user's,
    // the project's and the local file (they may only tighten); a managed
    // `accept` beats it and is refused at the start (`check_settings_files`).
    // Messages between chats go through derm's own `derm_message`.
    let mine = json!({
        "hooks": hooks(derm, chat),
        "enabledPlugins": {PLUGIN: false},
        "disableAllHooks": false,
        "crossSessionInbound": "refuse",
    });
    if let Value::Object(m) = mine {
        merge(&mut out, &m);
    }
    // An agent account's chat (box research BR-4; Tony's 22 Nov call to
    // keep `mcp-proxy.anthropic.com` closed there): Claude Code's updater
    // and claude.ai's connectors off, in the flag source, whose `env` is
    // applied after the user's, the project's and the local file's
    // (2.1.322: `Uo()` filters `ci`, user to policy, and each source's `env`
    // goes into `process.env` in that order), and whose
    // `disableClaudeAiConnectors: true` no other source can undo (`ePe()`
    // is true when any source says true).
    if account {
        let env: Map<String, Value> = ACCOUNT_ENV
            .iter()
            .map(|(k, v)| (k.to_string(), Value::from(*v)))
            .collect();
        match out.get_mut("env") {
            Some(Value::Object(have)) => {
                for (k, v) in env {
                    have.insert(k, v);
                }
            }
            _ => {
                out.insert("env".into(), Value::Object(env));
            }
        }
        out.insert("disableClaudeAiConnectors".into(), Value::Bool(true));
    }
    Value::Object(out)
}

/// What an agent account's Claude Code gets in derm's block's `env` and,
/// the same, on `env`'s argv (`run/user/project.rs` `project_env`): no
/// background update into its home (2.1.322 `vb`: `DISABLE_UPDATES`, or a
/// true `DISABLE_AUTOUPDATER`; Anthropic's own sandbox runner sets
/// `DISABLE_AUTOUPDATER: "1"` and `ENABLE_CLAUDEAI_MCP_SERVERS: "false"`
/// for the Claude Code it starts, the same bundle), and no claude.ai
/// connectors, whose calls go to `mcp-proxy.anthropic.com` (its
/// `MCP_PROXY_URL`; `Uyt()` reads `ENABLE_CLAUDEAI_MCP_SERVERS` with `cs`,
/// which takes `0`, `false`, `no`, `off`).
pub const ACCOUNT_ENV: &[(&str, &str)] = &[
    ("DISABLE_AUTOUPDATER", "1"),
    ("DISABLE_UPDATES", "1"),
    ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"),
];

/// The loader's variables, pinned empty in an account chat's block: a
/// project home's user settings `env` reaches derm's own hook, and an empty
/// value from the flag source wins over a user one (review R2, run "ldp2"
/// with Claude Code 2.1.322; glibc's ld.so takes an empty `LD_PRELOAD` as
/// none).
pub const ACCOUNT_LOADER: &[&str] = &["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"];

/// What derm's gate reads from its environment (`gate/daemon.rs`,
/// `gate/policy.rs`, `gate/core.rs`, `gate/serve/`): pinned in an account
/// chat's block, to derm's value when derm set one, else to empty, which
/// every reader takes as unset (`Env::get` trims and drops an empty value;
/// `load_for_hook` drops an empty `DERM_POLICY`), so a project home's
/// settings cannot name a policy, a socket, a token file or a mode for the
/// gate (review R2).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const ACCOUNT_GATE_VARS: &[&str] = &[
    "DERM_POLICY",
    "DERM_DAEMON_SOCKET",
    "DERM_CHAT_TOKEN_FILE",
    "GEMINI_CLI_DERM_CHAT_TOKEN_FILE",
    "DERM_CHAT_ID",
    "DERM_RUN",
    "DERM_BOUNDARY",
    "DERM_OTLP_ENDPOINT",
    "DERM_FULL_ACCESS",
    "DERM_ASKS",
    "DERM_MEMORY_STATE",
    "DERM_CONTROL_PATHS",
];

/// Never in the block: it is on argv, which every user of the machine can
/// read (`/proc/<pid>/cmdline`), so a value that is a credential or a route
/// to one stays in the environment only (case 85). A project home's
/// settings can still name these; the helper refuses such a file at the
/// chat's start (`landlock::setup`, review R2's rest).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const NOT_ON_ARGV: &[&str] = &[
    "DERM_CHAT_TOKEN",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "ANTHROPIC_BASE_URL",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
    "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
];

/// Review R1 and R2 (case RV-1): an agent account's Claude Code reads its
/// user settings from the project home, which the chat writes, and 2.1.322
/// applies each source's `env` over the process's in the order user,
/// project, local, flag, policy (`Uo()` over `ci`, `Object.assign(process.env,
/// ...)` per source; run "st6": user beats argv, "st7": flag beats user, and
/// "dpol": a user value for `DERM_POLICY` reached derm's hook). So every
/// variable derm sets for the chat that is not a secret also goes into derm's
/// block, the last `--settings` before any `--` in `args`: the store folder
/// (R1), the bridge's paths, the chat's homes, `PATH` and `SHELL`; the gate's
/// other variables empty; the loader's empty. `env_set` is what `derm run`
/// sets (only its `DERM_` and `OTEL_` names, `CLAUDE_CODE_ENABLE_TELEMETRY`
/// and the `NO_PROXY` pair are taken: the export's endpoint would otherwise
/// be a project home's to point at a listener of its own, which the
/// headers helper then hands the chat token), `assign` the paths `env` sets after the helper, `extra` the
/// helper's own (Claude Code's store folder). A value holding `token` or a
/// URL with a user part is refused, never written.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn pin_account_env(
    args: &mut [String],
    env_set: &[(String, String)],
    assign: &[(String, String)],
    extra: &[(String, String)],
    token: Option<&str>,
) -> Result<(), String> {
    let end = args.iter().position(|w| w == "--").unwrap_or(args.len());
    let at = args[..end]
        .iter()
        .rposition(|w| w == "--settings")
        .filter(|i| i + 1 < end)
        .ok_or("internal: derm's --settings block is not in Claude Code's arguments")?;
    let mut block: Value = serde_json::from_str(&args[at + 1])
        .map_err(|e| format!("internal: derm's --settings block: {e}"))?;
    let derms = block
        .pointer("/hooks/PreToolUse/0/hooks/0/args/0")
        .and_then(Value::as_str)
        == Some("hook");
    if !derms {
        return Err("internal: the last --settings is not derm's block".into());
    }
    let mut env = Map::new();
    for k in ACCOUNT_GATE_VARS.iter().chain(ACCOUNT_LOADER) {
        env.insert((*k).to_string(), Value::from(""));
    }
    let taken = env_set
        .iter()
        .filter(|(k, _)| {
            k.starts_with("DERM_")
                || k.starts_with("OTEL_")
                || matches!(
                    k.as_str(),
                    "NO_PROXY" | "no_proxy" | "CLAUDE_CODE_ENABLE_TELEMETRY"
                )
        })
        .chain(assign)
        .chain(extra)
        .filter(|(k, _)| {
            !NOT_ON_ARGV.contains(&k.as_str()) && !ACCOUNT_LOADER.contains(&k.as_str())
        })
        // The helper's spec (`run/landlock` `SPEC_VAR`), removed before it execs.
        .filter(|(k, _)| k != "DERM_LANDLOCK_SPEC");
    for (k, v) in taken {
        let userinfo = v.split_once("://").is_some_and(|(_, rest)| {
            rest.split(['/', '?', '#'])
                .next()
                .unwrap_or("")
                .contains('@')
        });
        if token.is_some_and(|t| !t.is_empty() && v.contains(t)) || userinfo {
            return Err(format!(
                "internal: {k} holds a credential and would reach Claude Code's command line; refusing to start"
            ));
        }
        env.insert(k.clone(), Value::from(v.as_str()));
    }
    match block.get_mut("env") {
        Some(Value::Object(have)) => {
            for (k, v) in env {
                have.insert(k, v);
            }
        }
        _ => {
            block["env"] = Value::Object(env);
        }
    }
    args[at + 1] = serde_json::to_string(&block).map_err(|e| e.to_string())?;
    Ok(())
}

/// Adds derm's block as the last `--settings` of Claude Code's arguments.
/// Call it after every other edit of Claude Code's `--settings`: the
/// Standard tier's and the OTel export's.
pub fn register(
    plan: &mut Plan,
    derm: &str,
    chat: Option<&str>,
    account: bool,
) -> Result<(), String> {
    let at = start(plan);
    let text = serde_json::to_string(&block_for(&plan.args[at..], derm, chat, account))
        .map_err(|e| e.to_string())?;
    // Before a `--` of the user's, after which Claude Code reads every word
    // as the prompt (fix pass 6's review); else last.
    let end = plan.args[at..]
        .iter()
        .position(|w| w == "--")
        .map_or(plan.args.len(), |i| at + i);
    plan.args.splice(end..end, ["--settings".to_string(), text]);
    // `--safe-mode` "Sets CLAUDE_CODE_SAFE_MODE=1" (`claude --help`,
    // 2.1.322); whether the variable alone starts safe mode, every hook off,
    // was not read (I), so it never reaches the chat (fix pass 6's review).
    if !plan.env_remove.iter().any(|v| v == "CLAUDE_CODE_SAFE_MODE") {
        plan.env_remove.push("CLAUDE_CODE_SAFE_MODE".into());
    }
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

    /// Box research BR-4 and Tony's 22 Nov call: on an agent account the
    /// project home is the chat's to write, and Claude Code 2.1.322 applies
    /// each settings source's `env` to its process in the order user,
    /// project, local, flag, policy (`Uo()` is `ci.filter(...)`, `ci` that
    /// list; `Object.assign(process.env, I)` per source), so a project
    /// home's `~/.claude/settings.json` could turn the updater back on; in
    /// derm's flag block they win. `disableClaudeAiConnectors` from any
    /// source turns claude.ai's connectors off (`ePe()` is `Uo().some(...
    /// ===!0)`), which no other file can undo; so is the variable.
    #[test]
    fn br_4_an_account_chats_block_turns_updates_and_claude_ai_connectors_off() {
        let words = vec![
            "--settings".to_string(),
            r#"{"env":{"DISABLE_AUTOUPDATER":"0","KEEP":"x"},"disableClaudeAiConnectors":false}"#
                .to_string(),
        ];
        let b = block_for(&words, "/usr/local/bin/derm", Some("c1"), true);
        assert_eq!(b["env"]["DISABLE_AUTOUPDATER"], "1", "{b}");
        assert_eq!(b["env"]["DISABLE_UPDATES"], "1", "{b}");
        assert_eq!(b["env"]["ENABLE_CLAUDEAI_MCP_SERVERS"], "false", "{b}");
        assert_eq!(b["env"]["KEEP"], "x", "the chat's own env is kept: {b}");
        assert_eq!(b["disableClaudeAiConnectors"], true, "{b}");
        // A person's own chat: unchanged.
        let b = block_for(&words, "/usr/local/bin/derm", Some("c1"), false);
        assert_eq!(b["env"]["DISABLE_AUTOUPDATER"], "0", "{b}");
        assert!(b["env"].get("DISABLE_UPDATES").is_none(), "{b}");
        assert_eq!(b["disableClaudeAiConnectors"], false, "{b}");
    }

    /// Review R1 and R2 (red first; rules case RV-1): the variables derm
    /// sets for an account chat are in derm's flag block too, so a project
    /// home's `~/.claude/settings.json` `env` cannot move the store, the
    /// policy, the bridge's socket or token file, or load a library into
    /// derm's hook; and nothing secret reaches argv.
    #[test]
    fn rv_1_an_account_chats_block_pins_every_variable_derm_sets() {
        let words = vec!["-p".to_string(), "go".to_string()];
        let mut args = words.clone();
        let b = block_for(&words, "/usr/local/bin/derm", Some("c1"), true);
        args.extend(["--settings".to_string(), b.to_string()]);
        args.extend(["--".to_string(), "--settings".to_string(), "{}".to_string()]);
        let tok = "a".repeat(64);
        let env_set = vec![
            ("DERM_CHAT_ID".to_string(), "c1".to_string()),
            ("DERM_CHAT_TOKEN".to_string(), tok.clone()),
            (
                "DERM_CHAT_TOKEN_FILE".to_string(),
                "/run/derm-agent/1000/c1-x/chat.token".to_string(),
            ),
            (
                "DERM_DAEMON_SOCKET".to_string(),
                "/run/derm-agent/1000/c1-x/daemon.sock".to_string(),
            ),
            (
                "DERM_POLICY".to_string(),
                "/run/derm-agent/1000/c1-x/policy.json".to_string(),
            ),
            (
                "HTTPS_PROXY".to_string(),
                "http://derm:cred@127.0.0.1:9".to_string(),
            ),
            (
                "NO_PROXY".to_string(),
                "localhost,127.0.0.1,::1".to_string(),
            ),
            (
                "ANTHROPIC_BASE_URL".to_string(),
                "http://127.0.0.1:1/r/route/anthropic".to_string(),
            ),
            ("OTHER".to_string(), "x".to_string()),
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT".to_string(),
                "http://127.0.0.1:4318".to_string(),
            ),
            (
                "OTEL_EXPORTER_OTLP_HEADERS".to_string(),
                format!("authorization=Bearer {tok}"),
            ),
        ];
        let assign = vec![
            (
                "HOME".to_string(),
                "/var/lib/derm/agents/box/projects/p/home".to_string(),
            ),
            (
                "TMPDIR".to_string(),
                "/var/lib/derm/agents/box/projects/p/tmp".to_string(),
            ),
            (
                "XDG_RUNTIME_DIR".to_string(),
                "/var/lib/derm/agents/box/projects/p/run".to_string(),
            ),
            (
                "PATH".to_string(),
                "/usr/local/bin:/usr/bin:/bin".to_string(),
            ),
            ("SHELL".to_string(), "/bin/bash".to_string()),
            ("DISABLE_UPDATES".to_string(), "1".to_string()),
        ];
        let extra = vec![(
            "CLAUDE_SECURESTORAGE_CONFIG_DIR".to_string(),
            "/var/lib/derm/agents/box/signin/claude-code".to_string(),
        )];
        pin_account_env(&mut args, &env_set, &assign, &extra, Some(&tok)).unwrap();
        let at = args.iter().position(|w| w == "--").unwrap();
        let i = args[..at].iter().rposition(|w| w == "--settings").unwrap();
        let v: Value = serde_json::from_str(&args[i + 1]).unwrap();
        let env = &v["env"];
        assert_eq!(
            env["CLAUDE_SECURESTORAGE_CONFIG_DIR"], "/var/lib/derm/agents/box/signin/claude-code",
            "R1: {v}"
        );
        assert_eq!(
            env["DERM_POLICY"], "/run/derm-agent/1000/c1-x/policy.json",
            "R2: {v}"
        );
        assert_eq!(
            env["DERM_DAEMON_SOCKET"],
            "/run/derm-agent/1000/c1-x/daemon.sock"
        );
        assert_eq!(
            env["DERM_CHAT_TOKEN_FILE"],
            "/run/derm-agent/1000/c1-x/chat.token"
        );
        assert_eq!(env["DERM_CHAT_ID"], "c1");
        for k in [
            "HOME",
            "TMPDIR",
            "XDG_RUNTIME_DIR",
            "PATH",
            "SHELL",
            "DISABLE_UPDATES",
        ] {
            assert!(env[k].is_string(), "{k}: {v}");
        }
        assert_eq!(env["NO_PROXY"], "localhost,127.0.0.1,::1");
        assert_eq!(env["OTEL_EXPORTER_OTLP_ENDPOINT"], "http://127.0.0.1:4318");
        for k in ACCOUNT_LOADER {
            assert_eq!(env[*k], "", "{k}: {v}");
        }
        for k in [
            "DERM_FULL_ACCESS",
            "DERM_ASKS",
            "DERM_MEMORY_STATE",
            "GEMINI_CLI_DERM_CHAT_TOKEN_FILE",
        ] {
            assert_eq!(env[k], "", "{k} pinned empty: {v}");
        }
        for k in NOT_ON_ARGV {
            assert!(env.get(*k).is_none(), "{k} on argv: {v}");
        }
        assert!(env.get("OTHER").is_none(), "only derm's own names: {v}");
        let all = args.join(" ");
        assert!(!all.contains(&tok), "the chat token reached argv");
        assert!(!all.contains("cred@"), "a proxy credential reached argv");
        // The user's own `--settings` after `--` is the prompt's and untouched.
        assert_eq!(args[args.len() - 1], "{}");
        // A value that holds the token or a credential is refused.
        let mut again = args.clone();
        let bad = vec![("DERM_RUN".to_string(), format!("x{tok}"))];
        assert!(pin_account_env(&mut again, &bad, &[], &[], Some(&tok)).is_err());
        let bad = vec![("TMPDIR".to_string(), "http://u:p@h/".to_string())];
        assert!(pin_account_env(&mut again, &[], &bad, &[], Some(&tok)).is_err());
    }

    #[test]
    fn the_block_holds_derms_gate_and_turns_the_plugin_off() {
        let b = block(&s(&["-p", "go"]), "/opt/derm/bin/derm", Some("c1"));
        let pre = &b["hooks"]["PreToolUse"][0]["hooks"][0];
        assert_eq!(pre["command"], "/opt/derm/bin/derm");
        assert_eq!(
            pre["args"],
            json!(["hook", "claude-code", "pre", "--run-chat", "c1"])
        );
        assert_eq!(b["disableAllHooks"], false);
        assert_eq!(pre["onFailure"], "block");
        assert_eq!(b["hooks"]["PreToolUse"][0]["matcher"], "*");
        assert_eq!(
            b["hooks"]["PostToolUse"][0]["hooks"][0]["args"],
            json!(["hook", "claude-code", "post", "--run-chat", "c1"])
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
        let b = block(&words, "/d/derm", Some("c1"));
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

    /// Fix pass 6's review: words that start Claude Code with no hook.
    #[test]
    fn words_that_turn_every_hook_off_are_refused() {
        for words in [
            vec!["--bare", "-p", "x"],
            vec!["-p", "x", "--safe-mode"],
            vec!["--settings", r#"{"disableAllHooks":true}"#],
            vec![r#"--settings={"model":"m","disableAllHooks":true}"#],
        ] {
            let e = check_user_settings(&s(&words)).unwrap_err();
            assert!(e.contains("derm's gate"), "{words:?}: {e}");
        }
        assert!(check_user_settings(&s(&["--settings", r#"{"disableAllHooks":false}"#])).is_ok());
        // A prompt that only names the flag is the prompt (after -p).
        assert!(check_user_settings(&s(&["-p", "explain --bare"])).is_ok());
        // After a `--` every word is the prompt (fix pass 6's re-review).
        assert!(check_user_settings(&s(&["-p", "--", "--bare"])).is_ok());
        assert!(check_user_settings(&s(&["-p", "--", "--settings", "x"])).is_ok());
        assert!(
            block(&s(&["--", "--settings", r#"{"model":"m"}"#]), "/d", None)
                .get("model")
                .is_none()
        );
    }

    #[test]
    fn register_adds_the_last_settings_after_srts_command() {
        let mut p = Plan {
            program: "srt".into(),
            args: s(&["--settings", "/srt/s.json", "--", "claude", "-p", "go"]),
            ..Plan::default()
        };
        register(&mut p, "/d/derm", Some("c1"), false).unwrap();
        assert_eq!(p.args[p.args.len() - 2], "--settings");
        let b: Value = serde_json::from_str(p.args.last().unwrap()).unwrap();
        assert_eq!(
            b["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "/d/derm"
        );
        assert!(p.env_remove.iter().any(|v| v == "CLAUDE_CODE_SAFE_MODE"));
        // srt's own --settings is a file of srt's, not Claude Code's.
        assert!(b.get("filesystem").is_none(), "{b}");
        assert!(p.notes.iter().any(|n| n.contains("plugin is off")));
        // With no daemon (`--no-daemon`) the hook names no chat.
        let mut q = Plan {
            program: "claude".into(),
            args: s(&["-p", "go"]),
            ..Plan::default()
        };
        register(&mut q, "/d/derm", None, false).unwrap();
        let b: Value = serde_json::from_str(q.args.last().unwrap()).unwrap();
        assert_eq!(
            b["hooks"]["PreToolUse"][0]["hooks"][0]["args"],
            json!(["hook", "claude-code", "pre"])
        );
    }

    /// Fix pass 6's review: after a user's `--` Claude Code reads every word
    /// as the prompt, so derm's block goes before it.
    #[test]
    fn the_block_goes_before_a_users_double_dash() {
        let mut p = Plan {
            program: "claude".into(),
            args: s(&["-p", "--", "-x"]),
            ..Plan::default()
        };
        register(&mut p, "/d/derm", Some("c1"), false).unwrap();
        assert_eq!(p.args[1], "--settings");
        assert_eq!(&p.args[3..], &["--", "-x"]);
    }

    /// Fix pass 6's review: a settings file that turns every hook off.
    #[test]
    fn a_settings_file_that_turns_hooks_off_is_refused() {
        let d = std::env::temp_dir().join(format!("derm-cg-{}", std::process::id()));
        let home = d.join("home");
        let cwd = d.join("work");
        // An empty managed folder: this test is about the user's and the
        // project's files, and the real one may hold a file (fix pass 10).
        let nm = d.join("no-managed");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(cwd.join(".claude")).unwrap();
        assert!(check_settings_files_in(&nm, &home, None, &cwd).is_ok());
        for f in [
            home.join(".claude/settings.json"),
            cwd.join(".claude/settings.json"),
            cwd.join(".claude/settings.local.json"),
        ] {
            std::fs::write(&f, r#"{"disableAllHooks": true}"#).unwrap();
            let e = check_settings_files_in(&nm, &home, None, &cwd).unwrap_err();
            assert!(e.contains("disableAllHooks"), "{e}");
            std::fs::write(&f, r#"{"disableAllHooks": false}"#).unwrap();
        }
        assert!(check_settings_files_in(&nm, &home, None, &cwd).is_ok());
        // Fix pass 6's re-review: a file derm cannot read is refused, and a
        // repository root's local file is read from a subfolder.
        std::fs::write(cwd.join(".claude/settings.json"), "{not json").unwrap();
        assert!(check_settings_files_in(&nm, &home, None, &cwd)
            .unwrap_err()
            .contains("not JSON"));
        std::fs::write(cwd.join(".claude/settings.json"), "\u{feff}{}").unwrap();
        assert!(
            check_settings_files_in(&nm, &home, None, &cwd).is_ok(),
            "a byte-order mark is read past"
        );
        std::fs::create_dir_all(cwd.join(".git")).unwrap();
        let sub = cwd.join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            cwd.join(".claude/settings.local.json"),
            r#"{"disableAllHooks": true}"#,
        )
        .unwrap();
        assert!(check_settings_files_in(&nm, &home, None, &sub).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Fix pass 10, MW6R5-3: a managed settings file or one in its `.d`
    /// folder that turns every hook off refuses the start, as the user's
    /// and the project's do; an unreadable one is refused; a dot file in
    /// the folder is not Claude Code's and is skipped.
    #[test]
    fn mw6r5_3_a_managed_file_that_turns_hooks_off_is_refused() {
        let d = std::env::temp_dir().join(format!("derm-cg-m-{}", std::process::id()));
        let managed = d.join("managed");
        let home = d.join("home");
        let cwd = d.join("work");
        std::fs::create_dir_all(managed.join("managed-settings.d")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        assert!(check_settings_files_in(&managed, &home, None, &cwd).is_ok());
        std::fs::write(
            managed.join("managed-settings.json"),
            r#"{"disableAllHooks": true}"#,
        )
        .unwrap();
        let e = check_settings_files_in(&managed, &home, None, &cwd).unwrap_err();
        assert!(
            e.contains("managed-settings.json") && e.contains("disableAllHooks"),
            "{e}"
        );
        std::fs::write(managed.join("managed-settings.json"), "{}").unwrap();
        let drop_in = managed.join("managed-settings.d/50-team.json");
        std::fs::write(&drop_in, r#"{"disableAllHooks": true}"#).unwrap();
        assert!(check_settings_files_in(&managed, &home, None, &cwd)
            .unwrap_err()
            .contains("50-team.json"));
        std::fs::remove_file(&drop_in).unwrap();
        std::fs::write(
            managed.join("managed-settings.d/.hidden.json"),
            r#"{"disableAllHooks": true}"#,
        )
        .unwrap();
        assert!(check_settings_files_in(&managed, &home, None, &cwd).is_ok());
        std::fs::write(managed.join("managed-settings.json"), "{not json").unwrap();
        assert!(check_settings_files_in(&managed, &home, None, &cwd)
            .unwrap_err()
            .contains("not JSON"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P6 (lane PE): derm's block refuses Claude Code's own cross-session
    /// inbox, over a user's `--settings` that accepts it, as the last word
    /// (Claude Code reads only the last `--settings`, case 246).
    #[test]
    fn pe_the_block_refuses_claude_codes_cross_session_inbox_over_the_users_words() {
        let b = block(&[], "/usr/local/bin/derm", Some("c-a"));
        assert_eq!(b["crossSessionInbound"], "refuse");
        let b = block(
            &s(&[
                "--settings",
                r#"{"crossSessionInbound":"accept","model":"m"}"#,
            ]),
            "/usr/local/bin/derm",
            None,
        );
        assert_eq!(b["crossSessionInbound"], "refuse");
        assert_eq!(b["model"], "m", "the user's other keys stay");
    }

    /// P6 (lane PE), from the run against Claude Code 2.1.322 and 2.1.330
    /// (`plans/parallel/acctP_PE.md`, Research): derm's flag `refuse` held
    /// against a user's, a project's and a local `accept`, and a managed
    /// `accept` beat it. So a managed file (or one in its `.d` folder) that
    /// accepts refuses the start; a managed `hold`, and an `accept` in the
    /// user's, the project's or the local file, do not.
    #[test]
    fn pe_a_managed_file_that_accepts_other_sessions_messages_is_refused() {
        let d = std::env::temp_dir().join(format!("derm-cg-pe-{}", std::process::id()));
        let managed = d.join("managed");
        let home = d.join("home");
        let cwd = d.join("work");
        std::fs::create_dir_all(managed.join("managed-settings.d")).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(cwd.join(".claude")).unwrap();
        let accept = r#"{"crossSessionInbound": "accept"}"#;
        for f in [
            home.join(".claude/settings.json"),
            cwd.join(".claude/settings.json"),
            cwd.join(".claude/settings.local.json"),
        ] {
            std::fs::write(&f, accept).unwrap();
        }
        assert!(check_settings_files_in(&managed, &home, None, &cwd).is_ok());
        std::fs::write(
            managed.join("managed-settings.json"),
            r#"{"crossSessionInbound": "hold"}"#,
        )
        .unwrap();
        assert!(check_settings_files_in(&managed, &home, None, &cwd).is_ok());
        std::fs::write(managed.join("managed-settings.json"), accept).unwrap();
        let e = check_settings_files_in(&managed, &home, None, &cwd).unwrap_err();
        assert!(
            e.contains("managed-settings.json") && e.contains("crossSessionInbound"),
            "{e}"
        );
        std::fs::write(managed.join("managed-settings.json"), "{}").unwrap();
        std::fs::write(managed.join("managed-settings.d/10-org.json"), accept).unwrap();
        assert!(check_settings_files_in(&managed, &home, None, &cwd)
            .unwrap_err()
            .contains("10-org.json"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
