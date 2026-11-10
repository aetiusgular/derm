//! `derm connect <agent> --rules [--clear] [--write]` (wave 4 lane Q, T2.8):
//! your derm policy's deny rules, written into the agent's own deny list as a
//! second layer, for agents whose gate fails open (case 70). When the hook
//! crashes or times out, the agent's own engine still refuses the call.
//!
//! Deny only. An allow written there could skip the agent's own prompt when
//! derm's gate is not running (rules section 5, item 7), and the agents read
//! here skip an ask rule in their full-access modes, while a deny holds:
//!
//! - OpenClaude 0.32.0 (`@gitlawb/openclaude`, dist/cli.mjs):
//!   `hasPermissionsToUseToolInner` returns a deny rule's answer before it
//!   reads the mode, and an ask rule is skipped under `fullAccess`;
//!   `toolMatchesRule` takes `mcp__<server>__<tool>`, and `mcp__<server>` or
//!   `mcp__<server>__*` for a whole server; `Bash` names the shell. Read in
//!   this chat (V). File `~/.openclaude/settings.json`, `permissions.deny`
//!   (lane L's registration; `OPENCLAUDE_CONFIG_DIR`).
//! - Qwen Code 0.26.6 (QwenLM/qwen-code v0.26.6, 042c023): `permissions.deny`
//!   (`packages/cli/src/config/settingsSchema.ts:2755`); `mcp__server__tool`
//!   and `mcp__server__*` (`packages/core/src/permissions/rule-parser.ts:472,
//!   1728-1731`); `Bash` is the shell (`rule-parser.ts:59`); a deny ends the
//!   call before the approval mode (YOLO) is read
//!   (`packages/core/src/core/coreToolScheduler.ts:3988`, then `:4296`); the
//!   folder is `QWEN_HOME`, else `~/.qwen` (`config/storage.ts:193-210`).
//!   Read in this chat (V).
//!
//! What does not carry over, and stays with the gate: the reject list, the
//! shell-text check, control files, chat-scoped rules, rules for another
//! agent, a deny on every tool (`*`), and built-in tools other than the
//! shell, whose names differ per agent. Each skipped rule is named.
//!
//! The deny list is a list of strings, so derm cannot mark its own entries
//! inside it. It records what it added in `~/.derm/rules/<agent>.json`; the
//! next run takes those out before it adds the current set, and an entry you
//! had before derm is never recorded as derm's.

use std::path::PathBuf;

use derm_core::policy::lower_name;

use super::gate::{resolve, Place};
use super::json::{self, Value};
use super::write::{self, Current};
use super::{diff, log, names, Ctx};

pub struct Target {
    pub agent: &'static str,
    pub name: &'static str,
    pub place: Place,
    pub cli: &'static str,
    pub installed_if: &'static str,
}

pub fn targets() -> Vec<Target> {
    vec![
        Target {
            agent: "openclaude",
            name: "OpenClaude",
            place: Place {
                path: "~/.openclaude/settings.json".into(),
                home_env: Some("OPENCLAUDE_CONFIG_DIR".into()),
                xdg_config: false,
            },
            cli: "openclaude",
            installed_if: ".openclaude",
        },
        Target {
            agent: "qwen-code",
            name: "Qwen Code",
            place: Place {
                path: "~/.qwen/settings.json".into(),
                home_env: Some("QWEN_HOME".into()),
                xdg_config: false,
            },
            cli: "qwen",
            installed_if: ".qwen",
        },
    ]
}

/// Agents whose second layer was read and found impossible or not yet
/// verified, with why (lane Q's research, status doc).
const NOT_WRITTEN: &[(&str, &str)] = &[
    ("crush", "Crush 0.99.0 has no deny rule below a whole tool (options.disabled_tools removes the tool); no second layer"),
    ("kimi", "Kimi 1.52.0 has no allow, ask or deny rules; no second layer"),
    ("continue", "Continue 1.5.47 ignores permissions.yaml under --auto and --readonly; not written"),
    ("rovo-dev", "Rovo Dev's bash deny is not documented and its binary could not be read; not written"),
    ("droid", "Droid's permissionRules location is not settled (settings.general or the top level); not written yet"),
    ("auggie", "Auggie's toolPermissions were read from a minified bundle by a research agent only; not written yet"),
];

/// The MCP server name as the agent spells it: the policy's own `servers`
/// entry whose normalized form matches, with every character outside
/// `[A-Za-z0-9_-]` as `_` (OpenClaude's `normalizeNameForMCP`), else the
/// normalized name.
fn server_name(normalized: &str, servers: &[String]) -> String {
    let raw = servers
        .iter()
        .find(|s| lower_name(s) == normalized)
        .map_or(normalized, String::as_str);
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The policy's deny rules for `agent`, as the agent's own deny entries, and
/// each rule left out with the reason.
pub fn translate(
    policy: &derm_core::policy::PolicyFile,
    agent: &str,
) -> (Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for r in &policy.rules {
        if r.action != derm_core::policy::Action::Deny {
            continue;
        }
        // A command rule (policy.md section 7) denies one command, not the
        // shell: as the agent's own deny it would take the whole shell away.
        if let Some(words) = &r.command {
            skipped.push(format!(
                "bash {} (a command rule stays with the gate)",
                words.join(" ")
            ));
            continue;
        }
        if r.chat.is_some() {
            skipped.push(format!("{} (for one chat)", r.tool));
            continue;
        }
        if r.harness.as_deref().is_some_and(|h| h != agent) {
            continue;
        }
        let entry = if r.tool == "*" {
            skipped.push("* (a deny on every tool stays with the gate)".into());
            continue;
        } else if let Some((server, tool)) = r.tool.split_once('/') {
            let s = server_name(server, &policy.servers);
            if tool == "*" {
                format!("mcp__{s}__*")
            } else {
                format!("mcp__{s}__{tool}")
            }
        } else if r.tool == "bash" {
            "Bash".to_string()
        } else {
            skipped.push(format!(
                "{} (a built-in tool other than the shell; names differ per agent)",
                r.tool
            ));
            continue;
        };
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    (out, skipped)
}

fn strings(v: Option<&Value>) -> Result<Vec<String>, String> {
    match v {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| match i {
                Value::Str(s) => Ok(s.clone()),
                _ => Err("holds a value that is not a string; derm will not guess".to_string()),
            })
            .collect(),
        Some(_) => Err("is not a list; derm will not guess".into()),
    }
}

/// What derm added last time, from its record.
fn recorded(text: &str) -> Vec<String> {
    json::parse(text, false)
        .ok()
        .and_then(|d| d.root.map(|n| n.to_value()))
        .and_then(|v| strings(v.get("entries")).ok())
        .unwrap_or_default()
}

pub struct Opts<'a> {
    pub agent: &'a str,
    pub clear: bool,
    pub write: bool,
}

pub fn run(o: &Opts, ctx: &mut Ctx) -> Result<u8, String> {
    if o.agent == "gemini" {
        return run_gemini(o, ctx);
    }
    if o.agent == "codex" {
        return run_codex(o, ctx);
    }
    let all = targets();
    let Some(t) = all.iter().find(|t| t.agent == o.agent) else {
        if let Some((_, why)) = NOT_WRITTEN.iter().find(|(a, _)| *a == o.agent) {
            ctx.out.push_str(&format!("derm connect --rules: {why}\n"));
            return Ok(if o.write { 1 } else { 0 });
        }
        let mut ids: Vec<&str> = all.iter().map(|t| t.agent).collect();
        ids.push("gemini");
        ids.push("codex");
        return Err(format!(
            "no rule writer for `{}`; one of: {}",
            o.agent,
            ids.join(", ")
        ));
    };
    let policy_path = names::policy_path(&ctx.home, ctx.env);
    let (policy, problem) = derm_core::policy::load(&policy_path);
    let (want, skipped) = if o.clear {
        (Vec::new(), Vec::new())
    } else {
        if let Some(p) = problem {
            return Err(format!(
                "{}: {p}; derm writes no rules from a policy it cannot read",
                policy_path.display()
            ));
        }
        translate(&policy, t.agent)
    };
    let settings = resolve(&t.place, &ctx.home, ctx.env);
    let record = ctx.home.join(format!(".derm/rules/{}.json", t.agent));
    if !settings.starts_with(&ctx.home)
        || settings
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "{} is outside your home folder; derm writes user-level files under it only",
            settings.display()
        ));
    }
    let cur = write::read_current(&settings)?;
    let text = cur.text()?.to_string();
    let rec_cur = write::read_current(&record)?;
    let before = recorded(rec_cur.text().unwrap_or(""));
    let doc = json::parse(&text, false).map_err(|e| {
        format!(
            "{}: {e}; derm will not rewrite a file it cannot parse",
            settings.display()
        )
    })?;
    let root = doc.root.as_ref().map(|n| n.to_value());
    let existing = strings(
        root.as_ref()
            .and_then(|r| r.get_path(&["permissions"]))
            .and_then(|p| p.get("deny")),
    )
    .map_err(|e| format!("{}: permissions.deny {e}", settings.display()))?;
    // The user's own entries: everything but what derm added last time.
    let mine: Vec<String> = existing
        .iter()
        .filter(|e| !before.contains(e))
        .cloned()
        .collect();
    let mut list = mine.clone();
    let mut ours = Vec::new();
    for w in &want {
        if !list.contains(w) {
            list.push(w.clone());
            ours.push(w.clone());
        }
    }
    ctx.out.push_str(&format!(
        "derm connect --rules: {} ({}), {} from {}\n",
        t.name,
        t.agent,
        settings.display(),
        policy_path.display()
    ));
    for s in &skipped {
        ctx.out.push_str(&format!("skipped: {s}\n"));
    }
    if list == existing && ours == before {
        ctx.out
            .push_str("the agent's deny list already matches; nothing to change\n");
        return Ok(0);
    }
    let new_value = Value::Array(list.iter().map(|s| Value::Str(s.clone())).collect());
    let new_settings = if doc.root.is_none() {
        let mut whole = Value::Object(Vec::new());
        whole.set_path(&["permissions"], "deny", new_value.clone())?;
        format!("{}\n", json::pretty(&whole, "  ", ""))
    } else {
        let n = doc
            .set_member(&["permissions"], "deny", &new_value, true, true)
            .map_err(|e| format!("{}: {e:?}", settings.display()))?;
        super::verify_json(&text, &n, false, &["permissions"], "deny", Some(&new_value))?;
        n
    };
    let new_record = format!(
        "{}\n",
        json::pretty(
            &Value::object(vec![
                ("agent", Value::str(t.agent)),
                ("file", Value::str(&settings.display().to_string())),
                ("entries", Value::strings(&ours)),
            ]),
            "  ",
            ""
        )
    );
    let mut plans: Vec<(PathBuf, Current, String)> = Vec::new();
    if new_settings != text {
        plans.push((settings.clone(), cur.clone(), new_settings));
    }
    if rec_cur.text().ok() != Some(new_record.as_str()) {
        plans.push((record.clone(), rec_cur.clone(), new_record));
    }
    for (p, c, n) in &plans {
        let label = p.display().to_string();
        ctx.out.push('\n');
        ctx.out.push_str(&diff::unified_redacted(
            c.text().unwrap_or(""),
            n,
            &label,
            &format!("{label} (after derm connect --rules)"),
        ));
    }
    let installed = ctx.home.join(t.installed_if).exists()
        || ctx
            .env
            .var("PATH")
            .unwrap_or_default()
            .split(':')
            .filter(|d| d.starts_with('/'))
            .any(|d| std::path::Path::new(d).join(t.cli).is_file());
    if !installed {
        ctx.out.push_str(&format!(
            "\n{} does not look installed here; derm writes nothing for an agent that is not installed.\n",
            t.name
        ));
        return Ok(if o.write { 1 } else { 0 });
    }
    if !o.write {
        ctx.out
            .push_str("\ndry run: nothing written. Add --write to write it.\n");
        return Ok(0);
    }
    ctx.flush();
    if !ctx
        .confirm
        .confirm(&format!("Write {}'s deny list?", t.name))?
    {
        return Err("not confirmed; nothing written".into());
    }
    for (p, c, _) in &plans {
        if write::read_current(p)?.sha256 != c.sha256 {
            return Err(format!(
                "{} changed since the diff was shown; nothing written. Run the dry run again.",
                p.display()
            ));
        }
    }
    let backups = ctx.home.join(".derm/backups");
    let socket = super::log_socket(ctx);
    for (p, c, n) in &plans {
        let w = write::commit(p, t.agent, &c.sha256, n, &backups)?;
        let rec = log::Record {
            harness: t.agent.into(),
            path: p.display().to_string(),
            server: "derm-rules".into(),
            action: if o.clear {
                "rules-clear".into()
            } else {
                "rules".into()
            },
            sha256_before: c.sha256.clone(),
            sha256_after: w.sha256_after.clone(),
            backup: w.backup.as_ref().map(|b| b.display().to_string()),
            origin: format!("policy {}", policy_path.display()),
        };
        let logged = log::record(&socket, &ctx.home.join(".derm/connect.log"), &rec)
            .unwrap_or_else(|e| format!("nowhere ({e})"));
        ctx.out.push_str(&format!(
            "written: {} (sha256 {}). Logged to {logged}.\n",
            p.display(),
            w.sha256_after
        ));
    }
    Ok(0)
}

/// The first line of every file derm writes for Gemini, and of the one
/// derm-gemini-extension's `bin/derm-gemini-policy.mjs` prints for the same
/// path (lane I): how derm knows the file is its own.
pub const GEMINI_MARKER: &str = "# derm policy for Gemini CLI";

/// Gemini CLI 0.66.0 (google-gemini/gemini-cli v0.66.0, 9704132): every
/// `*.toml` in `<GEMINI_CLI_HOME or ~>/.gemini/policies` is the user tier
/// (`config/storage.ts:54-60, 150-151`, `utils/paths.ts:22-28`,
/// `policy/toml-loader.ts:169-173`), tier 4, ranked `4 + priority/1000`
/// (`toml-loader.ts:196-203, 299-307`). Rules are sorted by priority and the
/// first match decides (`policy/policy-engine.ts:255-256, 780-835`), so a
/// user deny ranks above YOLO's catch-all allow (default tier, 998, so 1.998;
/// `policies/yolo.toml:50-56`). `mcpName` names the server exactly and
/// `toolName = "*"` every tool of it (`policy-engine.ts:153-200`); the shell is
/// `run_shell_command` (`tools/definitions/base-declarations.ts:56`). Not
/// held: a run with `--policy <path>`, which replaces the user folder
/// (`policy/config.ts:119-122`), and an admin-tier allow.
///
/// Deny rules only, as for the JSON agents; the priority is lane I's
/// `priorityOf` (`packages/derm-gemini-extension/src/policyToml.ts`), so a
/// rule derm writes here ranks as the extension's printout would rank it.
pub fn gemini_toml(policy: &derm_core::policy::PolicyFile) -> (String, Vec<String>) {
    let mut out = vec![
        GEMINI_MARKER.to_string() + ", user tier. Written by `derm connect gemini --rules`",
        "# from your derm policy. Deny rules only; run it again after every change to".into(),
        "# ~/.derm/policy.json. The derm hook still runs first and applies the rest.".into(),
        String::new(),
    ];
    let mut skipped = Vec::new();
    for r in &policy.rules {
        if r.action != derm_core::policy::Action::Deny {
            continue;
        }
        // A command rule denies one command, not run_shell_command.
        if let Some(words) = &r.command {
            skipped.push(format!(
                "bash {} (a command rule stays with the gate)",
                words.join(" ")
            ));
            continue;
        }
        if r.chat.is_some() {
            skipped.push(format!("{} (for one chat)", r.tool));
            continue;
        }
        if r.harness.as_deref().is_some_and(|h| h != "gemini") {
            continue;
        }
        let (sel, spec) = if r.tool == "*" {
            skipped.push("* (a deny on every tool stays with the gate)".into());
            continue;
        } else if let Some((server, tool)) = r.tool.split_once('/') {
            let raw = policy
                .servers
                .iter()
                .find(|s| lower_name(s) == server)
                .map_or(server, String::as_str);
            (
                format!(
                    "mcpName = {}\ntoolName = {}",
                    json::quote(raw),
                    json::quote(tool)
                ),
                if tool == "*" { 1 } else { 2 },
            )
        } else if r.tool == "bash" {
            ("toolName = \"run_shell_command\"".to_string(), 2)
        } else {
            skipped.push(format!(
                "{} (a built-in tool other than the shell; names differ per agent)",
                r.tool
            ));
            continue;
        };
        // A `bash` deny narrows run_shell_command whatever rule allows it
        // (the hook's step 3a), so it outranks every rule `priorityOf` ranks,
        // as the extension's printout does (`BASH_DENY_PRIORITY`; review
        // W4-S6).
        let priority = if r.tool == "bash" {
            950
        } else {
            1 + if r.harness.is_some() { 300 } else { 0 } + spec * 100 + 20
        };
        out.push("[[rule]]".into());
        out.push(sel);
        out.push("decision = \"deny\"".into());
        out.push(format!("priority = {priority}"));
        out.push(format!(
            "denyMessage = {}",
            json::quote(&format!(
                "derm: rule {}{}",
                r.tool,
                r.harness
                    .as_deref()
                    .map_or(String::new(), |h| format!(" harness={h}"))
            ))
        ));
        out.push(String::new());
    }
    (format!("{}\n", out.join("\n").trim_end()), skipped)
}

fn run_gemini(o: &Opts, ctx: &mut Ctx) -> Result<u8, String> {
    let policy_path = names::policy_path(&ctx.home, ctx.env);
    let (policy, problem) = derm_core::policy::load(&policy_path);
    let (text, skipped) = if o.clear {
        gemini_toml(&derm_core::policy::PolicyFile::default())
    } else {
        if let Some(p) = problem {
            return Err(format!(
                "{}: {p}; derm writes no rules from a policy it cannot read",
                policy_path.display()
            ));
        }
        gemini_toml(&policy)
    };
    let base = ctx
        .env
        .var("GEMINI_CLI_HOME")
        .filter(|d| d.starts_with('/'))
        .map_or_else(|| ctx.home.clone(), PathBuf::from);
    let file = base.join(".gemini/policies/derm.toml");
    if !file.starts_with(&ctx.home)
        || file
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "{} is outside your home folder; derm writes user-level files under it only",
            file.display()
        ));
    }
    let cur = write::read_current(&file)?;
    let now = cur.text()?.to_string();
    if cur.bytes.is_some() && !now.starts_with(GEMINI_MARKER) {
        return Err(format!(
            "{} exists and is not derm's; derm will not replace it",
            file.display()
        ));
    }
    ctx.out.push_str(&format!(
        "derm connect --rules: Gemini CLI (gemini), {} from {}\n",
        file.display(),
        policy_path.display()
    ));
    for s in &skipped {
        ctx.out.push_str(&format!("skipped: {s}\n"));
    }
    ctx.out.push_str("note:   Gemini reads this folder unless it runs with --policy <path>, which replaces it; an admin-tier allow outranks these denies.\n");
    if now == text {
        ctx.out
            .push_str("the file already matches; nothing to change\n");
        return Ok(0);
    }
    let label = file.display().to_string();
    ctx.out.push('\n');
    ctx.out.push_str(&diff::unified_redacted(
        &now,
        &text,
        &label,
        &format!("{label} (after derm connect --rules)"),
    ));
    let installed = base.join(".gemini").exists()
        || ctx
            .env
            .var("PATH")
            .unwrap_or_default()
            .split(':')
            .filter(|d| d.starts_with('/'))
            .any(|d| std::path::Path::new(d).join("gemini").is_file());
    if !installed {
        ctx.out.push_str("\nGemini CLI does not look installed here; derm writes nothing for an agent that is not installed.\n");
        return Ok(if o.write { 1 } else { 0 });
    }
    if !o.write {
        ctx.out
            .push_str("\ndry run: nothing written. Add --write to write it.\n");
        return Ok(0);
    }
    ctx.flush();
    if !ctx
        .confirm
        .confirm("Write Gemini CLI's derm policy file?")?
    {
        return Err("not confirmed; nothing written".into());
    }
    if write::read_current(&file)?.sha256 != cur.sha256 {
        return Err(format!(
            "{} changed since the diff was shown; nothing written. Run the dry run again.",
            file.display()
        ));
    }
    let backups = ctx.home.join(".derm/backups");
    let socket = super::log_socket(ctx);
    let w = write::commit(&file, "gemini", &cur.sha256, &text, &backups)?;
    let rec = log::Record {
        harness: "gemini".into(),
        path: file.display().to_string(),
        server: "derm-rules".into(),
        action: if o.clear {
            "rules-clear".into()
        } else {
            "rules".into()
        },
        sha256_before: cur.sha256.clone(),
        sha256_after: w.sha256_after.clone(),
        backup: w.backup.as_ref().map(|b| b.display().to_string()),
        origin: format!("policy {}", policy_path.display()),
    };
    let logged = log::record(&socket, &ctx.home.join(".derm/connect.log"), &rec)
        .unwrap_or_else(|e| format!("nowhere ({e})"));
    ctx.out.push_str(&format!(
        "written: {} (sha256 {}). Logged to {logged}.\n",
        file.display(),
        w.sha256_after
    ));
    Ok(0)
}

/// What derm changed in Codex's `config.toml` last time: per server key,
/// the tools it added to `disabled_tools` and whether it created that key,
/// and the servers it set `enabled = false` on, with the value before.
#[derive(Debug, Default, PartialEq)]
pub struct CodexRecord {
    pub tools: Vec<(String, Vec<String>, bool)>,
    pub servers: Vec<(String, String)>,
}

impl CodexRecord {
    fn to_json(&self, file: &str) -> String {
        let tools = Value::Object(
            self.tools
                .iter()
                .map(|(k, t, created)| {
                    (
                        k.clone(),
                        Value::object(vec![
                            ("added", Value::strings(t)),
                            ("createdKey", Value::Bool(*created)),
                        ]),
                    )
                })
                .collect(),
        );
        let servers = Value::Object(
            self.servers
                .iter()
                .map(|(k, before)| (k.clone(), Value::str(before)))
                .collect(),
        );
        format!(
            "{}\n",
            json::pretty(
                &Value::object(vec![
                    ("agent", Value::str("codex")),
                    ("file", Value::str(file)),
                    ("tools", tools),
                    ("servers", servers),
                ]),
                "  ",
                ""
            )
        )
    }

    fn from_json(text: &str) -> CodexRecord {
        let Some(v) = json::parse(text, false)
            .ok()
            .and_then(|d| d.root.map(|n| n.to_value()))
        else {
            return CodexRecord::default();
        };
        let mut r = CodexRecord::default();
        if let Some(Value::Object(m)) = v.get("tools") {
            for (k, e) in m {
                let added = strings(e.get("added")).unwrap_or_default();
                let created = matches!(e.get("createdKey"), Some(Value::Bool(true)));
                r.tools.push((k.clone(), added, created));
            }
        }
        if let Some(Value::Object(m)) = v.get("servers") {
            for (k, b) in m {
                if let Value::Str(b) = b {
                    r.servers.push((k.clone(), b.clone()));
                }
            }
        }
        r
    }
}

/// Codex rust-v0.166.0 (6ff1e1c): `[mcp_servers.<s>] disabled_tools` removes
/// those tools, by their exact name, before Codex registers the server's
/// tools (`codex-mcp/src/tools.rs:63-103`, `connection_manager.rs:316`), and
/// `enabled = false` skips the server (`config/src/mcp_types.rs:243-245`,
/// `connection_manager.rs:396, 455`); neither depends on the approval mode,
/// so both hold under `--yolo`. There is no shell deny in `config.toml`
/// (Codex's `rules/*.rules` is another file; not written). derm changes only
/// servers that are already in the file, and undoes its own changes from the
/// record before it applies the policy again.
pub fn codex_plan(
    text: &str,
    policy: &derm_core::policy::PolicyFile,
    before: &CodexRecord,
) -> Result<(String, CodexRecord, Vec<String>), String> {
    let mut doc: toml_edit::DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| {
        format!(
            "not valid TOML ({}); derm will not rewrite a file it cannot parse",
            e.message()
        )
    })?;
    let mut notes = Vec::new();
    let keys: Vec<String> = doc
        .get("mcp_servers")
        .and_then(|i| i.as_table_like())
        .map(|t| t.iter().map(|(k, _)| k.to_string()).collect())
        .unwrap_or_default();
    fn server<'a>(
        doc: &'a mut toml_edit::DocumentMut,
        key: &str,
    ) -> Option<&'a mut dyn toml_edit::TableLike> {
        doc.get_mut("mcp_servers")
            .and_then(|i| i.as_table_like_mut())
            .and_then(|t| t.get_mut(key))
            .and_then(|i| i.as_table_like_mut())
    }
    // Undo what derm did last time.
    for (k, added, created) in &before.tools {
        if let Some(t) = server(&mut doc, k) {
            let empty =
                if let Some(arr) = t.get_mut("disabled_tools").and_then(|i| i.as_array_mut()) {
                    arr.retain(|v| !v.as_str().is_some_and(|s| added.iter().any(|a| a == s)));
                    arr.is_empty()
                } else {
                    false
                };
            if *created && empty {
                t.remove("disabled_tools");
            }
        }
    }
    for (k, was) in &before.servers {
        if let Some(t) = server(&mut doc, k) {
            if t.get("enabled").and_then(|i| i.as_bool()) == Some(false) {
                if was == "absent" {
                    t.remove("enabled");
                } else {
                    t.insert("enabled", toml_edit::value(true));
                }
            }
        }
    }
    let mut rec = CodexRecord::default();
    for r in &policy.rules {
        if r.action != derm_core::policy::Action::Deny {
            continue;
        }
        if let Some(words) = &r.command {
            notes.push(format!(
                "skipped: bash {} (a command rule stays with the gate)",
                words.join(" ")
            ));
            continue;
        }
        if r.chat.is_some() {
            notes.push(format!("skipped: {} (for one chat)", r.tool));
            continue;
        }
        if r.harness.as_deref().is_some_and(|h| h != "codex") {
            continue;
        }
        let Some((srv, tool)) = r.tool.split_once('/') else {
            notes.push(format!(
                "skipped: {} (Codex has no deny for a built-in tool in config.toml; its rules/*.rules is not written)",
                r.tool
            ));
            continue;
        };
        let Some(key) = keys.iter().find(|k| lower_name(k) == srv).cloned() else {
            notes.push(format!(
                "skipped: {} (no server `{srv}` in config.toml; run again after you connect it)",
                r.tool
            ));
            continue;
        };
        let t = server(&mut doc, &key)
            .ok_or_else(|| format!("`mcp_servers.{key}` is not a table; derm will not guess"))?;
        if tool == "*" {
            match t.get("enabled").map(|i| i.as_bool()) {
                Some(Some(false)) => {}
                Some(Some(true)) | None => {
                    let was = if t.get("enabled").is_some() {
                        "true"
                    } else {
                        "absent"
                    };
                    t.insert("enabled", toml_edit::value(false));
                    rec.servers.push((key.clone(), was.into()));
                }
                Some(None) => {
                    return Err(format!(
                        "`mcp_servers.{key}.enabled` is not true or false; derm will not guess"
                    ))
                }
            }
            continue;
        }
        let created = t.get("disabled_tools").is_none();
        if created {
            t.insert(
                "disabled_tools",
                toml_edit::Item::Value(toml_edit::Value::Array(toml_edit::Array::new())),
            );
        }
        let arr = t
            .get_mut("disabled_tools")
            .and_then(|i| i.as_array_mut())
            .ok_or_else(|| {
                format!("`mcp_servers.{key}.disabled_tools` is not a list; derm will not guess")
            })?;
        if arr.iter().any(|v| v.as_str() == Some(tool)) {
            continue;
        }
        arr.push(tool);
        match rec.tools.iter_mut().find(|(k, _, _)| *k == key) {
            Some((_, added, _)) => added.push(tool.to_string()),
            None => rec
                .tools
                .push((key.clone(), vec![tool.to_string()], created)),
        }
        notes.push(format!(
            "note: {} holds only if `{key}` names its tool exactly `{tool}`; Codex compares names as the server gives them",
            r.tool
        ));
    }
    Ok((doc.to_string(), rec, notes))
}

fn run_codex(o: &Opts, ctx: &mut Ctx) -> Result<u8, String> {
    let policy_path = names::policy_path(&ctx.home, ctx.env);
    let (policy, problem) = derm_core::policy::load(&policy_path);
    let policy = if o.clear {
        derm_core::policy::PolicyFile::default()
    } else {
        if let Some(p) = problem {
            return Err(format!(
                "{}: {p}; derm writes no rules from a policy it cannot read",
                policy_path.display()
            ));
        }
        policy
    };
    let file = resolve(
        &Place {
            path: "~/.codex/config.toml".into(),
            home_env: Some("CODEX_HOME".into()),
            xdg_config: false,
        },
        &ctx.home,
        ctx.env,
    );
    let record = ctx.home.join(".derm/rules/codex.json");
    if !file.starts_with(&ctx.home)
        || file
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "{} is outside your home folder; derm writes user-level files under it only",
            file.display()
        ));
    }
    let cur = write::read_current(&file)?;
    let text = cur.text()?.to_string();
    let rec_cur = write::read_current(&record)?;
    let before = CodexRecord::from_json(rec_cur.text().unwrap_or(""));
    let (new_text, rec, notes) =
        codex_plan(&text, &policy, &before).map_err(|e| format!("{}: {e}", file.display()))?;
    ctx.out.push_str(&format!(
        "derm connect --rules: Codex (codex), {} from {}\n",
        file.display(),
        policy_path.display()
    ));
    for n in &notes {
        ctx.out.push_str(&format!("{n}\n"));
    }
    let new_record = rec.to_json(&file.display().to_string());
    let mut plans: Vec<(PathBuf, Current, String)> = Vec::new();
    if new_text != text {
        plans.push((file.clone(), cur.clone(), new_text));
    }
    if rec != before
        || (rec_cur.bytes.is_some() && rec_cur.text().ok() != Some(new_record.as_str()))
    {
        plans.push((record.clone(), rec_cur.clone(), new_record));
    }
    if plans.is_empty() {
        ctx.out
            .push_str("config.toml already matches; nothing to change\n");
        return Ok(0);
    }
    for (p, c, n) in &plans {
        let label = p.display().to_string();
        ctx.out.push('\n');
        ctx.out.push_str(&diff::unified_redacted(
            c.text().unwrap_or(""),
            n,
            &label,
            &format!("{label} (after derm connect --rules)"),
        ));
    }
    let installed = file.parent().is_some_and(|d| d.exists())
        || ctx
            .env
            .var("PATH")
            .unwrap_or_default()
            .split(':')
            .filter(|d| d.starts_with('/'))
            .any(|d| std::path::Path::new(d).join("codex").is_file());
    if !installed {
        ctx.out.push_str("\nCodex does not look installed here; derm writes nothing for an agent that is not installed.\n");
        return Ok(if o.write { 1 } else { 0 });
    }
    if !o.write {
        ctx.out
            .push_str("\ndry run: nothing written. Add --write to write it.\n");
        return Ok(0);
    }
    ctx.flush();
    if !ctx.confirm.confirm("Write Codex's config.toml?")? {
        return Err("not confirmed; nothing written".into());
    }
    for (p, c, _) in &plans {
        if write::read_current(p)?.sha256 != c.sha256 {
            return Err(format!(
                "{} changed since the diff was shown; nothing written. Run the dry run again.",
                p.display()
            ));
        }
    }
    let backups = ctx.home.join(".derm/backups");
    let socket = super::log_socket(ctx);
    for (p, c, n) in &plans {
        let w = write::commit(p, "codex", &c.sha256, n, &backups)?;
        let rec = log::Record {
            harness: "codex".into(),
            path: p.display().to_string(),
            server: "derm-rules".into(),
            action: if o.clear {
                "rules-clear".into()
            } else {
                "rules".into()
            },
            sha256_before: c.sha256.clone(),
            sha256_after: w.sha256_after.clone(),
            backup: w.backup.as_ref().map(|b| b.display().to_string()),
            origin: format!("policy {}", policy_path.display()),
        };
        let logged = log::record(&socket, &ctx.home.join(".derm/connect.log"), &rec)
            .unwrap_or_else(|e| format!("nowhere ({e})"));
        ctx.out.push_str(&format!(
            "written: {} (sha256 {}). Logged to {logged}.\n",
            p.display(),
            w.sha256_after
        ));
    }
    Ok(0)
}
