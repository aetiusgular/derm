//! The model tap's launch environment (wave 5, lane S; rules cases 113 to
//! 115, 127). The wave 5 base cut this seam: `run_io` calls [`environment`]
//! once the plan is built, and adds the returned record to `run.start` as
//! `detail.tap` (`contracts/events.md` section 5). The variable or flag per
//! agent comes from `crates/derm-cli/src/connect/presets/wave5/tap.json`,
//! the launch shapes from `derm_tap::launch`.
//!
//! The tap runs in the daemon, which publishes it as `tap.endpoint` beside
//! `otlp.endpoint`. A chat is tapped when the chat token was minted, the
//! user's settings leave the tap on, the agent takes a base URL, and the
//! daemon publishes a tap. Otherwise it runs untapped, says so on the
//! terminal, and `run.start` says `tap.on: false` (case 127).
//!
//! Case 113: a base URL the user (or a planted file) already set would make
//! the harness skip the tap, or send it somewhere the tap would not, so
//! `derm run` refuses and names where it is set. The user removes it, or
//! turns the tap off in `~/.derm/settings.json`.

use std::path::{Path, PathBuf};

use derm_tap::{launch, route, settings};
use serde_json::{json, Value};

use super::plan::{split_url, Plan};

/// What the seam reads beyond the plan. `environment` gathers it from the
/// process as `RunEnv::real` does; the tests give their own.
pub(crate) struct Inputs {
    pub daemon_dir: Option<PathBuf>,
    pub home: Option<String>,
    pub cwd: Option<String>,
    /// Variables `derm run` inherited (for case 113).
    pub inherited: Vec<(String, String)>,
    /// Claude Code's managed settings file (and its `.d` folder).
    pub claude_managed: PathBuf,
}

impl Inputs {
    fn real(plan: &Plan) -> Self {
        Inputs {
            daemon_dir: derm_audit_linux::client::socket_path()
                .and_then(|s| s.parent().map(Path::to_path_buf)),
            home: derm_core::runtime::home_dir()
                .and_then(|h| h.into_os_string().into_string().ok()),
            cwd: plan.folders.first().cloned().or_else(|| {
                std::env::current_dir()
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned())
            }),
            inherited: std::env::vars().collect(),
            claude_managed: PathBuf::from(if cfg!(target_os = "macos") {
                "/Library/Application Support/ClaudeCode/managed-settings.json"
            } else {
                "/etc/claude-code/managed-settings.json"
            }),
        }
    }
}

/// The seam `run_io` calls.
pub(crate) fn environment(harness: &str, plan: &mut Plan) -> Result<Option<Value>, (u8, String)> {
    let inputs = Inputs::real(plan);
    environment_with(harness, plan, &inputs)
}

/// `run.start`'s `content` field (`contracts/events.md` section 5): the
/// content switch and its retention as the user's settings hold them when
/// the chat starts. `run_io` adds it beside `tap` (lane S's request 3).
pub(crate) fn content_record(home: Option<&str>) -> Value {
    let s = home
        .map(|h| settings::load(&settings::path_for(h)).0)
        .unwrap_or_default();
    json!({"on": s.content_days.is_some(), "retentionDays": s.content_days})
}

fn off(reason: Option<&str>) -> Option<Value> {
    let mut v = json!({"on": false, "via": "none"});
    if let Some(r) = reason {
        v["reason"] = json!(r);
    }
    Some(v)
}

/// The preset row's `tap` value, when it has one.
fn tap_row(harness: &str) -> Option<Value> {
    let table: Value = serde_json::from_str(crate::connect::presets::table_json()).ok()?;
    ["harnesses", "planned"].iter().find_map(|list| {
        table
            .get(*list)?
            .as_array()?
            .iter()
            .find(|r| r.get("id").and_then(Value::as_str) == Some(harness))
            .and_then(|r| r.get("tap").cloned())
            .filter(|t| !t.is_null())
    })
}

/// `tap.endpoint` in the daemon's folder: a loopback `http://` URL with a
/// port, else `None`.
pub(crate) fn read_endpoint(dir: &Path) -> Option<String> {
    let path = dir.join("tap.endpoint");
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() || meta.len() > 256 {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let url = text.trim();
    let (scheme, host, port, rest) = split_url(url)?;
    let loopback = host == "127.0.0.1" || host == "::1" || host == "localhost";
    (scheme == "http" && loopback && port > 0 && (rest.is_empty() || rest == "/"))
        .then(|| url.trim_end_matches('/').to_string())
}

pub(crate) fn environment_with(
    harness: &str,
    plan: &mut Plan,
    i: &Inputs,
) -> Result<Option<Value>, (u8, String)> {
    // No chat token: `--no-daemon` or a dry run. Nothing is recorded, so
    // nothing is said here; the tap runs in the daemon.
    let Some(token) = plan
        .env_set
        .iter()
        .find(|(k, _)| k == "DERM_CHAT_TOKEN")
        .map(|(_, v)| v.clone())
    else {
        return Ok(None);
    };
    let (prefs, warning) = match &i.home {
        Some(h) => settings::load(&settings::path_for(h)),
        None => (settings::Settings::default(), None),
    };
    if let Some(w) = warning {
        eprintln!("derm run: {w}");
    }
    if !prefs.tap_on {
        eprintln!("derm run: the model tap is off in your settings; this chat's tool calls are recorded by its gate and the OS feed only");
        return Ok(off(Some("setting")));
    }
    let Some(row) = tap_row(harness) else {
        return Ok(off(Some("no-base-url")));
    };
    if row.get("via").and_then(Value::as_str).unwrap_or("none") == "none" {
        return Ok(off(Some("no-base-url")));
    }
    if plan.sandbox_name.is_some() {
        // Case 113 still holds for what reaches the VM: the chat's folder is
        // mounted there and the harness's own words are passed on, so a base
        // URL a project file or the command line sets would send the chat
        // elsewhere. The host's environment, home and managed files stay on
        // the host (sbx passes only the variables derm names, plan.rs
        // OWNED_VARS) and are not read here (fix pass 12's review, finding 1).
        let in_vm = Inputs {
            daemon_dir: None,
            home: None,
            cwd: i.cwd.clone(),
            inherited: Vec::new(),
            claude_managed: PathBuf::new(),
        };
        if let Some(why) = base_url_already_set(harness, plan, &in_vm) {
            return Err((
                1,
                format!(
                    "derm run: {why}, and the sbx VM would read it; remove it, or run this chat under another boundary"
                ),
            ));
        }
        // MW5-37: sbx's host proxy adds the harness's credential only to
        // requests for the provider's own host (`credential@1`'s `inject`
        // domains and `resourceHosts`, docker/sandbox-kit-spec `6838e3e`;
        // Docker's sandbox credentials page), and no second kit can add a
        // host to it (one owner per service and phase). Through the tap the
        // request leaves the VM with the sandbox's sentinel and gets 401.
        eprintln!(
            "derm run: under sbx the model tap is off for this chat: sbx's proxy adds {harness}'s credential only to requests \
             for its provider's own host, so a request through the tap would carry none. sbx's policy log, derm's gate in the VM \
             (where derm's kit runs) and the host's OS feed record the chat"
        );
        return Ok(off(Some("sbx-credential")));
    }
    let Some(endpoint) = i.daemon_dir.as_deref().and_then(read_endpoint) else {
        eprintln!(
            "derm run: the daemon published no model tap (tap.endpoint); this chat runs untapped"
        );
        return Ok(off(Some("no-endpoint")));
    };
    if let Some(why) = base_url_already_set(harness, plan, i) {
        return Err((
            1,
            format!(
                "derm run: {why}, so {harness} would not reach the model tap. Remove it, or turn the tap off \
                 (\"tap\": {{\"on\": false}} in ~/.derm/settings.json) to run this chat untapped"
            ),
        ));
    }
    let route_text = route::of_token(&token);
    let l = match launch::launch(&row, &endpoint, &route_text) {
        Ok(l) => l,
        Err(launch::Off::NoBaseUrl) => return Ok(off(Some("no-base-url"))),
    };
    for (k, v) in &l.env {
        plan.env_set.retain(|(n, _)| n != k);
        plan.env_remove.retain(|n| n != k);
        plan.env_set.push((k.clone(), v.clone()));
    }
    if !l.args.is_empty() {
        let at = harness_args_start(plan);
        let mut args = plan.args.clone();
        args.splice(at..at, l.args.iter().cloned());
        plan.args = args;
    }
    if let Some(text) = plan.srt_settings.as_deref() {
        let mut v: Value = serde_json::from_str(text).map_err(|e| (1, e.to_string()))?;
        let (_, host, port, _) = split_url(&endpoint).ok_or((1, "bad tap endpoint".to_string()))?;
        let host = if host == "localhost" {
            "127.0.0.1".to_string()
        } else {
            host
        };
        let allow = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        if let Some(list) = v
            .pointer_mut("/network/allowedDomains")
            .and_then(Value::as_array_mut)
        {
            if !list.iter().any(|x| x.as_str() == Some(allow.as_str())) {
                list.push(json!(allow));
            }
        }
        plan.srt_settings = Some(serde_json::to_string_pretty(&v).map_err(|e| (1, e.to_string()))?);
    }
    Ok(Some(json!({
        "on": true,
        "via": l.via,
        "api": l.api.name(),
        "upstream": l.upstream,
    })))
}

/// Codex's subcommands that start a model session. Codex 0.163.0 ignores a
/// provider set with `-c` before `exec` and honours it after (run 4 Nov
/// 2026; lane S status doc, Research), so the tap's flags go right after one
/// of these, and first when there is none (the TUI).
pub(crate) const CODEX_SESSION_SUBCOMMANDS: &[&str] =
    &["exec", "e", "review", "resume", "fork", "app-server"];

/// Where the tap's flags go in `plan.args`: where the harness's own
/// arguments start (0 when the plan starts the harness itself, after
/// `-- <command>` under srt), then past a session subcommand.
fn harness_args_start(plan: &Plan) -> usize {
    let mut at = 0;
    if plan.program == "srt" {
        if let Some(p) = plan.args.iter().position(|a| a == "--") {
            at = (p + 2).min(plan.args.len());
        }
    }
    if plan
        .args
        .get(at)
        .is_some_and(|a| CODEX_SESSION_SUBCOMMANDS.contains(&a.as_str()))
    {
        at += 1;
    }
    at
}

/// Case 113: where a base URL is already set for this harness, in words for
/// the terminal; `None` when nothing is.
pub(crate) fn base_url_already_set(harness: &str, plan: &Plan, i: &Inputs) -> Option<String> {
    let inherited = |name: &str| i.inherited.iter().any(|(k, v)| k == name && !v.is_empty());
    match harness {
        "claude-code" => {
            for var in [
                "ANTHROPIC_BASE_URL",
                "CLAUDE_CODE_USE_BEDROCK",
                "CLAUDE_CODE_USE_VERTEX",
                "CLAUDE_CODE_USE_FOUNDRY",
                "CLAUDE_CODE_USE_MANTLE",
            ] {
                if inherited(var) {
                    return Some(format!("{var} is set in derm run's environment"));
                }
            }
            let mut files: Vec<PathBuf> = Vec::new();
            let config_dir = i
                .inherited
                .iter()
                .find(|(k, v)| k == "CLAUDE_CONFIG_DIR" && v.starts_with('/'))
                .map(|(_, v)| PathBuf::from(v))
                .or_else(|| i.home.as_ref().map(|h| Path::new(h).join(".claude")));
            if let Some(d) = config_dir {
                files.push(d.join("settings.json"));
            }
            if let Some(c) = &i.cwd {
                files.push(Path::new(c).join(".claude/settings.json"));
                files.push(Path::new(c).join(".claude/settings.local.json"));
            }
            files.push(i.claude_managed.clone());
            if let Some(dir) = i
                .claude_managed
                .parent()
                .map(|p| p.join("managed-settings.d"))
            {
                if let Ok(rd) = std::fs::read_dir(&dir) {
                    let mut more: Vec<PathBuf> = rd
                        .flatten()
                        .map(|e| e.path())
                        .filter(|p| p.extension().is_some_and(|x| x == "json"))
                        .collect();
                    more.sort();
                    files.extend(more);
                }
            }
            for f in files {
                if let Some(var) = claude_settings_route(&f) {
                    return Some(format!("{} sets {var}", f.display()));
                }
            }
            let mut a = plan.args.iter();
            while let Some(x) = a.next() {
                let v = if x == "--settings" {
                    a.next().map(String::as_str)
                } else {
                    x.strip_prefix("--settings=")
                };
                if let Some(v) = v {
                    let text = if v.trim_start().starts_with('{') {
                        v.to_string()
                    } else {
                        std::fs::read_to_string(v).unwrap_or_default()
                    };
                    if let Some(var) = settings_text_route(&text) {
                        return Some(format!("--settings sets {var}"));
                    }
                }
            }
            None
        }
        "codex" => {
            for x in &plan.args {
                let x = x.as_str();
                if x == "--oss"
                    || x == "--profile"
                    || x == "-p"
                    || x.starts_with("--profile=")
                    || x.starts_with("--local-provider")
                {
                    return Some(format!("{x} chooses Codex's provider on its command line"));
                }
            }
            let mut a = plan.args.iter();
            while let Some(x) = a.next() {
                let v = if x == "-c" || x == "--config" {
                    a.next().map(String::as_str)
                } else {
                    x.strip_prefix("--config=")
                };
                if let Some(v) = v {
                    let key = v.split('=').next().unwrap_or("").trim();
                    if key == "model_provider"
                        || key == "openai_base_url"
                        || key == "profile"
                        || key.starts_with("model_providers.")
                        || key.starts_with("profiles.")
                    {
                        return Some(format!(
                            "-c {key} chooses Codex's provider on its command line"
                        ));
                    }
                }
            }
            if inherited("OPENAI_BASE_URL") {
                return Some("OPENAI_BASE_URL is set in derm run's environment".into());
            }
            let codex_home = i
                .inherited
                .iter()
                .find(|(k, v)| k == "CODEX_HOME" && v.starts_with('/'))
                .map(|(_, v)| PathBuf::from(v))
                .or_else(|| i.home.as_ref().map(|h| Path::new(h).join(".codex")))?;
            let file = codex_home.join("config.toml");
            codex_config_route(&file).map(|what| format!("{} sets {what}", file.display()))
        }
        "gemini" => inherited("GOOGLE_GEMINI_BASE_URL")
            .then(|| "GOOGLE_GEMINI_BASE_URL is set in derm run's environment".into()),
        _ => None,
    }
}

/// The routing variable a Claude Code settings file's `env` sets, if any.
fn claude_settings_route(path: &Path) -> Option<&'static str> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return None;
    }
    settings_text_route(&std::fs::read_to_string(path).ok()?)
}

fn settings_text_route(text: &str) -> Option<&'static str> {
    let v: Value = serde_json::from_str(text).ok()?;
    let env = v.get("env")?.as_object()?;
    [
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "CLAUDE_CODE_USE_MANTLE",
    ]
    .into_iter()
    .find(|k| {
        env.get(*k)
            .is_some_and(|x| !x.is_null() && x.as_str() != Some(""))
    })
}

/// What in Codex's `config.toml` chooses a provider other than its own
/// OpenAI one, if anything: `model_provider`, `openai_base_url`, or a
/// `profile` whose table sets `model_provider`.
fn codex_config_route(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return None;
    }
    let doc: toml_edit::DocumentMut = std::fs::read_to_string(path).ok()?.parse().ok()?;
    if doc
        .get("openai_base_url")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        return Some("openai_base_url".into());
    }
    if let Some(p) = doc.get("model_provider").and_then(|v| v.as_str()) {
        if p != "openai" {
            return Some(format!("model_provider = \"{p}\""));
        }
    }
    if let Some(name) = doc.get("profile").and_then(|v| v.as_str()) {
        let p = doc
            .get("profiles")
            .and_then(|t| t.get(name))
            .and_then(|t| t.get("model_provider"))
            .and_then(|v| v.as_str());
        if let Some(p) = p.filter(|p| *p != "openai") {
            return Some(format!("profile \"{name}\" with model_provider = \"{p}\""));
        }
    }
    None
}

#[cfg(test)]
mod tests;
