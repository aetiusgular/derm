//! The command `derm run` starts, built as an argv list and an environment,
//! with no I/O: everything here is a pure function of its inputs, so every
//! boundary and harness is tested without starting anything.
//!
//! - `none`: the harness itself, with the chat's variables.
//! - `sbx`: `sbx run --name derm-<chat> -e NAME... [--kit KIT] AGENT CWD -- ARGS`
//!   (https://docs.docker.com/reference/cli/sbx/run/). Each variable goes as
//!   a bare `-e NAME`, which sbx copies from its own environment, so the
//!   token is never an argument. Loopback URLs become `host.docker.internal`
//!   (sbx's development workflow page), and the policy lines they need are
//!   printed, not run.
//! - `srt`: `srt --settings FILE -- COMMAND ARGS` (srt 0.0.81 `dist/cli.js:
//!   270-278`). The `--` matters: srt's commander would otherwise read a
//!   harness's `-c` as its own option. The settings allow the chat's loopback
//!   services by IP literal only, writes to the working folder, the
//!   harness's state and `/tmp`, and hide the user's secrets, the daemon's
//!   folder and the other harnesses' credentials.

use std::path::Path;

use serde_json::json;

use super::args::{Args, Boundary};
use super::harness::{Harness, Launch, HARNESSES};

/// Variables `derm run` owns: removed from what the child inherits, then set
/// from this run only, so a value left by an outer `derm run` never leaks in.
pub const OWNED_VARS: &[&str] = &[
    "DERM_CHAT_TOKEN",
    "DERM_CHAT_TOKEN_FILE",
    "GEMINI_CLI_DERM_CHAT_TOKEN_FILE",
    "DERM_CHAT_ID",
    "DERM_HARNESS",
    "DERM_BOUNDARY",
    "DERM_OTLP_ENDPOINT",
    "DERM_GATEWAY_URL",
    "DERM_DAEMON_SOCKET",
    "DERM_FULL_ACCESS",
];

/// Arguments and variables that turn an agent's own approvals off: Orca's
/// full-access setting per agent (`src/shared/tui-agent-permissions.ts:12-49`
/// at `f776923`, read for note AQ section 8, V), plus any `--dangerously-*`
/// flag (lane D's rule). A flag alone, or a flag and the value that makes it
/// full access, as two words or joined by `=`.
pub const FULL_ACCESS_FLAGS: &[&str] = &[
    "--yolo",
    "--trust-all-tools",
    "--allow-all",
    "--dangerously-skip-permissions",
    "--dangerously-bypass-approvals-and-sandbox",
    "--dangerously-allow-all",
];
pub const FULL_ACCESS_PAIRS: &[(&str, &str)] = &[
    ("--auto-approve", "true"),
    ("--allow", "*"),
    ("--agent", "auto-approve"),
    ("--approval-mode", "yolo"),
    ("--permission-mode", "bypassPermissions"),
    ("--auto", "high"),
];

/// A flag and value that turn one agent's approvals off, with the words the
/// record keeps (security review L7; each form from that CLI's `--help`).
/// Modes set in the agents' config files are not read.
fn agent_pair(harness: &str, flag: &str, value: &str) -> Option<String> {
    let unquote = |v: &str| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
    match harness {
        "codex" => {
            let hit = match flag {
                "-a" | "--ask-for-approval" => value == "never",
                "-s" | "--sandbox" => value == "danger-full-access",
                "-c" | "--config" => value.split_once('=').is_some_and(|(k, v)| {
                    let (k, v) = (k.trim(), unquote(v));
                    (k == "approval_policy" && v == "never")
                        || (k == "sandbox_mode" && v == "danger-full-access")
                }),
                _ => false,
            };
            hit.then(|| format!("{flag} {value}"))
        }
        "claude-code" if flag == "--settings" => {
            let v: serde_json::Value = serde_json::from_str(value).ok()?;
            (v["permissions"]["defaultMode"] == "bypassPermissions")
                .then(|| "--settings permissions.defaultMode=bypassPermissions".to_string())
        }
        _ => None,
    }
}

/// Single flags that turn one agent's approvals off: `-y` is `--yolo` for
/// Gemini CLI and its fork Qwen Code, and means other things elsewhere.
fn agent_flag(harness: &str, w: &str) -> bool {
    matches!((harness, w), ("gemini" | "qwen-code", "-y"))
}

/// The words in `rest` that put the agent in full access (case 83), and
/// `GOOSE_MODE=auto` when goose inherits it (Orca sets it as a variable).
pub fn full_access(rest: &[String], harness: &str, goose_mode: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let w = rest[i].as_str();
        if w == "--" {
            break;
        }
        let lower = w.to_ascii_lowercase();
        if lower.starts_with("--dangerously")
            || FULL_ACCESS_FLAGS.contains(&w)
            || agent_flag(harness, w)
        {
            out.push(w.to_string());
        } else if let Some((flag, value)) = w.split_once('=').filter(|(f, _)| f.starts_with('-')) {
            if FULL_ACCESS_PAIRS.contains(&(flag, value)) {
                out.push(w.to_string());
            } else if let Some(label) = agent_pair(harness, flag, value) {
                out.push(if label.starts_with("--settings ") {
                    label
                } else {
                    w.to_string()
                });
            }
        } else if let Some(next) = rest.get(i + 1) {
            if FULL_ACCESS_PAIRS.contains(&(w, next.as_str())) {
                out.push(format!("{w} {next}"));
                i += 1;
            } else if let Some(label) = agent_pair(harness, w, next) {
                out.push(label);
                i += 1;
            }
        }
        i += 1;
    }
    if harness == "goose" && goose_mode.is_some_and(|m| m.eq_ignore_ascii_case("auto")) {
        out.push("GOOSE_MODE=auto".into());
    }
    out
}

/// `true` when the policy can answer `ask` for some call: a rule says ask,
/// or no `*` rule catches what no other rule names (an unmatched call asks;
/// `contracts/policy.md` section 4). A missing or bad policy asks for
/// everything (`derm_core::policy::load`).
pub fn policy_asks(policy: Option<&derm_core::policy::PolicyFile>) -> bool {
    use derm_core::policy::Action;
    let Some(p) = policy else {
        return true;
    };
    p.rules.iter().any(|r| r.action == Action::Ask)
        || !p
            .rules
            .iter()
            .any(|r| r.tool == "*" && r.harness.is_none() && r.chat.is_none())
}

pub struct Inputs<'a> {
    pub args: &'a Args,
    pub chat: String,
    /// The working folder, absolute.
    pub cwd: String,
    pub home: String,
    pub token: Option<String>,
    /// A loopback `http://` URL (checked by `client::loopback_http`).
    pub otlp: Option<String>,
    pub gateway: Option<String>,
    /// The daemon's folder (socket, token), hidden under srt.
    pub daemon_dir: Option<String>,
    /// The socket `derm run` minted the chat token through, named to the
    /// harness's hooks under `--boundary none` (`DERM_DAEMON_SOCKET`; release
    /// check RC6).
    pub daemon_socket: Option<String>,
    /// Where srt's settings file for this chat goes.
    pub settings_path: String,
    /// Where the chat token is written for hooks (`DERM_CHAT_TOKEN_FILE`),
    /// beside srt's settings in the daemon's 0700 folder. Named to the child
    /// only under `--boundary none`.
    pub token_file: String,
    /// The policy file the harness's gate reads (`DERM_POLICY`, else
    /// `~/.derm/policy.json`). Under srt it is re-opened read-only inside the
    /// hidden `~/.derm` (box test w1, finding BX2).
    pub policy: String,
    /// The policy path is a regular file you own, with one link and no
    /// group or other write bit (`lstat`, done by the caller: this module
    /// reads no file). Only then is it re-opened (fix pass review R1: a
    /// link at that name re-opened what it pointed at, `~/.derm/backups`).
    pub policy_regular: bool,
    /// `policy_asks` of the policy the gate will read (the caller loads it).
    pub policy_asks: bool,
    /// `GOOSE_MODE` as `derm run` inherited it, if set and not empty.
    pub goose_mode: Option<String>,
    /// Cline's approval folder for this chat (`Launch::Cline`), and lane P's
    /// responder by absolute path when one was found on PATH.
    pub cline_dir: String,
    pub cline_responder: Option<String>,
    /// Absolute paths of what the harness's registered derm gate runs (for
    /// Cursor, the hook package folder and the node `~/.cursor/hooks.json`
    /// names; `gate_paths` in `run/mod.rs` reads them). srt keeps them
    /// read-only wherever they sit (re-review FP5-R2).
    pub gate_paths: Vec<String>,
    /// The git files in the chat's folder that srt's own denies (the
    /// folder's `.git/hooks` and `.git/config`) leave out, by absolute path
    /// (`run/mod.rs` lists them): each submodule's `config` and `hooks` under
    /// `.git/modules/**` (FP8-S2) and each `config.worktree` (re-review
    /// FP8R-5). git reads and runs what they name later, so srt keeps them
    /// read-only, for every harness.
    pub git_controls: Vec<String>,
    /// The computer-use bridge's address (`127.0.0.1:<port>` or
    /// `[::1]:<port>`) from the daemon's `cu.endpoint`, when computer use is
    /// on (Mac test w5 retest 3, MW5-22). Under srt the endpoint file is
    /// re-opened read-only and the port listed for srt's proxy, so
    /// `derm-daemon cu-mcp` inside can find and reach the bridge.
    pub cu_endpoint: Option<String>,
    /// The host is macOS (`cfg!(target_os = "macos")` in `derm run`; a field
    /// so the macOS shape of srt's settings is tested on any system).
    pub macos: bool,
    /// The harness starts on a terminal (`derm run`'s stdin is one).
    pub terminal: bool,
    /// What the files Codex reads say of its sign-in store (fix pass 6,
    /// FP5R-5; `run::codex_store` reads them, this module reads no file).
    pub codex_store: CodexStoreFiles,
}

/// Why Codex's sign-in may live in a store srt cannot write, from its files
/// (`run::codex_store`): the requirements and managed config, which win over
/// everything, and the config layers, which `-c` on the command line beats.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodexStoreFiles {
    pub managed: Option<String>,
    pub config: Option<String>,
    /// `$CODEX_HOME/auth.json` when `CODEX_HOME` moves it from `~/.codex`.
    pub auth_file: Option<String>,
    /// Why a managed file keeps Codex in its own sandbox, which cannot
    /// start inside srt (MW5-32): a requirement on its modes or profiles, or
    /// a managed `sandbox_mode` or `default_permissions`, which Codex layers
    /// over `-c` (`config/src/loader/mod.rs:420-440` at 0.163.0).
    pub managed_sandbox: Option<String>,
    /// The profile files in Codex's home (`<name>.config.toml`, a whole user
    /// config layer for `--profile <name>`, `core/src/config/mod.rs:269,
    /// 2075-2083`), by absolute path: kept read-only under srt (FP8-S1). srt
    /// on Linux takes no write patterns, so a profile made later is not held.
    pub profiles: Vec<String>,
}

/// The last `cli_auth_credentials_store` the harness's own words set with
/// Codex's `-c` (or `--config`), as written: `-c k=v`, `-ck=v`, `--config k=v`
/// or `--config=k=v`, the value's TOML quotes taken off. Codex applies `-c`
/// in order, so the last wins.
pub fn codex_store_from_args(rest: &[String]) -> Option<String> {
    let mut found = None;
    let mut it = rest.iter();
    while let Some(w) = it.next() {
        let pair = match w.as_str() {
            "-c" | "--config" => it.next().map(String::as_str),
            _ => w
                .strip_prefix("--config=")
                .or_else(|| w.strip_prefix("-c").filter(|r| !r.is_empty()))
                // FP8-S4: clap reads `-c=k=v` as `-c k=v`.
                .map(|r| if w.starts_with("-c=") { &r[1..] } else { r }),
        };
        let Some((k, v)) = pair.and_then(|p| p.split_once('=')) else {
            continue;
        };
        if k.trim() == "cli_auth_credentials_store" {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|x| x.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
                .unwrap_or(v);
            found = Some(v.to_string());
        }
    }
    found
}

/// Why Codex's sign-in may live in a store srt cannot write (`keyring`,
/// `auto`, or a value or file derm cannot read), or `None` for a file
/// (`file`, the default) or memory (`ephemeral`). The requirements win; then
/// `-c`; then the config files (Codex 0.163.0,
/// `core/src/config/mod.rs:4460-4466`).
pub fn codex_store_risk(rest: &[String], files: &CodexStoreFiles) -> Option<String> {
    if let Some(m) = &files.managed {
        return Some(m.clone());
    }
    match codex_store_from_args(rest) {
        Some(v) if matches!(v.as_str(), "file" | "ephemeral") => None,
        Some(v) => Some(format!("-c cli_auth_credentials_store={v}")),
        None => files.config.clone(),
    }
}

/// Mac test w5 retest 7, MW5-32: the `-c` pair that turns Codex's own
/// sandbox off, so srt is its sandbox. Codex 0.163.0 starts each command in
/// Seatbelt (`/usr/bin/sandbox-exec`, `sandboxing/src/seatbelt.rs:62`) or
/// bubblewrap, and neither starts inside srt 0.0.81's: macOS refuses a second
/// Seatbelt profile ("sandbox_apply: Operation not permitted", run on the
/// Mac), and srt's seccomp layer refuses a nested user namespace on Linux
/// (srt README lines 712-715; run in the cloud). `danger-full-access` is the
/// one mode that starts no sandbox (`sandboxing/src/manager.rs:313-329`,
/// `policy_transforms.rs:646-666`); `external-sandbox`, the mode Codex has
/// for this, is not accepted in its config (`config_requirements.rs:1467`).
/// It leaves Codex's approvals as they are.
pub const CODEX_SANDBOX_OFF: &str = r#"sandbox_mode="danger-full-access""#;

/// What the harness's own words say of Codex's own sandbox (MW5-32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodexOwnSandbox {
    /// Nothing: Codex's config and defaults decide.
    Unset,
    /// Turned off by the user's own words (full access, case 83).
    Off,
    /// Turned on by the user's own words, as written.
    On(String),
}

/// Reads Codex 0.163.0's sandbox flags in `rest`, at every level: `-s` and
/// `--sandbox` (`utils/cli/src/shared_options.rs:38-41`), `--approve-for-me`
/// and its alias `--not-so-yolo` (workspace-write, `:42-50, 82-94`), the
/// bypass flag and `--yolo` (`:52-59`), and `-c sandbox_mode=` or
/// `-c default_permissions=` in each form `-c` takes. Stops at `--`. A word
/// that turns the sandbox on wins over one that turns it off: Codex's `-s`
/// beats any `-c`, and the user's `-c` after derm's would win too.
pub fn codex_own_sandbox(rest: &[String]) -> CodexOwnSandbox {
    let unquote = |v: &str| {
        let v = v.trim();
        v.strip_prefix('"')
            .and_then(|x| x.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
            .unwrap_or(v)
            .to_string()
    };
    let mut on: Option<String> = None;
    let mut off = false;
    let mut i = 0;
    while i < rest.len() {
        let w = rest[i].as_str();
        if w == "--" {
            break;
        }
        let next = rest.get(i + 1).map(String::as_str);
        let mut take = |word: String, is_off: bool| {
            if is_off {
                off = true;
            } else if on.is_none() {
                on = Some(word);
            }
        };
        match w {
            "--dangerously-bypass-approvals-and-sandbox" | "--yolo" => take(w.into(), true),
            "--approve-for-me" | "--not-so-yolo" => take(w.into(), false),
            "-s" | "--sandbox" => {
                if let Some(v) = next {
                    take(format!("{w} {v}"), unquote(v) == "danger-full-access");
                    i += 1;
                }
            }
            "-c" | "--config" => {
                if let Some(pair) = next {
                    if let Some(hit) = codex_sandbox_pair(pair, &unquote) {
                        take(format!("{w} {pair}"), hit);
                    }
                    i += 1;
                }
            }
            _ => {
                if let Some(v) = w.strip_prefix("--sandbox=") {
                    take(w.into(), unquote(v) == "danger-full-access");
                } else if let Some(pair) = w.strip_prefix("--config=") {
                    if let Some(hit) = codex_sandbox_pair(pair, &unquote) {
                        take(w.into(), hit);
                    }
                } else if let Some(v) = w
                    .strip_prefix("-s")
                    .filter(|v| !v.is_empty() && !w.starts_with("--"))
                {
                    // FP8-S4: clap reads `-s=v` as `-s v`.
                    let v = v.strip_prefix('=').unwrap_or(v);
                    take(w.into(), unquote(v) == "danger-full-access");
                } else if let Some(pair) = w
                    .strip_prefix("-c")
                    .filter(|v| !v.is_empty() && !w.starts_with("--"))
                    .map(|v| v.strip_prefix('=').unwrap_or(v))
                {
                    if let Some(hit) = codex_sandbox_pair(pair, &unquote) {
                        take(w.into(), hit);
                    }
                }
            }
        }
        i += 1;
    }
    match (on, off) {
        (Some(w), _) => CodexOwnSandbox::On(w),
        (None, true) => CodexOwnSandbox::Off,
        (None, false) => CodexOwnSandbox::Unset,
    }
}

/// `Some(true)` for a `-c` pair that turns Codex's sandbox off, `Some(false)`
/// for one that chooses a sandboxed mode or profile, `None` for any other.
fn codex_sandbox_pair(pair: &str, unquote: &dyn Fn(&str) -> String) -> Option<bool> {
    let (k, v) = pair.split_once('=')?;
    match k.trim() {
        "sandbox_mode" => Some(unquote(v) == "danger-full-access"),
        "default_permissions" => Some(unquote(v) == ":danger-full-access"),
        _ => None,
    }
}

/// The refusal for a Codex chat under srt whose own sandbox would be on.
fn codex_sandbox_refusal(what: &str) -> String {
    format!(
        "codex: {what} keeps Codex's own sandbox on, and it cannot start inside srt's \
         (macOS refuses a second Seatbelt profile; srt on Linux refuses a nested user namespace), \
         so every command would fail while the turn reports it done (MW5-32). Under srt derm \
         turns Codex's own sandbox off and srt is its sandbox: leave the sandbox to derm, or run \
         with --boundary none to keep Codex's own"
    )
}

/// The name derm denies inside a missing control folder (MW5-32's Linux
/// half). Nothing creates it: srt holds the folder above it.
pub const ABSENT_FOLDER_MARK: &str = ".derm-absent";

/// Control entries that are folders, per harness, where it was read: Codex
/// 0.163.0 reads `rules` with `read_dir` (`core/src/exec_policy.rs:1121-1130`)
/// and keeps plugins in `plugins/cache` (the Mac's `~/.codex/plugins/cache`).
/// Other harnesses' control folders are not read for this yet.
fn control_folders(harness: &str) -> &'static [&'static str] {
    match harness {
        "codex" => &[
            ".codex/packages",
            ".codex/plugins",
            ".codex/prompts",
            ".codex/rules",
            ".codex/shell_snapshots",
            ".codex/tmp",
        ],
        _ => &[],
    }
}

/// MW5-32's Linux half (fix pass 8). srt 0.0.81 holds a `denyWrite` path that
/// does not exist by mounting over it, `/dev/null` for a file and an empty
/// read-only folder for a missing folder above it
/// (`linux-sandbox-utils.js:2334-2347`; README line 1128), so a missing
/// control folder becomes a device a program reading it as a folder fails on
/// (Codex: "failed to read rules files from ~/.codex/rules: Not a directory",
/// run). A missing control folder of the harness, in its home or the chat's
/// folder, is denied by a path inside it instead, so srt holds it as an
/// empty read-only folder: nothing can be made in it, and a reader finds no
/// entries (run in the cloud with srt 0.0.81). Linux only: Seatbelt denies
/// a path with no mount. `exists` follows no link the caller does not.
pub fn keep_absent_control_folders(
    p: &mut Plan,
    harness: &str,
    macos: bool,
    exists: &dyn Fn(&str) -> bool,
) {
    let folders = control_folders(harness);
    if macos || folders.is_empty() {
        return;
    }
    let Some(text) = p.srt_settings.as_deref() else {
        return;
    };
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let Some(list) = v["filesystem"]["denyWrite"].as_array_mut() else {
        return;
    };
    let mut inner = Vec::new();
    for e in list.iter() {
        let Some(path) = e
            .get("path")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
        else {
            continue;
        };
        let folder = folders.iter().any(|f| path.ends_with(&format!("/{f}")));
        if folder && !exists(&path) {
            inner.push(json!({"path": format!("{path}/{ABSENT_FOLDER_MARK}"), "literal": true}));
        }
    }
    // FP8-S5: beside the folder's own deny, never instead of it, so a folder
    // made between derm's look and srt's start is held too (run with srt
    // 0.0.81: with both, a missing folder is an empty read-only one and a
    // present one is read-only).
    let changed = !inner.is_empty();
    list.extend(inner);
    if changed {
        if let Ok(t) = serde_json::to_string_pretty(&v) {
            p.srt_settings = Some(t);
        }
    }
}

/// Fix pass 6 (FP5R-6): srt 0.0.81 resolves a configured path's links only
/// when the real path stays inside the path's own tree, and otherwise keeps
/// the spelling (`dist/sandbox/sandbox-utils.js:229-294, 480-490`), while
/// Seatbelt on macOS matches the kernel's real path, so a `denyWrite` of
/// `~/.claude/.credentials.json` with `~/.claude` linked to another folder
/// misses the file. Each deny in srt's settings (`denyRead`, `denyWrite`) is
/// written a second time by its real path when that differs, and so is each
/// literal `allowRead` inside a deny (one file, so nothing widens); the
/// write roots are left as they are (a link out of them fails closed).
/// `resolve` follows every link of the path, a missing last part kept as
/// written; `None` leaves the entry alone. Never `/`.
pub fn deny_real_paths(p: &mut Plan, resolve: &dyn Fn(&str) -> Option<String>) {
    let Some(text) = p.srt_settings.as_deref() else {
        return;
    };
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let mut linked: Vec<(String, String)> = Vec::new();
    let path_of = |e: &serde_json::Value| -> Option<String> {
        e.as_str()
            .or_else(|| e.get("path").and_then(serde_json::Value::as_str))
            .map(str::to_string)
    };
    for key in ["denyRead", "denyWrite", "allowRead"] {
        let Some(list) = v["filesystem"][key].as_array_mut() else {
            continue;
        };
        let mut extra = Vec::new();
        for e in list.iter() {
            if key == "allowRead" && e.get("literal") != Some(&json!(true)) {
                continue;
            }
            let Some(spelled) = path_of(e) else { continue };
            let Some(real) = resolve(&spelled) else {
                continue;
            };
            if real == spelled || real == "/" || !real.starts_with('/') {
                continue;
            }
            let mut twin = e.clone();
            match &mut twin {
                serde_json::Value::String(s) => *s = real.clone(),
                serde_json::Value::Object(m) => {
                    m.insert("path".into(), json!(real));
                }
                _ => continue,
            }
            if !list.contains(&twin) && !extra.contains(&twin) {
                extra.push(twin);
                if key != "allowRead" && !linked.iter().any(|(a, _)| *a == spelled) {
                    linked.push((spelled, real));
                }
            }
        }
        list.extend(extra);
    }
    if linked.is_empty() {
        return;
    }
    let Ok(text) = serde_json::to_string_pretty(&v) else {
        return;
    };
    p.srt_settings = Some(text);
    let shown: Vec<String> = linked
        .iter()
        .take(4)
        .map(|(a, b)| format!("{a} is {b}"))
        .collect();
    p.notes.push(format!(
        "derm run: {} of srt's denied paths reach another place through a link ({}{}); srt matches the place a link leads to on macOS and keeps the link's spelling, so derm denies the real path too",
        linked.len(),
        shown.join(", "),
        if linked.len() > 4 { ", ..." } else { "" }
    ));
}

/// The temp folder srt's settings let a chat write, named by its real path
/// (Mac test w5, MW5-13; case 111). On macOS `/tmp` is a link to
/// `/private/tmp`, and srt 0.0.81 keeps `/tmp` unresolved (its
/// `isSymlinkOutsideBoundary` exempts `/tmp/...`, not `/tmp` itself,
/// `dist/sandbox/sandbox-utils.js:229-292`), while Seatbelt compares the
/// kernel's real path: `/tmp` there granted nothing, and Claude Code's Bash
/// could not make its folder under `/private/tmp/claude-<uid>`.
pub fn srt_temp_root(macos: bool) -> &'static str {
    if macos {
        "/private/tmp"
    } else {
        "/tmp"
    }
}

#[derive(Debug, PartialEq)]
pub struct Plan {
    pub program: String,
    pub args: Vec<String>,
    /// Set in the child. Holds the token: never printed (`describe` shows
    /// names only).
    pub env_set: Vec<(String, String)>,
    pub env_remove: Vec<String>,
    pub kit: Option<String>,
    pub sandbox_name: Option<String>,
    /// srt's settings, written to `settings_path` (0600) before the start.
    pub srt_settings: Option<String>,
    /// The chat's folders and the harness's state folders, for `run.start`
    /// (the feed reads them).
    pub folders: Vec<String>,
    pub state_dirs: Vec<String>,
    /// Lines for the terminal: what the user may want to run themselves.
    pub notes: Vec<String>,
    /// The words that put the agent in full access (case 83).
    pub full_access: Vec<String>,
    /// A program derm starts beside the harness, outside any sandbox, and
    /// stops after it: lane P's Cline approval responder.
    pub companion: Option<(String, Vec<String>)>,
    /// A folder derm makes (0700) before the start and removes after it.
    pub scratch_dir: Option<String>,
}

/// A URL's parts: scheme, host (brackets removed), port (explicit or the
/// scheme's), and the rest from the first `/`. Only `http` and `https`.
pub fn split_url(url: &str) -> Option<(&str, String, u16, String)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let (h, p) = r.split_once(']')?;
        (h.to_string(), p.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (authority.to_string(), None),
        }
    };
    let port = match port {
        Some(p) => p.parse().ok().filter(|p| *p > 0)?,
        None if scheme == "https" => 443,
        None => 80,
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return None;
    }
    Some((scheme, host, port, path))
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn with_host(scheme: &str, host: &str, port: u16, path: &str) -> String {
    let h = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("{scheme}://{h}:{port}{path}")
}

/// A loopback URL as srt can allow it: `localhost` becomes `127.0.0.1`,
/// since srt resolves `localhost` to loopback and denies loopback unless an
/// IP literal is listed (srt README, "Resolved-address check").
fn srt_target(url: &str) -> Option<(String, String)> {
    let (scheme, host, port, path) = split_url(url)?;
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
    Some((with_host(scheme, &host, port, &path), allow))
}

/// A computer-use endpoint as the daemon writes it: a loopback address and a
/// port, nothing else (`127.0.0.1:<port>` or `[::1]:<port>`).
pub fn cu_endpoint_ok(e: &str) -> bool {
    let port = e
        .strip_prefix("127.0.0.1:")
        .or_else(|| e.strip_prefix("[::1]:"));
    port.is_some_and(|p| {
        !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && !p.starts_with('0')
            && p.parse::<u32>().is_ok_and(|n| (1..=65_535).contains(&n))
    })
}

pub fn build(i: &Inputs) -> Result<Plan, String> {
    let h: &Harness = i.args.harness;
    let home = i.home.trim_end_matches('/');
    let under_home = |rel: &str| format!("{home}/{rel}");
    let state_dirs: Vec<String> = h.state.iter().map(|s| under_home(s)).collect();
    let mut env: Vec<(String, String)> = vec![
        ("DERM_CHAT_ID".into(), i.chat.clone()),
        ("DERM_HARNESS".into(), h.id.into()),
        ("DERM_BOUNDARY".into(), i.args.boundary.name().into()),
    ];
    let mut otlp = i.otlp.clone();
    let mut gateway = i.gateway.clone();
    if let Some(g) = &gateway {
        if split_url(g).is_none() {
            return Err(format!(
                "--gateway-url {g:?} is not an http(s) URL with a host"
            ));
        }
    }
    let mut notes = Vec::new();
    // Case 80: the program named after `--`, else the harness's command.
    let command: String = i
        .args
        .program
        .clone()
        .unwrap_or_else(|| h.command.to_string());
    let mut program = command.clone();
    if h.id == "other" {
        notes.push(format!(
            "derm run: {command} has no preset: outside shape only (the boundary, the chat's variables, the OS feed); derm writes nothing into its config"
        ));
    }
    // Case 83: flags that turn the agent's own approvals off.
    let mut full = full_access(&i.args.rest, h.id, i.goose_mode.as_deref());
    // Launch settings (T2.9), before the boundary wraps the command.
    let mut launch_args: Vec<String> = Vec::new();
    let mut companion = None;
    let mut scratch_dir = None;
    match h.launch {
        Launch::None => {}
        Launch::Cline => {
            env.push(("CLINE_TOOL_APPROVAL_MODE".into(), "desktop".into()));
            env.push(("CLINE_TOOL_APPROVAL_DIR".into(), i.cline_dir.clone()));
            scratch_dir = Some(i.cline_dir.clone());
            let says_auto_approve = i
                .args
                .rest
                .iter()
                .any(|a| a == "--auto-approve" || a.starts_with("--auto-approve="));
            if !says_auto_approve {
                launch_args.extend(["--auto-approve".to_string(), "false".into()]);
            }
            if full.iter().any(|f| f.starts_with("--auto-approve")) {
                notes.push(
                    "derm run: --auto-approve true: Cline writes no approval file, so derm's responder sees no call (case 83)".into(),
                );
            }
            match &i.cline_responder {
                Some(r) => {
                    companion = Some((r.clone(), vec!["--dir".to_string(), i.cline_dir.clone()]))
                }
                None => notes.push(
                    "derm run: derm-cline-responder is not on PATH: Cline asks through its approval files and, with no answer, denies each gated call after 5 minutes".into(),
                ),
            }
            notes.push(
                "derm run: Cline answers its approval files only in a run with a prompt (an argument or piped stdin); the TUI uses its own approver".into(),
            );
        }
        Launch::Goose => {
            if i.goose_mode.is_none() && i.policy_asks {
                env.push(("GOOSE_MODE".into(), "approve".into()));
                notes.push(
                    "derm run: GOOSE_MODE=approve: the policy can ask, and goose's default, Auto, approves before its hook runs".into(),
                );
            }
        }
    }
    let mut args: Vec<String> = Vec::new();
    let mut kit = None;
    let mut sandbox_name = None;
    let mut srt_settings = None;
    match i.args.boundary {
        Boundary::None => {
            args.extend(launch_args.iter().cloned());
            args.extend(i.args.rest.iter().cloned());
            notes.push(format!(
                "derm run: {} runs with no sandbox; only its own gate and the OS feed watch it",
                h.id
            ));
        }
        Boundary::Sbx => {
            let sbx = h.sbx().ok_or_else(|| {
                format!(
                    "{} has no sbx form here (no built-in agent, no kit known); use srt or none",
                    h.id
                )
            })?;
            for url in [&mut otlp, &mut gateway].into_iter().flatten() {
                let (scheme, host, port, path) = split_url(url).ok_or("bad URL")?;
                if is_loopback(&host) {
                    *url = with_host(scheme, "host.docker.internal", port, &path);
                    notes.push(format!(
                        "derm run: the sandbox reaches the host's port {port} through a rule derm adds for this sandbox alone \
                         (sbx policy allow network --sandbox <its name> localhost:{port}), gone with the sandbox"
                    ));
                }
            }
            // Case 83 under sbx (request T-5): the kit starts the agent with
            // its own approvals off (`fullAccess`, read in each kit's
            // spec.yaml), whatever the command line says, so the gate gets
            // the hint and the record says so. A kit named with --kit is the
            // user's, and its words are not known.
            if i.args.kit.is_none() {
                for w in &sbx.full_access {
                    if !full.contains(w) {
                        full.push(w.clone());
                    }
                }
            }
            program = "sbx".into();
            // The chat id already starts with `derm-` (SB2: not `derm-derm-`),
            // and sbx refuses an underscore a `--chat` id may hold (lane T).
            let name = super::boundary::sbx::sandbox_name(&i.chat);
            args.extend(["run".to_string(), "--name".into(), name.clone()]);
            sandbox_name = Some(name);
            // The variables are named here and copied by sbx from its own
            // environment (`-e KEY`), which the child gets below.
            let mut names: Vec<&str> = OWNED_VARS.to_vec();
            names.retain(|n| *n != "DERM_CHAT_TOKEN" || i.token.is_some());
            // A host path means nothing inside the sandbox.
            names.retain(|n| {
                *n != "DERM_CHAT_TOKEN_FILE"
                    && *n != "GEMINI_CLI_DERM_CHAT_TOKEN_FILE"
                    && *n != "DERM_DAEMON_SOCKET"
            });
            names.retain(|n| *n != "DERM_OTLP_ENDPOINT" || otlp.is_some());
            names.retain(|n| *n != "DERM_FULL_ACCESS" || !full.is_empty());
            names.retain(|n| *n != "DERM_GATEWAY_URL" || gateway.is_some());
            for n in names {
                args.extend(["-e".to_string(), n.to_string()]);
            }
            let k = i.args.kit.clone().or(sbx.kit.clone());
            if let Some(k) = &k {
                args.extend(["--kit".to_string(), k.clone()]);
            }
            kit = k;
            args.push(sbx.agent.clone());
            args.push(i.cwd.clone());
            if !i.args.rest.is_empty() || !launch_args.is_empty() {
                args.push("--".into());
                args.extend(launch_args.iter().cloned());
                args.extend(i.args.rest.iter().cloned());
            }
            notes.push(
                "derm run: sbx runs the harness with its own defaults inside the VM, and local stdio MCP servers run on the host"
                    .into(),
            );
        }
        Boundary::Srt => {
            // srt's own subcommands must not be reachable as a harness name.
            if matches!(
                command.as_str(),
                "proxy" | "windows-install" | "windows-uninstall"
            ) {
                return Err(format!("{command} collides with an srt subcommand"));
            }
            // MW5-32: Codex's own sandbox cannot start inside srt's, so derm
            // turns it off and srt is its sandbox; a user's own word that
            // keeps it on, or a managed file that does, is refused first.
            let codex_sandbox_off = if h.id == "codex" {
                match codex_own_sandbox(&i.args.rest) {
                    CodexOwnSandbox::On(word) => return Err(codex_sandbox_refusal(&word)),
                    CodexOwnSandbox::Off => false,
                    CodexOwnSandbox::Unset => {
                        if let Some(why) = &i.codex_store.managed_sandbox {
                            return Err(codex_sandbox_refusal(why));
                        }
                        true
                    }
                }
            } else {
                false
            };
            let mut allowed: Vec<String> = Vec::new();
            for url in [&mut otlp, &mut gateway].into_iter().flatten() {
                let (rewritten, allow) = srt_target(url).ok_or("bad URL")?;
                *url = rewritten;
                allowed.push(allow);
            }
            if let Some(m) = &i.args.model_url {
                let (_, allow) = srt_target(m)
                    .ok_or_else(|| format!("--model-url {m:?} is not an http(s) URL"))?;
                allowed.push(allow);
            }
            allowed.extend(i.args.allow_hosts.iter().cloned());
            // MW5-22: the computer-use bridge's loopback port, through srt's
            // proxy like derm's other ports (case 163); the relay tunnels to it
            // with CONNECT (`bridge_cli::dial`). Only a loopback address.
            let cu = i.cu_endpoint.as_deref().filter(|e| cu_endpoint_ok(e));
            if let Some(e) = cu {
                allowed.push(e.to_string());
            }
            // MW5-24: the harness's own sign-in host, so it can renew an
            // expired access token inside srt (`harness::sign_in_hosts`).
            // MW5-26: not on macOS for a harness whose sign-in lives in the
            // keychain, which srt does not let it write: a renewal there
            // would land in a plaintext file and leave the keychain's token
            // stale, so the host stays shut and the file read-only.
            let keychain = i
                .macos
                .then(|| super::harness::macos_keychain_fallback(h.id))
                .flatten();
            // FP5R-5: Codex set to keep its sign-in in a keyring (`keyring`,
            // or `auto`, which falls back to `auth.json`), on any system:
            // srt lets it write neither the macOS keychain nor, on Linux, the
            // Secret Service's D-Bus, so a renewal would spend the keyring's
            // single-use refresh token (`run::codex_store`).
            let codex_keyring = (h.id == "codex")
                .then(|| codex_store_risk(&i.args.rest, &i.codex_store))
                .flatten();
            let sign_in: &[&str] = if keychain.is_some() {
                notes.push(format!(
                    "derm run: under srt on macOS {} cannot save a renewed sign-in in your keychain, so derm keeps its sign-in host shut and ~/{} read-only: once its access token expires the chat stops; run it once outside srt to renew, then start the chat again",
                    h.id,
                    keychain.unwrap_or_default()
                ));
                &[]
            } else if let Some(why) = &codex_keyring {
                notes.push(format!(
                    "derm run: codex may keep its sign-in in a keyring here ({why}), which srt does not let it write, so derm keeps its sign-in host shut and its auth.json read-only: once its access token expires the chat stops; run it once outside srt to renew, then start the chat again"
                ));
                &[]
            } else {
                super::harness::sign_in_hosts(h.id)
            };
            if !sign_in.is_empty() {
                allowed.extend(sign_in.iter().map(|s| s.to_string()));
                // FP4-S7: srt admits by host and port only (TLS is opaque to
                // its proxy), so every path on that host is open to every
                // process in the sandbox, and the tap records none of it.
                notes.push(format!(
                    "derm run: under srt {} may reach its sign-in host {} to renew its sign-in; srt admits any request on that host and port, and derm records none of them",
                    h.id,
                    sign_in.join(", ")
                ));
            }
            allowed.sort();
            allowed.dedup();
            let mut deny_read: Vec<String> = [
                ".ssh",
                ".gnupg",
                ".aws",
                ".config/gh",
                ".kube",
                ".password-store",
                ".local/share/keyrings",
                ".docker/config.json",
                ".netrc",
                ".git-credentials",
                ".derm",
                // The old name's folder, hidden while a tk install may be left
                // (rename review R1). derm never reads it.
                ".tk",
            ]
            .iter()
            .map(|r| under_home(r))
            .collect();
            if let Some(d) = &i.daemon_dir {
                deny_read.push(d.clone());
                // `$XDG_RUNTIME_DIR/tk` beside `$XDG_RUNTIME_DIR/derm`: a
                // tk-daemon's token (R1).
                if let Some(rt) = d.strip_suffix("/derm") {
                    deny_read.push(format!("{rt}/tk"));
                }
            }
            for other in HARNESSES.iter().filter(|o| o.id != h.id) {
                if let Some(c) = other.credential {
                    if Some(c) != h.credential {
                        deny_read.push(under_home(c));
                    }
                }
            }
            deny_read.sort();
            deny_read.dedup();
            // The gate's policy file, re-opened read-only inside the hidden
            // `~/.derm` (box test w1, BX2; srt 0.0.81 README line 119: an
            // `allowRead` beneath a broader `denyRead` wins, and line 584:
            // a `literal` entry is a path, never a pattern). Only a `.json`
            // directly in `~/.derm`: a `DERM_POLICY` naming anything else could
            // re-open a file srt hides on purpose.
            let derm_dir = under_home(".derm");
            let policy_ok = Path::new(&i.policy)
                .parent()
                .is_some_and(|d| d == Path::new(&derm_dir))
                && i.policy.ends_with(".json")
                && !i.policy.contains("/../")
                && !i.policy.contains("/./")
                && i.policy_regular;
            let mut allow_read = if policy_ok {
                vec![json!({"path": i.policy, "literal": true})]
            } else {
                notes.push(format!(
                    "derm run: {} is not a regular .json file of yours directly in {derm_dir} (no link, one name, not writable by others), so srt keeps it hidden and the gate inside finds no policy: every call will ask",
                    i.policy
                ));
                vec![]
            };
            // MW5-5's gate half, macOS: the daemon's folder stays hidden, and
            // its socket alone is re-opened, so the gate inside can check the
            // socket's owner and connect, and still read no token beside it
            // (Mac test w5, case d, run with srt 0.0.81: `allowUnixSockets`
            // admits the connect, `macos-sandbox-utils.js:966-979`;
            // `allowRead` the `lstat` the hook's owner check makes). srt
            // ignores `allowUnixSockets` on Linux, where seccomp refuses every
            // `socket(AF_UNIX)` (README lines 517-523), so nothing is added
            // there. The chat's token already scopes it to its own chat (case
            // 66); the socket gives it nothing the token does not.
            let mut unix_sockets: Vec<String> = Vec::new();
            if i.macos {
                if let Some(sock) = i.daemon_socket.as_deref().filter(|s| s.starts_with('/')) {
                    unix_sockets.push(sock.to_string());
                    allow_read.push(json!({"path": sock, "literal": true}));
                    env.push(("DERM_DAEMON_SOCKET".into(), sock.to_string()));
                }
            }
            // MW5-22: `cu.endpoint` beside the socket, re-opened read-only
            // like the socket (a literal path, so nothing else in the folder),
            // with the socket named so the relay finds that folder (macOS sets
            // it above; on Linux the relay's default is the same path).
            if cu.is_some() {
                if let Some(d) = &i.daemon_dir {
                    allow_read.push(json!({"path": format!("{}/cu.endpoint", d.trim_end_matches('/')), "literal": true}));
                }
                if !i.macos {
                    if let Some(sock) = i.daemon_socket.as_deref().filter(|s| s.starts_with('/')) {
                        env.push(("DERM_DAEMON_SOCKET".into(), sock.to_string()));
                    }
                }
            }
            let mut allow_write = vec![i.cwd.clone()];
            allow_write.extend(state_dirs.iter().cloned());
            allow_write.push(srt_temp_root(i.macos).into());
            // The gate's own switches stay read-only inside the state srt
            // lets the harness write (integration w1, security finding S6):
            // its hooks, plugin lists and MCP files, and derm's folder. srt
            // 0.0.81: `denyWrite` takes precedence over `allowWrite` (README
            // line 537); a literal entry is a path, never a pattern, and holds
            // for a file that does not exist yet (line 584).
            let mut deny_write: Vec<String> = h.control.iter().map(|c| under_home(c)).collect();
            // The chat's folder is writable too, and an agent loads a
            // project's own copy of its control files (Cline its
            // `.cline/plugins` and `.cline/hooks` with no trust prompt,
            // `packages/derm-cline/src/control.ts`), so the same paths there
            // are read-only, and Cline's `.clinerules` (re-review W4-R3).
            let cwd = i.cwd.trim_end_matches('/');
            if h.id == "codex" && cwd != home.trim_end_matches('/') {
                // FP8-S3: the whole project `.codex`, as Codex's own sandbox
                // held it (`protocol/src/permissions.rs:46-50`): one deny per
                // control file there left a missing `config.toml` held by
                // `/dev/null` on Linux, which Codex stops on
                // (`config/src/loader/mod.rs:1779-1796`); a missing folder is
                // held by `/dev/null`, which Codex skips as no folder
                // (`:1705-1714`). Not when the chat's folder is the home, whose
                // `.codex` is Codex's state.
                deny_write.push(format!("{cwd}/.codex"));
            } else {
                deny_write.extend(h.control.iter().map(|c| format!("{cwd}/{c}")));
            }
            // FP8-S2, FP8R-5: the git files srt's own denies leave out.
            deny_write.extend(
                i.git_controls
                    .iter()
                    .filter(|m| m.starts_with('/'))
                    .cloned(),
            );
            // FP8-S1: Codex's profile layers in its home.
            if h.id == "codex" {
                deny_write.extend(
                    i.codex_store
                        .profiles
                        .iter()
                        .filter(|p| p.starts_with('/'))
                        .cloned(),
                );
            }
            if h.id == "cline" {
                deny_write.push(format!("{cwd}/.clinerules"));
            }
            // Cursor runs Claude Code's hooks from a project's settings and
            // enabled plugins as third-party hooks
            // (https://cursor.com/docs/reference/third-party-hooks; seen on
            // the Mac, Mac test w4, MW4-5), so those stay read-only in the
            // chat's folder (fix pass 1's review, FP4-S1). They are not
            // Cursor's state, so they are not in its control list.
            // The whole `.claude` folder (re-review FP5-R4, FP5-R5: its hook
            // scripts, and a missing folder made as a link elsewhere; srt
            // mounts a read-only folder there on Linux and covers new paths
            // on macOS).
            if h.id == "cursor" {
                for c in [
                    ".claude/settings.json",
                    ".claude/settings.local.json",
                    ".claude/plugins",
                    ".claude",
                ] {
                    deny_write.push(format!("{cwd}/{c}"));
                }
            }
            // What derm's registered gate runs, wherever it sits (re-review
            // FP5-R2): a chat folder that is a derm clone holds the gate.
            deny_write.extend(i.gate_paths.iter().filter(|p| p.starts_with('/')).cloned());
            deny_write.push(under_home(".derm"));
            deny_write.push(under_home(".tk"));
            // MW5-26: never a plaintext copy of a keychain sign-in; FP5R-5:
            // nor of a Codex keyring one.
            deny_write.extend(keychain.map(under_home));
            if codex_keyring.is_some() {
                deny_write.push(under_home(".codex/auth.json"));
                deny_write.extend(
                    i.codex_store
                        .auth_file
                        .iter()
                        .filter(|p| p.starts_with('/'))
                        .cloned(),
                );
            }
            deny_write.sort();
            deny_write.dedup();
            let deny_write: Vec<serde_json::Value> = deny_write
                .into_iter()
                .map(|p| json!({"path": p, "literal": true}))
                .collect();
            let mut network = json!({
                "allowedDomains": allowed,
                "deniedDomains": [],
            });
            if !unix_sockets.is_empty() {
                network["allowUnixSockets"] = json!(unix_sockets);
            }
            let mut settings = json!({
                "network": network,
                "filesystem": {
                    "denyRead": deny_read,
                    "allowRead": allow_read,
                    "allowWrite": allow_write,
                    // srt also refuses writes to .git/hooks, .git/config,
                    // shell rc files, .vscode and .claude/commands on its own
                    // (README, "Mandatory Deny Paths").
                    "denyWrite": deny_write,
                },
            });
            // MW5-8: a harness on a terminal needs `ioctl` on its own
            // `/dev/ttys*` to read keys (raw mode); srt 0.0.81 on macOS allows
            // that only with `allowPty` (`macos-sandbox-utils.js:910-915,
            // 1021-1034`), and without it Claude Code's TUI took no keys.
            // `allowPty` opens read, write and `ioctl` on every `/dev/ttys*`
            // of the user's: another terminal's output and its input race,
            // not an injection into it (XNU `tty.c:1431-1439`: TIOCSTI needs
            // the caller's controlling tty unless root). Set only for a
            // harness started on a terminal, and said at the start.
            if i.macos && i.terminal {
                settings["allowPty"] = json!(true);
                notes.push(
                    "derm run: on a terminal under srt on macOS the harness gets srt's allowPty, so it can read keys: it can also read your other terminals (/dev/ttys*) and write to them, which can change what they show you, though it cannot type into them; start it with no terminal to leave it off"
                        .into(),
                );
            }
            srt_settings =
                Some(serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?);
            program = "srt".into();
            args.extend([
                "--settings".to_string(),
                i.settings_path.clone(),
                "--".into(),
                command.clone(),
            ]);
            args.extend(launch_args.iter().cloned());
            if codex_sandbox_off {
                // At derm's own `-c` level (case 184): after a session
                // subcommand that is the first word, else first, where the
                // tap's and the export's pairs go too.
                let lead = i
                    .args
                    .rest
                    .first()
                    .filter(|w| super::tap::CODEX_SESSION_SUBCOMMANDS.contains(&w.as_str()));
                args.extend(lead.cloned());
                args.extend(["-c".to_string(), CODEX_SANDBOX_OFF.to_string()]);
                args.extend(
                    i.args
                        .rest
                        .iter()
                        .skip(usize::from(lead.is_some()))
                        .cloned(),
                );
                notes.push(format!(
                    "derm run: Codex's own sandbox (Seatbelt on macOS, bubblewrap on Linux) cannot start inside srt's, so derm starts codex with -c {CODEX_SANDBOX_OFF} and srt is its sandbox: its commands may write this folder, srt's temp folder and Codex's home, but not .git/hooks, .git/config, a submodule's git config or hooks, a config.worktree, this folder's .codex, or Codex's config, .env, profiles, AGENTS.md, prompts, hooks, rules, plugins, packages, shell_snapshots and tmp (its skills, memories, sessions and logs stay writable); Codex's own hold on all of .git, .agents and .aws is off; they reach only the hosts srt lists, whatever sandbox_mode or default_permissions Codex's config sets, and Codex no longer asks to leave a sandbox. Its approvals are unchanged. To keep Codex's own sandbox, run with --boundary none"
                ));
                if lead.is_some_and(|w| w == "app-server") {
                    notes.push(
                        "derm run: a client that sets Codex's sandbox for a thread (app-server's thread/start) overrides this, and that thread's commands then fail under srt"
                            .into(),
                    );
                }
            } else {
                args.extend(i.args.rest.iter().cloned());
            }
            // Node's fetch takes srt's proxy only when asked (srt README,
            // "Node.js (Windows)": srt sets this on Windows only).
            env.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
        }
    }
    if let Some(t) = &i.token {
        env.push(("DERM_CHAT_TOKEN".into(), t.clone()));
        if i.args.boundary == Boundary::None {
            env.push(("DERM_CHAT_TOKEN_FILE".into(), i.token_file.clone()));
            // The socket this token came from, so the hook does not work it
            // out again from an environment that may not name the runtime
            // folder (release check RC6). The path only.
            if let Some(sock) = &i.daemon_socket {
                env.push(("DERM_DAEMON_SOCKET".into(), sock.clone()));
            }
            // Gemini CLI drops every variable named like a token from a
            // hook's environment under its env redaction, and always keeps
            // GEMINI_CLI_* (gemini-cli v0.66.0
            // environmentSanitization.ts:13-195, run by lane I); the
            // extension's hook reads this alias. The path only, never the
            // token (lane I's request 1, integration w2).
            if h.id == "gemini" {
                env.push((
                    "GEMINI_CLI_DERM_CHAT_TOKEN_FILE".into(),
                    i.token_file.clone(),
                ));
            }
        }
    }
    if let Some(o) = &otlp {
        env.push(("DERM_OTLP_ENDPOINT".into(), o.clone()));
    }
    if let Some(g) = &gateway {
        env.push(("DERM_GATEWAY_URL".into(), g.clone()));
    }
    if !full.is_empty() {
        // A hint for the gate (case 83): the hook core (`decideCall`) and
        // `derm acp` turn an ask into a deny on it (integration w4, lane R's
        // request 1). derm-pi's card still asks: Pi has no approvals of its
        // own that a bypass flag could turn off.
        env.push(("DERM_FULL_ACCESS".into(), "1".into()));
        notes.push(format!(
            "derm run: {} turns the harness's own approvals off (full access): recorded in run.start and shown by derm status; DERM_FULL_ACCESS=1 is set, so derm's hook gates and derm acp deny what they would ask",
            full.join(" ")
        ));
    }
    if let (true, Some(prog)) = (i.args.harness.id == "other", i.args.program.as_deref()) {
        if let Some(h) = super::harness::by_basename(prog).filter(|_| prog.contains('/')) {
            notes.push(format!(
                "derm run: {prog} is run as an unknown program, with no preset's folders; derm gives {}'s folders only to the bare name on PATH (`-- {}`)",
                h.id, h.command
            ));
        }
    }
    let plan = Plan {
        program,
        args,
        env_set: env,
        env_remove: OWNED_VARS.iter().map(|s| s.to_string()).collect(),
        kit,
        sandbox_name,
        srt_settings,
        folders: vec![i.cwd.clone()],
        state_dirs,
        notes,
        full_access: full,
        companion,
        scratch_dir,
    };
    no_token_in_args(&plan, i.token.as_deref())?;
    Ok(plan)
}

/// Defence in depth: the token never rides in an argument (rules section
/// 5, item 1). Run on the plan, and again on the argv derm adds to after it
/// (the OTel export; security review L13).
pub fn no_token_in_args(p: &Plan, token: Option<&str>) -> Result<(), String> {
    match token {
        Some(t) if !t.is_empty() && p.args.iter().any(|a| a.contains(t)) => {
            Err("internal: the chat token reached the command line; refusing to start".into())
        }
        _ => Ok(()),
    }
}

impl Plan {
    /// The parts `exec::spawn` reads, for a start under another program
    /// path (tests point `sbx` and `srt` at fakes).
    pub fn clone_for_start(&self) -> Plan {
        Plan {
            program: self.program.clone(),
            args: self.args.clone(),
            env_set: self.env_set.clone(),
            env_remove: self.env_remove.clone(),
            kit: None,
            sandbox_name: None,
            srt_settings: None,
            folders: Vec::new(),
            state_dirs: Vec::new(),
            notes: Vec::new(),
            full_access: Vec::new(),
            companion: None,
            scratch_dir: None,
        }
    }
}

/// The plan as the terminal shows it: argv, variable names (values only for
/// variables that carry no secret), the srt settings.
pub fn describe(p: &Plan) -> String {
    let mut s = String::new();
    s.push_str(&format!("program: {}\n", p.program));
    s.push_str(&format!(
        "argv: {}\n",
        serde_json::to_string(&p.args).unwrap_or_default()
    ));
    for (k, v) in &p.env_set {
        if k == "DERM_CHAT_TOKEN" {
            s.push_str(&format!("env: {k}=<chat token, not shown>\n"));
        } else {
            s.push_str(&format!("env: {k}={v}\n"));
        }
    }
    if let Some(k) = &p.kit {
        s.push_str(&format!("kit: {k}\n"));
    }
    if let Some((prog, args)) = &p.companion {
        s.push_str(&format!(
            "beside it: {prog} {}\n",
            serde_json::to_string(args).unwrap_or_default()
        ));
    }
    if let Some(t) = &p.srt_settings {
        s.push_str("srt settings:\n");
        s.push_str(t);
        s.push('\n');
    }
    for n in &p.notes {
        s.push_str(n);
        s.push('\n');
    }
    s
}

/// srt 0.0.81's own `NO_PROXY` without its loopback names
/// (`dist/sandbox/sandbox-utils.js:705-720`).
pub const SRT_NO_PROXY_WITHOUT_LOOPBACK: &str =
    "169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

/// Mac test w5, MW5-5 (and Linux, run in the cloud): under srt the harness
/// reaches derm's own loopback ports (the tap, the OTLP receiver) only
/// through srt's proxy, which admits exactly the `allowedDomains` derm
/// lists. srt sets `NO_PROXY` to `localhost,127.0.0.1,::1,...` (srt 0.0.81
/// `sandbox-utils.js:705-720`), so a client goes direct, and a direct
/// connect fails: on Linux the sandbox has its own loopback (bwrap
/// `--unshare-net`, README line 124), on macOS Seatbelt admits loopback only
/// to the proxy's ports (`macos-sandbox-utils.js:944-992`). srt sets its
/// variables before the command runs (`env` on macOS, bwrap `--setenv` on
/// Linux), so `/usr/bin/env` in front of the harness, inside the sandbox,
/// takes the loopback names out of `NO_PROXY`. Nothing is widened: the
/// proxy still refuses any port not listed (403, run). A no-op for any
/// other boundary.
pub fn srt_loopback_through_proxy(p: &mut Plan) {
    if p.program != "srt" {
        return;
    }
    let Some(at) = p.args.iter().position(|a| a == "--") else {
        return;
    };
    // env reads `A=b` as a variable and `-x` as its own option, and would
    // run the next word instead (review F5): such a word is left unwrapped.
    if p.args
        .get(at + 1)
        .is_none_or(|w| w.starts_with('-') || w.contains('='))
    {
        return;
    }
    let wrap = [
        "/usr/bin/env".to_string(),
        format!("NO_PROXY={SRT_NO_PROXY_WITHOUT_LOOPBACK}"),
        format!("no_proxy={SRT_NO_PROXY_WITHOUT_LOOPBACK}"),
    ];
    p.args.splice(at + 1..at + 1, wrap);
}

/// Mac test w5, MW5-15 (and Linux, reproduced in the cloud): Claude Code
/// 2.1.311's OTLP exporter never sends a loopback endpoint through a proxy
/// (its agent chooser skips the proxy for a hostname `localhost`, `::1` or
/// `127.x.x.x`, read in the binary), and under srt a direct loopback connect
/// fails, so a chat under srt sent no OTel record. The same port spelled as
/// an IPv4-mapped address is not loopback to that check, so the export goes
/// through srt's proxy, which admits it under derm's `127.0.0.1:<port>`
/// entry and passes `Host: 127.0.0.1:<port>` on (srt 0.0.81, run). Only the
/// `OTEL_EXPORTER_OTLP_*ENDPOINT` variables change, and only a plain
/// `http://127.0.0.1:<port>`; a no-op for any other boundary.
pub fn srt_otlp_through_proxy(p: &mut Plan) {
    if p.program != "srt" {
        return;
    }
    for (k, v) in p.env_set.iter_mut() {
        let named = k == "OTEL_EXPORTER_OTLP_ENDPOINT"
            || (k.starts_with("OTEL_EXPORTER_OTLP_") && k.ends_with("_ENDPOINT"));
        if !named {
            continue;
        }
        let Some(rest) = v.strip_prefix("http://127.0.0.1:") else {
            continue;
        };
        let port = rest.split('/').next().unwrap_or("");
        if port.parse::<u16>().is_ok_and(|n| n != 0) {
            *v = format!("http://[::ffff:127.0.0.1]:{rest}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::args::parse;

    const TOKEN: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn inputs<'a>(args: &'a Args) -> Inputs<'a> {
        Inputs {
            args,
            chat: "chat-b".into(),
            cwd: "/home/u/proj dir".into(),
            home: "/home/u".into(),
            token: Some(TOKEN.into()),
            otlp: Some("http://127.0.0.1:4318".into()),
            gateway: Some("http://127.0.0.1:8811/mcp".into()),
            daemon_dir: Some("/run/user/1000/derm".into()),
            daemon_socket: Some("/run/user/1000/derm/daemon.sock".into()),
            settings_path: "/run/user/1000/derm/srt/chat-b.json".into(),
            token_file: "/run/user/1000/derm/chats/chat-b.token".into(),
            policy: "/home/u/.derm/policy.json".into(),
            policy_regular: true,
            policy_asks: true,
            goose_mode: None,
            cline_dir: "/home/u/.cline/derm-approval/chat-b".into(),
            cline_responder: Some("/usr/local/bin/derm-cline-responder".into()),
            gate_paths: Vec::new(),
            git_controls: Vec::new(),
            cu_endpoint: None,
            macos: false,
            terminal: false,
            codex_store: CodexStoreFiles::default(),
        }
    }

    fn a(v: &[&str]) -> Args {
        parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn env<'p>(p: &'p Plan, k: &str) -> Option<&'p str> {
        p.env_set
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn none_is_the_bare_harness_with_the_chats_variables() {
        let args = a(&["pi", "--boundary", "none", "--", "-c", "a b"]);
        let p = build(&inputs(&args)).unwrap();
        assert_eq!(p.program, "pi");
        assert_eq!(p.args, vec!["-c", "a b"]);
        assert_eq!(env(&p, "DERM_CHAT_TOKEN"), Some(TOKEN));
        assert_eq!(env(&p, "DERM_OTLP_ENDPOINT"), Some("http://127.0.0.1:4318"));
        assert_eq!(
            env(&p, "DERM_GATEWAY_URL"),
            Some("http://127.0.0.1:8811/mcp")
        );
        assert_eq!(env(&p, "DERM_BOUNDARY"), Some("none"));
        // Who it runs as is said once lane V's seam decides (BW5-16).
        assert!(p.notes.iter().any(|n| n.contains("runs with no sandbox")));
        assert!(!p.notes.iter().any(|n| n.contains("as you")));
        for v in OWNED_VARS {
            assert!(p.env_remove.iter().any(|r| r == v), "{v} is cleared first");
        }
    }

    /// Integration w1: hooks read the chat token from a file when a harness
    /// strips secret-named variables (rules case 76). Only the bare boundary
    /// names it: srt hides the daemon's folder and sbx cannot see host paths.
    #[test]
    fn the_token_file_is_named_only_for_the_bare_boundary_and_only_with_a_token() {
        for (b, want) in [("none", true), ("srt", false), ("sbx", false)] {
            let args = a(&["pi", "--boundary", b]);
            let p = build(&inputs(&args)).unwrap();
            assert_eq!(
                env(&p, "DERM_CHAT_TOKEN_FILE"),
                want.then_some("/run/user/1000/derm/chats/chat-b.token"),
                "{b}"
            );
            assert!(
                !p.args.iter().any(|x| x.contains("DERM_CHAT_TOKEN_FILE")),
                "{b}"
            );
        }
        let args = a(&["pi", "--boundary", "none"]);
        let mut i = inputs(&args);
        i.token = None;
        assert!(env(&build(&i).unwrap(), "DERM_CHAT_TOKEN_FILE").is_none());
        assert!(OWNED_VARS.contains(&"DERM_CHAT_TOKEN_FILE"));
    }

    /// Release check RC6: `derm run` found the daemon through a private
    /// `/run/user/<uid>` that the harness's own environment does not name
    /// (an SSH shell with no `XDG_RUNTIME_DIR`), so the hook must be told
    /// which socket minted its token. Only the bare boundary reaches the
    /// host's socket; an inherited value is cleared everywhere.
    #[test]
    fn the_daemon_socket_is_named_only_for_the_bare_boundary_and_only_with_a_token() {
        let sock = "/run/user/1000/derm/daemon.sock";
        for (b, want) in [("none", true), ("srt", false), ("sbx", false)] {
            let args = a(&["claude-code", "--boundary", b]);
            let p = build(&inputs(&args)).unwrap();
            assert_eq!(env(&p, "DERM_DAEMON_SOCKET"), want.then_some(sock), "{b}");
            assert!(
                !p.args.iter().any(|x| x.contains("DERM_DAEMON_SOCKET")),
                "{b}: never an sbx -e name or an argument"
            );
            assert!(
                p.env_remove.iter().any(|r| r == "DERM_DAEMON_SOCKET"),
                "{b}"
            );
        }
        let args = a(&["claude-code", "--boundary", "none"]);
        let mut i = inputs(&args);
        i.token = None;
        assert!(env(&build(&i).unwrap(), "DERM_DAEMON_SOCKET").is_none());
        assert!(OWNED_VARS.contains(&"DERM_DAEMON_SOCKET"));
    }

    /// Lane I's request 1: Gemini's hook gets the token file under the name
    /// Gemini's env redaction keeps; no other harness gets the alias.
    #[test]
    fn gemini_also_gets_the_token_file_under_its_kept_prefix() {
        let args = a(&["gemini", "--boundary", "none"]);
        let p = build(&inputs(&args)).unwrap();
        let file = Some("/run/user/1000/derm/chats/chat-b.token");
        assert_eq!(env(&p, "DERM_CHAT_TOKEN_FILE"), file);
        assert_eq!(env(&p, "GEMINI_CLI_DERM_CHAT_TOKEN_FILE"), file);
        for h in ["pi", "claude-code"] {
            let args = a(&[h, "--boundary", "none"]);
            let p = build(&inputs(&args)).unwrap();
            assert!(env(&p, "GEMINI_CLI_DERM_CHAT_TOKEN_FILE").is_none(), "{h}");
        }
        assert!(OWNED_VARS.contains(&"GEMINI_CLI_DERM_CHAT_TOKEN_FILE"));
    }

    #[test]
    fn sbx_for_pi_uses_the_kit_names_variables_and_rewrites_loopback() {
        let args = a(&["pi", "--boundary", "sbx", "--", "-p", "hi"]);
        let p = build(&inputs(&args)).unwrap();
        assert_eq!(p.program, "sbx");
        assert_eq!(
            p.args,
            vec![
                "run",
                "--name",
                "derm-chat-b",
                "-e",
                "DERM_CHAT_TOKEN",
                "-e",
                "DERM_CHAT_ID",
                "-e",
                "DERM_HARNESS",
                "-e",
                "DERM_BOUNDARY",
                "-e",
                "DERM_OTLP_ENDPOINT",
                "-e",
                "DERM_GATEWAY_URL",
                "--kit",
                "docker.io/sbx/pi-kit:latest",
                "pi",
                "/home/u/proj dir",
                "--",
                "-p",
                "hi",
            ]
        );
        assert_eq!(
            env(&p, "DERM_OTLP_ENDPOINT"),
            Some("http://host.docker.internal:4318")
        );
        assert_eq!(
            env(&p, "DERM_GATEWAY_URL"),
            Some("http://host.docker.internal:8811/mcp")
        );
        assert!(p.notes.iter().any(|n| n
            .contains("sbx policy allow network --sandbox <its name> localhost:4318")
            && n.contains("for this sandbox alone")));
        assert!(p.notes.iter().any(|n| n.contains("localhost:8811")));
        assert_eq!(p.kit.as_deref(), Some("docker.io/sbx/pi-kit:latest"));
    }

    #[test]
    fn sbx_for_a_built_in_agent_has_no_kit_and_a_harness_without_one_is_refused() {
        let args = a(&["claude-code", "--boundary", "sbx"]);
        let p = build(&inputs(&args)).unwrap();
        assert!(!p.args.contains(&"--kit".to_string()));
        assert_eq!(p.args[p.args.len() - 2], "claude");
        assert!(
            !p.args.contains(&"--".to_string()),
            "no separator without harness args"
        );
        let args = a(&["goose", "--boundary", "sbx"]);
        assert!(build(&inputs(&args)).unwrap_err().contains("no sbx form"));
    }

    #[test]
    fn srt_puts_the_separator_before_the_harness_and_allows_only_named_hosts() {
        let args = a(&[
            "pi",
            "--boundary",
            "srt",
            "--model-url",
            "http://localhost:8080/v1",
            "--allow-host",
            "[::1]:9000",
            "--",
            "-c",
        ]);
        let p = build(&inputs(&args)).unwrap();
        assert_eq!(p.program, "srt");
        assert_eq!(
            p.args,
            vec![
                "--settings",
                "/run/user/1000/derm/srt/chat-b.json",
                "--",
                "pi",
                "-c"
            ]
        );
        assert_eq!(env(&p, "NODE_USE_ENV_PROXY"), Some("1"));
        let s: serde_json::Value =
            serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
        assert_eq!(
            s["network"]["allowedDomains"],
            json!([
                "127.0.0.1:4318",
                "127.0.0.1:8080",
                "127.0.0.1:8811",
                "[::1]:9000"
            ])
        );
        let deny = s["filesystem"]["denyRead"].as_array().unwrap();
        for d in [
            "/home/u/.ssh",
            "/home/u/.derm",
            "/run/user/1000/derm",
            // The old name's folders, hidden while a tk install may be left
            // (rename review R1).
            "/home/u/.tk",
            "/run/user/1000/tk",
            "/home/u/.claude/.credentials.json",
            "/home/u/.codex/auth.json",
        ] {
            assert!(deny.iter().any(|v| v == d), "{d}");
        }
        assert!(
            !deny.iter().any(|v| v == "/home/u/.pi/agent/auth.json"),
            "Pi keeps its own login"
        );
        assert_eq!(
            s["filesystem"]["allowWrite"],
            json!(["/home/u/proj dir", "/home/u/.pi/agent", "/tmp"])
        );
    }

    fn srt_of(p: &Plan) -> serde_json::Value {
        serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap()
    }

    /// Mac test w5 retest 4, MW5-24: under derm's srt, Claude Code could not
    /// renew its sign-in ("OAuth refresh failed (expected): proxy refused the
    /// connection"), so once its access token expired every chat under the
    /// default boundary ended with "401 OAuth access token has expired".
    /// Claude Code 2.1.311 refreshes at `https://platform.claude.com/v1/oauth/token`
    /// (its bundle), Codex 0.163.0 at `https://auth.openai.com/oauth/token`
    /// (`codex-rs/login/src/auth/manager.rs:212`). srt's proxy admits each
    /// harness's own sign-in host and no other harness's.
    #[test]
    fn srt_lets_a_harness_renew_its_own_sign_in() {
        for (id, host, other) in [
            (
                "claude-code",
                "platform.claude.com:443",
                "auth.openai.com:443",
            ),
            ("codex", "auth.openai.com:443", "platform.claude.com:443"),
        ] {
            let args = a(&[id, "--boundary", "srt"]);
            let p = build(&inputs(&args)).unwrap();
            let allowed = srt_of(&p)["network"]["allowedDomains"].clone();
            let list = allowed.as_array().unwrap();
            assert!(list.contains(&json!(host)), "{id}: {allowed}");
            assert!(!list.contains(&json!(other)), "{id}: {allowed}");
            assert!(
                p.notes.iter().any(|n| n.contains(host)
                    && n.contains("sign-in")
                    && n.contains("records none")),
                "{id}: {:?}",
                p.notes
            );
        }
        let args = a(&["pi", "--boundary", "srt"]);
        let p = build(&inputs(&args)).unwrap();
        let allowed = srt_of(&p)["network"]["allowedDomains"].clone();
        assert!(
            !allowed.as_array().unwrap().iter().any(|h| {
                let h = h.as_str().unwrap();
                h.starts_with("platform.claude.com") || h.starts_with("auth.openai.com")
            }),
            "{allowed}"
        );
    }

    /// Mac test w5 retest 5, MW5-26: Claude Code 2.1.318 on macOS keeps its
    /// sign-in in the login keychain and falls back to a plaintext
    /// `~/.claude/.credentials.json` when a keychain write fails (its bundle:
    /// `keychain-with-plaintext-fallback`, `plaintext_fallback_used`), which
    /// it did under srt, where the keychain write failed. A renewal there
    /// would leave the rotated token outside the keychain the host reads.
    /// On macOS derm keeps that file read-only and the sign-in host shut;
    /// on Linux the file is Claude Code's only store and both stay open.
    #[test]
    fn mw5_26_on_macos_claude_codes_sign_in_never_lands_in_a_plaintext_file() {
        let args = a(&["claude-code", "--boundary", "srt"]);
        let mac = build(&Inputs {
            macos: true,
            ..inputs(&args)
        })
        .unwrap();
        let v = srt_of(&mac);
        let deny = v["filesystem"]["denyWrite"].as_array().unwrap();
        assert!(
            deny.contains(&json!({"path": "/home/u/.claude/.credentials.json", "literal": true})),
            "{deny:?}"
        );
        let allowed = v["network"]["allowedDomains"].as_array().unwrap();
        assert!(
            !allowed
                .iter()
                .any(|h| h.as_str().unwrap().starts_with("platform.claude.com")),
            "{allowed:?}"
        );
        assert!(
            mac.notes
                .iter()
                .any(|n| n.contains("keychain") && n.contains("outside srt")),
            "{:?}",
            mac.notes
        );
        assert!(!mac
            .notes
            .iter()
            .any(|n| n.contains("may reach its sign-in host")));
        // Linux: the file is the store; renewing there keeps the host's copy.
        let linux = build(&inputs(&args)).unwrap();
        let v = srt_of(&linux);
        let deny = v["filesystem"]["denyWrite"].as_array().unwrap();
        assert!(
            !deny
                .iter()
                .any(|d| d["path"].as_str().unwrap().ends_with(".credentials.json")),
            "{deny:?}"
        );
        assert!(v["network"]["allowedDomains"]
            .as_array()
            .unwrap()
            .contains(&json!("platform.claude.com:443")));
        // Codex keeps its sign-in in `auth.json` by default on every system
        // (`AuthCredentialsStoreMode::File`), so its host stays open on macOS.
        let args = a(&["codex", "--boundary", "srt"]);
        let mac = build(&Inputs {
            macos: true,
            ..inputs(&args)
        })
        .unwrap();
        assert!(srt_of(&mac)["network"]["allowedDomains"]
            .as_array()
            .unwrap()
            .contains(&json!("auth.openai.com:443")));
    }

    #[test]
    fn srt_names_the_temp_root_by_its_real_path_on_macos() {
        // MW5-13: srt 0.0.81 keeps `/tmp` unresolved on macOS, where it is a
        // link, and Seatbelt matched nothing under it.
        let args = a(&["claude-code", "--boundary", "srt"]);
        let mac = build(&Inputs {
            macos: true,
            ..inputs(&args)
        })
        .unwrap();
        let w = srt_of(&mac)["filesystem"]["allowWrite"].clone();
        assert!(
            w.as_array().unwrap().contains(&json!("/private/tmp")),
            "{w}"
        );
        assert!(!w.as_array().unwrap().contains(&json!("/tmp")), "{w}");
        let linux = build(&inputs(&args)).unwrap();
        let w = srt_of(&linux)["filesystem"]["allowWrite"].clone();
        assert!(w.as_array().unwrap().contains(&json!("/tmp")), "{w}");
        assert!(
            !w.as_array().unwrap().contains(&json!("/private/tmp")),
            "{w}"
        );
    }

    #[test]
    fn srt_opens_the_computer_use_endpoint_and_its_port_and_nothing_else() {
        // Mac test w5 retest 3, MW5-22: under srt `derm-daemon cu-mcp` found
        // no `cu.endpoint` (its folder hidden) and could not reach the
        // bridge's port, so `derm_cu` listed no tools.
        let args = a(&["claude-code", "--boundary", "srt"]);
        for macos in [false, true] {
            let p = build(&Inputs {
                macos,
                cu_endpoint: Some("127.0.0.1:53276".into()),
                ..inputs(&args)
            })
            .unwrap();
            let s = srt_of(&p);
            let allowed = s["network"]["allowedDomains"].as_array().unwrap();
            assert!(allowed.contains(&json!("127.0.0.1:53276")), "{s}");
            let read = s["filesystem"]["allowRead"].as_array().unwrap();
            assert!(
                read.contains(&json!({"path": "/run/user/1000/derm/cu.endpoint", "literal": true})),
                "{s}"
            );
            // The folder stays hidden; the token beside it is never re-opened.
            let deny = s["filesystem"]["denyRead"].as_array().unwrap();
            assert!(deny.contains(&json!("/run/user/1000/derm")), "{s}");
            assert!(!read.iter().any(|r| r["path"]
                .as_str()
                .is_some_and(|p| p.ends_with("daemon.token") || p.ends_with("/derm"))));
            // The relay finds the folder by the socket's path.
            assert!(
                p.env_set
                    .iter()
                    .any(|(k, v)| k == "DERM_DAEMON_SOCKET"
                        && v == "/run/user/1000/derm/daemon.sock"),
                "{:?}",
                p.env_set
            );
        }
        // Off (no endpoint), or an endpoint that is not loopback and a port:
        // nothing added.
        for bad in [
            None,
            Some("10.0.0.5:53276"),
            Some("127.0.0.1:0"),
            Some("127.0.0.1:65536"),
            Some("127.0.0.1:80/x"),
            Some("localhost:53276"),
        ] {
            let p = build(&Inputs {
                cu_endpoint: bad.map(str::to_string),
                ..inputs(&args)
            })
            .unwrap();
            let s = srt_of(&p);
            let read = s["filesystem"]["allowRead"].as_array().unwrap();
            assert!(
                !read.iter().any(|r| r["path"]
                    .as_str()
                    .is_some_and(|p| p.ends_with("cu.endpoint"))),
                "{bad:?} {s}"
            );
            if let Some(b) = bad {
                let allowed = s["network"]["allowedDomains"].as_array().unwrap();
                assert!(!allowed.contains(&json!(b)), "{b} {s}");
            }
        }
        assert!(cu_endpoint_ok("[::1]:9"));
        assert!(!cu_endpoint_ok("127.0.0.1:09"));
    }

    #[test]
    fn srt_on_macos_opens_the_daemon_socket_and_nothing_else_in_its_folder() {
        // MW5-5's gate half: the socket by path (connect and lstat), the
        // folder still hidden, and its path named to the hook.
        let args = a(&["claude-code", "--boundary", "srt"]);
        let p = build(&Inputs {
            macos: true,
            ..inputs(&args)
        })
        .unwrap();
        let s = srt_of(&p);
        let sock = "/run/user/1000/derm/daemon.sock";
        assert_eq!(s["network"]["allowUnixSockets"], json!([sock]));
        let read = s["filesystem"]["allowRead"].as_array().unwrap();
        assert!(
            read.contains(&json!({"path": sock, "literal": true})),
            "{read:?}"
        );
        assert!(read.contains(&json!({"path": "/home/u/.derm/policy.json", "literal": true})));
        assert_eq!(read.len(), 2, "{read:?}");
        let deny = s["filesystem"]["denyRead"].as_array().unwrap();
        assert!(deny.contains(&json!("/run/user/1000/derm")), "{deny:?}");
        assert!(!s["filesystem"]["allowWrite"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w
                .as_str()
                .is_some_and(|w| w.starts_with("/run/user/1000/derm"))));
        assert_eq!(env(&p, "DERM_DAEMON_SOCKET"), Some(sock));
        assert_eq!(env(&p, "DERM_CHAT_TOKEN_FILE"), None);
        // Linux: srt ignores allowUnixSockets (seccomp refuses AF_UNIX).
        let linux = build(&inputs(&args)).unwrap();
        let s = srt_of(&linux);
        assert!(s["network"].get("allowUnixSockets").is_none());
        assert_eq!(s["filesystem"]["allowRead"].as_array().unwrap().len(), 1);
        assert_eq!(env(&linux, "DERM_DAEMON_SOCKET"), None);
        // No socket known (no daemon): nothing opened.
        let none = build(&Inputs {
            macos: true,
            daemon_socket: None,
            ..inputs(&args)
        })
        .unwrap();
        assert!(srt_of(&none)["network"].get("allowUnixSockets").is_none());
    }

    #[test]
    fn srt_on_macos_gives_a_harness_on_a_terminal_its_pty_and_says_so() {
        // MW5-8: without allowPty the harness cannot set raw mode on its
        // /dev/ttys* and takes no keys.
        let args = a(&["claude-code", "--boundary", "srt"]);
        let on = build(&Inputs {
            macos: true,
            terminal: true,
            ..inputs(&args)
        })
        .unwrap();
        assert_eq!(srt_of(&on)["allowPty"], json!(true));
        assert!(on
            .notes
            .iter()
            .any(|n| n.contains("allowPty") && n.contains("/dev/ttys")));
        for (macos, terminal) in [(true, false), (false, true), (false, false)] {
            let p = build(&Inputs {
                macos,
                terminal,
                ..inputs(&args)
            })
            .unwrap();
            assert!(srt_of(&p).get("allowPty").is_none(), "{macos} {terminal}");
            assert!(!p.notes.iter().any(|n| n.contains("allowPty")));
        }
    }

    #[test]
    fn under_srt_claude_codes_otlp_endpoint_is_spelled_so_it_takes_the_proxy() {
        // MW5-15: Claude Code 2.1.311 sends no loopback name through a
        // proxy; the mapped spelling of the same port is not one to it.
        let args = a(&["claude-code", "--boundary", "srt"]);
        let mut p = build(&inputs(&args)).unwrap();
        p.env_set.push((
            "OTEL_EXPORTER_OTLP_ENDPOINT".into(),
            "http://127.0.0.1:4318".into(),
        ));
        p.env_set.push((
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT".into(),
            "http://127.0.0.1:4318/v1/logs".into(),
        ));
        p.env_set.push((
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT".into(),
            "https://collector.example:4318".into(),
        ));
        srt_otlp_through_proxy(&mut p);
        assert_eq!(
            env(&p, "OTEL_EXPORTER_OTLP_ENDPOINT"),
            Some("http://[::ffff:127.0.0.1]:4318")
        );
        assert_eq!(
            env(&p, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"),
            Some("http://[::ffff:127.0.0.1]:4318/v1/logs")
        );
        assert_eq!(
            env(&p, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
            Some("https://collector.example:4318")
        );
        // Only DERM_OTLP_ENDPOINT's own spelling stays as srt_target wrote it.
        assert_eq!(env(&p, "DERM_OTLP_ENDPOINT"), Some("http://127.0.0.1:4318"));
        // No change for any other boundary.
        let none = a(&["claude-code", "--boundary", "none"]);
        let mut q = build(&inputs(&none)).unwrap();
        q.env_set.push((
            "OTEL_EXPORTER_OTLP_ENDPOINT".into(),
            "http://127.0.0.1:4318".into(),
        ));
        srt_otlp_through_proxy(&mut q);
        assert_eq!(
            env(&q, "OTEL_EXPORTER_OTLP_ENDPOINT"),
            Some("http://127.0.0.1:4318")
        );
    }

    /// MW5-13 on the machine itself: every srt write root that exists is
    /// named by its real path (case 111), so Seatbelt can match it.
    #[cfg(target_os = "macos")]
    #[test]
    fn srt_write_roots_are_real_paths_on_this_mac() {
        let dir = std::env::temp_dir().canonicalize().unwrap();
        let args = a(&["claude-code", "--boundary", "srt"]);
        let p = build(&Inputs {
            macos: cfg!(target_os = "macos"),
            cwd: dir.to_string_lossy().into_owned(),
            ..inputs(&args)
        })
        .unwrap();
        for w in srt_of(&p)["filesystem"]["allowWrite"].as_array().unwrap() {
            let w = w.as_str().unwrap();
            if let Ok(real) = std::fs::canonicalize(w) {
                assert_eq!(real, std::path::Path::new(w), "{w} is not its real path");
            }
        }
    }

    #[test]
    fn srt_lets_the_gate_read_its_policy_and_nothing_else_in_derm_s_folder() {
        // Box test w1, BX2: `denyRead` held `~/.derm` with `allowRead: []`, so
        // the gate inside srt found no policy and asked every call. srt
        // 0.0.81 README line 119: `allowRead` takes precedence over a broader
        // `denyRead`. Writes stay denied (`~/.derm` is in no `allowWrite`).
        let args = a(&["pi", "--boundary", "srt"]);
        let p = build(&inputs(&args)).unwrap();
        let s: serde_json::Value =
            serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
        assert_eq!(
            s["filesystem"]["allowRead"],
            json!([{"path": "/home/u/.derm/policy.json", "literal": true}])
        );
        assert!(!s["filesystem"]["allowWrite"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains(".derm")));
        // A DERM_POLICY anywhere but derm's own folder is not re-opened: it could
        // name a file srt hides on purpose.
        for elsewhere in [
            "/home/u/.ssh/id_ed25519",
            "/home/u/.derm/../.ssh/x.json",
            "/home/u/.derm/backups/a.json",
            "/home/u/.derm/policy",
        ] {
            let mut i = inputs(&args);
            i.policy = elsewhere.into();
            let p = build(&i).unwrap();
            let s: serde_json::Value =
                serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
            assert_eq!(s["filesystem"]["allowRead"], json!([]), "{elsewhere}");
            assert!(
                p.notes.iter().any(|n| n.contains("every call will ask")),
                "{:?}",
                p.notes
            );
        }
        // A link, a second hard link or a file others can write is not
        // re-opened: the caller says so after `lstat` (review R1).
        let mut i = inputs(&args);
        i.policy_regular = false;
        let p = build(&i).unwrap();
        let s: serde_json::Value =
            serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
        assert_eq!(s["filesystem"]["allowRead"], json!([]));
    }

    #[test]
    fn srt_for_claude_code_hides_pis_login_and_not_its_own() {
        let args = a(&["claude-code", "--boundary", "srt"]);
        let p = build(&inputs(&args)).unwrap();
        let s: serde_json::Value =
            serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
        let deny = s["filesystem"]["denyRead"].as_array().unwrap();
        assert!(deny.iter().any(|v| v == "/home/u/.pi/agent/auth.json"));
        assert!(!deny
            .iter()
            .any(|v| v == "/home/u/.claude/.credentials.json"));
    }

    #[test]
    fn no_daemon_means_no_token_and_no_feed_variables() {
        let args = a(&["pi", "--boundary", "sbx", "--no-daemon"]);
        let mut i = inputs(&args);
        i.token = None;
        i.otlp = None;
        i.gateway = None;
        let p = build(&i).unwrap();
        assert!(env(&p, "DERM_CHAT_TOKEN").is_none());
        assert!(!p.args.contains(&"DERM_CHAT_TOKEN".to_string()));
        assert!(!p.args.contains(&"DERM_OTLP_ENDPOINT".to_string()));
    }

    #[test]
    fn the_token_never_reaches_the_argv_or_the_description() {
        for b in ["none", "sbx", "srt"] {
            let args = a(&["pi", "--boundary", b, "--", "x"]);
            let p = build(&inputs(&args)).unwrap();
            assert!(p.args.iter().all(|x| !x.contains(TOKEN)), "{b}");
            assert!(!describe(&p).contains(TOKEN), "{b}");
        }
        // A harness argument that happens to hold the token is refused.
        let args = a(&["pi", "--boundary", "none", "--", TOKEN]);
        assert!(build(&inputs(&args)).unwrap_err().contains("token"));
    }

    #[test]
    fn dangerous_flags_are_noted() {
        let args = a(&[
            "claude-code",
            "--boundary",
            "none",
            "--",
            "--dangerously-skip-permissions",
        ]);
        let p = build(&inputs(&args)).unwrap();
        assert!(p
            .notes
            .iter()
            .any(|n| n.contains("--dangerously-skip-permissions")));
    }

    #[test]
    fn full_access_flags_set_the_gates_hint_and_are_kept() {
        // Orca's flag for each agent (note AQ section 8), alone, as a pair and
        // joined by `=`.
        for (harness, words) in [
            ("claude-code", vec!["--dangerously-skip-permissions"]),
            ("codex", vec!["--dangerously-bypass-approvals-and-sandbox"]),
            ("gemini", vec!["--yolo"]),
            ("kiro", vec!["--trust-all-tools"]),
            ("copilot-cli", vec!["--allow-all"]),
            ("amp", vec!["--dangerously-allow-all"]),
            ("cline", vec!["--auto-approve", "true"]),
            ("qwen-code", vec!["--approval-mode=yolo"]),
            ("grok", vec!["--permission-mode", "bypassPermissions"]),
            ("droid", vec!["--auto", "high"]),
        ] {
            let mut argv = vec![harness, "--boundary", "none", "--"];
            argv.extend(words.iter().copied());
            argv.push("do it");
            let args = a(&argv);
            let p = build(&inputs(&args)).unwrap();
            assert_eq!(env(&p, "DERM_FULL_ACCESS"), Some("1"), "{harness}");
            assert_eq!(p.full_access, vec![words.join(" ")], "{harness}");
            assert!(
                p.notes.iter().any(|n| n.contains("full access")),
                "{harness}"
            );
        }
        // A value that only looks like one is not full access, and nothing
        // after the agent's own `--` counts.
        for argv in [
            vec![
                "cline",
                "--boundary",
                "none",
                "--",
                "--auto-approve",
                "false",
            ],
            vec!["droid", "--boundary", "none", "--", "--auto", "low"],
            vec!["pi", "--boundary", "none", "--", "-p", "--yolo is a word"],
            vec!["pi", "--boundary", "none", "--", "--", "--yolo"],
        ] {
            let args = a(&argv);
            let p = build(&inputs(&args)).unwrap();
            assert_eq!(env(&p, "DERM_FULL_ACCESS"), None, "{argv:?}");
            assert!(p.full_access.is_empty(), "{argv:?}");
        }
        // An outer value never reaches the child: the variable is derm's.
        assert!(OWNED_VARS.contains(&"DERM_FULL_ACCESS"));
        // Under sbx it is named for the sandbox only when set.
        let args = a(&["codex", "--boundary", "sbx", "--", "--yolo"]);
        let p = build(&inputs(&args)).unwrap();
        assert!(p.args.windows(2).any(|w| w == ["-e", "DERM_FULL_ACCESS"]));
        // OpenCode's kit adds no such word (request T-5: the codex kit
        // itself starts Codex in full access, so it is no longer the case
        // to check this with).
        let args = a(&["opencode", "--boundary", "sbx"]);
        let p = build(&inputs(&args)).unwrap();
        assert!(!p.args.iter().any(|x| x == "DERM_FULL_ACCESS"));
    }

    /// Request T-5, case 83 under sbx: the kit's own full-access words are
    /// the chat's too, whatever the command line says, so the gate gets the
    /// hint and the record names them. Under srt and none they are not the
    /// kit's to add, and a kit named with --kit is the user's.
    #[test]
    fn a_kits_own_full_access_words_set_the_hint_under_sbx() {
        for (harness, words) in [
            ("claude-code", vec!["--dangerously-skip-permissions"]),
            ("codex", vec!["--dangerously-bypass-approvals-and-sandbox"]),
            ("gemini", vec!["--yolo"]),
            ("kiro", vec!["--trust-all-tools"]),
            ("amp", vec!["--dangerously-allow-all"]),
        ] {
            let args = a(&[harness, "--boundary", "sbx"]);
            let p = build(&inputs(&args)).unwrap();
            assert_eq!(p.full_access, words, "{harness}");
            assert_eq!(env(&p, "DERM_FULL_ACCESS"), Some("1"), "{harness}");
            assert!(
                p.args.windows(2).any(|w| w == ["-e", "DERM_FULL_ACCESS"]),
                "{harness}"
            );
            // The same word on the command line is not counted twice.
            let args = a(&[harness, "--boundary", "sbx", "--", words[0]]);
            assert_eq!(
                build(&inputs(&args)).unwrap().full_access,
                words,
                "{harness}"
            );
            for b in ["srt", "none"] {
                let args = a(&[harness, "--boundary", b]);
                let p = build(&inputs(&args)).unwrap();
                assert!(p.full_access.is_empty(), "{harness} {b}");
                assert_eq!(env(&p, "DERM_FULL_ACCESS"), None, "{harness} {b}");
            }
        }
        for harness in ["pi", "opencode", "droid"] {
            let args = a(&[harness, "--boundary", "sbx"]);
            assert!(
                build(&inputs(&args)).unwrap().full_access.is_empty(),
                "{harness}"
            );
        }
        let args = a(&["claude-code", "--boundary", "sbx", "--kit", "./my-kit"]);
        assert!(build(&inputs(&args)).unwrap().full_access.is_empty());
    }

    #[test]
    fn goose_inherits_auto_as_full_access_and_gets_approve_when_the_policy_asks() {
        let args = a(&["goose", "--boundary", "none", "--", "run", "-t", "x"]);
        let mut i = inputs(&args);
        let p = build(&i).unwrap();
        assert_eq!(env(&p, "GOOSE_MODE"), Some("approve"));
        // A policy that never asks leaves goose's mode alone.
        i.policy_asks = false;
        assert_eq!(env(&build(&i).unwrap(), "GOOSE_MODE"), None);
        // A mode the user chose is kept; `auto` is full access.
        i.policy_asks = true;
        i.goose_mode = Some("auto".into());
        let p = build(&i).unwrap();
        assert_eq!(env(&p, "GOOSE_MODE"), None);
        assert_eq!(p.full_access, vec!["GOOSE_MODE=auto"]);
        assert_eq!(env(&p, "DERM_FULL_ACCESS"), Some("1"));
        i.goose_mode = Some("smart_approve".into());
        let p = build(&i).unwrap();
        assert_eq!(env(&p, "GOOSE_MODE"), None);
        assert!(p.full_access.is_empty());
        // Only goose gets it.
        let args = a(&["pi", "--boundary", "none"]);
        assert_eq!(env(&build(&inputs(&args)).unwrap(), "GOOSE_MODE"), None);
    }

    #[test]
    fn policy_asks_reads_the_rules() {
        use derm_core::policy::{parse, PolicyFile};
        assert!(policy_asks(None));
        assert!(policy_asks(Some(&PolicyFile::default())));
        let p = parse(r#"{"version":1,"rules":[{"tool":"*","action":"deny"}]}"#).unwrap();
        assert!(!policy_asks(Some(&p)));
        let p = parse(r#"{"version":1,"rules":[{"tool":"*","action":"allow"},{"tool":"bash","action":"ask"}]}"#).unwrap();
        assert!(policy_asks(Some(&p)));
        // A catch-all for one harness leaves the others asking.
        let p = parse(r#"{"version":1,"rules":[{"tool":"*","harness":"pi","action":"deny"}]}"#)
            .unwrap();
        assert!(policy_asks(Some(&p)));
    }

    #[test]
    fn cline_gets_its_approval_files_and_the_responder() {
        let args = a(&["cline", "--boundary", "none", "--", "fix the bug"]);
        let p = build(&inputs(&args)).unwrap();
        assert_eq!(env(&p, "CLINE_TOOL_APPROVAL_MODE"), Some("desktop"));
        assert_eq!(
            env(&p, "CLINE_TOOL_APPROVAL_DIR"),
            Some("/home/u/.cline/derm-approval/chat-b")
        );
        assert_eq!(p.args, vec!["--auto-approve", "false", "fix the bug"]);
        assert_eq!(
            p.companion,
            Some((
                "/usr/local/bin/derm-cline-responder".to_string(),
                vec![
                    "--dir".to_string(),
                    "/home/u/.cline/derm-approval/chat-b".into()
                ]
            ))
        );
        assert_eq!(
            p.scratch_dir.as_deref(),
            Some("/home/u/.cline/derm-approval/chat-b")
        );
        // Under srt the settings go between the command and the prompt.
        let args = a(&["cline", "--boundary", "srt", "--", "fix"]);
        let p = build(&inputs(&args)).unwrap();
        let at = p.args.iter().position(|x| x == "cline").unwrap();
        assert_eq!(p.args[at + 1..], ["--auto-approve", "false", "fix"]);
        // The user's own `--auto-approve` is never doubled; `true` is full access.
        let args = a(&[
            "cline",
            "--boundary",
            "none",
            "--",
            "--auto-approve",
            "true",
            "go",
        ]);
        let p = build(&inputs(&args)).unwrap();
        assert_eq!(p.args, vec!["--auto-approve", "true", "go"]);
        assert!(p.notes.iter().any(|n| n.contains("no approval file")));
        // No responder found: Cline still starts, and the note says what then.
        let args = a(&["cline", "--boundary", "none", "--", "go"]);
        let mut i = inputs(&args);
        i.cline_responder = None;
        let p = build(&i).unwrap();
        assert!(p.companion.is_none());
        assert!(p.notes.iter().any(|n| n.contains("5 minutes")));
        // No other harness gets Cline's variables.
        let args = a(&["codex", "--boundary", "none"]);
        let p = build(&inputs(&args)).unwrap();
        assert_eq!(env(&p, "CLINE_TOOL_APPROVAL_DIR"), None);
        assert!(p.companion.is_none() && p.scratch_dir.is_none());
    }

    #[test]
    fn srt_keeps_the_gates_switches_read_only() {
        // Security finding S6: the state folder is writable, its control
        // files are not.
        for (id, file) in [
            ("claude-code", "/home/u/.claude/settings.json"),
            ("claude-code", "/home/u/.claude/plugins"),
            ("codex", "/home/u/.codex/hooks.json"),
            ("codex", "/home/u/.codex/config.toml"),
            ("pi", "/home/u/.pi/agent/settings.json"),
            ("gemini", "/home/u/.gemini/extensions"),
            ("droid", "/home/u/.factory/hooks.json"),
            // Fix pass 1's review, FP4-S1: Cursor's state is all of
            // `~/.cursor`, and hooks and code it runs as you live there too.
            ("cursor", "/home/u/.cursor/hooks.json"),
            ("cursor", "/home/u/.cursor/hooks"),
            ("cursor", "/home/u/.cursor/managed"),
            ("cursor", "/home/u/.cursor/plugins"),
            ("cursor", "/home/u/.cursor/extensions"),
            ("cursor", "/home/u/.cursor/argv.json"),
            ("cursor", "/home/u/.cursor/skills"),
            ("cursor", "/home/u/.cursor/commands"),
            ("cursor", "/home/u/.cursor/rules"),
            // Re-review FP5-R1: Cursor's own protected list is every
            // `.cursor/**/*.json` (https://cursor.com/docs/reference/sandbox.md,
            // read 4 Nov 2026), which a literal list cannot cover, so all of
            // `~/.cursor` is read-only under srt.
            ("cursor", "/home/u/.cursor"),
            // Re-review FP5-R4: Claude Code's hook scripts.
            ("claude-code", "/home/u/.claude/hooks"),
        ] {
            let args = a(&[id, "--boundary", "srt"]);
            let p = build(&inputs(&args)).unwrap();
            let v: serde_json::Value =
                serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
            let deny = v["filesystem"]["denyWrite"].as_array().unwrap();
            for want in [file, "/home/u/.derm", "/home/u/.tk"] {
                assert!(
                    deny.contains(&json!({"path": want, "literal": true})),
                    "{id}: {want} in {deny:?}"
                );
            }
            // Every entry is a literal path, so none is read as a pattern.
            assert!(deny.iter().all(|e| e["literal"] == json!(true)));
            // The state folder that holds them is still writable.
            let allow = v["filesystem"]["allowWrite"].as_array().unwrap();
            assert!(
                allow.iter().any(|w| file.starts_with(w.as_str().unwrap())),
                "{id}"
            );
        }
    }

    /// Re-review W4-R3: the chat's folder is writable under srt, and an
    /// agent loads a project's own copy of its control files (Cline its
    /// `.cline/plugins` and `.cline/hooks` with no trust prompt), so the
    /// same paths under the chat's folder are read-only too.
    #[test]
    fn srt_keeps_the_projects_copies_of_the_control_files_read_only() {
        for (id, files) in [
            (
                "cline",
                &[
                    "/home/u/proj dir/.cline/plugins",
                    "/home/u/proj dir/.cline/hooks",
                    "/home/u/proj dir/.clinerules",
                ][..],
            ),
            (
                "claude-code",
                &["/home/u/proj dir/.claude/settings.json"][..],
            ),
            // Fix pass 1's review, FP4-S1: Cursor loads a project's own
            // hooks and scripts and its `cli.json` permissions
            // (https://cursor.com/docs/agent/hooks,
            // https://cursor.com/docs/cli/reference/configuration, read 4
            // Nov 2026), and runs Claude Code's hooks from the project's
            // settings and enabled plugins as third-party hooks
            // (https://cursor.com/docs/reference/third-party-hooks; Mac test
            // w4, MW4-5).
            (
                "cursor",
                &[
                    "/home/u/proj dir/.cursor/hooks.json",
                    "/home/u/proj dir/.cursor/hooks",
                    "/home/u/proj dir/.cursor/cli.json",
                    "/home/u/proj dir/.claude/settings.json",
                    "/home/u/proj dir/.claude/settings.local.json",
                    "/home/u/proj dir/.claude/plugins",
                    // Re-review FP5-R1, R4, R5: the whole folders, so a
                    // `worktrees.json` or `sandbox.json`, a hook script, or
                    // a folder made as a link is no way round.
                    "/home/u/proj dir/.cursor",
                    "/home/u/proj dir/.claude",
                ][..],
            ),
            ("claude-code", &["/home/u/proj dir/.claude/hooks"][..]),
        ] {
            let args = a(&[id, "--boundary", "srt"]);
            let p = build(&inputs(&args)).unwrap();
            let v: serde_json::Value =
                serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
            let deny = v["filesystem"]["denyWrite"].as_array().unwrap();
            for want in files {
                assert!(
                    deny.contains(&json!({"path": want, "literal": true})),
                    "{id}: {want} in {deny:?}"
                );
            }
        }
    }

    /// Re-review FP5-R2: the files derm's registered gate runs (Cursor's
    /// `hooks.json` names a hook file and a node by absolute path) are
    /// read-only under srt, wherever they sit, so an agent whose chat folder
    /// is a derm clone cannot rewrite its own gate.
    #[test]
    fn srt_keeps_the_gates_own_files_read_only() {
        let args = a(&["cursor", "--boundary", "srt"]);
        let i = Inputs {
            gate_paths: vec![
                "/home/u/proj dir/packages/derm-hooks-native".into(),
                "/home/u/.local/node/bin/node".into(),
            ],
            ..inputs(&args)
        };
        let p = build(&i).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
        let deny = v["filesystem"]["denyWrite"].as_array().unwrap();
        for want in [
            "/home/u/proj dir/packages/derm-hooks-native",
            "/home/u/.local/node/bin/node",
        ] {
            assert!(
                deny.contains(&json!({"path": want, "literal": true})),
                "{want} in {deny:?}"
            );
        }
    }

    #[test]
    fn an_unknown_program_runs_with_the_outside_shape_only() {
        let args = a(&[
            "--boundary",
            "none",
            "--",
            "/opt/aider/bin/aider",
            "--model",
            "m",
        ]);
        let p = build(&inputs(&args)).unwrap();
        assert_eq!(p.program, "/opt/aider/bin/aider");
        assert_eq!(p.args, vec!["--model", "m"]);
        assert_eq!(env(&p, "DERM_HARNESS"), Some("other"));
        assert!(p.state_dirs.is_empty());
        assert!(p.notes.iter().any(|n| n.contains("outside shape only")));
        // Under srt it gets the folder and /tmp, nothing of any harness.
        let args = a(&["--boundary", "srt", "--", "aider"]);
        let p = build(&inputs(&args)).unwrap();
        let at = p.args.iter().position(|x| x == "--").unwrap();
        assert_eq!(p.args[at + 1], "aider");
        let v: serde_json::Value =
            serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
        assert_eq!(
            v["filesystem"]["allowWrite"],
            json!(["/home/u/proj dir", "/tmp"])
        );
        // No sbx form for a program derm does not know.
        let args = a(&["--boundary", "sbx", "--", "aider"]);
        assert!(build(&inputs(&args)).unwrap_err().contains("no sbx form"));
        // srt's own subcommands are refused as a program too.
        let args = a(&["--boundary", "srt", "--", "proxy"]);
        assert!(build(&inputs(&args))
            .unwrap_err()
            .contains("srt subcommand"));
    }

    #[test]
    fn urls_are_parsed_strictly() {
        assert_eq!(
            split_url("http://127.0.0.1:8811/mcp"),
            Some(("http", "127.0.0.1".into(), 8811, "/mcp".into()))
        );
        assert_eq!(
            split_url("https://h"),
            Some(("https", "h".into(), 443, String::new()))
        );
        assert_eq!(
            split_url("http://[::1]:4318"),
            Some(("http", "::1".into(), 4318, String::new()))
        );
        for bad in [
            "ftp://h",
            "http://",
            "http://u:p@h:1",
            "http://h:0",
            "http://h:x",
            "h:80",
            "http://a b",
        ] {
            assert!(split_url(bad).is_none(), "{bad}");
        }
        let args = a(&[
            "pi",
            "--boundary",
            "none",
            "--gateway-url",
            "file:///etc/passwd",
        ]);
        let mut i = inputs(&args);
        i.gateway = args.gateway_url.clone();
        assert!(build(&i).is_err());
    }

    /// Security review L7: the short forms and value pairs that turn an
    /// agent's approvals off, per agent (each checked against that CLI's
    /// `--help` by the reviewer).
    #[test]
    fn more_full_access_forms_are_caught_per_agent() {
        for (harness, words, want) in [
            ("gemini", vec!["-y"], "-y"),
            ("qwen-code", vec!["-y"], "-y"),
            ("codex", vec!["-a", "never"], "-a never"),
            (
                "codex",
                vec!["--ask-for-approval", "never"],
                "--ask-for-approval never",
            ),
            (
                "codex",
                vec!["--ask-for-approval=never"],
                "--ask-for-approval=never",
            ),
            (
                "codex",
                vec!["-s", "danger-full-access"],
                "-s danger-full-access",
            ),
            (
                "codex",
                vec!["--sandbox", "danger-full-access"],
                "--sandbox danger-full-access",
            ),
            (
                "codex",
                vec!["-c", "approval_policy=never"],
                "-c approval_policy=never",
            ),
            (
                "codex",
                vec!["-c", "approval_policy=\"never\""],
                "-c approval_policy=\"never\"",
            ),
            (
                "codex",
                vec!["-c", "sandbox_mode=danger-full-access"],
                "-c sandbox_mode=danger-full-access",
            ),
            (
                "claude-code",
                vec![
                    "--settings",
                    r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
                ],
                "--settings permissions.defaultMode=bypassPermissions",
            ),
        ] {
            let mut argv = vec![harness, "--boundary", "none", "--"];
            argv.extend(words.iter().copied());
            let args = a(&argv);
            let p = build(&inputs(&args)).unwrap();
            assert_eq!(p.full_access, vec![want.to_string()], "{harness} {words:?}");
        }
        // The same words for another agent, or another value, are not.
        for argv in [
            vec!["pi", "--boundary", "none", "--", "-y"],
            vec!["claude-code", "--boundary", "none", "--", "-a", "never"],
            vec!["codex", "--boundary", "none", "--", "-a", "on-request"],
            vec!["codex", "--boundary", "none", "--", "-c", "model=o3"],
            vec![
                "claude-code",
                "--boundary",
                "none",
                "--",
                "--settings",
                r#"{"permissions":{"defaultMode":"plan"}}"#,
            ],
        ] {
            let args = a(&argv);
            let p = build(&inputs(&args)).unwrap();
            assert!(p.full_access.is_empty(), "{argv:?}: {:?}", p.full_access);
        }
    }

    /// Security review L6: the note says who acts on DERM_FULL_ACCESS. Since
    /// integration w4 the hook core does too (lane R's request 1).
    #[test]
    fn the_full_access_note_says_who_acts_on_it() {
        let args = a(&[
            "claude-code",
            "--boundary",
            "none",
            "--",
            "--dangerously-skip-permissions",
        ]);
        let p = build(&inputs(&args)).unwrap();
        let note = p.notes.iter().find(|n| n.contains("full access")).unwrap();
        assert!(note.contains("derm acp"), "{note}");
        assert!(note.contains("hook gates"), "{note}");
        assert!(note.contains("deny what they would ask"), "{note}");
        assert!(!note.contains("still asks"), "{note}");
    }

    /// Security review L14: the files that change a harness's own approvals
    /// or trust are read-only under srt too.
    #[test]
    fn srt_keeps_approval_and_trust_files_read_only() {
        for (id, file) in [
            ("codex", "/home/u/.codex/rules"),
            ("gemini", "/home/u/.gemini/.env"),
            ("gemini", "/home/u/.gemini/trustedFolders.json"),
        ] {
            let args = a(&[id, "--boundary", "srt"]);
            let p = build(&inputs(&args)).unwrap();
            let v: serde_json::Value =
                serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
            let deny = v["filesystem"]["denyWrite"].as_array().unwrap();
            assert!(
                deny.contains(&json!({"path": file, "literal": true})),
                "{id}: {file} in {deny:?}"
            );
        }
    }

    /// Security review L13: the check runs on the final argv, after derm's
    /// own additions.
    #[test]
    fn a_token_in_the_final_argv_stops_the_run() {
        let args = a(&["pi", "--boundary", "none"]);
        let mut p = build(&inputs(&args)).unwrap();
        assert!(no_token_in_args(&p, Some("tok-123")).is_ok());
        p.args.push("--header=tok-123".into());
        assert!(no_token_in_args(&p, Some("tok-123")).is_err());
        assert!(no_token_in_args(&p, None).is_ok());
    }

    /// Security review L15: a path whose last part is a preset's command is
    /// not that preset: only the bare name is.
    #[test]
    fn a_path_named_like_a_preset_runs_as_an_unknown_program() {
        let args = a(&["--boundary", "none", "--", "/tmp/x/claude", "-p", "hi"]);
        assert_eq!(args.harness.id, "other");
        let p = build(&inputs(&args)).unwrap();
        assert!(
            p.notes
                .iter()
                .any(|n| n.contains("/tmp/x/claude") && n.contains("bare name")),
            "{:?}",
            p.notes
        );
        let args = a(&["--boundary", "none", "--", "claude", "-p", "hi"]);
        assert_eq!(args.harness.id, "claude-code");
    }

    /// MW5-5: inside srt the harness runs behind `/usr/bin/env` with srt's
    /// `NO_PROXY` less its loopback names, so derm's loopback ports go
    /// through srt's proxy; nothing changes for another boundary.
    #[test]
    fn under_srt_the_harness_reaches_derms_ports_through_the_proxy() {
        let args = a(&["--boundary", "srt", "--", "aider", "--model", "m"]);
        let mut p = build(&inputs(&args)).unwrap();
        srt_loopback_through_proxy(&mut p);
        let at = p.args.iter().position(|x| x == "--").unwrap();
        assert_eq!(
            &p.args[at + 1..],
            &[
                "/usr/bin/env",
                "NO_PROXY=169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
                "no_proxy=169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
                "aider",
                "--model",
                "m"
            ]
        );
        for loopback in ["localhost", "127.0.0.1", "::1"] {
            assert!(!SRT_NO_PROXY_WITHOUT_LOOPBACK
                .split(',')
                .any(|h| h == loopback));
        }
        let args = a(&["--boundary", "none", "--", "aider"]);
        let mut p = build(&inputs(&args)).unwrap();
        let before = p.args.clone();
        srt_loopback_through_proxy(&mut p);
        assert_eq!(p.args, before);
    }

    /// Fix pass 1's review, F5: env reads a word with `=` as a variable and
    /// one with a leading `-` as its own option, and would run the next word
    /// instead. Such a program word is left as srt would run it, unwrapped.
    #[test]
    fn a_program_word_env_would_misread_is_not_wrapped() {
        for word in ["A=b", "-i"] {
            let args = a(&["--boundary", "srt", "--", "aider"]);
            let mut p = build(&inputs(&args)).unwrap();
            let at = p.args.iter().position(|x| x == "--").unwrap();
            p.args[at + 1] = word.into();
            let before = p.args.clone();
            srt_loopback_through_proxy(&mut p);
            assert_eq!(p.args, before, "{word}");
        }
    }

    /// Separate review of fix pass 5, FP5R-5 (was FP5-S2), its probe, kept as
    /// fix pass 6's reproducing test. Codex
    /// 0.163.0 with `cli_auth_credentials_store = "auto"` saves to the
    /// keychain and, when that fails, to `$CODEX_HOME/auth.json`; a load takes
    /// the keychain's copy first (`login/src/auth/storage.rs:479-524`). Its
    /// refresh tokens are single use (`refresh_token_reused`,
    /// `login/src/auth/manager.rs:1688`). On macOS under srt, with its sign-in
    /// host open, a renewal would leave the rotated token in plaintext and
    /// the keychain's copy spent. Named on derm's own command line here, and
    /// derm still opens the host and leaves `auth.json` writable.
    #[test]
    fn fp5r_5_codex_auto_store_on_macos_is_treated_like_claude_codes() {
        let args = a(&[
            "codex",
            "--boundary",
            "srt",
            "--",
            "-c",
            "cli_auth_credentials_store=\"auto\"",
        ]);
        let mac = build(&Inputs {
            macos: true,
            ..inputs(&args)
        })
        .unwrap();
        let v = srt_of(&mac);
        let host_open = v["network"]["allowedDomains"]
            .as_array()
            .unwrap()
            .contains(&json!("auth.openai.com:443"));
        let file_shut = v["filesystem"]["denyWrite"]
            .as_array()
            .unwrap()
            .contains(&json!({"path": "/home/u/.codex/auth.json", "literal": true}));
        assert!(
            !host_open || file_shut,
            "host open {host_open}, auth.json read-only {file_shut}"
        );
    }

    /// FP5R-5, the rest: on Linux too (srt's seccomp keeps the Secret
    /// Service's D-Bus out of reach), from Codex's files as `run::codex_store`
    /// reads them, with the requirements winning over `-c` and `-c` over the
    /// config files; `file` and `ephemeral` keep the host open; another
    /// harness is never touched.
    #[test]
    fn fp5r_5_codex_keyring_stores_shut_the_sign_in_host_on_any_system() {
        let host = |p: &Plan| {
            srt_of(p)["network"]["allowedDomains"]
                .as_array()
                .unwrap()
                .contains(&json!("auth.openai.com:443"))
        };
        let shut = |p: &Plan, path: &str| {
            srt_of(p)["filesystem"]["denyWrite"]
                .as_array()
                .unwrap()
                .contains(&json!({"path": path, "literal": true}))
        };
        for words in [
            vec!["-c", "cli_auth_credentials_store=keyring"],
            vec!["-ccli_auth_credentials_store='auto'"],
            vec!["--config", "cli_auth_credentials_store=\"auto\""],
            vec!["--config=cli_auth_credentials_store=auto"],
            vec![
                "-c",
                "cli_auth_credentials_store=file",
                "-c",
                "cli_auth_credentials_store=auto",
            ],
        ] {
            let mut v = vec!["codex", "--boundary", "srt", "--"];
            v.extend(words.iter().copied());
            let args = a(&v);
            let p = build(&inputs(&args)).unwrap();
            assert!(!host(&p), "{words:?}");
            assert!(shut(&p, "/home/u/.codex/auth.json"), "{words:?}");
            assert!(p.notes.iter().any(|n| n.contains("keyring")), "{words:?}");
        }
        for words in [
            vec![],
            vec!["-c", "cli_auth_credentials_store=file"],
            vec!["-c", "cli_auth_credentials_store=ephemeral"],
            vec![
                "-c",
                "cli_auth_credentials_store=auto",
                "-c",
                "cli_auth_credentials_store=file",
            ],
        ] {
            let mut v = vec!["codex", "--boundary", "srt", "--"];
            v.extend(words.iter().copied());
            let args = a(&v);
            let p = build(&inputs(&args)).unwrap();
            assert!(host(&p), "{words:?}");
            assert!(!shut(&p, "/home/u/.codex/auth.json"), "{words:?}");
        }
        // From the files: the config layers, which `-c file` beats.
        let args = a(&["codex", "--boundary", "srt"]);
        let files = CodexStoreFiles {
            config: Some(
                "/home/u/.codex/config.toml sets cli_auth_credentials_store = \"auto\"".into(),
            ),
            auth_file: Some("/srv/ch/auth.json".into()),
            ..CodexStoreFiles::default()
        };
        let p = build(&Inputs {
            codex_store: files.clone(),
            ..inputs(&args)
        })
        .unwrap();
        assert!(!host(&p) && shut(&p, "/home/u/.codex/auth.json") && shut(&p, "/srv/ch/auth.json"));
        let args = a(&[
            "codex",
            "--boundary",
            "srt",
            "--",
            "-c",
            "cli_auth_credentials_store=file",
        ]);
        let p = build(&Inputs {
            codex_store: files.clone(),
            ..inputs(&args)
        })
        .unwrap();
        assert!(host(&p), "-c beats the config files");
        // The requirements win over `-c`.
        let p = build(&Inputs {
            codex_store: CodexStoreFiles {
                managed: Some(
                    "/etc/codex/requirements.toml sets cli_auth_credentials_store = \"keyring\""
                        .into(),
                ),
                ..CodexStoreFiles::default()
            },
            ..inputs(&args)
        })
        .unwrap();
        assert!(!host(&p), "the requirements beat -c");
        // Claude Code's row is untouched by Codex's store on Linux.
        let args = a(&[
            "claude-code",
            "--boundary",
            "srt",
            "--",
            "-c",
            "cli_auth_credentials_store=auto",
        ]);
        let p = build(&inputs(&args)).unwrap();
        assert!(srt_of(&p)["network"]["allowedDomains"]
            .as_array()
            .unwrap()
            .contains(&json!("platform.claude.com:443")));
    }

    /// FP5R-6: a deny through a link is written by its real path too, a
    /// literal `allowRead` too (one file), the write roots never; a path
    /// that resolves to itself or to `/` adds nothing, and the start says
    /// which paths were links.
    #[test]
    fn fp5r_6_a_deny_through_a_link_also_names_its_real_path() {
        let args = a(&["claude-code", "--boundary", "srt"]);
        let mut p = build(&Inputs {
            macos: true,
            ..inputs(&args)
        })
        .unwrap();
        let before = srt_of(&p);
        let resolve = |s: &str| -> Option<String> {
            if let Some(rest) = s.strip_prefix("/home/u/.claude/") {
                Some(format!("/Volumes/x/claude/{rest}"))
            } else if s == "/home/u/.claude" {
                Some("/Volumes/x/claude".into())
            } else if s == "/home/u/.ssh" {
                Some("/".into())
            } else if s.starts_with("/home/u/.derm") {
                Some(s.replacen("/home/u/.derm", "/srv/derm", 1))
            } else {
                Some(s.to_string())
            }
        };
        deny_real_paths(&mut p, &resolve);
        let v = srt_of(&p);
        let has =
            |key: &str, e: serde_json::Value| v["filesystem"][key].as_array().unwrap().contains(&e);
        assert!(has(
            "denyWrite",
            json!({"path": "/Volumes/x/claude/settings.json", "literal": true})
        ));
        assert!(has(
            "denyWrite",
            json!({"path": "/home/u/.claude/settings.json", "literal": true})
        ));
        assert!(has("denyRead", json!("/srv/derm")));
        assert!(has(
            "allowRead",
            json!({"path": "/srv/derm/policy.json", "literal": true})
        ));
        // A link to `/` adds nothing; the write roots are not resolved.
        assert!(!has("denyRead", json!("/")));
        assert_eq!(
            v["filesystem"]["allowWrite"],
            before["filesystem"]["allowWrite"]
        );
        assert!(
            p.notes.iter().any(|n| n.contains(
                "/home/u/.claude/.credentials.json is /Volumes/x/claude/.credentials.json"
            )),
            "{:?}",
            p.notes
        );
        // With no link, nothing changes.
        let mut q = build(&inputs(&args)).unwrap();
        let text = q.srt_settings.clone();
        let n = q.notes.len();
        deny_real_paths(&mut q, &|s: &str| Some(s.to_string()));
        assert_eq!(q.srt_settings, text);
        assert_eq!(q.notes.len(), n);
    }

    /// Mac test w5 retest 7, MW5-32: Codex 0.163.0 starts every command in
    /// its own sandbox, Seatbelt through `/usr/bin/sandbox-exec` on macOS
    /// (`sandboxing/src/seatbelt.rs:62`) and bubblewrap on Linux, and neither
    /// starts inside srt 0.0.81's ("sandbox-exec: sandbox_apply: Operation
    /// not permitted", run on the Mac; "bwrap: No permissions to create new
    /// namespace", run in the cloud with derm's settings; srt README lines
    /// 712-715), so every command failed while the turn said "done". Under
    /// srt derm starts Codex with `sandbox_mode = "danger-full-access"`, srt
    /// being its sandbox (Codex's `ExternalSandbox` idea, `protocol.rs:1192-1199`,
    /// and its help for the bypass flag: "Intended solely for running in
    /// environments that are externally sandboxed"), at derm's own `-c`
    /// level (case 184), and says so. Its approvals are left alone, so it is
    /// not full access (case 83).
    #[test]
    fn mw5_32_under_srt_codex_runs_with_its_own_sandbox_off_and_says_so() {
        let off = r#"sandbox_mode="danger-full-access""#;
        for macos in [false, true] {
            for (words, want) in [
                (vec!["exec", "go"], vec!["exec", "-c", off, "go"]),
                (vec!["app-server"], vec!["app-server", "-c", off]),
                (vec![], vec!["-c", off]),
                (vec!["-m", "x"], vec!["-c", off, "-m", "x"]),
            ] {
                let mut v = vec!["codex", "--boundary", "srt", "--"];
                v.extend(words.iter().copied());
                let args = a(&v);
                let p = build(&Inputs {
                    macos,
                    ..inputs(&args)
                })
                .unwrap();
                let at = p.args.iter().position(|w| w == "codex").unwrap() + 1;
                assert_eq!(p.args[at..].to_vec(), want, "{words:?}");
                assert!(
                    p.notes.iter().any(|n| n.contains("Codex's own sandbox")),
                    "{:?}",
                    p.notes
                );
                assert!(p.full_access.is_empty(), "{:?}", p.full_access);
                assert!(env(&p, "DERM_FULL_ACCESS").is_none());
            }
        }
        // Not under none or sbx, and never for another harness.
        for v in [
            vec!["codex", "--boundary", "none", "--", "exec", "go"],
            vec!["codex", "--boundary", "sbx", "--", "exec", "go"],
            vec!["claude-code", "--boundary", "srt", "--", "-p", "go"],
        ] {
            let args = a(&v);
            let p = build(&inputs(&args)).unwrap();
            assert!(
                !p.args.iter().any(|w| w.contains("sandbox_mode")),
                "{v:?}: {:?}",
                p.args
            );
        }
        // Words of the user's own that already turn it off: nothing added.
        for words in [
            vec!["--dangerously-bypass-approvals-and-sandbox"],
            vec!["--yolo"],
            vec!["-s", "danger-full-access"],
            vec!["exec", "--sandbox=danger-full-access", "go"],
            vec!["-c", "sandbox_mode=danger-full-access"],
        ] {
            let mut v = vec!["codex", "--boundary", "srt", "--"];
            v.extend(words.iter().copied());
            let args = a(&v);
            let p = build(&inputs(&args)).unwrap();
            assert!(!p.args.iter().any(|w| w == off), "{words:?}: {:?}", p.args);
        }
    }

    /// MW5-32: Codex's own sandbox named on the command line cannot start
    /// under srt, and derm does not override the user's own words, so the
    /// chat is refused before anything starts, saying why and the two ways
    /// out. Under none it is the user's call, as before.
    #[test]
    fn mw5_32_codexs_own_sandbox_named_under_srt_is_refused() {
        for words in [
            vec!["-s", "workspace-write"],
            vec!["--sandbox", "read-only"],
            vec!["--sandbox=read-only"],
            vec!["-sread-only"],
            vec!["exec", "-s", "workspace-write", "go"],
            vec!["--approve-for-me"],
            vec!["exec", "--not-so-yolo", "go"],
            vec!["-c", "sandbox_mode=\"workspace-write\""],
            vec!["exec", "--config=sandbox_mode='read-only'", "go"],
            vec!["-c", "default_permissions=\":workspace\""],
            vec!["-cdefault_permissions=\":read-only\""],
        ] {
            let mut v = vec!["codex", "--boundary", "srt", "--"];
            v.extend(words.iter().copied());
            let args = a(&v);
            let e = build(&inputs(&args)).unwrap_err();
            assert!(
                e.contains("Codex's own sandbox") && e.contains("--boundary none"),
                "{words:?}: {e}"
            );
        }
        let args = a(&["codex", "--boundary", "none", "--", "-s", "read-only"]);
        assert!(build(&inputs(&args)).is_ok());
    }

    /// MW5-32: a managed file that keeps Codex in its own sandbox (a
    /// requirement on the modes or profiles, or a managed `sandbox_mode`,
    /// which Codex layers over `-c`, `config/src/loader/mod.rs:420-440`)
    /// refuses srt, with the file's reason; `run::codex_store` reads them.
    #[test]
    fn mw5_32_a_managed_rule_on_codexs_sandbox_refuses_srt() {
        let why =
            "/etc/codex/requirements.toml sets allowed_sandbox_modes without danger-full-access";
        let files = CodexStoreFiles {
            managed_sandbox: Some(why.into()),
            ..CodexStoreFiles::default()
        };
        let args = a(&["codex", "--boundary", "srt", "--", "exec", "go"]);
        let e = build(&Inputs {
            codex_store: files.clone(),
            ..inputs(&args)
        })
        .unwrap_err();
        assert!(e.contains(why) && e.contains("Codex's own sandbox"), "{e}");
        let none = a(&["codex", "--boundary", "none", "--", "exec", "go"]);
        assert!(build(&Inputs {
            codex_store: files,
            ..inputs(&none)
        })
        .is_ok());
    }

    /// MW5-32's Linux half (fix pass 8, run in the cloud with derm's srt
    /// settings and the real Codex 0.163.0): srt 0.0.81 holds a missing
    /// `denyWrite` file by binding `/dev/null` over it
    /// (`linux-sandbox-utils.js:2334-2347`), and Codex reads `~/.codex/rules`
    /// as a folder (`core/src/exec_policy.rs:1121-1130`: a missing one is no
    /// rules, any other error is fatal), so a fresh Codex under derm's srt
    /// stopped with "failed to read rules files ...: Not a directory". A
    /// missing control folder is denied by a path inside it instead, which
    /// srt holds with an empty read-only folder (run: nothing can be made in
    /// it, and srt removes it after); one that exists, macOS, and other
    /// harnesses are left as they are.
    #[test]
    fn mw5_32_on_linux_a_missing_codex_control_folder_is_held_as_an_empty_folder() {
        let args = a(&["codex", "--boundary", "srt", "--", "exec", "go"]);
        let exists = |s: &str| s.ends_with("/.codex/plugins");
        let mut p = build(&inputs(&args)).unwrap();
        keep_absent_control_folders(&mut p, "codex", false, &exists);
        let v = srt_of(&p);
        let deny = v["filesystem"]["denyWrite"].as_array().unwrap().clone();
        let has = |s: &str| deny.contains(&json!({"path": s, "literal": true}));
        // Fix pass 8's review changed this: the folder's own deny stays beside
        // the inner one (FP8-S5), and the chat folder's `.codex` is denied
        // whole (FP8-S3), so nothing there is rewritten.
        let base = "/home/u/.codex";
        for f in ["rules", "tmp"] {
            assert!(has(&format!("{base}/{f}/{ABSENT_FOLDER_MARK}")), "{deny:?}");
            assert!(has(&format!("{base}/{f}")), "{deny:?}");
        }
        assert!(
            !has(&format!("{base}/plugins/{ABSENT_FOLDER_MARK}")),
            "{deny:?}"
        );
        assert!(has(&format!("{base}/plugins")), "{deny:?}");
        assert!(has(&format!("{base}/config.toml")), "{deny:?}");
        assert!(has("/home/u/proj dir/.codex"), "{deny:?}");
        assert!(
            !deny.iter().any(|e| e["path"]
                .as_str()
                .unwrap()
                .starts_with("/home/u/proj dir/.codex/")),
            "{deny:?}"
        );
        for (harness, macos, v) in [
            (
                "codex",
                true,
                vec!["codex", "--boundary", "srt", "--", "exec", "go"],
            ),
            (
                "claude-code",
                false,
                vec!["claude-code", "--boundary", "srt"],
            ),
        ] {
            let args = a(&v);
            let mut q = build(&Inputs {
                macos,
                ..inputs(&args)
            })
            .unwrap();
            let before = q.srt_settings.clone();
            keep_absent_control_folders(&mut q, harness, macos, &|_| false);
            assert_eq!(q.srt_settings, before, "{harness} macos {macos}");
        }
    }

    /// FP8-S4 (security review of fix pass 8): clap reads `-c=k=v` as
    /// `-c k=v` (run against Codex 0.163.0: `codex exec -c=foo` says
    /// "Invalid override (missing '='): foo"), so `-c=sandbox_mode=...` keeps
    /// Codex's own sandbox on and must be refused like `-c sandbox_mode=...`.
    /// `-s=danger-full-access` is Codex's own word for off and is not a refusal.
    #[test]
    fn fp8_s4_dash_c_equals_form_is_read() {
        for words in [
            vec!["exec", "-c=sandbox_mode=\"read-only\"", "go"],
            vec!["-c=default_permissions=\":workspace\""],
        ] {
            let mut v = vec!["codex", "--boundary", "srt", "--"];
            v.extend(words.iter().copied());
            let args = a(&v);
            assert!(build(&inputs(&args)).is_err(), "{words:?} was not refused");
        }
        let args = a(&["codex", "--boundary", "srt", "--", "-s=danger-full-access"]);
        assert!(
            build(&inputs(&args)).is_ok(),
            "-s=danger-full-access was refused"
        );
    }

    /// FP8-S1: with Codex's own sandbox off, its commands write `~/.codex`
    /// (derm's state folder for it). `~/.codex/.env` is loaded into Codex's
    /// environment at every start (Codex 0.163.0 `arg0/src/lib.rs:132,
    /// 274-280`, only `CODEX_*` names filtered), so it must stay read-only as
    /// `config.toml` does (Gemini's `.gemini/.env` already is).
    #[test]
    fn fp8_s1_codex_home_env_is_read_only_under_srt() {
        let args = a(&["codex", "--boundary", "srt", "--", "exec", "go"]);
        let p = build(&inputs(&args)).unwrap();
        let v = srt_of(&p);
        let deny = v["filesystem"]["denyWrite"].as_array().unwrap().clone();
        assert!(
            deny.iter().any(|e| e["path"] == "/home/u/.codex/.env"),
            "{deny:?}"
        );
    }

    /// FP8-S5: the rewrite replaces the folder's own deny. A folder that is
    /// missing when derm looks and present when srt starts (another chat's
    /// srt mount point, a concurrent Codex writing `default.rules`) is then
    /// writable (run with srt 0.0.81). Keeping the folder's deny beside the
    /// inner one holds it either way (run: srt mounts an empty read-only
    /// folder when it is missing, since a deny path lies beneath it).
    #[test]
    fn fp8_s5_the_folders_own_deny_is_kept_beside_the_inner_one() {
        let args = a(&["codex", "--boundary", "srt", "--", "exec", "go"]);
        let mut p = build(&inputs(&args)).unwrap();
        keep_absent_control_folders(&mut p, "codex", false, &|_| false);
        let v = srt_of(&p);
        let deny = v["filesystem"]["denyWrite"].as_array().unwrap().clone();
        assert!(
            deny.contains(&json!({"path": "/home/u/.codex/rules", "literal": true})),
            "{deny:?}"
        );
    }

    /// FP8-S1, S2, S3, S7 (fix pass 8): under srt Codex's commands no longer
    /// meet Codex's own sandbox, so what it held that srt did not is denied
    /// by derm: Codex's `.env`, its profiles and its `tmp/` in its home, a
    /// submodule's git config and hooks, and the whole `.codex` of the chat's
    /// folder (not when the folder is the home).
    #[test]
    fn fp8_what_codexs_own_sandbox_held_stays_read_only_under_srt() {
        let args = a(&["codex", "--boundary", "srt", "--", "exec", "go"]);
        let p = build(&Inputs {
            codex_store: CodexStoreFiles {
                profiles: vec![
                    "/home/u/.codex/work.config.toml".into(),
                    "rel.config.toml".into(),
                ],
                ..CodexStoreFiles::default()
            },
            git_controls: vec![
                "/home/u/proj dir/.git/modules/sub/config".into(),
                "/home/u/proj dir/.git/modules/sub/hooks".into(),
                "rel".into(),
            ],
            ..inputs(&args)
        })
        .unwrap();
        let v = srt_of(&p);
        let deny: Vec<String> = v["filesystem"]["denyWrite"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_string())
            .collect();
        for want in [
            "/home/u/.codex/.env",
            "/home/u/.codex/tmp",
            "/home/u/.codex/packages",
            "/home/u/.codex/shell_snapshots",
            "/home/u/.codex/AGENTS.md",
            "/home/u/.codex/prompts",
            "/home/u/.codex/work.config.toml",
            "/home/u/proj dir/.git/modules/sub/config",
            "/home/u/proj dir/.git/modules/sub/hooks",
            "/home/u/proj dir/.codex",
        ] {
            assert!(deny.iter().any(|d| d == want), "{want} not in {deny:?}");
        }
        // Only absolute paths; and the folder's own copies are covered by
        // its whole `.codex`, not one deny each.
        assert!(!deny.iter().any(|d| d.starts_with("rel")), "{deny:?}");
        assert!(
            !deny
                .iter()
                .any(|d| d == "/home/u/proj dir/.codex/config.toml"),
            "{deny:?}"
        );
        // Another harness gets the submodule denies too, and no Codex ones.
        let args = a(&["claude-code", "--boundary", "srt"]);
        let p = build(&Inputs {
            git_controls: vec!["/home/u/proj dir/.git/modules/sub/hooks".into()],
            ..inputs(&args)
        })
        .unwrap();
        let deny = srt_of(&p)["filesystem"]["denyWrite"].to_string();
        assert!(
            deny.contains("/home/u/proj dir/.git/modules/sub/hooks"),
            "{deny}"
        );
        assert!(!deny.contains("/home/u/proj dir/.codex\""), "{deny}");
        // The home as the chat's folder: Codex's own state is not denied whole.
        let args = a(&["codex", "--boundary", "srt", "--", "exec", "go"]);
        let p = build(&Inputs {
            cwd: "/home/u".into(),
            ..inputs(&args)
        })
        .unwrap();
        let deny: Vec<String> = srt_of(&p)["filesystem"]["denyWrite"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_string())
            .collect();
        assert!(!deny.iter().any(|d| d == "/home/u/.codex"), "{deny:?}");
        assert!(
            deny.iter().any(|d| d == "/home/u/.codex/config.toml"),
            "{deny:?}"
        );
    }

    /// FP8-S4: `-c=k=v` names the sign-in store as `-c k=v` does.
    #[test]
    fn fp8_s4_dash_c_equals_names_the_store() {
        let w = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            codex_store_from_args(&w(&["exec", "-c=cli_auth_credentials_store=\"keyring\""])),
            Some("keyring".into())
        );
        assert_eq!(
            codex_store_from_args(&w(&["-ccli_auth_credentials_store=file"])),
            Some("file".into())
        );
        assert!(matches!(
            codex_own_sandbox(&w(&["-s=read-only"])),
            CodexOwnSandbox::On(_)
        ));
        assert!(matches!(
            codex_own_sandbox(&w(&["-c=sandbox_mode=danger-full-access"])),
            CodexOwnSandbox::Off
        ));
    }
}
