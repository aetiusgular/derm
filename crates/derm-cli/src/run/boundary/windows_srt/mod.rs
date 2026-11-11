//! srt on Windows (wave 5b lane 5bD; `contracts/srt-windows.md`): the
//! handoff file, `derm.exe enter` as srt's command, one srt chat at a time on
//! the machine (case 230; note BC section 11: one sandbox account per
//! machine, two sandboxed processes open each other with full access, and
//! srt's CLI cannot run two chats at once).
//!
//! srt 0.0.82 runs the command on Windows as its `srt-sandbox` account, from
//! a fresh profile environment of that account overlaid with only `PATH`,
//! `PATHEXT`, its proxy set and git's (`src/sandbox/windows-sandbox-utils.ts:
//! 4357-4466`), through `cmd.exe /d /s /c <the -c string>`
//! (`vendor/srt-win-src/src/launch.rs:577-605`). So the plan `derm run`
//! built for Unix is rewritten here ([`rewrite`]):
//!
//! - srt runs `"<derm.exe>" enter "<handoff>"`, one string with `-c`
//!   ([`command_string`]);
//! - the chat's variables, its token and the harness's argv go in the
//!   handoff, which `derm run` writes in a folder of the user's that only
//!   the user can open, granting the sandbox account read and delete on the
//!   file alone; `derm enter` deletes it once read (case 231);
//! - beside it, the token file and `chat.json` (the policy `derm run` judged
//!   here and the daemon's route), read-only to the sandbox account for the
//!   chat's life;
//! - the harness keeps its state in a folder of derm's
//!   (`%USERPROFILE%\.derm-srt\state\<harness>`), given its sign-in and
//!   config by copy, emptied when the chat stops; the sign-in host stays shut
//!   so a renewal inside cannot spend the single-use refresh token the
//!   user's own copy holds (cases 181, 186 and 190's rule);
//! - srt's settings are written for Windows: the chat's folder and that
//!   state folder writable, the harness's control files and derm itself not,
//!   `%USERPROFILE%\.derm` and the user's own harness state unreadable
//!   (case 143), `network.allowLocalBinding` off (BCR-4), the srt-win
//!   backend pinned (BCR-9);
//! - a machine-wide lock ([`lock`]) holds while the chat runs, so a second
//!   srt chat, any Windows user's, is refused with the reason (case 230).
//!
//! The seam the wave 5b base cut: `run/preflight.rs` and
//! `run/boundary/probe.rs` ask [`refusal`] whether srt may start on Windows.
//! `run/mod.rs` calls [`wire`] once the plan is built (request 5bD-1,
//! `tests/windows/5bD/requests/`). Until integration applies that request,
//! [`WIRED`] is false and srt stays refused on Windows, as on the base.

// `wire` and what it calls are reached from `run/mod.rs` once request 5bD-1
// is applied; until then only the tests reach part of them. Request 5bD-1
// removes this line.
#![allow(dead_code)]

mod files;
pub(crate) mod lock;
mod settings;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use serde_json::Value;

use crate::enter::handoff::{self, Handoff};
use crate::run::harness::{self, Harness};
use crate::run::plan::Plan;

pub(crate) use files::Session;

/// Whether `run/mod.rs` calls [`wire`]. Request 5bD-1 sets it with the call.
pub(crate) const WIRED: bool = false;

/// Why derm does not start srt on Windows now, or `None` when it may.
pub(crate) fn refusal() -> Option<&'static str> {
    if !WIRED {
        return Some(crate::run::preflight::SRT_ON_WINDOWS);
    }
    lock::held_elsewhere().then_some(lock::HELD)
}

/// How long a handoff stays valid after it is written: srt's own start
/// (its proxies, its access lists on a first use of a folder) comes first.
pub(crate) const HANDOFF_LIFE_MS: u64 = 10 * 60 * 1000;

/// Where a harness keeps its state under srt on Windows: the variable that
/// names the folder, its name under derm's state folder, and the user's own
/// files copied in (relative to the user's profile, then to that folder).
pub(crate) struct Layout {
    pub variable: &'static str,
    pub folder: &'static str,
    pub copies: &'static [(&'static str, &'static str)],
}

/// The harnesses srt on Windows has a state layout for. Claude Code 2.1.322
/// reads `.claude.json` and `settings.json` from `CLAUDE_CONFIG_DIR` when it
/// is set (`globalConfig: join(dir, ".claude.json")`, `userSettings:
/// join(dir, "settings.json")`) and its sign-in from `.credentials.json` in
/// the same folder (read in `claude.exe` of `claude-code-win32-x64`).
/// Codex 0.167.1 reads everything from `CODEX_HOME`, which must exist and be
/// a folder (`codex-rs/utils/home-dir/src/lib.rs:6-46` at `rust-v0.167.1`).
pub(crate) fn layout(id: &str) -> Option<Layout> {
    match id {
        "claude-code" => Some(Layout {
            variable: "CLAUDE_CONFIG_DIR",
            folder: "claude",
            copies: &[
                (".claude.json", ".claude.json"),
                (".claude\\.credentials.json", ".credentials.json"),
                (".claude\\settings.json", "settings.json"),
            ],
        }),
        "codex" => Some(Layout {
            variable: "CODEX_HOME",
            folder: "codex",
            copies: &[
                (".codex\\config.toml", "config.toml"),
                (".codex\\auth.json", "auth.json"),
                (".codex\\hooks.json", "hooks.json"),
            ],
        }),
        _ => None,
    }
}

/// A command name to the program that runs it and the words that go before
/// the caller's.
pub(crate) type Launch<'a> = &'a dyn Fn(&str) -> Result<(String, Vec<String>), String>;

/// What the rewrite needs that the plan does not hold.
pub(crate) struct Ctx<'a> {
    pub chat: &'a str,
    pub harness: &'static Harness,
    /// The chat's folder and the user's profile, as `derm run` read them
    /// (`\\?\C:\...` forms are taken back to `C:\...`).
    pub cwd: &'a str,
    pub home: &'a str,
    /// `derm.exe`, by its absolute path.
    pub derm_exe: &'a str,
    pub token: Option<&'a str>,
    pub policy: &'a derm_core::policy::PolicyFile,
    pub policy_problem: Option<&'a str>,
    /// srt's sandbox account's name, from its install record.
    pub sandbox_user: Option<&'a str>,
    pub now_ms: u64,
    /// The program for a command name and the words that go before the
    /// caller's (lane Z's npm shim reading, case 138).
    pub launch: Launch<'a>,
    /// Whether a path exists (srt-win refuses a deny of nothing; I).
    pub exists: &'a dyn Fn(&str) -> bool,
}

/// What [`rewrite`] made: the files [`files::materialize`] writes.
#[derive(Debug)]
pub(crate) struct Prepared {
    pub handoff: Handoff,
    pub chat_dir: String,
    pub handoff_path: String,
    pub state_dir: String,
    /// (from, to), absolute.
    pub copies: Vec<(String, String)>,
}

/// `\\?\C:\x` as `C:\x`; any other form as written.
pub(crate) fn plain_win(p: &str) -> String {
    match p.strip_prefix(r"\\?\") {
        Some(rest) if handoff::win_absolute(rest) => rest.to_string(),
        _ => p.to_string(),
    }
}

/// `a` and `b` joined with one backslash.
pub(crate) fn join(a: &str, b: &str) -> String {
    format!(
        "{}\\{}",
        a.trim_end_matches('\\'),
        b.trim_start_matches('\\').replace('/', "\\")
    )
}

/// A path `cmd.exe /s /c` passes on as written inside double quotes: no
/// `"` (which ends the quotes), no `%` (expanded inside quotes too), no `!`
/// (expanded when delayed expansion is on), no control character, and not
/// ending in `\` (which would escape the closing quote for the program's
/// own argument parser).
pub(crate) fn cmd_safe(p: &str) -> bool {
    handoff::win_absolute(p)
        && !p.ends_with('\\')
        && !p
            .chars()
            .any(|c| matches!(c, '"' | '%' | '!') || c.is_control())
}

/// srt's `-c` string: `"<derm.exe>" enter "<handoff>"`. srt-win wraps it in
/// one pair of quotes for `cmd.exe /d /s /c` to strip and passes it on
/// verbatim (`launch.rs:577-605`, its test `build_cmdline_cmd_passthrough`).
pub(crate) fn command_string(derm_exe: &str, handoff_path: &str) -> Result<String, String> {
    for (what, p) in [("derm.exe", derm_exe), ("the handoff", handoff_path)] {
        if !cmd_safe(p) {
            return Err(format!(
                "srt on Windows runs derm through cmd.exe, which would read {what}'s path {p:?} as more than a path (a quote, %, ! or a control character, or not a drive path); move it"
            ));
        }
    }
    Ok(format!("\"{derm_exe}\" enter \"{handoff_path}\""))
}

/// The origin of a loopback URL, for the handoff's `daemon.http`.
fn origin(url: &str) -> Option<String> {
    let (scheme, host, port, _) = crate::run::plan::split_url(url)?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let o = format!("{scheme}://{host}:{port}");
    handoff::loopback_http(&o).then_some(o)
}

/// Rewrites the srt plan `plan::build` made into srt's Windows form, and
/// says which files to write. Writes nothing.
pub(crate) fn rewrite(p: &mut Plan, c: &Ctx) -> Result<Prepared, String> {
    if p.program != "srt" {
        return Err("internal: the Windows srt rewrite was given a plan that is not srt's".into());
    }
    let layout = layout(c.harness.id).ok_or_else(|| {
        format!(
            "derm has no srt state layout for {} on Windows yet (Claude Code and Codex only); use --boundary sbx, or none",
            c.harness.id
        )
    })?;
    let unix: Value = p
        .srt_settings
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .ok_or("internal: the srt plan has no settings")?;
    let settings_at = p
        .args
        .iter()
        .position(|a| a == "--settings")
        .and_then(|i| p.args.get(i + 1).cloned())
        .ok_or("internal: the srt plan names no settings file")?;
    let dash = p
        .args
        .iter()
        .position(|a| a == "--")
        .ok_or("internal: the srt plan has no `--`")?;
    let mut words: Vec<String> = p.args[dash + 1..].to_vec();
    // `plan::srt_loopback_through_proxy`'s wrap is for Unix: srt on Windows
    // deletes NO_PROXY itself, so loopback goes through its proxy
    // (windows-sandbox-utils.ts:4392-4403), and there is no /usr/bin/env.
    if words.first().is_some_and(|w| w == "/usr/bin/env")
        && words.get(1).is_some_and(|w| w.starts_with("NO_PROXY="))
        && words.get(2).is_some_and(|w| w.starts_with("no_proxy="))
    {
        words.drain(..3);
    }
    let command = words
        .first()
        .cloned()
        .ok_or("internal: no harness command")?;
    let (program, leading) = (c.launch)(&command)?;
    let program = plain_win(&program);
    if !handoff::exe_path(&program) {
        return Err(format!(
            "srt on Windows starts the harness by its absolute .exe path; {command} is {program}"
        ));
    }
    let mut argv = vec![program];
    argv.extend(leading);
    argv.extend(words.into_iter().skip(1));

    let token = c
        .token
        .ok_or("srt on Windows needs the daemon: the chat token and the gate's route come from it (drop --no-daemon)")?;
    let cwd = plain_win(c.cwd);
    let home = plain_win(c.home);
    let derm_exe = plain_win(c.derm_exe);
    for (what, p) in [("the chat's folder", &cwd), ("USERPROFILE", &home)] {
        if !handoff::win_absolute(p) {
            return Err(format!(
                "srt on Windows needs {what} as a drive path; it is {p:?}"
            ));
        }
    }
    let derm_root = join(&home, ".derm-srt");
    let chat_dir = join(&join(&derm_root, "chats"), c.chat);
    let state_dir = join(&join(&derm_root, "state"), c.harness.id);
    let harness_dir = join(&state_dir, layout.folder);
    let handoff_path = join(&chat_dir, "handoff.json");

    let mut variables = BTreeMap::new();
    let mut daemon = None;
    for (k, v) in &p.env_set {
        if k == "DERM_CHAT_TOKEN" {
            continue;
        }
        if k == "DERM_OTLP_ENDPOINT" {
            daemon = origin(v);
        }
        // srt sets NODE_USE_ENV_PROXY itself on Windows (:4458-4462).
        if handoff::reserved(k) {
            continue;
        }
        if !handoff::variable_name(k) {
            return Err(format!(
                "internal: the variable {k} cannot go into srt's handoff on Windows"
            ));
        }
        variables.insert(k.clone(), v.clone());
    }
    variables.insert(layout.variable.to_string(), harness_dir.clone());
    let daemon_http = daemon.ok_or(
        "srt on Windows needs the daemon's loopback port for the gate inside; the daemon published none",
    )?;
    let policy = serde_json::to_value(c.policy).map_err(|e| e.to_string())?;
    let h = Handoff {
        chat: c.chat.to_string(),
        harness: c.harness.id.to_string(),
        argv,
        cwd: cwd.clone(),
        variables,
        token: token.to_string(),
        daemon_http,
        policy,
        policy_problem: c.policy_problem.map(str::to_string),
        expires: c.now_ms + HANDOFF_LIFE_MS,
    };
    // The handoff is judged here by the rules `derm enter` reads it by.
    handoff::parse(handoff::to_json(&h).to_string().as_bytes(), c.now_ms)?;

    let sign_in = harness::sign_in_hosts(c.harness.id);
    let s = settings::build(&settings::Inputs {
        unix: &unix,
        harness: c.harness,
        cwd: &cwd,
        home: &home,
        state_dir: &state_dir,
        harness_dir: &harness_dir,
        derm_exe: &derm_exe,
        sandbox_user: c.sandbox_user,
        drop_hosts: sign_in,
        exists: c.exists,
    });
    p.srt_settings = Some(serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?);
    p.args = vec![
        "--settings".into(),
        settings_at,
        "-c".into(),
        command_string(&derm_exe, &handoff_path)?,
    ];
    // Everything the harness needs rides the handoff; srt's own process
    // gets none of the chat's variables.
    p.env_set.clear();
    p.state_dirs = vec![state_dir.clone()];
    p.notes.retain(|n| !n.contains("sign-in host"));
    p.notes.push(
        "derm run: srt on Windows runs every chat as one sandbox account, so this machine runs one srt chat at a time: another, any Windows user's, is refused while this one runs".into(),
    );
    if !sign_in.is_empty() {
        p.notes.push(format!(
            "derm run: under srt on Windows {} gets a copy of your sign-in in {state_dir}, and its sign-in host stays shut, so a renewal inside cannot spend the refresh token your own copy holds: once its access token expires the chat stops; run it once outside srt to renew, then start the chat again",
            c.harness.id
        ));
    }
    p.notes.push(format!(
        "derm run: {state_dir} is emptied when the chat stops (its sessions and history go with it), since any later srt session on this machine can read a folder srt was given to write"
    ));
    let copies = layout
        .copies
        .iter()
        .map(|(from, to)| (join(&home, from), join(&harness_dir, to)))
        .collect();
    Ok(Prepared {
        handoff: h,
        chat_dir,
        handoff_path,
        state_dir,
        copies,
    })
}

/// `run/mod.rs`'s one call on Windows (request 5bD-1): rewrites the plan
/// and, unless it is a dry run, takes the machine's lock and writes the
/// chat's files. The [`Session`] removes them and frees the lock when it is
/// dropped, as the chat ends.
#[allow(clippy::too_many_arguments)]
pub(crate) fn wire(
    p: &mut Plan,
    chat: &str,
    harness: &'static Harness,
    cwd: &str,
    home: &str,
    token: Option<&str>,
    policy: &derm_core::policy::PolicyFile,
    policy_problem: Option<&str>,
    dry_run: bool,
) -> Result<Option<Session>, (u8, String)> {
    files::wire(
        p,
        chat,
        harness,
        cwd,
        home,
        token,
        policy,
        policy_problem,
        dry_run,
    )
}
