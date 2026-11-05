//! Starting the harness as the agents' user (wave 5, lane V; S2 part c, rules
//! cases 53 and 125). The wave 5 base cut this seam: `run_io` calls [`wrap`]
//! on the launch plan just before the harness starts, and adds the returned
//! record to `run.start` as `detail.agentUser` (`contracts/events.md`
//! section 5).
//!
//! What it does, on Linux, for a chat with no boundary, when root has named
//! an agents' user for the person (`/etc/derm/agent-users.json`, written by
//! `packaging/linux/agent-user/install.sh` on the person's yes):
//!
//! 1. checks the user: it exists as the file says, it is not root or the
//!    person, and it is in no group that leads to root or to the person's
//!    files (`anchor::refusal`);
//! 2. checks, as that user, through the same `sudo` route, that it cannot
//!    reach the daemon's folder, `daemon.token`, `~/.derm` or the person's
//!    harness logins, that it can write the chat's folders, and that it has
//!    its own install of the harness; any miss stops the start and says what
//!    to change;
//! 3. opens the chat's bridge (`bridge.rs`): a relay to the daemon for this
//!    chat's token only, a read-only copy of the person's policy, the token
//!    file;
//! 4. rewrites the launch as `sudo -n -u <user> --preserve-env=<derm's
//!    variables> -- /usr/bin/env PATH=<the file's path> <harness> <args>`.
//!    The chat token and the bridge's paths stay in the environment, which
//!    only the harness's user and root can read (proc(5),
//!    `/proc/<pid>/environ`), never in arguments, which every local user can.
//!
//! The daemon, its token, the audit feed and the person's files stay the
//! person's. The agent gets nothing back: no `sudo` rule names it, and the
//! person's runtime folder is 0700.
//!
//! The launch plan no longer says the boundary (`Plan::clone_for_start`), so
//! `run_io` passes the chat's details in [`Context`] (lane V's request V-1,
//! applied by integration).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use serde_json::{json, Value};

use super::plan::Plan;

pub(crate) mod anchor;
pub(crate) mod bridge;

/// What `wrap_with` needs from `run_io` (lane V's request V-1).
pub(crate) struct Context<'a> {
    /// `none`, `srt` or `sbx`.
    pub boundary: &'a str,
    pub chat: &'a str,
    pub cwd: &'a str,
    pub folders: &'a [String],
    pub home: &'a str,
    /// The daemon's folder and socket, when a daemon is in use.
    pub daemon_dir: Option<&'a str>,
    pub daemon_socket: Option<&'a str>,
    pub token: Option<&'a str>,
    /// The policy file the gate would read.
    pub policy: &'a str,
}

/// Where `sudo` and `env` must be: root's, never found on `PATH` (case 37).
const SUDO: &str = "/usr/bin/sudo";
const ENV: &str = "/usr/bin/env";
const SH: &str = "/bin/sh";
/// The person may say a chat runs as them anyway (`DERM_RUN_AS=you`); the
/// chat is then unbounded as them, and the daemon's person check applies.
const RUN_AS_VAR: &str = "DERM_RUN_AS";

/// The open bridge, kept until `finish` (or the process's exit).
static BRIDGE: Mutex<Option<bridge::Bridge>> = Mutex::new(None);

/// Starts the harness as the agents' user when one is set up (module text).
pub(crate) fn wrap_with(launch: &mut Plan, ctx: &Context) -> Result<Option<Value>, (u8, String)> {
    if !cfg!(target_os = "linux") || ctx.boundary != "none" {
        // A boundary keeps the agent from the daemon's token already (srt
        // hides the folder; sbx runs a VM: tk_sbx_smoke.md, step 5).
        return Ok(None);
    }
    if run_as_you() {
        eprintln!("derm run: {RUN_AS_VAR}=you: the harness runs as you with no boundary; an agent can read daemon.token, so a yes for it needs your password (S2)");
        return Ok(None);
    }
    let me = euid();
    let entry = match anchor::for_owner(me) {
        Ok(None) => return Ok(None),
        Ok(Some(e)) => e,
        Err(why) => return Err((1, why.to_string())),
    };
    let fail = |why: String| -> Result<Option<Value>, (u8, String)> {
        Err((1, format!("{why}; not starting the harness (S2 part c)")))
    };
    let Some(agent) = anchor::account(&entry.user) else {
        return fail(format!(
            "{} names {}, which is not a user here",
            anchor::ANCHOR,
            entry.user
        ));
    };
    if agent.uid != entry.uid {
        return fail(format!(
            "{} has uid {}, not {} as {} says",
            entry.user,
            agent.uid,
            entry.uid,
            anchor::ANCHOR
        ));
    }
    let Some(owner) = anchor::account(&entry.owner).filter(|o| o.uid == me) else {
        return fail(format!(
            "{} names owner {} with another uid than yours",
            anchor::ANCHOR,
            entry.owner
        ));
    };
    let Some(groups) = anchor::groups(&agent) else {
        return fail(format!("the groups of {} could not be read", agent.name));
    };
    if let Some(why) = anchor::refusal(&agent, &groups, &owner) {
        return fail(why);
    }
    let sudo = trusted_tool(SUDO, true).map_err(|e| (1, e.to_string()))?;
    let env_tool = trusted_tool(ENV, false).map_err(|e| (1, e.to_string()))?;
    let sh = trusted_tool(SH, false).map_err(|e| (1, e.to_string()))?;
    let program = Path::new(&launch.program)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && !n.starts_with('-'))
        .ok_or_else(|| (1, format!("{} is not a program name", launch.program)))?
        .to_string();

    // As the agents' user: what it must not reach, what it must write.
    let home = ctx.home.trim_end_matches('/');
    let mut hidden: Vec<String> = Vec::new();
    if let Some(d) = ctx.daemon_dir {
        hidden.push(d.to_string());
        hidden.push(format!("{d}/daemon.token"));
    }
    hidden.push(format!("{home}/.derm"));
    hidden.push(ctx.policy.to_string());
    for h in super::harness::HARNESSES {
        if let Some(c) = h.credential {
            hidden.push(format!("{home}/{c}"));
        }
    }
    hidden.sort();
    hidden.dedup();
    let mut writable: Vec<String> = vec![ctx.cwd.to_string()];
    writable.extend(ctx.folders.iter().cloned());
    writable.sort();
    writable.dedup();
    let probe = Probe {
        sudo: &sudo,
        sh: &sh,
        user: &entry.user,
        path: &entry.path,
        program: &program,
        hidden: &hidden,
        writable: &writable,
    };
    let found = probe.run().map_err(|e| (1, e.to_string()))?;
    if let Some(why) = found.refusal(&entry.user, &program) {
        return fail(why);
    }

    // The bridge, when there is a daemon to bridge to.
    let mut set: Vec<(String, String)> = Vec::new();
    if let (Some(sock), Some(token)) = (ctx.daemon_socket, ctx.token) {
        let base = PathBuf::from(bridge::BASE_ROOT).join(me.to_string());
        let b = bridge::open(&bridge::Spec {
            base: &base,
            base_parent_owner: 0,
            chat: ctx.chat,
            agent_uid: agent.uid,
            daemon_socket: Path::new(sock),
            token,
            policy: Some(Path::new(ctx.policy)),
        })
        .map_err(|e| (1, format!("the chat's bridge: {e}")))?;
        set = bridge_env(&b, &launch.env_set);
        if let Ok(mut slot) = BRIDGE.lock() {
            *slot = Some(b);
        }
        // SAFETY: atexit registers a plain function with no arguments; it
        // runs once at a normal exit, after `run_io` returns.
        unsafe {
            libc::atexit(finish_at_exit);
        }
    }
    rewrite(launch, &sudo, &env_tool, &entry, &program, &set);
    eprintln!(
        "derm run: {program} starts as {}, not as you (S2 part c): your daemon, its token and your files stay yours",
        entry.user
    );
    Ok(Some(json!({
        "user": entry.user,
        "uid": entry.uid,
        "how": anchor::HOW_SUDO,
    })))
}

/// The variables that point the gate inside at the bridge.
fn bridge_env(b: &bridge::Bridge, env: &[(String, String)]) -> Vec<(String, String)> {
    let path = |p: &Path| p.to_string_lossy().into_owned();
    let mut set = vec![
        ("DERM_DAEMON_SOCKET".to_string(), path(b.socket())),
        ("DERM_POLICY".to_string(), path(b.policy())),
    ];
    for name in ["DERM_CHAT_TOKEN_FILE", "GEMINI_CLI_DERM_CHAT_TOKEN_FILE"] {
        if env.iter().any(|(k, _)| k == name) {
            set.push((name.into(), path(b.token_file())));
        }
    }
    set
}

/// Stops the chat's bridge and removes its folder. `run_io` calls it after
/// the harness exits; `atexit` covers an exit that skips that.
pub(crate) fn finish() {
    if let Ok(mut slot) = BRIDGE.lock() {
        slot.take();
    }
}

extern "C" fn finish_at_exit() {
    finish();
}

fn run_as_you() -> bool {
    std::env::var(RUN_AS_VAR).is_ok_and(|v| v == "you")
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// `path` resolved, a regular file of root's that no one else can write, in
/// folders of root's no one else can write; `setid`: it must be set-user-id
/// (sudo). Returns the resolved path.
fn trusted_tool(path: &str, setid: bool) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let real = std::fs::canonicalize(path).map_err(|e| format!("{path}: {e}"))?;
    let m = std::fs::metadata(&real).map_err(|e| format!("{}: {e}", real.display()))?;
    let ok =
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && (!setid || m.mode() & 0o4000 != 0);
    let parents_ok = real
        .ancestors()
        .skip(1)
        .all(|p| std::fs::metadata(p).is_ok_and(|d| d.uid() == 0 && d.mode() & 0o022 == 0));
    if !ok || !parents_ok {
        return Err(format!(
            "{path} ({}) is not a root-owned program{} that only root can change",
            real.display(),
            if setid { ", set-user-id," } else { "" }
        ));
    }
    Ok(real.to_string_lossy().into_owned())
}

/// The variables the harness keeps under `sudo`: derm's own, and a few a
/// terminal program needs. Never `HOME`, `PATH`, `USER`, `LOGNAME`, `SHELL`,
/// `XDG_*`, `SUDO_*` or the loader's: those describe the person, are set for
/// the agents' user, or change what a program loads.
fn keep(name: &str) -> bool {
    const NEVER: &[&str] = &[
        "HOME",
        "PATH",
        "USER",
        "LOGNAME",
        "SHELL",
        "MAIL",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
    ];
    let plain = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && !name.as_bytes()[0].is_ascii_digit();
    plain && !NEVER.contains(&name) && !name.starts_with("XDG_") && !name.starts_with("SUDO_")
}

/// The terminal's variables, kept when derm run has them.
const TERMINAL: &[&str] = &[
    "TERM",
    "COLORTERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
];

fn rewrite(
    launch: &mut Plan,
    sudo: &str,
    env_tool: &str,
    entry: &anchor::Entry,
    program: &str,
    set: &[(String, String)],
) {
    for (k, v) in set {
        launch.env_set.retain(|(n, _)| n != k);
        launch.env_set.push((k.clone(), v.clone()));
    }
    let mut names: Vec<String> = launch
        .env_set
        .iter()
        .map(|(k, _)| k.clone())
        .filter(|k| keep(k))
        .collect();
    names.extend(
        TERMINAL
            .iter()
            .filter(|t| std::env::var_os(t).is_some())
            .map(|t| t.to_string()),
    );
    names.sort();
    names.dedup();
    let mut args = vec!["-n".to_string(), "-u".into(), entry.user.clone()];
    if !names.is_empty() {
        args.push(format!("--preserve-env={}", names.join(",")));
    }
    args.push("--".into());
    args.push(env_tool.to_string());
    args.push(format!("PATH={}", entry.path));
    args.push(program.to_string());
    args.append(&mut launch.args);
    launch.program = sudo.to_string();
    launch.args = args;
}

/// One check run as the agents' user, through the route the harness will
/// take. The script is fixed; every path goes in as an argument.
struct Probe<'a> {
    sudo: &'a str,
    sh: &'a str,
    user: &'a str,
    path: &'a str,
    program: &'a str,
    hidden: &'a [String],
    writable: &'a [String],
}

/// Prints `<kind>\t<path>\0` per finding, then `done\t-\0`. `reach`: a path
/// the agent can read (a file) or enter or list (a folder); `nowrite`: a chat
/// folder it cannot write; `prog-missing`: the harness is not on its `PATH`.
const PROBE_SCRIPT: &str = r#"set -u
p=$1; prog=$2; shift 2
out() { printf '%s\t%s\0' "$1" "$2"; }
if PATH=$p command -v "$prog" >/dev/null 2>&1; then :; else out prog-missing "$prog"; fi
mode=hidden
for a in "$@"; do
  if [ "$a" = "--" ]; then mode=write; continue; fi
  if [ "$mode" = hidden ]; then
    if [ -d "$a" ]; then
      if [ -x "$a" ] || [ -r "$a" ]; then out reach "$a"; fi
    elif [ -r "$a" ]; then out reach "$a"; fi
  else
    if [ -d "$a" ] && [ -w "$a" ] && [ -x "$a" ]; then :; else out nowrite "$a"; fi
  fi
done
out done -
"#;

#[derive(Debug, Default, PartialEq)]
struct Found {
    reach: Vec<String>,
    nowrite: Vec<String>,
    prog_missing: bool,
}

impl Probe<'_> {
    fn argv(&self) -> Vec<String> {
        let mut a = vec![
            "-n".to_string(),
            "-u".into(),
            self.user.to_string(),
            "--".into(),
            self.sh.to_string(),
            "-c".into(),
            PROBE_SCRIPT.into(),
            "derm-probe".into(),
            self.path.to_string(),
            self.program.to_string(),
        ];
        a.extend(self.hidden.iter().cloned());
        a.push("--".into());
        a.extend(self.writable.iter().cloned());
        a
    }

    fn run(&self) -> Result<Found, String> {
        let out = Command::new(self.sudo)
            .args(self.argv())
            .current_dir("/")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("{}: {e}", self.sudo))?;
        match parse(&out.stdout) {
            Some(f) if out.status.success() => Ok(f),
            _ => Err(format!(
                "sudo could not start a program as {} without a password ({}); the rule install.sh writes is missing, or another rule overrides it",
                self.user,
                String::from_utf8_lossy(&out.stderr)
                    .trim()
                    .chars()
                    .take(200)
                    .collect::<String>()
            )),
        }
    }
}

/// The probe's output, or `None` when it did not finish.
fn parse(out: &[u8]) -> Option<Found> {
    let mut f = Found::default();
    let mut done = false;
    for rec in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let text = String::from_utf8_lossy(rec);
        let (kind, path) = text.split_once('\t')?;
        match kind {
            "reach" => f.reach.push(path.to_string()),
            "nowrite" => f.nowrite.push(path.to_string()),
            "prog-missing" => f.prog_missing = true,
            "done" => done = true,
            _ => return None,
        }
    }
    done.then_some(f)
}

impl Found {
    fn refusal(&self, user: &str, program: &str) -> Option<String> {
        if !self.reach.is_empty() {
            return Some(format!(
                "{user} can reach {}: it could read the daemon's token or your logins. Make your home 0750 or tighter (chmod o-rx ~), and check the folders above",
                self.reach.join(", ")
            ));
        }
        if !self.nowrite.is_empty() {
            return Some(format!(
                "{user} cannot write {}: give it the chat's folders (a folder outside your home, shared with {user}; packaging/linux/agent-user/README.md)",
                self.nowrite.join(", ")
            ));
        }
        if self.prog_missing {
            return Some(format!(
                "{user} has no {program} on its PATH: install it as {user} and log in there (packaging/linux/agent-user/README.md)"
            ));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(env: &[(&str, &str)]) -> Plan {
        Plan {
            program: "/home/tony/.local/share/fnm/node-versions/v24/bin/pi".into(),
            args: vec!["--model".into(), "local".into()],
            env_set: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            env_remove: Vec::new(),
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

    fn entry() -> anchor::Entry {
        anchor::Entry {
            user: "derm-agent".into(),
            uid: 998,
            owner: "tony".into(),
            owner_uid: 1000,
            path: "/var/lib/derm-agent/.local/bin:/usr/bin:/bin".into(),
            how: "sudo".into(),
        }
    }

    #[test]
    fn the_launch_becomes_sudo_with_the_token_in_the_environment_only() {
        let token = "c".repeat(64);
        let mut p = plan(&[
            ("DERM_CHAT_TOKEN", &token),
            ("DERM_CHAT_TOKEN_FILE", "/run/user/1000/derm/chats/x.token"),
            ("DERM_DAEMON_SOCKET", "/run/user/1000/derm/daemon.sock"),
            ("DERM_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
            ("HOME", "/home/tony"),
        ]);
        let set = vec![
            (
                "DERM_DAEMON_SOCKET".to_string(),
                "/run/derm-agent/1000/c-1/daemon.sock".to_string(),
            ),
            (
                "DERM_CHAT_TOKEN_FILE".to_string(),
                "/run/derm-agent/1000/c-1/chat.token".to_string(),
            ),
        ];
        rewrite(
            &mut p,
            "/usr/bin/sudo",
            "/usr/bin/env",
            &entry(),
            "pi",
            &set,
        );
        assert_eq!(p.program, "/usr/bin/sudo");
        assert_eq!(&p.args[..3], &["-n", "-u", "derm-agent"]);
        let kept = p.args[3].strip_prefix("--preserve-env=").unwrap();
        for name in [
            "DERM_CHAT_TOKEN",
            "DERM_CHAT_TOKEN_FILE",
            "DERM_DAEMON_SOCKET",
            "DERM_OTLP_ENDPOINT",
        ] {
            assert!(kept.split(',').any(|n| n == name), "{name} kept: {kept}");
        }
        assert!(
            !kept.split(',').any(|n| n == "HOME"),
            "the person's HOME is not passed"
        );
        let i = p.args.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &p.args[i + 1..],
            &[
                "/usr/bin/env",
                "PATH=/var/lib/derm-agent/.local/bin:/usr/bin:/bin",
                "pi",
                "--model",
                "local"
            ]
        );
        assert!(
            p.args.iter().all(|a| !a.contains(&token)),
            "no token in argv"
        );
        assert!(
            p.args.iter().all(|a| !a.contains("/run/derm-agent")),
            "no bridge path in argv"
        );
        let get = |k: &str| {
            p.env_set
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            get("DERM_DAEMON_SOCKET"),
            Some("/run/derm-agent/1000/c-1/daemon.sock")
        );
        assert_eq!(
            get("DERM_CHAT_TOKEN_FILE"),
            Some("/run/derm-agent/1000/c-1/chat.token")
        );
    }

    /// The seam between lanes S and V (integration w5, phase 2): the model
    /// tap points the harness at itself with launch variables (lane S's
    /// `derm_tap::launch`), and the agents' user gets only the variables
    /// `--preserve-env` names. Every variable the tap sets, for every agent
    /// it taps, must reach the agents' user, or the chat would run untapped
    /// while its `run.start` says tapped.
    #[test]
    fn the_taps_launch_variables_reach_the_agents_user() {
        let table: Value =
            serde_json::from_str(crate::connect::presets::table_json()).expect("preset table");
        let mut tapped = 0;
        for row in ["harnesses", "planned"]
            .iter()
            .filter_map(|l| table.get(*l).and_then(Value::as_array))
            .flatten()
        {
            let Some(tap) = row.get("tap").filter(|t| !t.is_null()) else {
                continue;
            };
            let Ok(l) = derm_tap::launch::launch(tap, "http://127.0.0.1:4000", &"a".repeat(32))
            else {
                continue;
            };
            tapped += 1;
            let mut p = plan(&[("DERM_CHAT_TOKEN", &"c".repeat(64))]);
            p.env_set.extend(l.env.iter().cloned());
            p.args.extend(l.args.iter().cloned());
            rewrite(&mut p, "/usr/bin/sudo", "/usr/bin/env", &entry(), "x", &[]);
            let kept = p.args[3].strip_prefix("--preserve-env=").unwrap();
            for (name, _) in &l.env {
                assert!(
                    kept.split(',').any(|n| n == name),
                    "{}: {name} not kept: {kept}",
                    row["id"]
                );
            }
            // Argv the tap adds (Codex's provider flags) follows the program.
            let i = p.args.iter().position(|a| a == "--").unwrap();
            for a in &l.args {
                assert!(p.args[i..].contains(a), "{}: {a}", row["id"]);
            }
        }
        assert!(tapped >= 3, "Claude Code, Codex and Gemini CLI are tapped");
    }

    #[test]
    fn variables_that_describe_the_person_or_change_loading_are_not_kept() {
        for ok in [
            "DERM_CHAT_TOKEN",
            "NODE_USE_ENV_PROXY",
            "ANTHROPIC_BASE_URL",
            "GEMINI_CLI_DERM_CHAT_TOKEN_FILE",
        ] {
            assert!(keep(ok), "{ok}");
        }
        for no in [
            "HOME",
            "PATH",
            "USER",
            "XDG_RUNTIME_DIR",
            "SUDO_USER",
            "LD_PRELOAD",
            "lower",
            "1X",
            "A-B",
            "",
        ] {
            assert!(!keep(no), "{no}");
        }
    }

    #[test]
    fn the_probes_output_and_what_it_refuses() {
        let out =
            b"reach\t/run/user/1000/derm\0nowrite\t/home/tony/proj\0prog-missing\tpi\0done\t-\0";
        let f = parse(out).unwrap();
        assert_eq!(f.reach, ["/run/user/1000/derm"]);
        assert_eq!(f.nowrite, ["/home/tony/proj"]);
        assert!(f.prog_missing);
        assert!(f
            .refusal("derm-agent", "pi")
            .unwrap()
            .contains("can reach /run/user/1000/derm"));
        let f = parse(b"nowrite\t/p\0done\t-\0").unwrap();
        assert!(f
            .refusal("derm-agent", "pi")
            .unwrap()
            .contains("cannot write /p"));
        let f = parse(b"prog-missing\tpi\0done\t-\0").unwrap();
        assert!(f
            .refusal("derm-agent", "pi")
            .unwrap()
            .contains("no pi on its PATH"));
        assert_eq!(
            parse(b"done\t-\0").unwrap().refusal("derm-agent", "pi"),
            None
        );
        assert_eq!(
            parse(b"reach\t/x\0"),
            None,
            "a probe that did not finish is not a pass"
        );
        assert_eq!(parse(b"oops\t/x\0done\t-\0"), None);
    }

    #[test]
    fn a_chat_under_a_boundary_is_left_alone() {
        let mut p = plan(&[]);
        let before = format!("{p:?}");
        for b in ["srt", "sbx"] {
            let ctx = Context {
                boundary: b,
                chat: "c",
                cwd: "/tmp",
                folders: &[],
                home: "/home/tony",
                daemon_dir: None,
                daemon_socket: None,
                token: None,
                policy: "/home/tony/.derm/policy.json",
            };
            assert_eq!(wrap_with(&mut p, &ctx), Ok(None));
        }
        assert_eq!(format!("{p:?}"), before);
    }

    #[test]
    fn sh_and_env_are_roots_here_and_env_is_not_set_id() {
        assert!(trusted_tool(SH, false).is_ok());
        assert!(trusted_tool(ENV, false).is_ok());
        assert!(trusted_tool("/nonexistent/sudo", true).is_err());
        assert!(trusted_tool(ENV, true).unwrap_err().contains("set-user-id"));
    }
}
