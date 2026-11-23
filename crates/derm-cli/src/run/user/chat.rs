//! A chat as one of the agent accounts, in its own Landlock domain
//! (accounts build, lane L1; note CB sections 5 and 6).
//!
//! `derm run`, as the person:
//!
//! 1. chooses the account (`accounts::choose`) and checks it: a user here
//!    with the uid and home the file names, its primary group
//!    `derm-agents` (the group the outbound block matches by `skgid`, which
//!    is the socket owner's group), in no group that leads to root or to the
//!    person (`anchor::refusal`);
//! 2. reads the kernel's Landlock ABI; below 6 it says what will not hold
//!    and asks, as case 129 does; with no one at a terminal it stops;
//! 3. checks, as the account, what lane V's probe checks (it cannot reach
//!    the daemon's folder, the token, `~/.derm`, the policy or the person's
//!    logins; it can write the chat's folders; it has the harness);
//! 4. opens the chat's bridge (`bridge.rs`);
//! 5. starts `sudo -n -u <account> -- <derm> landlock -- /usr/bin/env
//!    PATH=<the account's> <harness> <args>`, with the domain's spec, the
//!    chat token and the bridge's paths in the environment only.
//!
//! The helper is derm's own binary from a place only root can change, so no
//! chat can swap the program the next chat's domain comes from.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::super::plan::Plan;
use super::accounts::{self, Account};
use super::{anchor, bridge, landlock, project, Context};

/// Exit code for a start the person or the missing terminal stopped (the
/// same as case 129's).
const STOPPED: u8 = super::super::boundary::STOPPED;

/// Who answers a question at the start.
pub(crate) trait Person {
    fn terminal(&self) -> bool;
    fn ask(&mut self, question: &str) -> Option<String>;
    fn say(&mut self, line: &str);
}

/// The terminal, through the same reads case 129's question uses.
pub(crate) struct RealPerson(super::super::boundary::probe::Real);

impl RealPerson {
    pub(crate) fn new() -> Self {
        RealPerson(super::super::boundary::probe::Real::new())
    }
}

impl Person for RealPerson {
    fn terminal(&self) -> bool {
        use super::super::boundary::Probe;
        self.0.terminal()
    }
    fn ask(&mut self, question: &str) -> Option<String> {
        use super::super::boundary::Probe;
        self.0.ask(question)
    }
    fn say(&mut self, line: &str) {
        use super::super::boundary::Probe;
        self.0.say(line)
    }
}

/// What the domain will require, and who decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub require_landlock: bool,
    pub require_scopes: bool,
    /// `kernel` (ABI 6 or later, nothing to ask) or `person`.
    pub answered_by: &'static str,
}

/// ABI 6 and later: everything holds. Older: say what does not, and ask.
pub(crate) fn decide(abi: i64, person: &mut dyn Person) -> Result<Scope, (u8, String)> {
    if abi >= landlock::SCOPES_ABI {
        return Ok(Scope {
            require_landlock: true,
            require_scopes: true,
            answered_by: "kernel",
        });
    }
    let what = if abi < 1 {
        "this kernel has no Landlock, so chats on one agent account are not kept apart: each can read another's chat token in /proc/<pid>/environ, trace it and signal it".to_string()
    } else {
        format!("this kernel's Landlock (ABI {abi}) keeps chats on one agent account out of each other's /proc/<pid>/environ and ptrace, and not out of each other's signals or abstract Unix sockets (ABI 6, Linux 6.12)")
    };
    person.say(&format!("derm run: {what}."));
    person.say("derm run: Linux 6.12 or later keeps them apart fully; so does running one chat per account at a time.");
    if !person.terminal() {
        return Err((
            STOPPED,
            format!("{what}; no one is at a terminal to say run anyway, so not starting (case 129). Start it from a terminal to answer"),
        ));
    }
    let yes = person
        .ask("Run this chat anyway? [y/N] ")
        .is_some_and(|a| matches!(a.trim().to_ascii_lowercase().as_str(), "y" | "yes"));
    if !yes {
        return Err((STOPPED, "stopped: not run without the scopes".into()));
    }
    Ok(Scope {
        require_landlock: abi >= 1,
        require_scopes: false,
        answered_by: "person",
    })
}

/// The chat as `account` (module text). `found` is the file's accounts.
pub(crate) fn wrap(
    launch: &mut Plan,
    ctx: &Context,
    found: &[Account],
    person: &mut dyn Person,
) -> Result<Option<Value>, (u8, String)> {
    let fail = |why: String| -> Result<Option<Value>, (u8, String)> {
        Err((1, format!("{why}; not starting the harness")))
    };
    let settings = Path::new(ctx.home).join(".derm").join("settings.json");
    let (default, warn) = accounts::default_from(&settings);
    if let Some(w) = warn {
        eprintln!("derm run: {w}");
    }
    let flag = ctx.account.map(str::to_string);
    let acct = match accounts::choose(found, flag.as_deref(), default.as_deref()) {
        Ok(Some(a)) => a.clone(),
        Ok(None) => return Ok(None),
        Err(e) => return fail(e),
    };
    if let Some(why) = check_account(&acct) {
        return fail(why);
    }
    // Step P1 (lane PA): the chat's project, before anything starts. A chat
    // on an agent account outside every named folder is refused (P-C2).
    let registry = crate::project::load(&crate::project::path_in(Path::new(ctx.home)))
        .map_err(|why| (1, format!("{why}; a chat on an agent account needs its project, so not starting the harness")))?;
    let found = crate::project::find(&registry, Path::new(ctx.cwd));
    let Some(project) = found.project().cloned() else {
        return Err((
            1,
            format!(
                "{} is in no project; name one with: derm project add {}",
                ctx.cwd, ctx.cwd
            ),
        ));
    };
    let harness = launch
        .env_set
        .iter()
        .find(|(k, _)| k == "DERM_HARNESS")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "other".to_string());
    let scope = decide(landlock::abi(), person)?;
    let sudo = super::trusted_tool(super::SUDO, true).map_err(|e| (1, e))?;
    let env_tool = super::trusted_tool(super::ENV, false).map_err(|e| (1, e))?;
    let sh = super::trusted_tool(super::SH, false).map_err(|e| (1, e))?;
    let helper = helper_binary().map_err(|e| (1, e))?;
    let program = Path::new(&launch.program)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && !n.starts_with('-'))
        .ok_or_else(|| (1, format!("{} is not a program name", launch.program)))?
        .to_string();
    // Step P2: the harness is a root-owned install outside every home, found
    // on the chat's own PATH; the checked path is the one that runs.
    let path = project::PATH.to_string();
    let (program_path, program_real) = root_install(&program, &path).map_err(|e| (1, e))?;
    // Request PB-4 (contracts/projects.md 2.3): Pi below 1.5.1 locks the
    // link's path, not the store's file, so two projects can lose a sign-in
    // write (note CD C1; Pi 1.5.1 `CHANGELOG.md:96`). The version is read
    // from the install's own package.json, nothing is run.
    if harness == "pi" {
        pi_floor(Path::new(&program_real)).map_err(|e| (1, e))?;
    }

    // As the account, before any domain: what it must not reach, what it
    // must write (lane V's probe, unchanged).
    let home = ctx.home.trim_end_matches('/');
    let mut hidden: Vec<String> = Vec::new();
    if let Some(d) = ctx.daemon_dir {
        hidden.push(d.to_string());
        hidden.push(format!("{d}/daemon.token"));
    }
    hidden.push(format!("{home}/.derm"));
    hidden.push(ctx.policy.to_string());
    for h in super::super::harness::HARNESSES {
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
    let probe = super::Probe {
        sudo: &sudo,
        sh: &sh,
        user: &acct.name,
        path: &path,
        program: &program,
        hidden: &hidden,
        writable: &writable,
    };
    let found_probe = probe.run().map_err(|e| (1, e))?;
    if let Some(why) = found_probe.refusal(&acct.name, &program) {
        return fail(why);
    }

    let me = super::euid();
    let mut set: Vec<(String, String)> = Vec::new();
    let mut bridge_dir: Option<String> = None;
    if let (Some(sock), Some(token)) = (ctx.daemon_socket, ctx.token) {
        let base = PathBuf::from(bridge::BASE_ROOT).join(me.to_string());
        let b = bridge::open(&bridge::Spec {
            base: &base,
            base_parent_owner: 0,
            chat: ctx.chat,
            agent_uid: acct.uid,
            daemon_socket: Path::new(sock),
            token,
            policy: Some(Path::new(ctx.policy)),
        })
        .map_err(|e| (1, format!("the chat's bridge: {e}")))?;
        set = super::bridge_env(&b, &launch.env_set);
        bridge_dir = Some(b.dir().to_string_lossy().into_owned());
        if let Ok(mut slot) = super::BRIDGE.lock() {
            *slot = Some(b);
        }
        // SAFETY: as in lane V's path: a plain function, once, at exit.
        unsafe {
            libc::atexit(super::finish_at_exit);
        }
    }
    let pc = project::ProjectChat {
        account_home: &acct.home,
        project: &project.id,
        folders: &writable,
        harness: &harness,
        bridge: bridge_dir.as_deref(),
        require_scopes: scope.require_scopes,
    };
    let daemon = gateway_daemon(&helper);
    let entry = daemon
        .as_deref()
        .and_then(|d| project::gateway_entry(&harness, d));
    let entry_rel = entry.as_ref().map(|e| e.rel.clone());
    let mut spec = project::project_chat_spec(&pc);
    spec.require_landlock = scope.require_landlock;
    spec.setup = Some(project::project_setup(&pc, entry));
    spec.reprobe_secs = landlock::reprobe::INTERVAL_SECS;
    let pts = spec.write.iter().any(|w| w == landlock::PTS);
    set.push((
        landlock::SPEC_VAR.to_string(),
        serde_json::to_string(&spec).map_err(|e| (1, e.to_string()))?,
    ));
    // Request PA-2: derm's gate on the harness's own command line, since
    // the project home is the chat's to write (`project::harness_gate`).
    let pi_pkg = if harness == "pi" {
        match project::pi_package(project::PI_PACKAGE) {
            Ok(p) => Some(p),
            Err(why) => {
                if std::fs::symlink_metadata(project::PI_PACKAGE).is_ok() {
                    eprintln!("derm run: derm's Pi package is not used: {why}");
                }
                None
            }
        }
    } else {
        None
    };
    let gate = project::harness_gate(&harness, &helper, pi_pkg.as_deref());
    place_gate_args(&mut launch.args, ctx.harness_args_at, &harness, &gate.args);
    let mut assign = project::project_env(&pc);
    assign.extend(gate.env.iter().cloned());
    if !gate.line.is_empty() {
        eprintln!("{}", gate.line);
    }
    rewrite(
        launch,
        &Route {
            sudo: &sudo,
            env_tool: &env_tool,
            helper: &helper,
            user: &acct.name,
            assign: &assign,
            program: &program_path,
        },
        &set,
    );
    eprintln!(
        "derm run: {program} starts as {} ({}) in project {} ({}), in its own Landlock domain{}: other chats on the account cannot read its token, trace it{}; it writes its project's own home, temp and runtime folders, not the account home or another project's",
        acct.name,
        acct.subscription,
        project.id,
        project.folder.display(),
        if scope.require_scopes { "" } else { " without scopes" },
        if scope.require_scopes {
            ", signal it or reach its abstract sockets"
        } else {
            ""
        }
    );
    eprintln!(
        "{}",
        if pts {
            format!("derm run: {harness} opens terminals for its commands, so this chat keeps /dev/pts: from it, a chat could open another chat's terminal on this account (P5's stopgap holds only while no chat of the account keeps it)")
        } else {
            "derm run: /dev/pts is out of this chat's domain: it cannot open another chat's terminal, and its own tools cannot make a new one (Claude Code's background sessions need one)".to_string()
        }
    );
    eprintln!(
        "derm run: the account's firewall table is checked again every {}s while the chat runs, from outside its domain; the chat is stopped if it no longer holds{}",
        landlock::reprobe::INTERVAL_SECS,
        if scope.require_scopes {
            ""
        } else {
            " (without scopes the chat can signal that check and stop it)"
        }
    );
    if entry_rel.is_none() {
        eprintln!(
            "derm run: derm's project tools (derm_project) are not set up for {harness} here: {}",
            if daemon.is_none() {
                "no root-owned derm-daemon beside derm"
            } else {
                "derm writes no entry for this harness"
            }
        );
    }
    Ok(Some(json!({
        "user": acct.name,
        "uid": acct.uid,
        "how": anchor::HOW_SUDO,
        "account": acct.slug(),
        "landlock": {
            "abi": landlock::abi(),
            "scoped": scope.require_scopes,
            "answeredBy": scope.answered_by,
            "pts": pts,
            "reprobeSeconds": landlock::reprobe::INTERVAL_SECS,
        },
        "project": {
            "id": project.id.as_str(),
            "folder": project.folder.to_string_lossy(),
            "found": found.how(),
            "home": layout_home(&acct.home, &project.id),
            "gatewayEntry": entry_rel,
        },
        "harnessExe": program_real,
        "gate": {"expected": gate.expected, "how": gate.how},
    })))
}

/// The Pi an agent account runs, by the `package.json` of the install its
/// program sits in (`dist/cli.js` two folders down), at least 1.5.1.
pub(crate) fn pi_floor(program_real: &Path) -> Result<String, String> {
    const NAME: &str = "@earendil-works/pi-coding-agent";
    let fix =
        "install Pi 1.6.0 as root (sudo npm install -g @earendil-works/pi-coding-agent@1.6.0)";
    for dir in program_real.ancestors().skip(1).take(4) {
        let Ok(text) = std::fs::read_to_string(dir.join("package.json")) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v.get("name").and_then(Value::as_str) != Some(NAME) {
            continue;
        }
        let version = v.get("version").and_then(Value::as_str).unwrap_or("");
        let parts: Vec<u64> = version
            .split(['-', '+'])
            .next()
            .unwrap_or("")
            .split('.')
            .map(|p| p.parse().unwrap_or(0))
            .collect();
        let at_least = parts.len() == 3 && (parts[0], parts[1], parts[2]) >= (1, 5, 1);
        return if at_least {
            Ok(version.to_string())
        } else {
            Err(format!(
                "Pi {version} on an agent account: below 1.5.1 Pi locks the sign-in link, not the file, so two projects can lose a sign-in write; {fix}"
            ))
        };
    }
    Err(format!(
        "{} is not in a Pi install derm can read the version of; {fix}",
        program_real.display()
    ))
}

/// Puts derm's gate words before the harness's own (request PA-2): for
/// Codex past a session subcommand, beside the tap's and the export's `-c`
/// pairs, so every `-c` derm adds is on one side of it (case 184).
pub(crate) fn place_gate_args(
    args: &mut Vec<String>,
    words_at: Option<usize>,
    harness: &str,
    gate: &[String],
) {
    if gate.is_empty() {
        return;
    }
    let mut at = words_at.unwrap_or(0).min(args.len());
    if harness == "codex"
        && args
            .get(at)
            .is_some_and(|w| super::super::tap::CODEX_SESSION_SUBCOMMANDS.contains(&w.as_str()))
    {
        at += 1;
    }
    args.splice(at..at, gate.iter().cloned());
}

fn layout_home(account_home: &str, id: &crate::project::ProjectId) -> String {
    format!(
        "{}/{}",
        derm_core::project::layout::project_dir(account_home, id),
        derm_core::project::layout::HOME
    )
}

/// `program` on `path` (the project chat's `PATH`): the first folder that
/// holds it, as that path and as its real path, when root owns it and every
/// folder above it and no one else can write them (`trusted_tool`). The
/// harness then runs from a place no chat can change (AI-1).
pub(crate) fn root_install(program: &str, path: &str) -> Result<(String, String), String> {
    for dir in path.split(':').filter(|d| d.starts_with('/')) {
        let cand = format!("{}/{program}", dir.trim_end_matches('/'));
        if std::fs::symlink_metadata(&cand).is_err() {
            continue;
        }
        return match super::trusted_tool(&cand, false) {
            Ok(real) => Ok((cand, real)),
            Err(why) => Err(format!(
                "{why}: a chat on an agent account runs its harness only from a root-owned install; reinstall it as root"
            )),
        };
    }
    Err(format!(
        "{program} is not installed where every agent account runs it ({path}): install it as root, outside any home (for an npm harness: sudo npm install -g <package>), and start the chat again"
    ))
}

/// `derm-daemon` beside the helper, when it is a root-owned copy.
fn gateway_daemon(helper: &str) -> Option<String> {
    let dir = Path::new(helper).parent()?;
    super::trusted_tool(&dir.join("derm-daemon").to_string_lossy(), false).ok()
}

/// Why the account cannot run a chat, or `None`.
fn check_account(acct: &Account) -> Option<String> {
    let Some(agent) = anchor::account(&acct.name) else {
        return Some(format!(
            "{} names {}, which is not a user here; re-run the installer, or derm agents add {}",
            accounts::AGENTS,
            acct.name,
            acct.slug()
        ));
    };
    if agent.uid != acct.uid {
        return Some(format!(
            "{} has uid {}, not {} as {} says",
            acct.name,
            agent.uid,
            acct.uid,
            accounts::AGENTS
        ));
    }
    if agent.home.trim_end_matches('/') != acct.home.trim_end_matches('/') {
        return Some(format!(
            "{}'s home is {}, not {} as {} says",
            acct.name,
            agent.home,
            acct.home,
            accounts::AGENTS
        ));
    }
    let primary = anchor::group_name(agent.gid);
    if primary != accounts::GROUP {
        return Some(format!(
            "{}'s primary group is {primary}, not {}: the outbound block matches the socket owner's group (skgid), so it would not apply",
            acct.name,
            accounts::GROUP
        ));
    }
    let Some(owner) = anchor::account_by_uid(super::euid()) else {
        return Some("your own account could not be read".into());
    };
    let Some(groups) = anchor::groups(&agent) else {
        return Some(format!("the groups of {} could not be read", agent.name));
    };
    anchor::refusal(&agent, &groups, &owner)
}

/// The programs and paths of the route.
pub(super) struct Route<'a> {
    pub sudo: &'a str,
    pub env_tool: &'a str,
    pub helper: &'a str,
    pub user: &'a str,
    /// `PATH`, `HOME`, `TMPDIR`, `XDG_RUNTIME_DIR` and the harness's own:
    /// paths only, set by `env` after the helper.
    pub assign: &'a [(String, String)],
    pub program: &'a str,
}

/// `sudo -n -u <user> --preserve-env=<names> -- <helper> landlock --
/// <env> HOME=<...> TMPDIR=<...> XDG_RUNTIME_DIR=<...> PATH=<...> <program>
/// <args>`. Secrets go in the environment, names only on argv; the
/// assignments are paths.
pub(super) fn rewrite(launch: &mut Plan, r: &Route, set: &[(String, String)]) {
    let fixes = super::locale_fixes(&|k| std::env::var(k).ok());
    for (k, v) in set.iter().chain(fixes.iter()) {
        launch.env_set.retain(|(n, _)| n != k);
        launch.env_set.push((k.clone(), v.clone()));
    }
    let mut names: Vec<String> = launch
        .env_set
        .iter()
        .map(|(k, _)| k.clone())
        .filter(|k| super::keep(k))
        .collect();
    names.extend(
        super::TERMINAL
            .iter()
            .filter(|t| std::env::var_os(t).is_some())
            .map(|t| t.to_string()),
    );
    names.sort();
    names.dedup();
    let mut args = vec!["-n".to_string(), "-u".into(), r.user.to_string()];
    if !names.is_empty() {
        args.push(format!("--preserve-env={}", names.join(",")));
    }
    args.extend([
        "--".to_string(),
        r.helper.to_string(),
        landlock::SUBCOMMAND.to_string(),
        "--".to_string(),
        r.env_tool.to_string(),
    ]);
    args.extend(r.assign.iter().map(|(k, v)| format!("{k}={v}")));
    args.push(r.program.to_string());
    args.append(&mut launch.args);
    launch.program = r.sudo.to_string();
    launch.args = args;
}

/// Where root installs derm by hand or by package.
const ROOT_COPIES: &[&str] = &["/usr/local/bin/derm", "/usr/bin/derm"];

/// derm's own binary, from a place only root can change and every user can
/// run: this one, or a root copy with the same bytes (the helper's spec
/// format is this build's).
pub(crate) fn helper_binary() -> Result<String, String> {
    let me = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("derm's own path: {e}"))?;
    let me_s = me.to_string_lossy().into_owned();
    if let Ok(p) = super::trusted_tool(&me_s, false) {
        if everyone_can_run(Path::new(&p)) {
            return Ok(p);
        }
    }
    for c in ROOT_COPIES {
        if let Ok(p) = super::trusted_tool(c, false) {
            if everyone_can_run(Path::new(&p)) && same_bytes(Path::new(&p), &me) {
                return Ok(p);
            }
        }
    }
    Err(format!(
        "a chat on an agent account starts through derm itself, as that account, from a copy only root can change and the same build as this one; none was found. Install it: sudo install -m 0755 {me_s} /usr/local/bin/derm"
    ))
}

fn everyone_can_run(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o005 == 0o005)
        && p.ancestors()
            .skip(1)
            .all(|d| std::fs::metadata(d).is_ok_and(|m| m.permissions().mode() & 0o001 != 0))
}

fn same_bytes(a: &Path, b: &Path) -> bool {
    let (Ok(fa), Ok(fb)) = (std::fs::File::open(a), std::fs::File::open(b)) else {
        return false;
    };
    let (Ok(ma), Ok(mb)) = (fa.metadata(), fb.metadata()) else {
        return false;
    };
    if ma.len() != mb.len() {
        return false;
    }
    let (mut ra, mut rb) = (std::io::BufReader::new(fa), std::io::BufReader::new(fb));
    let (mut ba, mut bb) = ([0u8; 64 * 1024], [0u8; 64 * 1024]);
    loop {
        let (Ok(na), Ok(nb)) = (ra.read(&mut ba), rb.read(&mut bb)) else {
            return false;
        };
        if na != nb || ba[..na] != bb[..nb] {
            // Short reads of equal files could differ in size; read again
            // into one buffer at a time would cover it, but both are local
            // regular files read with the same buffer size.
            return false;
        }
        if na == 0 {
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        terminal: bool,
        answer: Option<&'static str>,
        said: Vec<String>,
        asked: Vec<String>,
    }
    impl Person for Fake {
        fn terminal(&self) -> bool {
            self.terminal
        }
        fn ask(&mut self, q: &str) -> Option<String> {
            self.asked.push(q.into());
            self.answer.map(str::to_string)
        }
        fn say(&mut self, l: &str) {
            self.said.push(l.into());
        }
    }
    fn fake(terminal: bool, answer: Option<&'static str>) -> Fake {
        Fake {
            terminal,
            answer,
            said: Vec::new(),
            asked: Vec::new(),
        }
    }

    #[test]
    fn pb_4_pi_below_1_5_1_is_refused_on_an_agent_account() {
        let t = std::env::temp_dir().join(format!("pb4-{}", std::process::id()));
        let cli = t.join("dist/cli.js");
        std::fs::create_dir_all(cli.parent().unwrap()).unwrap();
        std::fs::write(&cli, "").unwrap();
        let pkg = |v: &str| {
            std::fs::write(
                t.join("package.json"),
                format!(r#"{{"name":"@earendil-works/pi-coding-agent","version":"{v}"}}"#),
            )
            .unwrap()
        };
        for (v, ok) in [
            ("1.4.0", false),
            ("1.5.0", false),
            ("1.5.1", true),
            ("1.6.0", true),
            ("2.0.0-rc.1", true),
        ] {
            pkg(v);
            assert_eq!(pi_floor(&cli).is_ok(), ok, "{v}: {:?}", pi_floor(&cli));
        }
        std::fs::write(
            t.join("package.json"),
            r#"{"name":"other","version":"9.9.9"}"#,
        )
        .unwrap();
        assert!(pi_floor(&cli).is_err(), "not Pi's package");
        let _ = std::fs::remove_dir_all(&t);
    }

    #[test]
    fn pa_2_derms_gate_words_go_before_the_harnesss_own_past_codexs_subcommand() {
        let g = vec!["-c".to_string(), "hooks={}".to_string()];
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // `codex exec <prompt>` with the export's pairs after `exec`.
        let mut a = s(&["exec", "-c", "otel=1", "do it"]);
        place_gate_args(&mut a, Some(0), "codex", &g);
        assert_eq!(a, s(&["exec", "-c", "hooks={}", "-c", "otel=1", "do it"]));
        // The TUI: first.
        let mut a = s(&["fix it"]);
        place_gate_args(&mut a, Some(0), "codex", &g);
        assert_eq!(a, s(&["-c", "hooks={}", "fix it"]));
        // Pi: before its words, no subcommand rule.
        let mut a = s(&["--model", "x"]);
        place_gate_args(&mut a, Some(0), "pi", &["-e".to_string(), "/p".to_string()]);
        assert_eq!(a, s(&["-e", "/p", "--model", "x"]));
        // Nothing to add, nothing moves.
        let mut a = s(&["exec"]);
        place_gate_args(&mut a, Some(0), "codex", &[]);
        assert_eq!(a, s(&["exec"]));
    }

    #[test]
    fn abi_6_and_later_asks_nothing() {
        for abi in [6, 7, 9] {
            let mut p = fake(false, None);
            assert_eq!(
                decide(abi, &mut p),
                Ok(Scope {
                    require_landlock: true,
                    require_scopes: true,
                    answered_by: "kernel"
                })
            );
            assert!(p.said.is_empty() && p.asked.is_empty());
        }
    }

    #[test]
    fn an_older_abi_says_what_does_not_hold_and_asks_as_case_129_does() {
        // Ubuntu 24.04's 6.8 kernel: ABI 4.
        let mut p = fake(true, Some("y"));
        let s = decide(4, &mut p).unwrap();
        assert_eq!(
            s,
            Scope {
                require_landlock: true,
                require_scopes: false,
                answered_by: "person"
            }
        );
        assert!(
            p.said[0].contains("ABI 4") && p.said[0].contains("signals"),
            "{:?}",
            p.said
        );
        assert_eq!(p.asked.len(), 1);
        for no in [Some(""), Some("n"), Some("no"), None] {
            let mut p = fake(true, no);
            assert_eq!(decide(4, &mut p).unwrap_err().0, STOPPED);
        }
        // No one at a terminal: stop, never a default yes.
        let mut p = fake(false, Some("y"));
        let (code, why) = decide(4, &mut p).unwrap_err();
        assert_eq!(code, STOPPED);
        assert!(
            why.contains("no one is at a terminal") && why.contains("case 129"),
            "{why}"
        );
        assert!(p.asked.is_empty());
        // No Landlock at all.
        let mut p = fake(true, Some("yes"));
        let s = decide(0, &mut p).unwrap();
        assert!(!s.require_landlock && !s.require_scopes);
        assert!(p.said[0].contains("no Landlock"), "{:?}", p.said);
    }

    fn plan() -> Plan {
        Plan {
            program: "/home/tony/.local/bin/claude".into(),
            args: vec!["-p".into(), "hi".into()],
            env_set: Vec::new(),
            env_remove: Vec::new(),
            kit: None,
            sandbox_name: None,
            srt_settings: None,
            folders: Vec::new(),
            state_dirs: Vec::new(),
            notes: Vec::new(),
            full_access: Vec::new(),
            asks_allow: false,
            companion: None,
            scratch_dir: None,
        }
    }

    #[test]
    fn the_launch_runs_the_helper_as_the_account_with_nothing_secret_on_argv() {
        let token = "c".repeat(64);
        let mut p = plan();
        p.env_set.push(("DERM_CHAT_TOKEN".into(), token.clone()));
        let spec = r#"{"version":1,"read":["/run/derm-agent/1000/c-1-x"]}"#;
        let set = vec![
            (
                "DERM_CHAT_TOKEN_FILE".to_string(),
                "/run/derm-agent/1000/c-1-x/chat.token".to_string(),
            ),
            (landlock::SPEC_VAR.to_string(), spec.to_string()),
        ];
        let assign = vec![
            (
                "HOME".to_string(),
                "/var/lib/derm/agents/max/projects/6853732bf2a99f2b/home".to_string(),
            ),
            (
                "PATH".to_string(),
                "/usr/local/bin:/usr/bin:/bin".to_string(),
            ),
        ];
        rewrite(
            &mut p,
            &Route {
                sudo: "/usr/bin/sudo",
                env_tool: "/usr/bin/env",
                helper: "/usr/local/bin/derm",
                user: "derm-max",
                assign: &assign,
                program: "/usr/local/bin/claude",
            },
            &set,
        );
        assert_eq!(p.program, "/usr/bin/sudo");
        assert_eq!(&p.args[..3], &["-n", "-u", "derm-max"]);
        let kept = p.args[3].strip_prefix("--preserve-env=").unwrap();
        for n in [
            "DERM_CHAT_TOKEN",
            "DERM_CHAT_TOKEN_FILE",
            landlock::SPEC_VAR,
        ] {
            assert!(kept.split(',').any(|k| k == n), "{n}: {kept}");
        }
        let i = p.args.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &p.args[i + 1..],
            &[
                "/usr/local/bin/derm",
                "landlock",
                "--",
                "/usr/bin/env",
                "HOME=/var/lib/derm/agents/max/projects/6853732bf2a99f2b/home",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "/usr/local/bin/claude",
                "-p",
                "hi"
            ]
        );
        for a in &p.args {
            assert!(!a.contains(&token), "token on argv: {a}");
            assert!(!a.contains("/run/derm-agent"), "a bridge path on argv: {a}");
            assert!(!a.contains("\"version\""), "the spec on argv: {a}");
        }
        let get = |k: &str| {
            p.env_set
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get(landlock::SPEC_VAR).as_deref(), Some(spec));
    }

    #[test]
    fn the_harness_runs_only_from_a_root_owned_install_on_the_chats_path() {
        // `/bin/sh` is root's on every runner; a folder of this test's own
        // is not trusted unless the test runs as root.
        let (cand, real) = root_install("sh", "/nonexistent-dpa:/bin:/usr/bin").unwrap();
        assert_eq!(cand, "/bin/sh");
        assert!(real.starts_with('/'));
        let e = root_install("no-such-harness-dpa", project::PATH).unwrap_err();
        assert!(
            e.contains("sudo npm install -g") && e.contains(project::PATH),
            "{e}"
        );
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            let d = std::env::temp_dir().join(format!("dpa-bin-{}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("h"), "#!/bin/sh\n").unwrap();
            let e = root_install("h", &d.to_string_lossy()).unwrap_err();
            assert!(e.contains("root-owned"), "{e}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn an_account_that_is_not_a_user_here_is_refused_by_name() {
        let a = Account {
            name: "derm-nosuchacct".into(),
            uid: 4_000_001,
            subscription: "x".into(),
            home: "/var/lib/derm/agents/nosuchacct".into(),
        };
        let why = check_account(&a).unwrap();
        assert!(
            why.contains("not a user here") && why.contains("derm agents add nosuchacct"),
            "{why}"
        );
    }

    #[test]
    fn a_helper_needs_a_root_copy_of_this_build() {
        // The test binary sits in a build folder: either root's (this
        // workspace) or the CI user's. Either way the answer names the fix
        // or is a path only root can change.
        match helper_binary() {
            Ok(p) => assert!(super::super::trusted_tool(&p, false).is_ok(), "{p}"),
            Err(e) => assert!(e.contains("sudo install -m 0755"), "{e}"),
        }
        let me = std::env::current_exe().unwrap();
        assert!(same_bytes(&me, &me));
        assert!(!same_bytes(&me, Path::new("/bin/sh")));
    }
}
