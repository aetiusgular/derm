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
    // BT-15: an npm harness's whole package, not only its entry script.
    if let Some(pkg) = npm_package(Path::new(&program_real)) {
        closed_package(&pkg, 0).map_err(|e| (1, e))?;
    }
    // Request PB-4 (contracts/projects.md 2.3): Pi below 1.5.1 locks the
    // link's path, not the store's file, so two projects can lose a sign-in
    // write (note CD C1; Pi 1.5.1 `CHANGELOG.md:96`). The version is read
    // from the install's own package.json, nothing is run.
    if harness == "pi" {
        pi_floor(Path::new(&program_real)).map_err(|e| (1, e))?;
    }
    // Tony's call 4a: the store variable is verified at one release; another
    // is named, and the chat still starts.
    let claude_version = (harness == "claude-code")
        .then(|| crate::agents::signin::claude_version_of(Path::new(&program_real)));
    if let Some(found) = &claude_version {
        if let Some(note) = crate::agents::signin::claude_store_note(found.as_deref()) {
            eprintln!("derm run: {note}");
        }
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
    // Case 283: the chat's own way to its harness's sign-in host, for a
    // renewal; a brokered chat's derm-egress passes the same hosts through.
    let person_env = |k: &str| std::env::var(k).ok();
    // Tony's call 3b: each connection recorded, as source `run`.
    let recorder = ctx
        .sign_in_sink
        .clone()
        .map(|sink| crate::agents::tunnel::Recorder {
            sink,
            chat: ctx.chat.to_string(),
            harness: harness.clone(),
        });
    let route =
        sign_in_route(&harness, &launch.env_set, &person_env, recorder).map_err(|e| (1, e))?;
    let route_hosts = route.as_ref().map(|r| r.hosts.clone());
    if let Some(r) = &route {
        set.extend(r.env.iter().cloned());
        eprintln!(
            "derm run: {harness} renews its own sign-in through this chat's tunnel at {}, which admits only {} on 443, unread, and takes only this chat's proxy credential",
            r.tunnel.shown_url(),
            r.hosts
                .iter()
                .map(|h| h.trim_end_matches(":443"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Ok(mut slot) = SIGN_IN_ROUTE.lock() {
        *slot = route.map(|r| r.tunnel);
    }
    if let Some(line) = store_line(&harness, &acct.home) {
        eprintln!("{line}");
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
    let ungated_by_flag = if harness == "pi" {
        !pi_gate_decision(pi_pkg.as_deref(), ctx.ungated).map_err(|e| (1, e))?
    } else {
        false
    };
    let gate = project::harness_gate(&harness, &helper, pi_pkg.as_deref());
    place_gate_args(&mut launch.args, ctx.harness_args_at, &harness, &gate.args);
    let mut assign = project::project_env(&pc);
    assign.extend(gate.env.iter().cloned());
    if !gate.line.is_empty() {
        eprintln!("{}", gate.line);
    }
    // Review R1 and R2 (case RV-1): Claude Code reads the project home's
    // settings, whose `env` would outrank argv; every variable derm sets
    // that is not a secret goes into derm's flag block too.
    if harness == "claude-code" {
        let mut env_now: Vec<(String, String)> = launch.env_set.clone();
        env_now.extend(set.iter().cloned());
        let store = vec![(
            crate::agents::signin::CLAUDE_STORE_VAR.to_string(),
            crate::agents::signin::store_dir(&acct.home, "claude-code"),
        )];
        crate::run::claude_gate::pin_account_env(
            &mut launch.args,
            &env_now,
            &assign,
            &store,
            ctx.token,
        )
        .map_err(|e| (1, e))?;
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
    eprintln!("{PATHNAME_SOCKETS_LINE}");
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
        // Tony's call 4a: the Claude Code release found, against the one the
        // store variable was verified at.
        "storeVariable": claude_version.as_ref().map(|found| json!({
            "verifiedAt": crate::agents::signin::CLAUDE_STORE_VERIFIED_AT,
            "found": found,
        })),
        "gate": {"expected": gate.expected, "how": gate.how},
        // Tony's call 1a, not built: the store is not hidden from the
        // chat's commands (note CE section 2; lane PG).
        "signInStore": store_line(&harness, &acct.home).map(|_| json!({
            "hiddenFromTools": false,
            "detectedBy": "signin.read",
        })),
        // Tony's call 6a: started with `--ungated`, with no derm gate.
        "ungatedByFlag": ungated_by_flag,
        // Case 283: the chat's own sign-in tunnel's hosts, or null (a
        // brokered chat's derm-egress, or a harness with none).
        "signInTunnel": route_hosts,
        // Request PC R2: the daemon reads the chat's own bridge from here.
        "bridge": bridge_dir,
    })))
}

/// Tony's call 1a, not built (note CE section 2): what the start says of the
/// sign-in store's reach. Neither Claude Code's sandbox nor Codex's runs
/// inside the chat's Landlock domain (a domain may not mount, and both start
/// bubblewrap; Codex's Landlock-only mode refuses read restrictions), so the
/// store stays readable to every command the chat runs until lane PG's mount
/// layer; Pi has no sandbox of its own. `signin.read` flags a read by
/// anything but the harness (lane PC). `None` for a harness with no store.
pub(crate) fn store_line(harness: &str, account_home: &str) -> Option<String> {
    if !derm_core::project::layout::SIGNIN_HARNESSES.contains(&harness) {
        return None;
    }
    let dir = crate::agents::signin::store_dir(account_home, harness);
    let why = if harness == "pi" {
        "Pi has no sandbox of its own"
    } else {
        "its own sandbox cannot run inside this chat's Landlock domain, so derm's mount layer (lane PG) is what will hide it"
    };
    Some(format!(
        "derm run: {harness}'s sign-in store {dir} is readable by every command this chat runs ({why}); a read by anything but {harness} is flagged (signin.read)"
    ))
}

/// The flag a Pi account chat with no root-owned gate package needs to run
/// ungated (Tony's call 6a).
pub(crate) const UNGATED_FLAG: &str = "--ungated";

/// Tony's call 6a (review PI-S5): a Pi chat on an agent account with no
/// root-owned copy of derm's Pi package runs with no derm gate, so it is
/// refused by default, naming the install line; `--ungated` runs it as
/// before, and `run.start` says so. `Ok(true)`: gated; `Ok(false)`: ungated
/// by the flag.
pub(crate) fn pi_gate_decision(package: Option<&str>, ungated: bool) -> Result<bool, String> {
    match (package, ungated) {
        (Some(_), _) => Ok(true),
        (None, true) => Ok(false),
        (None, false) => Err(format!(
            "a Pi chat on an agent account runs only with derm's gate, from a root-owned copy of derm's Pi package at {pkg}, and there is none; install it (sudo install -d -o root -g root -m 0755 {pkg} && sudo cp -r <derm>/packages/derm-pi/. {pkg}/), or start the chat with {UNGATED_FLAG} to run it with no derm gate, which run.start records",
            pkg = super::project::PI_PACKAGE
        )),
    }
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

/// Case 283: a renewal inside an agent account's chat. The account reaches
/// loopback only (lane L2's table), so a harness renewing its sign-in in a
/// chat had no way to its sign-in host. A chat with no other proxy gets its
/// own sign-in tunnel (`agents::tunnel`, the login's), which admits only the
/// harness's sign-in hosts on 443 (`run/harness.rs` `sign_in_hosts`:
/// `platform.claude.com` for Claude Code, `auth.openai.com` for Codex),
/// passes TLS through unread, and takes only this chat's own proxy
/// credential, minted per chat and handed over in the environment only. A
/// brokered chat already has derm-egress as its proxy, which passes the same
/// hosts through unread (`broker::account_egress`), so it gets none.
pub(crate) struct SignInRoute {
    pub tunnel: crate::agents::tunnel::Tunnel,
    /// The proxy variables, the URL with its credential: a secret.
    pub env: Vec<(String, String)>,
    pub hosts: Vec<String>,
}

pub(crate) fn sign_in_route(
    harness: &str,
    env_set: &[(String, String)],
    person_env: &dyn Fn(&str) -> Option<String>,
    record: Option<crate::agents::tunnel::Recorder>,
) -> Result<Option<SignInRoute>, String> {
    let hosts = super::super::harness::sign_in_hosts(harness);
    let proxied = env_set
        .iter()
        .any(|(k, v)| matches!(k.as_str(), "HTTPS_PROXY" | "https_proxy") && !v.is_empty());
    if hosts.is_empty() || proxied {
        return Ok(None);
    }
    let names: Vec<&str> = hosts
        .iter()
        .filter_map(|h| h.strip_suffix(":443"))
        .collect();
    // The person's own http:// proxy, as the login's tunnel follows it.
    let upstream = crate::agents::tunnel::upstream_from(person_env).unwrap_or(None);
    let tunnel = crate::agents::tunnel::Tunnel::start_with(&names, upstream, record)
        .map_err(|e| format!("the chat's sign-in tunnel did not open: {e}"))?;
    let url = tunnel.url();
    let loopback = "localhost,127.0.0.1,::1".to_string();
    Ok(Some(SignInRoute {
        tunnel,
        env: vec![
            ("HTTPS_PROXY".into(), url.clone()),
            ("https_proxy".into(), url),
            ("NO_PROXY".into(), loopback.clone()),
            ("no_proxy".into(), loopback),
        ],
        hosts: names.iter().map(|h| format!("{h}:443")).collect(),
    }))
}

/// The chat's sign-in tunnel, kept for the life of `derm run` (its threads
/// serve until the process ends).
static SIGN_IN_ROUTE: std::sync::Mutex<Option<crate::agents::tunnel::Tunnel>> =
    std::sync::Mutex::new(None);

/// At the chat's end, what its sign-in tunnel refused or could not reach,
/// once each, and how many connections it turned away for want of room
/// (review R7: the records hold each connection; this is the line a person
/// at the terminal sees).
pub(crate) fn finish_sign_in_route() {
    let Ok(mut slot) = SIGN_IN_ROUTE.lock() else {
        return;
    };
    let Some(t) = slot.take() else {
        return;
    };
    for line in sign_in_route_lines(&t.refused(), &t.failed(), t.over_cap()) {
        eprintln!("{line}");
    }
}

pub(crate) fn sign_in_route_lines(
    refused: &[String],
    failed: &[String],
    over_cap: u64,
) -> Vec<String> {
    let mut out = Vec::new();
    if !refused.is_empty() {
        out.push(format!(
            "derm run: the chat's sign-in tunnel refused: {}",
            refused.join("; ")
        ));
    }
    if !failed.is_empty() {
        out.push(format!(
            "derm run: the chat's sign-in tunnel could not reach: {}",
            failed.join("; ")
        ));
    }
    if over_cap > 0 {
        out.push(format!(
            "derm run: the chat's sign-in tunnel turned away {over_cap} connection(s) over its cap of {}",
            crate::agents::tunnel::MAX_CONNECTIONS
        ));
    }
    out
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

/// BT-18 (P box test, medium): the domain's line names abstract sockets and
/// another project's folders, which read as covering a pathname Unix socket
/// there; it does not (run on the box: a chat in one project connected to
/// another project's Claude Code inbox in `run/cc-socks/`, and only Claude
/// Code's own `crossSessionInbound: "refuse"` stopped the message). Said at
/// the start until lane PG's mount layer closes it.
pub(crate) const PATHNAME_SOCKETS_LINE: &str = "derm run: this chat can still connect to a pathname Unix socket in another project's folders of this account (its domain does not cover connect(2) on one, and the files are the account's own); derm flags such a connect (net.unix, outside its project) and does not block it; lane PG's mount layer closes it";

/// The npm package `program_real` runs from (BT-15): the nearest folder
/// above it whose parent is a `node_modules` folder, or a scope (`@x`) in
/// one, as `<prefix>/lib/node_modules/<package>` and
/// `<prefix>/lib/node_modules/@scope/<package>` lay out a global install.
/// `None` for a program in no package (Claude Code's native binary).
pub(crate) fn npm_package(program_real: &Path) -> Option<PathBuf> {
    let is = |p: Option<&Path>, n: &str| p.and_then(Path::file_name).is_some_and(|f| f == n);
    for dir in program_real.ancestors().skip(1) {
        let parent = dir.parent();
        if is(parent, "node_modules") {
            return Some(dir.to_path_buf());
        }
        let scoped = parent
            .and_then(Path::file_name)
            .and_then(|f| f.to_str())
            .is_some_and(|f| f.starts_with('@'));
        if scoped && is(parent.and_then(Path::parent), "node_modules") {
            return Some(dir.to_path_buf());
        }
    }
    None
}

/// Every entry under the npm package `root` the `trusted` uid's and closed
/// to group and other writes (BT-15): `sudo npm install -g` keeps each
/// tarball entry's owner (node-tar sets `preserveOwner` when run as root,
/// `lib/unpack.js:177-178`, read on the box), so an entry script of root's
/// can load a dependency file another uid can rewrite. A link is taken as
/// itself, never followed (its target, inside the package, is walked as its
/// own entry); a link's own mode means nothing, its owner does. At most
/// 100,000 entries and 32 levels. The refusal names the fix.
pub(crate) fn closed_package(root: &Path, trusted: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let fix = |p: &Path, why: &str| {
        format!(
            "{} {why}: a harness on an agent account runs only from a package every file of which only root can change; run `sudo chown -R root:root {r} && sudo chmod -R go-w {r}` (npm run as root keeps each tarball's file owners), and start the chat again",
            p.display(),
            r = root.display()
        )
    };
    let mut seen = 0usize;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((d, depth)) = stack.pop() {
        let rd = std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        for e in rd {
            let e = e.map_err(|e| format!("{}: {e}", d.display()))?;
            seen += 1;
            if seen > 100_000 {
                return Err(format!(
                    "{} holds more than 100,000 entries",
                    root.display()
                ));
            }
            let path = e.path();
            let m =
                std::fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            if m.uid() != trusted {
                return Err(fix(&path, &format!("is uid {}'s, not root's", m.uid())));
            }
            if m.file_type().is_symlink() {
                continue;
            }
            if m.mode() & 0o022 != 0 {
                return Err(fix(&path, "can be written by group or others"));
            }
            if m.is_dir() {
                if depth >= 32 {
                    return Err(format!("{} is more than 32 folders deep", root.display()));
                }
                stack.push((path, depth + 1));
            } else if !m.is_file() {
                return Err(fix(&path, "is not a file or a folder"));
            }
        }
    }
    Ok(())
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

    /// Case 283 (red first): the chat's own sign-in tunnel, by credential,
    /// to its harness's sign-in host only; never `mcp-proxy.anthropic.com`
    /// (Tony's 22 Nov call), never for a chat that has a proxy already.
    #[test]
    fn case_283_an_unbrokered_account_chat_gets_its_own_sign_in_tunnel() {
        use std::io::{Read, Write};
        let none = |_: &str| None;
        let r = sign_in_route("claude-code", &[], &none, None)
            .unwrap()
            .expect("a route for Claude Code");
        assert_eq!(r.hosts, ["platform.claude.com:443"]);
        let get = |k: &str| r.env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let url = get("HTTPS_PROXY").unwrap();
        assert_eq!(get("https_proxy").as_deref(), Some(url.as_str()));
        assert!(
            url.starts_with("http://derm:") && url.contains("@127.0.0.1:"),
            "{url}"
        );
        assert_eq!(get("NO_PROXY").as_deref(), Some("localhost,127.0.0.1,::1"));
        assert_eq!(get("no_proxy").as_deref(), Some("localhost,127.0.0.1,::1"));
        assert!(
            get("HTTP_PROXY").is_none(),
            "plain http (the tap) stays direct"
        );
        let ask = |head: String| {
            let mut c = std::net::TcpStream::connect(("127.0.0.1", r.tunnel.port)).unwrap();
            c.set_read_timeout(Some(std::time::Duration::from_secs(20)))
                .unwrap();
            c.write_all(head.as_bytes()).unwrap();
            let mut b = [0u8; 64];
            let n = c.read(&mut b).unwrap_or(0);
            String::from_utf8_lossy(&b[..n]).into_owned()
        };
        let auth = format!("Proxy-Authorization: {}\r\n", r.tunnel.authorization());
        let got = ask("CONNECT platform.claude.com:443 HTTP/1.1\r\n\r\n".into());
        assert!(got.starts_with("HTTP/1.1 407"), "no credential: {got}");
        let got = ask(format!(
            "CONNECT mcp-proxy.anthropic.com:443 HTTP/1.1\r\n{auth}\r\n"
        ));
        assert!(got.starts_with("HTTP/1.1 403"), "mcp-proxy: {got}");
        let got = ask(format!(
            "CONNECT api.anthropic.com:443 HTTP/1.1\r\n{auth}\r\n"
        ));
        assert!(
            got.starts_with("HTTP/1.1 403"),
            "the model host goes through the tap only: {got}"
        );
        let got = ask(format!(
            "CONNECT platform.claude.com:443 HTTP/1.1\r\n{auth}\r\n"
        ));
        assert!(
            got.starts_with("HTTP/1.1 200") || got.starts_with("HTTP/1.1 502"),
            "admitted (502 where this machine cannot reach it): {got}"
        );
        let c = sign_in_route("codex", &[], &none, None).unwrap().unwrap();
        assert_eq!(c.hosts, ["auth.openai.com:443"]);
        // A brokered chat (derm-egress is its proxy) and a harness with no
        // sign-in host get none.
        let brokered = vec![(
            "HTTPS_PROXY".to_string(),
            "http://derm:x@127.0.0.1:1".to_string(),
        )];
        assert!(sign_in_route("claude-code", &brokered, &none, None)
            .unwrap()
            .is_none());
        assert!(sign_in_route("pi", &[], &none, None).unwrap().is_none());
        assert!(sign_in_route("other", &[], &none, None).unwrap().is_none());
    }

    /// A sink that keeps what the chat's tunnel posts.
    fn kept() -> (
        crate::agents::tunnel::Recorder,
        std::sync::Arc<std::sync::Mutex<Vec<derm_core::event::Event>>>,
    ) {
        let got: std::sync::Arc<std::sync::Mutex<Vec<derm_core::event::Event>>> =
            std::sync::Arc::default();
        let g = got.clone();
        (
            crate::agents::tunnel::Recorder {
                sink: std::sync::Arc::new(move |e| g.lock().unwrap().extend(e)),
                chat: "c-3b".into(),
                harness: "claude-code".into(),
            },
            got,
        )
    }

    fn wait_for(
        got: &std::sync::Mutex<Vec<derm_core::event::Event>>,
        n: usize,
    ) -> Vec<derm_core::event::Event> {
        let t = std::time::Instant::now();
        loop {
            let e = got.lock().unwrap().clone();
            if e.len() >= n || t.elapsed() > std::time::Duration::from_secs(10) {
                return e;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Tony's call 3b and review R7 (red first): the chat's sign-in tunnel
    /// posts one `signin.connect` per connection, as source `run`, naming the
    /// target, admitted or refused, the server name and the bytes, never the
    /// credential. Review R3 through the tunnel: plain bytes and a hello for
    /// another server are refused there too.
    #[test]
    fn call_3b_the_chats_sign_in_tunnel_records_each_connection() {
        use std::io::{Read, Write};
        let none = |_: &str| None;
        let (rec, got) = kept();
        let r = sign_in_route("claude-code", &[], &none, Some(rec))
            .unwrap()
            .expect("a route for Claude Code");
        let auth = format!("Proxy-Authorization: {}\r\n", r.tunnel.authorization());
        let ask = |head: String, then: &[u8]| {
            let mut c = std::net::TcpStream::connect(("127.0.0.1", r.tunnel.port)).unwrap();
            c.set_read_timeout(Some(std::time::Duration::from_secs(20)))
                .unwrap();
            c.write_all(head.as_bytes()).unwrap();
            c.write_all(then).unwrap();
            let mut b = Vec::new();
            let _ = c.read_to_end(&mut b);
            String::from_utf8_lossy(&b).into_owned()
        };
        let out = ask(
            format!("CONNECT mcp-proxy.anthropic.com:443 HTTP/1.1\r\n{auth}\r\n"),
            b"",
        );
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
        // Admitted by name; this machine may not reach it (502, failed).
        let _ = ask(
            format!("CONNECT platform.claude.com:443 HTTP/1.1\r\n{auth}\r\n"),
            b"GET / HTTP/1.1\r\n\r\n",
        );
        let _ = ask(
            format!("CONNECT platform.claude.com:443 HTTP/1.1\r\n{auth}\r\n"),
            &derm_egress::hello::client_hello_for(Some("other-tenant.example")),
        );
        let e = wait_for(&got, 3);
        assert_eq!(e.len(), 3, "{e:?}");
        let text = serde_json::to_string(&e).unwrap();
        let cred = r.tunnel.authorization();
        let secret = cred.trim_start_matches("Basic ");
        assert!(!text.contains(secret), "a record holds the credential");
        for x in &e {
            assert_eq!(x.kind, "signin.connect");
            assert_eq!(x.source, derm_core::event::Source::Run);
            assert_eq!(x.chat_id, "c-3b");
            for k in [
                "connectHost",
                "port",
                "verdict",
                "bytesUp",
                "bytesDown",
                "startedAt",
                "endedAt",
            ] {
                assert!(x.detail.get(k).is_some(), "{k}: {}", x.detail);
            }
        }
        let mcp = e
            .iter()
            .find(|x| x.detail["connectHost"] == "mcp-proxy.anthropic.com")
            .unwrap();
        assert_eq!(mcp.detail["verdict"], "refused", "{}", mcp.detail);
        let claude: Vec<_> = e
            .iter()
            .filter(|x| x.detail["connectHost"] == "platform.claude.com")
            .collect();
        assert_eq!(claude.len(), 2);
        for x in claude {
            // Unreachable here: failed. Reachable: refused for its first
            // flight (plain bytes, or another server's name).
            let v = x.detail["verdict"].as_str().unwrap();
            assert!(v == "refused" || v == "failed", "{}", x.detail);
            if v == "refused" {
                let why = x.detail["reason"].as_str().unwrap();
                assert!(
                    why == "the tunnel does not carry TLS"
                        || why == "the TLS server name is not the tunnel's host",
                    "{why}"
                );
            }
            assert_eq!(x.detail["bytesUp"], 0, "{}", x.detail);
        }
    }

    /// Review R6 (red first): the tunnel holds at most its cap, and a
    /// connection over it is refused and recorded, never a new thread.
    #[test]
    fn r6_the_chats_sign_in_tunnel_holds_at_most_its_cap() {
        use std::io::Read;
        let none = |_: &str| None;
        let (rec, got) = kept();
        let r = sign_in_route("claude-code", &[], &none, Some(rec))
            .unwrap()
            .unwrap();
        // Hold the cap's worth of connections open with half a head.
        let cap = crate::agents::tunnel::MAX_CONNECTIONS;
        let mut held = Vec::new();
        for _ in 0..cap {
            let mut c = std::net::TcpStream::connect(("127.0.0.1", r.tunnel.port)).unwrap();
            std::io::Write::write_all(&mut c, b"CONNECT ").unwrap();
            held.push(c);
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        let mut c = std::net::TcpStream::connect(("127.0.0.1", r.tunnel.port)).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut b = String::new();
        let _ = c.read_to_string(&mut b);
        assert!(b.starts_with("HTTP/1.1 503"), "{b:?}");
        assert_eq!(r.tunnel.over_cap(), 1);
        let e = wait_for(&got, 1);
        assert!(
            e.iter()
                .any(|x| x.detail["reason"] == crate::agents::tunnel::OVER_CAP),
            "{e:?}"
        );
        drop(held);
    }

    /// Tony's call 1a, not built: the start says the store is readable by
    /// the chat's commands, and why, per harness.
    #[test]
    fn call_1a_the_start_says_the_store_is_not_hidden_from_the_chats_commands() {
        let c = store_line("claude-code", "/var/lib/derm/agents/box").unwrap();
        assert!(
            c.contains("/var/lib/derm/agents/box/signin/claude-code") && c.contains("lane PG"),
            "{c}"
        );
        let p = store_line("pi", "/var/lib/derm/agents/box").unwrap();
        assert!(
            p.contains("no sandbox of its own") && p.contains("signin.read"),
            "{p}"
        );
        assert!(store_line("codex", "/a").unwrap().contains("lane PG"));
        assert_eq!(store_line("other", "/a"), None);
    }

    /// Tony's call 6a (red first).
    #[test]
    fn call_6a_a_pi_account_chat_without_derms_package_is_refused_unless_ungated() {
        assert_eq!(
            pi_gate_decision(Some("/usr/local/lib/derm/derm-pi"), false),
            Ok(true)
        );
        assert_eq!(
            pi_gate_decision(Some("/usr/local/lib/derm/derm-pi"), true),
            Ok(true)
        );
        let e = pi_gate_decision(None, false).unwrap_err();
        assert!(
            e.contains(super::super::project::PI_PACKAGE)
                && e.contains("sudo")
                && e.contains(UNGATED_FLAG),
            "{e}"
        );
        assert_eq!(pi_gate_decision(None, true), Ok(false));
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

    /// BT-15 (P box test, medium; red first): `sudo npm install -g` keeps
    /// each tarball entry's uid (node-tar's `preserveOwner` is true as root,
    /// `unpack.js:177-178`, read on the box), and Pi 1.6.0's install left 124
    /// files owned by other uids, one of them a login user's, under derm's
    /// "root-owned install", while derm checked only the entry script and its
    /// folders. The whole package the harness runs from is walked: every
    /// entry the trusted uid's and closed to group and other writes, a link
    /// only as itself, and the refusal names the `chown` line.
    #[test]
    fn bt_15_an_npm_harness_runs_only_from_a_package_closed_entry_by_entry() {
        use std::os::unix::fs::PermissionsExt;
        let me = derm_core::platform::effective_user();
        let base = std::env::temp_dir().join(format!("dpa-npm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let pkg = base.join("lib/node_modules/@earendil-works/pi-coding-agent");
        let dep = pkg.join("node_modules/proper-lockfile/lib");
        std::fs::create_dir_all(pkg.join("dist")).unwrap();
        std::fs::create_dir_all(&dep).unwrap();
        std::fs::write(pkg.join("dist/cli.js"), "#!/usr/bin/env node\n").unwrap();
        std::fs::write(pkg.join("package.json"), "{}").unwrap();
        std::fs::write(dep.join("lockfile.js"), "x").unwrap();
        std::os::unix::fs::symlink(
            "../proper-lockfile/lib/lockfile.js",
            pkg.join("node_modules/.bin-x"),
        )
        .unwrap();
        let real = pkg.join("dist/cli.js");
        assert_eq!(npm_package(&real).as_deref(), Some(pkg.as_path()));
        // Codex's unscoped layout, and a native binary in no package.
        let codex = base.join("lib/node_modules/codex/bin/codex.js");
        assert_eq!(
            npm_package(&codex).as_deref(),
            Some(base.join("lib/node_modules/codex").as_path())
        );
        assert_eq!(npm_package(Path::new("/usr/local/bin/claude")), None);
        assert_eq!(closed_package(&pkg, me), Ok(()));
        // One dependency's file others may write: refused, with the fix.
        std::fs::set_permissions(
            dep.join("lockfile.js"),
            std::fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        let e = closed_package(&pkg, me).unwrap_err();
        assert!(
            e.contains("lockfile.js") && e.contains("chown -R root:root"),
            "{e}"
        );
        std::fs::set_permissions(
            dep.join("lockfile.js"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        // Another uid's file (as root only: chown needs it).
        if me == 0 {
            std::os::unix::fs::chown(dep.join("lockfile.js"), Some(501), None).unwrap();
            let e = closed_package(&pkg, 0).unwrap_err();
            assert!(e.contains("lockfile.js"), "{e}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// BT-18: the start says pathname sockets in another project are
    /// reachable and only flagged.
    #[test]
    fn bt_18_the_start_says_another_projects_pathname_sockets_are_reachable() {
        assert!(PATHNAME_SOCKETS_LINE.contains("pathname Unix socket in another project"));
        assert!(PATHNAME_SOCKETS_LINE.contains("does not block it"));
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
