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
use super::{anchor, bridge, landlock, Context};

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
    let path = acct.path();

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
    let found = probe.run().map_err(|e| (1, e))?;
    if let Some(why) = found.refusal(&acct.name, &program) {
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
    let mut spec = landlock::chat_spec(&landlock::ChatPaths {
        folders: &writable,
        account_home: &acct.home,
        bridge: bridge_dir.as_deref(),
        path: &path,
        require_scopes: scope.require_scopes,
    });
    spec.require_landlock = scope.require_landlock;
    set.push((
        landlock::SPEC_VAR.to_string(),
        serde_json::to_string(&spec).map_err(|e| (1, e.to_string()))?,
    ));
    rewrite(
        launch,
        &Route {
            sudo: &sudo,
            env_tool: &env_tool,
            helper: &helper,
            user: &acct.name,
            path: &path,
            program: &program,
        },
        &set,
    );
    eprintln!(
        "derm run: {program} starts as {} ({}), in its own Landlock domain{}: other chats on the account cannot read its token, trace it{}",
        acct.name,
        acct.subscription,
        if scope.require_scopes { "" } else { " without scopes" },
        if scope.require_scopes {
            ", signal it or reach its abstract sockets"
        } else {
            ""
        }
    );
    Ok(Some(json!({
        "user": acct.name,
        "uid": acct.uid,
        "how": anchor::HOW_SUDO,
        "account": acct.slug(),
        "landlock": {
            "abi": landlock::abi(),
            "scoped": scope.require_scopes,
            "answeredBy": scope.answered_by,
        },
    })))
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
    pub path: &'a str,
    pub program: &'a str,
}

/// `sudo -n -u <user> --preserve-env=<names> -- <helper> landlock --
/// <env> PATH=<path> <program> <args>`. Values go in the environment, names
/// only on argv.
pub(super) fn rewrite(launch: &mut Plan, r: &Route, set: &[(String, String)]) {
    for (k, v) in set {
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
        format!("PATH={}", r.path),
        r.program.to_string(),
    ]);
    args.append(&mut launch.args);
    launch.program = r.sudo.to_string();
    launch.args = args;
}

/// Where root installs derm by hand or by package.
const ROOT_COPIES: &[&str] = &["/usr/local/bin/derm", "/usr/bin/derm"];

/// derm's own binary, from a place only root can change and every user can
/// run: this one, or a root copy with the same bytes (the helper's spec
/// format is this build's).
fn helper_binary() -> Result<String, String> {
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
        rewrite(
            &mut p,
            &Route {
                sudo: "/usr/bin/sudo",
                env_tool: "/usr/bin/env",
                helper: "/usr/local/bin/derm",
                user: "derm-max",
                path: "/var/lib/derm/agents/max/.local/bin:/usr/local/bin:/usr/bin:/bin",
                program: "claude",
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
                "PATH=/var/lib/derm/agents/max/.local/bin:/usr/local/bin:/usr/bin:/bin",
                "claude",
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
