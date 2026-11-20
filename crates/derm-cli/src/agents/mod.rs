//! `derm agents` (lane L4 of the accounts build,
//! `plans/parallel_build_accounts.md`; note CB sections 4 and 5): the agent
//! accounts a person's chats run as, one per subscription.
//!
//! ```text
//! derm agents add <slug> --subscription <label> [--print]
//! derm agents list
//! derm agents login <harness> [--account <slug>]
//! derm agents status [--account <slug>]
//! derm agents installer
//! ```
//!
//! - `add` prints the installer line and runs it under `sudo` only after a
//!   yes on the terminal. The installer is the one built into this derm
//!   (`installer` prints it); derm checks its hash again as root, from a
//!   root-owned copy, before it runs (case 37).
//! - `login` runs the harness's own sign-in as the account (`harness.rs`):
//!   the unmodified binary through the vendor's own flow, which Anthropic's
//!   terms allow (note CB 4.1, readings 1 and 3). derm reads, copies and
//!   stores nothing the sign-in writes, and its tunnel passes the sign-in's
//!   TLS through unread (`tunnel.rs`).
//! - `status` says which harnesses each account is signed in to by whether
//!   the harness's own file exists, asked as the account with `test -f`
//!   (stat(2)), never its content.
//!
//! Linux only: macOS and Windows accounts wait for sessions M and W (section
//! 7). Nothing here writes `/etc/derm/agents.json` (section 2).

pub mod harness;
pub mod registry;
pub mod tunnel;

#[cfg(test)]
mod tests;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::connect::write::{Confirm, Tty};
use registry::Account;

pub const USAGE: &str = "usage: derm agents <add|list|login|status|installer> ...
  derm agents add <slug> --subscription <label> [--print]
  derm agents list
  derm agents login <claude-code|codex> [--account <slug>]
  derm agents status [--account <slug>]
  derm agents installer";

/// The installer this derm runs (lane L2's; plans/parallel_build_accounts.md
/// section 3).
pub const INSTALLER: &str = include_str!("../../../../packaging/linux/agent-user/install.sh");

/// The script `add` runs as root: copy the installer into a fresh root-owned
/// folder, check its hash there, run it, remove the copy. Fixed text; every
/// value is an argument (`$1` the person's copy, `$2` its sha256, `$3` the
/// interpreter, the rest the installer's own arguments).
const ROOT_STEP: &str = r#"set -u
t=$1; h=$2; i=$3; shift 3
d=$(mktemp -d) || exit 96
cp -- "$t" "$d/install.sh" || { rm -rf -- "$d"; exit 96; }
s=$(sha256sum -- "$d/install.sh") || { rm -rf -- "$d"; exit 96; }
if [ "${s%% *}" != "$h" ]; then
  rm -rf -- "$d"
  echo "derm agents: the installer changed after derm read it; nothing ran" >&2
  exit 97
fi
"$i" "$d/install.sh" "$@"
rc=$?
rm -rf -- "$d"
exit $rc"#;

/// The presence check `status` runs as the account: stat(2) through `test`,
/// never an open. 0 present, 3 absent; anything else (sudo's own 1 among
/// them) is unknown.
const PRESENT: &str = r#"if [ -f "$HOME/$1" ]; then exit 0; fi; exit 3"#;

/// Where this command reads, what it runs, and what it may ask.
pub(crate) struct Ctx<'a> {
    pub registry: PathBuf,
    pub settings: PathBuf,
    /// The owner `/etc/derm/agents.json` must have: root.
    pub registry_owner: u32,
    pub me: u32,
    pub sudo: PathBuf,
    pub sh: PathBuf,
    /// The `PATH` derm hands `sudo` (sudo then sets its own).
    pub path_env: String,
    /// Whether `sudo` and `sh` must be root-owned programs only root can
    /// change (always, outside tests).
    pub check_tools: bool,
    pub installer: &'a str,
    pub linux: bool,
    pub terminal: bool,
    pub in_chat: Option<String>,
    pub confirm: &'a mut dyn Confirm,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

pub fn main(args: &[String]) -> u8 {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let mut tty = Tty;
    let mut ctx = Ctx {
        registry: PathBuf::from(registry::PATH),
        settings: Path::new(&home).join(".derm").join("settings.json"),
        registry_owner: 0,
        me: me(),
        sudo: PathBuf::from("/usr/bin/sudo"),
        sh: PathBuf::from("/bin/sh"),
        path_env: "/usr/bin:/bin".into(),
        check_tools: true,
        installer: INSTALLER,
        linux: cfg!(target_os = "linux"),
        terminal: terminal(),
        in_chat: inside_a_chat(),
        confirm: &mut tty,
        out: &mut out,
        err: &mut err,
    };
    run(&mut ctx, args)
}

#[cfg(unix)]
fn me() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn me() -> u32 {
    0
}

#[cfg(unix)]
fn terminal() -> bool {
    // SAFETY: isatty reads only the descriptor number.
    unsafe { libc::isatty(0) == 1 && libc::isatty(2) == 1 }
}

#[cfg(not(unix))]
fn terminal() -> bool {
    false
}

/// `derm setup`'s and `derm secret`'s rule: a chat token in the environment,
/// or a `derm run` among this process's ancestors (case 147).
fn inside_a_chat() -> Option<String> {
    for v in ["DERM_CHAT_TOKEN", "DERM_CHAT_TOKEN_FILE"] {
        if std::env::var_os(v).is_some_and(|x| !x.is_empty()) {
            return Some(format!("{v} is set, so this runs inside a derm run chat"));
        }
    }
    #[cfg(unix)]
    {
        let me = derm_core::platform::peer::me();
        if let Some(p) = derm_core::platform::peer::derm_run_ancestor(me) {
            return Some(format!("a derm run (pid {p}) started this"));
        }
    }
    None
}

pub(crate) fn run(ctx: &mut Ctx<'_>, args: &[String]) -> u8 {
    let verb = args.first().map(String::as_str);
    if verb == Some("installer") {
        let _ = ctx.out.write_all(ctx.installer.as_bytes());
        return 0;
    }
    if !matches!(verb, Some("add" | "list" | "login" | "status")) {
        let _ = writeln!(ctx.err, "{USAGE}");
        return 2;
    }
    if !ctx.linux {
        let _ = writeln!(
            ctx.err,
            "derm agents: Linux only for now; macOS and Windows agent accounts are not built (plans/toolkit_agent_accounts_plan.md, steps B and C)"
        );
        return 2;
    }
    let rest = &args[1..];
    match verb {
        Some("add") => add(ctx, rest),
        Some("list") => list(ctx, rest),
        Some("login") => login(ctx, rest),
        _ => status(ctx, rest),
    }
}

/// The value after `flag`, once; the other words.
fn take(args: &[String], flag: &str) -> Result<(Option<String>, Vec<String>), String> {
    let mut v = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            let x = args.get(i + 1).ok_or(format!("{flag} needs a value"))?;
            if v.replace(x.clone()).is_some() {
                return Err(format!("{flag} given twice"));
            }
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    Ok((v, rest))
}

fn fail(ctx: &mut Ctx<'_>, code: u8, why: &str) -> u8 {
    let _ = writeln!(ctx.err, "derm agents: {why}");
    code
}

/// The accounts, or none with the reason said once.
fn accounts(ctx: &mut Ctx<'_>) -> Vec<Account> {
    match registry::load(&ctx.registry, ctx.registry_owner) {
        Ok(a) => a,
        Err(why) => {
            let _ = writeln!(
                ctx.err,
                "derm agents: {why}; acting as if there are no accounts"
            );
            vec![]
        }
    }
}

fn default_slug(ctx: &mut Ctx<'_>) -> Option<String> {
    match registry::default_slug(&ctx.settings, ctx.me) {
        Ok(s) => s,
        Err(why) => {
            let _ = writeln!(ctx.err, "derm agents: {why}");
            None
        }
    }
}

/// One word quoted for a POSIX shell, so a printed line pastes as given.
fn quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@".contains(&b))
    {
        return s.into();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// The interpreter the installer names, by absolute path (case 37: never one
/// found on `PATH`).
fn interpreter(script: &str) -> Result<&'static str, String> {
    match script.lines().next().map(str::trim_end) {
        Some("#!/bin/bash") | Some("#!/usr/bin/env bash") | Some("#!/usr/bin/bash") => {
            Ok("/bin/bash")
        }
        Some("#!/bin/sh") | Some("#!/usr/bin/env sh") => Ok("/bin/sh"),
        other => Err(format!(
            "the installer names no interpreter derm runs ({})",
            other.unwrap_or("empty")
        )),
    }
}

/// A root-owned program that only root can change, its folders too.
#[cfg(unix)]
fn trusted(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let real = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let ok = std::fs::metadata(&real)
        .is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
        && real
            .ancestors()
            .skip(1)
            .all(|p| std::fs::metadata(p).is_ok_and(|d| d.uid() == 0 && d.mode() & 0o022 == 0));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{} is not a root-owned program that only root can change",
            path.display()
        ))
    }
}

#[cfg(not(unix))]
fn trusted(_: &Path) -> Result<(), String> {
    Err("not on this system".into())
}

fn tools(ctx: &Ctx<'_>) -> Result<(), String> {
    if ctx.check_tools {
        trusted(&ctx.sudo)?;
        trusted(&ctx.sh)?;
    }
    Ok(())
}

/// A command with derm's environment left out: only `PATH` (derm's fixed
/// one), and what a terminal program needs to draw. sudo's `env_reset` then
/// builds the account's own (sudoers(5)), so none of the person's keys
/// (`ANTHROPIC_API_KEY`, which outranks a sign-in: case 12) reach it.
fn sudo(ctx: &Ctx<'_>) -> Command {
    let mut c = Command::new(&ctx.sudo);
    c.env_clear().env("PATH", &ctx.path_env);
    for k in ["TERM", "COLORTERM", "LANG", "LC_ALL"] {
        if let Some(v) = std::env::var_os(k) {
            c.env(k, v);
        }
    }
    c
}

fn add(ctx: &mut Ctx<'_>, args: &[String]) -> u8 {
    let (label, rest) = match take(args, "--subscription") {
        Ok(x) => x,
        Err(e) => return fail(ctx, 2, &e),
    };
    let print_only = rest.iter().any(|a| a == "--print");
    let words: Vec<&String> = rest.iter().filter(|a| *a != "--print").collect();
    let (Some(&slug), true, Some(label)) = (words.first(), words.len() == 1, label) else {
        let _ = writeln!(ctx.err, "{USAGE}");
        return 2;
    };
    if !registry::slug_ok(slug) {
        return fail(ctx, 2, "a slug is 1 to 24 of a-z, 0-9 and -");
    }
    if !registry::label_ok(&label) {
        return fail(
            ctx,
            2,
            "a subscription label is 1 to 64 characters with no control characters and no space at either end",
        );
    }
    if let Some(why) = ctx.in_chat.clone() {
        return fail(
            ctx,
            1,
            &format!("refused inside a chat ({why}); run it in your own terminal"),
        );
    }
    if accounts(ctx).iter().any(|a| &a.slug == slug) {
        return fail(
            ctx,
            1,
            &format!("derm-agent-{slug} is set up already (`derm agents list`)"),
        );
    }
    let interp = match interpreter(ctx.installer) {
        Ok(i) => i,
        Err(e) => return fail(ctx, 1, &e),
    };
    let hash = sha256_hex(ctx.installer.as_bytes());
    let line = format!(
        "derm agents installer > install.sh && sudo {interp} install.sh --account {} --subscription {}",
        quote(slug),
        quote(&label)
    );
    let _ = writeln!(
        ctx.out,
        "derm-agent-{slug} for the subscription \"{}\": the installer, as root, makes the account in group {}, its home, its entry in {}, and the firewall table that keeps the group to loopback",
        registry::shown(&label),
        registry::GROUP,
        registry::PATH
    );
    let _ = writeln!(ctx.out, "  {line}");
    let _ = writeln!(ctx.out, "  installer sha256 {hash}");
    if print_only {
        return 0;
    }
    if !ctx.terminal {
        let _ = writeln!(ctx.out, "no terminal: not run; run the line above yourself");
        return 0;
    }
    if let Err(e) = tools(ctx) {
        return fail(ctx, 1, &format!("{e}; not run"));
    }
    match ctx.confirm.confirm("Run it now with sudo?") {
        Ok(true) => {}
        Ok(false) => {
            let _ = writeln!(ctx.out, "not run");
            return 1;
        }
        Err(e) => return fail(ctx, 1, &format!("{e}; not run")),
    }
    let dir = match private_dir() {
        Ok(d) => d,
        Err(e) => return fail(ctx, 1, &e),
    };
    let file = dir.join("install.sh");
    let wrote = write_new(&file, ctx.installer.as_bytes());
    let code = match wrote {
        Err(e) => fail(ctx, 1, &e),
        Ok(()) => {
            let st = sudo(ctx)
                .arg("--")
                .arg(&ctx.sh)
                .arg("-c")
                .arg(ROOT_STEP)
                .arg("derm-agents-install")
                .arg(&file)
                .arg(&hash)
                .arg(interp)
                .args(["--account", slug, "--subscription", &label])
                .status();
            match st {
                Ok(s) if s.success() => 0,
                Ok(s) => fail(ctx, 1, &format!("the installer stopped ({s})")),
                Err(e) => fail(ctx, 1, &format!("{}: {e}", ctx.sudo.display())),
            }
        }
    };
    let _ = std::fs::remove_dir_all(&dir);
    if code == 0 {
        let held = accounts(ctx).iter().any(|a| &a.slug == slug);
        let _ = writeln!(
            ctx.out,
            "{}",
            if held {
                format!("derm-agent-{slug} is set up; sign a harness in with `derm agents login <harness> --account {slug}`")
            } else {
                format!(
                    "the installer finished but {} does not hold derm-agent-{slug}",
                    registry::PATH
                )
            }
        );
        return if held { 0 } else { 1 };
    }
    code
}

/// A new folder only this user can enter, under the system's temporary
/// folder.
fn private_dir() -> Result<PathBuf, String> {
    let d = std::env::temp_dir().join(format!("derm-agents-{}", uuid::Uuid::new_v4().simple()));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(&d).map_err(|e| format!("{}: {e}", d.display()))?;
    Ok(d)
}

fn write_new(p: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = o.open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("{}: {e}", p.display()))
}

fn list(ctx: &mut Ctx<'_>, args: &[String]) -> u8 {
    if !args.is_empty() {
        let _ = writeln!(ctx.err, "{USAGE}");
        return 2;
    }
    let all = accounts(ctx);
    let def = default_slug(ctx);
    if all.is_empty() {
        let _ = writeln!(
            ctx.out,
            "no agent accounts; `derm agents add <slug> --subscription <label>` makes one"
        );
        return 0;
    }
    for a in &all {
        let _ = writeln!(
            ctx.out,
            "{}{}  uid {}  subscription \"{}\"  home {}",
            a.name,
            if def.as_deref() == Some(a.slug.as_str()) {
                " (default)"
            } else {
                ""
            },
            a.uid,
            registry::shown(&a.subscription),
            a.home
        );
    }
    if let Some(d) = def.filter(|d| !all.iter().any(|a| &a.slug == d)) {
        let _ = writeln!(
            ctx.err,
            "derm agents: agents.default names {d}, which is not set up"
        );
    }
    0
}

fn pick_one(ctx: &mut Ctx<'_>, flag: Option<&str>) -> Result<Account, u8> {
    let all = accounts(ctx);
    let def = default_slug(ctx);
    registry::pick(&all, flag, def.as_deref())
        .cloned()
        .map_err(|why| fail(ctx, 1, &why))
}

/// Whether the account has the harness's sign-in file, asked as the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Presence {
    Yes,
    No,
    Unknown,
}

pub(crate) fn present(ctx: &Ctx<'_>, a: &Account, file: &str) -> Presence {
    let st = sudo(ctx)
        .args(["-n", "-H", "-u", &a.name, "--"])
        .arg(&ctx.sh)
        .args(["-c", PRESENT, "derm-agents-status", file])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match st.ok().and_then(|s| s.code()) {
        Some(0) => Presence::Yes,
        Some(3) => Presence::No,
        _ => Presence::Unknown,
    }
}

fn status(ctx: &mut Ctx<'_>, args: &[String]) -> u8 {
    let (flag, rest) = match take(args, "--account") {
        Ok(x) => x,
        Err(e) => return fail(ctx, 2, &e),
    };
    if !rest.is_empty() {
        let _ = writeln!(ctx.err, "{USAGE}");
        return 2;
    }
    let all = match flag {
        Some(f) => match registry::pick(&accounts(ctx), Some(&f), None) {
            Ok(a) => vec![a.clone()],
            Err(why) => return fail(ctx, 1, &why),
        },
        None => accounts(ctx),
    };
    if all.is_empty() {
        let _ = writeln!(
            ctx.out,
            "no agent accounts; `derm agents add <slug> --subscription <label>` makes one"
        );
        return 0;
    }
    if let Err(e) = tools(ctx) {
        return fail(ctx, 1, &e);
    }
    let mut unknown = false;
    let mut claude = false;
    for a in &all {
        let mut parts = Vec::new();
        for h in harness::ALL {
            let p = present(ctx, a, h.file);
            claude |= h.id == "claude-code" && p == Presence::Yes;
            unknown |= p == Presence::Unknown;
            parts.push(format!(
                "{} {}",
                h.id,
                match p {
                    Presence::Yes => "signed in",
                    Presence::No => "not signed in",
                    Presence::Unknown => "unknown",
                }
            ));
        }
        let _ = writeln!(
            ctx.out,
            "{} (\"{}\"): {}",
            a.name,
            registry::shown(&a.subscription),
            parts.join(", ")
        );
    }
    let _ = writeln!(
        ctx.out,
        "read by whether each harness's own sign-in file exists ({}), as the account; derm opened none of them",
        harness::ALL.iter().map(|h| format!("~/{}", h.file)).collect::<Vec<_>>().join(", ")
    );
    if unknown {
        let _ = writeln!(
            ctx.out,
            "unknown: sudo could not run as the account without a password; the installer's sudoers rule lets you"
        );
    }
    if claude {
        let _ = writeln!(ctx.out, "note: {}", harness::INDIVIDUAL_USE);
    }
    0
}

fn login(ctx: &mut Ctx<'_>, args: &[String]) -> u8 {
    let (flag, rest) = match take(args, "--account") {
        Ok(x) => x,
        Err(e) => return fail(ctx, 2, &e),
    };
    let (Some(id), 1) = (rest.first(), rest.len()) else {
        let _ = writeln!(ctx.err, "{USAGE}");
        return 2;
    };
    let Some(h) = harness::find(id) else {
        return fail(
            ctx,
            2,
            &format!(
                "no sign-in known for {}; known: {}",
                registry::shown(id),
                harness::ALL
                    .iter()
                    .map(|h| h.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    };
    if let Some(why) = ctx.in_chat.clone() {
        return fail(
            ctx,
            1,
            &format!("refused inside a chat ({why}); run it in your own terminal"),
        );
    }
    if !ctx.terminal {
        return fail(ctx, 1, "a sign-in needs you at a terminal; not run");
    }
    let a = match pick_one(ctx, flag.as_deref()) {
        Ok(a) => a,
        Err(c) => return c,
    };
    if let Err(e) = tools(ctx) {
        return fail(ctx, 1, &e);
    }
    let t = match tunnel::Tunnel::start(h.hosts) {
        Ok(t) => t,
        Err(e) => return fail(ctx, 1, &format!("the sign-in's tunnel did not open: {e}")),
    };
    let _ = writeln!(
        ctx.out,
        "signing {} in as {} through {}'s own flow: `{}`; derm reads, copies and stores nothing it writes, and lets it reach only {} on 443, unread",
        h.id,
        a.name,
        h.vendor,
        h.argv.join(" "),
        h.hosts.join(", ")
    );
    let url = t.url();
    let st = sudo(ctx)
        .args(["-u", &a.name, "-i", "--", "/usr/bin/env"])
        .arg(format!("HTTPS_PROXY={url}"))
        .arg(format!("https_proxy={url}"))
        .args(["NO_PROXY=", "no_proxy="])
        .args(h.argv)
        .status();
    let code = match st {
        Ok(s) if s.success() => 0,
        Ok(s) => fail(ctx, 1, &format!("the sign-in ended ({s})")),
        Err(e) => return fail(ctx, 1, &format!("{}: {e}", ctx.sudo.display())),
    };
    let refused = t.refused();
    if !refused.is_empty() {
        let _ = writeln!(ctx.out, "the tunnel refused: {}", refused.join(", "));
    }
    let _ = match present(ctx, &a, h.file) {
        Presence::Yes => writeln!(
            ctx.out,
            "{} has {}'s sign-in file (~/{})",
            a.name, h.id, h.file
        ),
        Presence::No => writeln!(
            ctx.out,
            "{} has no {} sign-in file (~/{})",
            a.name, h.id, h.file
        ),
        Presence::Unknown => writeln!(
            ctx.out,
            "could not check {}'s sign-in file as {}",
            h.id, a.name
        ),
    };
    if h.id == "claude-code" {
        let _ = writeln!(ctx.out, "note: {}", harness::INDIVIDUAL_USE);
    }
    code
}
