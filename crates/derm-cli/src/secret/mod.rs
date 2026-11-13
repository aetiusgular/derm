//! `derm secret` (wave 6, lane 6C; `contracts/policy.md` section 8; the wave 6
//! plan section 2.2): the secrets derm-egress injects for named hosts, and the
//! local CA it terminates TLS with.
//!
//! ```text
//! derm secret add <id> --host <h> [--host <h>...] (--env <VAR> | --file <path> | --keychain <service>) [--note <text>]
//! derm secret list
//! derm secret check
//! derm secret remove <id>
//! derm secret ca create [--replace]
//! derm secret ca show
//! derm secret ca remove
//! ```
//!
//! Every verb that writes (`add`, `remove`, `ca create`, `ca remove`) runs only
//! from a terminal, and never inside a `derm run` chat: an agent that could
//! name a host for a secret, or make the CA, would route the secret where it
//! likes. A terminal is not proof of a person (case 89); what holds against an
//! agent is that it cannot reach this command's files (srt denies `~/.derm`,
//! the Standard tier's blocks deny its reads) and the presets' deny of `derm`
//! setup verbs (case 147). No verb ever prints a value; `check` reads each value
//! as a chat start would and says only whether it could.

// Called by `run/` once integration wires it (the lane's request); until
// then only its tests use it.
#[allow(dead_code)]
pub mod chain;

use std::path::{Path, PathBuf};

use derm_egress::ca::{self, Ca};
use derm_egress::secrets::{self, Entry, From};

pub const USAGE: &str = "usage: derm secret <add|list|check|remove|ca> ...
  derm secret add <id> --host <h> [--host <h>...] (--env <VAR> | --file <path> | --keychain <service>) [--note <text>]
  derm secret list
  derm secret check
  derm secret remove <id>
  derm secret ca <create [--replace]|show|remove>";

/// Where this command reads and writes, and what it may ask of the process.
pub(crate) struct Ctx<'a> {
    pub home: PathBuf,
    /// Whether a person's terminal is attached (stdin and stderr).
    pub terminal: bool,
    /// Why this looks like a `derm run` chat, if it does.
    pub in_chat: Option<String>,
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub out: &'a mut dyn std::io::Write,
    pub err: &'a mut dyn std::io::Write,
}

pub fn main(args: &[String]) -> u8 {
    let home = match std::env::var("HOME") {
        Ok(h) if h.starts_with('/') => PathBuf::from(h),
        _ => match std::env::var("USERPROFILE") {
            Ok(h) if Path::new(&h).is_absolute() => PathBuf::from(h),
            _ => {
                eprintln!("derm secret: no home folder (HOME)");
                return 2;
            }
        },
    };
    let env = |k: &str| std::env::var(k).ok();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let mut ctx = Ctx {
        home,
        terminal: terminal(),
        in_chat: inside_a_chat(),
        env: &env,
        out: &mut out,
        err: &mut err,
    };
    run(&mut ctx, args)
}

#[cfg(all(unix, not(test)))]
fn terminal() -> bool {
    // SAFETY: isatty reads only the descriptor number.
    unsafe { libc::isatty(0) == 1 && libc::isatty(2) == 1 }
}

#[cfg(any(windows, test))]
fn terminal() -> bool {
    // Windows: lane 6C reads no console mode yet, so the writing verbs refuse
    // there (fail safe). Tests never count as a terminal.
    false
}

/// `derm setup`'s rule (its `inside_a_chat`): a chat token in the
/// environment, or a `derm run` among this process's ancestors.
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
    let writes = matches!(verb, Some("add" | "remove"))
        || (verb == Some("ca")
            && matches!(args.get(1).map(String::as_str), Some("create" | "remove")));
    if writes {
        if let Some(why) = &ctx.in_chat {
            let _ = writeln!(
                ctx.err,
                "derm secret: refused inside a chat ({why}); run it in your own terminal"
            );
            return 2;
        }
        if !ctx.terminal {
            let _ = writeln!(
                ctx.err,
                "derm secret: {} runs only from a terminal",
                verb.unwrap_or("")
            );
            return 2;
        }
    }
    let r = match verb {
        Some("add") => add(ctx, &args[1..]),
        Some("list") => list(ctx),
        Some("check") => check(ctx),
        Some("remove") => remove(ctx, &args[1..]),
        Some("ca") => ca_verb(ctx, &args[1..]),
        _ => Err(USAGE.to_string()),
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(ctx.err, "derm secret: {e}");
            2
        }
    }
}

fn file_path(ctx: &Ctx<'_>) -> PathBuf {
    secrets::path_for(&ctx.home)
}

/// `add <id> --host <h>... (--env|--file|--keychain) [--note]`.
pub(crate) fn parse_add(args: &[String]) -> Result<Entry, String> {
    let id = args
        .first()
        .filter(|a| !a.starts_with('-'))
        .ok_or("add needs an id")?
        .clone();
    let mut hosts = Vec::new();
    let mut from: Option<From> = None;
    let mut note = None;
    let mut i = 1;
    while i < args.len() {
        let flag = args[i].as_str();
        let val = args
            .get(i + 1)
            .ok_or_else(|| format!("{flag} needs a value"))?
            .clone();
        let set = |from: &mut Option<From>, f: From| {
            if from.is_some() {
                Err("name one of --env, --file, --keychain".to_string())
            } else {
                *from = Some(f);
                Ok(())
            }
        };
        match flag {
            "--host" => hosts.push(val),
            "--env" => set(&mut from, From::Env(val))?,
            "--file" => set(&mut from, From::File(val))?,
            "--keychain" => set(&mut from, From::Keychain(val))?,
            "--note" => note = Some(val),
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }
    let from = from.ok_or("name where the value is read: --env, --file or --keychain")?;
    if hosts.is_empty() {
        return Err("add needs at least one --host".into());
    }
    Ok(Entry {
        id,
        hosts,
        from,
        note,
    })
}

fn add(ctx: &mut Ctx<'_>, args: &[String]) -> Result<(), String> {
    let e = parse_add(args)?;
    let path = file_path(ctx);
    let mut f = secrets::load(&path)?;
    if f.secrets.iter().any(|x| x.id == e.id) {
        return Err(format!("secret {} exists; remove it first", e.id));
    }
    f.secrets.push(e.clone());
    f.check()?;
    // The value must be readable now, as a chat start will read it; it is not
    // kept or shown.
    if let Err(x) = secrets::read_value(&e, ctx.env) {
        let _ = writeln!(ctx.err, "derm secret: warning: the value cannot be read now ({x}); chats fail to start until it can");
    }
    secrets::save(&path, &f)?;
    let _ = writeln!(
        ctx.out,
        "added {} for {} ({})",
        e.id,
        e.hosts.join(", "),
        describe(&e.from)
    );
    let _ = writeln!(
        ctx.out,
        "the agent sees a placeholder in {}",
        secrets::variable(&e)
    );
    if matches!(e.from, From::Env(_)) {
        let _ = writeln!(
            ctx.out,
            "note: a value from the environment stays in the start environment of the process that reads it, which any process of yours can read outside a sandbox (/proc on Linux, ps on macOS); --file or --keychain keeps it out"
        );
    }
    Ok(())
}

fn describe(f: &From) -> String {
    match f {
        From::Env(v) => format!("from ${v}"),
        From::File(p) => format!("from {p}"),
        From::Keychain(k) => format!("from the OS secret store, service {k}"),
    }
}

fn list(ctx: &mut Ctx<'_>) -> Result<(), String> {
    let f = secrets::load(&file_path(ctx))?;
    if f.secrets.is_empty() {
        let _ = writeln!(ctx.out, "no secrets ({})", file_path(ctx).display());
    }
    for e in &f.secrets {
        let note = e
            .note
            .as_deref()
            .map(|n| format!("  # {n}"))
            .unwrap_or_default();
        let _ = writeln!(
            ctx.out,
            "{}  {}  {}  -> ${}{note}",
            e.id,
            e.hosts.join(","),
            describe(&e.from),
            secrets::variable(e)
        );
    }
    Ok(())
}

fn check(ctx: &mut Ctx<'_>) -> Result<(), String> {
    let f = secrets::load(&file_path(ctx))?;
    let mut bad = 0;
    for e in &f.secrets {
        match secrets::read_value(e, ctx.env) {
            Ok(_) => {
                let _ = writeln!(ctx.out, "{}: ok", e.id);
            }
            Err(x) => {
                bad += 1;
                let _ = writeln!(ctx.out, "{}: {x}", e.id);
            }
        }
    }
    let dir = ca::dir_for(&ctx.home);
    match Ca::load(&dir) {
        Ok(Some(c)) if c.valid_for(7) => {
            let _ = writeln!(ctx.out, "CA: ok, {}", short(&c));
        }
        Ok(Some(c)) => {
            bad += 1;
            let _ = writeln!(
                ctx.out,
                "CA: expires within 7 days or has, {}; run derm secret ca create --replace",
                short(&c)
            );
        }
        Ok(None) if !f.secrets.is_empty() => {
            bad += 1;
            let _ = writeln!(ctx.out, "CA: none; run derm secret ca create");
        }
        Ok(None) => {}
        Err(x) => {
            bad += 1;
            let _ = writeln!(ctx.out, "CA: {x}");
        }
    }
    if bad > 0 {
        return Err(format!("{bad} problem(s)"));
    }
    Ok(())
}

fn remove(ctx: &mut Ctx<'_>, args: &[String]) -> Result<(), String> {
    let id = args.first().ok_or("remove needs an id")?;
    let path = file_path(ctx);
    let mut f = secrets::load(&path)?;
    let n = f.secrets.len();
    f.secrets.retain(|e| &e.id != id);
    if f.secrets.len() == n {
        return Err(format!("no secret {id}"));
    }
    secrets::save(&path, &f)?;
    let _ = writeln!(
        ctx.out,
        "removed {id} (its value, wherever it lives, is untouched)"
    );
    Ok(())
}

fn short(c: &Ca) -> String {
    let m = c.meta();
    let (y, mo, d) = ca::civil(m.not_after_day);
    format!(
        "{}, sha256 {}, valid to {y:04}-{mo:02}-{d:02}",
        m.common_name,
        &c.fingerprint()[..16]
    )
}

fn ca_verb(ctx: &mut Ctx<'_>, args: &[String]) -> Result<(), String> {
    let dir = ca::dir_for(&ctx.home);
    match args.first().map(String::as_str) {
        Some("create") => {
            let replace = match args.get(1).map(String::as_str) {
                None => false,
                Some("--replace") => true,
                Some(x) => return Err(format!("unknown flag {x}")),
            };
            let c = Ca::generate()?;
            c.save(&dir, replace)?;
            let _ = writeln!(ctx.out, "created {} in {}", short(&c), dir.display());
            let _ = writeln!(ctx.out, "its key never leaves {} (0600); brokered chats trust it through their own variables, never your system store", dir.join("ca-key.pem").display());
            Ok(())
        }
        Some("show") => match Ca::load(&dir)? {
            Some(c) => {
                let _ = writeln!(ctx.out, "{} ({})", short(&c), dir.join("ca.pem").display());
                Ok(())
            }
            None => Err("no CA; run derm secret ca create".into()),
        },
        Some("remove") => {
            let gone = Ca::remove(&dir)?;
            let _ = writeln!(
                ctx.out,
                "removed {} file(s); brokered chats will not start until a CA is created",
                gone.len()
            );
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

#[cfg(test)]
mod tests;
