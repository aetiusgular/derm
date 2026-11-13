//! `derm init` (wave 6, lane 6B; `plans/toolkit_wave6_plan.md` section 2.1):
//! the light tier in one command, with no root, no daemon and no Docker
//! sign-in. It finds the agents on PATH (`derm status`'s probes), writes the
//! default policy preset if you have no policy, registers derm's gate for
//! each agent through `derm connect` (which shows the change and asks again
//! before it writes, call 3), and says what the light tier does and does not
//! cover. `derm setup` stays the deep path: the daemon, the boundary, the
//! tap, computer use, the shims.
//!
//! ```text
//! derm init [--packages <folder>]   show the plan, ask once, then write
//! derm init --dry-run               show the plan; ask and write nothing
//! ```
//!
//! What it never does: start or install a daemon; run anything as root;
//! write a vendor's sandbox settings (the Standard tier holds only when
//! `derm run` delivers it, note AZ A2 and A4: a project file beats the
//! user's, so a user-file write would be advisory; it names
//! `derm run <agent> --tier standard` instead); change `tier.default` (Tony's
//! call 4 of 12 Nov keeps `whole` until E1); write over a policy you have;
//! run its writes inside a `derm run` chat (an agent must not set its own
//! policy, case 147; the presets deny `derm setup`, and `derm init` is a
//! request for the same deny).

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::gate::locallog;

pub const USAGE: &str = "usage: derm init [--packages <folder>]
       derm init --dry-run

  Finds your agents, writes the default policy if you have none, and
  registers derm's gate per agent (derm connect asks before each write).
  With no daemon, each gate decision is a line in ~/.derm/local/<chat>.jsonl.
  --packages  the folder of a derm release's source or a clone, which holds
              packages/ (the gates that are a plugin, not derm hook)";

/// Questions and output, so tests answer from a script.
pub trait Io {
    fn say(&mut self, text: &str);
    /// A yes or no; anything but a yes is a no.
    fn yes(&mut self, question: &str) -> bool;
}

/// The terminal: the plan on stdout, the question on stderr, the answer one
/// byte at a time from descriptor 0, so `derm connect`'s own question after
/// it reads its own answer.
pub struct Tty;

impl Tty {
    /// Both stdin and stderr are terminals. A pty is not a person (case 89):
    /// this guards against a script, not an agent.
    #[cfg(not(test))]
    pub fn present() -> bool {
        use std::io::IsTerminal;
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }

    /// Never in a test build: `cargo test` from a terminal must not ask.
    #[cfg(test)]
    pub fn present() -> bool {
        false
    }

    #[cfg(unix)]
    fn read_line() -> String {
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        loop {
            // SAFETY: reads one byte into a one-byte buffer from descriptor 0.
            let n = unsafe { libc::read(0, b.as_mut_ptr().cast(), 1) };
            if n != 1 || b[0] == b'\n' || out.len() > 4096 {
                break;
            }
            out.push(b[0]);
        }
        String::from_utf8_lossy(&out).trim().to_string()
    }

    #[cfg(not(unix))]
    fn read_line() -> String {
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
        s.trim().to_string()
    }
}

impl Io for Tty {
    fn say(&mut self, text: &str) {
        println!("{text}");
    }
    fn yes(&mut self, question: &str) -> bool {
        use std::io::Write;
        eprint!("{question} [no] / yes: ");
        let _ = std::io::stderr().flush();
        matches!(Tty::read_line().to_ascii_lowercase().as_str(), "y" | "yes")
    }
}

/// What `derm init` reads and does, so tests stand in a scratch home, fake
/// agents and a fake `derm connect`.
pub struct Ctx<'a> {
    pub home: PathBuf,
    pub io: &'a mut dyn Io,
    /// `derm status`'s agent rows (`watch::status::agents`).
    pub agents: Vec<Value>,
    /// The preset table's rows (`connect::presets::table_json`), for each
    /// agent's `sandbox` (lane 6A's table).
    pub rows: Vec<Value>,
    pub packages: Option<PathBuf>,
    /// What runs derm's gate through a program found on PATH, per agent
    /// (`doctor::stale_registrations`): such a gate decides in TypeScript.
    pub stale: &'a dyn Fn(&str) -> Vec<String>,
    /// Runs `derm connect` with these arguments (it asks on its own).
    pub connect: &'a mut dyn FnMut(&[String]) -> u8,
    pub dry_run: bool,
}

pub fn main(args: &[String]) -> u8 {
    let mut dry_run = false;
    let mut packages = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return 0;
            }
            "--packages" => {
                let Some(p) = args
                    .get(i + 1)
                    .map(PathBuf::from)
                    .filter(|p| p.is_absolute())
                else {
                    eprintln!("derm init: --packages takes an absolute folder\n{USAGE}");
                    return 2;
                };
                packages = Some(p);
                i += 1;
            }
            other => {
                eprintln!("derm init: unknown argument {other:?}\n{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    if !dry_run {
        if let Some(why) = inside_a_chat(&|k| std::env::var_os(k)) {
            eprintln!(
                "derm init: {why}. derm init changes your policy and your agents' settings; run it yourself, in a terminal of your own (derm init --dry-run only shows the plan)"
            );
            return 1;
        }
        if !Tty::present() {
            eprintln!(
                "derm init: asks before it writes and needs a terminal; `derm init --dry-run` shows the plan"
            );
            return 2;
        }
    }
    // HOME on Unix, USERPROFILE on Windows (lane Z's request 1).
    let Some(home) = derm_core::runtime::home_dir().filter(|h| h.is_absolute()) else {
        eprintln!("derm init: HOME is not set to an absolute folder");
        return 1;
    };
    let env = crate::watch::status::Env::real();
    let agents = crate::watch::status::agents(&env, false);
    let stale = |id: &str| crate::doctor::stale_registrations(id, &env);
    let mut connect = |a: &[String]| crate::connect::main(a);
    let mut tty = Tty;
    let mut ctx = Ctx {
        home,
        io: &mut tty,
        agents,
        rows: table_rows(),
        packages,
        stale: &stale,
        connect: &mut connect,
        dry_run,
    };
    run(&mut ctx)
}

/// Why this process looks like it runs inside a `derm run` chat, or `None`
/// (the rule `derm setup` keeps in `setup/mod.rs`).
pub(crate) fn inside_a_chat(var: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> Option<String> {
    for v in ["DERM_CHAT_TOKEN", "DERM_CHAT_TOKEN_FILE"] {
        if var(v).is_some_and(|x| !x.is_empty()) {
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

fn table_rows() -> Vec<Value> {
    let t: Value =
        serde_json::from_str(crate::connect::presets::table_json()).unwrap_or(Value::Null);
    ["harnesses", "planned"]
        .iter()
        .flat_map(|l| {
            t.get(*l)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// One agent's gate, as `derm init` will handle it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Gate {
    /// Registered already.
    Registered,
    /// `derm connect <id> --gate --write` (a `derm hook` gate, or a plugin
    /// with `--packages` given).
    Connect(Vec<String>),
    /// Installed through the agent's own command (Claude Code's and Codex's
    /// plugins): the commands, for you to run; derm runs none of them.
    Own(Vec<String>),
    /// A plugin gate and no `--packages`: the line to run, shown.
    NeedsPackages(String),
    /// No derm gate is built for it.
    None,
}

fn gate_for(agent: &Value, packages: Option<&Path>) -> Gate {
    let id = s(agent, "id");
    if s(&agent["gate"], "status") != "built" {
        return Gate::None;
    }
    if s(agent, "registered") == "yes" {
        return Gate::Registered;
    }
    let table = crate::connect::gate::table().unwrap_or_default();
    let row = table.iter().find(|a| a.agent == id);
    let derm_hook = row
        .and_then(|r| r.command.as_deref())
        .is_some_and(|c| c.contains("{derm}"));
    let own: Option<Vec<String>> = row.and_then(|r| {
        r.steps.iter().find_map(|st| match st {
            // `{version}` as `derm connect` fills it (`connect/gate.rs`
            // `fill_text`): this derm's own version.
            crate::connect::gate::Step::Commands { commands, .. } => Some(
                commands
                    .iter()
                    .map(|c| c.replace("{version}", env!("CARGO_PKG_VERSION")))
                    .collect(),
            ),
            _ => None,
        })
    });
    let words = |extra: &[String]| -> Vec<String> {
        let mut v = vec![id.to_string(), "--gate".to_string()];
        v.extend(extra.iter().cloned());
        v.push("--write".into());
        v
    };
    if derm_hook {
        return Gate::Connect(words(&[]));
    }
    if let Some(commands) = own {
        return Gate::Own(commands);
    }
    let package = gate_package(id);
    match (packages, package) {
        (Some(p), Some(pkg)) => {
            let hook = p.join("packages").join(pkg).display().to_string();
            Gate::Connect(words(&["--hook".into(), hook]))
        }
        (None, Some(pkg)) => Gate::NeedsPackages(format!(
            "derm connect {id} --gate --hook <derm's source>/packages/{pkg} --write"
        )),
        (_, None) => Gate::None,
    }
}

/// The package folder that holds an agent's gate (`connect/gates.json`'s
/// `package`, without its npm scope).
fn gate_package(id: &str) -> Option<String> {
    let t: Value = serde_json::from_str(include_str!("../connect/gates.json")).ok()?;
    t.get("agents")?
        .as_array()?
        .iter()
        .find(|r| s(r, "agent") == id)
        .map(|r| s(r, "package").rsplit('/').next().unwrap_or("").to_string())
        .filter(|p| !p.is_empty())
}

/// How the Standard tier reaches an agent, from lane 6A's sandbox row
/// (`contracts/sandbox.md`): `derm run` delivers it, so `derm init` only says
/// how to start it.
fn standard_line(id: &str, rows: &[Value]) -> Option<String> {
    let row = rows.iter().find(|r| s(r, "id") == id)?;
    let sb = row.get("sandbox").filter(|v| v.is_object())?;
    match s(sb, "via") {
        "settings-flag" | "config-override" => Some(format!(
            "  {id}: start it with `derm run {id} --tier standard`: derm run gives {id} its own sandbox from your policy (a user settings file would not hold: a project file beats it)"
        )),
        "advisory" => Some(format!(
            "  {id}: the Standard tier is not held (a repository file can widen {id}'s sandbox); use the Whole tier, `derm run {id}`"
        )),
        _ => None,
    }
}

/// What an ask becomes with no daemon to answer it, by the preset row's
/// `ask` (note AZ B2).
fn ask_word(agent: &Value) -> &'static str {
    match s(agent, "ask") {
        "own-prompt" => "an ask is the agent's own prompt",
        "approver-or-deny" => "an ask is a deny (no daemon to answer it)",
        _ => "what an ask becomes is not known",
    }
}

/// The whole of `derm init` after its checks. Returns the exit code.
pub fn run(ctx: &mut Ctx) -> u8 {
    let installed: Vec<Value> = ctx
        .agents
        .iter()
        .filter(|a| a.get("onPath").is_some_and(|p| !p.is_null()))
        .cloned()
        .collect();
    let policy_path = ctx.home.join(".derm").join("policy.json");
    let have_policy = std::fs::symlink_metadata(&policy_path).is_ok();
    let preset = if have_policy {
        None
    } else {
        crate::setup::presets::all()
            .ok()
            .and_then(|all| all.into_iter().find(|p| p.default))
    };

    // The plan.
    let mut plan = vec!["derm init: the light tier (no daemon, no root)".to_string()];
    plan.push(String::new());
    plan.push("Policy:".into());
    match (&preset, have_policy) {
        (_, true) => plan.push(format!("  kept: {}", policy_path.display())),
        (Some(p), false) => plan.push(format!(
            "  {}: the {} preset ({})",
            policy_path.display(),
            p.name,
            p.summary
        )),
        (None, false) => plan.push(format!(
            "  none, and no preset could be read: with no {} every call asks",
            policy_path.display()
        )),
    }
    plan.push(String::new());
    let mut gates: Vec<(String, Gate)> = Vec::new();
    let mut not_covered: Vec<String> = Vec::new();
    if installed.is_empty() {
        plan.push("Agents: none derm knows was found on PATH.".into());
    } else {
        plan.push("Agents found on PATH:".into());
        for a in &installed {
            let id = s(a, "id").to_string();
            let gate = gate_for(a, ctx.packages.as_deref());
            let what = match &gate {
                Gate::Registered => "derm's gate registered".to_string(),
                Gate::Connect(args) => format!("derm connect {}", args.join(" ")),
                Gate::Own(commands) => format!(
                    "its plugin installs through its own command, which you run: {}",
                    commands.join(" && ")
                ),
                Gate::NeedsPackages(line) => {
                    format!("needs --packages, or run `{line}` yourself")
                }
                Gate::None => "no derm gate for it".to_string(),
            };
            let fail = if s(a, "failMode").starts_with("open") {
                "; its gate fails open"
            } else {
                ""
            };
            plan.push(format!(
                "  {:<14} {}: {what}; {}{fail}",
                id,
                s(a, "name"),
                ask_word(a)
            ));
            // Note AZ, S1: these decide outside derm's Rust gate, so their
            // calls reach neither the light tier's log nor taint.
            if id == "amp" {
                not_covered.push(format!(
                    "  {id}: its plugin decides in TypeScript (no light-tier log, no taint)"
                ));
            }
            for p in (ctx.stale)(&id) {
                not_covered.push(format!("  {id}: {p}"));
            }
            gates.push((id, gate));
        }
    }
    if !not_covered.is_empty() {
        plan.push(String::new());
        plan.push("Not covered by the light tier:".into());
        plan.extend(not_covered);
    }
    let standard: Vec<String> = installed
        .iter()
        .filter_map(|a| standard_line(s(a, "id"), &ctx.rows))
        .collect();
    if !standard.is_empty() {
        plan.push(String::new());
        plan.push("The Standard tier (the agent's own sandbox from your policy), opt-in:".into());
        plan.extend(standard);
    }
    plan.push(String::new());
    plan.push(format!(
        "The log: with no daemon, each gate decision is a line in {}. The agent can write that file: an edited, dropped or reordered line shows (derm audit verify); a cut at the end or a whole rewrite shows only against an anchor (derm audit anchor). For the daemon, a boundary and the OS's own records, run derm setup.",
        locallog::folder(&ctx.home).join("<chat>.jsonl").display()
    ));
    ctx.io.say(&plan.join("\n"));

    let todo = preset.is_some() || gates.iter().any(|(_, g)| matches!(g, Gate::Connect(_)));
    if ctx.dry_run {
        ctx.io
            .say("\nA dry run: nothing is asked and nothing is written.");
        return 0;
    }
    if !todo {
        ctx.io.say("\nNothing to write.");
        return 0;
    }
    if !ctx
        .io
        .yes("\nGo ahead? derm connect asks again before each agent's write")
    {
        ctx.io.say("Nothing was written.");
        return 0;
    }

    let mut changed: Vec<String> = Vec::new();
    let mut problems = 0u8;
    if let Some(p) = preset {
        let text = crate::setup::presets::policy_text(&p);
        match crate::setup::presets::matcher_reads(&text)
            .and_then(|()| write_new_private(&policy_path, &text))
        {
            Ok(()) => changed.push(format!("{}: the {} preset", policy_path.display(), p.name)),
            Err(e) => {
                problems += 1;
                ctx.io.say(&format!("Policy not written: {e}"));
            }
        }
    }
    for (id, gate) in &gates {
        let Gate::Connect(args) = gate else {
            continue;
        };
        match (ctx.connect)(args) {
            0 => changed.push(format!("{id}: derm's gate, through derm connect")),
            c => ctx.io.say(&format!(
                "  derm connect {id} --gate exited {c}; nothing more was done for it."
            )),
        }
    }
    if changed.is_empty() {
        ctx.io.say("\nNothing was written.");
    } else {
        let lines: Vec<String> = changed.iter().map(|c| format!("  {c}")).collect();
        ctx.io.say(&format!("\nWritten:\n{}", lines.join("\n")));
    }
    if problems > 0 {
        1
    } else {
        0
    }
}

/// Writes `text` to `path`, which must not exist yet, 0600, in a `~/.derm`
/// of yours that no one else can write (made 0700). Never over a file and
/// never through a link.
fn write_new_private(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    let dir = path.parent().ok_or("no folder")?;
    own_derm_folder(dir)?;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = o
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(unix)]
fn own_derm_folder(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let made = match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !m.file_type().is_dir() {
        return Err(format!(
            "{} is not a folder (a link is refused)",
            dir.display()
        ));
    }
    if m.uid() != derm_core::platform::effective_user() {
        return Err(format!("{} belongs to another user", dir.display()));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!(
            "{} can be written by others; fix it with chmod 700 first",
            dir.display()
        ));
    }
    if made || m.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn own_derm_folder(dir: &Path) -> Result<(), String> {
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let m =
                std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            if m.is_dir() && !m.file_type().is_symlink() {
                Ok(())
            } else {
                Err(format!("{} is not a folder", dir.display()))
            }
        }
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}
