//! `derm setup` (wave 5, lane W; `plans/toolkit_universal_plan.md` lane W):
//! find the installed agents, then one question per switch: the policy (a
//! preset, `setup/presets/`), what `derm run` does when no boundary is
//! available and no one can answer, the tap, the content switch and its
//! retention, a model server of your own for the tap, computer use, the
//! pre-install check, derm's gate per agent, and the launch route (a shim per
//! agent on `PATH`; Orca's command override printed). Then it writes what was
//! answered and prints every change.
//!
//! ```text
//! derm setup [--packages <folder>]   ask, one question per switch, then write
//! derm setup --dry-run               say what it found and would ask; write nothing
//! derm setup sandbox                 sbx and srt per agent; sbx login and policy init on a yes
//! derm setup presets                 list the policy presets
//! derm setup preset <name>           print a preset's policy
//! ```
//!
//! What it never does: write a project file, a managed file or a shell's
//! startup file; run an installer (it prints the line); write a policy this
//! derm's matcher cannot read (every call would ask); run inside a `derm run`
//! chat (an agent must not set its own policy; the gate and the boundary are
//! what stand against an agent, case 89, and srt keeps `~/.derm` read-only).
//! Writes go to `~/.derm/policy.json`, `~/.derm/settings.json` and
//! `~/.derm/bin/`, 0600 (shims 0700) in a 0700 folder, old files kept in
//! `~/.derm/backups/`. A gate is registered by `derm connect`, which shows
//! the change and asks again before it writes.

mod ask;
mod files;
pub(crate) mod presets;
mod settings;
mod shims;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use ask::Ask;

pub const USAGE: &str = "usage: derm setup [--packages <folder>]
       derm setup --dry-run
       derm setup sandbox
       derm setup presets
       derm setup preset <name>

  --packages  the folder of a derm release's source or a clone, which holds
              packages/ (the gates derm connect registers)";

/// Everything a run of `derm setup` reads from or does to the outside, so
/// tests can stand in a scratch home, a script of answers and fake agents.
pub struct Ctx<'a> {
    pub home: PathBuf,
    pub ask: &'a mut dyn Ask,
    /// `derm status`'s agent rows (`watch::status::agents`).
    pub agents: Vec<Value>,
    /// The preset table's rows, `executables` merged in.
    pub rows: Vec<Value>,
    /// derm's own path, for the shims.
    pub derm: PathBuf,
    pub packages: Option<PathBuf>,
    /// Whether this derm's matcher reads a policy text (`presets::matcher_reads`).
    pub matcher: fn(&str) -> Result<(), String>,
    /// Runs `derm connect` with these arguments (it asks on its own).
    pub connect: &'a mut dyn FnMut(&[String]) -> u8,
    pub dry_run: bool,
    /// What was written, for the summary.
    pub changed: Vec<String>,
}

pub fn main(args: &[String]) -> u8 {
    match args.first().map(String::as_str) {
        Some("presets") if args.len() == 1 => return list_presets(),
        Some("preset") if args.len() == 2 => return print_preset(&args[1]),
        Some("sandbox") if args.len() == 1 => return sandbox_main(),
        Some("-h" | "--help") => {
            println!("{USAGE}");
            return 0;
        }
        _ => {}
    }
    let mut dry_run = false;
    let mut packages = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry_run = true,
            "--packages" => {
                let Some(p) = args.get(i + 1).filter(|p| p.starts_with('/')) else {
                    eprintln!("derm setup: --packages takes an absolute folder\n{USAGE}");
                    return 2;
                };
                packages = Some(PathBuf::from(p));
                i += 1;
            }
            other => {
                eprintln!("derm setup: unknown argument {other:?}\n{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    if let Some(why) = inside_a_chat(&|k| std::env::var_os(k)) {
        eprintln!(
            "derm setup: {why}. derm setup changes your policy and settings; run it yourself, in a terminal of your own"
        );
        return 1;
    }
    // A person answers; a script or an agent's tool has no terminal (and a
    // pty is not a person, case 89: the gate and the boundary are what stand
    // against an agent).
    if !dry_run && !ask::Tty::present() {
        eprintln!(
            "derm setup: asks one question per switch and needs a terminal; `derm setup --dry-run` shows what it would ask"
        );
        return 2;
    }
    let Some(home) = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
    else {
        eprintln!("derm setup: HOME is not set");
        return 1;
    };
    let derm = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("derm"));
    let env = crate::watch::status::Env::real();
    let agents = crate::watch::status::agents(&env, false);
    let rows = table_rows();
    let mut tty = ask::Tty;
    let mut connect = |a: &[String]| crate::connect::main(a);
    let mut ctx = Ctx {
        home,
        ask: &mut tty,
        agents,
        rows,
        derm,
        packages,
        matcher: presets::matcher_reads,
        connect: &mut connect,
        dry_run,
        changed: Vec::new(),
    };
    run(&mut ctx)
}

/// Why this process looks like it runs inside a `derm run` chat, or `None`.
fn inside_a_chat(var: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> Option<String> {
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

fn list_presets() -> u8 {
    match presets::all() {
        Ok(all) => {
            for p in all {
                println!(
                    "{}{}\n  {}\n",
                    p.name,
                    if p.default { " (the default)" } else { "" },
                    p.summary
                );
            }
            0
        }
        Err(e) => {
            eprintln!("derm setup: a preset is broken: {e}");
            1
        }
    }
}

fn print_preset(name: &str) -> u8 {
    match presets::find(name) {
        Some(p) => {
            print!("{}", presets::policy_text(&p));
            0
        }
        None => {
            eprintln!("derm setup: no preset {name:?}; `derm setup presets` lists them");
            2
        }
    }
}

/// The agents found on PATH, by id.
fn installed(agents: &[Value]) -> Vec<String> {
    agents
        .iter()
        .filter(|a| a.get("onPath").is_some_and(|p| !p.is_null()))
        .filter_map(|a| a.get("id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// The whole of `derm setup` after its checks: what it found, the questions,
/// the writes, the summary. Returns the exit code.
pub fn run(ctx: &mut Ctx) -> u8 {
    let installed = installed(&ctx.agents);
    say_found(ctx, &installed);
    if ctx.dry_run {
        ctx.ask
            .say("A dry run: nothing is asked and nothing is written.");
    } else {
        ctx.ask.say("One question per switch. Return takes the choice in [brackets], which changes nothing or is the safe one.\n");
    }

    let backups = ctx.home.join(".derm").join("backups");
    let mut problems = 0u8;

    // 1. The policy.
    let policy_path = ctx.home.join(".derm").join("policy.json");
    let chosen = ask_policy(ctx, &policy_path);

    // 2 to 7. The settings file.
    let settings_path = settings::path_for(&ctx.home);
    let old = match settings::read(&settings_path) {
        Ok(o) => o,
        Err(e) => {
            ctx.ask.say(&format!(
                "Your settings file {e}; derm's readers ignore it now, and derm setup will not write over it: fix it (chmod 600) or move it away, then run derm setup again."
            ));
            None
        }
    };
    let mut doc = settings::start(old.clone());
    ask_settings(ctx, &mut doc);

    // 8. The gate per agent.
    ask_gates(ctx, &installed);

    // 9. The launch route.
    let shim_plan = shims::plan(&ctx.rows, &installed);
    let write_shims = ask_shims(ctx, &shim_plan);

    if ctx.dry_run {
        return 0;
    }

    // The writes, after every answer.
    if let Some(p) = chosen {
        let text = presets::policy_text(&p);
        match (ctx.matcher)(&text) {
            Err(e) => {
                problems += 1;
                ctx.ask.say(&format!(
                    "Not written: this derm's matcher refuses the {} preset ({e}). It holds command rules (contracts/policy.md section 7), which this derm does not read yet; with the file in place every call would ask. Your policy is unchanged.",
                    p.name
                ));
            }
            Ok(()) => match files::write_private(&policy_path, &text, &backups) {
                Ok(b) => ctx.changed.push(format!(
                    "{}: the {} preset{}",
                    policy_path.display(),
                    p.name,
                    b.map(|b| format!(" (the old file is {})", b.display()))
                        .unwrap_or_default()
                )),
                Err(e) => {
                    problems += 1;
                    ctx.ask.say(&format!("Not written: {e}"));
                }
            },
        }
    }
    let new_text = settings::text(&doc);
    let old_text = old.map(|o| settings::text(&o));
    if old_text.as_deref() != Some(new_text.as_str()) {
        match settings::problem(&new_text) {
            Err(e) => {
                problems += 1;
                ctx.ask.say(&format!(
                    "Not written: the settings would fail the schema ({e})."
                ));
            }
            Ok(()) => match files::write_private(&settings_path, &new_text, &backups) {
                Ok(b) => ctx.changed.push(format!(
                    "{}{}",
                    settings_path.display(),
                    b.map(|b| format!(" (the old file is {})", b.display()))
                        .unwrap_or_default()
                )),
                Err(e) => {
                    problems += 1;
                    ctx.ask.say(&format!("Not written: {e}"));
                }
            },
        }
    }
    if write_shims {
        let dir = shims::folder(&ctx.home);
        let mut wrote = Vec::new();
        for (exe, id) in &shim_plan {
            let path = dir.join(exe);
            match shims::text(exe, id, &ctx.derm, &dir)
                .and_then(|t| files::write_shim(&path, &t, shims::MARKER))
            {
                Ok(true) => wrote.push(exe.clone()),
                Ok(false) => {}
                Err(e) => {
                    problems += 1;
                    ctx.ask.say(&format!("Shim not written: {e}"));
                }
            }
        }
        if !wrote.is_empty() {
            ctx.changed
                .push(format!("{}: shims for {}", dir.display(), wrote.join(", ")));
        }
        ctx.ask.say(&format!(
            "The shims run only when {} comes before the agents' own folders on PATH. derm does not edit your shell's startup file; add this line to it yourself:\n  {}",
            dir.display(),
            shims::path_line(&dir)
        ));
    }

    // The summary.
    if ctx.changed.is_empty() {
        ctx.ask.say("\nNothing was written.");
    } else {
        ctx.ask.say("\nWritten:");
        let lines: Vec<String> = ctx.changed.iter().map(|c| format!("  {c}")).collect();
        ctx.ask.say(&lines.join("\n"));
    }
    if problems > 0 {
        1
    } else {
        0
    }
}

fn say_found(ctx: &mut Ctx, installed: &[String]) {
    if installed.is_empty() {
        ctx.ask
            .say("derm setup: no agent derm knows was found on PATH.");
        return;
    }
    let mut lines = vec!["derm setup: agents found on PATH".to_string()];
    for a in &ctx.agents {
        if !installed.iter().any(|i| i == s(a, "id")) {
            continue;
        }
        let gate = match (s(&a["gate"], "status"), s(a, "registered")) {
            ("built", "yes") => "derm's gate registered".to_string(),
            ("built", r) => format!("derm's gate built, registered: {r}"),
            ("", _) => "no derm gate".to_string(),
            (st, _) => format!("derm's gate {st}"),
        };
        let fail = if s(a, "failMode").starts_with("open") {
            ", fails open"
        } else {
            ""
        };
        lines.push(format!(
            "  {:<14} {} ({gate}{fail})",
            s(a, "id"),
            s(a, "name")
        ));
    }
    ctx.ask.say(&lines.join("\n"));
}

fn ask_policy(ctx: &mut Ctx, path: &Path) -> Option<presets::Preset> {
    let all = match presets::all() {
        Ok(a) => a,
        Err(e) => {
            ctx.ask.say(&format!(
                "The presets are broken ({e}); no policy is offered."
            ));
            return None;
        }
    };
    let have = std::fs::symlink_metadata(path).is_ok();
    let mut text = String::from(
        "\nPolicy (~/.derm/policy.json), what each agent's gate allows, asks about or denies:",
    );
    for p in &all {
        text.push_str(&format!(
            "\n  {}{}: {}",
            p.name,
            if p.default { " (default)" } else { "" },
            p.summary
        ));
    }
    text.push_str("\n  derm's sbx kit puts the gate in the VM only when you have a usable policy (lane T); there every ask is a deny.");
    ctx.ask.say(&text);
    let mut choices: Vec<&str> = Vec::new();
    if have {
        choices.push("keep");
    }
    choices.extend(all.iter().map(|p| p.name.as_str()));
    if !have {
        choices.push("none");
    }
    if ctx.dry_run {
        ctx.ask.say(if have {
            "Would ask: keep your policy, or replace it with a preset."
        } else {
            "Would ask: write a preset (workspace-write first). With no policy every call not on the reject list asks."
        });
        return None;
    }
    let q = if have {
        "You have a policy. Keep it, or replace it with a preset (the old one is kept in ~/.derm/backups)?"
    } else {
        "You have no policy, so every call asks. Write one?"
    };
    let answer = ctx.ask.choose(q, &choices);
    all.into_iter().find(|p| p.name == answer)
}

fn ask_settings(ctx: &mut Ctx, doc: &mut serde_json::Map<String, Value>) {
    let get = |doc: &serde_json::Map<String, Value>, sec: &str, key: &str| -> Value {
        doc.get(sec)
            .and_then(|s| s.get(key))
            .cloned()
            .unwrap_or(Value::Null)
    };
    if ctx.dry_run {
        ctx.ask.say("Would ask, each kept as it is on Return: what derm run does with no boundary and no one to ask (it stops); the tap (on); content capture (off); a model server of your own for the tap; computer use (off); the pre-install check (off).");
        return;
    }

    // What derm run does when no boundary is available and no one can answer.
    let pre = get(doc, "boundary", "preAnswer");
    ctx.ask.say(&format!(
        "\nWhen no boundary (sbx, srt) is available, derm run asks whether to run as you. With no one at a terminal (a script, a scheduled run) it stops, unless a pre-answer says otherwise. Now: {}.",
        if pre.is_string() { pre.as_str().unwrap_or("").to_string() } else { "not set (stop)".into() }
    ));
    match ctx
        .ask
        .choose("Pre-answer for scripts?", &["leave", "stop", "run-as-you"])
        .as_str()
    {
        "stop" => settings::set(doc, "boundary", "preAnswer", json!("stop")),
        "run-as-you" => {
            ctx.ask.say("A script's chat will run with your full rights and no boundary; derm status shows the pre-answer.");
            settings::set(doc, "boundary", "preAnswer", json!("run-as-you"))
        }
        _ => {}
    }

    // The tap.
    let on = get(doc, "tap", "on").as_bool().unwrap_or(true);
    ctx.ask.say(&format!(
        "\nThe model tap sits between each agent and its model on this machine and records every tool call the model asks for (names, hashes, sizes, paths), never your keys. Now: {}.",
        if on { "on" } else { "off" }
    ));
    let first = if on { "on" } else { "off" };
    let second = if on { "off" } else { "on" };
    let a = ctx.ask.choose("The tap?", &[first, second]);
    if a != first || doc.get("tap").and_then(|t| t.get("on")).is_some() {
        settings::set(doc, "tap", "on", json!(a == "on"));
    }

    // Content capture.
    let days = get(doc, "content", "retentionDays").as_u64();
    let content_on = get(doc, "content", "on").as_bool().unwrap_or(false);
    ctx.ask.say(&format!(
        "\nContent capture keeps prompts, tool arguments, results and the model's text on this machine only, 0600, for 1 to 7 days, then deletes them. Now: {}.",
        if content_on { format!("on, {} days", days.unwrap_or(0)) } else { "off".into() }
    ));
    let a = ctx.ask.choose(
        "Content capture? (off, or days to keep)",
        &["keep", "off", "1", "2", "3", "4", "5", "6", "7"],
    );
    match a.as_str() {
        "off" => {
            doc.insert("content".into(), json!({"on": false}));
        }
        "keep" => {}
        d => {
            if let Ok(n) = d.parse::<u64>() {
                doc.insert("content".into(), json!({"on": true, "retentionDays": n}));
            }
        }
    }

    // A model server of your own (lane S's request 6; case 113).
    ctx.ask.say("\nThe tap forwards only to the model hosts it knows. A server you run (on this machine or your own box) can be added by name; nothing else adds one.");
    if ctx
        .ask
        .choose("Add a model server of your own?", &["no", "yes"])
        == "yes"
    {
        let key = ctx
            .ask
            .line("Its name (a-z, 0-9 and -)")
            .to_ascii_lowercase();
        let base = ctx
            .ask
            .line("Its base URL (https://..., or http://... for this machine or your own box)");
        let local = ctx.ask.choose(
            "Is it on this machine or a box of your own?",
            &["no", "yes"],
        ) == "yes";
        match settings::upstream_problem(&key, &base, local) {
            Some(why) => ctx.ask.say(&format!("Not added: {why}.")),
            None => {
                let mut ups = doc
                    .get("tap")
                    .and_then(|t| t.get("upstreams"))
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                if ups.len() >= 16 && !ups.contains_key(&key) {
                    ctx.ask.say("Not added: 16 servers at most.");
                } else {
                    ups.insert(key.clone(), json!({"base": base, "local": local}));
                    settings::set(doc, "tap", "upstreams", Value::Object(ups));
                    ctx.ask.say(&format!(
                        "Added {key}. derm's tap reads it at its next start; until integration w5's close wires it, derm run still refuses a base URL it did not set (case 113)."
                    ));
                }
            }
        }
    }

    // Computer use (lane U's R6).
    let cu = get(doc, "computerUse", "on").as_bool().unwrap_or(false);
    ctx.ask.say(&format!(
        "\nComputer use lets an agent see and drive apps on this machine through derm's computer_use tool, each app approved on a card. Off by default; until the second-user box test passes, keep it off on any machine an agent can reach as you. Now: {}.",
        if cu { "on" } else { "off" }
    ));
    let a = ctx.ask.choose(
        "Computer use?",
        &[if cu { "on" } else { "off" }, if cu { "off" } else { "on" }],
    );
    if (a == "on") != cu || doc.get("computerUse").is_some() {
        settings::set(doc, "computerUse", "on", json!(a == "on"));
        if (a == "on") != cu {
            ctx.ask.say("It takes effect when the daemon restarts (systemctl --user restart derm-daemon, or the launchd agent).");
        }
    }

    // The pre-install check (lane X; call 10).
    let check = get(doc, "installs", "check").as_bool().unwrap_or(false);
    ctx.ask.say(&format!(
        "\nThe pre-install check looks up each new package before an agent installs it: a name not in its registry or a known-malicious one is denied. It sends package names and versions to the project's registry and to api.osv.dev, the daemon's only calls out besides the tap. Every new package asks either way. Now: {}.",
        if check { "on" } else { "off" }
    ));
    let a = ctx.ask.choose(
        "The pre-install check?",
        &[
            if check { "on" } else { "off" },
            if check { "off" } else { "on" },
        ],
    );
    if (a == "on") != check || doc.get("installs").and_then(|i| i.get("check")).is_some() {
        settings::set(doc, "installs", "check", json!(a == "on"));
    }
}

fn ask_gates(ctx: &mut Ctx, installed: &[String]) {
    let todo: Vec<Value> = ctx
        .agents
        .iter()
        .filter(|a| installed.iter().any(|i| i == s(a, "id")))
        .filter(|a| s(&a["gate"], "status") == "built" && s(a, "registered") != "yes")
        .cloned()
        .collect();
    if todo.is_empty() {
        return;
    }
    ctx.ask
        .say("\nderm's gate is built for these agents and not registered:");
    for a in &todo {
        let id = s(a, "id").to_string();
        let package = gate_package(&id);
        let hook = match (&ctx.packages, &package) {
            (Some(p), Some(pkg)) => Some(p.join("packages").join(pkg)),
            _ => None,
        };
        let line = format!(
            "derm connect {id} --gate --hook {} --write",
            hook.as_ref()
                .map(|h| h.display().to_string())
                .unwrap_or_else(|| format!(
                    "<derm's source>/packages/{}",
                    package.clone().unwrap_or_default()
                ))
        );
        if ctx.dry_run {
            ctx.ask.say(&format!(
                "  {} ({id}): would ask, then run `{line}`",
                s(a, "name")
            ));
            continue;
        }
        let q = format!("Register derm's gate in {} ({id})? derm connect shows the change and asks again before it writes", s(a, "name"));
        if ctx.ask.choose(&q, &["no", "yes"]) != "yes" {
            continue;
        }
        let Some(hook) = hook else {
            ctx.ask.say(&format!(
                "  derm setup does not know where derm's packages are: run it again with --packages <folder of a release's source or a clone>, or run `{line}` yourself."
            ));
            continue;
        };
        let args: Vec<String> = [id.as_str(), "--gate", "--hook"]
            .iter()
            .map(|x| x.to_string())
            .chain([hook.display().to_string(), "--write".into()])
            .collect();
        let code = (ctx.connect)(&args);
        if code == 0 {
            ctx.changed
                .push(format!("{id}: derm's gate, through derm connect"));
        } else {
            ctx.ask.say(&format!(
                "  derm connect {id} --gate exited {code}; nothing more was done for it."
            ));
        }
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

fn ask_shims(ctx: &mut Ctx, plan: &[(String, String)]) -> bool {
    if plan.is_empty() {
        return false;
    }
    let names: Vec<String> = plan.iter().map(|(e, id)| format!("{e} ({id})")).collect();
    let ids: Vec<&String> = {
        let mut v: Vec<&String> = plan.iter().map(|(_, id)| id).collect();
        v.dedup();
        v
    };
    let mut orca = String::from("Orca: set each agent's command override in Orca's settings to:");
    for id in &ids {
        orca.push_str(&format!("\n  {id}: {}", shims::orca_override(id)));
    }
    ctx.ask.say(&format!(
        "\nAn agent started from a plain terminal is not seen by derm's tap, gate records or boundary. A shim in {} runs each through `derm run`: {}.\n{orca}",
        shims::folder(&ctx.home).display(),
        names.join(", ")
    ));
    if ctx.dry_run {
        ctx.ask.say("Would ask: write the shims.");
        return false;
    }
    ctx.ask.choose("Write the shims?", &["no", "yes"]) == "yes"
}

// ---------------------------------------------------------------- sandbox

fn sandbox_main() -> u8 {
    if let Some(why) = inside_a_chat(&|k| std::env::var_os(k)) {
        eprintln!("derm setup sandbox: {why}; run it yourself, in a terminal of your own");
        return 1;
    }
    let env = crate::watch::status::Env::real();
    let installed = installed(&crate::watch::status::agents(&env, false));
    let mut tty = ask::Tty;
    sandbox(&mut tty, &installed, &env.path, ask::Tty::present())
}

/// `derm setup sandbox`: for each installed agent `derm run` knows, whether
/// sbx and srt can run it here now and the line that would install the one
/// that cannot (lane T's `boundary::availability`, the same probes `derm
/// run` makes). derm prints install lines and runs none of them. On a yes
/// at a terminal it runs `sbx login` and `sbx policy init` (SB8), each shown
/// first.
fn sandbox(ask: &mut dyn Ask, installed: &[String], path: &str, person: bool) -> u8 {
    let mut lines = Vec::new();
    let mut sbx_missing = false;
    for id in installed {
        let Some([sbx, srt]) = crate::run::boundary::availability(id) else {
            continue;
        };
        for (r, name) in [(sbx, "sbx"), (srt, "srt")] {
            match r {
                Ok(()) => lines.push(format!("  {id:<14} {name}: usable")),
                Err(reason) => {
                    if name == "sbx" {
                        sbx_missing = true;
                    }
                    let install = reason
                        .install
                        .map(|i| format!("\n{:<20}to install: {i}", ""))
                        .unwrap_or_default();
                    lines.push(format!("  {id:<14} {name}: {}{install}", reason.why));
                }
            }
        }
    }
    if lines.is_empty() {
        ask.say("derm setup sandbox: no installed agent that derm run knows.");
        return 0;
    }
    ask.say(&format!(
        "Boundaries per agent (derm run picks sbx, then srt, and asks when neither is usable):\n{}",
        lines.join("\n")
    ));
    ask.say(
        "derm prints install lines and runs none of them: an install needs your own sudo or brew.",
    );
    let Some(sbx) = crate::watch::status::find_on_path("sbx", path) else {
        return 0;
    };
    if !person {
        return 0;
    }
    for (args, why) in [
        (
            vec!["login"],
            "sbx needs you signed in to Docker. Run `sbx login` now?",
        ),
        (
            vec!["policy", "init"],
            "sbx asks for its network policy once per machine (SB8). Run `sbx policy init` now?",
        ),
    ] {
        if sbx_missing && args == ["policy", "init"] {
            continue;
        }
        let shown = format!("{} {}", sbx.display(), args.join(" "));
        if ask.choose(&format!("{why} ({shown}, as you)"), &["no", "yes"]) != "yes" {
            continue;
        }
        let status = std::process::Command::new(&sbx)
            .args(&args)
            .env("SBX_NO_TELEMETRY", "1")
            .status();
        ask.say(&match status {
            Ok(s) if s.success() => format!("{shown}: done"),
            Ok(s) => format!("{shown}: exited {}", s.code().unwrap_or(-1)),
            Err(e) => format!("{shown}: {e}"),
        });
    }
    0
}
