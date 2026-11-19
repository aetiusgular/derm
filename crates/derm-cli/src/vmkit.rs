//! `derm kit register <agent>`: derm's gate registered for one agent inside
//! derm's sbx VM, by derm itself (19 Nov 2026; note BZ section 4.3 and
//! `plans/parallel/tk_kit_rust.md`).
//!
//! derm's sbx kits for Claude Code, Copilot CLI, Droid, Cursor and Kiro
//! carry a Node and derm's TypeScript hook, and register that hook with a
//! Node script (`packaging/sbx-kit/register-hooks.mjs`,
//! `register-agent.mjs`). With `DERM_SBX_KIT=rust` the kit carries a Linux
//! derm instead, as Codex's kit does, and its install script runs this
//! command to write the registration: `derm hook <agent> <event>` by derm's
//! own absolute path.
//!
//! One source for each entry:
//! - Claude Code: [`crate::run::claude_gate::hooks`], the entries `derm run
//!   claude-code` puts in its own `--settings` on a host (exec form, no
//!   shell, `onFailure: "block"`), merged into Claude Code's managed
//!   settings, which are root's (`/etc/claude-code/managed-settings.json`
//!   on Linux: code.claude.com settings docs, "Settings files").
//! - The four command-hook agents: their rows of `connect/gates.json`, the
//!   table `derm connect <agent> --gate` writes from, applied with the same
//!   functions ([`gate::add_to_array`], [`gate::owned`]).
//!
//! `derm connect --gate --write` asks on the terminal before it writes, so
//! that a script or an agent cannot answer for the person (case 89). A
//! kit's install step has no terminal. This command writes without asking,
//! and so it runs in one place only: where derm's kit wrote its VM marker,
//! a file root owns in a folder root owns ([`daemon::vm_marker`], the check
//! the gate's VM route rests on, W5C-S2). A process on a host cannot make
//! that marker without being root there. Inside the VM the agent has sudo
//! (Docker's security page; lane T's P4-O1), so nothing here holds against
//! an agent that sets out to change its own registration, as nothing in the
//! kit does.

// The planning half is used on Unix only, where the kit is built and run.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};

use crate::connect::gate::{self, Outcome, Step, Vars};
use crate::connect::presets::Env;

pub const USAGE: &str = "usage: derm kit register <claude-code|copilot-cli|droid|cursor|kiro> [--home <the agent's home>]\n(run by derm's sbx kit inside its VM; it refuses anywhere else)";

/// The agent whose registration is root's, in its managed settings.
pub(crate) const CLAUDE: &str = "claude-code";
/// The agents whose registration sits in their own config under their home.
pub(crate) const HOME_AGENTS: &[&str] = &["copilot-cli", "droid", "cursor", "kiro"];
/// Claude Code's managed settings on Linux.
pub(crate) const MANAGED: &str = "/etc/claude-code/managed-settings.json";

/// No variable moves a file in the VM: the kit names the home itself.
struct NoEnv;
impl Env for NoEnv {
    fn var(&self, _key: &str) -> Option<String> {
        None
    }
}

/// One file a registration holds, and its new text when it must change.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Planned {
    pub path: PathBuf,
    pub text: Option<String>,
}

/// Claude Code's managed settings with derm's two hook entries added.
/// Every other key and every other hook is kept; a second run changes
/// nothing. Refused when the file is not a JSON object, its `hooks` is not
/// an object or an event's value is not a list, rather than replace what
/// another kit wrote (`register-hooks.mjs`, `merge`). Object keys come out
/// sorted: serde_json's map is ordered by key in this build.
pub(crate) fn plan_claude(derm: &str, file: &Path, have: Option<&str>) -> Result<Planned, String> {
    let shown = file.display();
    let mut root: serde_json::Value = match have.map(str::trim) {
        None | Some("") => serde_json::json!({}),
        Some(t) => serde_json::from_str(t).map_err(|_| format!("{shown} is not JSON"))?,
    };
    let obj = root
        .as_object_mut()
        .ok_or_else(|| format!("{shown} does not hold a JSON object"))?;
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| format!("\"hooks\" in {shown} is not an object"))?;
    let ours = crate::run::claude_gate::hooks(derm, None);
    let ours = ours.as_object().ok_or("internal: no hook entries")?;
    for (event, add) in ours {
        let list = hooks
            .entry(event.clone())
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .ok_or_else(|| format!("\"hooks.{event}\" in {shown} is not a list"))?;
        for e in add.as_array().ok_or("internal: an event with no list")? {
            if !list.contains(e) {
                list.push(e.clone());
            }
        }
    }
    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(&root).map_err(|e| format!("internal: {e}"))?
    );
    Ok(Planned {
        path: file.to_path_buf(),
        text: (have != Some(text.as_str())).then_some(text),
    })
}

/// The registration of one command-hook agent under `home`, from its row of
/// `gates.json`: each file with its new text. `read` gives a file's text,
/// or `None` when it is not there.
pub(crate) fn plan_agent(
    agent: &str,
    derm: &str,
    home: &Path,
    read: &dyn Fn(&Path) -> Result<Option<String>, String>,
) -> Result<Vec<Planned>, String> {
    if !HOME_AGENTS.contains(&agent) {
        return Err(format!("derm's kit has no registration for `{agent}`"));
    }
    let table = gate::table_for("linux")?;
    let row = table
        .iter()
        .find(|a| a.agent == agent)
        .ok_or_else(|| format!("gates.json: no row for {agent}"))?;
    let line = row
        .command
        .as_deref()
        .filter(|t| t.contains("{derm}"))
        .ok_or_else(|| format!("gates.json: {agent}'s row does not run derm"))?;
    let version = env!("CARGO_PKG_VERSION").to_string();
    let vars = Vars {
        command: Some(gate::fill_text(line, "node", None, None, &version, derm)),
        version,
        ..Vars::default()
    };
    // A file that would shadow derm's entry (Droid's hooks.json merges over
    // its settings.json per event: the row's note).
    for p in &row.refuse_if_exists {
        let f = home.join(p.strip_prefix("~/").unwrap_or(p));
        if read(&f)?.is_some() {
            return Err(format!(
                "{} exists and would shadow derm's gate",
                f.display()
            ));
        }
    }
    // (path, what is on disk, what it will hold), in the row's order.
    let mut files: Vec<(PathBuf, Option<String>, String)> = Vec::new();
    let slot = |path: PathBuf,
                files: &mut Vec<(PathBuf, Option<String>, String)>|
     -> Result<usize, String> {
        if let Some(i) = files.iter().position(|(p, _, _)| *p == path) {
            return Ok(i);
        }
        let on_disk = read(&path)?;
        let now = on_disk.clone().unwrap_or_default();
        files.push((path, on_disk, now));
        Ok(files.len() - 1)
    };
    for st in &row.steps {
        match st {
            Step::JsonArrayEntry {
                at,
                jsonc,
                array,
                entry,
                create_with,
                chain,
            } if chain.is_empty() => {
                let path = gate::resolve(at, home, &NoEnv);
                let i = slot(path, &mut files)?;
                let entry = gate::fill(entry, &vars)?;
                match gate::add_to_array(
                    &files[i].2,
                    *jsonc,
                    array,
                    &entry,
                    &row.markers,
                    create_with.as_ref(),
                    false,
                )
                .map_err(|e| format!("{}: {e}", files[i].0.display()))?
                {
                    Outcome::Changed(t) => files[i].2 = t,
                    Outcome::Same => {}
                }
            }
            Step::OwnedFile { at, content } => {
                let path = gate::resolve(at, home, &NoEnv);
                let i = slot(path, &mut files)?;
                let content = gate::fill(content, &vars)?;
                if let Some(t) = gate::owned(
                    &files[i].2,
                    files[i].1.is_some(),
                    &content,
                    &row.markers,
                    false,
                )
                .map_err(|e| format!("{}: {e}", files[i].0.display()))?
                {
                    files[i].2 = t;
                }
            }
            _ => {
                return Err(format!(
                    "gates.json: {agent}'s row has a step derm's kit does not write"
                ))
            }
        }
    }
    Ok(files
        .into_iter()
        .map(|(path, on_disk, now)| Planned {
            text: (on_disk.as_deref() != Some(now.as_str())).then_some(now),
            path,
        })
        .collect())
}

/// Why this process may not register `agent`, or `None` when it may.
/// `marker` is [`daemon::vm_marker`]'s answer; `root` whether the process
/// runs as root; `home_owner_is_me` whether the home it was given is its
/// own user's (unused for Claude Code).
pub(crate) fn refusal(
    agent: &str,
    marker: Option<&str>,
    root: bool,
    home: Option<&Path>,
    home_is_mine: bool,
) -> Option<String> {
    if let Some(why) = marker {
        return Some(format!(
            "derm kit register runs only inside derm's sbx VM, where derm's kit wrote its marker ({why}). On your own machine use `derm connect {agent} --gate`, which asks before it writes"
        ));
    }
    if agent == CLAUDE {
        if home.is_some() {
            return Some(
                "claude-code takes no --home: its gate goes in Claude Code's managed settings"
                    .into(),
            );
        }
        if !root {
            return Some(format!(
                "{MANAGED} is root's; the kit runs this step as root"
            ));
        }
        return None;
    }
    if !HOME_AGENTS.contains(&agent) {
        return Some(format!("derm's kit has no registration for `{agent}`"));
    }
    let Some(home) = home else {
        return Some(format!("{agent} needs --home <the agent's home>"));
    };
    if !home.is_absolute() {
        return Some("--home takes an absolute path".into());
    }
    if root {
        return Some(format!(
            "{agent} keeps its hooks in its own config under {}, which the agent's user writes; the kit runs this step as that user, not as root",
            home.display()
        ));
    }
    if !home_is_mine {
        return Some(format!("{} is not this user's own folder", home.display()));
    }
    None
}

#[cfg(unix)]
fn read_text(path: &Path) -> Result<Option<String>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {}", path.display(), e.kind())),
        Ok(m) if !m.file_type().is_file() => {
            return Err(format!("{} is not a regular file", path.display()))
        }
        Ok(_) => {}
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|e| format!("{}: {}", path.display(), e.kind()))
}

/// Writes `text` to `path` through a new file beside it and a rename, so a
/// reader never sees half a file; folders on the way are made.
#[cfg(unix)]
fn write_text(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let shown = path.display();
    let dir = path
        .parent()
        .ok_or_else(|| format!("{shown} has no folder"))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e.kind()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{shown} has no name"))?;
    let tmp = dir.join(format!(".{name}.derm-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| format!("{}: {}", tmp.display(), e.kind()))?;
    let done = f
        .write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = done {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{shown}: {}", e.kind()));
    }
    Ok(())
}

#[cfg(unix)]
fn register(agent: &str, home: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    use std::os::unix::fs::MetadataExt;
    let me = derm_core::platform::real_user();
    let marker = daemon_marker();
    let home_is_mine = home
        .and_then(|h| std::fs::symlink_metadata(h).ok())
        .is_some_and(|m| m.file_type().is_dir() && m.uid() == me);
    if let Some(why) = refusal(agent, marker.as_deref(), me == 0, home, home_is_mine) {
        return Err(why);
    }
    let derm = gate::self_path()?;
    let planned = if agent == CLAUDE {
        let file = Path::new(MANAGED);
        vec![plan_claude(&derm, file, read_text(file)?.as_deref())?]
    } else {
        let home = home.ok_or("internal: no home")?;
        plan_agent(agent, &derm, home, &read_text)?
    };
    let mut out = Vec::new();
    for p in planned {
        if let Some(text) = &p.text {
            write_text(&p.path, text)?;
        }
        out.push(p.path);
    }
    Ok(out)
}

/// Why the VM marker does not hold here, or `None` when it does.
#[cfg(unix)]
fn daemon_marker() -> Option<String> {
    crate::gate::daemon::vm_marker(
        Path::new(crate::gate::daemon::VM_MARKER),
        cfg!(target_os = "linux"),
        &crate::gate::daemon::lstat,
    )
}

pub fn main(args: &[String]) -> u8 {
    let (agent, home) = match args {
        [verb, agent] if verb == "register" => (agent.as_str(), None),
        [verb, agent, flag, home] if verb == "register" && flag == "--home" => {
            (agent.as_str(), Some(PathBuf::from(home)))
        }
        _ => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    #[cfg(not(unix))]
    {
        let _ = (agent, home);
        eprintln!("derm kit register: derm's sbx VM is Linux; this command does nothing here");
        1
    }
    #[cfg(unix)]
    match register(agent, home.as_deref()) {
        Ok(files) => {
            // One path a line, for the kit's install script.
            for f in files {
                println!("{}", f.display());
            }
            0
        }
        Err(why) => {
            eprintln!("derm kit: {why}");
            1
        }
    }
}

// The kit is built and run on Unix only, and its paths are Unix paths.
#[cfg(all(test, unix))]
#[path = "vmkit_tests.rs"]
mod tests;
