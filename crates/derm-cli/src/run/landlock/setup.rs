//! What the helper makes, as the agent account and before the chat's
//! domain, for a chat inside a project (lane PA; `contracts/projects.md`
//! section 2.2 and 2.3; plan step P2).
//!
//! - `<account home>/projects/<id>/{home,tmp,run}`, each the account's,
//!   0700, made with `mkdirat` under an already-open parent and opened with
//!   `O_NOFOLLOW`, so a link a chat planted in its place is refused, never
//!   followed (the shape of case 273). A folder that is there with another
//!   owner or another mode is refused too.
//! - derm's gateway entry, `derm_project`, in the harness's own config file
//!   inside the project home, only when that file is not there yet
//!   (`O_CREAT | O_EXCL | O_NOFOLLOW`), so a chat's or the person's later
//!   edits are never overwritten (`contracts/project-tools.md` section 1).
//! - the sign-in links into the account's store, by lane PB's
//!   `agents::signin::link_project_home`, for the harnesses that have one.
//!
//! The account home itself is written by none of this beyond `projects/`,
//! which the installer makes from lane PF on (this makes it when an older
//! install did not).

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use derm_core::project::layout;

/// What the helper makes (in the spec, so in the environment: paths and the
/// entries' text, nothing secret).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Setup {
    /// `/var/lib/derm/agents/<slug>`.
    pub account_home: String,
    /// The project's id (16 hex).
    pub project: String,
    /// The harness's id, for its sign-in store.
    pub harness: String,
    /// Files made in the project home when they are not there.
    #[serde(default)]
    pub files: Vec<File>,
}

/// One file in the project home, by its path under it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct File {
    pub rel: String,
    pub text: String,
}

/// Makes the project's folders, the gateway entries and the sign-in links;
/// returns the variables the sign-in store asks for (Claude Code's store
/// folder, when lane PB's switch is on).
pub(crate) fn make(s: &Setup) -> Result<Vec<(String, String)>, String> {
    let id = derm_core::project::ProjectId::parse(&s.project)
        .ok_or_else(|| format!("{:?} is not a project id", s.project))?;
    if !s.account_home.starts_with('/') || !plain_rel(&s.account_home[1..]) {
        return Err(format!("{:?} is not an account home", s.account_home));
    }
    let me = euid();
    let home_fd = super::rule_fd(&s.account_home)?
        .ok_or_else(|| format!("{} is not there; re-run the installer", s.account_home))?;
    let home_fd: OwnedFd = home_fd.into();
    let m = fstat(home_fd.as_raw_fd())?;
    if m.st_mode & libc::S_IFMT != libc::S_IFDIR || m.st_uid != me {
        return Err(format!(
            "{} is not a folder of this account (uid {me})",
            s.account_home
        ));
    }
    let projects = private_dir(&home_fd, layout::PROJECTS, me, &s.account_home)?;
    let dir_text = layout::project_dir(&s.account_home, &id);
    let proj = private_dir(&projects, id.as_str(), me, &dir_text)?;
    let mut parts = Vec::new();
    for part in [layout::HOME, layout::TMP, layout::RUN] {
        parts.push(private_dir(&proj, part, me, &format!("{dir_text}/{part}"))?);
    }
    let project_home = format!("{dir_text}/{}", layout::HOME);
    // BT-2 and BT-17: Claude Code's own state file is merged, not made only
    // when missing, so a project home skips Claude Code's onboarding and
    // keeps derm's entry after Claude Code wrote the file first.
    if s.harness == "claude-code" {
        let entry = s.files.iter().find(|f| f.rel == CLAUDE_JSON);
        if let Err(why) = claude_json(&parts[0], entry.map(|f| f.text.as_str()), me) {
            eprintln!(
                "derm {}: {project_home}/{CLAUDE_JSON}: {why}; derm's onboarding seed and gateway entry were not written there",
                super::SUBCOMMAND
            );
        }
    }
    // FX3-1: Pi reads `mcp.json` from its agent folder, which call 7a makes
    // per chat, so its entry goes there (below), not into the project home.
    let pi_entry = (s.harness == "pi")
        .then(|| s.files.iter().find(|f| f.rel == PI_MCP))
        .flatten();
    for f in s.files.iter().filter(|f| {
        !(s.harness == "claude-code" && f.rel == CLAUDE_JSON)
            && !(s.harness == "pi" && f.rel == PI_MCP)
    }) {
        // An entry is a convenience: a name that is not a plain path, or a
        // folder on its way that is not this account's own, leaves that
        // entry out and says so; the chat still starts.
        if let Err(why) = new_file(&parts[0], &f.rel, &f.text, me) {
            eprintln!(
                "derm {}: {why}; derm's gateway entry was not written there",
                super::SUBCOMMAND
            );
        }
    }
    // Review R2's rest (case RV-1): what derm cannot pin in its flag block,
    // since the block is on argv, is refused here, as the account, before
    // the domain, when the project home's user settings name it.
    if s.harness == "claude-code" {
        claude_settings_refusal(&parts[0], &project_home)?;
    }
    // Tony's call 7a (review PI-S3): Pi reads extensions, settings packages,
    // `shellPath`, `shellCommandPrefix`, `models.json` and its project trust
    // from its agent folder, which in the project home is the chat's to
    // write; each Pi chat gets a folder of its own instead.
    if s.harness == "pi" {
        let run_text = format!("{dir_text}/{}", layout::RUN);
        return pi_agent_dir(
            &parts[2],
            &run_text,
            &s.account_home,
            &project_home,
            &PiRoot::system(),
            me,
            pi_entry.map(|f| f.text.as_str()),
        );
    }
    if layout::SIGNIN_HARNESSES.contains(&s.harness.as_str()) {
        let linked = crate::agents::signin::link_project_home(
            Path::new(&s.account_home),
            Path::new(&project_home),
            &s.harness,
        )?;
        return Ok(linked.env);
    }
    Ok(Vec::new())
}

/// Where a Pi account chat's agent folder is filled from (Tony's call 7a):
/// `settings.json` and `models.json` in a root-owned folder, every part of
/// its path root's and closed to group and other writes, read as
/// `derm_core::owner::read_anchor` reads the anchor. With no folder, derm's
/// own settings ([`PI_DEFAULT_SETTINGS`]) and no `models.json`.
pub(crate) struct PiRoot {
    pub dir: std::path::PathBuf,
    pub from: std::path::PathBuf,
    pub trusted: u32,
}

impl PiRoot {
    pub(crate) fn system() -> PiRoot {
        PiRoot {
            dir: PI_ROOT_SETTINGS.into(),
            from: "/".into(),
            trusted: 0,
        }
    }
}

/// The root-owned folder a Pi account chat's agent folder is filled from.
pub(crate) const PI_ROOT_SETTINGS: &str = "/etc/derm/pi-agent";

/// derm's own Pi settings for an account chat, when root wrote none: no
/// package, no extension, and a project's own `.pi` never trusted (Pi
/// 1.6.0's `defaultProjectTrust`, `core/settings-manager.js:789-792`; with
/// `never` and no trust record, `core/project-trust.js:42-47` answers
/// untrusted, and `-a` on the chat's own command line still wins: run).
pub(crate) const PI_DEFAULT_SETTINGS: &str = "{\n  \"defaultProjectTrust\": \"never\"\n}\n";

/// Makes the chat's own Pi agent folder under the project's runtime folder
/// (`run`, open as `run_fd`), fills it from `root`, links its `auth.json` to
/// the account's store, and returns `PI_CODING_AGENT_DIR` and
/// `PI_CODING_AGENT_SESSION_DIR` (the project home's `.pi/agent/sessions`,
/// so the project's sessions are kept across chats; Pi 1.6.0 `main.js:
/// 593-596`).
pub(crate) fn pi_agent_dir(
    run_fd: &OwnedFd,
    run_text: &str,
    account_home: &str,
    project_home: &str,
    root: &PiRoot,
    me: u32,
    mcp: Option<&str>,
) -> Result<Vec<(String, String)>, String> {
    use derm_core::owner::{read_anchor, Anchor};
    let read_root = |name: &str| -> Result<Option<String>, String> {
        let f = root.dir.join(name);
        match read_anchor(&f, &root.from, root.trusted) {
            Anchor::Absent => Ok(None),
            Anchor::Text(t) => Ok(Some(t)),
            Anchor::Problem(p) => Err(format!(
                "{p}: Pi's settings for agent accounts come only from a root-owned file that no one else can write; fix it or remove it, and start the chat again"
            )),
        }
    };
    let settings = match read_root("settings.json")? {
        None => PI_DEFAULT_SETTINGS.to_string(),
        Some(t) => {
            let mut v: serde_json::Value = serde_json::from_str(&t)
                .map_err(|e| format!("{}/settings.json is not JSON: {e}", root.dir.display()))?;
            let o = v
                .as_object_mut()
                .ok_or_else(|| format!("{}/settings.json is not an object", root.dir.display()))?;
            o.entry("defaultProjectTrust")
                .or_insert_with(|| serde_json::Value::from("never"));
            let mut t = serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?;
            t.push('\n');
            t
        }
    };
    let models = read_root("models.json")?;
    let name = format!("pi-agent-{}", uuid::Uuid::new_v4().simple());
    let shown = format!("{run_text}/{name}");
    let c = cname(&name)?;
    // SAFETY: `c` lives across the call; `run_fd` is an open folder. A new
    // name, so nothing a chat left there is reused.
    if unsafe { libc::mkdirat(run_fd.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
        return Err(format!("{shown}: {}", std::io::Error::last_os_error()));
    }
    let dir = private_dir(run_fd, &name, me, &shown)?;
    new_file(&dir, "settings.json", &settings, me)?;
    if let Some(m) = models {
        new_file(&dir, "models.json", &m, me)?;
    }
    if let Some(m) = mcp {
        new_file(&dir, "mcp.json", m, me)?;
    }
    crate::agents::signin::link_pi_agent_dir(Path::new(account_home), Path::new(&shown))?;
    Ok(vec![
        ("PI_CODING_AGENT_DIR".to_string(), shown),
        (
            "PI_CODING_AGENT_SESSION_DIR".to_string(),
            format!("{project_home}/.pi/agent/sessions"),
        ),
    ])
}

/// Review R2's rest: an agent account's Claude Code reads its user settings
/// from `<project home>/.claude/settings.json`, which the chat writes, and
/// applies its `env` over the process's (2.1.322; review run "st6"). derm
/// pins every variable it sets in its flag block (`claude_gate::
/// pin_account_env`), except those it may not put on argv
/// (`claude_gate::NOT_ON_ARGV`: the proxy URLs with their credential, the
/// tap's route, the export's headers, the chat token). A file that names one
/// of those, is a link, or is not JSON derm can read, stops the start: a
/// planted `ANTHROPIC_BASE_URL` would send the sign-in's bearer token to a
/// listener of the chat's own. The file is read here, after the chat that
/// wrote it ended and before this chat starts; a chat of the same project
/// running beside it could still write it after this read (I; open, low).
fn claude_settings_refusal(home: &OwnedFd, project_home: &str) -> Result<(), String> {
    let shown = format!("{project_home}/.claude/settings.json");
    let dir = match open_no_follow(home.as_raw_fd(), ".claude", libc::O_DIRECTORY)? {
        Some(d) => d,
        None => return Ok(()),
    };
    let Some(f) = open_no_follow(dir.as_raw_fd(), "settings.json", libc::O_NONBLOCK)? else {
        return Ok(());
    };
    let m = fstat(f.as_raw_fd())?;
    if m.st_mode & libc::S_IFMT != libc::S_IFREG || m.st_size > 1024 * 1024 {
        return Err(format!(
            "{shown} is not a plain file under 1 MiB; move it out of the way and start the chat again"
        ));
    }
    let mut text = String::new();
    use std::io::Read;
    std::fs::File::from(f)
        .read_to_string(&mut text)
        .map_err(|e| format!("{shown}: {e}"))?;
    settings_env_refusal(&text, crate::run::claude_gate::NOT_ON_ARGV)
        .map_err(|why| format!("{shown} {why}; remove it there and start the chat again"))
}

/// Why a Claude Code settings file's `env` may not run in an account chat,
/// or `Ok`: it names one of `names` (in any letter case: Claude Code reads
/// the name as written, and the environment of a POSIX process is
/// case-sensitive, so only exact names matter; case folding is not applied).
pub(crate) fn settings_env_refusal(text: &str, names: &[&str]) -> Result<(), String> {
    let v: serde_json::Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|_| {
            "is not JSON derm can read, so derm cannot tell what its env sets".to_string()
        })?;
    let Some(env) = v.get("env") else {
        return Ok(());
    };
    let Some(env) = env.as_object() else {
        return Err("has an env that is not an object".into());
    };
    let named: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| env.contains_key(*n))
        .collect();
    if named.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "sets {} in its env, which derm sets for this chat and cannot pin (a credential or a route to one)",
            named.join(", ")
        ))
    }
}

/// Pi's MCP file under the project home's agent folder, where derm's
/// gateway entry for Pi sits (`run/user/project.rs` `gateway_entry`).
const PI_MCP: &str = ".pi/agent/mcp.json";
/// Claude Code's user state file under the project home (`~/.claude.json`).
const CLAUDE_JSON: &str = ".claude.json";
/// Past this a `.claude.json` is not read (Claude Code's grows with its
/// project list; this only stops a runaway file).
const CLAUDE_JSON_MAX: i64 = 8 * 1024 * 1024;

/// BT-2 and BT-17 (P box test): `.claude.json` in the project home with
/// `hasCompletedOnboarding: true` and, when `entry` is given (derm's gateway
/// entry, `{"mcpServers": {"derm_project": ...}}`), derm's server merged in;
/// every other key the harness or the person wrote stays. A new file is
/// seeded as Claude Code 2.1.322's own sandbox seeds a fresh config folder
/// (`{hasCompletedOnboarding: true, autoUpdates: false}`, its `Oa()`, read in
/// the binary): its onboarding's preflight fetches `api.anthropic.com`
/// outside the tap, which the chat's sign-in tunnel refuses, and Claude Code
/// then exits (`process.exit(1)`, BT-2). The file is opened without
/// following a link, must be a regular file of this account's with one
/// link, and is replaced by a new file renamed over it, never written in
/// place; a file that is not a JSON object is left as it is (an error).
/// Nothing is written when nothing changes. A chat of the same project
/// running beside this one can write the file between the read and the
/// rename, as two Claude Codes on one config folder can (I; open, low).
fn claude_json(home: &OwnedFd, entry: Option<&str>, me: u32) -> Result<(), String> {
    use serde_json::{Map, Value};
    let found = open_no_follow(home.as_raw_fd(), CLAUDE_JSON, libc::O_NONBLOCK)?;
    let (mut obj, fresh) = match found {
        None => {
            let mut m = Map::new();
            m.insert("autoUpdates".into(), Value::Bool(false));
            (m, true)
        }
        Some(fd) => {
            let st = fstat(fd.as_raw_fd())?;
            if st.st_mode & libc::S_IFMT != libc::S_IFREG
                || st.st_uid != me
                || st.st_nlink != 1
                || st.st_size > CLAUDE_JSON_MAX
            {
                return Err(
                    "not a plain file of this account's with one link, or too large".into(),
                );
            }
            let mut text = String::new();
            use std::io::Read;
            std::fs::File::from(fd)
                .read_to_string(&mut text)
                .map_err(|e| e.to_string())?;
            match serde_json::from_str::<Value>(&text) {
                Ok(Value::Object(m)) => (m, false),
                _ => return Err("not a JSON object".into()),
            }
        }
    };
    let mut changed = fresh;
    if obj.get("hasCompletedOnboarding") != Some(&Value::Bool(true)) {
        obj.insert("hasCompletedOnboarding".into(), Value::Bool(true));
        changed = true;
    }
    if let Some(e) = entry {
        let v: Value = serde_json::from_str(e).map_err(|e| e.to_string())?;
        let servers = v
            .get("mcpServers")
            .and_then(Value::as_object)
            .ok_or("derm's entry has no mcpServers")?;
        let list = obj
            .entry("mcpServers")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or("its mcpServers is not an object")?;
        for (k, x) in servers {
            if list.get(k) != Some(x) {
                list.insert(k.clone(), x.clone());
                changed = true;
            }
        }
    }
    if !changed {
        return Ok(());
    }
    let text = serde_json::to_string_pretty(&Value::Object(obj)).map_err(|e| e.to_string())?;
    let tmp = format!("{CLAUDE_JSON}.derm-{}", uuid::Uuid::new_v4().simple());
    new_file(home, &tmp, &text, me)?;
    let (a, b) = (cname(&tmp)?, cname(CLAUDE_JSON)?);
    // SAFETY: both names live across the call; `home` is an open folder.
    // renameat replaces the name, never a link's target.
    let r = unsafe { libc::renameat(home.as_raw_fd(), a.as_ptr(), home.as_raw_fd(), b.as_ptr()) };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: as above.
        unsafe { libc::unlinkat(home.as_raw_fd(), a.as_ptr(), 0) };
        return Err(e.to_string());
    }
    Ok(())
}

/// `name` in the folder `dir`, opened without following a link; `None` when
/// it is not there.
fn open_no_follow(dir: RawFd, name: &str, extra: i32) -> Result<Option<OwnedFd>, String> {
    let c = cname(name)?;
    // SAFETY: `c` lives across the call; `dir` is an open folder.
    let fd = unsafe {
        libc::openat(
            dir,
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | extra,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => Err(format!(
                "{name} in the project home is a link or not what it should be; derm follows no link there"
            )),
            _ => Err(format!("{name}: {e}")),
        };
    }
    // SAFETY: a new descriptor that nothing else owns.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// A relative path of plain parts only.
fn plain_rel(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.contains('\0')
        && rel.split('/').all(|p| !p.is_empty())
        && Path::new(rel)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

fn cname(name: &str) -> Result<CString, String> {
    CString::new(name).map_err(|_| format!("{name:?}: a NUL in the name"))
}

fn fstat(fd: RawFd) -> Result<libc::stat, String> {
    // SAFETY: `st` is written by the kernel; `fd` is open.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(format!("fstat: {}", std::io::Error::last_os_error()));
    }
    Ok(st)
}

/// `name` under `parent`, made 0700 when it is not there, opened without
/// following a link, and required to be a folder of `me` with mode 0700.
fn private_dir(parent: &OwnedFd, name: &str, me: u32, shown: &str) -> Result<OwnedFd, String> {
    let fd = dir_at(parent, name, shown)?;
    let m = fstat(fd.as_raw_fd())?;
    if m.st_uid != me || m.st_mode & 0o7777 != 0o700 {
        return Err(format!(
            "{shown} is there with uid {} and mode {:o}, not this account's with 0700: remove it, or fix it with chmod 700",
            m.st_uid,
            m.st_mode & 0o7777
        ));
    }
    Ok(fd)
}

/// `name` under `parent`: made 0700 when missing, then opened as a folder
/// with `O_NOFOLLOW`.
fn dir_at(parent: &OwnedFd, name: &str, shown: &str) -> Result<OwnedFd, String> {
    let c = cname(name)?;
    // SAFETY: `c` lives across the call; `parent` is an open folder.
    let r = unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(format!("{shown}: {e}"));
        }
    }
    // SAFETY: as above.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "{shown}: {} (a link there is refused, never followed)",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `text` as `rel` under `home`, only when no file is there; the folders on
/// the way are made 0700 when missing and must be the account's.
fn new_file(home: &OwnedFd, rel: &str, text: &str, me: u32) -> Result<(), String> {
    if !plain_rel(rel) {
        return Err(format!("{rel:?} is not a plain path in the project home"));
    }
    let parts: Vec<&str> = rel.split('/').collect();
    let (leaf, dirs) = parts.split_last().ok_or("an empty path")?;
    let mut at: Option<OwnedFd> = None;
    for d in dirs {
        let parent = at.as_ref().unwrap_or(home);
        let fd = dir_at(parent, d, rel)?;
        if fstat(fd.as_raw_fd())?.st_uid != me {
            return Err(format!("{rel}: {d} is not this account's"));
        }
        at = Some(fd);
    }
    let parent = at.as_ref().unwrap_or(home);
    let c = cname(leaf)?;
    // SAFETY: `c` lives across the call.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        // There already: the harness's or the person's own, left as it is.
        if e.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(format!("{rel}: {e}"));
    }
    // SAFETY: a new descriptor that nothing else owns.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    use std::io::Write;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{rel}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct Tmp(std::path::PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn account() -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "dpa-acct-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Tmp(std::fs::canonicalize(&p).unwrap())
    }
    fn setup(home: &Path, harness: &str, files: Vec<File>) -> Setup {
        Setup {
            account_home: home.to_string_lossy().into_owned(),
            project: derm_core::project::ProjectId::of_real_path("/srv/a")
                .as_str()
                .to_string(),
            harness: harness.into(),
            files,
        }
    }

    #[test]
    fn the_project_folders_are_made_private_and_a_planted_link_is_refused() {
        let a = account();
        let s = setup(&a.0, "other", Vec::new());
        assert_eq!(make(&s), Ok(Vec::new()));
        let dir = a.0.join("projects").join(&s.project);
        for p in [
            a.0.join("projects"),
            dir.clone(),
            dir.join("home"),
            dir.join("tmp"),
            dir.join("run"),
        ] {
            let m = std::fs::symlink_metadata(&p).unwrap();
            assert!(m.is_dir(), "{}", p.display());
            assert_eq!(m.mode() & 0o7777, 0o700, "{}", p.display());
        }
        // Again: the same folders are fine.
        assert_eq!(make(&s), Ok(Vec::new()));
        // A link a chat put in place of `tmp` is refused, never followed.
        std::fs::remove_dir(dir.join("tmp")).unwrap();
        std::os::unix::fs::symlink("/etc", dir.join("tmp")).unwrap();
        let e = make(&s).unwrap_err();
        assert!(e.contains("tmp") && e.contains("link"), "{e}");
        std::fs::remove_file(dir.join("tmp")).unwrap();
        // A folder there with another mode is refused.
        std::fs::create_dir(dir.join("tmp")).unwrap();
        std::fs::set_permissions(dir.join("tmp"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(make(&s).unwrap_err().contains("0700"));
    }

    #[test]
    fn a_gateway_entry_is_written_only_where_no_file_is() {
        let a = account();
        let entry = File {
            rel: ".codex/config.toml".into(),
            text: "[mcp_servers.derm_project]\n".into(),
        };
        let s = setup(&a.0, "other", vec![entry.clone()]);
        make(&s).unwrap();
        let f =
            a.0.join("projects")
                .join(&s.project)
                .join("home/.codex/config.toml");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), entry.text);
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o600);
        // The person's or the harness's own edit stays.
        std::fs::write(&f, "model = \"x\"\n").unwrap();
        make(&s).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "model = \"x\"\n");
        // A link in its place is neither followed nor replaced.
        std::fs::remove_file(&f).unwrap();
        let target = a.0.join("elsewhere");
        std::os::unix::fs::symlink(&target, &f).unwrap();
        make(&s).unwrap();
        assert!(!target.exists());
        // A path that leaves the home writes nothing and still starts.
        let s2 = setup(
            &a.0,
            "other",
            vec![File {
                rel: "../x".into(),
                text: "x".into(),
            }],
        );
        assert!(make(&s2).is_ok());
        assert!(!a.0.join("projects").join(&s.project).join("x").exists());
    }

    #[test]
    fn a_harness_with_a_sign_in_store_asks_lane_pbs_links() {
        let a = account();
        // On the base, lane PB's function says it is not built; the start
        // is refused rather than run with no sign-in.
        let r = make(&setup(&a.0, "codex", Vec::new()));
        match r {
            Ok(_) => {}
            Err(e) => assert!(e.contains("sign-in"), "{e}"),
        }
    }

    /// Review R2's rest (case RV-1): a project home whose Claude Code user
    /// settings name a variable derm sets and cannot pin stops the start.
    #[test]
    fn rv_1_a_project_home_settings_env_derm_cannot_pin_stops_the_start() {
        let a = account();
        let store = a.0.join("signin").join("claude-code");
        std::fs::create_dir_all(&store).unwrap();
        for d in [a.0.join("signin"), store.clone()] {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let s = setup(&a.0, "claude-code", Vec::new());
        make(&s).unwrap();
        let claude = a.0.join("projects").join(&s.project).join("home/.claude");
        std::fs::create_dir_all(&claude).unwrap();
        let file = claude.join("settings.json");
        std::fs::write(&file, r#"{"env":{"DERM_POLICY":"/x","KEEP":"1"}}"#).unwrap();
        assert!(make(&s).is_ok(), "a name derm pins in its block is fine");
        for planted in [
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:9"}}"#,
            r#"{"env":{"HTTPS_PROXY":"http://127.0.0.1:9"}}"#,
            r#"{"env":{"DERM_CHAT_TOKEN":"x"}}"#,
            r#"{"env":{"OTEL_EXPORTER_OTLP_HEADERS":"x"}}"#,
            "{not json",
        ] {
            std::fs::write(&file, planted).unwrap();
            let e = make(&s).unwrap_err();
            assert!(e.contains("settings.json"), "{planted}: {e}");
        }
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", &file).unwrap();
        assert!(make(&s).unwrap_err().contains("link"));
        std::fs::remove_file(&file).unwrap();
        assert!(make(&s).is_ok());
    }

    fn pi_store(a: &Tmp) {
        let store = a.0.join("signin").join("pi");
        std::fs::create_dir_all(&store).unwrap();
        for d in [a.0.join("signin"), store] {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn var<'a>(env: &'a [(String, String)], k: &str) -> Option<&'a str> {
        env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    /// Tony's call 7a (red first; review PI-S3): each Pi chat gets its own
    /// agent folder under the project's runtime folder, with derm's settings
    /// and the store's `auth.json`; the project home's `~/.pi/agent`, which
    /// the chat writes, is not what Pi reads.
    #[test]
    fn call_7a_each_pi_chat_gets_its_own_agent_folder() {
        let a = account();
        pi_store(&a);
        let s = setup(&a.0, "pi", Vec::new());
        let env = make(&s).unwrap();
        let dir = var(&env, "PI_CODING_AGENT_DIR")
            .expect("an agent folder")
            .to_string();
        let run = a.0.join("projects").join(&s.project).join("run");
        assert!(Path::new(&dir).starts_with(&run), "{dir}");
        let m = std::fs::symlink_metadata(&dir).unwrap();
        assert!(m.is_dir() && m.mode() & 0o7777 == 0o700, "{dir}");
        assert_eq!(
            std::fs::read_to_string(Path::new(&dir).join("settings.json")).unwrap(),
            PI_DEFAULT_SETTINGS
        );
        assert_eq!(
            std::fs::read_link(Path::new(&dir).join("auth.json")).unwrap(),
            a.0.join("signin/pi/auth.json")
        );
        let home = a.0.join("projects").join(&s.project).join("home");
        assert_eq!(
            var(&env, "PI_CODING_AGENT_SESSION_DIR"),
            Some(home.join(".pi/agent/sessions").to_str().unwrap())
        );
        // A second chat gets a second folder.
        let env2 = make(&s).unwrap();
        assert_ne!(var(&env2, "PI_CODING_AGENT_DIR").unwrap(), dir);
    }

    /// Tony's call 7a: a root-owned folder fills it instead, and one that is
    /// not root's stops the start.
    #[test]
    fn call_7a_the_agent_folder_is_filled_from_root_owned_settings() {
        let a = account();
        pi_store(&a);
        let s = setup(&a.0, "pi", Vec::new());
        make(&s).unwrap();
        let proj = a.0.join("projects").join(&s.project);
        let run_fd = super::super::rule_fd(proj.join("run").to_str().unwrap())
            .unwrap()
            .unwrap();
        let run_fd: OwnedFd = run_fd.into();
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        let rootdir = a.0.join("etc-pi");
        std::fs::create_dir(&rootdir).unwrap();
        std::fs::set_permissions(&rootdir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            rootdir.join("settings.json"),
            r#"{"defaultProvider":"local"}"#,
        )
        .unwrap();
        std::fs::write(rootdir.join("models.json"), r#"{"providers":{}}"#).unwrap();
        for f in ["settings.json", "models.json"] {
            std::fs::set_permissions(rootdir.join(f), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
        let root = PiRoot {
            dir: rootdir.clone(),
            from: a.0.clone(),
            trusted: me,
        };
        let run_text = proj.join("run").to_string_lossy().into_owned();
        let home_text = proj.join("home").to_string_lossy().into_owned();
        let acct = a.0.to_string_lossy().into_owned();
        let env = pi_agent_dir(&run_fd, &run_text, &acct, &home_text, &root, me, None).unwrap();
        let dir = Path::new(var(&env, "PI_CODING_AGENT_DIR").unwrap()).to_path_buf();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(v["defaultProvider"], "local");
        assert_eq!(
            v["defaultProjectTrust"], "never",
            "derm's default where root names none"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("models.json")).unwrap(),
            r#"{"providers":{}}"#
        );
        // A file others can write is refused, and so the start.
        std::fs::set_permissions(
            rootdir.join("models.json"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        let e = pi_agent_dir(&run_fd, &run_text, &acct, &home_text, &root, me, None).unwrap_err();
        assert!(e.contains("models.json"), "{e}");
    }

    /// FX3-1 (found reading Pi 1.6.0 for this pass; red first): Pi's MCP
    /// extension reads `mcp.json` from its agent folder (`getAgentDir()`,
    /// `PI_CODING_AGENT_DIR` first; `dist/extensions/mcp/index.js:1200`,
    /// `config.js:4-5, 105`), which call 7a made a folder of each chat's own,
    /// so derm's entry in the project home's `.pi/agent/mcp.json` was never
    /// read. It goes into the chat's agent folder.
    #[test]
    fn fx3_1_a_pi_chats_agent_folder_holds_derms_gateway_entry() {
        let a = account();
        pi_store(&a);
        let entry =
            crate::run::user::project::gateway_entry("pi", "/usr/local/bin/derm-daemon").unwrap();
        assert_eq!(entry.rel, ".pi/agent/mcp.json");
        let s = setup(&a.0, "pi", vec![entry.clone()]);
        let env = make(&s).unwrap();
        let dir = var(&env, "PI_CODING_AGENT_DIR").unwrap();
        assert_eq!(
            std::fs::read_to_string(Path::new(dir).join("mcp.json")).unwrap(),
            entry.text
        );
        // Not left where Pi no longer reads it.
        let home = a.0.join("projects").join(&s.project).join("home");
        assert!(!home.join(".pi/agent/mcp.json").exists());
    }

    fn claude_store(a: &Tmp) {
        let store = a.0.join("signin").join("claude-code");
        std::fs::create_dir_all(&store).unwrap();
        for d in [a.0.join("signin"), store] {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn claude_json(a: &Tmp, s: &Setup) -> serde_json::Value {
        let f =
            a.0.join("projects")
                .join(&s.project)
                .join("home/.claude.json");
        serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap()
    }

    fn derm_entry() -> File {
        crate::run::user::project::gateway_entry("claude-code", "/usr/local/bin/derm-daemon")
            .unwrap()
    }

    /// BT-2 (P box test, high; red first): a new project home's first Claude
    /// Code chat ran Claude Code 2.1.322's onboarding, whose preflight calls
    /// `api.anthropic.com` outside the tap; the tunnel refused it and the
    /// chat exited (and, during a renewal, emptied the account's sign-in,
    /// BT-8). The project home's `.claude.json` is seeded as Claude Code's own
    /// sandbox seeds a fresh config folder (`hasCompletedOnboarding: true`,
    /// `autoUpdates: false`; its `Oa()`, read in the 2.1.322 binary), with
    /// derm's entry, and with no root `derm-daemon` too.
    #[test]
    fn bt_2_a_fresh_project_homes_claude_json_skips_onboarding_and_holds_derms_entry() {
        let a = account();
        claude_store(&a);
        let s = setup(&a.0, "claude-code", vec![derm_entry()]);
        make(&s).unwrap();
        let v = claude_json(&a, &s);
        assert_eq!(v["hasCompletedOnboarding"], true, "{v}");
        assert_eq!(v["autoUpdates"], false, "{v}");
        assert_eq!(
            v["mcpServers"]["derm_project"]["args"][0], "project-mcp",
            "{v}"
        );
        let f =
            a.0.join("projects")
                .join(&s.project)
                .join("home/.claude.json");
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o600);
        // No root derm-daemon: no entry, still no onboarding.
        let b = account();
        claude_store(&b);
        let s = setup(&b.0, "claude-code", Vec::new());
        make(&s).unwrap();
        let v = claude_json(&b, &s);
        assert_eq!(v["hasCompletedOnboarding"], true, "{v}");
        assert!(v.get("mcpServers").is_none(), "{v}");
    }

    /// BT-17 (P box test, medium; red first): Claude Code writes
    /// `.claude.json` on its first start, and derm's entry was written only
    /// where no file was (`O_EXCL`), so it never reached a project home where
    /// Claude Code had run, while `run.start` named it. It is merged into the
    /// harness's own file, which keeps every other key; a link there is not
    /// followed or replaced, and a file that is not a JSON object is left.
    #[test]
    fn bt_17_derms_entry_is_merged_into_an_existing_claude_json() {
        let a = account();
        claude_store(&a);
        let s = setup(&a.0, "other", Vec::new());
        make(&s).unwrap();
        let home = a.0.join("projects").join(&s.project).join("home");
        let f = home.join(".claude.json");
        std::fs::write(
            &f,
            r#"{"numStartups":3,"theme":"dark","mcpServers":{"mine":{"type":"stdio","command":"/bin/true"}}}"#,
        )
        .unwrap();
        let s = setup(&a.0, "claude-code", vec![derm_entry()]);
        make(&s).unwrap();
        let v = claude_json(&a, &s);
        assert_eq!(v["numStartups"], 3, "{v}");
        assert_eq!(v["theme"], "dark", "{v}");
        assert_eq!(v["mcpServers"]["mine"]["command"], "/bin/true", "{v}");
        assert_eq!(v["mcpServers"]["derm_project"]["type"], "stdio", "{v}");
        assert_eq!(v["hasCompletedOnboarding"], true, "{v}");
        // An existing file keeps its own autoUpdates (derm's block pins the
        // updater off anyway, R1).
        assert!(v.get("autoUpdates").is_none(), "{v}");
        // A link in its place is neither followed nor replaced; the chat
        // still starts.
        std::fs::remove_file(&f).unwrap();
        let target = a.0.join("elsewhere.json");
        std::fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(&target, &f).unwrap();
        make(&s).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}");
        assert!(std::fs::symlink_metadata(&f)
            .unwrap()
            .file_type()
            .is_symlink());
        // Not a JSON object: left as it is.
        std::fs::remove_file(&f).unwrap();
        std::fs::write(&f, "[1]").unwrap();
        make(&s).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "[1]");
    }

    #[test]
    fn only_plain_relative_paths() {
        for ok in [".claude.json", ".codex/config.toml", ".pi/agent/mcp.json"] {
            assert!(plain_rel(ok), "{ok}");
        }
        for no in ["", "/x", "../x", "a/../b", "a//b", "a/", "./a", "a\0b"] {
            assert!(!plain_rel(no), "{no:?}");
        }
    }
}
