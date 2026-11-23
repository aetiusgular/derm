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
    for f in &s.files {
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
