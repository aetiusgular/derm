//! One sign-in per subscription per device (lane PB's; `contracts/
//! projects.md` section 2.3; plan step P3, Tony's call 17).
//!
//! Each account keeps one sign-in store per harness in
//! `<account home>/signin/<harness>/`, outside every project home, made by
//! the installer (lane PF). A project home reaches it this way, as note CD
//! sections 2.1 to 2.3 read each harness at the version in use and lane PB
//! read again (`plans/parallel/acctP_PB.md`, Research):
//!
//! - Codex 0.167.2: `<home>/.codex/auth.json` and `<home>/.codex/auth.lock`
//!   are links to the store's. Codex resolves every link in the path to the
//!   target, writes `.auth-*` in the target's folder and renames it onto the
//!   target, so the link survives (`login/src/auth/storage_file.rs:10-62`,
//!   `storage.rs:274-295` at `rust-v0.167.2`); a hard-linked target is
//!   refused there (`check_replaceable`). Its cross-process commit lock is
//!   `<home>/auth.lock` opened with `create(true)` (`storage.rs:189-212`),
//!   which through a link opens, or makes, the store's one lock (C6).
//! - Pi 1.6.0 (nothing below 1.5.1): `<home>/.pi/agent/auth.json` is a link
//!   to the store's. Pi writes `{}` through the link when the file is
//!   missing, then locks the resolved file with proper-lockfile 4.1.2's
//!   default `realpath: true` (`dist/core/auth-storage.js:34-66`;
//!   `lib/lockfile.js:15-22, 210`), so linked homes share one lock folder
//!   beside the target (#11655; C1).
//! - Claude Code 2.1.322: no link (a renewal renames a staged file over the
//!   path, by read); `CLAUDE_SECURESTORAGE_CONFIG_DIR` names the store
//!   folder (11 uses in the 2.1.322 binary), behind [`CLAUDE_CODE_STORE`],
//!   which stays off until P-B1 passes on the box
//!   (`plans/parallel_build_accounts.md` 8.5). With it off a Claude Code
//!   chat on an agent account is refused (`contracts/projects.md` 2.3).
//!
//! Called by lane PA's helper as the account, before the chat's domain.
//! Nothing here opens, reads, copies or writes a sign-in file (note CB 4.1):
//! the store is looked at by `fstatat` with no follow, and the links are
//! made by `symlinkat` under folders opened one part at a time with
//! `O_NOFOLLOW`, so no link derm did not make is followed.

use std::path::{Path, PathBuf};

/// The switch for Claude Code's shared store. Off until `plans/parallel/
/// acctP_box_research.md` records P-B1 as passing; P integration turns it
/// on (`plans/parallel_build_accounts.md` 8.5). A constant, not a setting:
/// nothing a chat or a project file can set turns it on.
pub const CLAUDE_CODE_STORE: bool = false;

/// Claude Code's store folder variable (2.1.322, binary read: `function
/// SB(){let e=process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR;...}`).
pub const CLAUDE_STORE_VAR: &str = "CLAUDE_SECURESTORAGE_CONFIG_DIR";

/// Why a Claude Code chat on an agent account is refused while the switch
/// is off.
pub const CLAUDE_CODE_OFF: &str = "Claude Code's shared sign-in store is off until the box shows a renewal keeps it (P-B1, plans/parallel_build_accounts.md 8.5); a Claude Code chat on an agent account is refused until then (contracts/projects.md 2.3)";

/// What a project home needs from the account's sign-in store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Linked {
    /// The links made, as paths in the project home.
    pub links: Vec<PathBuf>,
    /// Variables the harness gets (Claude Code's store folder, when its
    /// switch is on).
    pub env: Vec<(String, String)>,
}

/// One harness's store: the file the sign-in leaves there, and the links a
/// project home gets (path in the home, name in the store).
pub struct Store {
    pub harness: &'static str,
    pub file: &'static str,
    pub links: &'static [(&'static str, &'static str)],
}

pub const STORES: &[Store] = &[
    Store {
        harness: "codex",
        file: "auth.json",
        links: &[
            (".codex/auth.json", "auth.json"),
            (".codex/auth.lock", "auth.lock"),
        ],
    },
    Store {
        harness: "pi",
        file: "auth.json",
        links: &[(".pi/agent/auth.json", "auth.json")],
    },
    Store {
        harness: "claude-code",
        file: ".credentials.json",
        links: &[],
    },
];

pub fn store(harness: &str) -> Option<&'static Store> {
    STORES.iter().find(|s| s.harness == harness)
}

/// Whether `harness`'s sign-in lives in the account's store today: Codex and
/// Pi always, Claude Code when its switch is on.
pub fn uses_store(harness: &str) -> bool {
    uses_store_with(harness, CLAUDE_CODE_STORE)
}

pub(crate) fn uses_store_with(harness: &str, claude_on: bool) -> bool {
    match harness {
        "codex" | "pi" => true,
        "claude-code" => claude_on,
        _ => false,
    }
}

/// `<account home>/signin/<harness>`.
pub fn store_dir(account_home: &str, harness: &str) -> String {
    derm_core::project::layout::signin_dir(account_home, harness)
}

/// Makes `project_home`'s links into `<account_home>/signin/<harness>/`
/// for `harness` (`claude-code`, `codex`, `pi`), as the account, before the
/// chat's domain. Never reads, copies or writes a sign-in file's content
/// (note CB 4.1); never follows a link it did not make. A harness with no
/// store here gets nothing (its sign-in, if any, stays in the project home).
pub fn link_project_home(
    account_home: &Path,
    project_home: &Path,
    harness: &str,
) -> Result<Linked, String> {
    link_with(account_home, project_home, harness, CLAUDE_CODE_STORE)
}

/// [`link_project_home`] with the Claude Code switch given (tests).
pub(crate) fn link_with(
    account_home: &Path,
    project_home: &Path,
    harness: &str,
    claude_on: bool,
) -> Result<Linked, String> {
    let Some(st) = store(harness) else {
        return Ok(Linked::default());
    };
    if harness == "claude-code" && !claude_on {
        return Err(CLAUDE_CODE_OFF.into());
    }
    imp::link(account_home, project_home, st)
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    /// An open folder, closed on drop.
    struct Dir(i32);

    impl Drop for Dir {
        fn drop(&mut self) {
            // SAFETY: closes the descriptor this value owns.
            unsafe { libc::close(self.0) };
        }
    }

    fn c(name: &[u8]) -> Result<CString, String> {
        CString::new(name).map_err(|_| "a path holds a NUL".to_string())
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// `path`, absolute, opened one part at a time with `O_NOFOLLOW`: no part
    /// may be a link. `..` and `.` parts are refused.
    fn open_dir(path: &Path) -> Result<Dir, String> {
        if !path.is_absolute() {
            return Err(format!("{} is not an absolute path", path.display()));
        }
        // SAFETY: a literal path, flags for a folder with no follow.
        let root = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root < 0 {
            return Err(format!("/: {}", std::io::Error::last_os_error()));
        }
        let mut d = Dir(root);
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(n) => d = open_in(&d, n.as_bytes(), path)?,
                _ => return Err(format!("{}: a `.` or `..` part", path.display())),
            }
        }
        Ok(d)
    }

    fn open_in(d: &Dir, name: &[u8], whole: &Path) -> Result<Dir, String> {
        let n = c(name)?;
        // SAFETY: `d` is an open folder; `n` a NUL-terminated name.
        let fd = unsafe {
            libc::openat(
                d.0,
                n.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::ELOOP) | Some(libc::ENOTDIR) => format!(
                    "{}: {} is a link or not a folder; derm follows no link it did not make",
                    whole.display(),
                    String::from_utf8_lossy(name)
                ),
                _ => format!("{}: {e}", whole.display()),
            });
        }
        Ok(Dir(fd))
    }

    /// The folder is this process's user's and no one else can write it.
    fn mine(d: &Dir, what: &Path) -> Result<(), String> {
        // SAFETY: an all-zero stat is a valid out-buffer for fstat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `d` is open; `st` is written by the call.
        if unsafe { libc::fstat(d.0, &mut st) } != 0 {
            return Err(format!(
                "{}: {}",
                what.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: geteuid takes no arguments and cannot fail.
        let me = unsafe { libc::geteuid() };
        if st.st_uid != me || st.st_mode & 0o022 != 0 {
            return Err(format!(
                "{} is not this account's own folder closed to others (owner {}, mode {:o})",
                what.display(),
                st.st_uid,
                st.st_mode & 0o7777
            ));
        }
        Ok(())
    }

    /// The store's entry, looked at without following or opening it: absent,
    /// or one plain file with one name.
    fn plain_or_absent(d: &Dir, name: &str, what: &Path) -> Result<(), String> {
        let n = c(name.as_bytes())?;
        // SAFETY: as in `mine`.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `d` is open; no follow.
        let r = unsafe { libc::fstatat(d.0, n.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        if r != 0 {
            return if errno() == libc::ENOENT {
                Ok(())
            } else {
                Err(format!(
                    "{}: {}",
                    what.join(name).display(),
                    std::io::Error::last_os_error()
                ))
            };
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_nlink != 1 {
            return Err(format!(
                "{} is not one plain file (a link, a folder or a second name); derm links no project to it",
                what.join(name).display()
            ));
        }
        Ok(())
    }

    /// `name` in `d`, made 0700 when missing, opened with no follow, and the
    /// account's own.
    fn sub(d: &Dir, name: &str, what: &Path) -> Result<Dir, String> {
        let n = c(name.as_bytes())?;
        // SAFETY: `d` is open; a fresh folder, never through a link.
        if unsafe { libc::mkdirat(d.0, n.as_ptr(), 0o700) } != 0 && errno() != libc::EEXIST {
            return Err(format!(
                "{}: {}",
                what.join(name).display(),
                std::io::Error::last_os_error()
            ));
        }
        let s = open_in(d, name.as_bytes(), &what.join(name))?;
        mine(&s, &what.join(name))?;
        Ok(s)
    }

    /// The link `name` in `d` to `target`: made when missing, kept when it
    /// already names `target`, refused when anything else is there.
    fn link_one(d: &Dir, name: &str, target: &str, shown: &Path) -> Result<(), String> {
        let n = c(name.as_bytes())?;
        let t = c(target.as_bytes())?;
        for _ in 0..2 {
            let mut buf = vec![0u8; 4096];
            // SAFETY: `d` is open; `buf` is writable for its length.
            let len =
                unsafe { libc::readlinkat(d.0, n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
            if len >= 0 {
                buf.truncate(len as usize);
                if buf == target.as_bytes() {
                    return Ok(());
                }
                return Err(format!(
                    "{} is a link to {}, not to this account's sign-in store; derm does not replace it",
                    shown.display(),
                    String::from_utf8_lossy(&buf)
                ));
            }
            match errno() {
                libc::ENOENT => {
                    // SAFETY: as above; the link's text is `target`.
                    if unsafe { libc::symlinkat(t.as_ptr(), d.0, n.as_ptr()) } == 0 {
                        return Ok(());
                    }
                    if errno() != libc::EEXIST {
                        return Err(format!(
                            "{}: {}",
                            shown.display(),
                            std::io::Error::last_os_error()
                        ));
                    }
                    // Made by someone else in between: look again, once.
                }
                libc::EINVAL => {
                    return Err(format!(
                        "{} is there and is not derm's link (a sign-in the harness wrote in this project home?); move it out of the way and the next chat links it",
                        shown.display()
                    ))
                }
                _ => {
                    return Err(format!(
                        "{}: {}",
                        shown.display(),
                        std::io::Error::last_os_error()
                    ))
                }
            }
        }
        Err(format!("{}: changed while derm linked it", shown.display()))
    }

    pub(super) fn link(
        account_home: &Path,
        project_home: &Path,
        st: &Store,
    ) -> Result<Linked, String> {
        let acct = account_home
            .to_str()
            .ok_or("the account's home is not UTF-8")?;
        let store_s = store_dir(acct, st.harness);
        let store_p = PathBuf::from(&store_s);
        let store = open_dir(&store_p).map_err(|e| {
            format!("{e} (the account's sign-in store; `derm agents add` makes it)")
        })?;
        mine(&store, &store_p)?;
        for (_, in_store) in st.links {
            plain_or_absent(&store, in_store, &store_p)?;
        }
        plain_or_absent(&store, st.file, &store_p)?;
        let mut out = Linked::default();
        if st.links.is_empty() {
            out.env.push((CLAUDE_STORE_VAR.to_string(), store_s));
            return Ok(out);
        }
        let home = open_dir(project_home)?;
        mine(&home, project_home)?;
        for (in_home, in_store) in st.links {
            let rel = Path::new(in_home);
            let parts: Vec<&str> = rel.iter().map(|p| p.to_str().unwrap_or_default()).collect();
            let (leaf, folders) = parts.split_last().ok_or("an empty link path")?;
            let mut at = project_home.to_path_buf();
            let mut d: Option<Dir> = None;
            for f in folders {
                let next = sub(d.as_ref().unwrap_or(&home), f, &at)?;
                at = at.join(f);
                d = Some(next);
            }
            let target = format!("{store_s}/{in_store}");
            let shown = project_home.join(rel);
            link_one(d.as_ref().unwrap_or(&home), leaf, &target, &shown)?;
            out.links.push(shown);
        }
        Ok(out)
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    pub(super) fn link(_: &Path, _: &Path, _: &Store) -> Result<Linked, String> {
        Err("agent accounts are Linux only for now".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(tag: &str) -> Scratch {
        let p = std::env::temp_dir().join(format!(
            "derm-signin-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(std::fs::canonicalize(&p).unwrap())
    }

    fn account(s: &Scratch, harnesses: &[&str]) -> PathBuf {
        let a = s.0.join("agents/max");
        for h in harnesses {
            let d = a.join("signin").join(h);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        a
    }

    fn home(s: &Scratch, p: &str) -> PathBuf {
        let h = s.0.join(p).join("home");
        std::fs::create_dir_all(&h).unwrap();
        std::fs::set_permissions(&h, std::fs::Permissions::from_mode(0o700)).unwrap();
        h
    }

    #[test]
    fn codex_gets_two_links_into_the_store_and_a_second_call_keeps_them() {
        let s = scratch("codex");
        let a = account(&s, &["codex"]);
        let h = home(&s, "p1");
        let got = link_project_home(&a, &h, "codex").unwrap();
        assert_eq!(
            got.links,
            [h.join(".codex/auth.json"), h.join(".codex/auth.lock")]
        );
        assert!(got.env.is_empty());
        for (l, t) in [("auth.json", "auth.json"), ("auth.lock", "auth.lock")] {
            assert_eq!(
                std::fs::read_link(h.join(".codex").join(l)).unwrap(),
                a.join("signin/codex").join(t)
            );
        }
        let m = std::fs::metadata(h.join(".codex"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m, 0o700);
        // Idempotent: the next chat of the project finds its links.
        assert_eq!(link_project_home(&a, &h, "codex").unwrap(), got);
        // Nothing was made in the store: derm never writes a sign-in file.
        assert_eq!(
            std::fs::read_dir(a.join("signin/codex")).unwrap().count(),
            0
        );
    }

    #[test]
    fn pi_gets_one_link_under_its_agent_folder() {
        let s = scratch("pi");
        let a = account(&s, &["pi"]);
        let h = home(&s, "p1");
        let got = link_project_home(&a, &h, "pi").unwrap();
        assert_eq!(got.links, [h.join(".pi/agent/auth.json")]);
        assert_eq!(
            std::fs::read_link(h.join(".pi/agent/auth.json")).unwrap(),
            a.join("signin/pi/auth.json")
        );
    }

    /// Anything in the way is refused, never replaced or followed: a file
    /// the harness left, a link elsewhere, a link where a folder goes, a
    /// store entry that is a link or has a second name, a store others can
    /// write, a store that is missing.
    #[test]
    fn what_is_already_there_is_refused_never_replaced_or_followed() {
        let s = scratch("refuse");
        let a = account(&s, &["codex", "pi"]);
        let h = home(&s, "p1");
        std::fs::create_dir_all(h.join(".codex")).unwrap();
        std::fs::write(h.join(".codex/auth.json"), "{}").unwrap();
        let e = link_project_home(&a, &h, "codex").unwrap_err();
        assert!(e.contains("is not derm's link"), "{e}");
        assert_eq!(
            std::fs::read_to_string(h.join(".codex/auth.json")).unwrap(),
            "{}"
        );
        std::fs::remove_file(h.join(".codex/auth.json")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", h.join(".codex/auth.json")).unwrap();
        let e = link_project_home(&a, &h, "codex").unwrap_err();
        assert!(e.contains("is a link to /etc/passwd"), "{e}");
        // A link where derm makes a folder is not followed.
        let elsewhere = s.0.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, h.join(".pi")).unwrap();
        let e = link_project_home(&a, &h, "pi").unwrap_err();
        assert!(e.contains("is a link or not a folder"), "{e}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        // The store's entry: a link (a chat could plant one) or a second name.
        let h2 = home(&s, "p2");
        std::os::unix::fs::symlink(h.join("x"), a.join("signin/pi/auth.json")).unwrap();
        let e = link_project_home(&a, &h2, "pi").unwrap_err();
        assert!(e.contains("not one plain file"), "{e}");
        std::fs::remove_file(a.join("signin/pi/auth.json")).unwrap();
        std::fs::write(a.join("signin/pi/auth.json"), "{}").unwrap();
        std::fs::hard_link(a.join("signin/pi/auth.json"), s.0.join("second")).unwrap();
        let e = link_project_home(&a, &h2, "pi").unwrap_err();
        assert!(e.contains("not one plain file"), "{e}");
        std::fs::remove_file(s.0.join("second")).unwrap();
        assert!(link_project_home(&a, &h2, "pi").is_ok());
        // A store others can write, and a missing one.
        std::fs::set_permissions(
            a.join("signin/codex"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let e = link_project_home(&a, &home(&s, "p3"), "codex").unwrap_err();
        assert!(e.contains("closed to others"), "{e}");
        let e = link_project_home(&s.0.join("agents/none"), &h2, "codex").unwrap_err();
        assert!(e.contains("derm agents add"), "{e}");
        // A relative or `..` path.
        assert!(link_project_home(Path::new("agents/max"), &h2, "pi").is_err());
        assert!(link_project_home(&a, &h2.join("../p2/home"), "pi").is_err());
    }

    #[test]
    fn claude_code_gets_its_store_folder_by_variable_only_when_the_switch_is_on() {
        let s = scratch("cc");
        let a = account(&s, &["claude-code"]);
        let h = home(&s, "p1");
        assert!(
            !std::hint::black_box(CLAUDE_CODE_STORE),
            "the switch stays off until P-B1; P integration turns it on and changes this line"
        );
        let e = link_project_home(&a, &h, "claude-code").unwrap_err();
        assert!(e.contains("P-B1"), "{e}");
        let got = link_with(&a, &h, "claude-code", true).unwrap();
        assert!(got.links.is_empty());
        assert_eq!(
            got.env,
            [(
                CLAUDE_STORE_VAR.to_string(),
                a.join("signin/claude-code").to_string_lossy().into_owned()
            )]
        );
        assert_eq!(
            std::fs::read_dir(&h).unwrap().count(),
            0,
            "nothing in the home"
        );
        // A harness with no store here gets nothing.
        assert_eq!(
            link_project_home(&a, &h, "gemini").unwrap(),
            Linked::default()
        );
        assert!(uses_store("codex") && uses_store("pi") && !uses_store("claude-code"));
        assert!(uses_store_with("claude-code", true));
    }
}
