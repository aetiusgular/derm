//! `/etc/derm/agent-users.json`: which local user runs a person's agents
//! (wave 5 lane V; S2 part c, rules cases 53 and 125).
//!
//! The file is written by root, once, by `packaging/linux/agent-user/
//! install.sh` on the person's yes, and read by `derm run` (to start the
//! harness as that user) and by the gate inside the harness (to know which
//! owner's files it may trust: lane V's request V-3). Root writes it because
//! neither the person nor the agent should be able to change it alone: the
//! person's own processes include any agent that runs as them, and the agent
//! runs as the user it names.
//!
//! The file is trusted only when every part of its path is root's and no one
//! else can write it (the same rule `sudo` applies to `/etc/sudoers.d`,
//! sudoers(5), "the file must be owned by root and not writable by group or
//! other"). Anything else reads as "no agents' user": `derm run` then starts
//! the harness as the person, as before wave 5.

use std::ffi::{CStr, CString};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Where root keeps the file.
pub const ANCHOR: &str = "/etc/derm/agent-users.json";
/// It is read only up to this size.
const MAX_BYTES: u64 = 64 * 1024;
/// The only route lane V builds (`run.start`'s `agentUser.how`).
pub const HOW_SUDO: &str = "sudo";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct File {
    version: u32,
    agents: Vec<Entry>,
}

/// One owner's agents' user, as root wrote it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    /// The agents' user (`derm-agent` by default).
    pub user: String,
    pub uid: u32,
    /// The person whose chats run as `user`.
    pub owner: String,
    pub owner_uid: u32,
    /// `PATH` for the harness under `user`: absolute folders only. The
    /// person's own `PATH` names folders in their home, which `user` cannot
    /// reach and should not learn.
    pub path: String,
    /// How `derm run` switches user: `sudo`, the only route built.
    pub how: String,
}

/// The entry for `owner_uid`, or why there is none. `Ok(None)`: no file, so
/// no agents' user is set up (the common case). `Err`: a file is there and
/// cannot be trusted or read; `derm run` refuses rather than guess.
pub fn for_owner(owner_uid: u32) -> Result<Option<Entry>, String> {
    load(Path::new(ANCHOR), Path::new("/"), 0, owner_uid)
}

/// `for_owner` with the file, the folder the trust check starts at, and the
/// trusted owner named, for tests (a test cannot make a file root's).
pub fn load(
    file: &Path,
    from: &Path,
    trusted: u32,
    owner_uid: u32,
) -> Result<Option<Entry>, String> {
    let meta = match std::fs::symlink_metadata(file) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", file.display())),
    };
    trusted_path(file, from, trusted)?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", file.display()));
    }
    if meta.len() > MAX_BYTES {
        return Err(format!(
            "{} is larger than {MAX_BYTES} bytes",
            file.display()
        ));
    }
    let text = read_nofollow(file)?;
    let parsed: File = serde_json::from_str(&text)
        .map_err(|e| format!("{}: not the expected JSON ({e})", file.display()))?;
    if parsed.version != 1 {
        return Err(format!(
            "{}: version {} is not 1",
            file.display(),
            parsed.version
        ));
    }
    let mine: Vec<&Entry> = parsed
        .agents
        .iter()
        .filter(|e| e.owner_uid == owner_uid)
        .collect();
    let entry = match mine.as_slice() {
        [] => return Ok(None),
        [one] => (*one).clone(),
        _ => {
            return Err(format!(
                "{}: names more than one agents' user for uid {owner_uid}",
                file.display()
            ))
        }
    };
    check_entry(&entry)?;
    Ok(Some(entry))
}

/// What an entry must say before anything acts on it.
fn check_entry(e: &Entry) -> Result<(), String> {
    if !plain_name(&e.user) || !plain_name(&e.owner) {
        return Err("a user name in the file is not a plain login name".into());
    }
    if e.uid == 0 {
        return Err(format!("{} has uid 0: agents never run as root", e.user));
    }
    if e.uid == e.owner_uid || e.user == e.owner {
        return Err(format!(
            "{} is the owner's own account: it separates nothing",
            e.user
        ));
    }
    if e.how != HOW_SUDO {
        return Err(format!("`how` is {:?}; only \"sudo\" is built", e.how));
    }
    check_path_list(&e.path)?;
    Ok(())
}

/// A login name as `useradd` takes it on Debian and Ubuntu (adduser.conf's
/// NAME_REGEX), without the trailing `$` machine accounts allow: no path,
/// option or shell character can hide in it.
pub fn plain_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// `PATH` for the agents' user: absolute folders, no empty entry (an empty
/// entry means the working folder, which the agent writes), no `.` or `..`.
fn check_path_list(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > 4096 {
        return Err("`path` is empty or too long".into());
    }
    for part in path.split(':') {
        let bad = part.is_empty()
            || !part.starts_with('/')
            || part.split('/').any(|c| c == "." || c == "..")
            || part.chars().any(char::is_control);
        if bad {
            return Err(format!("`path` holds {part:?}: absolute folders only"));
        }
    }
    Ok(())
}

/// Every component from `from` down to `file` belongs to `trusted` and no
/// one else can write it; none is a link. `from` is `/` outside tests.
pub fn trusted_path(file: &Path, from: &Path, trusted: u32) -> Result<(), String> {
    let rest = file
        .strip_prefix(from)
        .map_err(|_| format!("{} is not under {}", file.display(), from.display()))?;
    let mut at = from.to_path_buf();
    let mut parts: Vec<PathBuf> = vec![at.clone()];
    for c in rest.components() {
        at.push(c);
        parts.push(at.clone());
    }
    for p in parts {
        let m = std::fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        if m.file_type().is_symlink() {
            return Err(format!("{} is a link", p.display()));
        }
        if m.uid() != trusted {
            return Err(format!("{} is not owned by uid {trusted}", p.display()));
        }
        if m.mode() & 0o022 != 0 {
            return Err(format!("{} can be written by group or others", p.display()));
        }
    }
    Ok(())
}

fn read_nofollow(file: &Path) -> Result<String, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(file)
        .map_err(|e| format!("{}: {e}", file.display()))?;
    let mut text = String::new();
    f.by_ref()
        .take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(text)
}

/// A local account as the password database has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

/// `getpwnam_r(3)`.
pub fn account(name: &str) -> Option<Account> {
    let c = CString::new(name).ok()?;
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: an all-zero passwd is a valid out-parameter; the buffer outlives
    // the pointers getpwnam_r stores in it, and we copy out before it drops.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            c.as_ptr(),
            &mut pw,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() {
        return None;
    }
    // SAFETY: getpwnam_r succeeded, so pw_name and pw_dir point into buf.
    let (pname, dir) = unsafe { (CStr::from_ptr(pw.pw_name), CStr::from_ptr(pw.pw_dir)) };
    Some(Account {
        name: pname.to_string_lossy().into_owned(),
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        home: dir.to_string_lossy().into_owned(),
    })
}

/// The names of every group `account` is in, its primary group included
/// (`getgrouplist(3)` and `getgrgid_r(3)`). `None` where the OS call failed.
#[cfg(target_os = "linux")]
pub fn groups(account: &Account) -> Option<Vec<String>> {
    let c = CString::new(account.name.as_str()).ok()?;
    let mut n: libc::c_int = 64;
    let mut gids: Vec<libc::gid_t> = vec![0; n as usize];
    for _ in 0..4 {
        // SAFETY: gids holds n entries; getgrouplist writes at most n and sets
        // n to the count it needs when that is more.
        let rc = unsafe { libc::getgrouplist(c.as_ptr(), account.gid, gids.as_mut_ptr(), &mut n) };
        if rc >= 0 {
            gids.truncate(n.max(0) as usize);
            return Some(gids.iter().map(|g| group_name(*g)).collect());
        }
        if n <= 0 || n > 65_536 {
            return None;
        }
        gids = vec![0; n as usize];
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub fn groups(_account: &Account) -> Option<Vec<String>> {
    None
}

#[cfg(target_os = "linux")]
fn group_name(gid: libc::gid_t) -> String {
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: as in `account`: a zeroed out-parameter and a buffer that
    // outlives the pointers stored in it.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::group = std::ptr::null_mut();
    let rc =
        unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return format!("gid {gid}");
    }
    // SAFETY: getgrgid_r succeeded, so gr_name points into buf.
    unsafe { CStr::from_ptr(gr.gr_name) }
        .to_string_lossy()
        .into_owned()
}

/// Groups that give their members root, or a way to it, or another user's
/// files (case 125; Docker's Linux post-install page: the `docker` group
/// "grants root-level privileges"; `lxd`, `incus-admin` and `libvirt` start
/// guests with host mounts; `disk` reads raw block devices; `shadow` reads
/// password hashes; `adm` and `systemd-journal` read logs that hold other
/// users' command lines, S0-3).
pub const FORBIDDEN_GROUPS: &[&str] = &[
    "root",
    "sudo",
    "admin",
    "wheel",
    "docker",
    "lxd",
    "incus",
    "incus-admin",
    "libvirt",
    "disk",
    "shadow",
    "adm",
    "systemd-journal",
];

/// Why `agent` may not run agents for `owner`, if it may not.
pub fn refusal(agent: &Account, groups: &[String], owner: &Account) -> Option<String> {
    if agent.uid == 0 {
        return Some(format!("{} has uid 0", agent.name));
    }
    if agent.uid == owner.uid {
        return Some(format!(
            "{} is uid {}, the owner's own",
            agent.name, owner.uid
        ));
    }
    for g in groups {
        if FORBIDDEN_GROUPS.contains(&g.as_str()) {
            return Some(format!(
                "{} is in the group `{g}`, which gives a way to root or to others' files (case 125)",
                agent.name
            ));
        }
    }
    // The owner's own group reads the owner's home on Ubuntu (HOME_MODE 0750).
    if let Some(g) = owner_group(owner) {
        if groups.contains(&g) {
            return Some(format!(
                "{} is in `{g}`, the owner's own group, which can read the owner's files",
                agent.name
            ));
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn owner_group(owner: &Account) -> Option<String> {
    let g = group_name(owner.gid);
    (!g.starts_with("gid ")).then_some(g)
}

#[cfg(not(target_os = "linux"))]
fn owner_group(_owner: &Account) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// A folder tree a test owns: `<tmp>/derm-anchor-*/etc/derm/agent-users.json`,
    /// each part the test's, 0755, the file 0644.
    fn tree(text: &str) -> (tempdir::Dir, PathBuf) {
        let d = tempdir::Dir::new();
        let file = d.path().join("etc/derm/agent-users.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        for p in [d.path().join("etc"), d.path().join("etc/derm")] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&file, text).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        (d, file)
    }

    fn entry_json(owner_uid: u32) -> String {
        format!(
            r#"{{"version":1,"agents":[{{"user":"derm-agent","uid":4242,"owner":"tony","ownerUid":{owner_uid},"path":"/usr/local/bin:/usr/bin:/bin","how":"sudo"}}]}}"#
        )
    }

    // The trust check starts at the test's own folder (`<tmp>/derm-anchor-*`,
    // three levels above the file), which the test owns; outside tests it
    // starts at `/` with root as the owner.
    fn load_here(file: &Path) -> Result<Option<Entry>, String> {
        load_in(file, me())
    }

    fn load_in(file: &Path, trusted: u32) -> Result<Option<Entry>, String> {
        load(file, file.ancestors().nth(3).unwrap(), trusted, me())
    }

    #[test]
    fn no_file_means_no_agents_user() {
        let d = tempdir::Dir::new();
        let file = d.path().join("etc/derm/agent-users.json");
        assert_eq!(load_here(&file), Ok(None));
    }

    #[test]
    fn the_owners_entry_is_found_and_another_owners_is_not() {
        let (_d, file) = tree(&entry_json(me()));
        let e = load_here(&file).unwrap().expect("the owner's entry");
        assert_eq!(e.user, "derm-agent");
        assert_eq!(e.uid, 4242);
        let (_d2, file2) = tree(&entry_json(me().wrapping_add(1)));
        assert_eq!(load_here(&file2), Ok(None));
    }

    #[test]
    fn a_file_others_can_write_or_a_link_is_not_trusted() {
        let (_d, file) = tree(&entry_json(me()));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = load_here(&file).unwrap_err();
        assert!(err.contains("written by group or others"), "{err}");

        let (_d2, file2) = tree(&entry_json(me()));
        let parent = file2.parent().unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = load_here(&file2).unwrap_err();
        assert!(err.contains("written by group or others"), "{err}");

        let (d3, file3) = tree(&entry_json(me()));
        let real = d3.path().join("real.json");
        std::fs::rename(&file3, &real).unwrap();
        std::os::unix::fs::symlink(&real, &file3).unwrap();
        let err = load_here(&file3).unwrap_err();
        assert!(err.contains("is a link"), "{err}");
    }

    #[test]
    fn a_file_owned_by_someone_else_is_not_trusted() {
        let (_d, file) = tree(&entry_json(me()));
        let err = load_in(&file, me().wrapping_add(1)).unwrap_err();
        assert!(err.contains("not owned by uid"), "{err}");
    }

    #[test]
    fn entries_that_separate_nothing_or_hide_characters_are_refused() {
        for (bad, why) in [
            (r#""user":"derm-agent","uid":0"#, "uid 0"),
            (r#""user":"tony","uid":4242"#, "owner's own account"),
            (r#""user":"../x","uid":4242"#, "plain login name"),
            (r#""user":"-rf","uid":4242"#, "plain login name"),
        ] {
            let text = format!(
                r#"{{"version":1,"agents":[{{{bad},"owner":"tony","ownerUid":{},"path":"/usr/bin","how":"sudo"}}]}}"#,
                me()
            );
            let (_d, file) = tree(&text);
            let err = load_here(&file).unwrap_err();
            assert!(err.contains(why), "{bad}: {err}");
        }
        for (path, why) in [
            ("/usr/bin::/bin", "absolute folders only"),
            ("bin:/usr/bin", "absolute folders only"),
            ("/usr/../tmp", "absolute folders only"),
            ("", "empty"),
        ] {
            let text = format!(
                r#"{{"version":1,"agents":[{{"user":"derm-agent","uid":4242,"owner":"tony","ownerUid":{},"path":"{path}","how":"sudo"}}]}}"#,
                me()
            );
            let (_d, file) = tree(&text);
            let err = load_here(&file).unwrap_err();
            assert!(err.contains(why), "{path:?}: {err}");
        }
        let text = entry_json(me()).replace(r#""how":"sudo""#, r#""how":"setuid""#);
        let (_d, file) = tree(&text);
        assert!(load_here(&file).unwrap_err().contains("only \"sudo\""));
    }

    #[test]
    fn unknown_keys_two_entries_or_another_version_are_refused() {
        let extra =
            entry_json(me()).replace(r#""how":"sudo""#, r#""how":"sudo","shell":"/bin/sh""#);
        let (_d, file) = tree(&extra);
        assert!(load_here(&file).unwrap_err().contains("expected JSON"));

        let one = format!(
            r#"{{"user":"derm-agent","uid":4242,"owner":"tony","ownerUid":{},"path":"/usr/bin","how":"sudo"}}"#,
            me()
        );
        let (_d2, file2) = tree(&format!(r#"{{"version":1,"agents":[{one},{one}]}}"#));
        assert!(load_here(&file2).unwrap_err().contains("more than one"));

        let (_d3, file3) = tree(&entry_json(me()).replace(r#""version":1"#, r#""version":2"#));
        assert!(load_here(&file3).unwrap_err().contains("version 2"));
    }

    #[test]
    fn plain_names() {
        for ok in ["derm-agent", "_derm", "a1", "derm_agent"] {
            assert!(plain_name(ok), "{ok}");
        }
        for bad in [
            "",
            "Derm",
            "1abc",
            "-x",
            "a b",
            "a/b",
            "a$",
            &"a".repeat(33),
        ] {
            assert!(!plain_name(bad), "{bad}");
        }
    }

    #[test]
    fn an_agent_in_a_root_group_or_the_owners_group_is_refused() {
        let owner = Account {
            name: "tony".into(),
            uid: 1000,
            gid: 1000,
            home: "/home/tony".into(),
        };
        let agent = Account {
            name: "derm-agent".into(),
            uid: 998,
            gid: 998,
            home: "/var/lib/derm-agent".into(),
        };
        assert_eq!(refusal(&agent, &["derm-agent".into()], &owner), None);
        for g in ["docker", "sudo", "lxd", "libvirt", "adm", "systemd-journal"] {
            let why = refusal(&agent, &["derm-agent".into(), g.into()], &owner).unwrap();
            assert!(why.contains(g), "{why}");
        }
        let root = Account {
            uid: 0,
            ..agent.clone()
        };
        assert!(refusal(&root, &[], &owner).unwrap().contains("uid 0"));
        let same = Account { uid: 1000, ..agent };
        assert!(refusal(&same, &[], &owner).unwrap().contains("owner's own"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_is_found_in_the_password_database() {
        let root = account("root").expect("root is in /etc/passwd");
        assert_eq!(root.uid, 0);
        let g = groups(&root).expect("root's groups");
        assert!(g.iter().any(|x| x == "root"), "{g:?}");
        assert_eq!(account("no-such-user-derm-v"), None);
    }

    /// A temporary folder removed on drop (no new dependency).
    mod tempdir {
        pub struct Dir(std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p = std::env::temp_dir()
                    .join(format!("derm-anchor-{}", uuid::Uuid::new_v4().simple()));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
