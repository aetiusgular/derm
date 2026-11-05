//! Content capture's files, written by the tap when the switch is on
//! (`contracts/events.md` section 5; rules cases 85 as changed, 114, 126).
//!
//! Layout, shared with the daemon's purge (`derm-daemon/src/content/`):
//! `<data>/content/<chat>/` (0700) holds `<ms>-r<days>-<id>.<part>` (0600),
//! where `<ms>` is when the file was opened, `<days>` the retention the user
//! had chosen then (1 to 7), `<id>` the request's id and `<part>` `request`,
//! `response`, or `argv` (a run's own argument words, case 85 as changed:
//! for `derm run` to keep there instead of the activity log). Each file carries its own retention, so turning content
//! off or shortening it later deletes nothing early (case 126). A file holds
//! a body as it crossed the tap: never a header, a URL or a query (case 114).

#[cfg(unix)]
use std::fs::DirBuilder;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

/// The folder under the daemon's data folder.
pub const DIR: &str = "content";

/// Where content goes and for how long.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The daemon's data folder; files go under `<root>/content/`.
    pub root: PathBuf,
    /// 1 to 7 (`settings.schema.json`).
    pub retention_days: u8,
}

/// A chat id that can name a folder: 1 to 128 of `[A-Za-z0-9._-]`, not `.`
/// or `..`, not starting with `.`.
pub fn chat_dir_ok(chat: &str) -> bool {
    !chat.is_empty()
        && chat.len() <= 128
        && !chat.starts_with('.')
        && chat
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A file name the purge recognizes: `(<ms>, <days>)`.
pub fn parse_name(name: &str) -> Option<(i64, u8)> {
    let mut parts = name.splitn(3, '-');
    let ms: i64 = parts.next()?.parse().ok()?;
    let days: u8 = parts.next()?.strip_prefix('r')?.parse().ok()?;
    let rest = parts.next()?;
    let ok = (1..=7).contains(&days)
        && (rest.ends_with(".request") || rest.ends_with(".response") || rest.ends_with(".argv"))
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ok.then_some((ms, days))
}

/// One content file being written.
#[derive(Debug)]
pub struct ContentFile {
    file: File,
    pub path: PathBuf,
    pub bytes: u64,
    pub failed: bool,
}

impl ContentFile {
    /// Appends; a failed write closes the file to further writes and is
    /// counted, never retried with the bytes in a log.
    pub fn append(&mut self, bytes: &[u8]) {
        if self.failed {
            return;
        }
        match self.file.write_all(bytes) {
            Ok(()) => self.bytes += bytes.len() as u64,
            Err(_) => self.failed = true,
        }
    }
}

/// Makes `dir` (0700) when missing, then checks it is a real folder (not a
/// link) of this user's with no group or other bits.
#[cfg(unix)]
fn private_dir(dir: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = std::fs::symlink_metadata(dir)?;
    let uid = derm_core::platform::real_user();
    if !m.file_type().is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err(io::Error::other(format!(
            "{} is not a private folder of this user's",
            dir.display()
        )));
    }
    Ok(())
}

/// Windows: the seam makes the folder, refuses a reparse point on its path
/// or another user's folder, and sets a protected user-only DACL (lane Z,
/// note AU section 5).
#[cfg(windows)]
fn private_dir(dir: &Path) -> io::Result<()> {
    derm_core::platform::private_dir(dir)
}

/// Opens a new content file for one part of one request.
pub fn open(
    target: &Target,
    chat: &str,
    at_ms: i64,
    id: &str,
    part: &str,
) -> io::Result<ContentFile> {
    if !chat_dir_ok(chat) {
        return Err(io::Error::other("chat id cannot name a folder"));
    }
    if !(1..=7).contains(&target.retention_days) {
        return Err(io::Error::other("retention must be 1 to 7 days"));
    }
    let top = target.root.join(DIR);
    private_dir(&top)?;
    let dir = top.join(chat);
    private_dir(&dir)?;
    let safe_id: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect();
    let name = format!("{at_ms}-r{}-{safe_id}.{part}", target.retention_days);
    if parse_name(&name).is_none() {
        return Err(io::Error::other("bad content file name"));
    }
    let path = dir.join(name);
    // The seam's `private_no_follow` is `.mode(0o600).custom_flags(O_NOFOLLOW)`
    // on Unix (lane Z's request Z-2).
    let file =
        derm_core::platform::private_no_follow(OpenOptions::new().write(true).create_new(true))
            .open(&path)?;
    Ok(ContentFile {
        file,
        path,
        bytes: 0,
        failed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("derm-tap-content-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn files_are_private_and_carry_their_retention() {
        let root = tmp("private");
        let t = Target {
            root: root.clone(),
            retention_days: 3,
        };
        let mut f = open(&t, "chat-1", 1_793_000_000_000, "req_abc", "request").unwrap();
        f.append(b"{\"model\":\"m\"}");
        let name = f.path.file_name().unwrap().to_str().unwrap().to_string();
        assert_eq!(parse_name(&name), Some((1_793_000_000_000, 3)));
        assert_private(&f.path, 0o600);
        assert_private(&root.join("content/chat-1"), 0o700);
        assert_private(&root.join("content"), 0o700);
        let _ = std::fs::remove_dir_all(root);
    }

    /// 0600 or 0700 on Unix; a private DACL on Windows (lane Z).
    #[cfg(unix)]
    fn assert_private(p: &Path, mode: u32) {
        assert_eq!(
            std::fs::metadata(p).unwrap().mode() & 0o777,
            mode,
            "{}",
            p.display()
        );
    }

    #[cfg(windows)]
    fn assert_private(p: &Path, _mode: u32) {
        assert!(
            derm_core::platform::windows::is_private_path(p),
            "{}",
            p.display()
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_or_a_shared_folder_is_refused() {
        let root = tmp("junction");
        std::fs::create_dir_all(root.join("elsewhere")).unwrap();
        let t = Target {
            root: root.clone(),
            retention_days: 1,
        };
        // A folder of ours: allowed, made private.
        open(&t, "chat-1", 1, "r", "request").unwrap();
        // A junction in the chat's place.
        let ok = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(root.join("content").join("chat-2"))
            .arg(root.join("elsewhere"))
            .status()
            .unwrap();
        assert!(ok.success());
        assert!(open(&t, "chat-2", 1, "r", "request").is_err());
        assert!(std::fs::read_dir(root.join("elsewhere"))
            .unwrap()
            .next()
            .is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_or_a_shared_folder_is_refused() {
        let root = tmp("link");
        std::fs::create_dir_all(root.join("elsewhere")).unwrap();
        std::fs::create_dir_all(root.join("content")).unwrap();
        std::fs::set_permissions(
            root.join("content"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere"), root.join("content/chat-2")).unwrap();
        let t = Target {
            root: root.clone(),
            retention_days: 1,
        };
        assert!(open(&t, "chat-2", 1, "r", "request").is_err());
        std::fs::set_permissions(
            root.join("content"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        assert!(open(&t, "chat-3", 1, "r", "request").is_err());
        assert!(std::fs::read_dir(root.join("elsewhere"))
            .unwrap()
            .next()
            .is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn names_and_chat_ids_that_could_escape_are_refused() {
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            ".hidden",
            "a b",
            &"x".repeat(129),
        ] {
            assert!(!chat_dir_ok(bad), "{bad}");
        }
        assert!(chat_dir_ok("chat-01HXYZ_a.b"));
        assert_eq!(parse_name("1-r8-x.request"), None);
        assert_eq!(parse_name("1-r0-x.request"), None);
        assert_eq!(parse_name("x-r1-x.request"), None);
        assert_eq!(parse_name("1-r1-x.other"), None);
        assert_eq!(parse_name("1-r7-req_1.response"), Some((1, 7)));
        assert_eq!(parse_name("1-r2-run_1.argv"), Some((1, 2)));
    }
}
