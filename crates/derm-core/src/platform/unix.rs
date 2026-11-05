//! The platform seam's Unix side (Linux and macOS). Each body is the code
//! that stood at its call site before the phase 3 merge, moved here unchanged
//! (the place it came from is named on each).

use std::fs::{File, Metadata, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

pub type UserId = u32;
pub type Listener = UnixListener;
pub type Stream = UnixStream;

pub fn real_user() -> UserId {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn effective_user() -> UserId {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub fn is_superuser() -> bool {
    real_user() == 0
}

pub fn owner(meta: &Metadata) -> UserId {
    meta.uid()
}

pub fn is_private(meta: &Metadata) -> bool {
    meta.mode() & 0o077 == 0
}

/// From `derm-core/src/runtime.rs` (`owned_private_dir`).
pub fn owned_private_dir(dir: &Path, user: &UserId) -> bool {
    match std::fs::symlink_metadata(dir) {
        Ok(m) => m.file_type().is_dir() && m.uid() == *user && m.mode() & 0o077 == 0,
        Err(_) => false,
    }
}

/// From `derm-daemon/src/socket.rs` (`private_dir`).
pub fn private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() {
        return Err(std::io::Error::other(format!(
            "{} is not a folder",
            dir.display()
        )));
    }
    let me = effective_user();
    if meta.uid() != me {
        return Err(std::io::Error::other(format!(
            "{} belongs to another user",
            dir.display()
        )));
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

pub fn set_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

pub fn set_private_file(path: &Path) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// The `.mode(0o600).custom_flags(libc::O_NOFOLLOW)` pair of
/// `derm-daemon/src/service.rs` (`lock_pid_file`, `write_private`).
pub fn private_no_follow(options: &mut OpenOptions) -> &mut OpenOptions {
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW)
}

/// From `derm-daemon/src/socket.rs` (`bind`).
pub fn bind(path: &Path) -> std::io::Result<Listener> {
    if let Some(parent) = path.parent() {
        private_dir(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => {
            return Err(std::io::Error::other("socket path is a folder"));
        }
        Ok(_) => std::fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn connect(path: &Path) -> std::io::Result<Stream> {
    UnixStream::connect(path)
}

/// From `derm-daemon/src/service.rs` (`lock_pid_file`).
pub fn try_lock_exclusive(file: &File) -> bool {
    // SAFETY: flock on a descriptor the caller owns; no memory involved.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    locked == 0
}

/// From `derm-cli/src/run/mod.rs` (`hostname`).
pub fn host_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname writes at
    // most that many bytes.
    let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if r != 0 {
        return String::new();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_matches_the_system() {
        // SAFETY: as above.
        assert_eq!(real_user(), unsafe { libc::getuid() });
        assert_eq!(effective_user(), unsafe { libc::geteuid() });
        assert_eq!(is_superuser(), real_user() == 0);
    }

    #[test]
    fn a_private_dir_is_made_0700_and_a_link_or_a_file_is_refused() {
        let root = std::env::temp_dir().join(format!("derm-plat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("a/b");
        private_dir(&dir).unwrap();
        let m = std::fs::symlink_metadata(&dir).unwrap();
        assert_eq!(m.mode() & 0o777, 0o700);
        assert!(owned_private_dir(&dir, &effective_user()));
        assert!(!owned_private_dir(&dir, &(effective_user() + 1)));
        std::fs::write(root.join("f"), b"x").unwrap();
        assert!(private_dir(&root.join("f")).is_err());
        std::os::unix::fs::symlink(&dir, root.join("l")).unwrap();
        assert!(!owned_private_dir(&root.join("l"), &effective_user()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_endpoint_is_private_and_a_stale_one_is_replaced() {
        let root = std::env::temp_dir().join(format!("derm-plsk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("d.sock");
        let first = bind(&path).unwrap();
        drop(first);
        let l = bind(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let _c = connect(&path).unwrap();
        let (_s, _) = l.accept().unwrap();
        std::fs::create_dir(root.join("dir.sock")).unwrap();
        assert!(bind(&root.join("dir.sock")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_lock_is_held_once() {
        let path = std::env::temp_dir().join(format!("derm-pllk-{}", std::process::id()));
        let a = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let b = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(try_lock_exclusive(&a));
        assert!(!try_lock_exclusive(&b));
        drop(a);
        assert!(try_lock_exclusive(&b));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_host_has_a_name() {
        assert!(!host_name().is_empty());
    }
}
