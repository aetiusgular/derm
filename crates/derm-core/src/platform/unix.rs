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

    /// Runs `name`, a test of this module, alone in a copy of this test
    /// binary, and fails if it fails there. A process another test thread
    /// starts holds a copy of every descriptor this process has open until
    /// it execs, and a copy keeps a file's flock (flock(2): the lock belongs
    /// to the open file description). So a lock test beside tests that start
    /// processes can see a dropped lock still held: CI run 42006478394,
    /// rust-macos, failed `the_lock_is_held_once` that way while the peer
    /// tests started theirs. Alone, nothing else starts a process.
    fn alone(name: &str) -> bool {
        if std::env::var_os("DERM_PLATFORM_ALONE").is_some() {
            return true;
        }
        let test = format!("platform::unix::tests::{name}");
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test.as_str(), "--exact", "--test-threads=1"])
            .env("DERM_PLATFORM_ALONE", "1")
            .output()
            .unwrap();
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{test} alone:\n{said}");
        assert!(
            said.contains("1 passed"),
            "{test} did not run alone:\n{said}"
        );
        false
    }

    #[test]
    fn the_lock_is_held_once() {
        if !alone("the_lock_is_held_once") {
            return;
        }
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

    /// Starts `true` from another thread and holds the child between its
    /// fork and its exec (a `pre_exec` closure that waits); returns once the
    /// child has forked, with the go signal and the thread.
    fn a_child_held_before_exec() -> (UnixStream, std::thread::JoinHandle<()>) {
        use std::io::Read;
        use std::os::unix::process::CommandExt;
        let (mut forked_rx, forked_tx) = UnixStream::pair().unwrap();
        let (go_tx, go_rx) = UnixStream::pair().unwrap();
        let (tx, rx) = (forked_tx.as_raw_fd(), go_rx.as_raw_fd());
        let spawner = std::thread::spawn(move || {
            let _keep = (forked_tx, go_rx);
            let mut c = std::process::Command::new("true");
            // SAFETY: write and read are async-signal-safe; the closure
            // touches no memory but a one-byte buffer on its own stack.
            unsafe {
                c.pre_exec(move || {
                    let mut b = [1u8];
                    libc::write(tx, b.as_ptr().cast(), 1);
                    libc::read(rx, b.as_mut_ptr().cast(), 1);
                    Ok(())
                });
            }
            assert!(c.status().unwrap().success());
        });
        let mut b = [0u8];
        forked_rx.read_exact(&mut b).unwrap();
        (go_tx, spawner)
    }

    /// The cause of CI run 42006478394's failure, held still: a child
    /// between fork and exec keeps a lock its parent dropped, and frees it
    /// once it execs (its copies are close-on-exec). Before `alone`, this is
    /// what `the_lock_is_held_once` met when a peer test started a process
    /// between its `drop(a)` and its last check.
    #[test]
    fn a_child_between_fork_and_exec_keeps_a_dropped_lock_until_it_execs() {
        use std::io::Write;
        if !alone("a_child_between_fork_and_exec_keeps_a_dropped_lock_until_it_execs") {
            return;
        }
        let path = std::env::temp_dir().join(format!("derm-pllk-x-{}", std::process::id()));
        let a = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let b = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(try_lock_exclusive(&a));
        let (mut go, spawner) = a_child_held_before_exec();
        drop(a);
        let held_by_the_child = !try_lock_exclusive(&b);
        go.write_all(&[1]).unwrap();
        spawner.join().unwrap();
        let free_after_exec = try_lock_exclusive(&b);
        let _ = std::fs::remove_file(&path);
        assert!(held_by_the_child, "the child's copy kept the lock");
        assert!(free_after_exec, "the exec closed the child's copy");
    }

    #[test]
    fn the_host_has_a_name() {
        assert!(!host_name().is_empty());
    }
}
