//! The platform seam (wave 5; lane Z's request 1, note AU section 12.1).
//!
//! derm's crates reach the operating system for seven things: the daemon's
//! endpoint (1), who is on the other end of it (2), who we are (3), files
//! and folders only we may read (4), a harness's process tree (5, in
//! `derm-cli`'s `platform` folder), one daemon per user (6), and the host's
//! name (7). Each is one function or type here, with today's Unix code in
//! `platform/unix.rs` and Windows' in `platform/windows/` (lane Z's folder).
//! Callers use these names, not `libc` or `std::os::unix`, so a Windows form
//! goes in lane Z's folder and nothing else moves.
//!
//! The names are integration's (phase 3 merge); the Unix bodies are the code
//! that stood at each call site before, moved and unchanged. What still calls
//! Unix directly is listed in `plans/parallel/tk_integration_w5.md` (phase 3,
//! the seam's rest).

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as imp;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use windows as imp;

use std::fs::{File, Metadata, OpenOptions};
use std::path::Path;

// ---- 3. Identity -------------------------------------------------------

/// A user as the system names one: a uid on Unix, a SID on Windows. Compared,
/// never parsed by callers.
pub type UserId = imp::UserId;

/// The user who started this process (Unix `getuid`).
pub fn real_user() -> UserId {
    imp::real_user()
}

/// The user this process acts as (Unix `geteuid`).
pub fn effective_user() -> UserId {
    imp::effective_user()
}

/// Whether this process runs as the system's superuser (root on Unix).
pub fn is_superuser() -> bool {
    imp::is_superuser()
}

/// Who owns the file or folder `meta` describes.
pub fn owner(meta: &Metadata) -> UserId {
    imp::owner(meta)
}

// ---- 4. Private files and folders --------------------------------------

/// Whether no one but the owner has any access to `meta`'s file (Unix: no
/// group or other bits).
pub fn is_private(meta: &Metadata) -> bool {
    imp::is_private(meta)
}

/// Whether `dir` is a folder, not a link, owned by `user`, private.
pub fn owned_private_dir(dir: &Path, user: &UserId) -> bool {
    imp::owned_private_dir(dir, user)
}

/// Makes `dir` (and its parents) and holds it private (Unix 0700), owned by
/// this user, not a link.
pub fn private_dir(dir: &Path) -> std::io::Result<()> {
    imp::private_dir(dir)
}

/// Sets an existing folder private to its owner (Unix 0700).
pub fn set_private_dir(path: &Path) -> std::io::Result<()> {
    imp::set_private_dir(path)
}

/// Sets an existing file private to its owner (Unix 0600).
pub fn set_private_file(path: &Path) -> std::io::Result<()> {
    imp::set_private_file(path)
}

/// Adds to `options`: a new file is private to us (Unix mode 0600), and the
/// last part of the path is never followed as a link (Unix `O_NOFOLLOW`).
pub fn private_no_follow(options: &mut OpenOptions) -> &mut OpenOptions {
    imp::private_no_follow(options)
}

// ---- 1. The daemon's endpoint ------------------------------------------

/// The daemon's listening endpoint (a Unix socket; a named pipe on Windows).
pub type Listener = imp::Listener;
/// One connection to or from the daemon's endpoint.
pub type Stream = imp::Stream;

/// Binds the daemon's endpoint at `path`: its folder made private when
/// missing and refused when it is a link or another user's, a stale endpoint
/// replaced, the endpoint itself private.
pub fn bind(path: &Path) -> std::io::Result<Listener> {
    imp::bind(path)
}

/// Connects to the daemon's endpoint at `path`.
pub fn connect(path: &Path) -> std::io::Result<Stream> {
    imp::connect(path)
}

// ---- 2. The peer -------------------------------------------------------

/// Who is on the other end of a connection, and our own ancestry (Unix:
/// `crate::peer`, `SO_PEERCRED` and `/proc`; Windows: lane Z's token-based
/// peer, note AU section 2.3).
#[cfg(unix)]
pub use crate::peer;

// ---- 6. One daemon per user --------------------------------------------

/// Takes an exclusive lock on `file` without waiting. `true` when we hold it;
/// `false` when another process does. The lock dies with its process.
pub fn try_lock_exclusive(file: &File) -> bool {
    imp::try_lock_exclusive(file)
}

// ---- 7. The host's name ------------------------------------------------

/// This machine's name, or `""` when the system does not say.
pub fn host_name() -> String {
    imp::host_name()
}
