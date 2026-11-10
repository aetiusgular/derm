//! derm's own platform code (wave 5). The seam's shared primitives are in
//! `derm_core::platform` (identity, private files, the daemon's endpoint,
//! the peer, the lock, the host's name); this folder holds what only `derm`
//! needs. On Unix that is `run/exec.rs` (the harness's process tree); on
//! Windows lane Z's `platform/windows/` provides `exec` with the same
//! functions (note AU section 12.1, primitive 5).

#[cfg(windows)]
pub mod windows;
