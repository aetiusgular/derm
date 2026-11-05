//! The daemon's platform code (wave 5). The seam's shared primitives are in
//! `derm_core::platform`: the daemon's endpoint (`bind`, `Listener`,
//! `Stream`), the peer, identity, private files and folders, and the
//! single-daemon lock. `platform/windows/` is lane Z's, for what only the
//! daemon needs on Windows (note AU section 12.2, step 2).

#[cfg(windows)]
pub mod windows;
