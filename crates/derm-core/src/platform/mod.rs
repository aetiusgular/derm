//! Per-platform code that is not Unix (wave 5). The wave 5 base cut this seam
//! so lane Z owns `platform/windows/` whole; this file only declares it.
//! Everything else in derm-core is Unix today (`peer.rs` is `cfg(unix)`).

#[cfg(windows)]
pub mod windows;
