//! Per-platform code that is not Unix (wave 5). `platform/windows/` is lane
//! Z's; this file only declares it. The daemon is Unix today: a Unix socket
//! and Unix peer checks.

#[cfg(windows)]
pub mod windows;
