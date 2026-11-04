//! Per-platform code that is not Unix (wave 5). `platform/windows/` is lane
//! Z's; this file only declares it. The rest of `derm` is Unix today.

#[cfg(windows)]
pub mod windows;
