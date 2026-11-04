//! The Windows OS feed (wave 5, lane Z): process, file and network events
//! for a chat's tree, turned into the daemon's event shape, as
//! `derm-audit-linux` does from `auditd`. Which source (Sysmon, ETW or
//! another) is lane Z's research note's answer (NF until then).
//!
//! Empty until lane Z, and compiled to nothing off Windows.

#[cfg(windows)]
mod windows;
