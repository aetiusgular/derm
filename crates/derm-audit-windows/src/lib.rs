//! The Windows OS feed (wave 5, lane Z): process, file and network events
//! for a chat's tree, read from Sysmon's event log and turned into the
//! daemon's event shape, as `derm-audit-linux` does from `auditd` (note AU
//! section 6; Tony's call of 4 Nov, 16:50: Sysmon).
//!
//! The parser and the feed are plain Rust and build and test everywhere;
//! only the event log reader is Windows'. derm never installs Sysmon: `derm
//! setup` shows the install and asks (rules section 5, item 2). Nothing here
//! starts a process or opens the network.

pub mod feed;
pub mod sysmon;
pub mod xml;

#[cfg(windows)]
pub mod reader;
