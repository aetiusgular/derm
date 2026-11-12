//! The daemon on Windows (wave 5, lane Z): its transport (AF_UNIX or a named
//! pipe), a peer's process and start time, the token file's ACLs. Empty
//! until lane Z's research note gives the build order. Compiled only on
//! Windows.

// Wave 5b lane 5bE: the Windows OS feed, a client of the derm-sysmon service.
pub mod sysmon_feed;
