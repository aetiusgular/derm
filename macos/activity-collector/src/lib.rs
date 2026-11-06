//! derm's activity collector (from MonoCode's, wave 3): the logic, kept
//! free of macOS calls so it builds and is tested on any host. Detection
//! only: nothing here blocks.

pub mod bundle;
pub mod caller;
pub mod daemon;
pub mod event;
pub mod filter;
pub mod lines;
pub mod log;
pub mod protocol;
pub mod replay;
pub mod retention;
pub mod seq;
pub mod service;
/// `SMAppService` for the app bundle's `register` commands. The file lives
/// with the daemon's collector seam so that CI's macOS job compiles and runs
/// it (CI does not build this workspace); see its header.
#[path = "../../../crates/derm-daemon/src/collector/sm_app_service.rs"]
pub mod sm_app_service;
pub mod timefmt;
pub mod tree;
