//! `derm-sysmon`: a Windows service that reads the Sysmon channel with the
//! rights an elevated reader has and hands each user's events to that
//! user's derm daemon over a named pipe (`contracts/sysmon-service.md`;
//! `plans/toolkit_wave5b_plan.md` section 0, item 3). Lane 5bE's.
//!
//! The portable part, built and tested on every OS:
//! - [`wire`]: the pipe's JSON lines;
//! - [`route`]: whose an event is (case 233);
//! - [`stream`]: one client's place, acks and gaps (case 232);
//! - [`acl`]: "only administrators can write this", decided from an
//!   owner and its access entries;
//! - [`cmdline`]: a Windows command line's words, for the argv shape;
//! - [`ingest`]: the daemon's side, without the pipe;
//! - [`decode`]: `derm-sysmon decode`.
//!
//! Windows only: [`service`] (the service, its channel reader and its pipe)
//! and [`client`] (the daemon's connection). The research behind each is
//! `tests/windows/5bE/RESEARCH.md`.

pub mod acl;
pub mod cmdline;
pub mod decode;
pub mod ingest;
pub mod route;
pub mod stream;
pub mod wire;

#[cfg(windows)]
pub mod client;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
mod win;

/// What the service does when Windows starts it.
#[cfg(windows)]
pub fn serve() -> Result<(), String> {
    service::run()
}

/// Off Windows there is no service.
#[cfg(not(windows))]
pub fn serve() -> Result<(), String> {
    Err("derm-sysmon runs only on Windows, as a service".into())
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_service_does_not_run() {
        assert!(super::serve().is_err());
    }
}
