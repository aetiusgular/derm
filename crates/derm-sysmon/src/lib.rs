//! `derm-sysmon`: a Windows service that reads the Sysmon channel with the
//! rights an elevated reader has and hands each user's events to that
//! user's derm daemon over a named pipe (`contracts/sysmon-service.md`;
//! `plans/toolkit_wave5b_plan.md` section 0, item 3). Lane 5bE's.
//!
//! Note BC section 11 (run on the box, 10 Nov): a virtual service account
//! (`NT SERVICE\<name>`) reads the channel once it is in Event Log Readers;
//! a pipe server reads its client's pid with `GetNamedPipeClientProcessId`,
//! cannot open a virtual account's client process (`OpenProcess` fails 5),
//! names its image with `NtQuerySystemInformation` class 88, and can
//! impersonate it only after it has read from the pipe (1368 before).
//!
//! The base's stub serves nothing: [`serve`] says it is not built.

/// What the service does when Windows starts it: on the base, nothing.
pub fn serve() -> Result<(), String> {
    Err("derm-sysmon: not built yet (wave 5b lane 5bE)".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stub_serves_nothing() {
        assert!(super::serve().is_err());
    }
}
