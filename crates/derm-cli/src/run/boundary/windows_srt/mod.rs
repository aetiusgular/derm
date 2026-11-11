//! srt on Windows (wave 5b lane 5bD; `contracts/srt-windows.md`): the
//! handoff file, `derm.exe enter` as srt's command, one srt chat at a time on
//! the machine (case 230; note BC section 11: one sandbox account per
//! machine, two sandboxed processes open each other with full access, and
//! srt's CLI cannot run two chats at once).
//!
//! The seam the wave 5b base cut: `run/preflight.rs` and
//! `run/boundary/probe.rs` ask [`refusal`] whether srt may start on Windows,
//! instead of refusing outright. On the base it refuses, as `main` did.

/// Why derm does not start srt on Windows, or `None` once lane 5bD's path
/// is built and srt may start.
pub(crate) fn refusal() -> Option<&'static str> {
    Some(crate::run::preflight::SRT_ON_WINDOWS)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_base_still_refuses_srt_on_windows() {
        assert!(super::refusal().is_some());
    }
}
