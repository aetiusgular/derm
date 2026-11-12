//! The Standard tier (wave 6, lane 6A; `plans/toolkit_wave6_plan.md` section
//! 2.1; `contracts/sandbox.md`). The wave 6 base cut this seam: `run_io`
//! calls [`environment`] once the plan is built, after the tap's, and adds a
//! returned record to `run.start` as `detail.tier` (`contracts/events.md`
//! section 6.1). The stub returns no record and changes nothing, so every
//! chat still runs as before (the Whole tier or none, as `--boundary` says).
//!
//! What lane 6A builds here, from note AZ (rows A1 to A11, AZ-7, AZ-12): the
//! agent's own sandbox written from derm's policy and delivered by `derm run`
//! (Claude Code by its own `--settings` file, Codex by `-c` pairs at its
//! own level), never by the user's files alone; one tier per chat under srt,
//! the vendor's sandbox kept on inside sbx; a refusal when the effective
//! settings carry `excludedCommands` or an escape hatch (cases 213 to 215).

use serde_json::Value;

use super::args::Boundary;
use super::plan::Plan;

/// The seam `run_io` calls. `Ok(None)`: no Standard-tier record (the stub).
/// An `Err` stops the run before the harness starts, as the tap's does.
pub(crate) fn environment(
    _harness: &str,
    _boundary: Boundary,
    _plan: &mut Plan,
) -> Result<Option<Value>, (u8, String)> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The base's stub changes nothing (the wave 6 base's gate).
    #[test]
    fn the_stub_adds_no_record_and_leaves_the_plan_alone() {
        let mut p = Plan {
            program: "claude".into(),
            args: vec!["-p".into(), "hi".into()],
            env_set: Vec::new(),
            env_remove: Vec::new(),
            kit: None,
            sandbox_name: None,
            srt_settings: None,
            folders: Vec::new(),
            state_dirs: Vec::new(),
            notes: Vec::new(),
            full_access: Vec::new(),
            companion: None,
            scratch_dir: None,
        };
        let before = format!("{p:?}");
        assert_eq!(
            environment("claude-code", Boundary::None, &mut p).unwrap(),
            None
        );
        assert_eq!(format!("{p:?}"), before);
    }
}
