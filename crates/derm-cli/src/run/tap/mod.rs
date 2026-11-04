//! The model tap's launch environment (wave 5, lane S; rules cases 113 to
//! 115, 127). The wave 5 base cut this seam: `run_io` calls [`environment`]
//! once the plan is built, and adds the returned record to `run.start` as
//! `detail.tap` (`contracts/events.md` section 5). The variable or flag per
//! agent comes from `crates/derm-cli/src/connect/presets/wave5/tap.json`.
//!
//! Lane S owns this folder. The base's stub changes nothing: no base URL is
//! set, and there is no record (so a chat reads as it did before wave 5, not
//! as "untapped").

use serde_json::Value;

use super::plan::Plan;

/// The wave 5 base's stub: the plan unchanged, no record.
pub(crate) fn environment(harness: &str, plan: &mut Plan) -> Result<Option<Value>, (u8, String)> {
    let _ = (harness, plan);
    Ok(None)
}
