//! Starting the harness as the agents' user (wave 5, lane V; S2 part c, rules
//! cases 53 and 125). The wave 5 base cut this seam: `run_io` calls [`wrap`]
//! on the launch plan just before the harness starts, and adds the returned
//! record to `run.start` as `detail.agentUser` (`contracts/events.md`
//! section 5).
//!
//! Lane V owns this folder. The base's stub changes nothing: the harness
//! starts as you, as before, and there is no record.

use serde_json::Value;

pub(crate) mod anchor;
pub(crate) mod bridge;

use super::plan::Plan;

/// The wave 5 base's stub: the launch unchanged, no record.
pub(crate) fn wrap(launch: &mut Plan) -> Result<Option<Value>, (u8, String)> {
    let _ = launch;
    Ok(None)
}
