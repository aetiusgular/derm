//! `derm cu` (wave 5, lane U; `plans/toolkit_universal_plan.md` lane U). Lane
//! U builds the `computer_use` tool's controls here, beside the daemon's
//! `computer_use/`, against `contracts/cu-tool.schema.json`.
//!
//! The wave 5 base cut this seam so lane U owns a whole folder: `main.rs`
//! sends `derm cu` here, and the stub hands it on to the wave 2 controls in
//! `watch/cu.rs` (lane K's request, integration w2), unchanged. Lane U may
//! replace the call; `watch/` stays integration's in wave 5.

pub fn main(args: &[String]) -> u8 {
    crate::watch::cu::main(args)
}
