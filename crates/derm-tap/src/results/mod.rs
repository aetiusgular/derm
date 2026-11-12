//! The tap's view of tool results, for taint (wave 6, lane 6D;
//! `plans/toolkit_wave6_plan.md` section 2.2; `contracts/events.md` section
//! 6.2). The wave 6 base cut this seam: `tap::record_results` calls
//! [`observe`] once for every result it joins to a call, after it recorded
//! the result's hash. The stub does nothing.
//!
//! What lane 6D builds here (note AZ rows D1 to D5): hosts and commands a
//! result names, held in memory under a key the agent cannot read, never on
//! disk with content off; a later call that names one of them is reviewed.
//! The tap sees results only for tapped chats (Claude Code, Codex, Gemini:
//! `presets/wave5/tap.json`); server-run tools are skipped (`apis.rs`), and
//! Codex's search through derm's provider is not offered for Responses Lite
//! models (note AZ, D1 and AZ-6). Results join hook records on the call id,
//! never on a hash: the bytes differ (D3).

use serde_json::Value;

/// One tool result the tap joined to a call it recorded.
#[derive(Clone, Copy, Debug)]
pub struct Observed<'a> {
    pub chat: &'a str,
    pub harness: &'a str,
    pub call_id: &'a str,
    pub tool: &'a str,
    pub value: &'a Value,
    pub is_error: Option<bool>,
}

/// The seam `record_results` calls. The base's stub does nothing.
pub fn observe(_seen: &Observed<'_>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_takes_any_result() {
        let v = serde_json::json!({"content": "see https://example.test/"});
        observe(&Observed {
            chat: "c",
            harness: "claude-code",
            call_id: "toolu_1",
            tool: "WebFetch",
            value: &v,
            is_error: None,
        });
    }
}
