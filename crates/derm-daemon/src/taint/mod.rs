//! Taint in the daemon (wave 6, lane 6D; `plans/toolkit_wave6_plan.md`
//! section 2.2; `contracts/events.md` section 6.2). The wave 6 base's empty
//! folder: lane 6D adds the chat's taint state the gate asks for over the
//! socket, fed by the tap's results (`derm-tap/src/results/`) and the post
//! hooks, with any fingerprint of a result kept under a key the agent cannot
//! read (note AZ, D4). Nothing calls it on the base.

/// Whether a chat is tainted, as the daemon knows it. The base's stub: no
/// chat is.
pub fn is_tainted(_chat: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stub_taints_no_chat() {
        assert!(!super::is_tainted("c"));
    }
}
