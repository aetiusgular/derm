//! Package installs at the gate (wave 5, lane X; `plans/toolkit_universal_plan.md`
//! lane X, `contracts/policy.md` section 6, note AT). The wave 5 base cut this
//! seam: `policy::evaluate` calls [`check`] for a shell tool whose answer is
//! still `Allow` after every other step, and returns what it says. Lane X owns
//! this folder; `policy.rs` stays integration's.
//!
//! The base's stub says "not an install" for every call, so nothing changes
//! until lane X fills it against `contracts/fixtures/installs/`. The hook
//! core's copy (`packages/derm-claude-plugin/src/core/installs/`) and
//! derm-pi's (`packages/derm-pi/src/installs/`) are held equal to this one by
//! the same fixture, as the rest of the matcher is.

use crate::policy::Action;

/// The install check's answer for one shell call that is an install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallDecision {
    /// `Ask` for a new package or version, `Deny` for a name the registry
    /// does not hold or a known-malicious one (with the pre-install check on).
    pub action: Action,
    /// Shown on the card; names each package and version, never the input.
    pub reason: String,
}

/// What the install check says about a shell call, or `None` when the call
/// is not an install (or the check has nothing to add). `normalized_tool` is
/// the matcher's normalized name; `folded` is the folded, escape-decoded
/// input text the matcher already read.
///
/// The wave 5 base's stub: never an install.
pub fn check(normalized_tool: &str, folded: &str) -> Option<InstallDecision> {
    let _ = (normalized_tool, folded);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_reads_no_call_as_an_install() {
        for text in [
            "npm install left-pad",
            "npx some-made-up-name",
            "pip install requests",
            "ls -la",
        ] {
            assert_eq!(check("bash", text), None, "{text}");
        }
    }
}
