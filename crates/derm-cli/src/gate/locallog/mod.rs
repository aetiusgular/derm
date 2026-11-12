//! The light tier's per-chat log (wave 6, lane 6B; `plans/toolkit_wave6_plan.md`
//! section 2.1; `contracts/events.md` section 6.4). The wave 6 base cut this
//! seam: every adapter record goes through [`daemon::post_event`], which
//! calls [`after_post`] with whether the daemon took it. The stub writes
//! nothing, so a record the daemon did not take is still lost, as before
//! (note AZ, AZ-2).
//!
//! What lane 6B builds here (note AZ rows B1 to B8, AZ-1, AZ-8): with no
//! daemon, the record appended to the chat's file under `~/.derm/local/`, one
//! `write` per line, under `File::lock` with a deadline below the hook's
//! registered timeout; the line format is `derm_core::audit_chain` (v2,
//! which hashes `seq` and the kind); a pre event whose append fails is a
//! deny. Every gated call reaches this seam only where its decision is made
//! in Rust: Amp's plugin, the sbx kit's Claude Code hook and registrations
//! written from the compat and native packages' template files still decide
//! in TypeScript (note AZ, S1), and `contracts/events.md` section 6.4 lists
//! them as not covered.
//!
//! [`daemon::post_event`]: super::daemon::post_event

use std::path::Path;

use super::daemon::{AdapterEvent, Env};

/// What the light tier did with one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // lane 6B constructs `Appended` and `Failed`
pub enum Outcome {
    /// Nothing to do: the daemon took the record, or the light tier is not
    /// built (the base's stub).
    Skipped,
    /// Appended to the chat's file.
    Appended,
    /// The append failed; a pre event's caller turns this into a deny.
    Failed,
}

/// The seam `post_event` calls after the daemon answered (`posted`).
pub fn after_post(_event: &AdapterEvent, _env: &Env, _cwd: &Path, _posted: bool) -> Outcome {
    Outcome::Skipped
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    #[test]
    fn the_stub_skips_every_record() {
        let e = AdapterEvent {
            id: "claude-code-t-decision-0".into(),
            chat_id: "s-1".into(),
            harness: "claude-code".into(),
            kind: "approval".into(),
            summary: "Bash".into(),
            detail: Map::new(),
        };
        let env = Env(Default::default());
        for posted in [true, false] {
            assert_eq!(
                after_post(&e, &env, Path::new("/"), posted),
                Outcome::Skipped
            );
        }
    }
}
