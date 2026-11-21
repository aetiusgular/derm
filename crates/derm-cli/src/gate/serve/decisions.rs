//! What `derm gate serve` decided, kept so that `approve` and `record` go on
//! its own copy and never on the answer a plugin hands back (review AI-7,
//! low, accounts integration; note CC section 6; case 287; lane PF).
//!
//! Before this, `approve` read the permission back from the reason text the
//! plugin returned (`Permission::of_reason`), so a plugin the agent can
//! change could record another permission's name, or approve an ask the
//! co-process never made. Now every decision is kept under a random id
//! (uuid v4 from the OS's random source: uuid 1.24.0 `src/rng.rs` reads
//! `getrandom`, the workspace enables no `fast-rng`) beside the call it was
//! made for, and `approve` and `record` find it by that id, or, while the
//! plugins' clients do not send the id back (`packages/*/src/serve/client.ts`
//! `answerOf` keeps only six fields), by the exact call. A call the
//! co-process never decided is refused. The prior art is derm's own
//! unguessable decision ids (case 98, `gate::daemon::decision_id`).

use std::collections::VecDeque;

use derm_core::policy::{self, Action};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::super::core::{GateAnswer, GateCall};

/// Decisions kept, at most: past it the oldest goes, and an `approve` for
/// it is refused, which the plugin turns into a deny (case 228).
pub(crate) const KEEP: usize = 4096;

/// What a call is, for finding its decision again: the harness, the tool as
/// the agent named it, the chat, the call's id, full access, and the input,
/// hashed whole. The tool's description is left out: it is not in the core's
/// call (`GateCall`), and a plugin sends the same one with both requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallKey([u8; 32]);

impl CallKey {
    pub(crate) fn of(call: &GateCall) -> CallKey {
        // A JSON array: each part framed, so no two calls share a key by
        // moving text from one field to the next.
        let parts = json!([
            call.harness,
            call.tool,
            call.chat,
            call.tool_use_id,
            call.full_access,
            call.tool_input,
        ]);
        let bytes = serde_json::to_vec(&parts).unwrap_or_default();
        CallKey(Sha256::digest(&bytes).into())
    }
}

struct Kept {
    id: String,
    key: CallKey,
    answer: GateAnswer,
}

#[derive(Default)]
pub(crate) struct Decisions {
    kept: VecDeque<Kept>,
}

impl Decisions {
    /// Keeps `answer` for the call `key` names, and returns its id.
    pub(crate) fn keep(&mut self, key: CallKey, answer: &GateAnswer) -> String {
        let id = format!("d-{}", uuid::Uuid::new_v4().simple());
        if self.kept.len() >= KEEP {
            self.kept.pop_front();
        }
        self.kept.push_back(Kept {
            id: id.clone(),
            key,
            answer: answer.clone(),
        });
        id
    }

    /// The decision kept for the call `key` names: the one under `id` when
    /// the plugin sends it back (and only if it was made for this call),
    /// else the newest for this call.
    pub(crate) fn find(&self, id: Option<&str>, key: &CallKey) -> Option<&GateAnswer> {
        match id {
            Some(id) => self
                .kept
                .iter()
                .find(|k| k.id == id)
                .filter(|k| &k.key == key)
                .map(|k| &k.answer),
            None => self
                .kept
                .iter()
                .rev()
                .find(|k| &k.key == key)
                .map(|k| &k.answer),
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.kept.len()
    }
}

fn rank(a: Action) -> u8 {
    match a {
        Action::Allow => 0,
        Action::Ask => 1,
        Action::Deny => 2,
    }
}

/// The answer `approve` and `record` go on: the co-process's own decision,
/// narrowed where the plugin narrowed it (Pi's memory index, Cline's and
/// Amp's rewrite rule, Cline's full access: each turns an allow into an ask,
/// or an ask into a deny, with a reason of its own). An answer that allows
/// more than the decision did is refused. The tool, the timeout, the
/// redaction count and the permission are always the decision's own; the
/// reason is the decision's own unless the plugin narrowed the action, when
/// it is the plugin's, the only words for why it asks. A narrowing of an
/// allow that redacted a secret-like value names `secrets`: the step the
/// core itself takes for a tool that writes or runs (`gate::core`,
/// `Step::SecretLikeValue`), from the decision's own count, never from the
/// plugin's words.
pub(crate) fn own_answer(own: &GateAnswer, theirs: &GateAnswer) -> Result<GateAnswer, String> {
    if rank(theirs.action) < rank(own.action) {
        return Err("the answer allows more than derm gate serve decided".into());
    }
    let mut a = own.clone();
    a.updated_input = None;
    if theirs.action != own.action {
        a.action = theirs.action;
        a.reason = theirs.reason.clone();
        if a.permission.is_none() && own.redacted > 0 {
            a.permission = policy::permission_of(policy::Step::SecretLikeValue);
        }
    }
    Ok(a)
}
