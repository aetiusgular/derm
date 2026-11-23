//! The daemon as step P's host (lane PE; `crate::project::Host`).
//!
//! `crate::project::State` asks the person across projects, records what it
//! did and charges a chat's socket share through this, so the project layer
//! reaches the approver and the log the way `approve` does without a lane
//! editing `daemon.rs`. It lives under `approver/` because that folder is a
//! child of `daemon` (declared there with `#[path]`) and reads the daemon's
//! private state, as the rest of the approver does.
//!
//! What `daemon.rs` needs to call (request PE-R1, one line after the daemon
//! is built in `new_with_state`): `approver::project::attach(&daemon);`.

use super::*;

use crate::project::{Asked, Host};

/// Hands the project layer its daemon. Idempotent: the first attach holds.
/// `daemon.rs` calls it once the daemon is built (request PE-R1).
pub(in crate::daemon) fn attach(daemon: &Arc<Daemon>) {
    let host: Arc<dyn Host> = daemon.clone();
    daemon.project.attach(Arc::downgrade(&host));
}

impl Host for Daemon {
    /// As `op_approve` does for a gate's ask: the request and its outcome
    /// are recorded (`approval-<uuid>`, case 35's last copy per id), and the
    /// answer is the approver's, `no` by `none` with none connected (case
    /// 63), `no` by `timeout` past the request's time. The card offers "this
    /// once" and "for this session" (request PE-R3); a session yes is
    /// recorded with scope `chat`, the asking chat's.
    fn ask(&self, mut request: ApprovalRequest) -> Asked {
        request.timeout_seconds = request
            .timeout_seconds
            .clamp(MIN_APPROVE_SECONDS, MAX_APPROVE_SECONDS);
        self.counters.approvals.fetch_add(1, Ordering::Relaxed);
        let record_id = format!("approval-{}", uuid::Uuid::new_v4().simple());
        self.approval_event(&record_id, &request, None, None, Value::Null);
        // Request PE-R3: the card offers "this once" and "for this session".
        request.offers = vec![AnswerScope::Once, AnswerScope::Session];
        let (answer, scope, by, approver) = self.wait_for_answer_scoped(&request, &|| false);
        self.approval_event(&record_id, &request, Some(answer), Some(by), approver);
        self.record_approval(ApprovalRecord {
            id: record_id,
            chat_id: request.chat.clone(),
            harness: request.harness.clone(),
            subject: ApprovalSubject::Tool,
            target: request.tool.clone(),
            scope: if scope == AnswerScope::Session {
                ApprovalScope::Chat
            } else {
                ApprovalScope::Once
            },
            granted: answer == Answer::Yes,
            granted_at: now_ms(),
            ended_at: None,
        });
        match (answer, scope) {
            (Answer::Yes, AnswerScope::Session) => Asked::Session,
            (Answer::Yes, AnswerScope::Once) => Asked::Once,
            (Answer::No, _) => Asked::No,
        }
    }

    fn record(&self, event: Event) {
        self.ingest(event);
    }

    fn quota(&self, chat: &str, bytes: usize) -> Result<(), String> {
        self.take_chat_quota(chat, bytes, now_ms(), std::time::Instant::now())
            .map_err(str::to_string)
    }
}

#[cfg(all(test, unix))]
#[path = "project_tests.rs"]
mod tests;
