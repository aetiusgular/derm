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
/// Unused outside tests until `daemon.rs` calls it (request PE-R1).
#[cfg_attr(not(all(test, unix)), allow(dead_code))]
pub(in crate::daemon) fn attach(daemon: &Arc<Daemon>) {
    let host: Arc<dyn Host> = daemon.clone();
    daemon.project.attach(Arc::downgrade(&host));
}

impl Host for Daemon {
    /// As `op_approve` does for a gate's ask: the request and its outcome
    /// are recorded (`approval-<uuid>`, case 35's last copy per id), and the
    /// answer is the approver's, `no` by `none` with none connected (case
    /// 63), `no` by `timeout` past the request's time. The protocol's answer
    /// is yes or no, so a yes is "this once" until the answer carries a
    /// scope (request PE-R3).
    fn ask(&self, mut request: ApprovalRequest) -> Asked {
        request.timeout_seconds = request
            .timeout_seconds
            .clamp(MIN_APPROVE_SECONDS, MAX_APPROVE_SECONDS);
        self.counters.approvals.fetch_add(1, Ordering::Relaxed);
        let record_id = format!("approval-{}", uuid::Uuid::new_v4().simple());
        self.approval_event(&record_id, &request, None, None, Value::Null);
        let (answer, by, approver) = self.wait_for_answer(&request, &|| false);
        self.approval_event(&record_id, &request, Some(answer), Some(by), approver);
        self.record_approval(ApprovalRecord {
            id: record_id,
            chat_id: request.chat.clone(),
            harness: request.harness.clone(),
            subject: ApprovalSubject::Tool,
            target: request.tool.clone(),
            scope: ApprovalScope::Once,
            granted: answer == Answer::Yes,
            granted_at: now_ms(),
            ended_at: None,
        });
        if answer == Answer::Yes {
            Asked::Once
        } else {
            Asked::No
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
