//! The daemon's approver: who may answer an `approve`, how the answer is
//! waited for, and the record of each registration (integration w2's S2 part
//! a; wave 5 lane V builds parts b and c here).
//!
//! The wave 5 base moved this code out of `daemon.rs` unchanged, so lane V
//! owns a whole folder (`plans/parallel_build_tk.md` section 7c). It is a
//! child module of `daemon` (declared there with `#[path]`), so it reads the
//! daemon's private state as before; the four methods `daemon.rs` calls are
//! `pub(super)`, the only edit. The registration branch of `dispatch` and
//! `op_approve` stay in `daemon.rs`. The approver's tests stay where they
//! were: `daemon.rs`'s `an_approver_whose_process_is_gone_or_reused_is_refused`
//! and `tests/socket.rs`.

use super::*;

// S2 part b: the person check before a `yes` an agent could forge (lane V).
pub(super) mod person;

impl Daemon {
    /// Sends the request to every approver; the first answer wins. None
    /// connected: `no` at once (case 63). None in time: `no` at the timeout.
    pub(super) fn wait_for_answer(&self, request: &ApprovalRequest) -> (Answer, AnsweredBy, Value) {
        let (tx, rx) = mpsc::sync_channel::<(Answer, Value)>(1);
        {
            let Ok(mut pending) = self.pending.lock() else {
                return (Answer::No, AnsweredBy::None, Value::Null);
            };
            let key = (request.chat.clone(), request.id.clone());
            let this_chat = pending.values().filter(|p| p.chat == request.chat).count();
            if pending.contains_key(&key)
                || pending.len() >= MAX_PENDING_APPROVALS
                || this_chat >= MAX_PENDING_PER_CHAT
            {
                return (Answer::No, AnsweredBy::None, Value::Null);
            }
            pending.insert(
                key,
                Pending {
                    answer: tx,
                    chat: request.chat.clone(),
                },
            );
        }
        let line = serde_json::to_string(&Push::Approve(request.clone())).ok();
        let mut reached = 0;
        if let (Some(line), Ok(mut approvers)) = (line, self.approvers.lock()) {
            approvers.retain(|a| a.send_line(line.clone()));
            reached = approvers.len();
        }
        let outcome = if reached == 0 {
            (Answer::No, AnsweredBy::None, Value::Null)
        } else {
            match rx.recv_timeout(Duration::from_secs(u64::from(request.timeout_seconds))) {
                Ok((answer, approver)) => (answer, AnsweredBy::Approver, approver),
                Err(_) => (Answer::No, AnsweredBy::Timeout, Value::Null),
            }
        };
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&(request.chat.clone(), request.id.clone()));
        }
        outcome
    }

    pub(super) fn op_answer(
        &self,
        conn: u64,
        id: &str,
        chat: Option<&str>,
        answer: Answer,
    ) -> Reply {
        let approver = self
            .approvers
            .lock()
            .ok()
            .and_then(|a| a.iter().find(|o| o.conn == conn).cloned());
        let Some(approver) = approver else {
            return error("not an approver");
        };
        let who = match approver.peer.as_deref() {
            Some(p) => p.record(),
            None => json!({ "inProcess": true }),
        };
        let Ok(pending) = self.pending.lock() else {
            return error("busy");
        };
        let mut waiting = pending
            .iter()
            .filter(|((c, i), _)| i == id && chat.is_none_or(|want| want == c));
        match (waiting.next(), waiting.next()) {
            // The channel holds one answer: the first wins, the rest fail
            // to send and are told nothing more.
            (Some((_, p)), None) => {
                let _ = p.answer.try_send((answer, who));
                ok()
            }
            (Some(_), Some(_)) => error("two chats wait on this id: name the chat"),
            (None, _) => error("no such request, or it was answered or timed out"),
        }
    }

    /// Why a socket peer may not become an approver, if it may not
    /// (integration w2, security finding S2; lane J's request 1a). A process
    /// that is a running chat's harness or descends from one is the agent;
    /// so is one under a `derm` program (a chat this daemon may not know, from
    /// before a restart). This does not stop an agent that leaves the tree
    /// (a double fork, `setsid`, tmux, `systemd-run --user`): S2 stays open
    /// until the approver proves a person (a PAM check) or agents run as
    /// another user.
    pub(super) fn approver_refusal(&self, peer: &ConnPeer) -> Option<String> {
        let Some(cred) = peer.cred.as_ref() else {
            return Some("the daemon cannot read who is asking".into());
        };
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        if cred.uid != me {
            return Some(format!("uid {} is not this daemon's user", cred.uid));
        }
        let Some(pid) = cred.pid else {
            return Some("the OS gave no pid for the peer".into());
        };
        // The pid must still be the process read at accept (review W2-S5): a
        // child that connects and exits leaves a pid with no ancestors, and
        // without a pidfd (macOS, Linux before 6.5) nothing else catches it.
        if let Some(why) = Self::peer_moved(pid, peer.start_time) {
            return Some(why);
        }
        let mut line = vec![pid];
        line.extend(derm_core::peer::ancestors(pid));
        let runs = self.runs.lock().map(|r| r.clone()).unwrap_or_default();
        for (chat, run) in &runs {
            let harness_pid = &run.pid;
            if line.contains(harness_pid) {
                return Some(format!(
                    "it runs inside chat {} (harness pid {harness_pid})",
                    clip(chat, 128)
                ));
            }
        }
        if let Some(derm) = derm_core::peer::derm_run_ancestor(pid) {
            return Some(format!(
                "it runs under a derm process (pid {derm}), a chat's shell"
            ));
        }
        // Read last, so a pid that was reused while the walk ran is caught.
        if let Some(fd) = peer.pidfd.as_ref() {
            if !derm_core::peer::pidfd_alive(fd) {
                return Some("the process that connected has exited".into());
            }
        }
        Self::peer_moved(pid, peer.start_time)
    }

    /// Why `pid` is no longer the process whose start time was read when the
    /// connection was accepted, if it is not.
    fn peer_moved(pid: u32, at_accept: Option<u64>) -> Option<String> {
        let Some(at_accept) = at_accept else {
            return Some("the daemon could not read the process at connect".into());
        };
        match derm_core::peer::start_time(pid) {
            None => Some("the process that connected is gone".into()),
            Some(now) if now != at_accept => {
                Some(format!("pid {pid} is not the process that connected"))
            }
            Some(_) => None,
        }
    }

    /// Records an approver's registration, or its refusal, with who it was.
    pub(super) fn approver_event(&self, out: &Outbox, accepted: bool, why: Option<&str>) {
        let peer = out
            .peer
            .as_deref()
            .map(ConnPeer::record)
            .unwrap_or(Value::Null);
        let program = peer
            .get("program")
            .and_then(Value::as_str)
            .unwrap_or("unknown program")
            .to_string();
        let pid = peer.get("pid").and_then(Value::as_u64);
        let summary = match (accepted, why) {
            (true, _) => format!("approver connected: {program} (pid {})", pid.unwrap_or(0)),
            (false, why) => format!("approver refused: {}", why.unwrap_or("")),
        };
        self.ingest(Event {
            id: format!("approver-{}", uuid::Uuid::new_v4().simple()),
            at: 0,
            chat_id: String::new(),
            harness: String::new(),
            source: Source::Approval,
            kind: "approver".into(),
            summary: clip(&summary, 200),
            detail: json!({
                "accepted": accepted,
                "reason": why,
                "peer": peer,
                "conn": out.conn,
            }),
            pid: pid.and_then(|p| u32::try_from(p).ok()),
            approval_id: None,
        });
    }
}
