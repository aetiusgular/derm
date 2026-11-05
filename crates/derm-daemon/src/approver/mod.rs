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

/// The platform's password checker, found once.
fn person_checker() -> &'static dyn person::Checker {
    static CHECKER: std::sync::OnceLock<Box<dyn person::Checker>> = std::sync::OnceLock::new();
    CHECKER.get_or_init(person::platform).as_ref()
}

/// One back-off for the whole daemon: a new connection waits as long.
fn person_backoff() -> &'static person::Backoff {
    static BACKOFF: std::sync::OnceLock<person::Backoff> = std::sync::OnceLock::new();
    BACKOFF.get_or_init(person::Backoff::default)
}

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

    /// `op_answer` with S2 part b's person check (lane V). A `yes` that an
    /// agent could have forged (`person::needed`) passes only with the
    /// person's password, checked by the system's helper with a back-off;
    /// otherwise it is refused and the request keeps waiting, so the person
    /// can still answer, or it times out to `no`. A `no` needs nothing.
    /// `ran_as_you`: a chat has run as the person, unbounded, since the daemon
    /// started. Integration's request V-2 calls this from `dispatch` with the
    /// `answer` line's `proof`; until then `op_answer` above is what runs.
    pub fn op_answer_proved(
        &self,
        conn: u64,
        id: &str,
        chat: Option<&str>,
        answer: Answer,
        password: Option<&mut Vec<u8>>,
        ran_as_you: bool,
    ) -> Reply {
        if answer == Answer::Yes {
            // The chat the yes is for: named, or the one chat waiting on `id`.
            let target = match chat {
                Some(c) => Some(c.to_string()),
                None => self.pending.lock().ok().and_then(|p| {
                    let mut w = p.keys().filter(|(_, i)| i == id).map(|(c, _)| c.clone());
                    match (w.next(), w.next()) {
                        (Some(c), None) => Some(c),
                        _ => None,
                    }
                }),
            };
            let Some(target) = target else {
                if let Some(p) = password {
                    person::wipe(p);
                }
                return self.op_answer(conn, id, chat, answer);
            };
            let why = {
                let runs = self.run_info.lock().map(|r| r.clone()).unwrap_or_default();
                person::needed(&runs, &target, ran_as_you)
            };
            if let Some(why) = why {
                let verdict = match person::own_user() {
                    Some(user) => person::verify(
                        person_checker(),
                        person_backoff(),
                        &user,
                        password,
                        std::time::Instant::now(),
                    ),
                    None => {
                        if let Some(p) = password {
                            person::wipe(p);
                        }
                        person::Verdict::Unavailable(
                            "the daemon cannot read its own user name".into(),
                        )
                    }
                };
                self.person_event(conn, &target, id, &why, &verdict);
                match verdict {
                    person::Verdict::Person => {}
                    person::Verdict::Wrong(w) => {
                        return error(format!("your password is needed because {why}: {w}"))
                    }
                    person::Verdict::Unavailable(u) => {
                        return error(format!("your password is needed because {why}, and {u}"))
                    }
                }
            } else if let Some(p) = password {
                person::wipe(p);
            }
        } else if let Some(p) = password {
            person::wipe(p);
        }
        self.op_answer(conn, id, chat, answer)
    }

    /// Records a person check: the chat, the request, why it was needed and
    /// what it found. Never the password.
    fn person_event(&self, conn: u64, chat: &str, id: &str, why: &str, verdict: &person::Verdict) {
        let (passed, detail) = match verdict {
            person::Verdict::Person => (true, None),
            person::Verdict::Wrong(w) => (false, Some(w.as_str())),
            person::Verdict::Unavailable(u) => (false, Some(u.as_str())),
        };
        self.ingest(Event {
            id: format!("person-{}", uuid::Uuid::new_v4().simple()),
            at: 0,
            chat_id: clip(chat, 128),
            harness: String::new(),
            source: Source::Approval,
            kind: "person.check".into(),
            summary: clip(
                &if passed {
                    format!("person check passed for {}", clip(id, 64))
                } else {
                    format!("person check failed for {}", clip(id, 64))
                },
                200,
            ),
            detail: json!({
                "passed": passed,
                "why": why,
                "result": detail,
                "request": clip(id, 128),
                "conn": conn,
            }),
            pid: None,
            approval_id: None,
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::store::ActivityLog;
    use std::sync::mpsc::Receiver;

    const TOKEN: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn daemon() -> (Arc<Daemon>, std::path::PathBuf) {
        let root =
            std::env::temp_dir().join(format!("derm-lane-v-{}", uuid::Uuid::new_v4().simple()));
        let data = root.join("data");
        let log: &'static ActivityLog =
            Box::leak(Box::new(ActivityLog::start(data.join("activity"))));
        (Daemon::new(TOKEN, log, &data, false).unwrap(), root)
    }

    fn line(rx: &Receiver<String>) -> Value {
        serde_json::from_str(&rx.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap()
    }

    fn start(d: &Arc<Daemon>, chat: &str, detail: Value) {
        let (out, rx, _) = Outbox::new(d.next_conn());
        d.handle(
            &Who::Daemon,
            Request::Event {
                event: Event {
                    id: format!("start-{chat}"),
                    at: 0,
                    chat_id: chat.into(),
                    harness: "pi".into(),
                    source: Source::Run,
                    kind: "run.start".into(),
                    summary: String::new(),
                    detail,
                    pid: Some(std::process::id()),
                    approval_id: None,
                },
            },
            &out,
        );
        assert_eq!(line(&rx)["ok"], true);
    }

    /// An approver, then one waiting `approve` from `chat`; returns the
    /// approver's conn, its pushes, the request id and the asker's thread.
    fn ask(
        d: &Arc<Daemon>,
        chat: &str,
    ) -> (
        u64,
        Receiver<String>,
        String,
        std::thread::JoinHandle<Value>,
    ) {
        let (approver, pushes, _) = Outbox::new(d.next_conn());
        d.handle(&Who::Daemon, Request::Approver {}, &approver);
        assert_eq!(line(&pushes)["ok"], true);
        let asker = d.clone();
        let who = Who::Chat {
            chat: chat.into(),
            harness: "pi".into(),
        };
        let request: ApprovalRequest = serde_json::from_value(json!({
            "id": "ap-1", "chat": chat, "harness": "pi", "tool": "bash",
            "summary": "run a command", "timeoutSeconds": 5
        }))
        .unwrap();
        let t = std::thread::spawn(move || {
            let (out, rx, _) = Outbox::new(asker.next_conn());
            asker.handle(&who, Request::Approve { request }, &out);
            line(&rx)
        });
        let push = line(&pushes);
        let id = push["approve"]["id"].as_str().unwrap().to_string();
        (approver.conn, pushes, id, t)
    }

    #[test]
    fn a_yes_for_a_chat_that_runs_as_you_needs_the_password_and_a_no_does_not() {
        let (d, root) = daemon();
        start(&d, "you-chat", json!({"boundary": "none"}));
        let (conn, _p, id, asker) = ask(&d, "you-chat");
        let r = d.op_answer_proved(conn, &id, Some("you-chat"), Answer::Yes, None, false);
        assert!(!r.ok, "{r:?}");
        let err = r.error.unwrap_or_default();
        assert!(
            err.contains("password is needed") && err.contains("runs as you"),
            "{err}"
        );
        // Still waiting: the person can answer no.
        let r = d.op_answer_proved(conn, &id, Some("you-chat"), Answer::No, None, false);
        assert!(r.ok, "{r:?}");
        let answer = asker.join().unwrap();
        assert_eq!(answer["answer"], "no", "{answer}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_yes_for_an_srt_chat_needs_nothing_unless_a_chat_runs_as_you() {
        let (d, root) = daemon();
        start(&d, "srt-chat", json!({"boundary": "srt"}));
        let (conn, _p, id, asker) = ask(&d, "srt-chat");
        let r = d.op_answer_proved(conn, &id, None, Answer::Yes, None, false);
        assert!(r.ok, "{r:?}");
        assert_eq!(asker.join().unwrap()["answer"], "yes");

        start(&d, "you-chat", json!({"boundary": "none"}));
        let (conn, _p, id, asker) = ask(&d, "srt-chat");
        let r = d.op_answer_proved(conn, &id, None, Answer::Yes, None, false);
        assert!(r
            .error
            .unwrap_or_default()
            .contains("can answer for others"));
        assert!(
            d.op_answer_proved(conn, &id, None, Answer::No, None, false)
                .ok
        );
        assert_eq!(asker.join().unwrap()["answer"], "no");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_chat_that_ran_as_you_since_start_keeps_the_check_on() {
        let (d, root) = daemon();
        start(&d, "srt-chat", json!({"boundary": "srt"}));
        let (conn, _p, id, asker) = ask(&d, "srt-chat");
        let r = d.op_answer_proved(conn, &id, None, Answer::Yes, None, true);
        assert!(r
            .error
            .unwrap_or_default()
            .contains("since the daemon started"));
        assert!(
            d.op_answer_proved(conn, &id, None, Answer::No, None, true)
                .ok
        );
        let _ = asker.join();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_failed_check_is_recorded_without_the_password() {
        let (d, root) = daemon();
        start(&d, "you-chat", json!({"boundary": "none"}));
        let (conn, _p, id, asker) = ask(&d, "you-chat");
        let mut pw = b"derm-lane-v-secret".to_vec();
        let _ = d.op_answer_proved(conn, &id, None, Answer::No, Some(&mut pw), false);
        assert!(pw.iter().all(|b| *b == 0), "a no wipes the password too");
        let _ = asker.join();
        let (conn, _p, id, asker) = ask(&d, "you-chat");
        let _ = d.op_answer_proved(conn, &id, None, Answer::Yes, None, false);
        let _ = d.op_answer_proved(conn, &id, None, Answer::No, None, false);
        let _ = asker.join();
        let events: Vec<Event> = d.order.lock().unwrap().iter().cloned().collect();
        let checks: Vec<&Event> = events.iter().filter(|e| e.kind == "person.check").collect();
        assert_eq!(checks.len(), 1, "one check, for the yes");
        assert_eq!(checks[0].detail["passed"], false);
        let all = serde_json::to_string(&events).unwrap();
        assert!(!all.contains("derm-lane-v-secret"));
        let _ = std::fs::remove_dir_all(root);
    }
}
