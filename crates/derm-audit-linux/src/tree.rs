//! Which chat an action belongs to, by process tree.
//!
//! The kernel cannot filter by tree (auditctl 3.1.2 has `ppid`, one level,
//! and nothing that follows descendants), so the rules filter by user and
//! this places each action. A process is in a chat's tree when it is the
//! root `derm run` started, when a member forked it (the parent's `clone`,
//! `fork`, `vfork` or `clone3` record names the child in `exit`), or when
//! its `ppid` is a member. The fork record matters: an orphan made with
//! `( setsid sh -c ... & )` already has `ppid=1` on its own first record
//! (`tests/fixtures/scenario1.raw.audit`, pid 1037).
//!
//! Records can arrive before `derm run`'s `run.start` reaches the feed (the
//! harness's own exec is the first). Unplaced actions wait in a bounded
//! buffer and are replayed when a root registers.

use std::collections::{HashMap, VecDeque};

use crate::action::{Action, What};

/// How long an unplaced action waits for its root, by its own timestamp.
pub const PENDING_MS: i64 = 15_000;
/// At most this many unplaced actions wait.
pub const PENDING_MAX: usize = 20_000;
/// How far past a chat's `run.stop` (by the stop's own time) a process that
/// had exited by then still places what the log says it did. The audit
/// stamps are the kernel's realtime clock and `run.stop`'s `at` the same
/// host's, so this covers the stop being written a moment after the last
/// exit (BW5R4-2).
pub const STOP_SLACK_MS: i64 = 2_000;
/// A stopped chat is kept for a feed that is behind until the log it reads
/// passes the stop, and at most this long by the feed's own clock after the
/// stop reached it (the daemon's join keeps its chats as long, MW5-34).
pub const STOP_KEEP_MAX_MS: i64 = 10 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    pub chat: String,
    pub harness: String,
    pub pid: u32,
    /// The chat's folders: writes inside them are expected.
    pub folders: Vec<String>,
    /// The harness's own state folders (`~/.pi/agent` for Pi), noise for
    /// the write check.
    pub state: Vec<String>,
    pub at: i64,
    /// `run.stop` was seen; the root process has ended.
    pub stopped: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pub chat: String,
    pub harness: String,
    pub root_pid: u32,
    /// The action is the root process's own.
    pub is_root: bool,
}

#[derive(Default)]
pub struct Tracker {
    roots: HashMap<u32, Root>,
    members: HashMap<u32, u32>,
    pending: VecDeque<Action>,
    dropped: u64,
    /// For a stopped root: the stop's own time and when the stop reached
    /// the feed (by `now`).
    stops: HashMap<u32, (i64, i64)>,
    /// Members that had exited at their chat's stop: the last log time at
    /// which an action of theirs is still the chat's (BW5R4-2).
    late: HashMap<u32, i64>,
    /// The newest audit time placed or waited on: how far the log is read.
    log_ms: i64,
    clock: Option<fn() -> i64>,
}

impl Tracker {
    pub fn new() -> Tracker {
        Tracker::default()
    }

    /// The feed's own clock, for `STOP_KEEP_MAX_MS` (tests set it).
    pub fn set_clock(&mut self, clock: fn() -> i64) {
        self.clock = Some(clock);
    }

    fn now(&self) -> i64 {
        match self.clock {
            Some(c) => c(),
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
        }
    }

    /// The newest audit time the feed has read.
    pub fn log_ms(&self) -> i64 {
        self.log_ms
    }

    pub fn root(&self, root_pid: u32) -> Option<&Root> {
        self.roots.get(&root_pid)
    }

    pub fn roots(&self) -> impl Iterator<Item = &Root> {
        self.roots.values()
    }

    /// Unplaced actions dropped because the buffer was full or they aged out.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Registers a root and replays the waiting actions, returning those now
    /// placed in timestamp order. A second root with the same pid replaces
    /// the first (a reused pid after the first chat stopped).
    pub fn register(&mut self, root: Root) -> Vec<(Action, Placement)> {
        let pid = root.pid;
        self.unregister_pid(pid);
        // The pid may have been a dead member of a chat still kept after its
        // stop: its cut-off was that process's, not this root's (fp13's
        // review, FP13R-2).
        self.late.remove(&pid);
        self.members.insert(pid, pid);
        self.roots.insert(pid, root);
        let waiting: Vec<Action> = self.pending.drain(..).collect();
        let mut placed = Vec::new();
        for action in waiting {
            match self.place_inner(&action) {
                Some(p) => placed.push((action, p)),
                None => self.pending.push_back(action),
            }
        }
        placed
    }

    /// A chat's root process ended (`run.stop`, stamped `at`). Members still
    /// alive stay placed, so a process the harness left running (a daemon it
    /// started) is still the chat's. A member that had exited, the root
    /// included, places what the log says it did up to `at` and
    /// `STOP_SLACK_MS`, and nothing after: a feed that is behind reads the
    /// stop before the chat's last lines (BW5R4-2). The chat is kept until
    /// the log passes that time, at most `STOP_KEEP_MAX_MS`; then dead
    /// members are dropped and the root goes when none is left.
    pub fn stop(&mut self, chat: &str, at: i64, alive: &dyn Fn(u32) -> bool) {
        let now = self.now();
        let deadline = at.saturating_add(STOP_SLACK_MS);
        let pids: Vec<u32> = self
            .roots
            .values()
            .filter(|r| r.chat == chat && !r.stopped)
            .map(|r| r.pid)
            .collect();
        for pid in &pids {
            if let Some(r) = self.roots.get_mut(pid) {
                r.stopped = true;
            }
            self.stops.insert(*pid, (at, now));
        }
        for (member, root) in &self.members {
            if pids.contains(root) && (*member == *root || !alive(*member)) {
                self.late.insert(*member, deadline);
            }
        }
        self.prune(alive);
    }

    /// Whether a stopped root is still kept for a feed that is behind.
    fn kept(&self, root: u32, now: i64) -> bool {
        self.stops.get(&root).is_some_and(|(at, seen)| {
            self.log_ms <= at.saturating_add(STOP_SLACK_MS)
                && now.saturating_sub(*seen) < STOP_KEEP_MAX_MS
        })
    }

    /// Drops members that no longer run, and stopped roots with no member
    /// left, once the log has passed their stop (`stop`). The feed calls it
    /// after a stop, when the log goes quiet, and once a minute.
    pub fn prune(&mut self, alive: &dyn Fn(u32) -> bool) {
        self.age_pending(self.age_base());
        let now = self.now();
        let stopped: Vec<(u32, bool)> = self
            .roots
            .values()
            .filter(|r| r.stopped)
            .map(|r| (r.pid, self.kept(r.pid, now)))
            .collect();
        let late = &self.late;
        self.members
            .retain(|pid, root| match stopped.iter().find(|(r, _)| r == root) {
                Some((_, true)) => true,
                // The root process itself has ended; its pid may be reused. So
                // may a member's that had exited at the stop.
                Some((_, false)) => *pid != *root && !late.contains_key(pid) && alive(*pid),
                None => *pid == *root || alive(*pid),
            });
        let held: std::collections::HashSet<u32> = self.members.values().copied().collect();
        self.roots.retain(|pid, r| !r.stopped || held.contains(pid));
        let roots = &self.roots;
        self.stops.retain(|pid, _| roots.contains_key(pid));
        let members = &self.members;
        self.late.retain(|pid, _| members.contains_key(pid));
    }

    /// Drops a chat's root and every member under it.
    pub fn unregister(&mut self, chat: &str) {
        let pids: Vec<u32> = self
            .roots
            .values()
            .filter(|r| r.chat == chat)
            .map(|r| r.pid)
            .collect();
        for pid in pids {
            self.unregister_pid(pid);
        }
    }

    fn unregister_pid(&mut self, root_pid: u32) {
        if self.roots.remove(&root_pid).is_some() {
            self.members.retain(|_, r| *r != root_pid);
            self.stops.remove(&root_pid);
            let members = &self.members;
            self.late.retain(|pid, _| members.contains_key(pid));
        }
    }

    /// A member that had exited at its chat's stop, acting after the stop's
    /// time: its pid was reused, and the action is not the chat's.
    fn too_late(&self, pid: u32, ts: i64) -> bool {
        self.late.get(&pid).is_some_and(|d| ts > *d)
    }

    /// Places one action, or keeps it waiting. Fork actions update the tree.
    pub fn place(&mut self, action: &Action) -> Option<Placement> {
        // The kernel stamps with the coarse realtime clock (linux
        // `kernel/auditsc.c`, `ktime_get_coarse_real_ts64`), which a clock
        // step moves: a stamp ahead of the feed's own clock is not progress,
        // or one record would end every stop's keep (fp13's review, FP13R-8;
        // the join's FP11-S4).
        if action.ts_ms <= self.now().saturating_add(STOP_SLACK_MS) {
            self.log_ms = self.log_ms.max(action.ts_ms);
        }
        self.age_pending(self.age_base());
        let placed = self.place_inner(action);
        if placed.is_none() {
            self.wait(action.clone());
        }
        placed
    }

    fn place_inner(&mut self, action: &Action) -> Option<Placement> {
        let root_pid = match self.members.get(&action.pid) {
            Some(r) if !self.too_late(action.pid, action.ts_ms) => *r,
            Some(_) => return None,
            None => {
                if self.too_late(action.ppid, action.ts_ms) {
                    return None;
                }
                let r = *self.members.get(&action.ppid)?;
                self.members.insert(action.pid, r);
                // A child of a member that had exited at the stop was made
                // before the stop: it is held to the same time.
                if let Some(d) = self.late.get(&action.ppid).copied() {
                    self.late.insert(action.pid, d);
                }
                r
            }
        };
        if let What::Fork { child } = action.what {
            self.members.insert(child, root_pid);
            if let Some(d) = self.late.get(&action.pid).copied() {
                self.late.insert(child, d);
            } else {
                self.late.remove(&child);
            }
        }
        let root = self.roots.get(&root_pid)?;
        Some(Placement {
            chat: root.chat.clone(),
            harness: root.harness.clone(),
            root_pid,
            is_root: action.pid == root_pid,
        })
    }

    fn wait(&mut self, action: Action) {
        // A fork outside every tree that hands out a pid a tree still holds
        // means that pid was reused: the new process is not the member.
        if let What::Fork { child } = action.what {
            if self.members.get(&child).is_some_and(|r| *r != child) {
                self.members.remove(&child);
                self.late.remove(&child);
            }
        }
        self.pending.push_back(action);
        self.age_pending(self.age_base());
    }

    /// The time waiting actions age against: the log's, never past the
    /// feed's own clock by more than the slack. `log_ms` is a running
    /// maximum, so after the clock stepped back it stays ahead, and every
    /// action that waited for its chat's `run.start` was dropped at once
    /// (fp13's second re-review, FP13RR2-2). A feed that is behind has its
    /// log time under the clock and ages by it, as before (BW5R4-1).
    fn age_base(&self) -> i64 {
        self.log_ms.min(self.now().saturating_add(STOP_SLACK_MS))
    }

    /// Lets go of waiting actions more than `PENDING_MS` older than the log
    /// the feed has read (its time, never the clock: a feed that is behind
    /// reads old lines, BW5R4-1). Until the re-review's FP13RR-3 this ran
    /// only when another action waited, so a stranger's lone action, with
    /// only placed ones after it, waited for good and held the kept place.
    fn age_pending(&mut self, newest: i64) {
        while self
            .pending
            .front()
            .is_some_and(|a| newest - a.ts_ms > PENDING_MS)
            || self.pending.len() > PENDING_MAX
        {
            self.pending.pop_front();
            self.dropped += 1;
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// The `(time, serial)` of each action waiting for its root.
    pub fn pending_keys(&self) -> impl Iterator<Item = (i64, u64)> + '_ {
        self.pending.iter().map(|a| (a.ts_ms, a.serial))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn act(ts: i64, pid: u32, ppid: u32, what: What) -> Action {
        Action {
            ts_ms: ts,
            serial: ts as u64,
            pid,
            ppid,
            uid: Some(1000),
            comm: "x".into(),
            exe: "/bin/x".into(),
            key: "derm_exec".into(),
            syscall: "execve",
            denied: false,
            cwd: None,
            what,
        }
    }

    fn root(pid: u32) -> Root {
        Root {
            chat: "c1".into(),
            harness: "pi".into(),
            pid,
            folders: vec!["/w".into()],
            state: vec![],
            at: 0,
            stopped: false,
        }
    }

    fn exec() -> What {
        What::Exec {
            argv: vec!["x".into()],
        }
    }

    #[test]
    fn an_orphan_is_followed_through_its_fork_record() {
        let mut t = Tracker::new();
        t.register(root(10));
        assert!(t.place(&act(1, 10, 1, What::Fork { child: 11 })).is_some());
        assert!(t.place(&act(2, 11, 10, What::Fork { child: 12 })).is_some());
        // 12 was reparented to init before its first own record.
        let p = t.place(&act(3, 12, 1, exec())).unwrap();
        assert_eq!(p.chat, "c1");
        assert!(!p.is_root);
        assert!(t.place(&act(4, 10, 1, exec())).unwrap().is_root);
    }

    #[test]
    fn records_before_the_root_registers_are_replayed() {
        let mut t = Tracker::new();
        assert!(t.place(&act(1, 10, 5, exec())).is_none());
        assert!(t.place(&act(2, 10, 5, What::Fork { child: 11 })).is_none());
        assert!(t.place(&act(3, 11, 10, exec())).is_none());
        assert!(t.place(&act(3, 99, 5, exec())).is_none());
        let placed = t.register(root(10));
        assert_eq!(placed.len(), 3);
        assert_eq!(t.pending_len(), 1, "the unrelated process still waits");
    }

    #[test]
    fn the_pending_buffer_is_bounded_in_time() {
        let mut t = Tracker::new();
        t.place(&act(0, 50, 1, exec()));
        t.place(&act(PENDING_MS + 1, 51, 1, exec()));
        assert_eq!(t.pending_len(), 1);
        assert_eq!(t.dropped(), 1);
    }

    #[test]
    fn an_unregistered_chat_places_nothing_more() {
        let mut t = Tracker::new();
        t.register(root(10));
        t.place(&act(1, 10, 1, What::Fork { child: 11 }));
        t.unregister("c1");
        assert!(t.place(&act(2, 11, 10, exec())).is_none());
    }

    #[test]
    fn a_process_left_running_after_the_stop_stays_the_chats() {
        let mut t = Tracker::new();
        t.register(root(10));
        t.place(&act(1, 10, 1, What::Fork { child: 11 }));
        t.place(&act(1, 10, 1, What::Fork { child: 12 }));
        // The root (10) and 12 have exited; 11 is a daemon the harness left.
        // The stop is at 2; the log is read past it below (BW5R4-2).
        t.stop("c1", 2, &|pid| pid == 11);
        let after = 2 + STOP_SLACK_MS + 1;
        assert_eq!(t.place(&act(after, 11, 1, exec())).unwrap().chat, "c1");
        assert!(t.place(&act(after, 12, 1, exec())).is_none());
        // Once 11 is gone too, the root goes.
        t.prune(&|_| false);
        assert!(t.root(10).is_none());
        assert!(t.place(&act(after + 1, 11, 1, exec())).is_none());
    }

    #[test]
    fn a_reused_pid_forked_from_outside_leaves_the_tree() {
        let mut t = Tracker::new();
        t.register(root(10));
        t.place(&act(1, 10, 1, What::Fork { child: 11 }));
        // 11 exits; an unrelated shell forks a new 11.
        t.place(&act(2, 300, 1, What::Fork { child: 11 }));
        assert!(t.place(&act(3, 11, 300, exec())).is_none());
    }

    #[test]
    fn unrelated_processes_of_the_same_user_are_not_placed() {
        let mut t = Tracker::new();
        t.register(root(10));
        assert!(t.place(&act(1, 77, 1, exec())).is_none());
    }

    /// BW5R4-2 (box test w5, retest 4): a feed that is behind reads the
    /// daemon's `run.stop` before the audit lines of the chat's last seconds.
    /// Those lines are still the chat's: a process that had exited at the
    /// stop places what it did up to the stop (and the slack), nothing after.
    #[test]
    fn bw5r4_2_lines_read_after_the_stop_are_still_the_chats() {
        let mut t = Tracker::new();
        t.register(root(10));
        t.place(&act(1_000, 10, 1, What::Fork { child: 11 }));
        // run.stop at 5_000; every process has exited.
        t.stop("c1", 5_000, &|_| false);
        // Lines stamped before the stop, read after it.
        let p = t.place(&act(4_000, 11, 10, What::Fork { child: 12 }));
        assert_eq!(p.map(|p| p.chat).as_deref(), Some("c1"));
        assert_eq!(t.place(&act(4_500, 12, 11, exec())).unwrap().chat, "c1");
        // Past the stop and its slack, a dead member's pid is not the chat's,
        // nor a child it forks then.
        let after = 5_000 + STOP_SLACK_MS + 1;
        assert!(t.place(&act(after, 12, 11, exec())).is_none());
        assert!(t
            .place(&act(after, 11, 10, What::Fork { child: 13 }))
            .is_none());
        // Once the log has passed the stop, the chat goes.
        t.prune(&|_| false);
        assert!(t.root(10).is_none());
    }

    /// A stopped chat kept for a feed that is behind is let go after
    /// `STOP_KEEP_MAX_MS` of the feed's own clock, whatever the log says.
    #[test]
    fn bw5r4_2_a_kept_chat_is_let_go_after_the_cap() {
        let mut t = Tracker::new();
        t.set_clock(|| 1_000_000);
        t.register(root(10));
        t.place(&act(1_000, 10, 1, What::Fork { child: 11 }));
        t.stop("c1", 5_000, &|_| false);
        t.prune(&|_| false);
        assert!(t.root(10).is_some(), "the log has not passed the stop yet");
        t.set_clock(|| 1_000_000 + STOP_KEEP_MAX_MS + 1);
        t.prune(&|_| false);
        assert!(t.root(10).is_none());
    }

    /// A process alive at the stop (a daemon the harness left) is not held
    /// to the stop's time.
    #[test]
    fn bw5r4_2_a_member_alive_at_the_stop_keeps_its_place() {
        let mut t = Tracker::new();
        t.register(root(10));
        t.place(&act(1_000, 10, 1, What::Fork { child: 11 }));
        t.stop("c1", 5_000, &|pid| pid == 11);
        let later = 5_000 + STOP_SLACK_MS + 60_000;
        assert_eq!(t.place(&act(later, 11, 1, exec())).unwrap().chat, "c1");
    }

    /// FP13R-2 (fp13 review): a new chat's root whose pid was a dead member
    /// of a chat still kept after its stop inherits that member's `late`
    /// deadline; every action of the new root after it is refused.
    #[test]
    fn fp13r_2_a_new_root_on_a_kept_chats_dead_members_pid_is_placed() {
        let mut t = Tracker::new();
        t.register(root(10));
        t.place(&act(1_000, 10, 1, What::Fork { child: 11 }));
        // c1 stops at 5_000; 10 and 11 have exited. The log is not past it.
        t.stop("c1", 5_000, &|_| false);
        // pid 11 is reused for the next chat's root (pid_max is 32768 on
        // this box, /proc/sys/kernel/pid_max).
        let mut r2 = root(11);
        r2.chat = "c2".into();
        t.register(r2);
        let p = t.place(&act(9_000, 11, 1, exec()));
        assert_eq!(p.map(|p| p.chat).as_deref(), Some("c2"));
    }

    /// FP13R-2b: the same with the reused pid first seen as a fork child
    /// of the new chat (not the root): `late` is removed only on a fork from
    /// a non-late parent, which holds; this one is the root case alone.
    #[test]
    fn fp13r_2b_a_stopped_chat_is_not_held_open_by_a_quiet_log_forever() {
        let mut t = Tracker::new();
        t.set_clock(|| 1_000_000);
        t.register(root(10));
        t.place(&act(1_000, 10, 1, What::Fork { child: 11 }));
        t.stop("c1", 5_000, &|_| false);
        // An OS event stamped after the stop is read (another user's noise
        // is not in the rules; any line of this user's): it waits unplaced.
        t.place(&act(5_000 + STOP_SLACK_MS + 1, 77, 1, exec()));
        t.prune(&|_| false);
        assert!(t.root(10).is_none(), "the log passed the stop");
    }

    /// FP13R-8 (fp13's review): `log_ms` was the running maximum of the
    /// kernel's realtime stamps, so one record stamped ahead (a clock step)
    /// ended every stopped chat's keep at once. A stamp ahead of the feed's
    /// own clock by more than the slack is not progress.
    #[test]
    fn fp13r_8_a_stamp_ahead_of_the_clock_does_not_end_a_keep() {
        let mut t = Tracker::new();
        t.set_clock(|| 10_000);
        t.register(root(10));
        t.place(&act(1_000, 10, 1, What::Fork { child: 11 }));
        t.stop("c1", 5_000, &|_| false);
        // An unrelated record stamped an hour ahead.
        t.place(&act(10_000 + 3_600_000, 77, 1, exec()));
        t.prune(&|_| false);
        assert!(t.root(10).is_some(), "the log has not passed the stop");
        assert!(t.log_ms() < 5_000 + STOP_SLACK_MS);
    }

    /// fp13 re-review 2 (FP13RR2-2): after the clock steps back more than
    /// `PENDING_MS`, `log_ms` (a running maximum) stays ahead, and every
    /// action that must wait for its chat's `run.start` is let go at once,
    /// so a chat's first records are lost. At `2f6bce5` an action aged only
    /// against the next waiting action's own stamp.
    #[test]
    fn fp13rr2_2_a_clock_step_back_does_not_drop_what_waits_for_run_start() {
        use std::sync::atomic::{AtomicI64, Ordering};
        static NOW: AtomicI64 = AtomicI64::new(100_000);
        let mut t = Tracker::new();
        t.set_clock(|| NOW.load(Ordering::Relaxed));
        t.register(root(20));
        assert!(t.place(&act(100_000, 20, 1, exec())).is_some());
        // The clock (the kernel's stamps and the feed's own alike) stepped
        // back 60 s; a chat's root acts before its run.start reaches the feed.
        NOW.store(40_000, Ordering::Relaxed);
        assert!(t.place(&act(40_000, 10, 5, exec())).is_none());
        let placed = t.register(root(10));
        assert_eq!(
            placed.len(),
            1,
            "the root's exec was dropped while it waited"
        );
    }

    /// FP13RR-3 (fp13's re-review): a stranger's lone action waited in
    /// `pending` for good when only placed actions came after it, and held
    /// the kept place at its line. It ages out by the log's own time.
    #[test]
    fn fp13rr_3_a_stranger_does_not_wait_in_pending_for_ever() {
        let mut t = Tracker::new();
        t.register(root(10));
        assert!(t.place(&act(1_000, 77, 1, exec())).is_none());
        for i in 0..3_600 {
            let ts = 2_000 + i * 1_000;
            assert!(t.place(&act(ts, 10, 1, exec())).is_some());
        }
        assert_eq!(t.pending_len(), 0);
    }
}
