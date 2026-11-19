//! Whether the audit rules loaded now record reads of each sensitive path
//! that exists now (E1-3, eval pass 1).
//!
//! The rules file is made once, by root, from the paths that exist then
//! (`rules.rs`). A sensitive folder made afterwards (`~/.aws` on the box,
//! made by a test script after the rules were installed) has no rule, and so
//! does one deleted and made again (an audit watch is on the inode), and so
//! does every path when the rules are not loaded. Reads there leave no
//! record, and nothing said so: the report read as a full watch.
//!
//! The feed cannot read the loaded rules (`auditctl -l` needs root) and
//! cannot load one. It can ask the kernel the one question that matters: it
//! opens each sensitive path that exists, read-only, and looks for its own
//! open in the log with the key `derm_sens`. Run in the cloud workspace on
//! 16 Nov 2026 (auditd 3.1.2, a plain user, the rules of `rules.rs`):
//!
//! - a folder under a `-F dir=` rule: the open of the folder itself has a
//!   record, key `derm_sens`, PATH `name` the path as it was opened;
//! - a file under a `-F path=` rule: the same;
//! - `/etc/shadow`, which the user cannot open: a record all the same, with
//!   `success=no exit=-13`, so a path need not be readable to be checked;
//! - a folder made after the rules were loaded: no record.
//!
//! The lines are in `tests/fixtures/e1-3-probe.auditd-3.1.2.audit`.
//!
//! The opens are the feed's own, so they never become events (`feed.rs`
//! drops its own pid's records). A round is settled once the log has been
//! read past the opens: a record `SETTLE_MS` newer than them, or a quiet log
//! that long after them. What is then unseen is not watched. The feed posts
//! the list as `feed.unwatched` when it changes; the daemon's report names
//! it.
//!
//! What this does not do: record the reads. Those made between the folder's
//! creation and the next install of the rules are not in the log, and the
//! report says so, with the paths and what to run.

use crate::record::{hex_or_text, Record};
use std::collections::{BTreeSet, HashSet};

/// The key of the sensitive rules (`rules.rs`).
const KEY: &str = "derm_sens";
/// How long after the opens the log must have been read to, before a path
/// with no record is called unwatched. auditd writes a record within
/// milliseconds; its `flush = INCREMENTAL_ASYNC` default and the feed's own
/// 100 ms poll are well inside this.
pub const SETTLE_MS: i64 = 3_000;
/// How often the check runs again with nothing new on disk: rules installed
/// since clear the list within this.
pub const AGAIN_MS: i64 = 10 * 60_000;
/// And while the last list was not empty: the person may have just run what
/// the report told them to (the review's E1R-15).
pub const AGAIN_UNWATCHED_MS: i64 = 30_000;

/// A settled round: the paths with no record, and whether the feed saw no
/// record of its own opens at all. That is not a rule missing for each
/// path: auditd is stopped, the rules are not loaded, or they name another
/// uid than the feed's (the review's E1R-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settled {
    pub unwatched: Vec<String>,
    pub none_seen: bool,
}

struct Round {
    begun_ms: i64,
    asked: BTreeSet<String>,
    seen: BTreeSet<String>,
    /// The feed's own `derm_sens` events of this round, by audit event key.
    own: HashSet<(i64, u64)>,
    /// A record newer than the opens by `SETTLE_MS` was read.
    passed: bool,
}

pub struct WatchCheck {
    own_pid: u32,
    round: Option<Round>,
    done_ms: Option<i64>,
    /// The sensitive paths that did not exist at the last round.
    missing: Vec<String>,
    /// The last list handed out by `settle`.
    last: Option<Vec<String>>,
}

impl WatchCheck {
    pub fn new(own_pid: u32) -> Self {
        Self {
            own_pid,
            round: None,
            done_ms: None,
            missing: Vec::new(),
            last: None,
        }
    }

    /// Whether to start a round now: none is open, and it is the first, or
    /// `AGAIN_MS` since the last, or a path missing then exists now.
    pub fn due(&self, now_ms: i64, exists: &dyn Fn(&str) -> bool) -> bool {
        if self.round.is_some() {
            return false;
        }
        match self.done_ms {
            None => true,
            Some(done) => {
                let again = if self.last.as_ref().is_some_and(|l| !l.is_empty()) {
                    AGAIN_UNWATCHED_MS
                } else {
                    AGAIN_MS
                };
                now_ms - done >= again || self.missing.iter().any(|p| exists(p))
            }
        }
    }

    /// Starts a round. `opened` are the paths the caller opened just after
    /// reading `now_ms` off the clock; `missing` the ones that do not exist.
    pub fn begin(&mut self, now_ms: i64, opened: Vec<String>, missing: Vec<String>) {
        self.missing = missing;
        self.round = Some(Round {
            begun_ms: now_ms,
            asked: opened.into_iter().collect(),
            seen: BTreeSet::new(),
            own: HashSet::new(),
            passed: false,
        });
    }

    /// One record of the log, in the order read.
    pub fn on_record(&mut self, r: &Record) {
        let Some(round) = self.round.as_mut() else {
            return;
        };
        if r.ts_ms >= round.begun_ms + SETTLE_MS {
            round.passed = true;
        }
        match r.kind.as_str() {
            "SYSCALL" => {
                if r.get_u32("pid") == Some(self.own_pid) && r.get("key") == Some(KEY) {
                    round.own.insert(r.event_key());
                }
            }
            "PATH" if round.own.contains(&r.event_key()) => {
                if let Some(name) = r.field("name") {
                    let name = if name.quoted {
                        name.value.clone()
                    } else {
                        hex_or_text(&name.value)
                    };
                    if round.asked.contains(&name) {
                        round.seen.insert(name);
                    }
                }
            }
            _ => {}
        }
    }

    /// Ends the round when the log has been read past its opens: the paths
    /// with no record, sorted. `idle` says the log is quiet now. None while
    /// the round is open or when there is none.
    pub fn settle(&mut self, now_ms: i64, idle: bool) -> Option<Settled> {
        let round = self.round.as_ref()?;
        let waited = now_ms - round.begun_ms >= SETTLE_MS;
        if !(round.passed || (idle && waited)) {
            return None;
        }
        let round = self.round.take()?;
        self.done_ms = Some(now_ms);
        Some(Settled {
            unwatched: round.asked.difference(&round.seen).cloned().collect(),
            none_seen: round.asked.len() > 1 && round.own.is_empty(),
        })
    }

    /// Whether `list` differs from the last one posted, and remembers it.
    /// The first list counts as a change even when empty: a daemon that kept
    /// an older feed's list is told it is over.
    pub fn changed(&mut self, list: &[String]) -> bool {
        if self.last.as_deref() == Some(list) {
            return false;
        }
        self.last = Some(list.to_vec());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::parse_line;

    const PROBE: &str = include_str!("../tests/fixtures/e1-3-probe.auditd-3.1.2.audit");

    fn fixture() -> (u32, i64, Vec<Record>) {
        let recs: Vec<Record> = PROBE.lines().filter_map(parse_line).collect();
        let first = recs.iter().find(|r| r.kind == "SYSCALL").expect("a record");
        (first.get_u32("pid").expect("pid"), first.ts_ms, recs)
    }

    fn paths(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// The box, eval pass 1: `~/.aws` was made after the rules were
    /// installed. The feed's opens of `~/.ssh`, `~/.netrc` and `/etc/shadow`
    /// are in the log with the key; its open of `~/.aws` is not.
    #[test]
    fn e1_3_a_folder_made_after_the_rules_is_named_unwatched() {
        let (pid, at, recs) = fixture();
        let mut c = WatchCheck::new(pid);
        assert!(c.due(at, &|_| false));
        c.begin(
            at - 5,
            paths(&[
                "/home/e13u/.ssh",
                "/home/e13u/.netrc",
                "/etc/shadow",
                "/home/e13u/.aws",
            ]),
            paths(&["/home/e13u/.kube"]),
        );
        for r in &recs {
            c.on_record(r);
        }
        assert_eq!(c.settle(at + 100, true), None, "too soon to tell");
        assert_eq!(
            c.settle(at + SETTLE_MS, true),
            Some(Settled {
                unwatched: paths(&["/home/e13u/.aws"]),
                none_seen: false
            })
        );
        assert!(c.changed(&paths(&["/home/e13u/.aws"])));
        assert!(!c.changed(&paths(&["/home/e13u/.aws"])), "posted once");
    }

    /// An unreadable file is still checked: `/etc/shadow`'s refused open has
    /// its record (`success=no exit=-13` in the fixture).
    #[test]
    fn e1_3_a_refused_open_still_shows_the_rule() {
        let (pid, at, recs) = fixture();
        assert!(PROBE.contains("success=no exit=-13"));
        let mut c = WatchCheck::new(pid);
        c.begin(at - 5, paths(&["/etc/shadow"]), Vec::new());
        for r in &recs {
            c.on_record(r);
        }
        assert_eq!(
            c.settle(at + SETTLE_MS, true).map(|s| s.unwatched),
            Some(Vec::new())
        );
        assert!(c.changed(&[]), "the first list is posted even when empty");
    }

    /// Another process's opens of the same paths prove nothing about what
    /// the rules cover for this check; only the feed's own count.
    #[test]
    fn e1_3_only_the_feeds_own_opens_count() {
        let (pid, at, recs) = fixture();
        let mut c = WatchCheck::new(pid + 1);
        c.begin(at - 5, paths(&["/home/e13u/.ssh"]), Vec::new());
        for r in &recs {
            c.on_record(r);
        }
        assert_eq!(
            c.settle(at + SETTLE_MS, true).map(|s| s.unwatched),
            Some(paths(&["/home/e13u/.ssh"]))
        );
    }

    /// The review's E1R-14: when the feed sees none of its own opens (auditd
    /// stopped, no rules loaded, rules for another uid), every path is
    /// unseen, and the round says that, so the report does not call each
    /// path a missing rule.
    #[test]
    fn e1_3_no_record_of_any_of_its_own_opens_is_said_apart() {
        let mut c = WatchCheck::new(4242);
        c.begin(1_000, paths(&["/home/u/.ssh", "/etc/shadow"]), Vec::new());
        assert_eq!(
            c.settle(1_000 + SETTLE_MS, true),
            Some(Settled {
                unwatched: paths(&["/etc/shadow", "/home/u/.ssh"]),
                none_seen: true
            })
        );
        // The next round comes sooner while a list stands (E1R-15).
        assert!(c.changed(&paths(&["/etc/shadow", "/home/u/.ssh"])));
        let done = 1_000 + SETTLE_MS;
        assert!(!c.due(done + AGAIN_UNWATCHED_MS - 1, &|_| false));
        assert!(c.due(done + AGAIN_UNWATCHED_MS, &|_| false));
    }

    /// A busy log never goes quiet: the round ends on a record newer than
    /// the opens by the settle time, and not before, whatever the clock
    /// says, since the feed may be reading old lines.
    #[test]
    fn e1_3_a_busy_log_settles_on_a_later_record() {
        let (pid, at, recs) = fixture();
        let mut c = WatchCheck::new(pid);
        c.begin(
            at - 5,
            paths(&["/home/e13u/.ssh", "/home/e13u/.aws"]),
            Vec::new(),
        );
        for r in &recs {
            c.on_record(r);
        }
        assert_eq!(c.settle(at + 60_000, false), None);
        let mut later = recs[0].clone();
        later.ts_ms = at - 5 + SETTLE_MS;
        later.serial += 1_000;
        c.on_record(&later);
        assert_eq!(
            c.settle(at + 60_000, false).map(|s| s.unwatched),
            Some(paths(&["/home/e13u/.aws"]))
        );
    }

    /// The next round: after `AGAIN_MS`, or at once when a path that was
    /// missing is there.
    #[test]
    fn e1_3_the_check_runs_again_when_a_missing_path_appears() {
        let mut c = WatchCheck::new(1);
        c.begin(1_000, Vec::new(), paths(&["/home/u/.aws"]));
        assert!(!c.due(1_500, &|_| true), "a round is open");
        assert_eq!(
            c.settle(1_000 + SETTLE_MS, true).map(|s| s.unwatched),
            Some(Vec::new())
        );
        let done = 1_000 + SETTLE_MS;
        assert!(!c.due(done + 1, &|_| false));
        assert!(c.due(done + 1, &|p| p == "/home/u/.aws"));
        assert!(c.due(done + AGAIN_MS, &|_| false));
    }
}
