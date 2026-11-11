//! Whose an event is (case 233; `contracts/sysmon-service.md` section 2).
//!
//! One `Router` per pipe client. It reads every record of the channel in
//! order and says whether this client's user may have it:
//!
//! - an event whose `User` is the client's own account: yes;
//! - an event whose `User` is another real user's: no, whatever was
//!   claimed;
//! - an event whose `User` is a sandbox account (srt's `srt-sandbox`, from
//!   the service's admin-only config): only when its process is in a tree
//!   this client claimed (an srt chat's processes, case 233);
//! - an event with no `User`, or one the service cannot resolve: by its
//!   `ProcessGuid`, when an earlier event named that process's user or the
//!   process is in a claimed tree.
//!
//! A claim names a process this client's user owns (the chat's root, which
//! `derm run` starts as the user); its descendants join the claim through
//! `ParentProcessGuid` when they run as the user or as a sandbox account,
//! never when they run as another real user. Every Sysmon event at the
//! version in use carries `User` (Windows test w5 5.1, built-in Sysmon
//! 10.0.26100.8521, schema 4.91: V), so the join by `ProcessGuid` covers an
//! older Sysmon or an account the service cannot resolve.
//!
//! Accounts are compared by SID: the event's `User` text goes through
//! [`Accounts::sid_of`] (`LookupAccountNameW` in the service), so the text's
//! exact form does not decide anything; an account that does not resolve is
//! no one's.

use std::collections::{HashMap, HashSet, VecDeque};

use derm_audit_windows::sysmon::PROVIDER;
use derm_audit_windows::xml::WinEvent;

/// How many processes a router remembers (owners, claims).
pub const KEEP: usize = 65_536;

/// Names to SIDs.
pub trait Accounts {
    /// The SID (`S-1-...`) of an account as Sysmon writes it, or `None`.
    fn sid_of(&mut self, account: &str) -> Option<String>;
}

/// A map that forgets its oldest entries past a size. Removal is O(1): an
/// order entry whose generation no longer matches is skipped when popped.
#[derive(Debug, Default)]
pub struct Bounded {
    map: HashMap<String, (String, u64)>,
    order: VecDeque<(String, u64)>,
    next: u64,
    cap: usize,
}

impl Bounded {
    pub fn new(cap: usize) -> Bounded {
        Bounded {
            cap,
            ..Bounded::default()
        }
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.map.get(k).map(|(v, _)| v.as_str())
    }

    pub fn insert(&mut self, k: &str, v: &str) {
        if let Some((old, _)) = self.map.get_mut(k) {
            *old = v.to_string();
            return;
        }
        self.next += 1;
        self.map.insert(k.to_string(), (v.to_string(), self.next));
        self.order.push_back((k.to_string(), self.next));
        while self.map.len() > self.cap {
            let Some((old, generation)) = self.order.pop_front() else {
                break;
            };
            if self.map.get(&old).is_some_and(|(_, g)| *g == generation) {
                self.map.remove(&old);
            }
        }
        // Stale order entries from removals are dropped once they outnumber
        // the live ones, so the queue stays within twice the map.
        if self.order.len() > 2 * self.cap.max(self.map.len()) {
            let map = &self.map;
            self.order
                .retain(|(k, g)| map.get(k).is_some_and(|(_, live)| live == g));
        }
    }

    pub fn remove(&mut self, k: &str) -> Option<String> {
        self.map.remove(k).map(|(v, _)| v)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Which client holds each claimed root, across the service's clients, so
/// two clients never hold one process.
#[derive(Debug, Default)]
pub struct Registry {
    held: HashMap<String, u64>,
}

impl Registry {
    fn take(&mut self, guid: &str, client: u64) -> Result<(), String> {
        match self.held.get(guid) {
            Some(c) if *c != client => Err("a process another client claimed".into()),
            _ => {
                self.held.insert(guid.to_string(), client);
                Ok(())
            }
        }
    }

    /// A client's claims go when it disconnects.
    pub fn release(&mut self, client: u64) {
        self.held.retain(|_, c| *c != client);
    }

    fn drop_guid(&mut self, guid: &str) {
        self.held.remove(guid);
    }
}

pub struct Router {
    /// The client's SID, read from its token.
    me: String,
    /// The sandbox accounts' SIDs.
    sandbox: HashSet<String>,
    /// Process guid to the SID an event named for it.
    owner: Bounded,
    /// Process guid to the chat whose claimed tree it is in.
    claimed: Bounded,
    client: u64,
}

impl Router {
    pub fn new(client: u64, me: &str, sandbox: HashSet<String>) -> Router {
        Router {
            me: me.to_string(),
            sandbox,
            owner: Bounded::new(KEEP),
            claimed: Bounded::new(KEEP),
            client,
        }
    }

    pub fn me(&self) -> &str {
        &self.me
    }

    /// Whether this client gets `e`. Called for every record in order.
    pub fn route(&mut self, e: &WinEvent, accounts: &mut dyn Accounts) -> bool {
        if e.provider != PROVIDER {
            return false;
        }
        let guid = e.data.get("ProcessGuid").map(String::as_str);
        let user = e
            .data
            .get("User")
            .filter(|u| !u.is_empty())
            .and_then(|u| accounts.sid_of(u));
        if e.event_id == 1 {
            if let (Some(g), Some(u)) = (guid, &user) {
                self.owner.insert(g, u);
            }
            let parent = e.data.get("ParentProcessGuid").map(String::as_str);
            if let (Some(g), Some(chat)) = (guid, parent.and_then(|p| self.claimed.get(p))) {
                let joins = match &user {
                    Some(u) => *u == self.me || self.sandbox.contains(u),
                    None => false,
                };
                if joins {
                    let chat = chat.to_string();
                    self.claimed.insert(g, &chat);
                }
            }
        }
        let claimed = guid.is_some_and(|g| self.claimed.get(g).is_some());
        let send = match &user {
            Some(u) if *u == self.me => true,
            Some(u) if self.sandbox.contains(u) => claimed,
            Some(_) => false,
            None => claimed || guid.and_then(|g| self.owner.get(g)) == Some(self.me.as_str()),
        };
        if e.event_id == 5 {
            if let Some(g) = guid {
                self.owner.remove(g);
                self.claimed.remove(g);
            }
        }
        send
    }

    /// The daemon claims a process (`claim`): only one this client's user
    /// owns, that the router has seen, and that no other client holds.
    pub fn claim(&mut self, guid: &str, chat: &str, registry: &mut Registry) -> Result<(), String> {
        if guid.is_empty() || guid.len() > 64 || chat.is_empty() || chat.len() > 128 {
            return Err("a claim needs a process guid and a chat".into());
        }
        match self.owner.get(guid) {
            Some(u) if u == self.me => {}
            Some(_) => return Err("a process of another account".into()),
            None => return Err("a process this service has not seen for you".into()),
        }
        registry.take(guid, self.client)?;
        self.claimed.insert(guid, chat);
        Ok(())
    }

    /// Forget a process another way than its exit event (tests, the
    /// registry on exit).
    pub fn exited(&mut self, guid: &str, registry: &mut Registry) {
        self.owner.remove(guid);
        if self.claimed.remove(guid).is_some() {
            registry.drop_guid(guid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use derm_audit_windows::xml;

    pub const ME: &str = "S-1-5-21-1-2-3-1001";
    pub const OTHER: &str = "S-1-5-21-1-2-3-1002";
    pub const SANDBOX: &str = "S-1-5-21-1-2-3-1003";

    struct Names;
    impl Accounts for Names {
        fn sid_of(&mut self, account: &str) -> Option<String> {
            match account.to_ascii_lowercase().as_str() {
                r"box\me" | "me" => Some(ME.into()),
                r"box\other" => Some(OTHER.into()),
                r"box\srt-sandbox" => Some(SANDBOX.into()),
                _ => None,
            }
        }
    }

    /// A Sysmon event in the field order the Windows test w5 recorded (5.1),
    /// written by hand: the captured XML holds the machine's names.
    fn ev(id: u32, record: u64, guid: &str, user: Option<&str>, parent: Option<&str>) -> WinEvent {
        let mut data =
            format!("<Data Name='ProcessGuid'>{guid}</Data><Data Name='ProcessId'>7</Data>");
        if let Some(p) = parent {
            data.push_str(&format!("<Data Name='ParentProcessGuid'>{p}</Data>"));
        }
        if let Some(u) = user {
            data.push_str(&format!("<Data Name='User'>{u}</Data>"));
        }
        xml::parse(&format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>{id}</EventID><EventRecordID>{record}</EventRecordID></System><EventData>{data}</EventData></Event>"
        ))
        .unwrap()
    }

    fn router() -> Router {
        Router::new(1, ME, [SANDBOX.to_string()].into_iter().collect())
    }

    #[test]
    fn handwritten_events_of_another_user_never_reach_this_client() {
        let mut r = router();
        let mut names = Names;
        assert!(r.route(&ev(1, 1, "{a}", Some(r"BOX\me"), None), &mut names));
        assert!(!r.route(&ev(1, 2, "{b}", Some(r"BOX\other"), None), &mut names));
        assert!(!r.route(&ev(11, 3, "{b}", Some(r"BOX\other"), None), &mut names));
        // Another user's event, though its process is claimed here: no.
        let mut reg = Registry::default();
        r.claim("{a}", "c1", &mut reg).unwrap();
        assert!(!r.route(&ev(11, 4, "{a}", Some(r"BOX\other"), None), &mut names));
        // An account that does not resolve, on a process no one named: no.
        assert!(!r.route(&ev(11, 5, "{z}", Some(r"BOX\ghost"), None), &mut names));
    }

    #[test]
    fn handwritten_events_with_no_user_are_joined_by_process_guid() {
        let mut r = router();
        let mut names = Names;
        assert!(r.route(&ev(1, 1, "{a}", Some(r"BOX\me"), None), &mut names));
        assert!(r.route(&ev(11, 2, "{a}", None, None), &mut names));
        assert!(!r.route(&ev(1, 3, "{b}", Some(r"BOX\other"), None), &mut names));
        assert!(!r.route(&ev(11, 4, "{b}", None, None), &mut names));
        // After the exit the guid is no one's.
        assert!(r.route(&ev(5, 5, "{a}", Some(r"BOX\me"), None), &mut names));
        assert!(!r.route(&ev(11, 6, "{a}", None, None), &mut names));
    }

    #[test]
    fn handwritten_sandbox_processes_go_only_to_the_client_that_claimed_their_root() {
        let mut reg = Registry::default();
        let mut mine = router();
        let mut theirs = Router::new(2, OTHER, [SANDBOX.to_string()].into_iter().collect());
        let mut names = Names;
        let root = ev(1, 1, "{root}", Some(r"BOX\me"), None);
        let child = ev(1, 2, "{sb}", Some(r"BOX\srt-sandbox"), Some("{root}"));
        let write = ev(11, 3, "{sb}", Some(r"BOX\srt-sandbox"), None);
        assert!(mine.route(&root, &mut names));
        assert!(!theirs.route(&root, &mut names));
        mine.claim("{root}", "c1", &mut reg).unwrap();
        // The other user cannot claim a process it does not own.
        assert!(theirs.claim("{root}", "c9", &mut reg).is_err());
        assert!(mine.route(&child, &mut names));
        assert!(!theirs.route(&child, &mut names));
        assert!(mine.route(&write, &mut names));
        assert!(!theirs.route(&write, &mut names));
        // A sandbox process outside any claimed tree reaches no one.
        let stray = ev(1, 4, "{sb2}", Some(r"BOX\srt-sandbox"), Some("{elsewhere}"));
        assert!(!mine.route(&stray, &mut names));
        assert!(!theirs.route(&stray, &mut names));
    }

    #[test]
    fn handwritten_a_claimed_tree_never_takes_in_another_real_users_process() {
        let mut reg = Registry::default();
        let mut r = router();
        let mut names = Names;
        r.route(&ev(1, 1, "{root}", Some(r"BOX\me"), None), &mut names);
        r.claim("{root}", "c1", &mut reg).unwrap();
        // A process of another user whose parent is the claimed root (a
        // parent named with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS).
        assert!(!r.route(
            &ev(1, 2, "{x}", Some(r"BOX\other"), Some("{root}")),
            &mut names
        ));
        assert!(!r.route(&ev(11, 3, "{x}", None, None), &mut names));
    }

    #[test]
    fn a_claim_needs_a_process_of_this_user_seen_here_and_held_by_no_other_client() {
        let mut reg = Registry::default();
        let mut a = router();
        let mut b = Router::new(2, ME, HashSet::new());
        let mut names = Names;
        assert!(a.claim("{unseen}", "c1", &mut reg).is_err());
        a.route(&ev(1, 1, "{o}", Some(r"BOX\other"), None), &mut names);
        assert!(a.claim("{o}", "c1", &mut reg).is_err());
        a.route(&ev(1, 2, "{m}", Some(r"BOX\me"), None), &mut names);
        b.route(&ev(1, 2, "{m}", Some(r"BOX\me"), None), &mut names);
        a.claim("{m}", "c1", &mut reg).unwrap();
        assert!(b.claim("{m}", "c2", &mut reg).is_err());
        reg.release(1);
        b.claim("{m}", "c2", &mut reg).unwrap();
        assert!(a.claim("", "c1", &mut reg).is_err());
    }

    #[test]
    fn another_providers_event_reaches_no_one() {
        let mut r = router();
        let mut e = ev(1, 1, "{a}", Some(r"BOX\me"), None);
        e.provider = "Microsoft-Windows-Security-Auditing".into();
        assert!(!r.route(&e, &mut Names));
    }

    #[test]
    fn the_router_forgets_its_oldest_processes_past_its_bound() {
        let mut b = Bounded::new(3);
        for k in ["a", "b", "c", "d"] {
            b.insert(k, "v");
        }
        assert_eq!(b.len(), 3);
        assert_eq!(b.get("a"), None);
        assert_eq!(b.get("d"), Some("v"));
        b.remove("c");
        assert_eq!(b.len(), 2);
        // A key removed and put back is not dropped by its old place.
        b.remove("b");
        b.insert("b", "w");
        b.insert("e", "v");
        assert_eq!(b.get("b"), Some("w"));
        assert_eq!(b.len(), 3);
        for i in 0..10_000 {
            b.insert(&format!("k{i}"), "v");
            b.remove(&format!("k{i}"));
        }
        assert!(b.order.len() <= 6 + 1);
    }
}
