//! `screen.put` (`contracts/daemon-protocol.md` section 6.3): the rendered
//! screen goes to the daemon on its own thread, so a slow or absent daemon
//! never holds the harness's output back. The thread keeps only the newest
//! screen: one waiting while a put is in flight replaces any older one.
//!
//! It speaks with the daemon's token (daemon scope), which `derm run` holds
//! as the person; a chat token's `screen.put` is refused by the daemon. The
//! line is built from `derm_daemon::protocol::Request::ScreenPut`, the
//! daemon's own type, so its shape is the one the daemon parses (case 112).
//!
//! Screen text is content: it goes only into the `screen.put` line, never
//! into a record, a log line or an error this module returns.

use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use derm_audit_linux::client::{self, Client, ClientError};
use derm_daemon::protocol::{Request, ScreenPut};

use super::Rendered;

/// After the daemon refuses a put, the next waits this long (a daemon
/// before lane PE answers `not built`; one that does not know the op
/// refuses the line).
pub(crate) const REFUSED_BACKOFF: Duration = Duration::from_secs(5);

/// What the publisher did, for `run.stop` (counts and the daemon's last
/// refusal; never screen text).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Stats {
    pub sent: u64,
    pub refused: u64,
    pub failed: u64,
    /// Screens replaced by a newer one before they were sent.
    pub replaced: u64,
    /// The daemon's own words for its last refusal, or the last socket
    /// error.
    pub last_error: Option<String>,
}

#[derive(Default)]
struct Slot {
    next: Option<Rendered>,
    done: bool,
    replaced: u64,
}

/// The `screen.put` sender for one chat.
pub(crate) struct Publisher {
    shared: Arc<(Mutex<Slot>, Condvar)>,
    result: mpsc::Receiver<Stats>,
}

impl Publisher {
    /// Starts the sender thread for `chat`, speaking to the daemon at
    /// `socket` with its token.
    pub(crate) fn start(socket: PathBuf, token: String, chat: String) -> Publisher {
        let shared = Arc::new((Mutex::new(Slot::default()), Condvar::new()));
        let (tx, result) = mpsc::channel();
        let theirs = shared.clone();
        std::thread::spawn(move || {
            let stats = send_loop(&theirs, &socket, token, &chat);
            let _ = tx.send(stats);
        });
        Publisher { shared, result }
    }

    /// The newest screen; an older one not yet sent is dropped.
    pub(crate) fn offer(&self, r: Rendered) {
        let (lock, cv) = &*self.shared;
        let mut slot = lock.lock().unwrap_or_else(|p| p.into_inner());
        if slot.next.replace(r).is_some() {
            slot.replaced += 1;
        }
        cv.notify_one();
    }

    /// Sends what is waiting, then stops. Waits at most `wait` for the last
    /// put; a daemon that does not answer by then is left to the client's
    /// own timeout, and the counts so far are returned.
    pub(crate) fn finish(self, wait: Duration) -> Stats {
        {
            let (lock, cv) = &*self.shared;
            let mut slot = lock.lock().unwrap_or_else(|p| p.into_inner());
            slot.done = true;
            cv.notify_one();
        }
        self.result.recv_timeout(wait).unwrap_or_else(|_| Stats {
            last_error: Some("the last screen.put did not finish in time".into()),
            ..Stats::default()
        })
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The `screen.put` line for `chat`.
pub(crate) fn line(chat: &str, r: &Rendered, at: i64) -> serde_json::Value {
    let req = Request::ScreenPut(ScreenPut {
        chat: chat.to_string(),
        rows: r.rows,
        cols: r.cols,
        text: r.text.clone(),
        scrollback_lines: r.scrollback_lines,
        at,
    });
    serde_json::to_value(&req).unwrap_or(serde_json::Value::Null)
}

/// Connects with `token`, or with the token file read again when the
/// daemon restarted since `derm run` started (box test w1, BX8); either must
/// give daemon scope.
fn connect(socket: &Path, token: &mut String) -> Result<Client, ClientError> {
    let first = Client::connect(socket, token, "derm run screen");
    let (c, hello) = match first {
        Ok(v) => v,
        Err(e) => {
            let dir = socket
                .parent()
                .ok_or_else(|| ClientError::NotRunning("the socket has no folder".into()))?;
            let fresh = client::read_daemon_token(dir).map_err(|_| e)?;
            if fresh == *token {
                return Err(ClientError::NotRunning(
                    "the daemon did not answer and its token has not changed".into(),
                ));
            }
            let v = Client::connect(socket, &fresh, "derm run screen")?;
            *token = fresh;
            v
        }
    };
    if hello.scope != "daemon" {
        return Err(ClientError::Refused(
            "the daemon's token gave chat scope, not daemon scope".into(),
        ));
    }
    Ok(c)
}

fn send_loop(
    shared: &(Mutex<Slot>, Condvar),
    socket: &Path,
    mut token: String,
    chat: &str,
) -> Stats {
    let (lock, cv) = shared;
    let mut stats = Stats::default();
    let mut conn: Option<Client> = None;
    let mut wait_until: Option<Instant> = None;
    loop {
        let (next, done) = {
            let mut slot = lock.lock().unwrap_or_else(|p| p.into_inner());
            while slot.next.is_none() && !slot.done {
                slot = cv.wait(slot).unwrap_or_else(|p| p.into_inner());
            }
            // After a refusal, wait out the backoff unless the chat ended.
            if let Some(t) = wait_until {
                while !slot.done && Instant::now() < t {
                    let left = t.saturating_duration_since(Instant::now());
                    slot = cv
                        .wait_timeout(slot, left)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
            }
            stats.replaced = slot.replaced;
            (slot.next.take(), slot.done)
        };
        let Some(r) = next else {
            return stats;
        };
        if conn.is_none() {
            match connect(socket, &mut token) {
                Ok(c) => conn = Some(c),
                Err(e) => {
                    stats.failed += 1;
                    stats.last_error = Some(e.to_string());
                    if done {
                        return stats;
                    }
                    wait_until = Some(Instant::now() + REFUSED_BACKOFF);
                    continue;
                }
            }
        }
        let c = conn.as_mut().expect("connected above");
        match c.request(&line(chat, &r, now_ms())) {
            Ok(_) => {
                stats.sent += 1;
                wait_until = None;
            }
            Err(ClientError::Refused(why)) => {
                stats.refused += 1;
                stats.last_error = Some(why);
                wait_until = Some(Instant::now() + REFUSED_BACKOFF);
            }
            Err(e) => {
                stats.failed += 1;
                stats.last_error = Some(e.to_string());
                conn = None;
            }
        }
        if done {
            let slot = lock.lock().unwrap_or_else(|p| p.into_inner());
            if slot.next.is_none() {
                return stats;
            }
        }
    }
}
