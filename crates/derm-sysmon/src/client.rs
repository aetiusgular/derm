//! The daemon's connection to the service (`contracts/sysmon-service.md`
//! section 3), run by `crates/derm-daemon/src/platform/windows/sysmon_feed/`
//! through [`Sink`], which the daemon implements.
//!
//! Before it sends anything the daemon checks the server:
//! - the pointer file and its folder (`%ProgramData%\derm-sysmon\`) can be
//!   written only by SYSTEM, administrators, TrustedInstaller and the
//!   service's account, so the name it holds is the service's;
//! - the name is a drawn one (`\\.\pipe\derm-sysmon-<32 hex>`);
//! - the pipe's server process is the one the service control manager runs
//!   the service in, and the service is running (`QueryServiceStatusEx`;
//!   the installer grants signed-in users that query). A name another user
//!   squatted while the service was down is served by another process, and
//!   refused.
//! - the service's reply names this process's own account.
//!
//! The pipe is opened for identification only (`SECURITY_IDENTIFICATION`):
//! the service reads who the daemon is and cannot act as it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use derm_core::event::Event;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
};

use crate::acl;
use crate::ingest::{Ingest, Out};
use crate::service::{admin_only, folder, NAME, PIPE_PREFIX};
use crate::win::{self, Got, Pipe};
use crate::wire::{self, FromDaemon, FromService};

/// What the daemon gives the feed.
pub trait Sink: Send + Sync + 'static {
    /// Every `derm run` record from now on (`Daemon::watch_runs`).
    fn runs(&self) -> Receiver<Event>;
    /// The `run.start` records of the chats running now, so a feed that
    /// attaches late knows them.
    fn running(&self) -> Vec<Event>;
    /// Stores one record (`Daemon::ingest`; a `feed.gap` also goes to the
    /// report's gaps).
    fn ingest(&self, e: Event);
    /// The daemon's clock, milliseconds since the epoch.
    fn now_ms(&self) -> i64;
}

/// The feed's state for `report.osFeed` (case 176).
#[derive(Default)]
pub struct Status {
    attached: AtomicBool,
    seen: AtomicBool,
    lost_at: AtomicI64,
    why: Mutex<Option<String>>,
}

impl Status {
    /// `attached`, `stopped` with when and why, or `none`.
    pub fn state(&self) -> serde_json::Value {
        let why = self.why.lock().ok().and_then(|w| w.clone());
        if self.attached.load(Ordering::SeqCst) {
            serde_json::json!({"state": "attached", "feed": "sysmon"})
        } else if self.seen.load(Ordering::SeqCst) {
            serde_json::json!({"state": "stopped", "feed": "sysmon",
                "since": self.lost_at.load(Ordering::SeqCst), "reason": why})
        } else {
            serde_json::json!({"state": "none", "feed": "sysmon", "reason": why})
        }
    }

    fn lost(&self, now: i64, why: String) {
        if self.attached.swap(false, Ordering::SeqCst) {
            self.lost_at.store(now, Ordering::SeqCst);
        }
        if let Ok(mut w) = self.why.lock() {
            *w = Some(why.chars().take(300).collect());
        }
    }
}

/// The pid the service control manager runs the service in, when it runs.
fn service_pid() -> Option<u32> {
    // SAFETY: local machine, default database; handles closed below.
    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return None;
    }
    let name = win::wide_str(NAME);
    // SAFETY: an open manager handle; NUL-terminated name.
    let svc = unsafe { OpenServiceW(scm, name.as_ptr(), SERVICE_QUERY_STATUS) };
    let mut out = None;
    if !svc.is_null() {
        // SAFETY: zeroed is a valid start for this plain struct.
        let mut st: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
        let mut need = 0u32;
        // SAFETY: the buffer is one SERVICE_STATUS_PROCESS.
        let ok = unsafe {
            QueryServiceStatusEx(
                svc,
                SC_STATUS_PROCESS_INFO,
                (&mut st as *mut SERVICE_STATUS_PROCESS).cast(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut need,
            )
        };
        if ok != 0 && st.dwCurrentState == SERVICE_RUNNING && st.dwProcessId != 0 {
            out = Some(st.dwProcessId);
        }
        // SAFETY: opened above; closed once.
        unsafe { CloseServiceHandle(svc) };
    }
    // SAFETY: as above.
    unsafe { CloseServiceHandle(scm) };
    out
}

fn drawn(name: &str) -> bool {
    name.strip_prefix(PIPE_PREFIX).is_some_and(|h| {
        h.len() == 32
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Opens the service's pipe and checks its server.
fn connect() -> Result<Pipe, String> {
    let svc = win::sid_of_account(&format!(r"NT SERVICE\{NAME}"))
        .ok_or("the derm-sysmon service is not installed")?;
    let trusted = [
        acl::SYSTEM,
        acl::ADMINISTRATORS,
        acl::TRUSTED_INSTALLER,
        svc.as_str(),
    ];
    let pointer: PathBuf = folder().join("pipe");
    admin_only(&pointer, &trusted, true)?;
    let text =
        std::fs::read_to_string(&pointer).map_err(|e| format!("{}: {e}", pointer.display()))?;
    let name = text.trim_end_matches(['\r', '\n']);
    if !drawn(name) {
        return Err("the pointer file holds no pipe name the service draws".into());
    }
    let h = win::open_pipe(name).map_err(|e| format!("the service's pipe: {e}"))?;
    let pipe = Pipe::new(h).map_err(|e| e.to_string())?;
    let server = win::server_pid(pipe.handle());
    if server.is_none() || server != service_pid() {
        return Err("the pipe's server is not the running derm-sysmon service".into());
    }
    Ok(pipe)
}

enum Msg {
    Line(String),
    Closed(String),
    Run(Event),
}

fn send(pipe: &Pipe, line: &FromDaemon) -> std::io::Result<()> {
    let mut text = line.to_line();
    text.push('\n');
    pipe.write_all(text.as_bytes(), Duration::from_secs(10))
}

/// Reads the pipe's lines into `tx` until it closes.
fn reader(pipe: Arc<Pipe>, tx: mpsc::Sender<Msg>) {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        while let Some(i) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=i).collect();
            let mut r = std::io::BufReader::new(&line[..]);
            match wire::read_line(&mut r, wire::MAX_LINE) {
                Ok(Some(l)) => {
                    if tx.send(Msg::Line(l)).is_err() {
                        return;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    let _ = tx.send(Msg::Closed(e.to_string()));
                    return;
                }
            }
        }
        if buf.len() > wire::MAX_LINE {
            let _ = tx.send(Msg::Closed("a line over the limit".into()));
            return;
        }
        let mut chunk = vec![0u8; 64 * 1024];
        match pipe.read(&mut chunk, None) {
            Ok(Got::Bytes(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Got::TimedOut) => {}
            Ok(Got::Closed) => {
                let _ = tx.send(Msg::Closed("the service closed the pipe".into()));
                return;
            }
            Err(e) => {
                let _ = tx.send(Msg::Closed(e.to_string()));
                return;
            }
        }
    }
}

/// One connection, from hello to its end. Returns why it ended.
fn session(sink: &Arc<dyn Sink>, status: &Status) -> String {
    let pipe = match connect() {
        Ok(p) => Arc::new(p),
        Err(e) => return e,
    };
    if let Err(e) = send(
        &pipe,
        &FromDaemon::Hello {
            protocol: wire::PROTOCOL,
        },
    ) {
        return e.to_string();
    }
    let (tx, rx) = mpsc::channel();
    {
        let (pipe, tx) = (pipe.clone(), tx.clone());
        std::thread::spawn(move || reader(pipe, tx));
    }
    // The hello's answer.
    let me = win::own_sid();
    match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Msg::Line(l)) => match FromService::parse(&l) {
            Ok(FromService::Reply(r)) if r.ok && r.user.is_some() && r.user == me => {}
            Ok(FromService::Reply(r)) if !r.ok => {
                return format!("the service refused: {}", r.error.unwrap_or_default())
            }
            _ => return "the service's answer did not name this account".into(),
        },
        Ok(Msg::Closed(why)) => return why,
        _ => return "no answer to hello".into(),
    }
    status.attached.store(true, Ordering::SeqCst);
    status.seen.store(true, Ordering::SeqCst);
    let runs = sink.runs();
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for e in runs {
                if tx.send(Msg::Run(e)).is_err() {
                    return;
                }
            }
        });
    }
    let mut ing = Ingest::new();
    let mut outs = Vec::new();
    for e in sink.running() {
        outs.extend(ing.on_run(&e));
    }
    loop {
        for o in outs.drain(..) {
            match o {
                Out::Ingest(e) => sink.ingest(e),
                Out::Send(line) => {
                    if let Err(e) = send(&pipe, &line) {
                        return e.to_string();
                    }
                }
            }
        }
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Msg::Line(l)) => match FromService::parse(&l) {
                Ok(line) => outs.extend(ing.on_service(line, sink.now_ms())),
                Err(e) => return format!("a line from the service: {e}"),
            },
            Ok(Msg::Run(e)) => outs.extend(ing.on_run(&e)),
            Ok(Msg::Closed(why)) => return why,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return "the feed's threads ended".into(),
        }
        ing.tick(sink.now_ms());
    }
}

/// Runs the feed for the daemon's life: connects, and connects again after
/// a pause when the connection ends or cannot be made.
pub fn spawn(sink: Arc<dyn Sink>, status: Arc<Status>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut pause = Duration::from_secs(2);
        loop {
            let why = session(&sink, &status);
            // A session that attached starts the pauses over.
            if status.attached.load(Ordering::SeqCst) {
                pause = Duration::from_secs(2);
            }
            status.lost(sink.now_ms(), why);
            std::thread::sleep(pause);
            pause = (pause * 2).min(Duration::from_secs(60));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_drawn_name_is_taken_from_the_pointer() {
        assert!(drawn(&format!("{PIPE_PREFIX}{}", "0a".repeat(16))));
        assert!(!drawn(&format!("{PIPE_PREFIX}{}", "0A".repeat(16))));
        assert!(!drawn(r"\\.\pipe\derm-sysmon-x"));
        assert!(!drawn(&format!(r"\\.\pipe\other-{}", "0a".repeat(16))));
    }

    #[test]
    fn with_no_service_installed_the_feed_says_so_and_does_not_attach() {
        let why = match connect() {
            Ok(_) => return, // a machine with the service: nothing to check here
            Err(e) => e,
        };
        assert!(!why.is_empty());
        let s = Status::default();
        s.lost(5, why);
        assert_eq!(s.state()["state"], "none");
    }
}
