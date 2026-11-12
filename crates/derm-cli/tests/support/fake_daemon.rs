//! A fake derm daemon for tests, ported from the hook core's
//! `packages/derm-claude-plugin/src/testing/fakeDaemon.ts` at `e29ce27`
//! (the wave 5b base): `contracts/daemon-protocol.md` section 2 on a Unix
//! socket in a fresh 0700 folder, a `daemon.token` beside it, every client
//! line recorded. Used by `gate/`'s unit tests (through `#[path]`) and by
//! the `derm hook` red tests in `tests/`. Unix only, as the TypeScript's.
#![cfg(unix)]
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

pub const DAEMON_TOKEN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
pub const CHAT_TOKEN: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// How the fake answers `approve` (`ApproveBehaviour`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Approve {
    Yes,
    No,
    None,
    Timeout,
    Hang,
    Close,
    Refuse,
}

impl Approve {
    pub fn parse(s: &str) -> Approve {
        match s {
            "yes" => Approve::Yes,
            "no" => Approve::No,
            "timeout" => Approve::Timeout,
            "hang" => Approve::Hang,
            "close" => Approve::Close,
            "refuse" => Approve::Refuse,
            _ => Approve::None,
        }
    }
}

pub struct FakeDaemon {
    pub dir: PathBuf,
    pub socket: PathBuf,
    lines: Arc<Mutex<Vec<(usize, Value)>>>,
    behaviour: Arc<Mutex<Approve>>,
    stop: Arc<AtomicBool>,
}

static SEQ: AtomicUsize = AtomicUsize::new(0);

impl FakeDaemon {
    /// Starts one under `root` (a short folder: a socket path holds at most
    /// about 104 bytes).
    pub fn start(approve: Approve, root: Option<&Path>) -> FakeDaemon {
        let root = root
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let dir = root.join(format!(
            "tkd-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fake daemon folder");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let token = dir.join("daemon.token");
        std::fs::write(&token, format!("{DAEMON_TOKEN}\n")).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).expect("fake daemon socket");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let behaviour = Arc::new(Mutex::new(approve));
        let stop = Arc::new(AtomicBool::new(false));
        let (l2, b2, s2) = (lines.clone(), behaviour.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut conns = 0;
            while !s2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        conns += 1;
                        // BSD and macOS hand the accepted socket the
                        // listener's O_NONBLOCK; Linux does not (accept(2),
                        // VERSIONS, man7.org). The connection reads blocking.
                        let _ = stream.set_nonblocking(false);
                        let (l3, b3) = (l2.clone(), b2.clone());
                        let conn = conns;
                        std::thread::spawn(move || serve(stream, conn, l3, b3));
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
        });
        FakeDaemon {
            dir,
            socket,
            lines,
            behaviour,
            stop,
        }
    }

    pub fn set_approve(&self, b: Approve) {
        *self.behaviour.lock().unwrap() = b;
    }

    /// Every parsed client line, in order, with its connection number.
    pub fn lines(&self) -> Vec<(usize, Value)> {
        self.lines.lock().unwrap().clone()
    }

    pub fn events(&self) -> Vec<Value> {
        self.of("event", "event")
    }

    pub fn approvals(&self) -> Vec<Value> {
        self.of("approve", "request")
    }

    fn of(&self, op: &str, field: &str) -> Vec<Value> {
        self.lines()
            .into_iter()
            .filter(|(_, l)| l["op"] == op)
            .map(|(_, l)| l[field].clone())
            .collect()
    }

    /// The variables for a hook that should reach this daemon.
    pub fn env(&self, with_chat_token: bool) -> Vec<(String, String)> {
        let mut v = vec![(
            "DERM_DAEMON_SOCKET".to_string(),
            self.socket.display().to_string(),
        )];
        if with_chat_token {
            v.push(("DERM_CHAT_TOKEN".into(), CHAT_TOKEN.into()));
        }
        v
    }
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn serve(
    stream: UnixStream,
    conn: usize,
    lines: Arc<Mutex<Vec<(usize, Value)>>>,
    behaviour: Arc<Mutex<Approve>>,
) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut send = |v: Value| {
        let _ = writer.write_all(format!("{v}\n").as_bytes());
    };
    let mut greeted = false;
    for raw in BufReader::new(stream).lines() {
        let Ok(raw) = raw else { return };
        let Ok(line) = serde_json::from_str::<Value>(&raw) else {
            send(json!({"ok": false, "error": "not JSON"}));
            continue;
        };
        lines.lock().unwrap().push((conn, line.clone()));
        if !greeted {
            if line["op"] != "hello" {
                send(json!({"ok": false, "error": "hello first"}));
                return;
            }
            match line["token"].as_str() {
                Some(DAEMON_TOKEN) => send(
                    json!({"ok": true, "scope": "daemon", "daemon": {"version": "0.0.0-fake", "pid": std::process::id(), "protocol": 1}}),
                ),
                Some(CHAT_TOKEN) => send(json!({"ok": true, "scope": "chat", "chat": "chat-fake"})),
                _ => {
                    send(json!({"ok": false, "error": "bad token"}));
                    return;
                }
            }
            greeted = true;
            continue;
        }
        match line["op"].as_str() {
            Some("event") => send(json!({"ok": true, "id": line["event"]["id"]})),
            Some("approve") => {
                let id = line["request"]["id"].clone();
                match *behaviour.lock().unwrap() {
                    Approve::Yes => {
                        send(json!({"ok": true, "id": id, "answer": "yes", "by": "approver"}))
                    }
                    Approve::No => {
                        send(json!({"ok": true, "id": id, "answer": "no", "by": "approver"}))
                    }
                    Approve::None => {
                        send(json!({"ok": true, "id": id, "answer": "no", "by": "none"}))
                    }
                    Approve::Timeout => {
                        send(json!({"ok": true, "id": id, "answer": "no", "by": "timeout"}))
                    }
                    Approve::Close => return,
                    Approve::Refuse => send(json!({"ok": false, "error": "refused"})),
                    Approve::Hang => {}
                }
            }
            other => send(
                json!({"ok": false, "error": format!("fake daemon: op {} not supported", other.unwrap_or("undefined"))}),
            ),
        }
    }
}
