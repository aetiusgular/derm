//! The bridge between a harness that runs as the agents' user and the
//! person's daemon (wave 5 lane V; S2 part c).
//!
//! The daemon's socket sits in a folder only its owner can enter (0700,
//! `crates/derm-daemon/src/socket.rs`), so a hook running as another user
//! cannot reach it. That is the point of part c: the agent never sees
//! `daemon.token` or the socket that takes it. The chat still needs its own
//! scope: the hook posts its decisions and asks for approvals with the chat
//! token (case 66). So `derm run`, which runs as the person, keeps a
//! per-chat folder the agents' user can enter but not list or write, and in
//! it:
//!
//! - `daemon.sock`, a relay: it accepts only the agents' user (checked with
//!   `SO_PEERCRED`, unix(7)), reads the first line, passes it on only when it
//!   is `hello` with this chat's token, then copies bytes both ways to the
//!   daemon's socket. Another user, another chat's token, or the daemon's own
//!   token never reach the daemon through it;
//! - `policy.json`, a read-only copy of the person's policy, made at start
//!   (the gate inside reads its rules from it; a change to the person's file
//!   reaches the next chat, not this one);
//! - `chat.token`, the chat token, for harnesses that strip token variables
//!   from a hook's environment (case 76).
//!
//! The folder is `<base>/<chat>-<random>`, where `<base>` is
//! `/run/derm-agent/<owner uid>`, made by root's tmpfiles line at install
//! (`packaging/linux/agent-user/`): 0711, the person's. Others can pass
//! through a 0711 folder but cannot list it, so the random part keeps the
//! chat's folder from being found by any user but one told its path. Its
//! files are readable by everyone who has that path: the agent has it
//! anyway (it is the chat's own token and policy), and no one else does.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Where the bridges of all owners sit, made by root at install.
pub const BASE_ROOT: &str = "/run/derm-agent";
/// The first line must arrive this fast, and be no longer than this.
const HELLO_DEADLINE: Duration = Duration::from_secs(5);
const MAX_HELLO_BYTES: u64 = 64 * 1024;
/// Hooks are short-lived; this many at once is far past what one chat makes.
const MAX_CONNECTIONS: usize = 64;
/// The policy copy is read only up to this size (the gate's own limit is
/// smaller; this one only stops a runaway file).
const MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;

/// One chat's bridge. Dropping it stops the relay and removes the folder.
pub struct Bridge {
    dir: PathBuf,
    socket: PathBuf,
    policy: PathBuf,
    token_file: PathBuf,
    stop: Arc<AtomicBool>,
}

impl Bridge {
    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn socket(&self) -> &Path {
        &self.socket
    }
    pub fn policy(&self) -> &Path {
        &self.policy
    }
    pub fn token_file(&self) -> &Path {
        &self.token_file
    }
}

/// What a bridge needs.
pub struct Spec<'a> {
    /// `/run/derm-agent/<owner uid>`, or a test's folder.
    pub base: &'a Path,
    /// The uid that owns `base`'s parent: root outside tests.
    pub base_parent_owner: u32,
    pub chat: &'a str,
    /// The only uid the relay serves.
    pub agent_uid: u32,
    pub daemon_socket: &'a Path,
    pub token: &'a str,
    /// The person's policy file; `None` or unreadable leaves no copy, so the
    /// gate finds no policy and asks for every call.
    pub policy: Option<&'a Path>,
}

/// Makes the folder, its files and the relay.
pub fn open(spec: &Spec) -> Result<Bridge, String> {
    let me = euid();
    check_base(spec.base, spec.base_parent_owner, me)?;
    if !super::anchor::plain_name(&chat_part(spec.chat)) {
        return Err(format!("chat id {:?} cannot name a folder", spec.chat));
    }
    let dir = spec.base.join(format!(
        "{}-{}",
        chat_part(spec.chat),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let bridge = Bridge {
        socket: dir.join("daemon.sock"),
        policy: dir.join("policy.json"),
        token_file: dir.join("chat.token"),
        dir,
        stop: Arc::new(AtomicBool::new(false)),
    };
    // Files first, then the folder opens to others, then the socket.
    if let Some(src) = spec.policy {
        if let Some(text) = read_policy(src, me) {
            write_new(&bridge.policy, &text, 0o644)?;
        }
    }
    write_new(
        &bridge.token_file,
        format!("{}\n", spec.token).as_bytes(),
        0o644,
    )?;
    let listener = UnixListener::bind(&bridge.socket)
        .map_err(|e| format!("{}: {e}", bridge.socket.display()))?;
    std::fs::set_permissions(&bridge.socket, std::fs::Permissions::from_mode(0o666))
        .map_err(|e| format!("{}: {e}", bridge.socket.display()))?;
    std::fs::set_permissions(&bridge.dir, std::fs::Permissions::from_mode(0o711))
        .map_err(|e| format!("{}: {e}", bridge.dir.display()))?;
    let relay = Relay {
        agent_uid: spec.agent_uid,
        daemon_socket: spec.daemon_socket.to_path_buf(),
        token: spec.token.to_string(),
        stop: bridge.stop.clone(),
        open: Arc::new(AtomicUsize::new(0)),
    };
    std::thread::Builder::new()
        .name("derm-agent-bridge".into())
        .spawn(move || relay.serve(listener))
        .map_err(|e| format!("the bridge's relay did not start: {e}"))?;
    Ok(bridge)
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees `stop`.
        let _ = UnixStream::connect(&self.socket);
        for f in [&self.socket, &self.policy, &self.token_file] {
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// `base` is a folder of ours, 0711 or tighter for others (no write, no
/// list), not a link, in a parent root keeps (no one else can write it, so
/// no one can swap `base`).
fn check_base(base: &Path, parent_owner: u32, me: u32) -> Result<(), String> {
    let parent = base
        .parent()
        .ok_or_else(|| format!("{} has no parent", base.display()))?;
    let pm = std::fs::symlink_metadata(parent).map_err(|e| {
        format!(
            "{}: {e} (the agents' user is not set up: packaging/linux/agent-user/install.sh)",
            parent.display()
        )
    })?;
    if pm.file_type().is_symlink()
        || !pm.is_dir()
        || pm.uid() != parent_owner
        || pm.mode() & 0o022 != 0
    {
        return Err(format!(
            "{} must be a folder of uid {parent_owner} that no one else can write",
            parent.display()
        ));
    }
    let m = std::fs::symlink_metadata(base).map_err(|e| {
        format!(
            "{}: {e} (the agents' user is set up for another person, or its tmpfiles line did not run: `systemd-tmpfiles --create`)",
            base.display()
        )
    })?;
    if m.file_type().is_symlink() || !m.is_dir() || m.uid() != me {
        return Err(format!(
            "{} must be a folder of yours, not a link",
            base.display()
        ));
    }
    if m.mode() & 0o066 != 0 {
        return Err(format!(
            "{} lets others list or write it; it must be 0711 or tighter",
            base.display()
        ));
    }
    Ok(())
}

/// The chat id as a folder name: what `plain_name` accepts, at most 32.
fn chat_part(chat: &str) -> String {
    let mut s: String = chat
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '_' | '-' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => '-',
        })
        .take(24)
        .collect();
    if !s.starts_with(|c: char| c.is_ascii_lowercase() || c == '_') {
        s.insert(0, '_');
    }
    s
}

/// The person's policy, when it is a regular file of theirs, not a link.
/// Anything else leaves the copy out (the gate then asks for every call).
fn read_policy(src: &Path, me: u32) -> Option<Vec<u8>> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(src)
        .ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() || m.uid() != me || m.len() > MAX_POLICY_BYTES {
        return None;
    }
    let mut buf = Vec::new();
    Read::by_ref(&mut f)
        .take(MAX_POLICY_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

/// A new file (never an existing one or a link) with `mode`.
fn write_new(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn euid() -> u32 {
    derm_core::platform::effective_user()
}

struct Relay {
    agent_uid: u32,
    daemon_socket: PathBuf,
    token: String,
    stop: Arc<AtomicBool>,
    open: Arc<AtomicUsize>,
}

impl Relay {
    fn serve(self, listener: UnixListener) {
        let me = Arc::new(self);
        for stream in listener.incoming() {
            if me.stop.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = stream else { continue };
            if me.open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                me.open.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let relay = me.clone();
            let spawned = std::thread::Builder::new()
                .name("derm-agent-bridge-conn".into())
                .spawn(move || {
                    let _ = relay.one(stream);
                    relay.open.fetch_sub(1, Ordering::SeqCst);
                });
            if spawned.is_err() {
                me.open.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    /// One hook connection: who it is, its first line, then the copy.
    fn one(&self, client: UnixStream) -> std::io::Result<()> {
        let Some(peer) = derm_core::platform::peer::of(&client) else {
            return Ok(());
        };
        if peer.uid != self.agent_uid {
            return Ok(());
        }
        client.set_read_timeout(Some(HELLO_DEADLINE))?;
        let mut reader = BufReader::new(client.try_clone()?);
        let mut line = Vec::new();
        reader
            .by_ref()
            .take(MAX_HELLO_BYTES)
            .read_until(b'\n', &mut line)?;
        if !hello_for(&line, &self.token) {
            return Ok(());
        }
        client.set_read_timeout(None)?;
        let mut daemon = UnixStream::connect(&self.daemon_socket)?;
        daemon.write_all(&line)?;
        if line.last() != Some(&b'\n') {
            daemon.write_all(b"\n")?;
        }
        // What the hook sent after its first line is still in `reader`'s
        // buffer: it goes first.
        let ahead = reader.buffer().to_vec();
        daemon.write_all(&ahead)?;
        let mut from_daemon = daemon.try_clone()?;
        let mut to_client = client.try_clone()?;
        let back = std::thread::spawn(move || {
            let _ = std::io::copy(&mut from_daemon, &mut to_client);
            let _ = to_client.shutdown(std::net::Shutdown::Write);
        });
        let mut rest = reader.into_inner();
        let _ = std::io::copy(&mut rest, &mut daemon);
        let _ = daemon.shutdown(std::net::Shutdown::Write);
        let _ = back.join();
        Ok(())
    }
}

/// Whether `line` is `{"op":"hello","token":<token>, ...}` with exactly
/// this chat's token. The comparison takes the same time for any token of
/// the right length.
pub fn hello_for(line: &[u8], token: &str) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
        return false;
    };
    if v.get("op").and_then(|o| o.as_str()) != Some("hello") {
        return false;
    }
    let Some(given) = v.get("token").and_then(|t| t.as_str()) else {
        return false;
    };
    let (a, b) = (given.as_bytes(), token.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAT: &str = "derm-0123abcd";
    const TOKEN: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            // Short: a Unix socket path holds 108 bytes (case 111).
            let p = PathBuf::from(format!(
                "/tmp/dv-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..10]
            ));
            std::fs::create_dir_all(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `<tmp>/base` (0711, ours) in `<tmp>` (0755, ours), a fake daemon that
    /// echoes every line it reads, and a policy file.
    fn setup() -> (
        Tmp,
        PathBuf,
        PathBuf,
        PathBuf,
        std::sync::mpsc::Receiver<String>,
    ) {
        let t = Tmp::new();
        let base = t.0.join("base");
        std::fs::DirBuilder::new()
            .mode(0o711)
            .create(&base)
            .unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o711)).unwrap();
        let sock = t.0.join("d.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(s) = s else { continue };
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let mut w = s.try_clone().unwrap();
                    for l in BufReader::new(s).lines() {
                        let Ok(l) = l else { break };
                        let _ = tx.send(l.clone());
                        let _ = writeln!(w, "echo {l}");
                    }
                });
            }
        });
        let policy = t.0.join("policy.json");
        std::fs::write(&policy, br#"{"version":1,"rules":[]}"#).unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        (t, base, sock, policy, rx)
    }

    fn spec<'a>(base: &'a Path, sock: &'a Path, policy: &'a Path, agent_uid: u32) -> Spec<'a> {
        Spec {
            base,
            base_parent_owner: euid(),
            chat: CHAT,
            agent_uid,
            daemon_socket: sock,
            token: TOKEN,
            policy: Some(policy),
        }
    }

    fn talk(sock: &Path, lines: &[&str]) -> Vec<String> {
        let s = UnixStream::connect(sock).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut w = s.try_clone().unwrap();
        for l in lines {
            writeln!(w, "{l}").unwrap();
        }
        let _ = w.shutdown(std::net::Shutdown::Write);
        BufReader::new(s).lines().map_while(Result::ok).collect()
    }

    fn hello(token: &str) -> String {
        format!(r#"{{"op":"hello","token":"{token}","client":"t"}}"#)
    }

    #[test]
    fn the_folder_its_files_and_their_modes() {
        let (_t, base, sock, policy, _rx) = setup();
        let b = open(&spec(&base, &sock, &policy, euid())).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o7777;
        assert_eq!(mode(b.dir()), 0o711, "others pass through, never list");
        assert_eq!(mode(b.policy()), 0o644);
        assert_eq!(mode(b.token_file()), 0o644);
        assert_eq!(
            std::fs::read(b.policy()).unwrap(),
            std::fs::read(&policy).unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(b.token_file()).unwrap(),
            format!("{TOKEN}\n")
        );
        let name = b.dir().file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("derm-0123abcd-") && name.len() == "derm-0123abcd-".len() + 32,
            "{name}"
        );
        let dir = b.dir().to_path_buf();
        drop(b);
        assert!(!dir.exists(), "dropping the bridge removes its folder");
    }

    #[test]
    fn the_relay_passes_this_chats_hello_and_what_follows() {
        let (_t, base, sock, policy, rx) = setup();
        let b = open(&spec(&base, &sock, &policy, euid())).unwrap();
        let got = talk(b.socket(), &[&hello(TOKEN), r#"{"op":"event"}"#]);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got[0].starts_with("echo {\"op\":\"hello\""), "{got:?}");
        assert_eq!(got[1], r#"echo {"op":"event"}"#);
        assert!(rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .contains(TOKEN));
    }

    #[test]
    fn another_token_or_a_first_line_that_is_not_hello_never_reaches_the_daemon() {
        let (_t, base, sock, policy, rx) = setup();
        let b = open(&spec(&base, &sock, &policy, euid())).unwrap();
        let other = "b".repeat(64);
        for first in [
            hello(&other),
            hello(&TOKEN[..63]),
            r#"{"op":"event","token":"x"}"#.to_string(),
            r#"{"op":"approver"}"#.to_string(),
            "not json".to_string(),
        ] {
            let got = talk(b.socket(), &[&first, r#"{"op":"approver"}"#]);
            assert!(got.is_empty(), "{first}: {got:?}");
        }
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "nothing reached the daemon"
        );
    }

    #[test]
    fn a_peer_of_another_uid_is_dropped() {
        let (_t, base, sock, policy, rx) = setup();
        let b = open(&spec(&base, &sock, &policy, euid().wrapping_add(1))).unwrap();
        let got = talk(b.socket(), &[&hello(TOKEN)]);
        assert!(got.is_empty(), "{got:?}");
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    }

    #[test]
    fn a_policy_that_is_a_link_or_missing_is_not_copied() {
        let (t, base, sock, policy, _rx) = setup();
        let link = t.0.join("link.json");
        std::os::unix::fs::symlink(&policy, &link).unwrap();
        let b = open(&spec(&base, &sock, &link, euid())).unwrap();
        assert!(!b.policy().exists(), "a link is not followed");
        drop(b);
        let missing = t.0.join("none.json");
        let b = open(&spec(&base, &sock, &missing, euid())).unwrap();
        assert!(!b.policy().exists());
    }

    #[test]
    fn a_base_others_can_list_or_write_or_a_link_is_refused() {
        let (t, base, sock, policy, _rx) = setup();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = open(&spec(&base, &sock, &policy, euid())).err().unwrap();
        assert!(err.contains("0711 or tighter"), "{err}");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o711)).unwrap();
        std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = open(&spec(&base, &sock, &policy, euid())).err().unwrap();
        assert!(err.contains("no one else can write"), "{err}");
        std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = t.0.join("lbase");
        std::os::unix::fs::symlink(&base, &link).unwrap();
        let err = open(&spec(&link, &sock, &policy, euid())).err().unwrap();
        assert!(err.contains("not a link"), "{err}");
        let err = open(&spec(&t.0.join("absent"), &sock, &policy, euid()))
            .err()
            .unwrap();
        assert!(err.contains("tmpfiles"), "{err}");
    }

    #[test]
    fn hello_matching() {
        assert!(hello_for(hello(TOKEN).as_bytes(), TOKEN));
        assert!(hello_for(format!("{}\n", hello(TOKEN)).as_bytes(), TOKEN));
        assert!(!hello_for(hello(&TOKEN.to_uppercase()).as_bytes(), TOKEN));
        assert!(!hello_for(br#"{"op":"hello"}"#, TOKEN));
        assert!(!hello_for(
            format!(r#"{{"op":"Hello","token":"{TOKEN}"}}"#).as_bytes(),
            TOKEN
        ));
        assert!(!hello_for(
            format!(r#"{{"op":"hello","token":["{TOKEN}"]}}"#).as_bytes(),
            TOKEN
        ));
    }

    #[test]
    fn chat_ids_become_plain_folder_names() {
        assert_eq!(chat_part("derm-0123abcd"), "derm-0123abcd");
        assert_eq!(chat_part("Chat/../x"), "chat----x");
        assert_eq!(chat_part("9lives"), "_9lives");
        assert!(super::super::anchor::plain_name(&chat_part(
            &"x".repeat(80)
        )));
    }
}
