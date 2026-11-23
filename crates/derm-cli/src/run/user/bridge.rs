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
/// Peers whose process tree cannot be read (`/proc` mounted `hidepid`, a
/// process gone before it was read): a share of their own, with a shorter
/// first-line deadline, so they can delay this chat but never hold it out
/// (I-2; the shape of case 167's fix in the daemon).
const MAX_UNPLACED: usize = 8;
const UNPLACED_DEADLINE: Duration = Duration::from_secs(2);
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
    #[cfg(any(test, target_os = "linux"))]
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
    open_placed(spec, real_place)
}

/// [`open`] with the rule that places a peer (tests give their own).
fn open_placed(spec: &Spec, place: fn(&UnixStream, u32) -> Place) -> Result<Bridge, String> {
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
        unplaced: Arc::new(AtomicUsize::new(0)),
        root: std::process::id(),
        place,
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
    /// Open connections whose peer could not be placed.
    unplaced: Arc<AtomicUsize>,
    /// This `derm run`'s pid: every process of the chat is below it.
    root: u32,
    place: fn(&UnixStream, u32) -> Place,
}

/// Where a connecting process sits relative to this chat (I-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// This `derm run` or a process below it: the chat's own.
    Ours,
    /// Placed, and not below this `derm run`: another chat of the account
    /// that found the socket's path (`/proc/net/unix` lists every bound
    /// path to every user, run on Linux 6.18; Landlock below ABI 9 does not
    /// restrict a pathname connect). Dropped at once, before any read.
    Other,
    /// Its tree could not be read.
    Unplaced,
}

/// The peer by `SO_PEERCRED`'s pid, its ancestry from `/proc`, and the
/// process pinned by `SO_PEERPIDFD` where the kernel gives one (Linux 6.5),
/// so a pid that was reused while the ancestry was read places nothing
/// (`derm_core::peer`, case 97's reads).
fn real_place(stream: &UnixStream, root: u32) -> Place {
    let Some(pid) = derm_core::peer::of(stream).and_then(|p| p.pid) else {
        return Place::Unplaced;
    };
    let pidfd = derm_core::peer::pidfd_of(stream);
    let ancestors = derm_core::peer::ancestors(pid);
    if pidfd
        .as_ref()
        .is_some_and(|fd| !derm_core::peer::pidfd_alive(fd))
    {
        return Place::Unplaced;
    }
    if pid == root || ancestors.contains(&root) {
        Place::Ours
    } else if ancestors.is_empty() {
        Place::Unplaced
    } else {
        Place::Other
    }
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
        let deadline = match (self.place)(&client, self.root) {
            Place::Ours => HELLO_DEADLINE,
            Place::Other => return Ok(()),
            Place::Unplaced => {
                if self.unplaced.fetch_add(1, Ordering::SeqCst) >= MAX_UNPLACED {
                    self.unplaced.fetch_sub(1, Ordering::SeqCst);
                    return Ok(());
                }
                let r = self.serve_one(client, UNPLACED_DEADLINE);
                self.unplaced.fetch_sub(1, Ordering::SeqCst);
                return r;
            }
        };
        self.serve_one(client, deadline)
    }

    /// The first line within `deadline`, then the copy.
    fn serve_one(&self, client: UnixStream, deadline: Duration) -> std::io::Result<()> {
        client.set_read_timeout(Some(deadline))?;
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
        // A bridge that drops the peer (another uid) may close before the
        // write lands; the write then fails with a broken pipe, and what the
        // test checks is what came back (lane Z's request 11: macOS CI,
        // run 42077664795). A test that expects lines still fails on none.
        for l in lines {
            if writeln!(w, "{l}").is_err() {
                break;
            }
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

    /// I-2: another chat of the account that found this bridge's path is
    /// dropped before any read, so it holds no slot; peers that cannot be
    /// placed share 8 slots and a 2 s deadline, so the chat's own still
    /// reach the daemon.
    #[test]
    fn i_2_a_peer_from_another_chat_holds_no_slot_and_unplaced_ones_share_eight() {
        let (_t, base, sock, policy, rx) = setup();
        let b = open_placed(&spec(&base, &sock, &policy, euid()), |_, _| Place::Other).unwrap();
        let t0 = std::time::Instant::now();
        let got = talk(b.socket(), &[&hello(TOKEN)]);
        assert!(got.is_empty(), "{got:?}");
        assert!(t0.elapsed() < Duration::from_secs(1), "dropped at once");
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
        drop(b);

        let b = open_placed(&spec(&base, &sock, &policy, euid()), |_, _| Place::Unplaced).unwrap();
        // Nine silent peers: eight wait, the ninth is dropped at once.
        let mut held = Vec::new();
        for _ in 0..MAX_UNPLACED {
            held.push(UnixStream::connect(b.socket()).unwrap());
        }
        std::thread::sleep(Duration::from_millis(200));
        let ninth = UnixStream::connect(b.socket()).unwrap();
        ninth
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut buf = [0u8; 1];
        let t0 = std::time::Instant::now();
        assert_eq!((&ninth).read(&mut buf).unwrap_or(0), 0);
        assert!(
            t0.elapsed() < Duration::from_millis(900),
            "the ninth is not held"
        );
        // The eight end at their 2 s deadline, not 5 s.
        let t0 = std::time::Instant::now();
        held[0]
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        assert_eq!((&held[0]).read(&mut buf).unwrap_or(0), 0);
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        drop(held);
        std::thread::sleep(Duration::from_millis(300));
        // Once they are gone, an unplaced peer with this chat's hello passes.
        let got = talk(b.socket(), &[&hello(TOKEN)]);
        assert_eq!(got.len(), 1, "{got:?}");
    }

    /// I-2, with the real rule: a process this test started is ours; one
    /// that left the tree (its parent exited, so init took it) is another
    /// chat's and is dropped at once, not after the 5 s deadline.
    #[cfg(target_os = "linux")]
    #[test]
    fn i_2_a_process_outside_this_derm_runs_tree_is_dropped_at_once() {
        let (t, base, sock, policy, _rx) = setup();
        let b = open(&spec(&base, &sock, &policy, euid())).unwrap();
        let out = t.0.join("took");
        let script = format!(
            "import socket,time\ns=socket.socket(socket.AF_UNIX)\ns.connect({:?})\nt=time.time()\ns.settimeout(8)\ntry:\n  s.recv(1)\nexcept Exception:\n  pass\nopen({:?},'w').write(str(time.time()-t))\n",
            b.socket().to_string_lossy(),
            out.to_string_lossy()
        );
        let Ok(st) = std::process::Command::new("/bin/sh")
            .args(["-c", "(python3 -I -c \"$1\" &) ; exit 0", "sh", &script])
            .status()
        else {
            return;
        };
        assert!(st.success());
        let t0 = std::time::Instant::now();
        while !out.exists() && t0.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
        let Ok(took) = std::fs::read_to_string(&out) else {
            eprintln!("python3 is not here; not run");
            return;
        };
        let took: f64 = took.trim().parse().unwrap();
        assert!(took < 1.0, "a process outside the tree waited {took}s");
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
