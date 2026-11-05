//! The Unix socket server (`contracts/daemon-protocol.md`, sections 1 and 2):
//! JSON lines, one object per line, at most 1 MiB per line. Each connection
//! gets a reader thread (this file) and a writer thread, so pushes from
//! `tail` and `approver` never wait on the reader, and a slow client never
//! holds up the daemon.

use derm_core::platform::{Listener as UnixListener, Stream as UnixStream};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::daemon::{error, After, ConnPeer, Daemon, Outbox};
use crate::protocol::Request;

/// Longest line read, in bytes, before the newline.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;
/// Connections served at once. One more gets `busy` and is closed.
pub const MAX_CONNECTIONS: usize = 64;
/// Time a new connection has to send its `hello`.
pub const HELLO_DEADLINE: Duration = Duration::from_secs(10);

/// Binds `path`, replacing a stale socket file, and sets it to 0600. The
/// parent folder is created 0700 when missing, and refused when it is a link
/// or belongs to another user (the platform seam's `bind`).
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    derm_core::platform::bind(path)
}

/// Makes `dir` (and its parents) and holds it to 0700, owned by this user,
/// not a link (the platform seam's `private_dir`).
pub fn private_dir(dir: &Path) -> std::io::Result<()> {
    derm_core::platform::private_dir(dir)
}

/// Accepts connections until the listener fails. Each one runs on its own
/// thread.
pub fn serve(listener: UnixListener, daemon: Arc<Daemon>) {
    let open = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            open.fetch_sub(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = write_line(&mut stream, &error("busy"));
            continue;
        }
        let daemon = daemon.clone();
        let open = open.clone();
        let spawned = std::thread::Builder::new()
            .name("derm-daemon-conn".into())
            .spawn(move || {
                let _ = serve_one(stream, &daemon);
                open.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            eprintln!("derm-daemon: could not start a connection thread");
        }
    }
}

fn write_line<T: serde::Serialize>(w: &mut UnixStream, value: &T) -> std::io::Result<()> {
    let mut text = serde_json::to_string(value).map_err(std::io::Error::other)?;
    text.push('\n');
    w.write_all(text.as_bytes())
}

/// What one read of a line gave.
enum Line {
    Text(String),
    TooLong,
    NotUtf8,
    Closed,
}

fn read_line(reader: &mut impl BufRead) -> std::io::Result<Line> {
    let mut buf = Vec::new();
    let n = reader
        .by_ref()
        .take(MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(Line::Closed);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    } else if buf.len() > MAX_LINE_BYTES {
        return Ok(Line::TooLong);
    }
    Ok(match String::from_utf8(buf) {
        Ok(text) => Line::Text(text),
        Err(_) => Line::NotUtf8,
    })
}

/// Serves one connection until the client closes or a rule closes it.
pub fn serve_one(stream: UnixStream, daemon: &Arc<Daemon>) -> std::io::Result<()> {
    let conn = daemon.next_conn();
    // Who connected, read now: `SO_PEERCRED` holds the credentials of the
    // process that called connect(2) (unix(7)); the approver check uses it
    // (integration w2, S2).
    let peer = Arc::new(ConnPeer::of(&stream));
    let (out, rx, pending) = Outbox::with_peer(conn, Some(peer));
    let mut writer = stream.try_clone()?;
    let writer_thread = std::thread::Builder::new()
        .name("derm-daemon-write".into())
        .spawn(move || {
            for mut line in rx {
                line.push('\n');
                let failed = writer.write_all(line.as_bytes()).is_err();
                pending.fetch_sub(1, Ordering::SeqCst);
                if failed {
                    let _ = writer.shutdown(std::net::Shutdown::Both);
                    break;
                }
            }
        })?;
    let result = read_loop(&stream, daemon, &out);
    daemon.forget(conn);
    drop(out);
    // The writer drains what is queued (the last reply included), then
    // ends when every sender is gone.
    let _ = writer_thread.join();
    let _ = stream.shutdown(std::net::Shutdown::Both);
    result
}

fn read_loop(stream: &UnixStream, daemon: &Arc<Daemon>, out: &Outbox) -> std::io::Result<()> {
    stream.set_read_timeout(Some(HELLO_DEADLINE))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    // The first line: `hello`, or one error and the connection closes.
    let who = match read_line(&mut reader) {
        Ok(Line::Text(text)) => match serde_json::from_str::<Request>(&text) {
            Ok(Request::Hello { token, .. }) => match daemon.hello(&token) {
                Some(who) => who,
                None => {
                    out.send(&error("bad token"));
                    return Ok(());
                }
            },
            _ => {
                out.send(&error("hello first"));
                return Ok(());
            }
        },
        Ok(Line::TooLong) => {
            out.send(&error("line too long"));
            return Ok(());
        }
        Ok(Line::NotUtf8) => {
            out.send(&error("hello first"));
            return Ok(());
        }
        Ok(Line::Closed) | Err(_) => return Ok(()),
    };
    out.send(&Daemon::hello_reply(&who));
    stream.set_read_timeout(None)?;
    loop {
        let text = match read_line(&mut reader)? {
            Line::Closed => return Ok(()),
            Line::TooLong => {
                out.send(&error("line too long"));
                return Ok(());
            }
            Line::NotUtf8 => {
                out.send(&error("bad line: not UTF-8"));
                continue;
            }
            Line::Text(text) => text,
        };
        if text.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<Request>(&text) {
            Ok(r) => r,
            Err(e) => {
                out.send(&error(format!("bad line: {e}")));
                continue;
            }
        };
        if let After::Close = daemon.handle(&who, request, out) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "derm-sock-test-{}-{}",
            std::process::id(),
            &derm_core::token::mint().unwrap()[..12]
        ))
    }

    #[test]
    fn bind_sets_0600_and_a_0700_parent_and_replaces_a_stale_socket() {
        let root = temp_root();
        let path = root.join("derm/daemon.sock");
        drop(bind(&path).unwrap());
        // A stale socket file from a daemon that died is replaced.
        let _l = bind(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let parent = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent, 0o700);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_linked_socket_folder_is_refused() {
        let root = temp_root();
        let real = root.join("elsewhere");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.join("derm")).unwrap();
        assert!(bind(&root.join("derm/daemon.sock")).is_err());
        assert!(!real.join("daemon.sock").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_folder_at_the_socket_path_is_refused() {
        let root = temp_root();
        std::fs::create_dir_all(root.join("derm/daemon.sock")).unwrap();
        assert!(bind(&root.join("derm/daemon.sock")).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
