//! Starting the daemon as a process: the pid file and its lock, the
//! daemon's token file, the activity log, the receiver's endpoint file, the
//! socket, and the hourly retention pass. `main.rs` calls `start` and then
//! serves; the tests call it with temporary paths.

use derm_core::platform::Listener as UnixListener;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::daemon::{Daemon, Paths};
use crate::socket;

/// How often the daemon runs retention itself.
pub const RETENTION_EVERY: Duration = Duration::from_secs(3_600);
/// How often content capture's purge runs (case 126). Shorter than the log's
/// retention pass, so a file is gone within this long of its time.
pub const CONTENT_PURGE_EVERY: Duration = Duration::from_secs(600);

/// A started daemon. The pid file's lock lives as long as `lock`: a second
/// daemon cannot start while this one runs, and the lock goes with the
/// process however it ends.
pub struct Running {
    pub daemon: Arc<Daemon>,
    pub listener: UnixListener,
    pub paths: Paths,
    // Held for its lock; read only by Unix's `pid_file_fd` (lane Z).
    #[cfg_attr(not(unix), allow(dead_code))]
    lock: File,
}

impl Running {
    #[cfg(unix)]
    pub fn pid_file_fd(&self) -> i32 {
        use std::os::unix::io::AsRawFd;
        self.lock.as_raw_fd()
    }
}

/// Writes `text` to `path` through a new file beside it, mode 0600, never
/// following a link, then renames it into place.
pub fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut file =
        derm_core::platform::private_no_follow(OpenOptions::new().write(true).create_new(true))
            .open(&tmp)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// Opens and locks the pid file, and writes this pid into it. Refused when
/// another process holds the lock: the daemon already runs (contract,
/// section 1). The check is the lock, not the pid: a pid can be reused, a
/// lock dies with its process.
pub fn lock_pid_file(path: &Path) -> std::io::Result<File> {
    let mut file = derm_core::platform::private_no_follow(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
    )
    .open(path)?;
    if !derm_core::platform::try_lock_exclusive(&file) {
        let held = std::fs::read_to_string(path).unwrap_or_default();
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!("derm-daemon already runs (pid {})", held.trim()),
        ));
    }
    file.set_len(0)?;
    writeln!(file, "{}", std::process::id())?;
    file.sync_all()?;
    Ok(file)
}

/// Starts everything but the accept loop. Order: the private folders, the
/// lock (so a second daemon stops before it touches any file), the token,
/// the log, the receiver, the endpoint file, then the socket last, so a
/// client that can connect finds the token and the endpoint already there.
pub fn start(paths: Paths, log_prompts: bool) -> Result<Running, String> {
    let fail = |what: &str, e: std::io::Error| format!("{what}: {e}");
    // The pid, token and endpoint files sit beside the socket path, which on
    // Windows is the pointer file to a pipe drawn at random (`pipe.rs`); a
    // pipe name has no folder for them (WW5-6: `--socket \\.\pipe\x` failed
    // at "socket folder: Incorrect function").
    #[cfg(windows)]
    if derm_core::platform::windows::is_pipe_name(&paths.socket) {
        return Err(format!(
            "--socket {}: on Windows the daemon takes the path of its pointer file (a file in a folder of yours, such as %USERPROFILE%\\.derm\\run\\derm\\daemon.sock), never a pipe name: it draws the pipe's name itself each start and keeps its token beside that file",
            paths.socket.display()
        ));
    }
    socket::private_dir(paths.runtime_dir()).map_err(|e| fail("socket folder", e))?;
    socket::private_dir(&paths.data).map_err(|e| fail("data folder", e))?;
    let lock = lock_pid_file(&paths.pid_file()).map_err(|e| fail("pid file", e))?;
    let token = derm_core::token::mint().map_err(|e| fail("token", e))?;
    write_private(&paths.token_file(), &format!("{token}\n")).map_err(|e| fail("token file", e))?;
    crate::activity::init(&paths.data, None);
    let log = crate::activity::log().ok_or("the activity log did not start")?;
    if log.dir() != paths.log_dir() {
        return Err("the activity log already runs in another folder".into());
    }
    let daemon = Daemon::new_with_state(
        &token,
        log,
        &paths.data,
        log_prompts,
        Some(paths.state_file()),
    )?;
    write_private(&paths.endpoint_file(), &format!("{}\n", daemon.endpoint()))
        .map_err(|e| fail("endpoint file", e))?;
    // The model tap's endpoint (wave 5 lane S), beside the OTLP one. With no
    // tap, an old file goes, so `derm run` never points a chat at a port no
    // tap listens on.
    match daemon.tap_endpoint() {
        Some(url) => write_private(&paths.tap_endpoint_file(), &format!("{url}\n"))
            .map_err(|e| fail("tap endpoint file", e))?,
        None => match std::fs::remove_file(paths.tap_endpoint_file()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(fail("tap endpoint file", e))
            }
            _ => {}
        },
    }
    let listener = socket::bind(&paths.socket).map_err(|e| fail("socket", e))?;
    let retention = daemon.clone();
    let _ = std::thread::Builder::new()
        .name("derm-daemon-retention".into())
        .spawn(move || loop {
            retention.retention_pass(crate::activity::store::now_ms());
            std::thread::sleep(RETENTION_EVERY);
        });
    let purge = daemon.clone();
    let _ = std::thread::Builder::new()
        .name("derm-daemon-content-purge".into())
        .spawn(move || loop {
            purge.content_pass(crate::activity::store::now_ms());
            std::thread::sleep(CONTENT_PURGE_EVERY);
        });
    Ok(Running {
        daemon,
        listener,
        paths,
        lock,
    })
}

/// The default paths: the contract's socket and `daemon::default_data_dir`.
pub fn default_paths() -> Option<Paths> {
    Some(Paths {
        socket: crate::socket_path()?,
        data: crate::daemon::default_data_dir()?,
    })
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// WW5-6 (Windows test w5, 2.2): a pipe name as `--socket` failed late
    /// and unclearly ("socket folder: Incorrect function"), after the data
    /// folder step. Fails on `2ce607d`, whose error names no pointer file.
    #[test]
    fn ww5_6_a_pipe_name_as_the_socket_is_refused_with_the_reason() {
        let data = std::env::temp_dir().join(format!("derm-ww56-{}", std::process::id()));
        for name in [r"\\.\pipe\derm-ww56", r"\\?\pipe\derm-ww56"] {
            let e = match start(
                Paths {
                    socket: std::path::PathBuf::from(name),
                    data: data.clone(),
                },
                false,
            ) {
                Err(e) => e,
                Ok(_) => panic!("a daemon started on {name}"),
            };
            assert!(
                e.contains("pointer file") && e.contains("never a pipe name"),
                "{e}"
            );
        }
        assert!(
            !data.exists(),
            "the data folder was made before the refusal"
        );
    }
}
