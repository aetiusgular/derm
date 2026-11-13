//! Opening, locking and appending to one chat's log (`super`'s doc says why
//! each step is there).

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use derm_core::audit_chain::{self, Link};
use serde_json::Value;

/// The most the last line may hold; past it the file is not one derm
/// wrote (a record is a few hundred bytes).
const MAX_LINE: u64 = 1 << 20;

/// Appends one chain v2 line for `record` to `folder/name`, chained from
/// the file's last line. The line's `seq`.
pub fn append_line(
    folder: &Path,
    name: &str,
    kind: &str,
    record: &Value,
    deadline: Duration,
) -> Result<u64, String> {
    let start = Instant::now();
    own_folders(folder)?;
    let path = folder.join(name);
    let file = open_locked(&path, start, deadline)?;
    let written = (|| {
        let last = last_link(&file, &path)?;
        let (text, link) = audit_chain::line(last.as_ref(), kind, record)?;
        let mut buf = text.into_bytes();
        buf.push(b'\n');
        // One write for the line and its newline (note AZ B5).
        let n = (&file)
            .write(&buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if n != buf.len() {
            return Err(format!(
                "{}: a short write ({n} of {} bytes) left a torn line",
                path.display(),
                buf.len()
            ));
        }
        Ok(link.seq)
    })();
    let _ = file.unlock();
    written
}

/// The file's last link, `None` for an empty file. A file that does not end
/// in a newline, or whose last line is not chain v2, is refused: the next
/// line cannot chain from it, and guessing an earlier line would hide the
/// break from `derm audit verify`.
fn last_link(file: &File, path: &Path) -> Result<Option<Link>, String> {
    let len = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    if len == 0 {
        return Ok(None);
    }
    let broken = |why: &str| {
        format!(
            "{} {why}; nothing more is appended to it until it is moved away (derm audit verify names the line)",
            path.display()
        )
    };
    let mut want = len.min(64 * 1024);
    let line = loop {
        let off = len - want;
        let mut buf = vec![0u8; want as usize];
        read_exact_at(file, &mut buf, off).map_err(|e| format!("{}: {e}", path.display()))?;
        if buf.last() != Some(&b'\n') {
            return Err(broken(
                "does not end with a newline: its last line is torn or was edited",
            ));
        }
        let body = &buf[..buf.len() - 1];
        if let Some(i) = body.iter().rposition(|&b| b == b'\n') {
            break body[i + 1..].to_vec();
        }
        if off == 0 {
            break body.to_vec();
        }
        if want > MAX_LINE {
            return Err(broken(
                "ends in a line over 1 MiB, which derm did not write",
            ));
        }
        want = len.min(want * 4);
    };
    let text =
        std::str::from_utf8(&line).map_err(|_| broken("ends in a line that is not UTF-8"))?;
    audit_chain::parse(text)
        .map(Some)
        .map_err(|e| broken(&format!("ends in a line that is not chain v2 ({e})")))
}

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], off: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, off)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    // `seek_read` moves the file pointer; appends go to the end whatever the
    // pointer says (the handle has FILE_APPEND_DATA, not FILE_WRITE_DATA).
    while !buf.is_empty() {
        match file.seek_read(buf, off)? {
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            n => {
                buf = &mut buf[n..];
                off += n as u64;
            }
        }
    }
    Ok(())
}

/// Opens the log for read and append and takes its exclusive lock, trying
/// until `deadline` from `start`.
fn open_locked(path: &Path, start: Instant, deadline: Duration) -> Result<File, String> {
    let mut step = Duration::from_millis(1);
    let wait = |step: &mut Duration, why: String| -> Result<(), String> {
        let spent = start.elapsed();
        if spent >= deadline {
            return Err(why);
        }
        std::thread::sleep((*step).min(deadline - spent));
        *step = (*step * 2).min(Duration::from_millis(25));
        Ok(())
    };
    let file = loop {
        match open(path) {
            Ok(f) => break f,
            Err(Open::Busy(e)) => wait(
                &mut step,
                format!(
                    "{}: another program holds it without write sharing ({e}) for over {} ms",
                    path.display(),
                    deadline.as_millis()
                ),
            )?,
            Err(Open::Refused(why)) => return Err(why),
        }
    };
    check_file(&file, path)?;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => wait(
                &mut step,
                format!(
                    "{}: another writer held its lock for over {} ms",
                    path.display(),
                    deadline.as_millis()
                ),
            )?,
            Err(TryLockError::Error(e)) => {
                return Err(format!("{}: the lock failed ({e})", path.display()))
            }
        }
    }
}

enum Open {
    /// Worth trying again before the deadline (Windows error 32).
    #[cfg_attr(not(windows), allow(dead_code))]
    Busy(std::io::Error),
    Refused(String),
}

/// Read plus append, never append-only: on Windows "locking a file will fail
/// if the file is opened only for append. To lock a file, open it with one
/// of .read(true), .read(true).append(true), or .write(true)" (std's
/// `File::lock` docs, 1.89 on; run on NTFS by the wave 6 base, error 5).
#[cfg(unix)]
fn open(path: &Path) -> Result<File, Open> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        // A link at the file's place is refused (ELOOP); a FIFO does not
        // block the open and is refused by `check_file`.
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Open::Refused(format!("{}: {e} (a link is refused)", path.display())))
}

/// Rust's default share mode is read, write and delete (std's
/// `OpenOptionsExt::share_mode` docs), so the hooks of one chat share the
/// file and `derm audit` reads it while they write; only another program's
/// handle without write sharing gets error 32 (note AZ, AZ-8).
#[cfg(windows)]
fn open(path: &Path) -> Result<File, Open> {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) {
                Open::Busy(e)
            } else {
                Open::Refused(format!("{}: {e}", path.display()))
            }
        })
}

#[cfg(not(any(unix, windows)))]
fn open(path: &Path) -> Result<File, Open> {
    Err(Open::Refused(format!(
        "{}: the light tier's log is built for Unix and Windows",
        path.display()
    )))
}

/// What was opened is a plain file of this user's with one name, 0600.
#[cfg(unix)]
fn check_file(file: &File, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() {
        return Err(format!("{} is not a plain file", path.display()));
    }
    if m.uid() != derm_core::platform::effective_user() {
        return Err(format!("{} belongs to another user", path.display()));
    }
    // A second name would let a line land in another file of yours (a link
    // the agent made to a startup script).
    if m.nlink() != 1 {
        return Err(format!(
            "{} has {} names (a hard link); derm writes only a file with one",
            path.display(),
            m.nlink()
        ));
    }
    if m.mode() & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(windows)]
fn check_file(file: &File, path: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    let m = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("{} is not a plain file", path.display()));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn check_file(_file: &File, _path: &Path) -> Result<(), String> {
    Ok(())
}

/// `FILE_ATTRIBUTE_REPARSE_POINT` (Microsoft's file attribute constants):
/// a symbolic link or a junction.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// `~/.derm` and `~/.derm/local` as folders of this user's that no one else
/// can write, `local` made 0700. The home folder itself must exist; it is
/// never made. `~/.derm` is not re-moded here: that is `derm setup`'s, on
/// the person's word (`setup/files.rs` `own_folder`, whose rules these
/// follow).
fn own_folders(local: &Path) -> Result<(), String> {
    let derm = local.parent().ok_or("no folder above the log's")?;
    let home = derm.parent().ok_or("no home folder")?;
    if !std::fs::metadata(home).map(|m| m.is_dir()).unwrap_or(false) {
        return Err(format!("{} is not a folder", home.display()));
    }
    own_folder(derm, false)?;
    own_folder(local, true)
}

#[cfg(unix)]
fn own_folder(dir: &Path, tighten: bool) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let made = match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !m.file_type().is_dir() {
        return Err(format!(
            "{} is not a folder (a link is refused)",
            dir.display()
        ));
    }
    if m.uid() != derm_core::platform::effective_user() {
        return Err(format!("{} belongs to another user", dir.display()));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!(
            "{} can be written by others; fix it with chmod 700",
            dir.display()
        ));
    }
    if (made || tighten) && m.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

/// On Windows a new folder takes the profile's inherited ACL (the user,
/// SYSTEM and Administrators); a reparse point (a link or a junction, case
/// 137) is refused.
#[cfg(windows)]
fn own_folder(dir: &Path, _tighten: bool) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "{} is not a folder (a link or a junction is refused)",
            dir.display()
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn own_folder(dir: &Path, _tighten: bool) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}
