//! Private files under `~/.derm`: read only a regular file of yours that
//! only you can write (the readers' own rule: the hook core's
//! `loadPolicy`, the tap's and lane T's settings readers), write through a
//! new file in the same folder and a rename, 0600 in a 0700 folder, never
//! through a link, with the old file kept in `~/.derm/backups/` first.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The file's text, `Ok(None)` when there is none.
pub fn read_private(path: &Path, max: u64) -> Result<Option<String>, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let me = derm_core::platform::real_user();
    if !meta.file_type().is_file()
        || meta.uid() != me
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
    {
        return Err(format!(
            "{} is not a regular file of yours that only you can write",
            path.display()
        ));
    }
    if meta.len() > max {
        return Err(format!("{} is too large", path.display()));
    }
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut text = String::new();
    Read::by_ref(&mut f)
        .take(max)
        .read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(text))
}

/// `dir` as a folder of yours that no one else can write: made 0700 when
/// missing or readable by others; refused when it is a link, another user's, or open to others
/// (a folder others can write lets them swap the file, the hook core's
/// rule for the policy's folder).
pub fn own_folder(dir: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("{}: {e}", dir.display()))
        }
        Err(e) => Err(format!("{}: {e}", dir.display())),
        Ok(m) => {
            if !m.file_type().is_dir() {
                return Err(format!(
                    "{} is not a folder (a link is refused)",
                    dir.display()
                ));
            }
            if m.uid() != derm_core::platform::real_user() {
                return Err(format!("{} belongs to another user", dir.display()));
            }
            if m.mode() & 0o022 != 0 {
                return Err(format!(
                    "{} can be written by others; fix it with chmod 700 first",
                    dir.display()
                ));
            }
            // Readable by others (an earlier wave's 0755): made 0700, as a
            // new one is (BW5-2). Nothing derm runs reads it as another
            // user: the agents' user reaches the policy through the chat's
            // bridge, never this folder.
            if m.mode() & 0o077 != 0 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            Ok(())
        }
    }
}

fn stamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Writes `text` to `path` (0600), keeping any old file in `backups` first.
/// Returns the backup's path when there was an old file.
pub fn write_private(path: &Path, text: &str, backups: &Path) -> Result<Option<PathBuf>, String> {
    let dir = path.parent().ok_or("no folder")?;
    own_folder(dir)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("no file name")?;
    let backup = match read_private(path, 1024 * 1024)? {
        None => None,
        Some(old) => {
            own_folder(backups)?;
            let b = backups.join(format!("{name}.{}.{}", stamp(), std::process::id()));
            new_file(&b, &old)?;
            Some(b)
        }
    };
    let tmp = dir.join(format!(".{name}.derm-setup.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    new_file(&tmp, text)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })?;
    Ok(backup)
}

/// A new file (never an existing one or a link), 0600, synced.
fn new_file(path: &Path, text: &str) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// An executable file of yours (0700) for a shim: a new file, or a
/// replacement of a shim derm wrote before (`marker` in its text); any other
/// file at that path is left alone and refused.
pub fn write_shim(path: &Path, text: &str, marker: &str) -> Result<bool, String> {
    let dir = path.parent().ok_or("no folder")?;
    own_folder(dir)?;
    if let Some(old) = read_private(path, 64 * 1024).ok().flatten() {
        if old == text {
            return Ok(false);
        }
        if !old.contains(marker) {
            return Err(format!(
                "{} is not a shim derm wrote; left as it is",
                path.display()
            ));
        }
    } else if std::fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "{} is there and is not derm's; left as it is",
            path.display()
        ));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("no file name")?;
    let tmp = dir.join(format!(".{name}.derm-setup.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    new_file(&tmp, text)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })?;
    Ok(true)
}
