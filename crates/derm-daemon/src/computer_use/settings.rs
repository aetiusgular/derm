//! The switch for computer use: `computerUse.on` in `~/.derm/settings.json`
//! (`contracts/settings.schema.json`, lane U's key). Off by default (Tony,
//! 4 Nov: "yes computer use off by default"), and the schema says off in
//! every release until lane V's box test passes; lane W's `derm setup` asks.
//!
//! The file is read by the tap's rules (`derm_tap::settings::load`): a
//! regular file of this user's, not a link, with no group or other write
//! bit, one link, under 64 KiB, that the schema takes whole. Anything else
//! reads as off: a file an agent planted, or one this code cannot read,
//! never turns computer use on.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde_json::Value;

const MAX_FILE: u64 = 64 * 1024;

/// Whether the settings file at `path` turns computer use on. `false` for
/// no file, a file that is not the user's own, or one the schema refuses.
pub fn computer_use_on(path: &Path, uid: u32) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.file_type().is_file()
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
        || meta.len() > MAX_FILE
    {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    parse(&text).unwrap_or(false)
}

/// The key's value from the file's text, or why the file is refused. The
/// rest of the file must pass the tap's parser too (one file, one schema).
pub fn parse(text: &str) -> Result<bool, String> {
    derm_tap::settings::parse(text)?;
    let v: Value = serde_json::from_str(text).map_err(|_| "is not JSON".to_string())?;
    let Some(cu) = v.get("computerUse") else {
        return Ok(false);
    };
    let object = cu
        .as_object()
        .ok_or("has a computerUse that is not an object")?;
    let mut on = false;
    for (key, value) in object {
        match (key.as_str(), value) {
            ("on", Value::Bool(b)) => on = *b,
            _ => return Err(format!("has computerUse.{key} the schema does not allow")),
        }
    }
    Ok(on)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn off_unless_the_schema_takes_the_file_and_it_says_on() {
        assert_eq!(parse(r#"{"version":1}"#), Ok(false), "off by default");
        assert_eq!(parse(r#"{"version":1,"computerUse":{}}"#), Ok(false));
        assert_eq!(
            parse(r#"{"version":1,"computerUse":{"on":true}}"#),
            Ok(true)
        );
        assert_eq!(
            parse(r#"{"version":1,"computerUse":{"on":false}}"#),
            Ok(false)
        );
        for bad in [
            r#"{"version":1,"computerUse":{"on":"yes"}}"#,
            r#"{"version":1,"computerUse":{"on":true,"mode":"unrestricted"}}"#,
            r#"{"version":1,"computerUse":true}"#,
            r#"{"version":2,"computerUse":{"on":true}}"#,
            r#"{"version":1,"computerUse":{"on":true},"extra":1}"#,
            "not json",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_file_someone_else_could_write_reads_as_off() {
        let dir = std::env::temp_dir().join(format!("derm-cu-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, r#"{"version":1,"computerUse":{"on":true}}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        assert!(computer_use_on(&path, uid));
        assert!(!computer_use_on(&path, uid.wrapping_add(1)), "not ours");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(!computer_use_on(&path, uid), "group-writable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(!computer_use_on(&link, uid), "a link");
        std::fs::hard_link(&path, dir.join("second")).unwrap();
        assert!(!computer_use_on(&path, uid), "two links");
        assert!(!computer_use_on(&dir.join("missing.json"), uid));
        let _ = std::fs::remove_dir_all(dir);
    }
}
