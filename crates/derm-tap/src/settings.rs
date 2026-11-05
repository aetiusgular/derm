//! The tap's and content capture's keys in `~/.derm/settings.json`
//! (`contracts/settings.schema.json`): `tap.on` (default true) and
//! `content.on` with `content.retentionDays` (default off). `derm run` reads
//! them at the start of a chat and the daemon's tap at each request.
//!
//! The file is read only when it is a regular file of this user's (no link
//! followed), with no group or other write bit, under 64 KiB. Anything else,
//! a file that is not JSON, or a value the schema refuses, gives the
//! defaults (the schema: "A file that does not follow this schema is ignored
//! with a warning, and the defaults apply"), and the caller is told why.

use std::path::{Path, PathBuf};

use serde_json::Value;

const MAX_FILE: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub tap_on: bool,
    /// `Some(days)` when content capture is on.
    pub content_days: Option<u8>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            tap_on: true,
            content_days: None,
        }
    }
}

/// `$HOME/.derm/settings.json`.
pub fn path_for(home: &str) -> PathBuf {
    Path::new(home).join(".derm").join("settings.json")
}

/// The settings, and a warning when the file was there but not used.
pub fn load(path: &Path) -> (Settings, Option<String>) {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return (Settings::default(), None),
    };
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let warn = |why: &str| {
        (
            Settings::default(),
            Some(format!(
                "{} {why}; the defaults apply (tap on, content off)",
                path.display()
            )),
        )
    };
    if !meta.file_type().is_file()
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
    {
        return warn("is not a regular file of yours that only you can write");
    }
    if meta.len() > MAX_FILE {
        return warn("is too large");
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return warn("cannot be read");
    };
    match parse(&text) {
        Ok(s) => (s, None),
        Err(why) => warn(&why),
    }
}

/// The schema's rules for the keys this crate reads, plus the shape of the
/// rest (an unknown top-level key makes the whole file invalid).
pub fn parse(text: &str) -> Result<Settings, String> {
    let v: Value = serde_json::from_str(text).map_err(|_| "is not JSON".to_string())?;
    let obj = v.as_object().ok_or("is not a JSON object")?;
    if obj.get("version").and_then(Value::as_i64) != Some(1) {
        return Err("has no \"version\": 1".into());
    }
    for k in obj.keys() {
        if !matches!(
            k.as_str(),
            "version" | "boundary" | "tap" | "content" | "installs" | "computerUse"
        ) {
            return Err(format!("has a key the schema does not name ({k})"));
        }
    }
    let mut s = Settings::default();
    if let Some(tap) = obj.get("tap") {
        let t = tap.as_object().ok_or("has a tap that is not an object")?;
        for (k, v) in t {
            match (k.as_str(), v) {
                ("on", Value::Bool(b)) => s.tap_on = *b,
                _ => return Err(format!("has tap.{k} the schema does not allow")),
            }
        }
    }
    if let Some(content) = obj.get("content") {
        let c = content
            .as_object()
            .ok_or("has a content that is not an object")?;
        let mut on = false;
        let mut days: Option<u8> = None;
        for (k, v) in c {
            match k.as_str() {
                "on" => {
                    on = v
                        .as_bool()
                        .ok_or("has content.on that is not true or false")?
                }
                "retentionDays" => {
                    let d = v
                        .as_u64()
                        .filter(|d| (1..=7).contains(d))
                        .ok_or("has content.retentionDays outside 1 to 7")?;
                    days = Some(d as u8);
                }
                _ => return Err(format!("has content.{k} the schema does not allow")),
            }
        }
        if on {
            s.content_days = Some(days.ok_or("turns content on with no retentionDays")?);
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_examples_and_defaults() {
        let ex = include_str!("../../../contracts/fixtures/tap/settings.example.json");
        assert_eq!(
            parse(ex),
            Ok(Settings {
                tap_on: true,
                content_days: Some(3)
            })
        );
        assert_eq!(parse(r#"{"version":1}"#), Ok(Settings::default()));
        assert!(!parse(r#"{"version":1,"tap":{"on":false}}"#).unwrap().tap_on);
        assert_eq!(
            parse(r#"{"version":1,"content":{"on":false,"retentionDays":5}}"#)
                .unwrap()
                .content_days,
            None
        );
    }

    #[test]
    fn a_file_the_schema_refuses_gives_the_defaults() {
        for bad in [
            "not json",
            "[]",
            r#"{"version":2}"#,
            r#"{"version":1,"extra":true}"#,
            r#"{"version":1,"tap":{"on":"yes"}}"#,
            r#"{"version":1,"tap":{"on":true,"upstreams":{}}}"#,
            r#"{"version":1,"content":{"on":true}}"#,
            r#"{"version":1,"content":{"on":true,"retentionDays":8}}"#,
            r#"{"version":1,"content":{"on":true,"retentionDays":0}}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_file_another_user_could_write_or_a_link_is_not_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("derm-tap-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("settings.json");
        std::fs::write(&f, r#"{"version":1,"tap":{"on":false}}"#).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load(&f),
            (
                Settings {
                    tap_on: false,
                    content_days: None
                },
                None
            )
        );
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        let (s, warn) = load(&f);
        assert!(s.tap_on && warn.is_some());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        let (s, warn) = load(&link);
        assert!(s.tap_on && warn.is_some());
        assert_eq!(load(&dir.join("missing.json")), (Settings::default(), None));
        let _ = std::fs::remove_dir_all(dir);
    }
}
