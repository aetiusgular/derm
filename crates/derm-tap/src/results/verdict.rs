//! A chat's taint verdict (`contracts/policy.md` section 9, "Which
//! verdict"; Tony's call of 12 Nov: all three, chosen per task). Shared by
//! the gate (`derm-cli`'s `gate/taint/`) and the daemon (`derm-daemon`'s
//! `taint/`), which both depend on this crate.
//!
//! The order is `record` < `ask` < `deny`: anything that names a verdict
//! other than the chat's own start may only raise it ([`Verdict::raise`]).

use std::path::Path;

use serde_json::Value;

/// What a call taint catches gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// The call runs; a `taint.review` says what it would have been.
    Record,
    /// The call is asked about.
    Ask,
    /// The call is refused.
    Deny,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Record => "record",
            Verdict::Ask => "ask",
            Verdict::Deny => "deny",
        }
    }

    /// The schema's spelling only (`ask`, `deny`, `record`).
    pub fn parse(s: &str) -> Option<Verdict> {
        match s {
            "record" => Some(Verdict::Record),
            "ask" => Some(Verdict::Ask),
            "deny" => Some(Verdict::Deny),
            _ => None,
        }
    }

    /// The stricter of the two.
    pub fn raise(self, other: Verdict) -> Verdict {
        self.max(other)
    }
}

/// Where a chat's verdict came from (`run.start`'s `taint.from`, and what
/// `derm status` names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum From {
    /// `derm run --taint`.
    Flag,
    /// `~/.derm/settings.json`'s `taint.verdict`.
    Setting,
    /// Neither: `ask`.
    Default,
}

impl From {
    pub fn as_str(self) -> &'static str {
        match self {
            From::Flag => "flag",
            From::Setting => "setting",
            From::Default => "default",
        }
    }
}

const MAX_FILE: u64 = 64 * 1024;

/// A regular file of this user's, one link, that no one else may write: the
/// rule `crate::settings` reads the same file by.
#[cfg(unix)]
fn owner_only_writes(_path: &Path, meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.file_type().is_file()
        && meta.uid() == derm_core::platform::real_user()
        && meta.mode() & 0o022 == 0
        && meta.nlink() == 1
}

#[cfg(windows)]
fn owner_only_writes(path: &Path, meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_file() && derm_core::platform::windows::only_owner_writes(path)
}

#[cfg(not(any(unix, windows)))]
fn owner_only_writes(_path: &Path, _meta: &std::fs::Metadata) -> bool {
    false
}

/// `taint.verdict` from the settings file at `path` (`~/.derm/settings.json`),
/// and a warning when the file was there but not used. A file `crate::settings`
/// would ignore (not owner-only, too large, not JSON, an unknown key, a value
/// the schema refuses) gives no verdict, as it gives that reader its
/// defaults; so does a `taint` this schema refuses.
pub fn from_settings(path: &Path) -> (Option<Verdict>, Option<String>) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return (None, None);
    };
    let warn = |why: &str| {
        Some(format!(
            "{} {why}; taint's verdict is the default (ask)",
            path.display()
        ))
    };
    if !owner_only_writes(path, &meta) {
        return (
            None,
            warn("is not a regular file of yours that only you can write"),
        );
    }
    if meta.len() > MAX_FILE {
        return (None, warn("is too large"));
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return (None, warn("cannot be read"));
    };
    match parse_setting(&text) {
        Ok(v) => (v, None),
        Err(why) => (None, warn(&why)),
    }
}

/// The file's `taint.verdict`, after the whole file passed the schema's
/// rules for every key this crate reads.
pub fn parse_setting(text: &str) -> Result<Option<Verdict>, String> {
    crate::settings::parse(text)?;
    let v: Value = serde_json::from_str(text).map_err(|_| "is not JSON".to_string())?;
    let Some(taint) = v.get("taint") else {
        return Ok(None);
    };
    let t = taint
        .as_object()
        .ok_or("has a taint that is not an object")?;
    let mut out = None;
    for (k, v) in t {
        match (k.as_str(), v.as_str().and_then(Verdict::parse)) {
            ("verdict", Some(v)) => out = Some(v),
            _ => return Err(format!("has taint.{k} the schema does not allow")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raising_never_lowers() {
        use Verdict::*;
        assert_eq!(Record.raise(Ask), Ask);
        assert_eq!(Deny.raise(Record), Deny);
        assert_eq!(Ask.raise(Ask), Ask);
    }

    #[test]
    fn the_setting_is_read_and_checked() {
        assert_eq!(
            parse_setting(r#"{"version":1,"taint":{"verdict":"deny"}}"#),
            Ok(Some(Verdict::Deny))
        );
        assert_eq!(parse_setting(r#"{"version":1}"#), Ok(None));
        for bad in [
            r#"{"version":1,"taint":{"verdict":"allow"}}"#,
            r#"{"version":1,"taint":{"verdict":"ASK"}}"#,
            r#"{"version":1,"taint":{"verdict":"ask","more":1}}"#,
            r#"{"version":1,"taint":"deny"}"#,
            r#"{"version":1,"taint":{"verdict":"ask"},"other":1}"#,
            r#"{"taint":{"verdict":"ask"}}"#,
        ] {
            assert!(parse_setting(bad).is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_settings_file_others_can_write_names_no_verdict() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("dtaint-v-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("settings.json");
        std::fs::write(&f, r#"{"version":1,"taint":{"verdict":"record"}}"#).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(from_settings(&f).0, Some(Verdict::Record));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o622)).unwrap();
        let (v, warn) = from_settings(&f);
        assert_eq!(v, None);
        assert!(warn.unwrap().contains("only you can write"));
        assert_eq!(from_settings(&d.join("missing.json")), (None, None));
        let _ = std::fs::remove_dir_all(&d);
    }
}
