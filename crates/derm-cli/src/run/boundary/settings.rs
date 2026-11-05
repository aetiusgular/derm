//! `boundary.preAnswer` in `~/.derm/settings.json` (`contracts/settings.schema.json`):
//! the answer to the no-boundary question when no one is at a terminal
//! (case 129). Unset stops; `run-as-you` runs without a boundary; `stop`
//! stops. Off until set (lane W's `derm setup` writes it, behind a question).
//!
//! The file is read as the tap reads it (`derm_tap::settings::load`): only a
//! regular file of this user's, not a link, one link count, no group or
//! other write bit, at most 64 KiB. The schema's rule for a file that does
//! not follow it: "the defaults apply, except `boundary.preAnswer`, which
//! then counts as unset (so a script stops)". So any problem anywhere in the
//! file, in a key this lane does not read too, leaves the pre-answer unset.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::PreAnswer;

const MAX_FILE: u64 = 64 * 1024;

/// `$HOME/.derm/settings.json`.
pub(crate) fn path_for(home: &str) -> PathBuf {
    Path::new(home).join(".derm").join("settings.json")
}

/// The pre-answer, and why the file was not used when it was there.
pub(crate) fn load(path: &Path) -> (Option<PreAnswer>, Option<String>) {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return (None, None),
    };
    let uid = derm_core::platform::effective_user();
    let bad = |why: &str| (None, Some(format!("{} {why}", path.display())));
    if !meta.file_type().is_file()
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
    {
        return bad("is not a regular file of yours that only you can write");
    }
    if meta.len() > MAX_FILE {
        return bad("is too large");
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return bad("cannot be read");
    };
    match parse(&text) {
        Ok(p) => (p, None),
        Err(why) => bad(&why),
    }
}

/// The whole file against the schema; the pre-answer when it holds.
pub(crate) fn parse(text: &str) -> Result<Option<PreAnswer>, String> {
    // The tap's reader checks the version, the top-level keys, `tap` and
    // `content` against the same schema.
    derm_tap::settings::parse(text)?;
    let v: Value = serde_json::from_str(text).map_err(|_| "is not JSON".to_string())?;
    let obj = v.as_object().ok_or("is not a JSON object")?;
    if let Some(i) = obj.get("installs") {
        let i = i.as_object().ok_or("has installs that is not an object")?;
        for (k, v) in i {
            let fine = match k.as_str() {
                "check" => v.is_boolean(),
                "minAgeHours" => v.as_u64().is_some_and(|h| h <= 8760),
                _ => false,
            };
            if !fine {
                return Err(format!("has installs.{k} the schema does not allow"));
            }
        }
    }
    if let Some(c) = obj.get("computerUse") {
        let c = c
            .as_object()
            .ok_or("has computerUse that is not an object")?;
        for (k, v) in c {
            if !(k == "on" && v.is_boolean()) {
                return Err(format!("has computerUse.{k} the schema does not allow"));
            }
        }
    }
    let Some(b) = obj.get("boundary") else {
        return Ok(None);
    };
    let b = b.as_object().ok_or("has boundary that is not an object")?;
    let mut pre = None;
    for (k, v) in b {
        match (k.as_str(), v) {
            ("preAnswer", Value::Null) => pre = None,
            ("preAnswer", Value::String(s)) if s == "run-as-you" => pre = Some(PreAnswer::RunAsYou),
            ("preAnswer", Value::String(s)) if s == "stop" => pre = Some(PreAnswer::Stop),
            _ => return Err(format!("has boundary.{k} the schema does not allow")),
        }
    }
    Ok(pre)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_pre_answer_and_every_way_the_file_makes_it_unset() {
        assert_eq!(parse(r#"{"version":1}"#), Ok(None));
        assert_eq!(
            parse(r#"{"version":1,"boundary":{"preAnswer":"run-as-you"}}"#),
            Ok(Some(PreAnswer::RunAsYou))
        );
        assert_eq!(
            parse(r#"{"version":1,"boundary":{"preAnswer":"stop"}}"#),
            Ok(Some(PreAnswer::Stop))
        );
        assert_eq!(
            parse(r#"{"version":1,"boundary":{"preAnswer":null}}"#),
            Ok(None)
        );
        // A bad value, a bad key, a bad neighbour, a bad version: unset.
        for bad in [
            r#"{"version":1,"boundary":{"preAnswer":"yes"}}"#,
            r#"{"version":1,"boundary":{"preAnswer":"Run-As-You"}}"#,
            r#"{"version":1,"boundary":{"preAnswer":"run-as-you","default":"none"}}"#,
            r#"{"version":1,"boundary":"run-as-you"}"#,
            r#"{"version":1,"boundary":{"preAnswer":"run-as-you"},"tap":{"on":"no"}}"#,
            r#"{"version":1,"boundary":{"preAnswer":"run-as-you"},"installs":{"check":1}}"#,
            r#"{"version":1,"boundary":{"preAnswer":"run-as-you"},"computerUse":{"on":true,"x":1}}"#,
            r#"{"version":1,"boundary":{"preAnswer":"run-as-you"},"other":true}"#,
            r#"{"version":2,"boundary":{"preAnswer":"run-as-you"}}"#,
            r#"{"boundary":{"preAnswer":"run-as-you"}}"#,
            r#"not json"#,
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_file_others_can_write_or_a_link_is_not_read() {
        let d = std::env::temp_dir().join(format!(
            "derm-boundary-settings-{}-{}",
            std::process::id(),
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        ));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("settings.json");
        assert_eq!(load(&f), (None, None), "no file, no problem");
        std::fs::write(&f, r#"{"version":1,"boundary":{"preAnswer":"run-as-you"}}"#).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load(&f), (Some(PreAnswer::RunAsYou), None));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o620)).unwrap();
        let (p, why) = load(&f);
        assert_eq!(p, None);
        assert!(why.unwrap().contains("only you can write"));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = d.join("link.json");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert_eq!(load(&link).0, None, "a link is not followed");
        let hard = d.join("hard.json");
        std::fs::hard_link(&f, &hard).unwrap();
        assert_eq!(load(&f).0, None, "a second link to it is refused");
        let _ = std::fs::remove_dir_all(&d);
    }
}
