//! `~/.derm/settings.json` (`contracts/settings.schema.json`): read what is
//! there, change only the keys a question answered, check the whole file
//! against the schema, and write it private. A file that fails the schema is
//! ignored by every reader (and leaves `boundary.preAnswer` unset), so
//! nothing is written that would fail it.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

/// The keys the tap may not take as an upstream's name (the schema's).
const BUILT_IN: &[&str] = &["anthropic", "openai", "chatgpt", "openai-auto", "gemini"];

pub fn path_for(home: &Path) -> PathBuf {
    home.join(".derm").join("settings.json")
}

/// The file as it is: `Ok(None)` when there is none, an error when it is
/// there and not one of yours that only you can write, or fails the schema
/// (derm setup then starts from nothing and says so; it never keeps a bad
/// key by mistake).
pub fn read(path: &Path) -> Result<Option<Map<String, Value>>, String> {
    let text = match super::files::read_private(path, 64 * 1024) {
        Ok(Some(t)) => t,
        Ok(None) => return Ok(None),
        Err(e) => return Err(e),
    };
    problem(&text)?;
    let v: Value = serde_json::from_str(&text).map_err(|_| "is not JSON".to_string())?;
    Ok(v.as_object().cloned())
}

/// Sets `section.key` to `value`, creating the section.
pub fn set(doc: &mut Map<String, Value>, section: &str, key: &str, value: Value) {
    let s = doc
        .entry(section.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(o) = s.as_object_mut() {
        o.insert(key.to_string(), value);
    }
}

/// A new document, or the old one with `version` set.
pub fn start(old: Option<Map<String, Value>>) -> Map<String, Value> {
    let mut d = old.unwrap_or_default();
    d.insert("version".into(), json!(1));
    d
}

/// The file's text, pretty, one newline.
pub fn text(doc: &Map<String, Value>) -> String {
    let mut t = serde_json::to_string_pretty(&Value::Object(doc.clone())).unwrap_or_default();
    t.push('\n');
    t
}

/// Why `upstream` cannot be a `tap.upstreams` entry, or `None`.
pub fn upstream_problem(key: &str, base: &str, local: bool) -> Option<String> {
    let key_ok = !key.is_empty()
        && key.len() <= 32
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !key_ok {
        return Some("a name is 1 to 32 of a-z, 0-9 and -".into());
    }
    if BUILT_IN.contains(&key) {
        return Some(format!("{key} is a built-in upstream's name"));
    }
    let rest = if let Some(r) = base.strip_prefix("https://") {
        r
    } else if let Some(r) = base.strip_prefix("http://") {
        if !local {
            return Some("plain http only for a server on this machine or your own box".into());
        }
        r
    } else {
        return Some("the URL starts with https:// (or http:// for your own machine)".into());
    };
    let host = rest.split('/').next().unwrap_or("");
    if base.len() > 255
        || host.is_empty()
        || base.contains(['?', '#', '@', '\\'])
        || base.chars().any(char::is_whitespace)
    {
        return Some("a URL with a host, and no user, query or fragment".into());
    }
    None
}

/// The whole file against `contracts/settings.schema.json`: the tap's own
/// reader for `version`, the top-level keys, `tap` and `content`, and the
/// schema's rules for `boundary`, `installs` and `computerUse` (the rules
/// lane T's reader applies, `run/boundary/settings.rs`).
pub fn problem(text: &str) -> Result<(), String> {
    derm_tap::settings::parse(text)?;
    let v: Value = serde_json::from_str(text).map_err(|_| "is not JSON".to_string())?;
    let o = v.as_object().ok_or("is not a JSON object")?;
    if let Some(b) = o.get("boundary") {
        let b = b
            .as_object()
            .ok_or("has a boundary that is not an object")?;
        for (k, v) in b {
            let fine = k == "preAnswer"
                && (v.is_null() || v.as_str().is_some_and(|s| s == "run-as-you" || s == "stop"));
            if !fine {
                return Err(format!("has boundary.{k} the schema does not allow"));
            }
        }
    }
    if let Some(i) = o.get("installs") {
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
    if let Some(c) = o.get("computerUse") {
        let c = c
            .as_object()
            .ok_or("has computerUse that is not an object")?;
        for (k, v) in c {
            if !(k == "on" && v.is_boolean()) {
                return Err(format!("has computerUse.{k} the schema does not allow"));
            }
        }
    }
    Ok(())
}
