//! `/etc/derm/agents.json` (plans/parallel_build_accounts.md section 2),
//! written only by lane L2's installer as root; read here, never written.
//! A reader refuses the file unless it is a regular file, root-owned, not
//! group or world writable, and parses whole; it then acts as if no
//! accounts exist and names the fix.
//!
//! And the person's default account, `agents.default` in
//! `~/.derm/settings.json`, read with the checks `derm_tap::settings::load`
//! makes (a regular file of the person's, one link, that no one else may
//! write, at most 64 KiB).

use std::path::Path;

use serde_json::Value;

pub const PATH: &str = "/etc/derm/agents.json";
pub const GROUP: &str = "derm-agents";
const MAX_FILE: u64 = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub slug: String,
    /// `derm-agent-<slug>`.
    pub name: String,
    pub uid: u32,
    /// The label the person typed; shown back, never parsed.
    pub subscription: String,
    pub home: String,
}

/// `[a-z0-9-]{1,24}` (section 2).
pub fn slug_ok(s: &str) -> bool {
    (1..=24).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A label the person types: 1 to 64 characters, none a control or format
/// character, so it prints back as typed and goes on an argument list whole.
pub fn label_ok(s: &str) -> bool {
    let n = s.chars().count();
    (1..=64).contains(&n)
        && s.trim() == s
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(c as u32, 0x200b..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069 | 0xfeff)
        })
}

/// What a label looks like on a terminal: control characters as `?`, in
/// case the file holds one the installer did not refuse.
pub fn shown(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The accounts, or why the file was not used (the caller then acts as if
/// there are none). `Ok(vec![])` when the file is not there.
pub fn load(path: &Path, owner: u32) -> Result<Vec<Account>, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let fix = "set the accounts up again with `derm agents add`";
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file; {fix}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != owner || meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is not root-owned or can be written by others (owner {}, mode {:o}); {fix}",
                path.display(),
                meta.uid(),
                meta.mode() & 0o7777
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    if meta.len() > MAX_FILE {
        return Err(format!("{} is too large; {fix}", path.display()));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|why| format!("{} {why}; {fix}", path.display()))
}

/// The whole file or nothing.
pub fn parse(text: &str) -> Result<Vec<Account>, String> {
    let v: Value = serde_json::from_str(text).map_err(|_| "is not JSON".to_string())?;
    let o = v.as_object().ok_or("is not a JSON object")?;
    if o.get("version").and_then(Value::as_i64) != Some(1) {
        return Err("has no \"version\": 1".into());
    }
    if o.get("group").and_then(Value::as_str) != Some(GROUP) {
        return Err(format!("does not name the group {GROUP}"));
    }
    let list = o
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or("has no \"accounts\" list")?;
    let mut out: Vec<Account> = Vec::new();
    for a in list {
        let s = |k: &str| a.get(k).and_then(Value::as_str);
        let name = s("name").ok_or("has an account with no name")?;
        let slug = name
            .strip_prefix("derm-agent-")
            .filter(|x| slug_ok(x))
            .ok_or_else(|| {
                format!(
                    "has an account not named derm-agent-<slug>: {}",
                    shown(name)
                )
            })?;
        let uid = a
            .get("uid")
            .and_then(Value::as_u64)
            .and_then(|u| u32::try_from(u).ok())
            .filter(|u| *u != 0)
            .ok_or_else(|| format!("gives {name} no uid, or uid 0"))?;
        let subscription =
            s("subscription").ok_or_else(|| format!("gives {name} no subscription"))?;
        let home = s("home")
            .filter(|h| h.starts_with('/') && !h.split('/').any(|p| p == ".." || p == "."))
            .ok_or_else(|| format!("gives {name} no absolute home"))?;
        if out.iter().any(|x| x.slug == slug || x.uid == uid) {
            return Err(format!("names {name} or its uid twice"));
        }
        out.push(Account {
            slug: slug.into(),
            name: name.into(),
            uid,
            subscription: subscription.into(),
            home: home.into(),
        });
    }
    Ok(out)
}

/// `agents.default`, or `None` (no file, no key), or why it was not used.
pub fn default_slug(settings: &Path, me: u32) -> Result<Option<String>, String> {
    let meta = match std::fs::symlink_metadata(settings) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    #[cfg(unix)]
    let mine = {
        use std::os::unix::fs::MetadataExt;
        meta.file_type().is_file()
            && meta.uid() == me
            && meta.mode() & 0o022 == 0
            && meta.nlink() == 1
    };
    #[cfg(not(unix))]
    let mine = {
        let _ = me;
        meta.file_type().is_file()
    };
    if !mine || meta.len() > 64 * 1024 {
        return Err(format!(
            "{} is not a regular file of yours that only you can write; agents.default not read",
            settings.display()
        ));
    }
    let text =
        std::fs::read_to_string(settings).map_err(|e| format!("{}: {e}", settings.display()))?;
    let v: Value = serde_json::from_str(&text).map_err(|_| {
        format!(
            "{} is not JSON; agents.default not read",
            settings.display()
        )
    })?;
    match v.get("agents").and_then(|a| a.get("default")) {
        None => Ok(None),
        Some(Value::String(s)) if slug_ok(s) => Ok(Some(s.clone())),
        Some(_) => Err(format!(
            "{}: agents.default is not a slug ([a-z0-9-], 1 to 24)",
            settings.display()
        )),
    }
}

/// The chat's account (section 2): the flag, else `agents.default`, else a
/// refusal naming `derm agents add`.
pub fn pick<'a>(
    accounts: &'a [Account],
    flag: Option<&str>,
    default: Option<&str>,
) -> Result<&'a Account, String> {
    let (slug, from) = match (flag, default) {
        (Some(s), _) => (s, "--account"),
        (None, Some(s)) => (s, "agents.default"),
        (None, None) => {
            return Err(
                "no account named: give --account <slug>, or set agents.default in ~/.derm/settings.json; `derm agents add <slug> --subscription <label>` makes one"
                    .into(),
            )
        }
    };
    accounts.iter().find(|a| a.slug == slug).ok_or_else(|| {
        format!(
            "{from} names {}, which {PATH} does not hold; `derm agents add {} --subscription <label>` makes it",
            shown(slug),
            if slug_ok(slug) { slug } else { "<slug>" }
        )
    })
}
