//! `/etc/derm/agents.json` (plans/parallel_build_accounts.md section 2),
//! written only by lane L2's installer as root; read, never written.
//!
//! One reader (integration, requests L1-8 and R7): on Linux this calls
//! `run::user::accounts`, which `derm run` uses too, so the trust rule (every
//! folder from `/` root's and writable by no one else, no link, a regular
//! file read without following one) and the parse are the same for both.
//! Elsewhere no accounts exist yet (`derm agents` says Linux only first).
//!
//! And the person's default account, `agents.default` in
//! `~/.derm/settings.json`, through the same reader `derm run` uses.

use std::path::Path;

pub use crate::run::user::slug::{AGENTS as PATH, GROUP, SLUG_MAX};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub slug: String,
    /// `derm-<slug>`.
    pub name: String,
    pub uid: u32,
    /// The label the person typed; shown back, never parsed.
    pub subscription: String,
    pub home: String,
}

/// `[a-z0-9-]{1,15}`, not reserved (section 2; `run/user/slug.rs`).
pub fn slug_ok(s: &str) -> bool {
    crate::run::user::slug::plain_slug(s)
}

/// The installer's own limit (lane L2, `accounts.py` `valid-label`).
pub const LABEL_MAX: usize = 120;

/// A label the person types: 1 to 120 characters, none a control or format
/// character, so it prints back as typed and goes on an argument list whole.
/// The installer refuses more (every Cf, Zl, Zp, Cs, Co and Cn character);
/// this is the part derm can tell without a Unicode table.
pub fn label_ok(s: &str) -> bool {
    let n = s.chars().count();
    (1..=LABEL_MAX).contains(&n)
        && s.trim() == s
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(c as u32, 0xad | 0x600..=0x605 | 0x180e | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x2069 | 0xfeff | 0xfff9..=0xfffb | 0xe0001..=0xe007f)
        })
}

/// What a label looks like on a terminal: control characters as `?`, in
/// case the file holds one the installer did not refuse.
pub fn shown(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(target_os = "linux")]
fn ours(a: crate::run::user::accounts::Account) -> Account {
    Account {
        slug: a.slug().to_string(),
        name: a.name,
        uid: a.uid,
        subscription: a.subscription,
        home: a.home,
    }
}

/// The accounts, or why the file was not used (the caller then acts as if
/// there are none). `Ok(vec![])` when the file is not there. `from` is the
/// folder trust starts at (`/` outside tests) and `owner` the uid every part
/// of the path must have (root outside tests).
#[cfg(target_os = "linux")]
pub fn load(path: &Path, from: &Path, owner: u32) -> Result<Vec<Account>, String> {
    match crate::run::user::accounts::load(path, from, owner) {
        (_, Some(why)) => Err(why),
        (a, None) => Ok(a.into_iter().map(ours).collect()),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn load(_: &Path, _: &Path, _: u32) -> Result<Vec<Account>, String> {
    Ok(vec![])
}

/// The whole file or nothing (the same parser `derm run` uses).
#[cfg(all(test, target_os = "linux"))]
pub fn parse(text: &str) -> Result<Vec<Account>, String> {
    crate::run::user::accounts::parse(text).map(|a| a.into_iter().map(ours).collect())
}

/// `agents.default`, or `None` (no file, no key), or why it was not used.
#[cfg(target_os = "linux")]
pub fn default_slug(settings: &Path) -> Result<Option<String>, String> {
    match crate::run::user::accounts::default_from(settings) {
        (_, Some(why)) => Err(why),
        (d, None) => Ok(d),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn default_slug(_: &Path) -> Result<Option<String>, String> {
    Ok(None)
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
