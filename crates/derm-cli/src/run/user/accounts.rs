//! `/etc/derm/agents.json`: the agent accounts, one per subscription
//! (`plans/parallel_build_accounts.md` section 2; note CB section 5).
//!
//! Written only by lane L2's installer, as root; read here and by
//! `derm agents`. Neither reader writes it. A reader refuses the file unless
//! it is a regular file, root-owned, not group or world writable (every
//! folder above it too, as `sudo` asks of `/etc/sudoers.d`), and parses
//! whole; it then acts as if no accounts exist and names the fix.
//!
//! The chat's account: `derm run --account <slug>`, else `agents.default`
//! in `~/.derm/settings.json`, else `derm run` refuses and names the ways to
//! choose or add one.

use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

pub use super::slug::{AGENTS, GROUP};
/// The fix a refused or missing file names.
const FIX: &str = "re-run the installer (sudo packaging/linux/agent-user/install.sh --account <slug> --subscription <label>), or derm agents add <slug>";
/// `subscription` is shown back, never parsed; it is cut to this.
const MAX_LABEL: usize = 120;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    group: String,
    accounts: Vec<Account>,
}

/// One agent account, as root wrote it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// `derm-<slug>`.
    pub name: String,
    pub uid: u32,
    /// The label the person chose for the subscription it signs in to.
    pub subscription: String,
    /// `/var/lib/derm/agents/<slug>`.
    pub home: String,
}

impl Account {
    /// The part after `derm-`.
    pub fn slug(&self) -> &str {
        self.name.strip_prefix(PREFIX).unwrap_or(&self.name)
    }

    // No `path()` since step P: a project chat's `PATH` holds no home
    // folder (`run/user/project.rs`'s `PATH`), and `derm agents login`
    // builds its own.
}

pub use super::slug::{plain_slug, PREFIX, SLUG_MAX};

/// The accounts on this machine, and why the file was not used when it is
/// there and refused.
pub fn load_default() -> (Vec<Account>, Option<String>) {
    load(Path::new(AGENTS), Path::new("/"), 0)
}

/// [`load_default`] with the root of trust and its owner given (tests).
pub fn load(file: &Path, from: &Path, trusted: u32) -> (Vec<Account>, Option<String>) {
    match std::fs::symlink_metadata(file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), None),
        _ => {}
    }
    match read(file, from, trusted) {
        Ok(a) => (a, None),
        Err(why) => (
            Vec::new(),
            Some(format!(
                "{why}; treated as no agent accounts. To fix: {FIX}"
            )),
        ),
    }
}

fn read(file: &Path, from: &Path, trusted: u32) -> Result<Vec<Account>, String> {
    let meta = std::fs::symlink_metadata(file).map_err(|e| format!("{}: {e}", file.display()))?;
    super::anchor::trusted_path(file, from, trusted)?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", file.display()));
    }
    let text = super::anchor::read_nofollow(file)?;
    parse(&text).map_err(|why| format!("{}: {why}", file.display()))
}

/// The file's text, whole or not at all (section 2's contract). The one
/// parser: `derm agents` reads through it too (request L1-8).
pub fn parse(text: &str) -> Result<Vec<Account>, String> {
    let f: File =
        serde_json::from_str(text).map_err(|e| format!("is not the expected JSON ({e})"))?;
    if f.version != 1 {
        return Err(format!("version {} is not 1", f.version));
    }
    if f.group != GROUP {
        return Err(format!("group {:?} is not {GROUP:?}", f.group));
    }
    let mut seen_uid = std::collections::BTreeSet::new();
    let mut seen_name = std::collections::BTreeSet::new();
    for a in &f.accounts {
        let slug = a.name.strip_prefix(PREFIX).unwrap_or("");
        if !plain_slug(slug) {
            return Err(format!(
                "{:?} is not derm-<slug> with a slug of a-z, 0-9 and -, 1 to {SLUG_MAX} long and not reserved",
                a.name
            ));
        }
        if a.uid == 0 {
            return Err(format!("{} has uid 0", a.name));
        }
        if a.home != format!("/var/lib/derm/agents/{slug}") {
            return Err(format!(
                "{}'s home {:?} is not /var/lib/derm/agents/{slug}",
                a.name, a.home
            ));
        }
        if a.subscription.chars().count() > MAX_LABEL
            || a.subscription.chars().any(char::is_control)
        {
            return Err(format!(
                "{}'s subscription label is longer than {MAX_LABEL} or holds control characters",
                a.name
            ));
        }
        if !seen_uid.insert(a.uid) || !seen_name.insert(a.name.clone()) {
            return Err(format!("{} or uid {} is named twice", a.name, a.uid));
        }
    }
    Ok(f.accounts)
}

/// The chat's account: the flag, else the default, else none (and then a
/// refusal when accounts exist, since the chat would otherwise run as the
/// person beside agent accounts that keep chats apart).
pub fn choose<'a>(
    accounts: &'a [Account],
    flag: Option<&str>,
    default: Option<&str>,
) -> Result<Option<&'a Account>, String> {
    let names = || {
        accounts
            .iter()
            .map(|a| a.slug().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let Some(slug) = flag.or(default) else {
        if accounts.is_empty() {
            return Ok(None);
        }
        return Err(format!(
            "this machine has agent accounts ({}); choose one with derm run --account <slug> or agents.default in ~/.derm/settings.json, or add one with derm agents add <slug>",
            names()
        ));
    };
    let from = if flag.is_some() {
        "--account"
    } else {
        "agents.default"
    };
    if accounts.is_empty() {
        return Err(format!(
            "{from} names {slug:?}, and no agent accounts are set up here ({AGENTS}); add one with derm agents add {slug}"
        ));
    }
    accounts
        .iter()
        .find(|a| a.slug() == slug)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "{from} names {slug:?}, which is not one of this machine's agent accounts ({}); add it with derm agents add {slug}",
                names()
            )
        })
}

/// `agents.default` from `~/.derm/settings.json`, read with the checks the
/// tap's and the pre-answer's readers make (a regular file of this user's,
/// one link, no group or other write bit, at most 64 KiB), and why the file
/// was not used when it was there.
pub fn default_from(settings: &Path) -> (Option<String>, Option<String>) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(settings) else {
        return (None, None);
    };
    let bad = |why: &str| {
        (
            None,
            Some(format!(
                "{} {why}; agents.default not read",
                settings.display()
            )),
        )
    };
    let mine = meta.file_type().is_file()
        && meta.uid() == derm_core::platform::effective_user()
        && meta.mode() & 0o022 == 0
        && meta.nlink() == 1;
    if !mine {
        return bad("is not a regular file of yours that only you can write");
    }
    if meta.len() > 64 * 1024 {
        return bad("is too large");
    }
    let Ok(text) = std::fs::read_to_string(settings) else {
        return bad("cannot be read");
    };
    match parse_default(&text) {
        Ok(d) => (d, None),
        Err(why) => bad(&why),
    }
}

/// `agents` holds only `default`, a slug or null.
pub fn parse_default(text: &str) -> Result<Option<String>, String> {
    // The whole file against the schema first, as every other reader of it
    // does (`derm_tap::settings::parse`), so a file the tap ignores names no
    // default either.
    derm_tap::settings::parse(text)?;
    let v: Value = serde_json::from_str(text).map_err(|_| "is not JSON".to_string())?;
    let Some(a) = v.get("agents") else {
        return Ok(None);
    };
    let a = a.as_object().ok_or("has agents that is not an object")?;
    let mut out = None;
    for (k, v) in a {
        match (k.as_str(), v) {
            ("default", Value::Null) => out = None,
            ("default", Value::String(s)) if plain_slug(s) => out = Some(s.clone()),
            _ => return Err(format!("has agents.{k} the schema does not allow")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn account(slug: &str, uid: u32) -> Account {
        Account {
            name: format!("derm-{slug}"),
            uid,
            subscription: format!("{slug} plan"),
            home: format!("/var/lib/derm/agents/{slug}"),
        }
    }

    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn dir() -> Dir {
        let d = std::env::temp_dir().join(format!("derm-acct-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        Dir(d)
    }

    fn write(d: &Dir, text: &str, mode: u32) -> std::path::PathBuf {
        let f = d.0.join("agents.json");
        std::fs::write(&f, text).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        f
    }

    const GOOD: &str = r#"{"version":1,"group":"derm-agents","accounts":[
        {"name":"derm-max","uid":1201,"subscription":"Claude Max","home":"/var/lib/derm/agents/max"},
        {"name":"derm-gpt","uid":1202,"subscription":"ChatGPT Plus","home":"/var/lib/derm/agents/gpt"}]}"#;

    fn me() -> u32 {
        derm_core::platform::effective_user()
    }

    #[test]
    fn the_file_as_the_installer_writes_it() {
        let d = dir();
        let f = write(&d, GOOD, 0o644);
        let (a, warn) = load(&f, &d.0, me());
        assert_eq!(warn, None);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].slug(), "max");
        // Step P2 removed the home-first `PATH` this checked (AI-1's cause);
        // a project chat's PATH is `run/user/project.rs`'s, with no home.
        assert_eq!(a[0].home, "/var/lib/derm/agents/max");
        let (none, warn) = load(&d.0.join("missing.json"), &d.0, me());
        assert!(none.is_empty() && warn.is_none());
    }

    #[test]
    fn a_file_it_cannot_trust_or_read_whole_counts_as_no_accounts_and_names_the_fix() {
        let d = dir();
        let cases: &[(&str, u32)] = &[
            (GOOD, 0o664),
            (GOOD, 0o646),
            ("{", 0o644),
            (&GOOD.replace("\"version\":1", "\"version\":2"), 0o644),
            (&GOOD.replace("derm-agents", "wheel"), 0o644),
            (&GOOD.replace("\"uid\":1201", "\"uid\":0"), 0o644),
            (&GOOD.replace("derm-max", "derm-MAX"), 0o644),
            (&GOOD.replace("derm-max", "max"), 0o644),
            // The lanes' first form, and a slug over 15 or reserved.
            (&GOOD.replace("derm-max", "derm-agent-max"), 0o644),
            (
                &GOOD.replace("derm-max", "derm-abcdefghijklmnop").replace(
                    "/var/lib/derm/agents/max",
                    "/var/lib/derm/agents/abcdefghijklmnop",
                ),
                0o644,
            ),
            (
                &GOOD
                    .replace("derm-max", "derm-agents")
                    .replace("/var/lib/derm/agents/max", "/var/lib/derm/agents/agents"),
                0o644,
            ),
            (
                &GOOD.replace("/var/lib/derm/agents/max", "/home/max"),
                0o644,
            ),
            (&GOOD.replace("\"uid\":1202", "\"uid\":1201"), 0o644),
            (&GOOD.replace("Claude Max", "Claude\u{1b}[2J"), 0o644),
            (&GOOD.replace("\"group\"", "\"extra\":1,\"group\""), 0o644),
        ];
        for (text, mode) in cases {
            let f = write(&d, text, *mode);
            let (a, warn) = load(&f, &d.0, me());
            assert!(a.is_empty(), "{text} {mode:o}");
            let w = warn.unwrap_or_default();
            assert!(
                w.contains("treated as no agent accounts") && w.contains("derm agents add"),
                "{w}"
            );
        }
        // Owned by another uid than the trusted one.
        let f = write(&d, GOOD, 0o644);
        let (a, warn) = load(&f, &d.0, me() + 1);
        assert!(a.is_empty() && warn.is_some());
        // A link.
        let l = d.0.join("link.json");
        std::os::unix::fs::symlink(&f, &l).unwrap();
        assert!(load(&l, &d.0, me()).1.unwrap().contains("is a link"));
    }

    #[test]
    fn the_flag_then_the_default_then_a_refusal() {
        let a = [account("max", 1201), account("gpt", 1202)];
        assert_eq!(
            choose(&a, Some("gpt"), Some("max"))
                .unwrap()
                .unwrap()
                .slug(),
            "gpt"
        );
        assert_eq!(
            choose(&a, None, Some("max")).unwrap().unwrap().slug(),
            "max"
        );
        let e = choose(&a, None, None).unwrap_err();
        assert!(
            e.contains("max, gpt") && e.contains("--account") && e.contains("derm agents add"),
            "{e}"
        );
        let e = choose(&a, Some("pro"), None).unwrap_err();
        assert!(
            e.contains("--account names \"pro\"") && e.contains("derm agents add pro"),
            "{e}"
        );
        let e = choose(&a, None, Some("pro")).unwrap_err();
        assert!(e.contains("agents.default names"), "{e}");
        assert_eq!(choose(&[], None, None), Ok(None));
        assert!(choose(&[], Some("max"), None)
            .unwrap_err()
            .contains("no agent accounts"));
        assert!(choose(&[], None, Some("max")).is_err());
    }

    #[test]
    fn agents_default_is_read_the_way_the_other_settings_are() {
        assert_eq!(parse_default(r#"{"version":1}"#), Ok(None));
        assert_eq!(
            parse_default(r#"{"version":1,"agents":{"default":"max"}}"#),
            Ok(Some("max".into()))
        );
        assert_eq!(
            parse_default(r#"{"version":1,"agents":{"default":null}}"#),
            Ok(None)
        );
        for bad in [
            r#"{"agents":{"default":"MAX"}}"#,
            r#"{"agents":{"default":"../x"}}"#,
            r#"{"agents":{"other":1}}"#,
            r#"{"agents":"max"}"#,
            "{",
        ] {
            assert!(parse_default(bad).is_err(), "{bad}");
        }
        let d = dir();
        let f = d.0.join("settings.json");
        std::fs::write(&f, r#"{"version":1,"agents":{"default":"max"}}"#).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(default_from(&f), (Some("max".into()), None));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o622)).unwrap();
        let (d0, w) = default_from(&f);
        assert!(d0.is_none() && w.unwrap().contains("only you can write"));
        assert_eq!(default_from(&d.0.join("none.json")), (None, None));
    }

    #[test]
    fn slugs() {
        for ok in ["max", "a", "pro-2", &"x".repeat(15), "agentx", "my-agent"] {
            assert!(plain_slug(ok), "{ok}");
        }
        for no in [
            "",
            "Max",
            "a_b",
            "a.b",
            "../a",
            &"x".repeat(16),
            "a b",
            "agent",
            "agents",
            "agent-tonyg",
        ] {
            assert!(!plain_slug(no), "{no}");
        }
    }
}
