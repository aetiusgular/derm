//! `~/.derm/secrets.json` (`contracts/secrets.schema.json`;
//! `contracts/policy.md` section 8): the secrets the broker injects, by id,
//! with the hosts each may go to and where its value is read at chat start.
//! The file never holds a value. It is written only by `derm secret`, from a
//! terminal, owner-only (0600 in a 0700 folder on Unix), and read back only
//! when it is a regular file of the user's that no one else can read or write
//! (the policy file's checks, case 226, tightened to no group or other bit at
//! all, since the file names where each value lives).
//!
//! Values are read from where an entry says: a variable of the reader's own
//! environment (which `derm run` then leaves out of the harness's), a file of
//! the user's that no one else can read, or the OS secret store (macOS
//! `security`, Linux `secret-tool`, each by absolute path with an argument
//! list). A value shorter than [`crate::MIN_VALUE_LEN`] or holding a control
//! character is refused: the first cannot be told from ordinary text, the
//! second would split a header.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Secret;

pub const VERSION: u64 = 1;
const MAX_SECRETS: usize = 64;
const MAX_HOSTS: usize = 16;
/// A value file larger than this is not a secret.
const MAX_VALUE_FILE: u64 = 64 * 1024;

/// The whole file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub version: u64,
    pub secrets: Vec<Entry>,
}

impl Default for File {
    fn default() -> Self {
        File {
            version: VERSION,
            secrets: Vec::new(),
        }
    }
}

/// One secret, by id. No value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub hosts: Vec<String>,
    pub from: From,
    /// Where else the value goes toward the secret's own hosts, beside
    /// headers: one named field each, `body:<path>` or `query:<param>`
    /// (decision 2, item 2; review W6C-S8, Tony's call of 13 Nov). Absent is
    /// headers only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Entry {
    /// The fields the value is also swapped into (a load has checked each).
    pub fn spots(&self) -> Vec<crate::place::Spot> {
        self.placement
            .iter()
            .flatten()
            .filter_map(|x| crate::place::spot(x))
            .collect()
    }
}

/// Where a value is read at chat start (exactly one key, as the schema's
/// `oneOf`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum From {
    Env(String),
    File(String),
    Keychain(String),
}

/// `<home>/.derm/secrets.json`.
pub fn path_for(home: &Path) -> PathBuf {
    home.join(".derm").join("secrets.json")
}

/// Whether `id` fits `^[a-z][a-z0-9-]{0,31}$`.
pub fn id_ok(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Whether `h` is an exact lowercase host name with at least one dot, labels
/// of 1 to 63 letters, digits and inner hyphens (the schema's pattern).
pub fn host_ok(h: &str) -> bool {
    let labels: Vec<&str> = h.split('.').collect();
    labels.len() >= 2
        && h.len() <= 253
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

/// Whether `v` fits `^[A-Z][A-Z0-9_]{0,63}$`.
pub fn env_ok(v: &str) -> bool {
    let b = v.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_uppercase()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

impl File {
    /// Every rule of the schema serde does not check itself.
    pub fn check(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err(format!("version {} is not {VERSION}", self.version));
        }
        if self.secrets.len() > MAX_SECRETS {
            return Err(format!("more than {MAX_SECRETS} secrets"));
        }
        let mut ids: Vec<&str> = Vec::new();
        for e in &self.secrets {
            if !id_ok(&e.id) {
                return Err(format!("id {:?} is not ^[a-z][a-z0-9-]{{0,31}}$", e.id));
            }
            if ids.contains(&e.id.as_str()) {
                return Err(format!("id {} appears twice", e.id));
            }
            ids.push(&e.id);
            if e.hosts.is_empty() || e.hosts.len() > MAX_HOSTS {
                return Err(format!("secret {}: 1 to {MAX_HOSTS} hosts", e.id));
            }
            for (i, h) in e.hosts.iter().enumerate() {
                if !host_ok(h) {
                    return Err(format!(
                        "secret {}: host {h:?} is not an exact lowercase name",
                        e.id
                    ));
                }
                if e.hosts[..i].contains(h) {
                    return Err(format!("secret {}: host {h} appears twice", e.id));
                }
            }
            match &e.from {
                From::Env(v) if !env_ok(v) => {
                    return Err(format!(
                        "secret {}: variable {v:?} is not ^[A-Z][A-Z0-9_]{{0,63}}$",
                        e.id
                    ))
                }
                // WW6-4: absolute by the system's own rule (`C:\...` on
                // Windows), and never a network path (`\\server\share`,
                // `//server/share`), which Windows would open over SMB.
                From::File(p) if !file_source_ok(p) => {
                    return Err(format!(
                        "secret {}: file {p:?} is not an absolute path on this system (a network path is refused)",
                        e.id
                    ))
                }
                From::Keychain(k) if k.is_empty() || k.chars().count() > 128 => {
                    return Err(format!(
                        "secret {}: keychain service of 1 to 128 characters",
                        e.id
                    ))
                }
                _ => {}
            }
            if let Some(p) = &e.placement {
                let mut seen: Vec<&str> = Vec::new();
                if p.is_empty() || p.len() > 8 {
                    return Err(format!("secret {}: placement holds 1 to 8 fields", e.id));
                }
                for x in p {
                    if crate::place::spot(x).is_none() || seen.contains(&x.as_str()) {
                        return Err(format!(
                            "secret {}: placement {x:?} is not body:<path> or query:<param>, \
                             once each",
                            e.id
                        ));
                    }
                    seen.push(x);
                }
            }
            if e.note.as_ref().is_some_and(|n| n.chars().count() > 200) {
                return Err(format!("secret {}: note over 200 characters", e.id));
            }
        }
        Ok(())
    }
}

/// Parse and check the file's text.
/// A `--file` source derm reads: absolute here, and not a network path
/// (Windows test w6, WW6-4).
fn file_source_ok(p: &str) -> bool {
    std::path::Path::new(p).is_absolute() && !p.starts_with("//") && !p.starts_with("\\\\")
}

pub fn parse(text: &str) -> Result<File, String> {
    let f: File = serde_json::from_str(text).map_err(|e| format!("secrets.json: {e}"))?;
    f.check().map_err(|e| format!("secrets.json: {e}"))?;
    Ok(f)
}

/// The file's text, as `derm secret` writes it.
pub fn render(f: &File) -> String {
    let mut s = serde_json::to_string_pretty(f).unwrap_or_default();
    s.push('\n');
    s
}

/// Read and check the file. A missing file is an empty list; a file that is
/// not a regular file of the user's, or that anyone else can read or write, is
/// refused.
pub fn load(path: &Path) -> Result<File, String> {
    match read_private(path, 1024 * 1024) {
        Ok(Some(text)) => parse(&text),
        Ok(None) => Ok(File::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Write the file whole: a private temporary beside it, then a rename, in a
/// folder made 0700 if missing. The folder must be the user's and closed to
/// others.
pub fn save(path: &Path, f: &File) -> Result<(), String> {
    f.check()?;
    let dir = path.parent().ok_or("no folder")?;
    write_private(dir, path, render(f).as_bytes())
}

/// The variable the agent finds a secret's placeholder in: the entry's own
/// variable for `env`, else `DERM_SECRET_<ID>` (the id upper-cased, `-` as
/// `_`).
pub fn variable(e: &Entry) -> String {
    match &e.from {
        From::Env(v) => v.clone(),
        _ => format!(
            "DERM_SECRET_{}",
            e.id.to_ascii_uppercase().replace('-', "_")
        ),
    }
}

/// A fresh placeholder for `id` (section 8.2): `dermsecret_<id>_<16 hex>`,
/// the hex drawn per chat.
pub fn mint_placeholder(id: &str) -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "no random source".to_string())?;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("dermsecret_{id}_{hex}"))
}

/// Whether a value may be brokered: long enough to scan for, no control
/// character.
pub fn value_ok(v: &str) -> Result<(), String> {
    if v.len() < crate::MIN_VALUE_LEN {
        return Err(format!("shorter than {} bytes", crate::MIN_VALUE_LEN));
    }
    if v.chars().any(char::is_control) {
        return Err("holds a control character or a line break".into());
    }
    Ok(())
}

/// Read one entry's value now. `env` is the reader's own environment. The
/// error never holds the value.
pub fn read_value(e: &Entry, env: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let v = match &e.from {
        From::Env(name) => env(name).ok_or_else(|| format!("{name} is not set"))?,
        From::File(p) => {
            let text = read_private(Path::new(p), MAX_VALUE_FILE)
                .map_err(|x| format!("{p}: {x}"))?
                .ok_or_else(|| format!("{p} does not exist"))?;
            text.strip_suffix("\r\n")
                .or_else(|| text.strip_suffix('\n'))
                .unwrap_or(&text)
                .to_string()
        }
        From::Keychain(service) => keychain(service)?,
    };
    value_ok(&v).map_err(|x| format!("secret {}: the value {x}", e.id))?;
    Ok(v)
}

/// Every entry's value and a fresh placeholder, for one chat. One unreadable
/// value fails the whole set, so a chat never starts with part of its
/// secrets; the error names the secret, never a value.
pub fn for_chat(f: &File, env: &dyn Fn(&str) -> Option<String>) -> Result<Vec<Secret>, String> {
    let mut out = Vec::with_capacity(f.secrets.len());
    for e in &f.secrets {
        let value = read_value(e, env).map_err(|x| format!("secret {}: {x}", e.id))?;
        out.push(Secret {
            id: e.id.clone(),
            value,
            hosts: e.hosts.clone(),
            placeholder: mint_placeholder(&e.id)?,
        });
    }
    Ok(out)
}

#[cfg(target_os = "macos")]
fn keychain(service: &str) -> Result<String, String> {
    run_store(
        "/usr/bin/security",
        &["find-generic-password", "-s", service, "-w"],
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn keychain(service: &str) -> Result<String, String> {
    run_store("/usr/bin/secret-tool", &["lookup", "service", service])
}

#[cfg(windows)]
fn keychain(_service: &str) -> Result<String, String> {
    Err("the OS secret store is not read on Windows yet (lane 6C)".into())
}

#[cfg(unix)]
fn run_store(program: &str, args: &[&str]) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .envs(
            [
                "HOME",
                "DBUS_SESSION_BUS_ADDRESS",
                "XDG_RUNTIME_DIR",
                "USER",
            ]
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (*k, v))),
        )
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{program} found no item ({})", out.status));
    }
    let mut v = String::from_utf8(out.stdout).map_err(|_| "the stored value is not UTF-8")?;
    if v.ends_with('\n') {
        v.pop();
    }
    Ok(v)
}

/// Read a file that must be a regular file of this user's with no group or
/// other bit, opened without following a link at its last part and without
/// blocking on a FIFO. `None` when it does not exist.
#[cfg(unix)]
pub(crate) fn read_private(path: &Path, max: u64) -> Result<Option<String>, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() {
        return Err("not a regular file".into());
    }
    // SAFETY: getuid has no preconditions and cannot fail.
    let me = unsafe { libc::getuid() };
    if m.uid() != me {
        return Err("not owned by this user".into());
    }
    if m.mode() & 0o077 != 0 {
        return Err(format!(
            "mode {:o} lets others read or write it; it must be 0600",
            m.mode() & 0o777
        ));
    }
    if m.len() > max {
        return Err(format!("larger than {max} bytes"));
    }
    let mut s = String::new();
    f.take(max + 1)
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    Ok(Some(s))
}

#[cfg(windows)]
pub(crate) fn read_private(path: &Path, max: u64) -> Result<Option<String>, String> {
    let m = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if !m.is_file() {
        return Err("not a regular file".into());
    }
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if !derm_core::platform::windows::only_owner_writes_file(&f) {
        return Err("someone else may write it".into());
    }
    if m.len() > max {
        return Err(format!("larger than {max} bytes"));
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Write `bytes` to `path` through a 0600 temporary in `dir`, which is made
/// 0700 when missing and must be this user's, closed to others.
#[cfg(unix)]
pub(crate) fn write_private(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // SAFETY: getuid has no preconditions and cannot fail.
    let me = unsafe { libc::getuid() };
    if !m.is_dir() || m.uid() != me || m.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is not a folder of yours that only you can write",
            dir.display()
        ));
    }
    let name = path.file_name().ok_or("no file name")?.to_string_lossy();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    let done = f.write_all(bytes).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = done.and_then(|_| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{}: {e}", path.display()));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn write_private(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".secrets.{}.tmp", std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, from: From) -> Entry {
        Entry {
            placement: None,
            id: id.into(),
            hosts: vec!["api.github.com".into()],
            from,
            note: None,
        }
    }

    #[test]
    fn the_schemas_fixture_parses_and_renders_back() {
        let text = include_str!("../../../contracts/fixtures/secrets/secrets.example.json");
        let f = parse(text).unwrap();
        assert_eq!(parse(&render(&f)).unwrap(), f);
    }

    #[test]
    fn the_schemas_rules_are_held() {
        let ok = File {
            version: 1,
            secrets: vec![entry("github", From::Env("GH_TOKEN".into()))],
        };
        assert!(ok.check().is_ok());
        let bad = |f: File| f.check().is_err();
        let mut f = ok.clone();
        f.secrets[0].id = "GitHub".into();
        assert!(bad(f));
        let mut f = ok.clone();
        f.secrets[0].id = "a_b".into();
        assert!(bad(f), "an underscore would let placeholders overlap");
        let mut f = ok.clone();
        f.secrets[0].hosts = vec!["*.github.com".into()];
        assert!(bad(f));
        let mut f = ok.clone();
        f.secrets[0].hosts = vec!["localhost".into()];
        assert!(bad(f), "one label");
        let mut f = ok.clone();
        f.secrets[0].hosts = vec!["api.github.com:443".into()];
        assert!(bad(f), "a port");
        let mut f = ok.clone();
        f.secrets[0].hosts = vec!["API.github.com".into()];
        assert!(bad(f));
        let mut f = ok.clone();
        f.secrets[0].from = From::Env("gh_token".into());
        assert!(bad(f));
        let mut f = ok.clone();
        f.secrets[0].from = From::File("relative/path".into());
        assert!(bad(f));
        let mut f = ok.clone();
        f.secrets.push(entry("github", From::Env("X".into())));
        assert!(bad(f), "duplicate id");
        let mut f = ok;
        f.version = 2;
        assert!(bad(f));
        assert!(parse(r#"{"version":1,"secrets":[],"value":"x"}"#).is_err());
        assert!(parse(
            r#"{"version":1,"secrets":[{"id":"a","hosts":["a.b"],"from":{"env":"A","file":"/x"}}]}"#
        )
        .is_err());
        assert!(parse(
            r#"{"version":1,"secrets":[{"id":"a","hosts":["a.b"],"from":{"env":"A"},"value":"x"}]}"#
        )
        .is_err());
    }

    /// Windows test w6, WW6-4: a `--file` source `C:\\...` was refused as
    /// "not an absolute path" (`starts_with('/')`), and then every chat.
    /// A file source is absolute by the system's own rule; a network path
    /// (`\\\\server\\share`) is not taken on any system.
    #[test]
    fn ww6_4_a_file_source_is_absolute_by_the_systems_own_rule() {
        let with = |p: &str| File {
            version: 1,
            secrets: vec![entry("gh", From::File(p.into()))],
        };
        assert_eq!(with(r"C:\Users\u\gh.val").check().is_ok(), cfg!(windows));
        assert_eq!(with("/home/u/gh.val").check().is_ok(), !cfg!(windows));
        assert!(with(r"\\server\share\gh.val").check().is_err());
        assert!(with("//server/share/gh.val").check().is_err());
        assert!(with(r"Users\u\gh.val").check().is_err());
        assert!(with(r"\Users\u\gh.val").check().is_err());
    }

    #[test]
    fn a_placeholder_has_the_contracts_form_and_differs_per_draw() {
        let a = mint_placeholder("github").unwrap();
        let b = mint_placeholder("github").unwrap();
        assert_ne!(a, b);
        let hex = a.strip_prefix("dermsecret_github_").unwrap();
        assert_eq!(hex.len(), 16);
        assert!(hex
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    }

    #[test]
    fn the_variable_is_the_entrys_own_or_derm_secret_id() {
        assert_eq!(
            variable(&entry("gh", From::Env("GH_TOKEN".into()))),
            "GH_TOKEN"
        );
        assert_eq!(
            variable(&entry("my-key", From::File("/x".into()))),
            "DERM_SECRET_MY_KEY"
        );
    }

    #[test]
    fn a_short_or_multiline_value_is_refused_and_the_error_holds_no_value() {
        let e = entry("gh", From::Env("GH".into()));
        let short = read_value(&e, &|_| Some("abc".into())).unwrap_err();
        assert!(!short.contains("abc"), "{short}");
        let nl =
            read_value(&e, &|_| Some("long-enough-value\r\nX-Injected: 1".into())).unwrap_err();
        assert!(nl.contains("control"), "{nl}");
        assert!(read_value(&e, &|_| None).unwrap_err().contains("not set"));
        assert_eq!(
            read_value(&e, &|_| Some("long-enough-value".into())).unwrap(),
            "long-enough-value"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_value_file_must_be_the_users_alone_and_not_a_link() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("derm-egress-vf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("v");
        std::fs::write(&p, "long-enough-value\n").unwrap();
        let e = entry("gh", From::File(p.to_string_lossy().into()));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_value(&e, &|_| None).unwrap_err().contains("0600"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_value(&e, &|_| None).unwrap(), "long-enough-value");
        let l = d.join("link");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        let el = entry("gh", From::File(l.to_string_lossy().into()));
        assert!(
            read_value(&el, &|_| None).is_err(),
            "a link is not followed"
        );
        let fifo = d.join("fifo");
        let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let ef = entry("gh", From::File(fifo.to_string_lossy().into()));
        assert!(read_value(&ef, &|_| None).unwrap_err().contains("regular"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_0600_in_a_0700_folder_and_load_refuses_a_widened_file() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = std::env::temp_dir().join(format!("derm-egress-sf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join(".derm").join("secrets.json");
        let f = File {
            version: 1,
            secrets: vec![entry("gh", From::Env("GH".into()))],
        };
        save(&p, &f).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(p.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(load(&p).unwrap(), f);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load(&p).is_err());
        assert_eq!(load(&d.join("missing.json")).unwrap(), File::default());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn for_chat_fails_whole_when_one_value_is_missing() {
        let f = File {
            version: 1,
            secrets: vec![
                entry("a", From::Env("A".into())),
                entry("b", From::Env("B".into())),
            ],
        };
        let env = |k: &str| (k == "A").then(|| "long-enough-value".to_string());
        let e = for_chat(&f, &env).unwrap_err();
        assert!(e.contains("secret b"), "{e}");
        let all = |_: &str| Some("long-enough-value".to_string());
        let s = for_chat(&f, &all).unwrap();
        assert_eq!(s.len(), 2);
        assert!(s[0].placeholder.starts_with("dermsecret_a_"));
    }
}
