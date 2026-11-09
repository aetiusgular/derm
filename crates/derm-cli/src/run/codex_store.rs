//! Where Codex keeps its sign-in, read from the files Codex reads, before a
//! chat under srt (fix pass 6, FP5R-5; the separate review of fix pass 5).
//!
//! Codex 0.163.0 keeps its ChatGPT sign-in where `cli_auth_credentials_store`
//! says (`codex-rs/config/src/types.rs:133-146`): `file` (the default,
//! `$CODEX_HOME/auth.json`), `keyring` (the OS keyring; a save fails when it
//! is unavailable), `auto` (the keyring, falling back to `auth.json` on a
//! failed save, and loading the keyring's copy first,
//! `login/src/auth/storage.rs:479-524`) or `ephemeral` (memory only). Its
//! refresh tokens are single use (`refresh_token_reused`,
//! `login/src/auth/manager.rs:1688`). Under srt the keyring cannot be written
//! (macOS: srt's write roots, inferred as for Claude Code, MW5-26; Linux:
//! srt's seccomp refuses every `socket(AF_UNIX)`, so the Secret Service's
//! D-Bus is out of reach, FP2-L1), so with `keyring` or `auto` a renewal
//! inside srt spends the refresh token the keyring still holds and leaves the
//! rotated one in plaintext (`auto`) or nowhere (`keyring`): the host's Codex
//! is signed out.
//!
//! The setting can come from (Codex 0.163.0, `config/src/loader/mod.rs:80,
//! 113-130, 730-746`, `layer_io.rs:22, 222-231`, `macos.rs:27-53`,
//! `core/src/config/mod.rs:4460-4466`): the requirements (`/etc/codex/
//! requirements.toml`, the legacy `/etc/codex/managed_config.toml` and
//! `$CODEX_HOME/managed_config.toml`, and on macOS the managed preferences of
//! `com.openai.codex`), which win over everything; then `-c` on the command
//! line; then the config layers (`/etc/codex/config.toml`,
//! `$CODEX_HOME/config.toml`, a project's `.codex/config.toml`). derm reads
//! the TOML files for the one key and fails safe: a file it cannot read, or
//! managed preferences it does not parse, count as a store that is not a
//! file. This module only reads; `plan` decides.
//!
//! The same managed files are read for Codex's own sandbox (fix pass 8,
//! MW5-32): under srt derm turns it off with `-c`, and a managed file that
//! keeps it on (`sandbox_reason`) wins over `-c`, so srt is refused.

use std::path::{Path, PathBuf};

use super::plan::CodexStoreFiles;

/// The roots the files hang from, so a test can use a scratch folder.
pub struct Roots {
    /// `/etc/codex`.
    pub etc: PathBuf,
    /// `/Library/Managed Preferences` (macOS only).
    pub managed_prefs: Option<PathBuf>,
    /// The user's name, for the per-user managed preferences folder.
    pub user: Option<String>,
}

impl Roots {
    pub fn real(macos: bool) -> Roots {
        Roots {
            etc: PathBuf::from("/etc/codex"),
            managed_prefs: macos.then(|| PathBuf::from("/Library/Managed Preferences")),
            user: std::env::var("USER")
                .ok()
                .filter(|u| !u.is_empty() && !u.contains('/')),
        }
    }
}

/// Values that keep the sign-in out of a store srt cannot write.
fn safe(value: &str) -> bool {
    matches!(value, "file" | "ephemeral")
}

/// A TOML file's document: `Ok(None)` when the file is absent, `Err` when
/// it cannot be read whole.
fn doc_of(path: &Path) -> Result<Option<toml_edit::DocumentMut>, String> {
    let text = match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{} could not be read ({e})", path.display())),
        Ok(m) if m.len() > 1 << 20 => {
            return Err(format!(
                "{} is over 1 MiB, so derm did not read it",
                path.display()
            ))
        }
        Ok(_) => std::fs::read_to_string(path)
            .map_err(|e| format!("{} could not be read ({e})", path.display()))?,
    };
    text.parse()
        .map(Some)
        .map_err(|_| format!("{} is not TOML derm can read", path.display()))
}

/// The top-level `cli_auth_credentials_store` of a TOML file: `Ok(None)`
/// when the file or the key is absent, `Err` when it cannot be read whole.
fn value_of(path: &Path) -> Result<Option<String>, String> {
    let Some(doc) = doc_of(path)? else {
        return Ok(None);
    };
    match doc.get("cli_auth_credentials_store") {
        None => Ok(None),
        Some(item) => match item.as_str() {
            Some(v) => Ok(Some(v.to_string())),
            None => Err(format!(
                "{} sets cli_auth_credentials_store to something other than a string",
                path.display()
            )),
        },
    }
}

/// Why `path` may set a store srt cannot write, if it does.
fn reason(path: &Path) -> Option<String> {
    match value_of(path) {
        Ok(None) => None,
        Ok(Some(v)) if safe(&v) => None,
        Ok(Some(v)) => Some(format!(
            "{} sets cli_auth_credentials_store = \"{v}\"",
            path.display()
        )),
        Err(e) => Some(e),
    }
}

/// Why a managed file keeps Codex in its own sandbox (MW5-32), which cannot
/// start inside srt's: Codex 0.163.0's requirements constrain the modes
/// (`allowed_sandbox_modes`), the profiles (`allowed_permission_profiles`)
/// and the default profile (`default_permissions`)
/// (`config/src/config_requirements.rs:1046-1056`), and the legacy managed
/// config is a layer over the command line's `-c`
/// (`config/src/loader/mod.rs:420-440`), so a `sandbox_mode` or
/// `default_permissions` there beats derm's. A file derm cannot read counts.
fn sandbox_reason(path: &Path) -> Option<String> {
    let doc = match doc_of(path) {
        Ok(None) => return None,
        Ok(Some(d)) => d,
        Err(e) => return Some(e),
    };
    let p = path.display();
    if let Some(item) = doc.get("sandbox_mode") {
        if item.as_str() != Some("danger-full-access") {
            return Some(format!(
                "{p} sets sandbox_mode = {}",
                item.to_string().trim()
            ));
        }
    }
    if let Some(item) = doc.get("default_permissions") {
        if item.as_str() != Some(":danger-full-access") {
            return Some(format!(
                "{p} sets default_permissions = {}",
                item.to_string().trim()
            ));
        }
    }
    if let Some(item) = doc.get("allowed_sandbox_modes") {
        let allows = item
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("danger-full-access")));
        if !allows {
            return Some(format!(
                "{p} sets allowed_sandbox_modes without danger-full-access"
            ));
        }
    }
    if doc.get("allowed_permission_profiles").is_some() {
        return Some(format!(
            "{p} sets allowed_permission_profiles, which derm does not read"
        ));
    }
    // FP8-S6: a managed `[permissions.filesystem] deny_read` refuses a
    // full-access profile (`core/src/config/mod.rs:4230-4245`,
    // `permission_profile_catalog.rs:128-145`), and a `[[remote_sandbox_config]]`
    // whose host pattern matches replaces `allowed_sandbox_modes`
    // (`config/src/config_requirements.rs:1494-1508`); derm does not match
    // host patterns, so any such table counts.
    let deny_read = doc
        .get("permissions")
        .and_then(|t| t.get("filesystem"))
        .and_then(|t| t.get("deny_read"))
        .is_some_and(|d| d.as_array().is_none_or(|a| !a.is_empty()));
    if deny_read {
        return Some(format!(
            "{p} sets permissions.filesystem.deny_read, which Codex enforces with its own sandbox"
        ));
    }
    if doc.get("remote_sandbox_config").is_some() {
        return Some(format!(
            "{p} sets remote_sandbox_config, which derm does not read"
        ));
    }
    None
}

fn first(reasons: impl IntoIterator<Item = Option<String>>) -> Option<String> {
    let all: Vec<String> = reasons.into_iter().flatten().collect();
    (!all.is_empty()).then(|| all.join("; "))
}

/// Reads the files Codex reads for its store. `codex_home` is `CODEX_HOME`
/// when set to an absolute path, else `~/.codex`; `cwd` is the chat's
/// folder, from which a project's `.codex/config.toml` files are read up to
/// the root (at most 64 levels).
pub fn read(home: &str, cwd: &str, codex_home_env: Option<&str>, roots: &Roots) -> CodexStoreFiles {
    let default_home = Path::new(home).join(".codex");
    let codex_home = codex_home_env
        .filter(|h| crate::run::args::absolute(h))
        .map(PathBuf::from)
        .unwrap_or_else(|| default_home.clone());
    let managed_files = [
        roots.etc.join("requirements.toml"),
        roots.etc.join("managed_config.toml"),
        codex_home.join("managed_config.toml"),
    ];
    let mut managed: Vec<Option<String>> = managed_files.iter().map(|f| reason(f)).collect();
    let mut managed_sandbox: Vec<Option<String>> =
        managed_files.iter().map(|f| sandbox_reason(f)).collect();
    if let Some(prefs) = &roots.managed_prefs {
        let mut plists = vec![prefs.join("com.openai.codex.plist")];
        if let Some(u) = &roots.user {
            plists.push(prefs.join(u).join("com.openai.codex.plist"));
        }
        for p in plists {
            if std::fs::symlink_metadata(&p).is_ok() {
                let why = format!(
                    "{} holds managed preferences for Codex, which derm does not read",
                    p.display()
                );
                managed.push(Some(why.clone()));
                managed_sandbox.push(Some(why));
            }
        }
    }
    let mut config = vec![
        reason(&roots.etc.join("config.toml")),
        reason(&codex_home.join("config.toml")),
    ];
    let mut dir = Some(Path::new(cwd));
    for _ in 0..64 {
        let Some(d) = dir else { break };
        let f = d.join(".codex").join("config.toml");
        if f != codex_home.join("config.toml") {
            config.push(reason(&f));
        }
        dir = d.parent();
    }
    CodexStoreFiles {
        managed: first(managed),
        config: first(config),
        auth_file: (codex_home != default_home)
            .then(|| codex_home.join("auth.json").to_string_lossy().into_owned()),
        managed_sandbox: first(managed_sandbox),
        profiles: profiles_in(&codex_home),
    }
}

/// The `<name>.config.toml` profile layers in Codex's home (FP8-S1), at most
/// 256, sorted; `config.toml` itself is a control file already. Only names
/// are read; a link is listed by its own path.
fn profiles_in(codex_home: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(codex_home) else {
        return Vec::new();
    };
    let mut out: Vec<String> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            (name.len() > ".config.toml".len() && name.ends_with(".config.toml"))
                .then(|| codex_home.join(&name).to_string_lossy().into_owned())
        })
        .collect();
    // Re-review FP8R-4: the same 256 whatever order the folder lists them in.
    out.sort();
    out.truncate(256);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("derm-codex-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn roots(d: &Path) -> Roots {
        Roots {
            etc: d.join("etc"),
            managed_prefs: Some(d.join("prefs")),
            user: Some("u".into()),
        }
    }

    /// FP5R-5: each file Codex reads its store from, in each way it can say
    /// one srt cannot write, and the ways it cannot.
    #[test]
    fn fp5r_5_codex_store_is_read_from_every_file_codex_reads() {
        let d = scratch("read");
        let home = d.join("home");
        let proj = home.join("p").join("sub");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::create_dir_all(d.join("etc")).unwrap();
        let r = roots(&d);
        let read_now = || read(home.to_str().unwrap(), proj.to_str().unwrap(), None, &r);
        // Nothing set: Codex's default, a file.
        let f = read_now();
        assert!(
            f.managed.is_none() && f.config.is_none() && f.auth_file.is_none(),
            "{f:?}"
        );
        // `file` and `ephemeral` are safe; `auto` and `keyring` are not.
        let user = home.join(".codex").join("config.toml");
        for (v, unsafe_) in [
            ("file", false),
            ("ephemeral", false),
            ("auto", true),
            ("keyring", true),
        ] {
            std::fs::write(
                &user,
                format!("model = \"x\"\ncli_auth_credentials_store = \"{v}\"\n"),
            )
            .unwrap();
            let f = read_now();
            assert_eq!(f.config.is_some(), unsafe_, "{v}: {f:?}");
            assert!(f.managed.is_none(), "{v}");
        }
        // A file derm cannot parse fails safe.
        std::fs::write(&user, "cli_auth_credentials_store = \n").unwrap();
        assert!(read_now().config.unwrap().contains("not TOML"));
        std::fs::remove_file(&user).unwrap();
        // A project's `.codex/config.toml`, above the chat's folder.
        std::fs::create_dir_all(home.join("p").join(".codex")).unwrap();
        std::fs::write(
            home.join("p").join(".codex").join("config.toml"),
            "cli_auth_credentials_store = \"auto\"\n",
        )
        .unwrap();
        assert!(read_now().config.is_some());
        std::fs::remove_dir_all(home.join("p").join(".codex")).unwrap();
        // The requirements win over everything, and are read apart.
        std::fs::write(
            d.join("etc").join("requirements.toml"),
            "cli_auth_credentials_store = \"keyring\"\n",
        )
        .unwrap();
        let f = read_now();
        assert!(f.managed.is_some() && f.config.is_none(), "{f:?}");
        std::fs::remove_file(d.join("etc").join("requirements.toml")).unwrap();
        // Managed preferences derm does not parse fail safe.
        std::fs::create_dir_all(d.join("prefs").join("u")).unwrap();
        std::fs::write(
            d.join("prefs").join("u").join("com.openai.codex.plist"),
            "x",
        )
        .unwrap();
        assert!(read_now().managed.is_some());
        std::fs::remove_dir_all(d.join("prefs")).unwrap();
        // CODEX_HOME moves the config and the auth file.
        let elsewhere = d.join("ch");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(
            elsewhere.join("config.toml"),
            "cli_auth_credentials_store = \"auto\"\n",
        )
        .unwrap();
        let f = read(
            home.to_str().unwrap(),
            proj.to_str().unwrap(),
            Some(elsewhere.to_str().unwrap()),
            &r,
        );
        assert!(f.config.is_some(), "{f:?}");
        assert_eq!(
            f.auth_file.as_deref(),
            Some(elsewhere.join("auth.json").to_str().unwrap())
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// MW5-32: a managed file that keeps Codex in its own sandbox under srt,
    /// in each key Codex reads for it, and the ones that do not.
    #[test]
    fn mw5_32_a_managed_rule_on_codexs_sandbox_is_read() {
        let d = scratch("sandbox");
        let home = d.join("home");
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::create_dir_all(d.join("etc")).unwrap();
        let r = roots(&d);
        let read_now = || read(home.to_str().unwrap(), home.to_str().unwrap(), None, &r);
        assert!(read_now().managed_sandbox.is_none());
        let req = d.join("etc").join("requirements.toml");
        for (text, kept) in [
            (
                "allowed_sandbox_modes = [\"read-only\", \"workspace-write\"]\n",
                true,
            ),
            (
                "allowed_sandbox_modes = [\"read-only\", \"danger-full-access\"]\n",
                false,
            ),
            ("allowed_sandbox_modes = \"read-only\"\n", true),
            ("default_permissions = \":workspace\"\n", true),
            ("default_permissions = \":danger-full-access\"\n", false),
            (
                "[allowed_permission_profiles]\n\":workspace\" = true\n",
                true,
            ),
            ("model = \"x\"\n", false),
            ("allowed_sandbox_modes = \n", true),
        ] {
            std::fs::write(&req, text).unwrap();
            let f = read_now();
            assert_eq!(f.managed_sandbox.is_some(), kept, "{text}: {f:?}");
        }
        std::fs::remove_file(&req).unwrap();
        // The legacy managed config is a layer over `-c`.
        for file in [
            d.join("etc").join("managed_config.toml"),
            home.join(".codex").join("managed_config.toml"),
        ] {
            std::fs::write(&file, "sandbox_mode = \"read-only\"\n").unwrap();
            assert!(read_now().managed_sandbox.unwrap().contains("sandbox_mode"));
            std::fs::write(&file, "sandbox_mode = \"danger-full-access\"\n").unwrap();
            assert!(read_now().managed_sandbox.is_none());
            std::fs::remove_file(&file).unwrap();
        }
        // A user's own config does not count: `-c` beats it.
        std::fs::write(
            home.join(".codex").join("config.toml"),
            "sandbox_mode = \"read-only\"\n",
        )
        .unwrap();
        assert!(read_now().managed_sandbox.is_none());
        // Managed preferences derm does not parse fail safe.
        std::fs::create_dir_all(d.join("prefs")).unwrap();
        std::fs::write(d.join("prefs").join("com.openai.codex.plist"), "x").unwrap();
        assert!(read_now().managed_sandbox.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// FP8-S6: two requirements keys that also keep Codex sandboxed under
    /// srt, read in Codex 0.163.0: a managed `[permissions.filesystem]
    /// deny_read` refuses `danger-full-access`
    /// (`core/src/config/permission_profile_catalog.rs:129-145`, validator
    /// added at `core/src/config/mod.rs:4230-4245`), and a matching
    /// `[[remote_sandbox_config]]` replaces `allowed_sandbox_modes`
    /// (`config/src/config_requirements.rs:1495-1509`). Either falls back to
    /// read-only with a startup warning only (`mod.rs:2300-2330`).
    #[test]
    fn fp8_s6_more_managed_sandbox_keys_are_read() {
        let d = scratch("fp8s6");
        let home = d.join("home");
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::create_dir_all(d.join("etc")).unwrap();
        let r = roots(&d);
        let req = d.join("etc").join("requirements.toml");
        for text in [
            "[permissions.filesystem]\ndeny_read = [\"/home/u/.ssh\"]\n",
            "[[remote_sandbox_config]]\nhostname_patterns = [\"*\"]\nallowed_sandbox_modes = [\"read-only\"]\n",
        ] {
            std::fs::write(&req, text).unwrap();
            let f = read(home.to_str().unwrap(), home.to_str().unwrap(), None, &r);
            assert!(f.managed_sandbox.is_some(), "{text}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// FP8-S1: the profile layers in Codex's home are listed, not its
    /// `config.toml`, nor a file merely named `.config.toml`.
    #[test]
    fn fp8_s1_codexs_profiles_are_listed() {
        let d = scratch("fp8s1");
        let home = d.join("home");
        let ch = home.join(".codex");
        std::fs::create_dir_all(&ch).unwrap();
        for f in [
            "config.toml",
            "work.config.toml",
            ".config.toml",
            "notes.toml",
        ] {
            std::fs::write(ch.join(f), "").unwrap();
        }
        let r = roots(&d);
        let f = read(home.to_str().unwrap(), home.to_str().unwrap(), None, &r);
        assert_eq!(
            f.profiles,
            vec![ch.join("work.config.toml").to_string_lossy().into_owned()]
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
