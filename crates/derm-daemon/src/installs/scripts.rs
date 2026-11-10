//! Each manager's install-script policy for a project (wave 5 lane X;
//! universal plan lane X item 3), for `derm status`, and the launch variables
//! the strict preset sets. Install scripts are a dependency's code running at
//! install; whether they run depends on the manager's version and settings:
//!
//! - npm 12 runs no dependency's `preinstall`, `install` or `postinstall`
//!   unless `allowScripts` in `package.json` names it ("Dependency install
//!   scripts are blocked by default", npm 12.2.2's `npm-install-scripts.md`);
//!   below 12 it runs them.
//! - pnpm 10 runs none by default (`onlyBuiltDependencies`, note AT); below
//!   10.26.0 a git dependency bypassed that (CVE-2025-69264).
//! - yarn 4.18.1's `enableScripts` defaults to off (its bundle:
//!   `enableScripts:{description:"If true, packages are allowed to have
//!   install scripts by default",type:"BOOLEAN",default:!1}`); yarn 1 runs
//!   them. Older yarn 4 releases were not read.
//! - bun runs only its list (`trustedDependencies`, note AT).
//! - pip, uv, poetry and pdm build a source package, which runs its build
//!   code, unless told to use wheels only.
//! - cargo runs a crate's `build.rs` when it builds (I: `cargo install`
//!   builds; `cargo add` does not).
//! - go runs no package code at `go get` or `go install` (I).

use std::path::Path;

use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptPolicy {
    pub manager: &'static str,
    /// From `packageManager` in `package.json`, when it names one.
    pub version: Option<String>,
    /// `run`, `allowlist` (only listed packages), `off` or `unknown`.
    pub scripts: &'static str,
    pub why: String,
}

impl ScriptPolicy {
    pub fn to_json(&self) -> Value {
        json!({"manager": self.manager, "version": self.version, "scripts": self.scripts, "why": self.why})
    }
}

fn read_small(p: &Path) -> Option<String> {
    let m = std::fs::symlink_metadata(p).ok()?;
    if !m.is_file() || m.len() > 1 << 20 {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

/// `(major, minor, patch)` of a version string's numbers.
fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|x| x.parse::<u64>().ok());
    Some((
        it.next()??,
        it.next().flatten().unwrap_or(0),
        it.next().flatten().unwrap_or(0),
    ))
}

/// The policy of every manager the project shows signs of (its lockfile or
/// its config), read from the project folder only. Nothing is run.
pub fn script_policy(project: &Path) -> Vec<ScriptPolicy> {
    let pkg: Option<Value> =
        read_small(&project.join("package.json")).and_then(|t| serde_json::from_str(&t).ok());
    let package_manager = pkg
        .as_ref()
        .and_then(|p| p.get("packageManager"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let pm_version = |name: &str| -> Option<String> {
        let pm = package_manager.as_deref()?;
        let (n, v) = pm.split_once('@')?;
        (n == name).then(|| v.split('+').next().unwrap_or(v).to_string())
    };
    let exists = |f: &str| std::fs::symlink_metadata(project.join(f)).is_ok();
    let list_len = |v: Option<&Value>| {
        v.map_or(0, |x| {
            x.as_array()
                .map_or(x.as_object().map_or(0, |o| o.len()), |a| a.len())
        })
    };
    let mut out = Vec::new();

    if exists("package-lock.json") || exists("npm-shrinkwrap.json") || pm_version("npm").is_some() {
        let version = pm_version("npm");
        let allow = list_len(pkg.as_ref().and_then(|p| p.get("allowScripts")));
        let (scripts, why) = match version.as_deref().and_then(semver) {
            Some((m, _, _)) if m >= 12 => ("allowlist", format!("npm 12 runs only the {allow} packages allowScripts names")),
            Some(_) => ("run", "npm below 12 runs every dependency's install scripts".to_string()),
            None => ("unknown", format!("npm 12 runs only the packages allowScripts names ({allow} named); below 12 it runs them all")),
        };
        out.push(ScriptPolicy {
            manager: "npm",
            version,
            scripts,
            why,
        });
    }
    if exists("pnpm-lock.yaml") || pm_version("pnpm").is_some() {
        let version = pm_version("pnpm");
        let built = list_len(
            pkg.as_ref()
                .and_then(|p| p.get("pnpm"))
                .and_then(|p| p.get("onlyBuiltDependencies")),
        );
        let (scripts, why) = match version.as_deref().and_then(semver) {
            Some((m, mi, _)) if m > 10 || (m == 10 && mi >= 26) => ("allowlist", format!("pnpm 10 and later run only the packages listed to build ({built} in package.json)")),
            Some((10, _, _)) => ("allowlist", "pnpm 10 blocks install scripts, but a git dependency bypasses that below 10.26.0 (CVE-2025-69264)".to_string()),
            Some(_) => ("run", "pnpm below 10 runs every dependency's install scripts".to_string()),
            None => ("unknown", "pnpm 10 and later block install scripts by default; below 10 they run".to_string()),
        };
        out.push(ScriptPolicy {
            manager: "pnpm",
            version,
            scripts,
            why,
        });
    }
    if exists("yarn.lock") || pm_version("yarn").is_some() {
        let version = pm_version("yarn");
        let rc = read_small(&project.join(".yarnrc.yml"));
        let setting = rc.as_deref().and_then(|t| {
            t.lines().find_map(|l| {
                let l = l.trim();
                let v = l.strip_prefix("enableScripts:")?.trim();
                Some(v == "true")
            })
        });
        let berry = rc.is_some()
            || version
                .as_deref()
                .and_then(semver)
                .is_some_and(|(m, _, _)| m >= 2);
        let (scripts, why) = match (berry, setting) {
            (_, Some(true)) => ("run", ".yarnrc.yml sets enableScripts: true".to_string()),
            (_, Some(false)) => ("off", ".yarnrc.yml sets enableScripts: false".to_string()),
            (true, None) => ("unknown", "yarn 4.18.1 runs none by default (enableScripts off); older yarn 2 to 4 releases were not read".to_string()),
            (false, None) => ("run", "yarn 1 runs every dependency's install scripts".to_string()),
        };
        out.push(ScriptPolicy {
            manager: "yarn",
            version,
            scripts,
            why,
        });
    }
    if exists("bun.lock") || exists("bun.lockb") || pm_version("bun").is_some() {
        let trusted = list_len(pkg.as_ref().and_then(|p| p.get("trustedDependencies")));
        let why = if trusted > 0 {
            format!("bun runs only the {trusted} packages trustedDependencies names")
        } else {
            "bun runs only its built-in list of trusted packages".to_string()
        };
        out.push(ScriptPolicy {
            manager: "bun",
            version: pm_version("bun"),
            scripts: "allowlist",
            why,
        });
    }
    for (manager, files) in [
        ("uv", &["uv.lock"][..]),
        ("poetry", &["poetry.lock"][..]),
        ("pdm", &["pdm.lock"][..]),
        ("pip", &["requirements.txt", "pylock.toml"][..]),
    ] {
        if files.iter().any(|f| exists(f)) {
            out.push(ScriptPolicy {
                manager,
                version: None,
                scripts: "run",
                why: "a source package is built at install, which runs its build code, unless wheels only is set".into(),
            });
        }
    }
    if exists("Cargo.lock") || exists("Cargo.toml") {
        out.push(ScriptPolicy {
            manager: "cargo",
            version: None,
            scripts: "run",
            why: "a crate's build.rs runs when it is built".into(),
        });
    }
    out
}

/// The launch variables the strict preset adds (never written into a config
/// file): npm reads `npm_config_*` as its settings ("Any environment
/// variables that start with `npm_config_` will be interpreted as a
/// configuration parameter", npm 12.2.2's `config.md`; `ignore-scripts`);
/// pip reads `PIP_<OPTION>` (pip 26.3's `configuration.py`,
/// `get_environ_vars`); uv reads `UV_NO_BUILD` (uv 0.13.7's help:
/// "Don't build source distributions [env: UV_NO_BUILD=]"). Not verified
/// for pnpm 12 and bun (lane X's Research).
pub fn strict_env() -> &'static [(&'static str, &'static str)] {
    &[
        ("npm_config_ignore_scripts", "true"),
        ("PIP_ONLY_BINARY", ":all:"),
        ("UV_NO_BUILD", "1"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(files: &[(&str, &str)]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "derm-x-scripts-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for (f, t) in files {
            std::fs::write(d.join(f), t).unwrap();
        }
        d
    }

    #[test]
    fn npm_by_version_and_allow_list() {
        let d = project(&[
            (
                "package.json",
                r#"{"packageManager":"npm@12.2.2","allowScripts":{"esbuild":true,"sharp":true}}"#,
            ),
            ("package-lock.json", "{}"),
        ]);
        let p = script_policy(&d);
        assert_eq!(
            p[0],
            ScriptPolicy {
                manager: "npm",
                version: Some("12.2.2".into()),
                scripts: "allowlist",
                why: "npm 12 runs only the 2 packages allowScripts names".into()
            }
        );
        let d = project(&[("package.json", r#"{"packageManager":"npm@10.9.9"}"#)]);
        assert_eq!(script_policy(&d)[0].scripts, "run");
        let d = project(&[("package-lock.json", "{}")]);
        assert_eq!(script_policy(&d)[0].scripts, "unknown");
    }

    #[test]
    fn pnpm_yarn_bun_and_the_rest() {
        assert_eq!(script_policy(&project(&[("package.json", r#"{"packageManager":"pnpm@10.12.1"}"#)]))[0].why, "pnpm 10 blocks install scripts, but a git dependency bypasses that below 10.26.0 (CVE-2025-69264)");
        assert_eq!(
            script_policy(&project(&[(
                "package.json",
                r#"{"packageManager":"pnpm@12.16.1"}"#
            )]))[0]
                .scripts,
            "allowlist"
        );
        assert_eq!(
            script_policy(&project(&[(
                "package.json",
                r#"{"packageManager":"pnpm@9.0.0"}"#
            )]))[0]
                .scripts,
            "run"
        );
        assert_eq!(
            script_policy(&project(&[
                ("yarn.lock", ""),
                ("package.json", r#"{"packageManager":"yarn@1.22.22"}"#)
            ]))[0]
                .scripts,
            "run"
        );
        assert_eq!(
            script_policy(&project(&[
                ("yarn.lock", ""),
                (".yarnrc.yml", "enableScripts: false\n")
            ]))[0]
                .scripts,
            "off"
        );
        assert_eq!(
            script_policy(&project(&[
                ("yarn.lock", ""),
                (".yarnrc.yml", "nodeLinker: pnp\n")
            ]))[0]
                .scripts,
            "unknown"
        );
        assert_eq!(
            script_policy(&project(&[
                ("bun.lock", ""),
                ("package.json", r#"{"trustedDependencies":["esbuild"]}"#)
            ]))[0]
                .why,
            "bun runs only the 1 packages trustedDependencies names"
        );
        let p = script_policy(&project(&[("uv.lock", ""), ("Cargo.toml", "")]));
        assert_eq!(
            p.iter().map(|x| x.manager).collect::<Vec<_>>(),
            vec!["uv", "cargo"]
        );
        assert!(script_policy(&project(&[("README.md", "")])).is_empty());
        assert_eq!(p[0].to_json()["scripts"], "run");
    }

    #[test]
    fn the_strict_variables() {
        assert_eq!(
            strict_env(),
            &[
                ("npm_config_ignore_scripts", "true"),
                ("PIP_ONLY_BINARY", ":all:"),
                ("UV_NO_BUILD", "1")
            ]
        );
        assert_eq!(semver("10.26.0"), Some((10, 26, 0)));
        assert_eq!(semver("12.2.2+sha512.abc"), Some((12, 2, 2)));
        assert_eq!(semver("x"), None);
    }
}
