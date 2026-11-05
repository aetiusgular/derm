//! Package installs at the gate (wave 5, lane X; `plans/toolkit_universal_plan.md`
//! lane X, `contracts/policy.md` section 6, note AT). The wave 5 base cut this
//! seam: `policy::evaluate` calls [`check`] for a shell tool whose answer is
//! still `Allow` after every other step, and returns what it says. Lane X owns
//! this folder; `policy.rs` stays integration's.
//!
//! What it answers (rules cases 130 to 135): not an install, or an install
//! whose every package the project's lockfile already pins at the version
//! the command names, is `None` (the allow stands); any other install is
//! `Ask`, the reason naming each package and its version or "no version", and
//! what the check cannot name. The lockfile is read only with a [`Context`]
//! that gives the call's folder and raw text; the seam passes none yet, so
//! every install asks (a request for integration: `tk_lane_X.md`).
//!
//! A port of the hook core's `packages/derm-claude-plugin/src/core/installs/`
//! (canonical), held equal to it and to derm-pi's copy by
//! `contracts/fixtures/installs/`.

pub mod lockfile;
pub mod parse;

use std::path::Path;

pub use lockfile::{find_lockfile, parse_lockfile, LockEntry, LockKind};
pub use parse::{parse_installs, Form, Install, Manager, Package, Unseen};

use crate::policy::Action;

/// The install check's answer for one shell call that is an install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallDecision {
    /// `Ask` for a new package or version, `Deny` for a name the registry
    /// does not hold or a known-malicious one (with the pre-install check on).
    pub action: Action,
    /// Shown on the card; names each package and version, never the input.
    pub reason: String,
}

/// What a caller knows about the call beyond its folded text (the hook
/// core's `InstallContext`).
#[derive(Default)]
pub struct Context<'a> {
    /// The shell text as the agent sent it. A lockfile vouches for a name
    /// only when this, lowercased, equals the folded text.
    pub raw: Option<&'a str>,
    /// The absolute folder the command runs in.
    pub cwd: Option<&'a Path>,
    /// Reads a manager's lockfile entries; defaults to the nearest lockfile
    /// at or above `cwd`.
    #[allow(clippy::type_complexity)]
    pub lockfile: Option<&'a dyn Fn(Manager) -> Option<Vec<LockEntry>>>,
}

const MAX_LISTED: usize = 8;
const MAX_REASON: usize = 600;

fn unseen_text(u: Unseen) -> &'static str {
    match u {
        Unseen::Path => "a local path",
        Unseen::Url => "a URL",
        Unseen::Git => "a git source",
        Unseen::Requirements => "the packages a requirements file names",
        Unseen::Update => "updated versions the command does not name",
        Unseen::Stdin => "names read from another command's output",
        Unseen::Spec => "a package spec the check cannot read",
        Unseen::Registry => "a registry other than the default",
    }
}

/// What the install check says about a shell call, or `None` when the call
/// is not an install (the seam's signature; no lockfile is read).
pub fn check(normalized_tool: &str, folded: &str) -> Option<InstallDecision> {
    check_with(normalized_tool, folded, None)
}

/// [`check`] with what the caller knows of the call's folder and raw text.
pub fn check_with(
    normalized_tool: &str,
    folded: &str,
    context: Option<&Context>,
) -> Option<InstallDecision> {
    let _ = normalized_tool;
    let installs = parse_installs(folded);
    if installs.is_empty() {
        return None;
    }
    if let Some(ctx) = context {
        if all_pinned(&installs, folded, ctx) {
            return None;
        }
    }
    Some(InstallDecision {
        action: Action::Ask,
        reason: install_reason(&installs),
    })
}

/// The card's text (the hook core's `installReason`).
pub fn install_reason(installs: &[Install]) -> String {
    let parts: Vec<String> = installs
        .iter()
        .map(|inst| {
            let verb = match (inst.form, inst.global) {
                (Form::Run, _) => "runs",
                (Form::Add, true) => "installs for the user",
                (Form::Add, false) => "adds",
            };
            let mut what: Vec<String> = inst
                .packages
                .iter()
                .take(MAX_LISTED)
                .map(|p| {
                    format!(
                        "{} {}",
                        p.name,
                        p.version.as_deref().unwrap_or("(no version)")
                    )
                })
                .collect();
            if inst.packages.len() > MAX_LISTED {
                what.push(format!("and {} more", inst.packages.len() - MAX_LISTED));
            }
            what.extend(inst.unseen.iter().map(|u| unseen_text(*u).to_string()));
            let listed = if what.is_empty() {
                "packages the command does not name".to_string()
            } else {
                what.join(", ")
            };
            format!("{} {} {}", inst.manager.as_str(), verb, listed)
        })
        .collect();
    let reason = format!("package install: {}", parts.join("; "));
    if reason.chars().count() > MAX_REASON {
        let cut: String = reason.chars().take(MAX_REASON - 3).collect();
        format!("{cut}...")
    } else {
        reason
    }
}

/// An exact version: no range operator, tag word or wildcard (the hook
/// core's `EXACT`, `^v?[0-9]+(\.[0-9a-z-]+)*(\+[0-9a-z.-]+)?$`).
fn exact(v: &str) -> bool {
    let v = v.strip_prefix('v').unwrap_or(v);
    let (main, build) = match v.split_once('+') {
        Some((m, b)) => (m, Some(b)),
        None => (v, None),
    };
    let mut parts = main.split('.');
    let first = parts.next().unwrap_or("");
    !first.is_empty()
        && first.chars().all(|c| c.is_ascii_digit())
        && parts.all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
        && build.is_none_or(|b| {
            !b.is_empty()
                && b.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        })
}

/// PEP 503's name normalization; npm, crates and Go names compare as written.
fn same_name(manager: Manager, a: &str, b: &str) -> bool {
    if manager.ecosystem() == "PyPI" {
        parse::collapse_separators(&a.to_lowercase())
            == parse::collapse_separators(&b.to_lowercase())
    } else {
        a == b
    }
}

fn pinned(manager: Manager, pkg: &Package, entries: &[LockEntry], any_version: bool) -> bool {
    if pkg.version.as_deref().is_some_and(|v| !exact(v)) {
        return false;
    }
    entries.iter().any(|e| {
        e.registry
            && same_name(manager, &e.name, &pkg.name)
            && match &pkg.version {
                None => any_version,
                Some(v) => &e.version == v,
            }
    })
}

/// True when the lockfile already pins every package of every install (the
/// hook core's `allPinned`; npx and bunx run the project's own copy, the
/// other run forms fetch every time).
fn all_pinned(installs: &[Install], folded: &str, ctx: &Context) -> bool {
    match ctx.raw {
        Some(raw) if raw.to_lowercase() == folded => {}
        _ => return false,
    }
    let mut cache: Vec<(Manager, Option<Vec<LockEntry>>)> = Vec::new();
    for inst in installs {
        if inst.global || !inst.unseen.is_empty() || inst.packages.is_empty() {
            return false;
        }
        let runs_local =
            inst.form == Form::Run && matches!(inst.manager, Manager::Npm | Manager::Bun);
        if inst.form == Form::Run && !runs_local {
            return false;
        }
        if !cache.iter().any(|(m, _)| *m == inst.manager) {
            let entries = match ctx.lockfile {
                Some(read) => read(inst.manager),
                None => ctx
                    .cwd
                    .and_then(|cwd| find_lockfile(inst.manager, cwd))
                    .map(|f| f.entries),
            };
            cache.push((inst.manager, entries));
        }
        let Some((_, Some(entries))) = cache.iter().find(|(m, _)| *m == inst.manager) else {
            return false;
        };
        if !inst
            .packages
            .iter()
            .all(|p| pinned(inst.manager, p, entries, runs_local))
        {
            return false;
        }
    }
    true
}

/// The `install.call` record's detail (`contracts/events.md` section 5;
/// `wave5-records.schema.json` `installCall`), one per install.
pub fn install_call_details(
    installs: &[Install],
    decision: Action,
    tool_use_id: Option<&str>,
    lockfile: Option<&dyn Fn(Manager) -> Option<Vec<LockEntry>>>,
) -> Vec<serde_json::Value> {
    let action = match decision {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    };
    installs
        .iter()
        .map(|inst| {
            let entries = lockfile.and_then(|read| read(inst.manager));
            let packages: Vec<serde_json::Value> = inst
                .packages
                .iter()
                .take(256)
                .map(|p| {
                    let in_lock = entries.as_ref().map(|es| {
                        es.iter().any(|e| same_name(inst.manager, &e.name, &p.name) && p.version.as_ref().is_none_or(|v| &e.version == v))
                    });
                    serde_json::json!({
                        "name": p.name.chars().take(214).collect::<String>(),
                        "version": p.version.as_ref().map(|v| v.chars().take(128).collect::<String>()),
                        "ecosystem": inst.manager.ecosystem(),
                        "inLockfile": in_lock,
                    })
                })
                .collect();
            serde_json::json!({
                "trust": "client",
                "toolUseId": tool_use_id.map(|t| t.chars().take(128).collect::<String>()),
                "manager": inst.manager.as_str(),
                "form": match inst.form { Form::Add => "add", Form::Run => "run" },
                "packages": packages,
                "decision": action,
                "check": null,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_install_asks_and_names_its_packages() {
        let d = check("bash", "npm install left-pad").unwrap();
        assert_eq!(d.action, Action::Ask);
        assert_eq!(d.reason, "package install: npm adds left-pad (no version)");
        for text in ["ls -la", "npm test", "npm ci", "echo npm install x"] {
            assert_eq!(check("bash", text), None, "{text}");
        }
    }

    #[test]
    fn a_pinned_package_keeps_the_allow_only_with_matching_raw_text() {
        let read = |m: Manager| {
            (m == Manager::Npm).then(|| {
                vec![LockEntry {
                    name: "left-pad".into(),
                    version: "1.3.0".into(),
                    registry: true,
                }]
            })
        };
        let ctx = Context {
            raw: Some("npm i left-pad@1.3.0"),
            cwd: None,
            lockfile: Some(&read),
        };
        assert_eq!(check_with("bash", "npm i left-pad@1.3.0", Some(&ctx)), None);
        let cyrillic = Context {
            raw: Some("npm i l\u{435}ft-pad@1.3.0"),
            cwd: None,
            lockfile: Some(&read),
        };
        assert_eq!(
            check_with("bash", "npm i left-pad@1.3.0", Some(&cyrillic))
                .unwrap()
                .action,
            Action::Ask
        );
        assert_eq!(
            check_with("bash", "npm i left-pad@1.3.0", None)
                .unwrap()
                .action,
            Action::Ask
        );
    }

    #[test]
    fn exact_matches_the_hook_cores_pattern() {
        for v in [
            "1.3.0",
            "v0.20.0",
            "2.0.0rc1",
            "1.0.0-beta.1",
            "1.0.0+build.5",
            "18",
        ] {
            assert!(exact(v), "{v}");
        }
        for v in ["^1.3.0", ">=2", "latest", "*", "", "v", "1..2", "1.0+"] {
            assert!(!exact(v), "{v}");
        }
    }
}
