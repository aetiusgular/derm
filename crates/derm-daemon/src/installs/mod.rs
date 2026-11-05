//! The daemon's side of package installs (wave 5, lane X; rules cases 130 to
//! 134; `plans/toolkit_universal_plan.md` lane X items 2 to 5):
//!
//! - [`check`]: the pre-install check, off until the user turns it on; then
//!   the package's registry and OSV, with names and versions only;
//! - [`lockdiff`]: the lockfile diff per install call (`install.lockdiff`);
//! - [`control`]: an install tree's writes to control paths
//!   (`install.control`), read from the join's candidate sets;
//! - [`scripts`]: each manager's install-script policy for `derm status`, and
//!   the strict preset's launch variables.
//!
//! Lane X owns this folder; the daemon outside it is integration's in wave 5,
//! so the wiring (a socket op for the check, the ingest calls for the diff
//! and the flags, `derm status`'s rows) is a request for integration
//! (`plans/parallel/tk_lane_X.md`). Each part is tested here on its own.

pub mod check;
pub mod control;
pub mod lockdiff;
pub mod scripts;

use std::path::Path;

use serde_json::{json, Value};

pub use check::{CheckSettings, Fetch, PreInstall, Query, UreqFetch, Verdict};

/// Packages one request may name (the check's own cap).
pub const MAX_REQUEST_PACKAGES: usize = check::MAX_QUERIES;

/// The body of the `install.check` request integration routes from the
/// socket (proposed in `tk_lane_X.md`, Requests): `{"packages": [{"ecosystem",
/// "name", "version"}], "cwd"?}`; the reply is `{"ran", "results", "verdict":
/// {"action": "deny" | "ask" | null, "reason"}}`. `results` items are
/// `wave5-records.schema.json`'s `installCall.check.results`. A request the
/// shape refuses is an error, never a pass.
pub fn check_request(
    pre: &PreInstall,
    request: &Value,
    settings: CheckSettings,
    home: Option<&Path>,
    now_ms: i64,
) -> Result<Value, String> {
    let list = request
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("no packages")?;
    if list.len() > MAX_REQUEST_PACKAGES {
        return Err(format!("more than {MAX_REQUEST_PACKAGES} packages"));
    }
    let mut queries = Vec::with_capacity(list.len());
    for p in list {
        let ecosystem = p
            .get("ecosystem")
            .and_then(Value::as_str)
            .ok_or("a package with no ecosystem")?;
        if !matches!(ecosystem, "npm" | "PyPI" | "crates.io" | "Go") {
            return Err("an ecosystem the check does not know".into());
        }
        let name = p
            .get("name")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty() && n.len() <= 214)
            .ok_or("a package with no name")?;
        let version = match p.get("version") {
            None | Some(Value::Null) => None,
            Some(Value::String(v)) if v.len() <= 128 => Some(v.clone()),
            _ => return Err("a version that is not a short string".into()),
        };
        queries.push(Query {
            ecosystem: ecosystem.into(),
            name: name.into(),
            version,
        });
    }
    let cwd = match request.get("cwd") {
        None | Some(Value::Null) => None,
        Some(Value::String(c)) if Path::new(c).is_absolute() => Some(Path::new(c.as_str())),
        _ => return Err("a cwd that is not an absolute path".into()),
    };
    let mut skip: Vec<&str> = Vec::new();
    if let Some(project) = cwd {
        for eco in ["npm", "PyPI", "crates.io"] {
            if queries.iter().any(|q| q.ecosystem == eco)
                && check::registry_override(eco, project, home)
            {
                skip.push(eco);
            }
        }
    }
    let (ran, findings, verdict) = pre.run(&queries, settings, &skip, now_ms);
    let (action, reason) = match verdict {
        Verdict::Deny(r) => (json!("deny"), json!(r)),
        Verdict::Ask(r) => (json!("ask"), json!(r)),
        Verdict::Nothing => (Value::Null, Value::Null),
    };
    Ok(json!({
        "ran": ran,
        "results": findings.iter().map(check::Finding::to_json).collect::<Vec<_>>(),
        "verdict": {"action": action, "reason": reason},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use check::Response;

    struct Npm404;
    impl Fetch for Npm404 {
        fn get(&self, _: &str) -> Result<Response, String> {
            Ok(Response {
                status: 404,
                body: b"{\"error\":\"Not found\"}".to_vec(),
            })
        }
        fn post_json(&self, _: &str, _: &[u8]) -> Result<Response, String> {
            Err("not called".into())
        }
    }

    #[test]
    fn the_request_shape_and_its_reply() {
        let pre = PreInstall::new(Box::new(Npm404));
        let on = CheckSettings {
            on: true,
            min_age_hours: 48,
        };
        let r = check_request(&pre, &json!({"packages": [{"ecosystem": "npm", "name": "derm-made-up-name-x7q2z9", "version": null}]}), on, None, 0).unwrap();
        assert_eq!(
            r,
            json!({"ran": true, "results": [{"name": "derm-made-up-name-x7q2z9", "version": null, "exists": false, "ageHours": null, "osv": []}], "verdict": {"action": "deny", "reason": "pre-install check: derm-made-up-name-x7q2z9: not in the registry"}})
        );
        let off = check_request(
            &pre,
            &json!({"packages": [{"ecosystem": "npm", "name": "x"}]}),
            CheckSettings::default(),
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            off,
            json!({"ran": false, "results": [], "verdict": {"action": null, "reason": null}})
        );
        for bad in [
            json!({}),
            json!({"packages": [{"ecosystem": "rubygems", "name": "x"}]}),
            json!({"packages": [{"ecosystem": "npm", "name": ""}]}),
            json!({"packages": [{"ecosystem": "npm", "name": "x", "version": 1}]}),
            json!({"packages": [{"ecosystem": "npm", "name": "x"}], "cwd": "relative"}),
            json!({"packages": vec![json!({"ecosystem": "npm", "name": "x"}); 65]}),
        ] {
            assert!(check_request(&pre, &bad, on, None, 0).is_err(), "{bad}");
        }
    }
}
