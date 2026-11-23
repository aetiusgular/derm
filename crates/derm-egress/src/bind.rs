//! Which project's chats a secret is for (plan step P10's I-4, "egress
//! swapping only the chat's project's secrets"; Tony's call 16, the project
//! as the trust unit; `research-notes/CC_project_scoped_agents.md` R1).
//!
//! `~/.derm/secret-projects.json`, beside `secrets.json` and under the same
//! rules: written only by `derm secret` from a terminal, owner-only, read
//! back only when no one else can read or write it. A file of its own rather
//! than a field on each `secrets.json` entry, so the secrets schema and every
//! reader of it stay as they are (a field there is a request for P
//! integration, `plans/parallel/acctP_PB.md`).
//!
//! ```json
//! {"version": 1, "projects": {"github": ["6853732bf2a99f2b"]}}
//! ```
//!
//! The rule ([`for_project`]): a chat of a project gets the secrets bound to
//! that project and no others; a chat in no project (one that runs as the
//! person, `project: ""`, `contracts/projects.md` 1.4) gets the secrets bound
//! to no project and no others. So a secret is for one set of chats only, and
//! an agent account's chat, which always has a project, gets nothing the
//! person did not bind to its project.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::secrets::{self, File};

pub const VERSION: u64 = 1;
const MAX_SECRETS: usize = 64;
const MAX_PROJECTS: usize = 32;

/// The whole file: secret id to the project ids its chats are.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    pub version: u64,
    pub projects: BTreeMap<String, Vec<String>>,
}

impl Default for Bindings {
    fn default() -> Self {
        Bindings {
            version: VERSION,
            projects: BTreeMap::new(),
        }
    }
}

/// `<home>/.derm/secret-projects.json`.
pub fn path_for(home: &Path) -> PathBuf {
    home.join(".derm").join("secret-projects.json")
}

impl Bindings {
    /// What serde does not check: the version, ids, project ids (16
    /// lowercase hex, `derm_core::project::valid_id`), no repeats, no empty
    /// list, the caps.
    pub fn check(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err(format!("version {} is not {VERSION}", self.version));
        }
        if self.projects.len() > MAX_SECRETS {
            return Err(format!("more than {MAX_SECRETS} secrets"));
        }
        for (id, list) in &self.projects {
            if !secrets::id_ok(id) {
                return Err(format!("id {id:?} is not ^[a-z][a-z0-9-]{{0,31}}$"));
            }
            if list.is_empty() || list.len() > MAX_PROJECTS {
                return Err(format!("{id}: 1 to {MAX_PROJECTS} projects"));
            }
            let mut seen: Vec<&str> = Vec::new();
            for p in list {
                if !derm_core::project::valid_id(p) {
                    return Err(format!(
                        "{id}: {p:?} is not a project id (16 lowercase hex)"
                    ));
                }
                if seen.contains(&p.as_str()) {
                    return Err(format!("{id}: project {p} twice"));
                }
                seen.push(p);
            }
        }
        Ok(())
    }

    /// The projects `id` is bound to; empty when it is bound to none.
    pub fn of(&self, id: &str) -> &[String] {
        self.projects.get(id).map_or(&[], Vec::as_slice)
    }

    /// Binds `id` to `project` too. `Err` when the id or project is not well
    /// formed, or the caps are passed.
    pub fn bind(&mut self, id: &str, project: &str) -> Result<(), String> {
        let list = self.projects.entry(id.to_string()).or_default();
        if !list.iter().any(|p| p == project) {
            list.push(project.to_string());
        }
        self.check()
    }

    /// Forgets every binding of `id` (`derm secret remove`).
    pub fn forget(&mut self, id: &str) {
        self.projects.remove(id);
    }
}

pub fn parse(text: &str) -> Result<Bindings, String> {
    let b: Bindings =
        serde_json::from_str(text).map_err(|e| format!("secret-projects.json: {e}"))?;
    b.check()
        .map_err(|e| format!("secret-projects.json: {e}"))?;
    Ok(b)
}

/// Read and check the file: missing is no binding; one others can read or
/// write, a link or a FIFO is refused (`secrets.json`'s checks).
pub fn load(path: &Path) -> Result<Bindings, String> {
    match secrets::read_private(path, 256 * 1024) {
        Ok(Some(text)) => parse(&text),
        Ok(None) => Ok(Bindings::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Write the file whole, privately, as `secrets::save` does.
pub fn save(path: &Path, b: &Bindings) -> Result<(), String> {
    b.check()?;
    let dir = path.parent().ok_or("no folder")?;
    let mut s = serde_json::to_string_pretty(b).map_err(|e| e.to_string())?;
    s.push('\n');
    secrets::write_private(dir, path, s.as_bytes())
}

/// The secrets a chat of `project` gets (`""` for a chat in no project),
/// and the ids left out, in the file's order. The returned file's entries
/// are the input's own, so a reader that pairs entries with values pairs
/// them with this file.
pub fn for_project(f: &File, b: &Bindings, project: &str) -> (File, Vec<String>) {
    let mut kept = File {
        version: f.version,
        secrets: Vec::new(),
    };
    let mut left = Vec::new();
    for e in &f.secrets {
        let bound = b.of(&e.id);
        let mine = if project.is_empty() {
            bound.is_empty()
        } else {
            bound.iter().any(|p| p == project)
        };
        if mine {
            kept.secrets.push(e.clone());
        } else {
            left.push(e.id.clone());
        }
    }
    (kept, left)
}

/// Why a secret was left out of a chat, for its start line.
pub fn why_left_out(b: &Bindings, id: &str, project: &str) -> String {
    let bound = b.of(id);
    match (bound.is_empty(), project.is_empty()) {
        (true, false) => format!(
            "{id} is bound to no project, so no project's chat gets it (bind it: derm secret bind {id} --project {project})"
        ),
        (false, true) => format!("{id} is bound to project {}, and this chat is in none", bound.join(", ")),
        _ => format!("{id} is bound to project {}, not {project}", bound.join(", ")),
    }
}

#[cfg(test)]
mod tests {

    /// Request PB-3: the contract's fixture is a file this reader takes.
    #[test]
    fn the_contracts_fixture_parses() {
        let b = parse(include_str!(
            "../../../contracts/fixtures/project/secret-projects.json"
        ))
        .unwrap();
        assert_eq!(b.of("linear").len(), 2);
    }

    use super::*;
    use crate::secrets::{Entry, From};

    const A: &str = "6853732bf2a99f2b";
    const B: &str = "0123456789abcdef";

    fn file(ids: &[&str]) -> File {
        File {
            version: 1,
            secrets: ids
                .iter()
                .map(|id| Entry {
                    id: id.to_string(),
                    hosts: vec!["api.github.com".into()],
                    from: From::Env("X_TOKEN".into()),
                    placement: None,
                    note: None,
                })
                .collect(),
        }
    }

    /// I-4: a project's chat gets only what is bound to its project; a chat
    /// in no project only what is bound to none.
    #[test]
    fn a_chat_gets_only_the_secrets_bound_to_its_own_project() {
        let f = file(&["gh", "npm", "loose"]);
        let mut b = Bindings::default();
        b.bind("gh", A).unwrap();
        b.bind("npm", A).unwrap();
        b.bind("npm", B).unwrap();
        let ids = |f: &File| f.secrets.iter().map(|e| e.id.clone()).collect::<Vec<_>>();
        let (a, left) = for_project(&f, &b, A);
        assert_eq!(ids(&a), ["gh", "npm"]);
        assert_eq!(left, ["loose"]);
        let (bb, left) = for_project(&f, &b, B);
        assert_eq!(ids(&bb), ["npm"]);
        assert_eq!(left, ["gh", "loose"]);
        let (none, left) = for_project(&f, &b, "");
        assert_eq!(ids(&none), ["loose"]);
        assert_eq!(left, ["gh", "npm"]);
        let (other, left) = for_project(&f, &b, "ffffffffffffffff");
        assert!(other.secrets.is_empty());
        assert_eq!(left.len(), 3);
        assert!(why_left_out(&b, "loose", A).contains("derm secret bind loose --project"));
        assert!(why_left_out(&b, "gh", B).contains(A));
        assert!(why_left_out(&b, "gh", "").contains("in none"));
    }

    #[test]
    fn the_file_is_parsed_whole() {
        let ok = format!(r#"{{"version":1,"projects":{{"gh":["{A}"]}}}}"#);
        assert_eq!(parse(&ok).unwrap().of("gh"), [A]);
        for bad in [
            r#"{"version":2,"projects":{}}"#.to_string(),
            r#"{"version":1,"projects":{},"x":1}"#.to_string(),
            format!(r#"{{"version":1,"projects":{{"Gh":["{A}"]}}}}"#),
            r#"{"version":1,"projects":{"gh":[]}}"#.to_string(),
            format!(r#"{{"version":1,"projects":{{"gh":["{A}","{A}"]}}}}"#),
            r#"{"version":1,"projects":{"gh":["0123456789ABCDEF"]}}"#.to_string(),
            r#"{"version":1,"projects":{"gh":["../../x"]}}"#.to_string(),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
        let mut b = Bindings::default();
        assert!(b.bind("gh", "not-an-id").is_err());
        b.projects.clear();
        b.bind("gh", A).unwrap();
        b.forget("gh");
        assert!(b.of("gh").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private_and_round_trips() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("derm-bind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = path_for(&d);
        assert_eq!(load(&p).unwrap(), Bindings::default());
        let mut b = Bindings::default();
        b.bind("gh", A).unwrap();
        save(&p, &b).unwrap();
        assert_eq!(load(&p).unwrap(), b);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&p).is_err(), "readable by others is refused");
        let _ = std::fs::remove_dir_all(&d);
    }
}
