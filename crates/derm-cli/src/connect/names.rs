//! Server names that one underscore apart make one tool name (re-review
//! W2-R1's residue, integration w2; lane Q's card in
//! `plans/parallel_build_tk.md` section 7a).
//!
//! In the forms that put a single `_` between server and tool, the gate
//! cannot tell server `exa_evil` with tool `read` from server `exa` with tool
//! `evil_read` (`contracts/policy.md` section 4, step 3a, the open note). The
//! matcher's step 1 turns `-` and `.` into `_`, and OpenCode does the same to
//! the names it sends, so a server derm writes as `exa-evil` arrives as
//! `exa_evil_<tool>`, and a listed `exa` takes it with its `exa/*` allow.
//!
//! derm connect refuses to write a server whose name, after step 1, equals a
//! name already there or is one `_` longer or shorter than one (the
//! configured servers in the user file, and the policy's `servers`). Auggie
//! puts the server last (`<tool>_<server>`), so there it is the suffix that
//! collides. `derm connect <agent> --check-names` lists such pairs in the
//! user file, the current folder's project file and the policy.

use std::path::{Path, PathBuf};

use derm_core::policy::lower_name;

use super::json;
use super::presets::{Env, Format, Preset};

/// Where the single `_` sits, per agent id. Read from each row's
/// `toolNameForm` (presets/*.json at 824ae83): OpenCode and Kilo
/// `<server>_<tool>`, Gemini and Crush `mcp_<server>_<tool>`, Kiro's hooks
/// `mcp_s_t`, Mistral Vibe's model form `s_t`, oh-my-pi
/// `mcp__<server>_<tool>`; Auggie `t_s`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    ServerFirst,
    ServerLast,
}

pub fn form(agent: &str) -> Option<Form> {
    match agent {
        "opencode" | "kilo" | "gemini" | "crush" | "kiro" | "mistral-vibe" | "oh-my-pi" => {
            Some(Form::ServerFirst)
        }
        "auggie" => Some(Form::ServerLast),
        _ => None,
    }
}

/// Whether two names, after step 1, are one name or one `_` apart in the
/// agent's form.
pub fn collide(a: &str, b: &str, form: Form) -> bool {
    let (a, b) = (lower_name(a), lower_name(b));
    if a == b {
        return true;
    }
    let (short, long) = if a.len() < b.len() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    match form {
        Form::ServerFirst => long.starts_with(&format!("{short}_")),
        Form::ServerLast => long.ends_with(&format!("_{short}")),
    }
}

/// The server names in a config file's server container, in file order.
/// Unreadable or unparsable text gives none (the write path refuses such a
/// file on its own).
pub fn configured(preset: &Preset, text: &str) -> Vec<String> {
    let path: Vec<&str> = preset.entry_path.iter().map(String::as_str).collect();
    match preset.format {
        Format::Json | Format::Jsonc => json::parse(text, preset.format == Format::Jsonc)
            .ok()
            .and_then(|d| d.root.map(|n| n.to_value()))
            .and_then(|v| v.get_path(&path).cloned())
            .map(|v| match v {
                json::Value::Object(m) => m.into_iter().map(|(k, _)| k).collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default(),
        Format::Toml => {
            let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
                return Vec::new();
            };
            doc.get(&preset.entry_path[0])
                .and_then(toml_edit::Item::as_table_like)
                .map(|t| t.iter().map(|(k, _)| k.to_string()).collect())
                .unwrap_or_default()
        }
        Format::Yaml => Vec::new(),
    }
}

/// The policy file the gate reads: `DERM_POLICY` when it is an absolute
/// path, else `~/.derm/policy.json` (derm-core's `default_path`, through the
/// caller's environment so tests never read the real one).
pub fn policy_path(home: &Path, env: &dyn Env) -> PathBuf {
    match env.var("DERM_POLICY").filter(|p| p.starts_with('/')) {
        Some(p) => PathBuf::from(p),
        None => home.join(".derm/policy.json"),
    }
}

/// The policy's `servers`; none when the file is missing or invalid.
pub fn policy_servers(home: &Path, env: &dyn Env) -> Vec<String> {
    let (policy, _) = derm_core::policy::load(&policy_path(home, env));
    policy.servers
}

/// One name from a place, for the messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Named {
    pub name: String,
    pub place: String,
}

/// The first name in `existing` that `new` collides with, if any.
pub fn clash<'a>(new: &str, existing: &'a [Named], form: Form) -> Option<&'a Named> {
    existing
        .iter()
        .find(|e| e.name != new && collide(new, &e.name, form))
}

/// Every pair in `names` that collides, each once. Two entries of one name
/// from two places (the user file and the policy) are the same server and
/// not a pair.
pub fn pairs(names: &[Named], form: Form) -> Vec<(Named, Named)> {
    let mut out = Vec::new();
    for (i, a) in names.iter().enumerate() {
        for b in &names[i + 1..] {
            if a.name != b.name && collide(&a.name, &b.name, form) {
                out.push((a.clone(), b.clone()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_underscore_apart_in_either_direction() {
        let f = Form::ServerFirst;
        assert!(collide("exa", "exa-evil", f));
        assert!(collide("exa-evil", "exa", f));
        assert!(collide("exa", "exa_evil", f));
        assert!(collide("exa", "EXA", f));
        assert!(collide("exa", "exa.files", f));
        assert!(!collide("exa", "exasearch", f));
        assert!(!collide("exa", "search-exa", f));
        assert!(collide("exa", "search-exa", Form::ServerLast));
        assert!(!collide("exa", "exa-evil", Form::ServerLast));
    }

    #[test]
    fn pairs_skip_one_name_from_two_places() {
        let n = |name: &str, place: &str| Named {
            name: name.into(),
            place: place.into(),
        };
        let names = vec![
            n("exa", "user"),
            n("exa", "policy"),
            n("exa_evil", "project"),
            n("search", "user"),
        ];
        let p = pairs(&names, Form::ServerFirst);
        assert_eq!(p.len(), 2);
        assert!(p
            .iter()
            .all(|(a, b)| a.name == "exa" && b.name == "exa_evil"));
    }

    #[test]
    fn only_the_single_underscore_forms_are_listed() {
        for a in ["opencode", "kilo", "gemini", "crush", "oh-my-pi", "auggie"] {
            assert!(form(a).is_some(), "{a}");
        }
        for a in ["claude-code", "codex", "pi", "qwen-code", "goose", "grok"] {
            assert!(form(a).is_none(), "{a}");
        }
    }
}
