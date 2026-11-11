//! srt's settings for a chat on Windows, from the Unix plan's network part
//! and Windows paths (srt 0.0.82, `src/sandbox/sandbox-config.ts` and the
//! README's "Windows (alpha)" section).
//!
//! On Windows srt enforces the filesystem lists with access entries for its
//! sandbox account (README, "Security model"): `allowWrite` an inheriting
//! modify entry and a write-restricted token that admits only those roots;
//! `allowRead` an inheriting read and execute entry; `denyRead` and
//! `denyWrite` an inheriting deny entry, and a deny of deleting children on
//! the parent. A deny beneath an `allowWrite` root leaves read and execute.

use serde_json::{json, Value};

use super::join;
use crate::run::harness::{Harness, HARNESSES};

pub(super) struct Inputs<'a> {
    /// The settings `plan::build` wrote for Unix: their `network` part is
    /// read (derm's loopback ports, the model host, the hosts asked for).
    pub unix: &'a Value,
    pub harness: &'static Harness,
    pub cwd: &'a str,
    pub home: &'a str,
    pub state_dir: &'a str,
    pub harness_dir: &'a str,
    pub derm_exe: &'a str,
    pub sandbox_user: Option<&'a str>,
    /// Hosts to leave out of `allowedDomains` (the sign-in host).
    pub drop_hosts: &'a [&'a str],
    pub exists: &'a dyn Fn(&str) -> bool,
}

/// A path relative to the user's profile, written with `/` as the harness
/// table writes it, under a root.
fn under(root: &str, rel: &str) -> String {
    join(root, &rel.replace('/', "\\"))
}

pub(super) fn build(i: &Inputs) -> Value {
    let allowed: Vec<Value> = i.unix["network"]["allowedDomains"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|d| d.as_str().is_some_and(|d| !i.drop_hosts.contains(&d)))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let h = i.harness;

    // Writes: the harness's control files in the chat's folder (as on Unix,
    // `plan.rs`: Codex's whole project `.codex` unless the folder is the
    // profile), the repository's hooks and config, the control files of the
    // harness's state copy (its settings name derm's gate), and derm itself.
    let mut deny_write: Vec<String> = Vec::new();
    let cwd_is_home = i.cwd.eq_ignore_ascii_case(i.home);
    if h.id == "codex" && !cwd_is_home {
        deny_write.push(join(i.cwd, ".codex"));
    } else {
        deny_write.extend(h.control.iter().map(|c| under(i.cwd, c)));
    }
    deny_write.push(join(i.cwd, ".git\\hooks"));
    deny_write.push(join(i.cwd, ".git\\config"));
    if let Some(state) = h.state.first() {
        let prefix = format!("{state}/");
        deny_write.extend(
            h.control
                .iter()
                .filter_map(|c| c.strip_prefix(&prefix))
                .map(|rest| under(i.harness_dir, rest)),
        );
    }
    deny_write.push(i.derm_exe.to_string());

    // Reads: derm's own folder (case 143) and every harness's own state in
    // the user's profile: the chat works from its copy.
    let mut deny_read = vec![join(i.home, ".derm")];
    for other in HARNESSES {
        deny_read.extend(other.state.iter().map(|s| under(i.home, s)));
    }

    for list in [&mut deny_write, &mut deny_read] {
        list.retain(|p| (i.exists)(p));
        list.sort_by_key(|p| p.to_ascii_lowercase());
        list.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    }
    let literal = |v: Vec<String>| -> Vec<Value> {
        v.into_iter()
            .map(|p| json!({"path": p, "literal": true}))
            .collect()
    };
    let mut windows = json!({"backend": "srt-win"});
    if let Some(u) = i.sandbox_user {
        windows["sandboxUser"] = json!(u);
    }
    json!({
        "network": {
            "allowedDomains": allowed,
            "deniedDomains": [],
            "allowLocalBinding": false,
        },
        "filesystem": {
            "allowWrite": literal(vec![i.cwd.to_string(), i.state_dir.to_string()]),
            "allowRead": literal(vec![i.derm_exe.to_string()]),
            "denyWrite": literal(deny_write),
            "denyRead": literal(deny_read),
        },
        "windows": windows,
    })
}
