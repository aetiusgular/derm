//! Paths as taint compares them, and the two lists taint reads them against
//! (`contracts/policy.md` section 9).
//!
//! A path's key is absolute, `.` and `..` resolved by the text (no link is
//! followed: the file may not exist yet, and a hook must not open what the
//! agent named), `/` as the separator, folded as the gate folds every input
//! (`derm_core::policy::fold_text`: lowercase, look-alike letters to ASCII).
//! Folding merges names a case-sensitive disk keeps apart, which only makes
//! more files "the session's own" or "protected": taint only raises.

use std::path::{Component, Path, PathBuf};

use derm_core::policy::{fold_text, names_control_path, CONTROL_PATHS};

/// The key of `raw` (a word of the agent's), read from `cwd`, with `~/` and
/// `$HOME/` under `home`.
pub fn key(raw: &str, cwd: &Path, home: Option<&Path>) -> String {
    let raw = raw.trim();
    let expanded: PathBuf = if let (Some(rest), Some(h)) = (
        raw.strip_prefix("~/")
            .or_else(|| raw.strip_prefix("$home/"))
            .or_else(|| raw.strip_prefix("${home}/"))
            .or_else(|| raw.strip_prefix("$HOME/"))
            .or_else(|| raw.strip_prefix("${HOME}/")),
        home,
    ) {
        h.join(rest)
    } else if raw == "~" {
        home.map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(raw))
    } else {
        let p = PathBuf::from(raw.replace('\\', "/"));
        if p.is_absolute() || raw.starts_with('/') {
            p
        } else {
            cwd.join(p)
        }
    };
    let mut parts: Vec<String> = Vec::new();
    for c in expanded.components() {
        match c {
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    fold_text(&format!("/{}", parts.join("/")).replace('\\', "/"))
}

/// Whether a run of `run_raw` (key `run_key`) is of a file whose key is
/// `written`: the same key, or, for a run named relatively, a written file
/// whose key ends with the relative path (the agent may have `cd`'d between
/// the write and the run, and the hook reads both from its own folder).
pub fn same_file(run_raw: &str, run_key: &str, written: &str) -> bool {
    if run_key == written {
        return true;
    }
    let rel = run_raw.trim();
    if rel.starts_with('/') || rel.starts_with('~') || rel.starts_with('$') || rel.is_empty() {
        return false;
    }
    // `/diag.py`: the key read from the root, so the tail starts at a `/`.
    written.ends_with(&key(rel, Path::new("/"), None))
}

/// A file name a runner such as `uv run` takes as a script.
pub fn script_like(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    [
        ".py", ".sh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".lua",
    ]
    .iter()
    .any(|e| w.ends_with(e))
}

/// Folders whose files run code or steer an agent later, beyond the edit
/// itself, in key form (each matched as a whole path segment run). After a
/// chat took in untrusted content, a write under one is reviewed. The
/// selection follows OpenMoat 0.19.0's `PROTECTED_WRITES` (`openmoat-core`
/// `src/taint.rs:50`, 166 globs: CI, git hooks, editor tasks, build and test
/// definitions, agent instructions and settings; MIT OR Apache-2.0, read,
/// not copied), grouped by why, and adds the shell's startup files.
const PROTECTED_DIRS: &[&str] = &[
    // CI and the code it runs
    ".github/workflows",
    ".github/actions",
    ".circleci",
    ".buildkite",
    ".gitlab",
    // git hooks, wherever `core.hookspath` usually points
    ".git/hooks",
    ".husky",
    ".githooks",
    ".git-hooks",
    "githooks",
    "git-hooks",
    // editors' tasks and run configurations, which the editor runs
    ".vscode",
    ".idea",
    ".devcontainer",
    ".fleet",
    ".zed",
    // build tools' own folders
    ".cargo",
    ".mvn",
    "gradle/wrapper",
    // agents: instructions, skills, settings, hooks the next session obeys
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".gemini",
    ".pi",
    ".opencode",
    ".windsurf",
    ".continue",
    ".kiro",
    ".qwen",
    ".copilot",
    ".github/instructions",
    ".github/hooks",
    ".github/agents",
    ".github/copilot",
    ".config/opencode",
    ".config/git",
    ".config/fish",
    // what every Python start runs
    ".venv/bin",
    "venv/bin",
];

/// File names, by the last segment, that run code or steer an agent.
const PROTECTED_NAMES: &[&str] = &[
    ".gitlab-ci.yml",
    "jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".pre-commit-config.yaml",
    "lefthook.yml",
    ".lefthook.yml",
    "makefile",
    "gnumakefile",
    "justfile",
    ".justfile",
    "taskfile.yml",
    "taskfile.yaml",
    "package.json",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    "bunfig.toml",
    "pnpm-workspace.yaml",
    "deno.json",
    "deno.jsonc",
    "build.rs",
    "cargo.toml",
    "go.mod",
    "go.work",
    "cmakelists.txt",
    "cmakepresets.json",
    "pom.xml",
    "mvnw",
    "gradlew",
    "gradle.properties",
    "settings.gradle",
    "build.gradle",
    "rakefile",
    "gemfile",
    ".rspec",
    "composer.json",
    "conftest.py",
    "pytest.ini",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "tox.ini",
    "noxfile.py",
    "sitecustomize.py",
    "usercustomize.py",
    "dockerfile",
    "containerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    ".devcontainer.json",
    ".envrc",
    "claude.md",
    "agents.md",
    "gemini.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".mcp.json",
    ".claude.json",
    "copilot-instructions.md",
    "opencode.json",
    "opencode.jsonc",
    // the shell's startup files
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".kshrc",
    ".inputrc",
    ".gitconfig",
    ".gitmodules",
];

/// File name endings that run code (build files, editor runs).
const PROTECTED_ENDINGS: &[&str] = &[
    ".code-workspace",
    ".run.xml",
    ".gradle",
    ".gradle.kts",
    ".mk",
    ".cmake",
    ".csproj",
    ".fsproj",
    ".vbproj",
    ".props",
    ".targets",
    ".gemspec",
    ".rake",
    ".pth",
];

fn under(key: &str, dir: &str) -> bool {
    let probe = format!("/{dir}");
    key.contains(&format!("{probe}/")) || key.ends_with(&probe)
}

fn last(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

/// Why a write to `key` is protected, or `None`: taint's own list, or a
/// control path of the policy's step 7a (`derm_core::policy::CONTROL_PATHS`).
pub fn protected(key: &str) -> Option<String> {
    if let Some(d) = PROTECTED_DIRS.iter().find(|d| under(key, d)) {
        return Some(format!("{d}/"));
    }
    let name = last(key);
    if PROTECTED_NAMES.contains(&name) {
        return Some(name.to_string());
    }
    if let Some(e) = PROTECTED_ENDINGS.iter().find(|e| name.ends_with(*e)) {
        return Some(format!("*{e}"));
    }
    CONTROL_PATHS
        .iter()
        .find(|e| names_control_path(key, e))
        .map(|e| e.to_string())
}

/// Folders and files that hold credentials, in key form: a read of one
/// taints the chat (`secret-read`). OpenMoat 0.19.0's default policy calls
/// its group `secrets-paths` (`engine/taint.rs` `SECRET_RULE`); this list is
/// derm's, from where the agents and the common CLIs keep keys.
const SECRET_DIRS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".kube",
    ".password-store",
    ".docker/config.json",
    ".config/gh",
    ".terraform.d",
    ".oci",
    ".config/doctl",
    "library/keychains",
    ".local/share/keyrings",
];

const SECRET_NAMES: &[&str] = &[
    ".netrc",
    "_netrc",
    ".pypirc",
    ".git-credentials",
    ".vault-token",
    ".pgpass",
    ".npmrc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "shadow",
    "credentials",
    ".credentials.json",
    "auth.json",
];

/// Whether `key` names a secret: a file under a secret folder, one of the
/// secret names, or a `.env` file (`.env`, `.env.local`; not `.envrc`).
pub fn secret(key: &str) -> bool {
    if SECRET_DIRS.iter().any(|d| under(key, d)) {
        return true;
    }
    let name = last(key);
    SECRET_NAMES.contains(&name) || name == ".env" || name.starts_with(".env.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_absolute_resolved_and_folded() {
        let cwd = Path::new("/w/proj");
        let home = Some(Path::new("/home/u"));
        assert_eq!(key("run.sh", cwd, home), "/w/proj/run.sh");
        assert_eq!(key("./a/../B.SH", cwd, home), "/w/proj/b.sh");
        assert_eq!(key("~/.ssh/id_rsa", cwd, home), "/home/u/.ssh/id_rsa");
        assert_eq!(key("/tmp/x", cwd, home), "/tmp/x");
    }

    #[test]
    fn a_relative_run_meets_the_file_by_its_tail() {
        assert!(same_file("diag.py", "/w/diag.py", "/w/diag.py"));
        assert!(same_file("diag.py", "/other/diag.py", "/w/sub/diag.py"));
        assert!(same_file("sub/x.sh", "/w/sub/x.sh", "/q/sub/x.sh"));
        assert!(!same_file("ag.py", "/w/ag.py", "/w/diag.py"));
        assert!(!same_file("/abs/x.sh", "/abs/x.sh", "/w/x.sh"));
    }

    #[test]
    fn taints_protected_list_names_paths_no_control_entry_names() {
        // `Makefile`, `conftest.py` and `build.rs` are taint's own: step 7a's
        // control paths and step 7d's lists (integration w6's close) name
        // none of them, so a policy ask is never counted as taint's.
        let step7d = |k: &str| {
            [
                derm_core::policy::SECRET_PATHS,
                derm_core::policy::RUNS_LATER_PATHS,
                derm_core::policy::METADATA_ADDRESSES,
            ]
            .iter()
            .any(|l| l.iter().any(|e| derm_core::policy::names_entry(k, e)))
        };
        for k in ["/w/makefile", "/w/conftest.py", "/w/build.rs"] {
            assert!(protected(k).is_some(), "{k}");
            assert!(
                !CONTROL_PATHS.iter().any(|e| names_control_path(k, e)),
                "{k} is a control path"
            );
            assert!(!step7d(k), "{k} is named by step 7d");
        }
        // Since the close these are the policy's too (step 7d asks first).
        for k in ["/w/.husky/pre-commit", "/w/app.code-workspace"] {
            assert!(protected(k).is_some(), "{k}");
            assert!(step7d(k), "{k}");
        }
        for k in [
            "/w/.github/workflows/release.yml",
            "/w/.agents/skills/deploy/skill.md",
            "/home/u/.bashrc",
        ] {
            assert!(protected(k).is_some(), "{k}");
        }
        for k in [
            "/w/src/main.rs",
            "/w/readme.md",
            "/w/makefile.txt",
            "/w/github/x",
        ] {
            assert_eq!(protected(k), None, "{k}");
        }
    }

    #[test]
    fn secrets_are_read_by_folder_and_name() {
        for k in [
            "/home/u/.ssh/id_rsa",
            "/home/u/.aws/credentials",
            "/w/.env",
            "/w/.env.local",
            "/home/u/.config/gh/hosts.yml",
        ] {
            assert!(secret(k), "{k}");
        }
        for k in ["/w/.envrc", "/w/env.ts", "/w/src/ssh.rs", "/w/docs/aws.md"] {
            assert!(!secret(k), "{k}");
        }
    }
}
