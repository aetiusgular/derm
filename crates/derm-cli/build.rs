//! The build's commit for `derm --version` (box test w6 BW6-9, Mac test w6
//! MW6-1, Windows test w6 WW6-10: each test built the head and could not
//! tell from `derm --version` that it ran it).
//!
//! A build of the release's own tag prints `derm <version>` alone, as
//! Homebrew's install test expects (`packaging/homebrew/derm.rb.in`,
//! `assert_equal "derm #{version}"`): the tag `v<version>` points at the
//! commit, or the release workflow's `GITHUB_REF` names it. Any other build
//! from a git checkout adds ` (<short commit>)`; a build with no git (a
//! source tarball) adds nothing.

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let dir = Path::new(&dir);
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let tag = format!("v{version}");
    println!("cargo:rerun-if-env-changed=GITHUB_REF");
    let commit = git(dir, &["rev-parse", "--short=7", "HEAD"]);
    let tagged = std::env::var("GITHUB_REF").is_ok_and(|r| r == format!("refs/tags/{tag}"))
        || git(dir, &["tag", "--points-at", "HEAD"]).is_some_and(|t| t.lines().any(|l| l == tag));
    let suffix = match commit {
        Some(c) if !tagged => format!(" ({c})"),
        _ => String::new(),
    };
    println!("cargo:rustc-env=DERM_BUILD_SUFFIX={suffix}");
    // Build again when HEAD moves: a checkout or a commit writes the
    // git folder's `logs/HEAD` (a worktree has its own).
    if let Some(gd) = git(dir, &["rev-parse", "--absolute-git-dir"]) {
        for f in ["HEAD", "logs/HEAD"] {
            let p = Path::new(&gd).join(f);
            if p.exists() {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
}
