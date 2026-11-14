//! `derm --version` prints its name and the release version.
use std::process::Command;

#[test]
fn version_names_the_binary_and_the_release() {
    let out = Command::new(env!("CARGO_BIN_EXE_derm"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success(), "exit {:?}", out.status);
    let text = String::from_utf8_lossy(&out.stdout);
    let want = format!("derm {}", env!("CARGO_PKG_VERSION"));
    let line = text
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("{text:?}"));
    // Box test w6 BW6-9: any build but the release's own tag names its
    // commit, ` (<7 hex>)`; a release build prints the version alone.
    match line.strip_prefix(&want) {
        Some("") => {}
        Some(rest) => {
            let c = rest
                .strip_prefix(" (")
                .and_then(|r| r.strip_suffix(')'))
                .unwrap_or_else(|| panic!("{line:?}"));
            assert!(
                c.len() >= 7 && c.bytes().all(|b| b.is_ascii_hexdigit()),
                "{line:?}"
            );
        }
        None => panic!("{line:?}"),
    }
}

/// Review FP1-R1's test gap: in a git checkout whose HEAD the release tag
/// does not name, the line names HEAD's commit; a tag build names none.
#[test]
fn a_build_off_the_release_tag_names_its_commit() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let Some(head) = git(&["rev-parse", "HEAD"]) else {
        return; // no git: a source tarball, nothing to name
    };
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let tagged = std::env::var("GITHUB_REF").is_ok_and(|r| r == format!("refs/tags/{tag}"))
        || git(&["tag", "--points-at", "HEAD"]).is_some_and(|t| t.lines().any(|l| l == tag));
    let out = Command::new(env!("CARGO_BIN_EXE_derm"))
        .arg("--version")
        .output()
        .unwrap();
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let bare = format!("derm {}", env!("CARGO_PKG_VERSION"));
    if tagged {
        assert_eq!(line, bare);
    } else {
        assert_eq!(line, format!("{bare} ({})", &head[..7]));
    }
}
