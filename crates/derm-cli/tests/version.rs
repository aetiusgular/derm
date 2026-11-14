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
