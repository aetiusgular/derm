//! `derm --version` prints its name and the release version.
use std::process::Command;

#[test]
fn version_names_the_binary_and_the_release() {
    let out = Command::new(env!("CARGO_BIN_EXE_derm"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success(), "exit {:?}", out.status);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("derm {}\n", env!("CARGO_PKG_VERSION"))
    );
}
