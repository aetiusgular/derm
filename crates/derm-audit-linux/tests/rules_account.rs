//! `derm-audit-feed rules --account <slug>` (step P, lane PC): what it
//! refuses before it prints anything. The printed file itself is
//! `rules::tests::pc_an_agent_accounts_rules_watch_its_sign_in_store`'s; a
//! run against a real account was done by hand as root in lane PC's cloud
//! workspace (`plans/parallel/acctP_PC.md`).
#![cfg(unix)]

use std::process::Command;

fn rules(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_derm-audit-feed"))
        .arg("rules")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn pc_an_account_that_is_not_a_user_here_is_named_and_nothing_printed() {
    let (code, out, err) = rules(&["--account", "pcnosuch7q2"]);
    assert_eq!(code, 2, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("derm-pcnosuch7q2 is not a user here"), "{err}");
    assert!(err.contains("derm agents add pcnosuch7q2"), "{err}");
}

#[test]
fn pc_a_slug_the_accounts_file_refuses_is_refused() {
    for slug in [
        "agent",
        "agents",
        "agent-x",
        "Max",
        "../x",
        "",
        "sixteen-chars-xx",
    ] {
        let (code, out, err) = rules(&["--account", slug]);
        assert_eq!(code, 2, "{slug:?}: {err}");
        assert!(out.is_empty(), "{slug:?}");
        assert!(
            err.contains("not an agent account's slug"),
            "{slug:?}: {err}"
        );
    }
    let (code, _, err) = rules(&["--account", "max", "--home", "/home/x"]);
    assert_eq!(code, 2);
    assert!(err.contains("takes no --home"), "{err}");
}

/// Without `--account` the person's own file is as before.
#[test]
fn pc_the_person_s_own_rules_are_unchanged_without_account() {
    let (code, out, err) = rules(&["--uid", "1000", "--home", "/home/pcx"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("50-derm-1000.rules"));
    assert!(!out.contains("/var/lib/derm/agents"));
}
