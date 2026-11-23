//! Step P8's first part (lane PC): AF_UNIX connects against records the
//! kernel itself wrote. `unix_connect_6_18.raw.audit` holds Linux
//! 6.18.44's own SYSCALL, SOCKADDR, CWD, PATH, PROCTITLE and EOE records
//! for three `connect` calls, read from the audit netlink socket in lane
//! PC's cloud workspace on 21 Nov 2026 (no auditd there: a small client set
//! audit on, added `-a always,exit -F arch=b64 -S connect -k derm_net`,
//! and printed each record as auditd's RAW format writes it, `type=<name>
//! msg=<the kernel's text>`; then removed the rule and set audit off). As
//! root, pid 585 (CPython 3.13), in `/home/claude/probe`:
//!
//! ```text
//! connect(AF_UNIX, "/tmp/dsk")        addrlen 11   (serial 15)
//! connect(AF_UNIX, "\0dabs")          addrlen 7    (serial 16)
//! connect(AF_UNIX, "/tmp/dsk", 110)   addrlen 110, zeros after the path (serial 17)
//! ```
//!
//! Not the box's: no SOCKADDR line from the box's auditd 4.1.2 on 7.0.0-43
//! was recorded (`plans/parallel/acctP_box_research.md` has no such item
//! done), so the box's line is Not verified. The kernel's format is the
//! same at v7.0 by source (`kernel/auditsc.c:1739-1747`, `audit.c:2074-2101`).

use derm_audit_linux::parse_for_root;
use derm_audit_linux::tree::Root;
use derm_core::event::Source;
use serde_json::{json, Value};

const LOG: &str = include_str!("fixtures/unix_connect_6_18.raw.audit");

#[test]
fn pc_the_kernels_own_af_unix_records_give_unix_connects() {
    let root = Root {
        chat: "chat-u".into(),
        harness: "claude-code".into(),
        pid: 585,
        folders: vec!["/home/claude/probe".into()],
        state: vec![],
        at: 0,
        stopped: false,
    };
    let events = parse_for_root(LOG, root, "/root");
    let unix: Vec<_> = events.iter().filter(|e| e.kind == "unix.connect").collect();
    let got: Vec<(&str, bool)> = unix
        .iter()
        .map(|e| {
            (
                e.detail["path"].as_str().unwrap(),
                e.detail["abstract"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![("/tmp/dsk", false), ("@dabs", true), ("/tmp/dsk", false)],
        "{events:#?}"
    );
    for e in &unix {
        assert_eq!(e.source, Source::Auditd);
        assert_eq!(e.chat_id, "chat-u");
        assert_eq!(e.pid, Some(585));
        assert_eq!(e.detail["syscall"], json!("connect"));
        assert_eq!(e.detail["exe"], Value::from("/usr/local/bin/python3.13"));
        assert!(e.summary.starts_with("connect unix "), "{}", e.summary);
        // No new-host preflag: a Unix socket is not a host.
        assert!(e.detail.get("preflags").is_none(), "{e:?}");
    }
    // None of them is an inet connect.
    assert!(events.iter().all(|e| e.kind != "net.connect"));
}

/// The daemon reads the feed's kind by its own copy of the name (the daemon
/// does not depend on this crate); the two stay one string.
#[test]
fn pc_the_daemon_reads_the_feeds_unix_connect_kind() {
    assert_eq!(
        derm_audit_linux::map::UNIX_CONNECT,
        derm_daemon::installs::project::UNIX_CONNECT
    );
}

/// The daemon's copy of the system files the account's rules watch, which
/// it reads as no sign-in read, is this crate's list.
#[test]
fn pc_the_daemon_knows_the_system_files_the_account_rules_watch() {
    let mine: Vec<&str> = derm_audit_linux::sensitive::SYSTEM_FILES
        .iter()
        .chain(derm_audit_linux::sensitive::SYSTEM_DIRS)
        .copied()
        .collect();
    assert_eq!(mine, derm_daemon::installs::project::SYSTEM_SENSITIVE);
}
