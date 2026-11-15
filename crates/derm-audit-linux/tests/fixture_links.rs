//! Links and bubblewrap's setup, against logs recorded with auditd 3.1.2 on
//! Ubuntu 24.04.5 (kernel 6.18.44-fc-v470, bubblewrap 0.9.0) in integration
//! w6's fix pass 3 cloud workspace, 14 Nov 2026, with the rules of
//! `derm-audit-feed rules --uid 30033 --home /home/tk` (box test w6 retest 2,
//! BW6R2-1 and BW6R2-2). The box runs kernel 7.0.0-43 and bubblewrap 0.11.1;
//! bubblewrap's `/dev` links and mount points are the same calls in both
//! (`bubblewrap.c:1390-1422` at v0.11.1, read).
//!
//! `links_6_18.enriched.audit`, as user `tk` (uid 30033), root pid 8746:
//!
//! ```text
//! cd /home/tk/s2proj
//! ln -s /tmp/rec/s2/zzzzzzzzzzzzzzz/pre-commit /home/tk/s2proj/.git/hooks/pre-commit
//! ln -s /tmp/rec/s2/target.txt /home/tk/s2proj/link.txt
//! bwrap --ro-bind / / --tmpfs /home/tk --bind /home/tk/s2proj /home/tk/s2proj \
//!   --ro-bind /etc/hostname /home/tk/s2proj/.gitconfig --ro-bind /etc/hostname /home/tk/.gitconfig \
//!   --tmpfs /home/tk/.derm --ro-bind /etc/hostname /home/tk/.derm/policy.json --dev /dev true
//! ```
//!
//! `links_matched_6_18.enriched.audit`, root pid 8783 (`sh`), in
//! `/home/tk/s2proj`: `ln -s /tmp/rec/s3/zzzzzzzzzzzzzz/pc2
//! /home/tk/s2proj/.git/hooks/pc2` (a target whose folder is as long as the
//! link's, so 6.18's `__audit_inode_child` takes it as the new entry) and
//! `ln -s ../../../tmp/rec/s3/x/hooks pc3`.

use derm_audit_linux::parse_for_root;
use derm_audit_linux::tree::Root;
use derm_core::event::Event;
use serde_json::Value;

const LINKS: &str = include_str!("fixtures/links_6_18.enriched.audit");
const MATCHED: &str = include_str!("fixtures/links_matched_6_18.enriched.audit");
const HOME: &str = "/home/tk";

fn root(pid: u32) -> Root {
    Root {
        chat: "chat-l".into(),
        harness: "claude-code".into(),
        pid,
        folders: vec!["/home/tk/s2proj".into()],
        state: vec![],
        at: 0,
        stopped: false,
    }
}

fn s<'a>(e: &'a Event, k: &str) -> &'a str {
    e.detail.get(k).and_then(Value::as_str).unwrap_or("")
}

fn links(events: &[Event]) -> Vec<(String, String)> {
    events
        .iter()
        .filter(|e| e.kind == "link")
        .map(|e| (s(e, "path").to_string(), s(e, "dest").to_string()))
        .collect()
}

#[test]
fn bw6r2_1_a_symlink_names_its_target_and_the_link_it_made() {
    let events = parse_for_root(LINKS, root(8746), HOME);
    let got = links(&events);
    for want in [
        (
            "/tmp/rec/s2/zzzzzzzzzzzzzzz/pre-commit",
            "/home/tk/s2proj/.git/hooks/pre-commit",
        ),
        ("/tmp/rec/s2/target.txt", "/home/tk/s2proj/link.txt"),
        ("/proc/self/fd/0", "/newroot/dev/stdin"),
        ("/proc/self/fd", "/newroot/dev/fd"),
        ("/proc/kcore", "/newroot/dev/core"),
        ("pts/ptmx", "/newroot/dev/ptmx"),
    ] {
        assert!(
            got.iter().any(|(f, t)| f == want.0 && t == want.1),
            "{want:?} not in {got:?}"
        );
    }
}

#[test]
fn bw6r2_1_a_target_the_kernel_took_as_the_new_entry_is_not_the_link() {
    // The record: PARENT `/home/tk/s2proj/.git/hooks/`, then CREATE with the
    // target's name and no UNKNOWN item (items=2).
    let events = parse_for_root(MATCHED, root(8783), HOME);
    let got = links(&events);
    assert!(
        got.contains(&(
            "/tmp/rec/s3/zzzzzzzzzzzzzz/pc2".to_string(),
            "/home/tk/s2proj/.git/hooks/pc2".to_string()
        )),
        "{got:?}"
    );
    assert!(
        got.contains(&(
            "../../../tmp/rec/s3/x/hooks".to_string(),
            "/home/tk/s2proj/pc3".to_string()
        )),
        "{got:?}"
    );
    // The control path is the link's folder, and the feed flags it there.
    let hook = events
        .iter()
        .find(|e| e.kind == "link" && s(e, "dest").ends_with("/hooks/pc2"))
        .unwrap();
    assert_eq!(s(hook, "dev"), "fe:00");
}

#[test]
fn bw6r2_2_a_write_keeps_the_device_it_landed_on() {
    let events = parse_for_root(LINKS, root(8746), HOME);
    let dev = |p: &str| {
        events
            .iter()
            .find(|e| e.kind == "create" && s(e, "path") == p)
            .map(|e| s(e, "dev").to_string())
            .unwrap_or_else(|| panic!("no create {p}"))
    };
    // bubblewrap's tmpfs root, the tmpfs at ~/.derm, and the host's disk
    // under the writable bind.
    assert_eq!(dev("/newroot/home/tk/.gitconfig"), "00:2a");
    assert_eq!(dev("/newroot/home/tk/.derm/policy.json"), "00:2b");
    assert_eq!(dev("/newroot/home/tk/s2proj/.gitconfig"), "fe:00");
}

#[test]
fn bw6r2_1_kernel_7_0_order_from_the_6_18_record_not_recorded() {
    // Linux 7.0 reads the target's name before the link's
    // (`CLASS(filename, old)` then `new`, fs/namei.c:5664-5665 at v7.0), so
    // the matched target is item 0 and the link's folder item 1. Built from
    // the 6.18 record by swapping the two items' numbers; not recorded on a
    // 7.0 kernel (the box retest checks it, `tk_integration_w6_fp3.md`).
    let parent = "item=0 name=\"/home/tk/s2proj/.git/hooks/\"";
    let target = "item=1 name=\"/tmp/rec/s3/zzzzzzzzzzzzzz/pc2\"";
    assert!(MATCHED.contains(parent) && MATCHED.contains(target));
    let swapped = MATCHED
        .replace(parent, "item=9 name=\"/home/tk/s2proj/.git/hooks/\"")
        .replace(target, "item=0 name=\"/tmp/rec/s3/zzzzzzzzzzzzzz/pc2\"")
        .replace(
            "item=9 name=\"/home/tk/s2proj/.git/hooks/\"",
            "item=1 name=\"/home/tk/s2proj/.git/hooks/\"",
        );
    let events = parse_for_root(&swapped, root(8783), HOME);
    assert!(
        links(&events).contains(&(
            "/tmp/rec/s3/zzzzzzzzzzzzzz/pc2".to_string(),
            "/home/tk/s2proj/.git/hooks/pc2".to_string()
        )),
        "{:?}",
        links(&events)
    );
}
