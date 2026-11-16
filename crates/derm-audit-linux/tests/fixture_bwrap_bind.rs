//! bubblewrap's look at its own bind, against a log recorded on the box
//! (`panda`, Ubuntu 26.04, kernel 7.0.0-43, auditd 4.1.2 userspace, srt
//! 0.0.82's bubblewrap 0.11.1 at `/usr/local/libexec/derm-srt/bwrap`), with
//! the rules `derm-audit-feed rules` installed there for uid 1000, 14 Nov
//! 2026 (box test w6 retest 3, BW6R3-1). Raw format, as the box logs it.
//!
//! `bwrap_bind_7_0.raw.audit`, root pid 14008 (`sh`), the file a scratch
//! `{}` in `~/.derm/run`, which the rules watch (`-F dir=... -k derm_sens`),
//! bound the way srt binds a chat's route file:
//!
//! ```text
//! F=/home/opone/.derm/run/fp4-fixture.json
//! bwrap --ro-bind / / --tmpfs /home/opone/.derm --ro-bind $F $F --dev /dev cat $F
//! cat $F
//! ```
//!
//! bubblewrap 0.11.1's `bind_mount()` opens each destination with
//! `O_PATH | O_CLOEXEC` after the mount, to find it in the mount table
//! (`bind-mount.c:397-408` at v0.11.1, read): serial 58110, `a2=280000`.
//! `cat` reads the bound file inside (58129) and the host's file outside
//! (58133), each `a2=80000` (`O_RDONLY | O_CLOEXEC`). `O_PATH` is
//! `010000000` in `include/uapi/asm-generic/fcntl.h:83-84` at Linux v7.0,
//! which x86 uses (it has no `fcntl.h` of its own).

use derm_audit_linux::parse_for_root;
use derm_audit_linux::tree::Root;
use derm_core::event::Event;
use serde_json::Value;

const BIND: &str = include_str!("fixtures/bwrap_bind_7_0.raw.audit");
const HOME: &str = "/home/opone";
const FILE: &str = "/home/opone/.derm/run/fp4-fixture.json";

fn root() -> Root {
    Root {
        chat: "chat-b".into(),
        harness: "other".into(),
        pid: 14008,
        folders: vec!["/home/opone/w6box/fp4".into()],
        state: vec![],
        at: 0,
        stopped: false,
    }
}

fn s<'a>(e: &'a Event, k: &str) -> &'a str {
    e.detail.get(k).and_then(Value::as_str).unwrap_or("")
}

fn opens(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.kind == "open").collect()
}

#[test]
fn bw6r3_1_an_o_path_open_says_it_reads_nothing() {
    let events = parse_for_root(BIND, root(), HOME);
    let bwrap: Vec<_> = opens(&events)
        .into_iter()
        .filter(|e| s(e, "comm") == "bwrap")
        .collect();
    assert_eq!(bwrap.len(), 1, "{events:#?}");
    assert_eq!(s(bwrap[0], "path"), format!("/newroot{FILE}"));
    assert_eq!(
        bwrap[0].detail.get("pathOnly").and_then(Value::as_bool),
        Some(true),
        "{:?}",
        bwrap[0].detail
    );
}

#[test]
fn bw6r3_1_a_read_open_says_nothing_of_the_kind() {
    let events = parse_for_root(BIND, root(), HOME);
    let reads: Vec<_> = opens(&events)
        .into_iter()
        .filter(|e| s(e, "comm") == "cat" && s(e, "path") == FILE)
        .collect();
    // Inside the sandbox (the bound file) and on the host.
    assert_eq!(reads.len(), 2, "{events:#?}");
    for e in reads {
        assert_eq!(e.detail.get("pathOnly"), None, "{:?}", e.detail);
    }
}
