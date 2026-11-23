//! Step P's red test in the Linux feed (the base, 20 Nov 2026; lane PC's
//! P8 first part; `contracts/events.md` section 7.2, `net.unix`). No lane
//! edits this file; P integration drops the `ignore` once lane PC is green.

/// An AF_UNIX `connect`'s `saddr` keeps its path, and an abstract socket its
/// name after `@`. The bytes are what a real connect passed the kernel,
/// recorded with `strace -f -e trace=connect -xx` of CPython's
/// `socket.connect` on Linux 6.18.44 (20 Nov 2026): `{sa_family=AF_UNIX,
/// sun_path="/tmp/dsk"}, 11` (with its NUL) and `sun_path=@"dabs"}, 7`.
/// The audit `SOCKADDR` record logs those `addrlen` bytes in hex (Linux
/// `kernel/auditsc.c` `__audit_sockaddr`, not re-read; no auditd here, so
/// no audit record was recorded: rules 9.12, Not verified in
/// `plans/parallel/acctP_base.md`). Red on the base: the feed drops every
/// AF_UNIX address (`action.rs` `sockaddr`, its test "AF_UNIX is not kept").
#[test]
fn pc_an_af_unix_connect_keeps_its_path_or_abstract_name() {
    use derm_audit_linux::action::unix_sockaddr;
    assert_eq!(
        unix_sockaddr("01002F746D702F64736B00").as_deref(),
        Some("/tmp/dsk")
    );
    assert_eq!(unix_sockaddr("01000064616273").as_deref(), Some("@dabs"));
    // Not AF_UNIX, or no path: none.
    assert_eq!(unix_sockaddr("0200005000000000"), None);
    assert_eq!(unix_sockaddr("0100"), None);
}
