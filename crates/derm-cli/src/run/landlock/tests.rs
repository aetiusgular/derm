//! Note CB section 6's check (`research-notes/CB_llcheck.c`), ported: two
//! "chats" A and B as one uid. Each may be put in its own domain through the
//! real helper ([`enter_main`]), which execs this test binary again, so the
//! whole process, every thread, is in the domain (a domain covers the thread
//! that made it and what it starts; libtest runs a test on a spawned
//! thread). A then tries to reach B: `/proc/B/environ` (where a chat token
//! sits), `/proc/B/cwd`, ptrace, `process_vm_readv`, a signal, B's abstract
//! socket; and reads what stays readable (`cmdline`, `status`).
//!
//! The roles: with [`SPEC_VAR`] set, the process is the helper and enters;
//! without it, [`ROLE`] names what it does. The parent is the test itself.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use serde_json::{json, Value};

use super::*;

const ROLE: &str = "DERM_LLCHECK_ROLE";
const B_PID: &str = "DERM_LLCHECK_B_PID";
const B_SOCK: &str = "DERM_LLCHECK_B_SOCK";
const FS_BASE: &str = "DERM_LLCHECK_FS_BASE";
const TOKEN: &str = "tok-of-chat-B";

fn test_name(f: &str) -> String {
    let m = module_path!();
    let m = m.split_once("::").map(|(_, rest)| rest).unwrap_or(m);
    format!("{m}::{f}")
}

/// When this process was started as a role, does it and exits.
fn role(test: &str) {
    if std::env::var_os(SPEC_VAR).is_some() {
        // The helper: enter the domain, exec this test again as the role.
        let exe = std::env::current_exe().unwrap();
        let args = vec![
            "--".to_string(),
            exe.to_string_lossy().into_owned(),
            "--exact".into(),
            test_name(test),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ];
        std::process::exit(enter_main(&args) as i32);
    }
    let Ok(r) = std::env::var(ROLE) else { return };
    match r.as_str() {
        "b" => role_b(),
        "a" => role_a(),
        "fs" => role_fs(),
        other => panic!("unknown role {other}"),
    }
    std::process::exit(0);
}

/// B: holds a chat token in its start environment (the parent set it),
/// lets any process ptrace it where Yama would stop a sibling (so the
/// control row means something on a Yama host; Landlock is not Yama), and
/// listens on an abstract socket.
fn role_b() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};
    // SAFETY: prctl with integer arguments; EINVAL without Yama is fine.
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0);
    }
    let name = std::env::var(B_SOCK).unwrap();
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let _l = UnixListener::bind_addr(&addr).unwrap();
    println!("LLCHECK up");
    std::thread::sleep(std::time::Duration::from_secs(30));
}

fn read_file(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

fn role_a() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};
    let b: i32 = std::env::var(B_PID).unwrap().parse().unwrap();
    let environ = read_file(&format!("/proc/{b}/environ"))
        .is_some_and(|d| d.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    let cwd = std::fs::read_link(format!("/proc/{b}/cwd")).is_ok();
    let cmdline = read_file(&format!("/proc/{b}/cmdline")).is_some_and(|d| !d.is_empty());
    let status = read_file(&format!("/proc/{b}/status")).is_some_and(|d| !d.is_empty());
    // SAFETY: plain syscalls on a pid; a successful attach is undone.
    let ptrace = unsafe {
        let r = libc::ptrace(libc::PTRACE_ATTACH, b, 0, 0);
        if r == 0 {
            libc::waitpid(b, std::ptr::null_mut(), 0);
            libc::ptrace(libc::PTRACE_DETACH, b, 0, 0);
        }
        r == 0
    };
    let mut dst = [0u8; 8];
    let local = libc::iovec {
        iov_base: dst.as_mut_ptr().cast(),
        iov_len: 8,
    };
    let remote = libc::iovec {
        iov_base: 0x400000 as *mut libc::c_void,
        iov_len: 8,
    };
    // SAFETY: reads at most 8 bytes into `dst`.
    let vmread = unsafe {
        let n = libc::process_vm_readv(b, &local, 1, &remote, 1, 0);
        n >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EFAULT)
    };
    // SAFETY: SIGCONT to a running process changes nothing.
    let signal = unsafe { libc::kill(b, libc::SIGCONT) } == 0;
    let name = std::env::var(B_SOCK).unwrap();
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let abstract_socket = UnixStream::connect_addr(&addr).is_ok();
    println!(
        "LLCHECK {}",
        json!({"environ": environ, "cwd": cwd, "cmdline": cmdline, "status": status,
               "ptrace": ptrace, "vmread": vmread, "signal": signal, "abstract": abstract_socket})
    );
}

/// Everything under `/`, so only the domain boundary differs (as in the C
/// check).
fn spec_all() -> Spec {
    Spec {
        version: 1,
        write: vec!["/".into()],
        require_landlock: true,
        require_scopes: abi() >= SCOPES_ABI,
        ..Spec::default()
    }
}

fn spawn_role(test: &str, role: &str, spec: Option<&Spec>, env: &[(&str, String)]) -> Child {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().unwrap();
    let mut c = Command::new(exe);
    if let Some(u) = role_uid() {
        c.uid(u).gid(u);
    }
    c.args([
        "--exact",
        &test_name(test),
        "--nocapture",
        "--test-threads=1",
    ])
    .env(ROLE, role)
    .env_remove(SPEC_VAR)
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit());
    if let Some(s) = spec {
        c.env(SPEC_VAR, serde_json::to_string(s).unwrap());
    }
    for (k, v) in env {
        c.env(k, v);
    }
    c.spawn().unwrap()
}

/// The first `LLCHECK ` line a role prints.
fn line_of(child: &mut Child) -> String {
    let out = child.stdout.take().unwrap();
    let mut r = BufReader::new(out);
    let mut l = String::new();
    loop {
        l.clear();
        if r.read_line(&mut l).unwrap() == 0 {
            panic!("the role ended before its LLCHECK line");
        }
        // libtest prints `test <name> ... ` with no newline before the
        // test's own output.
        if let Some(i) = l.find("LLCHECK ") {
            let rest = l[i + "LLCHECK ".len()..].trim().to_string();
            child.stdout = Some(r.into_inner());
            return rest;
        }
    }
}

fn one(ll_a: bool, ll_b: bool) -> Value {
    const T: &str = "llcheck_two_chats_as_one_uid_reach_nothing_of_each_other";
    let sock = format!("derm-llcheck-{}", uuid::Uuid::new_v4().simple());
    let spec = spec_all();
    let mut b = spawn_role(
        T,
        "b",
        ll_b.then_some(&spec),
        &[("DERM_CHAT_TOKEN", TOKEN.into()), (B_SOCK, sock.clone())],
    );
    assert_eq!(line_of(&mut b), "up");
    let mut a = spawn_role(
        T,
        "a",
        ll_a.then_some(&spec),
        &[(B_PID, b.id().to_string()), (B_SOCK, sock)],
    );
    let got: Value = serde_json::from_str(&line_of(&mut a)).unwrap();
    let _ = a.wait();
    let _ = b.kill();
    let _ = b.wait();
    got
}

/// As uid 0 a domain does not stop a read of a sibling's
/// `/proc/<pid>/environ` (run with note CB's own C program on Linux 6.18,
/// ABI 7: reached as root, refused as a plain user; the kernel's reason is
/// not read). Agent accounts are never uid 0 (`anchor::refusal`), so a run
/// as root puts both roles in `nobody`, one plain uid, as the note did.
fn role_uid() -> Option<u32> {
    (derm_core::platform::effective_user() == 0).then_some(65534)
}

fn yama() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[test]
fn llcheck_two_chats_as_one_uid_reach_nothing_of_each_other() {
    role("llcheck_two_chats_as_one_uid_reach_nothing_of_each_other");
    let abi = abi();
    if abi < 1 {
        eprintln!("not run: this kernel has no Landlock (ABI {abi})");
        return;
    }
    let scoped = abi >= SCOPES_ABI;
    // ptrace attach and process_vm_readv also pass Yama; B allows any
    // tracer, which Yama 2 and 3 ignore.
    let attach_ok = yama() <= 1;
    let rows = [
        ("none/none", false, false),
        ("ll/ll", true, true),
        ("ll/none", true, false),
        ("none/ll", false, true),
    ];
    for (name, ll_a, ll_b) in rows {
        let got = one(ll_a, ll_b);
        let a_in_domain = ll_a;
        // A in a domain reaches B only when B is in a sub-domain of A's,
        // which none of these rows has; A outside any domain reaches all.
        let reach = !a_in_domain;
        let mut want = json!({
            "environ": reach, "cwd": reach, "cmdline": true, "status": true,
            "ptrace": reach && attach_ok, "vmread": reach && attach_ok,
            "signal": reach || !scoped, "abstract": reach || !scoped,
        });
        if !attach_ok && reach {
            // Yama decides, not Landlock: not asserted.
            want["ptrace"] = got["ptrace"].clone();
            want["vmread"] = got["vmread"].clone();
        }
        assert_eq!(got, want, "A/B = {name}, ABI {abi}");
    }
}

/// C: in a chat's domain, reads and writes the paths the parent made.
fn role_fs() {
    let base = std::env::var(FS_BASE).unwrap();
    let read = |p: &str| std::fs::read(format!("{base}/{p}")).is_ok();
    let write = |p: &str| std::fs::write(format!("{base}/{p}"), b"x").is_ok();
    let sh = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .status()
        .is_ok_and(|s| s.success());
    let got = json!({
        "ownToken": read("bridge-a/chat.token"),
        "otherToken": read("bridge-b/chat.token"),
        "ownFolderWrite": write("chat-a/new"),
        "otherFolderRead": read("chat-b/secret"),
        "otherFolderWrite": write("chat-b/new"),
        "homeWrite": write("home/.config-x"),
        "bridgeWrite": write("bridge-a/x"),
        "personRead": read("person/.ssh-key"),
        "etc": std::fs::read("/etc/passwd").is_ok(),
        "devNull": std::fs::write("/dev/null", b"x").is_ok(),
        "sh": sh,
    });
    println!("LLCHECK {got}");
}

/// The chat's own folders, bridge and home, and nothing of another chat's
/// or the person's, with the spec `derm run` builds ([`super::chat_spec`]).
#[test]
fn a_chats_domain_reaches_its_own_folders_and_no_other_chats() {
    const T: &str = "a_chats_domain_reaches_its_own_folders_and_no_other_chats";
    role(T);
    if abi() < 1 {
        eprintln!("not run: this kernel has no Landlock");
        return;
    }
    // Outside /tmp, which every chat's domain may write.
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("llcheck-fs-{}", uuid::Uuid::new_v4().simple()));
    for d in ["bridge-a", "bridge-b", "chat-a", "chat-b", "home", "person"] {
        std::fs::create_dir_all(base.join(d)).unwrap();
    }
    for f in [
        "bridge-a/chat.token",
        "bridge-b/chat.token",
        "chat-b/secret",
        "person/.ssh-key",
    ] {
        std::fs::write(base.join(f), b"t").unwrap();
    }
    if let Some(u) = role_uid() {
        for d in [
            "", "bridge-a", "bridge-b", "chat-a", "chat-b", "home", "person",
        ] {
            std::os::unix::fs::chown(base.join(d), Some(u), Some(u)).unwrap();
        }
    }
    let base = std::fs::canonicalize(&base).unwrap();
    let s = |p: &str| base.join(p).to_string_lossy().into_owned();
    let spec = chat_spec(&ChatPaths {
        folders: &[s("chat-a")],
        account_home: &s("home"),
        bridge: Some(&s("bridge-a")),
        path: "/usr/local/bin:/usr/bin:/bin",
        require_scopes: false,
    });
    // The test binary stands in for the harness, so its folder is the
    // harness's install.
    let mut spec = spec;
    let exe = std::env::current_exe().unwrap();
    spec.exec
        .push(exe.parent().unwrap().to_string_lossy().into_owned());
    let mut c = spawn_role(
        T,
        "fs",
        Some(&spec),
        &[(FS_BASE, base.to_string_lossy().into_owned())],
    );
    let got: Value = serde_json::from_str(&line_of(&mut c)).unwrap();
    let _ = c.wait();
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(
        got,
        json!({
            "ownToken": true, "otherToken": false,
            "ownFolderWrite": true, "otherFolderRead": false, "otherFolderWrite": false,
            "homeWrite": true, "bridgeWrite": false, "personRead": false,
            "etc": true, "devNull": true, "sh": true,
        })
    );
}

/// The helper starts nothing when it cannot make what the spec asks for.
#[test]
fn the_helper_refuses_a_missing_or_bad_spec_and_a_usage_error() {
    assert_eq!(enter_main(&[]), 2);
    assert_eq!(enter_main(&["--".into()]), 2);
    assert_eq!(enter_main(&["/bin/true".into()]), 2);
}

#[test]
fn the_rights_and_the_attribute_follow_the_abi() {
    assert_eq!(sys::fs_rights(1), (1 << 13) - 1);
    assert_eq!(sys::fs_rights(2), (1 << 14) - 1);
    assert_eq!(sys::fs_rights(4), (1 << 15) - 1);
    assert_eq!(sys::fs_rights(5), (1 << 16) - 1);
    assert_eq!(sys::fs_rights(7), (1 << 16) - 1);
    assert_eq!(
        [1, 3, 4, 5, 6, 7].map(sys::attr_size),
        [8, 8, 16, 16, 24, 24]
    );
}

#[test]
fn a_chats_spec_holds_no_root_and_no_other_chat() {
    let s = chat_spec(&ChatPaths {
        folders: &["/srv/agents/p".into()],
        account_home: "/var/lib/derm/agents/max",
        bridge: Some("/run/derm-agent/1000/c-1-abc"),
        path: "/var/lib/derm/agents/max/.local/bin:/usr/bin:relative",
        require_scopes: true,
    });
    for v in [&s.read, &s.exec, &s.write] {
        assert!(!v.iter().any(|p| p == "/"), "{v:?}");
        assert!(
            !v.iter()
                .any(|p| p == "/run/derm-agent" || p.starts_with("/home")),
            "{v:?}"
        );
    }
    assert!(s.read.contains(&"/run/derm-agent/1000/c-1-abc".to_string()));
    assert!(!s.write.iter().any(|p| p.starts_with("/run/derm-agent")));
    assert!(s.write.contains(&"/srv/agents/p".to_string()));
    assert!(s.write.contains(&"/var/lib/derm/agents/max".to_string()));
    assert!(s
        .exec
        .contains(&"/var/lib/derm/agents/max/.local/bin".to_string()));
    assert!(!s.exec.iter().any(|p| p == "relative"));
    assert!(s.require_landlock && s.require_scopes);
}
