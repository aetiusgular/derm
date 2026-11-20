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

/// The test binary, where the roles' uid can run it: itself, or as root a
/// hard link (a copy across file systems) in a fresh folder under the
/// system's temporary folder, since a 0700 home keeps `nobody` from the
/// build folder. Removed on drop.
struct Exe {
    path: std::path::PathBuf,
    dir: Option<std::path::PathBuf>,
}

impl Exe {
    fn new() -> Exe {
        use std::os::unix::fs::PermissionsExt;
        let me = std::env::current_exe().unwrap();
        if role_uid().is_none() {
            return Exe {
                path: me,
                dir: None,
            };
        }
        let dir = std::path::Path::new("/tmp")
            .join(format!("derm-llcheck-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("derm-test");
        if std::fs::hard_link(&me, &path).is_err() {
            std::fs::copy(&me, &path).unwrap();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Exe {
            path,
            dir: Some(dir),
        }
    }
}

impl Drop for Exe {
    fn drop(&mut self) {
        if let Some(d) = &self.dir {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

fn spawn_role(
    exe: &Exe,
    test: &str,
    role: &str,
    spec: Option<&Spec>,
    env: &[(&str, String)],
) -> Child {
    use std::os::unix::process::CommandExt;
    let mut c = Command::new(&exe.path);
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

fn one(exe: &Exe, ll_a: bool, ll_b: bool) -> Value {
    const T: &str = "llcheck_two_chats_as_one_uid_reach_nothing_of_each_other";
    let sock = format!("derm-llcheck-{}", uuid::Uuid::new_v4().simple());
    let spec = spec_all();
    let mut b = spawn_role(
        exe,
        T,
        "b",
        ll_b.then_some(&spec),
        &[("DERM_CHAT_TOKEN", TOKEN.into()), (B_SOCK, sock.clone())],
    );
    assert_eq!(line_of(&mut b), "up");
    let mut a = spawn_role(
        exe,
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
    let exe = Exe::new();
    let rows = [
        ("none/none", false, false),
        ("ll/ll", true, true),
        ("ll/none", true, false),
        ("none/ll", false, true),
    ];
    for (name, ll_a, ll_b) in rows {
        let got = one(&exe, ll_a, ll_b);
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
    // Outside /tmp, which every chat's domain may write; as root under
    // /run (no domain grants it), which `nobody` can pass through where a
    // 0700 home stops it.
    let name = format!("llcheck-fs-{}", uuid::Uuid::new_v4().simple());
    let base = if role_uid().is_some() {
        std::path::Path::new("/run").join(name)
    } else {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(name)
    };
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
    // No derm firewall table holds the test's uid here; the network check
    // has its own tests (`netcheck.rs`, and the one below).
    assert!(spec.check_network);
    spec.check_network = false;
    let exe = Exe::new();
    spec.exec
        .push(exe.path.parent().unwrap().to_string_lossy().into_owned());
    let mut c = spawn_role(
        &exe,
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

/// L2's request: a chat's helper checks the account's firewall table before
/// it makes the domain, and starts nothing when the table does not refuse
/// (here no table holds this uid). Nothing is applied to this test's thread:
/// the check comes first.
#[test]
fn the_helper_starts_nothing_when_the_accounts_table_does_not_refuse() {
    // On a machine whose table holds this uid the check would pass and the
    // helper would exec in this test's process: not here.
    if netcheck::check().is_ok() {
        return;
    }
    let spec = Spec {
        version: 1,
        write: vec!["/".into()],
        check_network: true,
        ..Spec::default()
    };
    assert_eq!(enter(&spec, &["/bin/true".into()]), 126);
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
    assert!(
        s.check_network,
        "every chat's helper checks the account's table"
    );
}

/// Review AI-2 (accounts integration): a rule path is opened with every
/// link followed, so a chat that replaces a folder of the account's (its
/// `~/.local/bin`, a chat folder) with a link widens the next chat's domain
/// to the link's target: another chat's bridge and its `chat.token`. A link
/// the account or anyone but root owns is refused, and the start with it;
/// root's own links (merged /usr: `/bin -> usr/bin`) are followed.
#[test]
fn ai_2_a_rule_path_through_a_link_not_roots_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::temp_dir().join(format!("derm-ai2-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(base.join("target")).unwrap();
    std::fs::write(base.join("target/secret.txt"), "x").unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    let link = base.join("bin");
    std::os::unix::fs::symlink(base.join("target"), &link).unwrap();
    // As root here: the link stands for one a chat made, so not root's.
    let l = std::ffi::CString::new(link.to_string_lossy().as_bytes()).unwrap();
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(unsafe { libc::lchown(l.as_ptr(), 65534, 65534) }, 0);
    }
    let e = rule_fd(&link.to_string_lossy()).unwrap_err();
    assert!(e.contains("link"), "{e}");
    // A link below the rule's own path is the domain's business, not a widening:
    // only links on the path itself count. A folder with no link opens.
    assert!(rule_fd(&base.join("target").to_string_lossy())
        .unwrap()
        .is_some());
    // Not there: no rule, no error.
    assert!(rule_fd(&base.join("none").to_string_lossy())
        .unwrap()
        .is_none());
    // Root's links on the system's own paths are followed (where /bin is one).
    if std::fs::symlink_metadata("/bin").is_ok_and(|m| m.file_type().is_symlink()) {
        assert!(rule_fd("/bin").unwrap().is_some());
    }
    // A link in a folder above the path, not only the last part.
    let deep = base.join("bin").join("secret.txt");
    assert!(rule_fd(&deep.to_string_lossy()).is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

/// Review AI-1 (accounts integration, open, high; Tony's call): every chat
/// may write the account home, and the next chat runs its harness from
/// `<home>/.local/bin` and reads its config there, so one chat can plant
/// code that runs inside the next chat's domain and hands it that chat's
/// token. Red until the home is split into read-only installs and config
/// and per-chat writable state (plans/toolkit_agent_accounts_plan.md,
/// revision 4, call 7).
#[test]
#[ignore = "AI-1 open: needs the account home's split, Tony's call"]
fn ai_1_no_folder_a_chat_runs_from_is_one_every_chat_may_write() {
    let s = chat_spec(&ChatPaths {
        folders: &["/srv/agents/p".into()],
        account_home: "/var/lib/derm/agents/max",
        bridge: None,
        path: "/var/lib/derm/agents/max/.local/bin:/usr/bin",
        require_scopes: true,
    });
    for e in &s.exec {
        for w in &s.write {
            assert!(
                !e.starts_with(w.as_str()),
                "{e} runs code from {w}, which every chat writes"
            );
        }
    }
}

/// Review AI-4 (accounts integration, open, medium): `/dev/pts` is fully
/// open in every chat's domain, and sudo's `use_pty` gives each chat a pty
/// owned by the account, so a sibling can open another chat's terminal,
/// write to it and race its input (reproduced by the reviewer). Red until a
/// chat's terminal is its own (a devpts per chat, or Landlock's later
/// rights).
#[test]
#[ignore = "AI-4 open: a chat's pty is not its own yet"]
fn ai_4_a_chat_cannot_open_another_chats_terminal_by_path() {
    let s = chat_spec(&ChatPaths {
        folders: &[],
        account_home: "/var/lib/derm/agents/max",
        bridge: None,
        path: "/usr/bin",
        require_scopes: true,
    });
    assert!(
        !s.write.iter().any(|w| w == "/dev/pts"),
        "every chat may open every /dev/pts/<n>"
    );
}
