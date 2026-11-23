#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

//! `derm agents` (lane L4). Every program it runs is a stand-in here: `sudo`
//! is a script that drops sudo's own options and runs the rest as the test's
//! user, with the account's home set as sudo's `-H` and `-i` would; the
//! harnesses are scripts that write their sign-in file. Shapes from the real
//! programs at the versions in use (sudo 1.9.15p5's options; `claude auth
//! login` of Claude Code 2.1.322 and `codex login --device-auth` of Codex
//! 0.167.2, plans/parallel/acct_L4.md, Research). No test runs the real sudo
//! or the real installer.

use super::*;
use crate::connect::write::Confirm;

struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dir(tag: &str) -> Dir {
    let d = std::env::temp_dir().join(format!(
        "derm-agents-{tag}-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&d).unwrap();
    Dir(d)
}

fn s(a: &[&str]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}

/// An executable script written from a child process, so this test process
/// never holds it open for write (case 154; `run/mod.rs` `script`).
#[cfg(unix)]
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let p = bin.join(name);
    let mut w = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(&p)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(
        &mut w.stdin.take().unwrap(),
        format!("#!/bin/sh\n{body}\n").as_bytes(),
    )
    .unwrap();
    assert!(w.wait().unwrap().success());
    p
}

/// sudo's stand-in: records its argv, drops `-n`, `-H`, `-i`, `-u <user>`
/// and `--`, sets the account's home and runs the rest. `exit` stands for a
/// sudo that cannot run as the account without a password.
#[cfg(unix)]
fn fake_sudo(d: &Path, home: &Path, fail: bool) -> PathBuf {
    let log = d.join("sudo.log");
    script(
        d,
        "sudo",
        &format!(
            r#"printf '%s\n' "$*" >> '{log}'
{fail}
while [ $# -gt 0 ]; do
  case "$1" in
    -n|-H|-i|--preserve-env=*) shift ;;
    -u) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
HOME='{home}'; export HOME
exec "$@""#,
            log = log.display(),
            home = home.display(),
            fail = if fail { "exit 1" } else { "" },
        ),
    )
}

/// A file written from a child process, for the same reason: a fork of
/// another test's thread holds a copy of this process's descriptors until
/// it execs, and its close would reach an inotify watch set up after the
/// write (CI's Linux job saw an IN_CLOSE_WRITE so, on f388f2e).
#[cfg(target_os = "linux")]
fn put(p: &Path, text: &str) {
    let ok = Command::new("/bin/sh")
        .args(["-c", "printf '%s' \"$2\" > \"$1\"", "sh"])
        .arg(p)
        .arg(text)
        .status()
        .unwrap()
        .success();
    assert!(ok);
}

/// `derm landlock`'s stand-in: records its words and whether the spec came
/// through, drops the spec as the real one does, and runs what follows `--`.
#[cfg(unix)]
fn fake_helper(d: &Path) -> PathBuf {
    let log = d.join("helper.log");
    script(
        d,
        "derm-helper",
        &format!(
            r#"printf '%s|spec=%s\n' "$*" "${{DERM_LANDLOCK_SPEC:+yes}}" >> '{log}'
unset DERM_LANDLOCK_SPEC
[ "$1" = landlock ] && [ "$2" = -- ] || exit 2
shift 2
exec "$@""#,
            log = log.display()
        ),
    )
}

struct Yes(bool, usize);
impl Confirm for Yes {
    fn confirm(&mut self, _q: &str) -> Result<bool, String> {
        self.1 += 1;
        Ok(self.0)
    }
}

const REGISTRY: &str = r#"{"version":1,"group":"derm-agents","accounts":[
  {"name":"derm-max","uid":61001,"subscription":"Claude Max (work)","home":"/var/lib/derm/agents/max"},
  {"name":"derm-plus","uid":61002,"subscription":"ChatGPT Plus","home":"/var/lib/derm/agents/plus"}]}"#;

struct Setup {
    d: Dir,
    /// Read by the Linux tests (the registry is Linux's alone).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    home: PathBuf,
    sudo: PathBuf,
}

/// A registry file of the test's user, 0644, and an agent home.
#[cfg(unix)]
fn setup(tag: &str, sudo_fails: bool) -> Setup {
    use std::os::unix::fs::PermissionsExt;
    let d = dir(tag);
    let reg = d.0.join("agents.json");
    std::fs::write(&reg, REGISTRY).unwrap();
    std::fs::set_permissions(&reg, std::fs::Permissions::from_mode(0o644)).unwrap();
    let home = d.0.join("agent-home");
    std::fs::create_dir_all(&home).unwrap();
    let sudo = fake_sudo(&d.0, &home, sudo_fails);
    Setup { d, home, sudo }
}

struct Ran {
    code: u8,
    out: String,
    err: String,
    asked: usize,
}

#[cfg(unix)]
fn go(st: &Setup, args: &[&str], f: impl FnOnce(&mut Ctx<'_>)) -> Ran {
    go_with(st, args, PACKAGE, true, f)
}

#[cfg(unix)]
fn go_with(
    st: &Setup,
    args: &[&str],
    package: &[(&str, &str)],
    yes: bool,
    f: impl FnOnce(&mut Ctx<'_>),
) -> Ran {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut y = Yes(yes, 0);
    let env = |_: &str| None;
    let mut ctx = Ctx {
        registry: st.d.0.join("agents.json"),
        registry_root: st.d.0.clone(),
        settings: st.d.0.join("settings.json"),
        registry_owner: me(),
        sudo: st.sudo.clone(),
        sh: PathBuf::from("/bin/sh"),
        helper: Ok(fake_helper(&st.d.0)),
        login_path_first: Some(st.d.0.join("bin").to_string_lossy().into_owned()),
        path_env: format!("{}:/usr/bin:/bin", st.d.0.join("bin").display()),
        check_tools: false,
        package,
        root_tmp: st.d.0.clone(),
        linux: true,
        terminal: true,
        in_chat: None,
        confirm: &mut y,
        env: &env,
        out: &mut out,
        err: &mut err,
    };
    f(&mut ctx);
    let code = run(&mut ctx, &s(args));
    drop(ctx);
    Ran {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
        asked: y.1,
    }
}

fn sudo_log(st: &Setup) -> String {
    std::fs::read_to_string(st.d.0.join("sudo.log")).unwrap_or_default()
}

// ---- the registry (section 2's contract) ----

#[cfg(target_os = "linux")]
#[test]
fn the_registry_parses_whole_or_not_at_all() {
    let a = registry::parse(REGISTRY).unwrap();
    assert_eq!(a.len(), 2);
    assert_eq!(a[0].slug, "max");
    assert_eq!(a[0].subscription, "Claude Max (work)");
    for bad in [
        r#"{"version":2,"group":"derm-agents","accounts":[]}"#,
        r#"{"version":1,"group":"wheel","accounts":[]}"#,
        r#"{"version":1,"group":"derm-agents"}"#,
        // One bad entry refuses the whole file.
        r#"{"version":1,"group":"derm-agents","accounts":[
          {"name":"derm-ok","uid":61001,"subscription":"x","home":"/var/lib/derm/agents/ok"},
          {"name":"root","uid":0,"subscription":"x","home":"/root"}]}"#,
        r#"{"version":1,"group":"derm-agents","accounts":[{"name":"derm-UP","uid":5,"subscription":"x","home":"/var/lib/derm/agents/UP"}]}"#,
        r#"{"version":1,"group":"derm-agents","accounts":[{"name":"derm-a","uid":0,"subscription":"x","home":"/var/lib/derm/agents/a"}]}"#,
        r#"{"version":1,"group":"derm-agents","accounts":[{"name":"derm-a","uid":5,"subscription":"x","home":"h"}]}"#,
        r#"{"version":1,"group":"derm-agents","accounts":[{"name":"derm-a","uid":5,"subscription":"x","home":"/a/../b"}]}"#,
        r#"{"version":1,"group":"derm-agents","accounts":[
          {"name":"derm-a","uid":5,"subscription":"x","home":"/var/lib/derm/agents/a"},
          {"name":"derm-b","uid":5,"subscription":"y","home":"/var/lib/derm/agents/b"}]}"#,
        // The lanes' first form, a slug over 15, and a reserved slug.
        r#"{"version":1,"group":"derm-agents","accounts":[{"name":"derm-agent-a","uid":5,"subscription":"x","home":"/var/lib/derm/agents/agent-a"}]}"#,
        r#"{"version":1,"group":"derm-agents","accounts":[{"name":"derm-abcdefghijklmnop","uid":5,"subscription":"x","home":"/var/lib/derm/agents/abcdefghijklmnop"}]}"#,
        r#"{"version":1,"group":"derm-agents","accounts":[{"name":"derm-agents","uid":5,"subscription":"x","home":"/var/lib/derm/agents/agents"}]}"#,
        "not json",
    ] {
        assert!(registry::parse(bad).is_err(), "{bad}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_registry_others_can_write_or_that_is_a_link_or_not_roots_is_not_used() {
    use std::os::unix::fs::PermissionsExt;
    let st = setup("reg", false);
    let reg = st.d.0.join("agents.json");
    let root = &st.d.0;
    assert_eq!(registry::load(&reg, root, me()).unwrap().len(), 2);
    // Not the owner the reader requires (root, outside tests).
    let e = registry::load(&reg, root, me().wrapping_add(1)).unwrap_err();
    assert!(
        e.contains("not owned by uid") && e.contains("derm agents add"),
        "{e}"
    );
    for mode in [0o664, 0o646] {
        std::fs::set_permissions(&reg, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(registry::load(&reg, root, me()).is_err(), "{mode:o}");
    }
    std::fs::set_permissions(&reg, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link = st.d.0.join("link.json");
    std::os::unix::fs::symlink(&reg, &link).unwrap();
    assert!(registry::load(&link, root, me())
        .unwrap_err()
        .contains("is a link"));
    // A folder above it that others can write (L1's rule, now the only one).
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(registry::load(&reg, root, me())
        .unwrap_err()
        .contains("can be written by group or others"));
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
    // No file: no accounts, no complaint.
    assert_eq!(
        registry::load(&st.d.0.join("none.json"), root, me()),
        Ok(vec![])
    );
    // `list` acts as if there were none and names the fix.
    std::fs::set_permissions(&reg, std::fs::Permissions::from_mode(0o666)).unwrap();
    let r = go(&st, &["list"], |_| {});
    assert_eq!(r.code, 0);
    assert!(r.out.contains("no agent accounts"), "{}", r.out);
    assert!(
        r.err.contains("acting as if there are no accounts"),
        "{}",
        r.err
    );
}

#[cfg(target_os = "linux")]
#[test]
fn the_chats_account_is_the_flag_then_agents_default_then_a_refusal() {
    use std::os::unix::fs::PermissionsExt;
    let st = setup("pick", false);
    let a = registry::parse(REGISTRY).unwrap();
    assert_eq!(
        registry::pick(&a, Some("plus"), Some("max")).unwrap().slug,
        "plus"
    );
    assert_eq!(registry::pick(&a, None, Some("max")).unwrap().slug, "max");
    let e = registry::pick(&a, None, None).unwrap_err();
    assert!(e.contains("derm agents add"), "{e}");
    let e = registry::pick(&a, Some("nope"), None).unwrap_err();
    assert!(
        e.contains("does not hold") && e.contains("derm agents add nope"),
        "{e}"
    );
    // agents.default is read beside keys this reader does not know, from a
    // file only the person can write.
    let set = st.d.0.join("settings.json");
    std::fs::write(
        &set,
        r#"{"version":1,"tap":{"on":true},"agents":{"default":"plus"}}"#,
    )
    .unwrap();
    std::fs::set_permissions(&set, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(registry::default_slug(&set), Ok(Some("plus".into())));
    let r = go(&st, &["list"], |_| {});
    assert!(r.out.contains("derm-plus (default)"), "{}", r.out);
    std::fs::set_permissions(&set, std::fs::Permissions::from_mode(0o620)).unwrap();
    assert!(registry::default_slug(&set).is_err());
    std::fs::set_permissions(&set, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&set, r#"{"agents":{"default":"../x"}}"#).unwrap();
    assert!(registry::default_slug(&set).is_err());
}

#[test]
fn slugs_and_labels() {
    for ok in ["a", "max-2", "abcdefghijklmno", "agentx"] {
        assert!(registry::slug_ok(ok), "{ok}");
    }
    for bad in [
        "",
        "A",
        "a_b",
        "a.b",
        "abcdefghijklmnop",
        "é",
        "agent",
        "agents",
        "agent-x",
    ] {
        assert!(!registry::slug_ok(bad), "{bad}");
    }
    assert!(registry::label_ok("Claude Max (work) — Tony's"));
    for bad in [
        "",
        " x",
        "x ",
        "a\nb",
        "a\u{1b}[31m",
        "a\u{202e}b",
        &"x".repeat(121),
    ] {
        assert!(!registry::label_ok(bad), "{bad:?}");
    }
    assert_eq!(registry::shown("a\u{1b}b"), "a?b");
}

// ---- add ----

#[cfg(unix)]
#[test]
fn add_prints_the_installer_line_and_runs_nothing_without_a_yes() {
    let st = setup("add-print", false);
    let r = go(
        &st,
        &[
            "add",
            "work",
            "--subscription",
            "Claude Max 'work'",
            "--print",
        ],
        |_| {},
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains(r#"derm agents installer derm-agents-install && sudo derm-agents-install/install.sh --account work --subscription 'Claude Max '\''work'\'''"#),
        "{}",
        r.out
    );
    let (_, sums) = package_check(PACKAGE).unwrap();
    assert!(
        r.out.contains(&format!(
            "6 files, sha256 of their list {}",
            sha256_hex(sums.as_bytes())
        )),
        "{}",
        r.out
    );
    assert!(r
        .out
        .contains("undo: sudo /usr/local/libexec/derm/agent-user/uninstall.sh --account work"));
    assert_eq!(r.asked, 0);
    assert_eq!(sudo_log(&st), "", "--print runs nothing");
    // No terminal: printed, not run, not asked.
    let r = go(&st, &["add", "work", "--subscription", "x"], |c| {
        c.terminal = false
    });
    assert_eq!((r.code, r.asked), (0, 0));
    assert!(r.out.contains("no terminal: not run"));
    // A no on the terminal.
    let r = go_with(
        &st,
        &["add", "work", "--subscription", "x"],
        PACKAGE,
        false,
        |_| {},
    );
    assert_eq!((r.code, r.asked), (1, 1));
    assert!(r.out.contains("not run"));
    assert_eq!(sudo_log(&st), "");
}

// Reads the registry, which only Linux reads (one reader, run/user/accounts.rs).
#[cfg(target_os = "linux")]
#[test]
fn add_is_refused_inside_a_chat_and_for_a_bad_slug_label_or_a_taken_slug() {
    let st = setup("add-refuse", false);
    let r = go(&st, &["add", "work", "--subscription", "x"], |c| {
        c.in_chat = Some("DERM_CHAT_TOKEN is set".into())
    });
    assert_eq!((r.code, r.asked), (1, 0));
    assert!(r.err.contains("refused inside a chat"), "{}", r.err);
    for args in [
        &["add", "Work", "--subscription", "x"][..],
        &["add", "work", "--subscription", "a\nb"],
        &["add", "work"],
        &["add", "--subscription", "x"],
        &["add", "a", "b", "--subscription", "x"],
        // 16: one more than Windows' 20 characters leave after derm-, the
        // same slug on every system (section 2 as integration narrowed it).
        &["add", "abcdefghijklmnop", "--subscription", "x"],
        // Reserved: wave 5's derm-agent, the group derm-agents, and
        // derm-agent-<x>, wave 5's sudoers file for a person x.
        &["add", "agent", "--subscription", "x"],
        &["add", "agents", "--subscription", "x"],
        &["add", "agent-tonyg", "--subscription", "x"],
    ] {
        assert_eq!(go(&st, args, |_| {}).code, 2, "{args:?}");
    }
    let r = go(&st, &["add", "max", "--subscription", "x"], |_| {});
    assert_eq!(r.code, 1);
    assert!(r.err.contains("set up already"), "{}", r.err);
    assert_eq!(sudo_log(&st), "");
}

/// The installer package runs from a root-owned copy whose hashes are
/// checked there (case 37), whole: `install.sh` reaches a file beside it, as
/// lane L2's passes control to `install-account.sh`.
#[cfg(target_os = "linux")]
#[test]
fn after_a_yes_add_runs_the_installer_package_it_showed_through_sudo() {
    let st = setup("add-run", false);
    let got = st.d.0.join("installer-args");
    let install =
        "#!/bin/bash\nexec \"$(dirname \"${BASH_SOURCE[0]}\")/install-account.sh\" \"$@\"\n";
    let account = format!("#!/bin/bash\nprintf '%s\\n' \"$@\" > '{}'\n", got.display());
    let pkg = [
        ("install.sh", install),
        ("install-account.sh", account.as_str()),
    ];
    let r = go_with(
        &st,
        &["add", "work", "--subscription", "Claude Max (work)"],
        &pkg,
        true,
        |_| {},
    );
    // The stand-in adds no account, so derm says so.
    assert_eq!(r.code, 1, "{} {}", r.out, r.err);
    assert!(r.out.contains("does not hold derm-work"), "{}", r.out);
    assert_eq!(r.asked, 1);
    assert_eq!(
        std::fs::read_to_string(&got).unwrap(),
        "--account\nwork\n--subscription\nClaude Max (work)\n"
    );
    let log = sudo_log(&st);
    assert!(log.starts_with("-- /bin/sh -c set -u"), "{log}");
    assert!(
        log.contains(&format!(
            "{}  install-account.sh",
            sha256_hex(account.as_bytes())
        )),
        "{log}"
    );
    // Root's copy is gone.
    assert!(!std::fs::read_dir(&st.d.0).unwrap().flatten().any(|e| e
        .file_name()
        .to_string_lossy()
        .starts_with("derm-agents-install.")));
}

#[test]
fn the_built_in_package_is_lane_l2s_whole_installer() {
    let (interp, sums) = package_check(PACKAGE).unwrap();
    assert_eq!(interp, "/bin/bash");
    for n in [
        "install.sh",
        "install-account.sh",
        "uninstall.sh",
        "uninstall-account.sh",
        "accounts.py",
        "derm-agents-nft.service",
    ] {
        assert!(sums.lines().any(|l| l.ends_with(&format!("  {n}"))), "{n}");
    }
    // install.sh hands --account to the file beside it.
    assert!(PACKAGE[0].1.contains("install-account.sh"));
    assert!(
        package_check(&[("x.sh", "#!/bin/sh\n")]).is_err(),
        "no install.sh"
    );
    assert!(package_check(&[("install.sh", "#!/bin/sh\n"), ("../x", "")]).is_err());
    assert!(package_check(&[("install.sh", "#!/bin/sh\n"), (".x", "")]).is_err());
}

/// A copy changed between derm's read and root's run is not run.
#[cfg(target_os = "linux")]
#[test]
fn an_installer_changed_before_roots_copy_is_not_run() {
    let st = setup("add-swap", false);
    // This sudo appends to the person's copy of install.sh (in the folder
    // that is its 5th word after `--`) before running: what an agent racing
    // the write would do.
    let home = st.home.clone();
    let sudo = script(
        &st.d.0,
        "sudo-swap",
        &format!(
            "shift\nprintf 'echo planted > {p}\\n' >> \"$5/install.sh\"\nHOME='{h}' exec \"$@\"",
            p = st.d.0.join("planted").display(),
            h = home.display()
        ),
    );
    let fake = [("install.sh", "#!/bin/sh\nexit 0\n")];
    let r = go_with(
        &st,
        &["add", "work", "--subscription", "x"],
        &fake,
        true,
        |c| c.sudo = sudo.clone(),
    );
    assert_eq!(r.code, 1);
    assert!(r.err.contains("the installer stopped"), "{}", r.err);
    assert!(
        !st.d.0.join("planted").exists(),
        "the changed installer ran"
    );
}

#[test]
fn the_installers_interpreter_is_named_by_absolute_path() {
    assert_eq!(interpreter(PACKAGE[0].1), Ok("/bin/bash"));
    assert_eq!(interpreter("#!/bin/sh\n"), Ok("/bin/sh"));
    assert_eq!(interpreter("#!/usr/bin/env bash\n"), Ok("/bin/bash"));
    assert!(interpreter("#!/tmp/x\n").is_err());
    assert!(interpreter("").is_err());
}

#[test]
fn installer_writes_the_package_into_a_new_folder() {
    let d = dir("pkg");
    let to = d.0.join("derm-agents-install");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut y = Yes(false, 0);
    let env = |_: &str| None;
    let mut ctx = Ctx {
        registry: PathBuf::from("/nonexistent"),
        registry_root: PathBuf::from("/"),
        settings: PathBuf::from("/nonexistent"),
        registry_owner: 0,
        sudo: PathBuf::from("/nonexistent"),
        helper: Err("no helper here".into()),
        login_path_first: None,
        sh: PathBuf::from("/bin/sh"),
        path_env: String::new(),
        check_tools: true,
        package: PACKAGE,
        root_tmp: PathBuf::from("/nonexistent"),
        linux: false,
        terminal: false,
        in_chat: None,
        confirm: &mut y,
        env: &env,
        out: &mut out,
        err: &mut err,
    };
    let to_s = to.to_string_lossy().into_owned();
    assert_eq!(run(&mut ctx, &s(&["installer", &to_s])), 0);
    assert_eq!(
        run(&mut ctx, &s(&["installer", &to_s])),
        1,
        "never into a folder that is there"
    );
    assert_eq!(run(&mut ctx, &s(&["installer"])), 2);
    assert_eq!(run(&mut ctx, &s(&["list"])), 2, "Linux only");
    assert_eq!(run(&mut ctx, &s(&[])), 2);
    drop(ctx);
    for (n, t) in PACKAGE {
        assert_eq!(std::fs::read_to_string(to.join(n)).unwrap(), *t, "{n}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(to.join(n)).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, if n.ends_with(".sh") { 0o755 } else { 0o644 }, "{n}");
        }
    }
    assert!(String::from_utf8(err).unwrap().contains("Linux only"));
}

// ---- status ----

// Reads the registry, which only Linux reads (one reader, run/user/accounts.rs).
#[cfg(target_os = "linux")]
#[test]
fn status_reads_presence_of_the_harnesss_own_file_and_warns_of_individual_use() {
    let st = setup("status", false);
    std::fs::create_dir_all(st.home.join(".claude")).unwrap();
    std::fs::write(st.home.join(".claude/.credentials.json"), "{}").unwrap();
    // What `codex login status` leaves with no sign-in (run, Codex 0.167.2),
    // in the account's store (step P3), and an old sign-in in the account's
    // home, which no project's chat reads any more.
    std::fs::create_dir_all(st.home.join("signin/codex")).unwrap();
    std::fs::write(st.home.join("signin/codex/auth.json.lock"), "").unwrap();
    std::fs::write(st.home.join("signin/codex/auth.lock"), "").unwrap();
    std::fs::create_dir_all(st.home.join(".codex")).unwrap();
    std::fs::write(st.home.join(".codex/auth.json"), "").unwrap();
    let r = go(&st, &["status", "--account", "max"], |_| {});
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains(
            r#"derm-max ("Claude Max (work)"): claude-code signed in, codex not signed in"#
        ),
        "{}",
        r.out
    );
    assert!(r.out.contains("derm opened none of them"));
    assert!(r.out.contains("~/signin/codex/auth.json"), "{}", r.out);
    assert!(
        r.out.contains("assume ordinary, individual usage"),
        "{}",
        r.out
    );
    // Asked as the account, non-interactively, by stat(2) only.
    let log = sudo_log(&st);
    assert!(log.contains("-n -H -u derm-max -- /bin/sh -c"), "{log}");
    assert!(!log.contains("cat ") && !log.contains("<"), "{log}");
    // Every account when none is named; the warning only with a Claude sign-in.
    std::fs::remove_file(st.home.join(".claude/.credentials.json")).unwrap();
    let r = go(&st, &["status"], |_| {});
    assert!(r.out.contains("derm-max") && r.out.contains("derm-plus"));
    assert!(!r.out.contains("individual usage"), "{}", r.out);
}

// Reads the registry, which only Linux reads (one reader, run/user/accounts.rs).
#[cfg(target_os = "linux")]
#[test]
fn status_says_unknown_when_sudo_cannot_run_as_the_account() {
    let st = setup("status-nopw", true);
    let r = go(&st, &["status", "--account", "plus"], |_| {});
    assert_eq!(r.code, 0);
    assert!(
        r.out.contains("claude-code unknown, codex unknown"),
        "{}",
        r.out
    );
    assert!(r.out.contains("without a password"));
}

/// inotify (inotify(7)): the events on one file, by name, in a folder.
#[cfg(target_os = "linux")]
struct Watch(i32);

#[cfg(target_os = "linux")]
impl Watch {
    fn on(dir: &Path) -> Watch {
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: plain syscalls on a path this test owns.
        unsafe {
            let fd = libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC);
            assert!(fd >= 0);
            let p = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
            let mask =
                libc::IN_OPEN | libc::IN_ACCESS | libc::IN_CLOSE_NOWRITE | libc::IN_CLOSE_WRITE;
            assert!(libc::inotify_add_watch(fd, p.as_ptr(), mask) >= 0);
            Watch(fd)
        }
    }

    /// (opens, reads, closes after reading only, closes after writing).
    fn counts(&self, name: &str) -> (usize, usize, usize, usize) {
        let mut buf = vec![0u8; 64 * 1024];
        let mut c = (0, 0, 0, 0);
        loop {
            // SAFETY: reads into a buffer of the given size.
            let n = unsafe { libc::read(self.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return c;
            }
            let mut i = 0usize;
            while i < n as usize {
                let mask = u32::from_ne_bytes(buf[i + 4..i + 8].try_into().unwrap());
                let len = u32::from_ne_bytes(buf[i + 12..i + 16].try_into().unwrap()) as usize;
                let raw = &buf[i + 16..i + 16 + len];
                let ev = String::from_utf8_lossy(raw)
                    .trim_end_matches('\0')
                    .to_string();
                if ev == name {
                    c.0 += (mask & libc::IN_OPEN != 0) as usize;
                    c.1 += (mask & libc::IN_ACCESS != 0) as usize;
                    c.2 += (mask & libc::IN_CLOSE_NOWRITE != 0) as usize;
                    c.3 += (mask & libc::IN_CLOSE_WRITE != 0) as usize;
                }
                i += 16 + len;
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: closes the descriptor this value owns.
        unsafe { libc::close(self.0) };
    }
}

/// derm opens no login file: the kernel reports every open of the file
/// (inotify(7), IN_OPEN), and `status` makes none (CB 4.1).
#[cfg(target_os = "linux")]
#[test]
fn status_opens_no_login_file() {
    let st = setup("status-noopen", false);
    let c = st.home.join(".claude");
    let x = st.home.join("signin/codex");
    std::fs::create_dir_all(&c).unwrap();
    std::fs::create_dir_all(&x).unwrap();
    put(&c.join(".credentials.json"), "{\"made-up\":1}");
    put(&x.join("auth.json"), "{\"made-up\":1}");
    let (wc, wx) = (Watch::on(&c), Watch::on(&x));
    let r = go(&st, &["status", "--account", "max"], |_| {});
    assert!(
        r.out.contains("claude-code signed in, codex signed in"),
        "{}",
        r.out
    );
    assert_eq!(wc.counts(".credentials.json"), (0, 0, 0, 0));
    assert_eq!(wx.counts("auth.json"), (0, 0, 0, 0));
}

// ---- login ----

/// The harness's own sign-in runs as the account with derm's environment
/// left out and the tunnel as its proxy; derm then opens nothing it wrote.
#[cfg(target_os = "linux")]
#[test]
fn login_runs_the_harnesss_own_sign_in_as_the_account_and_opens_nothing_it_wrote() {
    let st = setup("login", false);
    let seen = st.d.0.join("seen");
    script(
        &st.d.0,
        "claude",
        &format!(
            "printf '%s\\n' \"$*\" > '{s}.args'\nenv | cut -d= -f1 | sort > '{s}.env'\nprintf '%s %s\\n' \"$HTTPS_PROXY\" \"$https_proxy\" > '{s}.proxy'\nmkdir -p \"$HOME/.claude\"\nprintf made-up > \"$HOME/.claude/.credentials.json\"",
            s = seen.display()
        ),
    );
    let c = st.home.join(".claude");
    std::fs::create_dir_all(&c).unwrap();
    let w = Watch::on(&c);
    let r = go(&st, &["login", "claude-code", "--account", "max"], |_| {});
    assert_eq!(r.code, 0, "{} {}", r.out, r.err);
    assert_eq!(
        std::fs::read_to_string(seen.with_extension("args")).unwrap(),
        "auth login\n"
    );
    // Review AI-3: no login shell, and the sign-in starts through derm
    // landlock with its domain's spec in the environment only.
    let log = sudo_log(&st);
    assert!(
        log.starts_with(
            "-u derm-max -H --preserve-env=DERM_LANDLOCK_SPEC,HTTPS_PROXY,https_proxy -- "
        ),
        "{log}"
    );
    // I-3: the tunnel's URL, with this sign-in's credential, reaches the
    // harness in both spellings through the environment, never on argv.
    let proxy = std::fs::read_to_string(seen.with_extension("proxy")).unwrap();
    let (upper, lower) = proxy.trim_end().split_once(' ').unwrap();
    assert_eq!(upper, lower);
    assert!(
        upper.starts_with("http://derm:") && upper.contains("@127.0.0.1:"),
        "{upper}"
    );
    let helper_log = std::fs::read_to_string(st.d.0.join("helper.log")).unwrap();
    for argv in [&log, &helper_log] {
        assert!(
            !argv.contains("derm:") && !argv.contains("_PROXY=http"),
            "{argv}"
        );
    }
    assert!(!log.split_whitespace().any(|w| w == "-i"), "{log}");
    let helper = std::fs::read_to_string(st.d.0.join("helper.log")).unwrap();
    assert!(
        helper.starts_with("landlock -- /usr/bin/env PATH=")
            && helper
                .contains(":/var/lib/derm/agents/max/.local/bin:/usr/local/bin:/usr/bin:/bin "),
        "{helper}"
    );
    assert!(helper.trim_end().ends_with("|spec=yes"), "{helper}");
    assert!(!helper.contains("{\""), "the spec is not on argv: {helper}");
    // Only derm's fixed variables reach sudo; none of the person's keys.
    let env = std::fs::read_to_string(seen.with_extension("env")).unwrap();
    for k in env.lines() {
        assert!(
            matches!(
                k,
                "PATH"
                    | "HOME"
                    | "PWD"
                    | "SHLVL"
                    | "OLDPWD"
                    | "_"
                    | "HTTPS_PROXY"
                    | "https_proxy"
                    | "NO_PROXY"
                    | "no_proxy"
                    | "TERM"
                    | "COLORTERM"
                    | "LANG"
                    | "LC_ALL"
            ),
            "{k} reached the harness"
        );
    }
    assert!(
        r.out.contains("derm-max has claude-code's sign-in file"),
        "{}",
        r.out
    );
    assert!(r.out.contains("individual usage"));
    // The harness opened the file once, to write it; derm never did.
    assert_eq!(w.counts(".credentials.json"), (1, 0, 0, 1));
}

#[cfg(unix)]
#[test]
fn login_needs_a_terminal_an_account_and_a_known_harness_and_is_refused_in_a_chat() {
    let st = setup("login-refuse", false);
    let r = go(&st, &["login", "claude-code"], |_| {});
    assert_eq!(r.code, 1);
    assert!(r.err.contains("derm agents add"), "{}", r.err);
    let r = go(&st, &["login", "pi", "--account", "max"], |_| {});
    assert_eq!(r.code, 2);
    assert!(r.err.contains("known: claude-code, codex"), "{}", r.err);
    let r = go(&st, &["login", "codex", "--account", "max"], |c| {
        c.terminal = false
    });
    assert_eq!(r.code, 1);
    let r = go(&st, &["login", "codex", "--account", "max"], |c| {
        c.in_chat = Some("x".into())
    });
    assert_eq!(r.code, 1);
    assert_eq!(sudo_log(&st), "");
}

#[cfg(target_os = "linux")]
#[test]
fn codex_signs_in_with_its_device_flow() {
    let st = setup("login-codex", false);
    // Step P3: the sign-in goes into the account's store, which the
    // installer makes; without it nothing runs.
    let r = go(&st, &["login", "codex", "--account", "plus"], |_| {});
    assert_eq!(r.code, 1);
    assert!(
        r.err.contains("sign-in store") && r.err.contains("missing"),
        "{}",
        r.err
    );
    assert!(
        !sudo_log(&st).contains("landlock"),
        "the sign-in did not start"
    );
    std::fs::create_dir_all(st.home.join("signin/codex")).unwrap();
    let seen = st.d.0.join("seen.args");
    script(
        &st.d.0,
        "codex",
        &format!("printf '%s\\n' \"$*\" > '{}'\nexit 1", seen.display()),
    );
    let r = go(&st, &["login", "codex", "--account", "plus"], |_| {});
    assert_eq!(r.code, 1);
    assert!(r.err.contains("the sign-in ended"), "{}", r.err);
    assert_eq!(
        std::fs::read_to_string(&seen).unwrap(),
        "login --device-auth\n"
    );
    assert!(
        r.out
            .contains("has no codex sign-in file (~/signin/codex/auth.json)"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("individual usage"));
    // Codex writes `$CODEX_HOME/auth.json` (note CD 2.2): its home is the
    // store, a path on `env`'s argv, not a secret.
    let helper = std::fs::read_to_string(st.d.0.join("helper.log")).unwrap();
    assert!(
        helper.contains(
            " CODEX_HOME=/var/lib/derm/agents/plus/signin/codex codex login --device-auth"
        ),
        "{helper}"
    );
}

// ---- the tunnel ----

#[test]
fn the_tunnel_reads_one_connect_target() {
    use tunnel::target;
    assert_eq!(
        target("CONNECT Platform.Claude.com:443 HTTP/1.1\r\nHost: x\r\n\r\n").as_deref(),
        Some("platform.claude.com:443")
    );
    for bad in [
        "GET http://platform.claude.com/ HTTP/1.1\r\n\r\n",
        "CONNECT platform.claude.com HTTP/1.1\r\n\r\n",
        "CONNECT platform.claude.com:443 HTTP/1.1 x\r\n\r\n",
        "CONNECT a@platform.claude.com:443 HTTP/1.1\r\n\r\n",
        "CONNECT [::1]:443 HTTP/1.1\r\n\r\n",
        "CONNECT :443 HTTP/1.1\r\n\r\n",
    ] {
        assert_eq!(target(bad), None, "{bad}");
    }
}

#[test]
fn the_tunnel_never_dials_an_address_that_is_not_public() {
    for a in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
    ] {
        assert!(tunnel::non_public(a.parse().unwrap()), "{a}");
    }
    for a in ["1.1.1.1", "160.79.104.10", "2606:4700::1111"] {
        assert!(!tunnel::non_public(a.parse().unwrap()), "{a}");
    }
}

/// An admitted CONNECT passes the bytes both ways untouched; any other
/// target gets 403 and is named afterwards.
#[test]
fn the_tunnel_admits_only_the_sign_in_hosts_and_passes_bytes_unread() {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_addr = up.local_addr().unwrap();
    let echo = std::thread::spawn(move || {
        let (mut s, _) = up.accept().unwrap();
        let mut b = [0u8; 5];
        s.read_exact(&mut b).unwrap();
        s.write_all(&b.iter().rev().copied().collect::<Vec<_>>())
            .unwrap();
    });
    let allow = vec!["platform.claude.com:443".to_string()];
    let refused = std::sync::Mutex::new(Vec::new());
    let cred = derm_egress::auth::ProxyCredential::mint().unwrap();
    let pa = format!("Proxy-Authorization: {}\r\n", cred.header_value());
    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = front.local_addr().unwrap();
    std::thread::scope(|sc| {
        sc.spawn(|| {
            for _ in 0..2 {
                let (c, _) = front.accept().unwrap();
                tunnel::serve(c, &allow, &refused, Some(&cred), &|t: &str| {
                    assert_eq!(t, "platform.claude.com:443");
                    TcpStream::connect(up_addr).map_err(|e| e.to_string())
                });
            }
        });
        let mut c = TcpStream::connect(addr).unwrap();
        // The first bytes of the TLS handshake may come with the head.
        c.write_all(
            format!("CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: platform.claude.com:443\r\n{pa}\r\n")
                .as_bytes(),
        )
        .unwrap();
        c.write_all(b"\x16\x03\x01").unwrap();
        let mut head = [0u8; 39];
        c.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"HTTP/1.1 200 Connection established\r\n\r\n");
        c.write_all(b"\x00\x01").unwrap();
        let mut back = [0u8; 5];
        c.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"\x01\x00\x01\x03\x16");
        drop(c);
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(format!("CONNECT statsig.anthropic.com:443 HTTP/1.1\r\n{pa}\r\n").as_bytes())
            .unwrap();
        let mut r = String::new();
        c.read_to_string(&mut r).unwrap();
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    });
    echo.join().unwrap();
    assert_eq!(*refused.lock().unwrap(), ["statsig.anthropic.com:443"]);
}

/// The person's own proxy, read as curl reads it.
#[test]
fn the_tunnel_takes_the_persons_http_proxy_and_its_no_proxy() {
    let env = |vars: &'static [(&'static str, &'static str)]| {
        move |k: &str| {
            vars.iter()
                .find(|(a, _)| *a == k)
                .map(|(_, v)| v.to_string())
        }
    };
    assert_eq!(tunnel::upstream_from(&env(&[])), Ok(None));
    let u = tunnel::upstream_from(&env(&[
        ("HTTPS_PROXY", "http://proxy.corp:3128/"),
        ("NO_PROXY", "localhost, .internal.corp,openai.com:443"),
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(u.addr, "proxy.corp:3128");
    assert!(
        u.skips("auth.openai.com") && u.skips("a.internal.corp") && !u.skips("platform.claude.com")
    );
    assert!(
        !u.skips("notopenai.com"),
        "a domain, not a suffix of letters"
    );
    // The lowercase variable wins; a port-less proxy is port 80.
    let u = tunnel::upstream_from(&env(&[
        ("https_proxy", "proxy:8080"),
        ("HTTPS_PROXY", "http://x:1"),
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(u.addr, "proxy:8080");
    assert_eq!(
        tunnel::upstream_from(&env(&[("https_proxy", "http://proxy")]))
            .unwrap()
            .unwrap()
            .addr,
        "proxy:80"
    );
    assert!(
        tunnel::upstream_from(&env(&[("https_proxy", "http://*"), ("no_proxy", "*")]))
            .unwrap()
            .unwrap()
            .skips("anything")
    );
    for bad in [
        "http://user:pw@proxy:3128",
        "socks5://proxy:1080",
        "https://proxy:443",
        "http://:3128",
    ] {
        let vars: &'static [(&'static str, &'static str)] =
            Box::leak(vec![("https_proxy", bad)].into_boxed_slice());
        assert!(tunnel::upstream_from(&env(vars)).is_err(), "{bad}");
    }
}

/// Through the person's proxy: its 200 opens the stream; any other answer is
/// a 502 to the harness and named afterwards.
#[test]
fn the_tunnel_goes_on_through_the_persons_proxy_and_names_its_refusal() {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    // A stand-in proxy: 200 for platform.claude.com, 403 for the rest, the
    // way this workspace's egress proxy answers (run, 20 Nov 2026).
    let px = TcpListener::bind("127.0.0.1:0").unwrap();
    let px_addr = px.local_addr().unwrap().to_string();
    let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let h2 = heads.clone();
    std::thread::spawn(move || {
        for c in px.incoming().flatten() {
            let h2 = h2.clone();
            std::thread::spawn(move || {
                let mut c = c;
                let mut b = vec![0u8; 512];
                let n = c.read(&mut b).unwrap();
                let head = String::from_utf8_lossy(&b[..n]).to_string();
                assert!(
                    !head.to_ascii_lowercase().contains("proxy-authorization"),
                    "the sign-in's credential went on to the person's proxy: {head}"
                );
                h2.lock()
                    .unwrap()
                    .push(head.lines().next().unwrap_or("").to_string());
                if head.starts_with("CONNECT platform.claude.com:443 ") {
                    c.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
                    let mut x = [0u8; 3];
                    c.read_exact(&mut x).unwrap();
                    c.write_all(&x).unwrap();
                } else {
                    c.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                }
            });
        }
    });
    let up = tunnel::Upstream {
        addr: px_addr.clone(),
        no_proxy: vec![],
    };
    let t = tunnel::Tunnel::start(&["platform.claude.com", "auth.openai.com"], Some(up)).unwrap();
    let pa = t.authorization();
    let connect = |target: &str| {
        let mut c = TcpStream::connect(("127.0.0.1", t.port)).unwrap();
        c.write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {pa}\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        c
    };
    let mut c = connect("platform.claude.com:443");
    let mut head = [0u8; 39];
    c.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 Connection established\r\n\r\n");
    c.write_all(b"abc").unwrap();
    let mut back = [0u8; 3];
    c.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"abc");
    let mut c = connect("auth.openai.com:443");
    let mut r = String::new();
    c.read_to_string(&mut r).unwrap();
    assert!(r.starts_with("HTTP/1.1 502"), "{r}");
    assert_eq!(
        t.failed(),
        [format!(
            "auth.openai.com:443: the proxy {px_addr} answered \"HTTP/1.1 403 Forbidden\""
        )]
    );
    let seen = heads.lock().unwrap().clone();
    assert_eq!(
        seen,
        [
            "CONNECT platform.claude.com:443 HTTP/1.1",
            "CONNECT auth.openai.com:443 HTTP/1.1"
        ]
    );
    assert!(t.refused().is_empty());
}

// ---- the broker in an agent account's chat (secret/chain.rs) ----

mod chain_for_accounts {
    use crate::secret::chain::{self, Input};
    use derm_egress::secrets::{Entry, From};

    fn entry(id: &str, from: From) -> Entry {
        Entry {
            placement: None,
            id: id.into(),
            hosts: vec!["api.github.com".into()],
            from,
            note: None,
        }
    }

    fn input<'a>(tier: &'a str, boundary: &'a str, sec: &'a [(Entry, String)]) -> Input<'a> {
        Input {
            harness: "claude-code",
            tier,
            boundary,
            secrets: sec,
            egress_url: Some("http://127.0.0.1:41000"),
            ca_file: "/run/derm-agent/1000/chat/derm-ca.pem",
            bundle_file: "/run/derm-agent/1000/chat/derm-bundle.pem",
            fingerprint: "0123456789abcdef0123",
        }
    }

    #[test]
    fn an_agent_accounts_chat_is_brokered_and_no_other_unbounded_chat_is() {
        assert!(chain::brokered_for("whole", "none", Some("derm-max")));
        assert!(!chain::brokered_for("whole", "none", None));
        assert!(!chain::brokered_for("whole", "sbx", Some("derm-max")));
        assert!(!chain::brokered_for("standard", "sbx", Some("derm-max")));
        assert_eq!(
            chain::brokered("whole", "none"),
            chain::brokered_for("whole", "none", None)
        );
        assert!(chain::brokered("whole", "srt") && chain::brokered("standard", "none"));
    }

    #[test]
    fn an_api_key_in_an_agent_accounts_chat_goes_out_through_derm_egress() {
        let sec = vec![(
            entry("gh", From::Env("GH_TOKEN".into())),
            "dermsecret_gh_0123456789abcdef".to_string(),
        )];
        let p = chain::plan_for(&input("whole", "none", &sec), Some("derm-max")).unwrap();
        assert!(p.brokered);
        let get = |k: &str| p.env.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
        assert_eq!(get("GH_TOKEN"), Some("dermsecret_gh_0123456789abcdef"));
        assert_eq!(get("HTTPS_PROXY"), Some("http://127.0.0.1:41000"));
        assert_eq!(get("NO_PROXY"), Some("localhost,127.0.0.1,::1"));
        assert!(p.remove.is_empty());
        assert!(p.srt_network.is_none());
        let line = p.line.unwrap();
        assert!(
            line.contains("as derm-max, whose own network is loopback only"),
            "{line}"
        );
        // The same chat with no account is not brokered, as before.
        let p = chain::plan(&input("whole", "none", &sec)).unwrap();
        assert!(!p.brokered);
        assert_eq!(p.remove, ["GH_TOKEN"]);
    }

    #[test]
    fn a_claude_subscription_token_is_never_brokered_into_an_agent_accounts_chat() {
        let sec = vec![(
            entry("claude", From::Env("CLAUDE_CODE_OAUTH_TOKEN".into())),
            "dermsecret_claude_0123456789abcdef".to_string(),
        )];
        let e = chain::plan_for(&input("whole", "none", &sec), Some("derm-max")).unwrap_err();
        assert!(e.contains("derm agents login claude-code"), "{e}");
        // Under sbx nothing is brokered at all (case 218), as before.
        assert!(
            !chain::plan_for(&input("whole", "sbx", &sec), Some("derm-max"))
                .unwrap()
                .brokered
        );
    }
}

/// I-3 (plan step P10; note CC section 6): while a sign-in runs, its tunnel
/// takes only the client it handed its credential to. Any other local
/// client (another account, a chat, the person's own program) gets 407
/// before its target is read, nothing is dialled, and the refusal is named
/// once. The URL the sign-in gets carries the credential; the shown one
/// does not.
#[test]
fn the_sign_in_tunnel_takes_only_the_client_holding_its_credential() {
    use std::io::Read;
    use std::net::TcpStream;
    let t = tunnel::Tunnel::start(&["platform.claude.com"], None).unwrap();
    let other = derm_egress::auth::ProxyCredential::mint().unwrap();
    for extra in [
        String::new(),
        format!("Proxy-Authorization: {}\r\n", other.header_value()),
        format!(
            "Proxy-Authorization: {}\r\nProxy-Authorization: {}\r\n",
            t.authorization(),
            t.authorization()
        ),
        format!("Authorization: {}\r\n", t.authorization()),
    ] {
        let mut c = TcpStream::connect(("127.0.0.1", t.port)).unwrap();
        c.write_all(
            format!("CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: platform.claude.com:443\r\n{extra}\r\n")
                .as_bytes(),
        )
        .unwrap();
        let mut r = String::new();
        c.read_to_string(&mut r).unwrap();
        assert!(r.starts_with("HTTP/1.1 407 "), "{extra:?}: {r}");
        assert!(r.contains("Proxy-Authenticate: Basic"), "{r}");
    }
    assert_eq!(t.refused(), [tunnel::NO_CREDENTIAL]);
    assert!(t.failed().is_empty(), "nothing was dialled");
    let url = t.url();
    assert!(
        url.starts_with("http://derm:") && url.ends_with(&format!("@127.0.0.1:{}", t.port)),
        "{url}"
    );
    assert_eq!(
        t.shown_url(),
        format!("http://<credential>@127.0.0.1:{}", t.port)
    );
}

/// Request PC R5: `derm agents status` names the account's audit rules file
/// by presence, never reading it.
#[test]
fn pc_r5_status_names_the_accounts_audit_rules_file_by_presence() {
    let d = std::env::temp_dir().join(format!("derm-r5-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&d).unwrap();
    let line = super::audit_rules_line(&d, 996);
    assert!(
        line.contains("none") && line.contains("50-derm-996.rules"),
        "{line}"
    );
    std::fs::write(d.join("50-derm-996.rules"), "-a never,exit\n").unwrap();
    let line = super::audit_rules_line(&d, 996);
    assert!(
        line.contains("is there") && line.contains("auditctl -l | grep uid=996"),
        "{line}"
    );
    let line = super::audit_rules_line(&d.join("absent"), 996);
    assert!(line.contains("no auditd"), "{line}");
    let _ = std::fs::remove_dir_all(&d);
}
