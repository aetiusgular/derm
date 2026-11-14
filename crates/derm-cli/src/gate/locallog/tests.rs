use std::path::{Path, PathBuf};
use std::time::Duration;

use derm_core::audit_chain;
use serde_json::{json, Map};

use super::*;

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "derm-6b-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    p
}

fn event(chat: &str, kind: &str, n: usize) -> AdapterEvent {
    let mut detail = Map::new();
    detail.insert("toolUseId".into(), json!(format!("toolu_{n}")));
    AdapterEvent {
        id: format!("claude-code-toolu_{n}"),
        chat_id: chat.into(),
        harness: "claude-code".into(),
        kind: kind.into(),
        summary: "Bash".into(),
        detail,
    }
}

fn env_home(home: &Path) -> Env {
    #[cfg(windows)]
    let k = "USERPROFILE";
    #[cfg(not(windows))]
    let k = "HOME";
    Env::of(&[(k, home.to_str().unwrap())])
}

fn lines(home: &Path, chat: &str) -> Vec<String> {
    std::fs::read_to_string(log_path(home, chat))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn verify(lines: &[String]) {
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    audit_chain::verify(&refs, None, None).unwrap();
}

#[test]
fn a_record_the_daemon_took_is_not_written_again() {
    let home = scratch("taken");
    let o = after_post(&event("s-1", "approval", 0), &env_home(&home), &home, true);
    assert_eq!(o, Outcome::Skipped);
    assert!(!home.join(".derm").exists());
}

#[test]
fn records_the_daemon_did_not_take_chain_in_the_chats_file() {
    let home = scratch("chain");
    let env = env_home(&home);
    for (n, kind) in ["approval", "tool.call", "install.call", "approval"]
        .iter()
        .enumerate()
    {
        let o = after_post(&event("s-1", kind, n), &env, &home, false);
        assert_eq!(o, Outcome::Appended { seq: n as u64 });
    }
    let l = lines(&home, "s-1");
    assert_eq!(l.len(), 4);
    verify(&l);
    let first = audit_chain::parse(&l[0]).unwrap();
    assert_eq!(first.kind, "approval");
    assert_eq!(first.record["chatId"], "s-1");
    assert_eq!(first.record["source"], "adapter");
    assert_eq!(first.record["detail"]["trust"], "client");
    assert!(first.record["at"].as_u64().unwrap() > 0);
    // Another chat, another file and another chain.
    after_post(&event("s-2", "approval", 9), &env, &home, false);
    assert_eq!(lines(&home, "s-2").len(), 1);
    verify(&lines(&home, "s-2"));
}

#[test]
fn the_record_is_the_event_post_event_sends() {
    let mut e = event("s-1", "approval", 0);
    e.summary = "x".repeat(300);
    let r = record(&e, 7);
    let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["at", "chatId", "detail", "harness", "id", "kind", "source", "summary"]
    );
    assert_eq!(r["summary"].as_str().unwrap().len(), 200);
    assert_eq!(r["at"], 7);
    // A surrogate pair cut in half at 200 units loses the half, as
    // `post_event`'s summary does.
    e.summary = format!("{}😀", "a".repeat(199));
    assert_eq!(record(&e, 0)["summary"].as_str().unwrap(), "a".repeat(199));
}

#[test]
fn a_float_in_a_record_is_written_as_text_so_the_call_is_not_denied() {
    let home = scratch("float");
    let mut e = event("s-1", "tool.call", 0);
    e.detail
        .insert("durationS".into(), json!({"v": [1.5e-7, 2, -0.0]}));
    assert_eq!(
        after_post(&e, &env_home(&home), &home, false),
        Outcome::Appended { seq: 0 }
    );
    let l = lines(&home, "s-1");
    verify(&l);
    let rec = audit_chain::parse(&l[0]).unwrap().record;
    assert_eq!(
        rec["detail"]["durationS"]["v"],
        json!(["1.5e-7", 2, "-0.0"])
    );
}

#[test]
fn a_home_that_is_not_absolute_fails() {
    let o = after_post(
        &event("s-1", "approval", 0),
        &Env::of(&[]),
        Path::new("/"),
        false,
    );
    assert!(
        matches!(o, Outcome::Failed(ref w) if w.contains("no home folder")),
        "{o:?}"
    );
    #[cfg(not(windows))]
    let o = after_post(
        &event("s-1", "approval", 0),
        &Env::of(&[("HOME", "relative/home")]),
        Path::new("/"),
        false,
    );
    assert!(matches!(o, Outcome::Failed(_)), "{o:?}");
}

#[test]
fn a_missing_home_is_never_made() {
    let home = scratch("nohome").join("missing");
    let o = after_post(&event("s-1", "approval", 0), &env_home(&home), &home, false);
    assert!(
        matches!(o, Outcome::Failed(ref w) if w.contains("is not a folder")),
        "{o:?}"
    );
    assert!(!home.exists());
}

#[test]
fn a_torn_or_foreign_last_line_stops_the_chain_and_leaves_the_file() {
    let home = scratch("torn");
    let env = env_home(&home);
    after_post(&event("s-1", "approval", 0), &env, &home, false);
    let path = log_path(&home, "s-1");
    let good = std::fs::read(&path).unwrap();
    // A line cut mid-write: no newline at the end.
    std::fs::write(&path, [&good[..], b"{\"v\":2,\"seq\""].concat()).unwrap();
    let o = after_post(&event("s-1", "tool.call", 1), &env, &home, false);
    assert!(
        matches!(o, Outcome::Failed(ref w) if w.contains("does not end with a newline")),
        "{o:?}"
    );
    // A line that is not chain v2.
    std::fs::write(&path, [&good[..], b"not json\n"].concat()).unwrap();
    let o = after_post(&event("s-1", "tool.call", 1), &env, &home, false);
    assert!(
        matches!(o, Outcome::Failed(ref w) if w.contains("not chain v2")),
        "{o:?}"
    );
    // An empty last line.
    std::fs::write(&path, [&good[..], b"\n"].concat()).unwrap();
    let o = after_post(&event("s-1", "tool.call", 1), &env, &home, false);
    assert!(matches!(o, Outcome::Failed(_)), "{o:?}");
    assert_eq!(std::fs::read(&path).unwrap(), [&good[..], b"\n"].concat());
    // Moved away, the chat starts a new chain.
    std::fs::rename(&path, path.with_extension("old")).unwrap();
    assert_eq!(
        after_post(&event("s-1", "tool.call", 1), &env, &home, false),
        Outcome::Appended { seq: 0 }
    );
}

#[test]
fn a_long_last_line_is_found_past_the_first_read() {
    let home = scratch("long");
    let env = env_home(&home);
    let mut e = event("s-1", "approval", 0);
    e.detail.insert("pad".into(), json!("p".repeat(200_000)));
    after_post(&e, &env, &home, false);
    after_post(&event("s-1", "tool.call", 1), &env, &home, false);
    let l = lines(&home, "s-1");
    assert_eq!(l.len(), 2);
    verify(&l);
}

#[test]
fn a_held_lock_fails_at_the_deadline_and_writes_nothing() {
    let home = scratch("held");
    let env = env_home(&home);
    after_post(&event("s-1", "approval", 0), &env, &home, false);
    let path = log_path(&home, "s-1");
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(&path)
        .unwrap();
    // Read before the lock: on Windows the lock is mandatory, and another
    // handle's read fails with error 33 while it is held (CI's Windows job,
    // run 43340976574; `a_plain_reader_meets_error_33_while_a_hook_holds_the_lock`).
    let before = std::fs::read(&path).unwrap();
    holder.lock().unwrap();
    let t = std::time::Instant::now();
    let r = append(
        &home,
        &event("s-1", "tool.call", 1),
        1,
        Duration::from_millis(150),
    );
    let took = t.elapsed();
    assert!(
        r.as_ref().is_err_and(|w| w.contains("held its lock")),
        "{r:?}"
    );
    assert!(took >= Duration::from_millis(150), "{took:?}");
    assert!(took < Duration::from_millis(1500), "{took:?}");
    holder.unlock().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    holder.lock().unwrap();
    // Released inside the deadline, the append goes through.
    let h = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        drop(holder);
    });
    assert_eq!(
        append(
            &home,
            &event("s-1", "tool.call", 1),
            1,
            Duration::from_millis(2000)
        ),
        Ok(1)
    );
    h.join().unwrap();
}

#[test]
fn threads_of_one_chat_append_whole_chained_lines() {
    let home = scratch("threads");
    let env = env_home(&home);
    let hs: Vec<_> = (0..8)
        .map(|t| {
            let home = home.clone();
            let env = env.clone();
            std::thread::spawn(move || {
                for i in 0..50 {
                    let o = after_post(&event("s-1", "approval", t * 1000 + i), &env, &home, false);
                    assert!(matches!(o, Outcome::Appended { .. }), "{o:?}");
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let l = lines(&home, "s-1");
    assert_eq!(l.len(), 400);
    verify(&l);
}

/// The child half of the next test: appends when its variable names a home.
#[test]
fn child_appends_when_asked() {
    let Some(home) = std::env::var_os("DERM_6B_CHILD_HOME") else {
        return;
    };
    let home = PathBuf::from(home);
    let env = env_home(&home);
    for i in 0..100 {
        let o = after_post(&event("s-1", "tool.call", i), &env, &home, false);
        assert!(matches!(o, Outcome::Appended { .. }), "{o:?}");
    }
}

/// Note AZ B5 with this writer: processes, not threads, each with its own
/// open of the file, as a chat's hooks are.
#[test]
fn processes_of_one_chat_append_whole_chained_lines() {
    let home = scratch("procs");
    let me = std::env::current_exe().unwrap();
    let kids: Vec<_> = (0..4)
        .map(|_| {
            std::process::Command::new(&me)
                .args([
                    "gate::locallog::tests::child_appends_when_asked",
                    "--exact",
                    "--test-threads=1",
                ])
                .env("DERM_6B_CHILD_HOME", &home)
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for mut k in kids {
        assert!(k.wait().unwrap().success());
    }
    let l = lines(&home, "s-1");
    assert_eq!(l.len(), 400);
    verify(&l);
}

#[test]
fn denies_only_a_failed_append_in_the_light_tier() {
    let failed = Outcome::Failed("x".into());
    let cwd = Path::new("/");
    assert!(denies(&failed, &Env::of(&[]), cwd).is_some_and(|w| w.contains("fails closed")));
    let token = "a".repeat(64);
    let in_a_run = Env::of(&[("DERM_CHAT_TOKEN", token.as_str())]);
    // A token under a real `derm run`: the record was the daemon's.
    crate::gate::daemon::UNDER_DERM_RUN.with(|u| u.set(Some(true)));
    assert_eq!(denies(&failed, &in_a_run, cwd), None);
    // The same token with no `derm run` above the hook, as a project's
    // settings can set it (W6C-S4): still the light tier.
    crate::gate::daemon::UNDER_DERM_RUN.with(|u| u.set(Some(false)));
    assert!(denies(&failed, &in_a_run, cwd).is_some_and(|w| w.contains("fails closed")));
    crate::gate::daemon::UNDER_DERM_RUN.with(|u| u.set(None));
    assert_eq!(
        denies(&Outcome::Appended { seq: 0 }, &Env::of(&[]), cwd),
        None
    );
    assert_eq!(denies(&Outcome::Skipped, &Env::of(&[]), cwd), None);
}

#[test]
fn a_chat_id_that_names_a_parent_stays_in_the_folder() {
    let home = scratch("dots");
    let env = env_home(&home);
    for chat in ["..", ".", "", "../../x", "/etc/passwd"] {
        let o = after_post(&event(chat, "approval", 0), &env, &home, false);
        assert!(matches!(o, Outcome::Appended { .. }), "{chat}: {o:?}");
    }
    let mut names: Vec<String> = std::fs::read_dir(folder(&home))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut want = [
        "_...jsonl",
        "_..jsonl",
        "_.._.._x.jsonl",
        "_.jsonl",
        "_etc_passwd.jsonl",
    ];
    want.sort();
    assert_eq!(names, want);
    assert_eq!(std::fs::read_dir(home.join(".derm")).unwrap().count(), 1);
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().mode() & 0o777
    }

    #[test]
    fn the_folder_is_0700_and_the_file_0600() {
        let home = scratch("modes");
        after_post(&event("s-1", "approval", 0), &env_home(&home), &home, false);
        assert_eq!(mode(&home.join(".derm")), 0o700);
        assert_eq!(mode(&folder(&home)), 0o700);
        assert_eq!(mode(&log_path(&home, "s-1")), 0o600);
    }

    #[test]
    fn a_loose_local_folder_or_file_is_tightened() {
        let home = scratch("loose");
        let env = env_home(&home);
        after_post(&event("s-1", "approval", 0), &env, &home, false);
        std::fs::set_permissions(folder(&home), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(
            log_path(&home, "s-1"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(
            after_post(&event("s-1", "tool.call", 1), &env, &home, false),
            Outcome::Appended { seq: 1 }
        );
        assert_eq!(mode(&folder(&home)), 0o700);
        assert_eq!(mode(&log_path(&home, "s-1")), 0o600);
    }

    #[test]
    fn an_existing_derm_folder_keeps_its_mode_unless_others_can_write_it() {
        let home = scratch("dermmode");
        std::fs::create_dir(home.join(".derm")).unwrap();
        std::fs::set_permissions(home.join(".derm"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let env = env_home(&home);
        assert!(matches!(
            after_post(&event("s-1", "approval", 0), &env, &home, false),
            Outcome::Appended { .. }
        ));
        assert_eq!(mode(&home.join(".derm")), 0o755);
        std::fs::set_permissions(home.join(".derm"), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let o = after_post(&event("s-1", "approval", 1), &env, &home, false);
        assert!(
            matches!(o, Outcome::Failed(ref w) if w.contains("written by others")),
            "{o:?}"
        );
    }

    #[test]
    fn links_at_the_folders_or_the_file_are_refused() {
        let home = scratch("links");
        let elsewhere = scratch("elsewhere");
        let env = env_home(&home);
        // ~/.derm as a link.
        std::os::unix::fs::symlink(&elsewhere, home.join(".derm")).unwrap();
        let o = after_post(&event("s-1", "approval", 0), &env, &home, false);
        assert!(
            matches!(o, Outcome::Failed(ref w) if w.contains("a link is refused")),
            "{o:?}"
        );
        std::fs::remove_file(home.join(".derm")).unwrap();
        // ~/.derm/local as a link.
        std::fs::create_dir(home.join(".derm")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, folder(&home)).unwrap();
        let o = after_post(&event("s-1", "approval", 0), &env, &home, false);
        assert!(matches!(o, Outcome::Failed(_)), "{o:?}");
        std::fs::remove_file(folder(&home)).unwrap();
        // The log as a link to a file of yours.
        std::fs::create_dir(folder(&home)).unwrap();
        let target = elsewhere.join("startup.sh");
        std::fs::write(&target, "echo hi\n").unwrap();
        std::os::unix::fs::symlink(&target, log_path(&home, "s-1")).unwrap();
        let o = after_post(&event("s-1", "approval", 0), &env, &home, false);
        assert!(
            matches!(o, Outcome::Failed(ref w) if w.contains("a link is refused")),
            "{o:?}"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "echo hi\n");
        assert!(std::fs::read_dir(&elsewhere).unwrap().count() == 1);
    }

    #[test]
    fn a_hard_link_to_another_file_is_refused() {
        let home = scratch("hard");
        let env = env_home(&home);
        std::fs::create_dir_all(folder(&home)).unwrap();
        let target = home.join("startup.sh");
        std::fs::write(&target, "echo hi\n").unwrap();
        std::fs::hard_link(&target, log_path(&home, "s-1")).unwrap();
        let o = after_post(&event("s-1", "approval", 0), &env, &home, false);
        assert!(
            matches!(o, Outcome::Failed(ref w) if w.contains("hard link")),
            "{o:?}"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "echo hi\n");
    }

    #[test]
    fn a_fifo_at_the_files_place_does_not_block_and_is_refused() {
        let home = scratch("fifo");
        let env = env_home(&home);
        std::fs::create_dir_all(folder(&home)).unwrap();
        let p = log_path(&home, "s-1");
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: a valid C string and a mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t = std::time::Instant::now();
        let o = after_post(&event("s-1", "approval", 0), &env, &home, false);
        assert!(
            matches!(o, Outcome::Failed(ref w) if w.contains("not a plain file")),
            "{o:?}"
        );
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_file_is_held_with_its_own_lock_not_the_process_s() {
        // flock locks an open file description: a second open in this same
        // process waits, so threads and processes are treated alike.
        let home = scratch("ofd");
        after_post(&event("s-1", "approval", 0), &env_home(&home), &home, false);
        let p = log_path(&home, "s-1");
        let a = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&p)
            .unwrap();
        let b = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&p)
            .unwrap();
        a.lock().unwrap();
        assert!(matches!(
            b.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        assert_eq!(std::fs::symlink_metadata(&p).unwrap().nlink(), 1);
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    /// Windows test w6, WW6-6: on Windows the light tier refused only a
    /// reparse point. `~\.derm\local` that Everyone may write and a log
    /// with a second name are refused, and a log others may read is made
    /// the user's alone, as on Unix (`check_file`, `own_folder`).
    #[test]
    fn ww6_6_the_folder_and_the_file_are_checked_as_on_unix() {
        use derm_core::platform::windows as w;
        let me = w::effective_user();
        // A log others may read: appended, then the user's alone.
        let home = scratch("ww66a");
        let env = env_home(&home);
        after_post(&event("s-1", "approval", 0), &env, &home, false);
        let p = log_path(&home, "s-1");
        w::set_dacl_sddl(&p, &format!("D:(A;;FA;;;{me})(A;;FR;;;WD)")).unwrap();
        assert!(!w::is_private_path(&p));
        assert_eq!(
            after_post(&event("s-1", "tool.call", 1), &env, &home, false),
            Outcome::Appended { seq: 1 }
        );
        assert!(w::is_private_path(&p));
        // A second name: refused.
        std::fs::hard_link(&p, home.join("other-name.txt")).unwrap();
        let r = after_post(&event("s-1", "tool.call", 2), &env, &home, false);
        assert!(
            matches!(&r, Outcome::Failed(why) if why.contains("names")),
            "{r:?}"
        );
        // The folder: Everyone may write it, refused.
        let home = scratch("ww66b");
        let env = env_home(&home);
        after_post(&event("s-2", "approval", 0), &env, &home, false);
        let local = home.join(".derm").join("local");
        w::set_dacl_sddl(&local, &format!("D:(A;OICI;FA;;;{me})(A;OICI;FA;;;WD)")).unwrap();
        let r = after_post(&event("s-2", "tool.call", 1), &env, &home, false);
        assert!(
            matches!(&r, Outcome::Failed(why) if why.contains("written by others")),
            "{r:?}"
        );
    }

    #[test]
    fn a_read_and_append_handle_takes_the_lock_where_an_append_only_one_cannot() {
        let home = scratch("winlock");
        after_post(&event("s-1", "approval", 0), &env_home(&home), &home, false);
        let p = log_path(&home, "s-1");
        let only = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        let e = only.try_lock();
        assert!(matches!(e, Err(std::fs::TryLockError::Error(_))), "{e:?}");
        let both = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&p)
            .unwrap();
        both.try_lock().unwrap();
    }

    #[test]
    fn a_handle_without_write_sharing_is_waited_for_then_refused() {
        use std::os::windows::fs::OpenOptionsExt;
        let home = scratch("winshare");
        let env = env_home(&home);
        after_post(&event("s-1", "approval", 0), &env, &home, false);
        let p = log_path(&home, "s-1");
        // FILE_SHARE_READ (1) only: an editor's or an indexer's open.
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&p)
            .unwrap();
        let r = append(
            &home,
            &event("s-1", "tool.call", 1),
            1,
            Duration::from_millis(150),
        );
        assert!(
            r.as_ref()
                .is_err_and(|w| w.contains("without write sharing")),
            "{r:?}"
        );
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(holder);
        });
        assert_eq!(
            append(
                &home,
                &event("s-1", "tool.call", 1),
                1,
                Duration::from_millis(2000)
            ),
            Ok(1)
        );
        h.join().unwrap();
        verify(&lines(&home, "s-1"));
    }

    #[test]
    fn a_reader_with_read_write_and_delete_sharing_does_not_block_a_hook() {
        use std::os::windows::fs::OpenOptionsExt;
        let home = scratch("winreader");
        let env = env_home(&home);
        after_post(&event("s-1", "approval", 0), &env, &home, false);
        // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, as
        // `derm audit` opens it (events.md 6.4).
        let _reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(7)
            .open(log_path(&home, "s-1"))
            .unwrap();
        assert_eq!(
            after_post(&event("s-1", "tool.call", 1), &env, &home, false),
            Outcome::Appended { seq: 1 }
        );
    }

    /// For `derm audit` (lane 6E): `LockFileEx` locks are mandatory, so a
    /// reader that opens the log while a hook holds its lock gets error 33
    /// (ERROR_LOCK_VIOLATION) and must retry; a hook holds it for
    /// milliseconds (note AZ B4: 10.9 ms on average on NTFS).
    #[test]
    fn a_plain_reader_meets_error_33_while_a_hook_holds_the_lock() {
        let home = scratch("win33");
        after_post(&event("s-1", "approval", 0), &env_home(&home), &home, false);
        let p = log_path(&home, "s-1");
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&p)
            .unwrap();
        holder.lock().unwrap();
        let e = std::fs::read(&p).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(33), "{e}");
        holder.unlock().unwrap();
        assert!(!std::fs::read(&p).unwrap().is_empty());
    }

    #[test]
    fn a_junction_at_the_local_folder_is_refused() {
        let home = scratch("winjunction");
        let elsewhere = scratch("winelsewhere");
        std::fs::create_dir(home.join(".derm")).unwrap();
        let ok = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(folder(&home))
            .arg(&elsewhere)
            .status()
            .unwrap()
            .success();
        assert!(ok, "mklink /J");
        let o = after_post(&event("s-1", "approval", 0), &env_home(&home), &home, false);
        assert!(
            matches!(o, Outcome::Failed(ref w) if w.contains("junction")),
            "{o:?}"
        );
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }
}

/// Re-review W6C-R7, case 270, Tony's R7 call (option 1): under srt on
/// Linux the light log's append succeeded into srt's tmpfs over `~/.derm`
/// and the record went with the sandbox (run as root and, by this pass, as
/// a plain user). It is not written there, so the call is denied.
// Mount points and `/proc` are Linux's; the paths here are Unix paths (a
// Windows join puts `\` before `.derm`, CI's windows job).
#[cfg(unix)]
#[test]
fn r7_no_light_log_where_it_would_go_with_the_sandbox() {
    let home = Path::new("/home/u");
    let lo = "Inter-|\n face |\n    lo: 0\n";
    let eth = "Inter-|\n face |\n    lo: 0\n  eth0: 1\n";
    let srt_mounts = "36 25 0:30 / /home/u/.derm rw,nosuid - tmpfs tmpfs rw\n37 36 8:1 /home/u/.derm/policy.json /home/u/.derm/policy.json ro - ext4 /dev/sda1 rw\n";
    let sys = |net: &str, mounts: &str| System {
        netdev: Some(net.to_string()),
        mountinfo: Some(mounts.to_string()),
    };
    assert!(kept_away(home, &sys(lo, ""))
        .unwrap()
        .contains("only loopback"));
    assert!(kept_away(home, &sys(eth, srt_mounts))
        .unwrap()
        .contains("/home/u/.derm is a mount"));
    // A mount point with a space, as mountinfo escapes it.
    let spaced = Path::new("/home/a b");
    assert!(kept_away(
        spaced,
        &sys(
            eth,
            "40 25 0:31 / /home/a\\040b/.derm/local rw - tmpfs tmpfs rw\n"
        )
    )
    .is_some());
    // Not a mount at or under ~/.derm: kept.
    assert_eq!(
        kept_away(home, &sys(eth, "41 25 0:32 / /home/u/.dermx rw - tmpfs tmpfs rw\n36 1 8:1 / / rw - ext4 /dev/sda1 rw\n")),
        None
    );
    assert_eq!(
        kept_away(
            home,
            &System {
                netdev: None,
                mountinfo: None
            }
        ),
        None
    );
    // A volume or a bind of a folder on disk at ~/.derm keeps its files
    // (review FP2-R3): only a tmpfs, as srt's, goes with the sandbox.
    assert_eq!(
        kept_away(
            home,
            &sys(eth, "42 25 8:1 /vol /home/u/.derm rw - ext4 /dev/sdb1 rw\n")
        ),
        None
    );
    // And the seam fails, so the light tier denies.
    let h = scratch("r7");
    let out = after_post_with(
        &event("c-r7", "approval", 0),
        &env_home(&h),
        &h,
        false,
        &sys(lo, ""),
    );
    assert!(
        matches!(&out, Outcome::Failed(w) if w.contains("only loopback")),
        "{out:?}"
    );
    assert!(!h.join(".derm").exists());
}
