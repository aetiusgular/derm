//! Lane PC's tests for `installs::project` (step P4 and P8's first part).
//! Each case names what it holds; the contract is `contracts/events.md` 7.2.

use super::*;

const SLUG: &str = "max";
const ID: &str = "aaaaaaaaaaaaaaaa";
const HOME: &str = "/var/lib/derm/agents/max/projects/aaaaaaaaaaaaaaaa/home";
const HARNESS: &str = "/usr/local/bin/claude";
const CHAT: &str = "derm-c1";

fn ev(id: &str, kind: &str, source: Source, at: i64, detail: Value) -> Event {
    Event {
        project: String::new(),
        id: id.into(),
        at,
        chat_id: CHAT.into(),
        harness: "claude-code".into(),
        source,
        kind: kind.into(),
        summary: String::new(),
        detail,
        pid: Some(4242),
        approval_id: None,
    }
}

/// `derm run`'s `run.start` for an account chat, as `run/mod.rs` and
/// `run/user/chat.rs` write it (`agentUser` with `account` and `landlock`;
/// `project` as `contracts/events.md` 7.1 adds it).
fn start(scoped: bool) -> Event {
    ev(
        "run-start-1",
        "run.start",
        Source::Run,
        1_000,
        json!({
            "cwd": "/home/u/work/repo",
            "folders": ["/home/u/work/data"],
            "harnessExe": HARNESS,
            "harnessChildExe": null,
            "agentUser": {"user": "derm-max", "uid": 996, "how": "sudo", "account": SLUG,
                "landlock": {"abi": 7, "scoped": scoped, "answeredBy": null}},
            "project": {"id": ID, "folder": "/home/u/work"},
        }),
    )
}

fn os(id: &str, kind: &str, at: i64, detail: Value) -> Event {
    ev(id, kind, Source::Auditd, at, detail)
}

fn kinds_of(out: &[Event]) -> Vec<&str> {
    out.iter().map(|e| e.kind.as_str()).collect()
}

/// The red test's cases (`pc_a_write_to_a_project_homes_run_later_files_is_flagged`),
/// and the readings around them.
#[test]
fn project_control_names_run_later_paths_in_the_home_only() {
    for (rel, marker) in [
        (".claude/settings.json", ".claude/"),
        (".claude.json", ".claude.json"),
        (".codex/config.toml", ".codex/config.toml"),
        (".pi/agent/settings.json", ".pi/agent/"),
        (".agents/skills/x/SKILL.md", ".agents/skills/"),
        (
            ".cache/codex-runtimes/codex-primary-runtime/plugins/p/x",
            ".cache/codex-runtimes/",
        ),
        (".local/bin/claude", ".local/bin/"),
        (".bashrc", ".bashrc"),
        // Codex walks each folder for `.agents/skills` (host_roots.rs:225).
        ("work/.agents/skills/y/SKILL.md", ".agents/skills/"),
        // git's hooks in a repository kept in the home.
        ("repo/.git/hooks/pre-commit", ".git/hooks/"),
    ] {
        let path = format!("{HOME}/{rel}");
        assert_eq!(
            project_control(&path, HOME).as_deref(),
            Some(marker),
            "{rel}"
        );
    }
    for p in [
        format!("{HOME}/notes.txt"),
        format!("{HOME}/.claude.json.tmp.12.ab"),
        format!("{HOME}/x/.local/bin/y"),
        format!("{HOME}/.local/bin"),
        format!("{HOME}/.cache/other/x"),
        "/srv/work/a/.local/bin/x".into(),
        // A home of another project, and a name that only starts like it.
        "/var/lib/derm/agents/max/projects/bbbbbbbbbbbbbbbb/home/.bashrc".into(),
        format!("{HOME}x/.bashrc"),
        // A package's own files under a store, as control_path reads them.
        format!("{HOME}/repo/node_modules/p/.github/workflows/ci.yml"),
    ] {
        assert_eq!(project_control(&p, HOME), None, "{p}");
    }
    // A name as a process wrote it: `..` parts that land in the home count,
    // and so does the name as written.
    assert_eq!(
        project_control(
            "/var/lib/derm/agents/max/projects/aaaaaaaaaaaaaaaa/tmp/../home/.bashrc",
            HOME
        )
        .as_deref(),
        Some(".bashrc")
    );
    assert_eq!(
        project_control(&format!("{HOME}/x/../.local/bin/z"), HOME).as_deref(),
        Some(".local/bin/")
    );
    // A trailing `/` on the home is the same home; no home is no match.
    assert!(project_control(&format!("{HOME}/.bashrc"), &format!("{HOME}/")).is_some());
    assert_eq!(project_control("/.bashrc", ""), None);
    assert_eq!(project_control("/.bashrc", "/"), None);
}

#[test]
fn a_write_to_a_run_later_file_in_an_account_chats_home_is_flagged() {
    let mut f = ProjectFlags::new();
    assert!(f.observe(&start(true)).is_empty());
    assert!(f.is_account_chat(CHAT));
    let out = f.observe(&os(
        "auditd-1-1",
        "create",
        2_000,
        json!({"path": format!("{HOME}/.claude/settings.json"), "exe": "/usr/bin/bash"}),
    ));
    assert_eq!(kinds_of(&out), vec![kinds::CONTROL], "{out:?}");
    let r = &out[0];
    assert_eq!(r.source, Source::Derm);
    assert_eq!(r.project, ID, "the chat's project, set by the daemon");
    assert_eq!(r.chat_id, CHAT);
    assert_eq!(r.detail["marker"], ".claude/");
    assert_eq!(r.detail["path"], format!("{HOME}/.claude/settings.json"));
    assert_eq!(
        r.detail["process"],
        json!({"pid": 4242, "exe": "/usr/bin/bash"})
    );
    assert_eq!(r.detail["account"], SLUG);
    assert_eq!(r.detail["effect"], "auditd-1-1");
    assert_eq!(r.id, "project-control-auditd-1-1-0");
    // A rename puts its new name in place: the temp file is no marker, the
    // `.claude.json` it becomes is (Claude Code's own save, note CD 2.1).
    let out = f.observe(&os(
        "auditd-1-2",
        "rename",
        2_100,
        json!({"path": format!("{HOME}/.claude.json.tmp.9.ab"), "dest": format!("{HOME}/.claude.json"), "exe": HARNESS}),
    ));
    assert_eq!(kinds_of(&out), vec![kinds::CONTROL]);
    assert_eq!(out[0].detail["path"], format!("{HOME}/.claude.json"));
    // An ordinary file is nothing; so is a write in the person's folder,
    // which the feed's own checks cover.
    for (id, p) in [
        ("auditd-1-3", format!("{HOME}/notes.txt")),
        ("auditd-1-4", "/home/u/work/repo/src/a.rs".to_string()),
    ] {
        assert!(f
            .observe(&os(
                id,
                "write",
                2_200,
                json!({"path": p, "exe": "/usr/bin/bash"})
            ))
            .is_empty());
    }
}

#[test]
fn only_an_account_chats_own_os_records_are_read() {
    let mut f = ProjectFlags::new();
    // A chat that runs as the person (no agentUser) is no account chat.
    let mut person = start(true);
    person.detail.as_object_mut().unwrap().remove("agentUser");
    f.observe(&person);
    assert!(!f.is_account_chat(CHAT));
    let write = || {
        os(
            "auditd-2-1",
            "create",
            2_000,
            json!({"path": format!("{HOME}/.bashrc"), "exe": "/usr/bin/bash"}),
        )
    };
    assert!(f.observe(&write()).is_empty());
    // A `run.start` that is not `derm run`'s (any other source) starts none.
    let mut forged = start(true);
    forged.source = Source::Adapter;
    f.observe(&forged);
    assert!(!f.is_account_chat(CHAT));
    // A slug the accounts file would refuse names no account.
    let mut bad = start(true);
    bad.detail["agentUser"]["account"] = json!("../x");
    f.observe(&bad);
    assert!(!f.is_account_chat(CHAT));
    f.observe(&start(true));
    assert!(f.is_account_chat(CHAT));
    // The same write posted by a chat token's sources is not the kernel's.
    for source in [Source::Adapter, Source::Otel, Source::Derm] {
        let mut e = write();
        e.source = source;
        assert!(f.observe(&e).is_empty(), "{source:?}");
    }
    assert_eq!(kinds_of(&f.observe(&write())), vec![kinds::CONTROL]);
    // Another chat's record is that chat's: none here.
    let mut other = write();
    other.chat_id = "derm-other".into();
    other.id = "auditd-2-2".into();
    assert!(f.observe(&other).is_empty());
}

#[test]
fn the_project_comes_from_the_events_field_or_run_starts_detail() {
    // The daemon's own stamp (`project` on the event) is read first.
    let mut f = ProjectFlags::new();
    let mut s = start(true);
    s.project = "bbbbbbbbbbbbbbbb".into();
    f.observe(&s);
    let other_home = "/var/lib/derm/agents/max/projects/bbbbbbbbbbbbbbbb/home";
    let out = f.observe(&os(
        "auditd-3-1",
        "write",
        2_000,
        json!({"path": format!("{other_home}/.zshrc"), "exe": "/usr/bin/zsh"}),
    ));
    assert_eq!(kinds_of(&out), vec![kinds::CONTROL]);
    assert_eq!(out[0].project, "bbbbbbbbbbbbbbbb");
    // No valid id anywhere: no home is known, so no project.control; the
    // account's sign-in store and its sockets are still read.
    let mut f = ProjectFlags::new();
    let mut s = start(true);
    s.detail["project"] = json!({"id": "../../etc", "folder": "/home/u/work"});
    f.observe(&s);
    assert!(f
        .observe(&os(
            "auditd-3-2",
            "write",
            2_000,
            json!({"path": format!("{HOME}/.bashrc"), "exe": "/usr/bin/bash"})
        ))
        .is_empty());
    let out = f.observe(&os(
        "auditd-3-3",
        "open",
        2_100,
        json!({"path": "/var/lib/derm/agents/max/signin/codex/auth.json", "exe": "/usr/bin/cat"}),
    ));
    assert_eq!(kinds_of(&out), vec![kinds::SIGNIN_READ]);
    assert_eq!(out[0].project, "");
}

#[test]
fn a_sign_in_file_opened_by_anything_but_the_harness_is_flagged() {
    let mut f = ProjectFlags::new();
    f.observe(&start(true));
    let cred = "/var/lib/derm/agents/max/signin/claude-code/.credentials.json";
    // The harness's own reads and its `.storage-write` lock (note CB).
    for (id, p) in [
        ("auditd-4-1", cred.to_string()),
        (
            "auditd-4-2",
            "/var/lib/derm/agents/max/signin/claude-code/.storage-write".into(),
        ),
    ] {
        assert!(f
            .observe(&os(id, "open", 2_000, json!({"path": p, "exe": HARNESS})))
            .is_empty());
    }
    let out = f.observe(&os(
        "auditd-4-3",
        "open",
        2_100,
        json!({"path": cred, "exe": "/usr/bin/python3.13"}),
    ));
    assert_eq!(kinds_of(&out), vec![kinds::SIGNIN_READ], "{out:?}");
    assert_eq!(out[0].detail["process"]["exe"], "/usr/bin/python3.13");
    assert!(out[0].detail.get("forWrite").is_none());
    // A second process opening it is its own record; the same one again
    // within a minute is not.
    assert!(f
        .observe(&os(
            "auditd-4-4",
            "open",
            2_200,
            json!({"path": cred, "exe": "/usr/bin/python3.13"})
        ))
        .is_empty());
    assert_eq!(
        kinds_of(&f.observe(&os(
            "auditd-4-5",
            "open",
            2_300,
            json!({"path": cred, "exe": "/usr/bin/cat"})
        ))),
        vec![kinds::SIGNIN_READ]
    );
    // An open for writing reads too when it is O_RDWR; the rules key it
    // `derm_write`, so it arrives as a write.
    let out = f.observe(&os(
        "auditd-4-6",
        "write",
        2_400,
        json!({"path": "/var/lib/derm/agents/max/signin/codex/auth.json", "exe": "/usr/bin/vim"}),
    ));
    assert_eq!(kinds_of(&out), vec![kinds::SIGNIN_READ]);
    assert_eq!(out[0].detail["forWrite"], true);
    // O_PATH opens no file (open(2)); a path beside the store is not in it.
    for (id, p, extra) in [
        ("auditd-4-7", cred.to_string(), json!(true)),
        (
            "auditd-4-8",
            "/var/lib/derm/agents/max/signinx/a".to_string(),
            json!(false),
        ),
        (
            "auditd-4-9",
            "/var/lib/derm/agents/other/signin/codex/auth.json".to_string(),
            json!(false),
        ),
    ] {
        assert!(
            f.observe(&os(
                id,
                "open",
                2_500,
                json!({"path": p, "exe": "/usr/bin/cat", "pathOnly": extra})
            ))
            .is_empty(),
            "{p}"
        );
    }
    // Through a link P3 makes in a project home (any of the account's
    // projects): the record names the link (run, 6.18.44).
    for (i, link) in SIGNIN_LINKS.iter().enumerate() {
        let p = format!("/var/lib/derm/agents/max/projects/bbbbbbbbbbbbbbbb/home/{link}");
        assert_eq!(
            kinds_of(&f.observe(&os(
                &format!("auditd-4-link-{i}"),
                "open",
                2_550,
                json!({"path": p, "exe": "/usr/bin/cat"})
            ))),
            vec![kinds::SIGNIN_READ],
            "{p}"
        );
    }
    // A read the store's rule matched by the account's own uid, through a
    // link anywhere: flagged; the same path read by another uid (the
    // person's derm run, whose own rules watch its own home) is not; nor is
    // a system file the account's rules also watch.
    for (id, path, uid, flagged) in [
        ("auditd-4-u1", "/tmp/x/link", 996, true),
        ("auditd-4-u2", "/tmp/x/link2", 1000, false),
        ("auditd-4-u3", "/etc/shadow", 996, false),
        ("auditd-4-u4", "/etc/sudoers.d/90-x", 996, false),
    ] {
        let out = f.observe(&os(
            id,
            "open",
            2_560,
            json!({"path": path, "exe": "/usr/bin/cat", "uid": uid}),
        ));
        assert_eq!(out.len(), usize::from(flagged), "{path} {uid}");
    }
    // The uid rule is for reads only: a write elsewhere is not a sign-in open.
    assert!(f
        .observe(&os(
            "auditd-4-u5",
            "write",
            2_570,
            json!({"path": "/tmp/x/out", "exe": "/usr/bin/cat", "uid": 996})
        ))
        .is_empty());
    // A `..` that lands in the store is in it.
    assert_eq!(
        kinds_of(&f.observe(&os(
            "auditd-4-10",
            "open",
            2_600,
            json!({"path": "/var/lib/derm/agents/max/projects/../signin/pi/auth.json", "exe": "/usr/bin/cat"})
        ))),
        vec![kinds::SIGNIN_READ]
    );
}

#[test]
fn a_unix_connect_is_recorded_and_outside_when_it_leaves_the_project() {
    let mut f = ProjectFlags::new();
    f.observe(&start(true));
    let dir = "/var/lib/derm/agents/max/projects/aaaaaaaaaaaaaaaa";
    let bridge = format!(
        "{BRIDGE_ROOT}/1000/{}-0123456789abcdef0123456789abcdef/daemon.sock",
        CHAT
    );
    let cases: Vec<(String, bool)> = vec![
        (format!("{dir}/run/cc-socks/77.sock"), false),
        (format!("{dir}/tmp/x.sock"), false),
        ("/home/u/work/repo/.s".into(), false),
        ("/home/u/work/other/.s".into(), false),
        (bridge, false),
        ("/run/systemd/resolve/io.systemd.Resolve".into(), true),
        ("/run/dbus/system_bus_socket".into(), true),
        // Another project's runtime folder in the same account (N-1).
        (
            "/var/lib/derm/agents/max/projects/bbbbbbbbbbbbbbbb/run/cc-socks/9.sock".into(),
            true,
        ),
        ("/tmp/cc-socks-996/9.sock".to_string(), true),
        // Another chat's bridge, and a folder that only looks like one.
        (
            format!("{BRIDGE_ROOT}/1000/derm-c2-0123456789abcdef0123456789abcdef/daemon.sock"),
            true,
        ),
        (format!("{BRIDGE_ROOT}/1000/{CHAT}-xyz/daemon.sock"), true),
        ("?rel.sock".into(), true),
        ("@abstract-name".into(), false),
    ];
    for (i, (path, outside)) in cases.iter().enumerate() {
        let out = f.observe(&os(
            &format!("auditd-5-{i}"),
            UNIX_CONNECT,
            2_000 + i as i64,
            json!({"path": path, "exe": "/usr/bin/curl", "abstract": path.starts_with('@')}),
        ));
        assert_eq!(kinds_of(&out), vec![kinds::NET_UNIX], "{path}");
        assert_eq!(out[0].detail["outside"], *outside, "{path}");
        assert_eq!(out[0].detail["abstract"], path.starts_with('@'), "{path}");
        assert_eq!(out[0].detail["path"], path.as_str());
    }
    // One record per socket a minute.
    assert!(f
        .observe(&os(
            "auditd-5-again",
            UNIX_CONNECT,
            30_000,
            json!({"path": "/run/dbus/system_bus_socket", "exe": "/usr/bin/curl"})
        ))
        .is_empty());
    let out = f.observe(&os(
        "auditd-5-later",
        UNIX_CONNECT,
        2_100 + REPEAT_MS,
        json!({"path": "/run/dbus/system_bus_socket", "exe": "/usr/bin/curl"}),
    ));
    assert_eq!(kinds_of(&out), vec![kinds::NET_UNIX]);
    // A denied connect says so.
    let out = f.observe(&os(
        "auditd-5-denied",
        UNIX_CONNECT,
        3_000,
        json!({"path": "/run/user/1000/bus", "exe": "/usr/bin/curl", "denied": true}),
    ));
    assert_eq!(out[0].detail["denied"], true);
    assert_eq!(out[0].detail["outside"], true);
}

/// Without Landlock's abstract-socket scope (ABI below 6, or the person's
/// answer to run without it, case 275) an abstract name can be anyone's.
#[test]
fn an_abstract_socket_is_outside_when_the_domain_does_not_scope_it() {
    let mut f = ProjectFlags::new();
    f.observe(&start(false));
    let out = f.observe(&os(
        "auditd-6-1",
        UNIX_CONNECT,
        2_000,
        json!({"path": "@/tmp/.X11-unix/X0", "exe": "/usr/bin/xclip"}),
    ));
    assert_eq!(out[0].detail["outside"], true);
    assert!(out[0].summary.contains("abstract"), "{}", out[0].summary);
}

#[test]
fn a_flood_is_capped_per_minute_and_the_next_record_says_how_many_were_not_written() {
    let mut f = ProjectFlags::new();
    f.observe(&start(true));
    let mut written = 0;
    for i in 0..(MAX_PER_MINUTE + 30) {
        written += f
            .observe(&os(
                &format!("auditd-7-{i}"),
                UNIX_CONNECT,
                2_000,
                json!({"path": format!("/tmp/s{i}"), "exe": "/usr/bin/x"}),
            ))
            .len();
    }
    assert_eq!(written, MAX_PER_MINUTE as usize);
    let out = f.observe(&os(
        "auditd-7-next",
        UNIX_CONNECT,
        2_000 + 60_000,
        json!({"path": "/tmp/next", "exe": "/usr/bin/x"}),
    ));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].detail["notRecorded"], 30);
}

#[test]
fn a_chat_is_kept_after_its_stop_while_the_join_keeps_it_and_starts_afresh() {
    let mut f = ProjectFlags::new();
    f.observe(&start(true));
    f.observe(&ev("run-stop-1", "run.stop", Source::Run, 5_000, json!({})));
    // An effect that arrives late, inside the join's keep (MW5-17), is read.
    let out = f.observe(&os(
        "auditd-8-1",
        "write",
        6_000,
        json!({"path": format!("{HOME}/.profile"), "exe": "/usr/bin/sh"}),
    ));
    assert_eq!(kinds_of(&out), vec![kinds::CONTROL]);
    // Long after, with the feed past the stop: let go.
    let mut late = os(
        "auditd-8-2",
        "write",
        5_000 + 11 * 60_000,
        json!({"path": format!("{HOME}/.zshenv"), "exe": "/usr/bin/sh", "auditAt": 5_000 + 11 * 60_000}),
    );
    late.chat_id = "derm-unrelated".into();
    f.observe(&late);
    let mut again = late.clone();
    again.chat_id = CHAT.into();
    again.id = "auditd-8-3".into();
    assert!(f.observe(&again).is_empty());
    assert!(!f.is_account_chat(CHAT));
    // The same id run again starts afresh, with what it was seen before
    // forgotten.
    f.observe(&start(true));
    assert!(f.is_account_chat(CHAT));
}

/// Through the ingest wiring the daemon calls (`InstallRecords::observe`).
#[test]
fn the_ingest_wiring_gives_the_project_records() {
    let mut r = super::super::ingest::InstallRecords::new();
    assert!(r.observe(&start(true), |_| None, 1_000).is_empty());
    let out = r.observe(
        &os(
            "auditd-9-1",
            UNIX_CONNECT,
            2_000,
            json!({"path": "/run/systemd/resolve/io.systemd.Resolve", "exe": "/usr/bin/getent"}),
        ),
        |_| None,
        2_000,
    );
    assert_eq!(kinds_of(&out), vec![kinds::NET_UNIX]);
}

/// End to end through the daemon's own `ingest` and `report`: the records
/// are stored, counted by kind, and carry the chat's project.
#[test]
fn the_daemon_stores_and_counts_the_project_records() {
    let root = std::env::temp_dir().join(format!(
        "derm-pc-{}-{}",
        std::process::id(),
        &derm_core::token::mint().unwrap()[..12]
    ));
    let data = root.join("data");
    let log: &'static crate::activity::store::ActivityLog = Box::leak(Box::new(
        crate::activity::store::ActivityLog::start(data.join("activity")),
    ));
    let d = crate::daemon::Daemon::new(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        log,
        &data,
        false,
    )
    .unwrap();
    let t0 = crate::activity::store::now_ms();
    d.ingest(start(true));
    for (id, kind, detail) in [
        (
            "auditd-10-1",
            "create",
            json!({"path": format!("{HOME}/.claude/settings.json"), "exe": "/usr/bin/bash"}),
        ),
        (
            "auditd-10-2",
            "open",
            json!({"path": "/var/lib/derm/agents/max/signin/codex/auth.json", "exe": "/usr/bin/cat"}),
        ),
        (
            "auditd-10-3",
            UNIX_CONNECT,
            json!({"path": "/run/dbus/system_bus_socket", "exe": "/usr/bin/busctl"}),
        ),
    ] {
        d.ingest(os(id, kind, 0, detail));
    }
    let mut by_kind = Value::Null;
    for _ in 0..200 {
        let r = d.report(
            Some(CHAT),
            t0 - 1_000,
            crate::activity::store::now_ms() + 1_000,
        );
        by_kind = r["byKind"].clone();
        if by_kind.get(kinds::NET_UNIX).is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    for k in [kinds::CONTROL, kinds::SIGNIN_READ, kinds::NET_UNIX] {
        assert_eq!(by_kind[k], 1, "{k}: {by_kind}");
    }
    let _ = std::fs::remove_dir_all(root);
}
