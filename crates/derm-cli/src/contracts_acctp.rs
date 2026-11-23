//! Step P's red tests inside derm-cli (the base, 20 Nov 2026;
//! `plans/parallel_build_accounts.md` section 8.3, item 7). One or more per
//! lane, each `#[ignore]`d with its owner and the reason it fails on the
//! base, and each calling only the functions the base declared
//! (`project/`, `run/user/project.rs`, `run/pty/`, `agents/signin.rs`,
//! `run/claude_gate.rs`). No lane edits this file (`scripts/
//! lane-ownership.json`, `noLane`); a lane runs its own with
//! `cargo test -p derm-cli -- --ignored <name>`, and P integration drops each
//! `ignore` once the lane is green. A case a lane finds wrong is a request.
//!
//! P integration (22 Nov 2026) dropped every `ignore` but Claude Code's
//! linked sign-in (`pb_claude_code_*`); its fix pass dropped that one once
//! the box research recorded P-B1 as passing by the store-folder variable
//! (`plans/parallel/acctP_box_research.md`, 22 Nov 22:40) and turned
//! `agents::signin::CLAUDE_CODE_STORE` on with it.
//!
//! The process-level ones are `tests/contracts_acctp.rs` (PF) and the
//! daemon's and the Linux feed's `tests/contracts_acctp.rs` (PE, PC, the
//! base's record field).

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::project::{self, Found, Project, ProjectId, Registry};
use crate::run::user::project::{project_chat_spec, project_env, ProjectChat};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    use std::os::unix::fs::PermissionsExt;
    let p = std::env::temp_dir().join(format!("dacctp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    // The registry's checks read every folder from `/`; temp_dir's real path.
    Scratch(std::fs::canonicalize(&p).unwrap())
}

fn under(path: &str, folder: &str) -> bool {
    let f = folder.trim_end_matches('/');
    path == f || path.starts_with(&format!("{f}/"))
}

const ACCOUNT: &str = "/var/lib/derm/agents/max";

fn chat<'a>(id: &'a ProjectId, folders: &'a [String], harness: &'a str) -> ProjectChat<'a> {
    ProjectChat {
        account_home: ACCOUNT,
        project: id,
        folders,
        harness,
        bridge: None,
        require_scopes: true,
    }
}

// ---------------------------------------------------------------- lane PA

/// P-C1, AI-1 across projects (contracts/projects.md section 2.2): a chat
/// of project A writes its own project's home, temp and runtime folders and
/// nothing of project B's, on one account. Red on the base: the chat's
/// domain writes the whole account home (`landlock/mod.rs`'s `chat_spec`),
/// which holds every project's folders.
#[test]
fn pa_two_projects_in_one_account_do_not_reach_each_other() {
    let a = ProjectId::of_real_path("/srv/work/a");
    let b = ProjectId::of_real_path("/srv/work/b");
    let fa = vec!["/srv/work/a".to_string()];
    let spec = project_chat_spec(&chat(&a, &fa, "codex"));
    let a_dir = derm_core::project::layout::project_dir(ACCOUNT, &a);
    let b_dir = derm_core::project::layout::project_dir(ACCOUNT, &b);
    for part in ["home", "tmp", "run"] {
        let b_part = format!("{b_dir}/{part}");
        for w in &spec.write {
            assert!(
                !under(&b_part, w),
                "project A's chat writes {w}, which holds project B's {part}"
            );
        }
        let a_part = format!("{a_dir}/{part}");
        assert!(
            spec.write.iter().any(|w| under(&a_part, w)),
            "project A's chat cannot write its own {part}"
        );
    }
    // Nothing a chat runs comes from a folder a chat writes (AI-1).
    for e in &spec.exec {
        for w in &spec.write {
            assert!(!under(e, w), "{e} runs code from {w}, which a chat writes");
        }
    }
}

/// P2 (contracts/projects.md section 2.2 and 2.3): the harness's `HOME`,
/// `TMPDIR` and `XDG_RUNTIME_DIR` are its project's, its `PATH` holds no
/// folder a chat writes, and Codex's store is reached by its links, not a
/// variable. Red on the base: no project variables at all.
#[test]
fn pa_a_project_chat_gets_its_own_home_tmp_and_runtime_folder() {
    let a = ProjectId::of_real_path("/srv/work/a");
    let fa = vec!["/srv/work/a".to_string()];
    let env = project_env(&chat(&a, &fa, "codex"));
    let get = |k: &str| {
        env.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let dir = derm_core::project::layout::project_dir(ACCOUNT, &a);
    assert_eq!(get("HOME"), format!("{dir}/home"), "{env:?}");
    assert_eq!(get("TMPDIR"), format!("{dir}/tmp"), "{env:?}");
    assert_eq!(get("XDG_RUNTIME_DIR"), format!("{dir}/run"), "{env:?}");
    assert_eq!(get("PATH"), "/usr/local/bin:/usr/bin:/bin", "{env:?}");
    assert!(
        env.iter().all(|(n, _)| n != "CODEX_HOME"),
        "CODEX_HOME must exist when set; the home's .codex is used: {env:?}"
    );
}

fn write(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn named(folder: &Path, name: &str) -> Project {
    let real = std::fs::canonicalize(folder).unwrap();
    Project {
        id: ProjectId::of_real_path(&real.to_string_lossy()),
        folder: real,
        name: name.into(),
        added: 0,
    }
}

/// P1, P-C2, P-C3 (contracts/projects.md sections 1.4 and 1.5): the
/// deepest named folder wins, by whole path parts; a linked worktree outside
/// every named folder joins the project its common folder sits in, with
/// git 2.48's relative links (`worktree.useRelativePaths`, resolved as git
/// `v2.48.0` `setup.c:976-982` and `worktree.c:114-118` do); a `.git` file
/// whose back-link does not name it back finds nothing; a folder outside
/// every project finds nothing. The link files are written by hand in the
/// form git writes them (git 2.43.0 run here for the absolute form; the
/// relative form by git 2.48.0's source; no git 2.48 was run). Red on the
/// base: `find` finds nothing.
#[test]
fn pa_the_nearest_named_folder_and_a_relative_worktree_find_their_project() {
    let s = scratch("find");
    let t = &s.0;
    for d in [
        "work/sub/x",
        "work/other",
        "work/repo/.git/worktrees/wt",
        "workbench",
        "wt",
        "evil",
    ] {
        std::fs::create_dir_all(t.join(d)).unwrap();
    }
    // The worktree `wt` beside `work`, linked both ways with relative paths.
    write(
        &t.join("wt/.git"),
        "gitdir: ../work/repo/.git/worktrees/wt\n",
    );
    // git v2.48.0 writes `relative_path(<worktree>, <gitdir>)` + `/.git`
    // (`worktree.c:1040-1042`, `write_worktree_linking_files`) and reads it
    // joined to `worktrees/<id>/` after stripping `/.git` and `gitdir`
    // (`worktree.c:107-117`): five `..` from `work/repo/.git/worktrees/wt`
    // to the folder `wt` sits in (request PA-1; four named `work/wt`).
    write(
        &t.join("work/repo/.git/worktrees/wt/gitdir"),
        "../../../../../wt/.git\n",
    );
    write(&t.join("work/repo/.git/worktrees/wt/commondir"), "../..\n");
    // A planted `.git` that claims the same worktree folder.
    write(
        &t.join("evil/.git"),
        "gitdir: ../work/repo/.git/worktrees/wt\n",
    );
    let work = named(&t.join("work"), "work");
    let sub = named(&t.join("work/sub"), "sub");
    let reg = Registry {
        projects: vec![work.clone(), sub.clone()],
    };
    assert_eq!(
        project::find(&reg, &t.join("work/sub/x")),
        Found::Folder(sub)
    );
    assert_eq!(
        project::find(&reg, &t.join("work/other")),
        Found::Folder(work.clone())
    );
    // `/work` does not hold `/workbench`: whole parts only.
    assert_eq!(project::find(&reg, &t.join("workbench")), Found::None);
    assert_eq!(project::find(&reg, &t.join("wt")), Found::Worktree(work));
    assert_eq!(project::find(&reg, &t.join("evil")), Found::None);
}

/// Contracts/projects.md section 1.1 (case 226's checks): the registry
/// reads whole when it is the person's and private, and is refused when
/// others can write it. Red on the base: `load` refuses everything.
#[test]
fn pa_the_registry_reads_whole_and_refuses_a_file_others_can_write() {
    use std::os::unix::fs::PermissionsExt;
    let s = scratch("registry");
    let file = s.0.join(project::FILE);
    let fixture = include_str!("../../../contracts/fixtures/project/projects.json");
    std::fs::write(&file, fixture).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let reg = project::load(&file).expect("a private registry reads");
    let want: Value = serde_json::from_str(fixture).unwrap();
    assert_eq!(
        reg.projects.len(),
        want["projects"].as_array().unwrap().len()
    );
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o620)).unwrap();
    assert!(
        project::load(&file).is_err(),
        "a group-writable registry is refused"
    );
    std::fs::write(&file, r#"{"version":1,"projects":[],"extra":1}"#).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(project::load(&file).is_err(), "an unknown field is refused");
}

// ---------------------------------------------------------------- lane PB

/// Codex 0.167.2's save, as its source does it (`login/src/auth/
/// storage.rs:274-295`, `storage_file.rs:10-62` at `rust-v0.167.2`): resolve
/// every link to the target, write `.auth-<n>` in the target's folder, sync,
/// rename onto the target. Copied in shape from that source (rules 9.12),
/// not run against Codex.
fn codex_save(link: &Path, text: &str) {
    let mut target = link.to_path_buf();
    for _ in 0..40 {
        match std::fs::read_link(&target) {
            Ok(next) => {
                target = if next.is_absolute() {
                    next
                } else {
                    target.parent().unwrap().join(next)
                }
            }
            Err(_) => break,
        }
    }
    let tmp = target.parent().unwrap().join(".auth-test");
    std::fs::write(&tmp, text).unwrap();
    std::fs::File::open(&tmp).unwrap().sync_all().unwrap();
    std::fs::rename(&tmp, &target).unwrap();
}

fn flock(path: &Path, wait: bool) -> Option<std::fs::File> {
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap();
    let op = libc::LOCK_EX | if wait { 0 } else { libc::LOCK_NB };
    (unsafe { libc::flock(f.as_raw_fd(), op) } == 0).then_some(f)
}

fn account_with_store(s: &Scratch, harness: &str) -> PathBuf {
    let acct = s.0.join("agents/max");
    std::fs::create_dir_all(acct.join("signin").join(harness)).unwrap();
    acct
}

/// P3, P-C4, C6 (contracts/projects.md section 2.3): two project homes
/// reach one Codex `auth.json` and one `auth.lock` by links; a save through
/// either leaves one regular file in the store and both links in place; the
/// commit lock is one lock. Red on the base: no link is made.
#[test]
fn pb_codex_links_survive_a_save_and_share_the_commit_lock() {
    let s = scratch("codex-links");
    let acct = account_with_store(&s, "codex");
    let (pa, pb) = (s.0.join("proj-a/home"), s.0.join("proj-b/home"));
    for home in [&pa, &pb] {
        std::fs::create_dir_all(home).unwrap();
        crate::agents::signin::link_project_home(&acct, home, "codex")
            .expect("the project home is linked");
    }
    codex_save(&pa.join(".codex/auth.json"), "{\"tokens\":1}");
    codex_save(&pb.join(".codex/auth.json"), "{\"tokens\":2}");
    let store = acct.join("signin/codex/auth.json");
    let meta = std::fs::symlink_metadata(&store).unwrap();
    assert!(meta.is_file(), "the store holds one regular file");
    for home in [&pa, &pb] {
        let link = home.join(".codex/auth.json");
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "{\"tokens\":2}");
    }
    let held = flock(&pa.join(".codex/auth.lock"), true).expect("lock through A");
    assert!(
        flock(&pb.join(".codex/auth.lock"), false).is_none(),
        "B's commit lock is not A's: linked homes would overwrite each other's tokens"
    );
    drop(held);
}

/// P3, C1 (contracts/projects.md section 2.3): Pi 1.6.0's links resolve to
/// one store file, so its `proper-lockfile` lock on the resolved path
/// (`dist/core/auth-storage.js:50-51`, #11655) is one lock. Red on the base:
/// no link is made.
#[test]
fn pb_pi_links_resolve_to_one_store_file() {
    let s = scratch("pi-links");
    let acct = account_with_store(&s, "pi");
    let (pa, pb) = (s.0.join("proj-a/home"), s.0.join("proj-b/home"));
    for home in [&pa, &pb] {
        std::fs::create_dir_all(home).unwrap();
        crate::agents::signin::link_project_home(&acct, home, "pi")
            .expect("the project home is linked");
    }
    std::fs::write(acct.join("signin/pi/auth.json"), "{}").unwrap();
    let ra = std::fs::canonicalize(pa.join(".pi/agent/auth.json")).unwrap();
    let rb = std::fs::canonicalize(pb.join(".pi/agent/auth.json")).unwrap();
    assert_eq!(ra, rb);
    assert_eq!(
        ra,
        std::fs::canonicalize(acct.join("signin/pi/auth.json")).unwrap()
    );
}

/// P3's Claude Code half (contracts/projects.md section 2.3): no link (a
/// renewal renames over it, Claude Code 2.1.322 by read); the store folder
/// by `CLAUDE_SECURESTORAGE_CONFIG_DIR`. Behind a switch that was off until
/// P-B1 passed on the box (section 8.5; 22 Nov 2026).
#[test]
fn pb_claude_code_shares_its_store_by_folder_variable_not_a_link() {
    let s = scratch("cc-store");
    let acct = account_with_store(&s, "claude-code");
    let home = s.0.join("proj-a/home");
    std::fs::create_dir_all(&home).unwrap();
    let linked = crate::agents::signin::link_project_home(&acct, &home, "claude-code")
        .expect("the project home is set up");
    assert!(
        linked.links.is_empty(),
        "no link for Claude Code: {linked:?}"
    );
    let want = acct
        .join("signin/claude-code")
        .to_string_lossy()
        .into_owned();
    assert!(
        linked
            .env
            .iter()
            .any(|(k, v)| k == "CLAUDE_SECURESTORAGE_CONFIG_DIR" && *v == want),
        "{linked:?}"
    );
}

// ---------------------------------------------------------------- lane PD

fn corpus() -> Vec<Value> {
    let v: Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/project/screen-corpus.json"
    ))
    .unwrap();
    v["cases"].as_array().unwrap().clone()
}

/// Characters `derm_terminal_read` may never carry (contracts/
/// project-tools.md section 3.3): Cc other than `\n` and `\t`, the Cf
/// characters the corpus names, and U+FFFD.
fn forbidden(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(c, '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}'
            | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}' | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}' | '\u{fffd}' | '\u{e0001}' | '\u{e0020}'..='\u{e007f}')
}

/// P5, P-C5 (contracts/project-tools.md section 3; the corpus in
/// `contracts/fixtures/project/screen-corpus.json`): the reader's text holds
/// no control or format character and keeps what a terminal shows. Red on
/// the base: the reader returns the raw bytes.
#[test]
fn pd_a_terminal_read_returns_no_control_bytes() {
    for case in corpus() {
        let name = case["name"].as_str().unwrap();
        let mut r = crate::run::pty::Reader::new(24, 80);
        r.feed(case["input"].as_str().unwrap().as_bytes());
        let out = r.text(None);
        let bad: Vec<String> = out
            .text
            .chars()
            .filter(|c| forbidden(*c))
            .map(|c| format!("U+{:04X}", c as u32))
            .collect();
        assert!(bad.is_empty(), "{name}: {bad:?} in {:?}", out.text);
        for want in case["shows"].as_array().unwrap() {
            let want = want.as_str().unwrap();
            assert!(
                out.text.contains(want),
                "{name}: {want:?} not in {:?}",
                out.text
            );
        }
        assert!(out.text.len() <= derm_core::project::screen::MAX_TEXT_BYTES);
    }
}

/// The daemon's second pass (contracts/project-tools.md section 3.4): the
/// same filter over text that never went through a reader. Red on the
/// base: `clean` keeps everything.
#[test]
fn pd_clean_removes_control_and_format_characters_and_counts_them() {
    let c = derm_core::project::screen::clean("a\u{202e}b\u{200b}c\u{1b}[0m\u{85}\u{fffd} \n");
    assert_eq!(c.text, "abc[0m\n", "{c:?}");
    assert_eq!(c.removed, 5, "{c:?}");
    let big = "x".repeat(derm_core::project::screen::MAX_TEXT_BYTES + 10);
    let c = derm_core::project::screen::clean(&big);
    assert!(c.truncated && c.text.len() <= derm_core::project::screen::MAX_TEXT_BYTES);
}

// ---------------------------------------------------------------- lane PE

/// P6, P-C6 (contracts/project-tools.md section 2.3): a Claude Code chat
/// under derm starts with `crossSessionInbound: "refuse"` in derm's last
/// `--settings`, since on Linux its inbox takes lines with no auth by
/// default (2.1.322 `ZNr()` is true on Windows only, by read). Red on the
/// base: derm's block does not carry the key.
#[test]
fn pe_a_claude_code_chat_refuses_other_sessions_messages() {
    let block = crate::run::claude_gate::block(&[], "/usr/local/bin/derm", Some("c-a"));
    assert_eq!(block["crossSessionInbound"], "refuse", "{block}");
}
