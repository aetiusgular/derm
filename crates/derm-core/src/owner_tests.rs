//! `owner.test.ts`'s `ownersFor` and `readAnchor` cases (the gate's own
//! checks under an agents' user are in `derm-cli`'s `gate/daemon_tests.rs`).

use super::*;
use serde_json::json;

fn entry(uid: u32, owner_uid: u32) -> String {
    json!({"version": 1, "agents": [{"user": "derm-agent", "uid": uid, "owner": "tony", "ownerUid": owner_uid, "path": "/usr/bin", "how": "sudo"}]}).to_string()
}

fn trusted(uids: &[u32], agent: bool) -> Owners {
    Owners {
        uids: uids.to_vec(),
        agent,
        problem: None,
    }
}

#[test]
fn trusts_this_user_when_there_is_no_file_or_no_entry_for_it() {
    assert_eq!(owners_for(1000, None), trusted(&[1000], false));
    assert_eq!(
        owners_for(1000, Some(&entry(998, 1001))),
        trusted(&[1000], false)
    );
}

#[test]
fn trusts_only_the_owner_under_an_agents_user() {
    assert_eq!(
        owners_for(998, Some(&entry(998, 1000))),
        trusted(&[1000], true)
    );
}

#[test]
fn trusts_no_one_when_the_file_is_broken_or_names_nonsense() {
    for text in [
        "{",
        "[]",
        r#"{"version":2,"agents":[]}"#,
        r#"{"version":1,"agents":[{"uid":"998"}]}"#,
    ] {
        let o = owners_for(998, Some(text));
        assert!(o.uids.is_empty(), "{text}");
        assert!(o.problem.is_some(), "{text}");
    }
    assert!(owners_for(998, Some(&entry(998, 998))).uids.is_empty());
    assert!(owners_for(998, Some(&entry(998, 0))).uids.is_empty());
    let a: Value = serde_json::from_str(&entry(998, 1000)).unwrap();
    let b: Value = serde_json::from_str(&entry(998, 1001)).unwrap();
    let two = json!({"version": 1, "agents": [a["agents"][0], b["agents"][0]]}).to_string();
    assert!(owners_for(998, Some(&two)).uids.is_empty());
}

fn accounts(uids: &[u32]) -> String {
    let a: Vec<Value> = uids
        .iter()
        .map(|u| json!({"name": format!("derm-a{u}"), "uid": u, "subscription": "s", "home": format!("/var/lib/derm/agents/a{u}")}))
        .collect();
    json!({"version": 1, "group": "derm-agents", "accounts": a}).to_string()
}

/// Review R2 (red first): an agent account trusts the people who own a
/// bridge base, never itself or another account.
#[test]
fn r2_an_agent_account_trusts_the_bridges_people_and_never_an_account() {
    let text = accounts(&[996, 995]);
    assert_eq!(
        owners_for_account(996, Some(&text), &[1000, 1001, 995, 996]),
        Some(trusted(&[1000, 1001], true)),
    );
    // Not an account: the old rules decide.
    assert_eq!(owners_for_account(1000, Some(&text), &[1000]), None);
    assert_eq!(owners_for_account(996, None, &[1000]), None);
    // No bridge base: no one, every call asks.
    let o = owners_for_account(996, Some(&text), &[]).unwrap();
    assert!(o.uids.is_empty() && o.agent && o.problem.is_some(), "{o:?}");
    // Root is never a bridge's person.
    let o = owners_for_account(996, Some(&text), &[0]).unwrap();
    assert!(o.uids.is_empty(), "{o:?}");
    // A file that cannot be read whole: no one.
    for bad in [
        "{",
        r#"{"version":2,"accounts":[]}"#,
        r#"{"version":1,"accounts":[{"uid":"996"}]}"#,
    ] {
        let o = owners_for_account(996, Some(bad), &[1000]).unwrap();
        assert!(o.uids.is_empty() && o.problem.is_some(), "{bad}: {o:?}");
    }
}

#[cfg(unix)]
#[test]
fn r2_bridge_owners_are_the_folders_that_name_their_own_owner() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let root = std::env::temp_dir().join(format!("derm-bridges-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mine = root.join(me.to_string());
    std::fs::create_dir(&mine).unwrap();
    std::fs::set_permissions(&mine, std::fs::Permissions::from_mode(0o711)).unwrap();
    // Named for someone else, owned by me: not theirs, dropped.
    let other = root.join((me + 1).to_string());
    std::fs::create_dir(&other).unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o711)).unwrap();
    // Not a number, a link, one others can write: dropped.
    std::fs::create_dir(root.join("x")).unwrap();
    std::os::unix::fs::symlink(&mine, root.join("7")).unwrap();
    assert_eq!(bridge_owners(&root, me), vec![me]);
    std::fs::set_permissions(&mine, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(bridge_owners(&root, me).is_empty());
    std::fs::set_permissions(&mine, std::fs::Permissions::from_mode(0o711)).unwrap();
    // A root others can write trusts nothing under it.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(bridge_owners(&root, me).is_empty());
    // A root of someone else's trusts nothing under it.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(bridge_owners(&root, me + 7).is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
mod anchor {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};

    fn me() -> u32 {
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() }
    }

    struct Tree {
        root: PathBuf,
        file: PathBuf,
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn mode(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }
    fn tree() -> Tree {
        let root = std::env::temp_dir().join(format!("derm-owner-{}", uuid_like()));
        let dir = root.join("etc").join("derm");
        std::fs::create_dir_all(&dir).unwrap();
        for p in [&root, &root.join("etc"), &dir] {
            mode(p, 0o755);
        }
        let file = dir.join("agent-users.json");
        std::fs::write(&file, entry(998, 1000)).unwrap();
        mode(&file, 0o644);
        Tree { root, file }
    }
    fn uuid_like() -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        format!(
            "{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[test]
    fn reads_a_file_whose_whole_path_the_trusted_user_holds() {
        let t = tree();
        assert_eq!(
            read_anchor(&t.file, &t.root, me()),
            Anchor::Text(entry(998, 1000))
        );
        assert_eq!(
            read_anchor(&t.root.join("none.json"), &t.root, me()),
            Anchor::Absent
        );
    }

    fn problem(a: Anchor, needle: &str) {
        match a {
            Anchor::Problem(p) => assert!(p.contains(needle), "{p}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn refuses_one_others_can_write_a_link_or_one_another_user_owns() {
        let t = tree();
        mode(&t.file, 0o666);
        problem(
            read_anchor(&t.file, &t.root, me()),
            "written by group or others",
        );
        let t = tree();
        mode(t.file.parent().unwrap(), 0o777);
        problem(
            read_anchor(&t.file, &t.root, me()),
            "written by group or others",
        );
        let t = tree();
        let real = t.root.join("real.json");
        std::fs::write(&real, entry(998, 1000)).unwrap();
        mode(&real, 0o644);
        std::fs::remove_file(&t.file).unwrap();
        symlink(&real, &t.file).unwrap();
        problem(read_anchor(&t.file, &t.root, me()), "is a link");
        let t = tree();
        problem(read_anchor(&t.file, &t.root, me() + 1), "not owned by uid");
    }
}

/// BT-11: a hint names only a base listing would have found; a path not
/// under the root, one through `..`, a first part that is no plain number,
/// and a base not named by its own owner name no one.
#[cfg(unix)]
#[test]
fn bt_11_a_hint_names_only_a_bridge_base_of_its_own_owner() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let root = std::env::temp_dir().join(format!("derm-bt11-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mine = root.join(me.to_string());
    std::fs::create_dir(&mine).unwrap();
    std::fs::set_permissions(&mine, std::fs::Permissions::from_mode(0o711)).unwrap();
    let other = root.join((me + 1).to_string());
    std::fs::create_dir(&other).unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o711)).unwrap();
    let tok = mine.join("chat-x/chat.token");
    assert_eq!(bridge_owners_for(&root, me, &[tok.as_path()]), vec![me]);
    for bad in [
        std::path::PathBuf::from("/tmp/x/chat.token"),
        root.join("../x/chat.token"),
        root.join(format!("+{me}/chat.token")),
        other.join("chat-x/chat.token"),
    ] {
        // Listing still finds mine; the hint adds no one.
        assert_eq!(
            bridge_owners_for(&root, me, &[bad.as_path()]),
            vec![me],
            "{bad:?}"
        );
    }
    std::fs::set_permissions(&mine, std::fs::Permissions::from_mode(0o731)).unwrap();
    assert!(bridge_owners_for(&root, me, &[tok.as_path()]).is_empty());
    // A root of someone else's trusts no hint.
    std::fs::set_permissions(&mine, std::fs::Permissions::from_mode(0o711)).unwrap();
    assert!(bridge_owners_for(&root, me + 7, &[tok.as_path()]).is_empty());
    let _ = std::fs::remove_dir_all(&root);
}
