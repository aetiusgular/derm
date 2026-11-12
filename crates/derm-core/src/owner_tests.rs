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
