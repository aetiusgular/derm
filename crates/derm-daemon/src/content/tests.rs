use super::*;
use derm_tap::content::{open, Target};

const T0: i64 = 1_793_000_000_000;

fn root(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("derm-content-purge-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(data: &Path, chat: &str, at: i64, days: u8, id: &str) -> PathBuf {
    let mut f = open(&Target { root: data.to_path_buf(), retention_days: days }, chat, at, id, "request").unwrap();
    f.append(b"PROMPT");
    f.path.clone()
}

#[test]
fn case_126_files_go_at_their_own_retention_and_the_records_stay_hashed() {
    let data = root("retention");
    let short = write(&data, "chat-a", T0, 1, "r1");
    let long = write(&data, "chat-a", T0, 7, "r7");
    let mut p = Purger::new(&data);
    assert!(p.pass_with(T0 + DAY_MS - 1, 0).is_empty());
    let ev = p.pass_with(T0 + DAY_MS, 0);
    assert!(!short.exists() && long.exists(), "shortening or turning off deletes nothing early");
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].kind, "content.purge");
    assert_eq!(ev[0].source, Source::Derm);
    assert_eq!(ev[0].chat_id, "chat-a");
    assert_eq!(ev[0].detail, json!({"trust": "daemon", "files": 1, "bytes": 6, "retentionDays": 1, "reason": "retention"}));
    assert!(!serde_json::to_string(&ev).unwrap().contains("PROMPT"));
    assert_eq!(kept(&data), (1, 6, Some(T0 + 7 * DAY_MS)));
    p.pass_with(T0 + 7 * DAY_MS, 0);
    assert!(!long.exists());
    assert!(!data.join("content/chat-a").exists(), "an empty chat folder goes too");
    assert_eq!(kept(&data), (0, 0, None));
    let _ = std::fs::remove_dir_all(data);
}

#[test]
fn case_126_a_clock_set_back_still_deletes_on_time_across_a_restart() {
    let data = root("clock");
    let f = write(&data, "chat-b", T0, 2, "r");
    // The wall clock jumps back ten days right after the file was written.
    let back = T0 - 10 * DAY_MS;
    let mut p = Purger::new(&data);
    assert!(p.pass_with(back, DAY_MS).is_empty());
    assert!(f.exists());
    // The daemon restarts: what it saw pass is kept in .ages.json.
    let ages = data.join("content/.ages.json");
    assert_eq!(std::fs::metadata(&ages).unwrap().mode() & 0o777, 0o600);
    let mut p = Purger::new(&data);
    assert!(p.pass_with(back + DAY_MS, DAY_MS - 1).is_empty());
    assert_eq!(p.pass_with(back + 2 * DAY_MS, 1).len(), 1);
    assert!(!f.exists());
    let _ = std::fs::remove_dir_all(data);
}

#[test]
fn a_clock_moved_forward_deletes_early_never_late() {
    let data = root("forward");
    let f = write(&data, "chat-c", T0, 3, "r");
    let mut p = Purger::new(&data);
    p.pass_with(T0 + 30 * DAY_MS, 0);
    assert!(!f.exists());
    let _ = std::fs::remove_dir_all(data);
}

#[test]
fn links_and_strangers_files_are_never_followed_or_deleted() {
    use std::os::unix::fs::PermissionsExt;
    let data = root("links");
    write(&data, "chat-d", T0, 1, "r");
    // Someone else's files, and a chat folder that is a link to them.
    let elsewhere = data.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
    let victim = elsewhere.join(format!("{T0}-r1-x.request"));
    std::fs::write(&victim, "keep").unwrap();
    std::os::unix::fs::symlink(&elsewhere, data.join("content/chat-e")).unwrap();
    // A link inside a real chat folder, named like content.
    std::os::unix::fs::symlink(&victim, data.join(format!("content/chat-d/{T0}-r1-link.request"))).unwrap();
    // A file whose name the layout does not know.
    std::fs::write(data.join("content/chat-d/notes.txt"), "mine").unwrap();
    let mut p = Purger::new(&data);
    let ev = p.pass_with(T0 + 2 * DAY_MS, 0);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].detail["files"], 1);
    assert!(victim.exists());
    assert!(data.join("content/chat-d/notes.txt").exists());
    assert!(data.join("content/chat-d").exists(), "a folder with other files stays");
    let _ = std::fs::remove_dir_all(data);
}

#[test]
fn a_content_folder_others_can_read_is_left_alone() {
    use std::os::unix::fs::PermissionsExt;
    let data = root("shared");
    let f = write(&data, "chat-f", T0, 1, "r");
    std::fs::set_permissions(data.join("content"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut p = Purger::new(&data);
    assert!(p.pass_with(T0 + 5 * DAY_MS, 0).is_empty());
    assert!(f.exists());
    let _ = std::fs::remove_dir_all(data);
}
