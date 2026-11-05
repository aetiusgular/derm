//! The lockfile diff per install call (wave 5 lane X; universal plan lane X
//! item 5; rules case 132's "the lockfile diff still records what it
//! installed"). At an install call's start the daemon keeps the project's
//! lockfile entries for that manager; at its end it reads them again and
//! records `install.lockdiff`: packages added, removed and changed, with
//! versions (`contracts/events.md` section 5). Names and versions are
//! metadata, kept with the content switch off (case 85 as changed).
//!
//! The readers are derm-core's (`derm_core::installs::lockfile`), the same
//! the gate uses, held equal to the hook core's by the lockfile fixtures.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};

use derm_core::event::{Event, Source};
use derm_core::installs::lockfile::{
    lockfiles, parse_lockfile, read_lockfile_text, LockEntry, LockKind,
};
use derm_core::installs::Manager;
use serde_json::{json, Value};

/// Calls waiting for their end at once (oldest go first).
pub const MAX_PENDING: usize = 256;
/// A call with no end seen is dropped after this long.
pub const PENDING_MS: i64 = 30 * 60 * 1000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<(String, String)>,
    pub removed: Vec<(String, String)>,
    /// Name, the versions before, the versions after (each joined by ", ").
    pub changed: Vec<(String, String, String)>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

fn versions(entries: &[LockEntry]) -> BTreeMap<&str, BTreeSet<&str>> {
    let mut m: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for e in entries {
        m.entry(e.name.as_str())
            .or_default()
            .insert(e.version.as_str());
    }
    m
}

/// What changed between two lockfiles' entries, by name. A name pinned at
/// several versions (npm's nested copies) changes when the set does.
pub fn diff(before: &[LockEntry], after: &[LockEntry]) -> Diff {
    let b = versions(before);
    let a = versions(after);
    let mut d = Diff::default();
    for (name, vs) in &a {
        match b.get(name) {
            None => d
                .added
                .extend(vs.iter().map(|v| (name.to_string(), v.to_string()))),
            Some(old) if old != vs => d.changed.push((
                name.to_string(),
                old.iter().copied().collect::<Vec<_>>().join(", "),
                vs.iter().copied().collect::<Vec<_>>().join(", "),
            )),
            Some(_) => {}
        }
    }
    for (name, vs) in &b {
        if !a.contains_key(name) {
            d.removed
                .extend(vs.iter().map(|v| (name.to_string(), v.to_string())));
        }
    }
    d
}

struct Pending {
    chat: String,
    harness: String,
    manager: Manager,
    file: PathBuf,
    kind: LockKind,
    before: Option<Vec<LockEntry>>,
    started: i64,
}

/// Lockfile snapshots of install calls in flight.
#[derive(Default)]
pub struct LockDiffs {
    pending: HashMap<String, Pending>,
    order: VecDeque<String>,
}

/// The lockfile `manager` writes for a project folder: the nearest one at or
/// above `cwd`, else the first name in `cwd` itself (a lockfile the install
/// is about to create).
pub fn lockfile_for(manager: Manager, cwd: &Path) -> Option<(PathBuf, LockKind)> {
    let names = lockfiles(manager);
    if names.is_empty() || !cwd.is_absolute() {
        return None;
    }
    for dir in cwd.ancestors().take(32) {
        for (file, kind) in names {
            let p = dir.join(file);
            if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file()) {
                return Some((p, *kind));
            }
        }
    }
    names.first().map(|(file, kind)| (cwd.join(file), *kind))
}

fn read(file: &Path, kind: LockKind) -> Option<Vec<LockEntry>> {
    read_lockfile_text(file).map(|t| parse_lockfile(kind, &t))
}

impl LockDiffs {
    pub fn new() -> Self {
        Self::default()
    }

    /// An install call started: keep its project's lockfile as it is now.
    /// `call` is the `install.call` record's id.
    pub fn start(
        &mut self,
        call: &str,
        chat: &str,
        harness: &str,
        manager: Manager,
        cwd: &Path,
        now: i64,
    ) {
        let Some((file, kind)) = lockfile_for(manager, cwd) else {
            return;
        };
        self.pending.retain(|_, p| now - p.started < PENDING_MS);
        self.order.retain(|c| self.pending.contains_key(c));
        if self.pending.len() >= MAX_PENDING {
            if let Some(old) = self.order.pop_front() {
                self.pending.remove(&old);
            }
        }
        let before = read(&file, kind);
        self.pending.insert(
            call.to_string(),
            Pending {
                chat: chat.to_string(),
                harness: harness.to_string(),
                manager,
                file,
                kind,
                before,
                started: now,
            },
        );
        self.order.push_back(call.to_string());
    }

    /// The call ended: the `install.lockdiff` record, or `None` when nothing
    /// changed (or the call was never started here).
    pub fn finish(&mut self, call: &str, now: i64) -> Option<Event> {
        let p = self.pending.remove(call)?;
        self.order.retain(|c| c != call);
        let after = read(&p.file, p.kind);
        let before = p.before.clone().unwrap_or_default();
        let after = after.unwrap_or_default();
        let d = diff(&before, &after);
        if d.is_empty() {
            return None;
        }
        Some(record(call, &p, &d, now))
    }

    pub fn forget_chat(&mut self, chat: &str) {
        self.pending.retain(|_, p| p.chat != chat);
        self.order.retain(|c| self.pending.contains_key(c));
    }
}

fn pkg(name: &str, version: &str, manager: Manager) -> Value {
    json!({"name": name.chars().take(214).collect::<String>(), "version": version.chars().take(128).collect::<String>(), "ecosystem": manager.ecosystem()})
}

fn record(call: &str, p: &Pending, d: &Diff, now: i64) -> Event {
    let file_name = p
        .file
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut parts = Vec::new();
    if !d.added.is_empty() {
        parts.push(format!("{} added", d.added.len()));
    }
    if !d.removed.is_empty() {
        parts.push(format!("{} removed", d.removed.len()));
    }
    if !d.changed.is_empty() {
        parts.push(format!("{} changed", d.changed.len()));
    }
    Event {
        id: format!("lockdiff-{call}"),
        at: now,
        chat_id: p.chat.clone(),
        harness: p.harness.clone(),
        source: Source::Derm,
        kind: "install.lockdiff".into(),
        summary: format!("{file_name}: {}", parts.join(", ")),
        detail: json!({
            "trust": "daemon",
            "call": call,
            "manager": p.manager.as_str(),
            "lockfile": p.file.to_string_lossy().chars().take(4096).collect::<String>(),
            "added": d.added.iter().map(|(n, v)| pkg(n, v, p.manager)).collect::<Vec<_>>(),
            "removed": d.removed.iter().map(|(n, v)| pkg(n, v, p.manager)).collect::<Vec<_>>(),
            "changed": d.changed.iter().map(|(n, f, t)| json!({"name": n, "from": f, "to": t})).collect::<Vec<_>>(),
        }),
        pid: None,
        approval_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/../../contracts/fixtures/installs/lockfiles/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn every_fixture_pair_diffs_to_the_same_change() {
        // Each manager's before and after: left-pad 1.3.0 then left-pad 1.2.0,
        // is-number 7.0.0, @types/node 20.11.0 (and its undici-types).
        for (b, a, kind) in [
            (
                "package-lock.before.json",
                "package-lock.after.json",
                LockKind::PackageLock,
            ),
            (
                "pnpm-lock.before.yaml",
                "pnpm-lock.after.yaml",
                LockKind::PnpmLock,
            ),
            ("yarn4.before.lock", "yarn4.after.lock", LockKind::YarnLock),
            ("yarn1.before.lock", "yarn1.after.lock", LockKind::YarnLock),
            ("bun.before.lock", "bun.after.lock", LockKind::BunLock),
        ] {
            let d = diff(
                &parse_lockfile(kind, &fixture(b)),
                &parse_lockfile(kind, &fixture(a)),
            );
            let added: Vec<&str> = d.added.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(
                added,
                vec!["@types/node", "is-number", "undici-types"],
                "{a}"
            );
            assert_eq!(
                d.changed,
                vec![("left-pad".into(), "1.3.0".into(), "1.2.0".into())],
                "{a}"
            );
            assert!(d.removed.is_empty(), "{a}");
        }
        for (b, a, kind) in [
            ("uv.before.lock", "uv.after.lock", LockKind::UvLock),
            (
                "poetry.before.lock",
                "poetry.after.lock",
                LockKind::PoetryLock,
            ),
            ("pdm.before.lock", "pdm.after.lock", LockKind::PdmLock),
        ] {
            let d = diff(
                &parse_lockfile(kind, &fixture(b)),
                &parse_lockfile(kind, &fixture(a)),
            );
            assert_eq!(d.added, vec![("idna".into(), "3.10".into())], "{a}");
            assert_eq!(
                d.changed,
                vec![("six".into(), "1.16.0".into(), "1.17.0".into())],
                "{a}"
            );
        }
        let d = diff(
            &parse_lockfile(LockKind::CargoLock, &fixture("Cargo.before.lock")),
            &parse_lockfile(LockKind::CargoLock, &fixture("Cargo.after.lock")),
        );
        assert_eq!(d.added, vec![("ryu".into(), "1.0.18".into())]);
        assert_eq!(
            d.changed,
            vec![("itoa".into(), "1.0.11".into(), "1.0.14".into())]
        );
        let d = diff(
            &parse_lockfile(LockKind::GoSum, &fixture("go.before.sum")),
            &parse_lockfile(LockKind::GoSum, &fixture("go.after.sum")),
        );
        assert_eq!(
            d.added,
            vec![("github.com/BurntSushi/toml".into(), "v1.4.0".into())]
        );
        assert_eq!(
            d.changed,
            vec![(
                "golang.org/x/text".into(),
                "v0.19.0".into(),
                "v0.20.0".into()
            )]
        );
    }

    #[test]
    fn a_removed_package_and_nested_versions() {
        let e = |n: &str, v: &str| LockEntry {
            name: n.into(),
            version: v.into(),
            registry: true,
        };
        let d = diff(&[e("a", "1"), e("b", "1"), e("b", "2")], &[e("b", "2")]);
        assert_eq!(d.removed, vec![("a".into(), "1".into())]);
        assert_eq!(d.changed, vec![("b".into(), "1, 2".into(), "2".into())]);
        assert!(diff(&[e("a", "1")], &[e("a", "1")]).is_empty());
    }

    #[test]
    fn a_call_records_its_diff_at_its_end_in_the_fixtures_shape() {
        let dir = std::env::temp_dir().join(format!("derm-x-lockdiff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            fixture("package-lock.before.json"),
        )
        .unwrap();
        let mut t = LockDiffs::new();
        t.start(
            "claude-code-toolu_INSTALL1-install",
            "chat-fixture",
            "claude-code",
            Manager::Npm,
            &dir.join("sub"),
            1_793_000_005_000,
        );
        std::fs::write(
            dir.join("package-lock.json"),
            fixture("package-lock.after.json"),
        )
        .unwrap();
        let r = t
            .finish("claude-code-toolu_INSTALL1-install", 1_793_000_009_000)
            .unwrap();
        assert_eq!(r.kind, "install.lockdiff");
        assert_eq!(r.source, Source::Derm);
        assert_eq!(r.id, "lockdiff-claude-code-toolu_INSTALL1-install");
        assert_eq!(r.summary, "package-lock.json: 3 added, 1 changed");
        assert_eq!(
            r.detail["lockfile"],
            dir.join("package-lock.json").to_string_lossy().to_string()
        );
        assert_eq!(
            r.detail["added"][0],
            json!({"name": "@types/node", "version": "20.11.0", "ecosystem": "npm"})
        );
        assert_eq!(
            r.detail["changed"][0],
            json!({"name": "left-pad", "from": "1.3.0", "to": "1.2.0"})
        );
        assert!(
            t.finish("claude-code-toolu_INSTALL1-install", 0).is_none(),
            "once"
        );
        // A lockfile the install creates: everything is added.
        std::fs::remove_file(dir.join("package-lock.json")).unwrap();
        t.start("c2", "chat-fixture", "claude-code", Manager::Npm, &dir, 0);
        std::fs::write(
            dir.join("package-lock.json"),
            fixture("package-lock.before.json"),
        )
        .unwrap();
        assert_eq!(
            t.finish("c2", 1).unwrap().summary,
            "package-lock.json: 1 added"
        );
        // Nothing changed: no record.
        t.start("c3", "chat-fixture", "claude-code", Manager::Npm, &dir, 0);
        assert!(t.finish("c3", 1).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_calls_stay_bounded_and_age_out() {
        let dir = std::env::temp_dir();
        let mut t = LockDiffs::new();
        for i in 0..(MAX_PENDING + 10) {
            t.start(&format!("c{i}"), "chat", "pi", Manager::Npm, &dir, 0);
        }
        assert_eq!(t.pending.len(), MAX_PENDING);
        t.start("late", "chat", "pi", Manager::Npm, &dir, PENDING_MS + 1);
        assert_eq!(t.pending.len(), 1, "the old ones aged out");
        t.forget_chat("chat");
        assert!(t.pending.is_empty());
        assert!(
            lockfile_for(Manager::Pipx, &dir).is_none(),
            "pipx keeps no project lockfile"
        );
        assert!(lockfile_for(Manager::Npm, Path::new("relative")).is_none());
    }
}
