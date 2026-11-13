//! Anchors (`contracts/events.md` section 6.5, E3, case 216): a chain's head
//! kept where the agent cannot write, so a cut at the end or a whole rewrite
//! with a fresh chain shows. The prior art is OpenMoat 0.19.0's ADR-031
//! (`src/anchor.rs`, `src/anchor/git.rs`): one JSON line per anchor, appended
//! to a file the person keeps or committed on a ref of a git repository they
//! name, with plumbing only; nothing is sent anywhere; `verify --anchors`
//! reads them all back and checks that each anchored line is still in the
//! chain with its hash, so each anchor is still a prefix of the chain.
//!
//! derm's line also keeps the first line it verified (`start`), so a later
//! check also sees a cut at the head while that line is still kept (note
//! AZ, AZ-1's fix shape: "anchor each day's first prev").
//!
//! Made from a terminal by a person only (`derm audit anchor`): an agent that
//! could anchor whenever it liked could choose what the person's record says
//! the log was. The check guards against a script, not an agent (case 89).

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

/// The `format` of every anchor line.
pub const FORMAT: &str = "derm-audit-anchor-v1";
/// The ref anchors are committed on.
pub const REF: &str = "refs/derm/anchors";
/// The file in that ref's tree.
const FILE: &str = "anchors.jsonl";

/// One anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Which chain (`Source::label`).
    pub chain: String,
    /// The chain's rule, 1 or 2.
    pub v: u64,
    pub seq: u64,
    pub hash: String,
    /// The first line the anchor verified: its `seq` and `prev`.
    pub start: Option<(u64, String)>,
    pub anchored_ms: i64,
}

impl Record {
    pub fn line(&self) -> String {
        let mut o = json!({
            "format": FORMAT,
            "chain": self.chain,
            "v": self.v,
            "seq": self.seq,
            "hash": self.hash,
            "anchoredMs": self.anchored_ms,
        });
        if let Some((s, p)) = &self.start {
            o["start"] = json!({"seq": s, "prev": p});
        }
        o.to_string()
    }

    pub fn parse(text: &str) -> Result<Record, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        let o = v.as_object().ok_or("not an object")?;
        let allowed = ["format", "chain", "v", "seq", "hash", "start", "anchoredMs"];
        if o.keys().any(|k| !allowed.contains(&k.as_str())) {
            return Err("an unknown key".into());
        }
        if o.get("format").and_then(Value::as_str) != Some(FORMAT) {
            return Err(format!("not a {FORMAT} line"));
        }
        let hash = o.get("hash").and_then(Value::as_str).ok_or("no hash")?;
        if super::chains::parse_mark(&format!("0:{hash}")).is_err() {
            return Err("bad hash".into());
        }
        let start = match o.get("start") {
            None => None,
            Some(s) => {
                let seq = s.get("seq").and_then(Value::as_u64).ok_or("bad start")?;
                let prev = s.get("prev").and_then(Value::as_str).ok_or("bad start")?;
                super::chains::parse_mark(&format!("{seq}:{prev}"))?;
                Some((seq, prev.to_string()))
            }
        };
        Ok(Record {
            chain: o
                .get("chain")
                .and_then(Value::as_str)
                .ok_or("no chain")?
                .to_string(),
            v: o.get("v")
                .and_then(Value::as_u64)
                .filter(|v| *v == 1 || *v == 2)
                .ok_or("bad v")?,
            seq: o.get("seq").and_then(Value::as_u64).ok_or("no seq")?,
            hash: hash.to_string(),
            start,
            anchored_ms: o.get("anchoredMs").and_then(Value::as_i64).unwrap_or(0),
        })
    }
}

/// Anchor lines; blank lines skipped, any other bad line an error: an anchor
/// file that cannot be read in full cannot vouch for a log (OpenMoat's
/// `anchor::parse`).
pub fn parse_all(text: &str) -> Result<Vec<Record>, String> {
    let mut out = Vec::new();
    for (i, l) in text.lines().enumerate() {
        if l.trim().is_empty() {
            continue;
        }
        out.push(Record::parse(l).map_err(|e| format!("anchor line {}: {e}", i + 1))?);
    }
    if out.is_empty() {
        return Err("no anchors recorded".into());
    }
    Ok(out)
}

/// Where anchors are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    Git(PathBuf),
    File(PathBuf),
}

impl Place {
    /// A folder is a git repository, anything else a file.
    pub fn of(path: &Path) -> Place {
        if path.is_dir() {
            Place::Git(path.to_path_buf())
        } else {
            Place::File(path.to_path_buf())
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Place::Git(r) => format!("{} ({REF})", r.display()),
            Place::File(f) => f.display().to_string(),
        }
    }

    /// Every anchor kept here, oldest first.
    pub fn records(&self) -> Result<Vec<Record>, String> {
        let text = match self {
            Place::Git(r) => Git::new(r)?.read()?,
            Place::File(f) => {
                let lines = super::sources::lines_of(std::slice::from_ref(f))?;
                lines
                    .into_iter()
                    .map(|l| l.text)
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        };
        parse_all(&text).map_err(|e| format!("{}: {e}", self.describe()))
    }

    /// Keeps `record` here; for git, the new commit's id.
    pub fn append(&self, record: &Record) -> Result<Option<String>, String> {
        match self {
            Place::Git(r) => Git::new(r)?.append(record).map(Some),
            Place::File(f) => {
                append_private(f, &record.line())?;
                Ok(None)
            }
        }
    }
}

/// Appends one line, in one write, to a file of the person's: created 0600,
/// never through a link, and refused when it is not a plain file.
fn append_private(path: &Path, line: &str) -> Result<(), String> {
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.file_type().is_file() {
            return Err(format!("{}: not a plain file", path.display()));
        }
    }
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut f = o
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !f.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return Err(format!("{}: not a plain file", path.display()));
    }
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// git in one repository the person named, plumbing only.
///
/// What runs is the person's `git` from their PATH, in a terminal they typed
/// the command in. Nothing the repository's own config names runs (rules
/// cases 27 and 31, run with git 2.43.0 here): `core.hooksPath=/dev/null`
/// (git runs the `reference-transaction` hook on `update-ref`; seen in a
/// run, and not with the setting), `core.fsmonitor=false`, and
/// `protocol.allow=never`, so a read of a missing object in a partial clone
/// fails instead of fetching through the transport the repository names
/// (seen: "could not fetch ... from promisor remote"). The environment's
/// `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` and
/// `GIT_CONFIG_*` are removed, so the repository is the one named. Nothing is
/// pushed or fetched; the working tree, the index, `HEAD` and the branches
/// are never touched.
pub struct Git {
    dir: PathBuf,
}

impl Git {
    pub fn new(dir: &Path) -> Result<Git, String> {
        let g = Git {
            dir: dir.to_path_buf(),
        };
        g.run(&["rev-parse", "--git-dir"], None)
            .map_err(|_| format!("{} is not a git repository", dir.display()))?;
        Ok(g)
    }

    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<String, String> {
        let mut c = Command::new("git");
        c.arg("-C")
            .arg(&self.dir)
            .args([
                "--no-pager",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "protocol.allow=never",
            ])
            .args(args);
        for v in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
            "GIT_ALLOW_PROTOCOL",
            "GIT_EXEC_PATH",
        ] {
            c.env_remove(v);
        }
        c.env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| format!("running git: {e}"))?;
        if let (Some(b), Some(mut p)) = (stdin, child.stdin.take()) {
            p.write_all(b).map_err(|e| format!("writing to git: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting for git: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git {} failed: {}",
                args.first().copied().unwrap_or_default(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
    }

    fn tip(&self) -> Option<String> {
        let target = format!("{REF}^{{commit}}");
        self.run(&["rev-parse", "--verify", "--quiet", &target], None)
            .ok()
            .filter(|t| !t.is_empty())
    }

    fn file_at(&self, tip: Option<&str>) -> Result<String, String> {
        match tip {
            None => Ok(String::new()),
            Some(t) => self
                .run(&["cat-file", "blob", &format!("{t}:{FILE}")], None)
                .map(|s| s + "\n"),
        }
    }

    pub fn read(&self) -> Result<String, String> {
        let tip = self
            .tip()
            .ok_or_else(|| format!("no anchors in {}: {REF} does not exist", self.dir.display()))?;
        self.file_at(Some(&tip))
    }

    /// Commits `record` on [`REF`] against the tip it read, so two anchors
    /// made at once cannot drop one another.
    pub fn append(&self, record: &Record) -> Result<String, String> {
        let tip = self.tip();
        let mut text = self.file_at(tip.as_deref())?;
        text.push_str(&record.line());
        text.push('\n');
        let blob = self.run(&["hash-object", "-w", "--stdin"], Some(text.as_bytes()))?;
        let entry = format!("100644 blob {blob}\t{FILE}\n");
        let tree = self.run(&["mktree"], Some(entry.as_bytes()))?;
        let message = format!(
            "derm audit anchor: {} seq {}\n\nchain {}\nseq {}\nhash {}\n",
            record.chain, record.seq, record.chain, record.seq, record.hash
        );
        let mut args = vec!["commit-tree", tree.as_str()];
        if let Some(p) = &tip {
            args.extend(["-p", p.as_str()]);
        }
        let commit = self.run(&args, Some(message.as_bytes()))?;
        let zero = "0".repeat(blob.len());
        let old = tip.as_deref().unwrap_or(&zero);
        self.run(
            &["update-ref", "-m", "derm audit anchor", REF, &commit, old],
            None,
        )?;
        Ok(commit)
    }
}

/// Why this process should not anchor, or `None`: inside a `derm run` chat,
/// or with no terminal. A pty is not a person (case 89).
pub fn refuse(var: &dyn Fn(&str) -> Option<std::ffi::OsString>, tty: bool) -> Option<String> {
    for v in ["DERM_CHAT_TOKEN", "DERM_CHAT_TOKEN_FILE"] {
        if var(v).is_some_and(|x| !x.is_empty()) {
            return Some(format!(
                "{v} is set, so this runs inside a derm run chat; anchor from your own terminal"
            ));
        }
    }
    #[cfg(unix)]
    {
        let me = derm_core::platform::peer::me();
        if let Some(p) = derm_core::platform::peer::derm_run_ancestor(me) {
            return Some(format!(
                "a derm run (pid {p}) started this; anchor from your own terminal"
            ));
        }
    }
    if !tty {
        return Some("derm audit anchor is run by a person in a terminal, not by a script".into());
    }
    None
}

/// Both stdin and stderr are terminals. Never in a test build.
#[cfg(all(unix, not(test)))]
pub fn on_terminal() -> bool {
    // SAFETY: isatty reads only the descriptor number.
    unsafe { libc::isatty(0) == 1 && libc::isatty(2) == 1 }
}

#[cfg(any(not(unix), test))]
pub fn on_terminal() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u64) -> Record {
        Record {
            chain: "daemon".into(),
            v: 1,
            seq,
            hash: "b".repeat(64),
            start: Some((1, "0".repeat(64))),
            anchored_ms: 5,
        }
    }

    #[test]
    fn a_record_round_trips_and_strays_are_refused() {
        let r = rec(3);
        assert_eq!(Record::parse(&r.line()).unwrap(), r);
        let mut v: Value = serde_json::from_str(&r.line()).unwrap();
        v["extra"] = json!(1);
        assert!(Record::parse(&v.to_string()).is_err());
        assert!(Record::parse(&r.line().replace(FORMAT, "moat-audit-anchor-v1")).is_err());
        assert!(parse_all("\n\n").is_err());
        assert!(parse_all(&format!("{}\nnot json", r.line())).is_err());
    }

    #[test]
    fn a_file_place_appends_privately_and_refuses_a_link() {
        let d = std::env::temp_dir().join(format!("da-anc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let f = d.join("anchors");
        let p = Place::File(f.clone());
        p.append(&rec(1)).unwrap();
        p.append(&rec(2)).unwrap();
        let got = p.records().unwrap();
        assert_eq!(got.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = d.join("link");
            std::os::unix::fs::symlink(&f, &link).unwrap();
            assert!(Place::File(link).append(&rec(3)).is_err());
        }
        let _ = fs::remove_dir_all(&d);
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let o = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "{:?}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    /// Unix only: `core.hooksPath=/dev/null` under Git for Windows is not
    /// verified (lane 6E's status doc).
    #[cfg(unix)]
    #[test]
    fn a_git_place_commits_on_its_ref_and_runs_no_repository_hook() {
        let d = std::env::temp_dir().join(format!("da-git-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        git(&d, &["init", "-q"]);
        git(&d, &["config", "user.name", "T"]);
        git(&d, &["config", "user.email", "t@example.invalid"]);
        // A hook the repository names: it must not run (case 27).
        let mark = d.join("hook-ran");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for h in ["reference-transaction", "post-commit"] {
                let p = d.join(".git/hooks").join(h);
                fs::write(&p, format!("#!/bin/sh\ntouch {}\n", mark.display())).unwrap();
                fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let p = Place::of(&d);
        assert!(matches!(p, Place::Git(_)));
        let c1 = p.append(&rec(1)).unwrap().unwrap();
        let c2 = p.append(&rec(2)).unwrap().unwrap();
        assert_ne!(c1, c2);
        assert_eq!(p.records().unwrap().len(), 2);
        assert!(!mark.exists(), "a repository hook ran");
        // HEAD and the branches are untouched: no commit on a branch.
        assert!(Command::new("git")
            .arg("-C")
            .arg(&d)
            .args(["rev-parse", "--verify", "--quiet", "HEAD"])
            .output()
            .unwrap()
            .stdout
            .is_empty());
        assert_eq!(git(&d, &["rev-parse", REF]), c2);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_folder_that_is_no_repository_is_refused() {
        let d = std::env::temp_dir().join(format!("da-nogit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        // The temp folder sits in no repository (checked: git finds none).
        assert!(Git::new(&d).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn anchoring_is_refused_in_a_chat_and_without_a_terminal() {
        let none = |_: &str| None;
        assert!(refuse(&none, false).unwrap().contains("terminal"));
        let chat = |v: &str| (v == "DERM_CHAT_TOKEN").then(|| "x".into());
        assert!(refuse(&chat, true).unwrap().contains("derm run chat"));
        let file = |v: &str| (v == "DERM_CHAT_TOKEN_FILE").then(|| "/t".into());
        assert!(refuse(&file, true).is_some());
    }
}
