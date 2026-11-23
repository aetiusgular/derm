//! The audit rules file for one user. Printed, never installed: the install
//! runs as root, so it is shown and confirmed in the box test before it runs
//! (rules section 5, item 2, and section 10).
//!
//! Syntax and fields are auditctl's at 3.1.2 (man page, noble). Loaded and
//! checked in the lane's workspace on 27 Oct 2026: `auditctl -R` accepts
//! every line and `auditctl -l` prints `a2&0x3` and `a2&0x40` for the flag
//! filters. A `-F dir=` rule for a folder that does not exist does not
//! load, nor does a `-F path=` rule whose parent folder does not exist, and
//! without `-c` every rule after it is lost too (run: "There was an error in
//! line 2", then no rules). So the file starts with `-c`, those lines are
//! written only for paths that can load now, and they come last: a path
//! deleted before the next boot costs its own line only.
//!
//! A `-F path=` rule for a file that does not exist yet loads when its
//! parent folder exists, and records the file's opens once it is made (run
//! in the cloud workspace, 16 Nov 2026, auditctl 3.1.2, kernel 6.x: the rule
//! lists, and `cat` of the file made afterwards has a record with the key;
//! E1-3). So a missing sensitive file gets its rule when its folder is
//! there. A missing folder cannot be covered ahead of time: `-F path=` on
//! it records opens of the folder itself and creations in it, not reads of
//! the files inside (same run). `watchcheck.rs` finds those at run time.
//!
//! What it records, for processes of `uid` only (the kernel cannot filter
//! by process tree; `tree.rs` does that):
//! - `derm_exec`: execve and execveat, plus those of root processes whose
//!   login uid is the user's (a harness that ran `sudo`);
//! - `derm_fork`: clone, fork, vfork, clone3, for the tree;
//! - `derm_write`: open and openat with O_WRONLY, O_RDWR or O_CREAT, creat,
//!   openat2 (flags not filterable), truncate, rename*, unlink*, link*,
//!   symlink*;
//! - `derm_net`: connect (and i386 socketcall with call 3, connect);
//! - `derm_sens`: opens under the sensitive folders that exist when the file
//!   is made, and of the sensitive files whose folder exists then.
//!
//! The write rules come before the sensitive ones: the first matching rule
//! sets the key, and a read of `~/.ssh/id_x` matches no write rule, so it
//! gets `derm_sens`.

use crate::sensitive::{HOME_DIRS, HOME_FILES, SYSTEM_DIRS, SYSTEM_FILES};
use crate::syscalls::{names, Call, ARCH_I386, ARCH_X86_64};

pub struct RulesInput<'a> {
    pub uid: u32,
    pub home: &'a str,
    /// `$XDG_RUNTIME_DIR`, where the daemon keeps its token when it is set.
    pub runtime_dir: Option<&'a str>,
    /// Whether a path exists; the caller passes `Path::exists`.
    pub exists: &'a dyn Fn(&str) -> bool,
}

/// The rules text, and the sensitive paths left out because they do not
/// exist (shown to the user with the file).
pub fn render(input: &RulesInput) -> (String, Vec<String>) {
    let uid = input.uid;
    let mut out = String::new();
    out.push_str("## derm: the Linux OS feed (crates/derm-audit-linux). Generated; do not edit.\n");
    out.push_str("## Install (root, shown before it runs): install -m 0640 this file\n");
    // One file per uid, so rules for the agents' user never replace the
    // person's (box test w5, BW5-15).
    out.push_str(&format!(
        "##   /etc/audit/rules.d/50-derm-{uid}.rules && augenrules --load\n"
    ));
    out.push_str(&format!(
        "## Records processes of uid {uid}; the feed keeps only a derm run chat's process tree.\n"
    ));
    out.push_str(
        "## -c: keep loading past a rule that fails (a sensitive path deleted since).\n-c\n",
    );
    syscall_rules(&mut out, uid);
    let skipped = sensitive_rules(
        &mut out,
        uid,
        sensitive_paths(input.home, input.runtime_dir),
        input.exists,
    );
    (out, skipped)
}

/// Where every agent account's home is (`/etc/derm/agents.json`'s `home`,
/// whose one reader refuses any other, `crates/derm-cli/src/run/user/
/// accounts.rs`; `plans/parallel_build_accounts.md` section 2).
pub const AGENTS_ROOT: &str = "/var/lib/derm/agents";

/// The account's sign-in store under its home (`derm_core::project::layout::
/// SIGNIN`, made by the installer, `contracts/projects.md` 2.2).
pub const SIGNIN: &str = derm_core::project::layout::SIGNIN;

/// An agent account's slug as the accounts file takes it: `[a-z0-9-]{1,15}`,
/// and not `agent`, `agents` or `agent-*` (case 278).
pub fn account_slug(slug: &str) -> bool {
    (1..=15).contains(&slug.len())
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && slug != "agent"
        && slug != "agents"
        && !slug.starts_with("agent-")
}

pub struct AccountInput<'a> {
    /// The account's uid (never 0).
    pub uid: u32,
    /// The account's slug: its user is `derm-<slug>`, its home
    /// `/var/lib/derm/agents/<slug>`.
    pub slug: &'a str,
    /// Whether a path exists; the caller passes `Path::exists`.
    pub exists: &'a dyn Fn(&str) -> bool,
}

/// What an agent account's rules watch for reads, in order: its sign-in
/// store (step P4's `signin.read`, `contracts/events.md` 7.2), then the
/// system's secret files. Not the account home's own dot-files: since step
/// P a chat's `HOME` is a project home, and its run-later files are writes,
/// which the syscall rules already record.
pub fn account_paths(slug: &str) -> Vec<(Watch, String)> {
    let mut out = vec![(Watch::Dir, format!("{AGENTS_ROOT}/{slug}/{SIGNIN}"))];
    for d in SYSTEM_DIRS {
        out.push((Watch::Dir, (*d).to_string()));
    }
    for f in SYSTEM_FILES {
        out.push((Watch::File, (*f).to_string()));
    }
    out
}

/// The rules file for one agent account (step P, lane PC; note CD section 5,
/// `signin.read` and `net.unix`): the same syscall rules as the person's,
/// for the account's uid, so its chats' writes and connects (Unix sockets
/// included) reach the feed, and a `derm_sens` watch on its sign-in store.
/// Its own file, `50-derm-<uid>.rules`, beside the person's (BW5-15).
/// Printed, never installed: installing it is root's, on the box only on
/// Tony's yes (rules section 5, item 2).
pub fn render_account(input: &AccountInput) -> Result<(String, Vec<String>), String> {
    let uid = input.uid;
    if uid == 0 {
        return Err("refusing uid 0: an agent account is never root".into());
    }
    if !account_slug(input.slug) {
        return Err(format!(
            "{:?} is not an agent account's slug ([a-z0-9-]{{1,15}}, not agent, agents or agent-*)",
            input.slug
        ));
    }
    let slug = input.slug;
    let mut out = String::new();
    out.push_str(
        "## derm: the Linux OS feed (crates/derm-audit-linux). Generated; do not edit.
",
    );
    out.push_str(&format!(
        "## The agent account derm-{slug} (uid {uid}), home {AGENTS_ROOT}/{slug}: its chats' processes,
"
    ));
    out.push_str(
        "## and reads of its sign-in store by anything but the harness (derm's signin.read).
",
    );
    out.push_str(
        "## Install (root, shown before it runs): install -m 0640 this file
",
    );
    out.push_str(&format!(
        "##   /etc/audit/rules.d/50-derm-{uid}.rules && augenrules --load
"
    ));
    out.push_str("## Undo: rm /etc/audit/rules.d/50-derm-");
    out.push_str(&format!(
        "{uid}.rules && augenrules --load
"
    ));
    out.push_str(
        "## -c: keep loading past a rule that fails (a sensitive path deleted since).
-c
",
    );
    syscall_rules(&mut out, uid);
    let skipped = sensitive_rules(&mut out, uid, account_paths(slug), input.exists);
    Ok((out, skipped))
}

/// The syscall rules for `uid`: exec, fork, write, connect (both ABIs).
fn syscall_rules(out: &mut String, uid: u32) {
    for (arch, tag) in [(ARCH_X86_64, "b64"), (ARCH_I386, "b32")] {
        let list = |kinds: &[Call]| names(arch, kinds).join(",");
        let a = format!("-a always,exit -F arch={tag}");
        out.push_str(&format!(
            "{a} -S {} -F uid={uid} -k derm_exec\n",
            list(&[Call::Exec])
        ));
        out.push_str(&format!(
            "{a} -S {} -F auid={uid} -F euid=0 -k derm_exec\n",
            list(&[Call::Exec])
        ));
        out.push_str(&format!(
            "{a} -S {} -F uid={uid} -k derm_fork\n",
            list(&[Call::Fork])
        ));
        out.push_str(&format!(
            "{a} -S openat -F a2&03 -F uid={uid} -k derm_write\n"
        ));
        out.push_str(&format!(
            "{a} -S openat -F a2&0100 -F uid={uid} -k derm_write\n"
        ));
        out.push_str(&format!(
            "{a} -S open -F a1&03 -F uid={uid} -k derm_write\n"
        ));
        out.push_str(&format!(
            "{a} -S open -F a1&0100 -F uid={uid} -k derm_write\n"
        ));
        out.push_str(&format!(
            "{a} -S {} -F uid={uid} -k derm_write\n",
            list(&[
                Call::Creat,
                Call::OpenAt2,
                Call::Truncate,
                Call::Rename,
                Call::Unlink,
                Call::Link,
                Call::Symlink
            ])
        ));
        out.push_str(&format!("{a} -S connect -F uid={uid} -k derm_net\n"));
        if arch == ARCH_I386 {
            out.push_str(&format!(
                "{a} -S socketcall -F a0=3 -F uid={uid} -k derm_net\n"
            ));
        }
    }
}

/// The `derm_sens` lines for the watches that can load now; returns the
/// paths left out because they cannot.
fn sensitive_rules(
    out: &mut String,
    uid: u32,
    watches: Vec<(Watch, String)>,
    exists: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    let mut skipped = Vec::new();
    for (kind, path) in watches {
        let loads = match kind {
            Watch::Dir => exists(&path),
            // E1-3: a file's rule loads once its folder is there.
            Watch::File => exists(&path) || parent(&path).is_some_and(exists),
        };
        if !loads {
            skipped.push(path);
            continue;
        }
        let field = match kind {
            Watch::Dir => "dir",
            Watch::File => "path",
        };
        for tag in ["b64", "b32"] {
            out.push_str(&format!(
                "-a always,exit -F arch={tag} -S open,openat -F {field}={path} -F uid={uid} -k derm_sens\n"
            ));
        }
    }
    skipped
}

/// How a sensitive path is watched: a folder with everything under it, or
/// one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Watch {
    Dir,
    File,
}

/// Every path the rules file names for `derm_sens`, in its order: the one
/// list `render` writes rules from and `watchcheck` checks at run time.
pub fn sensitive_paths(home: &str, runtime_dir: Option<&str>) -> Vec<(Watch, String)> {
    let home = home.trim_end_matches('/');
    let mut out = Vec::new();
    for d in HOME_DIRS {
        out.push((Watch::Dir, format!("{home}/{d}")));
    }
    for d in SYSTEM_DIRS {
        out.push((Watch::Dir, (*d).to_string()));
    }
    if let Some(rt) = runtime_dir.filter(|r| plain_path(r)) {
        let rt = rt.trim_end_matches('/');
        out.push((Watch::Dir, format!("{rt}/derm")));
        // The old name's token folder, while a tk-daemon may be left running
        // (rename review R1).
        out.push((Watch::Dir, format!("{rt}/tk")));
    }
    for f in HOME_FILES {
        out.push((Watch::File, format!("{home}/{f}")));
    }
    for f in SYSTEM_FILES {
        out.push((Watch::File, (*f).to_string()));
    }
    out
}

fn parent(path: &str) -> Option<&str> {
    let (dir, _) = path.rsplit_once('/')?;
    (!dir.is_empty()).then_some(dir)
}

/// Whether a home path can go into a rule line unquoted: auditctl splits on
/// spaces, and the rules file has no quoting.
pub fn plain_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.split('/').any(|p| p == "..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_both_abis_and_only_existing_sensitive_paths() {
        let exists = |p: &str| p.ends_with("/.ssh") || p == "/etc/shadow";
        let (text, skipped) = render(&RulesInput {
            uid: 1000,
            home: "/home/ubuntu",
            runtime_dir: Some("/run/user/1000"),
            exists: &exists,
        });
        assert!(text.contains("\n-c\n"), "keeps loading past a failed rule");
        assert!(skipped.contains(&"/run/user/1000/derm".to_string()));
        assert!(skipped.contains(&"/run/user/1000/tk".to_string()));
        assert!(text
            .contains("-a always,exit -F arch=b64 -S execve,execveat -F uid=1000 -k derm_exec\n"));
        assert!(text.contains("-F arch=b32 -S socketcall -F a0=3 -F uid=1000 -k derm_net\n"));
        assert!(text.contains("-F dir=/home/ubuntu/.ssh -F uid=1000 -k derm_sens\n"));
        assert!(text.contains("-F path=/etc/shadow"));
        assert!(!text.contains(".netrc"));
        assert!(skipped.contains(&"/home/ubuntu/.netrc".to_string()));
        // The write rules come before the sensitive ones (first match keys).
        assert!(text.find("derm_write").unwrap() < text.find("derm_sens").unwrap());
        // No rule names a key longer than 31 bytes (auditctl's limit).
        for line in text.lines().filter(|l| l.starts_with("-a")) {
            let key = line.rsplit("-k ").next().unwrap();
            assert!(key.len() <= 31, "{line}");
        }
    }

    /// E1-3 (eval pass 1): `~/.npmrc` did not exist when the rules were
    /// made, so it had no rule and a later read of it was not recorded. A
    /// file's rule loads when its folder exists (see the module comment),
    /// so it is written; a file whose folder is missing, and a missing
    /// folder, still cannot be.
    #[test]
    fn e1_3_a_missing_file_gets_its_rule_when_its_folder_exists() {
        let exists = |p: &str| matches!(p, "/home/u" | "/home/u/.docker" | "/etc");
        let (text, skipped) = render(&RulesInput {
            uid: 1000,
            home: "/home/u",
            runtime_dir: None,
            exists: &exists,
        });
        assert!(text.contains("-S open,openat -F path=/home/u/.npmrc -F uid=1000 -k derm_sens\n"));
        assert!(text.contains("-F path=/home/u/.docker/config.json -F uid=1000 -k derm_sens\n"));
        assert!(text.contains("-F path=/etc/shadow "));
        assert!(!skipped.contains(&"/home/u/.npmrc".to_string()));
        // Its folder `~/.codex` is missing: the kernel refuses the rule.
        assert!(!text.contains(".codex/auth.json"));
        assert!(skipped.contains(&"/home/u/.codex/auth.json".to_string()));
        // A missing folder has no rule that would record reads inside it.
        assert!(!text.contains("/home/u/.aws"));
        assert!(skipped.contains(&"/home/u/.aws".to_string()));
    }

    /// Step P (lane PC): an agent account's own file, with the sign-in
    /// store watched for reads and the same syscall rules as the person's.
    #[test]
    fn pc_an_agent_accounts_rules_watch_its_sign_in_store() {
        let exists = |p: &str| {
            p == "/var/lib/derm/agents/max/signin" || p == "/etc" || p == "/etc/sudoers.d"
        };
        let (text, skipped) = render_account(&AccountInput {
            uid: 996,
            slug: "max",
            exists: &exists,
        })
        .unwrap();
        assert!(text.contains("\n-c\n"));
        assert!(text.contains("/etc/audit/rules.d/50-derm-996.rules"));
        assert!(text.contains("## Undo: rm /etc/audit/rules.d/50-derm-996.rules"));
        for line in [
            "-a always,exit -F arch=b64 -S execve,execveat -F uid=996 -k derm_exec\n",
            "-a always,exit -F arch=b64 -S connect -F uid=996 -k derm_net\n",
            "-a always,exit -F arch=b32 -S socketcall -F a0=3 -F uid=996 -k derm_net\n",
            "-a always,exit -F arch=b64 -S open,openat -F dir=/var/lib/derm/agents/max/signin -F uid=996 -k derm_sens\n",
            "-a always,exit -F arch=b32 -S open,openat -F dir=/var/lib/derm/agents/max/signin -F uid=996 -k derm_sens\n",
            "-F path=/etc/shadow -F uid=996 -k derm_sens\n",
        ] {
            assert!(text.contains(line), "{line}");
        }
        // The writes come first, so an open for writing keys derm_write.
        assert!(text.find("derm_write").unwrap() < text.find("derm_sens").unwrap());
        // No person's home path, and no other uid.
        assert!(!text.contains("/home/"));
        assert!(!text
            .lines()
            .filter(|l| l.starts_with("-a"))
            .any(|l| !l.contains("uid=996")));
        assert!(skipped.is_empty(), "{skipped:?}");
        // Its syscall rules are the person's, line for line, with its uid.
        let (person, _) = render(&RulesInput {
            uid: 996,
            home: "/home/x",
            runtime_dir: None,
            exists: &|_| false,
        });
        let sys = |t: &str| {
            t.lines()
                .filter(|l| l.starts_with("-a") && !l.contains("derm_sens"))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(sys(&text), sys(&person));
        for line in text.lines().filter(|l| l.starts_with("-a")) {
            assert!(line.rsplit("-k ").next().unwrap().len() <= 31, "{line}");
        }
    }

    #[test]
    fn pc_a_store_not_made_yet_is_named_and_a_bad_account_is_refused() {
        let (text, skipped) = render_account(&AccountInput {
            uid: 996,
            slug: "max",
            exists: &|p: &str| p == "/etc",
        })
        .unwrap();
        assert!(!text.contains("/signin"));
        assert_eq!(
            skipped,
            vec![
                "/var/lib/derm/agents/max/signin".to_string(),
                "/etc/sudoers.d".to_string()
            ]
        );
        for slug in [
            "",
            "Max",
            "../x",
            "a b",
            "agent",
            "agents",
            "agent-x",
            "sixteen-chars-xx",
        ] {
            assert!(
                render_account(&AccountInput {
                    uid: 996,
                    slug,
                    exists: &|_| true
                })
                .is_err(),
                "{slug:?}"
            );
        }
        assert!(render_account(&AccountInput {
            uid: 0,
            slug: "max",
            exists: &|_| true
        })
        .is_err());
        assert!(account_slug("max-2"));
    }

    #[test]
    fn plain_paths_only() {
        assert!(plain_path("/home/ubuntu"));
        assert!(!plain_path("/home/a b"));
        assert!(!plain_path("/home/../etc"));
        assert!(!plain_path("relative"));
    }
}
