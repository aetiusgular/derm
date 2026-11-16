//! Step 7e of `contracts/policy.md` section 4: a shell command that changes
//! the filesystem root, a system folder, a home folder, a top-level folder,
//! a mounted volume, a disk device or a parent folder, or signals every
//! process (E1-1, eval pass 1).
//!
//! The presets allow the shell and ask about named commands (section 7).
//! A command rule never names an operand, so `rm -rf /`, `sudo rm -rf /`,
//! `chmod -R 777 /`, `truncate -s 0 /etc/passwd`, `dd of=/dev/sda`,
//! `mkfs.ext4 /dev/sda1` and `kill -9 -1` were plain allowed shell calls
//! (MoatBench probe, 16 Nov 2026). Prior art asks or denies these by target:
//! OpenMoat 0.21.0's `destructive` policy (`policies/default-v1.yaml`) holds
//! writes to `~`, `/` and raw `/dev` disks. derm asks (Tony's R-E0-7: ask,
//! not deny), with the class and the program in the reason, never the text.
//!
//! What the tools themselves do (GNU coreutils 9.4, `--help`, run 16 Nov
//! 2026): `rm` refuses `/` unless `--no-preserve-root`; `chmod`, `chown` and
//! `chgrp` do not ("--no-preserve-root ... (the default)"). `kill` with the
//! pid `-1` signals every process the caller may signal (kill(2)).
//!
//! The step runs last, on an allow that stands: by then step 7b has asked
//! about `$`, `~`, a backslash, braces and globs, so every word here is the
//! literal the shell will pass. Paths are read lexically (`//`, `/./`, `..`),
//! in the folded text, so in lowercase.
//!
//! Not read: a command reached through a script, an alias, `find -exec` or
//! `xargs` input (section 7's known limits); Windows programs and paths; a
//! path under a symbolic link; a here-document's lines are read as commands,
//! which can only add an ask.

use crate::command::head_commands;

/// Programs whose every operand is written, removed or changed.
const CHANGE: &[&str] = &[
    "rm", "rmdir", "unlink", "shred", "chmod", "chown", "chgrp", "truncate", "tee",
];
/// Programs that write only their last operand (or `-t`'s folder); the
/// others are read.
const COPY: &[&str] = &["cp", "ln", "install"];
/// Disk tools: a filesystem, a partition table or a wipe on what they name.
const DISK: &[&str] = &[
    "mkfs",
    "mkfs.bfs",
    "mkfs.btrfs",
    "mkfs.cramfs",
    "mkfs.exfat",
    "mkfs.ext2",
    "mkfs.ext3",
    "mkfs.ext4",
    "mkfs.f2fs",
    "mkfs.fat",
    "mkfs.minix",
    "mkfs.msdos",
    "mkfs.ntfs",
    "mkfs.vfat",
    "mkfs.xfs",
    "mke2fs",
    "mkswap",
    "wipefs",
    "blkdiscard",
    "fdisk",
    "sfdisk",
    "cfdisk",
    "sgdisk",
    "gdisk",
    "parted",
    "newfs",
    "newfs_apfs",
    "newfs_hfs",
    "diskutil",
];
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "rbash", "yash",
    "eval",
];
const MAX_DEPTH: usize = 4;

/// Folders protected at any depth.
const TREES: &[&str] = &[
    "etc",
    "bin",
    "sbin",
    "lib",
    "lib32",
    "lib64",
    "libx32",
    "boot",
    "sys",
    "proc",
    "system",
    "library",
    "applications",
];
/// Under `/var`, protected at any depth; `/var/<x>` itself always is.
const VAR_TREES: &[&str] = &["lib", "db", "root"];
/// `/dev` names that are a disk, a volume or memory: a prefix, and whether
/// a digit or letter must follow it.
const DISKS: &[(&str, Follow)] = &[
    ("sd", Follow::Letter),
    ("hd", Follow::Letter),
    ("vd", Follow::Letter),
    ("xvd", Follow::Letter),
    ("nvme", Follow::Digit),
    ("mmcblk", Follow::Digit),
    ("rdisk", Follow::Digit),
    ("disk", Follow::Any),
    ("mapper", Follow::End),
    ("dm-", Follow::Digit),
    ("md", Follow::Digit),
    ("loop", Follow::Digit),
    ("sr", Follow::Digit),
    ("mem", Follow::End),
    ("kmem", Follow::End),
    ("port", Follow::End),
];

#[derive(Clone, Copy)]
enum Follow {
    Letter,
    Digit,
    Any,
    End,
}

/// What a path is, when changing it is worth a question. `strong` classes
/// hold for a copy's destination too; the others only for a path removed or
/// changed itself.
struct Class {
    what: &'static str,
    strong: bool,
}

fn class(what: &'static str, strong: bool) -> Option<Class> {
    Some(Class { what, strong })
}

/// Reads `word` as a path, lexically.
fn classify(word: &str) -> Option<Class> {
    let absolute = word.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    let mut climbs = 0usize;
    for p in word.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() && !absolute {
                    climbs += 1;
                }
            }
            other => parts.push(other),
        }
    }
    if !absolute {
        // `..`, `../..`: the folder above the chat's own.
        return (climbs > 0 && parts.is_empty())
            .then(|| class("a parent folder", false))
            .flatten();
    }
    // macOS keeps `/etc`, `/var` and `/tmp` under `/private`.
    if parts.len() >= 2 && parts[0] == "private" && matches!(parts[1], "etc" | "var" | "tmp") {
        parts.remove(0);
    }
    let Some(top) = parts.first().copied() else {
        return class("the filesystem root", false);
    };
    if TREES.contains(&top) {
        return class("a system folder", true);
    }
    match (top, parts.len()) {
        ("usr", n) => {
            // `/usr/local/<folder>/<file>` and deeper is where a person's
            // own installs go.
            if n >= 4 && parts[1] == "local" {
                None
            } else {
                class("a system folder", true)
            }
        }
        ("var", 1) => class("a system folder", false),
        ("var", n) => {
            if VAR_TREES.contains(&parts[1]) {
                class("a system folder", true)
            } else if n == 2 {
                class("a system folder", false)
            } else {
                None
            }
        }
        ("dev", 1) => class("a top-level folder", false),
        ("dev", _) => disk(parts[1])
            .then(|| class("a disk device", true))
            .flatten(),
        ("root", 1) => class("a home folder", false),
        ("home" | "users", 1 | 2) => class("a home folder", false),
        ("mnt" | "media" | "volumes", 2) => class("a mounted volume", false),
        (_, 1) => class("a top-level folder", false),
        _ => None,
    }
}

fn disk(name: &str) -> bool {
    DISKS.iter().any(|(prefix, follow)| {
        let Some(rest) = name.strip_prefix(prefix) else {
            return false;
        };
        let next = rest.bytes().next();
        match follow {
            Follow::Letter => next.is_some_and(|b| b.is_ascii_lowercase()),
            Follow::Digit => next.is_some_and(|b| b.is_ascii_digit()),
            Follow::Any => true,
            Follow::End => next.is_none(),
        }
    })
}

fn reason(what: &str, program: &str) -> String {
    format!("command changes {what}: `{program}`")
}

/// The words a command passes as operands: no flags, and everything after
/// `--`.
fn operands(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut all = false;
    for a in args {
        if !all && a == "--" {
            all = true;
        } else if all || !a.starts_with('-') || a == "-" {
            out.push(a.as_str());
        }
    }
    out
}

/// `-t <folder>`, `--target-directory <folder>` or `--target-directory=<folder>`.
fn target_directory(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return None;
        }
        if let Some(v) = a.strip_prefix("--target-directory=") {
            return Some(v);
        }
        if a == "-t" || a == "--target-directory" {
            return args.get(i + 1).map(String::as_str);
        }
        i += 1;
    }
    None
}

fn check(program: &str, args: &[String]) -> Option<String> {
    let any = |words: &[&str], strong_only: bool| {
        words
            .iter()
            .filter_map(|w| classify(w))
            .find(|c| c.strong || !strong_only)
            .map(|c| reason(c.what, program))
    };
    if program == "kill" {
        // `-1` as a pid: after the first argument (a signal comes first), or
        // after `--`.
        let dashes = args.iter().position(|a| a == "--");
        let every = args
            .iter()
            .enumerate()
            .any(|(i, a)| a == "-1" && (i > 0 || dashes.is_some_and(|d| d < i)));
        return every.then(|| format!("command signals every process: `{program}`"));
    }
    if matches!(program, "rm" | "chmod" | "chown" | "chgrp")
        && args.iter().any(|a| a == "--no-preserve-root")
    {
        return Some(reason("the filesystem root", program));
    }
    if program == "dd" {
        let outs: Vec<&str> = args.iter().filter_map(|a| a.strip_prefix("of=")).collect();
        return any(&outs, false);
    }
    let target = target_directory(args);
    let mut ops = operands(args);
    // `-t`'s folder is the destination, not one more operand.
    if let Some(i) = target.and_then(|t| ops.iter().position(|o| *o == t)) {
        ops.remove(i);
    }
    if COPY.contains(&program) || program == "mv" {
        // With `-t` every operand is a source; without, the last is the
        // destination.
        let (sources, dest): (&[&str], Option<&str>) = match target {
            Some(t) => (&ops[..], Some(t)),
            None if ops.len() >= 2 => (&ops[..ops.len() - 1], ops.last().copied()),
            None => (&ops[..], None),
        };
        // A copy into a folder changes no folder itself: only a system tree
        // or a disk as the destination counts.
        if let Some(r) = dest.and_then(|d| any(&[d], true)) {
            return Some(r);
        }
        // `mv` removes its sources; a copy only reads them.
        return if program == "mv" {
            any(sources, false)
        } else {
            None
        };
    }
    any(&ops, false)
}

/// The targets of output redirections in shell text (`>`, `>>`, `>|`, `&>`,
/// `2>`, `<>`), quotes read as the shell reads them. A descriptor (`>&2`,
/// `>&-`) is no target.
fn write_targets(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut at_word_start = true;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                at_word_start = false;
            }
            '#' if at_word_start => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            '>' => {
                i += 1;
                let mut descriptor = false;
                while i < chars.len() && matches!(chars[i], '>' | '|' | '&') {
                    descriptor = chars[i] == '&';
                    i += 1;
                }
                while i < chars.len() && matches!(chars[i], ' ' | '\t') {
                    i += 1;
                }
                let mut word = String::new();
                let mut q: Option<char> = None;
                while i < chars.len() {
                    let c = chars[i];
                    if let Some(open) = q {
                        if c == open {
                            q = None;
                        } else {
                            word.push(c);
                        }
                    } else if c == '\'' || c == '"' {
                        q = Some(c);
                    } else if matches!(
                        c,
                        ' ' | '\t' | '\n' | '\r' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
                    ) {
                        break;
                    } else {
                        word.push(c);
                    }
                    i += 1;
                }
                let is_descriptor =
                    descriptor && (word == "-" || word.bytes().all(|b| b.is_ascii_digit()));
                if !word.is_empty() && !is_descriptor {
                    out.push(word);
                }
                at_word_start = true;
                continue;
            }
            ' ' | '\t' | '\n' | '\r' | ';' | '&' | '|' | '(' | ')' => at_word_start = true,
            _ => at_word_start = false,
        }
        i += 1;
    }
    out
}

fn redirects(text: &str, depth: usize) -> Option<String> {
    for t in write_targets(text) {
        if let Some(c) = classify(&t) {
            return Some(reason(c.what, ">"));
        }
    }
    if depth >= MAX_DEPTH {
        return None;
    }
    // A shell's `-c` string and `eval`'s words are shell text of their own.
    for cmd in head_commands(text, SHELLS) {
        for arg in cmd.iter().skip(1).filter(|a| a.contains('>')) {
            if let Some(r) = redirects(arg, depth + 1) {
                return Some(r);
            }
        }
    }
    None
}

/// The reason to ask about folded shell text, if it holds such a command.
pub fn destructive(folded: &str) -> Option<String> {
    let mut heads: Vec<&str> = vec!["kill", "dd", "mv"];
    heads.extend(CHANGE);
    heads.extend(COPY);
    heads.extend(DISK);
    for cmd in head_commands(folded, &heads) {
        if let Some(r) = check(&cmd[0], &cmd[1..]) {
            return Some(r);
        }
    }
    redirects(folded, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn what(text: &str) -> Option<String> {
        destructive(text)
    }

    #[test]
    fn the_commands_eval_pass_1_found_allowed_ask() {
        for (text, want) in [
            ("rm -rf /", "command changes the filesystem root: `rm`"),
            ("sudo rm -rf /", "command changes the filesystem root: `rm`"),
            (
                "rm -rf --no-preserve-root /",
                "command changes the filesystem root: `rm`",
            ),
            (
                "chmod -r 777 /",
                "command changes the filesystem root: `chmod`",
            ),
            (
                "truncate -s 0 /etc/passwd",
                "command changes a system folder: `truncate`",
            ),
            (
                "dd if=/dev/zero of=/dev/sda bs=1m",
                "command changes a disk device: `dd`",
            ),
            (
                "mkfs.ext4 /dev/sda1",
                "command changes a disk device: `mkfs.ext4`",
            ),
            (
                "wipefs -a /dev/nvme0n1",
                "command changes a disk device: `wipefs`",
            ),
            ("kill -9 -1", "command signals every process: `kill`"),
            ("rm -rf /home/opone", "command changes a home folder: `rm`"),
            ("rm -rf ..", "command changes a parent folder: `rm`"),
            (
                "echo x > /etc/passwd",
                "command changes a system folder: `>`",
            ),
        ] {
            assert_eq!(what(text).as_deref(), Some(want), "{text}");
        }
    }

    #[test]
    fn paths_are_read_lexically() {
        for text in [
            "rm -rf //",
            "rm -rf /./",
            "rm -rf /tmp/..",
            "rm -rf /tmp/../etc/x",
            "rm -rf '/'",
            "rm -rf \"/etc\"/x",
            "rm -rf -- /",
            "rm -rf /private/etc/hosts",
            "rm -rf ../..",
            "rm -rf ./../",
        ] {
            assert!(what(text).is_some(), "{text}");
        }
    }

    #[test]
    fn wrappers_shells_and_lists_are_read() {
        for text in [
            "sudo -u root rm -rf /usr",
            "env x=1 nice chmod -r 777 /etc",
            "sh -c 'rm -rf /'",
            "bash -lc \"chown -r u /usr/lib\"",
            "true && rm -rf /var/lib/x; echo done",
            "eval rm -rf /boot",
            "sudo sh -c 'echo x > /etc/hosts'",
            "sudo tee /etc/sudoers.d/x",
            "echo x | sudo tee -a /etc/hosts",
            "/bin/rm -rf /",
        ] {
            assert!(what(text).is_some(), "{text}");
        }
    }

    #[test]
    fn work_in_a_project_and_in_temporary_folders_stays_allowed() {
        for text in [
            "rm -rf build",
            "rm -rf ./node_modules",
            "rm -rf /tmp/build",
            "rm -rf /var/tmp/x /var/folders/ab/cd",
            "rm -rf ../sibling",
            "rm -rf /home/u/proj/target",
            "rm -rf /workspace/proj/dist",
            "chmod +x scripts/run.sh",
            "chmod -r 755 .",
            "chown u:g file",
            "cp /etc/hosts ./hosts.copy",
            "cp -r src /tmp",
            "cp tool /usr/local/bin/tool",
            "install -m 755 tool /opt/tool/bin/tool",
            "ln -s /usr/lib/x.so ./x.so",
            "mv build /tmp",
            "mv a b",
            "tee out.log",
            "echo x > out.txt",
            "echo x > /dev/null 2>&1",
            "cmd 2>/dev/null >&2",
            "echo x >> /tmp/log",
            "dd if=/dev/sda of=disk.img",
            "dd if=/dev/zero of=/dev/null",
            "mkfs.ext4 disk.img",
            "truncate -s 0 out.log",
            "kill -9 1234",
            "kill -1 1234",
            "kill -hup 77",
            "git commit -m 'rm -rf / is bad'",
            "echo 'x > /etc/passwd'",
            "grep -r 'chmod 777 /' docs",
            "cat /etc/hosts",
            "ls /",
            "# rm -rf /",
            "echo a # > /etc/x",
        ] {
            assert_eq!(what(text), None, "{text}");
        }
    }

    #[test]
    fn a_copy_asks_only_for_a_system_destination() {
        assert!(what("cp x /etc/cron.d/x").is_some());
        assert!(what("cp -t /usr/bin x").is_some());
        assert!(what("cp --target-directory=/etc x").is_some());
        assert!(what("ln -sf /tmp/x /etc/ld.so.preload").is_some());
        assert!(what("install -m 4755 x /usr/bin/x").is_some());
        assert!(what("mv /etc/hosts .").is_some(), "mv removes its source");
        assert!(what("mv x /usr/bin/").is_some());
        assert!(what("mv -t /tmp /home/u").is_some());
        assert_eq!(what("mv -t /tmp build"), None);
        assert_eq!(what("cp x /"), None);
        assert_eq!(what("cp x /home/u"), None);
    }

    #[test]
    fn kill_minus_one_is_a_pid_only_after_a_signal_or_dashes() {
        assert!(what("kill -9 -1").is_some());
        assert!(what("kill -s kill -1").is_some());
        assert!(what("kill -- -1").is_some());
        assert!(what("kill -1 -1").is_some());
        assert!(what("sudo kill -kill -1").is_some());
        assert_eq!(what("kill -1"), None);
        assert_eq!(what("kill -1 55"), None);
    }

    #[test]
    fn devices_that_are_not_disks_are_plain() {
        for d in [
            "null", "zero", "stdout", "stderr", "tty", "shm/x", "fd/3", "urandom", "sdcard",
        ] {
            let text = format!("tee /dev/{d}");
            assert_eq!(what(&text).is_some(), d == "sdcard", "{text}");
        }
        for d in [
            "sda",
            "sdb1",
            "nvme0n1p2",
            "mmcblk0",
            "disk2",
            "rdisk2",
            "mapper/root",
            "dm-0",
            "md0",
            "loop3",
            "mem",
        ] {
            assert!(what(&format!("shred /dev/{d}")).is_some(), "{d}");
        }
    }
}
