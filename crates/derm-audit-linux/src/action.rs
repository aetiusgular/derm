//! An assembled event, read as one action: who did what to which path or
//! address. Field meanings are from the auditctl man page for auditd 3.1.2
//! and the records in `tests/fixtures/scenario1.raw.audit`.

use crate::assemble::AuditEvent;
use crate::record::{decode_hex, Record};
use crate::syscalls::{lookup, Call};

/// `AT_FDCWD` as the kernel prints a0 for `*at` calls: -100 as an unsigned
/// 32-bit or 64-bit value, in lower-case hex.
const AT_FDCWD: [&str; 2] = ["ffffff9c", "ffffffffffffff9c"];

/// errno values whose failure is worth showing: the boundary said no.
/// EPERM 1, EACCES 13, EROFS 30.
const DENIED: [i64; 3] = [-1, -13, -30];
/// EINPROGRESS: a non-blocking connect that has started (seen in the fixture).
const EINPROGRESS: i64 = -115;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub ts_ms: i64,
    pub serial: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: Option<u32>,
    pub comm: String,
    pub exe: String,
    pub key: String,
    pub syscall: &'static str,
    /// The syscall failed with EPERM, EACCES or EROFS.
    pub denied: bool,
    pub cwd: Option<String>,
    /// The device of the file written, as the PATH record prints it
    /// (`dev=fe:00`: the inode's `i_sb->s_dev`, `MAJOR:MINOR` in hex,
    /// kernel `audit_log_name`): for a write, create or truncate the item
    /// written, for a link the one made. `None` where the record has none.
    pub dev: Option<String>,
    pub what: What,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum What {
    Exec {
        argv: Vec<String>,
    },
    Fork {
        child: u32,
    },
    /// A file opened for writing (or created). `flags_known` is false for
    /// `openat2`, whose flags the record does not carry.
    Write {
        path: String,
        created: bool,
        flags_known: bool,
    },
    /// A read the rules watch (the `derm_sens` key).
    Open {
        path: String,
    },
    Truncate {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Unlink {
        path: String,
    },
    Link {
        from: String,
        to: String,
    },
    Connect {
        family: Family,
        addr: String,
        port: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Inet,
    Inet6,
}

/// Reads one event. `None` when it is not a syscall the feed keeps, or it
/// failed for a reason other than a denial (a PATH search's ENOENT, an
/// AF_UNIX connect, a socketcall that is not connect).
pub fn read(event: &AuditEvent) -> Option<Action> {
    let sys = event.first("SYSCALL")?;
    let arch = sys.get("arch")?;
    let number: u32 = sys.get("syscall")?.parse().ok()?;
    let (call, name) = lookup(arch, number)?;
    let exit: i64 = sys.get_i64("exit").unwrap_or(0);
    let success = sys.get("success") == Some("yes");
    let denied = !success && DENIED.contains(&exit);
    let cwd = event.first("CWD").and_then(|r| r.text("cwd"));
    let base = |what: What| Action {
        ts_ms: event.ts_ms,
        serial: event.serial,
        pid: sys.get_u32("pid").unwrap_or(0),
        ppid: sys.get_u32("ppid").unwrap_or(0),
        uid: sys.get_u32("uid"),
        comm: sys.text("comm").unwrap_or_default(),
        exe: sys.text("exe").unwrap_or_default(),
        key: sys.text("key").unwrap_or_default(),
        syscall: name,
        denied,
        cwd: cwd.clone(),
        dev: None,
        what,
    };
    let kept = success || denied;
    let paths = Paths::new(event, sys, cwd.as_deref());
    let mut dev: Option<String> = None;
    let what = match call {
        Call::Exec => {
            if !success {
                return None;
            }
            What::Exec {
                argv: argv(event.first("EXECVE")?),
            }
        }
        Call::Fork => {
            if !success || exit <= 0 {
                return None;
            }
            What::Fork {
                child: u32::try_from(exit).ok()?,
            }
        }
        Call::Open | Call::OpenAt | Call::OpenAt2 | Call::Creat => {
            if !kept {
                return None;
            }
            let (path, created) = paths.target()?;
            if sys.get("key") == Some("derm_sens") && !created && call != Call::Creat {
                What::Open { path }
            } else {
                dev = paths.target_dev();
                What::Write {
                    path,
                    created,
                    flags_known: call != Call::OpenAt2,
                }
            }
        }
        Call::Truncate => {
            if !kept {
                return None;
            }
            dev = paths.target_dev();
            What::Truncate {
                path: paths.target()?.0,
            }
        }
        Call::Rename => {
            if !kept {
                return None;
            }
            What::Rename {
                from: paths.of("DELETE")?,
                to: paths.of("CREATE").unwrap_or_else(|| "?".into()),
            }
        }
        Call::Unlink => {
            if !kept {
                return None;
            }
            What::Unlink {
                path: paths.of("DELETE")?,
            }
        }
        Call::Link => {
            if !kept {
                return None;
            }
            dev = paths.dev_of("CREATE");
            let to = paths.of("CREATE")?;
            let from = paths.of("NORMAL").unwrap_or_else(|| "?".into());
            What::Link { from, to }
        }
        Call::Symlink => {
            if !kept {
                return None;
            }
            dev = paths.dev_of("CREATE");
            let (from, to) = paths.symlink()?;
            What::Link { from, to }
        }
        Call::Connect | Call::SocketCall => {
            if call == Call::SocketCall && sys.get("a0") != Some("3") {
                return None;
            }
            if !(success || exit == EINPROGRESS || denied) {
                return None;
            }
            let saddr = event.first("SOCKADDR")?.get("saddr")?;
            let (family, addr, port) = sockaddr(saddr)?;
            What::Connect { family, addr, port }
        }
    };
    let mut action = base(what);
    action.dev = dev;
    Some(action)
}

/// EXECVE `argc` and `a0`..: each quoted, or hex when it holds a space or a
/// byte the kernel will not print. Long arguments come split as
/// `aN_len=` with `aN[0]=`, `aN[1]=` (kernel `audit_log_execve_info`); those
/// pieces are joined.
fn argv(rec: &Record) -> Vec<String> {
    let argc: usize = rec.get("argc").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut out = Vec::new();
    for n in 0..argc.min(4096) {
        let key = format!("a{n}");
        if let Some(text) = rec.text(&key) {
            out.push(text);
            continue;
        }
        let mut joined = Vec::new();
        let mut part = 0;
        while let Some(f) = rec.field(&format!("{key}[{part}]")) {
            if f.quoted {
                joined.extend_from_slice(f.value.as_bytes());
            } else {
                joined.extend(decode_hex(&f.value).unwrap_or_else(|| f.value.as_bytes().to_vec()));
            }
            part += 1;
        }
        if part == 0 {
            break; // the record was cut short
        }
        out.push(String::from_utf8_lossy(&joined).into_owned());
    }
    out
}

/// `saddr` hex: `sa_family` (2 bytes, little-endian), then for AF_INET the
/// port (big-endian) and 4 address bytes, for AF_INET6 the port, 4 bytes of
/// flow info and 16 address bytes. AF_UNIX and others: `None`.
pub fn sockaddr(hex: &str) -> Option<(Family, String, u16)> {
    let b = decode_hex(hex)?;
    if b.len() < 4 {
        return None;
    }
    let family = u16::from_le_bytes([b[0], b[1]]);
    let port = u16::from_be_bytes([b[2], b[3]]);
    match family {
        2 if b.len() >= 8 => Some((
            Family::Inet,
            format!("{}.{}.{}.{}", b[4], b[5], b[6], b[7]),
            port,
        )),
        10 if b.len() >= 24 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[8..24]);
            Some((Family::Inet6, std::net::Ipv6Addr::from(a).to_string(), port))
        }
        _ => None,
    }
}

/// The PATH items of one event, resolved to absolute paths where the record
/// allows it.
struct Paths {
    /// (nametype, name) in item order.
    items: Vec<(String, String)>,
    /// Each item's `dev=`, in the same order (an item the kernel never
    /// looked up, nametype `UNKNOWN`, has none).
    devs: Vec<Option<String>>,
    parents: Vec<String>,
    cwd: Option<String>,
    /// The call named its paths relative to the working folder (a0 is
    /// AT_FDCWD, or the call has no dirfd).
    from_cwd: bool,
}

impl Paths {
    fn new(event: &AuditEvent, sys: &Record, cwd: Option<&str>) -> Paths {
        let mut items: Vec<(usize, String, String, Option<String>)> = event
            .all("PATH")
            .filter_map(|r| {
                let item: usize = r.get("item")?.parse().ok()?;
                Some((
                    item,
                    r.get("nametype")?.to_string(),
                    r.text("name")?,
                    r.get("dev").map(str::to_string),
                ))
            })
            .collect();
        items.sort_by_key(|(i, _, _, _)| *i);
        let parents = items
            .iter()
            .filter(|(_, t, _, _)| t == "PARENT")
            .map(|(_, _, n, _)| n.clone())
            .collect();
        let syscall_name = sys
            .get("arch")
            .zip(sys.get("syscall").and_then(|s| s.parse().ok()))
            .and_then(|(a, n)| lookup(a, n))
            .map(|(_, name)| name)
            .unwrap_or("");
        // The dirfd arguments of the `*at` calls (man 2 openat, renameat2,
        // linkat, symlinkat, unlinkat, execveat). Every one must be AT_FDCWD.
        let dirfds: &[&str] = match syscall_name {
            "openat" | "openat2" | "unlinkat" | "execveat" => &["a0"],
            "renameat" | "renameat2" | "linkat" => &["a0", "a2"],
            "symlinkat" => &["a1"],
            _ => &[],
        };
        let from_cwd = dirfds
            .iter()
            .all(|a| sys.get(a).is_some_and(|v| AT_FDCWD.contains(&v)));
        Paths {
            devs: items.iter().map(|(_, _, _, d)| d.clone()).collect(),
            items: items.into_iter().map(|(_, t, n, _)| (t, n)).collect(),
            parents,
            cwd: cwd.map(str::to_string),
            from_cwd,
        }
    }

    /// The file an open, creat or truncate touched, and whether it was made.
    fn target(&self) -> Option<(String, bool)> {
        if let Some(p) = self.of("CREATE") {
            return Some((p, true));
        }
        let (idx, _) = self
            .items
            .iter()
            .enumerate()
            .find(|(_, (t, _))| t == "NORMAL")?;
        Some((self.resolve(idx), false))
    }

    /// The device of the item [`Paths::target`] names.
    fn target_dev(&self) -> Option<String> {
        self.dev_of("CREATE").or_else(|| self.dev_of("NORMAL"))
    }

    /// The device of the first item of a nametype.
    fn dev_of(&self, nametype: &str) -> Option<String> {
        let idx = self.items.iter().position(|(t, _)| t == nametype)?;
        self.devs.get(idx).cloned().flatten()
    }

    /// A symlink's target text and the link it made (box test w6 retest 2,
    /// BW6R2-1). `symlink(2)` takes the target as a name the kernel never
    /// looks up: it is an item of its own (nametype `UNKNOWN`), and the link
    /// is the `CREATE` item. But when the kernel files the new entry
    /// (`__audit_inode_child`, kernel/auditsc.c:2413-2426 at v7.0) it takes an
    /// `UNKNOWN` name that ends in the entry's name as the child, so the
    /// `CREATE` item then prints the target (`audit_log_name`, 1511-1515) and
    /// no `UNKNOWN` item is left. Where the cut falls depends on the order the
    /// names were read. On Linux 7.0 the target is read first
    /// (`CLASS(filename, old)`, fs/namei.c:5664-5665), no parent has been
    /// found when it is compared, and the cut is the target's own last part
    /// (`parent_len`, kernel/auditfilter.c:1277-1301): any target with the
    /// link's name matches (`/proc/self/fd` for bubblewrap's `/dev/fd`,
    /// `~/x/pre-commit` for `.git/hooks/pre-commit`). Where the link's name is
    /// read first (the 6.18 record, its `PARENT` item 0), the cut is at the
    /// length of the link's folder (`found_parent->name_len`, auditsc.c:
    /// 2417-2421), whatever character is there (fix pass 3's review,
    /// FP3-R1). The link is then that folder and the entry's name.
    fn symlink(&self) -> Option<(String, String)> {
        let create = self.items.iter().position(|(t, _)| t == "CREATE")?;
        if let Some(u) = self.items.iter().position(|(t, _)| t == "UNKNOWN") {
            return Some((self.items[u].1.clone(), self.resolve(create)));
        }
        let parent = self.items.iter().position(|(t, _)| t == "PARENT");
        let name = self.items[create].1.clone();
        let Some(p) = parent else {
            // No folder to place it in: the name as it stands.
            return Some(("?".into(), self.resolve(create)));
        };
        let dir = self.items[p].1.as_str();
        // An anonymous parent the kernel made (`name=(null)`, auditsc.c
        // 2429-2435, 1533) names no folder.
        if dir == "(null)" {
            return Some((name.clone(), format!("?{name}")));
        }
        // The kernel matched no target at all (its names list was full):
        // the `CREATE` item is the link itself, in the parent's folder
        // (fix pass 3's review, FP3-R4).
        let in_dir = |n: &str| {
            n.strip_prefix(dir)
                .is_some_and(|rest| !rest.is_empty() && !rest.trim_end_matches('/').contains('/'))
        };
        if dir.ends_with('/') && in_dir(&name) {
            return Some(("?".into(), self.resolve(create)));
        }
        let trimmed = name.trim_end_matches('/');
        let leaf = if p < create {
            // The cut at the folder's length (`audit_compare_dname_path`
            // with the parent's length, auditfilter.c:1311-1334). A folder
            // printed with no `/` at its end is the working folder the
            // kernel printed for a length of 0 (auditsc.c:1518-1525), so the
            // cut is at 0.
            if dir.ends_with('/') {
                trimmed.get(dir.len()..).filter(|l| !l.is_empty())
            } else {
                Some(trimmed).filter(|l| !l.is_empty() && !l.contains('/'))
            }
        } else {
            None
        }
        .or_else(|| trimmed.rsplit('/').next().filter(|l| !l.is_empty()))?;
        let to = if dir.starts_with('/') {
            join(dir, leaf)
        } else {
            let rel = join(dir, leaf);
            match self.cwd.as_deref().filter(|c| c.starts_with('/')) {
                Some(cwd) if self.from_cwd => join(cwd, &rel),
                _ => format!("?{rel}"),
            }
        };
        Some((name, to))
    }

    /// The first item of a nametype, resolved.
    fn of(&self, nametype: &str) -> Option<String> {
        let idx = self.items.iter().position(|(t, _)| t == nametype)?;
        Some(self.resolve(idx))
    }

    /// An absolute name stays. A relative one is joined to its PARENT item
    /// (the k-th non-parent item to the k-th parent: a rename has two
    /// parents, then the old and the new name), else to the working folder
    /// when the call named it from there. Anything else becomes `?<name>`,
    /// which no folder contains, so a check treats it as outside.
    fn resolve(&self, idx: usize) -> String {
        let name = &self.items[idx].1;
        if name.starts_with('/') {
            return name.clone();
        }
        let k = self.items[..idx]
            .iter()
            .filter(|(t, _)| t != "PARENT")
            .count();
        let base_name = name.rsplit('/').next().unwrap_or(name);
        if let Some(parent) = self.parents.get(k).filter(|p| p.starts_with('/')) {
            return join(parent, base_name);
        }
        if self.from_cwd {
            if let Some(cwd) = self.cwd.as_deref().filter(|c| c.starts_with('/')) {
                return join(cwd, name);
            }
        }
        format!("?{name}")
    }
}

fn join(dir: &str, name: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_inet_from_the_fixture() {
        assert_eq!(
            sockaddr("020001BB5DB8D70E0000000000000000"),
            Some((Family::Inet, "93.184.215.14".into(), 443))
        );
        assert_eq!(
            sockaddr("020000097F0000010000000000000000"),
            Some((Family::Inet, "127.0.0.1".into(), 9))
        );
    }

    #[test]
    fn sockaddr_inet6_and_unix() {
        // Synthetic (the workspace has no IPv6): AF_INET6 = 10, port 9, ::1.
        let v6 = "0A000009000000000000000000000000000000000000000100000000";
        assert_eq!(sockaddr(v6), Some((Family::Inet6, "::1".into(), 9)));
        assert_eq!(sockaddr("01002F746D70"), None, "AF_UNIX is not kept");
        assert_eq!(sockaddr("02"), None);
    }

    #[test]
    fn long_arguments_split_by_the_kernel_are_joined() {
        let rec = crate::record::parse_line(
            "type=EXECVE msg=audit(1.000:1): argc=2 a0=\"echo\" a1_len=6 a1[0]=616263 a1[1]=\"def\"",
        )
        .unwrap();
        assert_eq!(argv(&rec), vec!["echo".to_string(), "abcdef".to_string()]);
    }
}
