//! Whether a filesystem is mounted where the host can see it (box test w6
//! retest 2, BW6R2-2).
//!
//! bubblewrap makes the mount points of its binds as empty files and
//! folders under `/newroot`, its own tmpfs, before it pivots there
//! (`bubblewrap.c` `setup_newroot` at v0.11.1, read), and srt's `--tmpfs`
//! over a hidden folder is mounted in the sandbox's own mount namespace. The
//! audit feed names those files `/newroot/<host path>`, which the check
//! reads as the host path. The PATH record says which filesystem the file
//! was made on: `dev=` is the inode's `i_sb->s_dev` (kernel `audit_log_name`,
//! kernel/auditsc.c:1536-1537 at v7.0), and a mountinfo line's third field is
//! the same `s_dev` of the mount's superblock (proc_pid_mountinfo(5)). A file
//! made on a filesystem the daemon's own mount namespace has no mount of is
//! not a file of the host's: a bind of a host folder, however placed, is on a
//! filesystem the host has mounted. `stat(2)`'s `st_dev` is not used: btrfs
//! and overlayfs report another number there.

/// A device as `(major, minor)`.
pub type Dev = (u32, u32);

/// A PATH record's `dev=` (`fe:00`: `%02x:%02x`, hex).
pub fn parse_audit_dev(text: &str) -> Option<Dev> {
    let (a, b) = text.split_once(':')?;
    let hex = |s: &str| {
        (!s.is_empty() && s.len() <= 8 && s.bytes().all(|c| c.is_ascii_hexdigit()))
            .then(|| u32::from_str_radix(s, 16).ok())
            .flatten()
    };
    Some((hex(a)?, hex(b)?))
}

/// The mounts of one mount namespace, in mountinfo's order.
#[derive(Clone, Debug, Default)]
pub struct Mounts {
    rows: Vec<(String, Dev)>,
}

/// mountinfo's octal escapes (`\040` for a space, `\011`, `\012`, `\134`).
fn unescape(field: &str) -> Option<String> {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            let oct = b.get(i + 1..i + 4)?;
            if !oct.iter().all(|c| (b'0'..=b'7').contains(c)) {
                return None;
            }
            let v =
                (oct[0] - b'0') as u32 * 64 + (oct[1] - b'0') as u32 * 8 + (oct[2] - b'0') as u32;
            out.push(u8::try_from(v).ok()?);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl Mounts {
    /// Reads mountinfo's text. A line that does not parse is skipped.
    pub fn parse(text: &str) -> Mounts {
        let rows = text
            .lines()
            .filter_map(|line| {
                let mut f = line.split(' ');
                let _id = f.next()?;
                let _parent = f.next()?;
                let (ma, mi) = f.next()?.split_once(':')?;
                let _root = f.next()?;
                let point = unescape(f.next()?)?;
                Some((point, (ma.parse().ok()?, mi.parse().ok()?)))
            })
            .collect();
        Mounts { rows }
    }

    /// This process's mounts, on Linux (`/proc/self/mountinfo`).
    pub fn read() -> Option<Mounts> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        std::fs::read_to_string("/proc/self/mountinfo")
            .ok()
            .map(|t| Mounts::parse(&t))
    }

    /// Whether a mount of this namespace has the device.
    pub fn has_dev(&self, dev: Dev) -> bool {
        self.rows.iter().any(|(_, d)| *d == dev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cloud workspace's mountinfo where the feed's fixture
    /// `links_6_18.enriched.audit` was recorded (14 Nov 2026), less the
    /// lines no test reads.
    const RECORDED: &str = "22 27 0:21 / /proc rw,relatime - proc proc rw
24 27 0:6 / /dev rw,relatime - devtmpfs devtmpfs rw,size=4096132k,nr_inodes=1024033,mode=755
25 24 0:23 / /dev/shm rw,relatime - tmpfs tmpfs rw,size=8216668k
27 1 254:0 / / rw,relatime - ext4 /dev/vda rw,discard
29 27 254:32 / /opt/claude-code ro,nosuid,nodev,relatime - ext4 /dev/vdc ro,norecovery";

    #[test]
    fn the_audit_dev_is_hex() {
        assert_eq!(parse_audit_dev("fe:00"), Some((254, 0)));
        assert_eq!(parse_audit_dev("00:2a"), Some((0, 42)));
        assert_eq!(parse_audit_dev("103:02"), Some((259, 2)));
        assert_eq!(parse_audit_dev(""), None);
        assert_eq!(parse_audit_dev("fe"), None);
        assert_eq!(parse_audit_dev("fe:zz"), None);
        assert_eq!(parse_audit_dev(":00"), None);
    }

    #[test]
    fn a_device_is_mounted_here_or_not_and_escapes_are_read() {
        let m = Mounts::parse(RECORDED);
        assert!(m.has_dev((254, 0)));
        assert!(m.has_dev((0, 23)));
        // bubblewrap's root and the tmpfs at ~/.derm in the fixture.
        assert!(!m.has_dev((0, 42)));
        assert!(!m.has_dev((0, 43)));
        let m = Mounts::parse("1 0 254:0 / / rw - ext4 /dev/vda rw\n2 1 0:40 / /home/u/my\\040dir rw - tmpfs t rw\nbad line\n");
        assert!(m.has_dev((0, 40)));
        assert_eq!(m.rows[1].0, "/home/u/my dir");
        assert_eq!(unescape("a\\9xx"), None);
    }
}
