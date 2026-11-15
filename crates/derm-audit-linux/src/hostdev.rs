//! Whether a filesystem is mounted where the host can see it (box test w6
//! retest 2, BW6R2-2; fix pass 3's review, FP3-R2, FP3-R3).
//!
//! bubblewrap makes the mount points of its binds as empty files and
//! folders under `/newroot`, its own tmpfs, before it pivots there
//! (`bubblewrap.c` `setup_newroot` at v0.11.1, read), and srt's `--tmpfs`
//! over a hidden folder is mounted in the sandbox's own mount namespace. The
//! daemon reads those files as the host path they map to. The PATH record
//! says which filesystem the file was made on: `dev=` is the inode's
//! `i_sb->s_dev` (`audit_copy_inode`, kernel/auditsc.c:2226 at v7.0, printed
//! by `audit_log_name` at 1536-1540), and a mountinfo line's third field is
//! the same superblock's `s_dev` (`show_mountinfo`, fs/proc_namespace.c:143-144
//! at v7.0). A file made on a filesystem the host's mount namespace has no
//! mount of is not a file of the host's: a bind of a host folder, however
//! placed, is on a filesystem the host has mounted. The feed reads this when
//! it reads the event (the mounts of that moment, not of a later report),
//! and says so in the event (`devMounted`).

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

/// The devices of one mount namespace's mounts.
#[derive(Clone, Debug, Default)]
pub struct Mounts {
    devs: Vec<Dev>,
}

impl Mounts {
    /// Reads mountinfo's text: each line's third field, `major:minor` in
    /// decimal. A line that does not parse is skipped; text with no line
    /// that parses is `None`, never an empty set that would hold no device
    /// (FP3-R3).
    pub fn parse(text: &str) -> Option<Mounts> {
        let devs: Vec<Dev> = text
            .lines()
            .filter_map(|line| {
                let (ma, mi) = line.split(' ').nth(2)?.split_once(':')?;
                Some((ma.parse().ok()?, mi.parse().ok()?))
            })
            .collect();
        (!devs.is_empty()).then_some(Mounts { devs })
    }

    /// Whether a mount of this namespace has the device.
    pub fn has_dev(&self, dev: Dev) -> bool {
        self.devs.contains(&dev)
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
    fn a_device_is_mounted_here_or_not() {
        let m = Mounts::parse(RECORDED).unwrap();
        assert!(m.has_dev((254, 0)));
        assert!(m.has_dev((0, 23)));
        // bubblewrap's root and the tmpfs at ~/.derm in the fixture.
        assert!(!m.has_dev((0, 42)));
        assert!(!m.has_dev((0, 43)));
        // A mount point that does not unescape still gives its device.
        let m = Mounts::parse("2 1 0:40 / /home/u/my\\9dir rw - tmpfs t rw\nbad line\n").unwrap();
        assert!(m.has_dev((0, 40)));
        // Nothing that parses is no reading at all (FP3-R3).
        assert!(Mounts::parse("").is_none());
        assert!(Mounts::parse("garbage\nmore garbage\n").is_none());
    }
}
