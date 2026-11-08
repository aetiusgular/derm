//! Records to events. A syscall event is several records with one
//! `(timestamp, serial)`: SYSCALL, then EXECVE, CWD, PATH (one per item),
//! SOCKADDR, and PROCTITLE last. auditd's ENRICHED log on Ubuntu 24.04 writes
//! no EOE (seen in `tests/fixtures/scenario1.raw.audit`); a raw kernel stream
//! does. So an event ends at a record audit itself counts as last
//! (`LAST_RECORDS`: PROCTITLE, EOE and the single-record types), or when it
//! is the oldest of more than `MAX_OPEN` open events, or at `flush`.

use crate::record::Record;

/// Open events kept while waiting for their last record.
pub const MAX_OPEN: usize = 16;

/// Record types that end their event, as audit 4.1.2 decides it
/// (`common/common.c:55-69`, `audit_is_last_record`: PROCTITLE, EOE, AUDIT_USER,
/// types above AUDIT_LOGIN and below AUDIT_FIRST_EVENT (the user-space and
/// daemon messages), AUDIT_KERNEL, AUDIT_MAC_UNLBL_ALLOW to
/// AUDIT_MAC_CALIPSO_DEL, and AUDIT_FIRST_ANOM_MSG and above). The names are
/// `lib/msg_typetab.h` at tag `v4.1.2` (`4db9c700`), filtered by that rule
/// with the numbers in `lib/audit-records.h` and `linux/audit.h`; sorted for
/// a binary search. ausearch counts such a single-record event complete at
/// once (`docs/ausearch.8:38-41`). Before fp13's review the assembler ended
/// an event only at PROCTITLE or EOE, so a PAM `USER_ACCT` stayed open on a
/// busy log and held the feed's kept place back (FP13R-12).
const LAST_RECORDS: &[&str] = &[
    "ACCT_LOCK",
    "ACCT_UNLOCK",
    "ADD_GROUP",
    "ADD_USER",
    "ANOM_ACCESS_FS",
    "ANOM_ADD_ACCT",
    "ANOM_AMTU_FAIL",
    "ANOM_CRYPTO_FAIL",
    "ANOM_DEL_ACCT",
    "ANOM_EXEC",
    "ANOM_LOGIN_ACCT",
    "ANOM_LOGIN_FAILURES",
    "ANOM_LOGIN_LOCATION",
    "ANOM_LOGIN_ROOT",
    "ANOM_LOGIN_SERVICE",
    "ANOM_LOGIN_SESSIONS",
    "ANOM_LOGIN_TIME",
    "ANOM_MAX_DAC",
    "ANOM_MAX_MAC",
    "ANOM_MK_EXEC",
    "ANOM_MOD_ACCT",
    "ANOM_ORIGIN_FAILURES",
    "ANOM_RBAC_FAIL",
    "ANOM_RBAC_INTEGRITY_FAIL",
    "ANOM_ROOT_TRANS",
    "ANOM_SESSION",
    "CHGRP_ID",
    "CHUSER_ID",
    "CRED_ACQ",
    "CRED_DISP",
    "CRED_REFR",
    "CRYPTO_FAILURE_USER",
    "CRYPTO_IKE_SA",
    "CRYPTO_IPSEC_SA",
    "CRYPTO_KEY_USER",
    "CRYPTO_LOGIN",
    "CRYPTO_LOGOUT",
    "CRYPTO_PARAM_CHANGE_USER",
    "CRYPTO_REPLAY_USER",
    "CRYPTO_SESSION",
    "CRYPTO_TEST_USER",
    "DAC_CHECK",
    "DAEMON_ABORT",
    "DAEMON_ACCEPT",
    "DAEMON_CLOSE",
    "DAEMON_CONFIG",
    "DAEMON_END",
    "DAEMON_ERR",
    "DAEMON_RESUME",
    "DAEMON_ROTATE",
    "DAEMON_START",
    "DEL_GROUP",
    "DEL_USER",
    "DEV_ALLOC",
    "DEV_DEALLOC",
    "EOE",
    "FS_RELABEL",
    "GRP_AUTH",
    "GRP_CHAUTHTOK",
    "GRP_MGMT",
    "KERNEL",
    "LABEL_LEVEL_CHANGE",
    "LABEL_OVERRIDE",
    "MAC_CALIPSO_ADD",
    "MAC_CALIPSO_DEL",
    "MAC_CHECK",
    "MAC_CIPSOV4_ADD",
    "MAC_CIPSOV4_DEL",
    "MAC_IPSEC_ADDSA",
    "MAC_IPSEC_ADDSPD",
    "MAC_IPSEC_DELSA",
    "MAC_IPSEC_DELSPD",
    "MAC_IPSEC_EVENT",
    "MAC_MAP_ADD",
    "MAC_MAP_DEL",
    "MAC_UNLBL_ALLOW",
    "MAC_UNLBL_STCADD",
    "MAC_UNLBL_STCDEL",
    "PROCTITLE",
    "RESP_ACCT_LOCK",
    "RESP_ACCT_LOCK_TIMED",
    "RESP_ACCT_REMOTE",
    "RESP_ACCT_UNLOCK_TIMED",
    "RESP_ALERT",
    "RESP_ANOMALY",
    "RESP_EXEC",
    "RESP_HALT",
    "RESP_KILL_PROC",
    "RESP_ORIGIN_BLOCK",
    "RESP_ORIGIN_BLOCK_TIMED",
    "RESP_ORIGIN_UNBLOCK_TIMED",
    "RESP_SEBOOL",
    "RESP_SINGLE",
    "RESP_TERM_ACCESS",
    "RESP_TERM_LOCK",
    "ROLE_ASSIGN",
    "ROLE_MODIFY",
    "ROLE_REMOVE",
    "SERVICE_START",
    "SERVICE_STOP",
    "SOFTWARE_UPDATE",
    "SYSTEM_BOOT",
    "SYSTEM_RUNLEVEL",
    "SYSTEM_SHUTDOWN",
    "TEST",
    "TRUSTED_APP",
    "USER",
    "USER_ACCT",
    "USER_AUTH",
    "USER_AVC",
    "USER_CHAUTHTOK",
    "USER_CMD",
    "USER_DEVICE",
    "USER_END",
    "USER_ERR",
    "USER_LABELED_EXPORT",
    "USER_LOGIN",
    "USER_LOGOUT",
    "USER_MAC_CONFIG_CHANGE",
    "USER_MAC_POLICY_LOAD",
    "USER_MAC_STATUS",
    "USER_MGMT",
    "USER_ROLE_CHANGE",
    "USER_SELINUX_ERR",
    "USER_START",
    "USER_TTY",
    "USER_UNLABELED_EXPORT",
    "USYS_CONFIG",
    "VIRT_CONTROL",
    "VIRT_CREATE",
    "VIRT_DESTROY",
    "VIRT_INTEGRITY_CHECK",
    "VIRT_MACHINE_ID",
    "VIRT_MIGRATE_IN",
    "VIRT_MIGRATE_OUT",
    "VIRT_RESOURCE",
];

/// Whether a record of this type ends its event (`LAST_RECORDS`).
pub fn is_last_record(kind: &str) -> bool {
    LAST_RECORDS.binary_search(&kind).is_ok()
}

/// All records of one event, in the order they arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub ts_ms: i64,
    pub serial: u64,
    pub records: Vec<Record>,
}

impl AuditEvent {
    pub fn first(&self, kind: &str) -> Option<&Record> {
        self.records.iter().find(|r| r.kind == kind)
    }

    pub fn all<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a Record> + 'a {
        self.records.iter().filter(move |r| r.kind == kind)
    }
}

#[derive(Default)]
pub struct Assembler {
    open: Vec<AuditEvent>,
}

impl Assembler {
    pub fn new() -> Assembler {
        Assembler::default()
    }

    /// Adds a record; returns the events it completed, oldest first.
    pub fn push(&mut self, record: Record) -> Vec<AuditEvent> {
        let key = record.event_key();
        let ends = is_last_record(&record.kind);
        let pos = self.open.iter().position(|e| (e.ts_ms, e.serial) == key);
        let idx = match pos {
            Some(i) => i,
            None => {
                self.open.push(AuditEvent {
                    ts_ms: key.0,
                    serial: key.1,
                    records: Vec::new(),
                });
                self.open.len() - 1
            }
        };
        if record.kind != "EOE" {
            self.open[idx].records.push(record);
        }
        let mut done = Vec::new();
        if ends {
            done.push(self.open.remove(idx));
        }
        while self.open.len() > MAX_OPEN {
            done.push(self.open.remove(0));
        }
        done.retain(|e| !e.records.is_empty());
        done
    }

    /// Ends every open event, oldest first.
    pub fn flush(&mut self) -> Vec<AuditEvent> {
        let mut done: Vec<AuditEvent> = std::mem::take(&mut self.open);
        done.retain(|e| !e.records.is_empty());
        done
    }

    pub fn open_count(&self) -> usize {
        self.open.len()
    }

    /// The `(time, serial)` of each open event.
    pub fn open_keys(&self) -> impl Iterator<Item = (i64, u64)> + '_ {
        self.open.iter().map(|e| (e.ts_ms, e.serial))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::parse_line;

    fn rec(s: &str) -> Record {
        parse_line(s).unwrap()
    }

    #[test]
    fn proctitle_ends_an_event() {
        let mut a = Assembler::new();
        assert!(a
            .push(rec("type=SYSCALL msg=audit(1.000:1): syscall=59"))
            .is_empty());
        assert!(a
            .push(rec("type=CWD msg=audit(1.000:1): cwd=\"/\""))
            .is_empty());
        let done = a.push(rec("type=PROCTITLE msg=audit(1.000:1): proctitle=6C73"));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].records.len(), 3);
        assert_eq!(a.open_count(), 0);
    }

    #[test]
    fn interleaved_events_stay_apart_and_eoe_ends_one() {
        let mut a = Assembler::new();
        a.push(rec("type=SYSCALL msg=audit(1.000:1): syscall=59"));
        a.push(rec("type=SYSCALL msg=audit(1.000:2): syscall=42"));
        let done = a.push(rec("type=EOE msg=audit(1.000:1): "));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].serial, 1);
        let rest = a.flush();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].serial, 2);
    }

    #[test]
    fn too_many_open_events_push_out_the_oldest() {
        let mut a = Assembler::new();
        let mut out = Vec::new();
        for n in 0..(MAX_OPEN as u64 + 3) {
            out.extend(a.push(rec(&format!(
                "type=SYSCALL msg=audit(1.000:{n}): syscall=59"
            ))));
        }
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].serial, 0);
        assert_eq!(a.open_count(), MAX_OPEN);
    }
}
