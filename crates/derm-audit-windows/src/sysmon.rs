//! Sysmon's events as the feed's actions (note AU section 6; Tony's call of
//! 4 Nov, 16:50: "yes on Sysmon").
//!
//! What Microsoft's Sysmon page says (v15.22, 10 Sep 2026; read 5 Nov):
//! events go to `Applications and Services Logs/Microsoft/Windows/Sysmon/
//! Operational`; event 1 is a process creation whose `ProcessGuid` is "a
//! unique value for this process across a domain", added "to allow for
//! correlation of events even when Windows reuses process IDs"; 3 is a
//! network connection, "disabled by default", with `ProcessId` and
//! `ProcessGuid`; 5 a process that ended; 11 FileCreate, logged "when a file
//! is created or overwritten" (not on every write); 22 a DNS query; 23 and
//! 26 a file deleted (23 also archives it). The field names for 1, 3, 5 and
//! 11 are those of Sysmon's own schema dump (an older Sysmon, event version
//! 6.00, schema 3.30; V for those names then); for 22, 23 and 26 they are
//! read from third-party references and are I until the Windows test
//! captures v15.22's events. Every field is read by name, so a field Sysmon
//! adds later (`RuleName`, `FileVersion`) changes nothing.

use crate::xml::WinEvent;

/// The provider name every Sysmon event carries.
pub const PROVIDER: &str = "Microsoft-Windows-Sysmon";
/// The channel the reader queries.
pub const CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

/// One thing a process did, as Sysmon reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// Milliseconds since the epoch, from `UtcTime` (Sysmon's own clock).
    pub at_ms: Option<i64>,
    pub guid: String,
    pub pid: u32,
    pub image: String,
    pub what: What,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum What {
    /// Event 1. The command line's length only: its words stay out of the
    /// record unless content is on (case 85).
    Exec {
        parent_guid: String,
        parent_pid: u32,
        command_line_bytes: usize,
        user: String,
    },
    /// Event 5.
    Exit,
    /// Event 11: created or overwritten.
    Create { path: String },
    /// Events 23 and 26.
    Delete { path: String },
    /// Event 3, outbound only (`Initiated` true).
    Connect {
        addr: String,
        port: u16,
        host: String,
    },
    /// Event 22.
    Dns { query: String },
}

/// The action of a Sysmon event, or `None` for another provider, an event
/// the feed does not read, or one whose fields are not all there.
pub fn read(e: &WinEvent) -> Option<Action> {
    if e.provider != PROVIDER {
        return None;
    }
    let f = |k: &str| e.data.get(k).map(String::as_str);
    let guid = f("ProcessGuid")?.to_string();
    let pid: u32 = f("ProcessId")?.parse().ok()?;
    let image = f("Image").unwrap_or("").to_string();
    let what = match e.event_id {
        1 => What::Exec {
            parent_guid: f("ParentProcessGuid")?.to_string(),
            parent_pid: f("ParentProcessId")
                .and_then(|p| p.parse().ok())
                .unwrap_or(0),
            command_line_bytes: f("CommandLine").map_or(0, str::len),
            user: f("User").unwrap_or("").to_string(),
        },
        5 => What::Exit,
        11 => What::Create {
            path: f("TargetFilename")?.to_string(),
        },
        23 | 26 => What::Delete {
            path: f("TargetFilename")?.to_string(),
        },
        3 => {
            if !f("Initiated").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
                return None;
            }
            What::Connect {
                addr: f("DestinationIp")?.to_string(),
                port: f("DestinationPort")?.parse().ok()?,
                host: f("DestinationHostname").unwrap_or("").to_string(),
            }
        }
        22 => What::Dns {
            query: f("QueryName")?.to_string(),
        },
        _ => return None,
    };
    Some(Action {
        at_ms: f("UtcTime").and_then(utc_ms),
        guid,
        pid,
        image,
        what,
    })
}

/// Sysmon's `UtcTime` (`2026-11-05 09:30:01.123`) as milliseconds since the
/// epoch.
pub fn utc_ms(s: &str) -> Option<i64> {
    let (date, time) = s.trim().split_once(' ')?;
    let mut d = date.split('-');
    let (y, mo, da): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let (hms, frac) = time.split_once('.').unwrap_or((time, "0"));
    let mut t = hms.split(':');
    let (h, mi, se): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let ms: i64 = format!("{:0<3}", &frac[..frac.len().min(3)]).parse().ok()?;
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + h) * 60 + mi) * 60_000 + se * 1000 + ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_time_reads_as_epoch_milliseconds() {
        assert_eq!(utc_ms("1970-01-01 00:00:00.000"), Some(0));
        assert_eq!(utc_ms("2026-11-05 09:30:01.123"), Some(1_793_871_001_123));
        assert_eq!(utc_ms("2000-02-29 00:00:00.5"), Some(951_782_400_500));
        assert_eq!(utc_ms("2026-13-01 00:00:00.000"), None);
        assert_eq!(utc_ms("yesterday"), None);
    }
}
