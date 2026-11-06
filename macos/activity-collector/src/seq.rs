//! Events the kernel dropped for this collector (Mac test w5 retest 4,
//! MW5-23 and MW5-19's rest).
//!
//! Endpoint Security numbers every message it delivers to a client:
//! "Inspect the global sequence number per-client to detect whether the
//! kernel had to drop events for this client. If the kernel doesn't drop any
//! events for this client, `global_seq_num` increments by 1 for every
//! message", available from message version 5
//! (https://developer.apple.com/documentation/endpointsecurity/es_message_t/global_seq_num).
//! eslogger is that client here, and its JSON carries the field at the top
//! level (seen in captures from version 6 and 10; Apple's eslogger page does
//! not list the JSON's keys). A gap between two lines is the count the kernel
//! dropped before eslogger saw them; the collector's own channel drops come
//! after this reader and are counted apart (`Shared::dropped`).
//!
//! The reader looks only for the top-level `"global_seq_num":` and `"time":"`
//! keys, without parsing the line: it runs on every line eslogger prints,
//! before the filter. A JSON string cannot hold either key's spelling, since
//! a quote inside it is escaped. A line whose number cannot be read (too
//! long, not UTF-8, the key absent) is counted as read, so it is not taken
//! for a drop.

use std::collections::VecDeque;

use serde::Serialize;

use crate::timefmt;

/// How many gaps the collector keeps, newest last.
pub const KEEP_GAPS: usize = 64;

/// One gap: what the kernel dropped between two lines eslogger printed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    /// The event time of the line before the gap, when it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_ms: Option<i64>,
    /// The event time of the line after it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_ms: Option<i64>,
    pub count: u64,
}

/// Follows eslogger's `global_seq_num` across its lines.
#[derive(Debug, Default)]
pub struct SeqWatch {
    last: Option<u64>,
    last_time_ms: Option<i64>,
    /// Lines since `last` whose number was not read.
    unread: u64,
    /// Events the kernel dropped since this collector started.
    pub total: u64,
    gaps: VecDeque<Gap>,
}

impl SeqWatch {
    pub fn new() -> SeqWatch {
        SeqWatch::default()
    }

    /// One line eslogger printed, as read.
    pub fn line(&mut self, line: &[u8]) {
        let Some(seq) = number_after(line, b"\"global_seq_num\":").filter(|n| *n > 0) else {
            self.unread += 1;
            return;
        };
        let time = text_after(line, b"\"time\":\"").and_then(timefmt::parse_rfc3339_ms);
        if let Some(last) = self.last {
            if seq > last {
                let gap = (seq - last - 1).saturating_sub(self.unread);
                if gap > 0 {
                    self.total = self.total.saturating_add(gap);
                    if self.gaps.len() == KEEP_GAPS {
                        self.gaps.pop_front();
                    }
                    self.gaps.push_back(Gap {
                        from_ms: self.last_time_ms,
                        to_ms: time,
                        count: gap,
                    });
                }
            }
            // A number that does not rise is a new eslogger (its counter
            // starts again), not a drop.
        }
        self.last = Some(seq);
        self.last_time_ms = time;
        self.unread = 0;
    }

    /// A line the reader could not look at (too long, not UTF-8).
    pub fn unreadable(&mut self) {
        self.unread += 1;
    }

    /// eslogger started again: its counter starts again.
    pub fn restart(&mut self) {
        self.last = None;
        self.last_time_ms = None;
        self.unread = 0;
    }

    /// The gaps kept, oldest first.
    pub fn gaps(&self) -> Vec<Gap> {
        self.gaps.iter().cloned().collect()
    }
}

/// The digits after the first `key` in `line`, spaces allowed between.
fn number_after(line: &[u8], key: &[u8]) -> Option<u64> {
    let at = find(line, key)? + key.len();
    let rest = &line[at..];
    let rest = &rest[rest.iter().position(|b| *b != b' ')?..];
    let end = rest
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 || end > 20 {
        return None;
    }
    std::str::from_utf8(&rest[..end]).ok()?.parse().ok()
}

/// The text after the first `key` in `line`, up to the next quote, at most
/// 64 bytes.
fn text_after<'a>(line: &'a [u8], key: &[u8]) -> Option<&'a str> {
    let at = find(line, key)? + key.len();
    let rest = &line[at..];
    let end = rest.iter().take(64).position(|b| *b == b'"')?;
    std::str::from_utf8(&rest[..end]).ok()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(seq: u64, second: u32) -> String {
        format!(
            "{{\"version\":7,\"seq_num\":{seq},\"event\":{{\"create\":{{}}}},\"time\":\"2026-11-06T10:00:{second:02}.000000000Z\",\"process\":{{\"start_time\":\"2026-11-06T09:00:00.000000000Z\"}},\"global_seq_num\":{seq}}}"
        )
    }

    #[test]
    fn a_gap_in_the_global_number_is_what_the_kernel_dropped() {
        let mut w = SeqWatch::new();
        for (seq, s) in [(1, 0), (2, 1), (3, 2), (10, 5), (11, 6)] {
            w.line(line(seq, s).as_bytes());
        }
        assert_eq!(w.total, 6);
        let gaps = w.gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].count, 6);
        assert_eq!(
            gaps[0].from_ms,
            timefmt::parse_rfc3339_ms("2026-11-06T10:00:02Z")
        );
        assert_eq!(
            gaps[0].to_ms,
            timefmt::parse_rfc3339_ms("2026-11-06T10:00:05Z")
        );
    }

    #[test]
    fn lines_the_reader_could_not_look_at_are_not_drops() {
        let mut w = SeqWatch::new();
        w.line(line(1, 0).as_bytes());
        w.unreadable();
        w.line(b"{\"version\":7,\"event\":{}}");
        w.line(line(4, 1).as_bytes());
        assert_eq!(w.total, 0, "two lines were read, just not their numbers");
        w.line(line(9, 2).as_bytes());
        assert_eq!(w.total, 4);
    }

    #[test]
    fn a_new_eslogger_starts_its_count_again() {
        let mut w = SeqWatch::new();
        w.line(line(500, 0).as_bytes());
        w.line(line(1, 1).as_bytes());
        w.line(line(2, 2).as_bytes());
        assert_eq!(w.total, 0);
        w.restart();
        w.line(line(7, 3).as_bytes());
        assert_eq!(w.total, 0);
    }

    #[test]
    fn a_path_cannot_spell_the_key_and_old_versions_carry_none() {
        let mut w = SeqWatch::new();
        // A path holding the key's words is escaped JSON: no match.
        let tricky = r#"{"event":{"create":{"destination":{"existing_file":{"path":"/x/\"global_seq_num\":999"}}}},"global_seq_num":1}"#;
        w.line(tricky.as_bytes());
        w.line(line(2, 1).as_bytes());
        assert_eq!(w.total, 0);
        // A number of 0 (an older message version) is not read as one.
        let mut v = SeqWatch::new();
        v.line(b"{\"global_seq_num\":0}");
        v.line(b"{\"global_seq_num\":0}");
        assert_eq!(v.total, 0);
    }

    #[test]
    fn only_the_newest_gaps_are_kept() {
        let mut w = SeqWatch::new();
        let mut seq = 1;
        for i in 0..(KEEP_GAPS as u64 + 10) {
            w.line(line(seq, (i % 60) as u32).as_bytes());
            seq += 2;
        }
        assert_eq!(w.gaps().len(), KEEP_GAPS);
        assert_eq!(w.total, KEEP_GAPS as u64 + 9);
    }
}
