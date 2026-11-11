//! One client's place in the channel (case 232: each client has its own
//! cursor, and only its own acks move it).
//!
//! `pos` is the last record the service has read for this client, sent or
//! not; `sent` holds the ids sent and not yet acknowledged. The cursor kept
//! across restarts (`cursor`) is the last record whose every predecessor
//! this client either acknowledged or was never sent: on a reconnect the
//! service reads on from there, so nothing sent is lost, and what was sent
//! twice the daemon keeps once (its records are `sysmon-<record id>`).
//!
//! Gaps: records the channel no longer holds (it wrapped: the oldest id is
//! past `pos`), a hole inside what was read, and a channel whose ids start
//! again (it was cleared: the newest id is below `pos`). Whether record ids
//! are contiguous in a channel is I (lane 5bE's research, R12): a hole is
//! named, never filled.

use std::collections::VecDeque;

use crate::wire::Record;

/// How many sent records may wait for an ack before the service stops
/// reading for this client.
pub const MAX_UNACKED: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gap {
    pub from: u64,
    pub to: u64,
    pub reason: String,
}

#[derive(Debug)]
pub struct Stream {
    pos: u64,
    sent: VecDeque<u64>,
}

/// What one read gives this client.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Step {
    pub gaps: Vec<Gap>,
    pub send: Vec<Record>,
}

impl Stream {
    /// A client that acknowledged up to `cursor` (`None`: a new client,
    /// which starts after `newest`, the channel's last record now).
    pub fn new(cursor: Option<u64>, newest: Option<u64>) -> Stream {
        Stream {
            pos: cursor.or(newest).unwrap_or(0),
            sent: VecDeque::new(),
        }
    }

    /// Where the next read starts: records after this id.
    pub fn pos(&self) -> u64 {
        self.pos
    }

    /// Whether the service may read for this client now.
    pub fn ready(&self) -> bool {
        self.sent.len() < MAX_UNACKED
    }

    /// The channel's oldest and newest record ids, before a read.
    pub fn check(&mut self, oldest: Option<u64>, newest: Option<u64>) -> Vec<Gap> {
        let mut gaps = Vec::new();
        if let Some(newest) = newest {
            if newest < self.pos {
                gaps.push(Gap {
                    from: self.pos.saturating_add(1),
                    to: self.pos.saturating_add(1),
                    reason: "the channel was cleared: its record ids start again".into(),
                });
                self.pos = oldest.unwrap_or(1).saturating_sub(1);
                self.sent.clear();
            }
        }
        if let Some(oldest) = oldest {
            if oldest > self.pos.saturating_add(1) {
                gaps.push(Gap {
                    from: self.pos + 1,
                    to: oldest - 1,
                    reason: "records the channel no longer holds".into(),
                });
                self.pos = oldest - 1;
            }
        }
        gaps
    }

    /// Records read after `pos`, in order, with `keep(record)` saying which
    /// this client gets.
    pub fn read(&mut self, records: Vec<Record>, mut keep: impl FnMut(&Record) -> bool) -> Step {
        let mut step = Step::default();
        for r in records {
            if r.record_id <= self.pos {
                continue;
            }
            if r.record_id > self.pos + 1 {
                step.gaps.push(Gap {
                    from: self.pos + 1,
                    to: r.record_id - 1,
                    reason: "record ids the channel skipped".into(),
                });
            }
            self.pos = r.record_id;
            if keep(&r) {
                self.sent.push_back(r.record_id);
                step.send.push(r);
            }
        }
        step
    }

    /// The client acknowledged `id`: every sent record up to it is done. An
    /// id this client was never sent moves nothing.
    pub fn ack(&mut self, id: u64) -> Result<(), String> {
        if !self.sent.contains(&id) {
            return Err("an ack for a record this client was not sent".into());
        }
        while self.sent.front().is_some_and(|s| *s <= id) {
            self.sent.pop_front();
        }
        Ok(())
    }

    /// A record that will not be sent after all (too large for a line): it
    /// waits for no ack, and is named as a gap.
    pub fn unsend(&mut self, id: u64) {
        self.sent.retain(|s| *s != id);
    }

    /// The cursor to keep for this client's user.
    pub fn cursor(&self) -> u64 {
        match self.sent.front() {
            Some(first) => first - 1,
            None => self.pos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recs(ids: &[u64]) -> Vec<Record> {
        ids.iter()
            .map(|i| Record {
                record_id: *i,
                xml: format!("<{i}>"),
            })
            .collect()
    }

    #[test]
    fn a_new_client_starts_at_the_channels_end_and_a_known_one_at_its_cursor() {
        assert_eq!(Stream::new(None, Some(500)).pos(), 500);
        assert_eq!(Stream::new(Some(40), Some(500)).pos(), 40);
        assert_eq!(Stream::new(None, None).pos(), 0);
    }

    #[test]
    fn only_this_clients_acks_move_its_cursor_and_unsent_records_count_as_done() {
        let mut s = Stream::new(Some(100), Some(100));
        let step = s.read(recs(&[101, 102, 103, 104]), |r| r.record_id % 2 == 0);
        assert_eq!(
            step.send.iter().map(|r| r.record_id).collect::<Vec<_>>(),
            vec![102, 104]
        );
        assert!(step.gaps.is_empty());
        // Nothing acked: the cursor stays before the first record sent.
        assert_eq!(s.cursor(), 101);
        // An ack for a record another client got, or none got, is refused.
        assert!(s.ack(103).is_err());
        assert!(s.ack(999).is_err());
        assert_eq!(s.cursor(), 101);
        s.ack(102).unwrap();
        assert_eq!(s.cursor(), 103);
        s.ack(104).unwrap();
        assert_eq!(s.cursor(), 104);
        // A read with nothing for this client still moves it on.
        s.read(recs(&[105, 106]), |_| false);
        assert_eq!(s.cursor(), 106);
    }

    #[test]
    fn a_wrapped_a_skipping_and_a_cleared_channel_are_named_as_gaps() {
        let mut s = Stream::new(Some(100), Some(100));
        let gaps = s.check(Some(150), Some(200));
        assert_eq!(
            gaps,
            vec![Gap {
                from: 101,
                to: 149,
                reason: "records the channel no longer holds".into()
            }]
        );
        assert_eq!(s.pos(), 149);
        let step = s.read(recs(&[150, 153]), |_| true);
        assert_eq!(step.gaps.len(), 1);
        assert_eq!((step.gaps[0].from, step.gaps[0].to), (151, 152));
        // Cleared: the newest id is below where this client stands.
        let gaps = s.check(Some(1), Some(7));
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].reason.contains("cleared"));
        assert_eq!(s.pos(), 0);
        assert_eq!(s.cursor(), 0);
        let step = s.read(recs(&[1, 2]), |_| true);
        assert_eq!(step.send.len(), 2);
    }

    #[test]
    fn a_client_that_never_acks_stops_being_read_for() {
        let mut s = Stream::new(Some(0), Some(0));
        let ids: Vec<u64> = (1..=MAX_UNACKED as u64).collect();
        s.read(recs(&ids), |_| true);
        assert!(!s.ready());
        s.ack(10).unwrap();
        assert!(s.ready());
    }

    #[test]
    fn a_record_too_large_to_send_waits_for_no_ack() {
        let mut s = Stream::new(Some(0), Some(0));
        s.read(recs(&[1, 2, 3]), |_| true);
        s.unsend(1);
        s.ack(3).unwrap();
        assert_eq!(s.cursor(), 3);
    }
}
