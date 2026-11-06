//! Fix pass 4's review, FP4-S5: the reviewer's test, failing first: a chat's
//! drops stay placed after any number of later gaps.

use derm_activity_collector::seq::SeqWatch;

fn line(seq: u64, minute: u32, second: u32) -> String {
    format!(
        "{{\"version\":7,\"event\":{{\"create\":{{}}}},\"time\":\"2026-11-06T10:{minute:02}:{second:02}.000000000Z\",\"global_seq_num\":{seq}}}"
    )
}

/// The agent's burst during its run makes the kernel drop OS events for
/// eslogger; any later burst (a process it left behind, another chat, a
/// build) makes 64 more gaps, and the run's gap is no longer kept. The
/// daemon's `chatOsMissed` and `osKernelDrops` read only the kept gaps
/// (`kernel_drops_for`), so the chat reads as fully watched.
#[test]
fn fp4_s5_a_chats_drops_stay_placeable_after_later_gaps() {
    let mut w = SeqWatch::new();
    let mut seq = 1;
    w.line(line(seq, 0, 0).as_bytes());
    // The run: 10:00:00 to 10:00:05; 500 events dropped at 10:00:02.
    seq += 501;
    w.line(line(seq, 0, 2).as_bytes());
    // Later, from 10:05: 64 small gaps.
    for i in 0..64u32 {
        seq += 2;
        w.line(line(seq, 5, i % 60).as_bytes());
    }
    assert_eq!(w.total, 500 + 64);
    let run = (
        derm_activity_collector::timefmt::parse_rfc3339_ms("2026-11-06T10:00:00Z").unwrap(),
        derm_activity_collector::timefmt::parse_rfc3339_ms("2026-11-06T10:00:35Z").unwrap(),
    );
    let during: u64 = w
        .gaps()
        .iter()
        .filter(|g| g.from_ms.unwrap_or(0) <= run.1 && g.to_ms.unwrap_or(0) >= run.0)
        .map(|g| g.count)
        .sum();
    // The first later gap runs from the run's last line (10:00:02) to
    // 10:05:00, so its one event may have been dropped during the run: it
    // overlaps, and is counted, as before this fix. The run's own 500 stay.
    assert!(
        (500..=501).contains(&during),
        "the run's 500 dropped events are no longer placed: {during}"
    );
}
