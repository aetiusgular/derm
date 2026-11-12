//! `derm audit` (wave 6, lane 6E). The wave 6 base's stub: it answers a
//! usage error and changes nothing until the lane builds it.
//!
//! derm audit export|verify|anchor|why (wave 6 plan section 2.1;
//! contracts/events.md sections 6.4 and 6.5; note AZ rows E1 to E4, AZ-1).

pub const USAGE: &str = "derm audit: not built yet (wave 6, lane 6E)";

pub fn main(_args: &[String]) -> u8 {
    eprintln!("{USAGE}");
    2
}
