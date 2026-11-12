//! `derm secret` (wave 6, lane 6C). The wave 6 base's stub: it answers a
//! usage error and changes nothing until the lane builds it.
//!
//! derm secret add|list|remove: secrets the broker injects for named hosts
//! (wave 6 plan section 2.2; contracts/policy.md section 8; note AZ rows C1 to
//! C8).

pub const USAGE: &str = "derm secret: not built yet (wave 6, lane 6C)";

pub fn main(_args: &[String]) -> u8 {
    eprintln!("{USAGE}");
    2
}
