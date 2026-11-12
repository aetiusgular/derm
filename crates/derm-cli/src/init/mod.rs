//! `derm init` (wave 6, lane 6B). The wave 6 base's stub: it answers a
//! usage error and changes nothing until the lane builds it.
//!
//! derm init: one command, no root, no daemon: finds agents, registers gates,
//! writes the Standard tier where lane 6A supports it, prints what it changed
//! (wave 6 plan section 2.1; note AZ rows B7, A2).

pub const USAGE: &str = "derm init: not built yet (wave 6, lane 6B)";

pub fn main(_args: &[String]) -> u8 {
    eprintln!("{USAGE}");
    2
}
