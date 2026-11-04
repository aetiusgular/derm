//! `derm setup` (wave 5, lane W; `plans/toolkit_universal_plan.md` lane W):
//! find the installed agents, then one question each for the boundary, the
//! tap, the content switch, the gate, computer use, the pre-install check and
//! the launch route. The policy presets go under `setup/presets/`.
//!
//! The wave 5 base's stub: says it is not built and exits 2, writing nothing.

pub fn main(args: &[String]) -> u8 {
    let _ = args;
    eprintln!("derm setup: not built yet (wave 5, lane W)");
    2
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stub_writes_nothing_and_exits_2() {
        assert_eq!(super::main(&[]), 2);
        assert_eq!(super::main(&["--yes".to_string()]), 2);
    }
}
