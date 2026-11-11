//! `derm gate serve`: the gate as a co-process that the in-process plugins
//! (Pi and oh-my-pi through derm-pi, OpenCode, Kilo, OpenClaw, Amp, Cline)
//! start once per session (`contracts/gate-serve.md`). Lane 5bC's.
//!
//! The base's stub reads no request and answers none: it says it is not
//! built and exits 2, so a plugin that starts it fails closed (case 228:
//! the plugin denies every call while its co-process is not running).

pub fn main(args: &[String]) -> u8 {
    let _ = args;
    eprintln!("derm gate serve: not built yet (wave 5b lane 5bC); every call is denied");
    2
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stub_fails_closed() {
        assert_eq!(super::main(&[]), 2);
    }
}
