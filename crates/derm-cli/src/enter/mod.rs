//! `derm enter <handoff>`: the command srt runs inside its sandbox account
//! on Windows (`contracts/srt-windows.md`). It reads the chat's handoff file
//! once, sets the chat's variables and starts the harness. Lane 5bD's.
//!
//! The base's stub refuses: no harness starts.

pub fn main(args: &[String]) -> u8 {
    let _ = args;
    eprintln!("derm enter: not built yet (wave 5b lane 5bD); nothing is started");
    2
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stub_starts_nothing() {
        assert_eq!(super::main(&[]), 2);
    }
}
