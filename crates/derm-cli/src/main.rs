//! `derm`: the command line. `main.rs` only dispatches; each subcommand lives
//! in its own folder and is owned by one lane (plans/parallel_build_tk.md,
//! section 2, point 5): `connect/` lane C, `run/` lane D, `watch/` lane J in
//! wave 2; in wave 4 `connect/` is lane Q's, `run/`, `watch/`, `acp/` and
//! `doctor/` lane R's (section 7a); in wave 5 `cu/` is lane U's, `setup/` lane
//! W's and `platform/` lane Z's (section 7c). No lane edits this file during
//! a wave; a new subcommand is a request for integration.

mod acp;
mod connect;
// Wave 5 (the wave 5 base): `cu/` lane U, `setup/` lane W, `platform/` lane Z.
mod cu;
mod doctor;
// Wave 5b (the wave 5b base): `gate/` (integration's; `gate/serve/` lane
// 5bC), `hook/` (`claude_format/` lane 5bA, `native/` lane 5bB), `enter/`
// (lane 5bD).
mod enter;
mod gate;
mod hook;
mod platform;
mod run;
#[cfg(unix)]
mod setup;
mod watch;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Case 114: `derm run` holds a chat token and the harness it starts
    // inherits the limit (P2-4).
    derm_core::platform::no_core_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    // What an exited harness left running outlives `derm`, as on Unix (case
    // 68); until `derm` returns, or unwinds out of here, a late console close
    // can still end it (WW5-7, FPWR-3).
    #[cfg(windows)]
    let _release = Release;
    let code = dispatch(&args);
    ExitCode::from(code)
}

/// Releases the jobs of exited harnesses when `main` ends, a panic included.
#[cfg(windows)]
struct Release;

#[cfg(windows)]
impl Drop for Release {
    fn drop(&mut self) {
        platform::windows::exec::release_left();
    }
}

fn dispatch(args: &[String]) -> u8 {
    match args.first().map(String::as_str) {
        Some("connect") => connect::main(&args[1..]),
        Some("run") => run::main(&args[1..]),
        Some("watch") | Some("status") => watch::main(args),
        // Computer use's controls (toolkit plan T1.5; integration w2), through
        // lane U's folder since the wave 5 base.
        Some("cu") => cu::main(&args[1..]),
        // Wave 5 lane W (the wave 5 base's stub).
        #[cfg(unix)]
        Some("setup") => setup::main(&args[1..]),
        // `derm setup` writes private files with Unix modes; its Windows form
        // (ACLs through derm_core::platform) is not built (integration w5's
        // close; docs/install/windows.md says nothing installs on Windows yet).
        #[cfg(not(unix))]
        Some("setup") => {
            eprintln!("derm setup: not built for Windows yet (docs/install/windows.md)");
            2
        }
        // Wave 4 lane R (integration w2's scaffold).
        Some("acp") => acp::main(&args[1..]),
        Some("doctor") => doctor::main(&args[1..]),
        // Wave 5b (the wave 5b base): the gate in Rust.
        Some("hook") => hook::main(&args[1..]),
        Some("gate") => gate::main(&args[1..]),
        Some("enter") => enter::main(&args[1..]),
        Some("--version") => {
            println!("derm {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            eprintln!("usage: derm <connect|run|watch|status|cu|acp|doctor|setup|hook|gate|enter|--version> ...");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::dispatch;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn unknown_or_empty_command_is_usage_error() {
        assert_eq!(dispatch(&s(&[])), 2);
        assert_eq!(dispatch(&s(&["frobnicate"])), 2);
    }

    #[test]
    fn version_exits_zero() {
        assert_eq!(dispatch(&s(&["--version"])), 0);
    }

    #[test]
    fn each_subcommand_reaches_its_module() {
        // With no arguments each answers its usage error (2); the point is
        // that none panics. `status` is left out: it is a real report since
        // wave 2 (exit 0) and reads the machine's daemon socket and agent
        // config files, which a unit test must not (lane J's request 2,
        // integration w2). `watch::status` has its own tests on fixtures.
        for cmd in [
            "connect", "run", "watch", "cu", "acp", "doctor", "setup", "hook", "gate", "enter",
        ] {
            assert_eq!(dispatch(&s(&[cmd])), 2, "{cmd}");
        }
    }
}
