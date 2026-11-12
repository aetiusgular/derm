//! The gate in Rust (wave 5b, `plans/toolkit_wave5b_plan.md`; cut by the
//! wave 5b base). One decide path for every command hook (`derm hook`), the
//! in-process plugins' co-process (`derm gate serve`) and `derm acp`:
//!
//! - [`policy`]: the checked policy load, moved unchanged from `run/` (case
//!   226), and [`policy::load_for_hook`], which reads the policy a gate
//!   reads by the same rules with the hook core's trusted owners (owner
//!   rule from `derm_core::owner`, note BB BBR-4).
//! - [`core`]: the harness-neutral gate (`gate.ts`): input text, the
//!   policy's answer, redaction, install records, the ask's resolution.
//! - [`daemon`]: the daemon client (`daemon.ts`): `approve` and `event`.
//! - [`decide`]: `derm acp`'s decide path, moved unchanged from `acp/`.
//! - `serve/`: `derm gate serve`, lane 5bC's (a stub on the base).
//! - `locallog/`: the light tier's per-chat log, lane 6B's; `taint/`: taint
//!   at the gate, lane 6D's (the wave 6 base's stubs; `post_event` and
//!   `decide_call` call them).
//!
//! Everything here but `serve/`, `locallog/` and `taint/` is integration's
//! (wave 5b plan section 2.0, part 3; wave 6 plan section 2.0, part 3): a
//! lane that needs a change writes a request.

pub mod core;
pub mod daemon;
pub mod decide;
pub mod locallog;
pub mod policy;
pub mod serve;
pub mod taint;

#[cfg(all(test, unix))]
#[path = "../../tests/support/fake_daemon.rs"]
pub(crate) mod fake_daemon;

pub const USAGE: &str = "usage: derm gate serve --agent <id>

  The gate as a co-process for the plugins whose hosts load JavaScript only
  (contracts/gate-serve.md): JSON lines on stdin and stdout.";

pub fn main(args: &[String]) -> u8 {
    match args.first().map(String::as_str) {
        Some("serve") => serve::main(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            2
        }
    }
}
