//! `derm acp` (wave 4 lane R, toolkit plan T2.9): an ACP agent started the
//! way `derm run` starts a harness, with derm between the client and it.
//!
//! ```text
//! derm acp gemini --boundary srt -- --acp
//! derm acp --boundary none -- /opt/bin/some-acp-agent
//! ```
//!
//! The client (Orca's structured chats, Zed) starts `derm acp` in place of
//! the agent and speaks ACP on its stdin and stdout. derm answers the
//! permission requests the agent sends from the policy (`decide.rs`),
//! passes `ask` on to the client's own prompt, refuses client-side writes
//! and terminals the policy denies, and records every tool call the agent
//! reports in the daemon, under the chat `derm run` minted (`proxy.rs`).
//!
//! What it is not: a gate. An agent "MAY request permission" (ACP v1
//! `tool-calls.mdx:138`), so a call it never asks about runs; derm records
//! it "logged, not gated". The agent's own gate, where derm has one
//! registered, still runs inside it; `derm run`'s boundary still holds.
//!
//! Orca takes a single executable as a structured agent's command override
//! (`src/shared/tui-agent-launch-command-override.ts:5-21` at `f776923`,
//! note AQ section 7), so there `derm acp` needs a one-file wrapper per
//! agent (not run).

// The decide path moved to `crate::gate::decide` (the wave 5b base),
// unchanged; `derm acp` still answers through it.
pub use crate::gate::decide;
pub mod proxy;

use std::sync::Arc;

pub const USAGE: &str =
    "usage: derm acp <agent> --boundary sbx|srt|none [derm run options] [-- agent args...]
       derm acp --boundary sbx|srt|none [derm run options] -- <program> [args...]

  Starts the agent as `derm run` would, and sits between your ACP client and
  it: permission requests are answered from your policy (an ask goes to the
  client's prompt), client-side writes and terminals your policy denies are
  refused, and every tool call is recorded in the daemon. Calls the agent
  does not ask about are logged, not gated.";

pub fn main(args: &[String]) -> u8 {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        eprintln!("{USAGE}");
        return 2;
    }
    crate::run::main_with(args, &filter)
}

/// What `derm acp` decides with, from what `derm run` hands over: the policy
/// `derm run` loaded and checked once (FPW-S2, FPWR-5; never read again by
/// path here), and the chat.
pub(crate) fn ctx_from(p: &crate::run::Pipes) -> decide::Ctx {
    let policy = p.policy_file.clone();
    if let Some(problem) = &p.policy_problem {
        eprintln!(
            "derm acp: {}: {problem}; every call the agent asks about goes to your client",
            p.policy
        );
    }
    decide::Ctx {
        policy,
        harness: p.harness.clone(),
        chat: p.chat.clone(),
        full_access: p.full_access,
        confined: p.confined,
    }
}

/// What `derm run` hands over once the agent has started.
fn filter(p: crate::run::Pipes) -> Vec<std::thread::JoinHandle<()>> {
    let ctx = ctx_from(&p);
    let (tx, log) = proxy::log_channel(p.socket.clone(), p.token.clone());
    if log.is_none() {
        eprintln!("derm acp: no daemon token: answers are given, nothing is recorded");
    }
    let st = Arc::new(proxy::State::new(ctx, tx));
    proxy::start(
        st,
        Box::new(p.stdin),
        p.stdout,
        std::io::stdin(),
        std::io::stdout(),
        log,
    )
}

#[cfg(test)]
mod tests;
