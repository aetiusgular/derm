# Lane V's integration tests and requests (wave 5)

## Tests

Both make and remove local users, so they run only as root on a throwaway
Linux machine (a cloud workspace, a container), never on the box or the Mac.

- `agent-user.mjs`: S2 part c end to end. `install.sh` makes an owner's
  agents' user; the owner's daemon runs; `derm run pi --boundary none` starts
  a stand-in `pi` from the agents' user's own install; the gate's real client
  inside it reaches the daemon through the chat's bridge, reads the owner's
  policy, and cannot reach the owner's token, files, `sudo` or the approver.
  Needs requests V-1 and V-3 applied; `--core` names the hook core to copy.
  Run 4 Nov 2026 on a scratch tree with the three patches: 20 of 20 under
  classic sudo 1.9.15p5 and under sudo-rs 0.2.13 (Ubuntu 26.04's default).
- `srt-token.mjs`: S2 under srt 0.0.81. Needs srt, bubblewrap, socat and
  ripgrep. Run 4 Nov 2026: 6 of 6.

```
sudo node tests/integration/w5/V/agent-user.mjs --bin target/release --core packages/derm-claude-plugin/src/core
sudo node tests/integration/w5/V/srt-token.mjs --bin target/release --srt /tmp/cli/node_modules/.bin/srt
```

## Requests for integration (`requests/`)

Each patch applies with `git apply` on lane V's head, touches files no wave 5
lane owns (or, for V-2's one test fix, lane U's before lane U starts), and
was tested by lane V on a scratch tree with all three applied: `cargo test
-p derm-core -p derm-daemon -p derm-cli` 751 passed, 0 failed (715 at
`96f764b`); `npx vitest run` 67 files, 1,239 passed (1,231); clippy, `tsc`
and `sync-core.mjs --check` clean; both tests above pass; `w4.mjs` 49 of
49; `pi-live.mjs` 14 of 14; `memory-live.mjs` 9 of 9 and its untrusted run;
`tests/cli-contract/run.mjs` against Claude Code 2.1.311, Codex 0.163.0,
Gemini CLI 0.66.0 and Pi 1.4.0: 150 checks, 39 pass, 9 info, 0 fail, 102
skipped (the base's counts). Workspace `cargo test`: 805 passed, 0 failed
(769 at `96f764b`).

- `V-1-run-context.patch`: `run/mod.rs` calls `user::wrap_with` with the
  chat's boundary, folders, daemon and policy, and `user::finish()` when the
  harness exits; `run.start`'s `runsAs` names the agents' user. Removes the
  context-free `wrap` and the `allow(dead_code)` line from
  `run/user/mod.rs`.
- `V-2-person-proof.patch`: S2 part b wired. `protocol.rs`: `answer` takes an
  optional `proof: {password}`. `daemon.rs`: `dispatch` calls
  `op_answer_proved`; a `ran_as_you` flag; `run_info` keeps `agentUser`.
  `watch/approve.rs`: after a `yes` the daemon refuses for want of the
  password, the approver reads it with echo off, sends it once, wipes it,
  and shows the card again after a wrong one. Five existing tests answered
  `yes` for a chat with no `run.start`; each now starts its chat under srt
  first (their intent kept), and two tests are new. `tests/integration/w1.mjs`
  runs its hook checks before its Pi chat (which runs as you and so turns the
  check on for every later `yes`), starts `int-cc-1` under srt, and adds one
  check that after the Pi chat a `yes` without the password is refused:
  22 of 22 (20 before).
- `V-3-gate-trusts-the-owner.patch`: `src/core/owner.ts` in the canonical
  hook core (then `sync-core.mjs` copies it into the ten packages) and its
  port in derm-pi: a gate running as an agents' user trusts the files of the
  owner `/etc/derm/agent-users.json` names, never its own; a broken root
  file trusts no one. `daemon.ts`, `policy.ts` and derm-pi's `policy-store.ts`
  use it.
