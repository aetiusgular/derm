# Lane 5bA's contract checks and record (wave 5b)

Lane 5bA ported the Claude-format command hooks to Rust: `derm hook <agent>
<event>` for Claude Code, Codex, Gemini, OpenClaude, Qwen Code, Droid,
Command Code, Kimi Code, Auggie, Copilot CLI and Grok
(`crates/derm-cli/src/hook/claude_format/`). The project's status doc
(`plans/parallel/tk_lane_5bA.md`) is kept short because the project is
nearly full; this file holds the lane's full record.

## Files here

- `rust.mjs`: reruns lane L's, lane F's (`dermClaude.mjs`, `dermCodex.mjs`)
  and lane I's Gemini checks with derm's TypeScript hook replaced by the
  Rust one, staged at load (relative imports made absolute, the one line
  that names the hook changed, the three plugins copied with their
  `hooks/hooks.json` running `"<derm>" hook <agent> <event>`). Ids get
  `-rust`. `run.mjs` loads only one-letter lane folders, so this file runs
  itself with `run.mjs`'s CLI flags and `DERM_BIN`.
- `grokMarks.mjs`: two checks against the real Grok (BCR-7, below).

## What ran (10 Nov 2026, cloud, Linux, as root)

| Run | Result |
|---|---|
| `cargo test -p derm-cli --features w5b-red --test hook_cases_5bA` | 165 of 165 cases pass (166 with the harness's own test), three runs |
| `contracts_w5b` `another_agents_input_is_not_answered_in_this_dialect` | pass (the file's 4 other tests are 5bC's, 5bD's and 5bF's, red as on the base) |
| `cargo test -p derm-cli` | 595 unit tests, 0 failed; the lane's 24 under `hook::` |
| clippy `-D warnings` (all targets, `w5b-red`), `cargo fmt --all --check`, `npx tsc --noEmit`, `lane-scope.mjs 5bA` | clean |
| Contract checks, TypeScript hook (baseline), 57 checks | 48 pass, 7 info, 0 fail, 2 skipped |
| Contract checks, Rust hook (`rust.mjs`), 59 checks | 50 pass, 6 info, 1 fail, 2 skipped |
| Trial merge with `lane/5bB`, `lane/5bD`, `lane/5bE` | clean |

CLIs under `/tmp/cli` at the base's pins, none moved since (`npm view`, 10
Nov): Claude Code 2.1.322, Codex 0.167.1, Gemini 0.68.0, OpenClaude 0.35.1,
Qwen Code 0.27.2, Droid 1.8.0, Kimi 2.5.3, Copilot 1.0.109, Grok 1.0.77.
Skipped in both runs: `openclaude-derm-full-access` and `derm-claude-bypass`
(each CLI refuses its bypass flag as root; the Mac test runs them).

The one failure, `gemini-derm-fail-open-rust`, is the check's premise, not
the dialect: it hangs the gate with a FIFO as the policy file, and the Rust
policy load opens the file without blocking on a FIFO
(`crates/derm-cli/src/gate/policy.rs`, FPWR2-2), so the gate answers ("not a
regular file", every call asks) instead of hanging, and Gemini's fail-open
path is not reached. Gemini's own fail-open stays shown by the TypeScript
run (info). Integration: hang the gate another way in that check (a
command that sleeps past the timeout).

## Research (rules section 9)

| Item | Source, version | Mark |
|---|---|---|
| Each dialect's behaviour | the TypeScript adapters at `e29ce27` (`packages/derm-claude-plugin`, `derm-codex-plugin`, `derm-gemini-extension`, `derm-hooks-claude-compat`), replayed against their own recordings by the base (227 of 227) | V |
| Hook runners of Codex 0.167.1 and Gemini 0.68.0 | `contracts/hook-dialects.md` 9.1 (the base read them) | V |
| Grok 1.0.77 runs a hook in `~/.claude/settings.json` with compat on, and what it sends | run here: `grok -p --yolo` against the fake chat server, recording hooks in `~/.grok/hooks/own.json` and `~/.claude/settings.json`; both got Grok's own input, both spellings (`hookEventName: "pre_tool_use"`, `toolName`, `toolInput`, `toolInputTruncated`, `workspaceRoot`, and `hook_event_name: "PreToolUse"`, `tool_name`, ...), env `GROK_HOOK_NAME`, `GROK_HOOK_EVENT`. Settles section 9.2's NF | V (run) |
| Claude Code's own input carries neither Grok mark | the 48 recorded Claude Code calls in `contracts/fixtures/hook-cases/5bA.json`; note BC section 2 | V |
| Command Code 1.88.5 still strips `/TOKEN/i` and 14 more from a hook's environment (case 76) | `dist/cli.mjs`, `sanitizeHookEnv`'s list | V (read) |
| Auggie 0.37.1's `mcp_metadata` keys and `conversation_id` | `augment.mjs` | V (read) |
| Copilot's `toolArgs` as a JSON string, Grok's both spellings | note BC section 2; the contract runs above | V |
| Prior art for the deferral to another agent's gate | derm's own `runByCursor`/`cursorGateRegistered` (case 109); Orca's Cursor hook answers `{}`; dcg writes its own `current_exe()` for a registration (note BC section 3) | V |

## Decisions

- Grok's input in Claude Code's hook is told by both marks, `hookEventName`
  `pre_tool_use`/`post_tool_use` and a boolean `toolInputTruncated`. With
  derm's Grok gate registered in `~/.grok/hooks/derm.json` and every derm
  entry `failClosed`, Claude Code's hook prints nothing (no decision, no
  record); otherwise it blocks and names the fix. Run against real Grok:
  both checks in `grokMarks.mjs` pass.
- A registration in the wave 5b form counts as derm's only when its program
  is this derm (same real path) and writable by no one else (case 227);
  the node forms count by the checks `watch::register` already applies.
- A result's SHA-256 is taken over serde_json's text, keys sorted (the
  workspace has no `preserve_order`), so it differs from the TypeScript's
  for an object whose keys were not in order; the daemon reads only whether
  a hash is there (`join/mod.rs`). Gemini's and the compat agents' call keys
  are made the same way, so a pre and a post record still agree.
- Command Code's derived token file is Unix only; on Windows it derives
  nothing and an ask is a deny.

## Requests for integration

1. `tests/cli-contract/run.mjs`: load lane folders whose name is not one
   capital letter (`5bA`), or run `checks/5bA/rust.mjs` in step 3.
2. `checks/I/geminiGate.mjs` `gemini-derm-fail-open`: hang the gate by a
   command, not a FIFO policy (above).
3. Rules section 4 (proposed, from this lane): **a Claude Code hook run by
   Grok** (Grok's compat import, on by default): it defers to derm's Grok
   gate when that is registered and fails closed, else blocks naming the
   fix; never a decision as Claude Code. Extends case 109.

## Security (rules section 5)

1: no secret in fixtures or records; a denied call's input is never echoed
(test). 3: no shell string; the agent is argv's. 4: a hooks file another
agent reads is judged by owner and mode before it counts. 7: every new path
narrows (defer only to a fail-closed derm gate; an unreadable input denies).
8, 9: no outbound call, no new crate. 11: commits in Tony's name.

## Corner cases covered by tests

70 (every unreadable input is a deny; a post never blocks), 71, 72, 73
(Auggie, Grok cut input), 75 (Grok deferral, run), 76 (Gemini alias,
Command Code derived file), 77, 79, 82, 83 (full access after a narrowing),
109 (Cursor, Grok), 227 (registration by absolute path), 224 (Windows path
in the token test).

## Left behind

Cloud only: `/tmp/cli` (the CLIs), `/tmp/rec5a` (recordings and logs).
