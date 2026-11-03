# Privacy

derm sends no telemetry and has no account. What it records stays on your machine, in files only you can read. This page says what reaches the network, what does not, and how each claim was checked: **measured** (watched on a running system) or **read** (checked in the code, not watched).

## What does not reach the network

| Part | Claim | How it was checked |
|---|---|---|
| `derm-daemon` | Makes no outbound connection. It listens on its Unix socket and on one loopback port for OTLP | Measured on macOS 26.5.1: `lsof -nP -p <pid> -i` showed only `TCP 127.0.0.1:<port> (LISTEN)`, equal to `otlp.endpoint`, and LuLu raised no prompt (27 and 28 Oct 2026, Mac test w1 B3 and B4). Read: no client socket in its code except the computer-use relay, which refuses any address that is not loopback. Not measured on Linux |
| `derm` | Talks only to the daemon's socket | Read: no network client in `crates/derm-cli` |
| The gates (`packages/derm-*`) | Talk only to the daemon's socket. Pi's emitter posts to the daemon's OTLP port and refuses any endpoint that is not loopback, and any redirect | Read (`packages/derm-pi/src/otlp.ts`); the contract checks run each gate against fake model servers on 127.0.0.1 |
| `node library/cli.ts validate`, `export`, `takedown`, `library/site/build.ts`, `library/trust/cli.ts` (without the switches below) | No network | Read |

## What does, and its switch

| Part | What it contacts | Switch |
|---|---|---|
| `derm status --probe` | Runs each agent's `--version` as you; some agents check for updates when they do | Off unless you pass `--probe` |
| `derm run --boundary sbx` | Docker's sbx, signed in to your Docker account | Choose `srt` or `none` |
| `node library/mirror/cli.ts pull` | `registry.modelcontextprotocol.io`, and each mirrored remote's own host to probe it | `--no-probe` turns the probes off; the mirror runs only when you or a schedule you turn on run it |
| `node library/publish/cli.ts publish` | GitHub through `gh`; the DNS or `.well-known` lookup of the namespace proof | Only when you publish; `--open-pr` to act |
| `node library/cli.ts validate` | The registry's `/v0.1/validate` | `DERM_LIBRARY_ONLINE=1` |
| `node library/trust/cli.ts osv` and `scan` | `api.osv.dev` (package names and versions; one scanner reaches it too) | `DERM_TRUST_ONLINE=1`, `DERM_TRUST_SCAN=1` |

## What derm records, and where

- The activity log: tool calls, approvals, the agents' own telemetry and, with the OS feed, processes and file writes. In the daemon's data folder, 0600, one file per day, hash-chained.
- By default a record keeps tool names, decisions, sizes and hashes, not prompts, tool inputs or outputs (`contracts/events.md`). `DERM_LOG_CONTENT=1` turns content on. An `ask` shows the call's input to the approver in its terminal.
- The OS feed (Linux auditd, optional) keeps the command lines of a chat's processes, with secret-shaped words redacted, and the paths they wrote.
- `derm run`'s record keeps an agent's flags and the length of every other word unless `DERM_LOG_CONTENT=1`, since an argument can be a prompt.
- Every line `derm connect` prints from a file of yours goes through the redactor; a key already in your config is not echoed.

## What derm cannot speak for

The agents themselves: what Claude Code, Codex, Gemini CLI or any other agent sends to its own model provider is between you and that provider. derm can stop a tool call; it does not see or filter the model traffic. `derm run --boundary srt` limits which hosts an agent's tools can reach, not the agent's own API.
