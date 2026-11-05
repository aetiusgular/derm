# Privacy

derm sends no telemetry and has no account. What it records stays on your machine, in files only you can read. This page says what reaches the network, what does not, and how each claim was checked: **measured** (watched on a running system) or **read** (checked in the code, not watched).

## What does not reach the network

| Part | Claim | How it was checked |
|---|---|---|
| `derm-daemon`, apart from the model tap and computer use below | Makes no other outbound connection. It listens on its Unix socket (a named pipe on Windows), on one loopback port for OTLP and on one loopback port for the tap | Measured before wave 5 on macOS 26.5.1: `lsof -nP -p <pid> -i` showed only `TCP 127.0.0.1:<port> (LISTEN)`, equal to `otlp.endpoint`, and LuLu raised no prompt (27 and 28 Oct 2026, Mac test w1 B3 and B4). Since wave 5 the daemon also runs the tap; not measured again yet (Mac test w5, M-S5). Read: no other client socket in its code; the computer-use relay refuses any address that is not loopback |
| `derm` | Talks only to the daemon's socket | Read: no network client in `crates/derm-cli` |
| The gates (`packages/derm-*`) | Talk only to the daemon's socket. Pi's emitter posts to the daemon's OTLP port and refuses any endpoint that is not loopback, and any redirect | Read (`packages/derm-pi/src/otlp.ts`); the contract checks run each gate against fake model servers on 127.0.0.1 |
| `node library/cli.ts validate`, `export`, `takedown`, `library/site/build.ts`, `library/trust/cli.ts` (without the switches below) | No network | Read |

## What does, and its switch

| Part | What it contacts | Switch |
|---|---|---|
| `derm status --probe` | Runs each agent's `--version` as you; some agents check for updates when they do | Off unless you pass `--probe` |
| The model tap, in `derm-daemon` | For a chat `derm run` taps, the daemon forwards that agent's own model requests to the one provider the chat's route names, from a fixed table of four hosts: `api.anthropic.com`, `api.openai.com`, `chatgpt.com` (Codex on a ChatGPT sign-in) and `generativelanguage.googleapis.com`. It follows no redirect and forwards nowhere else; your own upstreams in `~/.derm/settings.json` (`tap.upstreams`) are read and not used yet. These are the calls the agent makes anyway, now through the daemon: a firewall such as LuLu sees `derm-daemon` connect, not the agent (read; not measured) | `"tap": {"on": false}` in `~/.derm/settings.json`, or `derm run ... --no-tap` for one chat; an untapped chat is recorded as `untapped` |
| Computer use, in `derm-daemon` on Linux | Starts `cua-driver mcp --direct` as its child, as you, with the driver's telemetry and update check turned off by variable (`CUA_DRIVER_RS_TELEMETRY_ENABLED=false`, `CUA_DRIVER_RS_UPDATE_CHECK=false`, `CUA_TELEMETRY=0`; read, not measured) | Off by default; `"computerUse": {"on": true}` in `~/.derm/settings.json` turns it on |
| The pre-install check (gate) | Would ask the package's registry and `api.osv.dev` whether a package being installed exists and is known malware | Built off and not wired in this build: no call is made (`installs.check` in `~/.derm/settings.json` stays off until its socket operation lands) |
| `derm run` with no `--boundary` | Probes sbx (`sbx version`, `sbx ls`, which may start sbx's own daemon) and srt before the chat; every sbx command derm runs sets `SBX_NO_TELEMETRY=1` | Name a boundary with `--boundary` to skip the probes |
| `derm run --boundary sbx` | Docker's sbx, signed in to your Docker account; sbx pulls its images and kits on a create | Choose `srt` or `none` |
| `node library/mirror/cli.ts pull` | `registry.modelcontextprotocol.io`, and each mirrored remote's own host to probe it | `--no-probe` turns the probes off; the mirror runs only when you or a schedule you turn on run it |
| `node library/publish/cli.ts publish` | GitHub through `gh`; the DNS or `.well-known` lookup of the namespace proof | Only when you publish; `--open-pr` to act |
| `node library/cli.ts validate` | The registry's `/v0.1/validate` | `DERM_LIBRARY_ONLINE=1` |
| `node library/trust/cli.ts osv` and `scan` | `api.osv.dev` (package names and versions; one scanner reaches it too) | `DERM_TRUST_ONLINE=1`, `DERM_TRUST_SCAN=1` |

## What derm records, and where

- The activity log: tool calls, approvals, the agents' own telemetry and, with the OS feed, processes and file writes. In the daemon's data folder, 0600, one file per day, hash-chained.
- By default a record keeps tool names, decisions, sizes and hashes, not prompts, tool inputs or outputs (`contracts/events.md`). The content switch below is the only way content is kept, and then only in content files, never in a record (`DERM_LOG_CONTENT` is gone). An `ask` shows the call's input to the approver in its terminal.
- The tap's records (wave 5): per model call, the call id, the tool, hashes and sizes of its arguments and result, the paths the arguments name, the model, the token counts and the timing; no header and no body, with content off. A crash leaves no core file or crash dump (`RLIMIT_CORE` 0 from the first line of `derm-daemon` and `derm`; Windows Error Reporting off on Windows).
- Content capture (wave 5): off by default. `"content": {"on": true, "retentionDays": N}` in `~/.derm/settings.json`, N from 1 to 7, keeps the tapped requests' and replies' text, the agents' own telemetry's prompts, replies and tool inputs, and `derm run`'s argument words in the daemon's data folder, unencrypted, 0600, and deletes each file within 10 minutes of its N days, a daemon restart included; turning it off deletes nothing already kept until its time ends.
- The OS feed (Linux auditd, optional) keeps the command lines of a chat's processes, with secret-shaped words redacted, and the paths they wrote.
- `derm run`'s record keeps an agent's flags and the length of every other word, since an argument can be a prompt; with the content switch on the words go to a content file and the record says `contentKept`.
- Every line `derm connect` prints from a file of yours goes through the redactor; a key already in your config is not echoed.

## What derm cannot speak for

The agents themselves: what Claude Code, Codex, Gemini CLI or any other agent sends to its own model provider is between you and that provider. With the tap, the daemon carries a tapped chat's model traffic and records what is listed above; it does not change or filter it, and an agent derm does not tap (Pi until its provider route is built, Cursor, and the agents with no tap form in `crates/derm-cli/src/connect/presets/wave5/tap.json`) reaches its provider directly. derm can stop a tool call. `derm run --boundary srt` limits which hosts an agent's tools can reach, not the agent's own API.
