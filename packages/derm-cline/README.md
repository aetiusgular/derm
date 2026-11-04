# derm-cline

The derm policy gate for the Cline CLI (T2.7, wave 4 lane P), in two parts on derm's shared gate core: a Cline SDK plugin whose `beforeTool` hook checks every tool call, and a responder for Cline's approval files. Written against Cline's source at tag `cli-v3.0.74` and run against Cline 3.0.74 with a fake chat-completions server (`tests/cli-contract/checks/P/clineGate.mjs`). Not on your machines yet.

## The plugin (`src/plugin.ts`)

Cline runs a plugin's `beforeTool` before every tool, in every mode (TUI, prompt runs, JSON, `--yolo`), before its own approval policy.

- **Deny** answers `{skip: true, reason: "derm: <reason>"}`: that call is skipped, the model gets the reason, and the run goes on. derm never answers `stop`, which ends the run.
- **Ask** answers `{policy: {autoApprove: false}}`: Cline then asks through its own approval route, even when it was started with `--auto-approve true` (Cline's default, and what Orca starts it with). In the TUI that is Cline's own prompt; in a run with no one to ask, Cline denies the call ("requires approval in a TTY session"). Both were run.
- **Allow** answers nothing, so Cline's own policy decides; derm's allow never skips a prompt Cline would show.
- `run_commands` is checked as `bash`, one command per line, read the way Cline's own normalizer reads it (strings and `{command, args}` entries; an argv entry is checked as one command line). Input Cline could read two ways (`commands` beside `command` or `cmd`, an entry of another shape) is refused. Cline's read tools (`read_files`, `search_codebase`, `fetch_web_content`), which Cline approves on its own, reach the plugin too: a deny on `read_files` blocks it (run).
- Secret-like values are rewritten with `{input}` only for an MCP tool or `fetch_web_content`, whose input leaves the machine as it is; anywhere else (a shell command, an `editor` write, `apply_patch`) they make the call an ask.
- Input with long runs of secret-like words, which make the shared core's redaction slow, is refused before it is checked, so a slow check cannot run past Cline's 3 s and switch the plugin off (`src/budget.ts`).
- An allowed call whose input names Cline's plugin, hook or settings folders (`~/.cline/`, a project's `.cline/`, `~/Documents/Cline/`, `.clinerules`, `~/.agents/plugins`), the variables that move them (`CLINE_DIR`, `CLINE_DATA_DIR`, `CLINE_PLUGIN_*`, `CLINE_TOOL_APPROVAL_*`) or derm's approval folder asks.

The plugin reads nothing when it loads or is set up, never waits on the derm daemon (its record is sent and not awaited), and has no dependencies.

**It fails open.** Cline gives a hook 3 seconds; a hook that throws or takes longer is ignored and the call runs under Cline's own policy, and five failures in a row turn the plugin off until it is reloaded. The CLI has no switch for this (`hookErrorMode` is an SDK setting). derm's hook catches its own errors and answers a skip, and does nothing slow; what it cannot cover is Cline's timeout or its worker dying. `derm status` says "fails open" for Cline.

## The approval-file responder (`bin/derm-cline-approvals.mjs`)

With `CLINE_TOOL_APPROVAL_MODE=desktop` and `CLINE_TOOL_APPROVAL_DIR=<folder>`, Cline writes `<session>.request.<call>.json` and waits up to 5 minutes for `<session>.decision.<call>.json`, then denies. The responder answers each request once: an allow rule approves, a deny rule or the reject list refuses with derm's reason, and an ask waits on the derm daemon's approver (`derm watch --approve`); anything but its yes is a refusal. It writes each answer under a temporary name and renames it, so Cline never reads half a file. `derm run cline` (wave 4 lane R) starts it as `derm-cline-responder --dir <folder>` when that command is on PATH (the package's bin, since integration w4; `npm link` in this folder, or a link of your own to the script), else it says so and Cline denies each gated call after its 5 minutes. Since integration w4's review (W4-S4) `derm run` reads the script's first line, `#!/usr/bin/env node`, finds `node` on PATH by the same rule as the script (absolute, not from a folder the sandbox can write) and starts that `node` with the script, so a `node` planted in the project cannot run in its place; and the responder runs with a PATH of only the absolute entries outside the folders the sandbox can write, so what it or a wrapper starts by name later is not a planted program either (re-review W4-R1). A version manager's shim that picks its tool by the name it was started under (mise, Volta) does not start this way, because derm starts the resolved file (W4-R2, open; Cline then refuses each gated call after 5 minutes). Do not install the package under a `node_modules` folder (`npm install -g`): Node refuses to strip types from files there, the responder exits at once, and `derm run` still prints that it started it (review W4-S9; the calls then fail closed). By hand:

```
node --no-warnings /abs/path/derm/packages/derm-cline/bin/derm-cline-approvals.mjs --dir <folder> [--cwd <session folder>] [--until-pid <cline's pid>]
```

The folder must be yours, 0700, not a link, and outside the session folder. The responder stops answering if that changes, exits on SIGTERM, SIGINT or SIGHUP, or when the process `--until-pid` names exits. A responder that is not running is a refusal after Cline's 5 minutes.

**In Cline 3.0.74 a prompt run never writes a request.** Through Cline's hub (the default) an approval in a non-interactive run is refused before any file is written; with the local backend (`--data-dir`) the run has no session id yet when the first tool asks, so Cline refuses with "Desktop tool approval IPC is not configured". Both were run; `main` on 3 Nov has the same code. The responder answers Cline's own `requestDesktopToolApproval` correctly (run against `@cline/core` 0.2.0), so it works once Cline fixes the session id. Until then the plugin is the gate, and an ask in a headless run is a refusal.

## Install

Copy the package folder into Cline's global plugin folder, without the tests (Cline reads `package.json`'s `cline.plugins` entry, `./src/plugin.ts`):

```
mkdir -p ~/.cline/plugins/derm
cp -R /abs/path/derm/packages/derm-cline/package.json /abs/path/derm/packages/derm-cline/src ~/.cline/plugins/derm/
rm ~/.cline/plugins/derm/src/*.test.ts
```

or `cline plugin install /abs/path/derm/packages/derm-cline`, which copies a local folder into Cline's plugin store. Cline binds plugins to a session when it starts, so a running session keeps what it had. derm never writes a project's `.cline/plugins/`.

## Known limits

- **Plugins in a project run first.** Cline loads `<project>/.cline/plugins/` with no trust prompt, before the global folder. derm judges the input those plugins leave, and its ask merges over their policy (both run: a project plugin that sets `autoApprove: true` does not undo derm's ask, and one that rewrites a command to a rejected one is refused). A project plugin is code running inside Cline, so no hook stands against it; `~/Documents/Cline/Plugins/` loads after derm's.
- **The hub keeps its first environment.** Cline's hub daemon starts with the environment of the run that started it and loads plugins too. A session it runs reads the policy and the chat token from that environment, not from a later run's. `--data-dir` runs on the local backend, with no hub.
- **The responder's folder is the agent's to write.** The agent runs as you and its shell sees `CLINE_TOOL_APPROVAL_DIR`, so it can write a decision of its own. A decision derm did not write is recorded as a conflict and replaced by derm's answer while the request still waits; Cline may read the forged one first. The responder answers a request per identity (inode, times, size), writes nothing for a request that changed or went while it decided, removes an answer no Cline takes within 2 s, never takes the chat from the request file, and stops if the folder is replaced. None of that stops an agent that writes first: do not count the responder as a gate. Naming the folder in a command asks (the control list), and a boundary (`srt` `denyWrite`) is what stops it.

## Environment

`DERM_POLICY`, `DERM_DAEMON_SOCKET`, `DERM_CHAT_TOKEN`, `DERM_CHAT_TOKEN_FILE`, `DERM_CHAT_ID` (else Cline's conversation id). The plugin reads them in Cline's process (run: the plugin ran in the CLI's process with the run's environment); the responder in its own.
