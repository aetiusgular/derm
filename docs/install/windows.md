# Windows

derm does not run on Windows yet. This page says what exists and what is being built (wave 5, lane Z; `research-notes/AU_windows_platform.md`), so nothing here is an install line.

## What works today

Nothing derm ships runs on Windows. The release has no Windows build; CI's Windows job builds the workspace and is expected to fail until lane Z's work lands. derm's agent hooks, if a Windows agent ran them, refuse the daemon on Windows ("the daemon's endpoint cannot be checked on Windows yet"), so a Windows hook fails closed rather than trusting a pipe it cannot check.

## What is being built

| Part | On Windows |
|---|---|
| The daemon's socket | A named pipe, with a check that the server is the daemon before the gate trusts it (lane Z) |
| `derm run` | The agent's process tree held in a Job Object; Ctrl-C passed on as on Linux and macOS |
| The token file and `~/.derm` | Owner-only by access control lists, not file modes |
| The boundary | sbx on Windows 11 with the Windows Hypervisor Platform (`winget install -h Docker.sbx`, then `sbx login`; Docker's install page). A new machine also needs `sbx policy init <allow-all\|balanced\|deny-all>` before its first sandbox. srt: see below |
| The OS layer | Sysmon or ETW for processes, files and the network; see below for who may read Sysmon |
| The gate's shell check | PowerShell: an allow by command text holds only for plain words (`contracts/policy.md` step 7c) |

The Windows test runs on the box's Windows 11 drive before any of this is released.

## What the Windows test found (8 Nov 2026)

- **srt.** `derm run --boundary srt` stops on Windows, and with no `--boundary` derm never picks srt there. srt 0.0.81 runs the agent on Windows as its own `srt-sandbox` account, starting from that account's profile and passing on only `PATH`, `PATHEXT`, its proxy variables and git's (its `src/sandbox/windows-sandbox-utils.ts`), so the agent would have neither your sign-in nor derm's chat variables and gate. srt on Windows needs a design of its own. Wave 5b builds it: see "srt on Windows" below.
- **The hooks' policy file.** On Windows the JavaScript hooks and derm-pi read no policy file, and every call asks: Node reports a Windows file's mode from its read-only attribute alone and has no owner id, so a hook cannot tell who may write the file. A policy derm can check needs the file's access list, read by derm itself.
- **Sysmon.** Its event channel, `Microsoft-Windows-Sysmon/Operational`, can be read by SYSTEM, Administrators, Backup Operators, Server Operators and Event Log Readers only, and an administrator's normal (not elevated) session reads it as a user. A daemon that reads Sysmon as you therefore needs you in Event Log Readers (an administrator's one-time step: `net localgroup "Event Log Readers" <you> /add`, then sign out and in), or a reader that runs elevated. derm does not read Sysmon yet; which of the two it will ask for is open.
- **Elevation.** The daemon's own folders (`%USERPROFILE%\.derm\run\derm` and the data folder) are made as yours even from an elevated terminal, and the same folders an older build left owned by Administrators are taken back for you. Other files and folders derm makes from an elevated terminal (a chat's approval folder, a pid file) are still owned by Administrators, and a later run without elevation refuses them as another user's; remove them, or run elevated again.

## The gates on Windows (Windows test w5b, 11 Nov 2026)

- **The Claude Code, Codex and Gemini plugins** start `/bin/sh` on their launcher, which Windows does not have, so their gate cannot run there in this build, and an agent may run a call whose hook cannot start. `derm connect claude-code|codex|gemini --gate` says so and registers nothing.
- **Pi, oh-my-pi, OpenCode, Kilo Code and OpenClaw** run only the derm `DERM_BIN` names, which `derm run` sets to itself; started outside `derm run` they refuse every call.
- **Crush, goose, Hermes and the other `derm hook` lines** are not registered on Windows in this build either: `derm connect <agent> --gate` refuses with the reason.

## srt on Windows (wave 5b, lane 5bD; not released, not yet run on a Windows machine)

What `derm run --boundary srt` does on Windows once integration wires it in (`contracts/srt-windows.md`, `crates/derm-cli/src/run/boundary/windows_srt/`). Until then it still stops, as above.

- **Install srt once per machine.** `npm install -g @anthropic-ai/sandbox-runtime`, then `npx @anthropic-ai/sandbox-runtime windows-install`, which asks to elevate once (srt's README, "Windows (alpha)"). It makes the `srt-sandbox` account and its network filters, and by default makes the tool folders of your profile readable to sandboxed commands; derm needs that grant for a harness installed under your profile (npm's global folder). On a machine more than one person uses, srt's README says to install with `--skip-profile-grant`; then install the harness where every user can read it.
- **One srt chat at a time on the machine.** srt runs every chat, any Windows user's, as the one `srt-sandbox` account, whose processes can open each other, so derm runs one srt chat at a time and refuses a second with the reason.
- **What reaches the chat.** srt starts `derm.exe enter`, which reads the chat's handoff from `%USERPROFILE%\.derm-srt\chats\<chat>\` (yours alone; the sandbox account may read three files there and delete the handoff), deletes it, and starts the harness by its `.exe` with the chat's variables. derm needs the daemon for this (`--no-daemon` is refused under srt on Windows).
- **Where the harness keeps its state.** Claude Code and Codex only, for now. The harness works in `%USERPROFILE%\.derm-srt\state\<harness>`, given a copy of your sign-in and its config (Claude Code's `.claude.json`, `.credentials.json` and `settings.json`; Codex's `config.toml`, `auth.json` and `hooks.json`). The folder is emptied when the chat stops, its sessions and history with it, because srt keeps the write grant on it and any later sandboxed session on the machine can read it.
- **Sign-in.** The harness's sign-in host stays shut under srt on Windows, so a renewal inside cannot spend the single-use refresh token your own copy holds. Once the copied access token expires, the chat stops: run the harness once outside srt to renew, then start the chat again.
- **What the sandbox may not touch.** It writes only the chat's folder and that state folder; not the harness's control files there or in the project, not `.git\hooks` or `.git\config`, not `derm.exe`. It reads nothing of `%USERPROFILE%\.derm` or of any harness's own state in your profile.
- **Paths.** srt runs `derm.exe` through `cmd.exe`, so derm refuses to start srt when `derm.exe`, your profile or the handoff's path holds `"`, `%` or `!`. A folder on a network share or a mapped drive is refused, as srt refuses it.
- **Shared machines.** srt's README: another Windows user who runs `srt-win exec` without its write-restricted token can write into folders srt kept a grant on. derm's state folder is one of them while a chat runs.

## Running derm's tests on Windows

Some tests start `sh`, `sleep`, `cat` or `mkfifo` by name. GitHub's Windows runner has them on `PATH`, because its Git is installed with "Use Git and optional Unix tools from the Command Prompt" (`/o:PathOption=CmdTools`, which adds Git's `usr\bin`). On a machine whose Git was installed with the default option, put `C:\Program Files\Git\usr\bin` first on `PATH` for the test run; with it, the failures match CI's.
