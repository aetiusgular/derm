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

- **srt.** `derm run --boundary srt` stops on Windows, and with no `--boundary` derm never picks srt there. srt 0.0.81 runs the agent on Windows as its own `srt-sandbox` account, starting from that account's profile and passing on only `PATH`, `PATHEXT`, its proxy variables and git's (its `src/sandbox/windows-sandbox-utils.ts`), so the agent would have neither your sign-in nor derm's chat variables and gate. srt on Windows needs a design of its own.
- **The hooks' policy file.** On Windows the JavaScript hooks and derm-pi read no policy file, and every call asks: Node reports a Windows file's mode from its read-only attribute alone and has no owner id, so a hook cannot tell who may write the file. A policy derm can check needs the file's access list, read by derm itself.
- **Sysmon.** Its event channel, `Microsoft-Windows-Sysmon/Operational`, can be read by SYSTEM, Administrators, Backup Operators, Server Operators and Event Log Readers only, and an administrator's normal (not elevated) session reads it as a user. A daemon that reads Sysmon as you therefore needs you in Event Log Readers (an administrator's one-time step: `net localgroup "Event Log Readers" <you> /add`, then sign out and in), or a reader that runs elevated. derm does not read Sysmon yet; which of the two it will ask for is open.
- **Elevation.** A derm run from an elevated terminal makes its folders as yours, so a later run without elevation can use them; folders an older build left owned by Administrators are taken back for you.

## Running derm's tests on Windows

Some tests start `sh`, `sleep`, `cat` or `mkfifo` by name. GitHub's Windows runner has them on `PATH`, because its Git is installed with "Use Git and optional Unix tools from the Command Prompt" (`/o:PathOption=CmdTools`, which adds Git's `usr\bin`). On a machine whose Git was installed with the default option, put `C:\Program Files\Git\usr\bin` first on `PATH` for the test run; with it, the failures match CI's.
