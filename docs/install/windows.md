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
| The boundary | sbx on Windows 11 with the Windows Hypervisor Platform (`winget install -h Docker.sbx`, then `sbx login`; Docker's install page). srt's Windows support is an alpha |
| The OS layer | Sysmon or ETW for processes, files and the network |
| The gate's shell check | PowerShell: an allow by command text holds only for plain words (`contracts/policy.md` step 7c) |

The Windows test runs on the box's Windows 11 drive before any of this is released.
