# derm-sysmon, the Windows service (wave 5b, lane 5bE)

A per-user derm daemon cannot read Sysmon's channel: it grants read to
SYSTEM, administrators, Backup and Server Operators and Event Log Readers
only (Windows test w5, WW5-9). `derm-sysmon` reads it as the virtual account
`NT SERVICE\derm-sysmon` in Event Log Readers and hands each user's daemon
that user's events over a named pipe (`contracts/sysmon-service.md`).

Install (elevated PowerShell, after `cargo build --release`):

    .\install.ps1 -From ..\..\..\target\release

Undo:

    .\uninstall.ps1

`install.ps1` prints every step and asks before it changes anything (rules
section 5, item 2). It never installs Sysmon; `derm setup` shows Sysmon's own
install and asks for it.

What it leaves on the machine, all removed by `uninstall.ps1`:

| What | Where |
|---|---|
| The two programs | `%ProgramFiles%\derm\derm-sysmon.exe`, `derm-daemon.exe` |
| The service | `derm-sysmon`, automatic start, `NT SERVICE\derm-sysmon` |
| A group membership | `NT SERVICE\derm-sysmon` in Event Log Readers (S-1-5-32-573) |
| The service's folder | `%ProgramData%\derm-sysmon\` (`config.json`, `pipe`, `cursors.json`, `last-error.txt`) |
| The service's access list | signed-in users may query whether it runs (`sc sdset`) |

What it holds and what it does not (`tests/windows/5bE/RESEARCH.md`):

- A daemon is served only when its program is
  `%ProgramFiles%\derm\derm-daemon.exe` (checked by the client's image,
  `NtQuerySystemInformation` class 88) and its account is a signed-in user
  that is not a sandbox account; it gets only its own account's events, and
  an srt chat's `srt-sandbox` processes when they descend from a process it
  claimed.
- An agent running as you can start that program, or write into it once it
  runs, and so read your own events (BBR-2, case 232's open part). Another
  user's events never reach your daemon, and yours never reach theirs.
- The daemon refuses a pipe whose server is not the service's process, so a
  name squatted while the service was down is not trusted.
