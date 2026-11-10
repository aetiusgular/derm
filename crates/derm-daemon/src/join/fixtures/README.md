# Join fixtures

Recorded from real tools, not written by hand (rules section 9, item 12).

- `srt-linux-claude-2.1.319-auditd.jsonl`: one chat (`b510bs3`) from the daemon's own log on the box, 8 Nov 2026, 19:07 PST: `derm run claude-code --boundary srt` at `e9220a0` with Claude Code 2.1.319 (haiku, one Bash call writing `a.txt`), srt 0.0.81 through a bubblewrap 0.11.1 copy under an unconfined AppArmor profile (`docs/install/linux.md`), auditd 4.1.2, kernel 7.0.0-42-generic, Ubuntu 26.04.1. Kept: the chat's `run` and `tap` records, and every `auditd` fork and exec whose process, or whose child, is on the line from the run's root to the shell that wrote `a.txt`, with that write. `/home/opone` is written as `/home/u` and each record's `argv` is left out; nothing else changed. Inside bubblewrap's PID namespace a fork's `exit=` (the record's `child`) is the namespace's pid (`2`, `8`), while `pid=` and `ppid=` are the host's (Linux 7.0 `kernel/auditsc.c:1629-1638`, `kernel/fork.c:2666`).
