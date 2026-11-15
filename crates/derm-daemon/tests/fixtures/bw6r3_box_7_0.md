# bw6r3_box_7_0.jsonl

Five records from the daemon's log on the box (`panda`, Ubuntu 26.04, kernel 7.0.0-43, auditd 4.1.2 userspace), written by `derm-audit-feed` at `e8e05c3` on 14 Nov 2026 (box test w6 retest 3, BW6R3-1 and BW6R3-2), copied unedited from `~/.local/share/derm/activity/app-2026-11-15.jsonl`:

1. `auditd-1794720816125-51632`: srt 0.0.82's bubblewrap 0.11.1, in a Codex srt chat, opening the bind it made of the chat's route file (`O_RDONLY|O_CLOEXEC|O_PATH`, `a2=280000` in the audit record; `bind-mount.c:397-408` at v0.11.1). The feed at `e8e05c3` did not yet say `pathOnly`.
2. `auditd-1794720884146-53799` and `-53800`: derm's gate (`~/.local/bin/derm`), in a Claude Code srt chat with derm's plugin, creating and writing its taint state in srt's tmpfs over `~/.derm` (`dev 00:3e`, `devMounted: false`). The chat's `derm run` was `/home/opone/.local/bin/derm` too.
3. `auditd-1794724055120-71903`: the same look by bubblewrap in a Claude Code srt chat, written by the feed at `0f1d9ca`, which says `pathOnly: true` (the box retest after the fix).
4. `auditd-1794724057978-72640`: derm's gate (`~/.local/bin/derm`) in that chat reading its own route out of srt, `~/.derm/run/routes/<chat>.json` (`gate/daemon.rs` `srt_route_file`), one of three such reads in the chat. The file holds `daemonPort` and `proxyPort` only (`run/mod.rs`, `srt_route`).
