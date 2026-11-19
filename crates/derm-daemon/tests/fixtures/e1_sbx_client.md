# e1_sbx_client.jsonl

Fifteen records from the daemon's feed on the box (`panda`, Ubuntu 26.04, auditd rules `50-derm-1000.rules` as installed 16 Nov 2026 16:52), written by `derm-audit-feed` at `c82c7b3` during one real Claude Code turn in an sbx VM (`derm run --boundary sbx claude`, sbx 0.51.0, chat `e1sbx-turn1`, 16 Nov 2026 17:03). Copied unedited from `derm watch tail`'s output for that chat (`~/w6box/e1/sbxturn/turn1.jsonl` on the box).

The turn's feed held 60 file and network records from the kernel, every one from pid 296372, `/usr/bin/sbx`, tier `root`: the client `derm run` started. These fifteen are one of each kind and folder: its lock files (`~/.config/sandboxes`, `?.posixage.lock`), its analytics queue (`~/.local/share/sandboxes/.../analyticskit`), its feature-flag cache (`~/.cache/sandboxes`), and its connections (ports 443 and 65535, IPv4 and IPv6). Nothing the agent did in the VM is in the host's feed.
