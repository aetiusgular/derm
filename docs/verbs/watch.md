# derm watch and derm status

```
derm watch tail [--since 10m] [--chat ID] [--json]
derm watch report [--since T] [--until T] [--chat ID] [--json]
derm watch --approve
derm status [--json] [--probe]
```

Every command takes `--socket <path>` (absolute) to talk to another daemon.

- **`derm watch tail`** streams the daemon's feed: one line per event with the time, the chat, the agent, the source (`adapter`, `otel`, `run`, `auditd`, `sbx`) and a summary cleaned of terminal escapes. `--since 10m` shows the backlog first; `--json` prints the records.
- **`derm watch report`** counts a window (the last day by default): events by source and kind, approvals and how they were answered, the checks' flags (a write outside the chat's folders, a sensitive path, a new host, a process left running), and whether the log's hash chain holds. A second gate decision for one call is printed as `GATE CONFLICT`.
- **`derm watch --approve`** answers the gate's `ask`s from this terminal: each request shows its chat, its tool and the input as it will run; `y` or `n`. It refuses to start inside a chat (a `DERM_CHAT_*` or old `TK_CHAT_*` variable, or a `derm run` above it), and the daemon refuses an approver inside a running chat's process tree. An approver started outside the tree, a double fork or `setsid` away, can still answer: open finding S2. Run it from your own terminal.
- **`derm status`** prints one row per agent derm knows: whether it is installed, whether derm's gate is registered in it, its tier, whether it fails open, where an `ask` goes, and the version its row was verified at. Then the daemon (running or not, its socket) and the chats running now, read from the daemon. `--probe` also runs each agent's `--version` (each runs as you, and some agents check for updates when they do), and counts an install only when that exits 0.

An agent the coverage wave has not built shows as `planned`, not as missing.
