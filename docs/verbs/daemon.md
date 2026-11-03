# derm-daemon

```
derm-daemon --foreground [--socket PATH] [--data-dir PATH]
derm-daemon cu-mcp
derm-daemon collector-plan --binary ABSOLUTE_PATH
```

The daemon is one process per user. It holds:

- **the socket** (0600, in a 0700 folder: `$XDG_RUNTIME_DIR/derm/` on Linux, `~/Library/Application Support/derm/` on macOS), speaking JSON lines. The first line is a token. Its own token is in `daemon.token` (0600) and changes on every start; chats get their own tokens, which can post into their own chat and nothing else.
- **an OTLP receiver** on a loopback port (in `otlp.endpoint`), for the agents' own telemetry (Claude Code, Codex, Pi's emitter). A request needs a chat token in `x-derm-token`.
- **the activity log**, one hash-chained JSON-lines file per day, 0600. The last copy of a record wins per id, and a second gate decision for one call is kept as a conflict copy and flagged.
- **the approval channel**: a gate's `ask` waits for a connected approver (`derm watch --approve`) and becomes `no` when none answers in time.
- `chats.json`: the running chats, kept across a restart.

It makes no outbound connection. It refuses to start twice (`daemon.pid`).

Run it as a user service: `systemctl --user enable --now derm-daemon` on Linux (installed by the .deb, or from the tarball), a launchd agent on macOS (`crates/derm-daemon/units/io.github.aetiusgular.derm.daemon.plist`). See the [install pages](../README.md).

- `cu-mcp` is the stdio MCP server an agent starts for computer use: it relays to the daemon's loopback bridge with the chat's token. macOS only, and the helper is not in this release.
- `collector-plan` prints, and runs none of, the root commands that would install the macOS activity collector, with the hashes they check. The collector is not in this release.
