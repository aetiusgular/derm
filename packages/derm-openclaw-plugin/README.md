# derm-openclaw-plugin

The derm policy gate for OpenClaw (T2.4, wave 2 lane I). OpenClaw is not in Orca's agent grid; it is in the toolkit plan. Written against the npm package openclaw 2026.10.8 (its shipped docs and `dist/`) and run against it, on Node 24.22.1, with a fake chat-completions server (`tests/cli-contract/checks/I/openclawGate.mjs`). Not on your machines yet.

- **before_tool_call**, registered at the lowest priority (`-1000000`), so it runs after every other plugin.
  - **deny** returns `{block: true, blockReason: "derm: <reason>"}`, which is final in OpenClaw.
  - **ask** goes to the derm daemon's approver first (`derm watch --approve`). With no approver it returns `requireApproval`, which asks you through OpenClaw's plugin approvals (`/approve`). A non-interactive run (`openclaw agent exec`) has no one to ask, and OpenClaw refuses the call. An approver's no, or a timeout, is a block.
  - **allow** returns the params derm checked (with secret-like values redacted where derm redacted them). OpenClaw runs the last returned params, and every handler sees the original call, so a plugin that rewrote the params before derm is overridden: the call that runs is the call derm checked (run: `openclaw-derm-runs-last`). Codex's native relay in OpenClaw reads the same params handed back as no rewrite.
  - OpenClaw's shell tool `exec` (it turns `bash` into `exec`) is gated as **`bash`**, so a rule for `bash` covers it and the shell-text check runs. Code Mode's outer `exec` is gated as `exec`.
  - A call whose input names OpenClaw's config (`~/.openclaw/`, `openclaw.json`, `OPENCLAW_CONFIG_PATH`, `OPENCLAW_STATE_DIR`, `OPENCLAW_HOME`) asks: the config enables plugins and hot-reloads.
- **after_tool_call** records the call in the derm daemon (a hash and a size, no content). OpenClaw's `after_tool_call` cannot change a result, so derm does not redact OpenClaw's results.
- A throw or a timeout blocks: OpenClaw runs `before_tool_call` fail-closed. derm's handler has a 120 second budget (OpenClaw's default is 15), so an ask can wait; `plugins.entries.derm.hooks.timeouts.before_tool_call` overrides it.

MCP tools reach the gate as `<server>__<tool>` (no `mcp__` prefix, `-` kept); the gate reads `server/tool`.

## Install

From a clone of derm (OpenClaw needs Node 24.22.1 or later):

```bash
openclaw plugins install --link /abs/path/derm/packages/derm-openclaw-plugin --force
openclaw plugins enable derm
```

or list the folder in `~/.openclaw/openclaw.json` under `plugins.load.paths` and set `plugins.entries.derm.enabled: true` (the route the checks use). derm never installs into a workspace's `.openclaw/extensions`.

The plugin imports nothing from OpenClaw or npm and reads nothing until the first tool call.

## Known limits

- A plugin with a higher priority that already returned `requireApproval` freezes its own params snapshot, which derm's returned params cannot replace.
- Results are not redacted (no hook can change them before the model reads them; `tool_result_persist` changes only what is stored).

## Environment

As the Claude Code plugin: `DERM_POLICY`, `DERM_DAEMON_SOCKET`, `DERM_CHAT_TOKEN`, `DERM_CHAT_TOKEN_FILE`, `DERM_CHAT_ID` (else OpenClaw's `sessionId`).
