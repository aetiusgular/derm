# derm-hooks-claude-compat

derm's gate for eight agents whose hooks take Claude Code's shape: OpenClaude, Qwen Code, Droid, Command Code, Kimi Code, Auggie, Copilot CLI and Grok Build. One command hook, one dialect per agent (`src/agents.ts`), the shared gate core (`src/core/`, synced from `packages/derm-claude-plugin`; never edit it here). Wave 4, lane L, toolkit plan T2.5.

## What runs

Each agent runs, before every tool call:

```
node --no-warnings "<this folder>/bin/derm-hook.mjs" <agent id> pre
```

The hook reads the agent's input, maps its shell tool to `bash` (so a `bash` rule and the shell checks apply), asks the core, and answers in the agent's own reply format. It prints only that reply and never echoes the tool input. It needs Node 22.18 or later, and the package must not sit under a `node_modules` folder (Node strips types only outside one), so install it from the release's source archive or a clone.

`derm connect <agent> --gate` writes the registration (`src/registration.ts` holds each entry). Until that command exists, the entries are:

| Agent | File (user level) | Entry | Fails closed? | `ask` goes to |
|---|---|---|---|---|
| OpenClaude | `~/.openclaude/settings.json` | `hooks.PreToolUse`, matcher `*`, timeout 120 | No: a crash or timeout lets the call run | OpenClaude's prompt (an approver first; never in a bypass mode) |
| Qwen Code | `~/.qwen/settings.json` | `hooks.PreToolUse`, matcher `""`, timeout 120 | No | Qwen's prompt (an approver first; `-p`, ACP and yolo deny) |
| Droid | `~/.factory/settings.json` (never create `~/.factory/hooks.json`, which shadows it) | `hooks.PreToolUse`, matcher `*`, timeout 120 | No | the derm approver, else deny |
| Command Code | `~/.commandcode/settings.json` | `hooks.PreToolUse`, matcher `.*`, timeout 120, `failClosed: true` | Yes | the derm approver, else deny |
| Kimi Code | `~/.kimi-code/config.toml` | one `[[hooks]]` table: `event`, `command`, `timeout` only | No | the derm approver, else deny |
| Auggie | `~/.augment/settings.json` | `hooks.PreToolUse`, matcher `.*`, `metadata.includeMCPMetadata`, timeout 120000 (ms) | No | the derm approver, else deny |
| Copilot CLI | `~/.copilot/hooks/derm.json` (a file of its own) | `preToolUse`, `bash`, `timeoutSec` 120 | A crash denies; a timeout runs the call | Copilot's prompt (an approver first; not in autopilot) |
| Grok Build | `~/.grok/hooks/derm.json` (a file of its own), and `[compat.claude] hooks = false`, `[compat.cursor] hooks = false` in `~/.grok/config.toml` | `hooks.PreToolUse`, matcher `*`, timeout 120, `failClosed: true` | Yes, from 1.0.71; 1.0.70 ignores the switch | Grok's prompt (an approver first) |

What every row keeps (`contracts/hook-dialects.md` section 1): a call is allowed only where a policy rule says allow; a deny blocks that call, never the run; an `ask` never becomes "no decision".

## The chat token

Started with `derm run <agent> --boundary none`, the hook presents the chat's token to the daemon. Command Code strips every variable named like a token from a hook's environment, so there the hook finds the token file from `DERM_CHAT_ID` and `DERM_DAEMON_SOCKET`, which `derm run` also sets (`src/env.ts`). The core checks the file the same way either way.

## Tests

`npx vitest run packages/derm-hooks-claude-compat` runs each dialect against `contracts/fixtures/hook-dialects/<agent>/` and a fake daemon. `tests/cli-contract/checks/L/` runs the real CLIs that start without an account against fake model servers.
