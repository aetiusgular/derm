# derm-hooks-native

derm's gate as a command hook for six agents that each speak their own hook dialect: Cursor, Antigravity, goose, Mistral Vibe, Crush and Kiro (toolkit plan T2.6, wave 4 lane N). One launcher, `bin/derm-hook.mjs <agent>`, reads the agent's pre-tool input on stdin, decides with derm's shared gate core (`src/core/`, synced from `packages/derm-claude-plugin`, never edited here) and prints the agent's own reply.

Node 22.19 or later, from a folder that is not under `node_modules` (Node strips TypeScript types only outside it). Nothing loads or reads a file until the agent calls the hook.

## Register

`registration/<agent>/` holds the exact entry for each agent. Replace `<derm-hooks-native>` with the absolute path of this folder. `derm connect <agent> --gate` (wave 4 lane Q) writes the same entry under `derm connect`'s rules: user level only, a dry run first, and a refusal if the file changed since.

| Agent | File | Entry | Fails closed |
|---|---|---|---|
| Cursor CLI | `~/.cursor/hooks.json` | `preToolUse` and `beforeMCPExecution` | yes, `failClosed: true` |
| Antigravity CLI | `~/.gemini/config/hooks.json` | the named hook `derm`, `PreToolUse`; the file's other hooks are left alone | reported, not run |
| goose | `~/.agents/plugins/derm/` (`plugin.json`, `hooks/hooks.json`) | `PreToolUse` | yes, `on_failure: "block"` |
| Mistral Vibe | `~/.vibe/hooks.toml` | `[[hooks]]` `type = "pre_tool"` | yes, `strict = true` |
| Crush | `~/.config/crush/crush.json` | `hooks.PreToolUse` | **no: Crush lets a call through when a hook fails or times out** |
| Kiro CLI | `~/.kiro/hooks/derm.json` | `PreToolUse` | yes, any non-zero exit blocks (V3) |

Every entry runs the gate with a 120 second timeout; the gate caps its own wait for an approver at 90 seconds, so the agent's timeout is never what decides.

## What each agent gets

The policy is `~/.derm/policy.json` (`DERM_POLICY` moves it). A rule's `allow` is the only allow. An `ask` goes to the agent's own prompt where the agent shows one for a hook, else to `derm watch --approve`, else it is denied; never "no decision".

| Agent | Allow | Ask | Deny | Shell tools read as `bash` |
|---|---|---|---|---|
| Cursor | `permission: allow` | MCP calls: Cursor's own prompt; other tools: the approver or deny (Cursor does not enforce ask on `preToolUse`) | `permission: deny` | `Shell` |
| Antigravity | `decision: allow` | `force_ask` (Antigravity's prompt; a remembered "Always Allow" cannot answer it) | `decision: deny` | `run_command`, `manage_task` send_input |
| goose | exit 0, nothing printed | the approver or deny | exit 2 and `decision: block` | `shell` |
| Mistral Vibe | nothing printed (Vibe's own permission check follows) | the approver or deny | `decision: deny` on exit 0 | `file_system.bash`, `process.start`, `process.write` |
| Crush | `decision: allow` (pre-approves) | the approver or deny | exit 2 | `bash` |
| Kiro | exit 0, nothing printed (stdout would reach the model) | the approver or deny | exit 2 | `execute_bash`, `execute_pwsh` |

No reply that ends a run is ever used (Crush's exit 49 and `halt`, Antigravity's `terminate`).

MCP names that cannot say where the server ends ask instead of allowing: Crush and Kiro write `mcp_<server>_<tool>` with single underscores, so the gate splits them with the server names the agent is configured with and asks when two names fit, none does, or the configuration cannot be read whole (a dynamic `crushrc`, a Markdown Kiro profile). Cursor's `preToolUse` names an MCP tool with no server, so MCP calls are decided in `beforeMCPExecution`.

A secret-like value in an MCP call's input is redacted where the agent takes a rewritten input (Crush, Vibe) and denied where it does not. In a built-in tool it asks, since rewriting a file write or a command changes what it does.

## Not verified

Cursor, Antigravity and Kiro need an account or a seat, so their dialects are written from the vendors' docs and tested against fixtures only; their rows in `derm status` say "unverified". goose, Crush and Mistral Vibe run in the cloud against a fake model server (`tests/cli-contract/checks/N/`).
