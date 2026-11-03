# derm-kilo-plugin

The derm policy gate for the Kilo Code CLI (T2.4, wave 2 lane I). Lane F's OpenCode plugin with Kilo's id, paths and control files: Kilo is a fork of OpenCode. Written against Kilo's source at v7.8.18 and run against Kilo 7.8.18 with a fake chat-completions server (`tests/cli-contract/checks/I/kiloGate.mjs`). Not on your machines yet.

- **tool.execute.before** checks every built-in and MCP call against `~/.derm/policy.json` (or `$DERM_POLICY`). A deny throws, which stops the call; Kilo gives the model `derm: <reason>` as the tool's error.
- Kilo never asks a plugin's `permission.ask`, so a policy `ask` goes to the derm daemon's approver (`derm watch --approve`). Only an approver's yes lets the call through; no approver, or no daemon, is a deny.
- An allowed call whose input names Kilo's config or plugin folders (`~/.config/kilo/`, `.kilo/`, `.kilocode/`, `kilo.json`) or `KILO_CONFIG*` / `KILO_PURE` asks: a `.ts` file there is a plugin Kilo loads, with no trust prompt for a project's.
- Secret-like values in a tool's input are redacted in the very object the tool runs with; in a shell command or a write they make the call an ask. **tool.execute.after** redacts the output in place and records the call in the derm daemon (a hash, no content).
- MCP tools reach the plugin as `<server>_<tool>`, with `-` kept. List your server names in the policy's `servers` so the matcher can split them.

The plugin reads nothing when Kilo loads it, makes no network call and has no dependencies. It imports neither `@kilocode/plugin` nor `@opencode-ai/plugin`, and its `package.json` has no `engines.opencode`, which Kilo checks against its own 7.x version and refuses on a mismatch.

## Install

Either add the folder to `~/.config/kilo/kilo.json` (`kilo.fragment.json` has the block, with Kilo's own `permission` prompts kept as a second layer):

```
"plugin": ["file:///abs/path/derm/packages/derm-kilo-plugin"]
```

or put one line in `~/.config/kilo/plugin/derm.ts`, which Kilo loads at start:

```
export { default } from "file:///abs/path/derm/packages/derm-kilo-plugin/src/plugin.ts";
```

Both routes ran. derm never writes a project-level `kilo.json` or `.kilo/plugin/`, which an agent can also write. `KILO_PURE=1` or `kilo run --pure` loads no external plugin, derm's included.

## Known limits

- **A plugin that loads after derm can change a call after derm allowed it.** Kilo runs every plugin's `tool.execute.before` in load order on one `args` object: built-ins, the global config's plugin array, `~/.config/kilo/plugin/`, the project's config, the project's `.kilo/plugin/` (Kilo's docs, "Load order"). The check `kilo-derm-later-plugin` shows it. A project plugin is code running inside Kilo; no hook can stand against it. `derm status` is to list the project-level plugins it finds (rules case 78, wave 2 lane J).
- Plugin hooks have no timeout in Kilo (not found in its source); a hook that hangs holds the turn.

## Environment

As the OpenCode plugin: `DERM_POLICY`, `DERM_DAEMON_SOCKET`, `DERM_CHAT_TOKEN`, `DERM_CHAT_TOKEN_FILE`, `DERM_CHAT_ID` (else Kilo's `sessionID`).
