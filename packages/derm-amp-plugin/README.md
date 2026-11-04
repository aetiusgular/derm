# derm-amp-plugin

The derm policy gate for Amp (T2.7, wave 4 lane P): an Amp plugin with a `tool.call` and a `tool.result` handler on derm's shared gate core. Written against `@ampcode/plugin` 0.0.0-20261104001221-gc8c68be (its type definitions, npm, 3 Nov 2026) and Amp's plugin page. **Not run against Amp**: Amp needs an account (call 8), so this package is tested against fixtures built from the type definitions, and `derm status` says "unverified at" for its row.

- **tool.call** checks every call against `~/.derm/policy.json` (or `$DERM_POLICY`). An allow rule answers `{action: "allow"}`. A deny answers `{action: "reject-and-continue", message: "derm: <reason>"}`: that call is blocked and the agent goes on. derm never answers `error`, which stops Amp's thread worker.
- **An ask** goes to the derm daemon's approver first (`derm watch --approve`). When no approver is connected, or no daemon is reachable, Amp's own dialog asks you (`ctx.ui.confirm`), showing the tool, why derm asks and the input as derm checked it, redacted. Yes runs the call; no, a dismissed dialog, no answer within the policy's ask timeout, or no dialog at all (`amp -x`, a `code_exec` run inside a subagent) blocks it.
- `Bash` and `shell_command` are checked as `bash`, with the command and its folder from Amp's `helpers.shellCommandFromToolCall` and every other input field, so the shell-text check reads the command (rules cases 30 and 82). A shell command whose text derm cannot read asks; a call whose `cmd` and `command` differ, or where Amp's reading differs from the input, is refused.
- MCP tools reach the plugin as `mcp__<server>__<tool>`. Amp gives the model its MCP tools through `tool_search` and `code_exec`: derm matches `code_exec` by its own name, so a rule on `code_exec` covers the MCP calls made inside it (case 74). Whether Amp also runs `tool.call` for each tool a `code_exec` run calls is not documented.
- Secret-like values are redacted with `{action: "modify", input}` only for an MCP tool or a web tool (`web_search`, `read_web_page`), whose input leaves the machine as it is; anywhere else (a shell command, a file write, `code_exec`'s program) they make the call an ask. Input or output with long runs of secret-like words, which make the shared core's redaction slow, is refused (input) or has those runs taken out whole (output) first (`src/budget.ts`). **tool.result** redacts secret-like strings in the output before Amp sends it to the model, and records the call in the derm daemon (a hash, no content).
- An allowed call whose input names Amp's settings or plugin folders (`~/.config/amp/`, `.amp/`, `$XDG_CONFIG_HOME/amp/plugins`, `ampcode/`) or `dangerouslyAllowAll` asks: a `.ts` file there is a plugin Amp loads.

The plugin reads nothing when Amp loads it, makes no network call, and has no dependencies. It does not import `@ampcode/plugin`, whose licence is Amp's.

## Install

Amp loads a directory plugin from `~/.config/amp/plugins/<name>/index.ts` (or `$XDG_CONFIG_HOME/amp/plugins/<name>/` when that variable is set), with Bun. A plugin must resolve inside its plugin folder, so copy the files; a link to a clone is refused:

```
mkdir -p ~/.config/amp/plugins/derm
cp -R /abs/path/derm/packages/derm-amp-plugin/src/. ~/.config/amp/plugins/derm/
rm ~/.config/amp/plugins/derm/*.test.ts
```

Then run `plugins: reload` from Amp's command palette, or restart Amp. derm never writes a project's `.amp/plugins/`, which an agent can also write. `derm connect amp --gate` (wave 4 lane Q) is to do the same copy under `derm connect`'s rules.

## Known limits

- **Not run.** Every claim about Amp here comes from its type definitions and docs page, not from a run.
- **When a handler fails.** derm's handler catches every error and answers `reject-and-continue`. What Amp does when a handler throws, never answers, or its Bun process dies is not documented: it may let the call through.
- **Another plugin's answer.** Amp runs plugins' handlers in an order it does not define. Orca installs its own Amp plugin, whose `tool.call` answers allow; how Amp merges two answers is not documented. A plugin that runs after derm's can also change the input derm checked.
- **Full access.** Orca starts Amp with `--dangerously-allow-all`, which skips Amp's own permission prompts. Plugins still run as far as the docs say; derm's answer does not change with it (an ask is never an allow without a yes).

## Environment

`DERM_POLICY`, `DERM_DAEMON_SOCKET`, `DERM_CHAT_TOKEN`, `DERM_CHAT_TOKEN_FILE`, `DERM_CHAT_ID` (else Amp's thread id), read in the plugin's own process. Whether Amp passes its environment to a plugin's process is not documented; without the chat token an ask goes straight to Amp's dialog.
