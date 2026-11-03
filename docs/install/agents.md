# The agent adapters

Each adapter is the gate inside one agent: it reads `~/.derm/policy.json` before every tool call and answers allow, ask or deny in that agent's own terms. An `ask` goes to the agent's own prompt where the agent has one, else to the daemon's approver (`derm watch --approve`), else it becomes a deny. The adapters live in `packages/` and install from a clone of this repository until they are published to npm as `@aetiusgular/derm-*`.

```sh
git clone https://github.com/aetiusgular/derm && cd derm
```

| Agent | Install | Fails open? |
|---|---|---|
| Claude Code | `claude plugin marketplace add "$PWD"`, then `claude plugin install derm@derm` | No: `onFailure: "block"` |
| Codex | `codex plugin marketplace add "$PWD"`, then `codex plugin add derm@derm`, then trust both hooks in `/hooks` | Yes: Codex lets a call through when its hook process dies |
| Pi | `pi install "$PWD/packages/derm-pi"` (Pi cannot install a subfolder of a git source) | No: Pi blocks on a handler error |
| oh-my-pi | `omp install "$PWD/packages/derm-pi"` | No |
| OpenCode | add `"file://$PWD/packages/derm-opencode-plugin"` to `plugin` in `~/.config/opencode/opencode.json` (see `opencode.fragment.json`) | No |
| Kilo Code | add `"file://$PWD/packages/derm-kilo-plugin"` to `plugin` in `~/.config/kilo/kilo.json` | No |
| Gemini CLI | `gemini extensions install "$PWD/packages/derm-gemini-extension" --consent`, then save the user policy it prints (`node bin/derm-gemini-policy.mjs`) | Yes: Gemini lets a call through on every hook failure; the policy file is the second layer |
| Hermes Agent | `cp -r packages/derm-hermes-plugin ~/.hermes/plugins/derm && hermes plugins enable derm` (Node on Hermes's PATH) | No |
| OpenClaw | `openclaw plugins install --link "$PWD/packages/derm-openclaw-plugin" --force`, then `openclaw plugins enable derm` | No |
| Any other CLI agent | `derm run --boundary <sbx\|srt\|none> -- <command>`: no gate inside it, the boundary and the audit outside | n/a |

## Claude Code under managed settings

`packages/derm-claude-plugin/managed-settings.fragment.json` force-enables `derm@derm` and lets only managed hooks run. On its own it names the marketplace `derm` but not where `derm` comes from, so a marketplace someone else adds under that name could supply the plugin (open item S16). Pin the source in the same managed file: a managed `extraKnownMarketplaces` entry replaces a same-name entry from any lower scope, and the `strictKnownMarketplaces` allowlist matches a marketplace by its source, not its name ([Manage Claude Code plugins for your organization](https://code.claude.com/docs/en/plugins/org)).

```json
{
  "extraKnownMarketplaces": {
    "derm": { "source": { "source": "github", "repo": "aetiusgular/derm" } }
  },
  "strictKnownMarketplaces": [
    { "source": "github", "repo": "aetiusgular/derm" },
    { "source": "skills-dir" }
  ],
  "enabledPlugins": { "derm@derm": true }
}
```

Add the other marketplaces you allow to `strictKnownMarketplaces` (an allowlist blocks every source it does not name, the official marketplace included). For a clone on disk, use `{ "source": "directory", "path": "/abs/path/derm" }` in both places. Set `"disableSideloadFlags": true` as well, or `claude --plugin-dir` can still load another copy for a session. Not yet run on a managed machine.

`derm status` lists each agent it knows, whether its gate is registered, and whether that agent fails open. The full coverage, built and planned, is in the [README](../../README.md#harness-coverage); each agent's hook contract in [`contracts/hook-dialects.md`](../../contracts/hook-dialects.md).

## Before you rely on it

- A gate inside an agent runs with the agent's rights and in the agent's environment. It stops calls; it is not a sandbox. Use `derm run --boundary srt` or `sbx` for one.
- The chat token `derm run` gives an agent is in the agent's environment, so the agent's own shell can read it (by design: it can only post into its own chat).
- An approver started outside the agent's process tree can still answer the agent's asks (open finding S2). Run `derm watch --approve` only from your own terminal.
