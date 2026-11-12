# The agent adapters

`derm setup` registers each installed agent's gate for you, through `derm connect`, one question each, after writing a policy from a preset ([derm setup](setup.md)). The table below is the same by hand.

Each adapter is the gate inside one agent: it reads `~/.derm/policy.json` before every tool call and answers allow, ask or deny in that agent's own terms. An `ask` goes to the agent's own prompt where the agent has one, else to the daemon's approver (`derm watch --approve`), else it becomes a deny. The adapters live in `packages/` of this repository; none is on npm yet (`@aetiusgular/derm-*` when they are).

Write the policy before you register an adapter. With no `~/.derm/policy.json` every call not on the reject list asks: Claude Code, Pi, oh-my-pi, Gemini CLI, Hermes Agent, OpenClaw, OpenClaude, Qwen Code, GitHub Copilot CLI, Grok Build, Antigravity CLI, Amp and Cline CLI then prompt before every tool call, and Codex, OpenCode, Kilo Code, Droid, Command Code, Kimi Code, Auggie, Cursor, goose, Mistral Vibe, Crush and Kiro CLI deny every tool call unless `derm watch --approve` is running and you answer yes. (Cursor prompts for an MCP call, which it decides in `beforeMCPExecution`; its other tools go to the approver.) The format is in [the policy contract](../../contracts/policy.md).

Claude Code and Codex take the published repository as a plugin marketplace by name. The other agents install from a folder: the source of a release, or a clone.

Install derm itself first. Since wave 5b every gate runs `derm hook <agent>` (or, in Pi, oh-my-pi, OpenCode, Kilo Code, OpenClaw and Cline CLI, `derm gate serve`) by derm's absolute path, never from PATH (rules case 227). `derm connect <agent> --gate --write` writes that path from the derm you run it with, and needs no `--hook` for the agents below that use it. The Claude Code, Codex and Gemini plugins and the in-process plugins find derm in `~/.local/bin`, then Homebrew (`/opt/homebrew/bin` or `/usr/local/bin` on macOS, `/home/linuxbrew/.linuxbrew/bin` or `/usr/local/bin` on Linux), then `/usr/bin`, and run it only when only you or root can write it and its folder. On macOS Homebrew's installer leaves its folders writable by the `admin` group when you are an admin; derm trusts that group on those folders, and only when you are in it. Any admin account on the Mac can then replace derm there without a password, as it can every Homebrew tool on your PATH; on a Mac with a second admin account, install derm in `~/.local/bin` instead. Any other group or access list that lets someone else write refuses it, and the gate then blocks every call and says why. Homebrew on Linux makes its folders writable by your own group, which derm does not trust yet. The first derm that is there decides: when it is refused, the gate blocks and names it, and never goes on to the next folder's derm (fix that one or remove it). For a Homebrew derm, `derm connect --gate` writes Homebrew's stable path (`/opt/homebrew/opt/derm/bin/derm`), which `brew upgrade` keeps pointing at the current version; a line that names a version folder an upgrade removed runs nothing, and `derm doctor <agent>` names it.

```sh
# The source of a release (GitHub's "Source code (tar.gz)" of the tag)
v=<version>
curl -L -o derm-$v-src.tar.gz https://github.com/aetiusgular/derm/archive/refs/tags/v$v.tar.gz
tar -xzf derm-$v-src.tar.gz && cd derm-$v

# Or a clone
git clone https://github.com/aetiusgular/derm && cd derm
```

GitHub makes the source archive from the tag on request: it is not in `SHA256SUMS` and has no attestation. Where that matters, use a clone and `git checkout v<version>`.

| Agent | Install | Fails open? |
|---|---|---|
| Claude Code | `claude plugin marketplace add aetiusgular/derm`, then `claude plugin install derm@derm` (from a folder: `claude plugin marketplace add "$PWD"`) | No: `onFailure: "block"` |
| Codex | `codex plugin marketplace add aetiusgular/derm --ref v<version>`, then `codex plugin add derm@derm`, then trust both hooks in `/hooks` (from a folder: `codex plugin marketplace add "$PWD"`) | Yes: Codex lets a call through when its hook process dies |
| Pi | `pi install "$PWD/packages/derm-pi"` (Pi cannot install a subfolder of a git source) | No: Pi blocks on a handler error |
| oh-my-pi | `omp install "$PWD/packages/derm-pi"` | No |
| OpenCode | add `"file://$PWD/packages/derm-opencode-plugin"` to `plugin` in `~/.config/opencode/opencode.json` (see `opencode.fragment.json`) | No |
| Kilo Code | add `"file://$PWD/packages/derm-kilo-plugin"` to `plugin` in `~/.config/kilo/kilo.json` | No |
| Gemini CLI | `gemini extensions install "$PWD/packages/derm-gemini-extension" --consent`, then save the user policy it prints (`node bin/derm-gemini-policy.mjs`) | Yes: Gemini lets a call through on every hook failure; the policy file is the second layer |
| Hermes Agent | `cp -r packages/derm-hermes-plugin ~/.hermes/plugins/derm && hermes plugins enable derm`, then `derm connect hermes --gate --write` (writes `derm-path` beside `derm_gate.py`; the plugin runs derm by that path) | No: it blocks every call while it has no derm it can trust |
| OpenClaw | `openclaw plugins install --link "$PWD/packages/derm-openclaw-plugin" --force`, then `openclaw plugins enable derm` | No |
| OpenClaude | `derm connect openclaude --gate --write` (`~/.openclaude/settings.json`) | Yes: a killed or timed-out hook lets the call run; no switch |
| Qwen Code | `derm connect qwen-code --gate --write` (`~/.qwen/settings.json`, or under `QWEN_HOME`) | Yes, no switch |
| Droid | `derm connect droid --gate --write` (`~/.factory/settings.json`; a `~/.factory/hooks.json` turns it off) | Yes, no switch |
| Command Code | `derm connect command-code --gate --write` (needs an account; unverified) | No: `failClosed: true` |
| Kimi Code | `derm connect kimi --gate` prints the `[[hooks]]` entry for `~/.kimi-code/config.toml`; add it by hand | Yes, no switch; one unknown key drops every hook |
| Auggie | `derm connect auggie --gate --write` (needs an account; unverified) | Yes, no switch |
| GitHub Copilot CLI | `derm connect copilot-cli --gate --write` (`~/.copilot/hooks/derm.json`) | On a timeout only: a crashed hook denies |
| Grok Build | `derm connect grok --gate --write` (`~/.grok/hooks/derm.json`, compat imports off) | No from 1.0.71 (`failClosed`); yes on 1.0.70 |
| Cursor | `derm connect cursor --gate --write` (`~/.cursor/hooks.json`, beside Orca's entries; unverified) | No: `failClosed: true` |
| Antigravity CLI | `derm connect antigravity --gate --write` (a named hook in `~/.gemini/config/hooks.json`; unverified) | Not known |
| goose | `derm connect goose --gate --write` (a plugin folder under `~/.agents/plugins/`) | No: `on_failure: "block"` |
| Mistral Vibe | `derm connect mistral-vibe --gate --write` (`~/.vibe/hooks.toml`) | No: `strict = true` |
| Crush | `derm connect crush --gate --write` (`~/.config/crush/crush.json`) | Yes, no switch; sub-agents fire no hook |
| Kiro CLI | `derm connect kiro --gate --write` (`~/.kiro/hooks/derm.json`; unverified) | No: any exit but 0 blocks |
| Amp | copy `packages/derm-amp-plugin/src` without its tests to `~/.config/amp/plugins/derm/` (Amp refuses a plugin that resolves outside its folder; needs an account; unverified) | Not known |
| Cline CLI | copy `packages/derm-cline/package.json` and `src` without tests to `~/.cline/plugins/derm/` | Yes: a hook that throws or takes over 3 s is ignored, and five in a row turn the plugin off |
| Any other CLI agent | `derm run --boundary <sbx\|srt\|none> -- <command>`: no gate inside it, the boundary and the audit outside | n/a |

In print mode (`-p`) Cursor CLI still asks its own approval for an MCP call derm allows and, with no one to answer, rejects it; `--force` lets it run, and derm's denies still hold there (Mac test w5b). derm's allow means "not blocked" in Cursor (rules case 72).

Cursor's CLI also runs Claude Code's hooks, derm's plugin hook included, wherever the plugin is enabled (Cursor's "third-party hooks", on by default: [Third-party hooks](https://cursor.com/docs/reference/third-party-hooks)). derm's Claude Code hook knows Cursor's input: when derm's own Cursor gate is registered in `~/.cursor/hooks.json`, failing closed, it gives no decision and the Cursor gate decides, once; when it is not, it blocks every Cursor call and says to run `derm connect cursor --gate`, or to turn off Third-Party Imports in Cursor's settings. `derm run cursor` starts `cursor-agent` with a chat token, so an ask reaches `derm watch --approve`.

Codex pins the marketplace to the release's tag with `--ref v<version>` (OpenAI, [Build plugins](https://developers.openai.com/codex/plugins/build.md); `derm status` prints it with your version). Claude Code's marketplace added by name follows the repository's default branch, which can be ahead of the release you installed; to pin it, add a folder checked out at the tag instead. The folder installs (`--link`, `file://`, `pi install <folder>`) read the folder in place, so keep it where it is.

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
