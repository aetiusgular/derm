# Quick start: the light tier

`derm init` sets up derm's gate for the agents you have, in one command. It needs no root, no daemon and no Docker sign-in. With no daemon running, each gate decision goes to a log file per chat.

This is the light tier. It gates tool calls and keeps a record of them. It does not sandbox the agent and does not see what the OS saw. For that, run [derm setup](setup.md), which adds the daemon, a boundary around the agent and the OS's own records.

## 1. Install derm

Install the `derm` binary first: [Linux](linux.md), [macOS](macos.md) or [Windows](windows.md). The gates run derm by its absolute path, never from PATH ([the agent adapters](agents.md)).

## 2. See the plan

```sh
derm init --dry-run
```

It lists the agents it found on PATH and what it would do for each. It asks nothing and writes nothing. Run it anywhere, a chat included.

## 3. Run it

```sh
derm init
```

From a terminal of your own, not inside a `derm run` chat. It shows the same plan and asks once. On a yes:

- **Policy.** With no `~/.derm/policy.json`, it writes the default preset (`workspace-write`, see `derm setup presets`), 0600 in a 0700 folder. A policy you have is kept.
- **Gates.** For each agent whose gate is `derm hook`, it runs `derm connect <agent> --gate --write`, which shows the change and asks again before it writes.
- **Plugins.** Claude Code and Codex install derm's plugin through their own commands. `derm init` prints them; you run them. A plugin that installs from a folder (OpenCode, Kilo Code and others) needs `derm init --packages <folder of derm's source>`, or the line it prints.

It never writes a vendor's sandbox settings, never changes `tier.default`, and never writes over a file.

## What the light tier records

With no daemon, every gate decision is one line in the file below, and so is each call's result where derm registers the agent's post hook (Claude Code, Codex, Gemini CLI, Hermes Agent):

- `~/.derm/local/<chat>.jsonl` on Linux and macOS
- `%USERPROFILE%\.derm\local\<chat>.jsonl` on Windows

`<chat>` is the agent's session id, cleaned to letters, digits and `_ . : -` (`:` becomes `_` on Windows). Each line is chain v2: it holds the hash of the line before it, so lines chain from the first. A record holds hashes and sizes, never a tool's output or a file's content.

A line that cannot be written (the lock held for over a second, a torn last line, a folder that is a link) is not written anywhere else, and the reason is kept for the gate: a call whose decision could not be recorded is to be denied. That last step lands with the wave 6 integration; until then such a call runs as its decision said.

## What the log proves

The agent runs as you and can write this file. So:

- An edited, dropped, reordered or relabelled line shows: `derm audit verify <file>` names the first broken line.
- A cut at the end, or a whole new file, shows only against an anchor kept where the agent cannot write: `derm audit anchor`.

A file whose last line is torn or not chain v2 takes no more lines. Move it away and the chat starts a new one.

## What an ask becomes

With no daemon there is no approver. An agent that has its own prompt (Claude Code, Gemini CLI, Pi and others) shows a derm ask there. For the others (Codex, OpenCode, Cursor and others) an ask is a deny. `derm init` says which per agent.

## Not covered

Calls decided outside derm's Rust gate reach neither the log nor taint:

- Amp's plugin, which decides in TypeScript.
- A gate registered from an older derm's template files, which runs `node`. `derm init` and `derm doctor <agent>` name it; register it again with `derm connect <agent> --gate --write`.
- The sbx kit's Claude Code hook (only under `derm run --boundary sbx`, which is not the light tier).

## Going further

- `derm run <agent> --tier standard` gives Claude Code and Codex their own sandbox from your policy, once your derm has their rows. `derm run` delivers it; a settings file of yours would not hold, since a project file beats it.
- `derm setup` for the daemon, the boundary, the model tap and the OS records.
