# derm connect

Adds an MCP server, or a gateway, to one agent's own config file. It prints the file and the exact change first and writes nothing unless you pass `--write` and answer yes in the terminal.

```
derm connect --list
derm connect <harness> --from <entry.json> [--name N] [--replace] [--accept-host] [--write [--expect-sha256 H]]
derm connect <harness> --gateway docker --profile <id> [--url U [--bearer-env VAR]] [--name N] [--check-profile] [--write ...]
derm connect <harness> --gateway toolhive --workload <name> [--url U] [--name N]
derm connect <harness> --remove <name> [--write ...]
derm connect <harness> --allowlist [--from <entry.json> | --gateway ...]
derm connect <harness> --path
derm connect <harness> --check-names
derm connect <agent> --gate --hook <package folder> [--node <path>] [--write]
derm connect <agent> --ungate [--write]
derm connect <agent> --rules [--clear] [--write]
```

`--list` shows each agent it knows, the user config file on this system, and whether derm writes it or only prints the entry for you to paste (Hermes, OpenClaw, goose and Continue: print).

## What it will and will not write

- A dry run is the default. It shows the file's path and a diff; every line it prints from your file goes through the redactor first, so a key already in your config is not echoed.
- `--write` writes user-level files only, after a terminal yes. It never writes a project-level file, a managed file (`managed-mcp.json`, `managed-settings.json`, `requirements.toml`: `--allowlist` prints a fragment for an admin instead), or an `env` block with a literal value.
- It reads the file again just before writing and refuses if anything changed since the dry run (`--expect-sha256` pins what you reviewed).
- It refuses a value the agent would expand from your environment or disk (`$VAR`, `${VAR}`, `{env:…}`, `{file:…}`) in a url, an argument or a header.
- A header that reads a variable reads one named for its server: `DERM_<SERVER>__<VAR>`, so Context7's key is `DERM_CONTEXT7__CONTEXT7_API_KEY`. An entry from someone else can then name only variables under its own server's prefix, never `GITHUB_TOKEN` or `AWS_SECRET_ACCESS_KEY` (security finding S12). Export the namespaced name before you start the agent. The library's exports (`library/export`) write the same names.
- The old bytes go to `~/.derm/backups/` (0600); each write is logged to the daemon when it runs, else to `~/.derm/connect.log`.

An entry is a server in the official MCP registry's `server.json` format, such as one from the library (`library/catalog/<id>/server.json`). A remote that does not answer is reported and the entry is still printed.

## Names one underscore apart

OpenCode, Kilo and oh-my-pi name an MCP tool `<server>_<tool>`, so a server called `exa_evil` gives the same tool names as `exa` with tools called `evil_...`. `derm connect` refuses to add a server whose name is one `_` away from a server already configured or listed in your policy, for those agents, and `--check-names` lists any such pair it finds in the agent's files (exit 1 when there is one). The gate itself does not yet compare against your configured names; a project file can still add one (open item W2-R1).

## Registering a gate: `--gate` and `--ungate`

`--gate --hook <package folder>` writes derm's gate into the agent's own hook file, from `crates/derm-cli/src/connect/gates.json`: the entry the agent's adapter package documents, with the package's absolute path filled in. The usual rules hold: a dry run first, user-level files only, a terminal yes, a re-read before the write, a backup. derm finds its own entry by a marker, so a second `--gate` replaces it and never adds a second gate, and it keeps every other entry (Orca's included). Agents that install plugins through their own command (Claude Code, Codex, Pi, oh-my-pi, Gemini CLI, Hermes, OpenClaw) and Kimi Code get the commands or the entry printed instead. `--node <path>` pins the Node the hook runs with; the default is `node` on the agent's PATH.

For OpenCode and Kilo, `--gate` writes the last of the files the agent deep-merges that exists (OpenCode: `config.json`, `opencode.json`, `opencode.jsonc`), and refuses when an earlier one holds a `plugin` list the new one would replace. It also sets the four `permission` keys derm needs to `ask`, only where that narrows: an exact `allow` becomes `ask`; an absent key is added only beside allows and asks; a deny or a pattern is left and named.

`--ungate` takes derm's entry out and leaves the rest. It never deletes a file, and it leaves OpenCode's and Kilo's `permission` block as it is.

## A second rule layer: `--rules`

Some agents let a call through when their hook dies or times out. For four of them derm can also write your policy's denies into the agent's own rules, which hold without the hook: OpenClaude and Qwen Code (`permissions.deny` in their settings), Gemini CLI (`~/.gemini/policies/derm.toml`, an owned file) and Codex (`disabled_tools` and `enabled = false` for the servers already in `config.toml`). Only denies are written, never an allow. `--clear` takes derm's own entries out again, and Codex's undo gives back your file byte for byte.

Two limits. An agent's own list matches a tool's name as the server spells it, while derm's rules are lower-case snake: a deny on `github/create_issue` does not stop a tool the server calls `createIssue` in the agent's list (the gate still matches it). And Gemini's denies do not apply when Gemini runs with `--policy <path>`, which replaces the user policy folder. Droid and Auggie have no rule writer yet; Crush, Kimi Code, Continue and Rovo Dev have no deny list derm can write, and `--rules` says so.

## Agents

`--list` names them: `claude-code`, `codex`, `pi`, `opencode`, `gemini`, `cursor`, `qwen-code`, `copilot-cli`, `amp`, `crush`, `zed`, `kilo`, `codebuff`, `oh-my-pi` (write); `hermes`, `openclaw`, `goose`, `continue` (print). Each row's file, entry shape and name rules are in `crates/derm-cli/src/connect/presets/`. `--allowlist` on its own prints the managed fragment the Claude Code and Codex plugins ship (`managed-settings.fragment.json`, `requirements.fragment.toml`) for an admin; for any other agent it needs `--from` or `--gateway`. OpenCode's `permission` block is in `packages/derm-opencode-plugin/opencode.fragment.json`, or set by `--gate`.
