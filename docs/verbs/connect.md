# derm connect

Adds an MCP server, or a gateway, to one agent's own config file. It prints the file and the exact change first and writes nothing unless you pass `--write` and answer yes in the terminal.

```
derm connect --list
derm connect <harness> --from <entry.json> [--name N] [--replace] [--accept-host] [--write [--expect-sha256 H]]
derm connect <harness> --gateway docker --profile <id> [--url U [--bearer-env VAR]] [--name N] [--check-profile] [--write ...]
derm connect <harness> --gateway toolhive --workload <name> [--url U] [--name N]
derm connect <harness> --remove <name> [--write ...]
derm connect <harness> --allowlist (--from <entry.json> | --gateway ...)
derm connect <harness> --path
```

`--list` shows each agent it knows, the user config file on this system, and whether derm writes it or only prints the entry for you to paste (Hermes, OpenClaw and goose: print).

## What it will and will not write

- A dry run is the default. It shows the file's path and a diff; every line it prints from your file goes through the redactor first, so a key already in your config is not echoed.
- `--write` writes user-level files only, after a terminal yes. It never writes a project-level file, a managed file (`managed-mcp.json`, `managed-settings.json`, `requirements.toml`: `--allowlist` prints a fragment for an admin instead), or an `env` block with a literal value.
- It reads the file again just before writing and refuses if anything changed since the dry run (`--expect-sha256` pins what you reviewed).
- It refuses a value the agent would expand from your environment or disk (`$VAR`, `${VAR}`, `{env:…}`, `{file:…}`) in a url, an argument or a header.
- The old bytes go to `~/.derm/backups/` (0600); each write is logged to the daemon when it runs, else to `~/.derm/connect.log`.

An entry is a server in the official MCP registry's `server.json` format, such as one from the library (`library/catalog/<id>/server.json`). A remote that does not answer is reported and the entry is still printed.

## Agents

`claude-code`, `codex`, `pi`, `opencode`, `gemini`, `cursor`, `qwen-code`, `copilot-cli`, `amp`, `crush`, `zed` (write); `hermes`, `openclaw`, `goose` (print). Each row's file, entry shape and name rules are in `crates/derm-cli/src/connect/presets/`.
