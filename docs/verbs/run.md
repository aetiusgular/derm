# derm run

Starts an agent under a boundary, as a chat the daemon knows.

```
derm run <harness> --boundary sbx|srt|none [--chat ID] [--cwd DIR] [--gateway-url URL] [--model-url URL]
         [--allow-host HOST:PORT]... [--kit REF] [--no-daemon] [--dry-run] [-- harness args...]
```

It asks the daemon for a chat token, records `run.start` (the boundary, the agent and its arguments, with every word that is not a flag reduced to its length; with the content switch on in `~/.derm/settings.json`, the words go to a content file the record names), starts the agent with `DERM_CHAT_ID`, `DERM_CHAT_TOKEN` and `DERM_CHAT_TOKEN_FILE` (a 0600 file holding the same token, for agents that strip secret-named variables from a hook's environment), `DERM_OTLP_ENDPOINT`, under `--boundary none` `DERM_DAEMON_SOCKET` (the daemon's socket, so the agent's hooks reach the daemon that gave the token), and, with `--gateway-url`, `DERM_GATEWAY_URL` in its environment, and records `run.stop` when it ends. SIGINT, SIGTERM and SIGHUP sent to `derm` reach the agent. `--dry-run` prints the program, its arguments, its environment and the boundary's settings, and starts nothing.

## Boundaries

| Boundary | What it is | Notes |
|---|---|---|
| `sbx` | Docker's sandbox: the agent in a microVM (`sbx run`) | Needs Docker's sbx and its sign-in. The agent runs with sbx's own defaults inside the VM; local stdio MCP servers still run on the host. `sbx policy log` is tailed into the feed |
| `srt` | Anthropic's sandbox runtime: the agent with no network but the hosts you allow, and your secrets hidden | Needs `bwrap` and `socat` on Linux. derm writes the settings: only the gateway's and the model server's loopback ports and `--allow-host` reach the network; `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.derm`, the daemon's folder and the other agents' sign-ins are unreadable; the policy file is re-opened read-only. The agent may reach its own sign-in host to renew its sign-in (Claude Code `platform.claude.com:443`, Codex `auth.openai.com:443`; srt admits any request on that host and port, and derm records none of them), except Claude Code on macOS: it keeps its sign-in in the login keychain, which it cannot write under srt, so there derm keeps its sign-in host shut and `~/.claude/.credentials.json` read-only, and a chat whose access token expires stops until Claude Code runs once outside srt. Codex set to keep its sign-in in a keyring (`cli_auth_credentials_store` `keyring` or `auto`, from `-c`, its config files or its requirements; a file derm cannot read counts as one) is treated the same way on every system: `auth.openai.com` stays shut and its `auth.json` read-only. A denied path reached through a link is denied by its real path too, since srt keeps a link's spelling and macOS matches the real path |
| `none` | The agent as you, no sandbox | Only its own gate and the OS feed watch it. derm says so when it starts |

`--no-daemon` runs without a chat token: nothing is recorded. An agent derm has no row for runs from outside only: `derm run --boundary none -- <command>` (the coverage wave adds the row-less form and its record).
