# The library's commands

The library (`library/`) is a catalog of MCP servers, skills and bundles in the official MCP registry's format, with derm's own fields under `_meta["io.modelcontextprotocol.registry/publisher-provided"]["io.github.aetiusgular.derm"]`: its tier, status, how it runs, how each agent should expose it, and its trust records. Its commands run with Node 22.18 or later from a clone, not as `derm` subcommands.

| Command | What it does | Network |
|---|---|---|
| `node library/cli.ts validate [catalog]` | Every rule on every entry; exit 1 on an error | None, unless `DERM_LIBRARY_ONLINE=1` (posts each server to the registry's `/v0.1/validate`) or `DERM_LIBRARY_SKILLS_REF=1` (runs `skills-ref` on each skill) |
| `node library/cli.ts export <set\|all> <out>` | A set as a Claude Code and Codex marketplace, a Pi package, a Docker gateway profile, a ToolHive registry and the registry's list (`registry.json`, and `registry-include-deleted.json` with deleted entries) | None |
| `node library/cli.ts takedown <id> --reason <line> --report <#n\|url\|private>` | Sets the entry's status to `deleted`, changes nothing else, appends a line to `library/TAKEDOWNS.md`. Exports leave it out | None |
| `node library/mirror/cli.ts pull --out <dir>` | Mirrors the official MCP registry into a folder, and probes each remote | The registry's list API; with probes on (`--no-probe` turns them off), each mirrored remote's own host. Runs in CI on a schedule you turn on, never from the daemon |
| `node library/publish/cli.ts publish <entry> --library <clone> --proof github\|dns\|http` | Validates an entry, proves its namespace, records its hash and prints the pull request's steps; `--open-pr` runs them | GitHub (through `gh`), and the DNS or `.well-known` lookup the proof needs |
| `node library/trust/cli.ts names\|record\|drift\|pin\|due\|card` | Name checks against a brand list, recorded manifests per version, description drift, and the policy rules that pin descriptions | None |
| `node library/trust/cli.ts scan` and `osv` | Runs the pinned scanners; looks up packages in OSV | Only with `DERM_TRUST_SCAN=1` (one scanner reaches `api.osv.dev`) or `DERM_TRUST_ONLINE=1` (`api.osv.dev`) |
| `node library/site/build.ts <out>` | A static page over the catalog: search, a card per entry with its trust records, a `derm connect` line per agent | None |

A scan result is shown with its date and never as "safe": scanners miss things and over-flag. Report an entry with the "Report an entry" issue form; takedowns are logged in [`library/TAKEDOWNS.md`](../../library/TAKEDOWNS.md).
