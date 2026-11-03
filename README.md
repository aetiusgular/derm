# derm

derm is a skin for AI agents: a gate, a boundary and an audit around any coding agent.

- **The gate** runs before each tool call an agent makes and answers allow, ask or deny from one policy (`~/.derm/policy.json`), for every agent derm attaches to.
- **The boundary**: `derm run` starts an agent inside Docker's sbx or Anthropic's srt, or with none, and records what it ran.
- **The audit**: `derm-daemon` keeps one hash-chained activity log of tool calls, approvals, the agents' own telemetry and, on Linux, the OS feed from auditd. `derm watch` reads it.
- **The library**: a curated catalog of MCP servers, skills and bundles in the official MCP registry's format, with trust records and takedowns.

No telemetry, no account. What derm records stays on your machine ([privacy](docs/privacy.md)).

Status: released on GitHub ([releases](https://github.com/aetiusgular/derm/releases)): Linux x86_64 as a static tarball and a `.deb`, macOS as a signed, notarized zip, and on macOS through Homebrew (`brew install aetiusgular/tap/derm`). The gates install from this repository: Claude Code and Codex take it as a plugin marketplace by name, the others from a folder of the release's source ([the agents](docs/install/agents.md)); none is on npm yet. Tested in a Linux cloud workspace, on a Linux box (Pi in the TUI and in Orca, OpenCode, the systemd user unit) and on a Mac (the Claude Code and Codex plugins, the released zip and the Homebrew install). Built in parallel lanes; each crate and package says which lane owns it (`scripts/lane-ownership.json`).

## Docs

- Install: [Linux](docs/install/linux.md), [macOS](docs/install/macos.md), [the agents](docs/install/agents.md)
- Commands: [`derm connect`](docs/verbs/connect.md), [`derm run`](docs/verbs/run.md), [`derm watch` and `derm status`](docs/verbs/watch.md), [`derm cu`](docs/verbs/cu.md), [`derm-daemon`](docs/verbs/daemon.md), [the library](docs/verbs/library.md)
- [Privacy](docs/privacy.md): what reaches the network, what was measured and what was read
- [Benchmarks](docs/benchmarks.md): deferred tools on a local 27B model
- [Release notes](docs/release-notes.md); [`docs/llms.txt`](docs/llms.txt) for agents

## Open security items

Read these before relying on derm. Each is tracked in the status docs under `plans/parallel/`; the owner is the lane or session that fixes it.

| Item | Risk | What | Until fixed |
|---|---|---|---|
| S2 | High | An approver started outside an agent's process tree (a double fork, `setsid`, a terminal multiplexer) can answer that agent's `ask`s | Run `derm watch --approve` only from your own terminal. Computer use is not shipped because of it |
| W2-R1 | Medium | OpenCode's, Kilo's and oh-my-pi's single-underscore tool names cannot tell `exa_evil` from `exa` (owner: wave 4 lane Q) | Give servers names without `_` or `-` in those agents |
| Fails open | Medium | Codex lets a call through when its hook process dies; Gemini CLI on every hook failure | `derm status` marks them; Gemini's user policy file is the second layer |
| S6 | Medium | Under `derm run --boundary srt`, the agent's whole state folder is writable, and it holds the gate's own switches, so an agent inside srt can switch derm off for its next session (owner: wave 4 lane R) | Use `sbx` where that matters |
| Chat token | Medium, by design | A chat's token sits in the agent's environment, so the agent's shell can read it and post records into its own chat. It cannot approve, mint tokens, read other chats or switch the OS feed off | Treat a chat's own records as what that chat's processes said; OS-feed, run and approval records cannot be posted with it |
| Redactors | Medium | Secret redaction in run records, the OS feed and `derm connect`'s output is best-effort: multi-line TOML and YAML values and a key and value on two lines can still print | Keep `DERM_LOG_CONTENT` off; read a dry run before `--write` |
| Later hooks | Low to medium | In oh-my-pi, Kilo, Gemini CLI and Hermes a hook or extension that runs after derm's can still change a call's input after derm decided | Do not install other tool-call hooks beside derm's there |
| io_uring | Low to medium | File opens and connects done through io_uring are not seen by the auditd feed | None in this release |
| S16 | Low | The managed Claude Code fragment force-enables `derm@derm` without pinning where the `derm` marketplace comes from (owner: the Claude Code adapter) | Pin the source in managed settings ([the agents page](docs/install/agents.md#claude-code-under-managed-settings)) |
| S12 | Low | A catalog entry's `{anything}` placeholder becomes `${ANYTHING}`, so a stranger's entry could send any variable in your environment to its host (owner: wave 4 lane Q) | `derm connect` shows it in the diff and writes only on `--write` and a yes in your terminal: read the header lines |
| S15 | Low | Codex's hooks put `${PLUGIN_ROOT}` into a shell string, and Codex lets the call through if that shell cannot find `node` (exit 127) (owner: `derm doctor`, wave 4 lane R) | Check that `node` resolves from the shell Codex runs hooks in |
| BW2's residue | Low | A record the agent posts under an id of its own still counts in the chat's totals (a second decision for the same call is flagged) | Read `derm watch report`'s `GATE CONFLICT` lines |
| W2-S10 | Low | `trust.yml` installs its scanners without `--require-hashes` (owner: the release session; manual runs only) | Run `trust.yml` only by hand. W2-S8, W2-S9's residue and W2-S11's info items are in `plans/parallel/tk_integration_w2.md` |
| Backups | Low | `derm connect`'s backups in `~/.derm/backups` (0600 in 0700) have no retention | Clear them yourself |

## Build

`cargo test --workspace`, `npm ci --ignore-scripts`, `npx tsc --noEmit`, `npx vitest run`, `python3 -m unittest discover -s packages/derm-hermes-plugin/tests`. Node 22.19 or later (the hooks and `library/cli.ts` run through Node's type stripping); CI runs Node 24. The release artifacts are built by `.github/workflows/release.yml` (`packaging/`).

| Path | What |
|---|---|
| `crates/derm-core` | Shared types: policy, event, token; the Rust matcher |
| `crates/derm-daemon` | The OTLP receiver, the activity log, the socket server, the approval channel; computer use served on macOS (`derm-daemon cu-mcp`); the Mac collector's registration (`derm-daemon collector-plan`) |
| `crates/derm-cli` | `derm connect`, `derm run`, `derm watch`, `derm status`, `derm cu`; `derm acp` and `derm doctor` are stubs for wave 4. The preset table is one file per agent in `src/connect/presets/` |
| `crates/derm-audit-linux` | The Linux OS feed from auditd (`derm-audit-feed`) |
| `packages/derm-pi` | The Pi package (also oh-my-pi's): gate, emitter, memory extension |
| `packages/derm-claude-plugin`, `derm-codex-plugin`, `derm-opencode-plugin` | Claude Code, Codex and OpenCode adapters; the canonical hook core is `derm-claude-plugin/src/core/` |
| `packages/derm-gemini-extension`, `derm-hermes-plugin`, `derm-openclaw-plugin`, `derm-kilo-plugin` | Gemini CLI, Hermes Agent, OpenClaw and Kilo Code adapters (wave 2) |
| `packages/derm-hooks-claude-compat`, `derm-hooks-native`, `derm-amp-plugin`, `derm-cline` | Scaffolds for wave 4 (the hook core is synced in; nothing runs yet) |
| `library/` | Schema, validator, exports, catalog, takedowns (`library/takedown/`, logged in `library/TAKEDOWNS.md`); the registry mirror (`library/mirror/`), publish (`library/publish/`), trust records (`library/trust/`), the static browser (`library/site/`) |
| `contracts/` | What the parts agree on, with fixtures; `hook-dialects.md` for wave 4's agents |
| `tests/cli-contract/` | Checks against the real harness CLIs with fake model servers |
| `tests/integration/` | Cross-lane checks with the real daemon, `derm` and Pi |
| `tests/measure/` | The benchmark's scripts and results |
| `macos/` | The activity collector and the computer-use helper, own workspaces; not in the release |
| `docs/`, `packaging/` | The docs pages; the `.deb`, the release checks and the NOTICE generator |

Install the gates: one line per agent in [docs/install/agents.md](docs/install/agents.md). The library's commands run with Node, not as `derm` subcommands yet: `node library/cli.ts validate|export|takedown`, `node library/publish/cli.ts publish <entry-dir> --library <clone>` (prints the pull request's steps unless `--open-pr`), `node library/mirror/cli.ts pull --out <dir>`, `node library/trust/cli.ts record|scan|osv|pin`, `node library/site/build.ts <out-dir>` ([the library's page](docs/verbs/library.md)). Report a catalog entry with the "Report an entry" issue form.

## Harness coverage

How derm attaches to each agent in Orca's list. Tier G: derm registers a gate that runs before each tool call. Tier A: derm writes the agent's own allow, ask and deny rules. Tier O: derm wraps the agent from outside only (`derm run`, `derm watch`). Every agent also gets the outside shape. "Fails open" means the agent lets a call through when the gate crashes or times out and has no switch to stop that. Status says what ran, where and at which version; "planned" rows are research only (`research-notes/AQ_harness_coverage_matrix.md`).

| Agent | Tier | derm attaches through | Status |
|---|---|---|---|
| Pi | G | `packages/derm-pi` (`tool_call`) | Built, wave 1. Run in a real Pi 1.4.0 in the cloud (14 live checks) and on the box in the TUI and in Orca (box test w1); the memory extension (wave 2) in a real Pi 1.4.0 RPC session, 8 and 2 live checks |
| Claude Code | G | `packages/derm-claude-plugin` (PreToolUse, `onFailure: "block"`) | Built, wave 1. Contract checks pass against Claude Code 2.1.311; run in MonoCode and a terminal on the Mac (Mac test w1). `bypassPermissions` not run in the cloud (root) |
| Codex | G, fails open | `packages/derm-codex-plugin` (PreToolUse) | Built, wave 1. Contract checks pass against Codex 0.163.0 and 0.164.0; run on 0.161.0 on the Mac (Mac test w1) |
| OpenCode | G | `packages/derm-opencode-plugin` (`tool.execute.before`) | Built, wave 1. Run on the box against OpenCode 1.19.4 (box test w1) |
| Gemini CLI | G, fails open | BeforeTool hook | Built, wave 2 (`packages/derm-gemini-extension`). Contract checks pass against Gemini CLI 0.65.0 and 0.66.0 in the cloud; fails open on every hook failure (run). Not run on the box or the Mac |
| Hermes Agent | G | Python plugin `pre_tool_call` | Built, wave 2 (`packages/derm-hermes-plugin`). Unit tests only; Hermes itself not run (box test w2 4.3) |
| oh-my-pi | G | `derm-pi`, installed with `omp install` | Built, wave 2. Contract checks pass against omp 18.13.3 in the cloud (lane I) |
| Kilo Code | G | the OpenCode plugin with Kilo's paths | Built, wave 2 (`packages/derm-kilo-plugin`). Contract checks pass against Kilo 7.8.18 in the cloud |
| OpenClaude | G, fails open | PreToolUse in `~/.openclaude/settings.json` | Planned, wave 4 |
| Qwen Code | G, fails open | PreToolUse in `~/.qwen/settings.json` | Planned, wave 4 |
| Droid | G, fails open | PreToolUse in `~/.factory/settings.json`, beside Orca's entry | Planned, wave 4; fixtures only without a seat. Contract and fixtures: `contracts/hook-dialects.md` |
| Command Code | G | PreToolUse with `failClosed` | Planned, wave 4 |
| Kimi Code | G, fails open | `[[hooks]]` in `~/.kimi-code/config.toml` | Planned, wave 4 |
| Auggie | G, fails open | PreToolUse or a script policy | Planned, wave 4; fixtures only without a seat |
| GitHub Copilot CLI | G, open on timeout | preToolUse in `~/.copilot/hooks/` | Planned, wave 4 |
| Grok Build | G | PreToolUse in `~/.grok/hooks/` with `failClosed` | Planned, wave 4 |
| Cursor CLI | G | `~/.cursor/hooks.json` with `failClosed` | Planned, wave 4; fixtures only without a seat |
| Antigravity CLI | G, fail mode unknown | a bundle in `~/.gemini/config/hooks.json` | Planned, wave 4 |
| goose | G | a plugin's PreToolUse with `on_failure: "block"` | Planned, wave 4 |
| Mistral Vibe | G | `pre_tool` in `~/.vibe/hooks.toml` with `strict` | Planned, wave 4 |
| Charm Crush | G, fails open | PreToolUse in `crush.json` | Planned, wave 4 |
| Kiro CLI | G | a hook file in `~/.kiro/hooks/` | Planned, wave 4; fixtures only without a seat |
| Amp | G, fail mode unknown | a Bun plugin (`tool.call`) | Planned, wave 4; fixtures only without a seat |
| Cline CLI | G | the approval-file callback | Planned, wave 4 |
| Continue | A | `~/.continue/permissions.yaml` | Planned, wave 4 |
| Rovo Dev | A | `toolPermissions` in `~/.rovodev/config.yml` | Planned, wave 4; fixtures only without a seat |
| Codebuff | O | `derm run`, the MCP file | Planned, wave 4 |
| Any other CLI agent | O | `derm run -- <command>` | Planned, wave 4 |

Outside Orca's grid: OpenClaw, tier G, `packages/derm-openclaw-plugin` (`before_tool_call`, derm runs last): built, wave 2, contract checks pass against OpenClaw 2026.10.8 in the cloud (lane I). Wave 4's agents' hook contracts and fixtures are in `contracts/hook-dialects.md`.

Orca's ids differ for three agents: Orca says `claude`, `copilot` and `aug`; derm says `claude-code`, `copilot-cli` and (wave 4) Auggie's own id. The machine-readable form of this table is the preset table, one file per agent in `crates/derm-cli/src/connect/presets/` (the `coverage` field on each row; `index.json` lists the `harnesses` and the `planned` rows).

MIT. See `NOTICE` for what was copied from where.
