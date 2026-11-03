# derm

Working name. A local control plane for AI coding harnesses (a gate, a daemon with one audit log, `derm connect`, `derm run`) and a curated tool library on the official MCP registry's format.

Status: wave 1 merged to `main`; wave 2 integrated on `integration/w2`, not merged to `main`. Wave 1 ran in a Linux cloud workspace, then on the box (Pi in the TUI and in Orca, a real OpenCode, the systemd user unit) and on the Mac (the Claude Code and Codex plugins, MonoCode with Claude Code). Wave 2 ran in the cloud only; its box test and Mac test come next. Built in parallel lanes; each crate and package says which lane owns it (`scripts/lane-ownership.json`).

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
| `library/` | Schema, validator, exports, catalog; the registry mirror (`library/mirror/`), publish (`library/publish/`), trust records (`library/trust/`), the static browser (`library/site/`) |
| `contracts/` | What the parts agree on, with fixtures; `hook-dialects.md` for wave 4's agents |
| `tests/cli-contract/` | Checks against the real harness CLIs with fake model servers |
| `tests/integration/` | Cross-lane checks with the real daemon, `derm` and Pi |
| `macos/` | The activity collector and the computer-use helper, own workspaces |

Build: `cargo test --workspace`, `npm ci --ignore-scripts`, `npx tsc --noEmit`, `npx vitest run`, `python3 -m unittest discover -s packages/derm-hermes-plugin/tests`. Node 22.19 or later (the hooks and `library/cli.ts` run through Node's type stripping); CI runs Node 24.

Install from a clone (no published packages yet):

- Pi: `pi install /abs/path/derm/packages/derm-pi` (a git source cannot name a subfolder).
- Claude Code: `claude plugin marketplace add /abs/path/derm`, then `claude plugin install derm@derm`.
- Codex: `codex plugin marketplace add /abs/path/derm`, then `codex plugin add derm@derm`, then trust both hooks in `/hooks`.
- OpenCode: `"plugin": ["file:///abs/path/derm/packages/derm-opencode-plugin"]` in `~/.config/opencode/opencode.json` (`opencode.fragment.json`).
- oh-my-pi: `omp install /abs/path/derm/packages/derm-pi`.
- Gemini CLI: `gemini extensions install /abs/path/derm/packages/derm-gemini-extension --consent`, then save the user policy it prints.
- Kilo Code: `"plugin": ["file:///abs/path/derm/packages/derm-kilo-plugin"]` in `~/.config/kilo/kilo.json`, or the one line in `~/.config/kilo/plugin/derm.ts` (its README).
- Hermes Agent: `cp -r /abs/path/derm/packages/derm-hermes-plugin ~/.hermes/plugins/derm && hermes plugins enable derm` (Node on Hermes's PATH).
- OpenClaw: `openclaw plugins install --link /abs/path/derm/packages/derm-openclaw-plugin --force`, then `openclaw plugins enable derm`.

The library's commands run with Node, not as `derm` subcommands yet: `node library/cli.ts validate`, `node library/publish/cli.ts publish <entry-dir> --library <clone>` (what the plan calls `derm publish`; prints the pull request's steps unless `--open-pr`), `node library/mirror/cli.ts pull --out <dir>`, `node library/trust/cli.ts record|scan|osv|pin`, `node library/site/build.ts <out-dir>`.

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
