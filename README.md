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
| W2-R1 | Medium | OpenCode's, Kilo's and oh-my-pi's single-underscore tool names cannot tell `exa_evil` from `exa`. `derm connect` refuses to add such a name and `--check-names` lists the pairs it finds; the gate itself does not compare against your configured servers, so a project file can still add one (owner: the next `derm connect` work, request Q3 in `plans/parallel/tk_integration_w4.md`) | Give servers names without `_` or `-` in those agents; run `derm connect <agent> --check-names` |
| Fails open | Medium | Codex, Gemini CLI, OpenClaude, Qwen Code, Droid, Kimi Code, Auggie, Crush and Cline let a call through when the gate dies or times out, with no switch; Copilot CLI on a timeout | `derm status` marks them; `derm connect <agent> --rules` writes your denies into Codex's, Gemini's, OpenClaude's and Qwen's own rules as a second layer |
| L10 | Medium | Under `derm run --boundary srt`, Cline can write a decision file in the approval folder its responder reads (owner: the Cline adapter, lane P's card) | Run Cline with `--boundary none` and derm's plugin as its gate, or keep asks out of its policy |
| N1 | Medium | If Cursor's CLI does not fire `beforeMCPExecution`, its MCP calls are not gated; only a deny by bare tool name holds (owner: the Mac test w4) | Deny Cursor's MCP tools by name, or do not rely on derm for Cursor's MCP calls until the Mac test says it fires |
| Chat token | Medium, by design | A chat's token sits in the agent's environment, so the agent's shell can read it and post records into its own chat. It cannot approve, mint tokens, read other chats or switch the OS feed off | Treat a chat's own records as what that chat's processes said; OS-feed, run and approval records cannot be posted with it |
| Redactors | Medium | Secret redaction in run records, the OS feed and `derm connect`'s output is best-effort: multi-line TOML and YAML values and a key and value on two lines can still print | Keep `DERM_LOG_CONTENT` off; read a dry run before `--write` |
| Later hooks | Low to medium | In oh-my-pi, Kilo, Gemini CLI and Hermes a hook or extension that runs after derm's can still change a call's input after derm decided | Do not install other tool-call hooks beside derm's there |
| io_uring | Low to medium | File opens and connects done through io_uring are not seen by the auditd feed | None in this release |
| S16 | Low | The managed Claude Code fragment force-enables `derm@derm` without pinning where the `derm` marketplace comes from (owner: the Claude Code adapter) | Pin the source in managed settings ([the agents page](docs/install/agents.md#claude-code-under-managed-settings)) |
| Gemini's backstop | Low | Gemini's own rules in the extension cannot read past an escaped quote in a command (`\"`), because Gemini drops a rule written with the pattern that would (its own regex check); the hook still asks there, but not when the hook has died | None in this release |
| Gemini's printout | Low | When a deny in your policy reaches Gemini's shell, `derm-gemini-policy` keeps a `bash` ask at its own rank, which can still outrank that deny if the ask is scoped to Gemini and the deny is not; Gemini then asks where derm's hook denies (W4-R5; the hook still runs first) | Scope the deny the same way as the ask, or read the printout before saving it |
| S12's residue | Low | A catalog entry's header now names only a variable under its own server's prefix (`DERM_<SERVER>__<VAR>`, wave 4), so it cannot read `GITHUB_TOKEN`; an entry that takes the name of a server you already use (with `--replace`) reads that server's variables | `derm connect` shows it in the diff and writes only on `--write` and a yes in your terminal: read the header lines |
| W4-S5's residue | Low | The gate's control-file check does not see a command that changes into the folder above a control folder and names its last part (`cd ~/.config && rm -rf goose`), or the daemon's runtime folder itself (`rm -r /run/user/<uid>/derm`); `//`, `/./` and `<folder>/..` are read since integration w4 | `bash: allow` is full user power; keep the shell on ask where that matters |
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
| `crates/derm-cli` | `derm connect`, `derm run`, `derm watch`, `derm status`, `derm cu`, `derm acp` and `derm doctor` (the last two wave 4's). The preset table is one file per agent in `src/connect/presets/` |
| `crates/derm-audit-linux` | The Linux OS feed from auditd (`derm-audit-feed`) |
| `packages/derm-pi` | The Pi package (also oh-my-pi's): gate, emitter, memory extension |
| `packages/derm-claude-plugin`, `derm-codex-plugin`, `derm-opencode-plugin` | Claude Code, Codex and OpenCode adapters; the canonical hook core is `derm-claude-plugin/src/core/` |
| `packages/derm-gemini-extension`, `derm-hermes-plugin`, `derm-openclaw-plugin`, `derm-kilo-plugin` | Gemini CLI, Hermes Agent, OpenClaw and Kilo Code adapters (wave 2) |
| `packages/derm-hooks-claude-compat`, `derm-hooks-native`, `derm-amp-plugin`, `derm-cline` | Wave 4's adapters: Claude-format command hooks for eight agents, own-dialect hooks for six, Amp's plugin, Cline's plugin and its approval-file responder. Each holds a synced copy of the hook core in `src/core/` |
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
| OpenClaude | G, fails open | PreToolUse in `~/.openclaude/settings.json` (`packages/derm-hooks-claude-compat`) | Built, wave 4 (lane L). Contract checks pass against OpenClaude 0.34.0 in the cloud (5 pass, 1 info: a killed gate lets the call run); full access not run as root |
| Qwen Code | G, fails open | PreToolUse in `~/.qwen/settings.json` (`packages/derm-hooks-claude-compat`) | Built, wave 4 (lane L). Contract checks pass against Qwen Code 0.26.6 (7 pass, 1 info) |
| Droid | G, fails open | PreToolUse in `~/.factory/settings.json`, beside Orca's entry (`packages/derm-hooks-claude-compat`); a `~/.factory/hooks.json` turns it off | Built, wave 4 (lane L). Contract checks pass against Droid 1.3.0 in airgap mode with a local model (5 pass, 2 info) |
| Command Code | G | PreToolUse with `failClosed` (`packages/derm-hooks-claude-compat`) | Built, wave 4 (lane L). Fixtures only (needs an account): unverified at 1.88.2 |
| Kimi Code | G, fails open | `[[hooks]]` in `~/.kimi-code/config.toml` (`packages/derm-hooks-claude-compat`) | Built, wave 4 (lane L). Contract checks pass against Kimi Code 2.4.1 (5 pass, 2 info: an unknown key drops every hook); `derm connect kimi --gate` prints, does not write |
| Auggie | G, fails open | PreToolUse in `~/.augment/settings.json` (`packages/derm-hooks-claude-compat`) | Built, wave 4 (lane L). Fixtures only (needs an account): unverified at 0.36.0 |
| GitHub Copilot CLI | G, open on timeout | `~/.copilot/hooks/derm.json` (`packages/derm-hooks-claude-compat`) | Built, wave 4 (lane L). Contract checks pass against Copilot CLI 1.0.105 offline (6 pass) |
| Grok Build | G | `~/.grok/hooks/derm.json` with `failClosed`, compat imports off (`packages/derm-hooks-claude-compat`) | Built, wave 4 (lane L). Contract checks pass against Grok 1.0.71 (7 pass); on 1.0.70 a killed gate lets the call run |
| Cursor CLI | G | `~/.cursor/hooks.json`: preToolUse and beforeMCPExecution, `failClosed` (`packages/derm-hooks-native`) | Built, wave 4 (lane N). Fixtures from Cursor's docs; unverified until the Mac test w4 (the CLI is on Tony's Mac). An ask on a built-in tool goes to the approver or is denied |
| Antigravity CLI | G, fail mode unknown | a named hook in `~/.gemini/config/hooks.json` (`packages/derm-hooks-native`) | Built, wave 4 (lane N). Fixtures from its docs only; not installed, not run (Tony's call) |
| goose | G | a plugin folder's PreToolUse with `on_failure: "block"` (`packages/derm-hooks-native`) | Built, wave 4 (lane N). Contract checks pass against goose 1.57.0 (8 pass) |
| Mistral Vibe | G | `pre_tool` in `~/.vibe/hooks.toml` with `strict` (`packages/derm-hooks-native`) | Built, wave 4 (lane N). Contract checks pass against Mistral Vibe 3.0.4 (6 pass) |
| Charm Crush | G, fails open | PreToolUse in `~/.config/crush/crush.json` (`packages/derm-hooks-native`); sub-agents fire no hook | Built, wave 4 (lane N). Contract checks pass against Crush 0.99.0 (7 pass, 1 info: a killed gate lets the call run) |
| Kiro CLI | G | `~/.kiro/hooks/derm.json` (`packages/derm-hooks-native`) | Built, wave 4 (lane N). Fixtures from its docs only; not installed, not run (Tony's call) |
| Amp | G, fail mode unknown | a Bun plugin folder `~/.config/amp/plugins/derm/` (`packages/derm-amp-plugin`, `tool.call`) | Built, wave 4 (lane P). Unit tests against its type definitions; needs an account, not run: unverified |
| Cline CLI | G, fails open | an SDK plugin `~/.cline/plugins/derm/` (`packages/derm-cline`, `beforeTool`) | Built, wave 4 (lane P). Contract checks pass against Cline 3.0.74 (13 pass, 1 info: the approval files never reach a responder in a prompt run) |
| Continue | A | `derm connect continue` prints the MCP entry for `~/.continue/config.yaml` | Connect row verified at 1.5.47 (lane Q); no rule writer: its `permissions.yaml` is ignored under `--auto` and `--readonly` |
| Rovo Dev | A | `toolPermissions` in `~/.rovodev/config.yml` | Planned. Its bash deny is not documented; no rule writer yet (lane Q); needs an account |
| Codebuff | O | `derm connect codebuff` writes `~/.agents/mcp.json`; `derm run` as an unknown program | MCP file verified against its source at v1.0.679 and `main` (lane Q); 1.0.688 itself inferred |
| Any other CLI agent | O | `derm run --boundary <b> -- <command>`, and `derm acp` for one that speaks ACP | Built, wave 4 (lane R): run end to end in the cloud; `derm acp` against Gemini CLI 0.66.0 in `--acp` mode |

Outside Orca's grid: OpenClaw, tier G, `packages/derm-openclaw-plugin` (`before_tool_call`, derm runs last): built, wave 2, contract checks pass against OpenClaw 2026.10.8 in the cloud (lane I). Wave 4's agents' hook contracts and fixtures are in `contracts/hook-dialects.md`.

### Wave 5 columns: tap, intent, boundary

Built on `integration/w5`, run in the cloud only (`plans/parallel/tk_integration_w5.md`); generated from the preset table's wave 5 files (`crates/derm-cli/src/connect/presets/wave5/tap.json` and `kit.json`). Tap: how `derm run` points the agent at the daemon's model tap, in its launch environment only. Intent source: where derm reads what the model asked for (the tap, else the gate's hooks). Boundaries: what `derm run` can start the agent under; with no `--boundary` it takes sbx, then srt, then warns and asks (case 129), and since phase 4 takes srt before sbx for an agent whose gate is registered and fails closed, until derm's kit passes the box test. Under sbx only Claude Code has derm's gate inside the VM; every kit with full-access words starts its agent with its own approvals off, so an ask there is a deny (case 83). Cursor's intent from its record hooks (note AS) is not wired yet.

| Agent id | Tap | Intent source | Boundaries |
|---|---|---|---|
| `claude-code` | `ANTHROPIC_BASE_URL`, verified at 2.1.311 | tap | sbx `claude` (full-access words: `--dangerously-skip-permissions`; derm's gate in the VM through derm's kit), srt, none |
| `codex` | Codex provider flags, verified at 0.163.0 | tap | sbx `codex` (full-access words: `--dangerously-bypass-approvals-and-sandbox`; no derm gate in the VM), srt, none |
| `gemini` | `GOOGLE_GEMINI_BASE_URL`, verified at 0.66.0 | tap | sbx `gemini` (full-access words: `--yolo`; no derm gate in the VM), srt, none |
| `pi` | none: untapped | hooks | sbx `docker.io/sbx/pi-kit:latest` (full-access words: none; no derm gate in the VM), srt, none |
| `cursor` | none: untapped | hooks | sbx `cursor` (full-access words: `--yolo`; no derm gate in the VM), srt, none |
| `amp` | none: untapped | hooks | sbx `docker.io/sbx/amp-kit:latest` (full-access words: `--dangerously-allow-all`; no derm gate in the VM), srt, none |
| `auggie` | none: untapped | hooks | srt, none (no sbx form) |
| `droid` | none: untapped | hooks | sbx `droid` (full-access words: none; no derm gate in the VM), srt, none |
| `kiro` | none: untapped | hooks | sbx `kiro` (full-access words: `--trust-all-tools`; no derm gate in the VM), srt, none |
| `rovo-dev` | none: untapped | none (outside shape) | srt, none (no sbx form) |
| `codebuff` | none: untapped | none (outside shape) | srt, none (no sbx form) |
| `opencode` | no tap row: untapped | hooks | sbx `opencode` (full-access words: none; no derm gate in the VM), srt, none |
| `hermes` | no tap row: untapped | hooks | sbx `docker.io/sbx/hermes-agent-kit:latest` (full-access words: none; no derm gate in the VM), srt, none |
| `openclaw` | no tap row: untapped | hooks | sbx `docker.io/sbx/openclaw-kit:latest` (full-access words: none; no derm gate in the VM), srt, none |
| `goose` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `qwen-code` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `copilot-cli` | no tap row: untapped | hooks | sbx `copilot` (full-access words: `--yolo`; no derm gate in the VM), srt, none |
| `crush` | no tap row: untapped | hooks | sbx `docker.io/sbx/crush-kit:latest` (full-access words: `--yolo`; no derm gate in the VM), srt, none |
| `zed` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `kilo` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `oh-my-pi` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `continue` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `grok` | no tap row: untapped | hooks | sbx grok kit at sbx-kits-contrib `1de3c1e` (full-access words: `--yolo`; no derm gate in the VM), srt, none |
| `antigravity` | no tap row: untapped | hooks | sbx `docker.io/sbx/antigravity-kit:latest` (full-access words: `--dangerously-skip-permissions`; no derm gate in the VM; no `derm run` row yet (P4-R6)), srt, none |
| `openclaude` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `cline` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `command-code` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `kimi` | no tap row: untapped | hooks | srt, none (no sbx form) |
| `mistral-vibe` | no tap row: untapped | hooks | sbx `docker.io/sbx/vibe-kit:latest` (full-access words: `--agent auto-approve`; no derm gate in the VM; no `derm run` row yet (P4-R6)), srt, none |

Orca's ids differ for three agents: Orca says `claude`, `copilot` and `aug`; derm says `claude-code`, `copilot-cli` and `auggie`. Wave 4's install lines are in `docs/install/agents.md`; `derm connect <agent> --gate` writes most of them. The machine-readable form of this table is the preset table, one file per agent in `crates/derm-cli/src/connect/presets/` (the `coverage` field on each row; `index.json` lists the `harnesses` and the `planned` rows).

MIT. See `NOTICE` for what was copied from where.
