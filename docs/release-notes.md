# derm v0.1.3

One fix from the release check of v0.1.2 (3 Nov 2026). No change to the policy, the gates' decisions or the protocol.

## Changes since v0.1.2

- **`derm status`** printed each registration note cut at 160 characters, so the commands at the end of a long note (Codex's remove-then-add for a marketplace that is not derm's, or one pinned to another release, and Pi's install hint) did not show whole. Notes now print whole, still with every control character escaped. A registered agent that still needs something done (a Codex marketplace pinned to another release) now shows its note too; `derm status --json` marks it with `registeredNote`.

# derm v0.1.2

Fixes from the recheck of v0.1.1 (3 Nov 2026). No change to the policy, the gates' decisions or the protocol. v0.1.1's draft is replaced by this release; its changes are below.

## Changes since v0.1.1

- **`derm status` for Codex** told anyone with a `~/.codex/config.toml`, which is every Codex user, to run `codex plugin add derm@derm`, which fails until derm's marketplace is configured. It now names `codex plugin marketplace add aetiusgular/derm --ref v0.1.2` first, until `[marketplaces.derm]` is in the file.
- **The agents page** says to write `~/.derm/policy.json` before registering an adapter: with no policy every call asks, so Codex, OpenCode and Kilo Code deny every tool call unless `derm watch --approve` answers, and the other agents prompt before every call.

# derm v0.1.1

Fixes from the release check of v0.1.0 (3 Nov 2026). No change to the policy, the gates' decisions or the protocol.

## Changes since v0.1.0

- **Linux, a shell with no `XDG_RUNTIME_DIR`** (Tailscale SSH, and any route that skips PAM's `pam_systemd`): `derm status`, `derm watch` and `derm run` looked for the daemon in `~/.derm/run` while the systemd user unit listens in `/run/user/<uid>`, and said "not reachable". derm now takes `/run/user/<uid>` when the variable is unset and that folder is yours and 0700, in the daemon, the CLI, `derm connect`'s log and `derm-audit-feed`. An empty or relative `XDG_RUNTIME_DIR` counts as unset (0.1.0 put the socket in a relative `derm/` folder). `derm run --boundary none` also names the socket it used to the agent's hooks (`DERM_DAEMON_SOCKET`), so a hook reaches the daemon that gave it its chat token whatever the agent's environment holds.
- **`derm watch report` on a Mac** said "truncated" over an empty log: an absent collector (none ships yet) counted as a cut-short reply. It no longer does; a timeout or a reply that stopped mid-way still does, and the collector line says why.
- **`derm status`** gives install lines that work without a clone: `claude plugin marketplace add aetiusgular/derm` and `codex plugin marketplace add aetiusgular/derm`; for Pi, a folder of the release's source (`docs/install/agents.md`).
- **The macOS zip** unpacks to one folder, `derm-<version>-macos/`, as the Linux tarball does. Safari named 0.1.0's folder `derm-0` and merged a second download into it.
- `derm connect` reads the daemon's token with the same checks as `derm run` (a regular file you own, 0600), and `derm-audit-feed rules --uid <n>` no longer takes the caller's `XDG_RUNTIME_DIR` for another user's rules.
- `derm status` pins the Codex marketplace to the release's tag (`--ref v0.1.1`).
- The README, the install pages and the comments in the launchd plist and the tarball's systemd unit describe the published release, not the build.

Earlier notes follow.

# derm v0.1.0


The first release. derm is a skin for AI agents: a gate, a boundary and an audit around any coding agent.

## In this release

- `derm`, `derm-daemon` and, on Linux, `derm-audit-feed`.
- Linux x86_64: static binaries in `derm-0.1.0-x86_64-unknown-linux-musl.tar.gz`, and `derm_0.1.0_amd64.deb` with the systemd user unit, installed and not enabled.
- macOS: `derm-0.1.0-macos.zip`, universal binaries, signed with a Developer ID and the hardened runtime, notarized. A ticket cannot be stapled to a bare binary, so the first run of each binary needs a network connection while Gatekeeper looks the ticket up.
- Gates for Claude Code, Codex, Pi, oh-my-pi, OpenCode, Kilo Code, Gemini CLI, Hermes Agent and OpenClaw (`docs/install/agents.md`).
- The library: a catalog in the official MCP registry's format, its validator, exports, mirror, publish, trust records and takedowns.

On macOS also through Homebrew: `brew install aetiusgular/tap/derm`.

Check a download against `SHA256SUMS`. The Linux files carry GitHub build provenance: `gh attestation verify <file> --repo aetiusgular/derm`.

## Not in this release

- The macOS activity collector and the computer-use helper (built from `macos/`, not shipped).
- aarch64 Linux.
- The adapters on npm.
- The coverage wave: the gates for OpenClaude, Qwen Code, Droid, Command Code, Kimi Code, Auggie, Copilot CLI, Grok Build, Cursor, Antigravity, goose, Mistral Vibe, Crush, Kiro, Amp, Cline, Continue, Rovo Dev and Codebuff, `derm acp` and `derm doctor`.

## Known issues

- **S2 (high):** an approver started outside an agent's process tree (a double fork, `setsid`, a terminal multiplexer) can answer that agent's `ask`s. Run `derm watch --approve` only from your own terminal. This is why computer use is not shipped.
- Codex and Gemini CLI let a call through when their hook crashes; `derm status` says "fails open" for them.
- The single-underscore tool name forms of OpenCode, Kilo and oh-my-pi cannot tell `exa_evil` from `exa`: give servers names without `_` or `-` there.
- The redactors are best-effort.
- The full list, with each item's risk and owner, is in the README.
