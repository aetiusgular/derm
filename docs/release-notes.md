# derm v0.1.0

The first release. derm is a skin for AI agents: a gate, a boundary and an audit around any coding agent.

## In this release

- `derm`, `derm-daemon` and, on Linux, `derm-audit-feed`.
- Linux x86_64: static binaries in `derm-0.1.0-x86_64-unknown-linux-musl.tar.gz`, and `derm_0.1.0_amd64.deb` with the systemd user unit, installed and not enabled.
- macOS: `derm-0.1.0-macos.zip`, universal binaries, signed with a Developer ID and the hardened runtime, notarized. A ticket cannot be stapled to a bare binary, so the first run of each binary needs a network connection while Gatekeeper looks the ticket up.
- Gates for Claude Code, Codex, Pi, oh-my-pi, OpenCode, Kilo Code, Gemini CLI, Hermes Agent and OpenClaw, installed from a clone of the repository for now (`docs/install/agents.md`).
- The library: a catalog in the official MCP registry's format, its validator, exports, mirror, publish, trust records and takedowns.

On macOS also through Homebrew once the tap is up: `brew install aetiusgular/tap/derm`.

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
