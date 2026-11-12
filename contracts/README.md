# Contracts

Written by tk session 0 on 27 Oct 2026. Lanes build against these and their fixtures, not against each other's code (`plans/parallel_build_tk.md`, section 2, point 3). No lane edits this folder during a wave; a change is a request for integration. Since the wave 5 base, two exceptions: lane S may add files in `fixtures/tap/` and lane X in `fixtures/installs/` (`scripts/lane-ownership.json`). Wave 5b's red tests read `fixtures/hook-cases/`, `gate-serve/`, `srt-windows/` and `sysmon-service/`; wave 6's (`crates/derm-cli/tests/contracts_w6.rs`, `crates/derm-egress/tests/contract.rs`) read `fixtures/eval/`, `hook-w6/`, `audit/` and `sandbox/`; a lane that finds a recorded case wrong writes it under "Requests for integration" and does not change the case.

| Contract | Fixture | Filled by | Read by |
|---|---|---|---|
| `policy.md`, `policy.schema.json` | `fixtures/policy/` (10 rules, 21 cases) | B (Rust), A (TypeScript) | A, B, C, F |
| `daemon-protocol.md` | `fixtures/daemon/exchange.jsonl` | B | A, D, F; J in wave 2 |
| `entry.schema.json`, `shapes/` | `fixtures/entry/` (one per kind, plus a marketplace) | E | C, E; G, H in wave 2 |
| `harness-presets.schema.json` (the table is one file per agent in `crates/derm-cli/src/connect/presets/`, assembled by `presets.ts` and `presets.rs`; integration w2) | the table itself | C; wave 4 lanes L, N, P, Q by file | A, C, D, E, F, J; R in wave 4 |
| `events.md` | `tests/fixtures/otlp/` | A emits, B decodes | A, B |
| `docker-args.md` | the copied `docker_mcp.rs` | C | A (the redactor), C |
| `events.md` section 5, `wave5-records.schema.json` (wave 5, the wave 5 base) | `fixtures/tap/` (lane S may add files), `fixtures/installs/records.json` | S (tap, join, content), X (installs), U (`cu.action`), W (`agent.unregistered`, through integration) | S, T, U, V, W, X |
| `policy.md` section 6 (wave 5) | `fixtures/installs/cases.json` (lane X may add files) | X, in all three matchers | X, W |
| `settings.schema.json` (wave 5): `~/.derm/settings.json` | `fixtures/tap/settings.example.json` | W writes; S, T, U, X read their keys | S, T, U, W, X |
| `cu-tool.schema.json` (wave 5): Hermes's `computer_use` input, MIT (NOTICE) | none; `contracts.test.ts` holds a few inputs | U | U |
| `harness-presets.schema.json`'s `tap`, `kit`, `executables` (wave 5) | the empty tables in `crates/derm-cli/src/connect/presets/wave5/` | S, T, W, one table each | S, T, W, Z |
| `hook-dialects.md` section 9 (wave 5b, the wave 5b base): `derm hook`'s registration line, whose input it is (BCR-7), how a Rust dialect is held to the TypeScript | `fixtures/hook-cases/` (227 recorded cases, the recorder, `manual.json`) | 5bA, 5bB; 5bF for the lines | 5bA, 5bB, 5bF |
| `gate-serve.md` (wave 5b): `derm gate serve`'s JSON lines | `fixtures/gate-serve/` (held to `gate::core` by a test) | 5bC | 5bC |
| `srt-windows.md` (wave 5b): the handoff and `derm enter` | `fixtures/srt-windows/handoff.json` | 5bD | 5bD |
| `sysmon-service.md` (wave 5b): `derm-sysmon`'s pipe | `fixtures/sysmon-service/exchange.jsonl`, `tests/windows/fixtures/sysmon/chat.xml` | 5bE | 5bE |
| `fixtures/redact/` (wave 5b): the hook redactor's outputs, recorded from `core/redact.ts` | itself | the base (`derm_core::redact::hook`) | everyone |
| `sandbox.md` (wave 6, the wave 6 base): the Standard tier, policy to each agent's own sandbox; `harness-presets.schema.json`'s `sandbox` | `fixtures/sandbox/` (Claude Code 2.1.322 and Codex 0.167.2, recorded); the empty table `presets/wave6/sandbox.json` | 6A | 6A, 6B, 6C, 6F |
| `events.md` section 6 (wave 6): `run.start`'s `tier`, taint, egress and broker records, the light tier's log and chain v2, the export | `fixtures/audit/` (chain v2 and tampered copies; `derm_core::audit_chain` is the reference), `fixtures/hook-w6/` (Claude Code 2.1.322's hook inputs, recorded) | 6A, 6B, 6C, 6D, 6E | 6B, 6D, 6E, 6F |
| `policy.md` sections 8 and 9 (wave 6): secrets the broker injects, taint; `secrets.schema.json`, `settings.schema.json`'s `tier` and `taint` | `fixtures/secrets/secrets.example.json` | 6C, 6D | 6A, 6C, 6D |
| `eval.md`, `eval.schema.json` (wave 6): scenarios and results | `fixtures/eval/` (E0's allowed MoatBench steps, copied from OpenMoat 0.19.0, NOTICE; one scenario and one result) | 6F | 6F, E1, every lane's first tests |

A server's tool list is not in `server.json` (upstream's 2025-12-11 schema has no tool list, and derm's `_meta` object is `additionalProperties: false`): it lives in a sibling `tools.json` in the entry's folder, as the seed catalog does since wave 1. Integration w2 blessed that form at lane G's request: a tool list inside `_meta` would push a large server past the official registry's 4,096-byte cap on the publisher object (lane G, `validators.go:727-737`), and a mirrored entry has no tool list at all unless something connected to the server.

`contracts.test.ts` validates every fixture against its schema. The Rust fixture tests are `crates/derm-core/tests/policy_fixture.rs` and the test in `crates/derm-daemon/src/protocol.rs`.
