# Contracts

Written by tk session 0 on 27 Oct 2026. Lanes build against these and their fixtures, not against each other's code (`plans/parallel_build_tk.md`, section 2, point 3). No lane edits this folder during a wave; a change is a request for integration. Since the wave 5 base, two exceptions: lane S may add files in `fixtures/tap/` and lane X in `fixtures/installs/` (`scripts/lane-ownership.json`).

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

A server's tool list is not in `server.json` (upstream's 2025-12-11 schema has no tool list, and derm's `_meta` object is `additionalProperties: false`): it lives in a sibling `tools.json` in the entry's folder, as the seed catalog does since wave 1. Integration w2 blessed that form at lane G's request: a tool list inside `_meta` would push a large server past the official registry's 4,096-byte cap on the publisher object (lane G, `validators.go:727-737`), and a mirrored entry has no tool list at all unless something connected to the server.

`contracts.test.ts` validates every fixture against its schema. The Rust fixture tests are `crates/derm-core/tests/policy_fixture.rs` and the test in `crates/derm-daemon/src/protocol.rs`.
