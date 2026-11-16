# tests/eval: the eval suite (wave 6, lane 6F)

Scaffolded empty by the wave 6 base (12 Nov 2026). Lane 6F owns this folder and `docs/evidence/`. The contract is `contracts/eval.md` (scenario and result shapes, `contracts/eval.schema.json`); the plan is `plans/toolkit_wave6_plan.md` section 2.1, lane 6F (a) to (h), and section 3 (E1).

- The runner is `tests/eval/run.mjs`; `node tests/eval/run.mjs --suite moatbench --list` prints one scenario id per line. The base's red test `crates/derm-cli/tests/contracts_w6.rs` (`the_eval_runner_lists_the_e0_scenarios`) holds it to the E0 fixture's ids.
- TypeScript tests here end in `.test.ts` and run under `npx vitest run` (the base added `tests/eval/**/*.test.ts` to `vitest.config.ts`).
- Third-party tools run in the cloud or on the box only (rules section 5, item 2; the wave 6 plan's section 6, item 8). OpenMoat runs from its checksummed release binary (note AZ, F3), never from `/tmp` (it refuses to).
