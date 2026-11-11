// Runs the TypeScript dialect tests of the 17 agents and Hermes with the
// recorder of record-setup.ts (the wave 5b base). One worker, so the file it
// appends to is written in order.
//   DERM_HOOK_CASES_OUT=/tmp/raw.jsonl npx vitest run -c contracts/fixtures/hook-cases/record.vitest.config.ts
import path from "node:path";
import { defineConfig } from "vitest/config";

const root = path.resolve(import.meta.dirname, "..", "..", "..");

export default defineConfig({
  root,
  test: {
    include: [
      "packages/derm-claude-plugin/src/hook.test.ts",
      "packages/derm-codex-plugin/src/hook.test.ts",
      "packages/derm-gemini-extension/src/hook.test.ts",
      "packages/derm-hooks-claude-compat/src/*.test.ts",
      "packages/derm-hooks-native/src/*.test.ts",
      "packages/derm-hermes-plugin/src/*.test.ts",
    ],
    setupFiles: [path.join(import.meta.dirname, "record-setup.ts")],
    pool: "forks",
    poolOptions: { forks: { singleFork: true } },
    fileParallelism: false,
  },
});
