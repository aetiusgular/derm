import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";

// Only *.test.ts runs. A *.test.tsx or *.test.js file is not collected:
// the scope script refuses new ones so nothing is skipped without a word.
//
// On Windows the TypeScript dialect hook tests in scripts/windows-held.json
// are not run: those hooks do not run there (the Rust `derm hook` is the
// gate), and every one of their cases is held by a Rust test that runs on
// Windows. scripts/windows-holders.mjs, in the Linux CI job, fails when a
// case in them has no holder (note BF section 4.1). Linux and macOS run them.
// DERM_LIST_WINDOWS_HELD=1: the guard's own `vitest list`, which must see them.
const windowsHeld: string[] =
  process.platform === "win32" && process.env.DERM_LIST_WINDOWS_HELD !== "1"
    ? (JSON.parse(readFileSync(new URL("./scripts/windows-held.json", import.meta.url), "utf8")) as { files: string[] }).files
    : [];

export default defineConfig({
  test: {
    include: ["packages/*/**/*.test.ts", "library/**/*.test.ts", "contracts/**/*.test.ts", "packaging/**/*.test.ts", "tests/eval/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**", ...windowsHeld],
  },
});
