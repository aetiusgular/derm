// Each plugin package carries a NOTICE with derm's licence and the Unicode
// licence of its confusables table, and npm packs it (npm adds LICENSE and
// README on its own, NOTICE only when `files` names it or there is no list).
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// @ts-expect-error: a plain .mjs script with no types.
import { packagesWithTables } from "./gen-notices.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// npm as this OS starts it. On Windows `npm` is `npm.cmd`, which
// `execFileSync` cannot find (it tries no `.cmd`) and which Node starts only
// through a shell since CVE-2024-27980 (Node's April 2024 security
// releases). The Windows install carries npm's script beside node.exe
// (`node_modules\npm\bin\npm-cli.js`), run here with this node.
const NPM: [string, string[]] =
  process.platform === "win32" ? [process.execPath, [join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js")]] : ["npm", []];
const pkgs = packagesWithTables() as { name: string; table: string }[];

describe("plugin NOTICE files", () => {
  it("are current for every package that carries the table", () => {
    // 10 since the wave 5b close: derm-codex-plugin and derm-hermes-plugin
    // carry no core copy, so no table (their NOTICE is derm's licence alone).
    expect(pkgs.length).toBe(10);
    expect(() => execFileSync(process.execPath, [join(ROOT, "packaging", "gen-notices.mjs"), "--check"], { stdio: "pipe" })).not.toThrow();
  });

  it.each(pkgs.map((p) => p.name))("%s packs its NOTICE and its table", (name) => {
    const out = execFileSync(NPM[0], [...NPM[1], "pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: join(ROOT, "packages", name), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const files = (JSON.parse(out) as { files: { path: string }[] }[])[0]!.files.map((f) => f.path);
    expect(files).toContain("NOTICE");
    expect(files.some((f) => f.endsWith("confusables.ts"))).toBe(true);
  }, 60_000);
});
