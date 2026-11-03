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
const pkgs = packagesWithTables() as { name: string; table: string }[];

describe("plugin NOTICE files", () => {
  it("are current for every package that carries the table", () => {
    expect(pkgs.length).toBe(12);
    expect(() => execFileSync(process.execPath, [join(ROOT, "packaging", "gen-notices.mjs"), "--check"], { stdio: "pipe" })).not.toThrow();
  });

  it.each(pkgs.map((p) => p.name))("%s packs its NOTICE and its table", (name) => {
    const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: join(ROOT, "packages", name), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const files = (JSON.parse(out) as { files: { path: string }[] }[])[0]!.files.map((f) => f.path);
    expect(files).toContain("NOTICE");
    expect(files.some((f) => f.endsWith("confusables.ts"))).toBe(true);
  }, 60_000);
});
