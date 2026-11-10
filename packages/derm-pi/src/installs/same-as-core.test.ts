// derm-pi carries its own copy of the install check (it does not import the
// hook core). This holds the copy equal to the canonical one: parse.ts and
// lockfile.ts byte for byte, index.ts from its first import on (the header
// says which copy it is).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const here = new URL("./", import.meta.url);
const core = new URL("../../../derm-claude-plugin/src/core/installs/", import.meta.url);
const read = (dir: URL, f: string) => readFileSync(new URL(f, dir), "utf8");
const fromImports = (t: string) => t.slice(t.indexOf("\nimport "));

describe("derm-pi's installs/ equals the hook core's", () => {
  it("has the same parse.ts and lockfile.ts", () => {
    for (const f of ["parse.ts", "lockfile.ts"]) expect([f, read(here, f) === read(core, f)]).toEqual([f, true]);
  });
  it("has the same index.ts code", () => {
    expect(fromImports(read(here, "index.ts"))).toBe(fromImports(read(core, "index.ts")));
  });
});
