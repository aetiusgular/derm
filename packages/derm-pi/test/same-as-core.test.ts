// derm-pi carries its own copy of the command readers (it does not import the
// hook core). This holds the copies equal to the canonical ones, byte for
// byte: command.ts (section 7 and steps 7b, 7d) and destructive.ts (step 7e,
// eval pass 1's E1-1).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const here = new URL("../src/", import.meta.url);
const core = new URL("../../derm-claude-plugin/src/core/", import.meta.url);
const read = (dir: URL, f: string) => readFileSync(new URL(f, dir), "utf8");

describe("derm-pi's command readers equal the hook core's", () => {
  it("has the same command.ts and destructive.ts", () => {
    for (const f of ["command.ts", "destructive.ts"]) expect([f, read(here, f) === read(core, f)]).toEqual([f, true]);
  });
});
