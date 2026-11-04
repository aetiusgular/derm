// The wave 5 base's stub for lane X in derm-pi: no call is an install yet.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { installDecision } from "./index.ts";

describe("install seam (wave 5 base)", () => {
  it("reads no call as an install", () => {
    for (const text of ["npm install left-pad", "uvx some-made-up-name", "ls -la"]) {
      expect(installDecision("bash", text)).toBeUndefined();
    }
  });
  it("never reads as an install what the fixture says is not one (contracts/fixtures/installs/)", () => {
    const { cases } = JSON.parse(readFileSync(new URL("../../../../contracts/fixtures/installs/cases.json", import.meta.url), "utf8")) as { cases: { id: number; text: string; expect: { install: boolean } }[] };
    const not = cases.filter((c) => !c.expect.install);
    expect(not.length).toBeGreaterThanOrEqual(5);
    for (const c of not) expect([c.id, installDecision("bash", c.text)]).toEqual([c.id, undefined]);
  });
});
