// The wave 5 base's stub for lane X: no call is an install yet, and the
// matcher's answer for an install command is what it was before the seam.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { installDecision } from "./index.ts";
import { evaluate, type LoadedPolicy } from "../policy.ts";

const loaded: LoadedPolicy = { policy: { version: 1, askTimeoutSeconds: 60, servers: [], rules: [{ tool: "bash", action: "allow" }] } };

describe("install seam (wave 5 base)", () => {
  it("reads no call as an install", () => {
    for (const text of ["npm install left-pad", "npx some-made-up-name", "pip install requests", "ls -la"]) {
      expect(installDecision("bash", text)).toBeUndefined();
    }
  });
  it("leaves an allowed install command allowed until lane X", () => {
    const d = evaluate(loaded, { tool: "Bash", harness: "claude-code", inputText: "npm install left-pad" });
    expect(d.action).toBe("allow");
    expect(d.reason).toBe("rule bash");
  });
  it("never reads as an install what the fixture says is not one (contracts/fixtures/installs/)", () => {
    const { cases } = JSON.parse(readFileSync(new URL("../../../../../contracts/fixtures/installs/cases.json", import.meta.url), "utf8")) as { cases: { id: number; text: string; expect: { install: boolean } }[] };
    const not = cases.filter((c) => !c.expect.install);
    expect(not.length).toBeGreaterThanOrEqual(5);
    for (const c of not) expect([c.id, installDecision("bash", c.text)]).toEqual([c.id, undefined]);
  });
});
