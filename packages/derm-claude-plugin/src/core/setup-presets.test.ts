// Lane W's request W-2: derm setup's policy presets read by the hook core's
// matcher, with command rules (request W-1), against
// tests/cli-contract/checks/W/preset-cases.json.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import cases from "../../../../tests/cli-contract/checks/W/preset-cases.json" with { type: "json" };
import { evaluate, parsePolicy, type Call } from "./policy.ts";

const preset = (name: string) => JSON.parse(readFileSync(new URL(`../../../../crates/derm-cli/src/setup/presets/${name}.json`, import.meta.url), "utf8")).policy;

describe("derm setup's presets in the hook core (request W-2)", () => {
  for (const name of ["workspace-write", "read-only", "strict"]) {
    it(`${name} parses and answers its cases`, () => {
      const p = parsePolicy(preset(name));
      if (typeof p === "string") throw new Error(`${name}: ${p}`);
      for (const c of cases.cases.filter((x) => x.preset === name)) {
        const d = evaluate({ policy: p }, c.call as Call);
        expect([c.id, d.action]).toEqual([c.id, c.expect.action]);
        expect([c.id, d.reason.startsWith(c.expect.reasonPrefix)]).toEqual([c.id, true]);
      }
    });
  }
});
