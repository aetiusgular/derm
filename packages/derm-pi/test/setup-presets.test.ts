// Lane W's request W-2: derm setup's policy presets read by derm-pi's matcher.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import cases from "../../../tests/cli-contract/checks/W/preset-cases.json" with { type: "json" };
import { evaluate, parsePolicy } from "../src/policy.ts";

const preset = (name: string) => readFileSync(new URL(`../../../crates/derm-cli/src/setup/presets/${name}.json`, import.meta.url), "utf8");

describe("derm setup's presets in derm-pi (request W-2)", () => {
  for (const name of ["workspace-write", "read-only", "strict"]) {
    it(`${name} parses and answers its cases`, () => {
      const loaded = parsePolicy(JSON.stringify(JSON.parse(preset(name)).policy));
      expect(loaded.problem).toBeUndefined();
      for (const c of cases.cases.filter((x) => x.preset === name)) {
        const d = evaluate(loaded.policy, c.call);
        expect([c.id, d.action]).toEqual([c.id, c.expect.action]);
        expect([c.id, d.reason.startsWith(c.expect.reasonPrefix)]).toEqual([c.id, true]);
      }
    });
  }
});
