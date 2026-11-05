// derm-pi carries its own copy of the command-rule reader (it does not import
// the hook core): this holds it equal to the canonical one, byte for byte.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import invalid from "../../../contracts/fixtures/policy/invalid.json" with { type: "json" };
import { parsePolicy } from "./policy.ts";

describe("derm-pi's command.ts equals the hook core's", () => {
  it("is the same file", () => {
    const here = readFileSync(new URL("./command.ts", import.meta.url), "utf8");
    const core = readFileSync(new URL("../../derm-claude-plugin/src/core/command.ts", import.meta.url), "utf8");
    expect(here === core).toBe(true);
  });
  it("refuses each command shape the schema refuses", () => {
    for (const p of invalid.policies) expect(parsePolicy(JSON.stringify(p.policy)).problem, p.id).toBeDefined();
  });
});
