// Lane X's install decision in derm-pi (contracts/policy.md section 6; rules
// cases 130 to 135). The wave 5 base's stub test "reads no call as an
// install" is replaced by what lane X was asked to build.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { installDecision, parseInstalls } from "./index.ts";
import { evaluate, SHELL_TOOLS, type PolicyFile } from "../policy.ts";
import { decodeEscapes, foldText } from "../fold.ts";

const dir = new URL("../../../../contracts/fixtures/installs/", import.meta.url);
type BaseCase = { id: number; text: string; expect: { install: boolean; manager?: string; form?: string; packages?: { name: string; version: string | null }[] } };
type XCase = { id: number; text: string; installs: unknown[] };
const base = (JSON.parse(readFileSync(new URL("cases.json", dir), "utf8")) as { cases: BaseCase[] }).cases;
const lane = (JSON.parse(readFileSync(new URL("cases-x.json", dir), "utf8")) as { cases: XCase[] }).cases;
const folded = (t: string) => foldText(decodeEscapes(t));
const policy: PolicyFile = { version: 1, askTimeoutSeconds: 60, servers: [], rules: [{ tool: "*", action: "allow" }] };

describe("derm-pi's install reader, both fixtures", () => {
  it("reads the base's cases", () => {
    for (const c of base) {
      const got = parseInstalls(folded(c.text));
      if (!c.expect.install) expect([c.id, got]).toEqual([c.id, []]);
      else expect([c.id, got.map((g) => [g.manager, g.form, g.packages])]).toEqual([c.id, [[c.expect.manager, c.expect.form, c.expect.packages]]]);
    }
  });
  it("reads lane X's cases", () => {
    for (const c of lane) expect([c.id, parseInstalls(folded(c.text))]).toEqual([c.id, c.installs]);
  });
});

describe("derm-pi's matcher asks for an allowed install", () => {
  it("asks for every install of the base's fixture through Pi's shell tools, and leaves the rest", () => {
    for (const tool of SHELL_TOOLS) {
      for (const c of base) {
        const d = evaluate(policy, { tool, harness: "pi", inputText: c.text });
        expect([tool, c.id, d.action]).toEqual([tool, c.id, c.expect.install ? "ask" : "allow"]);
        if (c.expect.install) for (const p of c.expect.packages ?? []) expect(d.reason).toContain(p.name);
      }
    }
  });
  it("never reads as an install what the fixture says is not one (contracts/fixtures/installs/)", () => {
    const not = base.filter((c) => !c.expect.install);
    expect(not.length).toBeGreaterThanOrEqual(5);
    for (const c of not) expect([c.id, installDecision("bash", folded(c.text))]).toEqual([c.id, undefined]);
  });
  it("keeps the allow for a pinned package, given the context", () => {
    const lock = () => [{ name: "left-pad", version: "1.3.0", registry: true }];
    expect(installDecision("bash", "npm i left-pad@1.3.0", { raw: "npm i left-pad@1.3.0", lockfile: lock })).toBeUndefined();
    expect(installDecision("bash", folded("npm i lеft-pad@1.3.0"), { raw: "npm i lеft-pad@1.3.0", lockfile: lock })?.action).toBe("ask");
  });
});
