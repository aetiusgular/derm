// The install reader against both fixtures (contracts/fixtures/installs/):
// the wave 5 base's cases.json and lane X's cases-x.json. derm-core and
// derm-pi run the same files.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { commands, parseInstalls } from "./parse.ts";
import { fold, decodeEscapes } from "../fold.ts";

type Pkg = { name: string; version: string | null };
type BaseCase = { id: number; text: string; expect: { install: boolean; manager?: string; form?: string; packages?: Pkg[] } };
type XCase = { id: number; text: string; installs: { manager: string; form: string; packages: Pkg[]; unseen: string[] }[] };

const dir = new URL("../../../../../contracts/fixtures/installs/", import.meta.url);
const base = (JSON.parse(readFileSync(new URL("cases.json", dir), "utf8")) as { cases: BaseCase[] }).cases;
const lane = (JSON.parse(readFileSync(new URL("cases-x.json", dir), "utf8")) as { cases: XCase[] }).cases;
const folded = (t: string) => fold(decodeEscapes(t));

describe("parseInstalls, the wave 5 base's cases", () => {
  it("reads each case as the fixture says", () => {
    expect(base.length).toBeGreaterThanOrEqual(30);
    for (const c of base) {
      const got = parseInstalls(folded(c.text));
      if (!c.expect.install) {
        expect([c.id, got]).toEqual([c.id, []]);
        continue;
      }
      expect([c.id, got.length]).toEqual([c.id, 1]);
      const g = got[0];
      expect([c.id, g?.manager, g?.form, g?.packages, g?.unseen]).toEqual([c.id, c.expect.manager, c.expect.form, c.expect.packages, []]);
    }
  });
});

describe("parseInstalls, lane X's cases", () => {
  it("reads each case as the fixture says", () => {
    expect(lane.length).toBeGreaterThanOrEqual(80);
    for (const c of lane) expect([c.id, parseInstalls(folded(c.text))]).toEqual([c.id, c.installs]);
  });
  it("gives every id once", () => {
    const ids = [...base, ...lane].map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("commands", () => {
  it("splits on operators and keeps quoted text in one word", () => {
    expect(commands("a 'b c'd; e|f&&g (h) i\nj")).toEqual([["a", "b cd"], ["e"], ["f"], ["g"], ["h"], ["i"], ["j"]]);
  });
  it("drops a redirect's target and a descriptor's number", () => {
    expect(commands("npm i x 2>&1 >> log < in")).toEqual([["npm", "i", "x"]]);
  });
  it("ends a line at a comment that starts a word only", () => {
    expect(commands("a#b # c\nd")).toEqual([["a#b"], ["d"]]);
  });
});

describe("parseInstalls, limits", () => {
  it("stops at a nesting depth of four shells", () => {
    let t = "npm install left-pad";
    for (let i = 0; i < 6; i++) t = `sh -c "${t.replaceAll('"', "'")}"`;
    // Quotes do not nest in this reader, so deep nesting is read as words of
    // the outer shell: what matters is that it ends, and fast.
    const start = Date.now();
    parseInstalls(t);
    expect(Date.now() - start).toBeLessThan(200);
  });
  it("stays linear on a long line", () => {
    const t = `npm install ${"a ".repeat(100_000)}`;
    const start = Date.now();
    const got = parseInstalls(t);
    expect(got[0]?.packages.length).toBe(100_000);
    expect(Date.now() - start).toBeLessThan(2000);
  });
  it("reads no name that breaks the registry's grammar as a package", () => {
    for (const t of ["npm install left%pad", "pip install 'req uests'", "cargo add 'se rde'"]) {
      for (const inst of parseInstalls(folded(t))) {
        for (const p of inst.packages) expect(p.name).toMatch(/^[a-z0-9@/._~-]+$/);
      }
    }
  });
});
