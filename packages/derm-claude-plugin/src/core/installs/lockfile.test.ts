// The lockfile readers against lockfiles the managers wrote
// (contracts/fixtures/installs/lockfiles/). The expected entries were made
// without these readers (expected.json's comment says how).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseLockfile, type LockKind } from "./lockfile.ts";

const dir = new URL("../../../../../contracts/fixtures/installs/lockfiles/", import.meta.url);
const expected = JSON.parse(readFileSync(new URL("expected.json", dir), "utf8")) as { files: Record<string, { kind: LockKind; entries: unknown[] }> };

describe("parseLockfile", () => {
  it("reads every fixture lockfile as expected.json says", () => {
    const files = Object.entries(expected.files);
    expect(files.length).toBe(21);
    for (const [file, { kind, entries }] of files) {
      expect([file, parseLockfile(kind, readFileSync(new URL(file, dir), "utf8"))]).toEqual([file, entries]);
    }
  });
  it("gives nothing for text it cannot read, and never throws", () => {
    for (const kind of ["package-lock", "pnpm-lock", "yarn-lock", "bun-lock", "uv-lock", "poetry-lock", "pdm-lock", "pylock", "cargo-lock", "go-sum"] as LockKind[]) {
      for (const text of ["", "{", "null", "[[package]]\nname = 1", "\u0000\u0001", "packages:\n  :\n"]) expect(() => parseLockfile(kind, text)).not.toThrow();
    }
    expect(parseLockfile("package-lock", "{")).toEqual([]);
    expect(parseLockfile("bun-lock", "not json")).toEqual([]);
  });
  it("marks a git or file source as not the registry", () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0", resolved: "git+ssh://git@github.com/u/a.git#abc" }, "node_modules/b": { version: "1.0.0", resolved: "https://registry.npmjs.org/b/-/b-1.0.0.tgz" }, "node_modules/c": { version: "1.0.0", link: true } } });
    expect(parseLockfile("package-lock", lock)).toEqual([
      { name: "a", version: "1.0.0", registry: false },
      { name: "b", version: "1.0.0", registry: true },
    ]);
  });
  it("reads a lockfile v1's nested dependencies", () => {
    const lock = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } }, g: { version: "github:u/g#abc" } } });
    expect(parseLockfile("package-lock", lock)).toEqual([
      { name: "a", version: "1.0.0", registry: true },
      { name: "b", version: "2.0.0", registry: true },
    ]);
  });
});
