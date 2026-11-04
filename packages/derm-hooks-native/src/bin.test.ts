import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FALLBACK } from "../bin/fallback.mjs";
import { DIALECTS } from "./hook.ts";
import { fixture, type Fixture } from "./testing.ts";

const BIN = fileURLToPath(new URL("../bin/derm-hook.mjs", import.meta.url));
const run = (args: string[], input: string, env: Record<string, string>) => spawnSync(process.execPath, ["--no-warnings", BIN, ...args], { input, env: { PATH: process.env.PATH ?? "", ...env }, encoding: "utf8", timeout: 20_000 });

let f: Fixture;
beforeAll(async () => {
  f = await fixture();
});
afterAll(async () => {
  await f.close();
});

describe("bin/derm-hook.mjs", () => {
  it("the manifest names the launcher and this package", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { name: string; private: boolean; bin: Record<string, string> };
    expect(pkg.name).toBe("@aetiusgular/derm-hooks-native");
    expect(pkg.private).toBe(true);
    expect(pkg.bin["derm-hook-native"]).toBe("bin/derm-hook.mjs");
  });

  it("covers the same six agents as the dialects, with each one's own deny", () => {
    expect(Object.keys(FALLBACK).sort()).toEqual(Object.keys(DIALECTS).sort());
    for (const [id, dialect] of Object.entries(DIALECTS)) {
      expect((FALLBACK as Record<string, (r: string) => unknown>)[id]?.("derm: x"), id).toEqual(dialect.deny("x"));
    }
  });

  it("an unknown agent exits 2 with the reason on stderr", () => {
    const r = run(["claude"], "{}", f.env());
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/unknown agent "claude"/);
  });

  it("each agent's bad input comes back as that agent's deny, through the real launcher", () => {
    for (const [id, dialect] of Object.entries(DIALECTS)) {
      const r = run([id], "not json", f.env());
      const want = dialect.deny("hook input is not JSON");
      expect({ stdout: r.stdout, stderr: r.stderr, exitCode: r.status }, id).toEqual(want);
    }
  });

  it("an allowed call runs through the launcher end to end (Crush's allow)", () => {
    const r = run(["crush"], JSON.stringify({ event: "PreToolUse", session_id: "s", cwd: f.dir, tool_name: "bash", tool_input: { command: "ls" } }), f.env());
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toMatchObject({ decision: "allow" });
  });
});
