import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DIALECTS } from "./agents.ts";
import { GATE_TIMEOUT_SECONDS, hookCommand, registrationFor } from "./registration.ts";
import { HOOK_ASK_CAP_SECONDS } from "./core/gate.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.resolve(here, "..", "..", "..", "contracts", "fixtures", "hook-dialects");
const HOOK = path.resolve(here, "..", "bin", "derm-hook.mjs");
const AGENTS = Object.keys(DIALECTS);

/** The keys of an object and of the first item of every array under it, as paths. */
function shape(v: unknown, at = ""): string[] {
  if (Array.isArray(v)) return v.length ? shape(v[0], `${at}[]`) : [`${at}[]`];
  if (typeof v === "object" && v !== null) return Object.entries(v).flatMap(([k, x]) => [`${at}.${k}`, ...shape(x, `${at}.${k}`)]);
  return [];
}

describe("registration", () => {
  it("covers every dialect", () => {
    for (const agent of AGENTS) expect(registrationFor(agent, HOOK).agent).toBe(agent);
    expect(() => registrationFor("nope", HOOK)).toThrow();
  });

  it("waits longer than the gate's longest ask, so a slow ask is not a timeout (case 70)", () => {
    expect(GATE_TIMEOUT_SECONDS).toBeGreaterThan(HOOK_ASK_CAP_SECONDS + 10);
  });

  it.each(AGENTS.filter((a) => registrationFor(a, HOOK).format === "json"))("%s: the entry has the fixture's structure, with every tool matched", (agent) => {
    const reg = registrationFor(agent, HOOK);
    const fixture = JSON.parse(readFileSync(path.join(FIXTURES, agent, "register.json"), "utf8"));
    const want = new Set(shape(fixture).filter((p) => !/\.(name|description|sequential|matcher|failClosed|metadata)/.test(p)));
    const got = new Set(shape(reg.entry));
    for (const p of want) expect(got, `${agent}: ${p}`).toContain(p);
    const text = JSON.stringify(reg.entry);
    expect(text).toContain(`${agent} pre`);
    expect(text).not.toMatch(/"matcher":"(Bash|Execute|shell|launch-process|bash)"/);
  });

  it("Kimi: exactly the keys Kimi accepts, since a fifth makes it drop the whole config", () => {
    const text = registrationFor("kimi", HOOK).entry as string;
    const keys = text.split("\n").filter((l) => l.includes("=")).map((l) => l.split("=")[0]!.trim());
    for (const k of keys) expect(["event", "matcher", "command", "timeout"]).toContain(k);
    expect(text).toMatch(/^\[\[hooks\]\]\n/);
    expect(text).toContain(`timeout = ${GATE_TIMEOUT_SECONDS}`);
  });

  it("sets the fail-closed switch where the agent has one", () => {
    for (const agent of ["command-code", "grok"]) expect(JSON.stringify(registrationFor(agent, HOOK).entry)).toContain('"failClosed":true');
  });

  it("Grok: turns its Claude and Cursor hook imports off, so derm's gate does not run twice (case 75)", () => {
    const also = registrationFor("grok", HOOK).also ?? [];
    expect(also.map((a) => a.text).join("\n")).toMatch(/\[compat\.claude\]\nhooks = false[\s\S]*\[compat\.cursor\]\nhooks = false/);
  });

  it("Droid: never its hooks.json", () => {
    const reg = registrationFor("droid", HOOK);
    expect(reg.file).toBe("~/.factory/settings.json");
    expect(reg.mustNotExist).toEqual(["~/.factory/hooks.json", "~/.factory/hooks/hooks.json"]);
  });

  it("refuses a hook path a shell would read differently", () => {
    for (const bad of ["relative/derm-hook.mjs", '/a"b/x.mjs', "/a$HOME/x.mjs", "/a`id`/x.mjs", "/a\\b/x.mjs"]) expect(() => hookCommand("grok", bad), bad).toThrow();
  });

  it("the command line it gives runs the hook (a deny with no policy rule and no daemon)", () => {
    const cmd = hookCommand("kimi", HOOK);
    const r = spawnSync("/bin/sh", ["-c", cmd], {
      input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }),
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "", HOME: "/nonexistent", DERM_POLICY: "/nonexistent/policy.json", DERM_DAEMON_SOCKET: "/nonexistent/daemon.sock" },
    });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/^derm: /);
  });
});
