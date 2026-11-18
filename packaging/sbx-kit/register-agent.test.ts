// The sbx kit's registrar for the command-hook agents (Copilot CLI, Droid,
// Cursor, Kiro). It runs as root in the VM on whatever the agent's own kit
// left in its home, so it must write the entry each hook package names,
// keep every other key and hook, add derm's once, and refuse a shape it
// cannot merge. The entries are held equal to the packages' own
// registrations, with the kit's Node by its path in place of `node`.

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// @ts-expect-error: plain JavaScript, no declarations (it runs on the kit's Node with no build step).
import { AGENTS, command, plan, register } from "./register-agent.mjs";
import { registrationFor } from "../../packages/derm-hooks-claude-compat/src/registration.ts";

const NODE = "/opt/derm-kit/node";
const HOOK = "/opt/derm-kit/bin/derm-hook.mjs";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.join(HERE, "register-agent.mjs");
const NATIVE = path.join(HERE, "..", "..", "packages", "derm-hooks-native");

/** Every `node --no-warnings` at the start of a string becomes the kit's Node. */
function withKitNode(v: unknown): unknown {
  if (typeof v === "string") return v.replace(/^node --no-warnings /, `${NODE} --no-warnings `);
  if (Array.isArray(v)) return v.map(withKitNode);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, withKitNode(x)]));
  return v;
}

// The registrar runs in a Linux VM and joins with "/" whatever the host is,
// so the files it names are spelled that way here too (Windows opens them
// either way).
function home(): string {
  return mkdtempSync(path.join(tmpdir(), "derm-kit-agent-"));
}

describe("the entries are the hook packages' own", () => {
  it("lists the four agents", () => {
    expect([...AGENTS].sort()).toEqual(["copilot-cli", "cursor", "droid", "kiro"]);
  });

  it.each(["copilot-cli", "droid"])("%s: derm-hooks-claude-compat's registration", (agent) => {
    const want = registrationFor(agent, HOOK);
    const p = plan(agent, "/home/agent", NODE, HOOK);
    expect(p.file).toBe(want.file.replace(/^~/, "/home/agent"));
    expect(p.shape).toBe(want.shape === "own-file" ? "own" : "merge");
    expect(p.entry).toEqual(withKitNode(want.entry));
    expect(p.mustNotExist).toEqual((want.mustNotExist ?? []).map((f) => f.replace(/^~/, "/home/agent")));
  });

  it.each([
    ["cursor", "cursor/hooks.json", "/home/agent/.cursor/hooks.json", "merge"],
    ["kiro", "kiro/derm.json", "/home/agent/.kiro/hooks/derm.json", "own"],
  ])("%s: derm-hooks-native's registration file", (agent, rel, file, shape) => {
    const text = readFileSync(path.join(NATIVE, "registration", rel), "utf8").replaceAll("<derm-hooks-native>/bin/derm-hook.mjs", HOOK);
    const p = plan(agent, "/home/agent", NODE, HOOK);
    expect(p.file).toBe(file);
    expect(p.shape).toBe(shape);
    expect(p.entry).toEqual(withKitNode(JSON.parse(text)));
  });

  it("refuses a path a shell would read, a relative path and an unknown agent", () => {
    expect(() => command("droid", NODE, '/opt/x"y/hook.mjs')).toThrow(/shell/);
    expect(() => command("droid", "node", HOOK)).toThrow(/absolute/);
    expect(() => command("droid", NODE, "/opt/a b/hook.mjs")).toThrow(/shell/);
    expect(() => plan("codex", "/home/agent", NODE, HOOK)).toThrow(/no registration/);
    expect(() => plan("droid", "home", NODE, HOOK)).toThrow(/absolute/);
  });
});

describe("register", () => {
  it("writes a file of derm's own, and a second run leaves it as it is", () => {
    const h = home();
    try {
      const wrote = register("copilot-cli", h, NODE, HOOK);
      const file = path.posix.join(h, ".copilot", "hooks", "derm.json");
      expect(wrote).toEqual([file]);
      const first = readFileSync(file, "utf8");
      expect(JSON.parse(first).hooks.preToolUse[0].bash).toBe(`${NODE} --no-warnings "${HOOK}" copilot-cli pre`);
      register("copilot-cli", h, NODE, HOOK);
      expect(readFileSync(file, "utf8")).toBe(first);
    } finally {
      rmSync(h, { recursive: true, force: true });
    }
  });

  it("merges beside what is there: other keys, other hooks, once", () => {
    const h = home();
    try {
      mkdirSync(path.posix.join(h, ".factory"));
      const file = path.posix.join(h, ".factory", "settings.json");
      const other = { matcher: "Bash", hooks: [{ type: "command", command: "/usr/bin/true" }] };
      writeFileSync(file, JSON.stringify({ model: "x", hooks: { PreToolUse: [other], Stop: [other] } }));
      register("droid", h, NODE, HOOK);
      register("droid", h, NODE, HOOK);
      const out = JSON.parse(readFileSync(file, "utf8"));
      expect(out.model).toBe("x");
      expect(out.hooks.Stop).toEqual([other]);
      expect(out.hooks.PreToolUse).toHaveLength(2);
      expect(out.hooks.PreToolUse[0]).toEqual(other);
      expect(out.hooks.PreToolUse[1].hooks[0].command).toBe(`${NODE} --no-warnings "${HOOK}" droid pre`);
    } finally {
      rmSync(h, { recursive: true, force: true });
    }
  });

  it("Cursor: both events, beside another hook, with the file's version kept", () => {
    const h = home();
    try {
      mkdirSync(path.posix.join(h, ".cursor"));
      const file = path.posix.join(h, ".cursor", "hooks.json");
      writeFileSync(file, JSON.stringify({ version: 1, hooks: { preToolUse: [{ type: "command", command: "/x" }], stop: [{ command: "/y" }] } }));
      register("cursor", h, NODE, HOOK);
      register("cursor", h, NODE, HOOK);
      const out = JSON.parse(readFileSync(file, "utf8"));
      expect(out.version).toBe(1);
      expect(out.hooks.stop).toEqual([{ command: "/y" }]);
      expect(out.hooks.preToolUse).toHaveLength(2);
      expect(out.hooks.beforeMCPExecution).toHaveLength(1);
      expect(out.hooks.preToolUse[1]).toEqual({ type: "command", command: `${NODE} --no-warnings "${HOOK}" cursor`, timeout: 120, failClosed: true });
    } finally {
      rmSync(h, { recursive: true, force: true });
    }
  });

  it("refuses a file that would shadow the gate, a file that is not JSON and a shape it cannot merge; nothing is written", () => {
    const h = home();
    try {
      mkdirSync(path.posix.join(h, ".factory"));
      const settings = path.posix.join(h, ".factory", "settings.json");
      writeFileSync(path.posix.join(h, ".factory", "hooks.json"), "{}");
      expect(() => register("droid", h, NODE, HOOK)).toThrow(/hooks\.json.*shadow/);
      expect(existsSync(settings)).toBe(false);
      rmSync(path.posix.join(h, ".factory", "hooks.json"));
      writeFileSync(settings, "not json");
      expect(() => register("droid", h, NODE, HOOK)).toThrow(/not JSON/);
      writeFileSync(settings, JSON.stringify({ hooks: { PreToolUse: {} } }));
      expect(() => register("droid", h, NODE, HOOK)).toThrow(/not a list/);
      expect(readFileSync(settings, "utf8")).toBe(JSON.stringify({ hooks: { PreToolUse: {} } }));
      mkdirSync(path.posix.join(h, ".kiro", "hooks"), { recursive: true });
      writeFileSync(path.posix.join(h, ".kiro", "hooks", "derm.json"), JSON.stringify({ version: "v1", hooks: [] }));
      expect(() => register("kiro", h, NODE, HOOK)).toThrow(/is not derm's/);
    } finally {
      rmSync(h, { recursive: true, force: true });
    }
  });

  it("as a program: prints the files it wrote, and fails with the reason", () => {
    const h = home();
    try {
      const ok = spawnSync(process.execPath, [SCRIPT, "kiro", h, NODE, HOOK], { encoding: "utf8" });
      expect(ok.status).toBe(0);
      expect(ok.stdout.trim()).toBe(path.posix.join(h, ".kiro", "hooks", "derm.json"));
      const bad = spawnSync(process.execPath, [SCRIPT, "codex", h, NODE, HOOK], { encoding: "utf8" });
      expect(bad.status).toBe(1);
      expect(bad.stderr).toMatch(/derm kit: no registration for codex/);
      expect(spawnSync(process.execPath, [SCRIPT], { encoding: "utf8" }).status).toBe(2);
    } finally {
      rmSync(h, { recursive: true, force: true });
    }
  });
});
