import { readdirSync, readFileSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import plugin, { description, type AmpLike } from "./index.ts";

const here = path.dirname(fileURLToPath(import.meta.url));

/** Every .ts file the plugin folder holds when copied: src/ without tests. */
function shipped(dir = here): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) out.push(...shipped(p));
    else if (name.endsWith(".ts") && !name.endsWith(".test.ts")) out.push(p);
  }
  return out;
}

describe("the plugin entry", () => {
  it("registers tool.call and tool.result and reads no file when it loads (case 46)", () => {
    // In a fresh Node, with every fs read and stat counted through the
    // built-in module itself (syncBuiltinESMExports), so the named imports in
    // src/core see the counters too; counted from after the import (Node's own
    // loader reads the module files) to the end of the entry's call.
    const script = [
      'import fs from "node:fs"; import { syncBuiltinESMExports } from "node:module";',
      "const seen = []; let counting = false;",
      'for (const k of ["readFileSync","openSync","statSync","lstatSync","readdirSync","existsSync","realpathSync","fstatSync","readSync"]) { const f = fs[k]; fs[k] = (...a) => { if (counting) seen.push(k); return f(...a); }; }',
      "syncBuiltinESMExports();",
      `const mod = await import(${JSON.stringify(new URL("./index.ts", import.meta.url).href)});`,
      "counting = true; const names = []; mod.default({ on: (n) => names.push(n), helpers: {}, system: { workspaceRoot: null } });",
      "process.stdout.write(JSON.stringify({ names, seen }));",
    ].join("\n");
    const out = JSON.parse(execFileSync(process.execPath, ["--no-warnings", "--input-type=module", "-e", script], { encoding: "utf8", env: { ...process.env, DERM_POLICY: "/nonexistent/derm-policy.json" } }));
    expect(out.names).toEqual(["tool.call", "tool.result"]);
    expect(out.seen).toEqual([]);
  });
  it("uses Amp's shell helper and workspace root when it has them", async () => {
    const handlers = new Map<string, (e: unknown, c: unknown) => Promise<unknown>>();
    const shellCommandFromToolCall = vi.fn(() => ({ command: "export ANTHROPIC_BASE_URL=http://x" }));
    plugin({
      on: (name, h) => handlers.set(name, h as never),
      helpers: { shellCommandFromToolCall, filePathFromURI: () => "/nonexistent-derm-workspace" },
      system: { workspaceRoot: { toString: () => "file:///nonexistent-derm-workspace" } },
    });
    const out = await handlers.get("tool.call")?.({ toolUseID: "t1", tool: "Bash", input: { cmd: "export ANTHROPIC_BASE_URL=http://x" }, thread: { id: "T-1" } }, { ui: { confirm: async () => true } });
    expect(shellCommandFromToolCall).toHaveBeenCalledOnce();
    expect(out).toMatchObject({ action: "reject-and-continue", message: "derm: reject list: anthropic_base_url" });
  });
  it("exports a short static description, as Amp asks", () => {
    expect(description.length).toBeLessThanOrEqual(300);
    expect(readFileSync(path.join(here, "index.ts"), "utf8")).toMatch(/export const description = "[^"`$]+";/);
  });
});

describe("the plugin folder is copied whole (Amp loads only what resolves inside it)", () => {
  it("imports only node: built-ins and relative files inside src/", () => {
    for (const file of shipped()) {
      const text = readFileSync(file, "utf8");
      for (const m of text.matchAll(/^\s*(?:import|export)\s[^;]*?from\s+"([^"]+)"/gms)) {
        const spec = m[1] as string;
        if (spec.startsWith("node:")) continue;
        expect(spec.startsWith("./") || spec.startsWith("../"), `${path.relative(here, file)}: ${spec}`).toBe(true);
        const target = path.resolve(path.dirname(file), spec);
        expect(target.startsWith(`${here}${path.sep}`), `${path.relative(here, file)}: ${spec}`).toBe(true);
      }
    }
  });
  it("ships no test helpers", () => {
    for (const file of shipped()) expect(readFileSync(file, "utf8")).not.toMatch(/fakeDaemon|vitest/);
  });
});
