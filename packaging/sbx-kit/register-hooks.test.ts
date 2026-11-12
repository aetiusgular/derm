// The sbx kit's hook registrar (lane T, phase 4). It runs as root in the VM
// on whatever managed settings another kit left, so it must keep every
// other key and hook, add derm's once, and refuse a shape it cannot merge.

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// @ts-expect-error: plain JavaScript, no declarations (it runs on the image's Node with no build step).
import { POST_TIMEOUT, PRE_TIMEOUT, merge, registerFile } from "./register-hooks.mjs";

const NODE = "/usr/bin/node";
const HOOK = "/opt/derm-kit/bin/derm-hook.mjs";
// `fileURLToPath`, not the URL's pathname: on Windows the pathname is
// `/D:/a/...`, which Node read as `D:\D:\a\...` (CI's Windows job).
const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "register-hooks.mjs");

describe("merge", () => {
  it("adds a blocking PreToolUse and a PostToolUse in exec form to empty settings", () => {
    const out = merge({}, NODE, HOOK);
    expect(out.hooks.PreToolUse).toEqual([
      {
        matcher: "*",
        hooks: [{ type: "command", command: NODE, args: ["--no-warnings", HOOK, "pre"], timeout: PRE_TIMEOUT, onFailure: "block" }],
      },
    ]);
    expect(out.hooks.PostToolUse).toEqual([
      { matcher: "*", hooks: [{ type: "command", command: NODE, args: ["--no-warnings", HOOK, "post"], timeout: POST_TIMEOUT }] },
    ]);
  });

  it("keeps every other key and hook another kit wrote", () => {
    const other = { matcher: "Bash", hooks: [{ type: "command", command: "ggshield secret scan" }] };
    const before = {
      permissions: { defaultMode: "bypassPermissions" },
      statusLine: { type: "command", command: "~/.claude/statusline.sh" },
      hooks: { PreToolUse: [other], SessionStart: [{ hooks: [{ type: "command", command: "x" }] }] },
    };
    const snapshot = JSON.parse(JSON.stringify(before));
    const out = merge(before, NODE, HOOK);
    expect(before).toEqual(snapshot);
    expect(out.permissions).toEqual(before.permissions);
    expect(out.statusLine).toEqual(before.statusLine);
    expect(out.hooks.SessionStart).toEqual(before.hooks.SessionStart);
    expect(out.hooks.PreToolUse[0]).toEqual(other);
    expect(out.hooks.PreToolUse).toHaveLength(2);
  });

  it("adds nothing on a second run", () => {
    const once = merge({}, NODE, HOOK);
    expect(merge(once, NODE, HOOK)).toEqual(once);
  });

  it("refuses a shape it cannot merge rather than replace it", () => {
    expect(() => merge([], NODE, HOOK)).toThrow(/not hold a JSON object/);
    expect(() => merge({ hooks: [] }, NODE, HOOK)).toThrow(/"hooks" .* not an object/);
    expect(() => merge({ hooks: { PreToolUse: {} } }, NODE, HOOK)).toThrow(/not a list/);
    expect(() => merge({}, "node", HOOK)).toThrow(/absolute/);
  });
});

describe("registerFile and the command line", () => {
  it("creates the file when it is missing and merges into one that is there", () => {
    const d = mkdtempSync(path.join(tmpdir(), "derm-kit-reg-"));
    try {
      const f = path.join(d, "managed-settings.json");
      registerFile(f, NODE, HOOK);
      expect(JSON.parse(readFileSync(f, "utf8")).hooks.PreToolUse).toHaveLength(1);
      writeFileSync(f, JSON.stringify({ env: { A: "1" } }));
      const r = spawnSync(process.execPath, [SCRIPT, f, NODE, HOOK], { encoding: "utf8" });
      expect(r.status).toBe(0);
      const v = JSON.parse(readFileSync(f, "utf8"));
      expect(v.env).toEqual({ A: "1" });
      expect(v.hooks.PostToolUse).toHaveLength(1);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("exits 1 and leaves a file that is not JSON as it was", () => {
    const d = mkdtempSync(path.join(tmpdir(), "derm-kit-reg-"));
    try {
      const f = path.join(d, "managed-settings.json");
      writeFileSync(f, "{ not json");
      const r = spawnSync(process.execPath, [SCRIPT, f, NODE, HOOK], { encoding: "utf8" });
      expect(r.status).toBe(1);
      expect(r.stderr).toMatch(/is not JSON/);
      expect(readFileSync(f, "utf8")).toBe("{ not json");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});
