// Amp on `derm gate serve` (serve.ts; fix pass 6, note BE section 3.3),
// against a derm build (DERM_BIN, else target/debug or target/release), with
// the fake daemon for the approver, the records and taint. The path is off
// in index.ts until BBR-13's real Amp run; these tests run it directly.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { startFakeDaemon, type FakeDaemon } from "../../derm-claude-plugin/src/testing/fakeDaemon.ts";
import type { HandlerContext, ToolCallEvent } from "./amp.ts";
import { REDACTED } from "./core/redact.ts";
import { onToolCallServe, onToolResultServe, serveOn, type ServeDeps } from "./serve.ts";
import { GateServe } from "./serve/client.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, "../../..");
const DERM = process.env.DERM_TEST_NO_BUILD ? undefined : [process.env.DERM_BIN, path.join(ROOT, "target/debug/derm"), path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm.exe"), path.join(ROOT, "target/release/derm.exe")].find((p) => p !== undefined && existsSync(p));
const root = mkdtempSync(path.join(tmpdir(), "derm-amp-serve-"));
const policyFile = path.join(root, "policy.json");
// The session's folder: the policy sits outside it (case 226).
const project = path.join(root, "project");
mkdirSync(project);
writeFileSync(
  policyFile,
  JSON.stringify({
    version: 1,
    askTimeoutSeconds: 1,
    servers: ["exa", "github"],
    rules: [
      { tool: "bash", action: "allow" },
      { tool: "read", action: "allow" },
      { tool: "edit_file", action: "allow" },
      { tool: "exa/*", action: "allow" },
      { tool: "github/*", action: "ask" },
      { tool: "read_web_page", action: "allow" },
      { tool: "web_search", action: "deny" },
    ],
  }),
);

/** The co-processes the tests start, ended before the folder is removed. */
const live: GateServe[] = [];
let daemon: FakeDaemon;
beforeAll(async () => {
  daemon = await startFakeDaemon();
});
beforeEach(() => daemon.resetTaint());
afterAll(async () => {
  // Every co-process ends before its folder goes: on Windows a running
  // process holds its current folder (fix pass 7).
  await Promise.all(live.map((s) => s.closeAndWait()));
  await daemon.close();
  rmSync(root, { recursive: true, force: true });
});

const made: GateServe[] = [];
afterAll(() => {
  for (const s of made) s.close();
});
function deps(extra: Record<string, string> = {}, env?: Record<string, string>, more: Partial<ServeDeps> = {}): ServeDeps {
  const e = env ?? { DERM_POLICY: policyFile, ...daemon.env(), ...extra };
  const s = new GateServe({ agent: "amp", env: e, cwd: () => project, trusted: () => true, locate: () => ({ path: DERM as string }) });
  live.push(s);
  made.push(s);
  return { env: e, serve: () => s, ...more };
}
let n = 0;
const ev = (tool: string, input: Record<string, unknown> = {}): ToolCallEvent => ({ toolUseID: `toolu_s${++n}`, tool, input, thread: { id: "T-serve" } });
const ui = (answer: boolean | "unavailable"): HandlerContext & { asked: unknown[] } => {
  const asked: unknown[] = [];
  return {
    asked,
    ui: {
      confirm: (o) => {
        asked.push(o);
        if (answer === "unavailable") return Promise.reject(Object.assign(new Error("no UI"), { code: "PLUGIN_UI_NOT_AVAILABLE" }));
        return Promise.resolve(answer);
      },
    },
  };
};
const settle = () => new Promise((r) => setTimeout(r, 100));

describe("the switch", () => {
  it("is on only for DERM_AMP_GATE_SERVE=1", () => {
    expect(serveOn({})).toBe(false);
    for (const v of ["0", "true", "yes", "", "11"]) expect(serveOn({ DERM_AMP_GATE_SERVE: v }), v).toBe(false);
    expect(serveOn({ DERM_AMP_GATE_SERVE: "1" })).toBe(true);
    expect(serveOn({ DERM_AMP_GATE_SERVE: " 1\n" })).toBe(true);
  });
  it("the client copy is byte-identical to derm-pi's canonical one", () => {
    expect(readFileSync(path.join(here, "serve", "client.ts"), "utf8")).toBe(readFileSync(path.join(ROOT, "packages", "derm-pi", "src", "serve", "client.ts"), "utf8"));
  });
});

describe.runIf(DERM !== undefined)("tool.call on derm gate serve (needs a derm build)", () => {
  it("allows an allowed shell call in Amp's shape and records it once, as amp's", async () => {
    const before0 = daemon.events().length;
    const e = ev("Bash", { cmd: "ls" });
    expect(await onToolCallServe(e, ui(false), deps())).toEqual({ action: "allow" });
    await settle();
    const mine = daemon.events().slice(before0).filter((x) => x.kind === "approval" && (x.detail as { toolUseId?: string })?.toolUseId === e.toolUseID);
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({ harness: "amp", detail: { decision: "allow", tool: "bash" } });
  });
  it("rejects a deny and the reject list in the reject-and-continue shape, never error (case 79)", async () => {
    expect(await onToolCallServe(ev("web_search", { query: "q" }), ui(true), deps())).toMatchObject({ action: "reject-and-continue", message: expect.stringMatching(/^derm: /) });
    expect(await onToolCallServe(ev("shell_command", { command: "export ANTHROPIC_BASE_URL=http://x" }), ui(true), deps())).toMatchObject({ action: "reject-and-continue", message: "derm: reject list: anthropic_base_url" });
  });
  it("uses Amp's shell helper, and refuses two different commands in one input", async () => {
    let used = 0;
    const d = deps({}, undefined, { shellCommand: () => (used++, { command: "export ANTHROPIC_BASE_URL=http://x" }) });
    expect(await onToolCallServe(ev("Bash", { cmd: "export ANTHROPIC_BASE_URL=http://x" }), ui(true), d)).toMatchObject({ message: "derm: reject list: anthropic_base_url" });
    expect(used).toBe(1);
    // Amp's reading must agree with the input (amp.ts shellCommandOf).
    expect(await onToolCallServe(ev("Bash", { cmd: "ls" }), ui(true), d)).toMatchObject({ message: expect.stringMatching(/differs from its input/) });
    expect(await onToolCallServe(ev("Bash", { cmd: "ls", command: "rm -rf x" }), ui(true), deps())).toMatchObject({ action: "reject-and-continue", message: expect.stringMatching(/two different commands/) });
  });
  it("an Amp control file asks, from derm-core's list", async () => {
    daemon.setApprove("no");
    expect(await onToolCallServe(ev("Bash", { cmd: "cp x ~/.config/amp/plugins/y.ts" }), ui(false), deps())).toMatchObject({ action: "reject-and-continue" });
    expect(daemon.approvals().at(-1)).toMatchObject({ harness: "amp", tool: "bash" });
  });
  it("an ask goes to the approver, then, with none, to Amp's own dialog", async () => {
    daemon.setApprove("yes");
    expect(await onToolCallServe(ev("mcp__github__create_issue", {}), ui(false), deps())).toEqual({ action: "allow" });
    expect(daemon.approvals().at(-1)).toMatchObject({ harness: "amp", tool: "github/create_issue", chat: "T-serve" });
    daemon.setApprove("no");
    expect(await onToolCallServe(ev("mcp__github__create_issue", {}), ui(true), deps())).toMatchObject({ action: "reject-and-continue" });
    daemon.setApprove("none");
    const yes = ui(true);
    expect(await onToolCallServe(ev("mcp__github__create_issue", {}), yes, deps())).toEqual({ action: "allow" });
    expect(yes.asked).toHaveLength(1);
    expect(yes.asked[0]).toMatchObject({ title: "derm: allow github/create_issue?" });
    expect(await onToolCallServe(ev("mcp__github__create_issue", {}), ui(false), deps())).toMatchObject({ action: "reject-and-continue", message: expect.stringMatching(/declined in Amp/) });
    expect(await onToolCallServe(ev("mcp__github__create_issue", {}), ui("unavailable"), deps({}, undefined, { uiUnavailable: () => true }))).toMatchObject({ message: expect.stringMatching(/no one to ask/) });
  });
  it("rewrites a secret only where the input leaves as it is; elsewhere it asks", async () => {
    const out = await onToolCallServe(ev("mcp__exa__search", { query: "q", api_key: "abc" }), ui(false), deps());
    expect(out).toEqual({ action: "modify", input: { query: "q", api_key: REDACTED } });
    daemon.setApprove("none");
    const asked = ui(false);
    expect(await onToolCallServe(ev("edit_file", { path: "a.txt", content: "api_key=abcdefghijklmnop1234" }), asked, deps())).toMatchObject({ action: "reject-and-continue" });
  });
  it("a fetch keeps the chat's taint in the daemon (one decide path, case 229)", async () => {
    const before0 = daemon.taints().length;
    expect(await onToolCallServe(ev("read_web_page", { url: "https://example.com/" }), ui(false), deps())).toMatchObject({ action: expect.any(String) });
    const sent = daemon.taints().slice(before0);
    expect(sent.length).toBeGreaterThan(0);
  });
  it("fails closed with no co-process, and on bad input", async () => {
    const none: ServeDeps = { env: {}, serve: () => new GateServe({ agent: "amp", env: {}, cwd: () => project, trusted: () => true, locate: () => ({ problem: "no derm to run: DERM_BIN is not set" }) }) };
    expect(await onToolCallServe(ev("read", { path: "a" }), ui(true), none)).toMatchObject({ action: "reject-and-continue", message: expect.stringMatching(/co-process is not running/) });
    expect(await onToolCallServe({} as never, ui(true), deps())).toMatchObject({ action: "reject-and-continue" });
    const broken: ServeDeps = { env: {}, serve: () => { throw new Error("boom"); } };
    expect(await onToolCallServe(ev("read", {}), ui(true), broken)).toMatchObject({ message: "derm: hook error: boom" });
  });
});

describe.runIf(DERM !== undefined)("tool.result on derm gate serve (needs a derm build)", () => {
  it("redacts the output through the co-process and records the call", async () => {
    const before0 = daemon.events().length;
    const e = ev("Bash", { cmd: "env" });
    const out = await onToolResultServe({ ...e, status: "done", output: "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789" }, deps());
    expect(out).toMatchObject({ status: "done" });
    expect(JSON.stringify(out)).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz0123456789");
    await settle();
    expect(daemon.events().slice(before0).some((x) => x.kind === "tool.call" && x.harness === "amp")).toBe(true);
  });
  it("leaves a clean result alone", async () => {
    expect(await onToolResultServe({ ...ev("read", {}), status: "done", output: "hello" }, deps())).toBeUndefined();
  });
  it("still redacts with no co-process, in TypeScript", async () => {
    const none: ServeDeps = { env: {}, serve: () => { throw new Error("no co-process"); } };
    const out = await onToolResultServe({ ...ev("read", {}), status: "done", output: { text: "password=hunter2" } }, none);
    expect(JSON.stringify(out)).not.toContain("hunter2");
  });
});
