import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startFakeDaemon, type FakeDaemon } from "../../derm-claude-plugin/src/testing/fakeDaemon.ts";
import { REDACTED } from "./core/redact.ts";
import { DermBlocked, after, before, defaultDeps, type Deps } from "./kilo.ts";
import * as entry from "./plugin.ts";
import { GateServe } from "./serve/client.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
// Wave 5b (lane 5bC): the decision is `derm gate serve`'s, so these run
// against a derm build (DERM_BIN, else target/debug or target/release).
const ROOT = path.resolve(here, "../../..");
const DERM = process.env.DERM_TEST_NO_BUILD ? undefined : [process.env.DERM_BIN, path.join(ROOT, "target/debug/derm"), path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm.exe"), path.join(ROOT, "target/release/derm.exe")].find((p) => p !== undefined && existsSync(p));
const root = mkdtempSync(path.join(tmpdir(), "derm-kilo-"));
const policyFile = path.join(root, "policy.json");
// The session's folder: the policy sits outside it (case 226).
const project = path.join(root, "project");
mkdirSync(project);
writeFileSync(
  policyFile,
  JSON.stringify({
    version: 1,
    askTimeoutSeconds: 1,
    servers: ["exa", "github", "my-server"],
    rules: [
      { tool: "bash", action: "allow" },
      { tool: "read", action: "allow" },
      { tool: "exa/*", action: "allow" },
      { tool: "github/*", action: "ask" },
      { tool: "webfetch", action: "deny" },
    ],
  }),
);

let daemon: FakeDaemon;
beforeAll(async () => {
  daemon = await startFakeDaemon();
});
afterAll(async () => {
  await daemon.close();
  rmSync(root, { recursive: true, force: true });
});

// One co-process per environment, with derm by its absolute path (case 227).
function deps(extra: Record<string, string> = {}, env?: Record<string, string>): Deps {
  const e = env ?? { DERM_POLICY: policyFile, ...daemon.env(), ...extra };
  const s = new GateServe({ agent: "kilo", env: e, cwd: () => project, trusted: () => true, locate: () => ({ path: DERM as string }) });
  return { ...defaultDeps(e), serve: () => s };
}
const call = (tool: string) => ({ tool, sessionID: "ses_1", callID: `call_${Math.random().toString(36).slice(2)}` });

describe.runIf(DERM !== undefined)("tool.execute.before (needs a derm build)", () => {
  it("lets an allowed call through and records it", async () => {
    const before0 = daemon.events().length;
    await expect(before(call("bash"), { args: { command: "ls" } }, deps())).resolves.toBeUndefined();
    expect(daemon.events().slice(before0)[0]).toMatchObject({ harness: "kilo", kind: "approval", detail: { decision: "allow", tool: "bash" } });
  });
  it("throws to block a denied call, and on the reject list", async () => {
    await expect(before(call("webfetch"), { args: { url: "https://x" } }, deps())).rejects.toBeInstanceOf(DermBlocked);
    await expect(before(call("bash"), { args: { command: "export CHATGPT_BASE_URL=http://x" } }, deps())).rejects.toThrow("derm: reject list: chatgpt_base_url");
  });
  it("an ask is the approver's yes, else a throw (contract section 5)", async () => {
    daemon.setApprove("yes");
    await expect(before(call("github_create_issue"), { args: {} }, deps())).resolves.toBeUndefined();
    expect(daemon.approvals().at(-1)).toMatchObject({ harness: "kilo", tool: "github/create_issue", chat: "ses_1" });
    for (const b of ["no", "none", "timeout", "close"] as const) {
      daemon.setApprove(b);
      await expect(before(call("github_create_issue"), { args: {} }, deps()), b).rejects.toBeInstanceOf(DermBlocked);
    }
    await expect(before(call("github_create_issue"), { args: {} }, deps({}, { DERM_POLICY: policyFile, DERM_DAEMON_SOCKET: path.join(root, "absent.sock") }))).rejects.toThrow("not reachable");
  });
  it("redacts in place, so the tool runs with the redacted object", async () => {
    const args = { query: "q", api_key: "abc", nested: { url: "https://h/?token=zz9" } };
    const output = { args };
    await before(call("exa_search"), output, deps());
    expect(output.args).toBe(args);
    expect(args).toEqual({ query: "q", api_key: REDACTED, nested: { url: `https://h/?token=${REDACTED}` } });
  });
  it("fails closed on bad input", async () => {
    await expect(before({} as never, { args: {} }, deps())).rejects.toBeInstanceOf(DermBlocked);
    // A shell call with no args serializes to "{}", which the matcher cannot read: ask, then deny.
    daemon.setApprove("none");
    await expect(before(call("bash"), undefined as never, deps())).rejects.toBeInstanceOf(DermBlocked);
    const broken = { ...deps(), serve: () => { throw new Error("boom"); } };
    await expect(before(call("bash"), { args: {} }, broken)).rejects.toThrow("derm: hook error: boom");
  });
});

describe.runIf(DERM !== undefined)("Kilo's control files (needs a derm build)", () => {
  it("an allowed call that names Kilo's config or plugin folders asks, so it is denied with no approver", async () => {
    daemon.setApprove("none");
    for (const command of ["cp evil.ts /home/u/.config/kilo/plugin/", "echo x > kilo.json", "mkdir -p .kilo/plugin", "export KILO_PURE=1", "cat .kilocode/plugin/x.ts"]) {
      await expect(before(call("bash"), { args: { command } }, deps()), command).rejects.toThrow("control file");
    }
    daemon.setApprove("yes");
    await expect(before(call("bash"), { args: { command: "cat kilo.json" } }, deps())).resolves.toBeUndefined();
    daemon.setApprove("none");
  });
});

describe.runIf(DERM !== undefined)("tool.execute.after (needs a derm build)", () => {
  it("redacts a built-in tool's output and metadata in place", async () => {
    const out = { title: "bash", output: "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789", metadata: { output: "password=hunter2", exit: 0 } };
    await after({ ...call("bash"), args: {} }, out, deps());
    expect(out.output).toBe(`TOKEN=${REDACTED}`);
    expect(out.metadata).toEqual({ output: `password=${REDACTED}`, exit: 0 });
  });
  it("redacts an MCP result's text content in place", async () => {
    const content = [{ type: "text", text: "secret: s3cr3t" }];
    const out = { content };
    await after({ ...call("exa_search"), args: {} }, out, deps());
    expect(out.content).toBe(content);
    expect(content[0]?.text).toBe(`secret: ${REDACTED}`);
  });
  it("never throws", async () => {
    await expect(after(undefined as never, null, deps())).resolves.toBeUndefined();
  });
});

describe("plugin files", () => {
  it("the entry exports only the v1 default {id, server}, and server returns the two hooks", async () => {
    expect(Object.keys(entry)).toEqual(["default"]);
    expect(entry.default.id).toBe("derm");
    const hooks = await entry.default.server();
    expect(Object.keys(hooks).sort()).toEqual(["tool.execute.after", "tool.execute.before"]);
  });
  it.runIf(DERM !== undefined)("MCP names keep `-` in Kilo (sanitize keeps [a-zA-Z0-9_-]); the server still splits (needs a derm build)", async () => {
    const policy = path.join(root, "dash.json");
    writeFileSync(policy, JSON.stringify({ version: 1, servers: ["my-server"], rules: [{ tool: "my_server/*", action: "deny" }] }));
    await expect(before(call("my-server_do-it"), { args: {} }, deps({}, { DERM_POLICY: policy, DERM_DAEMON_SOCKET: path.join(root, "absent.sock") }))).rejects.toThrow("derm: rule my_server/*");
  });
  it("the package has no engines.opencode and imports no plugin SDK (Kilo would skip or install it)", () => {
    const pkg = JSON.parse(readFileSync(path.join(here, "..", "package.json"), "utf8"));
    expect(pkg.engines?.opencode).toBeUndefined();
    for (const f of ["plugin.ts", "kilo.ts", "control.ts"]) expect(readFileSync(path.join(here, f), "utf8")).not.toMatch(/from "@(opencode-ai|kilocode)\//);
  });
  it("the core copy is byte-identical to the canonical one", () => {
    const script = path.join(here, "..", "..", "derm-claude-plugin", "scripts", "sync-core.mjs");
    expect(() => execFileSync(process.execPath, [script, "--check"], { encoding: "utf8" })).not.toThrow();
  });
});

// Lane X's request 7 (integration w5, continue): the gate posts an
// `install.call` record for an install, beside its decision.
describe.runIf(DERM !== undefined)("install records (needs a derm build)", () => {
  it("posts install.call beside the decision", async () => {
    const n = daemon.events().length;
    await before({ ...call("bash"), callID: "call_inst1" }, { args: { command: "npm install left-pad@1.3.0" } }, deps()).catch(() => undefined);
    const ev = daemon.events().slice(n);
    const recs = ev.filter((e) => e.kind === "install.call") as { detail: Record<string, unknown>; harness: string }[];
    expect(recs).toHaveLength(1);
    expect(recs[0]?.harness).toBe("kilo");
    expect(recs[0]?.detail).toMatchObject({ manager: "npm", form: "add", packages: [{ name: "left-pad", version: "1.3.0", ecosystem: "npm" }], trust: "client" });
    const decision = (ev.find((e) => e.kind === "approval") as { detail: { decision: string } } | undefined)?.detail.decision;
    expect(recs[0]?.detail.decision).toBe(decision);
    expect(recs[0]?.detail.toolUseId).toBe("call_inst1");
  });
});

// Case 228: no co-process, no call. Runs with or without a derm build.
describe("a co-process that is not running", () => {
  it("blocks every call and says why, and blocks after a crash until it starts again", async () => {
    const none: Deps = { env: {}, serve: () => new GateServe({ agent: "kilo", env: {}, cwd: () => project, trusted: () => true, locate: () => ({ problem: "no derm to run: DERM_BIN is not set" }) }) };
    await expect(before(call("bash"), { args: { command: "ls" } }, none)).rejects.toThrow(/derm: the derm gate co-process is not running \(no derm to run/);
    const dead: Deps = {
      env: {},
      serve: () => new GateServe({ agent: "kilo", env: {}, cwd: () => project, trusted: () => true, locate: () => ({ path: process.execPath }), spawn: () => spawn(process.execPath, ["-e", "process.exit(3)"], { stdio: ["pipe", "pipe", "pipe"] }) }),
    };
    await expect(before(call("read"), { args: {} }, dead)).rejects.toBeInstanceOf(DermBlocked);
  });
  it("after() never throws without one", async () => {
    const none: Deps = { env: {}, serve: () => { throw new Error("no co-process"); } };
    await expect(after({ ...call("bash"), args: {} }, { output: "x" }, none)).resolves.toBeUndefined();
  });
  it("the client copy is byte-identical to derm-pi's canonical one", () => {
    expect(readFileSync(path.join(here, "serve", "client.ts"), "utf8")).toBe(readFileSync(path.join(ROOT, "packages", "derm-pi", "src", "serve", "client.ts"), "utf8"));
  });
});
