import { spawn } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startFakeDaemon, type FakeDaemon } from "../../derm-claude-plugin/src/testing/fakeDaemon.ts";
import { defaultDeps, type Deps } from "./cline.ts";
import { GateServe } from "./serve/client.ts";
import { decisionName, folderProblem, main, PARTIAL_GRACE_MS, parseArgs, parseRequestName, Responder, UNTAKEN_MS } from "./responder.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
// Wave 5b (lane 5bC): the decision is `derm gate serve`'s, so the answers
// need a derm build (DERM_BIN, else target/debug or target/release).
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const DERM = process.env.DERM_TEST_NO_BUILD ? undefined : [process.env.DERM_BIN, path.join(ROOT, "target/debug/derm"), path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm.exe"), path.join(ROOT, "target/release/derm.exe")].find((p) => p !== undefined && existsSync(p));
const root = mkdtempSync(path.join(tmpdir(), "derm-clr-"));
const work = path.join(root, "work");
mkdirSync(work);
const policyFile = path.join(root, "policy.json");
writeFileSync(
  policyFile,
  JSON.stringify({
    version: 1,
    askTimeoutSeconds: 1,
    servers: ["github"],
    rules: [
      { tool: "bash", action: "allow" },
      { tool: "github/*", action: "ask" },
      { tool: "fetch_web_content", action: "deny" },
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

let k = 0;
function folder(): string {
  const d = path.join(root, `cline-approvals-${++k}`);
  mkdirSync(d, { mode: 0o700 });
  chmodSync(d, 0o700);
  return d;
}
/** Writes a request the way Cline 3.0.74 does (tool-approval.ts:54-72): pretty JSON, plain writeFile. */
function request(dir: string, sessionId: string, toolCallId: string, toolName: string, input: unknown, extra: Record<string, unknown> = {}): string {
  const requestId = toolCallId.replace(/[^a-zA-Z0-9._-]+/g, "_");
  const name = `${sessionId}.request.${requestId}.json`;
  writeFileSync(path.join(dir, name), `${JSON.stringify({ requestId, sessionId, createdAt: new Date().toISOString(), toolCallId, toolName, input, iteration: 1, agentId: "agent_1", conversationId: "conv_1", ...extra }, null, 2)}\n`);
  return requestId;
}
function responder(dir: string, opts: { now?: () => number; log?: string[] } = {}): Responder {
  const log = opts.log ?? [];
  const env = { DERM_POLICY: policyFile, ...daemon.env() };
  const s = new GateServe({ agent: "cline", env, cwd: () => work, trusted: () => true, locate: () => ({ path: DERM as string }) });
  const deps: Deps = { ...defaultDeps(env, () => work), serve: () => s };
  return new Responder({ dir, cwd: work, deps, log: (l) => log.push(l), ...(opts.now ? { now: opts.now } : {}) });
}
async function pass(r: Responder): Promise<void> {
  await r.tick();
  await Promise.allSettled(r.pending);
}
function decision(dir: string, sessionId: string, requestId: string): Record<string, unknown> | undefined {
  const p = path.join(dir, decisionName(sessionId, requestId));
  return existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>) : undefined;
}

describe("the folder", () => {
  it("must be absolute, yours alone, a real folder, and outside the session folder", () => {
    const ok = folder();
    expect(folderProblem(ok, work)).toBeUndefined();
    expect(folderProblem("rel/dir", work)).toMatch("not an absolute path");
    expect(folderProblem(path.join(root, "absent"), work)).toMatch("does not exist");
    const open = folder();
    chmodSync(open, 0o755);
    expect(folderProblem(open, work)).toMatch("0700");
    const link = path.join(root, `link-${k}`);
    symlinkSync(ok, link);
    expect(folderProblem(link, work)).toMatch("is a link");
    const file = path.join(root, "plain-file");
    writeFileSync(file, "x");
    expect(folderProblem(file, work)).toMatch("not a folder");
    const inside = path.join(work, "cline-approvals");
    mkdirSync(inside, { mode: 0o700 });
    expect(folderProblem(inside, work)).toMatch("inside the session folder");
  });
});

describe("request names", () => {
  it("splits Cline's name into its session and request ids", () => {
    expect(parseRequestName("1793757838242_ebpm8.request.call_1.json")).toEqual({ sessionId: "1793757838242_ebpm8", requestId: "call_1" });
    expect(parseRequestName("s.request.toolu_01.A-b.json")).toEqual({ sessionId: "s", requestId: "toolu_01.A-b" });
    for (const bad of ["s.decision.r.json", ".request.r.json", "s.request..json", "s.request.r.txt", "s.request.r/x.json", "s x.request.r.json", ".derm-1.tmp"]) {
      expect(parseRequestName(bad), bad).toBeUndefined();
    }
  });
});

describe.runIf(DERM !== undefined)("answers (needs a derm build)", () => {
  it("an allowed call: a decision file Cline reads as yes, 0600, written whole", async () => {
    const dir = folder();
    const rid = request(dir, "s1", "call_1", "run_commands", { commands: ["ls"] });
    await pass(responder(dir));
    expect(decision(dir, "s1", rid)).toEqual({ approved: true });
    expect(lstatSync(path.join(dir, decisionName("s1", rid))).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir).filter((n) => n.endsWith(".tmp"))).toEqual([]);
  });
  it("a denied call and the reject list: approved false with derm's reason", async () => {
    const dir = folder();
    const a = request(dir, "s1", "c1", "fetch_web_content", { url: "https://x" });
    const b = request(dir, "s1", "c2", "run_commands", { commands: ["export CHATGPT_BASE_URL=http://x"] });
    await pass(responder(dir));
    expect(decision(dir, "s1", a)).toEqual({ approved: false, reason: "derm: rule fetch_web_content deny" });
    expect(decision(dir, "s1", b)).toEqual({ approved: false, reason: "derm: reject list: chatgpt_base_url" });
  });
  it("an ask waits on the approver: yes approves, anything else denies", async () => {
    const dir = folder();
    daemon.setApprove("yes");
    const a = request(dir, "s1", "c1", "github__create_issue", { title: "x" });
    await pass(responder(dir));
    expect(decision(dir, "s1", a)).toEqual({ approved: true });
    daemon.setApprove("no");
    const b = request(dir, "s1", "c2", "github__create_issue", { title: "y" });
    await pass(responder(dir));
    expect(decision(dir, "s1", b)).toMatchObject({ approved: false, reason: expect.stringContaining("declined in derm") });
    daemon.setApprove("yes");
  });
  it("answers each request once, and forgets it when Cline takes both files", async () => {
    const dir = folder();
    const rid = request(dir, "s1", "c1", "run_commands", { commands: ["ls"] });
    const r = responder(dir);
    await pass(r);
    rmSync(path.join(dir, decisionName("s1", rid)));
    await pass(r);
    expect(decision(dir, "s1", rid)).toBeUndefined();
    rmSync(path.join(dir, `s1.request.${rid}.json`));
    await pass(r);
    request(dir, "s1", "c1", "fetch_web_content", {});
    await pass(r);
    expect(decision(dir, "s1", rid)).toMatchObject({ approved: false });
  });
  it("a request file still being written is read again, then denied after a grace period", async () => {
    const dir = folder();
    writeFileSync(path.join(dir, "s1.request.c1.json"), '{"requestId": "c1", "sess');
    let now = 1_000;
    const r = responder(dir, { now: () => now });
    await pass(r);
    expect(decision(dir, "s1", "c1")).toBeUndefined();
    now += PARTIAL_GRACE_MS + 1;
    await pass(r);
    expect(decision(dir, "s1", "c1")).toEqual({ approved: false, reason: "derm: the request file does not parse yet" });
  });
  it("a request whose content does not match its name, or that is a link, is denied", async () => {
    const dir = folder();
    request(dir, "s1", "c1", "run_commands", { commands: ["ls"] }, { requestId: "other" });
    const target = path.join(root, `target-${k}.json`);
    writeFileSync(target, JSON.stringify({ requestId: "c2", sessionId: "s1", toolName: "run_commands", input: { commands: ["ls"] } }));
    symlinkSync(target, path.join(dir, "s1.request.c2.json"));
    await pass(responder(dir));
    expect(decision(dir, "s1", "c1")).toEqual({ approved: false, reason: "derm: the request file does not match its name" });
    expect(decision(dir, "s1", "c2")).toEqual({ approved: false, reason: "derm: the request file is a link" });
  });
  it("a decision derm did not write is replaced and recorded as a conflict (case 98)", async () => {
    const dir = folder();
    const rid = request(dir, "s1", "c1", "fetch_web_content", {});
    writeFileSync(path.join(dir, decisionName("s1", rid)), '{"approved": true}');
    const log: string[] = [];
    const before = daemon.events().length;
    await pass(responder(dir, { log }));
    expect(decision(dir, "s1", rid)).toMatchObject({ approved: false });
    expect(log.join("\n")).toContain("replaced a decision derm did not write");
    expect(daemon.events().slice(before).some((e) => (e.detail as { decision?: string }).decision === "conflict")).toBe(true);
  });
  it("stops answering when the folder is opened to others or swapped", async () => {
    const dir = folder();
    const r = responder(dir);
    expect(r.start()).toBeUndefined();
    chmodSync(dir, 0o777);
    request(dir, "s1", "c1", "run_commands", { commands: ["ls"] });
    await pass(r);
    expect(r.stopped).toMatch("0700");
    r.stop();
    expect(decision(dir, "s1", "c1")).toBeUndefined();
    chmodSync(dir, 0o700);
  });
  it("ignores files that are not requests: its own temp files, decisions, others", async () => {
    const dir = folder();
    writeFileSync(path.join(dir, ".derm-x.tmp"), "{}");
    writeFileSync(path.join(dir, "notes.txt"), "x");
    await pass(responder(dir));
    expect(readdirSync(dir).sort()).toEqual([".derm-x.tmp", "notes.txt"]);
  });
});

describe.runIf(DERM !== undefined)("an agent that writes in the folder (review P-S5, P-S8; needs a derm build)", () => {
  it("an answer no Cline takes is removed, so it cannot wait for a real request of the same name", async () => {
    const dir = folder();
    let now = 10_000;
    const r = responder(dir, { now: () => now });
    const rid = request(dir, "s1", "call_1", "run_commands", { commands: ["ls"] });
    await pass(r);
    expect(decision(dir, "s1", rid)).toEqual({ approved: true });
    const before = daemon.events().length;
    now += UNTAKEN_MS + 1;
    await pass(r);
    expect(decision(dir, "s1", rid)).toBeUndefined();
    expect(daemon.events().slice(before).some((e) => String((e.detail as { reason?: string }).reason).includes("not taken"))).toBe(true);
  });
  it("a request rewritten in place is answered again, for what it says now", async () => {
    const dir = folder();
    const r = responder(dir);
    const rid = request(dir, "s1", "c1", "run_commands", { commands: ["ls"] });
    await pass(r);
    expect(decision(dir, "s1", rid)).toEqual({ approved: true });
    rmSync(path.join(dir, decisionName("s1", rid)));
    await new Promise((res) => setTimeout(res, 20));
    request(dir, "s1", "c1", "fetch_web_content", { url: "https://x/with-a-longer-body" });
    await pass(r);
    expect(decision(dir, "s1", rid)).toEqual({ approved: false, reason: "derm: rule fetch_web_content deny" });
  });
  it("a request that goes while derm waits on the approver gets no answer, and a conflict is recorded", async () => {
    const dir = folder();
    daemon.setApprove("hang");
    const r = responder(dir);
    const rid = request(dir, "s1", "c1", "github__create_issue", { title: "x" });
    const before = daemon.events().length;
    const ticking = pass(r);
    await new Promise((res) => setTimeout(res, 200));
    rmSync(path.join(dir, `s1.request.${rid}.json`));
    await ticking;
    expect(decision(dir, "s1", rid)).toBeUndefined();
    expect(daemon.events().slice(before).some((e) => String((e.detail as { reason?: string }).reason).includes("gone before derm answered"))).toBe(true);
    daemon.setApprove("yes");
  }, 20_000);
  it("stops when the folder is swapped for another at the same path", async () => {
    const dir = folder();
    const r = responder(dir);
    expect(r.start()).toBeUndefined();
    renameSync(dir, `${dir}-moved`);
    mkdirSync(dir, { mode: 0o700 });
    chmodSync(dir, 0o700);
    request(dir, "s1", "c1", "run_commands", { commands: ["ls"] });
    await pass(r);
    r.stop("test");
    expect(decision(dir, "s1", "c1")).toBeUndefined();
  });
  it("never takes the chat from a request file", async () => {
    const dir = folder();
    const rid = request(dir, "s1", "c1", "fetch_web_content", {}, { conversationId: "forged-chat" });
    writeFileSync(path.join(dir, decisionName("s1", rid)), '{"approved": true}');
    const before = daemon.events().length;
    await pass(responder(dir));
    for (const e of daemon.events().slice(before)) expect(e.chatId).not.toBe("forged-chat");
  });
});

describe("the command", () => {
  it("parses its arguments and refuses anything else", () => {
    expect(parseArgs(["--dir", "/d", "--cwd", "/w", "--until-pid", "42"])).toEqual({ dir: "/d", cwd: "/w", untilPid: 42 });
    expect(parseArgs(["--until-pid", "0"]).error).toBeDefined();
    expect(parseArgs(["--dir"]).error).toBeDefined();
    expect(parseArgs(["--evil"]).error).toBeDefined();
  });
  it("exits 1 when it has no folder or a bad one", async () => {
    expect(await main([], {})).toBe(1);
    expect(await main(["--dir", path.join(root, "nope")], {})).toBe(1);
  });
  it.runIf(DERM !== undefined)("runs from its launcher, answers, and stops on SIGTERM with 0 (needs a derm build)", async () => {
    const dir = folder();
    const child = spawn(process.execPath, ["--no-warnings", path.join(here, "../bin/derm-cline-approvals.mjs"), "--dir", dir, "--cwd", work], {
      // derm by its absolute path: the responder never looks it up on PATH (case 227).
      env: { ...process.env, DERM_POLICY: policyFile, ...daemon.env(), DERM_BIN: DERM ?? "" },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let err = "";
    child.stderr.on("data", (d) => (err += d));
    const rid = request(dir, "s9", "c9", "run_commands", { commands: ["echo derm-not-logged"] });
    const deadline = Date.now() + 10_000;
    while (decision(dir, "s9", rid) === undefined && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    expect(decision(dir, "s9", rid)).toEqual({ approved: true });
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((r) => child.on("exit", r));
    expect(code, err).toBe(0);
    expect(err).toContain("answering in");
    expect(err).not.toContain("derm-not-logged");
  });
  it("stops by itself when the agent it was started for exits", async () => {
    const dir = folder();
    const agent = spawn(process.execPath, ["-e", "setTimeout(() => {}, 300)"]);
    const child = spawn(process.execPath, ["--no-warnings", path.join(here, "../bin/derm-cline-approvals.mjs"), "--dir", dir, "--cwd", work, "--until-pid", String(agent.pid)], { stdio: "ignore" });
    const code = await new Promise<number | null>((r) => child.on("exit", r));
    expect(code).toBe(0);
  });
});
