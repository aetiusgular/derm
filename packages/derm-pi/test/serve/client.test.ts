// The co-process client (src/serve/client.ts): the route to derm (case 227),
// failing closed and starting again (case 228), and the real `derm gate
// serve` when a build is there (target/debug/derm, or DERM_BIN).

import { spawn, type SpawnOptions } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { approve, decide, GateServe, installCandidates, locateDerm, record, redact, refuseCandidate, ServeUnavailable, sharedServe, type LocateDeps } from "../../src/serve/client.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const FAKE = path.join(here, "fake-serve.mjs");
const ROOT = path.resolve(here, "../../../..");
const unix = process.platform !== "win32";
const uid = typeof process.getuid === "function" ? process.getuid() : -1;

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function scratch(): string {
  const d = realpathSync(mkdtempSync(path.join(tmpdir(), "derm-serve-client-")));
  dirs.push(d);
  return d;
}

function fake(mode: string, opts: { startMs?: number; requestMs?: number } = {}): GateServe {
  const cwd = scratch();
  return new GateServe({
    agent: "pi",
    env: { FAKE_SERVE_MODE: mode, PATH: process.env.PATH },
    cwd: () => cwd,
    trusted: (u) => u === uid,
    startMs: opts.startMs ?? 3000,
    requestMs: opts.requestMs ?? 3000,
    locate: () => ({ path: process.execPath }),
    spawn: (_cmd: string, args: string[], o: SpawnOptions) => spawn(process.execPath, [FAKE, ...args], o),
  });
}

describe("failing closed (case 228)", () => {
  it("answers through a co-process that says hello", async () => {
    const s = fake("ok");
    const a = await decide(s, { tool: "bash", input: { command: "ls" } });
    expect(a.action).toBe("allow");
    s.close();
  });

  it("refuses when no derm can be found, and says why", async () => {
    const cwd = scratch();
    const s = new GateServe({ agent: "pi", env: {}, cwd: () => cwd, trusted: () => true, locate: () => ({ problem: "no derm to run" }) });
    await expect(s.request("decide", {})).rejects.toThrow(/no derm to run/);
  });

  it("refuses a co-process that refuses hello or never says it", async () => {
    await expect(fake("refuse-hello").request("decide", {})).rejects.toBeInstanceOf(ServeUnavailable);
    const t = Date.now();
    await expect(fake("silent-hello", { startMs: 300 }).request("decide", {})).rejects.toThrow(/did not answer hello/);
    expect(Date.now() - t).toBeLessThan(3000);
  });

  it("refuses every waiting call when the co-process dies, then starts it again", async () => {
    const cwd = scratch();
    let starts = 0;
    const s = new GateServe({
      agent: "pi",
      env: { PATH: process.env.PATH },
      cwd: () => cwd,
      trusted: () => true,
      requestMs: 3000,
      locate: () => ({ path: process.execPath }),
      spawn: (_c: string, args: string[], o: SpawnOptions) => {
        starts += 1;
        const mode = starts === 1 ? "die-on-request" : "ok";
        return spawn(process.execPath, [FAKE, ...args], { ...o, env: { ...o.env, FAKE_SERVE_MODE: mode } });
      },
    });
    const both = [s.request("decide", { call: { tool: "bash" } }), s.request("decide", { call: { tool: "bash" } })];
    for (const p of both) await expect(p).rejects.toThrow(/exited \(4\): boom/);
    const a = await decide(s, { tool: "bash", input: {} });
    expect(a.action).toBe("allow");
    expect(starts).toBe(2);
    s.close();
  });

  it("refuses a call it does not answer in time, or answers with garbage or out of order", async () => {
    for (const mode of ["hang", "garbage", "wrong-id", "die-on-request"]) {
      const s = fake(mode, { requestMs: 300 });
      await expect(s.request("decide", { call: { tool: "bash" } }), mode).rejects.toBeInstanceOf(ServeUnavailable);
      s.close();
    }
  });

  it("refuses everything once the session ended", async () => {
    const s = fake("ok");
    s.close();
    await expect(s.request("decide", {})).rejects.toThrow(/session ended/);
  });

  it("shares one co-process per agent and folder", () => {
    const cwd = scratch();
    const o = { agent: "pi", env: {}, cwd: () => cwd, trusted: () => true };
    expect(sharedServe(o)).toBe(sharedServe(o));
    expect(sharedServe({ ...o, agent: "oh-my-pi" })).not.toBe(sharedServe(o));
  });
});

describe("the route to derm (case 227)", () => {
  function binTree(): { root: string; bin: string; derm: string; deps: (env?: Record<string, string>) => LocateDeps } {
    const root = scratch();
    const bin = path.join(root, "home", ".local", "bin");
    mkdirSync(bin, { recursive: true });
    const derm = path.join(bin, "derm");
    writeFileSync(derm, "#!/bin/sh\n");
    chmodSync(derm, 0o755);
    for (const d of [bin, path.dirname(bin), path.join(root, "home")]) chmodSync(d, 0o755);
    const cwd = path.join(root, "project");
    mkdirSync(cwd);
    return { root, bin, derm, deps: (env = {}) => ({ env, cwd, platform: process.platform, home: path.join(root, "home"), trusted: (u) => u === uid }) };
  }

  it("never looks derm up on PATH", () => {
    const t = binTree();
    // A derm in a PATH folder only is never the one found (a fixed install
    // place on this machine may still hold one).
    const r = locateDerm({ ...t.deps({ PATH: t.bin }), home: "/nonexistent" });
    if ("path" in r) expect(r.path).not.toBe(t.derm);
    else expect(r.problem).not.toContain(t.bin);
  });

  it.runIf(unix)("takes DERM_BIN, else derm's install folder, each by case 109's rule", () => {
    const t = binTree();
    expect(locateDerm(t.deps({ DERM_BIN: t.derm }))).toEqual({ path: t.derm });
    expect(locateDerm(t.deps())).toEqual({ path: t.derm });
    expect(installCandidates("linux", "/h")[0]).toBe("/h/.local/bin/derm");
  });

  it.runIf(unix)("refuses a derm others may write, or in a folder others may write", () => {
    const t = binTree();
    chmodSync(t.derm, 0o775);
    expect(refuseCandidate(t.derm, t.deps())).toBe("others may write it");
    chmodSync(t.derm, 0o755);
    chmodSync(t.bin, 0o777);
    expect(refuseCandidate(t.derm, t.deps())).toMatch(/others may write/);
  });

  it.runIf(unix)("refuses a derm the session's folder holds, by name or through a link", () => {
    const t = binTree();
    const d = t.deps();
    const planted = path.join(d.cwd, "derm");
    writeFileSync(planted, "#!/bin/sh\n");
    chmodSync(planted, 0o755);
    expect(refuseCandidate(planted, d)).toMatch(/session's folder/);
    const link = path.join(t.root, "link-derm");
    symlinkSync(planted, link);
    expect(refuseCandidate(link, d)).toMatch(/session's folder/);
    expect(locateDerm(t.deps({ DERM_BIN: planted }))).toEqual({ path: t.derm });
  });

  it.runIf(unix)("refuses a derm owned by someone it does not trust, a folder, a relative path, a missing file", () => {
    const t = binTree();
    expect(refuseCandidate(t.derm, { ...t.deps(), trusted: () => false, stat: (p) => ({ uid: 4242, mode: 0o100755, isFile: !p.endsWith("bin"), isDir: p.endsWith("bin") }) })).toMatch(/does not trust/);
    expect(refuseCandidate(t.bin, t.deps())).toBe("not a regular file");
    expect(refuseCandidate("derm", t.deps())).toBe("not an absolute path");
    expect(refuseCandidate(path.join(t.bin, "nope"), t.deps())).toBe("not there");
    chmodSync(t.derm, 0o644);
    expect(refuseCandidate(t.derm, t.deps())).toBe("not executable");
  });

  it("on Windows takes only DERM_BIN, never a guessed folder", () => {
    expect(installCandidates("win32", "C:\\Users\\u")).toEqual([]);
    const r = locateDerm({ env: {}, cwd: "C:\\p", platform: "win32", home: "C:\\Users\\u", trusted: () => true });
    expect("problem" in r && r.problem).toMatch(/DERM_BIN/);
  });
});

// ---- the real co-process ------------------------------------------------

const DERM = process.env.DERM_TEST_NO_BUILD ? undefined : [process.env.DERM_BIN, path.join(ROOT, "target/debug/derm"), path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm.exe"), path.join(ROOT, "target/release/derm.exe")].find((p) => p && existsSync(p));
const POLICY = path.join(ROOT, "contracts/fixtures/gate-serve/policy.json");

describe.runIf(DERM !== undefined && unix)("against the real derm gate serve", () => {
  function real(agent = "opencode", extra: Record<string, string> = {}): { s: GateServe; home: string } {
    const root = scratch();
    const home = path.join(root, "home");
    const cwd = path.join(root, "project");
    mkdirSync(path.join(home, ".derm"), { recursive: true, mode: 0o700 });
    chmodSync(home, 0o700);
    mkdirSync(cwd);
    const policy = path.join(home, ".derm", "policy.json");
    writeFileSync(policy, readFixture(), { mode: 0o600 });
    const s = new GateServe({
      agent,
      env: { HOME: home, DERM_POLICY: policy, DERM_DAEMON_SOCKET: path.join(root, "no-daemon.sock"), ...extra },
      cwd: () => cwd,
      trusted: () => true,
      locate: () => ({ path: DERM as string }),
    });
    return { s, home };
  }
  function readFixture(): string {
    return readFileSync(POLICY, "utf8");
  }

  it("decides as the core does, and turns an unreachable approver into a deny for a host with no prompt", async () => {
    const { s } = real("opencode");
    expect((await decide(s, { tool: "bash", input: { command: "ls" } })).action).toBe("allow");
    const deny = await decide(s, { tool: "my-server_drop", input: {} });
    expect(deny).toMatchObject({ action: "deny", normalizedTool: "my_server/drop" });
    const ask = await decide(s, { tool: "write", input: { path: "a" }, toolUseId: "t1" });
    expect(ask.action).toBe("ask");
    const r = await approve(s, { tool: "write", input: { path: "a" }, toolUseId: "t1" }, ask, false);
    expect(r.kind).toBe("deny");
    expect((await approve(s, { tool: "write", input: { path: "a" } }, ask, true)).kind).toBe("harness");
    const red = await redact(s, { out: `ghp_${"A1b2C3d4E5".repeat(4)}` });
    expect(red.count).toBe(1);
    await record(s, { tool: "bash", input: {} }, ask, "ask", { label: "x" });
    s.close();
  });

  it("keeps working after many calls and answers them in order", async () => {
    const { s } = real("kilo");
    const answers = await Promise.all(Array.from({ length: 50 }, (_, i) => decide(s, { tool: i % 2 ? "bash" : "write", input: { command: "ls", path: "a" } })));
    expect(answers.map((a) => a.action)).toEqual(Array.from({ length: 50 }, (_, i) => (i % 2 ? "allow" : "ask")));
    s.close();
  });

  it("refuses a second hello and keeps running", async () => {
    const { s } = real("pi");
    await expect(s.request("hello", { agent: "kilo", protocol: 1 })).resolves.toMatchObject({ ok: false });
    expect((await decide(s, { tool: "bash", input: { command: "ls" } })).action).toBe("allow");
    s.close();
  });
});
