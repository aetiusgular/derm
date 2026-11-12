// The policy file on a real file system (integration w1 security finding
// S11). Since wave 5b (lane 5bC) the gate's policy is read by `derm gate
// serve`, through the loader every gate shares (`gate::policy::
// load_for_hook`, case 226), so the cases that decide need a derm build;
// derm-pi's own PolicyStore keeps its tests here while it stays in the
// package. The loader follows a link and judges the file it reaches and both
// folders, as the hook core does, where derm-pi refused every link
// (tk_lane_5bC.md, Decisions); on Windows it judges the file by its access
// list, so a private policy now applies there (wave 5b plan, call 3).
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createGate } from "../extensions/gate.ts";
import { PolicyStore, WINDOWS_POLICY_PROBLEM } from "../src/policy-store.ts";
import type { ToolCallResult } from "../src/pi-api.ts";
import { FakeRpcClient, fakePi } from "./fake-pi.ts";
import { DERM, removeRoot, stopServe } from "./serve/real.ts";
import { GateServe } from "../src/serve/client.ts";

const itDerm = it.runIf(DERM !== undefined);
const root = realpathSync(mkdtempSync(path.join(tmpdir(), "derm-pi-policy-")));
// The session's folder: apart from the policies, which a project could set.
const project = path.join(root, "project");
mkdirSync(project);
const started: GateServe[] = [];
// WB-P1-1: each co-process stopped and waited for before the folder goes.
afterAll(async () => {
  for (const s of started.splice(0)) await stopServe(s);
  removeRoot(root);
});

const allowRead = JSON.stringify({ version: 1, askTimeoutSeconds: 1, rules: [{ tool: "read", action: "allow" }] });

function gateWith(policyPath: string) {
  const client = new FakeRpcClient(() => ({ confirmed: false }));
  const pi = fakePi({ client });
  const env = { DERM_POLICY: policyPath, HOME: root, USERPROFILE: root, DERM_DAEMON_SOCKET: path.join(root, "no-daemon.sock") };
  const serve = new GateServe({ agent: "pi", env, cwd: () => project, trusted: (u) => u === (process.getuid?.() ?? 0), locate: () => ({ path: DERM as string }) });
  started.push(serve);
  createGate({ env: () => env, serve: () => serve })(pi.api);
  const call = () => pi.emit("tool_call", { type: "tool_call", toolName: "read", toolCallId: "c1", input: { path: "a.txt" } }) as Promise<ToolCallResult | undefined>;
  return { call, client };
}

describe("the policy file on disk", () => {
  it("on Windows no policy is read, since who may write it cannot be (WW5-3)", async () => {
    // Fails on 2ce607d: off POSIX both checks were skipped and the file loaded.
    const file = path.join(root, "win.json");
    writeFileSync(file, allowRead, { mode: 0o600 });
    chmodSync(file, 0o600);
    const onWindows = await new PolicyStore(file, undefined, undefined, false).get();
    expect(onWindows.problem).toBe(WINDOWS_POLICY_PROBLEM);
    expect(onWindows.policy.rules).toEqual([]);
    // On a POSIX host the same private file loads (on Windows its mode reads
    // 0o666, so the POSIX checks refuse it there).
    if (process.platform !== "win32") {
      expect((await new PolicyStore(file, undefined, undefined, true).get()).problem).toBeUndefined();
    }
  });

  itDerm("a regular private file is read and applied", async () => {
    const file = path.join(root, "policy.json");
    writeFileSync(file, allowRead, { mode: 0o600 });
    chmodSync(file, 0o600);
    const g = gateWith(file);
    const r = await g.call();
    if (process.platform === "win32") {
      // Judged by its access list now: never refused for want of a way to
      // read who may write it (WW5-3's reason is gone).
      expect(g.client.requests[0]?.message ?? "").not.toContain(WINDOWS_POLICY_PROBLEM);
    } else {
      expect(r).toBeUndefined();
    }
  });

  itDerm("a link is judged by the file it reaches and both folders: a target others may swap is refused", async () => {
    const target = path.join(root, "target.json");
    writeFileSync(target, allowRead, { mode: 0o600 });
    chmodSync(target, 0o600);
    const link = path.join(root, "link.json");
    symlinkSync(target, link);
    expect(await gateWith(link).call()).toBeUndefined();
    const open = path.join(root, "open");
    mkdirSync(open);
    chmodSync(open, 0o777);
    const swappable = path.join(open, "t.json");
    writeFileSync(swappable, allowRead, { mode: 0o600 });
    chmodSync(swappable, 0o600);
    const link2 = path.join(root, "link2.json");
    symlinkSync(swappable, link2);
    const g = gateWith(link2);
    expect(await g.call()).toMatchObject({ block: true });
    expect(g.client.requests[0]?.message).toContain("the policy file's folder");
  });

  itDerm("a FIFO at the path neither hangs the turn nor loads", async () => {
    const fifo = path.join(root, "policy.fifo");
    execFileSync("mkfifo", [fifo]);
    const g = gateWith(fifo);
    const started = Date.now();
    expect(await g.call()).toMatchObject({ block: true });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(g.client.requests[0]?.message).toContain("policy file is not a regular file");
  });

  itDerm("a file others can write is refused on the handle that would be read", async () => {
    const file = path.join(root, "open.json");
    writeFileSync(file, allowRead);
    chmodSync(file, 0o666);
    const g = gateWith(file);
    expect(await g.call()).toMatchObject({ block: true });
    expect(g.client.requests[0]?.message).toContain("someone other than you may write this policy file");
  });
});
