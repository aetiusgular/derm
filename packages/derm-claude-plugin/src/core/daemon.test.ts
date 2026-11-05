// Which token a hook presents to the daemon, and which paths it accepts from
// its environment. Integration w1 decision (plans/parallel/tk_integration_w1.md,
// Decisions): a hook is never the daemon. It presents the chat token `derm run`
// gave it, from DERM_CHAT_TOKEN or the file DERM_CHAT_TOKEN_FILE names, and never
// reads daemon.token. Paths from the environment (DERM_POLICY, DERM_DAEMON_SOCKET,
// DERM_CHAT_TOKEN_FILE) are refused inside the session's folder, where a
// cloned repository's settings file could point them.

import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { chatToken, decisionId, exchange, insideFolder, socketLooksOwned } from "./daemon.ts";
import { loadPolicyFrom } from "./policy.ts";
import { startFakeDaemon } from "../testing/fakeDaemon.ts";

const root = mkdtempSync(path.join(tmpdir(), "derm-tok-"));
chmodSync(root, 0o700);
const safe = path.join(root, "safe");
const project = path.join(root, "project");
mkdirSync(safe, { mode: 0o700 });
mkdirSync(project, { mode: 0o700 });
const CHAT = "a".repeat(64);
const tokenFile = path.join(safe, "token");
writeFileSync(tokenFile, `${CHAT}\n`, { mode: 0o600 });

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("chatToken", () => {
  it("never falls back to daemon.token beside the socket", async () => {
    const d = await startFakeDaemon({ approve: "yes" });
    try {
      expect(chatToken({ DERM_DAEMON_SOCKET: d.socket }, project)).toBeUndefined();
      const r = await exchange([{ op: "event", event: { id: "x" } }], { env: { DERM_DAEMON_SOCKET: d.socket }, client: "t", replyTimeoutMs: 500, cwd: project });
      expect("error" in r && r.error).toMatch(/no chat token/);
      expect(d.lines).toHaveLength(0);
    } finally {
      await d.close();
    }
  });

  it("takes DERM_CHAT_TOKEN first", () => {
    expect(chatToken({ DERM_CHAT_TOKEN: "b".repeat(64), DERM_CHAT_TOKEN_FILE: tokenFile }, project)).toBe("b".repeat(64));
  });

  it("reads DERM_CHAT_TOKEN_FILE when it is absolute, yours, private and outside the session folder", () => {
    expect(chatToken({ DERM_CHAT_TOKEN_FILE: tokenFile }, project)).toBe(CHAT);
  });

  it("refuses a token file that is relative, readable by others, a link, malformed or inside the session folder", () => {
    const loose = path.join(safe, "loose");
    writeFileSync(loose, CHAT, { mode: 0o600 });
    chmodSync(loose, 0o644);
    const link = path.join(safe, "link");
    symlinkSync(tokenFile, link);
    const bad = path.join(safe, "bad");
    writeFileSync(bad, "not-a-token", { mode: 0o600 });
    const planted = path.join(project, "token");
    writeFileSync(planted, CHAT, { mode: 0o600 });
    for (const f of ["token", loose, link, bad, planted]) expect(chatToken({ DERM_CHAT_TOKEN_FILE: f }, project), f).toBeUndefined();
  });
});

describe("a daemon-scope token is never presented (security finding S3)", () => {
  it("refuses DERM_CHAT_TOKEN_FILE naming daemon.token beside the socket", async () => {
    const d = await startFakeDaemon({ approve: "yes" });
    try {
      const env = { DERM_DAEMON_SOCKET: d.socket, DERM_CHAT_TOKEN_FILE: path.join(d.dir, "daemon.token") };
      expect(chatToken(env, project)).toBeUndefined();
      const r = await exchange([{ op: "event", event: { id: "x" } }], { env, client: "t", replyTimeoutMs: 500, cwd: project });
      expect("error" in r && r.error).toMatch(/no chat token/);
      expect(d.lines).toHaveLength(0);
    } finally {
      await d.close();
    }
  });

  it("closes when the daemon says the token it got has daemon scope, whatever file it came from", async () => {
    const d = await startFakeDaemon({ approve: "yes" });
    try {
      const copy = path.join(safe, "copied-token");
      writeFileSync(copy, `${d.token}\n`, { mode: 0o600 });
      const env = { DERM_DAEMON_SOCKET: d.socket, DERM_CHAT_TOKEN_FILE: copy };
      const r = await exchange([{ op: "approve", request: { id: "ap-1" } }], { env, client: "t", replyTimeoutMs: 500, cwd: project });
      expect("error" in r && r.error).toMatch(/daemon scope/);
      expect(d.lines.filter((l) => l.line.op !== "hello")).toHaveLength(0);
      const r2 = await exchange([{ op: "approve", request: { id: "ap-2" } }], { env: { DERM_DAEMON_SOCKET: d.socket, DERM_CHAT_TOKEN: d.token }, client: "t", replyTimeoutMs: 500, cwd: project });
      expect("error" in r2 && r2.error).toMatch(/daemon scope/);
    } finally {
      await d.close();
    }
  });
});

describe("paths from the environment", () => {
  it("insideFolder follows links on the folder and handles missing files", () => {
    expect(insideFolder(path.join(project, "a", "b.json"), project)).toBe(true);
    expect(insideFolder(path.join(safe, "p.json"), project)).toBe(false);
    expect(insideFolder(project, project)).toBe(true);
    const linkToProject = path.join(root, "via-link");
    symlinkSync(project, linkToProject);
    expect(insideFolder(path.join(linkToProject, "p.json"), project)).toBe(true);
    expect(insideFolder(path.join(project, "..", "safe", "p.json"), project)).toBe(false);
  });

  it("refuses DERM_DAEMON_SOCKET inside the session folder", async () => {
    const r = await exchange([{ op: "event", event: { id: "x" } }], { env: { DERM_DAEMON_SOCKET: path.join(project, "daemon.sock"), DERM_CHAT_TOKEN: CHAT }, client: "t", replyTimeoutMs: 500, cwd: project });
    expect("error" in r && r.error).toMatch(/inside the session folder/);
  });

  it("refuses a daemon socket inside the session folder or relative, whichever variable named it (S14)", async () => {
    if (process.platform === "darwin") return; // the socket there is under HOME, not XDG_RUNTIME_DIR
    for (const runtime of [path.join(project, "run"), "relative/run"]) {
      const r = await exchange([{ op: "event", event: { id: "x" } }], { env: { XDG_RUNTIME_DIR: runtime, DERM_CHAT_TOKEN: CHAT }, client: "t", replyTimeoutMs: 500, cwd: project });
      expect("error" in r && r.error, runtime).toMatch(/the daemon socket is (inside the session folder|not an absolute path)/);
    }
  });

  it("refuses DERM_POLICY inside the session folder, and accepts the same file elsewhere", () => {
    const body = JSON.stringify({ version: 1, rules: [{ tool: "bash", action: "allow" }] });
    const inProject = path.join(project, ".derm-policy.json");
    writeFileSync(inProject, body, { mode: 0o600 });
    const outside = path.join(safe, "policy.json");
    writeFileSync(outside, body, { mode: 0o600 });
    const refused = loadPolicyFrom({ DERM_POLICY: inProject }, project);
    expect(refused.problem).toMatch(/inside the session folder/);
    expect(refused.policy.rules).toHaveLength(0);
    expect(loadPolicyFrom({ DERM_POLICY: outside }, project).policy.rules).toHaveLength(1);
  });

  it("does not apply the folder check to the default ~/.derm/policy.json (a session started in HOME)", () => {
    const r = loadPolicyFrom({}, homedir());
    expect(r.problem ?? "").not.toMatch(/inside the session folder/);
  });
});

// Box test w2, BW2: a gate decision's id was `<harness>-<call id>-decision`.
// Call ids count up (OpenCode's `call_16`, `call_17`), so the agent, which
// holds the same chat token (case 66), posted a forged decision under the
// next call's id first; the real one became the conflict copy, and an id no
// call ever took stayed a plain forged decision. The id now ends in 128
// random bits the agent cannot know before the hook writes it.
describe("a gate decision's id (box test w2, BW2)", () => {
  it("cannot be known from the call id: two decisions for one call differ, and neither is the old form", () => {
    const a = decisionId("opencode", "call_17");
    const b = decisionId("opencode", "call_17");
    expect(a).not.toBe(b);
    for (const id of [a, b]) {
      expect(id).toMatch(/^opencode-call_17-decision-[0-9a-f]{32}$/);
      expect(id).not.toBe("opencode-call_17-decision");
    }
  });
  it("names an unknown call and stays under the daemon's id cap", () => {
    expect(decisionId("claude-code", undefined)).toMatch(/^claude-code-unknown-decision-[0-9a-f]{32}$/);
    const long = decisionId("claude-code", "x".repeat(400));
    expect(long.length).toBeLessThanOrEqual(128);
    expect(long).toMatch(/-decision-[0-9a-f]{32}$/);
    expect(decisionId("hermes", "a\nb c/d")).toMatch(/^hermes-a_b_c_d-decision-[0-9a-f]{32}$/);
  });
});

describe("the daemon's endpoint on Windows (lane Z's request 2)", () => {
  it("is never trusted until a server check exists, whatever the name", () => {
    for (const name of ["\\\\.\\pipe\\derm\\daemon", "C:\\Users\\me\\.derm\\run\\daemon.sock"]) {
      expect(socketLooksOwned(name, "win32")).toMatch(/cannot be checked on Windows/);
    }
  });

  it("is still checked the Unix way elsewhere", () => {
    expect(socketLooksOwned(path.join(tmpdir(), "no-such-derm-socket"), "linux")).toBe("no daemon socket");
  });
});

// Lane T's P4-R2 (integration w5, continue): inside an sbx VM the socket is
// not there, and the hook reaches the daemon over the receiver's HTTP port
// at host.docker.internal, only when derm run said so.
describe("the VM route", () => {
  const absent = path.join(root, "no-such-folder", "daemon.sock");
  const vmEnv = (extra: Record<string, string> = {}) => ({
    DERM_BOUNDARY: "sbx",
    DERM_OTLP_ENDPOINT: "http://host.docker.internal:4318",
    DERM_DAEMON_SOCKET: absent,
    ...extra,
  });

  // W5C-S2 (integration w5 continue): the route also needs the root-owned
  // marker derm's sbx kit writes; here a stand-in that holds. Spec change:
  // this test called vmEndpoint with the variables alone before.
  const marked = () => undefined;

  it("is taken only for sbx, a plain host.docker.internal URL, and no socket", async () => {
    const { vmEndpoint } = await import("./daemon.ts");
    expect(vmEndpoint(vmEnv(), marked)?.port).toBe("4318");
    for (const extra of [
      { DERM_BOUNDARY: "srt" },
      { DERM_BOUNDARY: "" },
      { DERM_OTLP_ENDPOINT: "http://127.0.0.1:4318" },
      { DERM_OTLP_ENDPOINT: "https://host.docker.internal:4318" },
      { DERM_OTLP_ENDPOINT: "http://host.docker.internal.evil.example:4318" },
      { DERM_OTLP_ENDPOINT: "http://host.docker.internal" },
      { DERM_OTLP_ENDPOINT: "http://u:p@host.docker.internal:4318" },
      { DERM_OTLP_ENDPOINT: "http://host.docker.internal:4318/v1/logs" },
      { DERM_OTLP_ENDPOINT: "http://host.docker.internal:4318/?x=1" },
      { DERM_OTLP_ENDPOINT: "not a url" },
      // A socket file where the socket would be: the host, never the VM route.
      { DERM_DAEMON_SOCKET: tokenFile },
    ]) {
      expect(vmEndpoint(vmEnv(extra), marked), JSON.stringify(extra)).toBeUndefined();
    }
  });

  // W5C-S2: a project can set every variable the route reads. On the host,
  // with derm's sbx kit nowhere, the variables alone never take the route.
  it("is never taken on the variables alone: the kit's root-owned marker must hold", async () => {
    const { vmEndpoint, vmMarker, VM_MARKER } = await import("./daemon.ts");
    expect(VM_MARKER).toBe("/opt/derm-kit/sbx-vm");
    expect(vmEndpoint(vmEnv(), () => "no VM marker")).toBeUndefined();
    // This test box has no kit installed: the default marker does not hold.
    expect(vmMarker()).toBeDefined();
    expect(vmEndpoint(vmEnv())).toBeUndefined();
  });

  it("the marker holds only for a plain file and folder that are root's alone, on Linux", async () => {
    const { vmMarker } = await import("./daemon.ts");
    type S = { uid: number; mode: number; nlink: number; file: boolean; dir: boolean };
    const fakeStat = (f: Partial<S>, d: Partial<S> = {}) => (p: string) => {
      const s = { uid: 0, mode: 0o100644, nlink: 1, file: true, dir: false, ...(p === "/k/sbx-vm" ? f : { file: false, dir: true, mode: 0o40755, ...d }) };
      return { uid: s.uid, mode: s.mode, nlink: s.nlink, isFile: () => s.file, isDirectory: () => s.dir };
    };
    expect(vmMarker("/k/sbx-vm", "linux", fakeStat({}))).toBeUndefined();
    const bad: [Partial<S>, Partial<S>][] = [
      [{ uid: 1000 }, {}],
      [{ mode: 0o100664 }, {}],
      [{ mode: 0o100646 }, {}],
      [{ nlink: 2 }, {}],
      [{ file: false }, {}],
      [{}, { uid: 1000 }],
      [{}, { mode: 0o40775 }],
      [{}, { dir: false }],
    ];
    for (const [f, d] of bad) expect(vmMarker("/k/sbx-vm", "linux", fakeStat(f, d)), JSON.stringify([f, d])).toBeDefined();
    // Windows gives uid 0 for every file: a marker there proves nothing.
    for (const sys of ["win32", "darwin"] as const) expect(vmMarker("/k/sbx-vm", sys, fakeStat({}))).toBeDefined();
    // A real file this user made is not root's.
    const mine = path.join(safe, "sbx-vm");
    writeFileSync(mine, "x", { mode: 0o644 });
    if (process.getuid?.() !== 0) expect(vmMarker(mine, "linux")).toMatch(/not root's alone/);
    expect(vmMarker(path.join(safe, "none", "sbx-vm"), "linux")).toMatch(/no VM marker/);
  });

  it("is not taken when a socket is where the default would be, whatever DERM_DAEMON_SOCKET names", async () => {
    const { vmEndpoint } = await import("./daemon.ts");
    const runtime = path.join(root, "runtime");
    mkdirSync(path.join(runtime, "derm"), { recursive: true, mode: 0o700 });
    writeFileSync(path.join(runtime, "derm", "daemon.sock"), "");
    expect(vmEndpoint(vmEnv({ XDG_RUNTIME_DIR: runtime }), marked)).toBeUndefined();
    expect(vmEndpoint(vmEnv({ XDG_RUNTIME_DIR: path.join(root, "no-runtime") }), marked)?.port).toBe("4318");
  });

  it("a project on the host that sets the variables never reaches its own listener", async () => {
    const http = await import("node:http");
    let asked = 0;
    const server = http.createServer((_req, res) => {
      asked++;
      res.end(JSON.stringify({ ok: true, id: "ap", answer: "yes", by: "approver" }));
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    try {
      const env = vmEnv({ DERM_OTLP_ENDPOINT: `http://host.docker.internal:${port}`, DERM_CHAT_TOKEN_FILE: tokenFile });
      const r = await exchange([{ op: "approve", request: { id: "ap" } }], { env, client: "t", replyTimeoutMs: 1000, cwd: project });
      expect(r).toEqual({ error: "no daemon socket" });
      expect(asked).toBe(0);
    } finally {
      server.close();
    }
  });

  it("posts each op to its route with the chat token and reads the reply line", async () => {
    const http = await import("node:http");
    const { postVm } = await import("./daemon.ts");
    const seen: { path: string | undefined; token: string | undefined; body: string }[] = [];
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        seen.push({ path: req.url, token: req.headers["x-derm-token"] as string, body });
        if (req.url === "/derm/v1/approve") return res.end(JSON.stringify({ ok: true, id: "ap", answer: "yes", by: "approver" }));
        if (req.url === "/derm/v1/event") return res.end(JSON.stringify({ ok: true, id: "e1" }));
        res.statusCode = 404;
        res.end("{}");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const url = new URL(`http://127.0.0.1:${port}`);
    try {
      const ev = await postVm(url, CHAT, { op: "event", event: { id: "e1" } }, 1000);
      expect(ev).toEqual({ ok: true, id: "e1" });
      const ap = await postVm(url, CHAT, { op: "approve", request: { id: "ap" } }, 1000);
      expect(ap).toMatchObject({ answer: "yes", by: "approver" });
      expect(seen.map((s) => [s.path, s.token, JSON.parse(s.body)])).toEqual([
        ["/derm/v1/event", CHAT, { event: { id: "e1" } }],
        ["/derm/v1/approve", CHAT, { request: { id: "ap" } }],
      ]);
      // An op with no route from a VM is never sent anywhere.
      expect(await postVm(url, CHAT, { op: "tail" }, 1000)).toEqual({ failed: "no route for tail from a VM" });
      expect(seen.length).toBe(2);
    } finally {
      server.close();
    }
    // Nothing listening: unreachable, within the connect timeout.
    const closed = await postVm(new URL(`http://127.0.0.1:${port}`), CHAT, { op: "event", event: {} }, 1000);
    expect(closed).toMatchObject({ failed: expect.stringMatching(/unreachable|timed out/) });
  });

  it("a status other than 200 is not a reply", async () => {
    const http = await import("node:http");
    const { postVm } = await import("./daemon.ts");
    const server = http.createServer((_req, res) => {
      res.statusCode = 401;
      res.end("{}");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    try {
      expect(await postVm(new URL(`http://127.0.0.1:${port}`), CHAT, { op: "approve", request: {} }, 1000)).toEqual({ failed: "daemon answered HTTP 401" });
    } finally {
      server.close();
    }
  });

  it("with no chat token the VM route is not tried", async () => {
    const r = await exchange([{ op: "event", event: {} }], { env: vmEnv(), client: "t", replyTimeoutMs: 500, cwd: project });
    expect(r).toEqual({ error: "no chat token (start the harness with derm run)" });
  });
});
