// Whose files the gate trusts (wave 5 lane V, request V-3): the person's own
// as before, or, under an agents' user, the person it works for and never
// itself (rules cases 53 and 125).

import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { chatToken, socketLooksOwned } from "./daemon.ts";
import { _setOwnersForTest, ownersFor, readAnchor } from "./owner.ts";
import { loadPolicy } from "./policy.ts";

const me = typeof process.getuid === "function" ? process.getuid() : 0;
const entry = (uid: number, ownerUid: number) =>
  JSON.stringify({ version: 1, agents: [{ user: "derm-agent", uid, owner: "tony", ownerUid, path: "/usr/bin", how: "sudo" }] });

afterEach(() => _setOwnersForTest(undefined));

describe("ownersFor", () => {
  it("trusts this user when there is no file or no entry for it", () => {
    expect(ownersFor(1000, undefined)).toEqual({ uids: [1000], agent: false });
    expect(ownersFor(1000, entry(998, 1001))).toEqual({ uids: [1000], agent: false });
  });
  it("trusts only the owner under an agents' user", () => {
    expect(ownersFor(998, entry(998, 1000))).toEqual({ uids: [1000], agent: true });
  });
  it("trusts no one when the file is broken or names nonsense", () => {
    for (const text of ["{", "[]", '{"version":2,"agents":[]}', '{"version":1,"agents":[{"uid":"998"}]}']) {
      const o = ownersFor(998, text);
      expect(o.uids, text).toEqual([]);
      expect(o.problem, text).toBeTruthy();
    }
    expect(ownersFor(998, entry(998, 998)).uids).toEqual([]);
    expect(ownersFor(998, entry(998, 0)).uids).toEqual([]);
    const two = JSON.stringify({ version: 1, agents: [JSON.parse(entry(998, 1000)).agents[0], JSON.parse(entry(998, 1001)).agents[0]] });
    expect(ownersFor(998, two).uids).toEqual([]);
  });
});

describe("readAnchor", () => {
  const tree = () => {
    const root = mkdtempSync(path.join(tmpdir(), "derm-owner-"));
    chmodSync(root, 0o755);
    const dir = path.join(root, "etc", "derm");
    mkdirSync(dir, { recursive: true, mode: 0o755 });
    chmodSync(path.join(root, "etc"), 0o755);
    chmodSync(dir, 0o755);
    const file = path.join(dir, "agent-users.json");
    writeFileSync(file, entry(998, 1000), { mode: 0o644 });
    chmodSync(file, 0o644);
    return { root, file };
  };
  it("reads a file whose whole path the trusted user holds", () => {
    const { root, file } = tree();
    expect(readAnchor(file, root, me)).toBe(entry(998, 1000));
    expect(readAnchor(path.join(root, "none.json"), root, me)).toBeUndefined();
    rmSync(root, { recursive: true, force: true });
  });
  it("refuses one others can write, a link, or one another user owns", () => {
    let t = tree();
    chmodSync(t.file, 0o666);
    expect(readAnchor(t.file, t.root, me)).toEqual({ problem: expect.stringContaining("written by group or others") });
    rmSync(t.root, { recursive: true, force: true });
    t = tree();
    chmodSync(path.dirname(t.file), 0o777);
    expect(readAnchor(t.file, t.root, me)).toEqual({ problem: expect.stringContaining("written by group or others") });
    rmSync(t.root, { recursive: true, force: true });
    t = tree();
    const real = path.join(t.root, "real.json");
    writeFileSync(real, entry(998, 1000), { mode: 0o644 });
    rmSync(t.file);
    symlinkSync(real, t.file);
    expect(readAnchor(t.file, t.root, me)).toEqual({ problem: expect.stringContaining("is a link") });
    rmSync(t.root, { recursive: true, force: true });
    t = tree();
    expect(readAnchor(t.file, t.root, me + 1)).toEqual({ problem: expect.stringContaining("not owned by uid") });
    rmSync(t.root, { recursive: true, force: true });
  });
});

describe.skipIf(typeof process.getuid !== "function")("the gate's checks under an agents' user", () => {
  it("refuses the agent's own policy, socket and token file, and takes the person's", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "derm-owner-gate-"));
    chmodSync(dir, 0o711);
    const policy = path.join(dir, "policy.json");
    writeFileSync(policy, JSON.stringify({ version: 1, rules: [] }), { mode: 0o644 });
    chmodSync(policy, 0o644);
    const token = path.join(dir, "chat.token");
    writeFileSync(token, `${"a".repeat(64)}\n`, { mode: 0o644 });
    chmodSync(token, 0o644);
    const sock = path.join(dir, "daemon.sock");
    const server = net.createServer();
    await new Promise<void>((r) => server.listen(sock, r));
    const env = { DERM_CHAT_TOKEN_FILE: token };
    const elsewhere = mkdtempSync(path.join(tmpdir(), "derm-owner-cwd-"));

    // This test's uid as the person, a made-up uid as the agent: the files
    // are the person's, so they are trusted, the 0644 token included.
    _setOwnersForTest({ uids: [me], agent: true });
    expect(loadPolicy(policy).problem).toBeUndefined();
    expect(socketLooksOwned(sock)).toBeUndefined();
    expect(chatToken(env, elsewhere)).toBe("a".repeat(64));

    // The same files seen by an agents' user whose owner is someone else:
    // they are the agent's own, so every one is refused.
    _setOwnersForTest({ uids: [me + 1], agent: true });
    expect(loadPolicy(policy).problem).toBe("policy file owned by another user");
    expect(socketLooksOwned(sock)).toBe("socket owned by another user");
    expect(chatToken(env, elsewhere)).toBeUndefined();

    // A broken root file trusts no one.
    _setOwnersForTest({ uids: [], agent: false, problem: "broken" });
    expect(loadPolicy(policy).problem).toBe("policy file owned by another user");

    // As the person (not an agent), a 0644 token is still too loose.
    _setOwnersForTest({ uids: [me], agent: false });
    expect(chatToken(env, elsewhere)).toBeUndefined();

    server.close();
    rmSync(dir, { recursive: true, force: true });
    rmSync(elsewhere, { recursive: true, force: true });
  });
});
