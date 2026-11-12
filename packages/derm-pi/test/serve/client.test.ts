// The co-process client (src/serve/client.ts): the route to derm (case 227),
// failing closed and starting again (case 228), and the real `derm gate
// serve` when a build is there (target/debug/derm, or DERM_BIN).

import { spawn, type SpawnOptions } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { aclGrantsWrite, ACL_WRITE_PERMS, approve, decide, GateServe, installCandidates, locateDerm, MACOS_ADMIN_GID, parseGroups, record, redact, refuseCandidate, ServeUnavailable, sharedServe, type LocateDeps } from "../../src/serve/client.ts";

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
    // BW5B-5 (box test w5b, step 7): the reason names which derm it ran,
    // since two builds can print the same version.
    await expect(both[0]).rejects.toThrow(`${process.execPath} gate serve exited (4)`);
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

// Integration w5b fix pass 1: MW5B-1 (an access list hidden behind "@") and
// MW5B-2 (Homebrew's admin-group prefix), as derm connect and the launcher
// read them (case 112; crates/derm-cli/src/connect/gate_tests.rs, mw5b_*).
describe("who else may write, on macOS (MW5B-1, MW5B-2)", () => {
  const u = "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEF12";
  const head = "-rwxr-xr-x@ 1 501 20 6840512 Nov 11 16:00 /Users/u/.local/bin/derm\n";

  it("reads an access list line in the form macOS's ls prints it (file_cmds-479 ls/print.c)", () => {
    expect(aclGrantsWrite(head)).toBe(false);
    const cases: [string, boolean][] = [
      [` 0: ${u} allow write`, true],
      [` 0: group:everyone allow write`, true],
      [` 0: ${u} inherited allow add_file,search,file_inherit`, true],
      [` 0: ${u} allow read,execute,readattr,readextattr,readsecurity`, false],
      [` 0: ${u} deny delete`, false],
      [` 0: ${u} deny write,append,delete,chown`, false],
      [` 0: ${u} allow list,search,add_subdirectory`, true],
      [` 0: ${u} unknown write`, true],
      [` 0: ${u} allow `, false],
      [` 0: ${u}`, true],
      [` 0: ${u} inherited`, true],
      ["garbage", true],
    ];
    for (const p of ACL_WRITE_PERMS) cases.push([` 0: ${u} allow ${p}`, true]);
    for (const [line, open] of cases) expect([line, aclGrantsWrite(`${head}${line}\n`)]).toEqual([line, open]);
    expect(aclGrantsWrite(`${head} 0: ${u} deny delete\n 1: ${u} allow write\n`)).toBe(true);
  });

  it("reads /usr/bin/id -G's groups", () => {
    expect(parseGroups("20 12 61 79 80 81\n")).toEqual([20, 12, 61, 79, 80, 81]);
    expect(parseGroups("20 x 80")).toBeUndefined();
    expect(parseGroups("")).toBeUndefined();
    expect(MACOS_ADMIN_GID).toBe(80);
  });

  // A Homebrew layout (also brewDeps below): /opt/homebrew/bin (g+rwx, group admin) links into a
  // keg whose folders are 0755 (the Mac test w5b, step 2).
  function brew(over: Partial<LocateDeps> & { binGid?: number; binMode?: number } = {}): LocateDeps {
    const bin = "/opt/homebrew/bin";
    const keg = "/opt/homebrew/Cellar/derm/0.1.3/bin";
    return {
      env: {},
      cwd: "/Users/u/proj",
      platform: "darwin",
      home: "/Users/u",
      trusted: (x) => x === 501,
      realpath: (p) => (p === `${bin}/derm` ? `${keg}/derm` : p),
      lstat: (p) => ({ isLink: p === `${bin}/derm` }),
      readlink: () => "../Cellar/derm/0.1.3/bin/derm",
      stat: (p) => {
        if (p === `${keg}/derm`) return { uid: 501, gid: 80, mode: 0o100755, isFile: true, isDir: false };
        if (p === keg) return { uid: 501, gid: 80, mode: 0o40755, isFile: false, isDir: true };
        if (p === bin) return { uid: 501, gid: over.binGid ?? 80, mode: over.binMode ?? 0o40775, isFile: false, isDir: true };
        throw new Error("no such file");
      },
      groups: () => [20, 12, 61, 79, 80, 81],
      acl: (p) => `drwxr-xr-x  3 501 80 96 Nov 11 16:00 ${p}\n`,
      ...over,
    };
  }

  it("trusts Homebrew's admin-group prefix for an admin (MW5B-2)", () => {
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew())).toBeUndefined();
  });

  it("refuses it for a user not in admin, for staff, for any group off macOS", () => {
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ groups: () => [20, 12] }))).toMatch(/others may write \/opt\/homebrew\/bin/);
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ groups: () => undefined }))).toMatch(/others may write/);
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ binGid: 20 }))).toMatch(/others may write/);
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ binMode: 0o40777 }))).toMatch(/others may write/);
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ platform: "linux" }))).toMatch(/others may write/);
  });

  it("refuses an access list that lets anyone write, behind an @ (MW5B-1)", () => {
    const allow = (p: string) => `-rwxr-xr-x@ 1 501 80 1 Nov 11 16:00 ${p}\n 0: group:everyone allow write\n`;
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ acl: (p) => (p.endsWith("/derm") ? allow(p) : `d\n`) }))).toBe("others may write it");
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ acl: (p) => (p === "/opt/homebrew/bin" ? allow(p) : `d\n`) }))).toMatch(/others may write \/opt\/homebrew\/bin/);
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ acl: () => undefined }))).toBe("others may write it");
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ acl: (p) => `d\n 0: ${u} deny delete\n` }))).toBeUndefined();
    // Off macOS the access list is not read: the mode bits are its mask.
    expect(refuseCandidate("/opt/homebrew/bin/derm", brew({ platform: "linux", binMode: 0o40755, acl: () => undefined }))).toBeUndefined();
  });
});

// The fix pass's review (FP1-S2, FP1-S8): every link hop's real folder is
// checked, as the launcher checks it; only a file named derm runs, and the
// client starts its real path; Homebrew's group bit is trusted on folders,
// never on the derm file.
describe("the route to derm through links (FP1-S2, FP1-S8)", () => {
  function chain(): { root: string; home: string; bin: string; x: string; y: string; d: LocateDeps } {
    const root = scratch();
    const home = path.join(root, "home");
    const bin = path.join(home, ".local", "bin");
    const x = path.join(root, "x");
    const y = path.join(root, "y");
    for (const f of [bin, x, y]) mkdirSync(f, { recursive: true });
    for (const f of [bin, path.dirname(bin), home, x, y]) chmodSync(f, 0o755);
    writeFileSync(path.join(y, "derm"), "#!/bin/sh\n");
    chmodSync(path.join(y, "derm"), 0o755);
    symlinkSync(path.join(y, "derm"), path.join(x, "derm"));
    symlinkSync(path.join(x, "derm"), path.join(bin, "derm"));
    const cwd = path.join(root, "project");
    mkdirSync(cwd);
    return { root, home, bin, x, y, d: { env: {}, cwd, platform: "linux", home, trusted: (u) => u === uid } };
  }

  it.runIf(unix)("refuses a chain through a folder others may write, as the launcher does", () => {
    const t = chain();
    expect(refuseCandidate(path.join(t.bin, "derm"), t.d)).toBeUndefined();
    chmodSync(t.x, 0o777);
    expect(refuseCandidate(path.join(t.bin, "derm"), t.d)).toMatch(new RegExp(`others may write ${t.x}`));
  });

  it.runIf(unix)("runs only a file named derm, and starts its real path", () => {
    const t = chain();
    expect(locateDerm(t.d)).toEqual({ path: path.join(t.y, "derm") });
    rmSync(path.join(t.x, "derm"));
    symlinkSync(realpathSync("/bin/sh"), path.join(t.x, "derm"));
    expect(refuseCandidate(path.join(t.bin, "derm"), t.d)).toBe("not named derm");
  });

  it("trusts Homebrew's admin group on a folder, never on the derm file", () => {
    const base = brewDeps();
    const file = (p: string) => p.endsWith("/derm");
    const stat = (p: string) => {
      const s = base.stat!(p);
      return file(p) ? { ...s, mode: 0o100775 } : s;
    };
    expect(refuseCandidate("/opt/homebrew/bin/derm", { ...base, stat })).toBe("others may write it");
  });
});

function brewDeps(): LocateDeps {
  const bin = "/opt/homebrew/bin";
  const keg = "/opt/homebrew/Cellar/derm/0.1.3/bin";
  return {
    env: {},
    cwd: "/Users/u/proj",
    platform: "darwin",
    home: "/Users/u",
    trusted: (x) => x === 501,
    realpath: (p) => (p === `${bin}/derm` ? `${keg}/derm` : p),
    lstat: (p) => ({ isLink: p === `${bin}/derm` }),
    readlink: () => "../Cellar/derm/0.1.3/bin/derm",
    stat: (p) => {
      if (p === `${keg}/derm`) return { uid: 501, gid: 80, mode: 0o100755, isFile: true, isDir: false };
      if (p === keg) return { uid: 501, gid: 80, mode: 0o40755, isFile: false, isDir: true };
      if (p === bin) return { uid: 501, gid: 80, mode: 0o40775, isFile: false, isDir: true };
      throw new Error("no such file");
    },
    groups: () => [20, 80],
    acl: (p) => `d 1 501 80 0 Nov 11 16:00 ${p}\n`,
  };
}
