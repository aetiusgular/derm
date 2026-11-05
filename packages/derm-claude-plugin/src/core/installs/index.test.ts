// Lane X's install decision through the hook core's matcher and gate
// (contracts/policy.md section 6; rules cases 130 to 135). The wave 5 base's
// stub test "leaves an allowed install command allowed until lane X" is
// replaced by what lane X was asked to build: an allowed install asks.
import { readFileSync } from "node:fs";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installDecision, installReason, installCallDetails, parseInstalls, findLockfile } from "./index.ts";
import { evaluate, SHELL_TOOLS, type LoadedPolicy } from "../policy.ts";
import { decideCall } from "../gate.ts";
import { fold, decodeEscapes } from "../fold.ts";
import type { LockEntry } from "./lockfile.ts";

const loaded: LoadedPolicy = { policy: { version: 1, askTimeoutSeconds: 60, servers: [], rules: [{ tool: "*", action: "allow" }] } };
const dir = new URL("../../../../../contracts/fixtures/installs/", import.meta.url);
type BaseCase = { id: number; text: string; expect: { install: boolean; packages?: { name: string; version: string | null }[] } };
const base = (JSON.parse(readFileSync(new URL("cases.json", dir), "utf8")) as { cases: BaseCase[] }).cases;
const folded = (t: string) => fold(decodeEscapes(t));

describe("an allowed install asks (case 130 with the check off, 131)", () => {
  it("every install of the base's fixture asks, naming each package; nothing else changes", () => {
    for (const c of base) {
      const d = evaluate(loaded, { tool: "Bash", harness: "claude-code", inputText: c.text });
      if (!c.expect.install) {
        expect([c.id, d.action, d.reason]).toEqual([c.id, "allow", "rule *"]);
        continue;
      }
      expect([c.id, d.action]).toEqual([c.id, "ask"]);
      expect(d.reason.startsWith("package install: ")).toBe(true);
      for (const p of c.expect.packages ?? []) {
        expect([c.id, d.reason.includes(p.name)]).toEqual([c.id, true]);
        expect([c.id, d.reason.includes(p.version ?? "(no version)")]).toEqual([c.id, true]);
      }
    }
  });
  it("names what it cannot see, and never the input's other words", () => {
    const r = installDecision("bash", folded("pip install -r requirements.txt --index-url https://user:hunter2@pypi.example.com/simple"))?.reason ?? "";
    expect(r).toBe("package install: pip adds a registry other than the default, the packages a requirements file names");
    expect(r).not.toContain("hunter2");
    expect(r).not.toContain("example.com");
    expect(installDecision("bash", folded("npm install https://user:tok@example.com/x.tgz"))?.reason).toBe("package install: npm adds a URL");
  });
  it("caps the card at eight names and 600 characters", () => {
    const many = `npm install ${Array.from({ length: 50 }, (_, i) => `pkg-${i}`).join(" ")}`;
    const r = installReason(parseInstalls(many));
    expect(r).toContain("pkg-7 (no version), and 42 more");
    expect(r).not.toContain("pkg-8 ");
    expect(installReason(parseInstalls(`npm install ${"a".repeat(214)} `.repeat(20))).length).toBeLessThanOrEqual(600);
  });
  it("leaves a call with no install alone", () => {
    for (const t of ["ls -la", "npm test", "npm ci", "uv sync", "echo npm install x", "git log"]) expect(installDecision("bash", folded(t))).toBeUndefined();
  });
});

describe("through every shell tool name (cases 82, 135)", () => {
  it("asks for the same install under each name the matcher reads as a shell", () => {
    for (const tool of SHELL_TOOLS) {
      const d = evaluate(loaded, { tool, harness: "gemini", inputText: "npm install left-pad" });
      expect([tool, d.action]).toEqual([tool, "ask"]);
    }
  });
  it("leaves a non-shell tool whose text names an install alone", () => {
    expect(evaluate(loaded, { tool: "Write", harness: "claude-code", inputText: "npm install left-pad" }).action).toBe("allow");
  });
  it("never turns an ask or a deny into an allow", () => {
    const deny: LoadedPolicy = { policy: { ...loaded.policy, rules: [{ tool: "bash", action: "deny" }] } };
    expect(evaluate(deny, { tool: "Bash", harness: "claude-code", inputText: "npm install left-pad" }).action).toBe("deny");
    const ask: LoadedPolicy = { policy: { ...loaded.policy, rules: [{ tool: "bash", action: "ask" }] } };
    expect(evaluate(ask, { tool: "Bash", harness: "claude-code", inputText: "npm ci" })).toMatchObject({ action: "ask", reason: "rule bash" });
  });
});

describe("full access (case 83)", () => {
  it("turns the install's ask into a deny", () => {
    const a = decideCall(loaded, { harness: "claude-code", tool: "Bash", toolInput: { command: "npx create-some-app x" }, fullAccess: true });
    expect(a.action).toBe("deny");
    expect(a.reason).toContain("package install: npm runs create-some-app (no version)");
  });
});

describe("the lockfile keeps an allow (section 6)", () => {
  const lock: Record<string, LockEntry[]> = {
    npm: [
      { name: "left-pad", version: "1.3.0", registry: true },
      { name: "@types/node", version: "20.11.0", registry: true },
      { name: "from-git", version: "1.0.0", registry: false },
      { name: "JSONStream", version: "1.3.5", registry: true },
    ],
    bun: [{ name: "left-pad", version: "1.3.0", registry: true }],
    pip: [{ name: "Django", version: "5.1.2", registry: true }],
    go: [{ name: "golang.org/x/text", version: "v0.20.0", registry: true }],
  };
  const ctx = (raw: string) => ({ raw, lockfile: (m: string) => lock[m] });
  const decide = (raw: string) => installDecision("bash", folded(raw), ctx(raw));
  it("keeps the allow when every package is pinned at the version named", () => {
    for (const raw of ["npm install left-pad@1.3.0", "npm i left-pad@1.3.0 @types/node@20.11.0", "pip install django==5.1.2", "pip install Django_==5.1.2".replace("_", ""), "go get golang.org/x/text@v0.20.0", "npx left-pad", "npx left-pad@1.3.0", "bunx left-pad"]) {
      expect([raw, decide(raw)]).toEqual([raw, undefined]);
    }
  });
  it("asks for anything else", () => {
    for (const raw of [
      "npm install left-pad", // no version: npm moves to the newest
      "npm install left-pad@1.2.0", // another version
      "npm install left-pad@^1.3.0", // a range
      "npm install left-pad@latest", // a tag
      "npm install left-pad@1.3.0 is-number@7.0.0", // one not pinned
      "npm install -g left-pad@1.3.0", // global: no project lockfile vouches
      "npm install from-git@1.0.0", // pinned, but not from the registry
      "npm install jsonstream@1.3.5", // the folded name of a capitalized entry is another package
      "pnpm dlx left-pad", // dlx fetches every time
      "npx left-pad@1.2.0", // npx with another version fetches it
      "npm install left-pad@1.3.0 && pip install requests==2.32.3",
      "pip install -r requirements.txt",
      "echo x | xargs npm install left-pad@1.3.0",
      "npm i lеft-pad@1.3.0", // a Cyrillic е: folds to the pinned name, installs another
    ]) {
      expect([raw, decide(raw)?.action]).toEqual([raw, "ask"]);
    }
  });
  it("asks with no context, no lockfile, or raw text that does not match", () => {
    expect(installDecision("bash", folded("npm i left-pad@1.3.0"))?.action).toBe("ask");
    expect(installDecision("bash", folded("npm i left-pad@1.3.0"), { raw: "npm i left-pad@1.3.0", lockfile: () => undefined })?.action).toBe("ask");
    expect(installDecision("bash", folded("npm i left-pad@1.3.0"), { raw: "npm i other@1.3.0", lockfile: (m) => lock[m] })?.action).toBe("ask");
  });
});

describe("the lockfile read from disk", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  const project = () => {
    const d = mkdtempSync(path.join(os.tmpdir(), "derm-x-"));
    dirs.push(d);
    return d;
  };
  const npmLock = readFileSync(new URL("lockfiles/package-lock.after.json", dir), "utf8");
  const snapshot = (cwd: string) => (m: Parameters<typeof findLockfile>[0]) => findLockfile(m, cwd)?.entries;
  it("finds the nearest lockfile above the folder", () => {
    const d = project();
    writeFileSync(path.join(d, "package-lock.json"), npmLock);
    const sub = path.join(d, "packages", "web");
    mkdirSync(sub, { recursive: true });
    expect(installDecision("bash", "npm i left-pad@1.2.0", { raw: "npm i left-pad@1.2.0", lockfile: snapshot(sub) })).toBeUndefined();
    expect(installDecision("bash", "npm i left-pad@1.3.0", { raw: "npm i left-pad@1.3.0", lockfile: snapshot(sub) })?.action).toBe("ask");
  });
  it("does not follow a lockfile that is a link, and does not read a relative folder", () => {
    const d = project();
    const elsewhere = project();
    writeFileSync(path.join(elsewhere, "real.json"), npmLock);
    symlinkSync(path.join(elsewhere, "real.json"), path.join(d, "package-lock.json"));
    expect(installDecision("bash", "npm i left-pad@1.2.0", { raw: "npm i left-pad@1.2.0", lockfile: snapshot(d) })?.action).toBe("ask");
    expect(installDecision("bash", "npm i left-pad@1.2.0", { raw: "npm i left-pad@1.2.0", lockfile: snapshot("relative/folder") })?.action).toBe("ask");
  });
  it("never reads the live lockfile itself: with no snapshot, an install the file pins still asks", () => {
    const d = project();
    writeFileSync(path.join(d, "package-lock.json"), npmLock);
    const ctx = { raw: "npm i left-pad@1.2.0", cwd: d } as unknown as Parameters<typeof installDecision>[2];
    expect(installDecision("bash", "npm i left-pad@1.2.0", ctx)?.action).toBe("ask");
  });
});

describe("the install.call record (contracts/events.md section 5)", () => {
  it("gives the schema's fields, with inLockfile null when no lockfile was read", () => {
    const installs = parseInstalls("npm add left-pad");
    expect(installCallDetails(installs, "ask", "toolu_INSTALL1")).toEqual([
      { trust: "client", toolUseId: "toolu_INSTALL1", manager: "npm", form: "add", packages: [{ name: "left-pad", version: null, ecosystem: "npm", inLockfile: null }], decision: "ask", check: null },
    ]);
    const withLock = installCallDetails(parseInstalls("pip install django==5.1.2"), "allow", null, () => [{ name: "Django", version: "5.1.2", registry: true }]);
    expect((withLock[0]?.packages as { inLockfile: boolean }[])[0]?.inLockfile).toBe(true);
  });
  it("never reads as an install what the fixture says is not one (contracts/fixtures/installs/)", () => {
    const not = base.filter((c) => !c.expect.install);
    expect(not.length).toBeGreaterThanOrEqual(5);
    for (const c of not) expect([c.id, installDecision("bash", folded(c.text))]).toEqual([c.id, undefined]);
  });
});
