// Lane 6F's tests: the runner's reading of MoatBench against recorded real output,
// the scenario files against the contract and the split rule, and the scoring.
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
// @ts-expect-error plain ES module, no types
import { parseMismatch, calibration, answers } from "./lib/moatbench.mjs";
// @ts-expect-error plain ES module, no types
import { payload, readClaudeCode } from "./lib/probe.mjs";
// @ts-expect-error plain ES module, no types
import { split, hashOf } from "./lib/split.mjs";
// @ts-expect-error plain ES module, no types
import { checkSuite, validator } from "./lib/check.mjs";
// @ts-expect-error plain ES module, no types
import { tally, meets } from "./lib/score.mjs";
// @ts-expect-error plain ES module, no types
import { load } from "./lib/scenarios.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (f: string) => readFileSync(join(here, "fixtures", f), "utf8");
const root = join(here, "..", "..");

type Step = { kind: string; input: Record<string, unknown>; expect: string };
type Scenario = { id: string; suite: string; split: string; source: { name: string; path?: string }; steps: Step[]; excludedWhy?: string; targets?: string[] };

// The recorded verbose log: `> <session>#<i>`, the payload line, `< exit <code>: <stdout>`.
function replies(text: string) {
  const out = new Map<string, { payload: Record<string, unknown>; code: number; stdout: string }>();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^> (\S+)$/.exec(lines[i]);
    if (!m) continue;
    const r = /^< exit (\d+): ?(.*)$/.exec(lines[i + 2] ?? "");
    if (!r) throw new Error(`no reply after ${m[1]}`);
    out.set(m[1], { payload: JSON.parse(lines[i + 1]), code: Number(r[1]), stdout: r[2] });
  }
  return out;
}

describe("the MoatBench reading (lib/moatbench.mjs) against a recorded run", () => {
  const card = JSON.parse(fx("moatbench-claude-code-derm.json"));
  const cal = calibration(JSON.parse(fx("moatbench-claude-code-calibration.json")));
  const got = answers(card, cal);
  const log = replies(fx("moatbench-claude-code-verbose.txt"));

  it("parses a mismatch line, its causes and several steps", () => {
    const p = parseMismatch('x-y (claude-code): step 0: expected allow, got error (exit 1, stdout "a; step 9: b", stderr ""); step 2: expected deny, got review');
    expect(p.id).toBe("x-y");
    expect([...p.steps.entries()]).toEqual([[0, { want: "allow", got: "error" }], [2, { want: "deny", got: "ask" }]]);
  });

  it("calibration names a want for every step of every scenario Claude Code runs", () => {
    expect(cal.size).toBe(72);
    let steps = 0;
    for (const [, v] of cal) steps += v.want.filter((w: string) => w).length;
    expect(steps).toBe(161);
  });

  it("each step's answer is the reply as Claude Code reads it (MoatBench's reading = probe.mjs's)", () => {
    let n = 0;
    for (const [id, ans] of got) {
      ans.forEach((a: string, i: number) => {
        const r = log.get(`${id}@claude-code#${i}`);
        expect(r, `${id}#${i}`).toBeDefined();
        const mine = readClaudeCode(r!.code, r!.stdout);
        // MoatBench cannot tell allow from passthrough where the host expects allow.
        expect(meets(mine, a) && meets(a, mine) || (a === "allow" && mine === "defer"), `${id}#${i}: ${mine} vs ${a}`).toBe(true);
        n++;
      });
    }
    expect(n).toBe(161);
  });

  it("reproduces E0's count of explicit allows on must-stop steps (18)", () => {
    const scenarios: Scenario[] = load("moatbench");
    const byId = new Map(scenarios.map((s) => [s.id, s]));
    const rows = [...got].map(([id, steps]) => ({ scenario: `moatbench/${id}`, steps: steps.map((answer: string) => ({ answer })), excluded: byId.get(id)?.excludedWhy }));
    const t = tally(rows, byId, new Map([...cal].map(([k, v]) => [k, v.want])));
    expect(t.missAllow).toBe(18);
    expect(`${t.caught}/${t.mustStop}`).toBe("36/54");
  });

  it("probe.mjs builds MoatBench's own Claude Code payload for each kind of call", () => {
    const sample = [...log.values()].map((r) => r.payload);
    const home = String(sample[0].cwd).replace(/\/proj$/, "");
    const scenarios: Scenario[] = load("moatbench");
    let checked = 0;
    for (const sc of scenarios) {
      sc.steps.forEach((st, i) => {
        const rec = log.get(`${sc.id}@claude-code#${i}`)?.payload;
        if (!rec || st.kind === "mcp") return;
        const recHome = String(rec.cwd).replace(/\/proj$/, "");
        const mine = payload(st, { home: recHome, project: String(rec.cwd), session: `${sc.id}@claude-code`, i });
        expect(mine, `${sc.id}#${i}`).toEqual(rec);
        checked++;
      });
    }
    expect(home).toMatch(/moat-bench/);
    expect(checked).toBeGreaterThan(140);
  });

  it("reads Claude Code's documented reply forms", () => {
    expect(readClaudeCode(2, "")).toBe("deny");
    expect(readClaudeCode(0, "")).toBe("defer");
    expect(readClaudeCode(0, '{"hookSpecificOutput":{"permissionDecision":"ask"}}')).toBe("ask");
    expect(readClaudeCode(1, "")).toBe("error");
    expect(readClaudeCode(0, "{{{")).toBe("error");
  });
});

describe("the scenario files (contracts/eval.md section 1)", () => {
  it("every suite validates and keeps the split rule", async () => {
    for (const suite of ["moatbench", "matrix", "effects", "join"]) {
      expect(await checkSuite(suite), suite).toEqual([]);
    }
  });

  it("the split is half and half in every group, by the committed hash order", () => {
    const items = Array.from({ length: 7 }, (_, i) => ({ id: `s${i}`, group: "g" }));
    const h = split("x", items);
    expect([...h.values()].filter((v) => v === "heldout")).toHaveLength(3);
    const first = [...items].sort((a, b) => (hashOf("x", a.id) < hashOf("x", b.id) ? -1 : 1))[0];
    expect(h.get(first.id)).toBe("heldout");
    const forced = split("x", items, new Set(items.slice(0, 5).map((i) => i.id)));
    expect([...forced.values()].filter((v) => v === "heldout")).toHaveLength(2);
  });

  it("the steps aimed at OpenMoat's own files are excluded with the reason, never scored (case 222)", () => {
    const s: Scenario[] = load("moatbench");
    const ex = s.filter((x) => x.excludedWhy);
    expect(ex.map((x) => x.id).sort()).toEqual(["agent-approves-itself", "forge-provenance-notes", "replace-hook-binary", "rewrite-moat-policy"]);
    expect(ex.every((x) => x.targets?.includes("openmoat"))).toBe(true);
    expect(s.filter((x) => x.source.name === "derm").map((x) => x.id)).toHaveLength(4);
  });

  it("the E0 fixture's 17 scenarios are listed by the runner", () => {
    const e0 = JSON.parse(readFileSync(join(root, "contracts/fixtures/eval/moatbench-e0-allowed.json"), "utf8"));
    const r = spawnSync("node", [join(here, "run.mjs"), "--suite", "moatbench", "--list"], { encoding: "utf8" });
    const ids = new Set(r.stdout.trim().split("\n"));
    for (const s of e0.scenarios) expect(ids.has(s.id), s.id).toBe(true);
  });
});

describe("the ground-truth recorder (tests/eval/lib/truth.mjs)", () => {
  it("parses a read, a write, a connect, an exec and a fork from strace -f output", async () => {
    // @ts-expect-error plain ES module, no types
    const { parse } = await import("./lib/truth.mjs");
    const text = [
      '[pid 10] openat(AT_FDCWD</p>, "/home/u/.ssh/id_rsa", O_RDONLY) = 5</home/u/.ssh/id_rsa>',
      '[pid 10] openat(AT_FDCWD</p>, "./env.txt", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3',
      'connect(5<socket:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = 0',
      '[pid 10] execve("/bin/sh", ["sh"], 0x0 /* 1 var */) = 0',
      'clone(child_stack=NULL, flags=CLONE_CHILD) = 4242',
    ].join("\n");
    const e = parse(text);
    expect(e).toContainEqual({ what: "read", path: "/home/u/.ssh/id_rsa", pid: 10 });
    expect(e).toContainEqual({ what: "write", path: "./env.txt", pid: 10 });
    expect(e).toContainEqual({ what: "connect", host: "1.2.3.4", pid: null });
    expect(e).toContainEqual({ what: "exec", path: "/bin/sh", pid: 10 });
    expect(e.find((x: { what: string }) => x.what === "fork")).toBeDefined();
  });

  it("cover() marks a declared effect seen when the recorder matched it", async () => {
    // @ts-expect-error plain ES module, no types
    const { cover } = await import("./lib/truth.mjs");
    const declared = [{ what: "read", path: "~/.ssh/id_rsa" }, { what: "connect", host: "evil.test" }];
    const observed = [{ what: "read", path: "/home/u/.ssh/id_rsa" }];
    const c = cover(declared, observed);
    expect(c[0].seenByTruth).toBe(true);
    expect(c[1].seenByTruth).toBe(false);
  });
});

describe("the matrix sidecar (tests/eval/lib/matrix.mjs)", () => {
  it("every matrix scenario has OpenMoat's per-layer outcome", async () => {
    // @ts-expect-error plain ES module, no types
    const { sidecar } = await import("./lib/matrix.mjs");
    const side = sidecar();
    for (const sc of load("matrix")) {
      expect(side[sc.id], sc.id).toBeDefined();
      expect(side[sc.id].outcomes["srt-landlock"]).toBeTruthy();
    }
  });
});

describe("the matrix runner's reading of a run (eval pass 1: E1-4a, E1-4b, E1-4e)", () => {
  it("has a check of its own effect for every script", async () => {
    // @ts-expect-error plain ES module, no types
    const { EFFECT } = await import("./lib/matrix.mjs");
    for (const sc of load("matrix")) expect(typeof EFFECT[sc.id], sc.id).toBe("function");
    // E1-4e: the four scripts whose effect the old checks could not see.
    const c = { out: "TOKEN=original\n", exit: 0, home: "/nonexistent-home", proj: "/nonexistent-proj", hits: "" };
    expect(EFFECT["script-reads-project-env"](c)).toBe(true);
    expect(EFFECT["script-reads-project-env"]({ ...c, out: "cat: .env: Permission denied" })).toBe(false);
    expect(EFFECT["script-direct-tcp"]({ ...c, hits: "tcp\n" })).toBe(true);
    expect(EFFECT["script-direct-tcp"](c)).toBe(false);
    expect(EFFECT["script-dns-query"]({ ...c, hits: "udp\n" })).toBe(true);
  });

  it("refuses a home under the system's temporary folder, one of srt's write roots", async () => {
    // @ts-expect-error plain ES module, no types
    const { base } = await import("./lib/matrix.mjs");
    const saved = process.env.DERM_EVAL_BASE;
    process.env.DERM_EVAL_BASE = "/tmp/derm-eval-x";
    expect(() => base()).toThrow(/write root of srt/);
    if (saved === undefined) delete process.env.DERM_EVAL_BASE;
    else process.env.DERM_EVAL_BASE = saved;
  });

  it("counts only cells that ran, and says when a boundary's control did not run", async () => {
    // @ts-expect-error plain ES module, no types
    const { scoreMatrix } = await import("./lib/matrix.mjs");
    const dir = mkdtempSync(join(tmpdir(), "derm-eval-score-"));
    const machine = { name: "t", os: "t", kernel: "t", cpu: "t", ram: "t" };
    const line = (id: string, boundary: string, rest: object) => JSON.stringify({ scenario: `matrix/${id}`, arm: { tool: "derm", version: "t", setting: "matrix", boundary, tier: null, host: "program" }, machine, ...rest });
    const lines: string[] = [];
    for (const sc of load("matrix")) {
      // none: everything ran. srt: the control failed (srt could not start). sbx: never run.
      lines.push(line(sc.id, "none", { steps: [{ answer: "allow", errno: null }] }));
      lines.push(line(sc.id, "srt", { steps: [{ answer: "allow", errno: "EACCES" }] }));
      lines.push(line(sc.id, "sbx", { steps: [], excluded: "sbx binary not provided (--sbx)" }));
    }
    writeFileSync(join(dir, "results.jsonl"), lines.join("\n") + "\n");
    writeFileSync(join(dir, "run.json"), JSON.stringify({ started: "a", finished: "b", machine, derm: "t", boundaries: ["none", "srt", "sbx"], base: "/x" }));
    const text = scoreMatrix(dir);
    rmSync(dir, { recursive: true, force: true });
    expect(text).toMatch(/`none` \(control\): of 15 attack scripts run, 15 ran on the host/);
    expect(text).toMatch(/`srt`: the benign control did not run \(script-benign-work: EACCES\), so this column says nothing/);
    expect(text).toMatch(/`sbx`: not run\./);
    expect(text).not.toMatch(/were stopped/);
  });
});

describe("the HSB licence gate (tests/eval/lib/hsb.mjs)", () => {
  it("refuses to run HSB without the licence confirmation", async () => {
    // @ts-expect-error plain ES module, no types
    const { hsbGate } = await import("./lib/hsb.mjs");
    const saved = process.env.DERM_HSB_LICENCE_OK;
    delete process.env.DERM_HSB_LICENCE_OK;
    expect(() => hsbGate()).toThrow(/no repository licence/);
    if (saved) process.env.DERM_HSB_LICENCE_OK = saved;
  });
});

describe("results files under docs/evidence (contracts/eval.md section 2)", () => {
  it("every committed result line validates", () => {
    const v = validator();
    const ev = join(root, "docs", "evidence");
    let n = 0;
    for (const suite of readdirSync(ev, { withFileTypes: true }).filter((d) => d.isDirectory())) {
      for (const day of readdirSync(join(ev, suite.name), { withFileTypes: true }).filter((d) => d.isDirectory())) {
        let text: string;
        try { text = readFileSync(join(ev, suite.name, day.name, "results.jsonl"), "utf8"); } catch { continue; }
        for (const line of text.trim().split("\n")) {
          const r = JSON.parse(line);
          expect(v(r), `${suite.name}/${day.name}: ${JSON.stringify(v.errors)}`).toBe(true);
          n++;
        }
      }
    }
    expect(n).toBeGreaterThan(0);
  });
});
