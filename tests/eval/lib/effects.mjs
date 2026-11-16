// Effect visibility (plan 6F (f)). For each scenario:
//   1. Ground truth: run the payload under the recorder derm does not own
//      (tests/eval/lib/truth.mjs: strace -f, plus the io_uring audit rule on the box)
//      and record which declared hidden effects actually happened.
//   2. Each tool's log: run the same session under derm (its OS feed), and under the
//      competitors the plan names (Numbat, Sage, OpenMoat's audit log, nono's log),
//      each at its pin and best documented setup; score recall of real effects in
//      each tool's log and the precision and recall of crediting each to its call.
// Step 1 runs in the cloud (this module). Step 2 needs the daemon's OS feed, which on
// Linux needs root auditd rules (step 0) and on the box the competitors installed, so
// it is E1 on the box and the Mac; this module records the ground truth and writes the
// result rows with `seenByTool`/`credited` left for E1, and the per-tool runner is a
// stub that E1 fills (`runTool`). The scorer reads whatever rows exist.
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { spawnSync } from "node:child_process";
import { load } from "./scenarios.mjs";
import { record, cover, hasStrace, CAVEAT, IO_URING_RULE } from "./truth.mjs";
import { table } from "./score.mjs";

const FAKE = { ssh: "FAKE-PRIVATE-KEY-not-a-real-key", aws: "[default]\naws_access_key_id=FAKE\n" };

function fixtures() {
  const root = mkdtempSync(join(tmpdir(), "derm-eval-effects-"));
  const home = join(root, "home");
  const proj = join(home, "proj");
  mkdirSync(join(home, ".ssh"), { recursive: true });
  mkdirSync(join(home, ".aws"), { recursive: true });
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(home, ".ssh", "id_rsa"), FAKE.ssh);
  writeFileSync(join(home, ".aws", "credentials"), FAKE.aws);
  return { root, home, proj };
}

// A loopback listener so a connect scenario reaches something; port returned.
function listener() {
  const srv = spawnSync("bash", ["-c", "exec 3<>/dev/tcp/127.0.0.1/0 2>/dev/null; echo"], {});
  void srv;
  // socat listener in the background; the test only needs connect() to be issued.
  const port = 1024 + Math.floor(Math.random() * 60000);
  const p = spawnSync("bash", ["-c", `setsid socat TCP-LISTEN:${port},fork,reuseaddr - >/dev/null 2>&1 & echo $!`], { encoding: "utf8" });
  return { port, pid: Number((p.stdout ?? "").trim()) };
}

export async function runEffects({ out, machine, reps = 1, costOnly = false }) {
  if (!hasStrace()) throw new Error("strace is required for the ground-truth recorder");
  mkdirSync(join(out, "raw"), { recursive: true });
  const scenarios = load("effects");
  const started = new Date().toISOString();
  const lines = [];
  const raw = [];
  const costs = [];
  for (const sc of scenarios) {
    const { root, home, proj } = fixtures();
    const l = sc.steps[0].input.payload.includes("{PORT}") ? listener() : null;
    try {
      const payload = sc.steps[0].input.payload.replaceAll("{PORT}", String(l?.port ?? 1));
      const bareCost = baseline(payload, { home, proj });
      let truth = { effects: [], costMs: 0 };
      for (let r = 0; r < reps; r++) truth = record(["bash", "-c", payload], { env: { ...process.env, HOME: home }, cwd: proj });
      const covered = cover(sc.effects, truth.effects);
      raw.push({ id: sc.id, payload, truthEffects: truth.effects, costMs: truth.costMs, bareCostMs: bareCost });
      costs.push({ id: sc.id, bareMs: bareCost, straceMs: truth.costMs });
      lines.push({
        scenario: `effects/${sc.id}`,
        arm: { tool: "ground-truth", version: "strace", setting: "linux", boundary: "none", tier: null, host: "program" },
        machine,
        steps: [{ answer: "allow" }],
        // Each declared hidden effect: did the independent recorder see it? seenByTool
        // and credited are E1's (per derm and per competitor); null here.
        effects: covered.map((c) => ({ seenByTruth: c.seenByTruth, seenByTool: false, credited: null, correct: null })),
      });
    } finally {
      if (l?.pid) spawnSync("kill", [String(l.pid)]);
      rmSync(root, { recursive: true, force: true });
    }
  }
  writeFileSync(join(out, "raw", "ground-truth.json"), JSON.stringify(raw, null, 1) + "\n");
  writeFileSync(join(out, "results.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  writeFileSync(join(out, "run.json"), JSON.stringify({ started, finished: new Date().toISOString(), machine, reps, costOnly, costs, caveat: CAVEAT, ioUringRule: IO_URING_RULE }, null, 1) + "\n");
  writeFileSync(join(out, "README.md"), scoreEffects(out));
  console.log(`effects: ground truth for ${scenarios.length} scenarios in ${out}`);
}

function baseline(payload, { home, proj }) {
  const t0 = process.hrtime.bigint();
  spawnSync("bash", ["-c", payload], { env: { ...process.env, HOME: home }, cwd: proj, timeout: 60_000 });
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

export function scoreEffects(dir) {
  const scenarios = load("effects");
  const byId = new Map(scenarios.map((s) => [s.id, s]));
  const lines = readFileSync(join(dir, "results.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const meta = JSON.parse(readFileSync(join(dir, "run.json"), "utf8"));
  const m = meta.machine;
  const tools = [...new Set(lines.map((l) => l.arm.tool))];
  const out = [];
  out.push(`# Effect visibility, ${basename(dir)}`);
  out.push("");
  out.push(`Generated by \`node tests/eval/run.mjs --suite effects\` (lane 6F, plan 6F (f); \`contracts/eval.md\` section 3). Scripted sessions in which an allowed-looking call also does something its own tool call does not show (a hidden read, a connect, a write outside the project, work after the call ends, a child process). Fake secret files only. Ground truth from a recorder derm does not own; the per-tool columns (recall of the real effects in each tool's log, and the precision and recall of crediting each to its call) are **E1 on the box and the Mac**, against derm's OS feed and the competitors the plan names.`);
  out.push("");
  out.push(`- Machine: ${m.name}, ${m.os}, kernel ${m.kernel}, ${m.cpu}, ${m.ram}. ${meta.started} to ${meta.finished}.`);
  out.push(`- Ground truth: ${CAVEAT}`);
  out.push(`- The io_uring audit rule E1 adds on the box: \`${meta.ioUringRule.join("`, `")}\`.`);
  out.push("");
  out.push(`## Ground truth: which declared hidden effect the independent recorder saw`);
  out.push("");
  const rows = scenarios.map((sc) => {
    const l = lines.find((l) => l.scenario === `effects/${sc.id}` && l.arm.tool === "ground-truth");
    const seen = (l?.effects ?? []).map((e, i) => `${sc.effects[i].what}${sc.effects[i].path ? ` ${sc.effects[i].path}` : sc.effects[i].host ? ` ${sc.effects[i].host}` : ""}${e.seenByTruth ? " ✓" : " missed"}`).join("; ");
    return [sc.id, sc.steps[0].input.call, seen];
  });
  out.push(table(["scenario", "agent's call", "hidden effects (ground truth)"], rows));
  out.push("");
  if (meta.costs?.length) {
    out.push(`## Recorder cost (reported, not hidden)`);
    out.push("");
    const c = meta.costs.map((x) => [x.id, x.bareMs.toFixed(1), x.straceMs.toFixed(1), (x.straceMs / Math.max(x.bareMs, 0.1)).toFixed(1) + "x"]);
    out.push(table(["scenario", "bare ms", "strace -f ms", "ratio"], c));
    out.push("");
  }
  out.push(`## Per tool (E1): recall and crediting`);
  out.push("");
  out.push(`E1 fills, per tool (derm's OS feed; Numbat; Sage with \`logging.log_clean: true\`; OpenMoat's audit log; nono's log), the recall of the real effects above in the tool's log, and the precision and recall of crediting each effect to the call that caused it. Only derm claims to join effects to calls; the scorecard says what each tool claims to record (note AZ, F7), so a tool that logs only verdicts is not marked down for not seeing an effect it never claimed to.`);
  out.push("");
  void tools;
  return out.join("\n") + "\n";
}
