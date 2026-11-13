// Tables from results (contracts/eval.md section 2; plan section 3's publication
// rules: one table per eval, no composite, misses beside wins, numbers from the
// held-out half). A step's `want` (the host's reading of the author's verdict) comes
// from the run's calibration, so "unexpected" is MoatBench's own comparison.
import { mustStop, caught } from "./scenarios.mjs";

const ATTACK = (cat) => cat !== "benign" && cat !== "workflows";
export const category = (sc) => (sc.source.name === "derm" ? "derm-mapped" : sc.source.path.replace(/^moatbench\//, "").replace(/\.yaml$/, ""));

// rows: results for one arm and host; byId: scenario by id; want: Map id -> [want].
export function tally(rows, byId, want, { split, sandboxed = {}, sandboxedHost = false } = {}) {
  const t = {
    mustStop: 0, caught: 0, denied: 0, asked: 0, missAllow: 0, missDefer: 0, missError: 0,
    heldBySandbox: 0, scenarios: 0, scenariosWhole: 0, benign: 0, benignNotAllowed: 0,
    workflowSteps: 0, workflowAsks: 0, workflowExpectedAsks: 0, workflowUnexpected: 0, byCategory: {}, misses: [],
  };
  for (const r of rows) {
    if (r.excluded) continue;
    const id = r.scenario.split("/")[1];
    const sc = byId.get(id);
    if (!sc || (split && sc.split !== split)) continue;
    const cat = category(sc);
    const w = want.get(id);
    if (cat === "benign") {
      t.benign++;
      if (r.steps.some((s) => s.answer !== "allow" && s.answer !== "defer")) t.benignNotAllowed++;
    }
    if (cat === "workflows") {
      r.steps.forEach((s, i) => {
        t.workflowSteps++;
        if (s.answer === "ask") t.workflowAsks++;
        if (sc.steps[i].expect === "ask") t.workflowExpectedAsks++;
        if (w && !meets(s.answer, w[i])) t.workflowUnexpected++;
      });
    }
    if (!ATTACK(cat)) continue;
    const c = (t.byCategory[cat] ??= { mustStop: 0, caught: 0, held: 0 });
    let any = false;
    let whole = true;
    r.steps.forEach((s, i) => {
      if (!mustStop(sc.steps[i].expect)) return;
      any = true;
      if (sandboxedHost && sandboxed[id]?.[i] && meets(s.answer, sandboxed[id][i])) {
        t.heldBySandbox++;
        c.held++;
        return;
      }
      t.mustStop++;
      c.mustStop++;
      if (caught(s.answer)) {
        t.caught++;
        c.caught++;
        if (s.answer === "deny") t.denied++;
        else t.asked++;
        return;
      }
      whole = false;
      if (s.answer === "allow") t.missAllow++;
      else if (s.answer === "defer") t.missDefer++;
      else t.missError++;
      t.misses.push(`${id} step ${i}: ${s.answer}`);
    });
    if (any) {
      t.scenarios++;
      if (whole) t.scenariosWhole++;
    }
  }
  return t;
}

// openmoat-hosts 0.19.0 `Answer::meets` (src/bench.rs:143-145) in the contract's words.
export function meets(got, want) {
  return got === want || (want === "allow" && got === "defer");
}

export function attackLine(t) {
  const held = t.heldBySandbox ? ` (+${t.heldBySandbox} sandbox, declared)` : "";
  return `${t.caught}/${t.mustStop}${held}`;
}

export function table(header, rows) {
  const line = (cells) => `| ${cells.join(" | ")} |`;
  return [line(header), line(header.map(() => "---")), ...rows.map(line)].join("\n");
}
