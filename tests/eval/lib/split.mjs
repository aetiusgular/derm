// The dev and held-out split (plans/toolkit_wave6_plan.md section 3: "Every corpus
// is split into a dev half and a held-out half before derm is tuned against it").
//
// The rule, fixed 12 Nov 2026 by lane 6F, the same for every suite:
//   1. Within each group (MoatBench: the source file, so every category keeps both
//      halves), scenarios are ordered by the SHA-256 of `<suite>/<id>`.
//   2. The first floor(n/2) of the group go to `heldout`, the rest to `dev`.
// The split is written into each scenario file and never recomputed after: a
// scenario added later gets its half from this rule once, and a test holds the
// committed files to the rule (tests/eval/eval.test.ts).
//
// `forcedDev` exists for a later suite whose scenarios are seen before the split.
// MoatBench does not use it. Every MoatBench scenario was seen in E0, and the 17 it
// missed were written into red tests before this lane started (the base's
// contracts_w6.rs; integration's R-E0-1 to R-E0-5, lane 6D's R-E0-6). Forcing those
// 17 into dev would leave a held-out half of scenarios derm already passed, a biased
// sample that overstates derm; a split that ignores them keeps the held-out half a
// fair sample of the set, and the scorecard says which held-out scenarios were seen
// (tests/eval/lib/score.mjs, `seen`). Decided by lane 6F (tk_lane_6F.md, Decisions).
import { createHash } from "node:crypto";

export function hashOf(suite, id) {
  return createHash("sha256").update(`${suite}/${id}`).digest("hex");
}

// items: [{ id, group }]; forcedDev: Set of ids. Returns Map id -> "dev"|"heldout".
export function split(suite, items, forcedDev = new Set()) {
  const groups = new Map();
  for (const it of items) {
    if (!groups.has(it.group)) groups.set(it.group, []);
    groups.get(it.group).push(it.id);
  }
  const out = new Map();
  for (const [, ids] of [...groups.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const forced = ids.filter((id) => forcedDev.has(id));
    const rest = ids.filter((id) => !forcedDev.has(id)).sort((a, b) => {
      const ha = hashOf(suite, a);
      const hb = hashOf(suite, b);
      return ha < hb ? -1 : ha > hb ? 1 : 0;
    });
    const heldout = Math.min(Math.floor(ids.length / 2), rest.length);
    for (const id of forced) out.set(id, "dev");
    rest.forEach((id, i) => out.set(id, i < heldout ? "heldout" : "dev"));
  }
  return out;
}
