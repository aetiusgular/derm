// The dev and held-out split (plans/toolkit_wave6_plan.md section 3: "Every corpus
// is split into a dev half and a held-out half before derm is tuned against it").
//
// The rule, fixed 12 Nov 2026 by lane 6F before any wave 6 fix ran against the
// suite, and the same for every suite:
//   1. A scenario derm has already been tuned against goes to `dev`, whatever its
//      hash. For MoatBench that is the 17 scenarios of
//      contracts/fixtures/eval/moatbench-e0-allowed.json: the base wrote red tests
//      from them, and integration's gate fixes (R-E0-1 to R-E0-5) and lane 6D's
//      first tests (R-E0-6) are written against them.
//   2. Within each group (MoatBench: the source file, so every category keeps both
//      halves), the other scenarios are ordered by the SHA-256 of `<suite>/<id>`.
//   3. The first floor(n/2) of the group go to `heldout`, or fewer when rule 1 has
//      already put more than half of the group in `dev`; the rest go to `dev`.
// The split is written into each scenario file and never recomputed after: a
// scenario added later gets its half from this rule once, and a test holds the
// committed files to the rule (tests/eval/eval.test.ts).
import { createHash } from "node:crypto";

export function hashOf(suite, id) {
  return createHash("sha256").update(`${suite}/${id}`).digest("hex");
}

// items: [{ id, group }]; forcedDev: Set of ids. Returns Map id -> "dev"|"heldout".
export function split(suite, items, forcedDev) {
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
