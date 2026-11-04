// A linear guard in front of the shared core's redaction (lane P review,
// finding P-S2). The core's secret-pair patterns (src/core/redact.ts
// QUOTED_PAIR and BARE_PAIR) backtrack on a long run of `[A-Za-z0-9_.-]`
// that holds many secret-like words: "token." repeated 500 times (3,000
// characters) takes about 1.1 s, 700 times 3.1 s (measured, Node 22.23). Cline
// gives a plugin hook 3 s and then runs the call under its own policy, and
// turns the plugin off after five failures (docs/sdk/plugins.mdx), so input
// built that way would switch derm off. The cost grows as len² × words per
// run (fitted on the measurements: 1,020 characters with 170 words, 43 ms;
// 3,000 with 500, 1.1 s); this sums that over every run, in one pass, and
// refuses input over the limit before the core sees it. The fix that removes
// the cause is in the core, a request for integration. Amp's plugin carries
// the same file (packages/derm-amp-plugin/src/budget.ts); a test holds them equal.

import { SECRET_LIKE } from "./core/redact.ts";

/** About 240 ms of the core's redaction on this machine class (2.4e-7 ms per unit, fitted). */
export const REDACTION_BUDGET = 1e9;
const RUN = /[A-Za-z0-9_.-]+/g;
const WORDS = new RegExp(SECRET_LIKE.source, "gi");

/** The estimated cost of redacting `text`: Σ len² × secret-like words, over its runs. */
export function redactionCost(text: string): number {
  let cost = 0;
  for (const m of text.matchAll(RUN)) {
    const run = m[0];
    if (run.length < 64) continue;
    const words = run.match(WORDS)?.length ?? 0;
    if (words > 0) cost += run.length * run.length * words;
  }
  return cost;
}

/** The estimated cost over every string key and value under `value`. */
export function valueCost(value: unknown, depth = 0): number {
  if (depth > 64) return Number.POSITIVE_INFINITY;
  if (typeof value === "string") return redactionCost(value);
  if (Array.isArray(value)) return value.reduce((n: number, v) => n + valueCost(v, depth + 1), 0);
  if (typeof value === "object" && value !== null) {
    let n = 0;
    for (const [k, v] of Object.entries(value)) n += redactionCost(k) + valueCost(v, depth + 1);
    return n;
  }
  return 0;
}

/** Why the input is refused before the core sees it, or undefined. */
export function overBudget(value: unknown): string | undefined {
  return valueCost(value) > REDACTION_BUDGET ? "input has long runs of secret-like words that derm cannot check in time" : undefined;
}

/** What replaces a run `defuse` takes out. */
export const DEFUSED = "[redacted by derm: long run with secret-like words]";

/**
 * For output that cannot be refused (a tool already ran): when the total cost
 * is over the budget, every run of 64 characters or more that holds a
 * secret-like word is replaced whole, in one pass, so the core's redaction
 * afterwards is cheap. Under the budget the text is returned as it is.
 */
export function defuseValue(value: unknown): { value: unknown; count: number } {
  if (valueCost(value) <= REDACTION_BUDGET) return { value, count: 0 };
  let count = 0;
  const walk = (v: unknown, depth: number): unknown => {
    if (depth > 64) return DEFUSED;
    if (typeof v === "string") {
      return v.replace(RUN, (run) => {
        WORDS.lastIndex = 0;
        if (run.length < 64 || !WORDS.test(run)) return run;
        count++;
        return DEFUSED;
      });
    }
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [walk(k, depth + 1) as string, walk(x, depth + 1)]));
    return v;
  };
  const out = walk(value, 0);
  return { value: out, count };
}
