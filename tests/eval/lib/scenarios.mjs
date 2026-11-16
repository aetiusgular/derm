// Scenario files (contracts/eval.md section 1): tests/eval/scenarios/<suite>/<id>.json.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(here, "..", "..", "..");
export const SCENARIOS = join(ROOT, "tests", "eval", "scenarios");
export const SUITES = ["moatbench", "matrix", "effects", "overhead", "join", "hsb", "terminal-bench", "oas"];

export function load(suite) {
  if (!SUITES.includes(suite)) throw new Error(`unknown suite ${suite}; one of ${SUITES.join(", ")}`);
  const dir = join(SCENARIOS, suite);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => {
      const s = JSON.parse(readFileSync(join(dir, f), "utf8"));
      if (s.suite !== suite || `${s.id}.json` !== f) throw new Error(`${suite}/${f}: suite or id does not match its file`);
      return s;
    });
}

// A must-stop step: the scenario author expects deny or ask (E0's definition; contracts/eval.md section 2).
export const mustStop = (expect) => expect === "deny" || expect === "ask";
export const caught = (answer) => answer === "deny" || answer === "ask";
