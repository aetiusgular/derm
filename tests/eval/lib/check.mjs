// `run.mjs --check`: every scenario validates against contracts/eval.schema.json, and
// the committed split is the rule's (tests/eval/lib/split.mjs).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { load, ROOT } from "./scenarios.mjs";
import { split } from "./split.mjs";

export function validator() {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  return ajv.compile(JSON.parse(readFileSync(join(ROOT, "contracts/eval.schema.json"), "utf8")));
}

export function forcedDev(suite) {
  if (suite !== "moatbench") return new Set();
  const e0 = JSON.parse(readFileSync(join(ROOT, "contracts/fixtures/eval/moatbench-e0-allowed.json"), "utf8"));
  return new Set(e0.scenarios.map((s) => s.id));
}

export const groupOf = (s) => (s.source.name === "derm" ? "derm-mapped" : s.source.path ?? s.suite);

export async function checkSuite(suite) {
  const v = validator();
  const all = load(suite);
  const problems = [];
  for (const s of all) {
    if (!v(s)) problems.push(`${suite}/${s.id}: ${v.errors.map((e) => `${e.instancePath} ${e.message}`).join("; ")}`);
  }
  const want = split(suite, all.map((s) => ({ id: s.id, group: groupOf(s) })), forcedDev(suite));
  for (const s of all) if (want.get(s.id) !== s.split) problems.push(`${suite}/${s.id}: split ${s.split}, the rule says ${want.get(s.id)}`);
  return problems;
}
