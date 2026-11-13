#!/usr/bin/env node
// Writes tests/eval/scenarios/matrix/<id>.json from OpenMoat's hostile-project
// scripts (plan 6F (b): "in the shape of OpenMoat's tests/differential/scenarios.yaml").
//   node tests/eval/lib/import-matrix.mjs <path to OpenMoat scenarios.yaml>
//
// Source: github.com/crocodile-labs/openmoat at 483d740 (= v0.19.0),
// `tests/differential/scenarios.yaml`, its `scripts:` list (MIT OR Apache-2.0;
// NOTICE). The gate allows `npm test` and never sees the script, so only the OS
// boundary can stop it (OpenMoat `crates/openmoat-cli/tests/e2e/differential/
// scripts.rs:1-10`). This importer only transforms the source file: every payload
// string comes from the parsed YAML. The matrix measures what each boundary did to
// the payload (errno per cell), against fake secret files in a throwaway home; the
// payloads are OpenMoat's own benchmark corpus, the same kind already vendored in
// the MoatBench scenarios. OpenMoat's per-layer outcomes go in a sidecar
// (openmoat-matrix.json) so the scenario files stay schema-valid.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { split } from "./split.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");

export function importScripts(yamlPath) {
  const doc = parse(readFileSync(yamlPath, "utf8"));
  const scripts = doc.scripts ?? [];
  const halves = split("matrix", scripts.map((s) => ({ id: s.id, group: "matrix" })));
  const scenarios = [];
  const sidecar = {};
  for (const s of scripts) {
    const o = {
      suite: "matrix",
      id: s.id,
      source: { name: "openmoat", version: "0.19.0", path: "tests/differential/scenarios.yaml (scripts)", licence: "MIT OR Apache-2.0" },
      split: halves.get(s.id),
      steps: [{ kind: "shell", input: { payload: s.payload } }],
    };
    if (!s.threat) {
      o.targets = ["none"];
      o.excludedWhy = "the control: ordinary work, expected to complete under every boundary";
    } else {
      o.targets = ["host"];
    }
    scenarios.push(o);
    // OpenMoat's recorded outcome per Linux layer, with its `why` and any `terminal`
    // need. The runner compares the real result on this machine against the layer it
    // ran under; "ran" means the boundary let the payload complete on the host.
    sidecar[s.id] = {
      why: s.why,
      threat: s.threat ?? null,
      terminal: !!s.terminal,
      outcomes: { "srt-landlock": s.landlock, "srt-isolate": s["isolate-linux"], sbx: s["codex-linux"] ?? s["claude-linux"] },
    };
  }
  return { scenarios, sidecar };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const yamlPath = process.argv[2];
  if (!yamlPath || !existsSync(yamlPath)) {
    console.error("usage: import-matrix.mjs <OpenMoat scenarios.yaml at 483d740>");
    process.exit(2);
  }
  const dir = join(root, "tests/eval/scenarios/matrix");
  mkdirSync(dir, { recursive: true });
  const { scenarios, sidecar } = importScripts(yamlPath);
  for (const s of scenarios) writeFileSync(join(dir, `${s.id}.json`), JSON.stringify(s, null, 2) + "\n");
  writeFileSync(
    join(here, "openmoat-matrix.json"),
    JSON.stringify({ $comment: "OpenMoat 0.19.0's per-layer outcomes for its hostile-project scripts (tests/differential/scenarios.yaml at 483d740); MIT OR Apache-2.0, NOTICE. Read by tests/eval/lib/matrix.mjs.", scenarios: sidecar }, null, 2) + "\n",
  );
  console.log(`${scenarios.length} matrix scenarios written to ${dir}`);
}
