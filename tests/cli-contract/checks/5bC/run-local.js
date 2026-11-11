// Runs this folder's checks until run.mjs loads 5b<X> lane folders
// (tk_lane_5bC.md, request 4). `.js`, so run.mjs never loads it as a check.
//   node tests/cli-contract/checks/5bC/run-local.js --cli opencode=<path> [--only id,id]
import { readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const cli = {};
let only;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--cli") {
    const [k, v] = args[++i].split("=");
    cli[k] = v;
  } else if (args[i] === "--only") only = new Set(args[++i].split(","));
}
let failed = 0;
for (const f of readdirSync(here).filter((n) => n.endsWith(".mjs")).sort()) {
  const mod = await import(pathToFileURL(path.join(here, f)).href);
  for (const c of mod.checks) {
    if (only && !only.has(c.id)) continue;
    const bin = cli[c.harness];
    if (!bin) {
      console.log(`SKIP  ${c.id}  no --cli ${c.harness}`);
      continue;
    }
    const t = Date.now();
    let r;
    try {
      r = await c.run({ binPath: bin });
    } catch (e) {
      r = { status: "error", finding: String(e) };
    }
    if (r.status === "fail" || r.status === "error") failed++;
    console.log(`${r.status.toUpperCase().padEnd(5)} ${c.id} (${Math.round((Date.now() - t) / 1000)}s)  ${r.finding}`);
  }
}
process.exitCode = failed ? 1 : 0;
