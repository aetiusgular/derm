#!/usr/bin/env node
// Copies the shared TypeScript helpers from packages/derm-claude-plugin/src/core/
// (the canonical copy) into the packages in `targets` below. Each harness
// copies a plugin's own folder into its cache and nothing outside it, so a
// plugin carries what it uses of the core itself. A test in each plugin runs
// this with --check.
//
//   node packages/derm-claude-plugin/scripts/sync-core.mjs          copy
//   node packages/derm-claude-plugin/scripts/sync-core.mjs --check  exit 1 on any difference
//
// Who carries what (19 Nov 2026). Every gate decides in Rust: `derm hook` for
// the command hooks, `derm gate serve` for the plugins. So a plugin carries
// only the small files its own process still uses:
// - owner.ts: who may own derm's files, for the serve client's check of the
//   derm it starts (Kilo, OpenClaw, OpenCode, Cline, Amp).
// - redact.ts: Cline's and Amp's guard in front of redaction, and Amp's
//   dialog text and its redaction with no co-process.
// - text.ts: Cline's approval responder's folder test.
// fold.ts and confusables.ts stay in the canonical folder for library/trust
// and crates/derm-core/gen/gen-fold-tables.mjs, which read them there.
// The copies that left: Codex's and Hermes's at the wave 5b close; the
// compat and native hook packages', with the packages, and the matcher in
// the five plugins, on 19 Nov 2026; later that day the matcher itself
// (policy, command, gate, daemon, destructive, installs) and the whole copy
// in derm-gemini-extension, whose printer became `derm connect gemini
// --rules --print`.

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const source = path.join(here, "..", "src", "core");
const check = process.argv.includes("--check");

// Tests stay with the canonical copy. Subfolders the core holds whole are
// listed here (none since `installs/` went on 19 Nov 2026).
const SUBFOLDERS = [];
const tsIn = (dir) => (existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".ts")) : []);
const all = [
  ...tsIn(source),
  ...SUBFOLDERS.flatMap((d) => tsIn(path.join(source, d)).map((f) => path.join(d, f))),
]
  .filter((f) => !f.endsWith(".test.ts"))
  .sort();

/** Package name to the core files it carries. */
const targets = {
  "derm-opencode-plugin": ["owner.ts"],
  "derm-kilo-plugin": ["owner.ts"],
  "derm-openclaw-plugin": ["owner.ts"],
  "derm-amp-plugin": ["owner.ts", "redact.ts"],
  "derm-cline": ["owner.ts", "redact.ts", "text.ts"],
};

let differences = 0;
let copies = 0;
for (const [pkg, files] of Object.entries(targets)) {
  const target = path.join(here, "..", "..", pkg, "src", "core");
  for (const f of files) {
    if (!all.includes(f)) {
      console.error(`${pkg}: ${f} is not a file of the core`);
      process.exit(1);
    }
  }
  if (!check) {
    mkdirSync(target, { recursive: true });
    for (const d of SUBFOLDERS) if (files.some((f) => f.startsWith(d + path.sep))) mkdirSync(path.join(target, d), { recursive: true });
  }
  const present = [...tsIn(target), ...SUBFOLDERS.flatMap((d) => tsIn(path.join(target, d)).map((f) => path.join(d, f)))];
  for (const extra of present.filter((f) => !files.includes(f))) {
    differences++;
    if (check) console.error(`extra: ${path.join(target, extra)}`);
    else rmSync(path.join(target, extra));
  }
  for (const f of files) {
    copies++;
    const want = readFileSync(path.join(source, f));
    const dest = path.join(target, f);
    const have = existsSync(dest) ? readFileSync(dest) : null;
    if (have && have.equals(want)) continue;
    differences++;
    if (check) console.error(`differs: ${dest}`);
    else writeFileSync(dest, want);
  }
}
if (check) {
  if (differences) process.exit(1);
  console.log(`core copies match (${copies} files in ${Object.keys(targets).length} packages)`);
} else {
  console.log(`synced ${copies} core files into ${Object.keys(targets).length} packages (${differences} written or removed)`);
}
