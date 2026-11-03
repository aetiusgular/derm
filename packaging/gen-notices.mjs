// Writes packages/<name>/NOTICE for every package that carries a copy of the
// Unicode-derived confusables table (release T6.1; integration w1's open
// item). A package published on its own must carry derm's licence and the
// Unicode licence with it. `--check` exits 1 when a NOTICE differs.
//
//   node packaging/gen-notices.mjs [--check]
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MIT = readFileSync(join(ROOT, "LICENSE"), "utf8").trimEnd();
const UNICODE = readFileSync(join(ROOT, "LICENSES", "Unicode-3.0.txt"), "utf8").trimEnd();

export function notice(name, table) {
  return `${name}
Part of derm, https://github.com/aetiusgular/derm

${MIT}

----------------------------------------------------------------------------

${table} holds mappings derived from Unicode confusables.txt 17.0.0
(2025-07-22), sha256 091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a,
from unicode-org/unicodetools at 578f6c0,
unicodetools/data/security/17.0.0/confusables.txt. It is used under the
Unicode License V3:

${UNICODE}
`;
}

export function packagesWithTables() {
  const out = [];
  for (const name of readdirSync(join(ROOT, "packages")).sort()) {
    for (const rel of ["src/core/confusables.ts", "src/confusables.ts"]) {
      if (existsSync(join(ROOT, "packages", name, rel))) out.push({ name, table: rel });
    }
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const check = process.argv.includes("--check");
  let bad = 0;
  for (const { name, table } of packagesWithTables()) {
    const path = join(ROOT, "packages", name, "NOTICE");
    const want = notice(name, table);
    const have = existsSync(path) ? readFileSync(path, "utf8") : undefined;
    if (have === want) continue;
    if (check) {
      console.error(`stale or missing: packages/${name}/NOTICE`);
      bad++;
    } else {
      writeFileSync(path, want);
      console.log(`wrote packages/${name}/NOTICE`);
    }
  }
  if (check) console.log(bad ? `${bad} NOTICE files differ` : "NOTICE files current");
  process.exit(bad ? 1 : 0);
}
