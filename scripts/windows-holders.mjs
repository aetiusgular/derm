#!/usr/bin/env node
// The holder guard for scripts/windows-held.json (note BF section 4.1).
//
//   node scripts/windows-holders.mjs [--list <vitest list --json output>]
//
// vitest skips the files in scripts/windows-held.json on Windows. That is
// only safe while every test in them is held by a Rust test that runs on
// Windows, so this script fails, on every system, when one is not:
//   - every listed file exists and has at least one test;
//   - every test (`<file> :: <name>`, as `vitest list` names it) has an entry
//     in contracts/fixtures/hook-cases/5bA.json, 5bB.json or manual.json;
//   - a 5bA or 5bB entry is replayed by a test in
//     crates/derm-cli/tests/hook_cases_<lane>.rs;
//   - a manual.json entry names its lane and how it was ported.
// Without --list it runs `npx vitest list <files> --json` itself (`--json` last:
// before the files it would take the first as its output path).
// Exit 0 when all are held, 1 when one is not, 2 on a usage error.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(root, p), "utf8");

/** The problems with `tests` (vitest list entries) against the holders, or [] when every one is held. */
export function problems({ files, tests, fixtures, replays }) {
  const out = [];
  const held = new Map();
  for (const [lane, doc] of Object.entries(fixtures)) {
    for (const c of doc.cases ?? doc) held.set(c.test, { lane, c });
  }
  const count = new Map(files.map((f) => [f, 0]));
  for (const t of tests) {
    if (!count.has(t.file)) continue;
    count.set(t.file, count.get(t.file) + 1);
    const id = `${t.file} :: ${t.name}`;
    const h = held.get(id);
    if (!h) {
      out.push(`no Rust holder: ${id}`);
      continue;
    }
    if (h.lane === "manual") {
      if (!h.c.lane || !h.c.how) out.push(`manual.json names no lane or no port: ${id}`);
    } else if (!replays[h.lane]?.has(h.c.id)) {
      out.push(`${h.lane}.json case ${h.c.id} is not replayed in hook_cases_${h.lane}.rs: ${id}`);
    }
  }
  for (const [f, n] of count) if (n === 0) out.push(`no tests listed in ${f} (moved or renamed? update scripts/windows-held.json)`);
  return out;
}

function main() {
  const args = process.argv.slice(2);
  let listFile;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--list" && args[i + 1]) listFile = args[++i];
    else {
      console.error(`windows-holders: unexpected argument ${JSON.stringify(args[i])}`);
      process.exit(2);
    }
  }
  const { files } = JSON.parse(read("scripts/windows-held.json"));
  const missing = files.filter((f) => !existsSync(join(root, f)));
  if (missing.length) {
    for (const f of missing) console.error(`windows-holders: listed file does not exist: ${f}`);
    process.exit(1);
  }
  const raw = listFile
    ? readFileSync(listFile, "utf8")
    : execFileSync(process.platform === "win32" ? "npx.cmd" : "npx", ["vitest", "list", ...files, "--json"], {
        cwd: root,
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
        shell: process.platform === "win32",
        stdio: ["ignore", "pipe", "inherit"],
      });
  const tests = JSON.parse(raw).map((t) => ({ file: relative(root, t.file).split(sep).join("/"), name: t.name }));
  const fixtures = {};
  for (const lane of ["5bA", "5bB", "manual"]) fixtures[lane] = JSON.parse(read(`contracts/fixtures/hook-cases/${lane}.json`));
  const replays = {};
  for (const lane of ["5bA", "5bB"]) {
    replays[lane] = new Set([...read(`crates/derm-cli/tests/hook_cases_${lane}.rs`).matchAll(/support::replay::case\(\s*CASES,\s*"([^"]+)"/g)].map((m) => m[1]));
  }
  const found = problems({ files, tests, fixtures, replays });
  if (found.length) {
    for (const p of found) console.error(`windows-holders: ${p}`);
    console.error(`windows-holders: ${found.length} of ${tests.length} tests not held; vitest must not skip these files on Windows until they are`);
    process.exit(1);
  }
  console.log(`windows-holders: ${tests.length} tests in ${files.length} files, each held by a Rust test`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
