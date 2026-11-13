#!/usr/bin/env node
// The eval suite's runner (lane 6F; contracts/eval.md; plans/toolkit_wave6_plan.md
// section 2.1 (a) to (h) and section 3).
//
//   node tests/eval/run.mjs --suite <suite> --list [--split dev|heldout]
//   node tests/eval/run.mjs --suite <suite> --check
//   node tests/eval/run.mjs --suite moatbench --run --out <dir> --openmoat <bin> --derm <bin>
//        [--hosts claude-code,codex,...] [--arms derm:workspace-write,derm:strict,derm:none,openmoat]
//        [--arm-file <json>] [--policy-dir <dir>] [--openmoat-tarball <release .tar.xz>]
//   node tests/eval/run.mjs --suite moatbench --score <dir>
//   node tests/eval/run.mjs --suite matrix --run --out <dir> --derm <bin> [--boundaries none,srt]
//   node tests/eval/run.mjs --suite matrix --score <dir>
//   node tests/eval/run.mjs --suite overhead --run --out <dir> --hook '<name>=<command>' ...
//
// Third-party tools run in the cloud or on the box only (rules section 5, item 2).
import { mkdirSync, writeFileSync, readFileSync, existsSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve, isAbsolute } from "node:path";
import { spawnSync } from "node:child_process";
import { load, SUITES } from "./lib/scenarios.mjs";
import { machine } from "./lib/machine.mjs";

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : dflt;
};
const many = (name) => args.flatMap((a, i) => (a === name && i + 1 < args.length ? [args[i + 1]] : []));

function die(msg, code = 2) {
  console.error(`run.mjs: ${msg}`);
  process.exit(code);
}

const suite = opt("--suite");
if (!suite || !SUITES.includes(suite)) die(`--suite is one of ${SUITES.join(", ")}`);

if (flag("--list")) {
  const want = opt("--split");
  if (want && want !== "dev" && want !== "heldout") die("--split is dev or heldout");
  for (const s of load(suite)) if (!want || s.split === want) console.log(s.id);
  process.exit(0);
}

if (flag("--check")) {
  const { checkSuite } = await import("./lib/check.mjs");
  const problems = await checkSuite(suite);
  for (const p of problems) console.error(p);
  console.log(`${suite}: ${load(suite).length} scenarios, ${problems.length} problems`);
  process.exit(problems.length ? 1 : 0);
}

export function sha256File(p) {
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}

function binary(name, p) {
  if (!p) die(`${name} is required`);
  const abs = resolve(p);
  if (!existsSync(abs) || !statSync(abs).isFile()) die(`${name}: ${abs} is not a file`);
  // OpenMoat refuses to run from /tmp, and a binary there is one an agent could swap.
  if (abs.startsWith("/tmp/")) die(`${name}: keep binaries out of /tmp (OpenMoat refuses to run from there)`);
  return abs;
}

function version(bin) {
  const r = spawnSync(bin, ["--version"], { encoding: "utf8" });
  return (r.stdout || r.stderr).trim().split("\n")[0];
}

if (suite === "moatbench" && flag("--run")) {
  const { runMoatbench } = await import("./lib/run-moatbench.mjs");
  const out = resolve(opt("--out") ?? die("--out <dir> is required"));
  const openmoat = binary("--openmoat", opt("--openmoat"));
  const derm = binary("--derm", opt("--derm"));
  const policyDir = resolve(opt("--policy-dir", "/opt/e1/policy"));
  const hosts = opt("--hosts", "claude-code,codex,copilot-cli,gemini-cli,goose,antigravity-cli,cursor,hermes").split(",");
  const arms = opt("--arms", "derm:workspace-write,derm:strict,derm:none,openmoat").split(",");
  const extra = opt("--arm-file") ? JSON.parse(readFileSync(opt("--arm-file"), "utf8")) : [];
  const tarball = opt("--openmoat-tarball");
  const openmoatTarball = tarball ? { name: tarball.split("/").pop(), sha256: sha256File(resolve(tarball)) } : undefined;
  await runMoatbench({ out, openmoat, derm, policyDir, hosts, arms, extra, versions: { openmoat: version(openmoat), derm: version(derm) }, sha: { openmoat: sha256File(openmoat), derm: sha256File(derm) }, machine: machine(), openmoatTarball });
  process.exit(0);
}

if (suite === "moatbench" && opt("--score")) {
  const { scoreMoatbench } = await import("./lib/run-moatbench.mjs");
  const dir = resolve(opt("--score"));
  writeFileSync(join(dir, "README.md"), scoreMoatbench(dir));
  console.log(`wrote ${join(dir, "README.md")}`);
  process.exit(0);
}

if (suite === "matrix" && flag("--run")) {
  const { runMatrix } = await import("./lib/matrix.mjs");
  const out = resolve(opt("--out") ?? die("--out <dir> is required"));
  const derm = binary("--derm", opt("--derm"));
  const boundaries = opt("--boundaries", "none,srt").split(",");
  const srt = opt("--srt");
  await runMatrix({ out, derm, srt: srt ? resolve(srt) : undefined, boundaries, machine: machine(), dermVersion: version(derm) });
  process.exit(0);
}

if (suite === "matrix" && opt("--score")) {
  const { scoreMatrix } = await import("./lib/matrix.mjs");
  const dir = resolve(opt("--score"));
  writeFileSync(join(dir, "README.md"), scoreMatrix(dir));
  console.log(`wrote ${join(dir, "README.md")}`);
  process.exit(0);
}

if (suite === "overhead" && flag("--run")) {
  const { runOverhead } = await import("./lib/overhead.mjs");
  const out = resolve(opt("--out") ?? die("--out <dir> is required"));
  const hooks = many("--hook").map((h) => {
    const i = h.indexOf("=");
    if (i <= 0) die("--hook is <name>=<command>");
    return { name: h.slice(0, i), command: h.slice(i + 1) };
  });
  if (hooks.length === 0) die("at least one --hook <name>=<command>");
  const reps = Number(opt("--reps", "3"));
  await runOverhead({ out, hooks, reps, machine: machine(), openmoat: opt("--openmoat") ? binary("--openmoat", opt("--openmoat")) : undefined });
  process.exit(0);
}

void isAbsolute;
die(`nothing to do for --suite ${suite}: give --list, --check, --run or --score`);
