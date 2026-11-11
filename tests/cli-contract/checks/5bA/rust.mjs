// Lane 5bA (wave 5b): every contract check of the Claude-format agents run
// again with derm's TypeScript hook replaced by the Rust one, `derm hook
// <agent> <event>` (plans/toolkit_wave5b_plan.md section 2.1: "the contract
// checks pass against every real CLI the cloud runs, each with derm's
// TypeScript hook replaced"), and lane 5bA's own Grok check (BCR-7).
//
// The checks are lane L's (L/*.mjs), lane F's (dermClaude.mjs,
// dermCodex.mjs) and lane I's Gemini (I/geminiGate.mjs), not copied by hand:
// at load this module stages each file in a temp folder with its relative
// imports made absolute, its own folder (HERE) kept as the original, and the
// one line that names derm's hook changed:
//   - L's `node --no-warnings "${HOOK}" <agent> pre` becomes
//     `"<derm>" hook <agent> pre`;
//   - the Claude Code plugin, the Codex plugin and the Gemini extension are
//     staged as copies whose hooks/hooks.json runs `"<derm>" hook <agent>
//     <event>` (derm by its absolute path, case 227) instead of node.
// Each check keeps its id with `-rust` added, so a run shows both.
//
// run.mjs loads only one-letter lane folders (`/^[A-Z]$/`), so this folder
// runs on its own:
//   DERM_BIN=target/debug/derm node tests/cli-contract/checks/5bA/rust.mjs \
//     --claude <claude> --codex <codex> --cli <agent>=<path> ... [--only <ids>] [--json <file>]
// (the same CLI flags as run.mjs). A check whose CLI is not given is skipped.

import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CHECKS = path.resolve(HERE, "..");
const ROOT = path.resolve(HERE, "..", "..", "..", "..");

/** derm's binary: DERM_BIN, else the workspace's release or debug build. */
export function dermBin() {
  for (const p of [process.env.DERM_BIN, path.join(ROOT, "target", "release", "derm"), path.join(ROOT, "target", "debug", "derm")]) {
    if (p && existsSync(p)) return path.resolve(p);
  }
  return null;
}

const DERM = dermBin();

/** A file's text with every relative import made absolute, except `keep`. */
function absolutize(text, fromDir, keep = []) {
  const fix = (spec) => (spec.startsWith(".") && !keep.includes(spec) ? pathToFileURL(path.resolve(fromDir, spec)).href : spec);
  return text
    .replace(/(from\s+)"([^"]+)"/g, (_m, a, spec) => `${a}"${fix(spec)}"`)
    .replace(/(import\(\s*)"([^"]+)"/g, (_m, a, spec) => `${a}"${fix(spec)}"`);
}

/** Replaces `from` in `text`, failing loudly when it is not there (a check that moved). */
function must(text, from, to, file) {
  if (!text.includes(from)) throw new Error(`5bA staging: ${file} no longer holds ${JSON.stringify(from.slice(0, 80))}`);
  return text.split(from).join(to);
}

const HERE_LINE = "const HERE = path.dirname(fileURLToPath(import.meta.url));";

/** A copy of a plugin package whose hooks/hooks.json runs derm's Rust hook. */
function stagePlugin(stage, pkg, agent, events) {
  const src = path.join(ROOT, "packages", pkg);
  const dst = path.join(stage, "packages", pkg);
  cpSync(src, dst, { recursive: true, filter: (p) => !p.includes(`${path.sep}node_modules`) });
  const file = path.join(dst, "hooks", "hooks.json");
  let text = readFileSync(file, "utf8");
  // Since lane 5bF the plugin's own hooks file runs `derm hook` through
  // hooks/derm-gate.sh: nothing to replace, the copy already runs Rust.
  if (text.includes("derm-gate.sh")) return dst;
  for (const [from, to] of events) {
    const re = new RegExp(`node --no-warnings \\\\"[^"\\\\]*derm-hook\\.mjs\\\\" ${from}`, "g");
    if (!re.test(text)) throw new Error(`5bA staging: ${pkg}/hooks/hooks.json has no ${from} hook`);
    text = text.replace(re, `\\"${DERM}\\" hook ${agent} ${to}`);
  }
  writeFileSync(file, text);
  return dst;
}

async function stage() {
  if (!DERM) return [];
  const st = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "derm5bA-"));
  const out = [];
  // Lane L: _lib.mjs and the agents' files, `./_lib.mjs` kept local.
  mkdirSync(path.join(st, "L"));
  const lDir = path.join(CHECKS, "L");
  const hookLine = 'node --no-warnings "${HOOK}" ';
  const rustLine = `"${DERM}" hook `;
  for (const f of readdirSync(lDir).filter((f) => f.endsWith(".mjs"))) {
    let t = absolutize(readFileSync(path.join(lDir, f), "utf8"), lDir, ["./_lib.mjs"]);
    if (t.includes(HERE_LINE)) t = t.replace(HERE_LINE, `const HERE = ${JSON.stringify(lDir)};`);
    if (f === "_lib.mjs" || f === "openclaude.mjs") t = must(t, hookLine, rustLine, `L/${f}`);
    writeFileSync(path.join(st, "L", f), t);
  }
  for (const f of readdirSync(lDir).filter((f) => f.endsWith(".mjs") && f !== "_lib.mjs").sort()) {
    const m = await import(pathToFileURL(path.join(st, "L", f)).href);
    out.push(...m.checks);
  }
  // Lane F: Claude Code and Codex, each with its plugin staged.
  const claudePlugin = stagePlugin(st, "derm-claude-plugin", "claude-code", [["pre", "pre"], ["post", "post"]]);
  const codexPlugin = stagePlugin(st, "derm-codex-plugin", "codex", [["pre", "pre"], ["post", "post"]]);
  const geminiExt = stagePlugin(st, "derm-gemini-extension", "gemini", [["before", "before"], ["after", "after"]]);
  const one = async (rel, name, from, to, harness, exportName) => {
    const src = path.join(CHECKS, rel);
    let t = absolutize(readFileSync(src, "utf8"), path.dirname(src));
    t = must(t, HERE_LINE, `const HERE = ${JSON.stringify(path.dirname(src))};`, rel);
    t = must(t, from, to, rel);
    const dst = path.join(st, name);
    writeFileSync(dst, t);
    const m = await import(pathToFileURL(dst).href);
    for (const c of m[exportName]) out.push({ ...c, harness: c.harness ?? harness });
  };
  await one("dermClaude.mjs", "dermClaude.mjs", 'const PLUGIN = path.resolve(HERE, "..", "..", "..", "packages", "derm-claude-plugin");', `const PLUGIN = ${JSON.stringify(claudePlugin)};`, "claude", "dermClaudeChecks");
  await one("dermCodex.mjs", "dermCodex.mjs", 'const PLUGIN = path.resolve(HERE, "..", "..", "..", "packages", "derm-codex-plugin");', `const PLUGIN = ${JSON.stringify(codexPlugin)};`, "codex", "dermCodexChecks");
  await one("I/geminiGate.mjs", "geminiGate.mjs", 'const EXTENSION = path.resolve(HERE, "..", "..", "..", "..", "packages", "derm-gemini-extension");', `const EXTENSION = ${JSON.stringify(geminiExt)};`, "gemini", "checks");
  // Lane 5bA's own.
  const g = await import(pathToFileURL(path.join(HERE, "grokMarks.mjs")).href);
  return [...out.map((c) => ({ ...c, id: `${c.id}-rust` })), ...g.grokMarksChecks(DERM)];
}

export const checks = await stage();

// ---- standalone runner (run.mjs does not load this folder) ----

function parseArgs(argv) {
  const out = { codex: null, claude: null, cli: {}, only: null, json: null, timeout: 240 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === "--codex") out.codex = next();
    else if (a === "--claude") out.claude = next();
    else if (a === "--cli") {
      const v = next();
      const eq = v.indexOf("=");
      out.cli[v.slice(0, eq)] = v.slice(eq + 1);
    } else if (a === "--only") out.only = new Set(next().split(","));
    else if (a === "--json") out.json = next();
    else if (a === "--timeout") out.timeout = Number(next());
    else throw new Error(`unknown argument ${a}`);
  }
  return out;
}

function version(bin) {
  try {
    return execFileSync(bin, ["--version"], { encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "pipe"] }).trim().split("\n")[0];
  } catch {
    return null;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = parseArgs(process.argv.slice(2));
  if (!DERM) {
    console.error("no derm binary (DERM_BIN, target/release, target/debug)");
    process.exit(2);
  }
  console.log(`derm: ${DERM}`);
  const results = [];
  for (const c of checks) {
    if (args.only && !args.only.has(c.id) && !args.only.has(c.id.replace(/-rust$/, ""))) continue;
    const bin = c.harness === "codex" ? args.codex : c.harness === "claude" ? args.claude : (args.cli[c.harness] ?? null);
    const v = bin ? version(bin) : null;
    if (!bin || !v) {
      results.push({ id: c.id, status: "skip", finding: `no ${c.harness} CLI` });
      console.log(`SKIP  ${c.id}`);
      continue;
    }
    const t0 = Date.now();
    let r;
    try {
      r = await Promise.race([
        c.run({ binPath: bin, version: v, codexPath: args.codex, claudePath: args.claude }),
        new Promise((resolve) => setTimeout(() => resolve({ status: "error", finding: `timed out after ${args.timeout}s` }), args.timeout * 1000)),
      ]);
    } catch (e) {
      r = { status: "error", finding: String(e?.stack ?? e) };
    }
    const s = Math.round((Date.now() - t0) / 1000);
    results.push({ id: `${c.id}@${v.split(" ")[0]}`, ...r, seconds: s });
    console.log(`${r.status.toUpperCase().padEnd(5)} ${c.id}@${v.split(" ")[0]} (${s}s)  ${String(r.finding ?? "").slice(0, 400)}`);
  }
  const n = (s) => results.filter((r) => r.status === s).length;
  console.log(`\n${results.length} checks: ${n("pass")} pass, ${n("info")} info, ${n("fail") + n("error")} fail or error, ${n("skip")} skipped`);
  if (args.json) writeFileSync(args.json, JSON.stringify(results, null, 2));
  process.exit(n("fail") + n("error") > 0 ? 1 : 0);
}
