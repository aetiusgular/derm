// Terminal-Bench through Harbor with derm in the path (plan 6F (g); eval pass
// 1's E1-4c). This file builds the bundle the Harbor agent
// (tests/eval/harbor/derm_codex.py) uploads into each task's container, and
// reads a finished Harbor job into one table. The task runs need Docker and
// a model the containers can reach, so they run on the box, never in CI.
//
//   node tests/eval/lib/terminal-bench.mjs bundle --out DIR --derm BIN --daemon BIN [--policy FILE]
//   node tests/eval/lib/terminal-bench.mjs score --jobs DIR [--jobs DIR ...] [--json FILE]
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..", "..");
const PLUGIN = path.join(REPO, "packages", "derm-codex-plugin");
const PRESET = path.join(REPO, "crates", "derm-cli", "src", "setup", "presets", "workspace-write.json");

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}

/**
 * Codex's trust entries for every handler of a plugin's hooks.json, as
 * tests/cli-contract/checks/dermCodex.mjs writes them (Codex 0.163.0 to
 * 0.169.0: hooks/src/engine/discovery.rs, config/src/fingerprint.rs). A test
 * holds the two equal.
 */
export function trustToml(hooksJson, keySource = "derm@derm") {
  const labels = { PreToolUse: "pre_tool_use", PostToolUse: "post_tool_use" };
  const lines = [];
  for (const [event, groups] of Object.entries(hooksJson.hooks)) {
    groups.forEach((group, gi) => {
      group.hooks.forEach((h, hi) => {
        const handler = { type: h.type, command: h.command, timeout: h.timeout ?? 600, async: h.async ?? false };
        if (h.statusMessage !== undefined) handler.statusMessage = h.statusMessage;
        const identity = { event_name: labels[event], hooks: [handler] };
        if (group.matcher !== undefined) identity.matcher = group.matcher;
        const hash = createHash("sha256").update(JSON.stringify(sortKeys(identity))).digest("hex");
        lines.push(`[hooks.state."${keySource}:hooks/hooks.json:${labels[event]}:${gi}:${hi}"]`, `trusted_hash = "sha256:${hash}"`, "");
      });
    });
  }
  return lines.join("\n");
}

/** The bundle: binaries, a local marketplace with derm's Codex plugin, its trust entries, the policy. */
export function buildBundle({ out, derm, daemon, policy }) {
  for (const [what, p] of [["--derm", derm], ["--daemon", daemon]]) {
    if (!p || !existsSync(p) || !statSync(p).isFile()) throw new Error(`${what}: no such file: ${p}`);
  }
  rmSync(out, { recursive: true, force: true });
  mkdirSync(path.join(out, "bin"), { recursive: true });
  cpSync(derm, path.join(out, "bin", "derm"));
  cpSync(daemon, path.join(out, "bin", "derm-daemon"));
  for (const b of ["derm", "derm-daemon"]) chmodSync(path.join(out, "bin", b), 0o755);
  const mkt = path.join(out, "mkt");
  mkdirSync(path.join(mkt, ".agents", "plugins"), { recursive: true });
  writeFileSync(
    path.join(mkt, ".agents", "plugins", "marketplace.json"),
    JSON.stringify({ name: "derm", plugins: [{ name: "derm", source: { source: "local", path: "./derm" } }] }),
  );
  for (const part of [".codex-plugin", "hooks"]) cpSync(path.join(PLUGIN, part), path.join(mkt, "derm", part), { recursive: true });
  const hooksJson = JSON.parse(readFileSync(path.join(PLUGIN, "hooks", "hooks.json"), "utf8"));
  writeFileSync(path.join(out, "trust.toml"), `\n${trustToml(hooksJson)}`);
  // The preset file's `policy` object alone is a policy (contracts/eval.md, section 4).
  const pol = policy ? JSON.parse(readFileSync(policy, "utf8")) : JSON.parse(readFileSync(PRESET, "utf8")).policy;
  if (!pol || typeof pol !== "object" || !Array.isArray(pol.rules)) throw new Error("the policy has no rules");
  writeFileSync(path.join(out, "policy.json"), JSON.stringify(pol, null, 2), { mode: 0o600 });
  return { out, files: ["bin/derm", "bin/derm-daemon", "mkt", "trust.toml", "policy.json"] };
}

/**
 * The fixed subset: Terminal-Bench's own sample of ten 2.0 tasks, as Harbor
 * 0.25.0's registry.json pins it (`terminal-bench-sample@2.0`,
 * laude-institute/terminal-bench-2-0-sample at 7e917f3). Not hand-picked.
 */
export const DATASET = "terminal-bench-sample@2.0";
export const SUBSET = Object.freeze([
  "build-cython-ext",
  "chess-best-move",
  "configure-git-webserver",
  "fix-code-vulnerability",
  "log-summary-date-ranges",
  "polyglot-c-py",
  "qemu-alpine-ssh",
  "qemu-startup",
  "regex-log",
  "sqlite-with-gcov",
]);

function readJson(p) {
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

/** One trial folder of a Harbor job, read into a row. Fields Harbor did not write stay null. */
export function readTrial(dir) {
  const result = readJson(path.join(dir, "result.json")) ?? {};
  const agentDir = path.join(dir, "agent");
  const report = readJson(path.join(agentDir, "derm-report.json"));
  const events = existsSync(path.join(agentDir, "derm-events.jsonl"))
    ? readFileSync(path.join(agentDir, "derm-events.jsonl"), "utf8")
        .split("\n")
        .filter(Boolean)
        .map((l) => {
          try {
            return JSON.parse(l);
          } catch {
            return null;
          }
        })
        .filter(Boolean)
    : null;
  const rewards = result.verifier_result?.rewards ?? result.verifier_result?.reward ?? null;
  const reward = typeof rewards === "number" ? rewards : rewards && typeof rewards === "object" ? (rewards.reward ?? Object.values(rewards)[0] ?? null) : null;
  const t = (a, b) => (a && b ? (Date.parse(b) - Date.parse(a)) / 1000 : null);
  const approvals = events ? events.filter((e) => e.kind === "approval" && e.source === "adapter") : null;
  const by = (d) => (approvals ? approvals.filter((e) => e.detail?.decision === d).length : null);
  return {
    trial: path.basename(dir),
    task: result.task_name ?? null,
    reward,
    error: result.exception_info?.exception_type ?? null,
    agentSeconds: t(result.agent_execution?.started_at, result.agent_execution?.finished_at),
    derm: report !== null,
    events: report?.events ?? null,
    flags: report?.flags ?? null,
    otel: report?.bySource?.otel ?? (events ? events.filter((e) => e.source === "otel").length : null),
    gateCalls: approvals ? approvals.length : null,
    allowed: by("allow"),
    denied: by("deny"),
    asked: by("ask"),
  };
}

/** Every trial of a job folder. */
export function readJob(jobDir) {
  return readdirSync(jobDir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(path.join(jobDir, d.name, "result.json")))
    .map((d) => readTrial(path.join(jobDir, d.name)));
}

/** One line per job: only trials that finished count toward the pass rate, and the rest are named. */
export function summarize(name, trials) {
  const ran = trials.filter((t) => t.reward !== null);
  const sum = (k) => ran.reduce((a, t) => a + (t[k] ?? 0), 0);
  const med = (xs) => {
    const s = xs.filter((x) => x !== null).sort((a, b) => a - b);
    return s.length ? s[Math.floor(s.length / 2)] : null;
  };
  return {
    job: name,
    trials: trials.length,
    scored: ran.length,
    passed: ran.filter((t) => t.reward >= 1).length,
    notScored: trials.filter((t) => t.reward === null).map((t) => `${t.task ?? t.trial}: ${t.error ?? "no reward"}`),
    medianAgentSeconds: med(ran.map((t) => t.agentSeconds)),
    withDermRecord: ran.filter((t) => t.derm).length,
    gateCalls: sum("gateCalls"),
    denied: sum("denied"),
    flags: sum("flags"),
    otelRecords: sum("otel"),
    trialsWithNoOtel: ran.filter((t) => t.derm && !t.otel).map((t) => t.task ?? t.trial),
  };
}

function arg(argv, name, many = false) {
  const out = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === name && argv[i + 1]) out.push(argv[++i]);
  return many ? out : out[0];
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "bundle") {
    const r = buildBundle({ out: path.resolve(arg(rest, "--out") ?? ""), derm: arg(rest, "--derm"), daemon: arg(rest, "--daemon"), policy: arg(rest, "--policy") });
    console.log(`bundle at ${r.out}: ${r.files.join(", ")}`);
  } else if (cmd === "score") {
    const rows = arg(rest, "--jobs", true).map((j) => summarize(path.basename(j), readJob(j)));
    const json = arg(rest, "--json");
    if (json) writeFileSync(json, JSON.stringify(rows, null, 2));
    for (const r of rows) console.log(JSON.stringify(r));
  } else {
    console.error("usage: terminal-bench.mjs bundle --out DIR --derm BIN --daemon BIN [--policy FILE]\n       terminal-bench.mjs score --jobs DIR [--jobs DIR ...] [--json FILE]");
    process.exit(2);
  }
}
