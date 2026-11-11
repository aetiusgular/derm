// Turns the recorder's raw.jsonl (record-setup.ts) into the red tests'
// fixtures: one JSON file per lane (5bA.json, 5bB.json) holding every
// recorded hook call, grouped by the TypeScript test case it came from, with
// temp folders, the fake daemon's folder and the repository named by
// placeholders; and the Rust test list per lane
// (crates/derm-cli/tests/hook_cases_<lane>.rs), one #[test] per case.
//   node contracts/fixtures/hook-cases/gen.mjs /tmp/raw.jsonl
// The wave 5b base ran it on main at e29ce27's TypeScript (10 Nov 2026).

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const here = import.meta.dirname;
const repo = path.resolve(here, "..", "..", "..");
const raw = readFileSync(process.argv[2] ?? path.join(here, "raw.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));

const LANE_A = new Set(["claude-code", "codex", "gemini", "openclaude", "qwen-code", "droid", "command-code", "kimi", "auggie", "copilot-cli", "grok"]);
const lane = (agent) => (LANE_A.has(agent) ? "5bA" : "5bB");

function placeholders(call) {
  const map = new Map();
  if (call.daemon) map.set(call.daemon.dir, "{D}");
  let n = 0;
  for (const f of call.files) {
    if (f.kind !== "dir") continue;
    const top = f.path.split("/").slice(0, 3).join("/");
    if (top === f.path && !map.has(top)) map.set(top, `{T${n++}}`);
  }
  map.set(call.repo, "{REPO}");
  return map;
}

function sub(s, map) {
  let out = s;
  // Longest first, so a folder inside another is named by its own placeholder.
  for (const [from, to] of [...map].sort((a, b) => b[0].length - a[0].length)) out = out.split(from).join(to);
  return out;
}

function sent(lines) {
  const out = [];
  for (const l of lines ?? []) {
    if (l.op === "hello") continue;
    if (l.op === "event") {
      const e = l.event ?? {};
      out.push({ op: "event", kind: e.kind ?? null, harness: e.harness ?? null, decision: e.detail?.decision ?? null, tool: e.detail?.tool ?? null });
    } else if (l.op === "approve") {
      const r = l.request ?? {};
      out.push({ op: "approve", harness: r.harness ?? null, tool: r.tool ?? null });
    } else out.push({ op: String(l.op) });
  }
  return out;
}

function reply(call) {
  const r = call.result;
  if (r && typeof r === "object" && "exitCode" in r) return { stdout: r.stdout, stderr: r.stderr, exit: r.exitCode };
  // Hermes's decide.ts answers with an object; `derm hook hermes` prints it.
  return { stdout: `${JSON.stringify(r)}\n`, stderr: "", exit: 0 };
}

const byTest = new Map();
for (const call of raw) {
  if (call.threw) throw new Error(`a recorded call threw: ${call.test}`);
  const map = placeholders(call);
  const files = call.files
    .filter((f) => !(call.daemon && f.path.startsWith(call.daemon.dir)))
    .filter((f) => f.kind !== "socket")
    .map((f) => ({ ...f, path: sub(f.path, map), ...(f.text != null ? { text: sub(f.text, map) } : {}), ...(f.target ? { target: sub(f.target, map) } : {}) }));
  const c = {
    agent: call.agent,
    event: call.event,
    stdin: sub(call.stdin, map),
    env: Object.fromEntries(Object.entries(call.env).map(([k, v]) => [k, sub(v, map)])),
    cwd: sub(call.cwd, map),
    files,
    daemon: call.daemon ? call.daemon.approve : null,
    want: (({ stdout, stderr, exit }) => ({ stdout: sub(stdout, map), stderr: sub(stderr, map), exit }))(reply(call)),
    sent: sent(call.sent),
    ms: call.ms,
    // A call no process can make the same way (a test passed its own
    // dependencies) is not replayed; manual.json lists it for the lane.
    ...(call.replayable === true ? {} : { manual: call.replayable }),
  };
  const t = byTest.get(call.test) ?? { test: call.test, entry: call.entry, calls: [] };
  t.calls.push(c);
  byTest.set(call.test, t);
}

function slug(test) {
  const [file, name] = test.split(" :: ");
  const stem = path.basename(file, ".test.ts").replace(/[^a-z0-9]+/gi, "_");
  const pkg = file.split("/")[1].replace(/^derm-/, "").replace(/[^a-z0-9]+/gi, "_");
  const s = `${pkg}__${stem}__${name}`.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  return s.slice(0, 110);
}

const manual = [];
for (const ln of ["5bA", "5bB"]) {
  const cases = [];
  const ids = new Set();
  for (const t of byTest.values()) {
    // A case belongs to the lane of its first call's agent; a case that
    // calls agents of both lanes would be split (none does at e29ce27).
    const lanes = new Set(t.calls.map((c) => lane(c.agent)));
    if (lanes.size > 1) throw new Error(`case spans lanes: ${t.test}`);
    if (!lanes.has(ln)) continue;
    let id = slug(t.test);
    for (let i = 2; ids.has(id); i++) id = `${slug(t.test).slice(0, 105).replace(/_+$/, "")}_${i}`;
    ids.add(id);
    cases.push({ id, test: t.test, entry: t.entry, calls: t.calls });
  }
  const doc = {
    source: "the TypeScript dialect tests at e29ce27, recorded by contracts/fixtures/hook-cases/record-setup.ts and turned into this file by gen.mjs (wave 5b base, 10 Nov 2026)",
    lane: ln,
    equivalence: "contracts/hook-dialects.md section 9.3",
    cases,
  };
  writeFileSync(path.join(here, `${ln}.json`), `${JSON.stringify(doc, null, 1)}\n`);
  for (const c of cases) for (const [i, call] of c.calls.entries()) if (call.manual) manual.push({ lane: ln, case: c.id, call: i, test: c.test, why: call.manual });
  const rs = [
    `//! Lane ${ln}'s red tests (the wave 5b base): every case of the TypeScript`,
    `//! dialect tests that calls a ${ln === "5bA" ? "Claude-format" : "native or Hermes"} hook, replayed against \`derm hook\` from`,
    `//! \`contracts/fixtures/hook-cases/${ln}.json\` by \`support/replay.rs\`. Generated by`,
    "//! `contracts/fixtures/hook-cases/gen.mjs`; do not edit by hand. They fail on",
    "//! the base, whose dialects are stubs, and pass when the lane is done.",
    "//! Run with `cargo test -p derm-cli --features w5b-red --test hook_cases_" + ln + "`.",
    "",
    "mod support;",
    "",
    "const CASES: &str = include_str!(\"../../../contracts/fixtures/hook-cases/" + ln + ".json\");",
    "",
    ...cases.flatMap((c) => [`/// ${c.test.replace(/\n/g, " ")}`, "#[test]", `fn ${c.id}() {`, `    support::replay::case(CASES, ${JSON.stringify(c.id)});`, "}", ""]),
  ].join("\n");
  writeFileSync(path.join(repo, "crates", "derm-cli", "tests", `hook_cases_${ln}.rs`), rs);
  console.log(ln, cases.length, "cases", cases.reduce((n, c) => n + c.calls.length, 0), "calls");
}

writeFileSync(path.join(here, "manual-calls.json"), `${JSON.stringify({ source: "gen.mjs: recorded calls the replay skips, for each lane to port by hand (contracts/hook-dialects.md section 9.4)", calls: manual }, null, 1)}\n`);
console.log("manual calls", manual.length);
