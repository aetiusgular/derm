// MoatBench through any hook (contracts/eval.md section 4; plan 6F (a)).
//
// How a step's answer is read, from OpenMoat 0.19.0's own code at 483d740
// (crates.io `openmoat` 0.19.0 `src/commands/bench.rs:309-357` and `openmoat-hosts`
// 0.19.0 `src/bench.rs:95-145`, read 12 Nov):
// - `openmoat bench --format json` lists each scenario whose steps miss as one
//   `mismatches` line, `<id> (<host>): step <i>: expected <want>, got <got>[ (<cause>)]`,
//   steps joined by "; ". A step is a miss unless `got == want`, or `want` is allow
//   and `got` passthrough (`Answer::meets`).
// - Against a hook (`--hook`), `want` is the host's reading of the scenario's
//   verdict (`Host::seen`: Codex reads review as deny, Cursor depends on the call).
//   Against OpenMoat itself, `want` is the kernel's verdict, with a step's
//   `sandboxed:` expectation where OpenMoat's OS sandbox holds the host.
// - A scenario with a call the host has no tool for is not sent on that host.
// So a step's answer is its mismatch's `got`, else its `want`. `want` per host is
// read from MoatBench itself: a calibration run with a hook that fails every call
// makes every step a miss (`got error`), and each line names its `want`. A step
// whose `want` is allow and that did not miss was answered allow or passthrough;
// MoatBench does not tell them apart, and neither does this runner (it records
// allow). No host logic is copied here.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// MoatBench host ids (`openmoat bench --help` at 0.19.0) and the derm hook each is
// registered with (`crates/derm-cli/src/hook/mod.rs` AGENTS; `connect/gates.json`).
export const DERM_HOOK = {
  "claude-code": "claude-code pre",
  codex: "codex pre",
  cursor: "cursor pre",
  "copilot-cli": "copilot-cli pre",
  "gemini-cli": "gemini before",
  goose: "goose pre",
  "antigravity-cli": "antigravity pre",
  hermes: "hermes pre",
};
// E0's limits (plans/parallel/tk_eval_baseline.md): Cursor partly (MoatBench sends
// beforeShellExecution and beforeReadFile, derm registers preToolUse and
// beforeMCPExecution), Hermes not comparable (derm gates Hermes through its Python
// plugin, not the shell-hook payload MoatBench sends). Reported, never ranked.
export const NOT_COMPARABLE = {
  hermes: "derm gates Hermes through derm_gate.py; MoatBench sends Hermes's shell-hook payload, which derm's registration never receives",
  cursor: "partly: MoatBench sends beforeShellExecution and beforeReadFile, which derm does not register (it registers preToolUse and beforeMCPExecution)",
};

// `expected X, got Y` words (openmoat-hosts 0.19.0 `Answer::word`) to the contract's.
const WORD = { allow: "allow", passthrough: "defer", error: "error", review: "ask", deny: "deny" };

export function word(w) {
  if (!(w in WORD)) throw new Error(`unknown MoatBench answer ${w}`);
  return WORD[w];
}

// One `mismatches` line to { id, host, steps: Map<i, {want, got}>, other: [lines] }.
export function parseMismatch(line) {
  const m = /^(\S+) \(([a-z-]+)\): (.*)$/s.exec(line);
  if (!m) throw new Error(`not a mismatch line: ${line}`);
  const [, id, host, rest] = m;
  const steps = new Map();
  const other = [];
  // A cause is in parentheses and can hold "; " inside quotes, so step entries are
  // found by their own pattern, not by splitting.
  const re = /step (\d+)(?: #[^:]+)?: expected (\w+), got (\w+)/g;
  let s;
  let matched = 0;
  while ((s = re.exec(rest))) {
    steps.set(Number(s[1]), { want: word(s[2]), got: word(s[3]) });
    matched++;
  }
  if (matched === 0) other.push(rest);
  return { id, host, steps, other };
}

export function runBench({ openmoat, host, hook, cwd }) {
  const args = ["bench", "--format", "json"];
  if (hook) args.push("--hook", hook);
  if (host) args.push("--host", host);
  const r = spawnSync(openmoat, args, { encoding: "utf8", cwd, maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0 && r.status !== 1) {
    throw new Error(`openmoat bench exited ${r.status}: ${r.stderr.slice(0, 400)}`);
  }
  return JSON.parse(r.stdout);
}

// The hook that fails every call (exit 1, stdout outside every protocol): every
// step is a miss, so every mismatch line names the step's `want` on that host.
export const FAIL_HOOK = "cat >/dev/null; echo '{{{derm-eval-calibration'; exit 1";

// From a calibration scorecard: Map id -> { want: [answer...] } for the scenarios the
// host ran. Throws if a step did not come back as an error (the calibration failed).
export function calibration(card) {
  const out = new Map();
  for (const line of card.mismatches) {
    const p = parseMismatch(line);
    const want = [];
    for (const [i, st] of p.steps) {
      if (st.got !== "error") throw new Error(`calibration: ${p.id} step ${i} got ${st.got}`);
      want[i] = st.want;
    }
    out.set(p.id, { want });
  }
  return out;
}

// Per-step answers of one run against the host's calibration.
export function answers(card, cal) {
  const miss = new Map();
  for (const line of card.mismatches) {
    const p = parseMismatch(line);
    miss.set(p.id, p);
  }
  const out = new Map();
  for (const [id, { want }] of cal) {
    const m = miss.get(id);
    out.set(id, want.map((w, i) => (m && m.steps.has(i) ? m.steps.get(i).got : w)));
  }
  return out;
}

// OpenMoat's own run: `want` is the kernel's verdict, not the host's reading, and a
// step's `sandboxed:` expectation holds where OpenMoat's OS sandbox is in place
// (bench.rs:303-318). The scorecard's `sandboxed` column says whether it was: it
// counts runs the sandbox is expected to hold, which only happens on such a host.
export function openmoatAnswers(card, scenarios, host, ran, sandboxedSteps) {
  const sandboxedHost = Object.values(card.categories).some((r) => r.sandboxed > 0);
  const miss = new Map();
  for (const line of card.mismatches) {
    const p = parseMismatch(line);
    if (p.host === host) miss.set(p.id, p);
  }
  const out = new Map();
  for (const sc of scenarios) {
    if (sc.source.name !== "openmoat" || !ran.has(sc.id)) continue;
    const alt = sandboxedSteps[sc.id] ?? {};
    out.set(
      sc.id,
      sc.steps.map((st, i) => {
        const m = miss.get(sc.id);
        if (m && m.steps.has(i)) return m.steps.get(i).got;
        if (sandboxedHost && alt[i]) return alt[i];
        return st.expect;
      }),
    );
  }
  return { answers: out, sandboxedHost };
}

export function sandboxedSteps() {
  return JSON.parse(readFileSync(join(here, "openmoat-sandboxed.json"), "utf8")).scenarios;
}
