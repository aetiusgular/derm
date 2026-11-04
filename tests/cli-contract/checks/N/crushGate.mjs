// Lane N: contract checks for derm's Crush dialect (T2.6) against the real
// Crush CLI, driven by `crush run` against a fake OpenAI chat-completions
// server (../../lib/fakeChat.mjs) with a fake derm daemon. The gate is
// registered in a scratch ~/.config/crush/crush.json as
// packages/derm-hooks-native/registration/crush/crush.json gives it.
//
//   node tests/cli-contract/run.mjs --cli crush=/path/to/crush --only crush-derm-deny,...

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { startFakeDaemon } from "../../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOOK = path.resolve(HERE, "..", "..", "..", "..", "packages", "derm-hooks-native", "bin", "derm-hook.mjs");

function run(bin, args, env, cwd, seconds = 150) {
  return new Promise((resolve) => {
    const child = spawn(bin, args, { env, cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => child.kill("SIGKILL"), seconds * 1000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
  });
}

/** One `crush run`. `hooks` replaces the PreToolUse list (default: derm's gate alone). */
async function crushTurn(bin, { policy, script, approve = "none", hooks, mcp = {}, daemon: withDaemon = true, flags = [] }) {
  const fake = await startFakeChat({ script });
  const daemon = await startFakeDaemon({ approve, root: "/tmp" });
  const root = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "crush-derm-"));
  const home = path.join(root, "home");
  const work = path.join(root, "work");
  mkdirSync(path.join(home, ".config", "crush"), { recursive: true });
  mkdirSync(path.join(work, ".git"), { recursive: true });
  const policyFile = path.join(root, "policy.json");
  writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o600 });
  const gate = { name: "derm-gate", command: `node --no-warnings "${HOOK}" crush`, timeout: 120 };
  writeFileSync(
    path.join(home, ".config", "crush", "crush.json"),
    JSON.stringify({
      providers: { fake: { type: "completions", base_url: fake.baseUrl, api_key: "x", models: [{ id: "fake-model", name: "fake", context_window: 100000, default_max_tokens: 1000 }] } },
      models: { large: { provider: "fake", model: "fake-model" }, small: { provider: "fake", model: "fake-model" } },
      mcp,
      hooks: { PreToolUse: hooks ? hooks(gate) : [gate] },
    }),
  );
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    XDG_CACHE_HOME: path.join(home, ".cache"),
    NO_COLOR: "1",
    DERM_POLICY: policyFile,
    ...(withDaemon ? daemon.env() : { DERM_DAEMON_SOCKET: path.join(root, "absent.sock") }),
  };
  try {
    const r = await run(bin, [...flags, "run", "--quiet", "run the step"], env, work);
    return { r, results: toolResults(fake), turns: fake.turns().length, daemon: { events: daemon.events(), approvals: daemon.approvals() }, work, root };
  } finally {
    await fake.close();
    await daemon.close();
    rmSync(root, { recursive: true, force: true });
  }
}

const bash = (command) => (_b, n) => (n === 0 ? { tool: "bash", args: { command, description: "step" } } : { text: "done" });
const ALLOW = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "allow" }] };
const DENY = { version: 1, rules: [{ tool: "bash", action: "deny" }] };
const ran = (t, marker) => t.results.some((x) => x.includes(marker));

export const checks = [
  {
    id: "crush-derm-allow",
    title: "An allowed bash call runs, and the daemon gets derm's record",
    harness: "crush",
    async run({ binPath }) {
      const t = await crushTurn(binPath, { policy: ALLOW, script: bash("echo crush-allowed-ran") });
      const kinds = t.daemon.events.map((e) => `${e.kind}:${e.harness}`);
      const ok = t.r.code === 0 && ran(t, "crush-allowed-ran") && kinds.includes("approval:crush");
      return { status: ok ? "pass" : "fail", finding: `exit ${t.r.code}; ran ${ran(t, "crush-allowed-ran")}; records ${JSON.stringify(kinds)}${ok ? "" : `; ${t.r.err.slice(-300)}`}` };
    },
  },
  {
    id: "crush-derm-deny",
    title: "A denied bash call does not run, the model gets derm's reason, and the turn goes on (case 79)",
    harness: "crush",
    async run({ binPath }) {
      const t = await crushTurn(binPath, { policy: DENY, script: bash("echo crush-denied-ran") });
      const reason = t.results.some((x) => x.includes("derm: rule bash"));
      const ok = !ran(t, "crush-denied-ran") && reason && t.turns >= 2 && t.r.code === 0;
      return { status: ok ? "pass" : "fail", finding: `ran ${ran(t, "crush-denied-ran")}; reason ${reason}; turns ${t.turns}; ${JSON.stringify(t.results).slice(0, 200)}` };
    },
  },
  {
    id: "crush-derm-reject",
    title: "The reject list blocks an endpoint key under an allow rule",
    harness: "crush",
    async run({ binPath }) {
      const t = await crushTurn(binPath, { policy: ALLOW, script: bash("echo export ANTHROPIC_BASE_URL=http://x >> .envrc") });
      const ok = t.results.some((x) => x.includes("reject list: anthropic_base_url"));
      return { status: ok ? "pass" : "fail", finding: JSON.stringify(t.results).slice(0, 240) };
    },
  },
  {
    id: "crush-derm-ask",
    title: "An ask is the derm approver's yes; with no approver it is a deny, never Crush's no-opinion (cases 71, 72)",
    harness: "crush",
    async run({ binPath }) {
      const policy = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "ask" }] };
      const yes = await crushTurn(binPath, { policy, approve: "yes", script: bash("echo crush-approved-ran") });
      const none = await crushTurn(binPath, { policy, approve: "none", script: bash("echo crush-unapproved-ran") });
      const asked = yes.daemon.approvals.filter((a) => a.harness === "crush").length;
      const ok = ran(yes, "crush-approved-ran") && !ran(none, "crush-unapproved-ran") && asked === 1;
      return { status: ok ? "pass" : "fail", finding: `yes: ran ${ran(yes, "crush-approved-ran")}, approvals ${asked}; none: ran ${ran(none, "crush-unapproved-ran")}, ${JSON.stringify(none.results).slice(0, 160)}` };
    },
  },
  {
    id: "crush-derm-control",
    title: "An allowed command that writes Crush's own config asks, and is denied with no approver",
    harness: "crush",
    async run({ binPath }) {
      const t = await crushTurn(binPath, { policy: ALLOW, script: bash("touch .crush.json") });
      const blocked = t.results.some((x) => x.includes("control file (crush.json)"));
      return { status: blocked ? "pass" : "fail", finding: JSON.stringify(t.results).slice(0, 240) };
    },
  },
  {
    id: "crush-derm-beside-other-hook",
    title: "With another PreToolUse hook before derm's that allows everything, derm's deny still wins and derm runs once (case 75)",
    harness: "crush",
    async run({ binPath }) {
      const other = { name: "other-status", command: `printf '{"decision":"allow"}'`, timeout: 10 };
      const t = await crushTurn(binPath, { policy: DENY, hooks: (gate) => [other, gate], script: bash("echo crush-beside-ran") });
      const decisions = t.daemon.events.filter((e) => e.kind === "approval" && e.harness === "crush").length;
      const ok = !ran(t, "crush-beside-ran") && decisions === 1;
      return { status: ok ? "pass" : "fail", finding: `ran ${ran(t, "crush-beside-ran")}; derm decisions ${decisions}; ${JSON.stringify(t.results).slice(0, 160)}` };
    },
  },
  {
    id: "crush-derm-full-access",
    title: "With every permission approved by Crush itself, derm's deny still blocks (case 83). Orca's --yolo is a TUI flag that `crush run` refuses; `crush run` approves its whole session (internal/app/app.go:391-393), the same skip --yolo sets (internal/cmd/root.go:291-307)",
    harness: "crush",
    async run({ binPath }) {
      const t = await crushTurn(binPath, { policy: DENY, script: bash("echo crush-yolo-ran") });
      const ok = !ran(t, "crush-yolo-ran") && t.results.some((x) => x.includes("derm: rule bash"));
      return { status: ok ? "pass" : "fail", finding: `exit ${t.r.code}; ${JSON.stringify(t.results).slice(0, 200)}${ok ? "" : ` ${t.r.err.slice(-300)}`}` };
    },
  },
  {
    id: "crush-derm-gate-killed",
    title: "A gate killed mid-call: Crush has no fail-closed switch, so the call runs (case 70; derm status says it fails open)",
    harness: "crush",
    async run({ binPath }) {
      const killed = { name: "derm-gate", command: `node -e "process.kill(process.pid, 'SIGKILL')"`, timeout: 10 };
      const t = await crushTurn(binPath, { policy: DENY, hooks: () => [killed], script: bash("echo crush-killed-ran") });
      const runs = ran(t, "crush-killed-ran");
      return { status: "info", finding: `killed hook: call ran ${runs} (expected true: Crush reads a failed hook as no opinion)` };
    },
  },
];
