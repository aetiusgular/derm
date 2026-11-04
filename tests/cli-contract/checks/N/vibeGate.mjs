// Lane N: contract checks for derm's Mistral Vibe dialect (T2.6) against
// the real Vibe CLI, driven by `vibe -p ... --auto-approve` against a fake
// OpenAI chat-completions server (../../lib/fakeChat.mjs) as a generic
// provider in a scratch $VIBE_HOME/config.toml, with a fake derm daemon.
// The gate is $VIBE_HOME/hooks.toml as packages/derm-hooks-native/
// registration/mistral-vibe/hooks.toml gives it. --auto-approve approves
// every call itself, so derm's gate is the only check.
//
//   node tests/cli-contract/run.mjs --cli mistral-vibe=/path/to/vibe --only vibe-derm-deny,...

import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { startFakeDaemon } from "../../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, "..", "..", "..", "..", "packages", "derm-hooks-native");
const REG = path.join(PKG, "registration", "mistral-vibe", "hooks.toml");

function run(bin, args, env, cwd, seconds = 180) {
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

const tomlString = (s) => JSON.stringify(s);

async function vibeTurn(bin, { policy, script, approve = "none", gateCommand, flags = ["--auto-approve"] }) {
  const fake = await startFakeChat({ script, model: "fake-model" });
  const daemon = await startFakeDaemon({ approve, root: "/tmp" });
  const root = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "vibe-derm-"));
  const home = path.join(root, "home");
  const vibeHome = path.join(home, ".vibe");
  const work = path.join(root, "work");
  mkdirSync(vibeHome, { recursive: true });
  mkdirSync(work);
  const policyFile = path.join(root, "policy.json");
  writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o600 });
  writeFileSync(
    path.join(vibeHome, "config.toml"),
    [
      'active_model = "fake"',
      "enable_telemetry = false",
      "enable_update_checks = false",
      "[[providers]]",
      'name = "fake"',
      `api_base = ${tomlString(fake.baseUrl)}`,
      'api_key_env_var = "FAKE_API_KEY"',
      'api_style = "openai"',
      'backend = "generic"',
      "[[models]]",
      'name = "fake-model"',
      'provider = "fake"',
      'alias = "fake"',
      "max_context_length = 32000",
      "",
    ].join("\n"),
  );
  let hooks = readFileSync(REG, "utf8").replace("<derm-hooks-native>", PKG);
  if (gateCommand !== undefined) hooks = hooks.replace(/^command = .*$/m, `command = ${tomlString(gateCommand)}`);
  writeFileSync(path.join(vibeHome, "hooks.toml"), hooks);
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    VIBE_HOME: vibeHome,
    FAKE_API_KEY: "x",
    NO_COLOR: "1",
    DERM_POLICY: policyFile,
    ...daemon.env(),
  };
  try {
    const r = await run(bin, ["-p", "run the step", ...flags, "--max-turns", "3"], env, work);
    return { r, results: toolResults(fake), turns: fake.turns().length, daemon: { events: daemon.events(), approvals: daemon.approvals() } };
  } finally {
    await fake.close();
    await daemon.close();
    rmSync(root, { recursive: true, force: true });
  }
}

const bash = (command) => (_b, n) => (n === 0 ? { tool: "bash", args: { command } } : { text: "done" });
const ALLOW = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "allow" }] };
const DENY = { version: 1, rules: [{ tool: "bash", action: "deny" }] };
const ran = (t, marker) => t.results.some((x) => x.includes(marker) && !x.includes("derm:"));
const denied = (t, text) => t.results.some((x) => x.includes(text));

export const checks = [
  {
    id: "vibe-derm-allow",
    title: "An allowed bash call runs under --auto-approve, and the daemon gets derm's record",
    harness: "mistral-vibe",
    async run({ binPath }) {
      const t = await vibeTurn(binPath, { policy: ALLOW, script: bash("echo vibe-allowed-ran") });
      const kinds = t.daemon.events.map((e) => `${e.kind}:${e.harness}`);
      const ok = ran(t, "vibe-allowed-ran") && kinds.includes("approval:mistral-vibe");
      return { status: ok ? "pass" : "fail", finding: `exit ${t.r.code}; records ${JSON.stringify(kinds)}; ${JSON.stringify(t.results).slice(0, 200)}${ok ? "" : ` ${t.r.err.slice(-400)}`}` };
    },
  },
  {
    id: "vibe-derm-deny",
    title: "A denied bash call does not run and the model gets derm's reason (a JSON deny on exit 0)",
    harness: "mistral-vibe",
    async run({ binPath }) {
      const t = await vibeTurn(binPath, { policy: DENY, script: bash("echo vibe-denied-ran") });
      const ok = !ran(t, "vibe-denied-ran") && denied(t, "derm: rule bash") && t.turns >= 2;
      return { status: ok ? "pass" : "fail", finding: `turns ${t.turns}; ${JSON.stringify(t.results).slice(0, 240)}` };
    },
  },
  {
    id: "vibe-derm-ask",
    title: "An ask is the derm approver's yes; with no approver it is a deny (Vibe has no prompt for a hook)",
    harness: "mistral-vibe",
    async run({ binPath }) {
      const policy = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "ask" }] };
      const yes = await vibeTurn(binPath, { policy, approve: "yes", script: bash("echo vibe-approved-ran") });
      const none = await vibeTurn(binPath, { policy, approve: "none", script: bash("echo vibe-unapproved-ran") });
      const asked = yes.daemon.approvals.filter((a) => a.harness === "mistral-vibe").length;
      const ok = ran(yes, "vibe-approved-ran") && !ran(none, "vibe-unapproved-ran") && asked === 1;
      return { status: ok ? "pass" : "fail", finding: `yes: ran ${ran(yes, "vibe-approved-ran")}, approvals ${asked}; none: ${JSON.stringify(none.results).slice(0, 200)}` };
    },
  },
  {
    id: "vibe-derm-control",
    title: "An allowed command that names Vibe's hooks file asks, and is denied with no approver",
    harness: "mistral-vibe",
    async run({ binPath }) {
      const t = await vibeTurn(binPath, { policy: ALLOW, script: bash("touch .vibe/hooks.toml") });
      return { status: denied(t, "control file (.vibe/)") ? "pass" : "fail", finding: JSON.stringify(t.results).slice(0, 240) };
    },
  },
  {
    id: "vibe-derm-gate-killed",
    title: "A gate killed mid-call blocks the call, through strict = true (case 70)",
    harness: "mistral-vibe",
    async run({ binPath }) {
      const t = await vibeTurn(binPath, { policy: ALLOW, gateCommand: `node -e "process.kill(process.pid, 'SIGKILL')"`, script: bash("echo vibe-killed-ran") });
      const ok = !ran(t, "vibe-killed-ran") && t.turns >= 2;
      return { status: ok ? "pass" : "fail", finding: JSON.stringify(t.results).slice(0, 240) };
    },
  },
  {
    id: "vibe-derm-full-access",
    title: "Under Orca's full-access setting (--agent auto-approve) derm's deny still blocks (case 83)",
    harness: "mistral-vibe",
    async run({ binPath }) {
      const t = await vibeTurn(binPath, { policy: DENY, flags: ["--agent", "auto-approve"], script: bash("echo vibe-agent-ran") });
      const ok = !ran(t, "vibe-agent-ran") && denied(t, "derm: rule bash");
      return { status: ok ? "pass" : "fail", finding: `exit ${t.r.code}; ${JSON.stringify(t.results).slice(0, 200)}${ok ? "" : ` ${t.r.err.slice(-300)}`}` };
    },
  },
];
