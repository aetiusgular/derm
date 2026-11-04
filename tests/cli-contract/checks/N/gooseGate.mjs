// Lane N: contract checks for derm's goose dialect (T2.6) against the real
// goose CLI, driven by `goose run --no-session --with-builtin developer`
// against a fake OpenAI chat-completions server (../../lib/fakeChat.mjs)
// through goose's openai provider (OPENAI_HOST, OPENAI_BASE_PATH), with a
// fake derm daemon. The gate is the plugin in
// packages/derm-hooks-native/registration/goose/derm/, copied into a scratch
// ~/.agents/plugins/derm/. goose's mode is left at its default (Auto), which
// approves every call itself, so derm's gate is the only check.
//
//   node tests/cli-contract/run.mjs --cli goose=/path/to/goose --only goose-derm-deny,...

import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { startFakeDaemon } from "../../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, "..", "..", "..", "..", "packages", "derm-hooks-native");
const REG = path.join(PKG, "registration", "goose", "derm");

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

/** derm's hooks.json with the package path filled in, or another command in its place. */
function hooksJson(command) {
  const text = readFileSync(path.join(REG, "hooks", "hooks.json"), "utf8").replace("<derm-hooks-native>", PKG);
  if (command === undefined) return text;
  const v = JSON.parse(text);
  v.hooks.PreToolUse[0].hooks[0].command = command;
  return JSON.stringify(v);
}

/** One `goose run`. `extraPlugins` maps a plugin name to its hooks.json text. */
async function gooseTurn(bin, { policy, script, approve = "none", gateCommand, extraPlugins = {}, env: extraEnv = {} }) {
  const fake = await startFakeChat({ script });
  const daemon = await startFakeDaemon({ approve, root: "/tmp" });
  const root = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "goose-derm-"));
  const home = path.join(root, "home");
  const work = path.join(root, "work");
  const plugin = (name, hooks) => {
    const dir = path.join(home, ".agents", "plugins", name);
    mkdirSync(path.join(dir, "hooks"), { recursive: true });
    writeFileSync(path.join(dir, "plugin.json"), name === "derm" ? readFileSync(path.join(REG, "plugin.json")) : JSON.stringify({ name, version: "0.0.1" }));
    writeFileSync(path.join(dir, "hooks", "hooks.json"), hooks);
  };
  plugin("derm", hooksJson(gateCommand));
  for (const [name, hooks] of Object.entries(extraPlugins)) plugin(name, hooks);
  mkdirSync(work);
  const policyFile = path.join(root, "policy.json");
  writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o600 });
  const host = new URL(fake.baseUrl).host;
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    XDG_STATE_HOME: path.join(home, ".local", "state"),
    XDG_CACHE_HOME: path.join(home, ".cache"),
    NO_COLOR: "1",
    GOOSE_PROVIDER: "openai",
    GOOSE_MODEL: "fake-model",
    OPENAI_HOST: `http://${host}`,
    OPENAI_BASE_PATH: "v1/chat/completions",
    OPENAI_API_KEY: "x",
    GOOSE_DISABLE_KEYRING: "1",
    GOOSE_TELEMETRY_ENABLED: "false",
    DERM_POLICY: policyFile,
    ...daemon.env(),
    ...extraEnv,
  };
  try {
    const r = await run(bin, ["run", "--no-session", "--with-builtin", "developer", "-t", "run the step"], env, work);
    return { r, results: toolResults(fake), turns: fake.turns().length, daemon: { events: daemon.events(), approvals: daemon.approvals() } };
  } finally {
    await fake.close();
    await daemon.close();
    rmSync(root, { recursive: true, force: true });
  }
}

const shell = (command) => (_b, n) => (n === 0 ? { tool: "shell", args: { command } } : { text: "done" });
const ALLOW = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "allow" }] };
const DENY = { version: 1, rules: [{ tool: "bash", action: "deny" }] };
const ran = (t, marker) => t.results.some((x) => x.includes(marker) && !x.includes("denied"));
const denied = (t, text) => t.results.some((x) => x.includes("Tool call denied by policy hook `derm`") && x.includes(text));

export const checks = [
  {
    id: "goose-derm-allow",
    title: "An allowed shell call runs under goose's default mode, and the daemon gets derm's record",
    harness: "goose",
    async run({ binPath }) {
      const t = await gooseTurn(binPath, { policy: ALLOW, script: shell("echo goose-allowed-ran") });
      const kinds = t.daemon.events.map((e) => `${e.kind}:${e.harness}`);
      const ok = t.r.code === 0 && ran(t, "goose-allowed-ran") && kinds.includes("approval:goose");
      return { status: ok ? "pass" : "fail", finding: `exit ${t.r.code}; ran ${ran(t, "goose-allowed-ran")}; records ${JSON.stringify(kinds)}${ok ? "" : `; ${JSON.stringify(t.results).slice(0, 200)} ${t.r.err.slice(-300)}`}` };
    },
  },
  {
    id: "goose-derm-deny",
    title: "A denied shell call does not run, the model gets derm's reason, and the turn goes on (case 79)",
    harness: "goose",
    async run({ binPath }) {
      const t = await gooseTurn(binPath, { policy: DENY, script: shell("echo goose-denied-ran") });
      const ok = !ran(t, "goose-denied-ran") && denied(t, "derm: rule bash") && t.turns >= 2;
      return { status: ok ? "pass" : "fail", finding: `turns ${t.turns}; ${JSON.stringify(t.results).slice(0, 240)}` };
    },
  },
  {
    id: "goose-derm-reject",
    title: "The reject list blocks an endpoint key under an allow rule",
    harness: "goose",
    async run({ binPath }) {
      const t = await gooseTurn(binPath, { policy: ALLOW, script: shell("echo export ANTHROPIC_BASE_URL=http://x >> .envrc") });
      return { status: denied(t, "reject list: anthropic_base_url") ? "pass" : "fail", finding: JSON.stringify(t.results).slice(0, 240) };
    },
  },
  {
    id: "goose-derm-ask",
    title: "An ask is the derm approver's yes; with no approver it is a deny (goose has no prompt for a hook)",
    harness: "goose",
    async run({ binPath }) {
      const policy = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "ask" }] };
      const yes = await gooseTurn(binPath, { policy, approve: "yes", script: shell("echo goose-approved-ran") });
      const none = await gooseTurn(binPath, { policy, approve: "none", script: shell("echo goose-unapproved-ran") });
      const asked = yes.daemon.approvals.filter((a) => a.harness === "goose").length;
      const ok = ran(yes, "goose-approved-ran") && !ran(none, "goose-unapproved-ran") && asked === 1;
      return { status: ok ? "pass" : "fail", finding: `yes: ran ${ran(yes, "goose-approved-ran")}, approvals ${asked}; none: ${JSON.stringify(none.results).slice(0, 200)}` };
    },
  },
  {
    id: "goose-derm-control",
    title: "An allowed command that writes into goose's plugin folder asks, and is denied with no approver",
    harness: "goose",
    async run({ binPath }) {
      const t = await gooseTurn(binPath, { policy: ALLOW, script: shell("mkdir -p .agents/plugins/evil") });
      return { status: denied(t, "control file (.agents/plugins/)") ? "pass" : "fail", finding: JSON.stringify(t.results).slice(0, 240) };
    },
  },
  {
    id: "goose-derm-beside-other-plugin",
    title: "Another plugin's PreToolUse hook that allows everything does not undo derm's deny, and derm runs once (case 75)",
    harness: "goose",
    async run({ binPath }) {
      const other = JSON.stringify({ hooks: { PreToolUse: [{ matcher: ".*", hooks: [{ type: "command", command: `printf '{"decision":"allow"}'` }] }] } });
      const t = await gooseTurn(binPath, { policy: DENY, extraPlugins: { "aaa-status": other }, script: shell("echo goose-beside-ran") });
      const decisions = t.daemon.events.filter((e) => e.kind === "approval" && e.harness === "goose").length;
      const ok = !ran(t, "goose-beside-ran") && decisions === 1;
      return { status: ok ? "pass" : "fail", finding: `derm decisions ${decisions}; ${JSON.stringify(t.results).slice(0, 200)}` };
    },
  },
  {
    id: "goose-derm-gate-killed",
    title: "A gate killed mid-call blocks the call, through on_failure: block (case 70)",
    harness: "goose",
    async run({ binPath }) {
      const t = await gooseTurn(binPath, { policy: ALLOW, gateCommand: `node -e "process.kill(process.pid, 'SIGKILL')"`, script: shell("echo goose-killed-ran") });
      const ok = !ran(t, "goose-killed-ran");
      return { status: ok ? "pass" : "fail", finding: JSON.stringify(t.results).slice(0, 240) };
    },
  },
  {
    id: "goose-derm-full-access",
    title: "Under Orca's full-access setting (GOOSE_MODE=auto) derm's deny still blocks (case 83)",
    harness: "goose",
    async run({ binPath }) {
      const t = await gooseTurn(binPath, { policy: DENY, env: { GOOSE_MODE: "auto" }, script: shell("echo goose-auto-ran") });
      const ok = !ran(t, "goose-auto-ran") && denied(t, "derm: rule bash");
      return { status: ok ? "pass" : "fail", finding: JSON.stringify(t.results).slice(0, 240) };
    },
  },
];
