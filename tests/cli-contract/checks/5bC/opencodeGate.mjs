// Wave 5b lane 5bC: the derm OpenCode plugin against the real OpenCode CLI,
// its decisions from `derm gate serve` (contracts/gate-serve.md), driven by
// `opencode run --format json` against a fake OpenAI chat-completions server
// (../../lib/fakeChat.mjs) with a fake derm daemon. Lane I's kiloGate.mjs is
// the model (Kilo is OpenCode's fork); OpenCode had no host check before.
// derm is named by DERM_BIN, the route `derm run` gives a plugin (case 227).
//
//   DERM_BIN=<target>/debug/derm node tests/cli-contract/run.mjs --cli opencode=/path/to/opencode --only opencode-serve-allow,...
//
// run.mjs loads one-letter lane folders only; until integration lets it
// load 5b<X> (tk_lane_5bC.md, request 4), run these with
// `node tests/cli-contract/checks/5bC/run-local.js --cli opencode=<path>`.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { startFakeDaemon } from "../../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..", "..");
const PLUGIN = path.join(ROOT, "packages", "derm-opencode-plugin");
const dermBin = () => [process.env.DERM_BIN, path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm")].find((p) => p && existsSync(p));

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

/** One `opencode run` with the plugin in the config's plugin array. */
async function turn(bin, { policy, script, approve = "none" }) {
  const fake = await startFakeChat({ script });
  const daemon = await startFakeDaemon({ approve, root: "/tmp" });
  const root = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "opencode-serve-"));
  const home = path.join(root, "home");
  const work = path.join(root, "work");
  mkdirSync(path.join(home, ".derm"), { recursive: true, mode: 0o700 });
  mkdirSync(work);
  const policyFile = path.join(home, ".derm", "policy.json");
  writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o600 });
  const config = {
    provider: { fake: { npm: "@ai-sdk/openai-compatible", name: "Fake", options: { baseURL: fake.baseUrl, apiKey: "x" }, models: { "fake-model": { name: "fake", tool_call: true } } } },
    model: "fake/fake-model",
    permission: { bash: "allow", edit: "allow" },
    plugin: [pathToFileURL(PLUGIN).href],
  };
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_CACHE_HOME: path.join(home, ".cache"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    OPENCODE_CONFIG_CONTENT: JSON.stringify(config),
    NO_COLOR: "1",
    DERM_POLICY: policyFile,
    DERM_BIN: dermBin() ?? "",
    ...daemon.env(),
  };
  try {
    const r = await run(bin, ["run", "--format", "json", "run the step"], env, work);
    return { r, results: toolResults(fake), daemon: { events: daemon.events(), approvals: daemon.approvals() } };
  } finally {
    await fake.close();
    await daemon.close();
    rmSync(root, { recursive: true, force: true });
  }
}

const bash = (command) => (_b, n) => (n === 0 ? { tool: "bash", args: { command, description: "step" } } : { text: "done" });
const skip = () => (dermBin() ? undefined : { status: "skip", finding: "no derm build (DERM_BIN, target/release, target/debug)" });

export const checks = [
  {
    id: "opencode-serve-allow",
    title: "An allowed bash call runs, decided by derm gate serve, and the daemon gets the approval and the tool.call",
    harness: "opencode",
    async run({ binPath }) {
      const s = skip();
      if (s) return s;
      const t = await turn(binPath, { policy: { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "allow" }] }, script: bash("echo oc-allowed-ran") });
      const ran = t.results.some((x) => x.includes("oc-allowed-ran"));
      const kinds = t.daemon.events.map((e) => `${e.kind}:${e.harness}`);
      const ok = ran && kinds.includes("approval:opencode") && kinds.includes("tool.call:opencode");
      return { status: ok ? "pass" : "fail", finding: `exit ${t.r.code}; ran ${ran}; records ${JSON.stringify(kinds)}${ok ? "" : `; ${t.r.err.slice(-300)}`}` };
    },
  },
  {
    id: "opencode-serve-deny",
    title: "A denied bash call does not run and the model gets derm's reason",
    harness: "opencode",
    async run({ binPath }) {
      const s = skip();
      if (s) return s;
      const t = await turn(binPath, { policy: { version: 1, rules: [{ tool: "bash", action: "deny" }] }, script: bash("echo oc-denied-ran") });
      const ran = t.results.some((x) => x.includes("oc-denied-ran"));
      const reason = t.results.some((x) => x.includes("derm: rule bash deny"));
      return { status: !ran && reason ? "pass" : "fail", finding: `ran ${ran}; reason ${reason}; ${JSON.stringify(t.results).slice(0, 200)}` };
    },
  },
  {
    id: "opencode-serve-ask",
    title: "An ask runs on the derm approver's yes and not with no approver (OpenCode has no ask of its own)",
    harness: "opencode",
    async run({ binPath }) {
      const s = skip();
      if (s) return s;
      const policy = { version: 1, askTimeoutSeconds: 2, rules: [{ tool: "bash", action: "ask" }] };
      const yes = await turn(binPath, { policy, approve: "yes", script: bash("echo oc-ask-yes-ran") });
      const none = await turn(binPath, { policy, approve: "none", script: bash("echo oc-ask-none-ran") });
      const ranYes = yes.results.some((x) => x.includes("oc-ask-yes-ran"));
      const ranNone = none.results.some((x) => x.includes("oc-ask-none-ran"));
      const ok = ranYes && !ranNone && yes.daemon.approvals.length === 1;
      return { status: ok ? "pass" : "fail", finding: `yes: ran ${ranYes}, approvals ${yes.daemon.approvals.length}; none: ran ${ranNone}, ${JSON.stringify(none.results).slice(0, 160)}` };
    },
  },
  {
    id: "opencode-serve-reject",
    title: "The reject list blocks an allowed bash call",
    harness: "opencode",
    async run({ binPath }) {
      const s = skip();
      if (s) return s;
      const t = await turn(binPath, { policy: { version: 1, rules: [{ tool: "bash", action: "allow" }] }, script: bash("export ANTHROPIC_BASE_URL=http://203.0.113.9") });
      const blocked = t.results.some((x) => x.includes("derm: reject list: anthropic_base_url"));
      return { status: blocked ? "pass" : "fail", finding: JSON.stringify(t.results).slice(0, 200) };
    },
  },
];
