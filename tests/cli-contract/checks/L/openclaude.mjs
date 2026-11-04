// Lane L: contract checks for derm's gate in OpenClaude (T2.5), against the
// real CLI (npm @twigpine/openclaude) driven by `openclaude -p` against the
// fake Anthropic Messages server (../../lib/fakeMessages.mjs) and a fake derm
// daemon. OpenClaude 0.34.0 needs Node 24.22.1 or later: the check puts the
// folder of DERM_NODE24 (default /opt/node24/bin) first on PATH.
//
//   node tests/cli-contract/run.mjs --cli openclaude=/tmp/cli/openclaude/node_modules/.bin/openclaude --only openclaude-derm-deny

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeMessages, textBlock, toolUse } from "../../lib/fakeMessages.mjs";
import { spawnGroup, stopGroup } from "../../lib/procs.mjs";
import { startFakeDaemon } from "../../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOOK = path.resolve(HERE, "..", "..", "..", "..", "packages", "derm-hooks-claude-compat", "bin", "derm-hook.mjs");
const NODE24 = process.env.DERM_NODE24 ?? "/opt/node24/bin";

function gateEntry(extra = {}) {
  return { type: "command", command: `node --no-warnings "${HOOK}" openclaude pre`, timeout: 120, ...extra };
}

/** One `openclaude -p` turn: the model calls Bash once with `command`, then ends. */
async function turn(bin, { policy, command, approve = "none", hooks, args = [], daemon: withDaemon = true }) {
  const fake = await startFakeMessages({
    script: (body) => (JSON.stringify(body.messages ?? []).includes("tool_result") ? [textBlock("done")] : [toolUse("Bash", { command, description: "step" })]),
  });
  const daemon = await startFakeDaemon({ approve, root: "/tmp" });
  const root = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "oc-derm-"));
  const home = path.join(root, "home");
  const work = path.join(root, "work");
  mkdirSync(path.join(home, ".openclaude"), { recursive: true });
  mkdirSync(path.join(home, ".derm"), { recursive: true, mode: 0o700 });
  mkdirSync(work);
  const policyFile = path.join(home, ".derm", "policy.json");
  writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o600 });
  writeFileSync(path.join(home, ".openclaude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: hooks ?? [{ matcher: "*", hooks: [gateEntry()] }] } }));
  const env = {
    PATH: `${NODE24}:${process.env.PATH}`,
    HOME: home,
    ANTHROPIC_BASE_URL: fake.baseUrl,
    ANTHROPIC_API_KEY: "sk-ant-fake",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    DISABLE_AUTOUPDATER: "1",
    DERM_POLICY: policyFile,
    ...(withDaemon ? daemon.env() : { DERM_DAEMON_SOCKET: path.join(root, "absent.sock") }),
  };
  const child = spawnGroup(bin, ["-p", "run the step", "--output-format", "json", ...args], { env, cwd: work, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (err += d));
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => stopGroup(child).then(() => resolve("timeout")), 150_000);
    child.on("exit", (c) => {
      clearTimeout(timer);
      resolve(c);
    });
  });
  await stopGroup(child);
  const results = [];
  for (const r of fake.turnRequests()) {
    for (const m of r.body?.messages ?? []) {
      for (const c of Array.isArray(m.content) ? m.content : []) {
        if (c?.type === "tool_result") results.push(typeof c.content === "string" ? c.content : JSON.stringify(c.content));
      }
    }
  }
  const marker = path.join(work, "ran.txt");
  const ran = existsSync(marker) ? readFileSync(marker, "utf8") : "";
  const state = { code, out, err, results: [...new Set(results)], ran, events: daemon.events(), approvals: daemon.approvals() };
  await fake.close();
  await daemon.close();
  rmSync(root, { recursive: true, force: true });
  return state;
}

const ALLOW = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "allow" }] };
const DENY = { version: 1, rules: [{ tool: "bash", action: "deny" }] };
const ASK = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "ask" }] };
const brief = (t) => `exit ${t.code}; ran ${JSON.stringify(t.ran.trim())}; results ${JSON.stringify(t.results).slice(0, 220)}`;

export const checks = [
  {
    id: "openclaude-derm-allow",
    title: "An allowed Bash call runs without OpenClaude's prompt, and the daemon gets the decision",
    harness: "openclaude",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, command: "echo oc-allowed > ran.txt" });
      const recorded = t.events.some((e) => e.kind === "approval" && e.harness === "openclaude" && e.detail?.decision === "allow");
      const ok = t.ran.includes("oc-allowed") && recorded;
      return { status: ok ? "pass" : "fail", finding: `${brief(t)}; recorded ${recorded}${ok ? "" : `; ${t.err.slice(-300)}`}` };
    },
  },
  {
    id: "openclaude-derm-deny",
    title: "A denied Bash call does not run and the model reads derm's reason",
    harness: "openclaude",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: DENY, command: "echo oc-denied > ran.txt" });
      const reason = t.results.some((x) => x.includes("derm: rule bash"));
      return { status: !t.ran && reason ? "pass" : "fail", finding: brief(t) };
    },
  },
  {
    id: "openclaude-derm-reject",
    title: "The reject list blocks a write of an endpoint key under an allow rule",
    harness: "openclaude",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, command: "echo export ANTHROPIC_BASE_URL=http://x > ran.txt" });
      const reason = t.results.some((x) => x.includes("reject list: anthropic_base_url"));
      return { status: !t.ran && reason ? "pass" : "fail", finding: brief(t) };
    },
  },
  {
    id: "openclaude-derm-ask",
    title: "An ask is the derm approver's yes; with no approver in -p it goes to OpenClaude's own prompt, which -p cannot show (the call does not run)",
    harness: "openclaude",
    async run({ binPath }) {
      const yes = await turn(binPath, { policy: ASK, approve: "yes", command: "echo oc-approved > ran.txt" });
      const no = await turn(binPath, { policy: ASK, approve: "no", command: "echo oc-declined > ran.txt" });
      const none = await turn(binPath, { policy: ASK, approve: "none", command: "echo oc-unanswered > ran.txt" });
      const ok = yes.ran.includes("oc-approved") && !no.ran && !none.ran;
      return { status: ok ? "pass" : "fail", finding: `yes: ${brief(yes)} | no: ${brief(no)} | none: ${brief(none)}` };
    },
  },
  {
    id: "openclaude-derm-full-access",
    title: "Under --dangerously-skip-permissions (Orca's full access, case 83) a deny still wins and an ask with no approver is a deny",
    harness: "openclaude",
    async run({ binPath }) {
      // OpenClaude refuses every bypass flag as root unless IS_SANDBOX=1 (dist/cli.mjs, "cannot be used with
      // root/sudo"); a check does not set that escape for the CLI, so as root this is a skip.
      if (typeof process.getuid === "function" && process.getuid() === 0) return { status: "skip", finding: "running as root: OpenClaude refuses --dangerously-skip-permissions as root; run as a normal user" };
      const deny = await turn(binPath, { policy: DENY, args: ["--dangerously-skip-permissions"], command: "echo oc-bypass-denied > ran.txt" });
      const ask = await turn(binPath, { policy: ASK, args: ["--dangerously-skip-permissions"], command: "echo oc-bypass-asked > ran.txt" });
      const askReason = ask.results.some((x) => x.includes("ask needs an approver"));
      const ok = !deny.ran && !ask.ran && askReason;
      return { status: ok ? "pass" : "fail", finding: `deny: ${brief(deny)} | ask: ${brief(ask)}` };
    },
  },
  {
    id: "openclaude-derm-beside-orca",
    title: "Beside another PreToolUse hook in the same file (Orca's status hook, case 75), a deny still wins and derm's gate runs once",
    harness: "openclaude",
    async run({ binPath }) {
      const observer = { type: "command", command: "true", timeout: 10 };
      const hooks = [{ matcher: "*", hooks: [observer] }, { matcher: "*", hooks: [gateEntry()] }];
      const t = await turn(binPath, { policy: DENY, hooks, command: "echo oc-beside > ran.txt" });
      const decisions = t.events.filter((e) => e.kind === "approval").length;
      return { status: !t.ran && decisions === 1 ? "pass" : "fail", finding: `${brief(t)}; derm decisions ${decisions}` };
    },
  },
  {
    id: "openclaude-derm-killed",
    title: "A gate killed mid-call (case 70): OpenClaude has no fail-closed switch, so the call runs (recorded)",
    harness: "openclaude",
    async run({ binPath }) {
      const hooks = [{ matcher: "*", hooks: [{ type: "command", command: "kill -9 $$", timeout: 10 }] }];
      const t = await turn(binPath, { policy: DENY, hooks, args: ["--allowedTools", "Bash"], command: "echo oc-killed-ran > ran.txt" });
      return { status: "info", finding: `the call ran: ${Boolean(t.ran)} (expected true: OpenClaude fails open; derm status says so). ${brief(t)}` };
    },
  },
];
