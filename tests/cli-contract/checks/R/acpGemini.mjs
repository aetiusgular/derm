// Lane R (wave 4, toolkit plan T2.9): `derm acp` between a scripted ACP
// client and the real Gemini CLI in `--acp` mode, against the fake Gemini
// API. No account, no network.
//
//   cargo build --release -p derm-cli
//   node tests/cli-contract/run.mjs --cli gemini=/tmp/cli/gemini/node_modules/.bin/gemini --only acp-gemini
//
// The derm binary is DERM_BIN, else target/release/derm, else
// target/debug/derm. `--no-daemon`: these checks are about the answers;
// the records are held by the Rust end-to-end test
// (`acp_answers_a_permission_request_between_the_client_and_a_real_agent`).
//
// What Gemini CLI 0.66.0 sends (run 3 Nov 2026): a `tool_call` and a
// `session/request_permission` with `kind: "execute"`, the command in
// `title`, no `name`, no `rawInput`; options `proceed_always`
// (allow_always), `proceed_once` (allow_once), `cancel` (reject_once). It
// asks for `touch`, and runs `echo` without asking.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { functionCall, startFakeGemini, text } from "../../lib/fakeGemini.mjs";
import { spawnGroup, stopGroup } from "../../lib/procs.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");

function dermBin() {
  for (const p of [process.env.DERM_BIN, path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm")]) {
    if (p && existsSync(p)) return p;
  }
  return null;
}

/**
 * One prompt turn: the fake model asks for one `run_shell_command`; the
 * scripted client answers whatever reaches it with `clientAnswer`.
 */
async function turn({ gemini, derm, command, rules, clientAnswer }) {
  const fake = await startFakeGemini({
    script: (_body, n) => (n === 0 ? [functionCall("run_shell_command", { command })] : [text("done")]),
  });
  const root = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "acp-r-"));
  const home = path.join(root, "home");
  const work = path.join(root, "work");
  mkdirSync(path.join(home, ".gemini"), { recursive: true });
  mkdirSync(work);
  writeFileSync(path.join(home, ".gemini", "settings.json"), JSON.stringify({ security: { auth: { selectedType: "gemini-api-key" } } }));
  const policy = path.join(root, "policy.json");
  writeFileSync(policy, JSON.stringify({ version: 1, rules }), { mode: 0o600 });
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    GEMINI_API_KEY: "fake-key",
    GOOGLE_GEMINI_BASE_URL: fake.baseUrl,
    GEMINI_CLI_TRUST_WORKSPACE: "true",
    GEMINI_CLI_NO_RELAUNCH: "true",
    NO_COLOR: "1",
    DERM_POLICY: policy,
  };
  const child = spawnGroup(derm, ["acp", "--boundary", "none", "--no-daemon", "--cwd", work, "--", gemini, "--acp"], {
    env,
    cwd: work,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));
  const seen = { requests: [], updates: [], answeredByClient: [] };
  const rl = readline.createInterface({ input: child.stdout });
  let id = 0;
  const pending = new Map();
  const send = (m) => child.stdin.write(JSON.stringify(m) + "\n");
  const call = (method, params) =>
    new Promise((resolve) => {
      const i = ++id;
      pending.set(i, resolve);
      send({ jsonrpc: "2.0", id: i, method, params });
    });
  rl.on("line", (line) => {
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      return;
    }
    if (m.id !== undefined && !m.method && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    } else if (m.method === "session/request_permission") {
      seen.requests.push(m);
      const opt = m.params.options.find((o) => o.kind === clientAnswer);
      seen.answeredByClient.push(opt?.optionId);
      send({ jsonrpc: "2.0", id: m.id, result: { outcome: { outcome: "selected", optionId: opt.optionId } } });
    } else if (m.method === "session/update") {
      const u = m.params?.update;
      if (u?.sessionUpdate === "tool_call" || u?.sessionUpdate === "tool_call_update") seen.updates.push(u);
    }
  });
  const timeout = (ms) => new Promise((r) => setTimeout(() => r({ timeout: true }), ms));
  let result;
  try {
    const init = await Promise.race([call("initialize", { protocolVersion: 1, clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false } }), timeout(60000)]);
    if (init.timeout) throw new Error(`no initialize reply; stderr: ${stderr.slice(-400)}`);
    const s = await call("session/new", { cwd: work, mcpServers: [] });
    const sid = s.result?.sessionId;
    if (!sid) throw new Error(`no session: ${JSON.stringify(s).slice(0, 300)}`);
    result = await Promise.race([call("session/prompt", { sessionId: sid, prompt: [{ type: "text", text: "run the step" }] }), timeout(90000)]);
  } finally {
    await stopGroup(child);
    await fake.close?.();
  }
  const statuses = seen.updates.map((u) => u.status).filter(Boolean);
  const out = { result, seen, statuses, stderr, work };
  rmSync(root, { recursive: true, force: true });
  return out;
}

export const checks = [
  {
    id: "acp-gemini",
    title: "derm acp answers Gemini CLI's ACP permission requests from the policy",
    harness: "gemini",
    async run({ binPath }) {
      const derm = dermBin();
      if (!derm) return { status: "skip", finding: "no derm binary (DERM_BIN, target/release, target/debug)" };
      const findings = [];
      let failed = false;
      const check = (ok, line) => {
        findings.push(`${ok ? "ok" : "FAIL"}: ${line}`);
        if (!ok) failed = true;
      };

      // 1. A deny: derm rejects, the client is never asked even though it
      // would have allowed, and the command does not run.
      const deny = await turn({
        gemini: binPath,
        derm,
        command: "touch derm-acp-deny",
        rules: [{ tool: "bash", action: "deny" }],
        clientAnswer: "allow_once",
      });
      check(deny.result?.result?.stopReason === "end_turn", `deny: the turn ended (${JSON.stringify(deny.result).slice(0, 120)})`);
      check(deny.seen.requests.length === 0, `deny: no permission request reached the client (${deny.seen.requests.length})`);
      check(deny.statuses.includes("failed") && !deny.statuses.includes("completed"), `deny: the call failed, never completed (${deny.statuses.join(",")})`);

      // 2. A catch-all allow: Gemini's call carries no name, so derm does
      // not allow it alone (case 73); the client's prompt decides.
      const ask = await turn({
        gemini: binPath,
        derm,
        command: "touch derm-acp-ask",
        rules: [{ tool: "*", action: "allow" }],
        clientAnswer: "reject_once",
      });
      check(ask.seen.requests.length === 1, `ask: the request reached the client (${ask.seen.requests.length})`);
      check(!ask.statuses.includes("completed"), `ask: the client's reject held (${ask.statuses.join(",")})`);

      // 3. The reject list over the title: denied by derm whatever the rules
      // and whatever the client would say.
      const reject = await turn({
        gemini: binPath,
        derm,
        command: "codex --dangerously-bypass-approvals-and-sandbox exec hi",
        rules: [{ tool: "*", action: "allow" }],
        clientAnswer: "allow_once",
      });
      check(reject.seen.requests.length === 0, `reject list: no request reached the client (${reject.seen.requests.length})`);
      check(!reject.statuses.includes("completed"), `reject list: the call never ran (${reject.statuses.join(",")})`);

      // 4. A call Gemini does not ask about: it runs, and derm can only log
      // it (information, not a failure).
      const quiet = await turn({
        gemini: binPath,
        derm,
        command: "echo derm-acp-quiet",
        rules: [{ tool: "bash", action: "deny" }],
        clientAnswer: "allow_once",
      });
      findings.push(
        `info: echo under a bash deny: ${quiet.seen.requests.length} request(s) to the client, statuses ${quiet.statuses.join(",") || "none"} (Gemini runs it without asking: logged, not gated)`,
      );

      return { status: failed ? "fail" : "pass", finding: findings.join("; ") };
    },
  },
];
