// Shared by lane L's checks: a scratch HOME with a policy, a fake derm daemon,
// one CLI run in its own process group, and what came back. run.mjs loads every
// .mjs file here and wants a `checks` array, so this one exports an empty one.

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnGroup, stopGroup } from "../../lib/procs.mjs";
import { startFakeDaemon } from "../../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts";

export const checks = [];

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const HOOK = path.resolve(HERE, "..", "..", "..", "..", "packages", "derm-hooks-claude-compat", "bin", "derm-hook.mjs");
export const hookCommand = (agent) => `node --no-warnings "${HOOK}" ${agent} pre`;

export const ALLOW = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "allow" }] };
export const DENY = { version: 1, rules: [{ tool: "bash", action: "deny" }] };
export const ASK = { version: 1, askTimeoutSeconds: 5, rules: [{ tool: "bash", action: "ask" }] };

export const brief = (t) => `exit ${t.code}; ran ${JSON.stringify(t.ran.trim())}; results ${JSON.stringify(t.results).slice(0, 220)}`;

/**
 * One run: `setup({ home, work, policyFile, daemonEnv })` writes the agent's
 * config and returns `{ bin, args, env }`; `collect()` returns the tool
 * results the fake model server saw. `ran` is the content of work/ran.txt.
 */
export async function oneRun({ prefix, policy, approve = "none", withDaemon = true, setup, collect, seconds = 150 }) {
  const daemon = await startFakeDaemon({ approve, root: "/tmp" });
  const root = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), `${prefix}-`));
  const home = path.join(root, "home");
  const work = path.join(root, "work");
  mkdirSync(path.join(home, ".derm"), { recursive: true, mode: 0o700 });
  mkdirSync(work);
  const policyFile = path.join(home, ".derm", "policy.json");
  writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o600 });
  const daemonEnv = withDaemon ? daemon.env() : { DERM_DAEMON_SOCKET: path.join(root, "absent.sock") };
  try {
    const { bin, args, env } = await setup({ root, home, work, policyFile, daemonEnv });
    const child = spawnGroup(bin, args, { env: { DERM_POLICY: policyFile, ...daemonEnv, ...env, HOME: home }, cwd: work, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const code = await new Promise((resolve) => {
      const timer = setTimeout(() => stopGroup(child).then(() => resolve("timeout")), seconds * 1000);
      child.on("exit", (c) => {
        clearTimeout(timer);
        resolve(c);
      });
    });
    await stopGroup(child);
    const marker = path.join(work, "ran.txt");
    return { code, out, err, results: collect(), ran: existsSync(marker) ? readFileSync(marker, "utf8") : "", events: daemon.events(), approvals: daemon.approvals() };
  } finally {
    await daemon.close();
    rmSync(root, { recursive: true, force: true });
  }
}
