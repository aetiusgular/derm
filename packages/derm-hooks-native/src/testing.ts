// Shared by this package's tests only (never loaded by the hook): a policy
// file in a fresh folder and the fake daemon from the canonical package.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { startFakeDaemon, type ApproveBehaviour, type FakeDaemon } from "../../derm-claude-plugin/src/testing/fakeDaemon.ts";

export type Fixture = {
  dir: string;
  policyFile: string;
  daemon: FakeDaemon;
  env: (extra?: Record<string, string>) => Record<string, string>;
  close: () => Promise<void>;
};

/** The rules every dialect's tests share: one per action, on built-in, shell and MCP names. */
export const RULES = [
  { tool: "bash", action: "allow" },
  { tool: "read", action: "allow" },
  { tool: "exa/*", action: "allow" },
  { tool: "my_server/*", action: "deny" },
  { tool: "github/*", action: "ask" },
  { tool: "write", action: "ask" },
];

export async function fixture(opts: { approve?: ApproveBehaviour; rules?: unknown[]; servers?: string[] } = {}): Promise<Fixture> {
  const dir = mkdtempSync(path.join(tmpdir(), "derm-native-"));
  const policyFile = path.join(dir, "policy.json");
  writeFileSync(policyFile, JSON.stringify({ version: 1, askTimeoutSeconds: 1, servers: opts.servers ?? ["exa", "my-server", "github"], rules: opts.rules ?? RULES }), { mode: 0o600 });
  const daemon = await startFakeDaemon({ approve: opts.approve ?? "none" });
  return {
    dir,
    policyFile,
    daemon,
    env: (extra = {}) => ({ DERM_POLICY: policyFile, HOME: dir, ...daemon.env(), ...extra }),
    close: async () => {
      await daemon.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Case 30's tokens: each turns an allowed shell command into an ask. */
export const CASE_30 = ["echo $HOME", "echo `id`", "echo !!", "echo {a,b}", "ls ~", "ls *.txt", "ls file?", "ls [ab]", "echo \\x", "print -l *(e:x:)"];
