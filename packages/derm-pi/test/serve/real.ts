// A real `derm gate serve` for derm-pi's tests (wave 5b lane 5bC): a derm
// build (DERM_BIN, else target/debug or target/release), a temp home with a
// private policy, a session folder apart from it, and no daemon, so an ask
// is Pi's own card.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { GateServe } from "../../src/serve/client.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
export const DERM = process.env.DERM_TEST_NO_BUILD ? undefined : [process.env.DERM_BIN, path.join(ROOT, "target/debug/derm"), path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm.exe"), path.join(ROOT, "target/release/derm.exe")].find((p) => p !== undefined && existsSync(p));
const UID = typeof process.getuid === "function" ? process.getuid() : -1;

export type Real = {
  root: string;
  home: string;
  project: string;
  policyPath: string;
  env: Record<string, string>;
  serve: (env: Record<string, string | undefined>, cwd: string, harness: string) => GateServe;
  close: () => void;
};

/** `policy` undefined: no policy file. `env` is added to the session's. */
export function real(policy: string | undefined, env: Record<string, string> = {}): Real {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "derm-pi-real-")));
  const home = path.join(root, "home");
  const project = path.join(root, "project");
  const policyPath = path.join(home, ".derm", "policy.json");
  mkdirSync(path.join(home, ".derm"), { recursive: true });
  mkdirSync(project);
  chmodSync(home, 0o700);
  chmodSync(path.join(home, ".derm"), 0o700);
  if (policy !== undefined) {
    writeFileSync(policyPath, policy);
    chmodSync(policyPath, 0o600);
  }
  const full = { HOME: home, DERM_DAEMON_SOCKET: path.join(root, "no-daemon.sock"), ...env };
  const made = new Map<string, GateServe>();
  return {
    root,
    home,
    project,
    policyPath,
    env: full,
    serve: (_env, _cwd, harness) => {
      let s = made.get(harness);
      if (s === undefined) {
        s = new GateServe({ agent: harness, env: full, cwd: () => project, trusted: (u) => u === UID, locate: () => ({ path: DERM as string }) });
        made.set(harness, s);
      }
      return s;
    },
    close: () => {
      for (const s of made.values()) s.close();
      rmSync(root, { recursive: true, force: true });
    },
  };
}
