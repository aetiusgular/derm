// derm's build for the in-process plugin checks (integration w5b, phase 1).
// Since lane 5bC the plugins decide through `derm gate serve` and find derm by
// an absolute path only: `DERM_BIN`, which `derm run` sets, else derm's fixed
// per-user install folders (packages/*/src/serve/client.ts:123-133; case 227).
// A check's harness runs without `derm run`, so it is given DERM_BIN here:
// the runner's own DERM_BIN, else this repository's release or debug build.
import { chmodSync, existsSync, mkdirSync, symlinkSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

export function dermBin() {
  for (const p of [process.env.DERM_BIN, path.join(ROOT, "target", "release", "derm"), path.join(ROOT, "target", "debug", "derm")]) {
    if (p && existsSync(p)) return path.resolve(p);
  }
  return undefined;
}

/** `{ DERM_BIN }` for a harness's environment, or nothing when no build exists. */
export function dermBinEnv() {
  const b = dermBin();
  return b ? { DERM_BIN: b } : {};
}

/**
 * derm at `<home>/.local/bin/derm` (a link to this build), where the plugins'
 * launcher finds it (lane 5bF: each plugin's hooks/derm-gate.sh runs derm from
 * its install folders only, never PATH or DERM_BIN; case 227). Nothing when
 * no build exists, so a check that needs derm then sees the launcher's own
 * "no derm this hook can trust".
 */
export function installDermAtHome(home) {
  const b = dermBin();
  if (!b) return undefined;
  const bin = path.join(home, ".local", "bin");
  mkdirSync(bin, { recursive: true });
  for (const d of [home, path.join(home, ".local"), bin]) chmodSync(d, 0o755);
  const link = path.join(bin, "derm");
  if (!existsSync(link)) symlinkSync(b, link);
  return link;
}
