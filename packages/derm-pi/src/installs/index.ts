// Package installs at the gate (wave 5, lane X; plans/toolkit_universal_plan.md
// lane X, contracts/policy.md section 6, note AT), derm-pi's copy: the same
// code as the hook core's (`packages/derm-claude-plugin/src/core/installs/`,
// canonical), held equal by `same-as-core.test.ts`. The wave 5 base cut this seam: `evaluate` calls
// `installDecision` for a shell tool whose answer is still allow after every
// other step, and returns what it says. Lane X owns this folder; the matcher
// around it stays integration's.
//
// What it answers (rules cases 130 to 135):
// - not an install, or an install whose every package the project's lockfile
//   already pins at the version the command names: undefined, the allow
//   stands;
// - any other install: `ask`, the reason naming each package and its version
//   or "no version", and what the check cannot name (a path, a URL, a git
//   source, a requirements file, an update, names read from another command,
//   a registry other than the default).
// The lockfile is read only with a context that gives the call's folder and
// raw text (`InstallContext`); the seam passes none yet, so today every
// install asks (a request for integration: tk_lane_X.md). The pre-install
// check (registry and OSV, off by default) runs in the daemon
// (crates/derm-daemon/src/installs/) and can only turn this `ask` into a
// `deny`.
//
// Held equal to derm-core's (`crates/derm-core/src/installs/`) and derm-pi's
// (`packages/derm-pi/src/installs/`) by contracts/fixtures/installs/.

import type { Action } from "../policy.ts";
import { findLockfile, type LockEntry } from "./lockfile.ts";
import { ECOSYSTEM, type Install, type Manager, type Package, parseInstalls, type Unseen } from "./parse.ts";

export { parseInstalls } from "./parse.ts";
export type { Install, Manager, Package, Unseen } from "./parse.ts";

export type InstallDecision = { action: Exclude<Action, "allow">; reason: string };

/** What a caller knows about the call beyond its folded text. */
export type InstallContext = {
  /** The shell text as the agent sent it. A lockfile vouches for a name only
   * when this, lowercased, equals the folded text: the fold maps look-alike
   * letters, so `lеft-pad` with a Cyrillic `е` reads as `left-pad`. */
  raw?: string;
  /** The absolute folder the command runs in, where the lockfile is looked up. */
  cwd?: string;
  /** Reads a manager's lockfile entries (tests; a caller that read them already).
   * Defaults to the nearest lockfile at or above `cwd`. */
  lockfile?: (manager: Manager) => LockEntry[] | undefined;
};

const MAX_LISTED = 8;
const MAX_REASON = 600;

const UNSEEN_TEXT: Record<Unseen, string> = {
  path: "a local path",
  url: "a URL",
  git: "a git source",
  requirements: "the packages a requirements file names",
  update: "updated versions the command does not name",
  stdin: "names read from another command's output",
  spec: "a package spec the check cannot read",
  registry: "a registry other than the default",
};

/**
 * What the install check says about a shell call, or undefined when the call
 * is not an install, or is one the lockfile already pins (the allow stands).
 * `normalizedTool` is the matcher's normalized name; `folded` the folded,
 * escape-decoded input.
 */
export function installDecision(normalizedTool: string, folded: string, context?: InstallContext): InstallDecision | undefined {
  void normalizedTool;
  const installs = parseInstalls(folded);
  if (installs.length === 0) return undefined;
  if (context !== undefined && allPinned(installs, folded, context)) return undefined;
  return { action: "ask", reason: installReason(installs) };
}

/** The card's text: every install, its manager and form, each package and version. */
export function installReason(installs: Install[]): string {
  const parts: string[] = [];
  for (const inst of installs) {
    const head = `${inst.manager} ${inst.form === "run" ? "runs" : inst.global ? "installs for the user" : "adds"}`;
    const names = inst.packages.slice(0, MAX_LISTED).map((p) => `${p.name} ${p.version ?? "(no version)"}`);
    if (inst.packages.length > MAX_LISTED) names.push(`and ${inst.packages.length - MAX_LISTED} more`);
    const unseen = inst.unseen.map((u) => UNSEEN_TEXT[u]);
    const what = [...names, ...unseen];
    parts.push(`${head} ${what.length ? what.join(", ") : "packages the command does not name"}`);
  }
  const reason = `package install: ${parts.join("; ")}`;
  return reason.length > MAX_REASON ? `${reason.slice(0, MAX_REASON - 3)}...` : reason;
}

// An exact version: no range operator, tag word or wildcard.
const EXACT = /^v?[0-9]+(\.[0-9a-z-]+)*(\+[0-9a-z.-]+)?$/;

/** PEP 503's name normalization; npm, crates and Go names compare as written. */
function sameName(manager: Manager, a: string, b: string): boolean {
  if (ECOSYSTEM[manager] === "PyPI") return a.replace(/[-_.]+/g, "-").toLowerCase() === b.replace(/[-_.]+/g, "-").toLowerCase();
  return a === b;
}

function pinned(manager: Manager, pkg: Package, entries: LockEntry[], anyVersion: boolean): boolean {
  if (pkg.version !== null && !EXACT.test(pkg.version)) return false;
  return entries.some((e) => e.registry && sameName(manager, e.name, pkg.name) && (pkg.version === null ? anyVersion : e.version === pkg.version));
}

/**
 * True when the lockfile already pins every package of every install. A run
 * form keeps the allow only where the manager runs the project's own copy
 * (`npx` and `npm exec`: "Package names provided without a specifier will be
 * matched with whatever version exists in the local project", npm 12.2.2's
 * npx.md; `bunx`: installs only "if not installed in node_modules", bun
 * 1.4.4's help). `pnpm dlx`, `yarn dlx`, `uvx`, `pipx run` and `go run`
 * fetch every time.
 */
function allPinned(installs: Install[], folded: string, context: InstallContext): boolean {
  if (context.raw === undefined || context.raw.toLowerCase() !== folded) return false;
  const read = context.lockfile ?? ((m: Manager) => (context.cwd === undefined ? undefined : findLockfile(m, context.cwd)?.entries));
  const cache = new Map<Manager, LockEntry[] | undefined>();
  for (const inst of installs) {
    if (inst.global || inst.unseen.length || inst.packages.length === 0) return false;
    const runsLocal = inst.form === "run" && (inst.manager === "npm" || inst.manager === "bun");
    if (inst.form === "run" && !runsLocal) return false;
    if (!cache.has(inst.manager)) cache.set(inst.manager, read(inst.manager));
    const entries = cache.get(inst.manager);
    if (entries === undefined) return false;
    // An add with no version moves to the newest one; only a run form keeps
    // whatever version is pinned.
    if (!inst.packages.every((p) => pinned(inst.manager, p, entries, runsLocal))) return false;
  }
  return true;
}

/** The `install.call` record's detail (contracts/events.md section 5;
 * wave5-records.schema.json `installCall`), one per install, for the gate to
 * post as an adapter record. `inLockfile` is null when no lockfile was read. */
export function installCallDetails(
  installs: Install[],
  decision: Action,
  toolUseId: string | null,
  lockfile?: (manager: Manager) => LockEntry[] | undefined,
): Record<string, unknown>[] {
  return installs.map((inst) => {
    const entries = lockfile?.(inst.manager);
    return {
      trust: "client",
      toolUseId: toolUseId === null ? null : toolUseId.slice(0, 128),
      manager: inst.manager,
      form: inst.form,
      packages: inst.packages.slice(0, 256).map((p) => ({
        name: p.name.slice(0, 214),
        version: p.version === null ? null : p.version.slice(0, 128),
        ecosystem: ECOSYSTEM[inst.manager],
        inLockfile: entries === undefined ? null : entries.some((e) => sameName(inst.manager, e.name, p.name) && (p.version === null || e.version === p.version)),
      })),
      decision,
      check: null,
    };
  });
}
