// Records every hook call the TypeScript dialect tests make, at the
// boundary `derm hook` has: the agent, the event, stdin, the environment,
// the files the environment names, the fake daemon's answer mode, and what
// came back (stdout, stderr, exit code, and the lines the hook sent the
// daemon). The wave 5b base's red tests replay each one against
// `derm hook <agent> <event>` (crates/derm-cli/tests/hook_cases.rs), so
// every case of the TypeScript tests becomes a Rust test held to the
// TypeScript's own behaviour (rules section 9, item 12), not to a
// hand-written expectation.
//
// Loaded only by record.vitest.config.ts; it changes no shipped code.

import { lstatSync, readdirSync, readFileSync, readlinkSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, vi } from "vitest";

const REPO = path.resolve(import.meta.dirname, "..", "..", "..");
const OUT = process.env.DERM_HOOK_CASES_OUT ?? path.join(REPO, "contracts", "fixtures", "hook-cases", "raw.jsonl");
const TMP = tmpdir();

type Daemon = { socket: string; dir: string; lines: { conn: number; line: Record<string, unknown> }[]; behaviour: string };
const daemons = new Map<string, Daemon>();
const defaults = new WeakSet<object>();

function testName(): string {
  const s = expect.getState();
  return `${path.relative(REPO, s.testPath ?? "?")} :: ${s.currentTestName ?? "?"}`;
}

/** Every file under `dir` (small trees only): kind, mode, and text or link target. */
function snapshot(dir: string, depth = 0): Record<string, unknown>[] {
  if (depth > 4) return [];
  const out: Record<string, unknown>[] = [];
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return out;
  }
  for (const n of names.slice(0, 200)) {
    const p = path.join(dir, n);
    let st;
    try {
      st = lstatSync(p);
    } catch {
      continue;
    }
    const rel = p;
    if (st.isSymbolicLink()) out.push({ path: rel, kind: "link", target: readlinkSync(p) });
    else if (st.isDirectory()) {
      out.push({ path: rel, kind: "dir", mode: st.mode & 0o7777 });
      out.push(...snapshot(p, depth + 1));
    } else if (st.isFile()) {
      let text: string | null = null;
      if (st.size <= 256 * 1024) text = readFileSync(p, "utf8");
      out.push({ path: rel, kind: "file", mode: st.mode & 0o7777, text });
    } else if (st.isSocket()) out.push({ path: rel, kind: "socket" });
    else if (st.isFIFO()) out.push({ path: rel, kind: "fifo" });
  }
  return out;
}

/** The temp folders the call can see: the top folder under tmpdir of every path in env and stdin. */
function tempRoots(texts: string[]): string[] {
  const roots = new Set<string>();
  const re = new RegExp(`${TMP.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/[^/"'\\s\\\\]+`, "g");
  for (const t of texts) for (const m of t.matchAll(re)) roots.add(m[0]);
  return [...roots];
}

function record(entry: string, agent: string, event: string, stdin: string, env: Record<string, string | undefined> | undefined, replayable: string | true, run: () => Promise<unknown>): Promise<unknown> {
  const envText = env ? Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined)) as Record<string, string> : {};
  const sock = envText.DERM_DAEMON_SOCKET;
  const d = sock ? daemons.get(sock) : undefined;
  const before = d ? d.lines.length : 0;
  const roots = tempRoots([stdin, ...Object.values(envText), process.cwd()]);
  const files = roots.flatMap((r) => [{ path: r, kind: "dir", mode: (() => { try { return lstatSync(r).mode & 0o7777; } catch { return null; } })() }, ...snapshot(r)]);
  const base = {
    test: testName(),
    entry,
    agent,
    event,
    stdin,
    env: envText,
    cwd: process.cwd(),
    repo: REPO,
    tmp: TMP,
    files,
    daemon: d ? { socket: d.socket, dir: d.dir, approve: d.behaviour } : null,
    replayable,
  };
  const started = Date.now();
  return run().then(
    (result) => {
      const sent = d ? d.lines.slice(before).map((l) => l.line) : [];
      appendFileSync(OUT, `${JSON.stringify({ ...base, result, sent, ms: Date.now() - started })}\n`);
      return result;
    },
    (error) => {
      appendFileSync(OUT, `${JSON.stringify({ ...base, threw: String(error) })}\n`);
      throw error;
    },
  );
}

/** Whether every function in `deps` came from a package's defaultDeps. */
function depsReplayable(deps: unknown): string | true {
  if (deps === undefined) return true;
  if (typeof deps !== "object" || deps === null) return "deps is not an object";
  for (const [k, v] of Object.entries(deps)) {
    if (typeof v === "function" && !defaults.has(v)) return `deps.${k} is the test's own function`;
  }
  return true;
}

/**
 * Marks the functions a package's defaultDeps made as the defaults, but only
 * when it was called with the environment alone: an extra argument (the
 * compat package's test-only `socketDirs`, which names the fake daemon's
 * folder as derm's own) changes what they do, and no process can pass it.
 */
function markDefaults<T>(make: (...a: never[]) => T) {
  return (...a: never[]) => {
    const d = make(...a) as Record<string, unknown>;
    if (a.length <= 1) for (const v of Object.values(d)) if (typeof v === "function") defaults.add(v);
    return d as T;
  };
}

// vi.mock is hoisted above every statement, so each path is a literal
// relative to this file; the factories run later, when a test imports the
// module, and by then everything above is defined.

vi.mock("../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts", async (orig) => {
  const m = (await orig()) as typeof import("../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts");
  return {
    ...m,
    startFakeDaemon: async (opts: Parameters<typeof m.startFakeDaemon>[0] = {}) => {
      const f = await m.startFakeDaemon(opts);
      const d: Daemon = { socket: f.socket, dir: f.dir, lines: f.lines, behaviour: opts.approve ?? "none" };
      daemons.set(f.socket, d);
      const set = f.setApprove;
      f.setApprove = (b) => {
        d.behaviour = b;
        set(b);
      };
      return f;
    },
  };
});

type RunHook = (event: string, stdin: string, env?: NodeJS.ProcessEnv, deps?: unknown) => Promise<unknown>;
function wrapOwn(file: string, agent: string, m: Record<string, unknown>) {
  const run = m.runHook as RunHook;
  const dd = m.defaultDeps as ((...a: never[]) => unknown) | undefined;
  return {
    ...m,
    ...(dd ? { defaultDeps: markDefaults(dd) } : {}),
    runHook: (event: string, stdin: string, env: NodeJS.ProcessEnv = process.env, deps?: unknown) =>
      record(`${file}#runHook`, agent, event, stdin, env, depsReplayable(deps), () => run(event, stdin, env, deps)),
  };
}

vi.mock("../../../packages/derm-claude-plugin/src/hook.ts", async (orig) =>
  wrapOwn("packages/derm-claude-plugin/src/hook.ts", "claude-code", (await orig()) as Record<string, unknown>),
);
vi.mock("../../../packages/derm-codex-plugin/src/hook.ts", async (orig) =>
  wrapOwn("packages/derm-codex-plugin/src/hook.ts", "codex", (await orig()) as Record<string, unknown>),
);
vi.mock("../../../packages/derm-gemini-extension/src/hook.ts", async (orig) =>
  wrapOwn("packages/derm-gemini-extension/src/hook.ts", "gemini", (await orig()) as Record<string, unknown>),
);

vi.mock("../../../packages/derm-hooks-claude-compat/src/hook.ts", async (orig) => {
  const m = (await orig()) as Record<string, unknown> & {
    runHook: (agent: string, event: string, stdin: string, env?: NodeJS.ProcessEnv, deps?: unknown) => Promise<unknown>;
    defaultDeps: (...a: never[]) => unknown;
  };
  return {
    ...m,
    defaultDeps: markDefaults(m.defaultDeps),
    runHook: (agent: string, event: string, stdin: string, env: NodeJS.ProcessEnv = process.env, deps?: unknown) =>
      record("packages/derm-hooks-claude-compat/src/hook.ts#runHook", agent, event, stdin, env, depsReplayable(deps), () => m.runHook(agent, event, stdin, env, deps)),
  };
});

vi.mock("../../../packages/derm-hooks-native/src/runner.ts", async (orig) => {
  const m = (await orig()) as Record<string, unknown> & {
    runPre: (dialect: { id: string }, stdin: string, env?: NodeJS.ProcessEnv, deps?: unknown) => Promise<unknown>;
    defaultDeps: (...a: never[]) => unknown;
  };
  return {
    ...m,
    defaultDeps: markDefaults(m.defaultDeps),
    runPre: (dialect: { id: string }, stdin: string, env: NodeJS.ProcessEnv = process.env, deps?: unknown) =>
      record("packages/derm-hooks-native/src/runner.ts#runPre", dialect.id, "pre", stdin, env, depsReplayable(deps), () => m.runPre(dialect, stdin, env, deps)),
  };
});

vi.mock("../../../packages/derm-hermes-plugin/src/decide.ts", async (orig) => {
  const m = (await orig()) as Record<string, unknown> & {
    handle: (stdin: string, deps?: { env?: NodeJS.ProcessEnv }) => Promise<unknown>;
    defaultDeps: (...a: never[]) => { env: NodeJS.ProcessEnv };
  };
  const dd = markDefaults(m.defaultDeps);
  return {
    ...m,
    defaultDeps: dd,
    handle: (stdin: string, deps?: { env?: NodeJS.ProcessEnv }) => {
      let event = "pre";
      try {
        event = String((JSON.parse(stdin) as { event?: unknown }).event ?? "pre");
      } catch {
        // not JSON: the hook's own answer is recorded
      }
      const d = deps ?? (dd() as { env: NodeJS.ProcessEnv });
      return record("packages/derm-hermes-plugin/src/decide.ts#handle", "hermes", event, stdin, d.env, depsReplayable(d), () => m.handle(stdin, deps));
    },
  };
});

writeFileSync(OUT, "", { flag: "a" });
