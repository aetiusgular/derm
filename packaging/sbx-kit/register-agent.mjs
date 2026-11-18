// Registers derm's gate for one command-hook agent in its own config under
// the agent's home, merging with what is there. Run by the sbx kit's install
// script as root inside the VM (packaging/sbx-kit/hooks/install.sh):
//
//   node register-agent.mjs <agent> <home> <node> <derm-hook.mjs>
//
// It prints each file it wrote, one per line, for the script to hand to the
// agent's user. Plain JavaScript with no dependencies.
//
// The entries are the hook packages' own (derm-hooks-claude-compat
// src/registration.ts for Copilot CLI and Droid; derm-hooks-native
// registration/ for Cursor and Kiro), with the kit's Node by its absolute
// path where they say `node`: sbx's images for these agents have no Node on
// PATH (seen in the VMs on the box, sbx 0.51.0, 17 Nov 2026; Cursor's has
// its own, which derm does not use). register-agent.test.ts holds the two
// equal.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const GATE_TIMEOUT_SECONDS = 120;
export const AGENTS = ["copilot-cli", "droid", "cursor", "kiro"];

/** Agents whose hook takes `<agent> pre`; the others take `<agent>` alone. */
const COMPAT = new Set(["copilot-cli", "droid"]);

function safePath(what, p) {
  if (typeof p !== "string" || !path.isAbsolute(p)) throw new Error(`the ${what} path must be absolute`);
  // The entry is a shell line in each of these agents.
  if (/["\\$`\s]/.test(p) || /[\u0000-\u001f\u007f\u2028\u2029]/.test(p)) throw new Error(`the ${what} path holds a character a shell would read`);
  return p;
}

/** The hook's command line for `agent`. */
export function command(agent, node, hook) {
  if (!AGENTS.includes(agent)) throw new Error(`no registration for ${agent}`);
  safePath("node", node);
  safePath("hook", hook);
  return `${node} --no-warnings "${hook}" ${agent}${COMPAT.has(agent) ? " pre" : ""}`;
}

/**
 * Where the entry goes and what it is. `own`: a file that is derm's alone.
 * `merge`: lists under `hooks` in a file that holds other settings.
 */
export function plan(agent, home, node, hook) {
  const cmd = command(agent, node, hook);
  if (typeof home !== "string" || !path.isAbsolute(home)) throw new Error("the home path must be absolute");
  const at = (...p) => path.posix.join(home, ...p);
  switch (agent) {
    case "copilot-cli":
      return {
        file: at(".copilot", "hooks", "derm.json"),
        shape: "own",
        entry: { version: 1, hooks: { preToolUse: [{ type: "command", bash: cmd, timeoutSec: GATE_TIMEOUT_SECONDS }] } },
        mustNotExist: [],
      };
    case "droid":
      return {
        file: at(".factory", "settings.json"),
        shape: "merge",
        entry: { hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: cmd, timeout: GATE_TIMEOUT_SECONDS }] }] } },
        // Droid merges either file over settings.json per event: a
        // PreToolUse list there shadows derm's (the package's note).
        mustNotExist: [at(".factory", "hooks.json"), at(".factory", "hooks", "hooks.json")],
      };
    case "cursor": {
      const h = { type: "command", command: cmd, timeout: GATE_TIMEOUT_SECONDS, failClosed: true };
      return { file: at(".cursor", "hooks.json"), shape: "merge", entry: { version: 1, hooks: { preToolUse: [h], beforeMCPExecution: [{ ...h }] } }, mustNotExist: [] };
    }
    case "kiro":
      return {
        file: at(".kiro", "hooks", "derm.json"),
        shape: "own",
        entry: {
          version: "v1",
          hooks: [
            {
              name: "derm-gate",
              description: "derm policy gate: exit 2 blocks the call, exit 0 prints nothing",
              trigger: "PreToolUse",
              action: { type: "command", command: cmd },
              timeout: GATE_TIMEOUT_SECONDS,
              enabled: true,
            },
          ],
        },
        mustNotExist: [],
      };
    default:
      throw new Error(`no registration for ${agent}`);
  }
}

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function readJson(file) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") return undefined;
    throw e;
  }
  if (text.trim() === "") return undefined;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${file} is not JSON`);
  }
}

/** True when `list` already holds an entry that runs this command line. */
function holds(list, cmd) {
  return JSON.stringify(list).includes(JSON.stringify(cmd));
}

/** `have` with the entry's hook lists added; every other key and hook kept. */
function merged(file, have, entry, cmd) {
  if (!isObject(have)) throw new Error(`${file} does not hold a JSON object`);
  const out = { ...entry, ...have };
  if (have.hooks !== undefined && !isObject(have.hooks)) throw new Error(`"hooks" in ${file} is not an object`);
  const hooks = { ...(have.hooks ?? {}) };
  for (const [event, add] of Object.entries(entry.hooks)) {
    const list = hooks[event] ?? [];
    if (!Array.isArray(list)) throw new Error(`"hooks.${event}" in ${file} is not a list`);
    hooks[event] = holds(list, cmd) ? list : [...list, ...add];
  }
  out.hooks = hooks;
  return out;
}

/** Writes the registration; returns the files written (none when it was there already). */
export function register(agent, home, node, hook) {
  const p = plan(agent, home, node, hook);
  const cmd = command(agent, node, hook);
  for (const f of p.mustNotExist) {
    if (existsSync(f)) throw new Error(`${f} exists and would shadow derm's gate in ${p.file}`);
  }
  const have = readJson(p.file);
  let next;
  if (p.shape === "own") {
    if (have !== undefined && JSON.stringify(have) !== JSON.stringify(p.entry)) throw new Error(`${p.file} exists and is not derm's`);
    next = p.entry;
  } else {
    next = merged(p.file, have ?? {}, p.entry, cmd);
  }
  const text = `${JSON.stringify(next, null, 2)}\n`;
  mkdirSync(path.dirname(p.file), { recursive: true });
  let same = false;
  try {
    same = readFileSync(p.file, "utf8") === text;
  } catch {
    same = false;
  }
  if (!same) {
    const tmp = `${p.file}.derm-${process.pid}`;
    writeFileSync(tmp, text, { mode: 0o644 });
    renameSync(tmp, p.file);
  }
  return [p.file];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [agent, home, node, hook] = process.argv.slice(2);
  if (!agent || !home || !node || !hook) {
    process.stderr.write("usage: node register-agent.mjs <agent> <home> <node> <derm-hook.mjs>\n");
    process.exit(2);
  }
  try {
    for (const f of register(agent, home, node, hook)) process.stdout.write(`${f}\n`);
  } catch (e) {
    process.stderr.write(`derm kit: ${e.message}\n`);
    process.exit(1);
  }
}
