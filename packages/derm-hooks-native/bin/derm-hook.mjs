#!/usr/bin/env node
// derm's gate for the lane N agents (wave 4, T2.6): Cursor, Antigravity,
// goose, Mistral Vibe, Crush and Kiro. Each agent's registration runs
//   node --no-warnings "<this package>/bin/derm-hook.mjs" <agent>
// with the agent's pre-tool input on stdin (registration/<agent>.* has the
// exact entry).
//
// Plain JavaScript on purpose. Several of these agents let a call through
// when a hook fails (Crush always; goose, Vibe and Cursor unless their switch
// is set), so this file turns every failure it can see into that agent's
// own deny before anything else can go wrong: an unknown agent, a Node that
// cannot run TypeScript, a module that does not load.

import { FALLBACK } from "./fallback.mjs";

const agent = process.argv[2] ?? "";

function failClosed(reason) {
  const text = `derm: ${reason}`;
  const f = FALLBACK[agent];
  if (f === undefined) {
    // An unknown agent: no reply shape is known, so a non-zero exit with the
    // reason is the most any hook runner reads as a failure.
    process.stderr.write(`${text}\n`);
    process.exitCode = 2;
    return;
  }
  const r = f(text);
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  process.exitCode = r.exitCode;
}

if (!Object.hasOwn(FALLBACK, agent)) {
  failClosed(`unknown agent "${String(agent).slice(0, 40)}": derm-hook.mjs takes cursor, antigravity, goose, mistral-vibe, crush or kiro`);
} else if (!process.features || !process.features.typescript) {
  failClosed(`this Node (${process.version}) cannot run the derm hook: it needs type stripping (Node 22.18 or later, not under node_modules)`);
} else {
  try {
    const mod = await import(new URL("../src/hook.ts", import.meta.url).href);
    process.exitCode = await mod.main(agent);
  } catch (error) {
    failClosed(`hook error: ${error && error.message ? error.message : String(error)}`);
  }
}
