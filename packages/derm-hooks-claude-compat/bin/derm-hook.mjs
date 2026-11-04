#!/usr/bin/env node
// derm hook launcher for the eight Claude-format agents (T2.5). Each agent's
// registration (src/registration.ts) runs:
//   node --no-warnings "<this package>/bin/derm-hook.mjs" <agent id> pre
// Plain JavaScript on purpose: it must block even on a Node that cannot load
// the TypeScript hook. Every one of the eight reads exit 2 as "deny this call"
// and shows stderr as the reason (contracts/hook-dialects.md section 2a), so a
// failure here is exit 2 with the reason on stderr, whatever the agent.

const agent = process.argv[2] ?? "";
const event = process.argv[3] ?? "";

function block(reason) {
  process.stderr.write(`derm: ${reason}\n`);
  process.exitCode = 2;
}

if (!process.features || !process.features.typescript) {
  block(`this Node (${process.version}) cannot run the derm hook: it needs type stripping (Node 22.18 or later, not under node_modules)`);
} else {
  try {
    const mod = await import(new URL("../src/hook.ts", import.meta.url).href);
    process.exitCode = await mod.main(agent, event);
  } catch (error) {
    block(`hook error: ${error && error.message ? error.message : String(error)}`);
  }
}
