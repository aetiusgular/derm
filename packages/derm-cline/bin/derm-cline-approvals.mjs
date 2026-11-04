#!/usr/bin/env node
// derm's approval-file responder for Cline (T2.7). `derm run cline` starts it:
//   node --no-warnings <package>/bin/derm-cline-approvals.mjs --dir <folder> [--cwd <session folder>] [--until-pid <pid>]
// Plain JavaScript on purpose: on a Node that cannot load the TypeScript
// responder it exits 1 with the reason, and Cline denies every waiting call
// after 5 minutes (it fails closed).

if (!process.features || !process.features.typescript) {
  process.stderr.write(`derm-cline-approvals: this Node (${process.version}) cannot run the responder: it needs type stripping (Node 22.18 or later, not under node_modules)\n`);
  process.exitCode = 1;
} else {
  try {
    const mod = await import(new URL("../src/responder.ts", import.meta.url).href);
    process.exitCode = await mod.main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`derm-cline-approvals: ${error && error.message ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
